/**
 * TLS handshake record state machine: integration and mutation tests.
 *
 * These tests drive forge's TLS record/handshake state machine entirely from
 * in-memory byte strings -- no sockets, servers, or network access. The focus
 * is on the receive-side state machine in lib/tls.js (the ctTable/hsTable
 * dispatch, the c.fragmented reassembly cache, and c.process()'s bounded
 * record loop) under adversarial input:
 *
 *   - handshake messages fragmented across records (including every byte
 *     offset and 1-byte continuation records),
 *   - handshake/record length field boundaries and lies,
 *   - handshake type and content type switches against the expected state,
 *   - replayed fragments and replayed full messages,
 *   - truncated record headers, handshake headers, and message bodies,
 *   - deterministic byte-level mutation ("fuzz") sweeps.
 *
 * Every failure-oriented sample asserts the three state-machine safety
 * properties: the engine never throws, never loops without returning, and
 * never advances its expect state on an invalid transition. Valid samples,
 * by contrast, must still parse and advance exactly as the state tables
 * prescribe. Test names encode the exact state transition each sample
 * triggers, so a failing sample identifies the edge it exercises.
 *
 * State names used below mirror the internal tables:
 *   client: SHE=0 SCE=1 SKE=2 SCR=3 SHD=4 SCC=5 SFI=6 SAD=7 SER=8
 *   server: CHE=0 CCE=1 CKE=2 CCV=3 CCC=4 CFI=5 CAD=6 CER=7
 */
var ASSERT = require('assert');
var forge = require('../../lib/forge');
require('../../lib/tls');
require('../../lib/aesCipherSuites');

(function() {

  describe('tls handshake record state machine', function() {
  // short aliases for the protocol constants under test
    var CT = forge.tls.ContentType;
    var HT = forge.tls.HandshakeType;
    var ALERT = forge.tls.Alert;

    // expect-state indices (see lib/tls.js state tables)
    var SHE = 0;
    var SCE = 1;
    var CHE = 0;
    var CKE = 2;

    // ----------------------------------------------------------------------
    // In-memory wire builders. Everything below produces plain binary strings
    // that are fed straight into c.process(); no I/O is ever performed.
    // ----------------------------------------------------------------------

    // build a TLS record: type(1) version(2) length(2) fragment
    function record(type, fragment, version) {
      version = version || [3, 1];
      var b = forge.util.createBuffer();
      b.putByte(type);
      b.putByte(version[0]);
      b.putByte(version[1]);
      b.putInt16(fragment.length);
      b.putBytes(fragment);
      return b.getBytes();
    }

    // build a handshake message fragment: type(1) length(3) body
    function handshake(type, body) {
      return String.fromCharCode(type) +
      forge.util.int32ToBytes(body.length).substr(1) + body;
    }

    // build a handshake message whose 24-bit length field is set explicitly,
    // independent of the actual body size (used for length-field lies)
    function handshakeWithLength(type, length, body) {
      return String.fromCharCode(type) +
      forge.util.int32ToBytes(length).substr(1) + body;
    }

    function repeat(bytes, count) {
      var b = forge.util.createBuffer();
      for(var i = 0; i < count; ++i) {
        b.putBytes(bytes);
      }
      return b.getBytes();
    }

    // A valid ServerHello body (38 bytes): TLS 1.0 version, 32 random bytes,
    // empty session id, TLS_RSA_WITH_AES_128_CBC_SHA (0x002f), compression 0.
    function validServerHelloBody() {
      return forge.util.hexToBytes('0301') +
      forge.util.createBuffer().fillWithByte(0x11, 32).getBytes() +
      forge.util.hexToBytes('00') + // session id length 0
      forge.util.hexToBytes('002f') + // cipher suite
      forge.util.hexToBytes('00'); // compression method null
    }

    // A valid ClientHello body (41 bytes): TLS 1.2 client version, 32 random
    // bytes, empty session id, one cipher suite (0x002f), compression null.
    function validClientHelloBody() {
      return forge.util.hexToBytes('0303') +
      forge.util.createBuffer().fillWithByte(0x22, 32).getBytes() +
      forge.util.hexToBytes('00') + // session id length 0
      forge.util.hexToBytes('0002002f') + // 2-byte vector: one suite
      forge.util.hexToBytes('0100'); // 1-byte vector: compression null
    }

    // create a connection that records everything its callbacks observe; the
    // tlsDataReady output is captured so alert records can be inspected
    function createConnection(server) {
      var log = {
        errors: [],
        alerts: [],
        sent: '',
        closed: 0,
        dataReady: 0
      };
      var c = forge.tls.createConnection({
        server: !!server,
        verify: function() {
          return true;
        },
        tlsDataReady: function(conn) {
          var bytes = conn.tlsData.getBytes();
          log.sent += bytes;
          // decode any alert records the engine emits
          var b = forge.util.createBuffer(bytes);
          while(b.length() >= 5) {
            var type = b.getByte();
            b.getBytes(2);
            var frag = b.getBytes(b.getInt16());
            if(type === CT.alert && frag.length >= 2) {
              log.alerts.push({
                level: frag.charCodeAt(0),
                description: frag.charCodeAt(1)
              });
            }
          }
        },
        dataReady: function(conn) {
          log.dataReady++;
          conn.data.getBytes();
        },
        closed: function() {
          log.closed++;
        },
        error: function(conn, error) {
          log.errors.push(error.message);
        }
      });
      if(!server) {
      // move a client into its initial SHE expect-state and discard the
      // ClientHello flight it queues
        c.handshake();
        log.sent = '';
      }
      return {c: c, log: log};
    }

    // Run one in-memory batch of bytes through the engine with the safety
    // guarantees every test relies on: a throw escapes the test as a failure,
    // and processing must return promptly (the internal loop is bounded by the
    // bytes supplied, so this also guards against non-consuming busy loops).
    function processBatch(c, bytes) {
      var start = process.hrtime ? process.hrtime() : null;
      var rval = c.process(bytes);
      if(start) {
        var elapsed = process.hrtime(start);
        var ms = elapsed[0] * 1000 + elapsed[1] / 1e6;
        ASSERT.ok(ms < 5000, 'process() took ' + ms + 'ms; possible busy loop');
      }
      return rval;
    }

    // feed bytes one at a time, returning the array of process() return values
    function processByteByByte(c, bytes) {
      var rvals = [];
      for(var i = 0; i < bytes.length; ++i) {
        rvals.push(processBatch(c, bytes.charAt(i)));
      }
      return rvals;
    }

    // ======================================================================
    // 1. Valid handshake records must survive intact (regression anchor).
    //    Every malformed-input test below is meaningful only if these legal
    //    samples still parse and drive the documented state transitions.
    // ======================================================================
    describe('valid handshake parsing is preserved', function() {
      it('parses a complete ServerHello and advances SHE -> SCE', function() {
        var t = createConnection(false);
        var msg = handshake(HT.server_hello, validServerHelloBody());

        var rval = processBatch(t.c, record(CT.handshake, msg));

        ASSERT.equal(rval, 0);
        ASSERT.deepEqual(t.log.errors, []);
        ASSERT.equal(t.c.fail, false);
        // SHE(0) -> SCE(1): the state machine advanced exactly one transition
        ASSERT.equal(t.c.expect, SCE);
        ASSERT.equal(t.c.fragmented, null);
        // the parse result is retained on the session
        ASSERT.equal(t.c.session.cipherSuite.name,
          'TLS_RSA_WITH_AES_128_CBC_SHA');
        ASSERT.equal(t.c.session.version.major, 3);
        ASSERT.equal(t.c.session.version.minor, 1);
        ASSERT.equal(t.c.session.id.length, 0);
      });

      it('parses a complete ClientHello on a server (CHE -> CKE)', function() {
        var t = createConnection(true);
        var msg = handshake(HT.client_hello, validClientHelloBody());

        var rval = processBatch(t.c, record(CT.handshake, msg));

        ASSERT.equal(rval, 0);
        ASSERT.deepEqual(t.log.errors, []);
        ASSERT.equal(t.c.fail, false);
        // no client-cert requirement: CHE(0) -> CKE(2)
        ASSERT.equal(t.c.expect, CKE);
        ASSERT.equal(t.c.open, true);
        // the server queues ServerHello + Certificate + ServerHelloDone
        var b = forge.util.createBuffer(t.log.sent);
        var sentTypes = [];
        while(b.length() >= 5) {
          sentTypes.push(b.getByte());
          b.getBytes(2);
          b.getBytes(b.getInt16());
        }
        ASSERT.deepEqual(sentTypes, [
          CT.handshake, CT.handshake, CT.handshake]);
      });

      it('keeps state SHE unchanged when an allowed heartbeat intervenes',
        function() {
          var t = createConnection(false);
          // a heartbeat is legal in every client state but must be ignored
          // before/during the handshake and must not move expect
          processBatch(t.c, record(CT.heartbeat,
            forge.util.hexToBytes('010003616263')));
          ASSERT.equal(t.c.expect, SHE);
          ASSERT.deepEqual(t.log.errors, []);

          // the valid ServerHello afterwards still parses SHE -> SCE
          var msg = handshake(HT.server_hello, validServerHelloBody());
          processBatch(t.c, record(CT.handshake, msg));
          ASSERT.equal(t.c.expect, SCE);
          ASSERT.deepEqual(t.log.errors, []);
        });

      it('parses multiple handshake messages packed into one record',
        function() {
          var t = createConnection(false);
          var serverHello = handshake(HT.server_hello, validServerHelloBody());
          // HelloRequest is accepted (and ignored) from SCE onwards
          var helloRequest = handshake(HT.hello_request, '');
          var packed = serverHello + helloRequest + helloRequest;

          processBatch(t.c, record(CT.handshake, packed));

          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.fail, false);
          // final state is still SCE; the HelloRequests caused no transition
          ASSERT.equal(t.c.expect, SCE);
          ASSERT.equal(t.c.input.length(), 0);
        });
    });

    // ======================================================================
    // 2. Cross-record fragmentation. Two distinct layering cases exist:
    //
    //  (a) RECORD-LAYER split: one TLS record's bytes arrive across several
    //      c.process() calls. The record header's declared length lets the
    //      engine buffer the fragment inside c.input until the whole record is
    //      present; this must reassemble for every cut, including cuts inside
    //      the 5-byte record header and the 4-byte handshake header.
    //
    //  (b) HANDSHAKE-LAYER split: a handshake message is spread across several
    //      complete TLS records. RFC 5246 6.2.1 permits this; the engine parks
    //      the first record in c.fragmented and appends subsequent same-type
    //      records. A captured defect (see the marked tests below) means the
    //      parked first record's bytes are discarded when it is cached, so this
    //      form cannot currently reassemble. The tests pin the safe, observable
    //      behavior: no throw, no busy loop, no illegal state advance.
    // ======================================================================
    describe('cross-record fragmentation', function() {
      var msg = handshake(HT.server_hello, validServerHelloBody());
      var fullRecord = record(CT.handshake, msg);

      it('(record layer) reassembles one record split at every byte offset',
        function() {
        // including cuts inside the record header (n < 5) and inside the
        // handshake header (5 <= n < 9)
          for(var cut = 1; cut < fullRecord.length; ++cut) {
            var t = createConnection(false);
            var r1 = processBatch(t.c, fullRecord.substr(0, cut));
            // a partial record reports a positive byte deficit, never fails
            ASSERT.ok(r1 > 0 || cut === fullRecord.length,
              'cut ' + cut + ' should report a deficit');
            ASSERT.equal(t.c.fail, false, 'cut ' + cut);
            var r2 = processBatch(t.c, fullRecord.substr(cut));
            ASSERT.equal(r2, 0, 'cut ' + cut);
            ASSERT.deepEqual(t.log.errors, [],
              'cut ' + cut + ' produced ' + t.log.errors);
            ASSERT.equal(t.c.expect, SCE,
              'cut ' + cut + ' must complete SHE -> SCE');
            ASSERT.equal(t.c.fragmented, null);
          }
        });

      it('(record layer) reassembles a record across three process() calls',
        function() {
          var t = createConnection(false);
          var third = Math.floor(fullRecord.length / 3);
          processBatch(t.c, fullRecord.substr(0, third));
          processBatch(t.c, fullRecord.substr(third, third));
          ASSERT.equal(t.c.expect, SHE);
          processBatch(t.c, fullRecord.substr(2 * third));
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.expect, SCE);
          ASSERT.equal(t.c.input.length(), 0);
        });

      it('(record layer) reassembles when delivered one byte at a time',
        function() {
          var t = createConnection(false);
          var rvals = processByteByByte(t.c, fullRecord);
          // the 5-byte record header deficit counts down 4,3,2,1 then the
          // 42-byte fragment deficit counts down to zero
          ASSERT.deepEqual(rvals.slice(0, 5), [4, 3, 2, 1, 42]);
          ASSERT.equal(rvals[rvals.length - 1], 0);
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.expect, SCE);
          ASSERT.equal(t.c.input.length(), 0);
        });

      // --- captured defect: handshake-layer fragment loss ---------------
      // Transition under test:
      //   SHE --handshake record (partial, length > bytes)--> parked
      //   parked --handshake continuation record--> stalls (first bytes lost)
      // handleHandshake() replaces the parked record's fragment with an empty
      // buffer when caching it, so continuation bytes append to an empty
      // fragment; the original type/length prefix can never be reconstructed.
      // Safety contract asserted here: the engine still returns promptly,
      // keeps SHE, does not throw, and does not mark the connection failed.
      it('DEFECT: handshake-layer split parks then stalls without advancing ' +
      'SHE (first fragment bytes are dropped)', function() {
        var t = createConnection(false);
        // first complete handshake record carries only part of the message
        var r1 = processBatch(t.c,
          record(CT.handshake, msg.substr(0, 10)));
        ASSERT.equal(r1, 0);
        ASSERT.equal(t.c.fragmented !== null, true);
        // the parked record's fragment was emptied: its 10 received bytes are
        // no longer present
        ASSERT.equal(t.c.fragmented.fragment.length(), 0);
        ASSERT.equal(t.c.expect, SHE);

        // every continuation offset keeps the engine parked in SHE
        for(var i = 10; i < msg.length; ++i) {
          var u = createConnection(false);
          processBatch(u.c, record(CT.handshake, msg.substr(0, 10)));
          processBatch(u.c, record(CT.handshake, msg.substr(i)));
          ASSERT.equal(u.c.fail, false, 'offset ' + i);
          ASSERT.deepEqual(u.log.errors, [], 'offset ' + i);
          ASSERT.equal(u.c.expect, SHE,
            'offset ' + i + ': illegal state advance');
        }
      });

      it('DEFECT: a one-byte-per-record handshake message never completes',
        function() {
          var t = createConnection(false);
          ASSERT.doesNotThrow(function() {
            for(var i = 0; i < msg.length; ++i) {
              processBatch(t.c, record(CT.handshake, msg.charAt(i)));
            }
          });
          // safe but stuck: still in SHE, no failure, no busy loop
          ASSERT.equal(t.c.fail, false);
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.expect, SHE);
        });

      it('recovers from a stalled park when a full valid message arrives as ' +
      'the continuation (SHE -> SCE)', function() {
      // Even with the fragment-loss defect, a continuation record that
      // itself satisfies the parked claim is dispatched as the message, so
      // a well-behaved peer retransmitting the full handshake message
      // recovers the handshake.
        var t = createConnection(false);
        processBatch(t.c, record(CT.handshake, msg.substr(0, 10))); // parks
        ASSERT.equal(t.c.expect, SHE);
        processBatch(t.c, record(CT.handshake, msg)); // full retransmission
        ASSERT.deepEqual(t.log.errors, []);
        ASSERT.equal(t.c.fail, false);
        ASSERT.equal(t.c.expect, SCE);
        ASSERT.equal(t.c.session.cipherSuite.name,
          'TLS_RSA_WITH_AES_128_CBC_SHA');
      });

      it('fails (no throw) when a parked fragment is continued by another ' +
      'content type: parked --alert--> fatal unexpected_message',
      function() {
        var t = createConnection(false);
        processBatch(t.c, record(CT.handshake, msg.substr(0, 6)));
        ASSERT.equal(t.c.fragmented !== null, true);

        // state transition under test: parked HS fragment + alert record
        processBatch(t.c, record(CT.alert,
          forge.util.hexToBytes('0228')));

        ASSERT.deepEqual(t.log.errors, ['Invalid fragmented record.']);
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.c.expect, SHE); // expect state is never advanced
        // a fatal unexpected_message alert (description 10) was sent
        ASSERT.equal(t.log.alerts.length, 1);
        ASSERT.equal(t.log.alerts[0].level, ALERT.Level.fatal);
        ASSERT.equal(t.log.alerts[0].description,
          ALERT.Description.unexpected_message);
      });

      [
        ['change_cipher_spec', CT.change_cipher_spec, '\x01'],
        ['application_data', CT.application_data, 'data'],
        ['heartbeat', CT.heartbeat, forge.util.hexToBytes('010000')]
      ].forEach(function(choice) {
        var name = choice[0];
        var type = choice[1];
        var frag = choice[2];
        it('fails on an interleaved ' + name + ' record mid-fragment',
          function() {
            var t = createConnection(false);
            processBatch(t.c, record(CT.handshake, msg.substr(0, 6)));
            ASSERT.doesNotThrow(function() {
              processBatch(t.c, record(type, frag));
            });
            ASSERT.deepEqual(t.log.errors, ['Invalid fragmented record.']);
            ASSERT.equal(t.c.fail, true);
            // once failed, further records are not dispatched (no new errors)
            var errorCount = t.log.errors.length;
            processBatch(t.c, record(type, frag));
            ASSERT.equal(t.log.errors.length, errorCount);
          });
      });
    });

    // ======================================================================
    // 3. Length field boundaries. Both the 16-bit record length and the 24-bit
    //    handshake length are attacker-controlled; assert exact boundary
    //    behavior and that oversized claims never trigger allocation or loops.
    // ======================================================================
    describe('length field boundaries', function() {
      var body = validServerHelloBody();

      it('accepts a handshake length that exactly equals its body', function() {
        var t = createConnection(false);
        var exact = handshakeWithLength(HT.server_hello, body.length, body);
        processBatch(t.c, record(CT.handshake, exact));
        ASSERT.deepEqual(t.log.errors, []);
        ASSERT.equal(t.c.expect, SCE);
      });

      it('rejects a handshake length one byte shorter than its body',
        function() {
          var t = createConnection(false);
          var shortLen = handshakeWithLength(
            HT.server_hello, body.length - 1, body);
          processBatch(t.c, record(CT.handshake, shortLen));
          // the 37-byte claimed message is below the 38-byte ServerHello
          // minimum, so parseHelloMessage rejects it as too short
          ASSERT.equal(t.log.errors.length, 1);
          ASSERT.ok(/too short/.test(t.log.errors[0]), t.log.errors[0]);
          ASSERT.equal(t.c.fail, true);
          ASSERT.equal(t.c.expect, SHE);
        });

      it('rejects an explicit zero-length ServerHello (boundary 0)',
        function() {
          var t = createConnection(false);
          processBatch(t.c, record(CT.handshake,
            handshakeWithLength(HT.server_hello, 0, '')));
          ASSERT.equal(t.log.errors.length, 1);
          ASSERT.ok(/too short/.test(t.log.errors[0]), t.log.errors[0]);
          ASSERT.equal(t.c.fail, true);
        });

      it('parks (does not allocate for) a 2^24-1 length claim with tiny data',
        function() {
        // record: handshake header claiming a 16 MiB message, one body byte
          var t = createConnection(false);
          var monster = handshakeWithLength(HT.server_hello, 0xffffff, 'x');
          var rval = processBatch(t.c, record(CT.handshake, monster));
          ASSERT.equal(rval, 0);
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.fail, false);
          // the message is parked; because parking drops the received bytes
          // the cached fragment is empty rather than 16 MiB -- nothing is
          // pre-allocated to the claimed length
          ASSERT.equal(t.c.fragmented !== null, true);
          ASSERT.equal(t.c.fragmented.fragment.length(), 0);
          ASSERT.equal(t.c.expect, SHE);
        });

      it('honors the 16-bit record length when the body is truncated',
        function() {
          var t = createConnection(false);
          var full = record(CT.handshake,
            handshake(HT.server_hello, body));
          // deliver everything except the final three fragment bytes
          var rval = processBatch(t.c, full.substr(0, full.length - 3));
          // process() reports exactly how many more bytes the record needs
          ASSERT.equal(rval, 3);
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.fail, false);
          // supplying the remainder completes the parse SHE -> SCE
          processBatch(t.c, full.substr(full.length - 3));
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.expect, SCE);
        });

      it('returns the exact byte deficit for a 65535-length record claim',
        function() {
          var t = createConnection(false);
          var b = forge.util.createBuffer();
          b.putByte(CT.handshake);
          b.putByte(3);
          b.putByte(1);
          b.putInt16(0xffff);
          b.putBytes(handshake(HT.server_hello, body).substr(0, 4));
          var rval = processBatch(t.c, b.getBytes());
          ASSERT.equal(rval, 0xffff - 4);
          ASSERT.equal(t.c.fail, false);
          ASSERT.equal(t.c.input.length(), 4);
        });

      it('keeps an over-long handshake claim parked across continuations ' +
      'without advancing SHE', function() {
        var t = createConnection(false);
        // claim two more bytes than the real body contains
        var lie = handshakeWithLength(
          HT.server_hello, body.length + 2, body.substr(0, 5));
        processBatch(t.c, record(CT.handshake, lie));
        ASSERT.equal(t.c.fragmented !== null, true);
        ASSERT.equal(t.c.expect, SHE);
        // continuation records cannot make up the lost first fragment, so the
        // engine must remain safely parked rather than parse garbage
        processBatch(t.c,
          record(CT.handshake, body.substr(5) + '\x00\x00'));
        ASSERT.equal(t.c.fail, false);
        ASSERT.deepEqual(t.log.errors, []);
        ASSERT.equal(t.c.expect, SHE);
      });
    });

    // ======================================================================
    // 4. Handshake type / content type switches. Each case pins a specific
    //    invalid edge in the ctTable/hsTable state tables.
    // ======================================================================
    describe('handshake type switching', function() {
      it('rejects a Certificate where SHE expects a ServerHello ' +
      '(hsTable[client][SHE][certificate] is empty)', function() {
        var t = createConnection(false);
        // transition under test: SHE --handshake(certificate)--> fatal
        processBatch(t.c, record(CT.handshake,
          handshake(HT.certificate, forge.util.hexToBytes('000000'))));
        ASSERT.deepEqual(t.log.errors,
          ['Unexpected message. Received TLS record out of order.']);
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.c.expect, SHE);
        ASSERT.equal(t.log.alerts[0].description,
          ALERT.Description.unexpected_message);
      });

      it('rejects an unknown handshake type (255) in SHE', function() {
        var t = createConnection(false);
        processBatch(t.c, record(CT.handshake,
          handshake(255, 'xx')));
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.c.expect, SHE);
        ASSERT.equal(t.log.alerts[0].description,
          ALERT.Description.unexpected_message);
      });

      it('rejects application_data in SHE (ctTable cell is empty)',
        function() {
          var t = createConnection(false);
          processBatch(t.c, record(CT.application_data, 'data'));
          ASSERT.equal(t.c.fail, true);
          ASSERT.equal(t.c.expect, SHE);
        });

      it('rejects change_cipher_spec in SHE (only legal in SCC)', function() {
        var t = createConnection(false);
        processBatch(t.c, record(CT.change_cipher_spec, '\x01'));
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.log.alerts[0].description,
          ALERT.Description.unexpected_message);
      });

      it('rejects an unknown content type 99 in SHE', function() {
        var t = createConnection(false);
        processBatch(t.c, record(99, 'xx'));
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.c.expect, SHE);
      });

      it('rejects a ServerHello where a server expects a ClientHello ' +
      '(hsTable[server][CHE][server_hello] is empty)', function() {
        var t = createConnection(true);
        processBatch(t.c, record(CT.handshake,
          handshake(HT.server_hello, validServerHelloBody())));
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.c.expect, CHE);
      });

      it('rejects a too-short ClientHello body on the server without ' +
      'advancing CHE', function() {
        var t = createConnection(true);
        var truncated = validClientHelloBody().substr(0, 37);
        processBatch(t.c, record(CT.handshake,
          handshake(HT.client_hello, truncated)));
        ASSERT.equal(t.log.errors.length, 1);
        ASSERT.ok(/ClientHello/.test(t.log.errors[0]), t.log.errors[0]);
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.c.expect, CHE);
      });

      it('advances SHE -> SCE on ServerHello, then rejects a replayed ' +
      'ServerHello (hsTable[client][SCE][server_hello] is empty)',
      function() {
        var t = createConnection(false);
        var msg = handshake(HT.server_hello, validServerHelloBody());
        processBatch(t.c, record(CT.handshake, msg));
        ASSERT.equal(t.c.expect, SCE);
        // transition under test: SCE --handshake(server_hello)--> fatal
        processBatch(t.c, record(CT.handshake, msg));
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.log.alerts[0].description,
          ALERT.Description.unexpected_message);
      });

      it('fails on an unknown type following a valid message in the same ' +
      'record without rolling back the good transition', function() {
        var t = createConnection(false);
        var combo = handshake(HT.server_hello, validServerHelloBody()) +
        handshake(255, 'xx');
        processBatch(t.c, record(CT.handshake, combo));
        // the good ServerHello already moved SHE -> SCE; the bad message then
        // fails fatally rather than silently resetting state
        ASSERT.equal(t.c.fail, true);
        ASSERT.equal(t.log.errors.length, 1);
      });
    });

    // ======================================================================
    // 5. Replayed fragments and messages. Reassembly is append-only; replays
    //    must either be absorbed deterministically or fail cleanly -- never
    //    corrupt state or loop.
    // ======================================================================
    describe('replayed fragments and messages', function() {
      var msg = handshake(HT.server_hello, validServerHelloBody());

      it('absorbs a replayed partial first record while staying parked in SHE',
        function() {
        // transition: SHE --partial HS--> parked --replayed partial HS-->
        // still parked (the replayed bytes cannot satisfy the claim)
          var t = createConnection(false);
          var head = msg.substr(0, 6); // 4-byte header + 2 body bytes
          processBatch(t.c, record(CT.handshake, head));
          processBatch(t.c, record(CT.handshake, head));
          ASSERT.doesNotThrow(function() {});
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.fail, false);
          ASSERT.equal(t.c.expect, SHE);
          ASSERT.equal(t.c.fragmented !== null, true);
        });

      it('treats a replayed full ServerHello as an out-of-order message',
        function() {
          var t = createConnection(false);
          var single = record(CT.handshake, msg);
          processBatch(t.c, single);
          ASSERT.equal(t.c.expect, SCE);
          // the second complete ServerHello cannot match any SCE handler
          processBatch(t.c, single);
          ASSERT.equal(t.c.fail, true);
          ASSERT.equal(t.log.errors[0],
            'Unexpected message. Received TLS record out of order.');
        });

      it('consumes many replayed continuation records without a busy loop ' +
      'or a state change', function() {
        var t = createConnection(false);
        // park a message, then feed the same one-byte continuation record
        // repeatedly; the engine returns promptly on every call
        var parked = handshakeWithLength(HT.server_hello, 38,
          validServerHelloBody().substr(0, 1));
        processBatch(t.c, record(CT.handshake, parked));
        ASSERT.doesNotThrow(function() {
          for(var i = 0; i < 50; ++i) {
            processBatch(t.c, record(CT.handshake, '\x00'));
          }
        });
        ASSERT.equal(t.c.fail, false);
        // the parked claim is never met by the dropped continuations
        ASSERT.equal(t.c.expect, SHE);
        ASSERT.equal(t.c.fragmented !== null, true);
      });

      it('stops dispatching after a fatal failure and buffers later input',
        function() {
        // once c.fail is set, _processRecord short-circuits: no further
        // handler runs, so no new errors are produced; undelivered bytes
        // still accumulate in c.input rather than being thrown away
          var t = createConnection(false);
          var bad = record(CT.application_data, 'data');
          processBatch(t.c, bad);
          ASSERT.equal(t.c.fail, true);
          var errorCount = t.log.errors.length;
          processBatch(t.c, bad);
          processBatch(t.c, bad);
          ASSERT.equal(t.log.errors.length, errorCount);
          // the two later 9-byte records sit unprocessed in the input buffer
          ASSERT.equal(t.c.input.length(), bad.length * 2);
          // a reset clears the buffered input and the fail flag
          t.c.reset();
          ASSERT.equal(t.c.input.length(), 0);
          ASSERT.equal(t.c.fail, false);
          ASSERT.equal(t.c.expect, SHE);
        });
    });

    // ======================================================================
    // 6. Truncated input at every layer: record header, handshake header,
    //    message body, and byte-at-a-time delivery. Truncation means "wait
    //    for more bytes", never a throw or a state transition.
    // ======================================================================
    describe('truncated input', function() {
      var msg = handshake(HT.server_hello, validServerHelloBody());
      var full = record(CT.handshake, msg);

      it('reports the precise deficit for partial record headers', function() {
        var expected = [5, 4, 3, 2, 1];
        for(var n = 0; n < 5; ++n) {
          var t = createConnection(false);
          var rval = processBatch(t.c, full.substr(0, n));
          ASSERT.equal(rval, expected[n], 'header prefix length ' + n);
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.fail, false);
          ASSERT.equal(t.c.input.length(), n);
        }
      });

      it('buffers a partial fragment and completes when the tail arrives ' +
      '(record-layer cut at every position)', function() {
        for(var cut = 5; cut < full.length; cut += 4) {
          var t = createConnection(false);
          processBatch(t.c, full.substr(0, cut));
          ASSERT.deepEqual(t.log.errors, [], 'cut ' + cut);
          ASSERT.equal(t.c.fail, false);
          processBatch(t.c, full.substr(cut));
          ASSERT.equal(t.c.expect, SCE, 'cut ' + cut);
        }
      });

      it('delivers one byte at a time with a monotonically resolved deficit',
        function() {
          var t = createConnection(false);
          var rvals = processByteByByte(t.c, full);
          // while the 5-byte header arrives the deficit counts down; then the
          // 42-byte fragment deficit counts down to zero
          ASSERT.deepEqual(rvals.slice(0, 5), [4, 3, 2, 1, 42]);
          ASSERT.equal(rvals[rvals.length - 1], 0);
          // every intermediate deficit is non-negative (no over-read)
          rvals.forEach(function(v) {
            ASSERT.ok(v >= 0);
          });
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.expect, SCE);
          ASSERT.equal(t.c.input.length(), 0);
        });

      it('treats an empty handshake record as a parked empty fragment',
        function() {
        // documented edge behavior: with zero fragment bytes the handshake
        // type/length read yields NaN, which compares as a length overrun,
        // so the record is parked rather than dispatched
          var t = createConnection(false);
          var rval = processBatch(t.c, record(CT.handshake, ''));
          ASSERT.equal(rval, 0);
          ASSERT.doesNotThrow(function() {
          // many empty records must be consumed without a busy loop
            processBatch(t.c, repeat(record(CT.handshake, ''), 1000));
          });
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.fail, false);
          ASSERT.equal(t.c.expect, SHE);
        });

      it('stays safe when the 4-byte handshake header spans two records ' +
      '(illegal framing; must not throw or advance SHE)', function() {
      // RFC 5246 does not permit splitting the handshake header across
      // records. forge reads type+length from the first record regardless,
      // so such framing cannot reassemble; assert the safety contract
      // instead of a successful parse: no throw, no state advance, no busy
      // loop, and a clean fatal error once the malformed message resolves.
        var t = createConnection(false);
        ASSERT.doesNotThrow(function() {
        // first record holds only 3 of the 4 handshake header bytes
          processBatch(t.c, record(CT.handshake, msg.substr(0, 3)));
          // second record carries the remainder
          processBatch(t.c, record(CT.handshake, msg.substr(3)));
        });
        ASSERT.equal(t.c.expect, SHE, 'expect state must never advance');
        // feed continuation bytes; the engine either stays parked or fails
        // fatally, but it always returns promptly
        var rval = processBatch(t.c,
          record(CT.handshake, forge.util.createBuffer()
            .fillWithByte(0, 128).getBytes()));
        ASSERT.equal(typeof rval, 'number');
        if(t.c.fail) {
          ASSERT.ok(t.log.errors.length >= 1);
          ASSERT.equal(t.log.alerts[0].level, ALERT.Level.fatal);
        } else {
          ASSERT.ok(t.c.fragmented !== null);
        }
      });

      it('handles process("") and process() as no-ops', function() {
        var t = createConnection(false);
        ASSERT.equal(processBatch(t.c, ''), 5);
        ASSERT.equal(processBatch(t.c), 5);
        ASSERT.equal(processBatch(t.c), 5);
        ASSERT.deepEqual(t.log.errors, []);
        ASSERT.equal(t.c.expect, SHE);
      });

      it('re-parses after a close_notify followed by a fresh handshake()',
        function() {
          var t = createConnection(false);
          // a warning close_notify closes the client but is not a failure
          processBatch(t.c, record(CT.alert,
            forge.util.hexToBytes('0100')));
          ASSERT.equal(t.log.closed, 1);
          ASSERT.equal(t.c.fail, false);
          // reopen the engine; a ServerHello on the new session parses
          t.c.handshake();
          processBatch(t.c, record(CT.handshake,
            handshake(HT.server_hello, validServerHelloBody())));
          ASSERT.deepEqual(t.log.errors, []);
          ASSERT.equal(t.c.expect, SCE);
        });
    });

    // ======================================================================
    // 7. Deterministic mutation testing. A fixed corpus of legal records is
    //    mutated byte-by-byte (single-byte flips, length-field sweeps, type
    //    sweeps, truncations and replays). For every mutant the same safety
    //    oracle applies: no throw, bounded processing time, and the expect
    //    state changes only when the mutant is still a legal transition.
    //    Each case name encodes the exact mutation and the state edge it
    //    probes, so a failure sample identifies the transition directly.
    // ======================================================================
    describe('mutation testing', function() {
      var serverHello = handshake(HT.server_hello, validServerHelloBody());

      // safety oracle: run a full mutant byte stream against a fresh
      // connection and assert the engine terminates cleanly
      function assertMutantSafe(label, bytes, server) {
        var t = createConnection(!!server);
        var startExpect = t.c.expect;
        ASSERT.doesNotThrow(function() {
          processBatch(t.c, bytes);
        }, label);
        // invariant: a failed engine never moves its expect state past where
        // the valid prefix legitimately took it, and every failure emits a
        // fatal alert
        if(t.c.fail) {
          ASSERT.ok(t.log.alerts.length >= 1,
            label + ': fatal failure without alert');
          ASSERT.equal(t.log.alerts[0].level, ALERT.Level.fatal, label);
        }
        ASSERT.ok(t.c.expect >= startExpect,
          label + ': expect state moved backwards');
        return t;
      }

      it('survives a content-type sweep over every reserved/unknown type',
        function() {
        // every type byte except the five defined ContentTypes; each must
        // map to handleUnexpected rather than a crash
          for(var type = 0; type <= 255; ++type) {
            if(type === CT.change_cipher_spec || type === CT.alert ||
            type === CT.handshake || type === CT.application_data ||
            type === CT.heartbeat) {
              continue;
            }
            var t = assertMutantSafe(
              'content-type ' + type + ' in SHE',
              record(type, serverHello));
            ASSERT.equal(t.c.fail, true, 'type ' + type);
            ASSERT.equal(t.c.expect, SHE);
          }
        });

      it('survives a handshake-type sweep in SHE', function() {
        for(var type = 0; type <= 255; ++type) {
          var t = assertMutantSafe('handshake-type ' + type + ' in SHE',
            record(CT.handshake,
              handshake(type, validServerHelloBody())));
          if(type === HT.server_hello) {
          // the one legal type in SHE must still parse SHE -> SCE
            ASSERT.equal(t.c.fail, false);
            ASSERT.equal(t.c.expect, SCE);
          } else {
          // every other type (including hello_request, which is only legal
          // from SCE onwards) is an unexpected message in SHE: fatal, with
          // an alert emitted and the expect state unchanged
            ASSERT.equal(t.c.fail, true, 'type ' + type);
            ASSERT.ok(t.log.alerts.length >= 1,
              'type ' + type + ' emitted no alert');
            ASSERT.equal(t.log.alerts[0].level, ALERT.Level.fatal,
              'type ' + type);
            ASSERT.equal(t.c.expect, SHE);
          }
        }
      });

      it('survives a handshake-type sweep in server CHE state', function() {
        for(var type = 0; type <= 255; ++type) {
          var t = assertMutantSafe('server handshake-type ' + type,
            record(CT.handshake,
              handshake(type, validClientHelloBody())), true);
          if(type === HT.client_hello) {
            ASSERT.equal(t.c.fail, false);
            ASSERT.equal(t.c.expect, CKE);
          } else {
            ASSERT.equal(t.c.fail, true, 'type ' + type);
            ASSERT.equal(t.c.expect, CHE);
          }
        }
      });

      it('survives single-byte XOR flips of every length-field byte',
        function() {
          var masks = [0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff];
          for(var pos = 1; pos <= 3; ++pos) {
            masks.forEach(function(mask) {
              var mutated = serverHello.split('');
              mutated[pos] = String.fromCharCode(
                mutated[pos].charCodeAt(0) ^ mask);
              var label = 'length byte ' + pos + ' XOR 0x' +
              mask.toString(16);
              var t = assertMutantSafe(label,
                record(CT.handshake, mutated.join('')));
              // no mutant may throw or advance; it either parks awaiting
              // continuation or fails with a recorded fatal alert
              ASSERT.ok(t.c.fail || t.c.fragmented !== null, label);
              ASSERT.equal(t.c.expect, SHE, label);
            });
          }
        });

      it('survives truncation at every single byte position', function() {
        var bytes = record(CT.handshake, serverHello);
        for(var n = 0; n < bytes.length; ++n) {
          var label = 'truncation after ' + n + ' bytes';
          var t = assertMutantSafe(label, bytes.substr(0, n));
          // a truncated stream never fails on its own and never advances
          ASSERT.equal(t.c.fail, false, label);
          ASSERT.equal(t.c.expect, SHE, label);
        }
      });

      it('survives record-length field sweeps (0, 1, mid, max)', function() {
        [0, 1, 0x7fff, 0xffff].forEach(function(len) {
          var b = forge.util.createBuffer();
          b.putByte(CT.handshake);
          b.putByte(3);
          b.putByte(1);
          b.putInt16(len);
          b.putBytes(serverHello);
          var wire = b.getBytes();
          var label = 'record length claim ' + len;
          var t = assertMutantSafe(label, wire);
          ASSERT.equal(t.c.expect, SHE, label);
          if(len <= serverHello.length + 5) {
          // small claims produce complete, invalid records -> fatal alert
            ASSERT.equal(t.c.fail, true, label);
          } else {
          // large claims are simply awaited: no allocation, no failure
            ASSERT.equal(t.c.fail, false, label);
            ASSERT.ok(t.c.input.length() <= wire.length, label);
          }
        });
      });

      it('survives replayed and doubled record streams', function() {
        var single = record(CT.handshake, serverHello);
        // the same valid record repeated: first advances, second is an
        // unexpected message in SCE -- fatal but controlled
        var t = assertMutantSafe('replayed valid ServerHello',
          single + single);
        ASSERT.equal(t.c.fail, true);
        // a bad record repeated: the first copy fails, the rest are not
        // dispatched, so exactly one error is produced
        var bad = record(CT.application_data, 'data');
        var t2 = assertMutantSafe('replayed application_data x20',
          repeat(bad, 20));
        ASSERT.equal(t2.c.fail, true);
        ASSERT.equal(t2.log.errors.length, 1);
      });

      it('survives handshake-layer fragmentation of each mutant across two ' +
      'records, never advancing SHE illegally', function() {
      // split every mutated handshake fragment across two complete records;
      // given the fragment-loss defect the message cannot reassemble, so the
      // invariant is: safe termination, no throw, SHE retained
        for(var type = 0; type <= 255; type += 17) {
          var fragment = handshake(type, validServerHelloBody());
          var cut = 4 + (type % (fragment.length - 4));
          var bytes = record(CT.handshake, fragment.substr(0, cut)) +
          record(CT.handshake, fragment.substr(cut));
          var t = assertMutantSafe(
            'split mutant handshake-type ' + type + ' at ' + cut, bytes);
          ASSERT.equal(t.c.expect, SHE, 'type ' + type);
          ASSERT.equal(t.c.input.length(), 0);
        }
      });

      it('survives a mixed-batch stress stream without a busy loop',
        function() {
        // deterministic jumble: an allowed heartbeat, a parked fragment, a
        // wrong-type continuation, a fatal alert, then ignored tail records
          var stream =
          record(CT.heartbeat, forge.util.hexToBytes('010000')) +
          record(CT.handshake, serverHello.substr(0, 6)) +
          record(CT.heartbeat, forge.util.hexToBytes('010000')) +
          record(CT.alert, forge.util.hexToBytes('0250')) +
          record(CT.handshake, serverHello) +
          repeat(record(CT.application_data, 'x'), 50);
          var t = createConnection(false);
          ASSERT.doesNotThrow(function() {
            processBatch(t.c, stream);
          });
          // the heartbeat while a fragment is parked is a fatal
          // invalid-fragmented-record condition; everything after is ignored
          ASSERT.equal(t.c.fail, true);
          ASSERT.ok(t.log.alerts.length >= 1);
          ASSERT.equal(t.log.alerts[0].level, ALERT.Level.fatal);
          ASSERT.equal(t.log.alerts[0].description,
            ALERT.Description.unexpected_message);
          // the queued fatal alert was actually written for the peer
          ASSERT.ok(t.log.sent.length > 0);
        });
    });
  });

})();
