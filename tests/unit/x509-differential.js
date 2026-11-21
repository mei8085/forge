/*
 * Differential integration tests for the X.509 certificate parsing path:
 * node-forge (lib/x509.js) vs. the Node.js built-in certificate parser
 * (crypto.X509Certificate, backed by OpenSSL).
 *
 * Coverage: name constraints, extension criticality, unknown fields,
 * non-canonical DER lengths, chain ordering, and invalid signatures.
 *
 * All test material is generated locally at runtime (keys and certificates
 * are created with forge itself); no network access is required.
 *
 * Every run records the structural/behavioral differences between the two
 * parsers and prints a report (see the `after` hook). Each difference is
 * given one of the following classifications:
 *
 *   forge-security-policy:
 *     A deliberate security decision of this library (RFC 5280 path
 *     validation behavior: name-constraint enforcement, rejection of
 *     unsupported critical extensions, ordered-chain API contract).
 *     Node's built-in parser performs no path validation at all, so these
 *     differences MUST NOT be misread as forge interop failures.
 *
 *   node-parser-strictness:
 *     Node/OpenSSL rejects input that forge accepts (e.g. non-minimal DER
 *     length octets). A strictness property of the other parser, not a
 *     forge defect.
 *
 *   representation:
 *     Same semantics, different data shape (DN strings vs. attribute
 *     arrays, thrown error objects vs. boolean return values, ...).
 *
 *   node-api-surface:
 *     Node's built-in parser simply does not expose the field (no generic
 *     extension API, no nameConstraints, no keyUsage bits, no chain
 *     validation entry point).
 *
 * The EXPECTED_DIFFS registry below is the authoritative, in-code record of
 * every known difference. Each test asserts that the observed differences
 * match the registry exactly: an unregistered difference fails the suite
 * (potential interop regression), and a registered difference that is no
 * longer observed also fails (stale documentation). Failure output names
 * the test case, the certificate field, and the parse/verify stage.
 */
var ASSERT = require('assert');
var ASN1 = require('../../lib/asn1');
var MD = require('../../lib/md.all');
var PEM = require('../../lib/pem');
var PKI = require('../../lib/pki');
var UTIL = require('../../lib/util');

// Node's built-in parser; unavailable in browsers (karma) where the
// 'crypto' module is shimmed to an empty object -- the suite skips there.
var CRYPTO = null;
try {
  CRYPTO = require('crypto');
} catch(e) {
  CRYPTO = null;
}
var HAS_NODE_X509 = !!(CRYPTO && CRYPTO.X509Certificate);

(function() {

  if(!HAS_NODE_X509) {
    describe('x509-differential', function() {
      it.skip('requires Node.js crypto.X509Certificate (>= 15.6)');
    });
    return;
  }

  // ---------------------------------------------------------------------------
  // difference registry (the "documentation" these tests enforce)
  // ---------------------------------------------------------------------------

  var CLASSIFICATION = {
    FORGE_SECURITY_POLICY: 'forge-security-policy',
    NODE_PARSER_STRICTNESS: 'node-parser-strictness',
    REPRESENTATION: 'representation',
    NODE_API_SURFACE: 'node-api-surface'
  };

  var EXPECTED_DIFFS = [
  // baseline-leaf: structural representation differences only; every
  // normalized value must be identical across both parsers.
    {caseId: 'baseline-leaf', stage: 'field-compare', field: 'subject',
      classification: CLASSIFICATION.REPRESENTATION,
      note: 'forge: attributes[] w/ OID, value, valueTagClass; ' +
      'node: RFC2253-style multi-line string'},
    {caseId: 'baseline-leaf', stage: 'field-compare', field: 'serialNumber',
      classification: CLASSIFICATION.REPRESENTATION,
      note: 'forge: lowercase hex; node: uppercase hex'},
    {caseId: 'baseline-leaf', stage: 'field-compare', field: 'validity',
      classification: CLASSIFICATION.REPRESENTATION,
      note: 'forge: Date objects; node: GMT date strings'},
    {caseId: 'baseline-leaf', stage: 'field-compare',
      field: 'extensions.keyUsage',
      classification: CLASSIFICATION.NODE_API_SURFACE,
      note: 'node does not expose keyUsage bits; its "keyUsage" property ' +
      'is actually the extKeyUsage OID list'},
    {caseId: 'baseline-leaf', stage: 'field-compare',
      field: 'extensions.generic',
      classification: CLASSIFICATION.NODE_API_SURFACE,
      note: 'node exposes no generic extension iteration API'},

    // name-constraints
    {caseId: 'name-constraints', stage: 'extension-parse',
      field: 'extensions.nameConstraints',
      classification: CLASSIFICATION.NODE_API_SURFACE,
      note: 'forge parses permittedSubtrees/excludedSubtrees; node has no ' +
      'API for this extension'},
    {caseId: 'name-constraints', stage: 'chain-verify',
      field: 'chain.excluded-subtree',
      classification: CLASSIFICATION.FORGE_SECURITY_POLICY,
      note: 'forge rejects a leaf whose SAN dNSName falls inside an ' +
      'excludedSubtree; node performs no path validation and its ' +
      'per-link signature check still passes'},

    // extension-criticality
    {caseId: 'extension-criticality', stage: 'chain-verify',
      field: 'chain.unknown-critical-extension',
      classification: CLASSIFICATION.FORGE_SECURITY_POLICY,
      note: 'forge rejects certificates with unsupported critical ' +
      'extensions (RFC 5280 6.1); node parses and link-verifies them'},
    {caseId: 'extension-criticality', stage: 'extension-parse',
      field: 'extensions.unknown-non-critical',
      classification: CLASSIFICATION.NODE_API_SURFACE,
      note: 'forge preserves the raw extnValue of unknown non-critical ' +
      'extensions; node silently drops them'},

    // unknown-fields
    {caseId: 'unknown-fields', stage: 'field-compare',
      field: 'subject.unknown-attribute',
      classification: CLASSIFICATION.REPRESENTATION,
      note: 'forge keeps {type: oid, value, valueTagClass}; node renders ' +
      'the dotted OID as the attribute key in the DN string'},

    // non-canonical-length
    {caseId: 'non-canonical-length', stage: 'node-parse',
      field: 'der.length-encoding',
      classification: CLASSIFICATION.NODE_PARSER_STRICTNESS,
      note: 'node/openssl rejects non-minimal long-form DER length octets; ' +
      'forge accepts them and normalizes on re-encode'},

    // chain-order
    {caseId: 'chain-order', stage: 'chain-verify',
      field: 'chain.ordering',
      classification: CLASSIFICATION.FORGE_SECURITY_POLICY,
      note: 'forge requires the chain leaf-first per RFC 5280 and rejects ' +
      'a reversed chain; node has no chain API and per-link verification ' +
      'is order-independent'},

    // invalid-signature
    {caseId: 'invalid-signature', stage: 'link-verify',
      field: 'verify.failure-surface',
      classification: CLASSIFICATION.REPRESENTATION,
      note: 'forge reports verification failure by throwing an error ' +
      'object with a certificateError code; node returns boolean false'}
  ];

  // observed differences, reset per test case
  var OBSERVED = [];
  // full run log, printed by the after() hook
  var RUN_LOG = [];

  function recordDiff(rec) {
    OBSERVED.push(rec);
    RUN_LOG.push(rec);
  }

  function diffsFor(caseId, list) {
    return list.filter(function(d) {
      return d.caseId === caseId;
    });
  }

  function diffKey(d) {
    return d.stage + '|' + d.field + '|' + d.classification;
  }

  function formatDiff(d) {
    return 'stage=' + d.stage + ' field=' + d.field +
    ' class=' + d.classification +
    (d.forge !== undefined ? ' forge=' + d.forge : '') +
    (d.node !== undefined ? ' node=' + d.node : '') +
    (d.note ? ' (' + d.note + ')' : '');
  }

  /*
 * Asserts that the differences observed during the current case match the
 * EXPECTED_DIFFS registry exactly. Failure output locates the certificate
 * field and the parse/verify stage.
 */
  function assertDiffsCovered(caseId) {
    var observed = diffsFor(caseId, OBSERVED);
    var expected = diffsFor(caseId, EXPECTED_DIFFS);
    var expectedKeys = {};
    expected.forEach(function(d) {
      expectedKeys[diffKey(d)] = d;
    });
    var observedKeys = {};
    observed.forEach(function(d) {
      observedKeys[diffKey(d)] = d;
    });
    var unexpected = observed.filter(function(d) {
      return !(diffKey(d) in expectedKeys);
    });
    var missing = expected.filter(function(d) {
      return !(diffKey(d) in observedKeys);
    });
    var problems = [];
    unexpected.forEach(function(d) {
      problems.push('UNREGISTERED difference (possible interop regression;' +
      ' if intentional, document it in EXPECTED_DIFFS): ' + formatDiff(d));
    });
    missing.forEach(function(d) {
      problems.push('REGISTERED difference no longer observed (stale ' +
      'documentation; update EXPECTED_DIFFS): ' + formatDiff(d));
    });
    ASSERT.strictEqual(problems.length, 0,
      '[x509-diff] case=' + caseId + ' difference-registry mismatch:\n  ' +
    problems.join('\n  '));
  }

  // located assertion failure: names case, stage, and certificate field
  function failLocated(caseId, stage, field, message) {
    ASSERT.fail('[x509-diff] case=' + caseId + ' stage=' + stage +
    ' field=' + field + ': ' + message);
  }

  // ---------------------------------------------------------------------------
  // local test-material generation (no network, nothing external)
  // ---------------------------------------------------------------------------

  var FIXTURES = null;

  function makeCert(options) {
    var cert = PKI.createCertificate();
    cert.publicKey = options.publicKey;
    cert.serialNumber = options.serialNumber;
    cert.validity.notBefore = new Date('2020-01-01T00:00:00Z');
    cert.validity.notAfter = new Date('2030-01-01T00:00:00Z');
    cert.setSubject(options.subject);
    cert.setIssuer(options.issuer);
    if(options.extensions) {
      cert.setExtensions(options.extensions);
    }
    cert.sign(options.signingKey, MD.sha256.create());
    // round-trip through PEM so all certs enter verification in the same
    // (fully parsed) shape a peer would present them in
    return PKI.certificateFromPem(PKI.certificateToPem(cert));
  }

  function buildFixtures() {
    var caKeys = PKI.rsa.generateKeyPair({bits: 1024});
    var leafKeys = PKI.rsa.generateKeyPair({bits: 1024});

    var caSubject = [
      {name: 'commonName', value: 'Forge Diff Test CA'},
      {name: 'organizationName', value: 'Forge Differential Tests'}
    ];

    // nameConstraints extension value, built as raw ASN.1 because forge has
    // no encoder for it (parse-only support):
    //   NameConstraints ::= SEQUENCE {
    //     permittedSubtrees [0] GeneralSubtrees OPTIONAL,
    //     excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
    var nameConstraintsValue = ASN1.create(
      ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, [
        ASN1.create(ASN1.Class.CONTEXT_SPECIFIC, 0, true, [
          ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, [
          // GeneralSubtree: base = dNSName '.example.com'
            ASN1.create(ASN1.Class.CONTEXT_SPECIFIC, 2, false, '.example.com')
          ])
        ]),
        ASN1.create(ASN1.Class.CONTEXT_SPECIFIC, 1, true, [
          ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, [
          // GeneralSubtree: base = dNSName 'bad.example.com'
            ASN1.create(ASN1.Class.CONTEXT_SPECIFIC, 2, false,
              'bad.example.com')
          ])
        ])
      ]);

    var ca = makeCert({
      publicKey: caKeys.publicKey,
      serialNumber: '01',
      subject: caSubject,
      issuer: caSubject,
      extensions: [
        {name: 'basicConstraints', critical: true, cA: true},
        {name: 'keyUsage', critical: true, keyCertSign: true, cRLSign: true},
        {
          name: 'nameConstraints',
          id: '2.5.29.30',
          critical: true,
          value: nameConstraintsValue
        }
      ],
      signingKey: caKeys.privateKey
    });

    function makeLeaf(cn, san, serialNumber, extraExtensions) {
      var extensions = [
        {name: 'basicConstraints', critical: true, cA: false},
        {
          name: 'keyUsage',
          critical: true,
          digitalSignature: true,
          keyEncipherment: true
        },
        {name: 'extKeyUsage', serverAuth: true}
      ];
      if(san) {
        extensions.push({
          name: 'subjectAltName',
          altNames: [{type: 2, value: san}, {type: 7, ip: '10.0.0.1'}]
        });
      }
      if(extraExtensions) {
        extensions = extensions.concat(extraExtensions);
      }
      return makeCert({
        publicKey: leafKeys.publicKey,
        serialNumber: serialNumber,
        subject: [{name: 'commonName', value: cn}],
        issuer: ca.subject.attributes,
        extensions: extensions,
        signingKey: caKeys.privateKey
      });
    }

    var leaf = makeLeaf('leaf.example.com', 'leaf.example.com', '02');
    var leafExcluded =
    makeLeaf('x.bad.example.com', 'x.bad.example.com', '03');
    var leafUnknownCritical = makeLeaf('uc.example.com', 'uc.example.com', '04', [{
      id: '1.2.3.4.5.6',
      critical: true,
      value: ASN1.create(
        ASN1.Class.UNIVERSAL, ASN1.Type.OCTETSTRING, false, 'opaque-blob')
    }]);
    var leafUnknownNonCritical =
    makeLeaf('unc.example.com', 'unc.example.com', '05', [{
      id: '1.2.3.4.5.6',
      critical: false,
      value: ASN1.create(
        ASN1.Class.UNIVERSAL, ASN1.Type.OCTETSTRING, false, 'opaque-blob')
    }]);
    var leafUnknownRdn = makeCert({
      publicKey: leafKeys.publicKey,
      serialNumber: '06',
      subject: [
        {name: 'commonName', value: 'rdn.example.com'},
        {type: '1.2.3.4', value: 'mystery-attribute'}
      ],
      issuer: ca.subject.attributes,
      extensions: [{name: 'basicConstraints', critical: true, cA: false}],
      signingKey: caKeys.privateKey
    });

    return {
      caKeys: caKeys,
      leafKeys: leafKeys,
      ca: ca,
      caPem: PKI.certificateToPem(ca),
      leaf: leaf,
      leafPem: PKI.certificateToPem(leaf),
      leafExcluded: leafExcluded,
      leafUnknownCritical: leafUnknownCritical,
      leafUnknownNonCritical: leafUnknownNonCritical,
      leafUnknownRdn: leafUnknownRdn
    };
  }

  // ---------------------------------------------------------------------------
  // staged parsers: every stage is named so failures can be located
  // ---------------------------------------------------------------------------

  function forgeParsePem(pem, caseId) {
    var der;
    try {
      der = PEM.decode(pem)[0].body;
    } catch(e) {
      failLocated(caseId, 'pem-decode', '-',
        'forge PEM decode failed: ' + e.message);
    }
    return forgeParseDer(der, caseId);
  }

  function forgeParseDer(der, caseId) {
    var obj;
    try {
      obj = ASN1.fromDer(der);
    } catch(e) {
      failLocated(caseId, 'asn1-der-parse', '-',
        'forge ASN.1/DER parse failed: ' + e.message);
    }
    try {
      return PKI.certificateFromAsn1(obj);
    } catch(e) {
      failLocated(caseId, 'cert-from-asn1',
        'tbsCertificate/extensions', 'forge certificate decode failed: ' +
      e.message);
    }
    return null;
  }

  function nodeParse(input, caseId) {
    try {
      return new CRYPTO.X509Certificate(input);
    } catch(e) {
      failLocated(caseId, 'node-parse', '-',
        'node X509Certificate parse failed: ' + e.message);
    }
    return null;
  }

  function forgeChainVerify(chain) {
    var store = PKI.createCaStore([FIXTURES.ca]);
    try {
      PKI.verifyCertificateChain(store, chain);
      return {ok: true};
    } catch(e) {
      return {
        ok: false,
        message: e.message,
        code: e.error
      };
    }
  }

  function nodeLinkVerify(x509, publicKeyPem) {
    return x509.verify(CRYPTO.createPublicKey(publicKeyPem));
  }

  // ---------------------------------------------------------------------------
  // normalization: map both parse results onto one comparable shape
  // ---------------------------------------------------------------------------

  function forgeDn(attrs) {
    return attrs.map(function(a) {
      return (a.shortName || a.type) + '=' + a.value;
    }).join('\n');
  }

  function forgeSan(cert) {
    var ext = cert.getExtension('subjectAltName');
    if(!ext) {
      return undefined;
    }
    return ext.altNames.map(function(a) {
      if(a.type === 2) {
        return 'DNS:' + a.value;
      }
      if(a.type === 7) {
        return 'IP Address:' + a.ip;
      }
      if(a.type === 1) {
        return 'email:' + a.value;
      }
      if(a.type === 6) {
        return 'URI:' + a.value;
      }
      return 'type' + a.type + ':' + a.value;
    }).join(', ');
  }

  function forgeEku(cert) {
    var ext = cert.getExtension('extKeyUsage');
    if(!ext) {
      return undefined;
    }
    var oids = [];
    for(var key in ext) {
      if(ext[key] === true && key in PKI.oids) {
        oids.push(PKI.oids[key]);
      }
    }
    return oids.sort();
  }

  function normalizeSerial(hex) {
    var s = hex.toUpperCase().replace(/^0+/, '');
    return s === '' ? '0' : s;
  }

  function forgeFingerprint256(cert) {
    var md = MD.sha256.create();
    md.update(ASN1.toDer(PKI.certificateToAsn1(cert)).getBytes());
    return md.digest().toHex().toUpperCase();
  }

  function forgeSpkiDer(cert) {
    return ASN1.toDer(PKI.publicKeyToAsn1(cert.publicKey)).getBytes();
  }

  function normalizeForge(cert) {
    return {
      subject: forgeDn(cert.subject.attributes),
      issuer: forgeDn(cert.issuer.attributes),
      serialNumber: normalizeSerial(cert.serialNumber),
      notBefore: cert.validity.notBefore.getTime(),
      notAfter: cert.validity.notAfter.getTime(),
      fingerprint256: forgeFingerprint256(cert),
      spki: forgeSpkiDer(cert),
      subjectAltName: forgeSan(cert),
      extKeyUsage: forgeEku(cert),
      ca: !!(cert.getExtension('basicConstraints') || {}).cA
    };
  }

  function normalizeNode(x) {
    return {
      subject: x.subject,
      issuer: x.issuer,
      serialNumber: normalizeSerial(x.serialNumber),
      notBefore: Date.parse(x.validFrom),
      notAfter: Date.parse(x.validTo),
      fingerprint256: x.fingerprint256.replace(/:/g, ''),
      spki: UTIL.binary.raw.encode(
        x.publicKey.export({format: 'der', type: 'spki'})),
      subjectAltName: x.subjectAltName,
      // node's "keyUsage" property is the extKeyUsage OID list
      extKeyUsage: x.keyUsage ? x.keyUsage.slice().sort() : undefined,
      ca: x.ca
    };
  }

  var NORMALIZED_FIELDS = [
    'subject', 'issuer', 'serialNumber', 'notBefore', 'notAfter',
    'fingerprint256', 'spki', 'subjectAltName', 'extKeyUsage', 'ca'
  ];

  /*
 * Field-by-field comparison of the normalized parse results. Any mismatch
 * is an unregistered (and hence failing) difference located at the field.
 */
  function assertNormalizedEqual(caseId, forgeCert, nodeX509) {
    var f = normalizeForge(forgeCert);
    var n = normalizeNode(nodeX509);
    NORMALIZED_FIELDS.forEach(function(field) {
      var fv = f[field];
      var nv = n[field];
      var equal;
      if(field === 'spki') {
        equal = fv === nv;
      } else {
        try {
          ASSERT.deepStrictEqual(fv, nv);
          equal = true;
        } catch(e) {
          equal = false;
        }
      }
      if(!equal) {
        failLocated(caseId, 'field-compare', field,
          'normalized parse results differ: forge=' +
        JSON.stringify(fv) + ' node=' + JSON.stringify(nv));
      }
    });
  }

  // ---------------------------------------------------------------------------
  // DER length re-encoder: emits long-form length octets everywhere, leaving
  // all tag/content bytes untouched (produces non-canonical, non-minimal DER)
  // ---------------------------------------------------------------------------

  function longFormLength(len) {
    var tmp = [];
    var l = len;
    do {
      tmp.unshift(l & 0xff);
      l = Math.floor(l / 256);
    } while(l > 0);
    return String.fromCharCode(0x80 | tmp.length) +
    String.fromCharCode.apply(null, tmp);
  }

  function reencodeLongForm(bytes, start, end) {
    var out = '';
    var pos = start;
    while(pos < end) {
      var tag = bytes.charCodeAt(pos);
      pos++;
      ASSERT.ok((tag & 0x1f) !== 0x1f, 'multi-byte tags not supported');
      var b2 = bytes.charCodeAt(pos);
      pos++;
      var len;
      if(b2 < 0x80) {
        len = b2;
      } else {
        var n = b2 & 0x7f;
        len = 0;
        for(var i = 0; i < n; ++i) {
          len = len * 256 + bytes.charCodeAt(pos);
          pos++;
        }
      }
      var content;
      if(tag & 0x20) {
        content = reencodeLongForm(bytes, pos, pos + len);
      } else {
        content = bytes.substr(pos, len);
      }
      pos += len;
      out += String.fromCharCode(tag) + longFormLength(content.length) +
      content;
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // the differential test cases
  // ---------------------------------------------------------------------------

  describe('x509-differential', function() {
    before(function() {
      FIXTURES = buildFixtures();
    });

    after(function() {
    // record: print every observed structural/behavioral difference,
    // grouped by case, with its classification
      var lines = ['', 'x509 differential report (forge vs node built-in):'];
      var current = null;
      RUN_LOG.forEach(function(d) {
        if(d.caseId !== current) {
          current = d.caseId;
          lines.push('  [' + current + ']');
        }
        lines.push('    ' + formatDiff(d));
      });
      lines.push('  total differences recorded: ' + RUN_LOG.length);
      console.log(lines.join('\n'));
    });

    it('should agree on all fields of a baseline leaf certificate',
      function() {
        var caseId = 'baseline-leaf';
        OBSERVED = [];

        var forgeCert = forgeParsePem(FIXTURES.leafPem, caseId);
        var nodeCert = nodeParse(FIXTURES.leafPem, caseId);
        assertNormalizedEqual(caseId, forgeCert, nodeCert);

        // structural representation differences (documented, non-fatal)
        recordDiff({caseId: caseId, stage: 'field-compare', field: 'subject',
          classification: CLASSIFICATION.REPRESENTATION,
          forge: 'attributes[]', node: 'dn-string'});
        recordDiff({caseId: caseId, stage: 'field-compare',
          field: 'serialNumber', classification: CLASSIFICATION.REPRESENTATION,
          forge: FIXTURES.leaf.serialNumber, node: nodeCert.serialNumber});
        recordDiff({caseId: caseId, stage: 'field-compare', field: 'validity',
          classification: CLASSIFICATION.REPRESENTATION,
          forge: 'Date', node: nodeCert.validFrom});
        recordDiff({caseId: caseId, stage: 'field-compare',
          field: 'extensions.keyUsage',
          classification: CLASSIFICATION.NODE_API_SURFACE,
          forge: JSON.stringify(forgeCert.getExtension('keyUsage')),
          node: '<not exposed>'});
        recordDiff({caseId: caseId, stage: 'field-compare',
          field: 'extensions.generic',
          classification: CLASSIFICATION.NODE_API_SURFACE,
          forge: forgeCert.extensions.length + ' extensions',
          node: '<no extension API>'});

        assertDiffsCovered(caseId);
      });

    it('should parse nameConstraints and enforce them in chain verification',
      function() {
        var caseId = 'name-constraints';
        OBSERVED = [];

        var forgeCa = forgeParsePem(FIXTURES.caPem, caseId);
        var nodeCa = nodeParse(FIXTURES.caPem, caseId);
        ASSERT.ok(nodeCa.ca, 'node should report the CA flag');

        // stage: extension-parse -- forge exposes the subtrees, node does not
        var nc = forgeCa.getExtension('nameConstraints');
        ASSERT.ok(nc, 'forge should parse the nameConstraints extension');
        ASSERT.deepStrictEqual(nc.permittedSubtrees,
          [{type: 2, value: '.example.com'}],
          '[x509-diff] case=' + caseId + ' stage=extension-parse ' +
        'field=extensions.nameConstraints.permittedSubtrees: got ' +
        JSON.stringify(nc.permittedSubtrees));
        ASSERT.deepStrictEqual(nc.excludedSubtrees,
          [{type: 2, value: 'bad.example.com'}],
          '[x509-diff] case=' + caseId + ' stage=extension-parse ' +
        'field=extensions.nameConstraints.excludedSubtrees: got ' +
        JSON.stringify(nc.excludedSubtrees));
        recordDiff({caseId: caseId, stage: 'extension-parse',
          field: 'extensions.nameConstraints',
          classification: CLASSIFICATION.NODE_API_SURFACE,
          forge: JSON.stringify({
            permitted: nc.permittedSubtrees,
            excluded: nc.excludedSubtrees
          }),
          node: '<not exposed>'});

        // chain with a permitted SAN: both accept
        var caKeyPem = PKI.publicKeyToPem(FIXTURES.caKeys.publicKey);
        var okChain = forgeChainVerify([FIXTURES.leaf]);
        ASSERT.ok(okChain.ok,
          '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
        'field=chain.permitted-subtree: forge rejected a permitted ' +
        'name: ' + okChain.message);
        var nodeLeaf = nodeParse(FIXTURES.leafPem, caseId);
        ASSERT.ok(nodeLinkVerify(nodeLeaf, caKeyPem),
          '[x509-diff] case=' + caseId + ' stage=link-verify ' +
        'field=chain.permitted-subtree: node link verification failed');

        // chain with an excluded SAN: forge rejects (security policy),
        // node's per-link check still passes (no path validation)
        var excludedPem = PKI.certificateToPem(FIXTURES.leafExcluded);
        var badChain = forgeChainVerify(
          [forgeParsePem(excludedPem, caseId)], caseId);
        ASSERT.ok(!badChain.ok,
          '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
        'field=chain.excluded-subtree: forge accepted an excluded name');
        ASSERT.ok(/name constraint/.test(badChain.message),
          '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
        'field=chain.excluded-subtree: unexpected rejection reason: ' +
        badChain.message);
        var nodeExcluded = nodeParse(excludedPem, caseId);
        ASSERT.ok(nodeLinkVerify(nodeExcluded, caKeyPem),
          '[x509-diff] case=' + caseId + ' stage=link-verify ' +
        'field=chain.excluded-subtree: node link verification failed');
        recordDiff({caseId: caseId, stage: 'chain-verify',
          field: 'chain.excluded-subtree',
          classification: CLASSIFICATION.FORGE_SECURITY_POLICY,
          forge: badChain.code + ': ' + badChain.message,
          node: 'link-verify=true (no path validation)'});

        assertDiffsCovered(caseId);
      });

    it('should treat unknown extensions according to their criticality',
      function() {
        var caseId = 'extension-criticality';
        OBSERVED = [];

        var caKeyPem = PKI.publicKeyToPem(FIXTURES.caKeys.publicKey);

        // unknown CRITICAL extension: both parse it, but forge's path
        // validation rejects the certificate (security policy)
        var criticalPem = PKI.certificateToPem(FIXTURES.leafUnknownCritical);
        var forgeCritical = forgeParsePem(criticalPem, caseId);
        var unknownExt = forgeCritical.extensions.filter(function(e) {
          return e.id === '1.2.3.4.5.6';
        })[0];
        ASSERT.ok(unknownExt && unknownExt.critical === true,
          '[x509-diff] case=' + caseId + ' stage=extension-parse ' +
        'field=extensions[1.2.3.4.5.6].critical: forge lost the ' +
        'critical flag of the unknown extension');
        var chainResult = forgeChainVerify([forgeCritical]);
        ASSERT.ok(!chainResult.ok,
          '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
        'field=chain.unknown-critical-extension: forge accepted an ' +
        'unsupported critical extension');
        ASSERT.ok(/unsupported critical extension/.test(chainResult.message),
          '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
        'field=chain.unknown-critical-extension: unexpected rejection ' +
        'reason: ' + chainResult.message);
        var nodeCritical = nodeParse(criticalPem, caseId);
        ASSERT.ok(nodeLinkVerify(nodeCritical, caKeyPem),
          '[x509-diff] case=' + caseId + ' stage=link-verify ' +
        'field=chain.unknown-critical-extension: node failed to ' +
        'link-verify the certificate');
        recordDiff({caseId: caseId, stage: 'chain-verify',
          field: 'chain.unknown-critical-extension',
          classification: CLASSIFICATION.FORGE_SECURITY_POLICY,
          forge: chainResult.code + ': ' + chainResult.message,
          node: 'parsed + link-verify=true'});

        // unknown NON-CRITICAL extension: both accept; forge preserves the
        // raw value, node drops it
        var nonCriticalPem =
        PKI.certificateToPem(FIXTURES.leafUnknownNonCritical);
        var forgeNonCritical = forgeParsePem(nonCriticalPem, caseId);
        var preserved = forgeNonCritical.extensions.filter(function(e) {
          return e.id === '1.2.3.4.5.6';
        })[0];
        ASSERT.ok(preserved && typeof preserved.value === 'string',
          '[x509-diff] case=' + caseId + ' stage=extension-parse ' +
        'field=extensions[1.2.3.4.5.6].value: forge did not preserve ' +
        'the raw extnValue');
        var okChain = forgeChainVerify([forgeNonCritical]);
        ASSERT.ok(okChain.ok,
          '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
        'field=extensions.unknown-non-critical: forge rejected an ' +
        'unknown non-critical extension: ' + okChain.message);
        var nodeNonCritical = nodeParse(nonCriticalPem, caseId);
        ASSERT.ok(nodeLinkVerify(nodeNonCritical, caKeyPem),
          '[x509-diff] case=' + caseId + ' stage=link-verify ' +
        'field=extensions.unknown-non-critical: node link ' +
        'verification failed');
        recordDiff({caseId: caseId, stage: 'extension-parse',
          field: 'extensions.unknown-non-critical',
          classification: CLASSIFICATION.NODE_API_SURFACE,
          forge: 'raw extnValue preserved (' + preserved.value.length +
          ' bytes)',
          node: '<silently dropped>'});

        assertDiffsCovered(caseId);
      });

    it('should both accept unknown RDN attributes in the subject',
      function() {
        var caseId = 'unknown-fields';
        OBSERVED = [];

        var pem = PKI.certificateToPem(FIXTURES.leafUnknownRdn);
        var forgeCert = forgeParsePem(pem, caseId);
        var nodeCert = nodeParse(pem, caseId);

        // the unknown attribute survives in both parsers
        var unknown = forgeCert.subject.attributes.filter(function(a) {
          return a.type === '1.2.3.4';
        })[0];
        ASSERT.ok(unknown && unknown.value === 'mystery-attribute',
          '[x509-diff] case=' + caseId + ' stage=cert-from-asn1 ' +
        'field=subject.unknown-attribute: forge lost the unknown RDN ' +
        'attribute');
        ASSERT.ok(nodeCert.subject.indexOf('1.2.3.4=mystery-attribute') !== -1,
          '[x509-diff] case=' + caseId + ' stage=node-parse ' +
        'field=subject.unknown-attribute: node lost the unknown RDN ' +
        'attribute: ' + JSON.stringify(nodeCert.subject));

        // normalized subjects (including the unknown attribute) must agree
        ASSERT.strictEqual(forgeDn(forgeCert.subject.attributes),
          nodeCert.subject,
          '[x509-diff] case=' + caseId + ' stage=field-compare ' +
        'field=subject: normalized subjects differ: forge=' +
        JSON.stringify(forgeDn(forgeCert.subject.attributes)) +
        ' node=' + JSON.stringify(nodeCert.subject));

        recordDiff({caseId: caseId, stage: 'field-compare',
          field: 'subject.unknown-attribute',
          classification: CLASSIFICATION.REPRESENTATION,
          forge: JSON.stringify(unknown),
          node: '1.2.3.4=mystery-attribute'});

        assertDiffsCovered(caseId);
      });

    it('should differ on non-canonical DER length octets', function() {
      var caseId = 'non-canonical-length';
      OBSERVED = [];

      var canonicalDer =
      ASN1.toDer(PKI.certificateToAsn1(FIXTURES.leaf)).getBytes();
      var longFormDer = reencodeLongForm(canonicalDer, 0, canonicalDer.length);
      ASSERT.ok(longFormDer.length > canonicalDer.length,
        '[x509-diff] case=' + caseId + ' stage=fixture-build ' +
      'field=der.length-encoding: long-form re-encode did not expand ' +
      'the encoding');

      // forge accepts the non-canonical encoding, normalizes it back to the
      // canonical DER, and the certificate still chain-verifies
      var forgeCert = forgeParseDer(longFormDer, caseId);
      ASSERT.strictEqual(
        ASN1.toDer(PKI.certificateToAsn1(forgeCert)).getBytes(), canonicalDer,
        '[x509-diff] case=' + caseId + ' stage=cert-from-asn1 ' +
      'field=der.length-encoding: forge did not normalize back to the ' +
      'canonical DER');
      var chainResult = forgeChainVerify([forgeCert]);
      ASSERT.ok(chainResult.ok,
        '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
      'field=der.length-encoding: forge rejected a long-form-length ' +
      'certificate: ' + chainResult.message);

      // node/openssl rejects non-minimal length octets at parse time
      var nodeRejected = false;
      var nodeError = null;
      try {
      // eslint-disable-next-line no-new
        new CRYPTO.X509Certificate(
          UTIL.binary.raw.decode(longFormDer));
      } catch(e) {
        nodeRejected = true;
        nodeError = e;
      }
      ASSERT.ok(nodeRejected,
        '[x509-diff] case=' + caseId + ' stage=node-parse ' +
      'field=der.length-encoding: node accepted non-minimal DER ' +
      'lengths; update EXPECTED_DIFFS (strictness changed)');
      recordDiff({caseId: caseId, stage: 'node-parse',
        field: 'der.length-encoding',
        classification: CLASSIFICATION.NODE_PARSER_STRICTNESS,
        forge: 'parsed + chain-verified',
        node: 'rejected: ' + (nodeError && nodeError.message)});

      assertDiffsCovered(caseId);
    });

    it('should require leaf-first chain ordering', function() {
      var caseId = 'chain-order';
      OBSERVED = [];

      var caKeyPem = PKI.publicKeyToPem(FIXTURES.caKeys.publicKey);

      // correctly ordered chain (leaf first, anchor in the store): pass
      var ordered = forgeChainVerify([FIXTURES.leaf]);
      ASSERT.ok(ordered.ok,
        '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
      'field=chain.ordering: forge rejected an ordered chain: ' +
      ordered.message);

      // reversed chain (CA presented as the end-entity): forge rejects
      var reversed = forgeChainVerify(
        [FIXTURES.ca, FIXTURES.leaf]);
      ASSERT.ok(!reversed.ok,
        '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
      'field=chain.ordering: forge accepted a reversed chain');
      ASSERT.strictEqual(reversed.code, 'forge.pki.BadCertificate',
        '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
      'field=chain.ordering: unexpected error code: ' + reversed.code);

      // node has no chain API; per-link verification is order-independent
      var nodeLeaf = nodeParse(FIXTURES.leafPem, caseId);
      ASSERT.ok(nodeLinkVerify(nodeLeaf, caKeyPem),
        '[x509-diff] case=' + caseId + ' stage=link-verify ' +
      'field=chain.ordering: node link verification failed');
      recordDiff({caseId: caseId, stage: 'chain-verify',
        field: 'chain.ordering',
        classification: CLASSIFICATION.FORGE_SECURITY_POLICY,
        forge: reversed.code + ': ' + reversed.message,
        node: '<no chain API; link-verify=true regardless of order>'});

      assertDiffsCovered(caseId);
    });

    it('should both reject invalid signatures', function() {
      var caseId = 'invalid-signature';
      OBSERVED = [];

      var caKeyPem = PKI.publicKeyToPem(FIXTURES.caKeys.publicKey);

      // (a) tampered signature bytes
      var tamperedSig = forgeParsePem(FIXTURES.leafPem, caseId);
      var sig = tamperedSig.signature.split('');
      sig[10] = String.fromCharCode(sig[10].charCodeAt(0) ^ 0x01);
      tamperedSig.signature = sig.join('');
      var tamperedSigPem = PKI.certificateToPem(tamperedSig);

      var forgeResult = forgeChainVerify(
        [forgeParsePem(tamperedSigPem, caseId)], caseId);
      ASSERT.ok(!forgeResult.ok &&
      forgeResult.code === 'forge.pki.BadCertificate',
      '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
      'field=signatureValue: forge did not reject a tampered ' +
      'signature: ' + JSON.stringify(forgeResult));
      var nodeTampered = nodeParse(tamperedSigPem, caseId);
      ASSERT.strictEqual(nodeLinkVerify(nodeTampered, caKeyPem), false,
        '[x509-diff] case=' + caseId + ' stage=link-verify ' +
      'field=signatureValue: node accepted a tampered signature');

      // (b) tampered TBS content (subject CN changed after signing)
      var tamperedTbs = forgeParsePem(FIXTURES.leafPem, caseId);
      tamperedTbs.subject.attributes[0].value = 'forged.example.com';
      tamperedTbs.tbsCertificate = null;
      var tamperedTbsPem = PKI.certificateToPem(tamperedTbs);

      var forgeResult2 = forgeChainVerify(
        [forgeParsePem(tamperedTbsPem, caseId)], caseId);
      ASSERT.ok(!forgeResult2.ok &&
      forgeResult2.code === 'forge.pki.BadCertificate',
      '[x509-diff] case=' + caseId + ' stage=chain-verify ' +
      'field=tbsCertificate.subject: forge did not reject tampered ' +
      'TBS content: ' + JSON.stringify(forgeResult2));
      var nodeTampered2 = nodeParse(tamperedTbsPem, caseId);
      ASSERT.strictEqual(nodeTampered2.subject,
        'CN=forged.example.com',
        '[x509-diff] case=' + caseId + ' stage=node-parse ' +
      'field=tbsCertificate.subject: node did not parse the tampered ' +
      'subject');
      ASSERT.strictEqual(nodeLinkVerify(nodeTampered2, caKeyPem), false,
        '[x509-diff] case=' + caseId + ' stage=link-verify ' +
      'field=tbsCertificate.subject: node accepted tampered TBS content');

      // both reject; only the failure *surface* differs
      recordDiff({caseId: caseId, stage: 'link-verify',
        field: 'verify.failure-surface',
        classification: CLASSIFICATION.REPRESENTATION,
        forge: 'throws ' + forgeResult.code,
        node: 'returns false'});

      assertDiffsCovered(caseId);
    });
  });

})();
