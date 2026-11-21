# Lenient BER Parsing and Byte Binding in X.509 Signature Verification

**Subject:** `node-forge` (this repository, version 1.4.4-0)
**Scope:** `lib/asn1.js`, `lib/x509.js`, `lib/rsa.js`
**Question:** How does the library's lenient BER acceptance interact with the byte-level binding of an X.509 certificate signature?

---

## 1. Executive summary

The signature on an X.509 Certificate is defined over the **exact octets** of the DER-encoded `tbsCertificate` (RFC 5280 §4.1.1.2; RFC 5280 mandates DER, a canonical subset of BER, for certificates). node-forge does **not** retain or hash the original on-the-wire `tbsCertificate` bytes. Instead it:

1. parses the input with a **BER-tolerant** parser (`asn1.fromDer`, despite its name),
2. stores an in-memory ASN.1 object tree, and
3. at verification time **re-encodes that tree** with `asn1.toDer` and hashes the *re-encoded* output.

The signature therefore binds the **canonical re-encoding of the parse tree**, not the transmitted bytes. This was demonstrated empirically: certificates whose `tbsCertificate` uses BER-only encodings (indefinite length, non-minimal long-form length, non-minimal INTEGER content) still verify successfully, because every such variant normalizes to the same canonical DER when the tree is re-encoded.

This design preserves compatibility with old/non-conformant encoders but means (a) invalid-BER/DER inputs are accepted as valid certificates, (b) multiple distinct byte strings share one signature and one parser-visible identity, which can split decision-making across systems that hash different representations, and (c) one part of the code base already treats non-canonical encoding as an attack surface — the embedded PKCS#1 `DigestInfo` check added for CVE-2026-119192 — while the certificate `tbsCertificate` layer has no equivalent check.

---

## 2. The data path, from wire bytes to signature check

### 2.1 Parse tree construction (`lib/asn1.js`)

`asn1.fromDer(bytes, options)` (`lib/asn1.js:434`) wraps `_fromDer` (`lib/asn1.js:488`). The parser is BER-tolerant in several concrete, source-visible ways:

- **Indefinite length is accepted.** `_getValueLength` returns `undefined` for the `0x80` length octet (`lib/asn1.js:386-388`). For constructed nodes, `_fromDer` then loops until it reads the two-zero end-of-contents octets (`lib/asn1.js:540-552`). DER forbids indefinite length entirely.
- **Non-minimal definite length is accepted.** Long form is accepted whenever bit 8 is set (`lib/asn1.js:392-402`); nothing rejects the redundant encodings `0x81 0x01` for length 1, or `0x82 0x00 0x01`. Both were confirmed to parse.
- **Non-minimal INTEGER content is accepted.** Primitive values are stored as raw byte strings (`lib/asn1.js:652`); the parser does not enforce the DER minimal-encoding rule for INTEGER.
- **BER BOOLEAN values are accepted.** Primitive content is copied verbatim, so `01 01 01` and `01 01 7F` parse as a true-valued BOOLEAN even though DER requires `0xFF`.
- **Truncated values can be accepted in lenient mode.** When a declared length exceeds the remaining bytes, strict mode throws; otherwise the parser silently clamps the length to the bytes available (`lib/asn1.js:518-528`).
- **BIT STRING contents are heuristically re-parsed.** When a primitive BIT STRING has zero unused bits, the parser *speculatively* tries to decode its content as an encapsulated ASN.1 object (`lib/asn1.js:573-630`). Because there is no schema, plain data that merely looks like ASN.1 can be turned into a composed node; the code comments acknowledge this hazard (`lib/asn1.js:421-426`).
- **Recursion is bounded** by `asn1.maxDepth = 256` (`lib/asn1.js:184`, enforced at `lib/asn1.js:491-493`), and `parseAllBytes` rejects trailing data (`lib/asn1.js:469-474`).

### 2.2 Re-encoding (`asn1.toDer`)

`asn1.toDer(obj)` (`lib/asn1.js:673`) serializes the tree back to **canonical DER**:

- Length is always emitted in the shortest legal form — short form under 128, otherwise minimal long form (`lib/asn1.js:738-764`). Indefinite length is never emitted.
- One leading `0x00` (positive) or `0xFF` (negative) is stripped from an INTEGER when redundant (`lib/asn1.js:720-728`). The adjacent `TODO` (`lib/asn1.js:718-719`) and the unit test (`tests/unit/asn1.js:1445-1470`) confirm that only **one** leading byte is removed; an INTEGER carrying two redundant leading bytes is still non-canonical after re-encoding.
- Primitive values other than INTEGER (BOOLEAN, OID, OCTET STRING, …) are copied verbatim, so BER variants such as `01 01 01` survive a round trip byte-for-byte.
- **BIT STRING special case.** Because speculative decoding (§2.1) could otherwise recompact arbitrary "signature-like" bits, a parsed BIT STRING saves its original content in `bitStringContents` and a snapshot in `original` (`lib/asn1.js:224-230`, `565-663`). On output, if the node is unchanged (`asn1.equals` against `original`, `lib/asn1.js:684-689`), the saved bytes are emitted verbatim; if any child was mutated, content is regenerated through the normal composed path and is thereby canonicalized.

### 2.3 The original signature input (`lib/x509.js`)

`certificateFromPem` → `asn1.fromDer(msg.body, strict)` → `certificateFromAsn1` (`lib/x509.js:804-825`, `1308`). The schema validator captures the `tbsCertificate` **node** (`captureAsn1: 'tbsCertificate'`, `lib/x509.js:161`) and the signature BIT STRING value (`captureBitStringValue: 'certSignature'`, `lib/x509.js:320`).

When `computeHash` is true, the digest that will be compared against the signature is computed from a **fresh re-encoding**:

```js
// lib/x509.js:1375-1377
var bytes = asn1.toDer(cert.tbsCertificate);
cert.md.update(bytes.getBytes());
```

The same re-encoding happens lazily during verification when no precomputed digest exists:

```js
// lib/x509.js:1182-1185
var tbsCertificate = child.tbsCertificate || pki.getTBSCertificate(child);
var bytes = asn1.toDer(tbsCertificate);
md.update(bytes.getBytes());
```

`_verifySignature` then feeds `md.digest()` and the captured signature into `publicKey.verify(...)` (`lib/x509.js:783-786`). The CSR path is structurally identical: `csr.verify` re-encodes `certificationRequestInfo` before digesting (`lib/x509.js:1943-1947`).

**Consequence — the signed message is a function of the parse tree, not of the input octets.** Any two inputs that produce equal trees produce equal verification digests. The original wire bytes of `tbsCertificate` are never stored on the certificate object and are never hashed.

### 2.4 Error propagation

- Structural parse failures throw from `_fromDer` with diagnostic fields (`available`/`remaining`/`requested`, `lib/asn1.js:360-368`, `518-524`) and surface from `certificateFromPem`/`certificateFromAsn1` before any crypto runs.
- Schema mismatch throws "Cannot read X.509 certificate" (`lib/x509.js:1312-1317`).
- A bad signature is normally reported as the boolean `false` from `rsa.key.verify`, but malformed PKCS#1 padding **throws** ("Encryption block is invalid.", `lib/rsa.js:1709`), so `cert.verify` can either return `false` or throw depending on how the signature was corrupted.
- `verifyCertificateChain` wraps each `parent.verify(cert)` in `try/catch` and collapses every exception into a generic `bad_certificate` result (`lib/x509.js:3772-3786`); the anchor loop does the same (`lib/x509.js:3700-3705`). Callers therefore cannot distinguish "BER parse error", "padding error", and "signature mismatch" at the chain API.
- A separate ordering quirk: `cert.verify` checks `cert.issued(child)` (issuer/subject name match) **before** the cryptographic check and throws on mismatch (`lib/x509.js:1162-1172`), so name-hash divergence can mask the signature result entirely.

---

## 3. Empirical findings (all reproduced against this tree)

Using a generated RSA-1024 self-signed certificate and a CA-signed leaf, bytes were mutated while correcting enclosing length octets, then re-parsed and verified.

| # | BER variant applied inside `tbsCertificate` | Re-encoded TBS equals originally signed TBS? | `verify` result |
|---|---|---|---|
| 1 | Non-minimal length on version INTEGER (`02 01 02` → `02 81 01 02`) | yes | **true** |
| 2 | Indefinite-length inner SEQUENCE / TBS wrapper (`30 80 … 00 00`) | yes | **true** |
| 3 | Indefinite-length outer Certificate (outside the signed region) | yes (TBS untouched) | **true** |
| 4 | Non-minimal INTEGER content (`02 01 02` → `02 02 00 02`) | yes — one leading `00` stripped by `toDer` | **true** |
| 5 | Indefinite `[0]` version wrapper | yes | **true** |
| 6 | Doubly-redundant INTEGER (`02 01 02` → `02 03 00 00 02`) | **no** — `toDer` strips only one byte, output still non-DER | **false** |
| 7 | Baseline untouched DER | yes | true |

Additional observations:

- Two byte-different certificates (cases 1 and 7) parse to certificates with identical serial, subject, and public-key identity, and **both verify under the same signature** — a direct demonstration that the signature does not uniquely identify an encoding.
- Trailing bytes after the outer SEQUENCE are rejected by default (`parseAllBytes`, `lib/asn1.js:469`).
- A 10-byte-truncated certificate parses with `{strict: false, parseAllBytes: false}`, but fails later in crypto; the lenient clamp itself does not error.
- BER BOOLEAN (`01 01 01`), non-minimal OID subidentifiers, and a NULL with content all survive `fromDer`→`toDer` unchanged — the parser accepts them and the serializer has no rule to canonicalize or reject them.
- Depth 255 of indefinite nesting parses; depth 256 throws "Max depth exceeded."
- The CA store (`lib/x509.js:2831-2853`) decides trust by comparing **canonical re-encoded** DER, so a BER-variant self-signed cert is not recognized as its own anchor even though its signature verifies; a BER-variant *leaf* under a canonical CA anchor reaches and passes the signature check.

---

## 4. The security trade-off: legacy compatibility vs. rejecting mutable encodings

### What the lenient parser buys

- Old software stacks (notably some PKCS#12 producers; `lib/pkcs12.js:527` explicitly comments "actually it's BER encoded") emit indefinite-length and other BER constructs. Strict rejection would break reading such artifacts.
- Re-encoding before hashing is a *normalization* strategy: every equivalent BER encoding converges on one canonical byte string, so one signature validates the whole equivalence class and interop with lenient peers is preserved.
- The BIT STRING `bitStringContents`/`original` machinery shows the maintainers already encountered the round-trip hazard and engineered a targeted preservation mechanism rather than switching to strict DER.

### What it costs

- **No enforcement of the X.509 DER mandate.** RFC 5280 §4.1 ("conforming implementations ... MUST use DER") is not enforced; invalid inputs are presented to applications as valid certificates.
- **Many-to-one byte binding.** A single signature covers an open-ended set of wire encodings (all length re-encodings, indefinite forms, and — because primitive values round-trip verbatim — BER BOOLEANs and non-minimal OIDs). Anything that fingerprints, caches, pins, or filters certificates on raw bytes (SPKI pins, certificate-transparency pre-cert handling, middlebox allow/deny rules, deduplication, audit logs) can be made to see a different byte string while forge reports the same verified identity.
- **Parser-confusion surface.** The same encoder flexibility was judged dangerous enough in the PKCS#1 layer to warrant a strict canonicalization check. CVE-2026-119192 states that "non-canonical DigestInfo encodings, such as NULL parameters with content, non-minimal length encodings, and non-canonical OIDs ... provide attackers space to construct forged signatures." The fix re-encodes the parsed `DigestInfo` and compares it byte-for-byte with the received block, rejecting any mismatch (`lib/rsa.js:1240-1255`). The certificate layer performs the first half of that recipe (re-encode and hash) but never the second half (compare against the transmitted bytes).
- **Inconsistent canonicalization.** INTEGER normalization removes only one redundant byte (§2.2), so case 6 above is rejected not because it is invalid BER — it parsed fine — but because the re-encoder cannot fully canonicalize it. Acceptance then depends on an implementation detail of the serializer rather than on a stated policy.
- **Swallowed diagnostics.** Chain verification converts all verification exceptions into one error class (§2.4), making anomalies such as parse-level leniency invisible to monitoring.

---

## 5. Exploitable boundaries and improvement recommendations

### Boundary A — Verification/decision split across two representations (representational smuggling)

**Mechanism.** Forge's trust decision is made over `toDer(parse(input))`; another component (a TLS middlebox, an anti-malware scanner, a logging/pinning layer, a second TLS library) may decide over the raw bytes or use a parser with different BER tolerance. Cases 1-5 show the two representations already diverge inside forge itself (wire bytes vs. hashed bytes), and case 7 shows the identities remain equal. An attacker can therefore present an encoding that the outer component classifies differently (unseen, un-pinned, or matched against a byte-oriented rule) while forge verifies the same certificate and key.

**Who can exploit it.** Anyone able to deliver a certificate over a protocol whose peer uses forge for verification — TLS handshakes (forge parses handshake certificates with default `fromDer`, `lib/tls.js:1246`), PEM intake, or PKCS#7/PKCS#12-wrapped certs. No private key is needed to re-wrap an existing validly issued certificate in BER; the signature stays valid because normalization reconstructs the signed TBS.

**Recommendations.**

1. Add a strict-DER mode for certificate intake that rejects, at parse time, indefinite length, non-minimal long-form length (`81 01`, `82 00 01`, …), non-minimal INTEGER content, non-canonical BOOLEAN, and content-bearing NULL — and make it the default for `certificateFromPem`/`certificateFromAsn1`, keeping the lenient path explicitly opt-in for legacy PKCS#12-style inputs.
2. Mirror the CVE-2026-119192 pattern at the certificate layer: after parsing, re-encode `tbsCertificate` and compare the result against the exact captured sub-string of the input; reject on mismatch. This closes the many-to-one gap without changing the digest computation.
3. Expose the original on-wire bytes (e.g. `cert.rawTbsCertificate`) so applications that pin or hash can bind to the transmitted encoding deliberately.

### Boundary B — Heuristic BIT STRING decoding and silent value reinterpretation

**Mechanism.** Primitive BIT STRINGs whose content happens to parse as ASN.1 are converted to composed nodes (`lib/asn1.js:573-630`). The code already documents that without schema context this "can erroneously decode values that happen to be valid ASN.1" (`lib/asn1.js:421-426`). The `bitStringContents` snapshot preserves bytes only while the node is untouched; any programmatic mutation switches the node to the regenerated path, at which point indefinite/long-form structures inside the former bit string are recompacted and the byte binding changes. The related resource-exhaustion history (CVE-2026-119191, CHANGELOG) shows this code path is a recurring vulnerability location; nested decoding is already disabled by default for quadratic-cost reasons (`lib/asn1.js:600-607`).

**Who can exploit it.** An attacker supplying a certificate (or any ASN.1 blob) whose key/signature BIT STRING is crafted to straddle the "decodable vs. opaque" threshold can induce two different in-memory shapes from near-identical inputs, and any application logic that introspects the tree (extension processors, custom key handling) sees the reinterpreted structure rather than the declared bit string.

**Recommendations.**

1. Remove speculative content decoding from the generic parser and require explicit, schema-driven unpacking at call sites that expect encapsulated data (SPKI, signatures). The code's own comment marks the flag for deprecation.
2. Until removed, default `decodeBitStrings: false` for the certificate and CSR entry points and audit every caller that relies on the implicit behavior.
3. When `bitStringContents` exists but the node was mutated, emit a warning/error path rather than silently regenerating canonical content, so byte-binding changes are observable.

### Boundary C — Lenient truncation and uniform error collapsing

**Mechanism.** `strict: false` clamps declared lengths to available bytes (`lib/asn1.js:526-527`), accepting structurally truncated objects, and `verifyCertificateChain` erases the distinction between parse anomalies, padding failures, and signature mismatches (`lib/x509.js:3700-3705`, `3772-3786`). The boolean-vs-throw behavior of `cert.verify` (§2.4) makes application-level handling similarly fragile.

**Who can exploit it.** An attacker feeding truncated or malformed certificates to a service that enabled lenient parsing gets best-effort parsing with no signal that the input was malformed; fuzzing and downgrade-style probes become indistinguishable from ordinary bad signatures in logs.

**Recommendations.**

1. Never allow `strict: false` on the certificate/CSR verification paths; reserve it for the legacy PKCS#12 call sites that need it, and document the threat model there.
2. Introduce distinct error codes for parse rejection, canonicalization mismatch, padding failure, and digest mismatch instead of collapsing everything to `bad_certificate`, and surface them through the verify callback.
3. Standardize `cert.verify` on returning `false` for any failed cryptographic check and reserving throws for programmer/usage errors.

### Cross-cutting hardening

- Finish INTEGER canonicalization (the `TODO` at `lib/asn1.js:718-719`): strip *all* redundant leading bytes, or reject non-minimal INTEGERs at parse time under the strict mode from recommendation A1.
- Reject length encodings whose leading long-form octets are zero and BOOLEAN values other than `0x00`/`0xFF` in strict mode; both currently round-trip silently.
- Add regression tests encoding each row of the §3 matrix so the normalization policy is intentional and reviewed rather than emergent.

---

## 6. Evidence classification

### Confirmed by source code and/or executed experiments in this tree

- `fromDer` accepts indefinite length, non-minimal long-form length, non-minimal INTEGER content, and BER BOOLEAN; `toDer` always emits minimal lengths and strips one redundant INTEGER byte (`lib/asn1.js:386-402`, `540-552`, `720-728`, `738-764`; experiments in §3).
- Verification hashes `asn1.toDer(captured tbsCertificate)`, never the original wire bytes (`lib/x509.js:1182-1185`, `1375-1377`; CSR analog at `1943-1947`).
- BER-variant certificates (indefinite/non-minimal encodings) verify successfully while differing on the wire (§3, cases 1-5); doubly-redundant INTEGERs fail because re-encoding cannot fully canonicalize them (case 6).
- Trailing bytes are rejected by default; depth is capped at 256; lenient mode accepts truncated values.
- BIT STRING content is speculatively re-parsed and preserved via `bitStringContents`/`original`, with canonical regeneration on mutation (`lib/asn1.js:224-230`, `573-630`, `684-689`).
- The PKCS#1 `DigestInfo` verification enforces a canonical-DER byte comparison after CVE-2026-119192, while the certificate TBS layer has no equivalent comparison (`lib/rsa.js:1240-1255` vs. `lib/x509.js:1375-1377`).
- Chain verification catches and collapses verification exceptions to generic errors (`lib/x509.js:3700-3705`, `3772-3786`); malformed PKCS#1 padding throws from `lib/rsa.js:1709`.
- The CA store compares re-encoded DER for trust identity (`lib/x509.js:2844-2851`).

### Judgments not fully evidenced here (require further work)

- **Real-world exploitability of representational smuggling (Boundary A).** The mechanism is demonstrated against forge alone; an actual cross-system divergence (e.g. a specific middlebox or second library accepting/rejecting the crafted BER in a security-relevant way) was not built or measured.
- **Impact through TLS specifically.** `lib/tls.js:1246` uses the same parser, but no end-to-end TLS handshake with a BER-variant certificate was exercised; protocol-layer length handling may reject such certificates before the X.509 layer sees them.
- **Primitive value round-tripping as an attack primitive.** BER BOOLEAN and non-minimal OIDs survive round trips, but no certificate extension processing path was shown to make a trust-relevant decision on such a field; whether this is exploitable depends on application schema handling.
- **Interaction with ed25519.** `lib/ed25519.js` exists but is not wired into `x509.js` signature OID handling, so the findings above apply to the RSA path; an ed25519 integration would inherit the same parse/re-encode behavior but this was not verified.
- **Performance/DoS severity of the remaining BIT STRING heuristics.** CVE-2026-119191 fixed depth-bypass and quadratic-copy issues; residual cost of the one-level default decoding under current limits was not benchmarked.
