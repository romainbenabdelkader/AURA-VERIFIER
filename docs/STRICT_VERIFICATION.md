# Strict verification: unreleased corrections

These changes tighten verifier policy without changing the published schemas
or any committed signed manifests, timestamp responses, queries or certificates.
They do not establish a new conformance level or a new specification version.

## Shared acceptance policy

- Only `aura_version` strings `1.0` and `1.1` are supported. Every other value,
  including missing values and the historical `0.1-test`, is an overall failure.
  Cryptographic dimensions may still be shown, but do not override that failure.
- The only supported asset hash algorithm is `SHA3-256`. A declared asset hash
  requires that explicit algorithm. Unsupported or conflicting declarations
  cause failure; no integrity success is inferred by computing another hash.
  Fileless declarations with no asset hash remain supported.
- Node checks `asymmetricKeyType === 'ed25519'` before signature verification.
  An Ed448 key/signature cannot pass by carrying an Ed25519 label. WebCrypto's
  Ed25519 key import already enforces the key type.
- RFC 8785 section 3.2.2.2 requires rejection of lone Unicode surrogates.
  The canonicalizer now rejects them in strings and property names; verification
  validates the complete object, including signature metadata. The timestamp
  digest uses the same canonicalizer and rejects these inputs as well.

Reference: https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2.2

Valid Unicode pairs, existing supported manifests and the public FreeTSA vector
are regression cases. Nothing is re-signed to repair historical evidence.

The historical `origin_proof_version: "0.1"` standard draft, Python v0.1 demo
and AUTHENTICA `aura_version: "0.1-pilot"` are different field models. None is
supported by this current verifier. Unsupported-version failures describe the
scope of this implementation, not whether an old signature was forged or whether
the evidence's legal effect has changed. Preserve old evidence and identify its
original implementation and trust/key-status policy for historical review.
Even a mathematically valid historical signature does not override a revoked-key
result under the supplied registry policy. Do not relabel or re-sign old proofs
to make them appear to be current-format evidence.

## Reproduce

With Node.js 20 or later and OpenSSL 3.x on PATH:

```sh
node tests/run-tests.js
node tests/test-timestamp-rfc3161.js
node tests/test-timestamp-public.js
node scripts/verify-timestamp-example.js
```

`tests/test-strict-verification.js` exercises the same signed packages through
Node and WebCrypto and asserts matching verdicts and signature/integrity
dimensions. It includes malformed declarations signed by their test issuer and
permissively serialized negative Unicode fixtures. These are acceptance-policy
tests, not demonstrations of forged Ed25519 signatures. WebCrypto runs under
Node in this suite; it does not replace browser UI/platform testing or an
independent implementation.

The historical committed `0.1-test` fixtures remain unchanged and are explicitly
tested as unsupported. The generator now writes new v1.0 packages to a separate,
new destination, uses a schema-compatible identifier, and refuses overwriting.
`tests/test-generated-vectors.js` checks all three generated cases through both
engines and confirms that rerunning cannot overwrite the signed destination.

## Limits and follow-up

These corrections address the four reproduced controls, not a full formal
audit of RFC 8785 or every AURA semantic rule. In particular, duplicate JSON
property detection before `JSON.parse`, cross-field issuer identifier policy,
and semantic validation of the issuer-declared date require separate review.
An existing base-schema pass treats date-time format as an annotation.
Cryptographic validity does not establish identity, representation, ownership
or dossier completeness. The local registry's provenance/freshness remains a
caller trust decision. RFC 3161 verification does not establish qualified eIDAS
status; see [the timestamp guide](RFC3161_TIMESTAMP.md).
