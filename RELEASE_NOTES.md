# Unreleased: consistent verification and historical compatibility

The Node and WebCrypto engines now reject unsupported manifest versions and
asset hash algorithms consistently. Node requires an Ed25519 public key instead
of accepting another EdDSA key type under an Ed25519 label. RFC 8785 JCS rejects
lone Unicode surrogates in values and property names, including signature
metadata; valid Unicode pairs are preserved.

## Compatibility and revoked keys

Only manifest versions `1.0` and `1.1` are supported. Historical formats,
including AUTHENTICA's private `0.1-pilot` format and the `0.1-test` fixtures,
now receive an invalid overall result for unsupported version. Their signed
bytes remain unchanged and their signature dimension may still be inspected.
This does not establish that a historical signature was forged or determine the
legal value of an old record. The standard draft's `origin_proof_version: "0.1"`,
the Python demo and `0.1-pilot` are different historical formats.

Revocation policy is unchanged: a key listed as revoked in the supplied registry
causes an invalid overall result, even when its signature is mathematically
verifiable. An issuer-declared date before revocation does not override that
policy. A timestamp or a version upgrade does not restore trust in a revoked key.
Report registry provenance and freshness separately from signature validity.

Pilot processing counts must not be presented as counts of currently valid
evidence unless the relevant corpus, key status and verification results have
actually been checked. Any later reissue is a new declaration with its actual
issuance date; it does not modify or retroactively validate the original record.

Declared asset hashes require an explicit `SHA3-256` algorithm. The test-vector
generator now creates current v1.0 packages in a separate fresh destination and
refuses overwriting. Historical signed fixtures, public TSA evidence and
published schemas are preserved.

Validation: 47 shared signed scenarios in Node and WebCrypto, including the
`0.1-pilot` rejection case, pass under Node 20.19.0, 22.14.0 and 24.22.1.
Existing regression and RFC 3161 suites pass. The public FreeTSA example remains
verifiable offline; no qualified eIDAS status is inferred. WebCrypto tests run
under Node and do not constitute independent-implementation or browser UI tests.

See [strict verification](docs/STRICT_VERIFICATION.md) for remaining scope and
review limits. This preparation does not create a release tag or archive DOI.

# Earlier pending notes: manifest schema validation

Signed v1.0/v1.1 manifests now undergo the assertion checks in the bundled
canonical base schemas. A valid signature on an incomplete v1.1 reference
anchor returns `status: invalid`, `signatureOk: true`, and
`schemaValidation.status: fail`, with field-specific errors.

CLI and browser reports expose base-schema validation separately. Existing
signature, exact-byte integrity, issuer key pin and revocation checks remain.
The guide INTEGRATORS.md explains versioning and reference-artifact semantics.

Compatibility: previously accepted malformed published manifests will fail.
Valid v1.0 manifests do not require v1.1 anchors. Unknown and legacy versions
may expose cryptographic dimensions and schema `not_checked`, but now have an
invalid overall verdict under the version policy above.
Date-time formats remain annotations. Remote archives, real-world issuer
identity and whole-implementation conformance are not assessed.

Validation: existing regression suite plus correctly signed malformed packages,
valid v1.0/v1.1 and extension fields in both Node and WebCrypto engines.
Bundled schemas match standard release v1.2.1 commit
91b2d51fd6808c6882728c6104e75becee2b9578.

Publication checklist:

- Review the code and integration guide together.
- Run `npm test` on Node 20 and 22 (automated in the proposed CI workflow).
- Choose a new verifier release version; do not overwrite an archived release.
- Publish the reviewed verifier and guide together and archive the exact release.
- Use the resulting archive coordinates only after they exist. Do not change
  published standard schemas or archived evidence to point to this pending build.

No release tag, archive DOI or certification is created by this preparation.
