# Pending release: manifest schema validation

Signed v1.0/v1.1 manifests now undergo the assertion checks in the bundled
canonical base schemas. A valid signature on an incomplete v1.1 reference
anchor returns `status: invalid`, `signatureOk: true`, and
`schemaValidation.status: fail`, with field-specific errors.

CLI and browser reports expose base-schema validation separately. Existing
signature, exact-byte integrity, issuer key pin and revocation checks remain.
The guide INTEGRATORS.md explains versioning and reference-artifact semantics.

Compatibility: previously accepted malformed published manifests will fail.
Valid v1.0 manifests do not require v1.1 anchors. Unknown and legacy versions
remain cryptographically checkable but report schema `not_checked`.
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
