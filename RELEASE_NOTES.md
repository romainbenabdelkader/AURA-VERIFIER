# Pending audit corrections before v1.2.0 publication

- Correct SHA3-256 padding at input lengths 135 modulo 136. Standard digests are
  accepted; the previously erroneous digest is rejected, without rewriting old proofs.
- Reject malformed supplied issuer registries and revocation entries; expose
  `registryValidation` and `keyStatusCheck: invalid_registry`.
- Apply canonical padded Base64 and exact Ed25519 signature length in both engines.
- Correct the human TDM signature-binding report and distinguish current
  revocation policy from unassessed historical validity.
- Add official NIST vectors, a native-crypto oracle, 44 shared package cases,
  real Chromium/Firefox/WebKit UI tests and a browser CI job.

See [audit correction and compatibility notes](docs/AUDIT_CORRECTIONS.md).
This change is prepared for review. No new version tag or Zenodo archive is
claimed; original evidence and archived releases remain unchanged.

# Pending follow-up to v1.2.0 preparation

- Reject duplicate JSON names in manifest and supplied issuer text, including
  escaped aliases and nested names; apply the same check to timestamp digests.
- Reject malformed or contradictory recognized asset-hash declarations.
- Report a declared hash without its file as not checked, including catalogue
  declarations; do not let catalogue markers suppress the missing-file warning.
- Check declared date syntax/calendar/offset separately from base-schema checks;
  flag leap seconds as unassessed, without claiming independent timestamp assurance.
- Reject contradictory present issuer identifiers and signed key labels.
- Report absent/untrusted registry status explicitly and refuse a matching
  current-key record whose status is revoked.
- Add 32 semantic-policy cases in both engines, preserving current public fixtures.
- Add 47 regression cases for parsing and signed-package acceptance.

No schema, historical signed evidence, version tag or DOI is changed.
Validation: the regression, synthetic/public RFC 3161 and offline suites pass
under Node 20.20.2, 22.23.4 and 24.22.1 with OpenSSL 3.6.2. The CI matrix now
includes Node 24. Additional local UI checks passed in Chrome, Firefox and
Playwright WebKit (11 cases in each); WebKit is not the Safari application.
This follow-up requires review before release. See docs/STRICT_VERIFICATION.md.

# AURA-VERIFIER v1.2.0

This source version brings together the changes since archived v1.1.0.
The release status is recorded on GitHub and Zenodo; source version metadata
alone does not establish that a release tag or an archive has been published.

## Included changes

- Detached RFC 3161 verification through the Node CLI and locally installed
  OpenSSL, including manifest binding, signature, supplied certificate chain
  and nonce checks when the original request is provided.
- A public, fictional AURA package with a real FreeTSA response and reproducible
  offline verification. The timestamp preimage is RFC 8785 JCS of the complete
  signed manifest, including its signature object.
- Base-schema checks for published manifest versions 1.0 and 1.1, with separate
  reporting of syntax, signatures, exact-byte integrity and archive-reference
  inspection. A DOI-shaped string does not establish archive resolution.
- Consistent rejection of unsupported versions and hash algorithms in Node and
  WebCrypto; explicit Ed25519 key-type enforcement in Node; rejection of lone
  Unicode surrogates in values and property names, including signature metadata.
- A generator that creates fictional v1.0 packages in a fresh separate directory
  and refuses overwriting. Historical signed fixtures remain unchanged.
- Current integrator instructions and explicit labels for historical formats.

## Compatibility and revoked keys

Only manifest versions `1.0` and `1.1` are supported. Historical formats,
including AUTHENTICA's private `0.1-pilot` format and the `0.1-test` fixtures,
receive an invalid overall result for unsupported version. Their signed bytes
remain unchanged and their signature dimension may still be inspected. This
does not establish that a historical signature was forged or determine its
legal value. The standard draft's `origin_proof_version: "0.1"`, the Python
demo and `0.1-pilot` are different historical formats.

Declared asset hashes require explicit `SHA3-256`. Valid v1.0 manifests do not
require v1.1 reference anchors. Correctly signed but malformed current-format
manifests fail schema/semantic checks; cryptographic validity does not override
those failures. Published schemas and existing signed/TSA evidence are unchanged.

Revocation policy is unchanged: a key listed as revoked in the supplied registry
causes an invalid overall result, even when its signature is mathematically
verifiable. An issuer-declared date before revocation does not override that
policy. A timestamp or version upgrade does not restore trust in a revoked key.
Registry provenance and freshness remain separate trust decisions.

Pilot processing counts must not be presented as counts of currently valid
evidence unless the relevant corpus, key status and results have been checked.
Any later reissue is a new declaration with its actual issuance date; it does
not modify or retroactively validate the original record.

## Verification and limits

The regression suite includes 47 shared signed scenarios through Node and
WebCrypto, with matching verdicts, and current-format generated vector checks.
Separate suites cover synthetic RFC 3161 evidence and the real public FreeTSA
fixture, including negative cases. Run `npm test` and `npm run test:timestamp`.

WebCrypto runs under Node in these tests; this is not browser UI testing or
independent-implementation reproduction. RFC 3161 does not establish qualified
eIDAS timestamp status. TSA revocation and long-term preservation, civil issuer
identity, legal authority, ownership and dossier completeness are not established.

See INTEGRATORS.md for the pending local date and identifier policy. Trusted
issuer identity, registry freshness and full leap-second validation remain unassessed. Base-schema date-time
formats remain annotations. See [strict verification](docs/STRICT_VERIFICATION.md)
and the [RFC 3161 guide](docs/RFC3161_TIMESTAMP.md).

## Archive references

Concept DOI: https://doi.org/10.5281/zenodo.21251286

Historical v1.1.0 archive: https://doi.org/10.5281/zenodo.22069698

The historical archive predates these additions and is preserved unchanged.
Reference a new version-specific DOI only after the archive has been reviewed
and published. Release and archive publication are separate from this source
preparation; no existing DOI, schema or signed reference anchor is rewritten.
