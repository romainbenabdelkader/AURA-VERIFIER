# AURA-VERIFIER v1.2.0

The source version is 1.2.0. GitHub Releases and the version-specific Zenodo
record establish publication; package.json alone does not. These notes describe
the changes since archived v1.1.0. Release packaging and archive publication
are separate from the source version recorded here.

## Verification changes

- Detached RFC 3161 verification through the Node CLI and local OpenSSL:
  binding to JCS of the complete signed manifest, supplied certificate-chain
  and signature verification, and nonce comparison when the request is supplied.
  The repository includes a real FreeTSA response over fictional public data.
- Base-schema validation for manifest versions 1.0 and 1.1, with separate
  reporting of schema, signature, exact-byte integrity, issuer metadata and
  archive-reference syntax. Unknown and historical versions are unsupported.
- Rejection of unsupported asset-hash algorithms, non-Ed25519 keys and lone
  Unicode surrogates, without modifying frozen schemas or signed evidence.
- Rejection of duplicate JSON property names, including escaped aliases;
  malformed or contradictory recognized hashes; inconsistent present issuer
  identifiers and signed key labels; and invalid supplied registry structures.
- Calendar and offset checks for declared issuance dates. These checks do not
  establish an independently attested time. Leap-second handling, comparison
  with a trusted clock, and registry temporal applicability remain unassessed.
  No comparison with the local clock or future-date warning is added in v1.2.0.
- Explicit reporting of missing asset checks, including catalogue declarations,
  and of missing, invalid or caller-supplied key-status information.

## Audit corrections

- Correct SHA3-256 padding for inputs whose length is 135 modulo 136. The old
  code found in archived verifier 1.0.1, 1.0.2 and 1.1.0 produced an incorrect
  digest at this boundary. Standard digests are now accepted and that erroneous
  digest is rejected. No historical evidence is rewritten or silently repaired.
- Require canonical padded standard Base64 and exactly 64 decoded bytes for an
  Ed25519 signature in both engines. Previously accepted encodings, including
  omitted padding, can now fail. Preserve their original bytes for diagnosis.
- Report invalid registry structure separately from registry trust. Authenticity,
  freshness, identity and authority are not established by a structural pass.
- Correct the human-readable TDM signature-binding line and distinguish current
  revocation acceptance policy from unassessed historical validity.
- Label the supplied snapshot's current key status separately from the examined
  key's revocation status; an active current record does not override revocation.

See [audit corrections](docs/AUDIT_CORRECTIONS.md) for exact behavior, affected
boundaries, reproduction instructions and remaining limits.

## Compatibility and historical evidence

Supported manifest versions remain 1.0 and 1.1. AUTHENTICA's private 0.1-pilot,
the 0.1-test fixtures, the standard's historical origin_proof_version 0.1 and
the Python demonstrations are distinct formats. Unsupported versions receive
an invalid overall result; their mathematical signature dimension can still be
inspected. An invalid overall result does not by itself establish forgery or
decide a historical document's legal value.

A key listed as revoked in the supplied registry remains rejected under the
current acceptance policy. An issuer-declared earlier date or a later timestamp
does not override that policy. Historical validity is not assessed. The date
and reason stated in a registry do not independently establish the actual date
of a key compromise. Registry authenticity and freshness remain separate.

Import simulations and processing counts do not establish counts of issued or
currently valid evidence. Such claims require an inventory and verification of
the relevant corpus. Any reissue is a new declaration with its actual date and
an explicit relationship to the preserved original.

## Tests and reproduction

The prepared source includes 137 official NIST SHA3-256 short-message vectors,
1,025 further native-crypto comparisons, and 44 audit package scenarios shared
between Node and WebCrypto. Existing strict-format, input-ambiguity, semantic,
generated-vector, RFC 3161 and offline suites remain included. Test-family counts
must not be added together as independent packages or production evidence.

The source validation record reports passing suites under Node 20.20.2,
22.23.4 and 24.22.1 with OpenSSL 3.6.2. An actual browser suite exercises the
44 audit scenarios and NIST vectors in Chromium, Firefox and Playwright WebKit,
with external requests blocked. WebCrypto-under-Node tests and real browser
tests are distinct; Playwright WebKit is not the Safari application.

Run `npm test`, `npm run test:timestamp` and `npm run demo:offline`.
See docs/AUDIT_CORRECTIONS.md for the pinned browser dependencies and
`npm run test:browser`. Each final release must be tied to its own exact
commit, archive checks and recorded results. These tests are engineering
evidence; they do not establish CAVP validation or certification.

## Limits and archives

Archive references are inspected syntactically; DOI resolution and remote bytes
are not verified by the offline verifier. Civil identity, authority, ownership,
dossier completeness, registry freshness, long-term timestamp preservation and
TSA revocation are not established. RFC 3161 verification does not establish
qualified eIDAS timestamp status. Unrecognized profiles are not certified.

Concept DOI: https://doi.org/10.5281/zenodo.21251286

Historical v1.1.0 archive: https://doi.org/10.5281/zenodo.22069698

The historical archive is preserved unchanged. Add a new version-specific DOI
and archive digest only after an actual reviewed publication. Never rewrite an
old signed reference anchor to point to new source bytes. See INTEGRATORS.md,
docs/STRICT_VERIFICATION.md and docs/RFC3161_TIMESTAMP.md.
