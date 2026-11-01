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

Duplicate JSON property handling before `JSON.parse`, cross-field issuer policy
and semantic date validation remain follow-up reviews. Base-schema date-time
formats remain annotations. See [strict verification](docs/STRICT_VERIFICATION.md)
and the [RFC 3161 guide](docs/RFC3161_TIMESTAMP.md).

## Archive references

Concept DOI: https://doi.org/10.5281/zenodo.21251286

Historical v1.1.0 archive: https://doi.org/10.5281/zenodo.22069698

The historical archive predates these additions and is preserved unchanged.
Reference a new version-specific DOI only after the archive has been reviewed
and published. Release and archive publication are separate from this source
preparation; no existing DOI, schema or signed reference anchor is rewritten.
