# AURA integrator self-check

This local verifier checks a supplied evidence package. A successful report is
not certification, endorsement, or a test of every behavior of an implementation.

## Versions and pinned sources

AURA-STANDARD release v1.2.1 (DOI 10.5281/zenodo.22071523) retains the
manifest schemas v1.0.0 and v1.1.0. Release and manifest versions differ.
Source: https://github.com/romainbenabdelkader/AURA-STANDARD/tree/91b2d51fd6808c6882728c6104e75becee2b9578

`src/base-schemas.js` embeds the two schema objects from `schema/`.
The checker implements their assertion keywords: type, const, required,
properties, pattern, minLength, items and local $ref. Additional properties
remain allowed. The date-time format is annotation-only, as in the default
JSON Schema 2020-12 vocabulary. Separate verifier policy checks the declared
date calendar/offset and identifier consistency; see below. This is not a general JSON Schema engine.
Only manifest versions `1.0` and `1.1` are supported. Unknown, missing and
historical versions produce an invalid overall result. Their base-schema
dimension may still report `not_checked`; it never establishes version support.
Asset hashes require an explicit `SHA3-256` algorithm; other declarations are
rejected and their integrity dimension is not reported as verified.
Node requires an Ed25519 public key, matching the WebCrypto import policy.
Lone Unicode surrogates in property names and values are rejected under
RFC 8785 section 3.2.2.2. See [compatibility notes](docs/STRICT_VERIFICATION.md).
The supported TDM profile is checked separately by the existing profile logic;
other profiles are not certified by a base-schema pass.

## Run without contacting the maintainer

With Node.js 20 or newer, from this repository:

```sh
node bin/aura.js verify --manifest manifest.json --public-key public-key.pem --asset asset.txt --issuer issuer.json --json
node tests/run-tests.js
```

For a committed current-format example, use the four input files under
`examples/rfc3161-freetsa/`. The Python `aura-core` and `aura-cli` repositories
are historical v0.1 demonstrations, not current-format JCS signing SDKs.
To create fictional v1.0 packages locally, run
`node scripts/generate-test-vector.js /path/to/a-new-directory`.
This is a test generator, not an issuer onboarding or production signing tool.

Exit codes: 0 valid under the local checks; 1 warnings/incomplete checks; 2 invalid
or input error. The browser verifier uses the same schema check.
No external files are uploaded by these verification functions.

Read the dimensions independently:

- `schemaValidation`: pass/fail/not_checked, schema ID and exact field errors.
- `signatureOk`: signature verification, including the signed reference anchor.
- `integrityStatus`: exact asset bytes verified, mismatch, not checked or N/A.
- `issuerKeyPinOk`: supplied public key compared with the signed SHA3-256 pin.
- `archiveResolution`: not_checked. Presence of a DOI is not proof it resolves,
  or that its archived bytes match the declared digest.
- `archiveReferences`: syntax-only inspection, with separate notices for URNs
  and other non-bare-DOI references. `doi_like` does not establish registration,
  resolution or byte integrity. Notices do not change schema or cryptographic
  validity; remote archive verification remains outside this offline check.
- `issuerIdentity`: not_assessed. Supplied issuer.json is metadata, not
  independent evidence that the signer represents a named organization.

The generated regression fixtures use local:test identifiers and synthetic
archive digests solely for syntax/cryptography tests; never copy them into
production evidence. They do not pass archive verification, which is not run.

## Reference anchor

v1.0 does not require an anchor. v1.1 requires all three blocks and every required
field in the pinned schema. Never fill unavailable coordinates with placeholders.
The published reference-anchor template points to older, fixed reference
artifacts (standard v1.1.0 and verifier v1.0.1). Those coordinates are not the
same as the current standard release DOI. Use a mutually consistent artifact,
version, digest and archive reference; changing a release label alone is not enough.

The template describes `verifier` as the reference AURA-VERIFIER artifact. The
schema fixes its name to AURA-VERIFIER. This is not a requirement to rename an
independent tool or claim that it ran. Identify the independent implementation
separately, and request clarification if its intended anchor semantics differ.
This guide does not change the published schema or resolve governance questions.

## Reproducible feedback

Generate a non-sensitive test asset and keep the asset, signed manifest, public
key and issuer.json together. Share them with the JSON report, verifier commit,
schema version and intended conformance level. Never share private keys.
Run negative tests for modified assets and manifests and for malformed but
correctly signed manifests. Our suite exercises both Node and WebCrypto paths.

Suggested description: “Independent implementation of the open AURA
specification. Tested with [verifier commit] against [schema version].
This is not an official AURA service, certification or endorsement.”

No certification registry or new label policy is introduced by this tool.


## Local semantic and trust policy

The frozen schemas are unchanged. `issuedAtValidation` is separate from the
base-schema result: the verifier requires RFC 3339 syntax (T/t and Z/z accepted),
seconds and an explicit offset, and checks calendar dates and component ranges.
It does not compare the declared date with a trusted clock, certificate lifetime
or revocation time, and does not establish the date's truth. Leap-second inputs
are not fully assessed and produce a warning, not a verified date. Negative-zero
offsets are preserved. No signed input is normalized or rewritten.

Present issuer identifiers (`issuer.id`, `reference_anchor.issuer_key.issuer_id`,
`issuer.json.issuer`, `issuer.json.issuer_id`) must be non-empty strings and agree
exactly. Present signed key identifiers (`issuer.key_id` and the anchor's
`key_id`) must agree. Optional missing v1.0 identifiers are not invented.
`issuerIdentifiers` reports these comparisons only, never civil or organizational
identity. The supplied registry's current key_id need not equal an old signed
key_id: rotation and revocation are still checked by key fingerprints.

`keyStatusCheck` distinguishes absence of a registry, presence on its revoked
list, and absence from that supplied list. A matching current-key record with
status revoked is also refused. `registryTrust` explicitly leaves authenticity
and freshness unassessed. The legacy keyRevoked boolean is retained; false alone
must not be interpreted as a fresh trusted non-revocation assertion.

Parsing duplicate names and semantic policy failures do not imply signature
forgery. Correctly signed but inconsistent records can have signatureOk=true and
an invalid overall result. Keep original evidence for historical inspection.


## Audit corrections and encoding compatibility

See [AUDIT_CORRECTIONS.md](docs/AUDIT_CORRECTIONS.md) before adopting this source
revision. It fixes the SHA3-256 block boundary, validates the supplied registry,
and consistently rejects non-canonical signature encodings. `registryValidation`
is a structural result, not a trust assertion. An invalid registry reports
`keyStatusCheck: invalid_registry`; never infer non-revocation from the boolean
`keyRevoked` alone. Historical validity remains explicitly unassessed.

Run the actual browser suite with `npm run test:browser` after installing the
pinned development dependency and its browsers as described in that guide.
