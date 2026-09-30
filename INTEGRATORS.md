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
JSON Schema 2020-12 vocabulary. This is not a general JSON Schema engine.
Unknown/legacy versions report `not_checked`, never a schema pass.
The supported TDM profile is checked separately by the existing profile logic;
other profiles are not certified by a base-schema pass.

## Run without contacting the maintainer

With Node.js 20 or newer, from this repository:

```sh
node bin/aura.js verify --manifest manifest.json --public-key public-key.pem --asset asset.txt --issuer issuer.json --json
node tests/run-tests.js
```

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
