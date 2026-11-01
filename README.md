# AURA Verifier MVP

Integrator instructions and limits: [INTEGRATORS.md](INTEGRATORS.md).

Independent verifier for AURA Evidence Packages.

Current release: v1.1.0.

This checkout includes unreleased validation fixes. See
[strict verification and compatibility](docs/STRICT_VERIFICATION.md).
Supported manifest versions are exactly `1.0` and `1.1`.

This project verifies AURA manifests without requiring an AUTHENTICA account,
the AUTHENTICA backend, or any upload to `lockdna.tech`.

## What It Verifies

- SHA3-256 asset integrity
- RFC-8785-JCS canonicalized manifest signature
- Ed25519 signature
- issuer public key fingerprint, when `issuer.json` is provided
- issuer status, when `issuer.json` is provided
- syntax and signed declaration semantics for the optional
  `AURA_TDM_RIGHTS_RESERVATION_V1` profile

Proof scope:

> This verifies integrity and the issuer signature. The issuance time is
> issuer-declared unless independent timestamp evidence is provided. It does not
> prove authorship, ownership, entitlement, grounding, citation or usage
> completeness.

## Detached RFC 3161 timestamp (Node CLI only)

This optional extension uses a **locally installed OpenSSL** binary and is **not**
implemented in the JavaScript-only browser verifier. The base AURA verifier
continues to run offline in both Node and WebCrypto.

The timestamp digest is SHA-256 of the RFC 8785 JCS canonical representation
of the **complete signed manifest**, including its signature object. Use
`node bin/aura.js timestamp-request --manifest manifest.json --out manifest.tsq`
to generate a query. Do NOT use `openssl ts -query -data manifest.json`:
that hashes noncanonical source bytes.

A separate SHA3-256 digest of that same canonical object is reported for
reference. It is NOT the same hash as the TSA's SHA-256 messageImprint.
The published v1.1 `prior_evidence.manifest_hash` schema does not yet
define its hash preimage, so this is a candidate mapping, not a normative
equivalence. No eIDAS qualification, revocation or TSA policy suitability
is inferred by this extension.

Reproduce verification of the committed, **real FreeTSA response over fictional
data**, without an account or network request:

```sh
node scripts/verify-timestamp-example.js
```

Requires Node.js 20+ and OpenSSL 3.x on PATH. A report with `status: "passed"`
and exit code 0 confirms the documented technical checks relative to the
supplied FreeTSA root. It is **not qualified eIDAS timestamp certification**.
The test issuer is fictional and must not be used in production.

See the [public vector and expected results](examples/rfc3161-freetsa/README.md)
and [RFC 3161 timestamp guide](docs/RFC3161_TIMESTAMP.md).

## CLI

```bash
./bin/aura.js verify \
  --asset examples/rfc3161-freetsa/asset.txt \
  --manifest examples/rfc3161-freetsa/manifest.json \
  --public-key examples/rfc3161-freetsa/public-key.pem
```

JSON output:

```bash
./bin/aura.js verify \
  --asset examples/rfc3161-freetsa/asset.txt \
  --manifest examples/rfc3161-freetsa/manifest.json \
  --public-key examples/rfc3161-freetsa/public-key.pem \
  --json
```

With issuer metadata:

```bash
./bin/aura.js verify \
  --asset examples/rfc3161-freetsa/asset.txt \
  --manifest examples/rfc3161-freetsa/manifest.json \
  --public-key examples/rfc3161-freetsa/public-key.pem \
  --issuer examples/rfc3161-freetsa/issuer.json
```

## Web Verifier

The web verifier performs cryptographic verification locally in the browser. In
local-file mode it does not upload the asset, manifest, public key or issuer
metadata, and it does not require an account, analytics service or verification
telemetry.

```bash
npm run serve:web
```

Then open:

```text
http://localhost:5177/web/
```

Drop or select:

- asset file
- AURA manifest JSON
- public key PEM
- optional issuer JSON

When the page is opened with `?manifest=...` or `?uid=...&src=...`, the verifier
can fetch a manifest and a manifest-pinned archived public key as a convenience.
Those requests are optional and are not offline: the remote servers may record
ordinary access metadata such as the requester's IP address, request time and
requested URL. For privacy-sensitive verification, open the verifier without
remote-loading parameters and supply the evidence and trust material as local
files.

A locally supplied `issuer.json` permits issuer-fingerprint, status and
revocation checks without a network request. The result reflects the freshness
of that local registry snapshot; update the snapshot separately when current
status is required.

## Test Vectors

Generate fresh local test vectors:

```bash
npm run generate:test-vector
```

The generator creates fictional v1.0 packages under `generated/test-vectors/`
and refuses an existing destination. To choose another destination:

```bash
node scripts/generate-test-vector.js /path/to/a-new-directory
```

The committed `tests/vectors/valid`, `invalid-asset` and `invalid-signature`
fixtures use the historical `0.1-test` version. Their signed bytes are preserved
as regression evidence; that version now produces an invalid overall result.
Use the public v1.0 example above or the newly generated packages for integration.

Run tests:

```bash
npm test
```

Run the reproducible local/offline verification demonstration:

```bash
npm run demo:offline
```

The demonstration blocks network access, runs both verification engines and checks
rejection of manifest and asset tampering. See
[`docs/OFFLINE_PRIVACY_DEMO.md`](docs/OFFLINE_PRIVACY_DEMO.md).

Included cases:

- valid asset + manifest + public key
- invalid asset against the same manifest
- invalid signature after manifest tampering
- valid AURA v1.1 verification through both Node and browser engines with remote
  access blocked
- confirmation that locally supplied evidence and trust material cause no
  remote key or manifest resolution
- acceptance of a correctly signed, asset-bound TDM rights-reservation profile
- rejection of signed TDM profile claims whose declaration is missing or is not
  exactly the JSON boolean `true`
- rejection of unknown manifest versions and unsupported/missing hash algorithms
- rejection of an Ed448 key/signature labeled Ed25519 by both engines
- rejection of lone Unicode surrogates in values and property names, including
  the signature object, while valid surrogate pairs continue to verify

For the optional TDM rights-reservation profile, the verifier reports profile
conformance separately from issuer authority, automated discoverability or
receipt, and legal effect. Those matters are not established by cryptographic
verification.

The private key used to generate test vectors is never written to disk.

## Security Notes

- Never include or publish an issuer private key.
- AURA public keys may be published and archived.
- This verifier checks technical facts only.
- It does not prove authorship, ownership, entitlement, licensing, infringement,
  grounding, citation or usage completeness.
- The issuance time it displays is issuer-declared unless independent timestamp
  evidence is provided.
- Remote convenience loading may create ordinary access logs at the contacted
  servers; it is not required for locally supplied verification material.

## Citation And Archive

Concept DOI (all versions):
https://doi.org/10.5281/zenodo.21251286

Latest archived version — AURA-VERIFIER v1.0.2:
https://doi.org/10.5281/zenodo.22063259
