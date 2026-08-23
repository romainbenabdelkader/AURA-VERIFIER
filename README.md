# AURA Verifier MVP

Independent verifier for AURA Evidence Packages.

Current release: v1.1.0.

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

## CLI

```bash
./bin/aura.js verify \
  --asset tests/vectors/valid/asset.txt \
  --manifest tests/vectors/valid/manifest.json \
  --public-key tests/vectors/valid/public-key.pem
```

JSON output:

```bash
./bin/aura.js verify \
  --asset tests/vectors/valid/asset.txt \
  --manifest tests/vectors/valid/manifest.json \
  --public-key tests/vectors/valid/public-key.pem \
  --json
```

With issuer metadata:

```bash
./bin/aura.js verify \
  --asset tests/vectors/valid/asset.txt \
  --manifest tests/vectors/valid/manifest.json \
  --public-key tests/vectors/valid/public-key.pem \
  --issuer tests/vectors/valid/issuer.json
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
