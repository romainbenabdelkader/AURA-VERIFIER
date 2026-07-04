# AURA Verifier MVP

Independent verifier for AURA Evidence Packages.

This project verifies AURA manifests without requiring an AUTHENTICA account,
the AUTHENTICA backend, or any upload to `lockdna.tech`.

## What It Verifies

- SHA3-256 asset integrity
- RFC-8785-JCS canonicalized manifest signature
- Ed25519 signature
- issuer public key fingerprint, when `issuer.json` is provided
- issuer status, when `issuer.json` is provided

Proof scope:

> This verifies integrity, signature and timestamped declaration. It does not
> adjudicate ownership, authorship, licensing or infringement.

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

The web verifier runs locally in the browser. It does not upload the asset,
manifest, or public key to any server.

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

## Test Vectors

Generate fresh local test vectors:

```bash
npm run generate:test-vector
```

Run tests:

```bash
npm test
```

Included cases:

- valid asset + manifest + public key
- invalid asset against the same manifest
- invalid signature after manifest tampering

The private key used to generate test vectors is never written to disk.

## Security Notes

- Never include or publish an issuer private key.
- AURA public keys may be published and archived.
- This verifier checks technical facts only.
- It does not decide legal ownership, authorship, licensing, or infringement.
