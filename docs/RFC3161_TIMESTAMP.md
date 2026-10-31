# Detached RFC 3161 timestamp verification (experimental CLI)

This is an **optional Node CLI capability**, not a change to AURA v1.0/v1.1 manifests.
It does not yet run in the browser verifier. A signed manifest remains unchanged.

## Exact binding

The TSA timestamps the SHA-256 digest of the **exact bytes of the complete signed manifest JSON file**, including its Ed25519 signature object, with no canonicalization or rewriting. RFC 3161 messageImprint hashing does not replace AURA's internal SHA3-256 asset binding or Ed25519 manifest signature.

Create a request and keep it:

```sh
openssl ts -query -data manifest.json -sha256 -cert -out manifest.tsq
```

Send the DER request to your chosen TSA using its documented interface. Archive its **TimeStampResp** as `manifest.tsr`; do not substitute a bare CMS token in this implementation. The manifest, response, original query and trust material should be kept together.

Verify without network requests:

```sh
node bin/aura.js verify --manifest manifest.json --public-key public-key.pem --asset audio.wav --issuer issuer.json   --timestamp-response manifest.tsr --timestamp-query manifest.tsq   --tsa-ca trusted-root.pem --tsa-untrusted tsa-chain.pem --json
```

The `--asset` parameter is optional when the AURA evidence is a fileless catalogue declaration.

## Interpretation

The result separates `issuedAt` (issuer declared) from `timestamp.genTime` (TSA asserted).
`timestamp.status=verified` means OpenSSL accepted the response status, the digest against the exact manifest bytes, the token signature, the certificate's timestamping purpose and its chain up to the **caller-provided** CA trust anchor. If an original query is supplied, a second check validates the query (including its nonce).
A caller must independently choose and authenticate the CA certificate. A self-signed test CA accepted by this command does not make a timestamp independently trusted. TSA policy acceptability, certificate revocation, historical validation/renewal and eIDAS qualified status are **not assessed**. An independent timestamp only supports existence **no later than** its generation time; it does not backdate earlier claimed creation or establish legal ownership, identity or AI model usage.

A bad token, mismatched manifest, untrusted authority or request nonce mismatch causes the CLI verification to fail. The timestamp result does not conceal failure of the underlying AURA signature or asset hash checks.

## Regression tests

```sh
node tests/test-timestamp-rfc3161.js
```

The suite uses ephemeral LOCAL test keys and a LOCAL simulated TSA; it does **not** demonstrate acceptance of a public TSA and does not establish qualified eIDAS status. A public, externally anchored evidence package with reproducible trust chain is a separate release gate.
