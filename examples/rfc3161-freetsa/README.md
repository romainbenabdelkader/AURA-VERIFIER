# Public AURA-Timestamped vector: fictional content, real FreeTSA token

This directory is self-contained verification material. The asset is a short
fictional text, the issuer is fictional, and its Ed25519 private key was ephemeral
and never saved. **The RFC 3161 response is real**, obtained from the public
FreeTSA endpoint on 31 October 2026. No AUTHENTICA service or account was used.
The fixture UID is a fixed test value, never a production identifier.

The manifest uses the existing AURA v1.0 schema. No schema was changed. This
avoids inventing archive references for a v1.1 reference anchor. Both versions
are supported by the timestamp verifier. The separate Closing Doors v1.1
demonstrator was also checked, but its audio and personal declarations are not
part of this public fixture.

## Verify after obtaining the repository

With Node.js 20+ and OpenSSL 3.x on PATH, from the repository root:

```sh
node scripts/verify-timestamp-example.js > timestamp-report.json
```

Expected: exit code 0, top-level `status: "passed"`, CLI result `status: "valid"`,
`signatureOk: true`, `assetHashOk: true`, `timestamp.status: "verified"`,
`nonceCheck: "passed_against_supplied_request"`,
`auraTimestampedChecks: "technical_checks_passed"` and
`qualifiedEidas: "not_assessed"`. No network connection is needed to replay this.
The original successful run is recorded in `verification-report.json`; a new
report will have a different check time and may have different runtime versions.

Direct CLI equivalent:

```sh
node bin/aura.js verify \
  --manifest examples/rfc3161-freetsa/manifest.json \
  --asset examples/rfc3161-freetsa/asset.txt \
  --public-key examples/rfc3161-freetsa/public-key.pem \
  --issuer examples/rfc3161-freetsa/issuer.json \
  --timestamp-response examples/rfc3161-freetsa/manifest.tsr \
  --timestamp-query examples/rfc3161-freetsa/manifest.tsq \
  --tsa-ca examples/rfc3161-freetsa/cacert.pem \
  --tsa-untrusted examples/rfc3161-freetsa/tsa.crt --json
```

## Fixed expected values

| Item | Value |
|---|---|
| TSA UTC time | 2026-10-31T12:46:49.000Z |
| TSA serial | 0x0999C8BC |
| TSA policy OID | 1.2.3.4.1 |
| Request and response nonce | 0x4A22EE1AA1758B71 |
| SHA-256 of full signed JCS manifest | 7e6e47d9ae402ae9878e078f4420f8d15e9385be676eebe23d3fa0f4bc973553 |
| SHA3-256 of full signed JCS manifest | b2b40f936f74baafadd9828e1ee5e33ba2cfb9c26b08b13b6c20952886e35181 |
| SHA-256 of response file | f26bb8c611d4ae7fd6a755818b014cc9ea2c50762de61b11cdacec07e7c24c14 |

`expected.json` includes SHA-256 hashes of all nine evidence files. These are
file hashes; the TSA messageImprint hashes canonical JSON, not the formatted
`manifest.json` source bytes. `manifest.canonical.json` includes the signature.

## Certificate provenance and trust

Downloaded over HTTPS from the provider:

- [FreeTSA root](https://freetsa.org/files/cacert.pem), file SHA-256
  `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438`.
- [FreeTSA signing certificate](https://freetsa.org/files/tsa.crt), file SHA-256
  `8bfb0305bb64e2571ca507552ef3245cb1c2fee8728e0ff8689225081ea13467`.

Both match file fingerprints published on the [FreeTSA site](https://freetsa.org/index_en.php)
when the fixture was created. This is provider-origin HTTPS provenance, not an
out-of-band trust audit. The certificates are third-party public trust material;
inclusion is not an endorsement or evidence of qualified status.

Chain: Free TSA / TSA / www.freetsa.org -> Free TSA / Root CA / www.freetsa.org.
The TSA certificate is valid 2026-02-15 through 2040-02-02; the root is valid
2016-03-13 through 2041-03-07. Exact UTC validity bounds and DER certificate
fingerprints are in the report. DER certificate fingerprints differ from the
PEM file hashes above. Some OpenSSL versions warn that the supplied terminal
`tsa.crt` is not a CA; it is supplied as untrusted chain material, not as the
trust anchor. The separate timestampsign chain check and token checks must
still succeed. Never ignore a nonzero verification exit code.

The pinned root is an explicit trust choice. Neither bundled bytes nor their
hashes independently authenticate their owner. Revocation, acceptable TSA
policy, long-term preservation and qualified eIDAS status are not assessed.
The fixture establishes no identity, ownership, originality, human origin or
AI training use. See the [eIDAS distinction](../../docs/RFC3161_TIMESTAMP.md#rfc-3161-is-not-qualified-eidas-timestamping).

## Independently create another fictional example (optional network step)

Do not regenerate or overwrite the committed evidence. To create a new signed
manifest and nonce in a new directory:

```sh
node scripts/create-timestamp-example.js my-timestamp-example
curl --fail --show-error --max-time 60 \
  -H 'Content-Type: application/timestamp-query' \
  --data-binary @my-timestamp-example/manifest.tsq \
  https://freetsa.org/tsr -o my-timestamp-example/manifest.tsr
curl --fail --show-error --max-time 60 https://freetsa.org/files/cacert.pem -o my-timestamp-example/cacert.pem
curl --fail --show-error --max-time 60 https://freetsa.org/files/tsa.crt -o my-timestamp-example/tsa.crt
node bin/aura.js verify \
  --manifest my-timestamp-example/manifest.json --asset my-timestamp-example/asset.txt \
  --public-key my-timestamp-example/public-key.pem --issuer my-timestamp-example/issuer.json \
  --timestamp-response my-timestamp-example/manifest.tsr --timestamp-query my-timestamp-example/manifest.tsq \
  --tsa-ca my-timestamp-example/cacert.pem --tsa-untrusted my-timestamp-example/tsa.crt --json
```

Authenticate the provider's current certificates before relying on them. A new
request produces different keys, signature, imprint, nonce, serial and TSA time;
it will not match this fixture's `expected.json`. Only a 69-byte digest query was
sent for the committed fixture. Verification of preserved evidence is free and
offline; future access to a public TSA depends on that provider's availability
and terms, not on AUTHENTICA.
