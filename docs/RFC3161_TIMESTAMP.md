# Detached RFC 3161 timestamp verification — experimental Node CLI

This optional feature does not alter any signed AURA v1.0/v1.1 manifests.
It requires OpenSSL installed locally; the browser verifier cannot perform
this operation yet and remains independently usable for core AURA checks.

## Exact canonical preimage

Timestamp SHA-256 of UTF-8 RFC-8785-JCS of the **complete signed manifest**
(including the `signature` field). Do not confuse this preimage with the
JCS of the *unsigned* manifest that Ed25519 signs internally. A pretty-printed
or reordered JSON serialisation remains equivalent under this timestamp rule.

The companion SHA3-256 digest refers to the same complete canonical object.
It is NOT the same digest value as SHA-256. The published AURA v1.1
`prior_evidence.manifest_hash` field is a string with unspecified preimage
semantics, so using this SHA3-256 for linked evidence is only a proposed
convention until normatively defined and adopted.

## Generate the correct request

```sh
node bin/aura.js timestamp-request --manifest manifest.json --out manifest.tsq
```

The command uses OpenSSL `ts -query -sha256 -digest <canonical SHA256>` and
includes a nonce and requested TSA certificate. Never use the raw-file
command `openssl ts -query -data manifest.json` for this profile.

Send the DER request to a compatible TSA and preserve both files, plus
the CA trust chain. Example transport (check the provider's current documentation):

```sh
curl --fail --show-error -H 'Content-Type: application/timestamp-query' \
  --data-binary @manifest.tsq https://freetsa.org/tsr -o manifest.tsr
```

Obtain and independently authenticate the correct CA certificate from its
publisher; downloading an arbitrary PEM from the same untrusted location
does not by itself establish independent trust.

## Verify offline

```sh
node bin/aura.js verify --manifest manifest.json --public-key public-key.pem \
  --issuer issuer.json --timestamp-response manifest.tsr \
  --timestamp-query manifest.tsq --tsa-ca trusted-root.pem \
  --tsa-untrusted tsa-chain.pem --json
```

Optionally add `--asset my-asset.wav` to verify the AURA asset binding too.
OpenSSL verifies the RFC 3161 TimeStampResp against the computed canonical
digest, token signature, TSA certificate purpose and chain to the caller-
supplied anchor. The original TSQ additionally checks the nonce and policy.
The CLI parses a GMT/UTC OpenSSL timestamp and reports ISO 8601 UTC.
Unknown date formats fail closed rather than silently using local time.

The selected trust anchor's independent authenticity, acceptable policy,
certificate revocation, long-term validation and qualified eIDAS status
are NOT assessed. Time of issuance never backdates evidence to July 2026;
it establishes a bound at the TSA time only. It does not prove authorship,
legal ownership, real-world creation time or AI training use.

## Tests

```sh
npm test
node tests/test-timestamp-rfc3161.js
```

These tests use an ephemeral simulated local TSA; not external validation.
Public third-party TSA evidence is a separate release gate.
