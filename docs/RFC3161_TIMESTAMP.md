# Detached RFC 3161 timestamp verification — Node CLI

This optional feature does not alter any signed AURA v1.0/v1.1 manifests.
It requires OpenSSL installed locally; the browser verifier cannot perform
this operation yet and remains independently usable for core AURA checks.

## Reproduce a real third-party timestamp for free

Prerequisites: Node.js 20 or newer and OpenSSL 3.x available as `openssl` on
PATH. No npm dependencies, AUTHENTICA account, private key or API key are needed.
From the repository root:

```sh
node scripts/verify-timestamp-example.js > timestamp-report.json
```

The [public fixture](../examples/rfc3161-freetsa/README.md) contains fictional
content and a genuine FreeTSA token. Verification uses only local files and
does not contact FreeTSA or AUTHENTICA. Expect exit code 0 and `status: "passed"`.
The report records source/evidence hashes, UTC time, exact commands, exit codes,
stdout/stderr, TSA chain and the complete CLI result. A failed check returns
nonzero; do not interpret the mere presence of a report as success.

`expected.json` pins the checked-in bytes, not an independently trusted identity.
Authenticate the source of the repository and the TSA anchor separately. Tests
use normal current-time certificate validation: they will fail when certificates
expire. Do not disable validation to preserve a green test. Historical or
long-term validation requires a separately designed preservation process.

On macOS the system `openssl` may be LibreSSL; select OpenSSL 3.x on PATH.
If a relocated OpenSSL installation cannot find its default configuration,
provide an explicit local configuration with `OPENSSL_CONF`. The recorded
macOS run used `OPENSSL_CONF=/dev/null` with the CA supplied explicitly. This
does not disable signature, purpose, chain or certificate-date checks. Only the
synthetic-test CA extensions were made explicit; no trust checks were relaxed.

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
The policy is reported numerically. The text-rendering command alone uses an
empty OpenSSL configuration to avoid machine-local OID aliases such as
`tsa_policy1`. Cryptographic verification retains the caller's configuration
and security policy; this reporting normalization does not relax trust checks.

The selected trust anchor's independent authenticity, acceptable policy,
certificate revocation, long-term validation and qualified eIDAS status
are NOT assessed. Time of issuance never backdates evidence to July 2026;
it establishes a bound at the TSA time only. It does not prove authorship,
legal ownership, real-world creation time or AI training use.

`auraTimestampedChecks: technical_checks_passed` is a report of this package's
checks, not certification of an implementation or of the issuer. Read the
individual dimensions too: asset integrity may be unverified when no asset
was supplied; the nonce is not assessed without the original query; issuer
identity and archive resolution remain separate. An independently timestamped
test declaration is still a test declaration.

## RFC 3161 is not qualified eIDAS timestamping

RFC 3161 specifies a timestamp protocol and token format. Successful OpenSSL
verification establishes a cryptographic binding relative to the chosen trust
anchor. It does not audit the provider or grant a legal qualification.

Under [eIDAS Article 41](https://eur-lex.europa.eu/eli/reg/2014/910), an electronic
timestamp must not be denied legal effect solely because it is electronic or
non-qualified. The specific presumption of accuracy of time and integrity is
reserved to qualified timestamps. A qualified service's relevant status must
be established through the applicable [EU trusted list](https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists)
and the relevant requirements, including Article 42. A valid certificate or
RFC 3161 token alone is insufficient. This example **does not establish qualified
eIDAS status** and always reports `qualifiedEidas: not_assessed`.

An exact-byte hash does not identify a transcoded or perceptually similar file.
No signed declaration is turned into proof of its truth, rights or human origin.
The hash and UID do not prove that a model trained on the asset.

## Tests

```sh
npm test
npm run test:timestamp
```

The timestamp suite has two parts:

- `tests/test-timestamp-rfc3161.js`: ephemeral synthetic TSA, positive checks
  and rejection of modified manifests, wrong tokens, untrusted CA, mismatched
  nonce, corrupt signatures and unsafe paths. The TSA is not a public authority.
- `tests/test-timestamp-public.js`: the preserved real public TSA response and
  end-to-end CLI checks, including canonical JSON reformatting, altered content,
  wrong issuer key, mismatched nonce, corrupt/missing token, incomplete trust
  parameters and explicit reporting when timestamp/query evidence is omitted.

CI runs both parts on Node 20 and 22 without requesting new timestamps. The
public vector is independently replayable; publication and CI success must not
be represented as a completed review by an external developer or institution.
