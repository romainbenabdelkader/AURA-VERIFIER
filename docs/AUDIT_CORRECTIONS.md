# Verification corrections in v1.2.0

The checks documented here do not establish independent audit or CAVP
validation. Existing signed evidence, frozen schemas and archived ZIPs are not
rewritten. Use the exact reviewed commit and published archive coordinates once
a release actually exists.

## SHA3-256 block-boundary correction

The previous `src/sha3.js` allocated an extra block when input length was
`135 + 136*k` bytes. At that boundary the domain suffix and the final padding bit
must share the same last byte (FIPS 202, sections 5.1 and 6.1). The corrected
allocation does this. The audit found identical affected code in verifier
archives 1.0.1, 1.0.2 and 1.1.0, and upstream commit
`92b89f210f104cbdbf831cf054bac4d3e87ddcad`.

For 135 ASCII `a` bytes the standard digest is:

```
8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9
```

The affected implementation instead returned:

```
d04ad3ea6dd566c44bddee03ae94243120a163b4515a0dee15009e3be94bc493
```

The corrected verifier accepts a correctly signed package declaring the standard
digest and rejects one declaring the latter value. It never labels the old value
as SHA3-256 or silently falls back to it. This is not evidence of an Ed25519
forgery or a demonstrated hash collision.

Inventory affected inputs using their exact original bytes and an external
SHA3-256 implementation. The full-manifest SHA3 digest can also be affected when
the canonical signed manifest has the boundary length. The RFC 3161 SHA-256
imprint path is separate. Do not assume every historical proof was affected.
Preserve originals; a later attestation must use its actual date and reference
the earlier evidence, without claiming to recreate its historical timestamp.

## Supplied issuer registry validation

`registryValidation` reports `pass`, `invalid` or `not_checked`, with field
errors. An explicitly supplied JSON null, scalar or array is invalid; it is
not treated as an absent registry. Invalid JSON or duplicate property names
remain input errors.

The current record requires both recognized fingerprints as 64-character
lowercase hexadecimal strings and a non-empty string status. A supplied
algorithm must be Ed25519. Unknown status strings retain the existing warning
policy; they are not treated as active. Optional key/revocation labels must be
non-empty strings when present. Unknown extension fields remain allowed.

`revoked_keys` may be omitted (the existing profile treats omission as an empty
list). If present it must be an array of objects. Each entry must have at least
one recognized SHA-256 or SHA3-256 fingerprint; every supplied recognized
fingerprint must have the correct format. A key label alone is insufficient.
Optional entry status must be `revoked`. A malformed entry invalidates the
registry even if other entries are well formed.

An invalid registry causes an invalid overall result and
`keyStatusCheck: "invalid_registry"`; its revocation list is not used to assert
non-revocation. `keyRevoked: false` alone is never a trusted non-revocation
assertion. The source remains caller-supplied. Authenticity, freshness and
temporal applicability of registry metadata are still not assessed.

Known revoked keys remain rejected under the current acceptance policy.
`signatureOk` remains the mathematical signature dimension, while
`historicalValidity` is explicitly `not_assessed`. A declared issuance date or
a timestamp does not automatically override that policy. The browser wording
now describes the policy without deciding every historical proof's value.

## Consistent signature encoding

Both engines require canonical RFC 4648 standard Base64: standard alphabet,
required padding, zero unused pad bits and no whitespace inside the encoded
signature. The decoded Ed25519 signature must contain exactly 64 bytes.
Base64URL, omitted or extra padding, trailing junk and ignored characters are
rejected consistently. PEM line wrapping is still removed before decoding its
Base64 content. No signed input is normalized or rewritten.

This deliberately tightens prior acceptance, including unpadded signatures
previously accepted by both engines. Preserve such original documents if an
integrator needs a historical diagnostic; do not silently re-encode them and
claim unchanged full-manifest hashes or timestamp preimages.

## Human-readable results

The TDM signature-binding line now reports yes/no/not checked for that dimension
instead of reusing a revocation message. Invalid registry structure is displayed
explicitly. Neither correction changes the meaning of a rights declaration or
establishes issuer authority, ownership, automated discovery or legal effect.

The former `Issuer status` label is now `Current registry key status`, explicitly
qualified as a supplied snapshot. It describes the current registry record, not
the historical signing key being examined. An active current record and a revoked
examined key may coexist; revocation still causes an invalid overall result.

## Declared-date policy for v1.2.0

The syntax, calendar and offset checks are retained without comparison to the
local system clock. A syntactically valid future date receives no future-date
warning. A pass is not an attestation of the issuance time. An application-level
clock warning can be considered separately without changing signed evidence or
presenting a local clock as a trusted timestamp source.

## Regression and browser reproduction

Run `npm test`, `npm run test:timestamp` and `npm run demo:offline`.
For actual browser UI tests:

```sh
npm ci --ignore-scripts
npx playwright install --with-deps chromium firefox webkit
npm run test:browser
```

Playwright is a pinned development dependency only; the verifier runtime remains
dependency-free. The CI browser job runs the same script. Reviewers may set
`AURA_PLAYWRIGHT_MODULE` to an installed module and `AURA_CHROME_EXECUTABLE` to
an installed Chrome executable. `AURA_BROWSER_REPORT` optionally saves results.
The test server binds loopback only and external browser requests are blocked.
WebKit testing is not a claim to have tested the Safari application.

The 137 NIST CAVP SHA3-256 short-message vectors are preserved as data with their
source archive and member hashes. Their expected values are not generated by
AURA. A further 1,025 binary input sizes are compared to Node's native crypto.
The package helper also uses native SHA3, avoiding a shared erroneous oracle.
Forty-four package scenarios exercise both engines and each real browser,
including valid native-hash packages and the rejected historical wrong digest.
Human-report assertions are included. Full-manifest SHA3 and SHA-256 outputs are
checked separately. Existing historical and TSA fixtures remain unchanged.

Sources:

- FIPS 202: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- NIST CAVP vectors: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
- Base64 policy: https://www.rfc-editor.org/rfc/rfc4648.html#section-3

These checks provide reproducible engineering evidence. They do not replace a
third-party review, a full historical-corpus audit or formal algorithm validation.
