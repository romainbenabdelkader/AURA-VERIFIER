import assert from 'node:assert/strict';
import fs from 'node:fs';
import { verifyAuraPackage } from '../src/verify-node.js';
import { sha3_256_hex } from '../src/sha3.js';

function readVector(name) {
  const dir = `tests/vectors/${name}`;
  return {
    assetBytes: fs.readFileSync(`${dir}/asset.txt`),
    manifestText: fs.readFileSync(`${dir}/manifest.json`, 'utf8'),
    publicKeyPem: fs.readFileSync(`${dir}/public-key.pem`, 'utf8'),
    issuerText: fs.readFileSync(`${dir}/issuer.json`, 'utf8'),
  };
}

assert.equal(
  sha3_256_hex(new Uint8Array()),
  'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
);
assert.equal(
  sha3_256_hex(new TextEncoder().encode('abc')),
  '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
);

const valid = await verifyAuraPackage(readVector('valid'));
assert.equal(valid.status, 'valid');
assert.equal(valid.assetHashOk, true);
assert.equal(valid.signatureOk, true);
assert.equal(valid.issuerKeyOk, true);

const invalidAsset = await verifyAuraPackage(readVector('invalid-asset'));
assert.equal(invalidAsset.status, 'invalid');
assert.equal(invalidAsset.assetHashOk, false);
assert.equal(invalidAsset.signatureOk, true);

const invalidSignature = await verifyAuraPackage(readVector('invalid-signature'));
assert.equal(invalidSignature.status, 'invalid');
assert.equal(invalidSignature.assetHashOk, true);
assert.equal(invalidSignature.signatureOk, false);

// Catalog claim: signed, timestamped declaration issued WITHOUT an asset file.
// Verified with no assetBytes -> signature checked, integrity not applicable.
const catalogClaim = await verifyAuraPackage({
  manifestText: fs.readFileSync('tests/vectors/catalog-claim/manifest.json', 'utf8'),
  publicKeyPem: fs.readFileSync('tests/vectors/catalog-claim/public-key.pem', 'utf8'),
  issuerText: fs.readFileSync('tests/vectors/catalog-claim/issuer.json', 'utf8'),
});
assert.equal(catalogClaim.status, 'valid');
assert.equal(catalogClaim.evidenceType, 'catalog_claim');
assert.equal(catalogClaim.signatureOk, true);
assert.equal(catalogClaim.integrityStatus, 'not_applicable');
assert.equal(catalogClaim.assetHashOk, null);
assert.equal(catalogClaim.issuerKeyPinOk, true);
assert.equal(catalogClaim.issuerKeyOk, true);

// A tampered catalog-claim signature must fail even with no asset file.
const tamperedManifest = JSON.parse(
  fs.readFileSync('tests/vectors/catalog-claim/manifest.json', 'utf8'),
);
tamperedManifest.catalog_claim.object_name = 'Tampered after signing';
const tampered = await verifyAuraPackage({
  manifestText: JSON.stringify(tamperedManifest),
  publicKeyPem: fs.readFileSync('tests/vectors/catalog-claim/public-key.pem', 'utf8'),
  issuerText: fs.readFileSync('tests/vectors/catalog-claim/issuer.json', 'utf8'),
});
assert.equal(tampered.status, 'invalid');
assert.equal(tampered.signatureOk, false);

// Revoked key: a cryptographically valid signature made with a key that the
// issuer registry lists as revoked (private_key_exposure) MUST fail — matched by
// fingerprint, not key_id, and it is a hard invalid, not a warning.
const revoked = await verifyAuraPackage({
  manifestText: fs.readFileSync('tests/vectors/catalog-claim/manifest.json', 'utf8'),
  publicKeyPem: fs.readFileSync('tests/vectors/catalog-claim/public-key.pem', 'utf8'),
  issuerText: fs.readFileSync('tests/vectors/catalog-claim/issuer-revoked.json', 'utf8'),
});
assert.equal(revoked.signatureOk, true); // signature itself is valid...
assert.equal(revoked.keyRevoked, true); // ...but the key is revoked
assert.equal(revoked.status, 'invalid'); // so overall verification is invalid
assert.equal(revoked.revocation.reason, 'private_key_exposure');
assert.ok(revoked.errors.some((e) => /revoked after private_key_exposure/.test(e)));

console.log('AURA verifier tests passed.');
