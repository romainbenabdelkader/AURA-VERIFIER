import assert from 'node:assert/strict';
import fs from 'node:fs';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { sha3_256_hex } from '../src/sha3.js';
import { createV11Package } from './helpers/v11-package.js';

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

// Catalog claim: REAL signed manifest (rotated key authentica-pilot-737817cd43fa1f63),
// issued WITHOUT an asset file. Verified with no assetBytes against the active
// issuer.json -> signature checked, integrity not applicable. This is a v1.0
// manifest (no reference_anchor), so there is no digest pin.
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
assert.equal(catalogClaim.issuerKeyPinOk, null); // v1.0: no reference_anchor pin
assert.equal(catalogClaim.keyRevoked, false);
assert.equal(catalogClaim.issuerKeyOk, true);

// A tampered catalog-claim signature must fail even with no asset file.
const tamperedManifest = JSON.parse(
  fs.readFileSync('tests/vectors/catalog-claim/manifest.json', 'utf8'),
);
tamperedManifest.catalog_claim.title = 'Tampered after signing';
const tampered = await verifyAuraPackage({
  manifestText: JSON.stringify(tamperedManifest),
  publicKeyPem: fs.readFileSync('tests/vectors/catalog-claim/public-key.pem', 'utf8'),
  issuerText: fs.readFileSync('tests/vectors/catalog-claim/issuer.json', 'utf8'),
});
assert.equal(tampered.status, 'invalid');
assert.equal(tampered.signatureOk, false);

// Revoked key: verifying with the REAL old (compromised) public key + the active
// issuer.json, whose revoked_keys[] lists that key. Matched by fingerprint (not
// key_id) -> hard invalid, regardless of signature.
const revoked = await verifyAuraPackage({
  manifestText: fs.readFileSync('tests/vectors/catalog-claim/manifest.json', 'utf8'),
  publicKeyPem: fs.readFileSync('tests/vectors/catalog-claim/revoked-public-key.pem', 'utf8'),
  issuerText: fs.readFileSync('tests/vectors/catalog-claim/issuer.json', 'utf8'),
});
assert.equal(revoked.keyRevoked, true);
assert.equal(revoked.status, 'invalid');
assert.equal(revoked.revocation.reason, 'private_key_exposure');
assert.equal(revoked.revocation.supersededBy, 'authentica-pilot-737817cd43fa1f63');
assert.ok(revoked.errors.some((e) => /revoked after private_key_exposure/.test(e)));

// A current v1.1 package must verify in both engines using only locally supplied
// material. Replacing fetch with a failing trap makes any remote dependency a
// regression, including remote manifest/key resolution or telemetry over fetch.
const localV11 = createV11Package();
const originalFetch = globalThis.fetch;
let fetchCalls = 0;
globalThis.fetch = async () => {
  fetchCalls += 1;
  throw new Error('Network access is disabled during local verification tests.');
};

try {
  const nodeLocal = await verifyAuraPackage(localV11);
  assert.equal(nodeLocal.status, 'valid');
  assert.equal(nodeLocal.signatureOk, true);
  assert.equal(nodeLocal.assetHashOk, true);
  assert.equal(nodeLocal.issuerKeyPinOk, true);
  assert.equal(nodeLocal.issuerKeyOk, true);

  const browserLocal = await verifyAuraPackageBrowser(localV11);
  assert.equal(browserLocal.status, 'valid');
  assert.equal(browserLocal.signatureOk, true);
  assert.equal(browserLocal.assetHashOk, true);
  assert.equal(browserLocal.issuerKeyPinOk, true);
  assert.equal(browserLocal.issuerKeyOk, true);

  const manifestTampered = structuredClone(localV11.manifest);
  manifestTampered.declarations.note = 'Modified after signing.';
  const nodeManifestTampered = await verifyAuraPackage({
    ...localV11,
    manifestText: JSON.stringify(manifestTampered),
  });
  const browserManifestTampered = await verifyAuraPackageBrowser({
    ...localV11,
    manifestText: JSON.stringify(manifestTampered),
  });
  assert.equal(nodeManifestTampered.status, 'invalid');
  assert.equal(nodeManifestTampered.signatureOk, false);
  assert.equal(browserManifestTampered.status, 'invalid');
  assert.equal(browserManifestTampered.signatureOk, false);

  const modifiedAsset = Buffer.from('Modified asset content\n', 'utf8');
  const nodeAssetTampered = await verifyAuraPackage({ ...localV11, assetBytes: modifiedAsset });
  const browserAssetTampered = await verifyAuraPackageBrowser({
    ...localV11,
    assetBytes: modifiedAsset,
  });
  assert.equal(nodeAssetTampered.status, 'invalid');
  assert.equal(nodeAssetTampered.assetHashOk, false);
  assert.equal(browserAssetTampered.status, 'invalid');
  assert.equal(browserAssetTampered.assetHashOk, false);

  assert.equal(fetchCalls, 0);
} finally {
  globalThis.fetch = originalFetch;
}

console.log('AURA verifier tests passed.');
