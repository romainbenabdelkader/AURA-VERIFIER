import assert from 'node:assert/strict';
import fs from 'node:fs';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { sha3_256_hex } from '../src/sha3.js';
import { createV11Package } from './helpers/v11-package.js';
import {
  checkManifestStructure,
  TDM_RIGHTS_RESERVATION_PROFILE,
} from '../src/schema-check.js';

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

const malformedPublishedV1 = checkManifestStructure({ aura_version: '1.0' });
assert.ok(malformedPublishedV1.errors.some((error) => /aura_uid/.test(error)));
assert.ok(malformedPublishedV1.errors.some((error) => /issuer/.test(error)));
assert.ok(malformedPublishedV1.errors.some((error) => /signature/.test(error)));

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

// Optional TDM rights-reservation profile: semantic constraints are checked in
// addition to cryptographic validity. A correctly signed value of the wrong JSON
// type must fail profile conformance even though its signature remains valid.
const tdmValidPackage = createV11Package({
  profile: TDM_RIGHTS_RESERVATION_PROFILE,
  declarations: { tdm_opt_out: true },
});
const tdmValidNode = await verifyAuraPackage(tdmValidPackage);
const tdmValidBrowser = await verifyAuraPackageBrowser(tdmValidPackage);
assert.equal(tdmValidNode.status, 'valid');
assert.equal(tdmValidNode.tdmRightsReservation.syntaxConformant, true);
assert.equal(tdmValidNode.tdmRightsReservation.declarationValid, true);
assert.equal(tdmValidNode.tdmRightsReservation.signatureBound, true);
assert.equal(tdmValidNode.tdmRightsReservation.assetBindingVerified, true);
assert.equal(tdmValidNode.tdmRightsReservation.profileVerified, true);
assert.equal(tdmValidBrowser.status, 'valid');
assert.equal(tdmValidBrowser.tdmRightsReservation.profileVerified, true);

const tdmWrongRegistry = JSON.parse(tdmValidPackage.issuerText);
tdmWrongRegistry.public_key_fingerprint_sha256 = '0'.repeat(64);
const tdmWrongRegistryResult = await verifyAuraPackage({
  ...tdmValidPackage,
  issuerText: JSON.stringify(tdmWrongRegistry),
});
assert.equal(tdmWrongRegistryResult.signatureOk, true);
assert.equal(tdmWrongRegistryResult.status, 'invalid');
assert.equal(tdmWrongRegistryResult.tdmRightsReservation.profileVerified, false);

const tdmWithoutAsset = await verifyAuraPackage({
  ...tdmValidPackage,
  assetBytes: null,
});
assert.equal(tdmWithoutAsset.status, 'warning');
assert.equal(tdmWithoutAsset.tdmRightsReservation.syntaxConformant, true);
assert.equal(tdmWithoutAsset.tdmRightsReservation.assetBindingVerified, false);
assert.equal(tdmWithoutAsset.tdmRightsReservation.profileVerified, false);

const tdmModifiedAsset = await verifyAuraPackage({
  ...tdmValidPackage,
  assetBytes: Buffer.from('Different TDM profile asset\n', 'utf8'),
});
assert.equal(tdmModifiedAsset.status, 'invalid');
assert.equal(tdmModifiedAsset.signatureOk, true);
assert.equal(tdmModifiedAsset.tdmRightsReservation.assetBindingVerified, false);
assert.equal(tdmModifiedAsset.tdmRightsReservation.profileVerified, false);

const tdmTamperedManifest = structuredClone(tdmValidPackage.manifest);
tdmTamperedManifest.declarations.tdm_opt_out = false;
const tdmTampered = await verifyAuraPackage({
  ...tdmValidPackage,
  manifestText: JSON.stringify(tdmTamperedManifest),
});
assert.equal(tdmTampered.status, 'invalid');
assert.equal(tdmTampered.signatureOk, false);
assert.equal(tdmTampered.tdmRightsReservation.profileVerified, false);

for (const invalidValue of ['true', 1, null, false, { reserved: true }]) {
  const invalidPackage = createV11Package({
    profile: TDM_RIGHTS_RESERVATION_PROFILE,
    declarations: { tdm_opt_out: invalidValue },
  });
  const nodeResult = await verifyAuraPackage(invalidPackage);
  const browserResult = await verifyAuraPackageBrowser(invalidPackage);

  assert.equal(nodeResult.signatureOk, true);
  assert.equal(nodeResult.status, 'invalid');
  assert.equal(nodeResult.tdmRightsReservation.syntaxConformant, false);
  assert.equal(nodeResult.tdmRightsReservation.profileVerified, false);
  assert.equal(browserResult.signatureOk, true);
  assert.equal(browserResult.status, 'invalid');
  assert.equal(browserResult.tdmRightsReservation.syntaxConformant, false);
  assert.equal(browserResult.tdmRightsReservation.profileVerified, false);
}

const missingTdmPackage = createV11Package({
  profile: TDM_RIGHTS_RESERVATION_PROFILE,
  declarations: { note: 'No TDM declaration.' },
});
const missingTdm = await verifyAuraPackage(missingTdmPackage);
assert.equal(missingTdm.signatureOk, true);
assert.equal(missingTdm.status, 'invalid');
assert.equal(missingTdm.tdmRightsReservation.syntaxConformant, false);
assert.equal(missingTdm.tdmRightsReservation.profileVerified, false);

console.log('AURA verifier tests passed.');
