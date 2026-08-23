import assert from 'node:assert/strict';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { createV11Package } from '../tests/helpers/v11-package.js';

const localPackage = createV11Package();
const originalFetch = globalThis.fetch;
let networkRequests = 0;

globalThis.fetch = async () => {
  networkRequests += 1;
  throw new Error('Network access is disabled for this demonstration.');
};

try {
  const nodeResult = await verifyAuraPackage(localPackage);
  const browserResult = await verifyAuraPackageBrowser(localPackage);

  const modifiedManifest = structuredClone(localPackage.manifest);
  modifiedManifest.declarations.note = 'Modified after signing.';
  const manifestTampering = await verifyAuraPackage({
    ...localPackage,
    manifestText: JSON.stringify(modifiedManifest),
  });

  const assetTampering = await verifyAuraPackage({
    ...localPackage,
    assetBytes: Buffer.from('Modified asset content\n', 'utf8'),
  });

  assert.equal(nodeResult.status, 'valid');
  assert.equal(browserResult.status, 'valid');
  assert.equal(manifestTampering.status, 'invalid');
  assert.equal(manifestTampering.signatureOk, false);
  assert.equal(assetTampering.status, 'invalid');
  assert.equal(assetTampering.assetHashOk, false);
  assert.equal(networkRequests, 0);

  console.log(JSON.stringify({
    demonstration: 'AURA local/offline privacy verification',
    auraVersion: '1.1',
    verifierVersion: '1.1.0',
    networkAccess: 'blocked',
    networkRequests,
    nodeEngine: {
      status: nodeResult.status,
      signatureOk: nodeResult.signatureOk,
      assetHashOk: nodeResult.assetHashOk,
      issuerKeyOk: nodeResult.issuerKeyOk,
    },
    browserEngine: {
      status: browserResult.status,
      signatureOk: browserResult.signatureOk,
      assetHashOk: browserResult.assetHashOk,
      issuerKeyOk: browserResult.issuerKeyOk,
    },
    tamperingChecks: {
      modifiedSignedManifestRejected: manifestTampering.status === 'invalid',
      modifiedAssetRejected: assetTampering.status === 'invalid',
    },
    privateKeyWrittenToDisk: false,
  }, null, 2));
} finally {
  globalThis.fetch = originalFetch;
}
