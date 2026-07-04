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

console.log('AURA verifier tests passed.');
