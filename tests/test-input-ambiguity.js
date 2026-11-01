import assert from 'node:assert/strict';
import { parseUniqueJson } from '../src/strict-json.js';
import { canonicalSignedManifestDigest } from '../src/manifest-digest.js';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { createV11Package } from './helpers/v11-package.js';

let cases = 0;
for (const text of [
  '{"x":1,"x":2}', '{"x":1,"\\u0078":1}',
  '{"nested":[{"x":1,"x":2}]}', '{"__proto__":1,"__proto__":2}',
  '{"":1,"":2}', '{"a\\nb":1,"a\\u000ab":2}',
]) {
  assert.throws(() => parseUniqueJson(text), /Duplicate JSON/);
  cases += 1;
}
for (const text of [
  '{}', '[]', 'null', 'true', '-1.2e+3', '"text"',
  '{"a":{"x":1},"b":{"x":2}}',
  '{"x":"a\\\"b\\\\c","arr":[null,true,false,-2e3,{},[]]}',
  ' \n { "__proto__": 1, "constructor": 2, "x": "é😀" } \t',
  '[{"x":1},{"x":2}]',
]) {
  assert.deepEqual(parseUniqueJson(text), JSON.parse(text));
  cases += 1;
}
for (const text of ['{"x":}', '{"x":1,}', '[1,]', '"unterminated', '{}{}']) {
  assert.throws(() => parseUniqueJson(text), SyntaxError);
  cases += 1;
}

const duplicateTransforms = [
  text => text.replace('"aura_version":', '"aura_version":"9.9","aura_version":'),
  text => text.replace('"aura_version":', '"aura_version":"1.1","\\u0061ura_version":'),
  text => text.replace('"algorithm":"Ed25519"', '"algorithm":"other","algorithm":"Ed25519"'),
  text => text.replace('"declarations":{', '"declarations":{"x":1,"x":2,'),
];
for (const transform of duplicateTransforms) {
  const pkg = createV11Package();
  pkg.manifestText = transform(pkg.manifestText);
  for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
    await assert.rejects(verify(pkg), /Duplicate JSON/);
  }
  assert.throws(() => canonicalSignedManifestDigest(pkg.manifestText), /Duplicate JSON/);
  cases += 1;
}
const duplicateIssuer = createV11Package();
duplicateIssuer.issuerText = duplicateIssuer.issuerText.replace('"status":', '"status":"revoked","status":');
for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
  await assert.rejects(verify(duplicateIssuer), /Duplicate JSON/);
}
cases += 1;

async function check(pkg, expected, integrity) {
  for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
    const result = await verify(pkg);
    assert.equal(result.status, expected);
    assert.equal(result.signatureOk, true);
    assert.equal(result.integrityStatus, integrity);
    if (integrity !== 'verified') assert.equal(result.assetHashOk, null);
  }
  cases += 1;
}
for (const alias of ['asset_hash', 'asset_hash_sha3_256']) {
  for (const value of ['f'.repeat(64), '', 7, {}, [], 'A'.repeat(64)]) {
    await check(createV11Package({ beforeSign: m => {
      if (alias === 'asset_hash') m.asset_hash = value;
      else m.asset.asset_hash_sha3_256 = value;
    }}), 'invalid', 'not_checked');
  }
}
await check(createV11Package({ beforeSign: m => {
  m.asset_hash = m.asset.hash;
  m.asset.asset_hash_sha3_256 = m.asset.hash;
}}), 'valid', 'verified');
for (const marker of [m => { m.catalog_claim = {}; }, m => { m.profile = 'catalog_claim'; }]) {
  await check({ ...createV11Package({ beforeSign: marker }), assetBytes: null }, 'warning', 'not_checked');
  await check(createV11Package({ beforeSign: marker }), 'valid', 'verified');
}
await check({ ...createV11Package({ beforeSign: m => {
  delete m.asset; m.catalog_claim = {};
}}), assetBytes: null }, 'valid', 'not_applicable');
await check({ ...createV11Package({ beforeSign: m => { m.asset_hash = 'f'.repeat(64); } }), assetBytes: null }, 'invalid', 'not_checked');
await check(createV11Package({ beforeSign: m => { m.asset_hash = null; } }), 'valid', 'verified');
await check({ ...createV11Package({ beforeSign: m => {
  delete m.asset.hash; delete m.asset.hash_algorithm;
  m.asset.asset_hash_sha3_256 = null; m.catalog_claim = {};
}}), assetBytes: null }, 'valid', 'not_applicable');
console.log(`Input ambiguity regression tests passed: ${cases} cases.`);
