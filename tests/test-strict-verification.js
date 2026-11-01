import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize, unsignedManifest } from '../src/jcs.js';
import { canonicalSignedManifestDigest } from '../src/manifest-digest.js';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { createV11Package } from './helpers/v11-package.js';

// Deliberately reproduce the former permissive serialization for negative
// Unicode fixtures. These signed inputs cannot be produced by compliant JCS.
function permissiveSerialize(value) {
  if (Array.isArray(value)) return `[${value.map(permissiveSerialize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${permissiveSerialize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function signedPackage(beforeSign, { keyType = 'ed25519', permissive = false } = {}) {
  const pkg = createV11Package();
  const { publicKey, privateKey } = crypto.generateKeyPairSync(keyType);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const sha256 = crypto.createHash('sha256').update(der).digest('hex');
  const sha3 = crypto.createHash('sha3-256').update(der).digest('hex');
  pkg.manifest.reference_anchor.issuer_key.public_key_digest = `sha3-256:${sha3}`;
  beforeSign(pkg.manifest);
  const serialize = permissive ? permissiveSerialize : canonicalize;
  pkg.manifest.signature.value = crypto.sign(null, Buffer.from(serialize(unsignedManifest(pkg.manifest))), privateKey).toString('base64');
  pkg.manifestText = JSON.stringify(pkg.manifest);
  pkg.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const issuer = JSON.parse(pkg.issuerText);
  issuer.public_key_fingerprint_sha256 = sha256;
  issuer.public_key_fingerprint_sha3_256 = sha3;
  pkg.issuerText = JSON.stringify(issuer);
  return pkg;
}

const results = [];
async function check(name, pkg, expected, inspect = () => {}) {
  const node = await verifyAuraPackage(pkg);
  const web = await verifyAuraPackageBrowser(pkg);
  for (const result of [node, web]) {
    assert.equal(result.status, expected, name);
    inspect(result);
  }
  assert.equal(node.signatureOk, web.signatureOk, name);
  assert.equal(node.integrityStatus, web.integrityStatus, name);
  results.push({ name, node: node.status, webCrypto: web.status, signatureOk: node.signatureOk });
}

for (const version of ['1.0', '1.1']) {
  await check(`supported-${version}`, signedPackage(m => { m.aura_version = version; }), 'valid');
}
for (const version of ['9.9', '0.1', '0.1-test', '0.1-pilot', '', null, 1.1, ['1.1'], '__proto__']) {
  await check(`unsupported-version-${JSON.stringify(version)}`, signedPackage(m => { m.aura_version = version; }), 'invalid', r => {
    assert.equal(r.signatureOk, true);
    assert.ok(r.errors.some(e => /Unsupported AURA manifest version/.test(e)));
  });
}
await check('missing-version', signedPackage(m => { delete m.aura_version; }), 'invalid');

for (const algorithm of ['MD5', 'SHA-256', 'sha3-256', '', null]) {
  await check(`unsupported-hash-${JSON.stringify(algorithm)}`, signedPackage(m => { m.asset.hash_algorithm = algorithm; }), 'invalid', r => {
    assert.equal(r.signatureOk, true);
    assert.equal(r.assetHashOk, null);
    assert.equal(r.integrityStatus, 'not_checked');
    assert.ok(r.errors.some(e => /Unsupported asset hash algorithm/.test(e)));
  });
}
await check('missing-hash-algorithm', signedPackage(m => { delete m.asset.hash_algorithm; }), 'invalid');
await check('conflicting-hash-algorithm', signedPackage(m => { m.asset_hash_algorithm = 'MD5'; }), 'invalid');
await check('unsupported-hash-without-asset', { ...signedPackage(m => { m.asset.hash_algorithm = 'MD5'; }), assetBytes: null }, 'invalid');
await check('fileless-catalog-claim', { ...signedPackage(m => { delete m.asset; m.catalog_claim = { title: 'Fictional' }; }), assetBytes: null }, 'valid', r => {
  assert.equal(r.integrityStatus, 'not_applicable');
});

await check('ed448-labeled-Ed25519', signedPackage(() => {}, { keyType: 'ed448' }), 'invalid', r => {
  assert.equal(r.signatureOk, false);
});

for (const value of ['\ud800', '\udfff', 'prefix\ud800suffix', '\ud800\ud800', '\udc00\ud800', '\ud83d\ude00\ud800']) {
  assert.throws(() => canonicalize(value), /lone Unicode surrogates/);
  assert.throws(() => canonicalize({ [value]: true }), /lone Unicode surrogates/);
  for (const position of ['value', 'key', 'array', 'signature']) {
    const pkg = signedPackage(m => {
      if (position === 'value') m.declarations.note = value;
      if (position === 'key') m.declarations[value] = 'Fictional';
      if (position === 'array') m.declarations.notes = [value];
      if (position === 'signature') m.signature.format = value;
    }, { permissive: true });
    await check(`invalid-Unicode-${position}-${JSON.stringify(value)}`, pkg, 'invalid', r => {
      assert.ok(r.errors.some(e => /canonicalization failed.*lone Unicode surrogates/.test(e)));
      assert.equal(r.signatureOk, false);
    });
    assert.throws(() => canonicalSignedManifestDigest(pkg.manifestText), /lone Unicode surrogates/);
  }
}

await check('valid-Unicode-pairs-and-controls', signedPackage(m => {
  m.declarations['\ud83d\ude00'] = ['\ud800\udc00', '\udbff\udfff', 'é', 'e\u0301', '\u0000\n'];
}), 'valid');
// RFC 8785 section 3.2.3 ordering example, including a valid surrogate pair.
assert.equal(canonicalize({ '\u20ac': 5, '\r': 1, '\ufb33': 7, '1': 2, '\ud83d\ude00': 6, '\u0080': 3, '\u00f6': 4 }),
  '{"\\r":1,"1":2,"\u0080":3,"ö":4,"€":5,"😀":6,"דּ":7}');
assert.equal(canonicalize({ x: 1.0, y: 1e-7 }), '{"x":1,"y":1e-7}');

console.log(JSON.stringify({ suite: 'strict-verification', cases: results.length, results }, null, 2));
