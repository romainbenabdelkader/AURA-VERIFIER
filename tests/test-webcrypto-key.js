import assert from 'node:assert/strict';
import fs from 'node:fs';
import { importEd25519VerificationKey } from '../src/webcrypto-key.js';
import { pemToDer, ed25519SignatureBytes } from '../src/pem.js';
import { canonicalize, unsignedManifest } from '../src/jcs.js';

const fixture = JSON.parse(fs.readFileSync(new URL('./vectors/ed25519/leading-zero-public-key.json', import.meta.url), 'utf8'));
const der = pemToDer(fixture.publicKeyPem);
assert.equal(der[12], 0, 'the fixed fixture must retain its leading-zero public byte');
const original = der.slice();
const manifest = JSON.parse(fixture.manifestText);
const payload = new TextEncoder().encode(canonicalize(unsignedManifest(manifest)));
const signature = ed25519SignatureBytes(manifest.signature.value);

// Model the browser's SPKI-import failure; raw imports and signature checks
// still use the native cryptographic provider on the exact fixture bytes.
let rawCalls = 0;
const provider = {
  async importKey(format, bytes, ...args) {
    if (format === 'spki') throw new DOMException('SPKI provider failure', 'DataError');
    rawCalls++;
    return crypto.subtle.importKey(format, bytes, ...args);
  },
};
for (const implementation of [crypto.subtle, provider]) {
  const key = await importEd25519VerificationKey(der, implementation);
  assert.equal(await crypto.subtle.verify('Ed25519', key, signature, payload), true);
  assert.equal(await crypto.subtle.verify('Ed25519', key, signature, new Uint8Array([1, ...payload])), false);
  assert.deepEqual(der, original, 'key pins continue to cover the original DER');
}
assert.equal(rawCalls, 1);
const malformed = [der.slice(0, -1), new Uint8Array([...der, 0])];
for (let i = 0; i < 12; i++) {
  const changed = der.slice(); changed[i] ^= 1; malformed.push(changed);
}
for (const bytes of malformed) {
  await assert.rejects(importEd25519VerificationKey(bytes, provider), { name: 'DataError' });
}
assert.equal(rawCalls, 1, 'malformed wrappers must never reach raw import');
await assert.rejects(importEd25519VerificationKey(der, {
  async importKey() { throw new DOMException('Unsupported provider', 'NotSupportedError'); },
}), { name: 'NotSupportedError' });
console.log('WebCrypto key import: leading-zero signature, tamper rejection and malformed-wrapper controls passed.');
