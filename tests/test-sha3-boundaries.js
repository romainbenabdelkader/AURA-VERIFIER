import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { sha3_256_hex } from '../src/sha3.js';
import { canonicalSignedManifestDigest } from '../src/manifest-digest.js';
import { canonicalize } from '../src/jcs.js';

const nativeDigest = bytes => crypto.createHash('sha3-256').update(bytes).digest('hex');
const nist = JSON.parse(fs.readFileSync(new URL('./vectors/sha3/nist-short-messages.json', import.meta.url)));
assert.equal(nist.vectors.length, 137);
for (const vector of nist.vectors) {
  const bytes = Buffer.from(vector.message, 'hex');
  assert.equal(bytes.length, vector.bytes);
  assert.equal(sha3_256_hex(bytes), vector.sha3_256, `NIST SHA3-256: ${vector.bytes} bytes`);
  assert.equal(nativeDigest(bytes), vector.sha3_256);
}

// Exercise several block boundaries using binary inputs, independently of NIST.
for (let length = 0; length <= 1024; length += 1) {
  const bytes = Uint8Array.from({ length }, (_, i) => (i * 73 + length) & 255);
  assert.equal(sha3_256_hex(bytes), nativeDigest(bytes), `Native SHA3-256: ${length} bytes`);
}
assert.equal(sha3_256_hex(Buffer.alloc(135, 0x61)), '8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9');

// The SHA3 field of a complete-manifest digest uses the same corrected primitive.
const manifest = { padding: '', signature: { value: 'placeholder-for-digest-only' } };
while (Buffer.byteLength(canonicalize(manifest)) % 136 !== 135) manifest.padding += 'a';
const bytes = Buffer.from(canonicalize(manifest));
const result = canonicalSignedManifestDigest(JSON.stringify(manifest));
assert.equal(result.canonicalBytesLength, bytes.length);
assert.equal(result.sha3_256, 'sha3-256:' + nativeDigest(bytes));
assert.equal(result.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
console.log('SHA3: 137 NIST vectors, 1025 binary lengths, 135-byte reproducer and full-manifest digest passed.');
