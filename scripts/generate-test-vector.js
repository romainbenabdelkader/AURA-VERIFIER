import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalize } from '../src/jcs.js';
import { sha3_256_hex } from '../src/sha3.js';

const outDir = path.join('tests', 'vectors', 'valid');
fs.mkdirSync(outDir, { recursive: true });

const asset = Buffer.from('hello AURA\n', 'utf8');
fs.writeFileSync(path.join(outDir, 'asset.txt'), asset);

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
const publicKeySha256 = crypto.createHash('sha256').update(publicKeyDer).digest('hex');
const publicKeySha3 = sha3_256_hex(new Uint8Array(publicKeyDer));

const unsignedManifest = {
  aura_version: '0.1-test',
  profile: 'AURA_TEST_VECTOR',
  aura_id: 'aura:v1:test-vector-valid',
  aura_uid: 'aura:v1:test-vector-valid',
  issuer: {
    id: 'AURA-TEST',
    service: 'AURA-VERIFIER',
    public_key_pem: publicKeyPem,
  },
  issued_at: '2026-01-01T00:00:00.000Z',
  asset: {
    filename: 'asset.txt',
    hash_algorithm: 'SHA3-256',
    hash: sha3_256_hex(asset),
  },
  proof: {
    scope: 'origin_integrity_consent_signal',
    signature_algorithm: 'Ed25519',
  },
  declarations: {
    legal_note: 'AURA establishes technical facts and does not decide legal ownership.',
  },
};

const signature = crypto.sign(null, Buffer.from(canonicalize(unsignedManifest)), privateKey);
const manifest = {
  ...unsignedManifest,
  signature: {
    algorithm: 'Ed25519',
    canonicalization: 'RFC-8785-JCS',
    format: 'Ed25519 raw signature, base64 encoded',
    value: signature.toString('base64'),
  },
};

const issuer = {
  issuer: 'AURA-TEST',
  algorithm: 'Ed25519',
  public_key_url: './public-key.pem',
  public_key_fingerprint_sha256: publicKeySha256,
  public_key_fingerprint_sha3_256: publicKeySha3,
  valid_from: '2026-01-01T00:00:00.000Z',
  status: 'active',
  key_id: `aura-test-${publicKeySha256.slice(0, 16)}`,
  verification_spec_url: './aura-verification-spec-v1.0.md',
  zenodo_public_key_doi: null,
  zenodo_spec_doi: null,
};

fs.writeFileSync(path.join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
fs.writeFileSync(path.join(outDir, 'public-key.pem'), publicKeyPem);
fs.writeFileSync(path.join(outDir, 'issuer.json'), `${JSON.stringify(issuer, null, 2)}\n`);

const invalidDir = path.join('tests', 'vectors', 'invalid-asset');
fs.mkdirSync(invalidDir, { recursive: true });
fs.writeFileSync(path.join(invalidDir, 'asset.txt'), 'tampered AURA\n');
fs.copyFileSync(path.join(outDir, 'manifest.json'), path.join(invalidDir, 'manifest.json'));
fs.copyFileSync(path.join(outDir, 'public-key.pem'), path.join(invalidDir, 'public-key.pem'));
fs.copyFileSync(path.join(outDir, 'issuer.json'), path.join(invalidDir, 'issuer.json'));

const tamperedDir = path.join('tests', 'vectors', 'invalid-signature');
fs.mkdirSync(tamperedDir, { recursive: true });
fs.copyFileSync(path.join(outDir, 'asset.txt'), path.join(tamperedDir, 'asset.txt'));
fs.copyFileSync(path.join(outDir, 'public-key.pem'), path.join(tamperedDir, 'public-key.pem'));
fs.copyFileSync(path.join(outDir, 'issuer.json'), path.join(tamperedDir, 'issuer.json'));
const tamperedManifest = structuredClone(manifest);
tamperedManifest.asset.filename = 'renamed-after-signing.txt';
fs.writeFileSync(
  path.join(tamperedDir, 'manifest.json'),
  `${JSON.stringify(tamperedManifest, null, 2)}\n`,
);

console.log(`Generated test vectors in ${outDir}`);
