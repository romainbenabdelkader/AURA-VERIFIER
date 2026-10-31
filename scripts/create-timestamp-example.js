// Creates fictional signed evidence and a query, never a TSA response.
// The ephemeral Ed25519 private key is never written to disk.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalize } from '../src/jcs.js';
import { createRfc3161TimestampQuery } from '../src/verify-timestamp-node.js';

const destination = process.argv[2];
if (!destination || process.argv.length !== 3) {
  throw new Error('Usage: node scripts/create-timestamp-example.js <NEW-directory>');
}
const dir = path.resolve(destination);
// Refuse to overwrite an existing fixture or a previously issued timestamp.
fs.mkdirSync(dir);
const write = (name, value) => fs.writeFileSync(path.join(dir, name), value);
const hash = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes).digest('hex');
const asset = Buffer.from('Fictional AURA timestamp example. No real work or rightsholder.\n', 'utf8');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const der = publicKey.export({ type: 'spki', format: 'der' });
const issuedAt = new Date().toISOString();
const manifest = {
  aura_version: '1.0',
  aura_uid: 'aura:v1:00000000000000000000000001',
  profile: 'AURA_RFC3161_PUBLIC_TEST',
  issuer: { id: 'FICTIONAL-TIMESTAMP-EXAMPLE', service: 'Independent local test' },
  issuer_role: 'test_issuer',
  issued_at: issuedAt,
  asset: { filename: 'asset.txt', hash_algorithm: 'SHA3-256', hash: hash('sha3-256', asset) },
  proof: { scope: 'asset_integrity_signed_declaration' },
  declarations: {
    fictional: true,
    legal_note: 'Test data only. No authorship, rights, identity, AI-origin or regulatory claim.',
  },
};
const signature = crypto.sign(null, Buffer.from(canonicalize(manifest), 'utf8'), privateKey);
manifest.signature = {
  algorithm: 'Ed25519', canonicalization: 'RFC-8785-JCS',
  format: 'Ed25519 raw signature, base64 encoded', value: signature.toString('base64'),
};
write('asset.txt', asset);
write('public-key.pem', publicKey.export({ type: 'spki', format: 'pem' }));
write('manifest.json', JSON.stringify(manifest, null, 2) + '\n');
write('manifest.canonical.json', canonicalize(manifest));
write('issuer.json', JSON.stringify({
  issuer: manifest.issuer.id, algorithm: 'Ed25519', status: 'active',
  public_key_fingerprint_sha256: hash('sha256', der),
  public_key_fingerprint_sha3_256: hash('sha3-256', der),
  valid_from: issuedAt, revoked_keys: [], test_only: true, production_use_prohibited: true,
}, null, 2) + '\n');
const query = createRfc3161TimestampQuery({
  manifestPath: path.join(dir, 'manifest.json'), requestPath: path.join(dir, 'manifest.tsq'),
});
console.log(JSON.stringify({ ...query,
  note: 'Submit manifest.tsq to a public TSA separately. No timestamp has been issued by this script.',
}, null, 2));
