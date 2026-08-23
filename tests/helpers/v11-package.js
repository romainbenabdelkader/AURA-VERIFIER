import nodeCrypto from 'node:crypto';
import { canonicalize } from '../../src/jcs.js';
import { sha3_256_hex } from '../../src/sha3.js';

export function createV11Package() {
  const assetBytes = Buffer.from('AURA v1.1 local verification regression\n', 'utf8');
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const publicKeySha256 = nodeCrypto.createHash('sha256').update(publicKeyDer).digest('hex');
  const publicKeySha3 = sha3_256_hex(publicKeyDer);

  const unsigned = {
    aura_version: '1.1',
    profile: 'AURA_EVIDENCE_PACKAGE',
    aura_uid: 'aura:v1:01ARZ3NDEKTSV4RRFFQ69G5FAV',
    issuer: {
      id: 'AURA-LOCAL-TEST',
      service: 'AURA-VERIFIER',
    },
    issued_at: '2026-01-01T00:00:00.000Z',
    asset: {
      filename: 'offline-test.txt',
      hash_algorithm: 'SHA3-256',
      hash: sha3_256_hex(assetBytes),
    },
    proof: {
      scope: 'asset_integrity_signed_declaration',
    },
    declarations: {
      note: 'Local regression fixture generated in memory.',
    },
    reference_anchor: {
      standard: {
        name: 'AURA',
        schema_version: '1.1',
        release_tag: 'v1.1.1',
        schema_digest: `sha3-256:${'0'.repeat(64)}`,
        archive_doi: 'local:test-standard',
      },
      verifier: {
        name: 'AURA-VERIFIER',
        version: '1.0.2-test',
        release_tag: 'v1.0.2-test',
        source_digest: `sha3-256:${'1'.repeat(64)}`,
        archive_doi: 'local:test-verifier',
      },
      issuer_key: {
        issuer_id: 'AURA-LOCAL-TEST',
        key_id: `aura-local-test-${publicKeySha256.slice(0, 16)}`,
        algorithm: 'Ed25519',
        public_key_digest: `sha3-256:${publicKeySha3}`,
        public_key_doi: 'local:test-key',
      },
    },
  };

  const signature = nodeCrypto.sign(null, Buffer.from(canonicalize(unsigned)), privateKey);
  const manifest = {
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      canonicalization: 'RFC-8785-JCS',
      format: 'Ed25519 raw signature, base64 encoded',
      value: signature.toString('base64'),
    },
  };
  const issuer = {
    issuer: 'AURA-LOCAL-TEST',
    algorithm: 'Ed25519',
    public_key_fingerprint_sha256: publicKeySha256,
    public_key_fingerprint_sha3_256: publicKeySha3,
    valid_from: '2026-01-01T00:00:00.000Z',
    status: 'active',
    key_id: `aura-local-test-${publicKeySha256.slice(0, 16)}`,
    revoked_keys: [],
  };

  return {
    assetBytes,
    manifest,
    manifestText: JSON.stringify(manifest),
    publicKeyPem,
    issuerText: JSON.stringify(issuer),
  };
}
