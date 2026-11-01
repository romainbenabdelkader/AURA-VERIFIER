import { createV11Package } from './v11-package.js';
import fs from 'node:fs';

// Expected digests in the fixture helper use Node crypto, not AURA's SHA3.
export function hardeningCases() {
  const cases = [];
  const add = (name, pkg, expected, humanIncludes) => cases.push({ name, pkg, expected, humanIncludes });
  const valid = { status: 'valid', signatureOk: true, integrityStatus: 'verified' };
  const invalidRegistry = { status: 'invalid', signatureOk: true, keyStatusCheck: 'invalid_registry' };
  add('canonical-package', createV11Package(), valid);
  // Fixed public fixture: random key generation only rarely covers this byte.
  const leadingZero = JSON.parse(fs.readFileSync(new URL('../vectors/ed25519/leading-zero-public-key.json', import.meta.url), 'utf8'));
  add('leading-zero-public-key', { ...leadingZero, assetBytes: Buffer.from(leadingZero.assetHex, 'hex') }, valid);
  for (const length of [135, 271, 407]) {
    add(`native-sha3-${length}`, createV11Package({ assetBytes: Buffer.alloc(length, 0x61) }), valid);
  }
  add('old-incorrect-sha3-135', createV11Package({
    assetBytes: Buffer.alloc(135, 0x61),
    beforeSign: m => { m.asset.hash = 'd04ad3ea6dd566c44bddee03ae94243120a163b4515a0dee15009e3be94bc493'; },
  }), { status: 'invalid', signatureOk: true, integrityStatus: 'mismatch' });

  const signatureCases = [
    ['non-alphabet', s => s + '!'],
    ['extra-padding', s => s + '='],
    ['suffix-after-padding', s => s + 'INJECTED'],
    ['missing-padding', s => s.replace(/=+$/, '')],
    ['whitespace', s => s.slice(0, 4) + '\n' + s.slice(4)],
    ['base64url', s => '-' + s.slice(1)],
    ['non-zero-pad-bits', s => {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      return s.slice(0, -3) + alphabet[alphabet.indexOf(s.at(-3)) | 1] + '==';
    }],
    ['short-signature', () => Buffer.alloc(63).toString('base64')],
    ['long-signature', () => Buffer.alloc(65).toString('base64')],
    ['non-string-signature', () => 123],
  ];
  for (const [name, mutate] of signatureCases) {
    const pkg = createV11Package();
    pkg.manifest.signature.value = mutate(pkg.manifest.signature.value);
    pkg.manifestText = JSON.stringify(pkg.manifest);
    add(name, pkg, { status: 'invalid', signatureOk: false });
  }

  function registryCase(name, mutate, expected = invalidRegistry) {
    const pkg = createV11Package();
    const issuer = JSON.parse(pkg.issuerText);
    const replacement = mutate(issuer);
    pkg.issuerText = JSON.stringify(replacement === undefined ? issuer : replacement);
    add(name, pkg, expected, expected === invalidRegistry ? 'Key revoked: not checked (invalid registry)' : undefined);
  }
  for (const [name, value] of [['object', {}], ['string', 'revoked'], ['null', null], ['boolean', false], ['strings', ['fingerprint']], ['null-entry', [null]], ['empty-entry', [{}]], ['numeric-fingerprint', [{ public_key_fingerprint_sha256: 123 }]], ['bad-hex', [{ public_key_fingerprint_sha256: 'x'.repeat(64) }]], ['key-id-only', [{ key_id: 'old' }]]]) {
    registryCase(`revoked-list-${name}`, issuer => { issuer.revoked_keys = value; });
  }
  registryCase('revoked-object-with-matching-fingerprint', issuer => {
    issuer.revoked_keys = { public_key_fingerprint_sha256: issuer.public_key_fingerprint_sha256 };
  });
  registryCase('revoked-mixed-valid-and-invalid', issuer => {
    issuer.revoked_keys = [{ public_key_fingerprint_sha256: issuer.public_key_fingerprint_sha256 }, null];
  });
  registryCase('revoked-entry-with-one-malformed-fingerprint', issuer => {
    issuer.revoked_keys = [{ public_key_fingerprint_sha256: issuer.public_key_fingerprint_sha256, public_key_fingerprint_sha3_256: 123 }];
  });
  registryCase('contradictory-revocation-status', issuer => {
    issuer.revoked_keys = [{ public_key_fingerprint_sha256: issuer.public_key_fingerprint_sha256, status: 'active' }];
  });
  for (const value of [null, false, [], 'registry']) registryCase(`registry-root-${JSON.stringify(value)}`, () => value);
  registryCase('missing-current-fingerprint', issuer => { delete issuer.public_key_fingerprint_sha256; });
  registryCase('bad-current-status', issuer => { issuer.status = {}; });
  registryCase('invalid-registry-algorithm', issuer => { issuer.algorithm = 'Ed448'; });
  registryCase('revocation-list-omitted', issuer => { delete issuer.revoked_keys; }, valid);
  registryCase('unrelated-revoked-key', issuer => { issuer.revoked_keys = [{ public_key_fingerprint_sha256: '0'.repeat(64) }]; }, valid);
  for (const field of ['public_key_fingerprint_sha256', 'public_key_fingerprint_sha3_256']) {
    registryCase(`matching-revoked-${field}`, issuer => { issuer.revoked_keys = [{ [field]: issuer[field] }]; }, { status: 'invalid', signatureOk: true, keyRevoked: true, keyStatusCheck: 'revoked', historicalValidity: 'not_assessed' });
  }
  registryCase('current-key-revoked', issuer => { issuer.status = 'revoked'; }, { status: 'invalid', signatureOk: true, keyRevoked: true, keyStatusCheck: 'revoked' });
  add('registry-absent', { ...createV11Package(), issuerText: null }, { status: 'warning', signatureOk: true, keyStatusCheck: 'not_checked' });

  const tdm = createV11Package({ profile: 'AURA_TDM_RIGHTS_RESERVATION_V1', declarations: { tdm_opt_out: true } });
  add('tdm-signature-bound', { ...tdm }, valid, 'TDM declaration signature-bound: yes');
  const changed = JSON.parse(tdm.manifestText); changed.issued_at = '2026-01-02T00:00:00Z';
  add('tdm-tampered-payload', { ...tdm, manifestText: JSON.stringify(changed) }, { status: 'invalid', signatureOk: false }, 'TDM declaration signature-bound: no');
  return cases;
}
