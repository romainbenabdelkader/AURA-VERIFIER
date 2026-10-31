import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { verifyRfc3161Timestamp } from '../src/verify-timestamp-node.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aura-rfc3161-'));
const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe', timeout: 15000 });
const file = (name, contents) => fs.writeFileSync(path.join(dir, name), contents);
const location = (name) => path.join(dir, name);

function makeTsa(prefix) {
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', prefix + '-root.key',
    '-out', prefix + '-root.pem', '-days', '2', '-subj', '/CN=' + prefix + ' TEST ONLY Root CA');
  run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', prefix + '-tsa.key',
    '-out', prefix + '-tsa.csr', '-subj', '/CN=' + prefix + ' TEST ONLY TSA');
  file(prefix + '-ext.cnf', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n');
  run('x509', '-req', '-in', prefix + '-tsa.csr', '-CA', prefix + '-root.pem', '-CAkey',
    prefix + '-root.key', '-CAcreateserial', '-out', prefix + '-tsa.pem',
    '-days', '2', '-extfile', prefix + '-ext.cnf');
  file(prefix + '-tsa.cnf', '[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\nserial=' + prefix +
    '-serial\ndigests=sha256\nsigner_cert=' + prefix + '-tsa.pem\nsigner_key=' + prefix +
    '-tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\nother_policies=1.2.3.4.1\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=yes\n');
  file(prefix + '-serial', '01\n');
}

const opts = (overrides = {}) => ({
  manifestPath: location('manifest.json'),
  responsePath: location('valid.tsr'),
  caPath: location('first-root.pem'),
  untrustedPath: location('first-tsa.pem'),
  queryPath: location('valid.tsq'),
  ...overrides,
});

try {
  // The exact signed manifest bytes, including a placeholder issuer signature,
  // are covered. This fixture tests RFC3161, NOT an AURA issuer's real key.
  file('manifest.json', '{"aura_version":"1.1","signature":{"algorithm":"Ed25519","value":"TEST_PLACEHOLDER"},"issued_at":"2026-07-10T00:00:00Z"}\n');
  file('other.json', '{"aura_version":"1.1","signature":{"algorithm":"Ed25519","value":"OTHER"}}\n');
  makeTsa('first');
  makeTsa('other');
  run('ts', '-query', '-data', 'manifest.json', '-sha256', '-cert', '-out', 'valid.tsq');
  run('ts', '-reply', '-config', 'first-tsa.cnf', '-queryfile', 'valid.tsq', '-chain', 'first-root.pem', '-out', 'valid.tsr');

  const good = verifyRfc3161Timestamp(opts());
  assert.equal(good.status, 'verified', good.error);
  assert.equal(good.binding, 'exact_full_signed_manifest_bytes');
  assert.equal(good.nonceCheck, 'passed_against_supplied_request');
  assert.equal(good.qualifiedEidas, 'not_assessed');

  file('modified.json', fs.readFileSync(location('manifest.json'), 'utf8').replace('TEST_PLACEHOLDER', 'TAMPERED'));
  assert.equal(verifyRfc3161Timestamp(opts({ manifestPath: location('modified.json') })).status, 'invalid');

  run('ts', '-query', '-data', 'other.json', '-sha256', '-cert', '-out', 'wrong.tsq');
  run('ts', '-reply', '-config', 'first-tsa.cnf', '-queryfile', 'wrong.tsq', '-chain', 'first-root.pem', '-out', 'wrong.tsr');
  assert.equal(verifyRfc3161Timestamp(opts({ responsePath: location('wrong.tsr') })).status, 'invalid');
  assert.equal(verifyRfc3161Timestamp(opts({ caPath: location('other-root.pem') })).status, 'invalid');

  run('ts', '-query', '-data', 'manifest.json', '-sha256', '-cert', '-out', 'different-nonce.tsq');
  assert.equal(verifyRfc3161Timestamp(opts({ queryPath: location('different-nonce.tsq') })).status, 'invalid');

  const broken = fs.readFileSync(location('valid.tsr'));
  broken[broken.length - 10] ^= 0xff;
  file('broken.tsr', broken);
  assert.equal(verifyRfc3161Timestamp(opts({ responsePath: location('broken.tsr') })).status, 'invalid');
  console.log('RFC3161: valid, modified-manifest, wrong-token, untrusted-CA, bad-nonce and tampered-token tests passed.');
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
