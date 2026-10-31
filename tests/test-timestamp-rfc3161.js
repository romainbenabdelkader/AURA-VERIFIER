import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRfc3161TimestampQuery, verifyRfc3161Timestamp } from '../src/verify-timestamp-node.js';
import { canonicalSignedManifestDigest } from '../src/manifest-digest.js';

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
  // This is a local TSA binding fixture, NOT a real signed AURA manifest.
  // The existing verifier regression suite tests actual Ed25519 signatures.
  const obj = {
    aura_version: '1.1',
    issued_at: '2026-07-10T00:00:00Z',
    signature: { algorithm: 'Ed25519', value: 'TEST_PLACEHOLDER' },
  };
  file('manifest.json', JSON.stringify(obj) + '\n');
  file('reformatted.json', JSON.stringify({
    signature: obj.signature,
    issued_at: obj.issued_at,
    aura_version: obj.aura_version,
  }, null, 4) + '\r\n');
  file('modified.json', JSON.stringify({
    ...obj, signature: { ...obj.signature, value: 'TAMPERED' },
  }));
  file('other.json', JSON.stringify({ ...obj, issued_at: '2026-10-31T00:00:00Z' }));
  makeTsa('first');
  makeTsa('other');

  const req = createRfc3161TimestampQuery({
    manifestPath: location('manifest.json'), requestPath: location('valid.tsq'),
  });
  assert.equal(req.status, 'created');
  assert.equal(req.binding, 'jcs_full_signed_manifest');
  assert.equal(req.timestampImprintSha256,
    canonicalSignedManifestDigest(fs.readFileSync(location('reformatted.json'), 'utf8')).sha256);
  run('ts', '-reply', '-config', 'first-tsa.cnf', '-queryfile', 'valid.tsq',
    '-chain', 'first-root.pem', '-out', 'valid.tsr');

  const good = verifyRfc3161Timestamp(opts());
  assert.equal(good.status, 'verified', good.error);
  assert.equal(good.binding, 'jcs_full_signed_manifest');
  assert.match(good.genTime, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.equal(good.nonceCheck, 'passed_against_supplied_request');
  assert.equal(good.qualifiedEidas, 'not_assessed');
  assert.equal(good.timestampImprintSha256, req.timestampImprintSha256);
  assert.equal(good.manifestHashSha3_256, req.manifestHashSha3_256);

  // Reformatting, key reordering and CRLF must not break the timestamp.
  assert.equal(verifyRfc3161Timestamp(opts({
    manifestPath: location('reformatted.json'),
  })).status, 'verified');
  // A changed signed declaration must fail.
  assert.equal(verifyRfc3161Timestamp(opts({
    manifestPath: location('modified.json'),
  })).status, 'invalid');

  createRfc3161TimestampQuery({
    manifestPath: location('other.json'), requestPath: location('wrong.tsq'),
  });
  run('ts', '-reply', '-config', 'first-tsa.cnf', '-queryfile', 'wrong.tsq',
    '-chain', 'first-root.pem', '-out', 'wrong.tsr');
  assert.equal(verifyRfc3161Timestamp(opts({
    responsePath: location('wrong.tsr'),
  })).status, 'invalid');
  assert.equal(verifyRfc3161Timestamp(opts({
    caPath: location('other-root.pem'),
  })).status, 'invalid');

  createRfc3161TimestampQuery({
    manifestPath: location('manifest.json'), requestPath: location('different-nonce.tsq'),
  });
  assert.equal(verifyRfc3161Timestamp(opts({
    queryPath: location('different-nonce.tsq'),
  })).status, 'invalid');

  const broken = fs.readFileSync(location('valid.tsr'));
  broken[broken.length - 10] ^= 0xff;
  file('broken.tsr', broken);
  assert.equal(verifyRfc3161Timestamp(opts({
    responsePath: location('broken.tsr'),
  })).status, 'invalid');

  assert.throws(() => verifyRfc3161Timestamp(opts({
    responsePath: '-untrusted',
  })), /Unsafe file path/);
  assert.throws(() => createRfc3161TimestampQuery({
    manifestPath: location('manifest.json'), requestPath: '-out',
  }), /Unsafe file path/);

  console.log('RFC3161: valid, canonical JSON, modified manifest, wrong token, untrusted CA, bad nonce, corrupt token, unsafe paths passed.');
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
