import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { AuraInputError } from '../src/verification-input.js';
import { formatHumanResult } from '../src/report.js';
import { createV11Package } from './helpers/v11-package.js';
import { pemErrorCases, jsonErrorCases } from './helpers/input-error-cases.js';

const engines = [verifyAuraPackage, verifyAuraPackageBrowser];
const pemCases = pemErrorCases();
let cases = 0;
for (const { name, pkg, expected } of pemCases) {
  for (const verify of engines) {
    const result = await verify(pkg);
    for (const [field, value] of Object.entries(expected)) assert.equal(result[field], value, `${name}/${field}`);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(error => /Invalid (supplied|manifest issuer) public key:/.test(error)));
    if (result.publicKeyFingerprintSha256 === null) {
      assert.match(formatHumanResult(result), /Key revoked: not checked \(public key unavailable\)/);
      assert.ok(!result.errors.some(error => /fingerprint does not match|Public key does not match reference_anchor/.test(error)));
    }
  }
  cases += 1;
}
for (const publicKeyPem of ['', null, undefined, 17, {}]) {
  for (const verify of engines) {
    const result = await verify({ ...createV11Package(), publicKeyPem });
    assert.equal(result.status, 'invalid');
    assert.equal(result.signatureOk, false);
    assert.equal(result.integrityStatus, 'verified');
    assert.equal(result.publicKeyFingerprintSha256, null);
    assert.equal(result.keyStatusCheck, 'not_checked');
  }
  cases += 1;
}

const jsonCases = jsonErrorCases();
for (const { pkg, field } of [
  ...jsonCases,
  { pkg: { ...createV11Package(), manifestText: {} }, field: 'manifestText' },
  { pkg: { ...createV11Package(), issuerText: {} }, field: 'issuerText' },
]) {
  for (const verify of engines) {
    await assert.rejects(verify(pkg), error => {
      assert.ok(error instanceof AuraInputError);
      assert.equal(error.code, 'invalid_json');
      assert.equal(error.field, field);
      return true;
    });
  }
  cases += 1;
}

// Unexpected caller/runtime failures must not become a fabricated input verdict.
for (const verify of engines) {
  const failure = new Error('Unexpected caller failure');
  await assert.rejects(verify({ get manifestText() { throw failure; } }), error => error === failure);
  const result = await verify(createV11Package());
  assert.equal(result.status, 'valid');
  assert.equal(result.signatureOk, true);
}
cases += 2;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aura-input-errors-'));
const cli = fileURLToPath(new URL('../bin/aura.js', import.meta.url));
function runCli(pkg, json = true) {
  for (const [name, value] of Object.entries({
    'manifest.json': pkg.manifestText, 'public-key.pem': pkg.publicKeyPem,
    'issuer.json': pkg.issuerText, 'asset.txt': pkg.assetBytes,
  })) fs.writeFileSync(path.join(dir, name), value);
  return spawnSync(process.execPath, [cli, 'verify',
    '--manifest', path.join(dir, 'manifest.json'), '--public-key', path.join(dir, 'public-key.pem'),
    '--issuer', path.join(dir, 'issuer.json'), '--asset', path.join(dir, 'asset.txt'),
    ...(json ? ['--json'] : []),
  ], { encoding: 'utf8' });
}
try {
  for (const { name, pkg, expected } of pemCases) {
    const cliResult = runCli(pkg);
    assert.equal(cliResult.status, 2, name);
    assert.equal(cliResult.stderr, '', name);
    const result = JSON.parse(cliResult.stdout);
    for (const [field, value] of Object.entries(expected)) assert.equal(result[field], value, `${name}/${field}`);
    cases += 1;
  }
  for (const { name, pkg, field } of jsonCases) {
    const cliResult = runCli(pkg);
    assert.equal(cliResult.status, 2, name);
    assert.equal(cliResult.stderr, '', name);
    const result = JSON.parse(cliResult.stdout);
    assert.equal(result.status, 'input_error');
    assert.equal(result.valid, false);
    assert.equal(result.error.code, 'invalid_json');
    assert.equal(result.error.field, field);
    assert.equal(Object.hasOwn(result, 'signatureOk'), false);
    assert.equal(Object.hasOwn(result, 'integrityStatus'), false);
    cases += 1;
  }
  const human = runCli(jsonCases[0].pkg, false);
  assert.equal(human.status, 2);
  assert.equal(human.stdout, '');
  assert.match(human.stderr, /AURA verification failed: Invalid JSON in manifestText/);
  cases += 1;
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
console.log(`Input error handling passed: ${cases} cases (both engines and CLI).`);
