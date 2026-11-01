import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aura-current-vectors-'));
const destination = path.join(temporary, 'vectors');
const generate = () => spawnSync(process.execPath, ['scripts/generate-test-vector.js', destination], { cwd: root, encoding: 'utf8' });
try {
  const generation = generate();
  assert.equal(generation.status, 0, generation.stdout + generation.stderr);
  for (const name of ['valid', 'invalid-asset', 'invalid-signature']) {
    const p = field => path.join(destination, name, field);
    const pkg = {
      assetBytes: fs.readFileSync(p('asset.txt')),
      manifestText: fs.readFileSync(p('manifest.json'), 'utf8'),
      publicKeyPem: fs.readFileSync(p('public-key.pem'), 'utf8'),
      issuerText: fs.readFileSync(p('issuer.json'), 'utf8'),
    };
    for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
      const result = await verify(pkg);
      assert.equal(result.schemaValidation.status, 'pass');
      assert.equal(result.status, name === 'valid' ? 'valid' : 'invalid');
      assert.equal(result.assetHashOk, name !== 'invalid-asset');
      assert.equal(result.signatureOk, name !== 'invalid-signature');
    }
  }
  const before = fs.readFileSync(path.join(destination, 'valid', 'manifest.json'));
  assert.notEqual(generate().status, 0);
  assert.deepEqual(fs.readFileSync(path.join(destination, 'valid', 'manifest.json')), before);
  console.log('Generated v1.0 vectors pass both engines; existing destinations are preserved.');
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
