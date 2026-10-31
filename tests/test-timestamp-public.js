import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createRfc3161TimestampQuery } from '../src/verify-timestamp-node.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = path.join(root, 'examples/rfc3161-freetsa');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aura-public-timestamp-'));
const p = (name) => path.join(dir, name);
const invoke = (args) => spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', timeout: 30000 });

try {
  // Reproduction uses the committed real TSA response, not a live service.
  const demo = invoke(['scripts/verify-timestamp-example.js']);
  assert.equal(demo.status, 0, demo.stdout + demo.stderr);
  assert.equal(JSON.parse(demo.stdout).status, 'passed');
  fs.cpSync(fixture, dir, { recursive: true });
  const base = {
    '--manifest': p('manifest.json'), '--public-key': p('public-key.pem'),
    '--issuer': p('issuer.json'), '--asset': p('asset.txt'),
    '--timestamp-response': p('manifest.tsr'), '--timestamp-query': p('manifest.tsq'),
    '--tsa-ca': p('cacert.pem'), '--tsa-untrusted': p('tsa.crt'),
  };
  const cli = (changes = {}, omitted = []) => invoke(['bin/aura.js', 'verify',
    ...Object.entries({ ...base, ...changes }).filter(([k]) => !omitted.includes(k)).flat(), '--json']);
  const rejected = (r) => {
    assert.equal(r.status, 2, r.stdout + r.stderr);
    if (r.stdout) {
      const result = JSON.parse(r.stdout);
      assert.equal(result.status, 'invalid');
      assert.equal(result.auraTimestampedChecks, 'not_established');
    }
  };
  const manifest = JSON.parse(fs.readFileSync(p('manifest.json'), 'utf8'));
  fs.writeFileSync(p('reordered.json'), JSON.stringify(Object.fromEntries(Object.entries(manifest).reverse()), null, 4) + '\r\n');
  assert.equal(cli({ '--manifest': p('reordered.json') }).status, 0);
  fs.writeFileSync(p('tampered.json'), JSON.stringify({ ...manifest, issued_at: '2026-01-01T00:00:00Z' }));
  rejected(cli({ '--manifest': p('tampered.json') }));
  fs.writeFileSync(p('wrong-asset.txt'), 'Different fictional content\n');
  rejected(cli({ '--asset': p('wrong-asset.txt') }));
  createRfc3161TimestampQuery({ manifestPath: p('manifest.json'), requestPath: p('different-nonce.tsq') });
  rejected(cli({ '--timestamp-query': p('different-nonce.tsq') }));
  const broken = fs.readFileSync(p('manifest.tsr'));
  broken[broken.length - 10] ^= 0xff;
  fs.writeFileSync(p('corrupt.tsr'), broken);
  rejected(cli({ '--timestamp-response': p('corrupt.tsr') }));
  rejected(cli({ '--timestamp-response': p('missing.tsr') }));
  rejected(cli({}, ['--tsa-ca']));
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(p('wrong-key.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  rejected(cli({ '--public-key': p('wrong-key.pem') }));
  const noQuery = cli({}, ['--timestamp-query']);
  assert.equal(noQuery.status, 0, noQuery.stdout + noQuery.stderr);
  assert.equal(JSON.parse(noQuery.stdout).timestamp.nonceCheck, 'not_assessed');
  const noTimestamp = cli({}, ['--timestamp-query', '--timestamp-response', '--tsa-ca', '--tsa-untrusted']);
  assert.equal(noTimestamp.status, 0);
  assert.equal(JSON.parse(noTimestamp.stdout).timestamp.status, 'not_provided');
  assert.equal(JSON.parse(noTimestamp.stdout).auraTimestampedChecks, 'not_established');
  // A corrupt checked-in fixture must fail the reproducible report as well.
  fs.writeFileSync(p('asset.txt'), 'Altered fixture\n');
  const corruptDemo = invoke(['scripts/verify-timestamp-example.js', dir]);
  assert.equal(corruptDemo.status, 1);
  assert.equal(JSON.parse(corruptDemo.stdout).status, 'failed');
  console.log('Public FreeTSA fixture and CLI: offline verification, canonical JSON, tampering, nonce, corrupt/missing token, incomplete trust, wrong issuer key and absent evidence passed.');
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
