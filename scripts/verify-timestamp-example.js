// Offline reproduction: local files, Node and OpenSSL only. No HTTP calls.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { canonicalize } from '../src/jcs.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.resolve(process.argv[2] || path.join(root, 'examples/rfc3161-freetsa'));
if (process.argv.length > 3) throw new Error('Usage: node scripts/verify-timestamp-example.js [evidence-directory]');
const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
const file = (name) => {
  assert.equal(path.basename(name), name, 'Evidence filenames must be basenames');
  return path.join(dir, name);
};
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const report = {
  node: process.version, checkedAt: new Date().toISOString(),
  sourceSha256: {}, evidenceSha256: {}, commands: [],
  limitations: [
    'Technical verification only; issuer identity and legal authority are not established.',
    'Trust is relative to the supplied CA. Authenticate that anchor separately.',
    'TSA-policy suitability, revocation and long-term validation are not assessed.',
    'RFC 3161 verification does not establish qualified eIDAS status.',
    'No proof of authorship, ownership, human origin, AI training use or earlier creation time.',
  ],
};
const portable = (s) => s.replaceAll(dir, '$EVIDENCE').replaceAll(root, '$REPO');
function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 300000, maxBuffer: 4 * 1024 * 1024 });
  report.commands.push({ command: command === process.execPath ? 'node' : command,
    args: args.map(portable), exitCode: result.status,
    stdout: portable(result.stdout || ''), stderr: portable(result.stderr || ''),
    error: result.error?.message || null });
  assert.equal(result.status, 0, `Command failed: ${command} ${args.join(' ')}\n${result.stderr || result.error || ''}`);
  return result.stdout;
}
try {
  for (const directory of ['src', 'bin']) {
    for (const name of fs.readdirSync(path.join(root, directory)).filter((n) => n.endsWith('.js')).sort()) {
      report.sourceSha256[directory + '/' + name] = sha256(fs.readFileSync(path.join(root, directory, name)));
    }
  }
  for (const [name, digest] of Object.entries(expected.filesSha256)) {
    const actual = sha256(fs.readFileSync(file(name)));
    report.evidenceSha256[name] = actual;
    assert.equal(actual, digest, `Evidence bytes changed: ${name}`);
  }
  const manifest = JSON.parse(fs.readFileSync(file('manifest.json'), 'utf8'));
  const canonical = Buffer.from(canonicalize(manifest), 'utf8');
  assert.ok(canonical.equals(fs.readFileSync(file(expected.canonicalFile))), 'Canonical bytes mismatch');
  assert.equal(sha256(canonical), expected.timestampImprintSha256);
  run('openssl', ['version']);
  const query = run('openssl', ['ts', '-query', '-in', file(expected.queryFile), '-text']);
  const reply = run('openssl', ['ts', '-reply', '-in', file(expected.responseFile), '-text']);
  assert.equal(query.match(/^Nonce:\s*(.+)$/m)?.[1], expected.nonce);
  assert.equal(reply.match(/^Nonce:\s*(.+)$/m)?.[1], expected.nonce);
  for (const name of ['cacert.pem', 'tsa.crt']) {
    run('openssl', ['x509', '-in', file(name), '-noout', '-subject', '-issuer', '-dates', '-fingerprint', '-sha256']);
  }
  run('openssl', ['verify', '-purpose', 'timestampsign', '-show_chain', '-CAfile', file('cacert.pem'), file('tsa.crt')]);
  const trust = ['-in', file(expected.responseFile), '-CAfile', file('cacert.pem'), '-untrusted', file('tsa.crt')];
  run('openssl', ['ts', '-verify', ...trust, '-queryfile', file(expected.queryFile)]);
  run('openssl', ['ts', '-verify', ...trust, '-data', file(expected.canonicalFile)]);
  const output = run(process.execPath, [path.join(root, 'bin/aura.js'), 'verify',
    '--manifest', file('manifest.json'), '--public-key', file('public-key.pem'),
    '--issuer', file('issuer.json'), '--asset', file(expected.assetFile),
    '--timestamp-response', file(expected.responseFile), '--timestamp-query', file(expected.queryFile),
    '--tsa-ca', file('cacert.pem'), '--tsa-untrusted', file('tsa.crt'), '--json']);
  const result = JSON.parse(output);
  assert.equal(result.status, 'valid');
  assert.equal(result.schemaValidation.status, 'pass');
  assert.equal(result.assetHashOk, true);
  assert.equal(result.signatureOk, true);
  assert.equal(result.issuerKeyOk, true);
  assert.equal(result.auraTimestampedChecks, 'technical_checks_passed');
  assert.equal(result.timestamp.status, 'verified');
  assert.equal(result.timestamp.genTime, expected.genTime);
  assert.equal(result.timestamp.tsaSerial, expected.tsaSerial);
  assert.equal(result.timestamp.tsaPolicy, expected.tsaPolicy);
  assert.equal(result.timestamp.manifestHashSha3_256, expected.manifestHashSha3_256);
  assert.equal(result.timestamp.timestampImprintSha256, expected.timestampImprintSha256);
  assert.equal(result.timestamp.nonceCheck, 'passed_against_supplied_request');
  assert.equal(result.timestamp.qualifiedEidas, 'not_assessed');
  report.result = result;
  report.status = 'passed';
} catch (error) {
  report.status = 'failed';
  report.error = error.message;
  process.exitCode = 1;
}
console.log(JSON.stringify(report, null, 2));
