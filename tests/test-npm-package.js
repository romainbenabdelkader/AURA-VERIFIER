import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const metadata = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aura package test-'));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, 'Run this test through npm run test:package.');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const results = [];

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024,
  });
  assert.ifError(result.error);
  return result;
}

function npm(args, cwd) {
  const result = run(process.execPath, [npmCli, ...args], cwd);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

function allowed(name) {
  return ['package.json', 'README.md', 'LICENSE', 'INTEGRATORS.md',
    'RELEASE_NOTES.md', 'CITATION.cff', 'scripts/verify-timestamp-example.js'].includes(name)
    || /^(?:bin|src|web|docs)\//.test(name)
    || name.startsWith('examples/rfc3161-freetsa/');
}

try {
  assert.equal(metadata.name, 'aura-verifier');
  assert.deepEqual(metadata.dependencies || {}, {});
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    assert.equal(metadata.scripts?.[hook], undefined, 'Unexpected install hook: ' + hook);
  }
  const packOutput = JSON.parse(npm(['pack', '--json', '--ignore-scripts',
    '--pack-destination', temporary], root));
  // npm 12 keys its result by package name; earlier versions return an array.
  const entries = Array.isArray(packOutput) ? packOutput : Object.values(packOutput);
  assert.equal(entries.length, 1, 'Exactly one package must be packed');
  const [packed] = entries;
  assert.equal(packed.name, metadata.name);
  assert.equal(packed.version, metadata.version);
  assert.deepEqual(packed.bundled, []);
  for (const file of packed.files) {
    assert.ok(allowed(file.path), 'Unexpected package entry: ' + file.path);
    assert.ok(!/(?:^|\/)(?:\.git|\.npmrc|node_modules)(?:\/|$)/.test(file.path));
  }
  for (const required of ['bin/aura.js', 'src/verify-node.js', 'src/verify-web.js',
    'src/base-schemas.js', 'web/app.js', 'LICENSE', 'README.md',
    'examples/rfc3161-freetsa/manifest.tsr', 'docs/NPM_DISTRIBUTION.md']) {
    assert.ok(packed.files.some((file) => file.path === required), 'Missing ' + required);
  }

  const tarball = path.join(temporary, packed.filename);
  const consumer = path.join(temporary, 'consumer');
  fs.mkdirSync(consumer);
  fs.writeFileSync(path.join(consumer, 'package.json'), '{"private":true}\n');
  npm(['install', '--offline', '--ignore-scripts', '--omit=dev', '--no-audit',
    '--no-fund', '--package-lock=false', tarball], consumer);
  const installed = path.join(consumer, 'node_modules', metadata.name);
  const cli = path.join(consumer, 'node_modules', '.bin',
    process.platform === 'win32' ? 'aura.cmd' : 'aura');
  assert.ok(fs.existsSync(cli), 'npm must install the aura command');
  for (const file of packed.files) {
    const bytes = fs.readFileSync(path.join(installed, file.path));
    assert.ok(!bytes.includes(Buffer.from('-----BEGIN PRIVATE KEY-----')));
    assert.ok(!bytes.includes(Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----')));
    if (/^(?:bin|src|web)\//.test(file.path)) {
      assert.deepEqual(bytes, fs.readFileSync(path.join(root, file.path)), file.path);
    }
  }
  const dependencies = fs.readdirSync(path.join(consumer, 'node_modules'))
    .filter((name) => !name.startsWith('.'));
  assert.deepEqual(dependencies, [metadata.name], 'No runtime dependency should be installed');

  const fixture = path.join(installed, 'examples/rfc3161-freetsa');
  const file = (name) => path.join(fixture, name);
  const defaults = {
    manifest: file('manifest.json'), 'public-key': file('public-key.pem'),
    asset: file('asset.txt'), issuer: file('issuer.json'),
  };
  function check(name, options, status, exitCode, assertions) {
    const args = ['verify'];
    for (const [key, value] of Object.entries({ ...defaults, ...options })) {
      if (value !== null) args.push('--' + key, value);
    }
    args.push('--json');
    // Exercise npm's executable link, not the source-tree CLI.
    const command = process.platform === 'win32' ? process.execPath : cli;
    const argv = process.platform === 'win32' ? [path.join(installed, 'bin/aura.js'), ...args] : args;
    const result = run(command, argv, consumer);
    assert.equal(result.status, exitCode, name + ': ' + result.stderr + result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, status, name);
    assertions(report);
    results.push({ name, status: report.status, exitCode: result.status });
  }
  check('valid', {}, 'valid', 0, (r) => {
    assert.equal(r.signatureOk, true);
    assert.equal(r.assetHashOk, true);
    assert.equal(r.issuerKeyOk, true);
  });
  const changedAsset = path.join(consumer, 'changed asset.txt');
  fs.writeFileSync(changedAsset, 'Changed after signing\n');
  check('changed-asset', { asset: changedAsset }, 'invalid', 2, (r) => {
    assert.equal(r.signatureOk, true);
    assert.equal(r.assetHashOk, false);
  });
  const changedManifest = path.join(consumer, 'changed manifest.json');
  const manifest = JSON.parse(fs.readFileSync(defaults.manifest, 'utf8'));
  manifest.declarations = { ...manifest.declarations, note: 'Changed after signing' };
  fs.writeFileSync(changedManifest, JSON.stringify(manifest));
  check('changed-manifest', { manifest: changedManifest }, 'invalid', 2, (r) => {
    assert.equal(r.signatureOk, false);
    assert.equal(r.assetHashOk, true);
  });
  check('missing-asset', { asset: null }, 'warning', 1, (r) => {
    assert.equal(r.signatureOk, true);
    assert.equal(r.integrityStatus, 'not_checked');
  });
  check('missing-issuer', { issuer: null }, 'warning', 1, (r) => {
    assert.equal(r.signatureOk, true);
    assert.equal(r.assetHashOk, true);
  });
  const badJson = path.join(consumer, 'bad.json');
  fs.writeFileSync(badJson, '{broken');
  check('malformed-json', { manifest: badJson }, 'input_error', 2, (r) => {
    assert.equal(r.error.code, 'invalid_json');
  });

  const inputs = {
    assetBytes: fs.readFileSync(defaults.asset),
    manifestText: fs.readFileSync(defaults.manifest, 'utf8'),
    issuerText: fs.readFileSync(defaults.issuer, 'utf8'),
    publicKeyPem: fs.readFileSync(defaults['public-key'], 'utf8'),
  };
  for (const [module, method] of [['verify-node.js', 'verifyAuraPackage'],
    ['verify-web.js', 'verifyAuraPackageBrowser']]) {
    const api = await import(pathToFileURL(path.join(installed, 'src', module)).href);
    const report = await api[method](inputs);
    assert.equal(report.status, 'valid');
    assert.equal(report.signatureOk, true);
    assert.equal(report.assetHashOk, true);
    results.push({ name: 'installed-' + module, status: report.status });
  }

  if (process.env.AURA_NPM_TEST_TIMESTAMP === '1') {
    const timestampOptions = {
      'timestamp-response': file('manifest.tsr'), 'timestamp-query': file('manifest.tsq'),
      'tsa-ca': file('cacert.pem'),
      // OpenSSL ts treats -untrusted as a whitespace-separated filename list.
      // A relative path avoids the spaces deliberately present in temporary.
      'tsa-untrusted': path.relative(consumer, file('tsa.crt')),
    };
    check('installed-rfc3161', timestampOptions, 'valid', 0, (r) => {
      assert.equal(r.timestamp.status, 'verified');
      assert.equal(r.timestamp.nonceCheck, 'passed_against_supplied_request');
      assert.equal(r.timestamp.qualifiedEidas, 'not_assessed');
    });
    check('installed-rfc3161-tampered', {
      ...timestampOptions, manifest: changedManifest,
    }, 'invalid', 2, (r) => {
      assert.equal(r.timestamp.status, 'invalid');
      assert.equal(r.signatureOk, false);
      assert.equal(r.assetHashOk, true);
    });
  }
  const digest = sha256(fs.readFileSync(tarball));
  const report = {
    name: metadata.name, version: metadata.version, node: process.version,
    npm: npm(['--version'], consumer).trim(), status: 'passed',
    files: packed.files.length, bytes: packed.size, sha256: digest, results,
    timestampChecked: process.env.AURA_NPM_TEST_TIMESTAMP === '1',
  };
  if (process.env.AURA_NPM_ARTIFACT_DIR) {
    const output = path.resolve(root, process.env.AURA_NPM_ARTIFACT_DIR);
    fs.mkdirSync(output, { recursive: true });
    fs.copyFileSync(tarball, path.join(output, packed.filename));
    fs.writeFileSync(path.join(output, 'package-test.json'), JSON.stringify(report, null, 2) + '\n');
    fs.writeFileSync(path.join(output, 'package-inventory.json'), JSON.stringify(packed, null, 2) + '\n');
    fs.writeFileSync(path.join(output, 'SHA256SUMS'), digest + '  ' + packed.filename + '\n');
  }
  console.log(JSON.stringify(report, null, 2));
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
