import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hardeningCases } from './helpers/hardening-cases.js';
import { canonicalize, unsignedManifest } from '../src/jcs.js';
import { pemToDer, ed25519SignatureBytes } from '../src/pem.js';
import { verifyAuraPackage } from '../src/verify-node.js';

// The optional override lets an offline reviewer use a preinstalled Playwright.
const { chromium, firefox, webkit } = await import(process.env.AURA_PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)).replace(/[\\/]$/, '');
const cases = hardeningCases();
const server = http.createServer((req, res) => {
  const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404); res.end(); return;
  }
  res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.json') ? 'application/json' : file.endsWith('.css') ? 'text/css' : 'text/html');
  res.end(fs.readFileSync(file));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const results = [];
try {
  for (const [name, engine] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
    const options = { headless: true };
    if (name === 'chromium' && process.env.AURA_CHROME_EXECUTABLE) options.executablePath = process.env.AURA_CHROME_EXECUTABLE;
    const browser = await engine.launch(options);
    const result = { browser: name, version: browser.version(), cases: [], externalRequests: [] };
    results.push(result);
    try {
      const page = await browser.newPage();
      await page.route('**/*', route => {
        if (new URL(route.request().url()).origin !== origin) {
          result.externalRequests.push(route.request().url()); return route.abort();
        }
        return route.continue();
      });
      await page.goto(origin + '/web/index.html');
      result.nistVectors = await page.evaluate(async () => {
        const { sha3_256_hex } = await import('/src/sha3.js');
        const data = await (await fetch('/tests/vectors/sha3/nist-short-messages.json')).json();
        for (const v of data.vectors) {
          const bytes = Uint8Array.from(v.message.match(/../g) || [], s => parseInt(s, 16));
          if (sha3_256_hex(bytes) !== v.sha3_256) throw new Error(`NIST vector failed: ${v.bytes}`);
        }
        return data.vectors.length;
      });
      assert.equal(result.nistVectors, 137);
      for (const { name: test, pkg, expected } of cases) {
        await page.goto(origin + '/web/index.html');
        for (const [selector, value, filename, mimeType] of [
          ['#manifest', pkg.manifestText, 'manifest.json', 'application/json'],
          ['#issuer', pkg.issuerText, 'issuer.json', 'application/json'],
          ['#publicKey', pkg.publicKeyPem, 'public-key.pem', 'text/plain'],
          ['#asset', pkg.assetBytes, 'asset.bin', 'application/octet-stream'],
        ]) {
          await page.locator(selector).setInputFiles(value === null ? [] : { name: filename, mimeType, buffer: Buffer.from(value) });
        }
        await page.locator('#verify').click();
        await page.locator('#result:not(.hidden) pre').waitFor();
        const actual = JSON.parse(await page.locator('#result pre').innerText());
        try {
          for (const [field, value] of Object.entries(expected)) assert.equal(actual[field], value, `${name}/${test}/${field}`);
        } catch (error) {
          // These are freshly generated fictional fixtures, with no private keys.
          // Preserve the failing input: a new run generates different signatures.
          result.failedCase = { name: test, expected, actual, fixture: {
            manifestText: pkg.manifestText, publicKeyPem: pkg.publicKeyPem,
            issuerText: pkg.issuerText, assetHex: Buffer.from(pkg.assetBytes).toString('hex'),
          } };
          try {
            result.failedCase.nodeResult = await verifyAuraPackage(pkg);
            const manifest = JSON.parse(pkg.manifestText);
            result.failedCase.nativeBrowser = await page.evaluate(async ({ der, signature, payload }) => {
              const results = {};
              for (const format of ['spki', 'raw']) {
                try {
                  const key = await crypto.subtle.importKey(format, new Uint8Array(format === 'raw' ? der.slice(-32) : der), 'Ed25519', false, ['verify']);
                  results[format] = await crypto.subtle.verify('Ed25519', key, new Uint8Array(signature), new Uint8Array(payload));
                } catch (e) { results[format] = String(e); }
              }
              return results;
            }, {
              der: Array.from(pemToDer(pkg.publicKeyPem)),
              signature: Array.from(ed25519SignatureBytes(manifest.signature.value)),
              payload: Array.from(Buffer.from(canonicalize(unsignedManifest(manifest)))),
            });
          } catch (diagnosticError) { result.failedCase.diagnosticError = String(diagnosticError); }
          console.error('Browser failure diagnostic: ' + JSON.stringify(result.failedCase));
          throw error;
        }
        if (actual.keyRevoked) {
          const message = await page.locator('.revoked-note').innerText();
          assert.ok(message.includes('historical validity is not assessed'));
          assert.ok(!message.includes('No signature from a revoked key can be trusted'));
        }
        if (actual.keyStatusCheck === 'invalid_registry') assert.equal(actual.registryValidation.status, 'invalid');
        result.cases.push({ name: test, status: actual.status, signatureOk: actual.signatureOk, keyStatusCheck: actual.keyStatusCheck, integrityStatus: actual.integrityStatus });
      }
      assert.equal(result.externalRequests.length, 0);
      console.log(`${name} ${result.version}: ${result.nistVectors} NIST vectors; ${result.cases.length} UI cases; no external requests.`);
    } finally { await browser.close(); }
  }
} finally {
  await new Promise(resolve => server.close(resolve));
  if (process.env.AURA_BROWSER_REPORT) fs.writeFileSync(process.env.AURA_BROWSER_REPORT, JSON.stringify(results, null, 2));
}
