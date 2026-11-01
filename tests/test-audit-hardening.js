import assert from 'node:assert/strict';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { formatHumanResult } from '../src/report.js';
import { base64ToBytes } from '../src/pem.js';
import { hardeningCases } from './helpers/hardening-cases.js';

const cases = hardeningCases();
for (const { name, pkg, expected, humanIncludes } of cases) {
  for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
    const result = await verify(pkg);
    for (const [field, value] of Object.entries(expected)) assert.equal(result[field], value, `${name}: ${field}`);
    if (humanIncludes) assert.ok(formatHumanResult(result).includes(humanIncludes), `${name}: human report`);
    if (name.startsWith('matching-revoked-')) {
      const human = formatHumanResult(result);
      assert.equal(result.status, 'invalid');
      assert.ok(human.includes('Key revoked: YES'), `${name}: examined key is revoked`);
      assert.ok(human.includes('Current registry key status: active (supplied snapshot)'), `${name}: distinguish current record from examined key`);
      assert.ok(!human.includes('Issuer status:'), `${name}: remove ambiguous status label`);
    }
    if (result.keyStatusCheck === 'invalid_registry') {
      assert.equal(result.registryValidation.status, 'invalid');
      assert.ok(result.registryValidation.errors.length > 0);
      assert.equal(result.registryTrust.source, 'caller_supplied');
    }
  }
}
// Compare the decoding branches without asserting Node's permissive behavior.
for (const value of ['', 'Zg==', 'Zm8=', 'Zm9v']) {
  const expected = Array.from(Buffer.from(value, 'base64'));
  const saved = globalThis.Buffer;
  try {
    assert.deepEqual(Array.from(base64ToBytes(value)), expected);
    globalThis.Buffer = undefined;
    assert.deepEqual(Array.from(base64ToBytes(value)), expected);
  } finally { globalThis.Buffer = saved; }
}
console.log(`Audit hardening: ${cases.length} cases passed in both engines, including human reports.`);
