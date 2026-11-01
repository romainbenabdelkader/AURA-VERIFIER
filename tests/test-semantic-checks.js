import assert from 'node:assert/strict';
import { createV11Package } from './helpers/v11-package.js';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { formatHumanResult } from '../src/report.js';
let cases = 0;
async function check(pkg, status, inspect) {
  for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
    const result = await verify(pkg);
    assert.equal(result.status, status);
    assert.equal(result.signatureOk, true);
    inspect?.(result);
  }
  cases += 1;
}
for (const date of ['2026-01-01T00:00:00Z', '2024-02-29T23:59:59.123456789+01:30', '2000-02-29t00:00:00z', '2026-11-01T00:00:00-00:00', '2026-12-31T00:00:00-23:59']) {
  await check(createV11Package({beforeSign:m=>{m.issued_at=date;}}), 'valid', r=>{
    assert.equal(r.issuedAtValidation.status,'pass');
    assert.equal(r.issuedAtValidation.independentlyAttested,false);
  });
}
for (const date of ['not-a-date','2026-02-29T00:00:00Z','1900-02-29T00:00:00Z','2026-04-31T00:00:00Z','2026-00-01T00:00:00Z','2026-01-00T00:00:00Z','2026-13-01T00:00:00Z','2026-01-01T24:00:00Z','2026-01-01T00:60:00Z','2026-01-01T00:00:61Z','2026-01-01T00:00:00+24:00','2026-01-01T00:00:00+00:60','2026-01-01','2026-01-01T00:00:00','2026-01-01T00:00:00Zjunk']) {
  await check(createV11Package({beforeSign:m=>{m.issued_at=date;}}), 'invalid', r=>{
    assert.equal(r.issuedAtValidation.status,'invalid');
    assert.equal(r.schemaValidation.status,'pass'); // Semantic policy is separate.
  });
}
await check(createV11Package({beforeSign:m=>{m.issued_at='2016-12-31T23:59:60Z';}}),'warning',r=>assert.equal(r.issuedAtValidation.status,'not_checked'));
for (const mutate of [m=>{m.issuer.id='OTHER';},m=>{m.issuer.key_id='OTHER';},m=>{m.issuer.id='';},m=>{m.issuer.key_id=null;}]) {
  await check(createV11Package({beforeSign:mutate}),'invalid',r=>assert.equal(r.issuerIdentifiers.status,'fail'));
}
const otherRegistry=createV11Package();const registry=JSON.parse(otherRegistry.issuerText);registry.issuer='OTHER';otherRegistry.issuerText=JSON.stringify(registry);
await check(otherRegistry,'invalid',r=>assert.equal(r.issuerIdentifiers.status,'fail'));
const aliases=createV11Package();const a=JSON.parse(aliases.issuerText);a.issuer_id=a.issuer;aliases.issuerText=JSON.stringify(a);
await check(aliases,'valid');a.issuer_id='OTHER';aliases.issuerText=JSON.stringify(a);await check(aliases,'invalid');
const noRegistry={...createV11Package(),issuerText:null};await check(noRegistry,'warning',r=>{
  assert.equal(r.keyStatusCheck,'not_checked');assert.equal(r.registryTrust.freshness,'not_assessed');
  assert.match(formatHumanResult(r),/Key revoked: not checked/);
});
const legacy=createV11Package({beforeSign:m=>{m.aura_version='1.0';delete m.reference_anchor;delete m.issuer.id;}});
await check(legacy,'valid',r=>assert.equal(r.issuerIdentifiers.status,'not_checked'));
const rotated=createV11Package();const rotatedRegistry=JSON.parse(rotated.issuerText);
rotatedRegistry.key_id='different-current-key-label';rotatedRegistry.revoked_keys=[{public_key_fingerprint_sha256:rotatedRegistry.public_key_fingerprint_sha256}];rotated.issuerText=JSON.stringify(rotatedRegistry);
await check(rotated,'invalid',r=>{assert.equal(r.keyRevoked,true);assert.equal(r.keyStatusCheck,'revoked');});
const revokedCurrent=createV11Package();const rc=JSON.parse(revokedCurrent.issuerText);rc.status='revoked';revokedCurrent.issuerText=JSON.stringify(rc);
await check(revokedCurrent,'invalid',r=>{assert.equal(r.keyRevoked,true);assert.equal(r.keyStatusCheck,'revoked');});
console.log(`Semantic policy tests passed: ${cases} cases in both engines.`);
