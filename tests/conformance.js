import assert from 'node:assert/strict';
import { checkBaseSchema } from '../src/base-schema-check.js';
import { verifyAuraPackage } from '../src/verify-node.js';
import { verifyAuraPackageBrowser } from '../src/verify-web.js';
import { createV11Package } from './helpers/v11-package.js';

const mutations = [
  m => { delete m.reference_anchor.standard.schema_digest; },
  m => { m.reference_anchor.verifier.name = 'Independent verifier'; },
  m => { delete m.reference_anchor.verifier.release_tag; },
  m => { delete m.reference_anchor.verifier.source_digest; },
  m => { delete m.reference_anchor.verifier.archive_doi; },
  m => { delete m.reference_anchor.issuer_key.public_key_doi; },
  m => { m.reference_anchor = null; },
  m => { m.issuer = []; },
  m => { m.aura_uid = 42; },
  m => { m.reference_anchor.issuer_key.public_key_doi = ''; },
  m => { m.reference_anchor.standard.schema_digest = 'sha3-256:wrong'; },
  m => { m.prior_evidence = [{}]; },
];
for (const beforeSign of mutations) {
  const pkg = createV11Package({ beforeSign });
  for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
    const result = await verify(pkg);
    assert.equal(result.signatureOk, true);
    assert.equal(result.schemaValidation.status, 'fail');
    assert.equal(result.status, 'invalid');
  }
}
for (const version of ['1.0', '1.1']) {
  const pkg = createV11Package({ beforeSign(m) {
    m.aura_version = version;
    if (version === '1.0') delete m.reference_anchor;
    m.extension = { accepted: true };
  } });
  for (const verify of [verifyAuraPackage, verifyAuraPackageBrowser]) {
    const result = await verify(pkg);
    assert.equal(result.status, 'valid');
    assert.equal(result.schemaValidation.status, 'pass');
    assert.equal(result.archiveResolution, 'not_checked');
    assert.equal(result.issuerIdentity, 'not_assessed');
  }
}
assert.equal(checkBaseSchema({ aura_version: '9.0' }).status, 'not_checked');
for (const version of ['__proto__', 'constructor', 'toString', ['1.1'], null]) {
  assert.equal(checkBaseSchema({ aura_version: version }).status, 'not_checked');
}
const missingSignatureField = createV11Package().manifest;
delete missingSignatureField.signature.canonicalization;
assert.equal(checkBaseSchema(missingSignatureField).status, 'fail');
console.log('Conformance regression tests passed (Node and WebCrypto).');
