import { createV11Package } from './v11-package.js';

export function pemErrorCases() {
  const pkg = createV11Package();
  const cases = [
    ['whitespace-key', ' \n\t '],
    ['invalid-base64-key', '-----BEGIN PUBLIC KEY-----\n%%%\n-----END PUBLIC KEY-----'],
    ['concatenated-keys', pkg.publicKeyPem + pkg.publicKeyPem],
  ].map(([name, publicKeyPem]) => ({
    name, pkg: { ...pkg, publicKeyPem }, expected: {
      status: 'invalid', signatureOk: false, integrityStatus: 'verified',
      assetHashOk: true, issuerKeyPinOk: null, issuerKeyOk: false,
      publicKeyFingerprintSha256: null, publicKeyFingerprintSha3_256: null,
      keyStatusCheck: 'not_checked', keyRevoked: false,
    },
  }));
  for (const [name, publicKeyPem] of [
    ['malformed-embedded-key', 'not a PEM'],
    ['non-text-embedded-key', { key: 'invalid' }],
    ['concatenated-embedded-keys', pkg.publicKeyPem + pkg.publicKeyPem],
  ]) {
    cases.push({ name, pkg: createV11Package({ beforeSign: manifest => {
      manifest.issuer.public_key_pem = publicKeyPem;
    } }), expected: {
      status: 'invalid', signatureOk: true, integrityStatus: 'verified',
      assetHashOk: true, issuerKeyPinOk: true, issuerKeyOk: true,
    } });
  }
  return cases;
}

export function jsonErrorCases() {
  return [
    ['malformed-manifest-json', 'manifestText', '{"a":'],
    ['duplicate-manifest-json', 'manifestText', '{"a":1,"a":2}'],
    ['malformed-issuer-json', 'issuerText', '{"a":'],
    ['duplicate-issuer-json', 'issuerText', '{"status":"revoked","status":"active"}'],
    ['empty-issuer-json', 'issuerText', ''],
  ].map(([name, field, value]) => ({ name, field, pkg: { ...createV11Package(), [field]: value } }));
}
