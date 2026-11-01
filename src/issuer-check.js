const FINGERPRINTS = ['public_key_fingerprint_sha256', 'public_key_fingerprint_sha3_256'];
const HEX_256 = /^[0-9a-f]{64}$/;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isText = value => typeof value === 'string' && value.trim().length > 0;

// Local input policy, not authentication or freshness verification of a registry.
// Unknown extension fields remain allowed; known revocation fields fail closed.
export function inspectIssuerRegistry(issuer, supplied = true) {
  const errors = [];
  if (!supplied) return { status: 'not_checked', errors };
  if (!isObject(issuer)) {
    return { status: 'invalid', errors: ['issuer.json must be a JSON object.'] };
  }
  for (const field of FINGERPRINTS) {
    if (typeof issuer[field] !== 'string' || !HEX_256.test(issuer[field])) {
      errors.push(`issuer.json.${field} must be a 64-character lowercase hexadecimal fingerprint.`);
    }
  }
  if (!isText(issuer.status)) errors.push('issuer.json.status must be a non-empty string.');
  if (issuer.algorithm !== undefined && issuer.algorithm !== 'Ed25519') {
    errors.push('issuer.json.algorithm must be Ed25519 when supplied.');
  }
  for (const field of ['key_id', 'revoked_at', 'revocation_reason', 'superseded_by']) {
    if (issuer[field] !== undefined && !isText(issuer[field])) errors.push(`issuer.json.${field} must be a non-empty string when supplied.`);
  }
  if (issuer.revoked_keys !== undefined) {
    if (!Array.isArray(issuer.revoked_keys)) {
      errors.push('issuer.json.revoked_keys must be an array when supplied.');
    } else {
      issuer.revoked_keys.forEach((entry, index) => {
        const label = `issuer.json.revoked_keys[${index}]`;
        if (!isObject(entry)) {
          errors.push(`${label} must be an object with a key fingerprint.`);
          return;
        }
        const present = FINGERPRINTS.filter(field => entry[field] !== undefined);
        if (present.length === 0) errors.push(`${label} must contain at least one key fingerprint; key_id alone is insufficient.`);
        for (const field of present) {
          if (typeof entry[field] !== 'string' || !HEX_256.test(entry[field])) {
            errors.push(`${label}.${field} must be a 64-character lowercase hexadecimal fingerprint.`);
          }
        }
        if (entry.status !== undefined && entry.status !== 'revoked') {
          errors.push(`${label}.status must be revoked when supplied.`);
        }
        for (const field of ['key_id', 'revoked_at', 'revocation_reason', 'superseded_by']) {
          if (entry[field] !== undefined && !isText(entry[field])) errors.push(`${label}.${field} must be a non-empty string when supplied.`);
        }
      });
    }
  }
  return { status: errors.length ? 'invalid' : 'pass', errors };
}
