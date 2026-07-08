// Lightweight, dependency-free structural validation against the published
// AURA manifest v1.1.0 schema (aura-standard.org/schema/aura-manifest-v1.1.0.json).
//
// The published schema is the normative reference for manifest shape. This is a
// minimal in-browser/in-node mirror of its hard constraints — enough to reject a
// malformed v1.1 manifest before we bother checking a signature, without pulling
// in a full JSON-Schema engine.
//
// It only gates manifests that declare aura_version "1.1". A v0.1/v1.0 manifest
// is passed through untouched: a conformant verifier MUST accept both v1.0 and
// v1.1 (see AURA-STANDARD schema/README.md).

const AURA_UID_RE = /^aura:v1:[0-9A-HJKMNP-TV-Z]{26}$/;
const DIGEST_RE = /^sha3-256:[0-9a-f]{64}$/;

export function checkManifestStructure(manifest) {
  const errors = [];
  const warnings = [];

  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    errors.push('Manifest is not a JSON object.');
    return { errors, warnings };
  }

  // Only v1.1 is gated here; older versions are accepted as-is.
  if (manifest.aura_version !== '1.1') {
    return { errors, warnings };
  }

  const required = [
    'aura_version',
    'aura_uid',
    'issuer',
    'issued_at',
    'signature',
    'reference_anchor',
  ];
  for (const key of required) {
    if (!(key in manifest)) errors.push(`v1.1 manifest is missing required field: ${key}.`);
  }

  if (manifest.aura_uid && !AURA_UID_RE.test(manifest.aura_uid)) {
    errors.push('aura_uid does not match the v1 pattern aura:v1:<26 Crockford-base32 chars>.');
  }

  const signature = manifest.signature;
  if (signature && typeof signature === 'object') {
    if (signature.algorithm && signature.algorithm !== 'Ed25519') {
      errors.push(`Unsupported signature algorithm: ${signature.algorithm} (schema requires Ed25519).`);
    }
    if (signature.canonicalization && signature.canonicalization !== 'RFC-8785-JCS') {
      errors.push(`Unexpected canonicalization: ${signature.canonicalization} (schema requires RFC-8785-JCS).`);
    }
  }

  const ra = manifest.reference_anchor;
  if (ra && typeof ra === 'object') {
    for (const block of ['standard', 'verifier', 'issuer_key']) {
      if (!(block in ra)) errors.push(`reference_anchor is missing required block: ${block}.`);
    }
    const ik = ra.issuer_key;
    if (ik && typeof ik === 'object') {
      if (ik.public_key_digest && !DIGEST_RE.test(ik.public_key_digest)) {
        errors.push('reference_anchor.issuer_key.public_key_digest is not a valid sha3-256:<64 hex> digest.');
      }
      if (ik.algorithm && ik.algorithm !== 'Ed25519') {
        errors.push('reference_anchor.issuer_key.algorithm must be Ed25519.');
      }
    }
  }

  return { errors, warnings };
}
