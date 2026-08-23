// Lightweight, dependency-free structural validation against the published
// AURA manifest v1.0.0 / v1.1.0 schemas and optional published profile
// overlays.
//
// The published schema is the normative reference for manifest shape. This is a
// minimal in-browser/in-node mirror of its hard constraints — enough to reject a
// malformed published manifest before checking a signature, without pulling
// in a full JSON-Schema engine.
//
// It gates manifests that declare aura_version "1.0" or "1.1". Legacy draft and
// explicit test-vector versions are passed through for backwards-compatible
// cryptographic checks.

const AURA_UID_RE = /^aura:v1:[0-9A-HJKMNP-TV-Z]{26}$/;
const DIGEST_RE = /^sha3-256:[0-9a-f]{64}$/;
const ASSET_HASH_RE = /^[0-9a-f]{64}$/;

export const TDM_RIGHTS_RESERVATION_PROFILE = 'AURA_TDM_RIGHTS_RESERVATION_V1';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function inspectTdmRightsReservation(manifest) {
  const claimed = manifest?.profile === TDM_RIGHTS_RESERVATION_PROFILE;
  const value = manifest?.declarations?.tdm_opt_out;

  return {
    claimed,
    fieldPath: 'declarations.tdm_opt_out',
    value: value === undefined ? null : value,
    declared: claimed && value === true,
  };
}

export function checkManifestStructure(manifest) {
  const errors = [];
  const warnings = [];

  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    errors.push('Manifest is not a JSON object.');
    return { errors, warnings };
  }

  // Published v1.0 and v1.1 manifests are structurally gated. Legacy draft and
  // explicit test-vector versions remain accepted for cryptographic checks.
  if (manifest.aura_version !== '1.0' && manifest.aura_version !== '1.1') {
    return { errors, warnings };
  }

  const required = [
    'aura_version',
    'aura_uid',
    'issuer',
    'issued_at',
    'signature',
  ];
  if (manifest.aura_version === '1.1') required.push('reference_anchor');
  for (const key of required) {
    if (!(key in manifest)) {
      errors.push(`v${manifest.aura_version} manifest is missing required field: ${key}.`);
    }
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
  if (manifest.aura_version === '1.1' && isObject(ra)) {
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

  const tdm = inspectTdmRightsReservation(manifest);
  if (tdm.claimed) {
    if (!isObject(manifest.issuer) || typeof manifest.issuer.id !== 'string' || manifest.issuer.id.length === 0) {
      errors.push(`${TDM_RIGHTS_RESERVATION_PROFILE} requires a non-empty issuer.id.`);
    }

    if (!isObject(manifest.asset)) {
      errors.push(`${TDM_RIGHTS_RESERVATION_PROFILE} requires an asset object.`);
    } else {
      if (manifest.asset.hash_algorithm !== 'SHA3-256') {
        errors.push(`${TDM_RIGHTS_RESERVATION_PROFILE} requires asset.hash_algorithm to be SHA3-256.`);
      }
      if (typeof manifest.asset.hash !== 'string' || !ASSET_HASH_RE.test(manifest.asset.hash)) {
        errors.push(`${TDM_RIGHTS_RESERVATION_PROFILE} requires asset.hash to be 64 lowercase hexadecimal SHA3-256 characters.`);
      }
    }

    if (!isObject(manifest.declarations) || manifest.declarations.tdm_opt_out !== true) {
      errors.push(`${TDM_RIGHTS_RESERVATION_PROFILE} requires declarations.tdm_opt_out to be exactly the JSON boolean true.`);
    }
  }

  return { errors, warnings };
}
