// Lightweight, dependency-free structural validation against the published
// AURA manifest v1.0.0 / v1.1.0 schemas and optional published profile
// overlays.
//
// The published schema is the normative reference for manifest shape. This is a
// minimal in-browser/in-node mirror of its hard constraints — enough to reject a
// malformed published manifest before checking a signature, without pulling
// in a full JSON-Schema engine.
//
// Only published manifest versions "1.0" and "1.1" are supported. A
// cryptographically valid signature cannot establish support for another version.

import { checkBaseSchema } from './base-schema-check.js';
const ASSET_HASH_RE = /^[0-9a-f]{64}$/;

export const TDM_RIGHTS_RESERVATION_PROFILE = 'AURA_TDM_RIGHTS_RESERVATION_V1';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function inspectAssetHash(manifest) {
  const hash = manifest?.asset?.hash || manifest?.asset?.asset_hash_sha3_256 || manifest?.asset_hash || null;
  const algorithms = [manifest?.asset?.hash_algorithm, manifest?.asset_hash_algorithm]
    .filter((value) => value !== undefined);
  return {
    hash,
    algorithmSupported: algorithms.length > 0 && algorithms.every((value) => value === 'SHA3-256'),
    algorithms,
  };
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
  const baseSchema = checkBaseSchema(manifest);
  const errors = [...baseSchema.errors];
  const warnings = [];

  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    errors.push('Manifest is not a JSON object.');
    return { errors, warnings };
  }

  // Do not interpret arbitrary future or historical versions as current AURA.
  if (manifest.aura_version !== '1.0' && manifest.aura_version !== '1.1') {
    errors.push('Unsupported AURA manifest version; supported versions are "1.0" and "1.1".');
  }

  const assetHash = inspectAssetHash(manifest);
  if (assetHash.algorithms.some((value) => value !== 'SHA3-256')) {
    errors.push('Unsupported asset hash algorithm; only SHA3-256 is supported.');
  } else if (assetHash.hash && !assetHash.algorithmSupported) {
    errors.push('A declared asset hash requires an explicit SHA3-256 hash algorithm.');
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
