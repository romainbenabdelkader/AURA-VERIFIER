import { canonicalize, unsignedManifest } from './jcs.js';
import { sha3_256_hex } from './sha3.js';
import { base64ToBytes, pemToDer, sameBytes } from './pem.js';
import { checkManifestStructure } from './schema-check.js';

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function extractAssetHash(manifest) {
  return manifest?.asset?.hash || manifest?.asset_hash || null;
}

// A catalog claim is a signed, timestamped catalogue declaration issued WITHOUT
// a supplied asset file. It is detected from explicit markers; the integrity
// decision below also treats "no file + no declared hash" as not-applicable.
function isCatalogClaim(manifest) {
  const marker =
    manifest?.evidence_type ||
    manifest?.evidenceType ||
    manifest?.proof_level ||
    manifest?.proofLevel ||
    manifest?.profile ||
    '';
  return (
    (manifest && typeof manifest.catalog_claim === 'object' && manifest.catalog_claim !== null) ||
    /catalog[_-]?claim/i.test(String(marker))
  );
}

function statusFromChecks(errors, warnings) {
  if (errors.length > 0) return 'invalid';
  if (warnings.length > 0) return 'warning';
  return 'valid';
}

export async function verifyAuraPackageBrowser({
  assetBytes = null,
  manifestText,
  publicKeyPem,
  issuerText = null,
}) {
  const warnings = [];
  const errors = [];
  const manifest = JSON.parse(manifestText);
  const issuer = issuerText ? JSON.parse(issuerText) : null;
  const signature = manifest.signature || {};

  // Structural validation against the v1.1.0 schema (no-op for v0.1/v1.0).
  const structure = checkManifestStructure(manifest);
  errors.push(...structure.errors);
  warnings.push(...structure.warnings);

  // --- Asset integrity (optional asset; fileless catalog claims are N/A) ---
  const manifestAssetHash = extractAssetHash(manifest);
  const catalogClaim = isCatalogClaim(manifest);
  let computedAssetHash = null;
  let assetHashOk = null; // true | false | null (not applicable / not checked)
  let integrityStatus; // 'verified' | 'mismatch' | 'not_checked' | 'not_applicable'

  if (assetBytes) {
    computedAssetHash = sha3_256_hex(new Uint8Array(assetBytes));
    if (manifestAssetHash) {
      assetHashOk = computedAssetHash === manifestAssetHash;
      integrityStatus = assetHashOk ? 'verified' : 'mismatch';
      if (!assetHashOk) errors.push('Asset hash mismatch.');
    } else {
      integrityStatus = 'not_checked';
      warnings.push('Asset file supplied but the manifest declares no asset hash; integrity was not checked.');
    }
  } else if (manifestAssetHash && !catalogClaim) {
    integrityStatus = 'not_checked';
    warnings.push('No asset file supplied; asset integrity was NOT verified. Supply the original file to check integrity.');
  } else {
    // Catalog claim / fileless declaration: no asset to hash. This is expected,
    // not an error — we verify the signed declaration, not file integrity.
    integrityStatus = 'not_applicable';
  }

  // --- Signature ---
  const publicKeyDer = pemToDer(publicKeyPem);
  const payload = new TextEncoder().encode(canonicalize(unsignedManifest(manifest)));
  let signatureOk = false;

  if (!signature.value) {
    errors.push('Manifest signature is missing.');
  } else {
    try {
      const key = await crypto.subtle.importKey('spki', publicKeyDer, { name: 'Ed25519' }, false, ['verify']);
      signatureOk = await crypto.subtle.verify({ name: 'Ed25519' }, key, base64ToBytes(signature.value), payload);
      if (!signatureOk) errors.push('Ed25519 signature mismatch.');
    } catch (error) {
      signatureOk = false;
      errors.push(
        `Browser Ed25519 verification failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const publicKeySha256 = await sha256Hex(publicKeyDer);
  const publicKeySha3 = sha3_256_hex(publicKeyDer);

  if (manifest?.issuer?.public_key_pem) {
    const manifestKeyDer = pemToDer(manifest.issuer.public_key_pem);
    if (!sameBytes(publicKeyDer, manifestKeyDer)) {
      errors.push('Provided public key does not match manifest issuer public key.');
    }
  }

  // --- Reference-anchor issuer-key digest pinning (v1.1) ---
  // The signed manifest pins the issuer key by its DER (SPKI) sha3-256 digest.
  // The key is trusted only if it matches that digest — trust is anchored in the
  // signed payload, never in where the key was fetched from.
  let issuerKeyPinOk = null;
  const pinnedDigest = manifest?.reference_anchor?.issuer_key?.public_key_digest || null;
  if (pinnedDigest) {
    issuerKeyPinOk = pinnedDigest === `sha3-256:${publicKeySha3}`;
    if (!issuerKeyPinOk) {
      errors.push('Public key does not match reference_anchor.issuer_key.public_key_digest (DER/SPKI sha3-256).');
    }
  }

  let issuerKeyOk = false;
  let issuerStatus = null;
  if (issuer) {
    issuerStatus = issuer.status || null;
    issuerKeyOk =
      issuer.public_key_fingerprint_sha256 === publicKeySha256 &&
      issuer.public_key_fingerprint_sha3_256 === publicKeySha3;

    if (!issuerKeyOk) errors.push('Issuer fingerprint does not match provided public key.');
    if (issuer.status !== 'active') warnings.push(`Issuer status is ${issuer.status || 'unknown'}.`);
  } else {
    warnings.push('No issuer.json provided; issuer status and fingerprint were not checked.');
  }

  // --- Revoked / compromised issuer keys (out-of-band, from issuer.json) ---
  // Match by public-key fingerprint (sha256 OR sha3-256/DER), never by key_id
  // alone: a manifest need not carry a key_id, and a compromised key means no
  // signature from it can be trusted. A match is a hard failure, not a warning.
  let keyRevoked = false;
  let revocation = null;
  const revokedKeys = issuer && Array.isArray(issuer.revoked_keys) ? issuer.revoked_keys : [];
  const revokedMatch = revokedKeys.find(
    (rk) =>
      (rk?.public_key_fingerprint_sha256 && rk.public_key_fingerprint_sha256 === publicKeySha256) ||
      (rk?.public_key_fingerprint_sha3_256 && rk.public_key_fingerprint_sha3_256 === publicKeySha3),
  );
  if (revokedMatch) {
    keyRevoked = true;
    const reason = revokedMatch.revocation_reason || 'key revocation';
    const superseded = revokedMatch.superseded_by ? `, superseded by ${revokedMatch.superseded_by}` : '';
    revocation = {
      keyId: revokedMatch.key_id || null,
      revokedAt: revokedMatch.revoked_at || null,
      reason,
      supersededBy: revokedMatch.superseded_by || null,
    };
    errors.push(`Key revoked after ${reason}${superseded}.`);
  }

  if (signature.canonicalization && signature.canonicalization !== 'RFC-8785-JCS') {
    warnings.push(`Unexpected canonicalization: ${signature.canonicalization}.`);
  }

  if (signature.algorithm && signature.algorithm !== 'Ed25519') {
    errors.push(`Unsupported signature algorithm: ${signature.algorithm}.`);
  }

  const status = statusFromChecks(errors, warnings);

  return {
    status,
    valid: status === 'valid',
    evidenceType: catalogClaim ? 'catalog_claim' : 'evidence_package',
    auraUid: manifest.aura_uid || manifest.aura_id || null,
    integrityStatus,
    assetHashOk,
    signatureOk,
    issuerKeyPinOk,
    issuerKeyOk,
    keyRevoked,
    revocation,
    issuerStatus,
    computedAssetHash,
    manifestAssetHash,
    publicKeyFingerprintSha256: publicKeySha256,
    publicKeyFingerprintSha3_256: publicKeySha3,
    canonicalization: signature.canonicalization || null,
    signatureAlgorithm: signature.algorithm || null,
    signatureFormat: signature.format || null,
    issuedAt: manifest.issued_at || null,
    proofScope: manifest?.proof?.scope || null,
    warnings,
    errors,
  };
}
