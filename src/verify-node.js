import { inspectIssuedAt, inspectIssuerIdentifiers } from './semantic-check.js';
import { parseUniqueJson } from './strict-json.js';
import crypto from 'node:crypto';
import { inspectArchiveReferences } from './archive-check.js';
import { checkBaseSchema } from './base-schema-check.js';
import { canonicalize, unsignedManifest } from './jcs.js';
import { sha3_256_hex } from './sha3.js';
import { base64ToBytes, pemToDer, sameBytes } from './pem.js';
import { checkManifestStructure, inspectAssetHash, inspectTdmRightsReservation } from './schema-check.js';

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// A catalog claim is a signed catalogue declaration with an issuer-declared issuance time, issued WITHOUT
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

export async function verifyAuraPackage({
  assetBytes = null,
  manifestText,
  publicKeyPem,
  issuerText = null,
}) {
  const warnings = [];
  const errors = [];
  const manifest = parseUniqueJson(manifestText);
  const issuer = issuerText ? parseUniqueJson(issuerText) : null;
  const signature = manifest?.signature || {};

  // Structural validation and supported-version/algorithm policy are shared
  // with the WebCrypto engine. Unsupported versions always invalidate the result.
  const structure = checkManifestStructure(manifest);
  errors.push(...structure.errors);
  warnings.push(...structure.warnings);
  const issuedAtValidation = inspectIssuedAt(manifest?.issued_at);
  const issuerIdentifiers = inspectIssuerIdentifiers(manifest, issuer);
  errors.push(...issuedAtValidation.errors, ...issuerIdentifiers.errors);
  warnings.push(...issuedAtValidation.warnings);
  const tdmReservation = inspectTdmRightsReservation(manifest);

  // --- Asset integrity (optional asset; fileless catalog claims are N/A) ---
  const { hash: manifestAssetHash, algorithmSupported, hashDeclared, hashDeclarationsValid } = inspectAssetHash(manifest);
  const catalogClaim = isCatalogClaim(manifest);
  let computedAssetHash = null;
  let assetHashOk = null; // true | false | null (not applicable / not checked)
  let integrityStatus; // 'verified' | 'mismatch' | 'not_checked' | 'not_applicable'

  if (hashDeclared && (!algorithmSupported || !hashDeclarationsValid)) {
    // Never label a digest as verified using a different algorithm.
    integrityStatus = 'not_checked';
  } else if (assetBytes) {
    computedAssetHash = sha3_256_hex(assetBytes);
    if (manifestAssetHash) {
      assetHashOk = computedAssetHash === manifestAssetHash;
      integrityStatus = assetHashOk ? 'verified' : 'mismatch';
      if (!assetHashOk) errors.push('Asset hash mismatch.');
    } else {
      integrityStatus = 'not_checked';
      warnings.push('Asset file supplied but the manifest declares no asset hash; integrity was not checked.');
    }
  } else if (hashDeclared) {
    integrityStatus = 'not_checked';
    warnings.push('No asset file supplied; asset integrity was NOT verified. Supply the original file to check integrity.');
  } else {
    // Catalog claim / fileless declaration: no asset to hash. This is expected,
    // not an error — we verify the signed declaration, not file integrity.
    integrityStatus = 'not_applicable';
  }

  // --- Signature ---
  let canonicalPayload = null;
  try {
    // Validate the complete JSON input, including fields in the signature object
    // which are excluded from the signature preimage.
    canonicalize(manifest);
    canonicalPayload = canonicalize(unsignedManifest(manifest));
  } catch (error) {
    errors.push(`Manifest canonicalization failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  let signatureOk = false;

  if (!signature.value) {
    errors.push('Manifest signature is missing.');
  } else if (canonicalPayload !== null) {
    try {
      const publicKey = crypto.createPublicKey(publicKeyPem);
      if (publicKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('Public key must be Ed25519.');
      }
      signatureOk = crypto.verify(
        null,
        Buffer.from(canonicalPayload),
        publicKey,
        Buffer.from(base64ToBytes(signature.value)),
      );
      if (!signatureOk) errors.push('Ed25519 signature mismatch.');
    } catch (error) {
      signatureOk = false;
      errors.push(`Signature verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  const publicKeyDer = pemToDer(publicKeyPem);
  const publicKeySha256 = sha256Hex(publicKeyDer);
  const publicKeySha3 = sha3_256_hex(publicKeyDer);

  if (manifest?.issuer?.public_key_pem) {
    const manifestKeyDer = pemToDer(manifest.issuer.public_key_pem);
    if (!sameBytes(publicKeyDer, manifestKeyDer)) {
      errors.push('Provided public key does not match manifest issuer public key.');
    }
  }

  // --- Reference-anchor issuer-key digest pinning (v1.1) ---
  // Trust is anchored in the signed payload's DER/SPKI sha3-256 digest, never in
  // where the key was fetched from.
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
  // A supplied current-key record can itself be revoked. Apply its status only
  // when its fingerprints match the provided key, never on a label alone.
  const effectiveRevocation = revokedMatch || (issuerKeyOk && issuer?.status === 'revoked' ? issuer : null);
  if (effectiveRevocation) {
    keyRevoked = true;
    const reason = effectiveRevocation.revocation_reason || 'key revocation';
    const superseded = effectiveRevocation.superseded_by ? `, superseded by ${effectiveRevocation.superseded_by}` : '';
    revocation = {
      keyId: effectiveRevocation.key_id || null,
      revokedAt: effectiveRevocation.revoked_at || null,
      reason,
      supersededBy: effectiveRevocation.superseded_by || null,
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
    schemaValidation: checkBaseSchema(manifest),
    issuedAtValidation,
    issuerIdentifiers,
    keyStatusCheck: issuer ? (keyRevoked ? 'revoked' : 'not_listed_as_revoked_in_supplied_registry') : 'not_checked',
    registryTrust: { source: issuer ? 'caller_supplied' : 'not_supplied', authenticity: 'not_assessed', freshness: 'not_assessed' },
    archiveResolution: 'not_checked',
    archiveReferences: inspectArchiveReferences(manifest),
    issuerIdentity: 'not_assessed',
    valid: status === 'valid',
    evidenceType: catalogClaim ? 'catalog_claim' : 'evidence_package',
    auraUid: manifest?.aura_uid || manifest?.aura_id || null,
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
    issuedAt: manifest?.issued_at || null,
    proofScope: manifest?.proof?.scope || null,
    tdmRightsReservation: {
      profileClaimed: tdmReservation.claimed,
      fieldPath: tdmReservation.fieldPath,
      declarationValue: tdmReservation.value,
      declarationValid: tdmReservation.declared,
      syntaxConformant: tdmReservation.claimed ? structure.errors.length === 0 : null,
      signatureBound: tdmReservation.claimed ? signatureOk : null,
      assetBindingVerified: tdmReservation.claimed ? assetHashOk === true : null,
      profileVerified:
        tdmReservation.claimed
          ? errors.length === 0 && signatureOk && assetHashOk === true
          : null,
      issuerAuthorityAssessed: false,
      discoverabilityAssessed: false,
      legalEffectAssessed: false,
    },
    warnings,
    errors,
  };
}
