import crypto from 'node:crypto';
import { canonicalize, unsignedManifest } from './jcs.js';
import { sha3_256_hex } from './sha3.js';
import { base64ToBytes, pemToDer, sameBytes } from './pem.js';

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function extractAssetHash(manifest) {
  return manifest?.asset?.hash || manifest?.asset_hash || null;
}

function statusFromChecks(errors, warnings) {
  if (errors.length > 0) return 'invalid';
  if (warnings.length > 0) return 'warning';
  return 'valid';
}

export async function verifyAuraPackage({ assetBytes, manifestText, publicKeyPem, issuerText = null }) {
  const warnings = [];
  const errors = [];
  const manifest = JSON.parse(manifestText);
  const issuer = issuerText ? JSON.parse(issuerText) : null;
  const signature = manifest.signature || {};
  const manifestAssetHash = extractAssetHash(manifest);
  const computedAssetHash = sha3_256_hex(assetBytes);
  const assetHashOk = Boolean(manifestAssetHash && computedAssetHash === manifestAssetHash);

  if (!manifestAssetHash) errors.push('Manifest asset hash is missing.');
  if (!assetHashOk) errors.push('Asset hash mismatch.');

  const canonicalPayload = canonicalize(unsignedManifest(manifest));
  let signatureOk = false;

  if (!signature.value) {
    errors.push('Manifest signature is missing.');
  } else {
    try {
      signatureOk = crypto.verify(
        null,
        Buffer.from(canonicalPayload),
        crypto.createPublicKey(publicKeyPem),
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
    auraUid: manifest.aura_uid || manifest.aura_id || null,
    assetHashOk,
    signatureOk,
    issuerKeyOk,
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
