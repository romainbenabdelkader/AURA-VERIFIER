import crypto from 'node:crypto';
import fs from 'node:fs';
import { canonicalize } from './jcs.js';
import { sha3_256_hex } from './sha3.js';

// One canonical preimage: JCS of the COMPLETE signed manifest, including the signature.
export function canonicalSignedManifestDigest(manifestText) {
  const manifest = JSON.parse(manifestText);
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) ||
      !manifest.signature || typeof manifest.signature.value !== 'string' || !manifest.signature.value) {
    throw new Error('A complete signed AURA manifest is required for RFC 3161 timestamping.');
  }
  const canonicalBytes = Buffer.from(canonicalize(manifest), 'utf8');
  return {
    sha256: crypto.createHash('sha256').update(canonicalBytes).digest('hex'),
    sha3_256: 'sha3-256:' + sha3_256_hex(canonicalBytes),
    canonicalBytesLength: canonicalBytes.length,
  };
}

export function assertSafeTimestampPath(filePath) {
  if (typeof filePath !== 'string' || !filePath ||
      filePath.startsWith('-') || filePath.includes('\0')) {
    throw new Error('Unsafe file path for OpenSSL: pass paths without a leading dash or NUL.');
  }
}

export function digestSignedManifestFile(manifestPath) {
  assertSafeTimestampPath(manifestPath);
  if (!fs.statSync(manifestPath).isFile()) throw new Error('Not a regular file: ' + manifestPath);
  return canonicalSignedManifestDigest(fs.readFileSync(manifestPath, 'utf8'));
}
