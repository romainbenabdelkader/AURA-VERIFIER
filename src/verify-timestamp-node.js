import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { assertSafeTimestampPath, digestSignedManifestFile } from './manifest-digest.js';

// CLI-only RFC 3161; messageImprint is SHA-256(JCS(full signed manifest)).
function openssl(args) {
  return execFileSync('openssl', args, {
    encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function parseOpenSslUtcTime(details) {
  const text = details.match(/^Time stamp:\s*(.+)$/m)?.[1]?.trim() || '';
  if (!/\s(?:GMT|UTC)$/i.test(text)) {
    throw new Error('Unrecognized OpenSSL TSA date or missing UTC/GMT timezone: ' + text);
  }
  const parsed = new Date(text.replace(/\sUTC$/i, ' GMT'));
  if (Number.isNaN(parsed.valueOf())) {
    throw new Error('Unable to parse TSA genTime as a valid UTC date: ' + text);
  }
  return parsed.toISOString();
}

export function createRfc3161TimestampQuery({ manifestPath, requestPath }) {
  assertSafeTimestampPath(manifestPath);
  assertSafeTimestampPath(requestPath);
  const digest = digestSignedManifestFile(manifestPath);
  // OpenSSL receives an already computed digest; it does not hash the raw JSON file.
  openssl(['ts', '-query', '-sha256', '-digest', digest.sha256, '-cert', '-out', requestPath]);
  return {
    status: 'created',
    requestPath,
    binding: 'jcs_full_signed_manifest',
    timestampImprintSha256: digest.sha256,
    manifestHashSha3_256: digest.sha3_256,
    note: 'This SHA3-256 digest is a candidate. prior_evidence.manifest_hash preimage semantics are not normative yet.',
  };
}

export function verifyRfc3161Timestamp({ manifestPath, responsePath, caPath, untrustedPath = null, queryPath = null }) {
  if (!manifestPath || !responsePath || !caPath) {
    throw new Error('RFC 3161 verification needs a manifest, a timestamp response and a TSA trust anchor.');
  }
  for (const value of [manifestPath, responsePath, caPath, untrustedPath, queryPath].filter(Boolean)) {
    assertSafeTimestampPath(value);
    if (!fs.statSync(value).isFile()) throw new Error('Not a regular file: ' + value);
  }
  const digest = digestSignedManifestFile(manifestPath);
  const trust = ['-in', responsePath, '-CAfile', caPath];
  if (untrustedPath) trust.push('-untrusted', untrustedPath);

  try {
    // Check response status, signature, TSA certificate purpose and chain
    // against caller-supplied trust anchor, plus the exact canonical digest.
    openssl(['ts', '-verify', ...trust, '-digest', digest.sha256]);
    // If request exists, check its nonce and policy, in addition to the digest.
    if (queryPath) openssl(['ts', '-verify', ...trust, '-queryfile', queryPath]);

    const details = openssl(['ts', '-reply', '-in', responsePath, '-text']);
    return {
      status: 'verified',
      standard: 'RFC3161',
      binding: 'jcs_full_signed_manifest',
      timestampImprintSha256: digest.sha256,
      manifestHashSha3_256: digest.sha3_256,
      genTime: parseOpenSslUtcTime(details),
      tsaPolicy: details.match(/^Policy OID:\s*(.+)$/m)?.[1]?.trim() || null,
      tsaSerial: details.match(/^Serial number:\s*(.+)$/m)?.[1]?.trim() || null,
      nonceCheck: queryPath ? 'passed_against_supplied_request' : 'not_assessed',
      trustBasis: 'supplied_ca_file',
      tsaPolicyAcceptability: 'not_assessed',
      revocationAndLongTermValidation: 'not_assessed',
      qualifiedEidas: 'not_assessed',
    };
  } catch (error) {
    const detail = error?.stderr?.toString('utf8') || error?.message || String(error);
    return {
      status: 'invalid',
      standard: 'RFC3161',
      binding: 'jcs_full_signed_manifest',
      timestampImprintSha256: digest.sha256,
      manifestHashSha3_256: digest.sha3_256,
      qualifiedEidas: 'not_assessed',
      error: detail.trim().slice(0, 1000),
    };
  }
}
