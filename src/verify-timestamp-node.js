import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

/**
 * Verifies a detached RFC 3161 TimeStampResp (.tsr) against the exact bytes
 * of a fully signed AURA manifest. No JSON reserialization is performed.
 * Trust anchors must be supplied explicitly; eIDAS qualification is NOT tested.
 */
export function verifyRfc3161Timestamp({ manifestPath, responsePath, caPath, untrustedPath = null, queryPath = null }) {
  if (!manifestPath || !responsePath || !caPath) {
    throw new Error('RFC 3161 verification needs a manifest, a timestamp response and a TSA trust anchor.');
  }
  for (const path of [manifestPath, responsePath, caPath, untrustedPath, queryPath].filter(Boolean)) {
    if (!fs.statSync(path).isFile()) throw new Error('Not a regular file: ' + path);
  }
  function openssl(args) {
    return execFileSync('openssl', args, {
      encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }
  const trust = ['-in', responsePath, '-CAfile', caPath];
  if (untrustedPath) trust.push('-untrusted', untrustedPath);

  try {
    // Checks response status, imprint over exact file bytes, signature, TSA
    // certificate purpose, and chain to the explicitly supplied trust anchor.
    openssl(['ts', '-verify', ...trust, '-data', manifestPath]);
    // Additionally check the original request, including nonce, if supplied.
    // This does NOT replace the mandatory file-to-imprint check above.
    if (queryPath) openssl(['ts', '-verify', ...trust, '-queryfile', queryPath]);

    const details = openssl(['ts', '-reply', '-in', responsePath, '-text']);
    const genTime = details.match(/^Time stamp:\s*(.+)$/m)?.[1]?.trim() || null;
    const policy = details.match(/^Policy OID:\s*(.+)$/m)?.[1]?.trim() || null;
    const serial = details.match(/^Serial number:\s*(.+)$/m)?.[1]?.trim() || null;
    if (!genTime) throw new Error('The TSA genTime could not be extracted.');
    return {
      status: 'verified',
      standard: 'RFC3161',
      binding: 'exact_full_signed_manifest_bytes',
      genTime,
      tsaPolicy: policy,
      tsaSerial: serial,
      nonceCheck: queryPath ? 'passed_against_supplied_request' : 'not_assessed',
      trustBasis: 'supplied_ca_file',
      tsaPolicyAcceptability: 'not_assessed',
      revocationAndLongTermValidation: 'not_assessed',
      qualifiedEidas: 'not_assessed',
    };
  } catch (error) {
    const detail = error?.stderr?.toString('utf8') || error?.message || String(error);
    return {
      status: 'invalid', standard: 'RFC3161', binding: 'exact_full_signed_manifest_bytes',
      qualifiedEidas: 'not_assessed',
      error: detail.trim().slice(0, 1000),
    };
  }
}
