export const PROOF_SCOPE =
  'This verifies integrity, signature and timestamped declaration. It does not adjudicate ownership, authorship, licensing or infringement.';

export function formatHumanResult(result) {
  const icon = result.status === 'valid' ? 'VALID' : result.status === 'warning' ? 'WARNING' : 'INVALID';
  const lines = [
    `AURA verification result: ${icon}`,
    '',
    `Status: ${result.status}`,
    `AURA UID: ${result.auraUid || 'unknown'}`,
    `Asset hash: ${result.assetHashOk ? 'OK' : 'FAIL'}`,
    `Signature: ${result.signatureOk ? 'OK' : 'FAIL'}`,
    `Issuer key: ${result.issuerKeyOk ? 'OK' : 'not checked'}`,
    `Issuer status: ${result.issuerStatus || 'not provided'}`,
    `Canonicalization: ${result.canonicalization || 'unknown'}`,
    `Signature algorithm: ${result.signatureAlgorithm || 'unknown'}`,
    '',
    `Computed asset hash: ${result.computedAssetHash}`,
    `Manifest asset hash: ${result.manifestAssetHash || 'missing'}`,
    '',
    `Proof scope: ${PROOF_SCOPE}`,
  ];

  if (result.warnings.length > 0) {
    lines.push('', 'Warnings:');
    for (const warning of result.warnings) lines.push(`- ${warning}`);
  }

  if (result.errors.length > 0) {
    lines.push('', 'Errors:');
    for (const error of result.errors) lines.push(`- ${error}`);
  }

  return lines.join('\n');
}
