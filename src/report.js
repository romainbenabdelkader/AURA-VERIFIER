export const PROOF_SCOPE =
  'This verifies integrity, signature and timestamped declaration. It does not adjudicate ownership, authorship, licensing or infringement.';

export function formatHumanResult(result) {
  const icon = result.status === 'valid' ? 'VALID' : result.status === 'warning' ? 'WARNING' : 'INVALID';
  const lines = [
    `AURA verification result: ${icon}`,
    '',
    `Status: ${result.status}`,
    `Evidence type: ${result.evidenceType || 'evidence_package'}`,
    `AURA UID: ${result.auraUid || 'unknown'}`,
    `Integrity: ${result.integrityStatus || (result.assetHashOk ? 'verified' : 'unknown')}`,
    `Signature: ${result.signatureOk ? 'OK' : 'FAIL'}`,
    `Key revoked: ${result.keyRevoked ? `YES — ${result.revocation?.reason || 'revoked'}${result.revocation?.supersededBy ? `, superseded by ${result.revocation.supersededBy}` : ''}` : 'no'}`,
    `Issuer key pin: ${result.issuerKeyPinOk === null || result.issuerKeyPinOk === undefined ? 'n/a' : result.issuerKeyPinOk ? 'OK' : 'FAIL'}`,
    `Issuer key: ${result.issuerKeyOk ? 'OK' : 'not checked'}`,
    `Issuer status: ${result.issuerStatus || 'not provided'}`,
    `Canonicalization: ${result.canonicalization || 'unknown'}`,
    `Signature algorithm: ${result.signatureAlgorithm || 'unknown'}`,
    '',
    `Computed asset hash: ${result.computedAssetHash || 'n/a (no asset supplied)'}`,
    `Manifest asset hash: ${result.manifestAssetHash || 'none (catalog claim)'}`,
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
