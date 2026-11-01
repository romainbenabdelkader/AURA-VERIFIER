// Local verifier policy, separate from the frozen schemas and from identity or
// timestamp assurance. Never rewrite signed strings to make them consistent.
export function inspectIssuedAt(value) {
  const result = { status: 'invalid', independentlyAttested: false, errors: [], warnings: [] };
  const match = typeof value === 'string' && /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) {
    result.errors.push('issued_at must be an RFC 3339 date-time with seconds and an explicit UTC offset.');
    return result;
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, offset] = match;
  const [year, month, day, hour, minute, second] = [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const offsetValid = /^[Zz]$/.test(offset) || (Number(offset.slice(1, 3)) <= 23 && Number(offset.slice(4, 6)) <= 59);
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 60 || !offsetValid) {
    result.errors.push('issued_at contains an impossible calendar date, time or UTC offset.');
    return result;
  }
  // Do not claim a complete leap-second validation without an authoritative
  // leap-second table. Preserve the input and report the unsupported check.
  if (second === 60) {
    result.status = 'not_checked';
    result.warnings.push('issued_at declares a leap second; leap-second validity is not assessed.');
    return result;
  }
  result.status = 'pass';
  return result;
}

export function inspectIssuerIdentifiers(manifest, issuer) {
  const errors = [];
  const groups = {
    issuer: [
      ['issuer.id', manifest?.issuer?.id],
      ['reference_anchor.issuer_key.issuer_id', manifest?.reference_anchor?.issuer_key?.issuer_id],
      ['issuer.json.issuer', issuer?.issuer],
      ['issuer.json.issuer_id', issuer?.issuer_id],
    ],
    signedKey: [
      ['issuer.key_id', manifest?.issuer?.key_id],
      ['reference_anchor.issuer_key.key_id', manifest?.reference_anchor?.issuer_key?.key_id],
    ],
  };
  let comparisons = 0;
  for (const entries of Object.values(groups)) {
    const present = entries.filter(([, value]) => value !== undefined);
    for (const [field, value] of present) {
      if (typeof value !== 'string' || value.trim().length === 0) errors.push(`${field}: identifier must be a non-empty string.`);
    }
    if (present.length > 1) {
      comparisons += present.length - 1;
      if (present.some(([, value]) => value !== present[0][1])) errors.push(`Issuer identifier mismatch between ${present.map(([field]) => field).join(', ')}.`);
    }
  }
  return { status: errors.length ? 'fail' : comparisons ? 'pass' : 'not_checked', comparisons, identityAssessed: false, errors };
}
