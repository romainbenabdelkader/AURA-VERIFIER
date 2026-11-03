import { parseUniqueJson } from './strict-json.js';
import { pemToDer } from './pem.js';

// Parsing errors are distinct from a completed verification report. Preserve
// the API's rejection behavior while giving callers a stable code and field.
export class AuraInputError extends Error {
  constructor(field, cause) {
    super(`Invalid JSON in ${field}: ${cause.message}`, { cause });
    this.name = 'AuraInputError';
    this.code = 'invalid_json';
    this.field = field;
  }
}

export function parseVerificationJson(text, field) {
  if (typeof text !== 'string') {
    throw new AuraInputError(field, new TypeError('JSON input must be text.'));
  }
  try {
    return parseUniqueJson(text);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new AuraInputError(field, error);
  }
}

// A malformed PEM must not discard other completed checks, such as asset
// integrity. No fingerprint or comparison may be derived from a failed decode.
export function inspectPublicKeyPem(pem, errors, label) {
  try {
    if (typeof pem !== 'string') throw new TypeError('Public key PEM must be text.');
    return pemToDer(pem);
  } catch (error) {
    errors.push(`${label}: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}
