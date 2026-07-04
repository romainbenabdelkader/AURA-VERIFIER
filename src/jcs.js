export function canonicalize(value) {
  return serialize(value);
}

function serialize(value) {
  if (value === null) return 'null';

  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('RFC-8785-JCS does not support non-finite numbers.');
    }
    return JSON.stringify(value);
  }

  if (typeof value === 'string') return JSON.stringify(value);

  if (Array.isArray(value)) {
    return `[${value.map((item) => serialize(item)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${serialize(value[key])}`)
      .join(',')}}`;
  }

  throw new Error(`Unsupported JSON value: ${typeof value}`);
}

export function unsignedManifest(manifest) {
  const { signature, ...unsigned } = manifest;
  return unsigned;
}
