export function canonicalize(value) {
  return serialize(value);
}

function serializeString(value) {
  // RFC 8785 section 3.2.2.2: lone surrogates are invalid in both values
  // and object property names. Valid UTF-16 pairs must remain unchanged.
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error('RFC-8785-JCS does not support lone Unicode surrogates.');
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error('RFC-8785-JCS does not support lone Unicode surrogates.');
    }
  }
  return JSON.stringify(value);
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

  if (typeof value === 'string') return serializeString(value);

  if (Array.isArray(value)) {
    return `[${value.map((item) => serialize(item)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((key) => `${serializeString(key)}:${serialize(value[key])}`)
      .join(',')}}`;
  }

  throw new Error(`Unsupported JSON value: ${typeof value}`);
}

export function unsignedManifest(manifest) {
  const { signature, ...unsigned } = manifest;
  return unsigned;
}
