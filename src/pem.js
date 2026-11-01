export function pemToDer(pem) {
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\s+/g, '');

  if (!base64) throw new Error('Invalid public key PEM.');
  return base64ToBytes(base64);
}

export function derToBase64(der) {
  return bytesToBase64(der);
}

export function bytesToBase64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');

  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(base64) {
  // RFC 4648 standard alphabet, required padding, and zero unused pad bits.
  // Validate before decoding: Buffer and atob otherwise accept different inputs.
  if (typeof base64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
    throw new Error('Expected canonical padded Base64.');
  }
  let bytes;
  if (typeof Buffer !== 'undefined') {
    bytes = new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    const binary = atob(base64);
    bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  }
  if (bytesToBase64(bytes) !== base64) throw new Error('Non-canonical Base64 pad bits.');
  return bytes;
}

export function ed25519SignatureBytes(value) {
  const bytes = base64ToBytes(value);
  if (bytes.length !== 64) throw new Error('Ed25519 signature must contain exactly 64 bytes.');
  return bytes;
}

export function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
