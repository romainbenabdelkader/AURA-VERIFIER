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
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(base64, 'base64'));

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
