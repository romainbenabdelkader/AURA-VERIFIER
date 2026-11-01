// RFC 8410 sections 3-4: Ed25519 OID, absent parameters, 32 key bytes.
const ED25519_SPKI_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

export async function importEd25519VerificationKey(der, subtle = crypto.subtle) {
  try {
    return await subtle.importKey('spki', der, { name: 'Ed25519' }, false, ['verify']);
  } catch (error) {
    // Some GCrypt-based browsers discard a leading zero during SPKI import.
    // Only a complete, canonical Ed25519 SPKI may use the raw-key path. Keep
    // the original DER unchanged for the manifest's digest and registry pins.
    if (error?.name !== 'DataError' || der.length !== 44 ||
        !ED25519_SPKI_PREFIX.every((byte, i) => der[i] === byte)) throw error;
    return subtle.importKey('raw', der.slice(ED25519_SPKI_PREFIX.length), { name: 'Ed25519' }, false, ['verify']);
  }
}
