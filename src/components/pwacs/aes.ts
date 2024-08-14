export class AesGcm {
  static async deriveKey(inKeyData?: Uint8Array, inSalt?: Uint8Array) {
    const key = inKeyData || crypto.getRandomValues(new Uint8Array(32))
    const salt = inSalt || crypto.getRandomValues(new Uint8Array(32))

    const baseKey = await crypto.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveKey'])
    const cryptoKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      baseKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt'],
    )

    return {
      cryptoKey,
      key,
      salt,
    }
  }
}
export default AesGcm
