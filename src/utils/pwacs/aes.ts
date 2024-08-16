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

  static async encrypt(key: CryptoKey, data: ArrayBuffer) {
    const iv = crypto.getRandomValues(new Uint8Array(16))
    const enc = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      key,
      data,
    )
    const res = new Uint8Array(iv.byteLength + enc.byteLength)
    res.set(iv, 0)
    res.set(new Uint8Array(enc), iv.byteLength)
    return res
  }

  static async encryptString(key: CryptoKey, data: string) {
    const textEnc = new TextEncoder()
    return AesGcm.encrypt(key, textEnc.encode(data))
  }

  static async decrypt(key: CryptoKey, data: ArrayBuffer) {
    const iv = data.slice(0, 16)
    const target = data.slice(16)
    console.debug('decrypt:', iv, target)

    const dec = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      key,
      target,
    )
    console.debug('decrypt:', dec)
    return dec
  }

  static async decryptString(key: CryptoKey, data: ArrayBuffer) {
    const textDec = new TextDecoder()
    return textDec.decode(await AesGcm.decrypt(key, data))
  }
}
export default AesGcm
