import { AesGcm } from './aes'
import { cbor } from './cbor'
import { RegistRequest, authWA, registWA } from './selfWebAuthn'

export type PwacsConfig = {
  cryptVerify: Uint8Array
  webAuthn: {
    id: Uint8Array
    publicKeyJwk: JsonWebKey
  }
}

const VERIFY_STRING = 'PWACS Verify'

export class PwaCryptoStorage {
  private key: CryptoKey

  constructor(key: CryptoKey) {
    this.key = key
  }

  static async setup(info: RegistRequest) {
    const { crypt, webAuthn } = await registWA(info)
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    const cryptVerify = await AesGcm.encryptString(keys.cryptoKey, VERIFY_STRING)
    console.debug('setup:', cryptVerify, webAuthn)

    const keys2 = await AesGcm.deriveKey(crypt.key, crypt.salt)
    console.debug(keys2)
    const res = await AesGcm.decryptString(keys2.cryptoKey, cryptVerify)
    console.debug(res)

    return cbor.encode<PwacsConfig>({
      cryptVerify,
      webAuthn,
    })
  }

  static async unlock(configData: Uint8Array) {
    const config = cbor.decode<PwacsConfig>(configData)
    console.debug('unlock:', config)
    const crypt = await authWA(config.webAuthn)
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    console.debug(keys)
    const res = await AesGcm.decryptString(keys.cryptoKey, config.cryptVerify)
    console.debug(res)
  }
}
