import { AesGcm } from './aes'
import { cbor } from './cbor'
import { AuthRequest, RegistRequest, authPasskey, registPasskey } from './selfPasskey'

export const PWACS_CONFIG_VER = 1

export type PwacsConfig = {
  symbol: 'PwacsConfig'
  version: number
  cryptVerify: Uint8Array
  authReq: AuthRequest
}

const VERIFY_STRING = 'PWACS Verify'

export class PwaCryptStorage {
  private configData: Uint8Array
  private key: CryptoKey

  constructor(configData: Uint8Array, key: CryptoKey) {
    this.configData = configData
    this.key = key
  }

  exportConfigData() {
    return this.configData
  }

  async encrypt(data: ArrayBuffer) {
    return AesGcm.encrypt(this.key, data)
  }

  async encryptString(data: string) {
    return AesGcm.encryptString(this.key, data)
  }

  async decrypt(data: ArrayBuffer) {
    return AesGcm.decrypt(this.key, data)
  }

  async decryptString(data: ArrayBuffer) {
    return AesGcm.decryptString(this.key, data)
  }

  static async setup(info: RegistRequest) {
    // Passkeyセットアップ
    const { crypt, webAuthn } = await registPasskey(info)

    // 複合チェック用暗号化文字列生成
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    const cryptVerify = await AesGcm.encryptString(keys.cryptoKey, VERIFY_STRING)

    // CBORエンコード
    return new PwaCryptStorage(
      cbor.encode<PwacsConfig>({
        symbol: 'PwacsConfig',
        version: PWACS_CONFIG_VER,
        cryptVerify,
        authReq: { appHost: info.appHost, webAuthn },
      }),
      keys.cryptoKey,
    )
  }

  static async unlock(configData: Uint8Array) {
    // CBORデコード
    const config = cbor.decode<PwacsConfig>(configData)

    // Passkey認証
    const crypt = await authPasskey(config.authReq)

    // 複合チェック
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    const dec = await AesGcm.decryptString(keys.cryptoKey, config.cryptVerify)
    if (dec !== VERIFY_STRING) {
      throw new Error('Invalid decrypted')
    }

    return new PwaCryptStorage(configData, keys.cryptoKey)
  }
}
