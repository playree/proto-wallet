import { AesGcm } from './aes'
import { cbor } from './cbor'
import { AuthRequest, RegistRequest, authPasskey, registPasskey } from './selfPasskey'

export type PwacsConfig = {
  cryptVerify: Uint8Array
  authReq: AuthRequest
}

const VERIFY_STRING = 'PWACS Verify'

export class PwaCryptStorage {
  private key: CryptoKey

  constructor(key: CryptoKey) {
    this.key = key
  }

  static async setup(info: RegistRequest) {
    // Passkeyセットアップ
    const { crypt, webAuthn } = await registPasskey(info)

    // 複合チェック用暗号化文字列生成
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    const cryptVerify = await AesGcm.encryptString(keys.cryptoKey, VERIFY_STRING)

    // CBORエンコード
    return cbor.encode<PwacsConfig>({
      cryptVerify,
      authReq: { appHost: info.appHost, webAuthn },
    })
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
  }
}
