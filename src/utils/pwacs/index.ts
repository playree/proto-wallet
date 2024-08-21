import { AesGcm } from './aes'
import { cbor } from './cbor'
import { AuthRequest, RegistRequest, authPasskey, registPasskey } from './selfPasskey'

export const PWACS_CONFIG_VER = 1

export type PwacsData = {
  symbol: 'Pwacs'
  version: number
  cryptVerify: Uint8Array
  authReq?: AuthRequest
}

export type SaveCallback = (key: string, value: Uint8Array) => Promise<void>
export type LoadCallback = (key: string) => Promise<Uint8Array | undefined>

type Config = {
  saveCB?: SaveCallback
  loadCB?: LoadCallback
  enableCache?: boolean
}

const VERIFY_STRING = 'PWACS Verify'

export class PwaCryptStorage {
  private configData: Uint8Array
  private key: CryptoKey
  private saveCB?: SaveCallback
  private loadCB?: LoadCallback
  private cache: Record<string, unknown>
  private isEnabledCache: boolean

  constructor(configData: Uint8Array, key: CryptoKey, config?: Config) {
    this.configData = configData
    this.key = key
    this.saveCB = config?.saveCB
    this.loadCB = config?.loadCB
    this.cache = {}
    this.isEnabledCache = !!config?.enableCache
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

  async save(key: string, data: Uint8Array) {
    if (!this.saveCB) {
      throw new Error('saveCB is not set')
    }
    await this.saveCB(key, await AesGcm.encrypt(this.key, data))
  }

  async saveString(key: string, data: string) {
    if (!this.saveCB) {
      throw new Error('saveCB is not set')
    }
    await this.saveCB(key, await AesGcm.encryptString(this.key, data))
  }

  async load(key: string) {
    if (!this.loadCB) {
      throw new Error('loadCB is not set')
    }
    const data = await this.loadCB(key)
    return data ? AesGcm.decrypt(this.key, data) : undefined
  }

  async loadString(key: string) {
    if (!this.loadCB) {
      throw new Error('loadCB is not set')
    }
    const data = await this.loadCB(key)
    return data ? AesGcm.decryptString(this.key, data) : undefined
  }

  static async setup(info: RegistRequest, config?: Config) {
    // Passkeyセットアップ
    const { crypt, webAuthn } = await registPasskey(info)

    // 複合チェック用暗号化文字列生成
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    const cryptVerify = await AesGcm.encryptString(keys.cryptoKey, VERIFY_STRING)

    // CBORエンコード
    return new PwaCryptStorage(
      cbor.encode<PwacsData>({
        symbol: 'Pwacs',
        version: PWACS_CONFIG_VER,
        cryptVerify,
        authReq: { appHost: info.appHost, webAuthn },
      }),
      keys.cryptoKey,
      config,
    )
  }

  static async setupFromPassword(password: string, config?: Config) {
    // パスワードからハッシュ生成
    const hashPassword = await crypto.subtle.digest('SHA-512', Buffer.from(password))

    // 複合チェック用暗号化文字列生成
    const keys = await AesGcm.deriveKey(
      new Uint8Array(hashPassword.slice(0, 32)),
      new Uint8Array(hashPassword.slice(32)),
    )
    const cryptVerify = await AesGcm.encryptString(keys.cryptoKey, VERIFY_STRING)

    // CBORエンコード
    return new PwaCryptStorage(
      cbor.encode<PwacsData>({
        symbol: 'Pwacs',
        version: PWACS_CONFIG_VER,
        cryptVerify,
      }),
      keys.cryptoKey,
      config,
    )
  }

  static async unlock(configData: Uint8Array, config?: Config) {
    // CBORデコード
    const data = cbor.decode<PwacsData>(configData)

    // Passkey認証
    if (!data.authReq) {
      throw new Error('Passkey not available')
    }
    const crypt = await authPasskey(data.authReq)

    // 複合チェック
    const keys = await AesGcm.deriveKey(crypt.key, crypt.salt)
    const dec = await AesGcm.decryptString(keys.cryptoKey, data.cryptVerify)
    if (dec !== VERIFY_STRING) {
      throw new Error('Unable to unlock')
    }

    return new PwaCryptStorage(configData, keys.cryptoKey, config)
  }

  static async unlockFromPassword(configData: Uint8Array, password: string, config?: Config) {
    // CBORデコード
    const data = cbor.decode<PwacsData>(configData)

    // パスワードからハッシュ生成
    const hashPassword = await crypto.subtle.digest('SHA-512', Buffer.from(password))

    // 複合チェック
    const keys = await AesGcm.deriveKey(
      new Uint8Array(hashPassword.slice(0, 32)),
      new Uint8Array(hashPassword.slice(32)),
    )
    const dec = await AesGcm.decryptString(keys.cryptoKey, data.cryptVerify)
    if (dec !== VERIFY_STRING) {
      throw new Error('Unable to unlock')
    }

    return new PwaCryptStorage(configData, keys.cryptoKey, config)
  }
}
