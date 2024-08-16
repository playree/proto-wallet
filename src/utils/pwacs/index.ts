import { cbor } from './cbor'
import { RegistInfo, RegistResponse, registWA } from './selfWebAuthn'

export type PwacsConfig = {
  cryptoVerify: Uint8Array
  publicKeyJwk: JsonWebKey
}

export class PwaCryptoStorage {
  private salt: Uint8Array
  private publicKeyJwk: JsonWebKey

  constructor({ keyid, publicKeyJwk }: RegistResponse) {
    this.salt = salt
    this.publicKeyJwk = publicKeyJwk
  }

  static async setup(info: RegistInfo) {
    const regInfo = await registWA(info)
    return cbor.encode(regInfo)
  }

  static restore(configData: Uint8Array) {
    const config = cbor.decode<RegistResponse>(configData)
    return new PwaCryptoStorage(config)
  }
}
