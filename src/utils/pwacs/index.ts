import { cbor } from './cbor'
import { RegistInfo, registWA } from './selfWebAuthn'

export class PwaCryptoStorage {
  static async setup(info: RegistInfo) {
    const regInfo = await registWA(info)
    return cbor.encode(regInfo)
  }

  static async restore(configData: Uint8Array) {
    const config = await cbor.decode(configData)
    console.debug('config:', config)
  }
}
