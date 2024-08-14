import { RegistInfo, registWA } from './selfWebAuthn'

export class PwaCryptoStorage {
  static async setup(info: RegistInfo) {
    return registWA(info)
  }
}
