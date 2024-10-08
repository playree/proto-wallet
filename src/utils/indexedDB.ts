import Dexie, { Table } from 'dexie'

export type IdxDbKey = 'pwacs_config'
export type IdxDbKeyCrypt = 'test' | 'test2'

export type KeyValue =
  | {
      key: IdxDbKey | IdxDbKeyCrypt
      isCrypt: false
      value: string | number | Uint8Array
    }
  | {
      key: IdxDbKey | IdxDbKeyCrypt | string
      isCrypt: true
      value: Uint8Array
    }

export class IdxDb extends Dexie {
  keyValue!: Table<KeyValue>

  constructor() {
    super('pwallet')
    this.version(1).stores({
      keyValue: 'key++',
    })
  }

  async setPwacsConfig(config: Uint8Array) {
    return this.keyValue.put({
      key: 'pwacs_config',
      isCrypt: false,
      value: config,
    })
  }

  async getPwacsConfig() {
    const kv = await this.keyValue.get('pwacs_config')
    return kv ? (kv.value as Uint8Array) : undefined
  }
}

export const idxDb = new IdxDb()
