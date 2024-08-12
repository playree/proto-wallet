import { decode, encode } from 'cbor-x'

const cborDecode = <T>(messagePack: Buffer | Uint8Array | ArrayBuffer): T => {
  if (messagePack instanceof ArrayBuffer) {
    return decode(Buffer.from(messagePack)) as T
  }
  return decode(messagePack) as T
}

const cborEncode = <T>(value: T): Buffer => {
  return encode(value)
}

export const cbor = {
  encode: cborEncode,
  decode: cborDecode,
}

export default cbor
