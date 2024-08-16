import base64url from 'base64url'

import { AesGcm } from './aes'
import { cbor } from './cbor'

export type RegistRequest = {
  appName: string
  appHost: string
  userName: string
  userDisplayName: string
}

export type RegistResponse = {
  crypt: {
    key: Uint8Array
    salt: Uint8Array
  }
  webAuthn: {
    id: Uint8Array
    publicKeyJwk: JsonWebKey
  }
}

export type AuthRequest = {
  id: Uint8Array
  publicKeyJwk: JsonWebKey
}

export type AuthResponse = {
  key: Uint8Array
  salt: Uint8Array
}

const newDataView = (array: Uint8Array) => new DataView(array.buffer, array.byteOffset, array.byteLength)

const coseToJwk = (cose: Uint8Array): JsonWebKey => {
  const coseObj = cbor.decode<{
    '1': number
    '3': number
    '-1': Buffer
    '-2': Buffer
    '-3': Buffer
  }>(cose)
  console.debug('publicKey(CBOR):', coseObj)

  if (coseObj[3] === -7) {
    return {
      kty: 'EC',
      crv: 'P-256',
      x: base64url(coseObj[-2]),
      y: base64url(coseObj[-3]),
    }
  } else if (coseObj[3] === -257) {
    return {
      kty: 'RSA',
      n: base64url(coseObj[-1]),
      e: base64url(coseObj[-2]),
    }
  }
  throw new Error('Unknown public key algorithm')
}

export const registWA = async ({
  appName,
  appHost,
  userName,
  userDisplayName,
}: RegistRequest): Promise<RegistResponse> => {
  const textDec = new TextDecoder()

  const keys = await AesGcm.deriveKey()
  console.debug('keys:', keys)
  const keyid = Buffer.concat([keys.key, keys.salt])

  const challenge = crypto.getRandomValues(new Uint8Array(32))
  console.debug('challenge:', base64url(Buffer.from(challenge)))

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: appName,
        id: appHost,
      },
      user: {
        id: keyid,
        name: userName,
        displayName: userDisplayName,
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' },
      ],
    },
  })) as PublicKeyCredential

  // レスポンスを解析
  const authAttRes = credential.response as AuthenticatorAttestationResponse
  const clientDataJSON: {
    challenge: string
    crossOrigin: boolean
    origin: string
    type: string
  } = JSON.parse(textDec.decode(authAttRes.clientDataJSON))
  console.debug('clientDataJSON:', clientDataJSON)

  // challengeの比較
  if (clientDataJSON.challenge !== base64url(Buffer.from(challenge))) {
    throw new Error('Invalid challenge')
  }

  // origin(domain)の比較
  const originHost = new URL(clientDataJSON.origin).hostname
  console.debug('originHost:', originHost)
  if (originHost !== appHost) {
    throw new Error('Invalid origin')
  }

  const { authData } = cbor.decode<{
    fmt: string
    attStmt: Record<string, unknown>
    authData: Uint8Array
  }>(authAttRes.attestationObject)
  console.debug('authData:', authData)

  const authDataView = newDataView(authData)
  const credentialIdLength = authDataView.getUint16(53, false)

  const authDataObj = {
    rpIdHash: authData.slice(0, 32),
    flags: authData[32],
    signCount: authDataView.getUint32(33, false),
    aaguid: authData.slice(37, 53),
    credentialIdLength,
    credentialId: authData.slice(55, 55 + credentialIdLength),
    credentialPublicKey: authData.slice(55 + credentialIdLength),
  }
  console.debug('authDataObj:', authDataObj)

  // rpIdHashの比較
  const rpIdHashReq = await crypto.subtle.digest('SHA-256', Buffer.from(appHost))
  if (!Buffer.from(rpIdHashReq).equals(authDataObj.rpIdHash)) {
    throw new Error('Invalid rpIdHash')
  }

  // 公開鍵取得
  const publicKeyJwk = coseToJwk(authDataObj.credentialPublicKey)
  console.debug('publicKeyJwk:', publicKeyJwk)

  return {
    crypt: {
      key: keys.key,
      salt: keys.salt,
    },
    webAuthn: {
      id: new Uint8Array(credential.rawId),
      publicKeyJwk,
    },
  }
}

export const authWA = async ({ id, publicKeyJwk }: AuthRequest): Promise<AuthResponse> => {
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  console.debug('challenge:', base64url(Buffer.from(challenge)))

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [
        {
          transports: ['internal'],
          type: 'public-key',
          id,
        },
      ],
    },
  })) as PublicKeyCredential

  const authAttRes = credential.response as AuthenticatorAssertionResponse

  const keys = await AesGcm.deriveKey(
    new Uint8Array(credential.rawId.slice(0, 16)),
    new Uint8Array(credential.rawId.slice(16)),
  )
  console.debug('keys:', keys)

  return {
    key: keys.key,
    salt: keys.salt,
  }
}
