import base64url from 'base64url'

import { cbor } from './cbor'

export type RegistInfo = {
  appName: string
  appHost: string
  userName: string
  userDisplayName: string
}

const newDataView = (array: Uint8Array) => new DataView(array.buffer, array.byteOffset, array.byteLength)

const coseToJwk = (cose: Uint8Array) => {
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

export const registWA = async ({ appName, appHost, userName, userDisplayName }: RegistInfo) => {
  const textDec = new TextDecoder()
  const textEnc = new TextEncoder()

  const keyid = crypto.getRandomValues(new Uint8Array(32))
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  console.debug('challenge:', base64url(Buffer.from(challenge)))

  const credential = await navigator.credentials.create({
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
  })

  // レスポンスを解析
  const authAttRes = (credential as PublicKeyCredential).response as AuthenticatorAttestationResponse
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
}
