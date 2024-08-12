'use client'

import { ExButton } from '@/components/nextekit/ui/button'
import { PwaCryptoStorage } from '@/components/pwacs'
import base64url from 'base64url'
import { decode as cborDecode } from 'cbor-x'
import { FC } from 'react'

const coseToJwk = (cose: Buffer) => {
  let publicKeyJwk = {}
  const publicKeyCbor = cborDecode(cose)
  if (publicKeyCbor[3] === -7) {
    publicKeyJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: base64url(publicKeyCbor[-2]),
      y: base64url(publicKeyCbor[-3]),
    }
  } else if (publicKeyCbor[3] === -257) {
    publicKeyJwk = {
      kty: 'RSA',
      n: base64url(publicKeyCbor[-1]),
      e: base64url(publicKeyCbor[-2]),
    }
  } else {
    throw new Error('Unknown public key algorithm')
  }
  return publicKeyJwk
}

export const RegisterClient: FC = () => {
  const register = async () => {
    const dec = new TextDecoder()
    const enc = new TextEncoder()

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: enc.encode('challengexxx').buffer,
        rp: {
          name: 'TestSite',
          id: 'localhost',
        },
        user: {
          id: enc.encode('userxxx').buffer,
          name: '1234@test.dev',
          displayName: 'TestUser',
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' },
        ],
      },
    })
    const authAttRes = (credential as PublicKeyCredential).response as AuthenticatorAttestationResponse
    const clientDataJSON: {
      challenge: string
      crossOrigin: boolean
      origin: string
      type: string
    } = JSON.parse(dec.decode(authAttRes.clientDataJSON))
    console.log('credential:', credential)
    console.log('clientDataJSON:', clientDataJSON)
    console.log('challenge:', base64url.decode(clientDataJSON.challenge))

    const attestationObject = cborDecode(Buffer.from(authAttRes.attestationObject))
    console.log('attestationObject', attestationObject)
    const credentialIdLength = (attestationObject.authData[53] << 8) + attestationObject.authData[54]
    const authData = {
      rpIdHash: attestationObject.authData.slice(0, 32),
      flags: attestationObject.authData[32],
      signCount:
        (attestationObject.authData[33] << 24) |
        (attestationObject.authData[34] << 16) |
        (attestationObject.authData[35] << 8) |
        attestationObject.authData[36],
      aaguid: attestationObject.authData.slice(37, 53),
      credentialIdLength,
      credentialId: attestationObject.authData.slice(55, 55 + credentialIdLength),
      credentialPublicKey: attestationObject.authData.slice(55 + credentialIdLength),
    }
    console.log('authData', authData)

    const publicKeyJwk = coseToJwk(authData.credentialPublicKey)
    console.log('publicKeyJwk', publicKeyJwk)
  }

  return <ExButton onPress={register}>test</ExButton>
}

export const RegisterClient2: FC = () => {
  const register = async () => {
    const res = await PwaCryptoStorage.setup({
      appName: 'ProtoWallet',
      appHost: 'localhost',
      userName: 'test@user.dev',
      userDisplayName: 'TestUser',
    })
    console.log('res:', res)
  }

  return <ExButton onPress={register}>test</ExButton>
}

export const AuthClient: FC = () => {
  const auth = async () => {
    const dec = new TextDecoder()
    const enc = new TextEncoder()

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: enc.encode('challengexxx').buffer,
        allowCredentials: [
          {
            transports: ['internal'],
            type: 'public-key',
            id: base64url.toBuffer('NMxfzDqyz-Zo_DDdAUVY8Mb8qqJmhgNb6aJL8BaR0Qw').buffer,
          },
        ],
      },
    })
    const authAttRes = (credential as PublicKeyCredential).response as AuthenticatorAssertionResponse
    console.log('credential:', credential)
    console.log('signature:', base64url.encode(Buffer.from(authAttRes.signature)))
    if (authAttRes.userHandle) {
      console.log('userHandle:', dec.decode(authAttRes.userHandle))
    }
  }

  return <ExButton onPress={auth}>test2</ExButton>
}
