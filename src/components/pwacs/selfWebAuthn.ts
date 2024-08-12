import { cbor } from './cbor'

export type RegistInfo = {
  appName: string
  appHost: string
  userName: string
  userDisplayName: string
}

export const registWA = async ({ appName, appHost, userName, userDisplayName }: RegistInfo) => {
  const textDec = new TextDecoder()
  const textEnc = new TextEncoder()

  const keyid = crypto.getRandomValues(new Uint8Array(32))
  const challenge = crypto.getRandomValues(new Uint8Array(32))

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

  const authAttRes = (credential as PublicKeyCredential).response as AuthenticatorAttestationResponse
  const clientDataJSON: {
    challenge: string
    crossOrigin: boolean
    origin: string
    type: string
  } = JSON.parse(textDec.decode(authAttRes.clientDataJSON))
  console.debug('clientDataJSON:', clientDataJSON)

  const { authData } = cbor.decode<{ authData: Uint8Array }>(authAttRes.attestationObject)
  console.debug('authData:', authData)

  const authDataView = new DataView(authData.buffer, authData.byteOffset, authData.byteLength)
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
}
