'use client'

import { ExButton } from '@/components/nextekit/ui/button'
import { idxDb } from '@/utils/indexedDB'
import { PwaCryptoStorage } from '@/utils/pwacs'
import base64url from 'base64url'
import { FC } from 'react'

export const RegisterClient: FC = () => {
  const register = async () => {
    const res = await PwaCryptoStorage.setup({
      appName: 'ProtoWallet',
      appHost: 'localhost',
      userName: 'test@user.dev',
      userDisplayName: 'TestUser',
    })
    console.log('res:', res)

    await idxDb.setPwacsConfig(res)
  }

  return <ExButton onPress={register}>test</ExButton>
}

export const AuthClient: FC = () => {
  const auth = async () => {
    const pwacsConfig = await idxDb.getPwacsConfig()
    if (pwacsConfig) {
      PwaCryptoStorage.restore(pwacsConfig)
    }
    // const dec = new TextDecoder()
    // const enc = new TextEncoder()

    // const credential = await navigator.credentials.get({
    //   publicKey: {
    //     challenge: enc.encode('challengexxx').buffer,
    //     allowCredentials: [
    //       {
    //         transports: ['internal'],
    //         type: 'public-key',
    //         id: base64url.toBuffer('NMxfzDqyz-Zo_DDdAUVY8Mb8qqJmhgNb6aJL8BaR0Qw').buffer,
    //       },
    //     ],
    //   },
    // })
    // const authAttRes = (credential as PublicKeyCredential).response as AuthenticatorAssertionResponse
    // console.log('credential:', credential)
    // console.log('signature:', base64url.encode(Buffer.from(authAttRes.signature)))
    // if (authAttRes.userHandle) {
    //   console.log('userHandle:', dec.decode(authAttRes.userHandle))
    // }
  }

  return <ExButton onPress={auth}>test2</ExButton>
}
