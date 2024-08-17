'use client'

import { ExButton } from '@/components/nextekit/ui/button'
import { idxDb } from '@/utils/indexedDB'
import { PwaCryptStorage } from '@/utils/pwacs'
import { FC } from 'react'

export const RegisterClient: FC = () => {
  const register = async () => {
    const res = await PwaCryptStorage.setup({
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
      await PwaCryptStorage.unlock(pwacsConfig)
    }
  }

  return <ExButton onPress={auth}>test2</ExButton>
}
