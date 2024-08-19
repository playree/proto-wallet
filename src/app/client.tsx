'use client'

import { ExButton } from '@/components/nextekit/ui/button'
import { idxDb } from '@/utils/indexedDB'
import { PwaCryptStorage } from '@/utils/pwacs'
import { FC } from 'react'

export const RegisterClient: FC = () => {
  const register = async () => {
    const pwacs = await PwaCryptStorage.setup({
      appName: 'ProtoWallet',
      appHost: 'localhost',
      userName: 'test@user.dev',
      userDisplayName: 'TestUser',
    })
    console.log('pwacs:', pwacs)

    await idxDb.setPwacsConfig(pwacs.exportConfigData())

    await idxDb.keyValue.put({
      key: 'test',
      isCrypt: true,
      value: await pwacs.encryptString('test123'),
    })
  }

  return <ExButton onPress={register}>test</ExButton>
}

export const AuthClient: FC = () => {
  const auth = async () => {
    const pwacsConfig = await idxDb.getPwacsConfig()
    if (pwacsConfig) {
      const pwacs = await PwaCryptStorage.unlock(pwacsConfig)
      const data = await idxDb.keyValue.get('test')
      if (data) {
        const teststr = await pwacs.decryptString(data.value as Uint8Array)
        console.debug('test:', teststr)
      }

      pwacs.setCallback({
        saveCB: async (key, value) => {
          await idxDb.keyValue.put({
            key,
            isCrypt: true,
            value,
          })
        },
        loadCB: async (key) => {
          const data = await idxDb.keyValue.get(key)
          return data ? (data.value as Uint8Array) : undefined
        },
      })
      await pwacs.saveString('cb', 'CB test')
      const cbres = await pwacs.loadString('cb')
      console.debug('cbres', cbres)
    }
  }

  return <ExButton onPress={auth}>test2</ExButton>
}
