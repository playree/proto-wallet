import { gridStyles } from '@/components/styles'
import { ThemeSwitchList } from '@/components/theme-switch'
import { FC } from 'react'

import { AuthClient, RegisterClient } from './client'

const Home: FC = () => {
  return (
    <main className='flex min-h-screen flex-col items-center justify-between p-24'>
      <div className='mb-4 flex items-center pl-8 lg:pl-0'>
        <div className='right-0 flex flex-auto justify-end'>
          <ThemeSwitchList size='sm' className='mr-2' />
        </div>
      </div>
      <div className={gridStyles()}>
        <div className='col-span-12'>
          <RegisterClient />
        </div>
        <div className='col-span-12'>
          <AuthClient />
        </div>
      </div>
    </main>
  )
}
export default Home
