// app/providers.tsx
'use client'

import { NextUIProvider } from '@nextui-org/react'

// app/providers.tsx

// app/providers.tsx

export function Providers({ children }: { children: React.ReactNode }) {
  return <NextUIProvider>{children}</NextUIProvider>
}
