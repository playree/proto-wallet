'use client'

import { IconSvgProps } from '@/types'
import { Button } from '@nextui-org/button'
import { Dropdown, DropdownItem, DropdownMenu, DropdownTrigger } from '@nextui-org/dropdown'
import { SwitchProps, useSwitch } from '@nextui-org/switch'
import { useIsSSR } from '@react-aria/ssr'
import { VisuallyHidden } from '@react-aria/visually-hidden'
import { useTheme } from 'next-themes'
import { FC, ReactNode, useEffect, useMemo, useState } from 'react'
import { twMerge } from 'tailwind-merge'

import { iconSizes } from './styles'

export interface ThemeSwitchProps {
  className?: string
  classNames?: SwitchProps['classNames']
}

const MoonFilledIcon = ({ size = 24, width, height, ...props }: IconSvgProps) => (
  <svg
    aria-hidden='true'
    focusable='false'
    height={size || height}
    role='presentation'
    viewBox='0 0 24 24'
    width={size || width}
    {...props}
  >
    <path
      d='M21.53 15.93c-.16-.27-.61-.69-1.73-.49a8.46 8.46 0 01-1.88.13 8.409 8.409 0 01-5.91-2.82 8.068 8.068 0 01-1.44-8.66c.44-1.01.13-1.54-.09-1.76s-.77-.55-1.83-.11a10.318 10.318 0 00-6.32 10.21 10.475 10.475 0 007.04 8.99 10 10 0 002.89.55c.16.01.32.02.48.02a10.5 10.5 0 008.47-4.27c.67-.93.49-1.519.32-1.79z'
      fill='currentColor'
    />
  </svg>
)

const SunFilledIcon = ({ size = 24, width, height, ...props }: IconSvgProps) => (
  <svg
    aria-hidden='true'
    focusable='false'
    height={size || height}
    role='presentation'
    viewBox='0 0 24 24'
    width={size || width}
    {...props}
  >
    <g fill='currentColor'>
      <path d='M19 12a7 7 0 11-7-7 7 7 0 017 7z' />
      <path d='M12 22.96a.969.969 0 01-1-.96v-.08a1 1 0 012 0 1.038 1.038 0 01-1 1.04zm7.14-2.82a1.024 1.024 0 01-.71-.29l-.13-.13a1 1 0 011.41-1.41l.13.13a1 1 0 010 1.41.984.984 0 01-.7.29zm-14.28 0a1.024 1.024 0 01-.71-.29 1 1 0 010-1.41l.13-.13a1 1 0 011.41 1.41l-.13.13a1 1 0 01-.7.29zM22 13h-.08a1 1 0 010-2 1.038 1.038 0 011.04 1 .969.969 0 01-.96 1zM2.08 13H2a1 1 0 010-2 1.038 1.038 0 011.04 1 .969.969 0 01-.96 1zm16.93-7.01a1.024 1.024 0 01-.71-.29 1 1 0 010-1.41l.13-.13a1 1 0 011.41 1.41l-.13.13a.984.984 0 01-.7.29zm-14.02 0a1.024 1.024 0 01-.71-.29l-.13-.14a1 1 0 011.41-1.41l.13.13a1 1 0 010 1.41.97.97 0 01-.7.3zM12 3.04a.969.969 0 01-1-.96V2a1 1 0 012 0 1.038 1.038 0 01-1 1.04z' />
    </g>
  </svg>
)

export const ThemeSwitch: FC<ThemeSwitchProps> = ({ className, classNames }) => {
  const { theme, setTheme } = useTheme()
  const isSSR = useIsSSR()

  const onChange = () => {
    if (theme === 'light') {
      setTheme('dark')
    } else {
      setTheme('light')
    }
  }

  const { Component, slots, isSelected, getBaseProps, getInputProps, getWrapperProps } = useSwitch({
    isSelected: theme === 'light',
    'aria-label': `Switch to ${theme === 'light' ? 'dark' : 'light'} mode`,
    onChange,
  })

  return (
    <Component
      {...getBaseProps({
        className: twMerge('cursor-pointer px-px transition-opacity hover:opacity-80', className, classNames?.base),
      })}
    >
      <VisuallyHidden>
        <input {...getInputProps()} />
      </VisuallyHidden>
      <div
        {...getWrapperProps()}
        className={slots.wrapper({
          class: twMerge(
            [
              'mx-0 h-auto w-auto rounded-lg bg-transparent px-0 pt-px',
              'flex items-center justify-center',
              'group-data-[selected=true]:bg-transparent',
              '!text-default-500',
            ],
            classNames?.wrapper,
          ),
        })}
      >
        {!isSelected || isSSR ? <SunFilledIcon size={22} /> : <MoonFilledIcon size={22} />}
      </div>
    </Component>
  )
}

export const ThemeSwitchList: FC<{ className?: string; size?: 'sm' | 'md' | 'lg' }> = ({ className, size = 'md' }) => {
  const iconSize = iconSizes[size]
  const { theme, setTheme, systemTheme } = useTheme()
  const [selectedKeys, setSelectedKeys] = useState(new Set([theme || 'system']))

  const lightIcon = useMemo(() => <SunFilledIcon size={iconSize} />, [iconSize])
  const darkIcon = useMemo(() => <MoonFilledIcon size={iconSize} />, [iconSize])
  const [systemIcon, setSystemIcon] = useState<ReactNode>()
  const [selectIcon, setSelectIcon] = useState<ReactNode>()
  const [selectedValue, setSelectedValue] = useState('Loading')

  useEffect(() => {
    setSystemIcon(systemTheme === 'dark' ? darkIcon : lightIcon)
  }, [darkIcon, lightIcon, systemTheme])

  useEffect(() => {
    console.debug('theme:', theme)
    switch (theme) {
      case 'system':
        setSelectIcon(systemIcon)
        break
      case 'light':
        setSelectIcon(lightIcon)
        break
      case 'dark':
        setSelectIcon(darkIcon)
        break
    }
  }, [darkIcon, lightIcon, systemIcon, theme])

  useEffect(() => {
    setSelectedValue(Array.from(selectedKeys).join(', ').replaceAll('_', ' '))
  }, [selectedKeys])

  return (
    <Dropdown className={className} size={size}>
      <DropdownTrigger>
        <Button size={size} variant='bordered' startContent={selectIcon} className={className}>
          {selectedValue === 'system' ? 'auto' : selectedValue}
        </Button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label='Select Theme'
        variant='flat'
        disallowEmptySelection
        selectionMode='single'
        selectedKeys={selectedKeys}
        onAction={(key) => {
          const keyString = key.toString()
          setSelectedKeys(new Set([keyString]))
          setTheme(keyString)
        }}
      >
        <DropdownItem key='system' startContent={systemIcon}>
          auto
        </DropdownItem>
        <DropdownItem key='light' startContent={lightIcon}>
          light
        </DropdownItem>
        <DropdownItem key='dark' startContent={darkIcon}>
          dark
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  )
}
