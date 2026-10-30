import '@testing-library/jest-dom/vitest'
import { cleanup, configure } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

import { resetSessionStore } from '../auth/session'
import { resetNavigationGuard } from '../routes/navigationGuard'
import { changeLocale } from '../i18n'

// The sign-in page probes GET /v1/auth/login-methods for the sign-up link.
// Most tests queue fetch responses in order, so the probe is mocked
// here (closed) and LoginRegistrationLink.test.tsx sets it per case.
vi.mock('../api/registrationAvailability', () => ({ registrationAvailable: vi.fn(async () => false) }))
// 登录页同样匿名读系统名称，默认读不到；LoginSystemBranding.test.tsx 按用例设置。
vi.mock('../api/publicBranding', () => ({ publicBranding: vi.fn(async () => null) }))

// antd 首次渲染较重，默认 1s 的 findBy/waitFor 在高负载机器上会偶发超时（同 seller-portal）。
configure({ asyncUtilTimeout: 5000 })

class ResizeObserverMock implements ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
})

Object.defineProperty(window, 'ResizeObserver', {
  writable: true,
  value: ResizeObserverMock,
})

const getComputedStyle = window.getComputedStyle.bind(window)
Object.defineProperty(window, 'getComputedStyle', {
  writable: true,
  value: (element: Element) => getComputedStyle(element),
})

afterEach(async () => {
  cleanup()
  resetSessionStore()
  resetNavigationGuard()
  vi.restoreAllMocks()
  await changeLocale('zh-CN')
})
