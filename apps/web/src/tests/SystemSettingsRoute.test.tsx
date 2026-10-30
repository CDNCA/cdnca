import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { beforeEach, vi } from 'vitest'

import { AppRoutes } from '../App'
import type { SystemConfigurationCategory } from '../api/systemConfiguration'
import { useSessionStore } from '../auth/session'
import { isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// Page mocks count mounts (useEffect), not renders: the shell's background
// requests re-render the route element, so a render count failed at random
// ("called once, but got 2 times"). Same fix as routeAuthorization.test.tsx.
const mounted = vi.hoisted(() => vi.fn())
const globalSettingsMounted = vi.hoisted(() => vi.fn())
const errorPagesMounted = vi.hoisted(() => vi.fn())

vi.mock('../pages/SystemGlobalSettingsPage', () => ({
  default: ({ initialTab }: { initialTab?: string }) => {
    useEffect(() => {
      globalSettingsMounted(initialTab)
    }, [initialTab])
    return <h1>system-global-settings-mounted-{initialTab ?? 'system'}</h1>
  },
}))

vi.mock('../pages/SystemSettingsPage', () => ({
  default: ({ initialCategory }: { initialCategory?: SystemConfigurationCategory }) => {
    useEffect(() => {
      mounted(initialCategory)
    }, [initialCategory])
    return <h1>system-settings-mounted-{initialCategory ?? 'nginx'}</h1>
  },
}))

vi.mock('../pages/ErrorPagesPage', () => ({
  default: () => {
    useEffect(() => {
      errorPagesMounted()
    }, [])
    return <h1>error-pages-mounted</h1>
  },
}))

beforeEach(() => {
  mounted.mockClear()
  globalSettingsMounted.mockClear()
  errorPagesMounted.mockClear()
})

describe('system configuration routes', () => {
  it('mounts the settings page for a platform administrator and marks its navigation implemented', async () => {
    const actor = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['system_configuration.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/sys/setting'])

    expect(await screen.findByRole('heading', { name: 'system-global-settings-mounted-system' })).toBeInTheDocument()
    expect(globalSettingsMounted).toHaveBeenCalledWith(undefined)
    expect(mounted).not.toHaveBeenCalled()
    expect(screen.getByLabelText('面包屑').textContent?.replace(/\s+/g, '')).toContain('首页/系统管理/系统配置')
    expect(isImplementedPath('admin', '/sys/setting', ['system_configuration.read'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/setting', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/setting', [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/setting', ['system_configuration.manage'])).toBe(false)
    expect(isImplementedPath('user', '/sys/setting')).toBe(false)
  })

  it('redirects the retired /sys/notification route to the notification tab of /sys/setting', async () => {
    const actor = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['system_configuration.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/sys/notification'])

    expect(await screen.findByRole('heading', { name: 'system-global-settings-mounted-notification' })).toBeInTheDocument()
    expect(globalSettingsMounted).toHaveBeenCalledWith('notification')
  })

  it.each([
    ['/config/nginx', 'nginx', '首页/全局配置/Nginx配置'],
    ['/config/res', 'resources', '首页/全局配置/资源配置'],
    ['/config/default', 'defaults', '首页/全局配置/默认配置'],
  ] as const)('mounts %s with the matching initial category', async (path, category, breadcrumb) => {
    const actor = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['system_configuration.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByRole('heading', { name: `system-settings-mounted-${category}` })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledWith(category)
    expect(screen.getByLabelText('面包屑').textContent?.replace(/\s+/g, '')).toContain(breadcrumb)
    expect(isImplementedPath('admin', path, ['system_configuration.read'])).toBe(true)
    expect(isImplementedPath('user', path, ['system_configuration.read'])).toBe(false)
  })

  it('mounts the dedicated error pages route', async () => {
    const actor = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['error_pages.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/config/error'])

    expect(await screen.findByRole('heading', { name: 'error-pages-mounted' })).toBeInTheDocument()
    expect(errorPagesMounted).toHaveBeenCalledOnce()
    expect(mounted).not.toHaveBeenCalled()
    expect(screen.getByLabelText('面包屑').textContent?.replace(/\s+/g, '')).toContain('首页/全局配置/错误页面')
    expect(isImplementedPath('admin', '/config/error', ['error_pages.read'])).toBe(true)
    expect(isImplementedPath('user', '/config/error', ['error_pages.read'])).toBe(false)
  })
})
