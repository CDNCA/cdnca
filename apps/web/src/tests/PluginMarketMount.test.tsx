import { screen } from '@testing-library/react'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import { pluginInstallationsApi } from '../api/pluginInstallations'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import {
  getBreadcrumbLabels,
  getNavigation,
  getParentNavigationKey,
  isImplementedPath,
} from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const permission = 'plugin_installations.read'
const path = '/sys/plugin-market'

// The node market and plugin store menus follow GET /v1/runtime-features
// market (vis-2); these mounts run with the market runtime on.
function stubMarketRuntime() {
  const original = globalThis.fetch
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => (
    String(input).endsWith('/v1/runtime-features')
      ? Promise.resolve(new Response(JSON.stringify({ features: {
        cache_control: false, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: true, package_auto_renew: false, origin_auth: false,
      } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      : original(input, init)
  ))
}

function authenticateTenant(permissions: string[]) {
  const actor = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('plugin marketplace mount', () => {
  it('lazy-loads the real tenant page behind the exact read permission', async () => {
    authenticateTenant([permission])
    const list = vi.spyOn(pluginInstallationsApi, 'list').mockResolvedValue({ items: [] })

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByRole('heading', { name: '插件市场' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/插件市场')
    expect(list).toHaveBeenCalledOnce()
    expect(list).toHaveBeenCalledWith(
      'memory-only-access-token',
      '22222222-2222-4222-8222-222222222222',
      { limit: 50 },
    )
  })

  it('denies a tenant without the exact read permission before any API request', async () => {
    authenticateTenant(['plugin_installations.manage', 'platform.admin'])
    const list = vi.spyOn(pluginInstallationsApi, 'list')

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })

  it('hides the customer route from a platform principal before any API request', async () => {
    const actor = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: [permission, 'platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const list = vi.spyOn(pluginInstallationsApi, 'list')

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })

  it('keeps the direct route permissioned without adding it to the sidebar', async () => {
    expect(isImplementedPath('user', path, [permission])).toBe(true)
    expect(isImplementedPath('user', path, [])).toBe(false)
    expect(isImplementedPath('user', path, ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', path, [permission])).toBe(false)
    expect(getParentNavigationKey('user', path)).toBe('system')
    expect(getBreadcrumbLabels('user', path)).toEqual(['首页', '系统管理', '插件市场'])

    const system = getNavigation('user', undefined, [permission])
      .find((item) => item.key === 'system')
    expect(system).toBeUndefined()

    await changeLocale('en-US')
    expect(i18n.t('navigation:pluginMarketplace')).toBe('Plugin marketplace')
    await changeLocale('qps-ploc')
    expect(i18n.t('navigation:pluginMarketplace')).toMatch(/^［.+］$/)
  })

  it('mounts the platform plugin store for marketplace codes and the legacy gate, not for tenants', async () => {
    expect(isImplementedPath('admin', '/sys/plugin-store', ['marketplace.browse'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/plugin-store', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('user', '/sys/plugin-store', ['marketplace.browse'])).toBe(false)
    stubMarketRuntime()
    for (const permissions of [['marketplace.purchase'], ['sites.manage']]) {
      const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const { unmount } = renderWithProviders(<AppRoutes />, ['/sys/plugin-store'])
      expect(await screen.findByRole('heading', { name: '插件商店' })).toBeInTheDocument()
      unmount()
    }
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['nodes.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    renderWithProviders(<AppRoutes />, ['/sys/plugin-store'])
    expect(await screen.findByText('无权访问')).toBeInTheDocument()
  })

  it('opens the node market for the new marketplace codes as well as sites.manage', async () => {
    stubMarketRuntime()
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['marketplace.browse'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    renderWithProviders(<AppRoutes />, ['/sys/node-market'])
    expect(await screen.findByRole('heading', { name: '节点市场' })).toBeInTheDocument()
  })
})
