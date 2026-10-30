import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { beforeEach, vi } from 'vitest'

import { AppRoutes } from '../App'
import { resetSessionStore, useSessionStore } from '../auth/session'
import { getDeclaredPaths, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

const mounted = vi.hoisted(() => ({
  certificateOrders: vi.fn(),
  cachePolicyHistory: vi.fn(),
}))

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/CertificateOrdersPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted.certificateOrders() }, [])
    return <h1>certificate-orders-page</h1>
  },
}))

vi.mock('../pages/CachePolicyHistoryPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted.cachePolicyHistory() }, [])
    return <h1>cache-policy-history-page</h1>
  },
}))

const routes = [
  ['/site/cert/orders', 'certificates.read', 'certificate-orders-page', mounted.certificateOrders],
  ['/site/cache-clean/history', 'sites.read', 'cache-policy-history-page', mounted.cachePolicyHistory],
] as const

function authenticate(permissions: string[], scopeKind: 'tenant' | 'platform' = 'tenant') {
  const actor = scopeKind === 'tenant'
    ? principal({ permissions })
    : principal({
        scope_kind: 'platform',
        tenant_id: null,
        roles: ['platform_admin'],
        permissions,
      })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

beforeEach(() => {
  resetSessionStore()
  for (const spy of Object.values(mounted)) spy.mockClear()
})

describe('Batch P route wiring', () => {
  it('declares the tenant-only navigation paths with their permissions', () => {
    expect(getDeclaredPaths()).toEqual(expect.arrayContaining(routes.map(([path]) => path)))
    for (const [path, permission] of routes) {
      expect(isImplementedPath('user', path, [permission])).toBe(true)
      expect(isImplementedPath('user', path, [])).toBe(false)
      expect(isImplementedPath('admin', path, [permission])).toBe(false)
    }
  })

  it.each(routes)('mounts %s only after the tenant permission gate', async (path, permission, heading, mount) => {
    authenticate([permission])

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(mount).toHaveBeenCalledOnce()
  })

  it.each(routes)('denies %s before lazy mounting when the permission is missing', async (path, _permission, _heading, mount) => {
    authenticate([])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(mount).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it.each(routes)('keeps %s tenant-only for platform principals', async (path, permission, _heading, mount) => {
    authenticate([permission], 'platform')

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(mount).not.toHaveBeenCalled()
  })
})
