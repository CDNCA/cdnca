import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { getBreadcrumbLabels, getNavigation, getNavigationSelectionKey, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

const mounted = vi.hoisted(() => vi.fn())

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/IdentitySessionsPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>identity-sessions-route-mounted</h1>
  },
}))

function LocationProbe() {
  const location = useLocation()
  return <output aria-label="location">{`${location.pathname}${location.search}${location.hash}`}</output>
}

function authenticate(kind: 'tenant' | 'platform') {
  const actor = kind === 'platform'
    ? principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    : principal()
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function findItem(role: 'admin' | 'user') {
  return getNavigation(role)
    .flatMap((group) => group.children ?? [group])
    .find((item) => item.key === '/account/sessions')
}

describe('identity session route and navigation', () => {
  beforeEach(async () => {
    mounted.mockClear()
    await i18n.changeLanguage('zh-CN')
  })

  it.each(['tenant', 'platform'] as const)('mounts for a valid %s owner and preserves query/hash', async (kind) => {
    authenticate(kind)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/account/sessions?cursor=opaque#device'])

    expect(await screen.findByRole('heading', { name: 'identity-sessions-route-mounted' })).toBeInTheDocument()
    expect(screen.getByLabelText('location')).toHaveTextContent('/account/sessions?cursor=opaque#device')
    expect(mounted).toHaveBeenCalledOnce()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('rejects a tenant owner without tenant lineage before lazy mounting or API access', async () => {
    const actor = principal({ tenant_id: null })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/account/sessions'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('keeps the implemented page direct-only with complete locale labels', async () => {
    expect(isImplementedPath('admin', '/account/sessions')).toBe(true)
    expect(isImplementedPath('user', '/account/sessions')).toBe(true)
    expect(findItem('admin')).toBeUndefined()
    expect(findItem('user')).toBeUndefined()
    expect(getNavigationSelectionKey('admin', '/account/sessions')).toBe('/sys/setting')
    expect(getNavigationSelectionKey('user', '/account/sessions')).toBe('/account/user')

    for (const [locale, expected] of [
      ['zh-CN', '登录设备'],
      ['en-US', 'Signed-in devices'],
    ] as const) {
      await i18n.changeLanguage(locale)
      expect(getBreadcrumbLabels('admin', '/account/sessions')).toEqual([
        i18n.t('navigation:home'), i18n.t('navigation:system'), expected,
      ])
      expect(getBreadcrumbLabels('user', '/account/sessions')).toEqual([
        i18n.t('navigation:home'), i18n.t('navigation:accountCenter'), expected,
      ])
    }
    await i18n.changeLanguage('qps-ploc')
    expect(getBreadcrumbLabels('admin', '/account/sessions')[2]).toMatch(/^［.+］$/)
    expect(getBreadcrumbLabels('user', '/account/sessions')[2]).toMatch(/^［.+］$/)
  })
})
