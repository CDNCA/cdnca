import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import {
  getBreadcrumbLabels,
  getNavigation,
  isImplementedPath,
} from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

const mounted = vi.hoisted(() => vi.fn())

beforeEach(() => {
  mounted.mockClear()
})

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/ControlUpgradesPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>control-upgrades-mounted</h1>
  },
}))

function authenticate(scope: 'platform' | 'tenant', permissions: string[]) {
  const actor = principal(scope === 'platform' ? {
    scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions,
  } : { permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}</output>
}

describe('control upgrade route', () => {
  it.each([
    ['control.upgrades.read'],
    ['platform.admin'],
  ])('mounts the page and navigation for a platform actor with %s', async (permission) => {
    authenticate('platform', [permission])
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/sys/op'])

    expect(await screen.findByRole('heading', { name: 'control-upgrades-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(isImplementedPath('admin', '/sys/op', [permission])).toBe(true)
    expect(getBreadcrumbLabels('admin', '/sys/op')).toEqual(['首页', '系统管理', '维护升级'])
    expect(getNavigation('admin', undefined, [permission])
      .find((item) => item.key === 'system')?.children)
      .toEqual(expect.arrayContaining([expect.objectContaining({ key: '/sys/op' })]))
  })

  it.each([
    { permissions: [] as string[] },
    { permissions: ['control.upgrades.check'] },
    { permissions: ['control.upgrades.manage'] },
  ])('shows 403 without mounting for a platform actor lacking read permission: $permissions', async ({ permissions }) => {
    authenticate('platform', permissions)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<AppRoutes />, ['/sys/op'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
    expect(isImplementedPath('admin', '/sys/op', permissions)).toBe(false)
  })

  it('keeps a tenant administrator outside the platform route even when it carries the permission string', async () => {
    authenticate('tenant', ['control.upgrades.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<never>(() => undefined))
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/sys/op'])

    expect(await screen.findByTestId('location')).toHaveTextContent('/home')
    expect(mounted).not.toHaveBeenCalled()
    expect(isImplementedPath('user', '/sys/op', ['control.upgrades.read'])).toBe(false)
  })
})
