import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { getBreadcrumbLabels, getNavigation, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

const mounted = vi.hoisted(() => vi.fn())

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/NodeMonitorSettingsPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>node-monitor-settings-mounted</h1>
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

describe('node monitor settings route', () => {
  beforeEach(() => mounted.mockClear())

  it.each([['system_configuration.read'], ['platform.admin']])(
    'mounts the page and navigation for a platform actor with %s',
    async (permission) => {
      authenticate('platform', [permission])
      renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/node/monitor-setting'])

      expect(await screen.findByRole('heading', { name: 'node-monitor-settings-mounted' })).toBeInTheDocument()
      expect(mounted).toHaveBeenCalledOnce()
      expect(isImplementedPath('admin', '/node/monitor-setting', [permission])).toBe(true)
      expect(getBreadcrumbLabels('admin', '/node/monitor-setting')).toEqual(['首页', '节点管理', '监控配置'])
      expect(getNavigation('admin', undefined, [permission]).find((item) => item.key === 'node')?.children)
        .toEqual(expect.arrayContaining([expect.objectContaining({ key: '/node/monitor-setting' })]))
    },
  )

  it('shows 403 without mounting or fetching when read permission is absent', async () => {
    authenticate('platform', ['system_configuration.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<AppRoutes />, ['/node/monitor-setting'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
    expect(isImplementedPath('admin', '/node/monitor-setting', ['system_configuration.manage'])).toBe(false)
  })

  it('keeps a tenant administrator outside the admin route', async () => {
    authenticate('tenant', ['system_configuration.read'])
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/node/monitor-setting'])

    expect(await screen.findByTestId('location')).toHaveTextContent('/home')
    expect(mounted).not.toHaveBeenCalled()
  })
})
