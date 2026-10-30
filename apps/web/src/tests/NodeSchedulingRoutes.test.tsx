import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { beforeEach, vi } from 'vitest'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { dashboardApi } from '../api/dashboard'
import { useSessionStore } from '../auth/session'
import { getNavigation, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'
import * as routePolicy from '../routes/routePolicy'

const mounted = vi.hoisted(() => ({
  lineGroups: vi.fn(),
  l2Topology: vi.fn(),
  l2TopologyDetail: vi.fn(),
}))
const tenantDashboardPermissions = [
  'sites.read',
  'certificates.read',
  'billing.account.read',
  'package_subscriptions.read',
  'traffic_packages.read',
  'announcements.read',
  'jobs.read',
]

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/NodeLineGroupsPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted.lineGroups() }, [])
    return <h1>node-line-groups-page</h1>
  },
}))

vi.mock('../pages/NodeL2TopologyPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted.l2Topology() }, [])
    return <h1>node-l2-topology-page</h1>
  },
}))

vi.mock('../pages/NodeL2TopologyDetailPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted.l2TopologyDetail() }, [])
    return <h1>node-l2-topology-detail-page</h1>
  },
}))

function authenticate(role: 'admin' | 'user', permissions?: string[]) {
  const actor = role === 'admin'
    ? principal({
        scope_kind: 'platform',
        tenant_id: null,
        username: 'admin',
        display_name: 'admin',
        roles: ['platform_admin'],
        permissions: permissions ?? ['nodes.read', 'nodes.manage'],
      })
    : principal({ permissions: permissions ?? tenantDashboardPermissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}</output>
}

function renderRoute(path: string) {
  return renderWithProviders(
    <>
      <AppRoutes />
      <LocationProbe />
    </>,
    [path],
  )
}

beforeEach(() => {
  for (const spy of Object.values(mounted)) spy.mockClear()
})

describe('node scheduling routes', () => {
  it('marks every scheduling route with the shared read permission while keeping L2 administrator-only', () => {
    const entries = getNavigation('admin').flatMap((item) => item.children ?? [])

    expect(entries.find((item) => item.key === '/node/line-group')?.implemented).toBe(true)
    expect(entries.find((item) => item.key === '/node/l2-config')?.implemented).toBe(true)
    expect(isImplementedPath('admin', '/node/line-group')).toBe(true)
    expect(isImplementedPath('admin', '/node/l2-config')).toBe(true)
    expect(isImplementedPath('admin', '/node/line-group', ['node_scheduling.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/line-group', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', '/node/l2-config', ['node_scheduling.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/l2-config', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', '/node/l2-config', [])).toBe(false)
    expect(isImplementedPath('user', '/node/line-group', ['node_scheduling.read'])).toBe(false)
    expect(isImplementedPath('user', '/node/line-group', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('user', '/node/line-group', [])).toBe(false)
    expect(isImplementedPath('user', '/node/line-group', ['node_scheduling.manage'])).toBe(false)
    expect(isImplementedPath('user', '/node/l2-config')).toBe(false)
    expect((routePolicy as Record<string, unknown>).nodeSchedulingReadPermission).toBe('node_scheduling.read')
  })

  it.each([
    ['/node/line-group', 'node-line-groups-page', 'lineGroups'],
    ['/node/l2-config', 'node-l2-topology-page', 'l2Topology'],
    [
      '/node/l2-config/node/33333333-3333-4333-8333-333333333333',
      'node-l2-topology-detail-page',
      'l2TopologyDetail',
    ],
  ] as const)('mounts the administrator page at %s', async (path, heading, spyName) => {
    authenticate('admin', ['node_scheduling.read'])

    renderRoute(path)

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(mounted[spyName]).toHaveBeenCalledOnce()
  })

  it.each([
    ['/node/line-group', 'lineGroups'],
    ['/node/l2-config', 'l2Topology'],
    ['/node/l2-config/node/33333333-3333-4333-8333-333333333333', 'l2TopologyDetail'],
  ] as const)('rejects platform.admin without node scheduling read at %s before mounting the page', async (path, spyName) => {
    authenticate('admin', ['platform.admin'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderRoute(path)

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(mounted[spyName]).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('rejects a tenant without node scheduling read before mounting line groups', async () => {
    authenticate('user', [])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderRoute('/node/line-group')

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(mounted.lineGroups).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it.each([
    ['tenant owner', ['node_scheduling.read', 'node_scheduling.manage']],
    ['tenant viewer', ['node_scheduling.read']],
  ])('keeps the node line-group route outside tenant access for an authenticated %s', async (_case, permissions) => {
    authenticate('user', permissions)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderRoute('/node/line-group')

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(mounted.lineGroups).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('keeps L2 topology blocked for a tenant', async () => {
    authenticate('user')
    const dashboardSpy = vi.spyOn(dashboardApi, 'tenant')
      .mockImplementation(() => new Promise<never>(() => undefined))

    renderRoute('/node/l2-config')

    expect(await screen.findByTestId('location')).toHaveTextContent('/home')
    expect(await screen.findByRole('region', { name: '服务概览' })).toBeInTheDocument()
    for (const spy of Object.values(mounted)) expect(spy).not.toHaveBeenCalled()
    expect(dashboardSpy).toHaveBeenCalledOnce()
    expect(dashboardSpy).toHaveBeenCalledWith(
      'memory-only-access-token', 'today', 'Asia/Shanghai', expect.any(AbortSignal), {},
    )
  })

  it('keeps an unknown L2 detail path on the existing 404 surface', async () => {
    authenticate('admin')

    renderRoute('/node/l2-config/node')

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    for (const spy of Object.values(mounted)) expect(spy).not.toHaveBeenCalled()
  })
})
