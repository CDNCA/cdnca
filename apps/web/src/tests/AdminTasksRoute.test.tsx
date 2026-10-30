import { screen, waitFor } from '@testing-library/react'
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { dashboardApi } from '../api/dashboard'
import { jobsApi } from '../api/jobs'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const mounted = vi.hoisted(() => vi.fn())
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
vi.mock('../pages/AdminTasksPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>admin-tasks-mounted</h1>
  },
}))

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}</output>
}

describe('/sys/task route authorization', () => {
  it('redirects a tenant before the privileged component mounts or requests data', async () => {
    const actor = principal({ permissions: tenantDashboardPermissions })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const dashboardSpy = vi.spyOn(dashboardApi, 'tenant')
      .mockImplementation(() => new Promise<never>(() => undefined))
    const jobsSpy = vi.spyOn(jobsApi, 'list')

    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/sys/task'])

    // 控制台壳懒加载，重定向要等壳装完才发生；期间只显示兜底，不挂载任何页面。
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/home'))
    expect(await screen.findByRole('region', { name: '服务概览' })).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
    expect(jobsSpy).not.toHaveBeenCalled()
    expect(dashboardSpy).toHaveBeenCalledOnce()
    expect(dashboardSpy).toHaveBeenCalledWith(
      'memory-only-access-token', 'today', 'Asia/Shanghai', expect.any(AbortSignal), {},
    )
  })

  it('mounts the task page for a platform administrator', async () => {
    const actor = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['jobs.read_all'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/sys/task'])

    expect(await screen.findByRole('heading', { name: 'admin-tasks-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/后台任务')
  })

  it('mounts the adaptive task page for a tenant with jobs.read', async () => {
    const actor = principal({ permissions: ['jobs.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/task'])

    expect(await screen.findByRole('heading', { name: 'admin-tasks-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/后台任务')
  })

  it('rejects a tenant without jobs.read before the task page mounts', async () => {
    const actor = principal({ permissions: ['jobs.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const jobsSpy = vi.spyOn(jobsApi, 'list')

    renderWithProviders(<AppRoutes />, ['/task'])

    expect(await screen.findByText('403')).toBeInTheDocument()
    expect(screen.getByText('无权访问')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
    expect(jobsSpy).not.toHaveBeenCalled()
  })
})
