import { screen } from '@testing-library/react'
import { useEffect } from 'react'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { getBreadcrumbLabels, getParentNavigationKey, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const mounted = vi.hoisted(() => vi.fn())

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/NodeL2TopologyDetailPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>node-line-group-lines-mounted</h1>
  },
}))

const groupID = '11111111-1111-4111-8111-111111111111'
const route = `/node/line-group/line/${groupID}`

function authenticate(permissions: string[]) {
  const actor = principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

beforeEach(() => mounted.mockClear())

describe('UX-01 observed node line-group detail route', () => {
  it('mounts the production detail page for an authorized administrator', async () => {
    authenticate(['node_scheduling.read'])

    renderWithProviders(<AppRoutes />, [route])

    expect(await screen.findByRole('heading', { name: 'node-line-group-lines-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/节点管理/设置解析')
  })

  it('denies an administrator before the privileged page mounts', async () => {
    authenticate(['nodes.read'])

    renderWithProviders(<AppRoutes />, [route])

    expect(await screen.findByText('403')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
  })

  it('publishes dynamic route ownership and exact RBAC without a menu duplicate', () => {
    expect(isImplementedPath('admin', route, ['node_scheduling.read'])).toBe(true)
    expect(isImplementedPath('admin', route, [])).toBe(false)
    expect(isImplementedPath('admin', route, ['platform.admin'])).toBe(false)
    expect(isImplementedPath('user', route, ['node_scheduling.read'])).toBe(false)
    expect(getParentNavigationKey('admin', route)).toBe('node')
    expect(getBreadcrumbLabels('admin', route)).toEqual(['首页', '节点管理', '设置解析'])
  })
})
