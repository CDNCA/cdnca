import { screen } from '@testing-library/react'
import { useEffect } from 'react'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { getNavigation, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const mounts = vi.hoisted(() => ({ messages: vi.fn() }))

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/AdminMessageQueryPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounts.messages() }, [])
    return <h1>admin-message-query-mounted</h1>
  },
}))

function authenticate(permissions: string[]) {
  const actor = principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

beforeEach(() => {
  mounts.messages.mockClear()
})

describe('UX-01 missing route closures', () => {
  it('mounts message delivery query only for system configuration readers', async () => {
    authenticate(['system_configuration.read'])

    renderWithProviders(<AppRoutes />, ['/sys/message'])

    expect(await screen.findByRole('heading', { name: 'admin-message-query-mounted' })).toBeInTheDocument()
    expect(mounts.messages).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/消息查询')
    expect(isImplementedPath('admin', '/sys/message', ['system_configuration.read'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/message', [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/message', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('user', '/sys/message', ['system_configuration.read'])).toBe(false)
  })

  it.each([
    ['/sys/message', 'messages'],
  ] as const)('denies %s before its page mounts', async (path, page) => {
    authenticate(['users.read'])

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('403')).toBeInTheDocument()
    expect(mounts[page]).not.toHaveBeenCalled()
  })

  it('publishes the implemented entry only to authorized admin navigation', () => {
    const entries = getNavigation('admin', undefined, [
      'system_configuration.read',
    ]).flatMap((item) => item.children ?? [])

    expect(entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: '/sys/message', implemented: true }),
    ]))
    // 社区版：财务管理（充值统计等）已删除。
    expect(isImplementedPath('admin', '/finance/recharge-count', ['platform.admin'])).toBe(false)
  })
})
