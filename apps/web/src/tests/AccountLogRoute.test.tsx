import { screen } from '@testing-library/react'
import { beforeEach, vi } from 'vitest'
import { useEffect } from 'react'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

const mounted = vi.hoisted(() => vi.fn())

vi.mock('../pages/AccountLogPage', () => ({
  // 计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后会让路由元素
  // 重新渲染，渲染次数取决于时序。
  default: function AccountLogPageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>account-observability-log-mounted</h1>
  },
}))

beforeEach(() => {
  mounted.mockClear()
})

describe('account observability log route', () => {
  it('mounts the account log page for a tenant identity reader', async () => {
    const actor = principal({ permissions: ['identity.self.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/account/log'])

    expect(await screen.findByRole('heading', { name: 'account-observability-log-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it.each([
    { permissions: [] as string[] },
  ])('returns 403 before lazy mounting for a tenant with permissions $permissions', async ({ permissions }) => {
    const actor = principal({ permissions })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/account/log'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  // 账户操作日志页对管理员展示的是他自己的操作日志，
  // 所以平台作用域（无租户）同样按自身作用域进入二级路由。
  it('mounts the account log page for a platform identity reader', async () => {
    const actor = principal({
      scope_kind: 'platform',
      scope_id: '01a0859f-e949-7d00-9c85-cc02f6332fde',
      tenant_id: null,
      roles: ['platform_owner'],
      permissions: ['platform.admin', 'identity.self.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/account/log'])

    expect(await screen.findByRole('heading', { name: 'account-observability-log-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(pageRequests(fetchSpy)).toEqual([])
  })
})
