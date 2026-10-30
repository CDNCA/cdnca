import { screen } from '@testing-library/react'
import { useEffect } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const mounted = vi.hoisted(() => vi.fn())

// 页面替身计挂载（useEffect）而非渲染：控制台壳懒加载、全量 i18n 资源随壳装入后路由元素
// 会重新渲染，渲染次数取决于时序。
vi.mock('../pages/SystemGlobalSettingsPage', () => ({
  default: function PageMock() {
    useEffect(() => { mounted() }, [])
    return <h1>system-global-settings-mounted</h1>
  },
}))

beforeEach(() => mounted.mockClear())

describe('system global settings route', () => {
  it('mounts the canonical settings page for an authorized administrator', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['system_configuration.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/sys/setting'])

    expect(await screen.findByRole('heading', { name: 'system-global-settings-mounted' })).toBeInTheDocument()
    expect(mounted).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/系统配置')
  })

  it('rejects the route before lazy mounting without read permission', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: [],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, ['/sys/setting'])

    expect(await screen.findByText('403')).toBeInTheDocument()
    expect(mounted).not.toHaveBeenCalled()
  })
})
