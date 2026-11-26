import { screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'

const menuOpenKey = (role: string) => { const p = useSessionStore.getState().principal!; return `cdnca.ui.menu-open.${role}.${p.scope_id}.${p.user_id}.v3` }
import { renderWithProviders } from '../test/render'

// 管理员两个菜单项都叫「实时监控」：可见文字沿用旧名，可访问名称与页面标题用全名区分。
function renderShell(admin: boolean, path: string) {
  const actor = admin
    ? principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    : principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  window.localStorage.setItem(menuOpenKey(admin ? 'admin' : 'user'), JSON.stringify(['node', 'monitor']))
  return renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<section aria-label="realtime-name-probe" />} />
      </Route>
    </Routes>,
    [path],
  )
}

afterEach(() => {
  window.localStorage.clear()
})

describe('实时监控菜单项与页面标题', () => {
  it.each([
    ['/node/realtime', '节点实时监控', '首页/节点管理/节点实时监控'],
    ['/monitor/site/realtime', '网站实时监控', '首页/统计分析/网站实时监控'],
  ])('管理员 %s：菜单名 %s、可见文字不变、标题用全名', async (path, name, trail) => {
    await i18n.changeLanguage('zh-CN')
    const { container } = renderShell(true, path)

    const node = screen.getByRole('menuitem', { name: '节点实时监控' })
    const site = screen.getByRole('menuitem', { name: '网站实时监控' })
    expect(node).toHaveTextContent(/^实时监控$/)
    expect(site).toHaveTextContent(/^实时监控$/)
    expect(screen.queryByRole('menuitem', { name: '实时监控' })).not.toBeInTheDocument()
    // 内层链接也用全名，链接列表里不再同名。
    expect(screen.getByRole('link', { name: '节点实时监控' })).toHaveAttribute('href', expect.stringMatching(/\/node\/realtime$/))
    expect(screen.getByRole('link', { name: '网站实时监控' })).toHaveAttribute('href', expect.stringMatching(/\/monitor\/site\/realtime$/))
    expect(screen.queryByRole('link', { name: '实时监控' })).not.toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name })).toHaveClass('ant-menu-item-selected')
    expect(container.querySelector('.shell-breadcrumb-current')).toHaveTextContent(new RegExp(`^${name}$`))
    expect(container.querySelector('.shell-breadcrumb-a11y')).toHaveTextContent(new RegExp(`^${trail}$`))
  })

  it('租户网站实时监控同样处理', async () => {
    await i18n.changeLanguage('zh-CN')
    const { container } = renderShell(false, '/monitor/site/realtime')

    const site = screen.getByRole('menuitem', { name: '网站实时监控' })
    expect(site).toHaveTextContent(/^实时监控$/)
    expect(site).toHaveClass('ant-menu-item-selected')
    expect(screen.getByRole('menuitem', { name: '四层实时监控' })).toBeInTheDocument()
    expect(container.querySelector('.shell-breadcrumb-current')).toHaveTextContent(/^网站实时监控$/)
    expect(container.querySelector('.shell-breadcrumb-a11y')).toHaveTextContent(/^首页\/统计分析\/网站实时监控$/)
  })

  it('英文名称包含可见文字', async () => {
    await i18n.changeLanguage('en-US')
    renderShell(true, '/node/realtime')

    for (const name of ['Node real-time monitoring', 'Site real-time monitoring']) {
      expect(screen.getByRole('menuitem', { name })).toHaveTextContent(/^Real-time monitoring$/)
    }
    await i18n.changeLanguage('zh-CN')
  })
})
