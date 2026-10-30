import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes, useLocation } from 'react-router-dom'

import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { useNavigationGuardStore } from '../routes/navigationGuard'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import shellStyles from '../components/AppShell.css?raw'
import i18n from '../i18n'

const reloadPage = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => {
      const navigate = actual.useNavigate()
      return (to: string | number, options?: object) => {
        if (to === 0) return reloadPage()
        if (typeof to === 'number') return navigate(to)
        return navigate(to, options)
      }
    },
  }
})

function LocationProbe() {
  return <output data-testid="shell-location">{useLocation().pathname}</output>
}

function renderAdmin(permissions = ['platform.admin', 'system_configuration.read']) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(<Routes><Route element={<AppShell />}><Route path="*" element={<LocationProbe />} /></Route></Routes>, ['/admin-home'])
}

beforeEach(() => reloadPage.mockClear())

describe('observed administrator shell actions', () => {
  it.each(['zh-CN', 'en-US', 'qps-ploc'])('keeps shell action translations complete in %s', async (locale) => {
    await i18n.changeLanguage(locale)
    renderAdmin()
    expect(screen.getByRole('button', { name: i18n.t('appShellReference:refreshPage') })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: i18n.t('common:accountMenu') }))
    expect(await screen.findByRole('menuitem', { name: i18n.t('appShellReference:systemSettings') })).toBeInTheDocument()
  })

  // C02: the account menu says who is signed in, on which side and with which roles.
  it('identifies the signed-in account, side and roles in the account menu', async () => {
    await i18n.changeLanguage('zh-CN')
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
      username: 'ops-admin', display_name: 'Ops Admin' })
    session.useSessionStore.getState().setSession(authResponse(admin), admin)
    const view = renderWithProviders(<Routes><Route element={<AppShell />}><Route path="*" element={<LocationProbe />} /></Route></Routes>, ['/admin-home'])
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    const identity = (await screen.findByText('Ops Admin')).closest('.shell-account-identity') as HTMLElement
    expect(within(identity).getByText('@ops-admin')).toBeInTheDocument()
    expect(within(identity).getByText('平台管理端 · 平台管理员')).toBeInTheDocument()
    view.unmount()

    const tenant = principal({ roles: ['tenant_owner'], username: 'shop-owner', display_name: 'Shop' })
    session.useSessionStore.getState().setSession(authResponse(tenant), tenant)
    renderWithProviders(<Routes><Route element={<AppShell />}><Route path="*" element={<LocationProbe />} /></Route></Routes>, ['/home'])
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    const tenantIdentity = (await screen.findByText('Shop')).closest('.shell-account-identity') as HTMLElement
    expect(within(tenantIdentity).getByText('@shop-owner')).toBeInTheDocument()
    expect(within(tenantIdentity).getByText('用户控制台 · 主账号')).toBeInTheDocument()
  })

  it('persists the theme toggle and restores it when the shell remounts', async () => {
    const originalTheme = window.localStorage.getItem('cdnca.ui.theme')
    window.localStorage.removeItem('cdnca.ui.theme')
    const view = renderAdmin()
    try {
      await act(async () => { fireEvent.click(screen.getByRole('button', { name: '切换暗色主题' })) })
      expect(document.body).toHaveClass('i-theme-dark')
      expect(window.localStorage.getItem('cdnca.ui.theme')).toBe('dark')
      view.unmount()
      renderAdmin()
      expect(screen.getByRole('button', { name: '切换亮色主题' })).toHaveAttribute('aria-pressed', 'true')
      expect(document.documentElement.dataset.theme).toBe('dark')
    } finally {
      if (originalTheme === null) window.localStorage.removeItem('cdnca.ui.theme')
      else window.localStorage.setItem('cdnca.ui.theme', originalTheme)
    }
  })

  it('does not expose administrator settings in the tenant account menu', async () => {
    const actor = principal({ permissions: ['identity.self.read'], display_name: 'Tenant name' })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    renderWithProviders(<Routes><Route element={<AppShell />}><Route path="*" element={<LocationProbe />} /></Route></Routes>, ['/home'])
    expect(screen.getByRole('button', { name: '刷新会话' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    expect(await screen.findByRole('menuitem', { name: /^Tenant name/ })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.queryByRole('menuitem', { name: '系统设置' })).not.toBeInTheDocument()
  })

  it('keeps the administrator brand and header fixed when only the sidebar collapses', async () => {
    const rendered = renderAdmin()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '折叠导航' })) })
    expect(rendered.container.querySelector('.app-shell')).toHaveClass('is-admin', 'is-collapsed')
    const style = document.createElement('style')
    style.textContent = shellStyles
    document.head.append(style)
    const desktop = [...style.sheet!.cssRules].find((rule) => 'conditionText' in rule && rule.conditionText === '(min-width: 768px)') as CSSMediaRule | undefined
    const rules = [...(desktop?.cssRules ?? [])] as CSSStyleRule[]
    const rule = (selector: string) => rules.find((candidate) => candidate.selectorText === selector)?.style
    expect(rule('.app-shell.is-admin.is-collapsed .app-sidebar')?.top).toBe('64px')
    expect(rule('.app-shell.is-admin.is-collapsed .app-header')?.getPropertyValue('padding-left')).toBe('256px')
    expect(rule('.app-shell.is-admin.is-collapsed .shell-brand')?.position).toBe('fixed')
    expect(rule('.app-shell.is-admin.is-collapsed .shell-brand')?.width).toBe('256px')
    expect(rule('.app-shell.is-admin.is-collapsed .shell-brand-crop')?.width).toBe('160.234375px')
    style.remove()
  })

  it('shows settings and logout in reference order and navigates to the real settings route', async () => {
    renderAdmin()
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    const settings = await screen.findByRole('menuitem', { name: '系统设置' })
    const menu = settings.closest('[role="menu"]')!
    // C02 puts the read-only identity line first; the actions keep the reference order.
    const items = within(menu as HTMLElement).getAllByRole('menuitem')
    expect(items[0]).toHaveAttribute('aria-disabled', 'true')
    expect(items.slice(1).map((item) => item.textContent)).toEqual(['系统设置', '退出登录'])
    // 默认夹具没有 identity.self.read：个人资料入口跟随路由权限隐藏（platform.admin 不兜底）。
    fireEvent.click(settings)
    expect(screen.getByTestId('shell-location')).toHaveTextContent('/sys/setting')
  })

  // fp-role ID-03：管理员账号菜单 → 个人资料（自己的账号，不是用户列表）。
  it('opens the administrator profile from the account menu', async () => {
    renderAdmin(['platform.admin', 'system_configuration.read', 'identity.self.read'])
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    const profile = await screen.findByRole('menuitem', { name: '个人资料' })
    const items = within(profile.closest('[role="menu"]') as HTMLElement).getAllByRole('menuitem')
    expect(items.slice(1).map((item) => item.textContent)).toEqual(['个人资料', '系统设置', '退出登录'])
    fireEvent.click(profile)
    expect(screen.getByTestId('shell-location')).toHaveTextContent('/account/user')
  })

  it('keeps the settings entry behind the existing route permission', async () => {
    renderAdmin(['nodes.read'])
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    await screen.findByRole('menuitem', { name: '退出登录' })
    expect(screen.queryByRole('menuitem', { name: '系统设置' })).not.toBeInTheDocument()
  })

  it('honors a declined unsaved-changes confirmation before opening settings', async () => {
    renderAdmin()
    useNavigationGuardStore.getState().setDirty(true)
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    fireEvent.click(await screen.findByRole('menuitem', { name: '系统设置' }))
    expect(window.confirm).toHaveBeenCalledOnce()
    expect(screen.getByTestId('shell-location')).toHaveTextContent('/admin-home')
  })

  it('refreshes the current page instead of refreshing only the authentication token', async () => {
    const refreshSession = vi.spyOn(session, 'refreshSession')
    renderAdmin()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新页面' })) })
    expect(reloadPage).toHaveBeenCalledOnce()
    expect(refreshSession).not.toHaveBeenCalled()
  })

  it('does not reload when the unsaved-changes confirmation is declined', async () => {
    renderAdmin()
    useNavigationGuardStore.getState().setDirty(true)
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新页面' })) })
    expect(window.confirm).toHaveBeenCalledOnce()
    expect(reloadPage).not.toHaveBeenCalled()
  })

  // 点退出就是退出。不等服务器应答、不带任何提示状态，直接回登录页。
  it('signs out at once: back on the login page without waiting for the server or any notice', async () => {
    const logout = vi.spyOn(session, 'logoutSession').mockReturnValue(new Promise<void>(() => undefined))
    renderAdmin()
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    fireEvent.click(await screen.findByRole('menuitem', { name: '退出登录' }))
    await waitFor(() => expect(screen.getByTestId('shell-location')).toHaveTextContent('/login'))
    expect(logout).toHaveBeenCalledOnce()
    expect(screen.queryByText(/未确认|重新注销/)).not.toBeInTheDocument()
  })

  it('retains the existing logout behavior', async () => {
    const logout = vi.spyOn(session, 'logoutSession').mockResolvedValue(undefined)
    renderAdmin()
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    fireEvent.click(await screen.findByRole('menuitem', { name: '退出登录' }))
    await waitFor(() => expect(logout).toHaveBeenCalledOnce())
    await waitFor(() => expect(screen.getByTestId('shell-location')).toHaveTextContent('/login'))
  })
})
