import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { resetNavigationGuard, useNavigationGuardStore } from '../routes/navigationGuard'
import { authResponse, principal } from '../test/fixtures'

// 页面菜单项是带 href（含 /dashboard basename）的真实链接；修饰键点击交给浏览器开新标签。
function LocationProbe() {
  return <output data-testid="menu-link-location">{useLocation().pathname}</output>
}

function renderShell(admin: boolean, path: string) {
  const actor = admin
    ? principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    : principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'billing.account.read', 'api_keys.self.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return render(
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter basename="/dashboard" initialEntries={[`/dashboard${path}`]}>
          <Routes>
            <Route element={<AppShell />}>
              <Route path="*" element={<LocationProbe />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}

const location = () => screen.getByTestId('menu-link-location').textContent

afterEach(() => {
  resetNavigationGuard()
  window.localStorage.clear()
  vi.restoreAllMocks()
})

describe.each([
  ['管理员', true, '/node/list', '节点实时监控', '/node/realtime'],
  ['租户', false, '/account/user', 'API密钥', '/account/api'],
])('%s侧栏页面菜单项链接', (_side, admin, start, name, target) => {
  async function setup() {
    await i18n.changeLanguage('zh-CN')
    renderShell(admin, start)
    const item = screen.getByRole('menuitem', { name })
    const link = within(item).getByRole('link')
    return { item, link, user: userEvent.setup() }
  }

  it('菜单项有正确 href，分组没有链接', async () => {
    const { link } = await setup()

    expect(link).toHaveAttribute('href', `/dashboard${target}`)
    expect(link).toHaveAttribute('tabindex', '-1')
    const group = screen.getByRole('menuitem', { name: admin ? '节点管理' : '账户中心' })
    expect(group.querySelector(':scope > a')).toBeNull()
  })

  it('普通点击在当前页导航', async () => {
    const { link, user } = await setup()

    await user.click(link)
    expect(location()).toBe(target)
  })

  it.each(['ctrlKey', 'metaKey', 'shiftKey'] as const)('%s 点击不导航、不阻止默认、不做离开检查', async (modifier) => {
    const { link } = await setup()
    useNavigationGuardStore.setState({ dirty: true })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)

    // 默认动作未被阻止（返回 true）；jsdom 随后跟随 href 会打印「Not implemented: navigation」，属预期噪声。
    expect(fireEvent.click(link, { [modifier]: true, button: 0, detail: 1 })).toBe(true)
    expect(location()).toBe(start)
    expect(confirm).not.toHaveBeenCalled()
  })

  it('未保存设置时普通点击仍提示，取消则留在原页', async () => {
    const { link, user } = await setup()
    useNavigationGuardStore.setState({ dirty: true })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)

    await user.click(link)
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(location()).toBe(start)

    confirm.mockReturnValue(true)
    await user.click(link)
    expect(confirm).toHaveBeenCalledTimes(2)
    expect(location()).toBe(target)
  })

  it('键盘回车（链接或菜单项获得焦点）只导航一次并做离开检查', async () => {
    const { item, link, user } = await setup()
    useNavigationGuardStore.setState({ dirty: true })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)

    link.focus()
    await user.keyboard('{Enter}')
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(location()).toBe(target)

    const back = screen.getByRole('menuitem', { name: admin ? '节点列表' : '个人资料' })
    back.focus()
    // rc-menu 按 KeyboardEvent.which 识别回车，user-event 不填 which，这里直接派发。
    fireEvent.keyDown(back, { key: 'Enter', which: 13, keyCode: 13 })
    expect(confirm).toHaveBeenCalledTimes(2)
    expect(location()).toBe(start)
    expect(item).toBeInTheDocument()
  })
})
