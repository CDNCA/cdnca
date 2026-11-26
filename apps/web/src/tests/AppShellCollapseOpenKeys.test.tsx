import { act, fireEvent, screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'

const menuOpenKey = (role: string) => { const p = useSessionStore.getState().principal!; return `cdnca.ui.menu-open.${role}.${p.scope_id}.${p.user_id}.v3` }
import { renderWithProviders } from '../test/render'

// 宽侧栏展开的分组在「折叠导航→展开导航」后被清空；折叠时图标弹出菜单的开合也写进了宽侧栏偏好。
function installDesktop() {
  vi.stubGlobal('innerWidth', 1920)
  vi.stubGlobal('innerHeight', 798)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }))
}

function renderShell(admin: boolean) {
  const actor = admin
    ? principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    : principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'sites.read', 'billing.account.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<section aria-label="collapse-probe" />} />
      </Route>
    </Routes>,
    [admin ? '/node/list' : '/home'],
  )
}

const group = (name: string) => screen.getByRole('menuitem', { name })

afterEach(() => {
  window.localStorage.clear()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe.each([
  ['管理员', true, ['网站管理', '统计分析'], ['site', 'monitor'], 'admin', '节点管理'],
  ['租户', false, ['网站管理', '统计分析'], ['site', 'monitor'], 'user', undefined],
])('%s宽侧栏分组在折叠前后保持', (_side, admin, names, keys, role, routeGroup) => {
  async function expandTwo() {
    installDesktop()
    await i18n.changeLanguage('zh-CN')
    const rendered = renderShell(admin)
    for (const name of names) {
      if (group(name).getAttribute('aria-expanded') !== 'true') fireEvent.click(group(name))
      expect(group(name)).toHaveAttribute('aria-expanded', 'true')
    }
    return rendered
  }
  const storedKeys = () => JSON.parse(window.localStorage.getItem(menuOpenKey(role)) ?? '[]') as string[]
  const toggle = () => screen.getByRole('button', { name: /^(折叠导航|展开导航)$/ })
  const expectWideOpen = () => {
    for (const name of names) expect(group(name)).toHaveAttribute('aria-expanded', 'true')
    if (routeGroup) expect(group(routeGroup)).toHaveAttribute('aria-expanded', 'true')
  }

  it('展开两组→折叠→展开，两组仍开且偏好未清空', async () => {
    await expandTwo()

    fireEvent.click(toggle())
    expect(toggle()).toHaveAccessibleName('展开导航')
    expect(storedKeys()).toEqual(keys)
    fireEvent.click(toggle())
    expect(toggle()).toHaveAccessibleName('折叠导航')
    expectWideOpen()
    expect(storedKeys()).toEqual(keys)
  })

  it('折叠时打开并关闭图标弹出菜单后展开，原分组仍开', async () => {
    await expandTwo()
    fireEvent.click(toggle())

    vi.useFakeTimers()
    fireEvent.mouseEnter(group(names[0]))
    act(() => { vi.advanceTimersByTime(500) })
    expect(group(names[0])).toHaveAttribute('aria-expanded', 'true')
    fireEvent.mouseLeave(group(names[0]))
    act(() => { vi.advanceTimersByTime(500) })
    expect(group(names[0])).toHaveAttribute('aria-expanded', 'false')
    vi.useRealTimers()
    expect(storedKeys()).toEqual(keys)

    fireEvent.click(toggle())
    expectWideOpen()
  })

  it('重新挂载后回读一致', async () => {
    const first = await expandTwo()
    fireEvent.click(toggle())
    fireEvent.click(toggle())
    first.unmount()

    renderShell(admin)
    expectWideOpen()
  })
})
