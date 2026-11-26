import { act, fireEvent, screen, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 分组展开箭头是图标字体字符 U+F116（.ant-menu-submenu-arrow::before），
// 无障碍树曾把它并进分组名，读成「网站管理 U+F116」。箭头须对辅助技术隐藏。
const styles = Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string

const privateUse = /[\uE000-\uF8FF]/

function installMatchMedia(width: number) {
  vi.stubGlobal('innerWidth', width)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: query === '(max-width: 767px)' && width <= 767,
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
    : principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<section aria-label="menu-name-probe" />} />
      </Route>
    </Routes>,
    ['/home'],
  )
}

let sheet: HTMLStyleElement | undefined

afterEach(() => {
  sheet?.remove()
  sheet = undefined
  window.localStorage.clear()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function expectGroupTitle(title: HTMLElement, name: string) {
  const arrow = title.querySelector('.ant-menu-submenu-arrow')
  expect(arrow).not.toBeNull()
  expect(arrow).toHaveAttribute('aria-hidden', 'true')
  expect(title).toHaveAccessibleName(name)
  expect(title.getAttribute('aria-label') ?? '').not.toMatch(privateUse)
  expect(['true', 'false']).toContain(title.getAttribute('aria-expanded'))
}

function expectNoPrivateUseNames() {
  for (const item of screen.getAllByRole('menuitem')) expect(item).not.toHaveAccessibleName(privateUse)
}

async function setup(admin: boolean, width: number) {
  installMatchMedia(width)
  await i18n.changeLanguage('zh-CN')
  sheet = document.createElement('style')
  sheet.textContent = styles
  document.head.append(sheet)
  renderShell(admin)
}

// 三种形态各断言一次：1440 宽侧栏、1440 折叠图标模式（含弹出子菜单）、390 抽屉。
describe.each([
  ['管理员', true, ['网站管理', '节点管理'], '统计分析', undefined],
  ['租户', false, ['网站管理'], '统计分析', undefined],
])('%s侧栏分组可访问名称', (_side, admin, groups, popupGroup, nestedGroup) => {
  it('1440 宽侧栏：名称不含箭头字符，展开/收起状态可读', async () => {
    await setup(admin, 1440)

    for (const group of groups) {
      const title = screen.getByRole('menuitem', { name: group })
      expectGroupTitle(title, group)
      const expanded = title.getAttribute('aria-expanded')
      fireEvent.click(title)
      expect(title).toHaveAttribute('aria-expanded', expanded === 'true' ? 'false' : 'true')
      expect(screen.getByRole('menuitem', { name: group })).toBe(title)
    }
    expectNoPrivateUseNames()
  })

  it('1440 折叠图标模式：分组与弹出子菜单标题名称不含箭头字符', async () => {
    await setup(admin, 1440)
    fireEvent.click(screen.getByRole('button', { name: '折叠导航' }))

    for (const group of groups) expectGroupTitle(screen.getByRole('menuitem', { name: group }), group)
    vi.useFakeTimers()
    try {
      const title = screen.getByRole('menuitem', { name: popupGroup })
      fireEvent.mouseEnter(title)
      act(() => { vi.advanceTimersByTime(500) })
      expect(title).toHaveAttribute('aria-expanded', 'true')
      const popup = document.querySelector('.ant-menu-submenu-popup') as HTMLElement
      expect(popup).not.toBeNull()
      for (const arrow of popup.querySelectorAll('.ant-menu-submenu-arrow')) expect(arrow).toHaveAttribute('aria-hidden', 'true')
      if (nestedGroup) expectGroupTitle(within(popup).getByRole('menuitem', { name: nestedGroup }), nestedGroup)
      for (const item of within(popup).getAllByRole('menuitem')) expect(item).not.toHaveAccessibleName(privateUse)
    } finally {
      vi.useRealTimers()
    }
    expectNoPrivateUseNames()
  })

  it('390 抽屉：打开后分组名称不含箭头字符，展开状态可读', async () => {
    await setup(admin, 390)
    fireEvent.click(screen.getByRole('button', { name: i18n.t('common:openNavigation') }))

    for (const group of groups) {
      const title = screen.getByRole('menuitem', { name: group })
      expectGroupTitle(title, group)
      const expanded = title.getAttribute('aria-expanded')
      fireEvent.click(title)
      expect(title).toHaveAttribute('aria-expanded', expanded === 'true' ? 'false' : 'true')
    }
    expectNoPrivateUseNames()
  })
})
