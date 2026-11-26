import { act, fireEvent, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 390×844 移动抽屉打开后焦点进抽屉、Tab 不出抽屉、Escape 关闭并还焦点；变宽到桌面后不再限制。
type Listener = (event: MediaQueryListEvent) => void

function installMatchMedia(width: number, height: number) {
  const listeners = new Set<Listener>()
  let matches = width <= 767
  vi.stubGlobal('innerWidth', width)
  vi.stubGlobal('innerHeight', height)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    get matches() { return query === '(max-width: 767px)' && matches },
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: (_type: string, listener: Listener) => { listeners.add(listener) },
    removeEventListener: (_type: string, listener: Listener) => { listeners.delete(listener) },
    dispatchEvent: () => false,
  }) as unknown as MediaQueryList)
  return (nextWidth: number) => {
    matches = nextWidth <= 767
    vi.stubGlobal('innerWidth', nextWidth)
    act(() => {
      for (const listener of listeners) listener({ matches, media: '(max-width: 767px)' } as MediaQueryListEvent)
    })
  }
}

function renderShell(admin: boolean) {
  const actor = admin
    ? principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    : principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const path = admin ? '/node/list' : '/site/list'
  return renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<section aria-label="drawer-focus-probe"><button type="button">正文按钮</button></section>} />
      </Route>
    </Routes>,
    [path],
  )
}

afterEach(() => {
  window.localStorage.clear()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const styles = Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string

// jsdom 不排版：从移动媒体查询里取抽屉宽度规则，按视口宽度换算。
function mobileSidebarWidth(viewport: number): number {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
    .filter((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 767px)')
    .flatMap((rule) => [...rule.cssRules])
    .filter((rule): rule is CSSStyleRule => 'selectorText' in rule && rule.selectorText === '.app-sidebar')
  style.remove()
  const width = rules.map((rule) => rule.style.getPropertyValue('width')).find(Boolean)
  const match = /^min\((\d+)vw, (\d+)px\)$/.exec(width ?? '')
  if (!match) throw new Error(`unexpected mobile sidebar width: ${width}`)
  return Math.min((Number(match[1]) / 100) * viewport, Number(match[2]))
}

const viewports: Array<[number, number]> = [[390, 844], [320, 720], [767, 720]]

describe.each([
  ['管理员', true],
  ['租户', false],
])('%s移动抽屉焦点', (_side, admin) => {
  async function openWithEnter(width = 390, height = 844) {
    await i18n.changeLanguage('zh-CN')
    const resize = installMatchMedia(width, height)
    const user = userEvent.setup()
    const { container } = renderShell(admin)
    const sidebar = container.querySelector('aside.app-sidebar') as HTMLElement
    const toggle = screen.getByRole('button', { name: i18n.t('common:openNavigation') })
    toggle.focus()
    await user.keyboard('{Enter}')
    const scrim = screen.getByRole('button', { name: i18n.t('common:closeNavigation') })
    const inDrawer = () => sidebar.contains(document.activeElement) || document.activeElement === scrim
    return { container, sidebar, toggle, scrim, user, resize, inDrawer }
  }

  it('320 px 视口抽屉宽 256 px，不超出视口', () => {
    expect(mobileSidebarWidth(320)).toBe(256)
    expect(mobileSidebarWidth(320)).toBeLessThan(320)
  })

  it.each(viewports)('%i×%i：Enter 打开后焦点在抽屉内（当前菜单项），背景 inert', async (width, height) => {
    const { sidebar, toggle, container, inDrawer } = await openWithEnter(width, height)

    expect(sidebar).toHaveClass('is-mobile-open')
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(inDrawer()).toBe(true)
    expect(document.activeElement).toHaveClass('ant-menu-item-selected')
    expect(container.querySelector('header.app-header')).toHaveAttribute('inert')
    expect(container.querySelector('main.app-main')).toHaveAttribute('inert')
  })

  it.each(viewports)('%i×%i：Tab 与 Shift+Tab 轮转不出抽屉（含关闭按钮）', async (width, height) => {
    const { scrim, user, inDrawer } = await openWithEnter(width, height)
    const visited = new Set<Element | null>()

    for (let step = 0; step < 8; step += 1) {
      await user.tab()
      expect(inDrawer()).toBe(true)
      visited.add(document.activeElement)
    }
    expect(visited.has(scrim)).toBe(true)
    for (let step = 0; step < 8; step += 1) {
      await user.tab({ shift: true })
      expect(inDrawer()).toBe(true)
    }
    scrim.focus()
    await user.tab()
    expect(inDrawer()).toBe(true)
    expect(document.activeElement).not.toBe(scrim)
  })

  it.each(viewports)('%i×%i：Escape 关闭并把焦点还给开关', async (width, height) => {
    const { sidebar, toggle, user, container } = await openWithEnter(width, height)

    await user.keyboard('{Escape}')
    expect(sidebar).not.toHaveClass('is-mobile-open')
    expect(sidebar).toHaveAttribute('inert')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
    expect(container.querySelector('header.app-header')).not.toHaveAttribute('inert')
    expect(container.querySelector('main.app-main')).not.toHaveAttribute('inert')
  })

  it.each(viewports)('%i×%i：点遮罩关闭并还焦点', async (width, height) => {
    const { sidebar, toggle, scrim, user } = await openWithEnter(width, height)

    await user.click(scrim)
    expect(sidebar).not.toHaveClass('is-mobile-open')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
  })

  it.each([[390, 1440], [767, 768]])('%i→%i 跨到桌面后释放焦点限制、无 inert 残留', async (from, to) => {
    const { sidebar, container, resize } = await openWithEnter(from, 720)

    resize(to)
    expect(sidebar).not.toHaveClass('is-mobile-open')
    expect(container.querySelector('[inert]')).toBeNull()
    expect(container.querySelector('.mobile-scrim')).toBeNull()
    expect(screen.getByRole('button', { name: i18n.t('common:collapseNavigation') })).toHaveAttribute('aria-expanded', 'true')

    const brand = sidebar.querySelector('button.shell-brand') as HTMLElement
    brand.focus()
    expect(fireEvent.keyDown(brand, { key: 'Tab', shiftKey: true })).toBe(true)
    expect(brand).toHaveFocus()
    expect(fireEvent.keyDown(brand, { key: 'Escape' })).toBe(true)
    const body = screen.getByRole('button', { name: '正文按钮' })
    body.focus()
    expect(fireEvent.keyDown(body, { key: 'Tab' })).toBe(true)
    expect(body).toHaveFocus()
    expect(container.querySelector('ul.shell-menu')).toHaveAttribute('role', 'menu')
  })
})
