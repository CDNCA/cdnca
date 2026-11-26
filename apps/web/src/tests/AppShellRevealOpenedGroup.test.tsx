import { act, fireEvent, screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 侧栏滚到底后点开最下面的分组，展开动画结束时只滚菜单容器，按最小位移露出组标题和尽量多的直接子项。
function installViewport(mobile: boolean, reducedMotion = false) {
  vi.stubGlobal('innerWidth', mobile ? 390 : 1280)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: (mobile && query === '(max-width: 767px)') || (reducedMotion && query === '(prefers-reduced-motion: reduce)'),
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }))
}

function rect(top: number, bottom: number) {
  return { top, bottom, left: 0, right: 200, width: 200, height: bottom - top, x: 0, y: top, toJSON: () => ({}) } as DOMRect
}

async function renderShell(mobile: boolean, reducedMotion = false) {
  installViewport(mobile, reducedMotion)
  await i18n.changeLanguage('zh-CN')
  const actor = principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const rendered = renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<section aria-label="reveal-probe" />} />
      </Route>
    </Routes>,
    ['/home'],
  )
  if (mobile) fireEvent.click(screen.getByRole('button', { name: '打开导航' }))
  const menu = rendered.container.querySelector<HTMLElement>('.shell-menu')!
  let scrollTop = 0
  Object.defineProperty(menu, 'scrollTop', { configurable: true, get: () => scrollTop, set: (value: number) => { scrollTop = value } })
  return { menu, scrolled: () => scrollTop }
}

// Lays the menu viewport out as [0, height) with the group title at titleTop and each direct child 40px tall below it.
function layout(menu: HTMLElement, height: number, titleTop: number) {
  Object.defineProperty(menu, 'clientHeight', { configurable: true, value: height })
  vi.spyOn(menu, 'getBoundingClientRect').mockReturnValue(rect(0, height))
  const title = screen.getByRole('menuitem', { name: '网站管理' })
  vi.spyOn(title, 'getBoundingClientRect').mockReturnValue(rect(titleTop, titleTop + 40))
  const list = document.getElementById(title.getAttribute('aria-controls') ?? '')!
  const items = [...list.children] as HTMLElement[]
  items.forEach((item, index) => {
    vi.spyOn(item, 'getBoundingClientRect').mockReturnValue(rect(titleTop + 40 + index * 40, titleTop + 80 + index * 40))
  })
  return { list, items }
}

function heightTransitionEnd(target: HTMLElement, propertyName = 'height') {
  const event = new Event('transitionend', { bubbles: true })
  Object.defineProperty(event, 'propertyName', { value: propertyName })
  act(() => { target.dispatchEvent(event) })
}

afterEach(() => {
  window.localStorage.clear()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe.each([['桌面宽侧栏', false], ['手机抽屉', true]] as const)('%s 点开底部分组', (_name, mobile) => {
  it('两项的组：动画结束后用最小位移露出标题和两个子项，第一次点击后无需再滚', async () => {
    const { menu, scrolled } = await renderShell(mobile)
    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    const { list, items } = layout(menu, 200, 160)
    expect(items).toHaveLength(2)

    heightTransitionEnd(list, 'opacity')
    expect(scrolled()).toBe(0)
    heightTransitionEnd(list)
    // 视口 200：标题 160–200，两个子项到 280；滚 80 后标题顶在 80、末项底在 200。
    expect(scrolled()).toBe(80)
  })

  it('放不下整组时优先露出标题和第一项', async () => {
    const { menu, scrolled } = await renderShell(mobile)
    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    const { list } = layout(menu, 100, 60)
    heightTransitionEnd(list)
    // 视口 100：标题 60–100、第一项到 140 放得下，第二项到 180 放不下。
    expect(scrolled()).toBe(40)
  })

  it('短组空间够时直接子项全部露出', async () => {
    const { menu, scrolled } = await renderShell(mobile)
    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    const { list, items } = layout(menu, 2000, 600)
    heightTransitionEnd(list)
    const lastBottom = 600 + 40 + items.length * 40
    expect(scrolled()).toBe(Math.max(0, lastBottom - 2000))
  })

  it('视口内已放得下时不移动', async () => {
    const { menu, scrolled } = await renderShell(mobile)
    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    const { list } = layout(menu, 2000, 20)
    heightTransitionEnd(list)
    expect(scrolled()).toBe(0)
  })

  it('没有过渡事件时由兜底计时器收尾；收拢分组不滚动', async () => {
    const { menu, scrolled } = await renderShell(mobile)
    vi.useFakeTimers()
    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    layout(menu, 200, 160)
    act(() => { vi.advanceTimersByTime(600) })
    expect(scrolled()).toBe(80)

    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    act(() => { vi.advanceTimersByTime(600) })
    expect(scrolled()).toBe(80)
  })

  it('减少动态效果：不等过渡事件和兜底计时器，下一帧就滚动', async () => {
    const { menu, scrolled } = await renderShell(mobile, true)
    const frames: FrameRequestCallback[] = []
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((callback) => frames.push(callback))
    const timeout = vi.spyOn(window, 'setTimeout')
    fireEvent.click(screen.getByRole('menuitem', { name: '网站管理' }))
    layout(menu, 200, 160)
    expect(scrolled()).toBe(0)
    expect(timeout.mock.calls.some(([, delay]) => delay === 520)).toBe(false)

    act(() => { frames.splice(0).forEach((callback) => callback(performance.now())) })
    expect(scrolled()).toBe(80)
  })
})
