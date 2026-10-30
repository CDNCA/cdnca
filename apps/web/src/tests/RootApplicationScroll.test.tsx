import { act, render, screen } from '@testing-library/react'
import { Link } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { RootApplication } from '../main'

vi.mock('react-dom/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-dom/client')>()
  return {
    ...original,
    createRoot: (container: Element | DocumentFragment) => container
      ? original.createRoot(container)
      : { render: vi.fn() },
  }
})

vi.mock('../App', () => ({
  AppRoutes: () => <nav><Link to="/sites">网站列表</Link><Link to="/nodes">节点列表</Link><Link to="/sites?page=2">第 2 页</Link><Link to="/tickets">工单</Link></nav>,
}))

// C05：页面滚动在 window 上（外壳都是 min-height），jsdom 不会真的滚动，这里记录 scrollY。
function stubWindowScroll() {
  let y = 0
  Object.defineProperty(window, 'scrollY', { configurable: true, get: () => y })
  const scrollTo = vi.spyOn(window, 'scrollTo').mockImplementation(((x: number | ScrollToOptions, top?: number) => {
    y = typeof x === 'number' ? (top ?? 0) : (x.top ?? 0)
  }) as typeof window.scrollTo)
  return { set: (value: number) => { y = value }, get: () => y, scrollTo }
}

// data router 每次导航都 new Request(url, { signal })；Node 的 Request 不认 jsdom 的 AbortSignal，测试里去掉 signal。
class JsdomRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    const { signal: _signal, ...rest } = init ?? {}
    super(input, rest)
  }
}

beforeEach(() => vi.stubGlobal('Request', JsdomRequest))
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('RootApplication scroll restoration (C05)', () => {
  it('scrolls a newly opened page to the top and restores the old position on browser back', async () => {
    window.history.replaceState(null, '', '/dashboard/sites')
    useSessionStore.getState().clearSession()
    const scroll = stubWindowScroll()
    render(<RootApplication />)
    expect(window.history.scrollRestoration).toBe('manual')

    scroll.set(640)
    await act(async () => { screen.getByRole('link', { name: '节点列表' }).click() })
    expect(window.location.pathname).toBe('/dashboard/nodes')
    expect(scroll.get()).toBe(0)

    scroll.set(120)
    await act(async () => {
      window.history.back()
      await new Promise((resolve) => window.addEventListener('popstate', resolve, { once: true }))
    })
    expect(window.location.pathname).toBe('/dashboard/sites')
    await vi.waitFor(() => expect(scroll.get()).toBe(640))
  })

  it('keeps the scroll position when only the query string of the same path changes', async () => {
    window.history.replaceState(null, '', '/dashboard/sites')
    useSessionStore.getState().clearSession()
    const scroll = stubWindowScroll()
    render(<RootApplication />)

    scroll.set(480)
    await act(async () => { screen.getByRole('link', { name: '第 2 页' }).click() })
    expect(window.location.pathname + window.location.search).toBe('/dashboard/sites?page=2')
    expect(scroll.get()).toBe(480)

    // 换到没来过的路径仍回顶部（已存位置在 ScrollRestoration 模块级记录里，跨用例保留，故另选路径）。
    await act(async () => { screen.getByRole('link', { name: '工单' }).click() })
    expect(window.location.pathname).toBe('/dashboard/tickets')
    expect(scroll.get()).toBe(0)
  })
})
