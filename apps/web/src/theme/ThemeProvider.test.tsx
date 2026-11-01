import { StrictMode } from 'react'
import { act, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { themeApi, type ThemeCurrent, type ThemeDocument } from '../api/theme'
import { ThemeProvider } from './ThemeProvider'
import { defaultAntdTokens, defaultThemeLayout, themeChangedEvent, useThemeRuntime } from './runtime'

// PLUG-THEME-RELOAD-01：同一 scope 的旧读取不能在新读取完成后覆盖主题（CSS href、data 属性、document、品牌槽）。

function current(id: string, char: string, brand: ThemeCurrent['brand_assets'] = {}): ThemeCurrent {
  return { schema: 'cdnca.theme.current/v1', revision: id === 'default' ? 2 : 1, theme_id: id, version: '1.0.0',
    package_sha256: char.repeat(64), tokens_url: `/v1/theme/theme.${char.repeat(64)}.json`,
    stylesheet_url: `/v1/theme/theme.${char.repeat(64)}.css`, scope: 'platform', brand_assets: brand }
}

function document(item: ThemeCurrent): ThemeDocument {
  return { schema: 'cdnca.theme.rendered/v1', id: item.theme_id, version: item.version, package_sha256: item.package_sha256,
    name: { 'zh-CN': item.theme_id }, antd_tokens: defaultAntdTokens, css_variables: {}, layout: defaultThemeLayout, brand: {} }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

function Readout() {
  const runtime = useThemeRuntime()
  return <output aria-label="theme">{`${runtime.document?.id ?? 'loading'}|${JSON.stringify(runtime.brandAssets)}`}</output>
}

const oldTheme = current('review.theme', 'a', { logo: 1 })
const newTheme = current('default', 'b', { logo: 2 })

function assertShowingNew() {
  expect(screen.getByLabelText('theme')).toHaveTextContent('default|{"logo":2}')
  expect(window.document.documentElement.dataset.cdncaThemeId).toBe('default')
  expect(window.document.documentElement.dataset.cdncaTheme).toBe('b'.repeat(64))
  expect(window.document.getElementById('cdnca-theme-stylesheet')?.getAttribute('href')).toBe(newTheme.stylesheet_url)
}

beforeEach(() => vi.restoreAllMocks())
afterEach(() => {
  window.document.getElementById('cdnca-theme-stylesheet')?.remove()
  delete window.document.documentElement.dataset.cdncaTheme
})

describe('ThemeProvider 请求代际', () => {
  it('串行变更：读到并应用新主题（正控）', async () => {
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(oldTheme).mockResolvedValueOnce(newTheme)
    vi.spyOn(themeApi, 'document').mockImplementation(async (item) => document(item))
    render(<ThemeProvider><Readout /></ThemeProvider>)
    await screen.findByText(/^review\.theme/)
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await screen.findByText(/^default/)
    assertShowingNew()
  })

  it('T-late：document 慢的旧读取迟到成功，不覆盖已应用的新主题', async () => {
    const late = deferred<ThemeDocument>()
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(oldTheme).mockResolvedValueOnce(newTheme)
    const load = vi.spyOn(themeApi, 'document').mockReturnValueOnce(late.promise).mockResolvedValueOnce(document(newTheme))
    render(<ThemeProvider><Readout /></ThemeProvider>)
    await waitFor(() => expect(load).toHaveBeenCalledTimes(1))
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await screen.findByText(/^default/)
    await act(async () => { late.resolve(document(oldTheme)) })
    assertShowingNew()
  })

  it('current 慢的旧读取迟到：不再读它的 document，也不覆盖新主题', async () => {
    const lateCurrent = deferred<ThemeCurrent>()
    vi.spyOn(themeApi, 'current').mockReturnValueOnce(lateCurrent.promise).mockResolvedValueOnce(newTheme)
    const load = vi.spyOn(themeApi, 'document').mockImplementation(async (item) => document(item))
    render(<ThemeProvider><Readout /></ThemeProvider>)
    await waitFor(() => expect(themeApi.current).toHaveBeenCalledTimes(1))
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await screen.findByText(/^default/)
    await act(async () => { lateCurrent.resolve(oldTheme) })
    assertShowingNew()
    expect(load).toHaveBeenCalledTimes(1)
  })

  it('旧读取迟到失败不影响新主题', async () => {
    const late = deferred<ThemeDocument>()
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(oldTheme).mockResolvedValueOnce(newTheme)
    vi.spyOn(themeApi, 'document').mockReturnValueOnce(late.promise).mockResolvedValueOnce(document(newTheme))
    render(<ThemeProvider><Readout /></ThemeProvider>)
    await waitFor(() => expect(themeApi.document).toHaveBeenCalledTimes(1))
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await screen.findByText(/^default/)
    await act(async () => { late.reject(new Error('late failure')) })
    assertShowingNew()
  })

  it('连续两次变更：只有最后一次生效', async () => {
    const first = deferred<ThemeDocument>()
    const second = deferred<ThemeDocument>()
    const middle = current('review.middle', 'c', { logo: 3 })
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(oldTheme).mockResolvedValueOnce(middle).mockResolvedValueOnce(newTheme)
    vi.spyOn(themeApi, 'document').mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
      .mockResolvedValueOnce(document(newTheme))
    render(<ThemeProvider><Readout /></ThemeProvider>)
    await waitFor(() => expect(themeApi.document).toHaveBeenCalledTimes(1))
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await waitFor(() => expect(themeApi.document).toHaveBeenCalledTimes(2))
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await screen.findByText(/^default/)
    await act(async () => { second.resolve(document(middle)); first.resolve(document(oldTheme)) })
    assertShowingNew()
  })

  it('最新读取失败时保留最近一次有效主题（反控）', async () => {
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(newTheme).mockRejectedValueOnce(new Error('latest failure'))
    vi.spyOn(themeApi, 'document').mockImplementation(async (item) => document(item))
    render(<ThemeProvider><Readout /></ThemeProvider>)
    await screen.findByText(/^default/)
    act(() => { window.dispatchEvent(new Event(themeChangedEvent)) })
    await waitFor(() => expect(themeApi.current).toHaveBeenCalledTimes(2))
    await act(async () => { await Promise.resolve() })
    assertShowingNew()
  })

  it('卸载后在途读取不再写 stylesheet', async () => {
    const late = deferred<ThemeDocument>()
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(oldTheme)
    vi.spyOn(themeApi, 'document').mockReturnValueOnce(late.promise)
    const view = render(<ThemeProvider><Readout /></ThemeProvider>)
    await waitFor(() => expect(themeApi.document).toHaveBeenCalledTimes(1))
    view.unmount()
    await act(async () => { late.resolve(document(oldTheme)) })
    expect(window.document.getElementById('cdnca-theme-stylesheet')).toBeNull()
  })

  it('StrictMode 下首个 effect 的读取不会覆盖第二个 effect 的结果', async () => {
    const late = deferred<ThemeDocument>()
    vi.spyOn(themeApi, 'current').mockResolvedValueOnce(oldTheme).mockResolvedValueOnce(newTheme)
    vi.spyOn(themeApi, 'document').mockImplementation((item) =>
      item.theme_id === oldTheme.theme_id ? late.promise : Promise.resolve(document(item)))
    render(<StrictMode><ThemeProvider><Readout /></ThemeProvider></StrictMode>)
    await screen.findByText(/^default/)
    await act(async () => { late.resolve(document(oldTheme)) })
    assertShowingNew()
  })
})
