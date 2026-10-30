import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { siteSchedule302Api, splitList, type Schedule302State } from '../../api/siteSchedule302'
import i18n from '../../i18n'
import { SiteSchedule302Card } from './SiteSchedule302Card'

vi.mock('../../api/siteSchedule302', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/siteSchedule302')>()
  return { ...actual, siteSchedule302Api: { get: vi.fn(), replace: vi.fn() } }
})

const siteId = '11111111-1111-4111-8111-111111111111'

function state(overrides: Partial<Schedule302State> = {}): Schedule302State {
  return {
    site_id: siteId, version: 3, plain_http: true, updated_at: null,
    settings: { enabled: false, target: 'address', keep_path: true, keep_query: true, signature_ttl_seconds: 60,
      https_to_http: false, extensions: [], path_prefixes: [], min_size_bytes: 0 },
    ...overrides,
  }
}

function renderCard(canManage = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><SiteSchedule302Card siteId={siteId} accessToken="token" canManage={canManage} /></QueryClientProvider>)
}

describe('SiteSchedule302Card', () => {
  beforeEach(async () => {
    vi.mocked(siteSchedule302Api.get).mockReset()
    vi.mocked(siteSchedule302Api.replace).mockReset()
    await i18n.changeLanguage('zh-CN')
  })

  it('warns that ordinary pages should not be scheduled and saves the large-file settings', async () => {
    vi.mocked(siteSchedule302Api.get).mockResolvedValue(state())
    vi.mocked(siteSchedule302Api.replace).mockImplementation(async (_token, _site, version, settings) =>
      state({ version: version + 1, settings, updated_at: '2026-10-18T00:00:00Z' }))
    renderCard()
    expect(await screen.findByText(/普通网页（HTML、接口、小图片）不建议开启/u)).toBeTruthy()
    const user = userEvent.setup()
    // fix-siteinstant：没有保存按钮；开关即保存，文本失焦保存（按 version 串行）。
    expect(screen.queryByRole('button', { name: /保\s*存/u })).toBeNull()
    await user.click(screen.getByRole('switch', { name: '开启 302 调度' }))
    await waitFor(() => expect(siteSchedule302Api.replace).toHaveBeenCalledTimes(1))
    const [, site, version, first, key] = vi.mocked(siteSchedule302Api.replace).mock.calls[0]!
    expect([site, version, first.enabled]).toEqual([siteId, 3, true])
    expect(key).toMatch(/^site-schedule302-/u)
    await user.type(screen.getByRole('textbox', { name: '文件扩展名' }), 'mp4, .zip')
    await user.type(screen.getByRole('textbox', { name: '路径前缀' }), '/download/')
    const size = screen.getByRole('spinbutton', { name: '最小文件大小（MB）' })
    await user.clear(size)
    await user.type(size, '10')
    fireEvent.blur(size)
    await waitFor(() => expect(vi.mocked(siteSchedule302Api.replace).mock.calls.at(-1)![3]).toEqual({ enabled: true, target: 'address',
      keep_path: true, keep_query: true, signature_ttl_seconds: 60, https_to_http: false, extensions: ['mp4', '.zip'],
      path_prefixes: ['/download/'], min_size_bytes: 10 * 1024 * 1024 }))
    // 每次提交都用上一次保存返回的 version。
    const versions = vi.mocked(siteSchedule302Api.replace).mock.calls.map((call) => call[2])
    expect(versions).toEqual(versions.map((_, index) => 3 + index))
  })

  it('refuses a site without an HTTP port and invalid lifetimes', async () => {
    vi.mocked(siteSchedule302Api.get).mockResolvedValue(state({ plain_http: false }))
    renderCard()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('switch', { name: '开启 302 调度' }))
    expect(screen.getByText(/本站没有 HTTP 端口/u)).toBeTruthy()
    const ttl = screen.getByRole('spinbutton', { name: '签名有效期（秒）' })
    await user.clear(ttl)
    fireEvent.blur(ttl)
    expect(siteSchedule302Api.replace).not.toHaveBeenCalled()
  })

  it('shows server refusals in plain words and is read-only without permission', async () => {
    vi.mocked(siteSchedule302Api.get).mockResolvedValue(state({ settings: { ...state().settings, enabled: true } }))
    vi.mocked(siteSchedule302Api.replace).mockRejectedValue(new ApiError('conflict', 409, 'version_conflict'))
    const { unmount } = renderCard()
    const user = userEvent.setup()
    const toggle = await screen.findByRole('switch', { name: '开启 302 调度' })
    await user.click(toggle)
    expect(await screen.findByText('站点已被修改，请刷新后重试')).toBeTruthy()
    // 失败回滚到服务端值（仍开启）。
    expect(toggle.getAttribute('aria-checked')).toBe('true')
    unmount()
    renderCard(false)
    expect(((await screen.findByRole('switch', { name: '开启 302 调度' })) as HTMLButtonElement).disabled).toBe(true)
  })

  it('renders in English', async () => {
    await i18n.changeLanguage('en-US')
    vi.mocked(siteSchedule302Api.get).mockResolvedValue(state())
    renderCard()
    expect(await screen.findByText('HTTP 302 scheduling')).toBeTruthy()
    expect(screen.getByText(/Not recommended for ordinary web pages/u)).toBeTruthy()
  })

  it('splits free-text lists', () => {
    expect(splitList(' mp4, zip，iso\n/a/ ')).toEqual(['mp4', 'zip', 'iso', '/a/'])
    expect(splitList('')).toEqual([])
  })
})
