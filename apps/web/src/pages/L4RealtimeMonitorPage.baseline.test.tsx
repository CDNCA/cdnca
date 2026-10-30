import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { resetSessionStore, useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import L4RealtimeMonitorPage from './L4RealtimeMonitorPage'
import l4RealtimeCSSRaw from './L4RealtimeMonitorPage.css?raw'
import { defaultLookCSS } from '../test/defaultLookCSS'

const l4RealtimeCSS = defaultLookCSS(l4RealtimeCSSRaw)

function authenticateAdmin() {
  const actor = principal({
    scope_kind: 'platform',
    scope_id: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions: ['platform.admin'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function emptyRealtimeResponse(input: RequestInfo | URL) {
  const url = new URL(String(input), 'https://cdnca.test')
  const range = url.searchParams.get('range') ?? '1h'
  const to = url.searchParams.get('to') ?? '2026-09-15T03:00:00Z'
  const from = url.searchParams.get('from') ?? '2026-09-15T02:00:00Z'
  return new Response(JSON.stringify({
    version: 'l4-realtime/v1',
    meta: { range, timezone: 'UTC', from, to, snapshot: { at: to, source_watermark: 0, finalized_through: to } },
    totals: { sessions: 0, bytes_up: 0, bytes_down: 0, errors: 0 },
    rows: [],
  }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function cssRules(selector: string): string[] {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return [...l4RealtimeCSS.matchAll(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 'g'))]
    .map((match) => match[1])
}

async function renderPage() {
  await act(async () => {
    renderWithProviders(<L4RealtimeMonitorPage />, ['/monitor/stream/realtime'])
    await Promise.resolve()
  })
}

describe('L4RealtimeMonitorPage canonical baseline', () => {
  beforeEach(async () => {
    resetSessionStore()
    await changeLocale('zh-CN')
    authenticateAdmin()
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await act(async () => resetSessionStore())
  })

  it('renders the canonical two-tab admin surface with a platform-wide realtime read and optional tenant/node filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(emptyRealtimeResponse(input)))
    await renderPage()

    const analytics = fetchSpy.mock.calls.filter((call) => String(call[0]).includes('/analytics/'))
    expect(analytics).toHaveLength(1)
    const url = new URL(String(analytics[0]?.[0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/l4-realtime')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(screen.getByRole('heading', { name: '四层转发实时监控' })).toHaveClass('visually-hidden')
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent?.trim())).toEqual(['带宽流量', '端口排行'])
    expect(screen.getByRole('tab', { name: '带宽流量', selected: true })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('输入端口，如88/TCP 99/UDP')).toBeEnabled()
    expect(await screen.findByRole('button', { name: '查询' })).toBeEnabled()
    // 租户/节点 are optional pickers (empty = whole control plane), not required IDs.
    expect(screen.getByRole('combobox', { name: '租户' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '节点' })).toBeInTheDocument()
    expect(screen.queryByLabelText('站点 ID')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('流 ID')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新' })).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: '带宽' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '流量' })).toBeInTheDocument()
    expect(screen.queryByText(/来源水位|已结算至|当前筛选范围内暂无/)).not.toBeInTheDocument()
  })

  it('keeps the traffic toolbar and sends the selected range and port filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(emptyRealtimeResponse(input)))
    await renderPage()
    const user = userEvent.setup()
    const range = screen.getByRole('group', { name: '时间范围' })
    const options = within(range).getAllByRole('radio')

    // 快捷项统一为今天/近7天/近30天/自定义，默认今天。
    expect(options.map((option) => option.closest('label')?.textContent?.trim())).toEqual(['今天', '近7天', '近30天', '自定义'])
    expect(within(range).getByRole('radio', { name: '今天' })).toBeChecked()
    expect(options.every((option) => !option.hasAttribute('disabled'))).toBe(true)

    await user.click(screen.getByText('近30天'))
    expect(within(range).getByRole('radio', { name: '近30天' })).toBeChecked()
    await user.click(screen.getByText('自定义'))
    // 自定义是共享组件的单个「选择时间范围」框（双月面板），不再是两个 datetime-local。
    expect(within(range).getByRole('textbox', { name: '选择时间范围' })).toBeInTheDocument()
    expect(document.querySelector('input[type="datetime-local"]')).not.toBeInTheDocument()
    await user.type(screen.getByPlaceholderText('输入端口，如88/TCP 99/UDP'), '88/TCP 99/UDP')
    const query = screen.getByRole('button', { name: '查询' })
    expect(query.querySelector('svg')).not.toBeNull()
    await user.click(query)
    expect(screen.queryByRole('button', { name: '刷新' })).not.toBeInTheDocument()
    await waitFor(() => {
      const urls = fetchSpy.mock.calls.slice(1).map((call) => new URL(String(call[0]), 'https://cdnca.test'))
      expect(urls.some((url) => url.searchParams.get('listen_port') === '88' && url.searchParams.get('protocol') === 'tcp')).toBe(true)
      expect(urls.some((url) => url.searchParams.get('listen_port') === '99' && url.searchParams.get('protocol') === 'udp')).toBe(true)
    })
  })

  it('renders the ranking toolbar and loads the selected top-port window', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(emptyRealtimeResponse(input)))
    await renderPage()
    const user = userEvent.setup()
    const rankingTab = screen.getByRole('tab', { name: '端口排行' })

    expect(rankingTab).not.toHaveAttribute('aria-disabled', 'true')
    await user.click(rankingTab)
    expect(screen.getByRole('tab', { name: '端口排行', selected: true })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('输入端口，如88/TCP 99/UDP')).not.toBeInTheDocument()
    const range = screen.getByRole('radiogroup', { name: '排行时间范围' })
    expect(within(range).getAllByRole('radio').map((option) => option.closest('label')?.textContent?.trim())).toEqual(['10分钟实时', '近30分钟', '近1小时'])
    expect(within(range).getByRole('radio', { name: '10分钟实时' })).toBeChecked()
    await user.click(screen.getByText('近30分钟'))
    expect(within(range).getByRole('radio', { name: '近30分钟' })).toBeChecked()
    const refresh = screen.getByRole('button', { name: '刷新' })
    expect(refresh.querySelector('svg')).not.toBeNull()
    await user.click(refresh)
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent?.trim())).toEqual(['排行', '端口', '连接数', '流量'])
    expect(screen.getByText('暂无数据')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.length).toBeGreaterThanOrEqual(3)
    const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/l4-realtime')
    expect(url.searchParams.get('range')).toBe('custom')
  })

  it('locks the current-static desktop card, toolbar, 350px charts and ranking table geometry', () => {
    expect(cssRules('.l4-realtime-baseline-page')[0]).toEqual(expect.stringContaining('max-width: 100%;'))
    expect(cssRules('.l4-realtime-baseline-panel')[0]).toEqual(expect.stringContaining('border: 1px solid #edf1f7;'))
    expect(cssRules('.l4-realtime-baseline-panel')[0]).toEqual(expect.stringContaining('border-radius: 8px;'))
    expect(cssRules('.l4-realtime-baseline-panel')[0]).toEqual(expect.stringContaining('padding: 18px 20px 20px;'))
    expect(cssRules('.l4-realtime-baseline-port')[0]).toEqual(expect.stringContaining('width: 260px;'))
    expect(cssRules('.l4-realtime-baseline-filter')[0]).toEqual(expect.stringContaining('gap: 10px;'))
    expect(cssRules('.l4-realtime-baseline-chart')[0]).toEqual(expect.stringContaining('min-height: 350px;'))
    expect(cssRules('.l4-realtime-baseline-chart-grid')[0]).toEqual(expect.stringContaining('grid-template-columns: repeat(2, minmax(0, 1fr));'))
    expect(cssRules('.l4-realtime-baseline-ranking-table')[0]).toEqual(expect.stringContaining('max-width: 900px;'))
    expect(l4RealtimeCSS).toContain('.l4-realtime-baseline-tabs .ant-tabs-tab:hover')
    expect(l4RealtimeCSS).toContain('.l4-realtime-baseline-tabs .ant-tabs-tab-active')
    expect(cssRules('.l4-realtime-baseline-tabs .ant-tabs-tab')[0]).toEqual(expect.stringContaining('border-radius: 8px;'))
    expect(cssRules('.l4-realtime-baseline-tabs .ant-tabs-tab-active')[0]).toEqual(expect.stringContaining('background: rgb(45 140 240 / 12%);'))
    expect(cssRules('.l4-realtime-baseline-ranking-toolbar')).toEqual(expect.arrayContaining([
      expect.stringContaining('margin-bottom: 14px;'),
    ]))
    expect(l4RealtimeCSS).toContain('.l4-realtime-baseline-range .ant-radio-button-wrapper-disabled')
  })

  it('locks the current-static 920/760 breakpoints for full-width mobile controls and internal table scroll', () => {
    expect(l4RealtimeCSS).toMatch(/@media \(max-width: 767px\)[\s\S]*\.app-main > \.l4-realtime-baseline-page[\s\S]*margin: 24px;/)
    expect(l4RealtimeCSS).toMatch(/@media \(max-width: 1300px\)[\s\S]*\.l4-realtime-baseline-chart-grid[\s\S]*grid-template-columns: minmax\(0, 1fr\);/)
    expect(l4RealtimeCSS).toMatch(/@media \(max-width: 920px\)[\s\S]*\.l4-realtime-baseline-port[\s\S]*width: 100%;/)
    expect(l4RealtimeCSS).toMatch(/@media \(max-width: 760px\)[\s\S]*\.l4-realtime-baseline-ranking-range[\s\S]*width: 100%;/)
    // 横向只由表格自身的 scroll.x 滚动，外框不再出第二条滚动条。
    expect(cssRules('.l4-realtime-baseline-ranking-table-scroll')[0]).not.toEqual(expect.stringContaining('overflow-x: auto;'))
  })
})
