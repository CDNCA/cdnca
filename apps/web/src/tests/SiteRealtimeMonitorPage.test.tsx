import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import dayjs from 'dayjs'
import userEvent from '@testing-library/user-event'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import SiteRealtimeMonitorPage from '../pages/SiteRealtimeMonitorPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'
const siteId = '018f0000-0000-7000-8000-000000000020'

function authenticate(scope: 'platform' | 'tenant') {
  const actor = principal({
    scope_kind: scope,
    scope_id: scope === 'platform' ? 'platform' : tenantId,
    tenant_id: scope === 'platform' ? null : tenantId,
    permissions: ['sites.read'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function realtimeResponse(input: RequestInfo | URL) {
  const url = new URL(String(input), 'http://cdnca.test')
  const from = url.searchParams.get('from')!
  const to = url.searchParams.get('to')!
  const coverageTo = new Date(Math.ceil(Date.parse(to) / 3600000) * 3600000).toISOString()
  const windows = (Date.parse(coverageTo) - Math.floor(Date.parse(from) / 3600000) * 3600000) / 3600000
  return json({
    data: {
      metric_version: 1,
      series_bucket_seconds: Math.ceil((Date.parse(to) - Date.parse(from)) / 60000 / 744) * 60,
      summary: {
        requests: 120, traffic_bytes: 5120, bandwidth_bps: 8000, connections: 7,
        status_2xx: 110, status_3xx: 2, status_4xx: 6, status_5xx: 2,
        cache_hits: 80, cache_misses: 40, errors: 2, average_duration_us: 2100,
        origin_connect_us: 100, origin_first_byte_us: 300, origin_total_us: 900,
      },
      series: [{ bucket: from, requests: 120, traffic_bytes: 5120, bandwidth_bps: 8000, connections: 7,
        cache_hits: 80, cache_misses: 40, cache_hit_bytes: 3072, status_4xx: 6, status_5xx: 2,
        origin_total_us: 900, origin_traffic_bytes: null, origin_bandwidth_bps: null }],
      top: [{ host: 'cdn.example.test', listen_port: 443, requests: 120, traffic_bytes: 5120 }],
      // query_version=4 live evidence: no settlement claim.
      evidence: {
        access_source_count: 120, connection_source_count: 7, expected_events: 0, observed_events: 120,
        error_ppm: 0, finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z',
        coverage_from: new Date(Math.floor(Date.parse(from) / 3600000) * 3600000).toISOString(),
        coverage_to: coverageTo, snapshot_at: to,
        coverage_complete: true, covered_windows: windows, requested_windows: windows, missing_windows: [],
      },
    },
    meta: { from, to, timezone: 'UTC', metric_version: 1, query_version: 4 },
  })
}

describe('SiteRealtimeMonitorPage', () => {
  it('opens a single range field with linked double calendars and time controls', async () => {
    authenticate('platform')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    expect(screen.getByRole('dialog', { name: '选择时间范围' })).toBeInTheDocument()
    expect(document.querySelectorAll('.cdnca-time-range-month')).toHaveLength(2)
    // Custom starts from the current quick window; picking a new start waits for the end before time can be set.
    expect(screen.getByRole('button', { name: '选择时间' })).toBeEnabled()
    await user.click(screen.getAllByRole('button', { name: dayjs().startOf('month').format('YYYY-MM-DD') })[0])
    expect(screen.getByRole('button', { name: '选择时间' })).toBeDisabled()
    expect(document.querySelector('input[type="datetime-local"]')).not.toBeInTheDocument()
  })
  it('fails closed before authentication without making a request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect(await screen.findByText('无权查看监控数据')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  // /monitor/site/realtime 只有「域名 + 监听端口 + 时间范围 + 查询」，
  // 没有租户/站点范围开关，因此平台管理员不再能在这页收窄租户范围。
  it('loads the platform-wide view immediately and keeps the host, port, and range filters', async () => {
    authenticate('platform')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    const initialURL = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(initialURL.pathname).toBe('/v1/admin/analytics/site-realtime')
    expect(initialURL.searchParams.has('tenant_id')).toBe(false)

    expect(screen.queryByRole('button', { name: '目标范围' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('租户 ID')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('站点 ID')).not.toBeInTheDocument()

    const hostInput = screen.getByLabelText('域名')
    expect(hostInput).toHaveAttribute('placeholder', '输入域名，多个空格分隔')
    const portInput = screen.getByLabelText('监听端口')
    expect(portInput).toHaveAttribute('placeholder', '输入监听端口')
    await user.type(hostInput, 'cdn.example.test')
    await user.type(portInput, '443')
    await user.click(screen.getByText('近7天'))
    await user.click(screen.getByRole('button', { name: '查询' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const url = new URL(String(fetchSpy.mock.calls[1][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/site-realtime')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(url.searchParams.has('site_id')).toBe(false)
    expect(url.searchParams.get('host')).toBe('cdn.example.test')
    expect(url.searchParams.get('listen_port')).toBe('443')
    expect(Date.parse(url.searchParams.get('to')!) - Date.parse(url.searchParams.get('from')!)).toBe(7 * 24 * 60 * 60 * 1000)
  })

  it('renders the four baseline quality charts without a summary strip or tenant-only diagnostics', async () => {
    authenticate('platform')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)

    expect((await screen.findAllByText('120')).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('tab', { name: '质量监控' }))
    expect(screen.getAllByRole('img').map((chart) => chart.getAttribute('aria-label'))).toEqual(['请求命中率', '字节命中率', '4xx状态码', '5xx状态码'])
    expect(document.querySelector('.analytics-summary')).not.toBeInTheDocument()
    expect(screen.queryByText('质量诊断')).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('renders the atomic tenant facts, evidence, quality, origin, and ranking without tenant override', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)

    expect((await screen.findAllByText('120')).length).toBeGreaterThan(0)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/site-realtime')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent?.trim())).toEqual(['基础数据', '质量监控', '回源监控'])
    expect(screen.getByText(/^数据快照 /)).toBeInTheDocument()
    expect(screen.queryByText(/发生器对账误差|已结算至/)).not.toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent?.trim())).toEqual(['域名 / 端口', '请求数', '流量'])
    expect(screen.getByText('cdn.example.test:443')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '质量监控' }))
    expect(screen.getByRole('img', { name: '请求命中率' })).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '回源监控' }))
    expect(screen.getAllByRole('img').map((chart) => chart.getAttribute('aria-label'))).toEqual(['回源带宽', '回源流量', '回源耗时'])
    expect(document.querySelector('.analytics-summary')).not.toBeInTheDocument()
  })

  it('labels the page and queries multiple space-separated domains as one aggregate', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)

    expect(await screen.findByRole('region', { name: '网站实时监控' })).toBeInTheDocument()
    expect((await screen.findAllByText('120')).length).toBeGreaterThan(0)
    const hostInput = screen.getByLabelText('域名')
    expect(hostInput).toHaveAttribute('placeholder', '输入域名，多个空格分隔')
    await user.type(hostInput, 'cdn.example.test static.example.test')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const url = new URL(String(fetchSpy.mock.calls[1][0]), 'http://cdnca.test')
    expect(url.searchParams.get('host')).toBe('cdn.example.test static.example.test')
    expect(screen.queryByText('请输入规范的小写域名。')).not.toBeInTheDocument()
  })

  it('maps unfinalized evidence without exposing storage details', async () => {
    authenticate('tenant')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'analytics_realtime_evidence_unavailable', message: 'clickhouse.internal:8123 secret' },
    }, 503))
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect(await screen.findByText('实时监控证据尚未结算，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByText(/clickhouse\.internal/)).not.toBeInTheDocument()
  })

  it('renders proven-empty zero evidence as a zero baseline without an error alert', async () => {
    authenticate('platform')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const response = await realtimeResponse(input).json()
      response.data.summary = Object.fromEntries(Object.keys(response.data.summary).map((key) => [key, 0]))
      response.data.series = []
      response.data.top = []
      Object.assign(response.data.evidence, { access_source_count: 0, connection_source_count: 0, observed_events: 0 })
      return json(response)
    })
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect(await screen.findByText(/^数据快照 /)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(document.querySelector('.analytics-page-error')).not.toBeInTheDocument()
    expect(screen.queryByText('实时监控证据尚未结算，请稍后重试。')).not.toBeInTheDocument()
    for (const title of ['带宽', '流量', '访问次数', 'QPS']) {
      const chart = screen.getByRole('img', { name: title })
      expect(chart.querySelectorAll('.analytics-realtime-series-dot')).toHaveLength(1)
      expect(chart.closest('section')?.querySelector('.analytics-realtime-no-data')).toBeNull()
    }
    expect(document.body).not.toHaveTextContent('NaN')
  })

  // stats-platform-l7：实时监控读实时入库数据（query_version=4），当前未结算的整点也显示，
  // 不再出现「所选时段数据尚未结算，已结算 0/1 个整点时段」；快捷范围截至当前分钟。
  it('reads live data for the current unsettled hour, platform-wide and newest minute included', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date('2026-10-24T08:37:20Z') })
    try {
      authenticate('platform')
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
      renderWithProviders(<SiteRealtimeMonitorPage />)
      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
      const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
      expect(url.searchParams.get('query_version')).toBe('4')
      expect(url.searchParams.has('tenant_id')).toBe(false)
      expect(url.searchParams.has('site_id')).toBe(false)
      expect(url.searchParams.get('to')).toBe('2026-10-24T08:38:00.000Z')
      // fix-rangecompact：默认今天，北京时间当天 00:00 起。
      expect(url.searchParams.get('from')).toBe('2026-10-23T16:00:00.000Z')
      expect((await screen.findAllByText('120')).length).toBeGreaterThan(0)
      expect(screen.queryByText(/尚未结算/)).not.toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('refreshes every 10 seconds, rolls a preset window to the current minute, and shows when it was updated', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date('2026-10-24T08:37:20Z') })
    try {
      authenticate('tenant')
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
      renderWithProviders(<SiteRealtimeMonitorPage />)
      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
      expect(await screen.findByTestId('site-realtime-updated')).toHaveTextContent(/^每 10 秒自动刷新，更新于 /)
      // 摘要里的连接数是窗口内聚合，不是当前并发。
      expect(screen.getByText('窗口内连接数')).toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
      await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThanOrEqual(2))
      await act(async () => { await vi.advanceTimersByTimeAsync(40_000) })
      await waitFor(() => {
        const last = new URL(String(fetchSpy.mock.calls.at(-1)![0]), 'http://cdnca.test')
        expect(last.searchParams.get('to')).toBe('2026-10-24T08:39:00.000Z')
      })
      // 窗口滚动时保留上一份数据，不闪成加载态。
      expect(screen.queryByLabelText('正在加载实时监控数据')).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not refresh while the page is hidden', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date('2026-10-24T08:37:20Z') })
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    try {
      authenticate('tenant')
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
      renderWithProviders(<SiteRealtimeMonitorPage />)
      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
      await act(async () => { await vi.advanceTimersByTimeAsync(65_000) })
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      visibility.mockRestore()
      vi.useRealTimers()
    }
  })

  it('rejects live evidence that claims settlement it does not have', async () => {
    authenticate('tenant')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const response = await realtimeResponse(input).json()
      Object.assign(response.data.evidence, { coverage_complete: false, missing_windows: [response.data.evidence.coverage_from] })
      return json(response)
    })
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect(await screen.findByText('实时监控数据无法通过完整性校验。')).toBeInTheDocument()
  })

  it('rejects malformed custom windows locally', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect((await screen.findAllByText('120')).length).toBeGreaterThan(0)
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const start = dayjs().startOf('month')
    await user.click(screen.getAllByRole('button', { name: start.format('YYYY-MM-DD') })[0])
    await user.click(screen.getByRole('button', { name: '下个月' }))
    // The 31-day limit is enforced in the picker: days beyond it cannot be picked as the end.
    expect(screen.getAllByRole('button', { name: start.add(2, 'month').format('YYYY-MM-DD') }).at(-1)!).toBeDisabled()
    expect(screen.getByRole('button', { name: '确定' })).toBeDisabled()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('queries exact custom minutes without rounding either boundary', async () => {
    authenticate('platform')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    await screen.findAllByText('120')
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const start = dayjs().startOf('month')
    await user.click(screen.getAllByRole('button', { name: start.format('YYYY-MM-DD') })[0])
    await user.click(screen.getAllByRole('button', { name: start.add(1, 'day').format('YYYY-MM-DD') })[0])
    await user.click(screen.getByRole('button', { name: '选择时间' }))
    await user.click(within(screen.getByRole('group', { name: '开始时间分钟' })).getByRole('button', { name: '30' }))
    await user.click(within(screen.getByRole('group', { name: '结束时间分钟' })).getByRole('button', { name: '45' }))
    await user.click(screen.getByRole('button', { name: '确定' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const url = new URL(String(fetchSpy.mock.calls[1][0]), 'http://cdnca.test')
    expect(url.searchParams.get('from')).toBe(new Date(`${start.format('YYYY-MM-DD')}T00:30:00+08:00`).toISOString())
    expect(url.searchParams.get('to')).toBe(new Date(`${start.add(1, 'day').format('YYYY-MM-DD')}T00:45:00+08:00`).toISOString())
  })

  it('sizes chart coordinates to the canvas without stretching font shapes', async () => {
    let resize: ResizeObserverCallback | undefined
    const originalObserver = window.ResizeObserver
    window.ResizeObserver = class { constructor(callback: ResizeObserverCallback) { resize = callback } observe() {} disconnect() {} unobserve() {} }
    authenticate('platform')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    renderWithProviders(<SiteRealtimeMonitorPage />)
    await screen.findAllByText('120')
    act(() => resize!([{ contentRect: { width: 810, height: 292 } }] as ResizeObserverEntry[], {} as ResizeObserver))
    expect(screen.getByRole('img', { name: 'QPS' })).toHaveAttribute('viewBox', '0 0 810 292')
    expect(screen.getByRole('img', { name: 'QPS' })).not.toHaveAttribute('preserveAspectRatio', 'none')
    window.ResizeObserver = originalObserver
  })

  it('shows actual quality values on hover and keyboard focus, and keeps uncollected origin bytes out of the series', async () => {
    authenticate('platform')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    await screen.findAllByText('120')
    await user.click(screen.getByRole('tab', { name: '质量监控' }))
    const ratio = screen.getByRole('img', { name: '请求命中率' })
    expect(ratio).toHaveAttribute('tabindex', '0')
    fireEvent.focus(ratio)
    expect(screen.getByRole('tooltip')).toHaveTextContent('请求命中率：66.67 %')
    expect(screen.getByRole('tooltip')).toHaveTextContent(/\d{4}\/\d{2}\/\d{2}/)
    fireEvent.keyDown(ratio, { key: 'Escape' })
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    const byteRatio = screen.getByRole('img', { name: '字节命中率' })
    vi.spyOn(byteRatio, 'getBoundingClientRect').mockReturnValue({ left: 0, width: 640 } as DOMRect)
    fireEvent.mouseMove(byteRatio, { clientX: 320 })
    expect(screen.getByRole('tooltip')).toHaveTextContent('字节命中率：60 %')
    fireEvent.mouseLeave(byteRatio)
    fireEvent.focus(screen.getByRole('img', { name: '4xx状态码' }))
    expect(screen.getByRole('tooltip')).toHaveTextContent('4xx状态码：6 次')
    await user.click(screen.getByRole('tab', { name: '回源监控' }))
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    expect(screen.getAllByText('未采集回源字节，暂无法计算此指标')).toHaveLength(2)
    for (const title of ['回源带宽', '回源流量']) {
      const chart = screen.getByRole('img', { name: title })
      expect(chart.querySelector('.analytics-realtime-series')).not.toBeInTheDocument()
      expect(chart.querySelector('.analytics-realtime-series-dot')).not.toBeInTheDocument()
    }
    fireEvent.focus(screen.getByRole('img', { name: '回源耗时' }))
    expect(screen.getByRole('tooltip')).toHaveTextContent('回源耗时：0.0009 秒')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('uses explicit bucket seconds for sparse QPS points and a truncated final bucket', async () => {
    authenticate('platform')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const response = await realtimeResponse(input).json()
      const from = Date.parse(response.meta.from)
      const to = Date.parse(response.meta.to)
      const bucketMilliseconds = response.data.series_bucket_seconds * 1000
      const lastBucket = from + Math.floor((to - from - 1) / bucketMilliseconds) * bucketMilliseconds
      const point = response.data.series[0]
      response.data.series = [
        { ...point, requests: 60, traffic_bytes: 2560, cache_hits: 20, cache_misses: 40, cache_hit_bytes: 512, status_4xx: 3, status_5xx: 1, connections: 3, bucket: new Date(from).toISOString() },
        { ...point, requests: 60, traffic_bytes: 2560, cache_hits: 60, cache_misses: 0, cache_hit_bytes: 2560, status_4xx: 3, status_5xx: 1, connections: 4, bucket: new Date(lastBucket).toISOString() },
      ]
      return json(response)
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    await screen.findAllByText('120')
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const start = dayjs().startOf('month')
    await user.click(screen.getAllByRole('button', { name: start.format('YYYY-MM-DD') })[0])
    await user.click(screen.getAllByRole('button', { name: start.add(1, 'day').format('YYYY-MM-DD') })[0])
    await user.click(screen.getByRole('button', { name: '选择时间' }))
    await user.click(within(screen.getByRole('group', { name: '结束时间分钟' })).getByRole('button', { name: '01' }))
    await user.click(screen.getByRole('button', { name: '确定' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    await screen.findAllByText('120')
    const chart = screen.getByRole('img', { name: 'QPS' })
    fireEvent.focus(chart)
    expect(screen.getByRole('tooltip')).toHaveTextContent('QPS：0.5')
    fireEvent.keyDown(chart, { key: 'ArrowRight' })
    expect(screen.getByRole('tooltip')).toHaveTextContent('QPS：1')
    fireEvent.keyDown(chart, { key: 'Home' })
    expect(screen.getByRole('tooltip')).toHaveTextContent('QPS：0.5')
    fireEvent.keyDown(chart, { key: 'End' })
    expect(screen.getByRole('tooltip')).toHaveTextContent('QPS：1')
    await user.click(screen.getByRole('tab', { name: '质量监控' }))
    const requestRatio = screen.getByRole('img', { name: '请求命中率' })
    fireEvent.focus(requestRatio)
    expect(screen.getByRole('tooltip')).toHaveTextContent('请求命中率：33.33 %')
    fireEvent.keyDown(requestRatio, { key: 'End' })
    expect(screen.getByRole('tooltip')).toHaveTextContent('请求命中率：100 %')
    fireEvent.blur(requestRatio)
    const byteRatio = screen.getByRole('img', { name: '字节命中率' })
    fireEvent.focus(byteRatio)
    expect(screen.getByRole('tooltip')).toHaveTextContent('字节命中率：20 %')
    fireEvent.keyDown(byteRatio, { key: 'End' })
    expect(screen.getByRole('tooltip')).toHaveTextContent('字节命中率：100 %')
  })

  it('leaves zero-denominator hit ratios and absent origin duration empty without NaN or invented zero points', async () => {
    authenticate('platform')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const response = await realtimeResponse(input).json()
      response.data.summary = Object.fromEntries(Object.keys(response.data.summary).map((key) => [key, 0]))
      response.data.series = [{ bucket: response.meta.from, requests: 0, traffic_bytes: 0, bandwidth_bps: 0, connections: 0,
        cache_hits: 0, cache_misses: 0, cache_hit_bytes: 0, status_4xx: 0, status_5xx: 0,
        origin_total_us: null, origin_traffic_bytes: null, origin_bandwidth_bps: null }]
      response.data.top = []
      Object.assign(response.data.evidence, { access_source_count: 0, connection_source_count: 0, observed_events: 0 })
      return json(response)
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    await screen.findByText(/^数据快照 /)
    await user.click(screen.getByRole('tab', { name: '质量监控' }))
    for (const title of ['请求命中率', '字节命中率']) {
      const chart = screen.getByRole('img', { name: title })
      expect(chart.querySelector('.analytics-realtime-series-dot')).not.toBeInTheDocument()
      fireEvent.focus(chart)
      expect(screen.getByRole('tooltip')).toHaveTextContent('当前筛选范围内暂无数据')
      fireEvent.blur(chart)
    }
    await user.click(screen.getByRole('tab', { name: '回源监控' }))
    const duration = screen.getByRole('img', { name: '回源耗时' })
    expect(duration.querySelector('.analytics-realtime-series-dot')).not.toBeInTheDocument()
    // 回源耗时空值不是“筛选范围内无数据”，而是这段时间没有回源样本。
    expect(duration.closest('section')).toHaveTextContent('无回源样本')
    fireEvent.focus(duration)
    expect(screen.getByRole('tooltip')).toHaveTextContent('无回源样本')
    fireEvent.blur(duration)
    expect(document.body).not.toHaveTextContent('NaN')
    expect(document.body).not.toHaveTextContent('Infinity')
  })

  it('loads the isolated pseudo locale namespace', async () => {
    await changeLocale('qps-ploc')
    authenticate('tenant')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(realtimeResponse(input)))
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect(await screen.findByRole('heading', { name: '［网站实时监控］' })).toBeInTheDocument()
  })

  it('mounts quality diagnostics from the tenant scope it already holds', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      if (url.pathname.endsWith('/site-quality-diagnostics')) {
        return Promise.resolve(json({
          items: [{
            event_id: 'diagnostic-1', occurred_at: url.searchParams.get('from'), site_id: siteId,
            node_id: '018f0000-0000-7000-8000-000000000030', request_id: 'request-1', trace_id: 'trace-1',
            config_version_id: '018f0000-0000-4000-8000-000000000031', installation_id: '018f0000-0000-4000-8000-000000000032',
            task_id: null, status_code: 502, category: 'upstream_5xx', cause_code: 'upstream_failure', action_code: 'inspect_upstream',
          }], next_cursor: null, snapshot: {
            at: url.searchParams.get('to'), source_watermark: 42,
            finalized_through: url.searchParams.get('to'),
            expires_at: new Date(Date.parse(url.searchParams.get('to')!) + 5 * 60 * 1000).toISOString(),
          },
        }))
      }
      return Promise.resolve(realtimeResponse(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteRealtimeMonitorPage />)
    expect((await screen.findAllByText('120')).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('tab', { name: '质量监控' }))
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('site-quality-diagnostics'))).toBe(false)
    await user.click(screen.getByText('高级质量诊断'))
    expect(await screen.findByText('018f0000-0000-4000-8000-000000000031')).toBeInTheDocument()
    const diagnosticCall = fetchSpy.mock.calls.find(([input]) => String(input).includes('site-quality-diagnostics'))
    expect(diagnosticCall).toBeDefined()
    const url = new URL(String(diagnosticCall![0]), 'http://cdnca.test')
    expect(url.searchParams.has('site_id')).toBe(false)
    expect(url.searchParams.has('tenant_id')).toBe(false)
  })
})
