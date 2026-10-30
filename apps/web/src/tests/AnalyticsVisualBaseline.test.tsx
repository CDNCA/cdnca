import { screen, waitFor, within } from '@testing-library/react'
import dayjs from 'dayjs'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { analyticsLogsApi } from '../api/analyticsLogs'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import L4RealtimeMonitorPage from '../pages/L4RealtimeMonitorPage'
import l4RealtimeStylesRaw from '../pages/L4RealtimeMonitorPage.css?raw'
import SiteAccessLogPage from '../pages/SiteAccessLogPage'
import accessLogStylesRaw from '../pages/SiteAccessLogPage.css?raw'
import SiteAnalysisPage from '../pages/SiteAnalysisPage'
import analysisStylesRaw from '../pages/SiteAnalysisPage.css?raw'
import SiteBlockLogPage from '../pages/SiteBlockLogPage'
import SiteRealtimeMonitorPage from '../pages/SiteRealtimeMonitorPage'
import WafLogsPage from '../pages/WafLogsPage'
import compactToolbarStylesRaw from '../styles/compact-toolbar.css?raw'
import baseStylesRaw from '../styles.css?raw'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultLookCSS } from '../test/defaultLookCSS'

const l4RealtimeStyles = defaultLookCSS(l4RealtimeStylesRaw)
const accessLogStyles = defaultLookCSS(accessLogStylesRaw)
const analysisStyles = defaultLookCSS(analysisStylesRaw)
const compactToolbarStyles = defaultLookCSS(compactToolbarStylesRaw)
const baseStyles = defaultLookCSS(baseStylesRaw)

const styles = [baseStyles, compactToolbarStyles, analysisStyles, accessLogStyles, l4RealtimeStyles].join('\n')

function styleRules(selector: string): CSSStyleRule[] {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
  style.remove()
  return rules
    .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    .filter((rule) => rule.selectorText.split(',').map((part) => part.trim()).includes(selector))
}

function lastStyleRule(selector: string): CSSStyleRule {
  const rule = styleRules(selector).at(-1)
  expect(rule, `missing CSS rule ${selector}`).toBeDefined()
  return rule!
}

function lastStyleRuleWith(selector: string, property: string): CSSStyleRule {
  const rule = styleRules(selector).reverse().find((candidate) => candidate.style.getPropertyValue(property) !== '')
  expect(rule, `missing CSS property ${property} on ${selector}`).toBeDefined()
  return rule!
}

function mediaStyleRules(selector: string, condition: string): CSSStyleRule[] {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
    .filter((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === condition)
    .flatMap((media) => [...media.cssRules])
  style.remove()
  return rules
    .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    .filter((rule) => rule.selectorText.split(',').map((part) => part.trim()).includes(selector))
}

function mobileStyleRules(selector: string): CSSStyleRule[] {
  return mediaStyleRules(selector, '(max-width: 767px)')
}

function authenticate() {
  const actor = principal({ permissions: ['sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

const accessMeta = {
  from: '2026-07-28T07:00:00.000Z', to: '2026-07-28T08:00:00.000Z', timezone: 'UTC',
  snapshot_at: '2026-07-28T08:00:00.000Z', consistency: 'snapshot',
  replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset',
}

const accessEvent = {
  event_id: 'visual-access-1', occurred_at: '2026-07-28T07:59:00.000Z',
  site_id: '018f0000-0000-7000-8000-000000000020', node_id: '018f0000-0000-7000-8000-000000000030',
  request_id: 'visual-request-1', trace_id: 'visual-trace-1',
  config_version_id: '018f0000-0000-7000-8000-000000000040', host: 'cdn.example.test', listen_port: 443,
  uri_path: '/asset.js', client_ip: '192.0.2.10', country_code: 'CN', carrier: 'CMCC',
  method: 'GET', protocol: 'HTTP/2', cache_status: 'HIT', upstream_result: 'ok', upstream_addr: '', status_code: 200,
  request_bytes: 128, response_bytes: 1024, duration_us: 900, task_id: null,
  installation_id: 'installation-authority-1',
  request_headers: { 'User-Agent': 'Mozilla/5.0' },
  response_headers: { 'Content-Type': 'text/javascript; charset=utf-8' },
  request_body: null, response_body: null, ja4: null, origin_connect_us: null,
  origin_first_byte_us: null, origin_total_us: null,
}

describe('statistics visual baseline', () => {
  afterEach(async () => {
    vi.restoreAllMocks()
    useSessionStore.getState().clearSession()
    await changeLocale('zh-CN')
  })

  it('keeps the access-log search structure and mobile table scroll owner', () => {
    const toolbar = lastStyleRule('.analytics-log-page.site-access-log-page .analytics-log-time-range')
    expect(toolbar.style.display).toBe('none')
    expect(toolbar.style.getPropertyValue('flex')).toBe('0 0 300px')

    const mobileToolbar = [...mediaStyleRules(
      '.analytics-log-page.site-access-log-page .analytics-log-time-range',
      '(max-width: 600px)',
    )].reverse().find((rule) => rule.style.getPropertyValue('width') !== '')
    expect(mobileToolbar?.style.width).toBe('100%')
    const mobileRange = [...mediaStyleRules(
      '.analytics-log-page.site-access-log-page .analytics-log-time-range',
      '(max-width: 600px)',
    )].reverse().find((rule) => rule.style.getPropertyValue('flex-wrap') !== '')
    expect(mobileRange?.style.getPropertyValue('flex-wrap')).toBe('wrap')

    const table = lastStyleRuleWith('.analytics-log-page.site-access-log-page .analytics-log-table', 'max-width')
    expect(table.style.getPropertyValue('max-width')).toBe('100%')
    // fix-dblscroll：表格 scroll.x 自己横滚，外层不再 overflow-x:auto（否则两条滚动条）。
    expect(table.style.getPropertyValue('overflow-x')).toBe('')
  })

  it('keeps current analysis and access controls aligned to the compact rhythm', () => {
    const selector = lastStyleRuleWith('.analytics-log-page.site-access-log-page .analytics-log-domain-control > .analytics-log-site-filter', 'width')
    expect(selector.style.getPropertyValue('width')).toBe('320px')
    const quickFilter = lastStyleRule('.analytics-log-page.site-access-log-page .analytics-log-quick-filter')
    expect(quickFilter.style.getPropertyValue('width')).toBe('108px')
    const searchInput = lastStyleRuleWith('.analytics-log-page.site-access-log-page .analytics-log-domain-control .analytics-log-site-filter .ant-input', 'padding-inline')
    expect(searchInput.style.getPropertyValue('padding-inline')).toBe('7px')
    const dateRange = lastStyleRule('.analytics-log-page.site-access-log-page .analytics-log-time-range')
    expect(dateRange.style.getPropertyValue('width')).toBe('300px')
    const dateInput = lastStyleRule('.analytics-log-page.site-access-log-page .analytics-log-time-range .analytics-log-time-field .ant-input')
    expect(dateInput.style.getPropertyValue('white-space')).toBe('')

    const timeRangeLabel = lastStyleRule('.analytics-log-page.site-access-log-page .analytics-log-time-range-label::after')
    expect(timeRangeLabel.style.getPropertyValue('content')).toBe("':'")

    const analysisSearch = lastStyleRule('.analytics-analysis-page .analytics-analysis-search-input')
    expect(analysisSearch.style.getPropertyValue('width')).toBe('320px')
    const analysisType = lastStyleRule('.analytics-analysis-page .analytics-analysis-search-type')
    expect(analysisType.style.getPropertyValue('width')).toBe('96px')
    expect(analysisType.style.getPropertyValue('min-width')).toBe('96px')
  })

  it('keeps page-specific analytics panels flat and compact', () => {
    const panel = lastStyleRule('.analytics-panel')
    expect(panel.style.getPropertyValue('border')).toBe('1px solid var(--cdnca-color-border-secondary)')
    expect(panel.style.getPropertyValue('border-radius')).toBe('4px')
    expect(panel.style.getPropertyValue('box-shadow')).toBe('0 1px 6px rgb(0 0 0 / 10%)')
    expect(panel.style.getPropertyValue('padding')).toBe('0 16px 16px')

    const analysisPanel = lastStyleRule('.analytics-analysis-page > .analytics-panel')
    expect(analysisPanel.style.getPropertyValue('box-shadow')).toBe('none')
    expect(analysisPanel.style.getPropertyValue('padding')).toBe('16px')
    const accessPanel = lastStyleRule('.analytics-log-page.site-access-log-page > .analytics-panel')
    expect(accessPanel.style.getPropertyValue('box-shadow')).toBe('0 3px 8px rgb(15 23 42 / 6%), 0 16px 34px rgb(15 23 42 / 8%)')
    const accessExportsPanel = lastStyleRule('.analytics-log-page.site-access-log-page > .analytics-panel.access-view-exports')
    expect(accessExportsPanel.style.getPropertyValue('box-shadow')).toBe('0 1px 3px rgb(15 23 42 / 4%), 0 12px 28px rgb(15 23 42 / 6%)')

    const filter = lastStyleRule('.analytics-analysis-page .analytics-filter-bar')
    expect(filter.style.getPropertyValue('background')).toBe('transparent')

    const table = lastStyleRule('.analytics-table-scroll')
    expect(table.style.getPropertyValue('border-top')).toBe('1px solid var(--cdnca-color-border-secondary)')
  })

  // TF-R01：查询窗口、快照时间、采集进度这一行是给人看的，不能被 1px clip 藏成只剩读屏可见。
  it('keeps the analysis result meta line visible in normal flow (TF-R01)', () => {
    for (const rule of styleRules('.analytics-analysis-page > .analytics-panel > .analytics-meta')) {
      expect(rule.style.getPropertyValue('clip')).toBe('')
      expect(rule.style.getPropertyValue('position')).not.toBe('absolute')
      expect(rule.style.getPropertyValue('width')).not.toBe('1px')
    }
    const meta = lastStyleRule('.analytics-meta')
    expect(meta.style.getPropertyValue('display')).toBe('flex')
    expect(meta.style.getPropertyValue('flex-wrap')).toBe('wrap')
  })

  it('keeps the layer-4 statistics shell and chart geometry stable', () => {
    const panel = lastStyleRule('.l4-realtime-baseline-panel')
    expect(panel.style.getPropertyValue('border')).toBe('1px solid #edf1f7')
    expect(panel.style.getPropertyValue('border-radius')).toBe('8px')
    const chart = lastStyleRule('.l4-realtime-baseline-chart')
    expect(chart.style.getPropertyValue('border')).toBe('1px solid var(--cdnca-color-border-secondary)')
    expect(chart.style.getPropertyValue('border-radius')).toBe('6px')
    const grid = lastStyleRule('.l4-realtime-baseline-chart-grid')
    expect(grid.style.getPropertyValue('grid-template-columns')).toBe('repeat(2, minmax(0, 1fr))')
    const mobile = mediaStyleRules('.l4-realtime-baseline-chart-grid', '(max-width: 1300px)').at(-1)
    expect(mobile?.style.getPropertyValue('grid-template-columns')).toBe('minmax(0, 1fr)')
  })

  it('keeps the observed mobile shell and current statistics controls usable', () => {
    const brand = mobileStyleRules('.mobile-header-brand').at(-1)
    expect(brand?.style.getPropertyValue('display')).toBe('none')
    const header = mobileStyleRules('.app-header').at(-1)
    expect(header?.style.getPropertyValue('left')).toBe('0')
    const mobilePanel = mobileStyleRules('.analytics-panel').at(-1)
    expect(mobilePanel?.style.getPropertyValue('padding')).toBe('0 16px 16px')

    const analysisMode = mobileStyleRules('.analytics-analysis-page .analytics-analysis-search-type').at(-1)
    expect(analysisMode?.style.getPropertyValue('width')).toBe('96px')
    const analysisSearch = mobileStyleRules('.analytics-analysis-page .analytics-analysis-search-input').at(-1)
    expect(analysisSearch?.style.getPropertyValue('width')).toBe('100%')
    const analysisFilter = mobileStyleRules('.analytics-analysis-page .analytics-filter-bar').at(-1)
    expect(analysisFilter?.style.getPropertyValue('align-items')).toBe('flex-start')
    const analysisRange = mobileStyleRules('.analytics-analysis-page .analytics-range-control').at(-1)
    expect(analysisRange?.style.getPropertyValue('flex')).toBe('0 0 auto')
    expect(analysisRange?.style.getPropertyValue('width')).toBe('100%')

    const accessControl = mediaStyleRules(
      '.analytics-log-page.site-access-log-page .analytics-log-domain-control',
      '(max-width: 600px)',
    ).at(-1)
    expect(accessControl?.style.getPropertyValue('width')).toBe('100%')
    expect(accessControl?.style.getPropertyValue('flex')).toBe('0 0 100%')
    const accessRange = mediaStyleRules(
      '.analytics-log-page.site-access-log-page .analytics-log-time-range',
      '(max-width: 600px)',
    ).at(-1)
    expect(accessRange?.style.getPropertyValue('width')).toBe('100%')

    const realtimeRangeGroup = mobileStyleRules('.analytics-realtime-primary-fields > .cdnca-time-range').at(-1)
    expect(realtimeRangeGroup?.style.getPropertyValue('width')).toBe('100%')
  })

  it('keeps the observed analysis table geometry inside its own horizontal scroll area', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [],
      dimension: 'domain',
      page: { snapshot_at: '2026-07-28T08:00:00.000Z' },
      meta: { from: '2026-07-28T07:50:00.000Z', to: '2026-07-28T08:00:00.000Z', timezone: 'UTC', metric_version: 1 },
    }))
    renderWithProviders(<SiteAnalysisPage />)

    const table = await screen.findByTestId('analytics-rank-table-scroll')
    expect(within(table).getByRole('columnheader', { name: '排行' })).toBeInTheDocument()
    expect(within(table).getByRole('columnheader', { name: '域名' })).toBeInTheDocument()
    expect([...table.querySelectorAll('col')].map((column) => column.style.width).slice(0, 6)).toEqual([
      '9%', '24%', '15%', '15%', '15%', '12%',
    ])

    // 概览面板(analytics-analysis-overview / metric-grid / trend)已删除，
    // 对应的几何断言随样式一并移除。
    const scrollShell = lastStyleRule('.analytics-analysis-page .analytics-table-scroll')
    expect(scrollShell.style.getPropertyValue('max-width')).toBe('100%')
    // fix-dblscroll：900px 宽度由表格 scroll.x 给出、在 .ant-table-content 内横滚，外层不滚。
    expect(scrollShell.style.getPropertyValue('overflow-x')).toBe('')
  })

  it('keeps the compact analysis tabs and searchable dimension control', () => {
    const tabs = lastStyleRule('.analytics-analysis-page .analytics-rank-tabs .ant-tabs-tab')
    // 未选中标签 31px、选中标签 32px。
    expect(tabs.style.getPropertyValue('height')).toBe('31px')
    expect(tabs.style.getPropertyValue('padding')).toBe('5px 16px')
    const tabNav = lastStyleRule('.analytics-analysis-page .analytics-rank-tabs > .ant-tabs-nav')
    expect(tabNav.style.getPropertyValue('height')).toBe('32px')
    expect(tabNav.style.getPropertyValue('margin-bottom')).toBe('15px')

    const selection = lastStyleRule('.analytics-analysis-page .analytics-analysis-search-input > .ant-input-wrapper > .ant-input-group-addon:first-child .ant-select-selection-item')
    expect(selection.style.getPropertyValue('padding-inline-end')).toBe('20px')
    expect(selection.style.getPropertyValue('line-height')).toBe('30px')
  })

  it('keeps the site realtime page to its three observed data tabs', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const request = new URL(String(input), 'https://cdnca.test')
      const from = request.searchParams.get('from')!
      const to = request.searchParams.get('to')!
      return Promise.resolve(json({
        data: {
          metric_version: 1, series_bucket_seconds: Math.ceil((Date.parse(to) - Date.parse(from)) / 60_000 / 744) * 60,
          summary: { requests: 1, traffic_bytes: 1024, bandwidth_bps: 1024, connections: 1, status_2xx: 1, status_3xx: 0, status_4xx: 0, status_5xx: 0, cache_hits: 1, cache_misses: 0, errors: 0, average_duration_us: 100, origin_connect_us: 10, origin_first_byte_us: 20, origin_total_us: 30 },
          series: [{ bucket: from, requests: 1, traffic_bytes: 1024, bandwidth_bps: 1024, connections: 1,
            cache_hits: 1, cache_misses: 0, cache_hit_bytes: 1024, status_4xx: 0, status_5xx: 0,
            origin_total_us: 30, origin_traffic_bytes: null, origin_bandwidth_bps: null }],
          top: [{ host: 'cdn.example.test', listen_port: 443, requests: 1, traffic_bytes: 1024 }],
          evidence: { access_source_count: 1, connection_source_count: 1, expected_events: 0, observed_events: 1, error_ppm: 0, finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z',
            coverage_from: from, coverage_to: to, snapshot_at: to,
            coverage_complete: true, covered_windows: (Date.parse(to) - Date.parse(from)) / 3_600_000,
            requested_windows: (Date.parse(to) - Date.parse(from)) / 3_600_000, missing_windows: [] },
        },
        meta: { from, to, timezone: 'UTC', metric_version: 1, query_version: 4 },
      }))
    })
    renderWithProviders(<SiteRealtimeMonitorPage />, ['/monitor/site/realtime'])

    expect(await screen.findAllByRole('tab')).toHaveLength(3)
    expect(screen.getByRole('tab', { name: '基础数据' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '质量监控' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '回源监控' })).toBeInTheDocument()
    const qps = screen.getByRole('region', { name: 'QPS' })
    expect(within(qps).getByRole('img')).toHaveTextContent('0.2')
    expect(within(qps).getByRole('img')).toHaveTextContent('1')
  })

  it('keeps the zero baseline and timestamp visible while realtime evidence is unavailable', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'analytics_realtime_evidence_unavailable' },
    }), { status: 503, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<SiteRealtimeMonitorPage />, ['/monitor/site/realtime'])

    expect(await screen.findByText('实时监控证据尚未结算，请稍后重试。')).toBeInTheDocument()
    const bandwidth = screen.getByRole('region', { name: '带宽' })
    const traffic = screen.getByRole('region', { name: '流量' })
    expect(within(bandwidth).getByRole('img')).toHaveTextContent('0.01 Kbps')
    expect(within(traffic).getByRole('img')).toHaveTextContent('0.00 KB')
    expect(within(traffic).getByRole('img')).not.toHaveTextContent('0.01 KB')
    expect(bandwidth.querySelector('.analytics-realtime-series-dot')).toBeInTheDocument()
    expect(bandwidth.querySelector('.analytics-realtime-x-label')).not.toBeEmptyDOMElement()
  })

  it('queries every observed realtime range with the selected time window', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'analytics_realtime_evidence_unavailable' },
    }), { status: 503, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<SiteRealtimeMonitorPage />, ['/monitor/site/realtime'])
    expect(await screen.findByText('实时监控证据尚未结算，请稍后重试。')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    const durationHours = (call: number) => {
      const url = new URL(String(fetchSpy.mock.calls[call]?.[0]), 'https://cdnca.test')
      return (Date.parse(url.searchParams.get('to')!) - Date.parse(url.searchParams.get('from')!)) / 3_600_000
    }
    // fix-rangecompact：快捷项统一为今天/近7天/近30天，默认今天（北京时间 00:00 至当前分钟）。
    const firstFrom = new URL(String(fetchSpy.mock.calls[0]?.[0]), 'https://cdnca.test').searchParams.get('from')!
    expect(new Date(firstFrom).toLocaleTimeString('en-GB', { timeZone: 'Asia/Shanghai', hour12: false })).toBe('00:00:00')

    const user = userEvent.setup()
    await user.click(screen.getByText('近7天'))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(durationHours(1)).toBe(7 * 24)

    await user.click(screen.getByText('近30天'))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(durationHours(2)).toBe(30 * 24)

    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const firstDay = dayjs().startOf('month').format('YYYY-MM-DD')
    await user.click(screen.getAllByRole('button', { name: firstDay })[0])
    await user.click(screen.getAllByRole('button', { name: firstDay })[0])
    await user.click(screen.getByRole('button', { name: '选择时间' }))
    await user.click(within(screen.getByRole('group', { name: '开始时间小时' })).getByRole('button', { name: '08' }))
    await user.click(within(screen.getByRole('group', { name: '结束时间小时' })).getByRole('button', { name: '11' }))
    await user.click(screen.getByRole('button', { name: '确定' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    // The quick ranges also roll every 10 seconds; the custom query is the last call (custom never rolls).
    await waitFor(() => expect(durationHours(fetchSpy.mock.calls.length - 1)).toBe(3))
  })

  it('keeps access log table and toolbar structure separate from the details drawer', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: [accessEvent], meta: accessMeta }))
    renderWithProviders(<SiteAccessLogPage />)

    const table = await screen.findByTestId('analytics-log-table')
    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    expect(within(table).getByText('HTTP/2')).toBeInTheDocument()
    expect(within(table).getByText('text/javascript; charset=utf-8')).toBeInTheDocument()
    expect(within(table).getByText('Mozilla/5.0')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '查询' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '申请下载' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '筛选维度' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '高级筛选' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: '时间范围' })).toBeVisible()
    expect(screen.getByRole('region', { name: '访问日志' })).toBeInTheDocument()
    for (const label of ['站点 ID', '节点 ID', '客户端 IP', '路径', '状态码', '地区代码', '运营商', '请求方法', '协议', '缓存状态', '开始时间', '结束时间']) {
      expect(screen.getByLabelText(label)).toBeInTheDocument()
    }

    expect([...table.querySelectorAll('.ant-table-thead th')].map((cell) => cell.textContent?.trim())).toEqual([
      '时间', '域名', '端口', '协议', '方法', 'URI', '状态码', '客户IP', 'TLS指纹', '地理位置', '运营商',
      '源地址', '内容类型', '来源', '浏览器', '回源耗时', '返回字节', '缓存命中', '操作',
    ])
    expect([...table.querySelectorAll('col')].map((column) => column.getAttribute('style'))).toEqual([
      'width: 150px;', 'width: 200px;', 'width: 70px;', 'width: 100px;', 'width: 100px;', 'width: 200px;',
      'width: 80px;', 'width: 150px;', 'width: 180px;', 'width: 150px;', 'width: 120px;', 'width: 150px;',
      'width: 200px;', 'width: 100px;', 'width: 200px;', 'width: 100px;', 'width: 100px;', 'width: 100px;',
      'width: 130px;',
    ])
  })

  it('keeps the access-log filter bar flexible across desktop and mobile', () => {
    const desktop = lastStyleRule('.analytics-log-page.site-access-log-page .analytics-filter-bar')
    expect(desktop.style.getPropertyValue('display')).toBe('flex')
    expect(desktop.style.getPropertyValue('justify-content')).toBe('space-between')
    expect(desktop.style.getPropertyValue('gap')).toBe('10px')
    const mobile = mediaStyleRules(
      '.analytics-log-page.site-access-log-page .analytics-log-domain-control',
      '(max-width: 600px)',
    ).at(-1)
    expect(mobile?.style.getPropertyValue('width')).toBe('100%')
  })

  it('keeps the blacklist toolbar aligned with the observed reference', async () => {
    authenticate()
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({ data: [], total_count: 0, snapshot_at: '2026-07-28T08:00:00Z' })
    renderWithProviders(<SiteBlockLogPage />, ['/monitor/site/block-log'])

    expect(screen.getByRole('heading', { name: '拉黑日志' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '解锁IP' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '解锁网站' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '导出黑名单' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入IP地址')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入网站ID')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入过滤器ID')).toBeInTheDocument()
  })

  it('keeps the history toolbar aligned with the observed reference', async () => {
    authenticate()
    vi.spyOn(analyticsLogsApi, 'listBlockHistory').mockResolvedValue({ data: [], total_count: 0, snapshot_at: '2026-07-28T08:00:00Z' })
    renderWithProviders(<SiteBlockLogPage />, ['/monitor/site/block-log'])

    await userEvent.setup().click(await screen.findByRole('tab', { name: '历史拉黑' }))

    expect(screen.getByRole('button', { name: '导出黑名单' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解锁IP' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解锁网站' })).not.toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入IP地址')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入网站ID')).toBeInTheDocument()
    expect(screen.getAllByPlaceholderText('选择时间范围')).toHaveLength(1)
    expect(screen.queryByPlaceholderText('请输入过滤器ID')).not.toBeInTheDocument()
    // Keep the clear link beside the inputs even before anything is filtered.
    expect(screen.getByRole('button', { name: '清除' })).toBeInTheDocument()
  })

  it('keeps blacklist top-level tabs aligned with the observed reference', async () => {
    authenticate()
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({ data: [], total_count: 0, snapshot_at: '2026-07-28T08:00:00Z' })
    renderWithProviders(<SiteBlockLogPage />)

    // 三个页签之后追加 CC 自动封禁历史（NF34，c7ed49dc6）。
    expect(await screen.findAllByRole('tab')).toHaveLength(4)
    expect(screen.getByRole('tab', { name: '当前拉黑', selected: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '拉黑统计' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '历史拉黑' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'CC 自动封禁' })).toBeInTheDocument()
  })

  it('keeps blacklist tables inside the shared scrollable statistics shell', () => {
    const table = lastStyleRule('.analytics-log-table')
    expect(table.style.getPropertyValue('max-width')).toBe('100%')
    expect(table.style.getPropertyValue('overflow-x')).toBe('')
    expect(table.style.getPropertyValue('border-top')).toBe('1px solid var(--cdnca-color-border-secondary)')
    const pagination = lastStyleRule('.analytics-log-pagination')
    expect(pagination.style.getPropertyValue('min-width')).toBe('0')

    const mobileTable = mobileStyleRules('.analytics-log-table').at(-1)
    expect(mobileTable?.style.getPropertyValue('max-width')).toBe('100%')
  })

  it('keeps the attack-log page in the shared statistics shell with overview and log detail tabs', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: { attacks: 0, blocked: 0, intercepted: 0, observed: 0, clients: 0, trend: [] },
      meta: { from: '2026-07-28T07:00:00.000Z', to: '2026-07-28T08:00:00.000Z', timezone: 'UTC', metric_version: 1 },
    }))
    renderWithProviders(<WafLogsPage />)

    expect(await screen.findAllByRole('tab')).toHaveLength(2)
    expect(screen.getByRole('tab', { name: '安全概览', selected: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '日志明细' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /查询$/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '更多筛选' })).toBeInTheDocument()
  })

  it('keeps the layer-4 realtime page in the compact statistics shell', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<L4RealtimeMonitorPage />)

    expect(await screen.findByPlaceholderText('输入端口，如88/TCP 99/UDP')).toBeInTheDocument()
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent?.trim())).toEqual(['带宽流量', '端口排行'])
    expect(screen.getByRole('button', { name: /查询$/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新' })).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: '带宽' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '流量' })).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('tab', { name: '端口排行' }))
    expect(screen.getByRole('button', { name: '刷新' })).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalled()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain('/v1/analytics/l4-realtime?')
  })
})
