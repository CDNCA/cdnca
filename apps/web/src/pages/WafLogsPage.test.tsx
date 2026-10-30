import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import WafLogsPage from './WafLogsPage'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function analyticsResponse(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'http://cdnca.test')
  const from = url.searchParams.get('from')!
  const to = url.searchParams.get('to')!
  const meta = { from, to, timezone: 'UTC', metric_version: 1 as const }
  if (url.pathname.endsWith('/waf-overview')) return json({
    data: {
      // The four actions add up to the attack total, as the server guarantees.
      attacks: 12,
      blocked: 6,
      intercepted: 2,
      observed: 3,
      auto_blocked: 1,
      clients: 7,
      trend: [
        { hour: from, attacks: 5, blocked: 3, intercepted: 1, observed: 1, auto_blocked: 0, clients: 4 },
        { hour: new Date(Date.parse(from) + 60 * 60 * 1000).toISOString(), attacks: 7, blocked: 3, intercepted: 1, observed: 2, auto_blocked: 1, clients: 5 },
      ],
      attack_types: [{ key: 'SQL 注入', count: 7 }, { key: 'XSS', count: 5 }],
      top_domains: [{ key: 'cdn.example.test', count: 8 }],
      top_clients: [{ key: '203.0.113.8', count: 7 }],
      top_countries: [{ key: 'CN', count: 6 }],
      top_provinces: [],
      top_carriers: [{ key: 'CMCC', count: 5 }],
      top_uris: [{ key: '/login', count: 4 }],
    },
    meta,
  })
  if (url.pathname.endsWith('/block-events')) return json({ data: blockEvents, meta: { ...logMeta, from, to } })
  return json({ data: [], meta })
}

const logMeta = { timezone: 'UTC', consistency: 'snapshot', replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset', snapshot_at: '2026-07-28T08:00:00Z' }
const blockEvents = [{
  event_id: 'waf-1', occurred_at: '2026-07-28T07:58:00Z', site_id: '018f0000-0000-7000-8000-000000000020', node_id: '018f0000-0000-7000-8000-000000000030',
  request_id: 'waf-request', trace_id: 'waf-trace', config_version_id: '018f0000-0000-7000-8000-000000000040',
  host: 'cdn.example.test', uri_path: '/login', client_ip: '203.0.113.8', country_code: 'CN', carrier: 'CMCC',
  event_type: 'waf', action: 'block', severity: 'high', rule_id: '942100', status_code: 403, request_bytes: 256, response_bytes: 64,
  task_id: null, installation_id: 'inst-1', request_headers: {}, response_headers: {}, request_body: null, response_body: null,
  ja4: null, origin_connect_us: null, origin_first_byte_us: null, origin_total_us: null,
  policy_id: '', detector: 'sqli', matched: "ARGS:id = 1' OR 1=1", user_agent: 'sqlmap/1.7', request_body_excerpt: '', count: 1,
  uri_query: 'id=1', site_domain: 'cdn.example.test', rule_name: 'SQL 注入',
}]

function authenticate(permissions = ['sites.read']) {
  const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('WafLogsPage', () => {
  it('renders the observed overview structure from real WAF breakdown fields', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    renderWithProviders(<WafLogsPage />)

    // 环形图去掉（与攻击类型表重复），总数只在命中概况里出现一次。
    expect(await screen.findByRole('list', { name: '命中概况' })).toHaveTextContent('12')
    expect(screen.getByRole('tab', { name: '安全概览' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '日志明细' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('输入域名，多个空格分隔')).toBeInTheDocument()
    expect(screen.getAllByText('攻击总数')).toHaveLength(2)
    // Summary card and trend legend share the name.
    expect(screen.getAllByText('自动封禁')).toHaveLength(2)
    expect(screen.getByRole('img', { name: '攻击趋势' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '攻击类型分布' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'SQL 注入' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '域名排行' })).toHaveTextContent('cdn.example.test')
    expect(screen.getByRole('region', { name: 'URI排行' })).toHaveTextContent('/login')
    expect(screen.getByRole('region', { name: '省份排行' })).toHaveTextContent('暂无数据')
    // 国家排行显示中文国名，不显示 ISO 代码
    expect(screen.getByRole('region', { name: '国家排行' })).toHaveTextContent('中国')
    expect(screen.getByRole('region', { name: '国家排行' })).not.toHaveTextContent(/^.*\bCN\b/)
    expect(screen.queryByText('查看已结算的安全事件趋势和原始拦截记录。')).not.toBeInTheDocument()

    const initialURL = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(Date.parse(initialURL.searchParams.get('to')!) - Date.parse(initialURL.searchParams.get('from')!)).toBe(24 * 60 * 60 * 1000)
  })

  // An attack type the server could not name never shows the whole UUID.
  it('names an unnamed UUID attack type by its first 8 characters', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const response = analyticsResponse(input)
      if (!new URL(String(input), 'http://cdnca.test').pathname.endsWith('/waf-overview')) return Promise.resolve(response)
      return response.json().then((body) => json({ ...body, data: { ...body.data, attack_types: [
        { key: '50d1c058-f720-5065-87df-f95e7f0a91f1', count: 7 },
        { key: 'aa96383a-a68f-544c-b6c2-69e991717cea', count: 2, name: '敏感路径与漏洞探测（naxsi） · 路径含已知特征 第 2 组' },
      ] } }))
    })
    renderWithProviders(<WafLogsPage />)

    expect(await screen.findByRole('cell', { name: '未命名规则（50d1c058）' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: '敏感路径与漏洞探测（naxsi） · 路径含已知特征 第 2 组' })).toBeInTheDocument()
    expect(screen.queryByText('50d1c058-f720-5065-87df-f95e7f0a91f1')).not.toBeInTheDocument()
  })

  it('keeps invalid overview filters local and sends canonical multi-domain filters', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    const domain = screen.getByPlaceholderText('输入域名，多个空格分隔')
    await user.type(domain, 'not a domain')
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(screen.getByText('请输入最多 64 个有效且不重复的域名，多个域名以空格分隔。')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    await user.clear(domain)
    await user.type(domain, 'CDN.example.test. static.example.test')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(new URL(String(fetchSpy.mock.calls[1][0]), 'http://cdnca.test').searchParams.get('domain')).toBe('cdn.example.test static.example.test')
  })

  it('denies accounts without the WAF read permission without issuing a request', () => {
    authenticate([])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<WafLogsPage />)

    expect(screen.getByText('无权查看 WAF 日志')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('maps an unavailable store to a localized retry state', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ code: 'analytics_store_unavailable' }, 503))
      .mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)

    expect(await screen.findByText('分析存储暂不可用，请稍后重试。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('list', { name: '命中概况' })).toHaveTextContent('12')
  })
})

// 页面重新设计（筛选区 / 命中概况 / 日志表 / 详情抽屉），数据与筛选能力不减。
describe('WafLogsPage redesign', () => {
  it('keeps the time range on the main filter row and folds site and node into 更多筛选', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))

    const filters = screen.getByRole('search', { name: '筛选条件' })
    expect(within(filters).getAllByLabelText('时间范围').length).toBeGreaterThan(0)
    expect(within(filters).queryByPlaceholderText('请输入站点 ID')).not.toBeInTheDocument()
    await user.click(within(filters).getByRole('button', { name: '更多筛选' }))
    expect(within(filters).getByPlaceholderText('请输入站点 ID')).toBeInTheDocument()
    expect(within(filters).getByPlaceholderText('请输入节点 ID')).toBeInTheDocument()
    await user.type(within(filters).getByPlaceholderText('请输入站点 ID'), 'not-a-site')
    await user.click(within(filters).getByRole('button', { name: '查询' }))
    expect(screen.getByText('请输入有效的站点 ID。')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(within(filters).getByRole('button', { name: '更多筛选（1）' })).toBeInTheDocument()
  })

  // 人机验证 joins 拦截/观察/自动封禁; the four counts and shares add up to the total.
  it('shows one summary strip whose action cards and shares add up to the attack total', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    renderWithProviders(<WafLogsPage />)

    const summary = await screen.findByRole('list', { name: '命中概况' })
    expect(within(summary).getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      '攻击总数12', '拦截次数6占 50%', '人机验证2占 16.67%', '观察次数3占 25%', '自动封禁1占 8.33%', '独立客户端IP7',
    ])
    const types = screen.getByRole('region', { name: '攻击类型分布' })
    expect(within(types).queryByRole('img')).not.toBeInTheDocument()
    expect(within(types).getByRole('cell', { name: /SQL 注入/ })).toBeInTheDocument()
    expect(within(types).getByText('58.33%')).toBeInTheDocument()
  })

  // The trend draws all five hit counts; each legend entry is
  // named and colored like its summary card and toggles its line.
  it('draws five trend lines whose legend matches the summary cards and toggles each line', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)

    const summary = await screen.findByRole('list', { name: '命中概况' })
    const trend = screen.getByRole('region', { name: '攻击趋势' })
    const names = ['攻击总数', '拦截次数', '人机验证', '观察次数', '自动封禁']
    const legend = within(trend).getByRole('group', { name: '图例' })
    const entries = within(legend).getAllByRole('button')
    expect(entries.map((entry) => entry.textContent)).toEqual(names)
    const lines = () => Array.from(trend.querySelectorAll('polyline')).map((line) => line.getAttribute('data-series'))
    expect(lines()).toEqual(['attacks', 'blocked', 'challenged', 'observed', 'autoBlocked'])
    expect(trend.querySelector('polyline[data-series="challenged"]')).toHaveAttribute('points', expect.stringContaining(','))

    // Same color variable value on the legend mark, the line and the summary card mark.
    const colors = new Set<string>()
    for (const [index, key] of ['attacks', 'blocked', 'challenged', 'observed', 'autoBlocked'].entries()) {
      const color = (entries[index].querySelector('i') as HTMLElement).style.getPropertyValue('--waf-series-color')
      expect(color).not.toBe('')
      expect((trend.querySelector(`polyline[data-series="${key}"]`) as SVGElement).style.getPropertyValue('--waf-series-color')).toBe(color)
      const card = summary.querySelector(`.waf-v2-summary-item--${key} i`) as HTMLElement
      expect(card.style.getPropertyValue('--waf-series-color')).toBe(color)
      colors.add(color)
    }
    expect(colors.size).toBe(5)

    for (const entry of entries) expect(entry).toHaveAttribute('aria-pressed', 'true')
    await user.click(within(legend).getByRole('button', { name: '人机验证' }))
    expect(within(legend).getByRole('button', { name: '人机验证' })).toHaveAttribute('aria-pressed', 'false')
    expect(lines()).toEqual(['attacks', 'blocked', 'observed', 'autoBlocked'])
    await user.click(within(legend).getByRole('button', { name: '自动封禁' }))
    expect(lines()).toEqual(['attacks', 'blocked', 'observed'])
    await user.click(within(legend).getByRole('button', { name: '人机验证' }))
    expect(lines()).toEqual(['attacks', 'blocked', 'challenged', 'observed'])
  })

  it('opens the log details filtered by a ranked domain or client IP over the same window', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)

    const domains = await screen.findByRole('region', { name: '域名排行' })
    await user.click(within(domains).getByRole('button', { name: '查看 cdn.example.test 的日志' }))
    expect(screen.getByRole('tab', { name: '日志明细' })).toHaveAttribute('aria-selected', 'true')
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/block-events'))).toBe(true))
    const overviewURL = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    const logURL = new URL(String(fetchSpy.mock.calls.find(([input]) => String(input).includes('/block-events'))![0]), 'http://cdnca.test')
    expect(logURL.searchParams.get('host')).toBe('cdn.example.test')
    expect(logURL.searchParams.get('from')).toBe(overviewURL.searchParams.get('from'))
    expect(logURL.searchParams.get('to')).toBe(overviewURL.searchParams.get('to'))

    await user.click(screen.getByRole('tab', { name: '安全概览' }))
    const clients = await screen.findByRole('region', { name: '客户端IP排行' })
    await user.click(within(clients).getByRole('button', { name: '查看 203.0.113.8 的日志' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/block-events'))).toHaveLength(2))
    const ipURL = new URL(String(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/block-events'))[1][0]), 'http://cdnca.test')
    expect(ipURL.searchParams.get('client_ip')).toBe('203.0.113.8')
    expect(ipURL.searchParams.has('host')).toBe(false)
  })

  it('lists events in six merged columns without horizontal scroll and opens grouped details from the row', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)
    await user.click(await screen.findByRole('tab', { name: '日志明细' }))

    const table = await screen.findByTestId('analytics-log-table')
    await within(table).findByText('/login?id=1')
    expect(within(table).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['时间', '网站', '来源', '命中规则', '处置', '操作'])
    expect(within(table).getByText('拦截')).toBeInTheDocument()
    expect(within(table).getByText('Web 应用防火墙 · 高')).toBeInTheDocument()
    expect(within(table).getByText('状态码 403')).toBeInTheDocument()
    expect(table.querySelector('.ant-table-content')?.getAttribute('style') ?? '').not.toContain('overflow-x')

    const filters = screen.getByRole('search', { name: '日志筛选' })
    expect(within(filters).getByLabelText('客户端 IP')).toBeInTheDocument()
    // The rarely used conditions sit in the shared 高级筛选 panel, closed at first.
    expect(within(filters).getByLabelText('状态码')).not.toBeVisible()
    await user.click(within(filters).getByRole('button', { name: '高级筛选' }))
    for (const label of ['站点 ID', '节点 ID', '路径', '状态码', '地区代码', '运营商', 'JA4']) expect(within(filters).getByLabelText(label)).toBeVisible()

    await user.click(within(table).getByText('cdn.example.test'))
    const drawer = await screen.findByRole('dialog')
    for (const heading of ['命中情况', '请求信息', '追踪信息']) expect(within(drawer).getByRole('heading', { name: heading })).toBeInTheDocument()
    expect(within(drawer).getByText("ARGS:id = 1' OR 1=1")).toBeInTheDocument()
    expect(within(drawer).getByText('waf-trace')).toBeInTheDocument()
  })

  // 概览攻击 3、观察 3，明细却为空——明细只查拦截/挑战。
  it('lists observed hits in the details by default and drills each summary metric into its action', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)
    const logURLs = () => fetchSpy.mock.calls.map(([input]) => new URL(String(input), 'http://cdnca.test')).filter((url) => url.pathname.endsWith('/block-events'))

    const summary = await screen.findByRole('list', { name: '命中概况' })
    await user.click(within(summary).getByRole('button', { name: '查看观察次数的日志' }))
    expect(screen.getByRole('tab', { name: '日志明细' })).toHaveAttribute('aria-selected', 'true')
    await waitFor(() => expect(logURLs()).toHaveLength(1))
    expect(logURLs()[0].searchParams.get('action')).toBe('log')
    expect(logURLs()[0].searchParams.get('event_type')).toBe('waf')
    const filters = screen.getByRole('search', { name: '日志筛选' })
    expect(within(filters).getByText('观察')).toBeInTheDocument()

    for (const [label, action] of [['查看拦截次数的日志', 'block'], ['查看人机验证的日志', 'challenge'], ['查看自动封禁的日志', 'temporary_ban'], ['查看攻击总数的日志', null]] as const) {
      await user.click(screen.getByRole('tab', { name: '安全概览' }))
      const strip = await screen.findByRole('list', { name: '命中概况' })
      const before = logURLs().length
      await user.click(within(strip).getByRole('button', { name: label }))
      await waitFor(() => expect(logURLs().length).toBe(before + 1))
      const url = logURLs()[before]
      expect(url.searchParams.get('action')).toBe(action)
      expect(url.searchParams.get('event_type')).toBe('waf')
    }
    await user.click(screen.getByRole('tab', { name: '安全概览' }))
    expect(within(await screen.findByRole('list', { name: '命中概况' })).queryByRole('button', { name: /独立客户端IP/ })).not.toBeInTheDocument()
  })

  it('offers every overview action in the details filter and carries the overview domain list', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(analyticsResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)
    const filters = screen.getByRole('search', { name: '筛选条件' })
    await user.type(within(filters).getByLabelText('域名'), 'a.example.test b.example.test')
    await user.click(within(filters).getByRole('button', { name: '查询' }))
    const summary = await screen.findByRole('list', { name: '命中概况' })
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('domain=a.example.test'))).toBe(true))
    await user.click(within(summary).getByRole('button', { name: '查看攻击总数的日志' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/block-events'))).toBe(true))
    const logURL = new URL(String(fetchSpy.mock.calls.find(([input]) => String(input).includes('/block-events'))![0]), 'http://cdnca.test')
    expect(logURL.searchParams.get('host')).toBe('a.example.test b.example.test')

    const logFilters = screen.getByRole('search', { name: '日志筛选' })
    await user.click(within(logFilters).getByRole('combobox', { name: '动作' }))
    const listbox = await screen.findByRole('listbox')
    expect(within(listbox).getAllByRole('option').map((option) => option.textContent)).toEqual(['全部', '拦截', '人机验证', '观察', '自动封禁'])
    await user.click(screen.getByTitle('观察'))
    await user.click(within(logFilters).getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/block-events'))).toHaveLength(2))
    const observed = new URL(String(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/block-events'))[1][0]), 'http://cdnca.test')
    expect(observed.searchParams.get('action')).toBe('log')
  })
})
