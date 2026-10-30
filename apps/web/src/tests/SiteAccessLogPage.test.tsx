import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import { analyticsLogsApi } from '../api/analyticsLogs'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { analyticsLogExportMessage, analyticsLogExportMessages } from '../i18n/analyticsLogExport'
import siteAccessLogCSSRaw from '../pages/SiteAccessLogPage.css?raw'
import SiteAccessLogPage from '../pages/SiteAccessLogPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultLookCSS } from '../test/defaultLookCSS'

const siteAccessLogCSS = defaultLookCSS(siteAccessLogCSSRaw)

const siteId = '018f0000-0000-7000-8000-000000000020'
const nodeId = '018f0000-0000-7000-8000-000000000030'

function authenticate() {
  const actor = principal({ permissions: ['sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function authenticateAdmin() {
  const actor = principal({
    scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
    permissions: ['platform.admin', 'sites.read'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function renderWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/site/access-logs']}>
            <SiteAccessLogPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function deferredResponse() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>((done) => { resolve = done })
  return { promise, resolve }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function meta(input: RequestInfo | URL, nextCursor?: string) {
  const url = new URL(String(input), 'https://cdnca.test')
  return {
    from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC',
    snapshot_at: '2026-07-28T08:00:00Z', ...(nextCursor ? { next_cursor: nextCursor } : {}),
    consistency: 'snapshot', replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset',
  }
}

function event(eventId: string, path: string) {
  return {
    event_id: eventId, occurred_at: '2026-07-28T07:59:00Z', site_id: siteId, node_id: nodeId,
    request_id: `${eventId}-request`, trace_id: '0af7651916cd43dd8448eb211c80319c',
    config_version_id: '018f0000-0000-7000-8000-000000000040',
    host: 'cdn.example.test', listen_port: 443, uri_path: path, client_ip: '192.0.2.10', country_code: 'CN', carrier: 'CMCC',
    method: 'GET', protocol: 'HTTP/2', cache_status: 'HIT', upstream_result: 'ok', upstream_addr: '', status_code: 200,
    request_bytes: 128, response_bytes: 1024, duration_us: 900,
    task_id: `${eventId}-task`, installation_id: 'installation-authority-1',
    request_headers: { Authorization: '[REDACTED]', 'X-Request-Class': 'asset' },
    response_headers: { 'Set-Cookie': '[REDACTED]' },
    request_body: { token: '[REDACTED]', profile: { name: 'alice' } }, response_body: { cached: true },
    ja4: 't13d1516h2_8daaf6152771', origin_connect_us: 100, origin_first_byte_us: 250, origin_total_us: 400,
  }
}

// LOG-01：日志视图会按当前条件找回导出申请；只统计日志读取。
function logCalls(spy: { mock: { calls: unknown[][] } }): unknown[][] {
  return spy.mock.calls.filter(([input]) => !new URL(String(input), 'https://cdnca.test').pathname.includes('/access/exports'))
}

function page(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'https://cdnca.test')
  if (url.pathname.includes('/access/exports')) return json({ data: [] })
  return url.searchParams.has('cursor')
    ? json({ data: [event('access-page-2', '/second.js')], meta: meta(input) })
    : json({ data: [event('access-page-1', '/asset.js')], meta: meta(input, 'cursor-page-2') })
}

describe('SiteAccessLogPage', () => {
  it('renders the observed administrator access-log baseline with 20 ordered columns', () => {
    authenticateAdmin()
    renderWithProviders(<SiteAccessLogPage />)

    const page = screen.getByRole('region', { name: '访问日志' })
    expect(page).toHaveClass('site-access-log-page')
    expect(within(page).getByRole('tab', { name: '日志查询' })).toHaveAttribute('aria-selected', 'true')
    expect(within(page).getByRole('tab', { name: '申请记录' })).toBeInTheDocument()
    expect(within(page).getByRole('combobox', { name: '筛选维度' })).toBeInTheDocument()
    expect(within(page).getByPlaceholderText('输入域名')).toBeInTheDocument()
    expect(within(page).getByRole('button', { name: '查询' })).toBeInTheDocument()
    expect(within(page).getByRole('button', { name: '申请下载' })).toBeInTheDocument()
    expect(within(page).getByRole('button', { name: '高级筛选' })).toHaveAttribute('aria-expanded', 'false')
    expect(within(page).getByRole('button', { name: '重置' })).toBeVisible()
    expect(within(page).queryByLabelText('开始时间')).not.toBeVisible()
    expect(within(page).queryByLabelText('结束时间')).not.toBeVisible()
    expect(within(page).getByRole('group', { name: '时间范围' })).toBeVisible()

    const headerRow = within(page).getByTestId('analytics-log-table').querySelector('.ant-table-thead > tr')
    expect([...headerRow!.querySelectorAll('th')].map((cell) => cell.textContent?.trim())).toEqual([
      '时间', '域名', '端口', '协议', '方法', 'URI', '状态码', '客户IP', 'TLS指纹', '地理位置', '运营商',
      '源地址', '内容类型', '来源', '浏览器', '回源耗时', '返回字节', '缓存命中', '节点ID', '操作',
    ])
    expect(within(page).getByText('共 0 条')).toBeInTheDocument()
    expect(within(page).getByText('10 条/页')).toBeInTheDocument()
    expect(within(page).queryByText('快照绑定的游标分页')).not.toBeInTheDocument()
    expect(i18n.getFixedT('zh-CN', 'analyticsLogs')('table.nodeId')).toBe('节点ID')
    expect(i18n.getFixedT('en-US', 'analyticsLogs')('table.nodeId')).toBe('Node ID')
    expect(i18n.getFixedT('qps-ploc', 'analyticsLogs')('table.nodeId')).not.toBe('table.nodeId')
    expect(siteAccessLogCSS).toMatch(/analytics-filter-bar[\s\S]+justify-content: space-between;[\s\S]+gap: 10px;[\s\S]+margin-bottom: 14px;/)
    expect(siteAccessLogCSS).toMatch(/analytics-log-search-form[\s\S]+margin: 10px 2px;[\s\S]+padding: 16px 16px 0;[\s\S]+border: 1px solid #edf1f7;[\s\S]+border-radius: 8px;[\s\S]+background: #fbfdff;/)
    expect(siteAccessLogCSS).toMatch(/analytics-log-search-form:hover[\s\S]+border-color: #dfe4ec;/)
    expect(siteAccessLogCSS).toMatch(/analytics-log-pagination[\s\S]+justify-content: flex-end;[\s\S]+margin-top: 20px;/)
    expect(siteAccessLogCSS).toContain('flex: 0 0 320px;')
    expect(siteAccessLogCSS).toContain('@media (max-width: 600px)')
  })

  it('defaults to the current local day and sends the same visible range', async () => {
    const now = new Date(2026, 8, 1, 15, 37, 42)
    const from = new Date(2026, 8, 1)
    const to = new Date(2026, 8, 2)
    vi.spyOn(Date, 'now').mockReturnValue(now.getTime())
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))

    renderWithProviders(<SiteAccessLogPage />)

    const range = screen.getByRole('group', { name: '时间范围' })
    expect(range).toHaveTextContent('时间范围')
    expect(range).toHaveTextContent('2026')
    expect(screen.getByLabelText('开始时间')).toHaveValue('2026-09-01T00:00')
    expect(screen.getByLabelText('结束时间')).toHaveValue('2026-09-02T00:00')
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const request = new URL(String(logCalls(fetchSpy)[0]![0]), 'https://cdnca.test')
    expect(request.searchParams.get('from')).toBe(from.toISOString())
    expect(request.searchParams.get('to')).toBe(to.toISOString())
  })

  it('masks UUID-only site and node references in log tables while retaining the technical value', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    renderWithProviders(<SiteAccessLogPage />)
    const user = userEvent.setup()
    fireEvent.change(screen.getByLabelText('租户 ID'), { target: { value: '018f0000-0000-7000-8000-000000000010' } })
    fireEvent.change(screen.getByLabelText('域名'), { target: { value: 'cdn.example.test' } })
    await user.click(screen.getByRole('button', { name: '查询' }))

    const table = await screen.findByTestId('analytics-log-table')
    const row = await within(table).findByRole('row', { name: /cdn\.example\.test/ })
    const nodeReference = within(row).getByLabelText(nodeId)
    expect(nodeReference).toHaveTextContent('—')
    expect(nodeReference).toHaveAttribute('title', nodeId)
    expect(within(table).queryByText(nodeId)).not.toBeInTheDocument()
  })

  it('names the node and marks requests that never reached the origin', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json({
      data: [
        { ...event('access-origin', '/ok'), node_name: 'C202610150242321', upstream_addr: '10.0.0.1:80, 10.0.0.2:80' },
        // 套餐过期页/拦截页：未回源，回源耗时为 null、上游结果为空
        { ...event('access-local', '/blocked'), host: 'local.example.test', status_code: 403, cache_status: 'BYPASS', upstream_result: '',
          origin_connect_us: null, origin_first_byte_us: null, origin_total_us: null, node_name: '' },
      ],
      meta: meta(input),
    })))
    renderWithProviders(<SiteAccessLogPage />)
    const user = userEvent.setup()
    fireEvent.change(screen.getByLabelText('租户 ID'), { target: { value: '018f0000-0000-7000-8000-000000000010' } })
    fireEvent.change(screen.getByLabelText('域名'), { target: { value: 'cdn.example.test' } })
    await user.click(screen.getByRole('button', { name: '查询' }))

    const table = await screen.findByTestId('analytics-log-table')
    const named = await within(table).findByRole('row', { name: /cdn\.example\.test/ })
    expect(within(named).getByText('C202610150242321')).toHaveAttribute('title', nodeId)
    expect(within(named).getByText('400 微秒')).toBeInTheDocument()
    // 源地址列读回源地址 upstream_addr，不显示诊断码 upstream_result
    expect(within(named).getByText('10.0.0.1:80, 10.0.0.2:80')).toBeInTheDocument()
    expect(within(named).queryByText('ok')).not.toBeInTheDocument()

    const local = within(table).getByRole('row', { name: /local\.example\.test/ })
    expect(within(local).getAllByText('未回源')).toHaveLength(2)
    expect(within(local).queryByText(/微秒/)).not.toBeInTheDocument()
    // 节点已删除（名称为空）时退回 UUID 占位
    expect(within(local).getByLabelText(nodeId)).toHaveTextContent('—')
  })

  it('keeps the applied time range readable and folds the other conditions into 高级筛选', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    renderWithProviders(<SiteAccessLogPage />)
    const user = userEvent.setup()

    const toggle = screen.getByRole('button', { name: '高级筛选' })
    expect(screen.getByRole('button', { name: '重置' })).toBeVisible()
    expect(screen.queryByLabelText('开始时间')).not.toBeVisible()
    expect(screen.getByLabelText('状态码')).not.toBeVisible()
    expect(screen.getByRole('group', { name: '时间范围' })).toHaveTextContent('时间范围')

    await user.click(toggle)
    const panel = screen.getByRole('group', { name: '高级筛选' })
    // The access log keeps its own from/to control, now inside the panel.
    expect(within(panel).getByLabelText('开始时间')).toBeVisible()
    expect(within(panel).getByLabelText('结束时间')).toBeVisible()
    for (const label of ['租户 ID', '站点 ID', '节点 ID', '客户端 IP', '路径', '状态码', '地区代码', '运营商', '请求方法', '协议', '缓存状态']) {
      expect(within(panel).getByLabelText(label)).toBeVisible()
    }

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    await user.type(within(panel).getByLabelText('状态码'), '404')
    await user.click(within(panel).getByRole('button', { name: '应用' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(new URL(String(fetchSpy.mock.calls.at(-1)![0]), 'https://cdnca.test').searchParams.get('status_code')).toBe('404')
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '移除条件 状态码' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(new URL(String(fetchSpy.mock.calls.at(-1)![0]), 'https://cdnca.test').searchParams.has('status_code')).toBe(false)
    expect(screen.getByRole('button', { name: '高级筛选' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    expect(screen.getByRole('button', { name: '高级筛选' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByLabelText('开始时间')).not.toBeVisible()
  })

  it('submits both time bounds after querying from the observed search field', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(screen.queryByLabelText('开始时间')).not.toBeVisible()
    expect(screen.getByRole('group', { name: '时间范围' })).toBeVisible()

    await user.type(screen.getByPlaceholderText('输入域名'), 'cdn.example.test{Enter}')

    await waitFor(() => expect(logCalls(fetchSpy)).toHaveLength(2))
    const request = new URL(String(logCalls(fetchSpy).at(-1)![0]), 'https://cdnca.test')
    expect(request.searchParams.get('host')).toBe('cdn.example.test')
    expect(request.searchParams.get('from')).not.toBeNull()
    expect(request.searchParams.get('to')).not.toBeNull()
  })

  it('sends the cache status selected from the observed quick-filter dropdown', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    // The platform view loads on entry without a tenant (stats-platform-l7).
    await waitFor(() => expect(logCalls(fetchSpy)).toHaveLength(1))
    const initial = new URL(String(logCalls(fetchSpy)[0]![0]), 'https://cdnca.test')
    expect(initial.pathname).toBe('/v1/admin/analytics/logs/access')
    expect(initial.searchParams.has('tenant_id')).toBe(false)
    await user.click(screen.getByRole('combobox', { name: '筛选维度' }))
    await user.click(screen.getByRole('option', { name: '缓存状态' }))
    await user.click(screen.getByRole('combobox', { name: '缓存状态' }))
    await user.click(screen.getByRole('option', { name: '命中' }))
    await user.click(screen.getByRole('button', { name: '查询' }))

    await waitFor(() => expect(logCalls(fetchSpy)).toHaveLength(2))
    const request = new URL(String(logCalls(fetchSpy).at(-1)![0]), 'https://cdnca.test')
    expect(request.searchParams.get('cache_status')).toBe('HIT')
    expect(request.searchParams.has('tenant_id')).toBe(false)
  })

  it.each([
    ['a tenant without sites.read', principal({ permissions: [] })],
    ['a platform without sites.read', principal({
      scope_kind: 'platform', scope_id: '33333333-3333-4333-8333-333333333333', tenant_id: null,
      roles: ['platform_admin'], permissions: [],
    })],
    ['a tenant without a scope identity', principal({ scope_id: '', permissions: ['sites.read'] })],
    ['a tenant with a blank scope identity', principal({
      scope_id: '   ', tenant_id: '   ', permissions: ['sites.read'],
    })],
    ['a tenant with a blank user identity', principal({ user_id: '   ', permissions: ['sites.read'] })],
    ['a platform with a blank scope identity', principal({
      scope_kind: 'platform', scope_id: '   ', tenant_id: null, permissions: ['sites.read'],
    })],
    ['a platform with a blank user identity', principal({
      scope_kind: 'platform', tenant_id: null, user_id: '   ', permissions: ['sites.read'],
    })],
  ])('fails closed with local RBAC and zero requests for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('无权查看日志')).toBeInTheDocument()
    expect(screen.getByText('当前账户没有此范围的日志读取权限。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps applied filters, page, detail, and token-free owner cache identity across a same-epoch token refresh', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    const oldToken = 'site-access-old-token'
    const newToken = 'site-access-new-token'
    useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: oldToken }, actor,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.type(screen.getByLabelText('站点 ID'), siteId)
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(logCalls(fetchSpy)).toHaveLength(2))
    await user.click(screen.getAllByRole('button', { name: '详情' })[0])
    expect(await screen.findByText('access-page-1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('/second.js')).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(screen.getByText('access-page-1-request')).toBeInTheDocument()
    const readsBeforeRefresh = logCalls(fetchSpy).length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken }, actor, 'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByText('/second.js')).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(screen.getByText('access-page-1-request')).toBeInTheDocument()
    expect(logCalls(fetchSpy)).toHaveLength(readsBeforeRefresh)
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    const ownerTuple = ['tenant', actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch]
    expect(queryKeys.some((key) => JSON.stringify(key).includes(JSON.stringify(ownerTuple)))).toBe(true)
    for (const key of queryKeys) {
      expect(JSON.stringify(key)).not.toContain(oldToken)
      expect(JSON.stringify(key)).not.toContain(newToken)
    }
    const filteredRead = fetchSpy.mock.calls
      .map(([input]) => new URL(String(input), 'https://cdnca.test'))
      .find((url) => url.searchParams.get('site_id') === siteId)
    expect(filteredRead?.searchParams.has('tenant_id')).toBe(false)
  }, 20_000)

  it('clears prior owner cache and detail state, then ignores a late prior-session response', async () => {
    const tenantA = principal({ permissions: ['sites.read'] })
    const tenantB = principal({
      scope_id: '99999999-9999-4999-8999-999999999999',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['sites.read'],
    })
    const late = deferredResponse()
    let tenantAReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      const url = String(input)
      // LOG-01：按条件找回导出申请单独应答，只统计日志读取。
      if (url.includes('/access/exports')) return Promise.resolve(json({ data: [] }))
      if (authorization === 'Bearer tenant-a-log-token') {
        tenantAReads += 1
        return tenantAReads === 1 ? Promise.resolve(page(input)) : late.promise
      }
      if (authorization === 'Bearer tenant-b-log-token') {
        return Promise.resolve(json({ data: [], meta: meta(input) }))
      }
      throw new Error(`unexpected analytics log request ${authorization} ${url}`)
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-log-token' }, tenantA,
    )
    const user = userEvent.setup()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    renderWithQueryClient(queryClient)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '详情' })[0])
    expect(await screen.findByText('access-page-1-request')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(tenantAReads).toBe(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-log-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.queryByText('/asset.js')).not.toBeInTheDocument()
    expect(screen.queryByText('access-page-1-request')).not.toBeInTheDocument()

    await act(async () => {
      late.resolve(page('/v1/analytics/logs/access?cursor=late'))
      await late.promise
    })

    expect(screen.queryByText('/second.js')).not.toBeInTheDocument()
    expect(screen.queryByText('access-page-2-request')).not.toBeInTheDocument()
    const cache = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => ({
      key: query.queryKey,
      data: query.state.data,
    })))
    expect(cache).not.toContain('/asset.js')
    expect(cache).not.toContain('/second.js')
    expect(logCalls(fetchSpy).filter(([, init]) => (
      new Headers((init as RequestInit | undefined)?.headers).get('Authorization') === 'Bearer tenant-b-log-token'
    ))).toHaveLength(1)
  }, 20_000)

  it('applies the host and path of a ranking row it was opened from', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    renderWithProviders(<SiteAccessLogPage />, ['/monitor/site/access-log?host=x.example&uri_path=%2Fa%2Fb'])
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const request = new URL(String(logCalls(fetchSpy)[0]![0]), 'https://cdnca.test')
    expect([request.searchParams.get('host'), request.searchParams.get('uri_path')]).toEqual(['x.example', '/a/b'])
  })

  // TEL-UX-DRILL：分析页下钻带来的时间、IP、TLS 指纹、地区、运营商、站点/节点原样生效并显示成标签。
  it('applies every drill-down condition from the analysis page and labels it (TEL-UX-DRILL)', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const from = '2026-07-22T09:50:00.000Z'
    const to = '2026-07-22T10:00:00.000Z'
    const query = new URLSearchParams({ from, to, host: 'a.example b.example', client_ip: '203.0.113.7', ja4: 't13d1516h2_8daaf6152771_02713d6af862',
      country_code: 'CN', carrier: '电信', site_id: siteId, node_id: nodeId })
    renderWithProviders(<SiteAccessLogPage />, [`/monitor/site/access-log?${query}`])
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const request = new URL(String(fetchSpy.mock.calls[0]![0]), 'https://cdnca.test').searchParams
    expect(Object.fromEntries(['from', 'to', 'host', 'client_ip', 'ja4', 'country_code', 'carrier', 'site_id', 'node_id'].map((key) => [key, request.get(key)])))
      .toEqual({ from, to, host: 'a.example b.example', client_ip: '203.0.113.7', ja4: 't13d1516h2_8daaf6152771_02713d6af862',
        country_code: 'CN', carrier: '电信', site_id: siteId, node_id: nodeId })
    const tags = screen.getByRole('group', { name: '时间范围' })
    expect(within(tags).getByText('203.0.113.7')).toBeInTheDocument()
    expect(within(tags).getByText('a.example b.example')).toBeInTheDocument()
  })

  // 无效下钻条件不能悄悄放宽成全部日志：不查询，提示条件无效。
  it('refuses an invalid drill-down condition instead of widening the query (TEL-UX-DRILL)', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    renderWithProviders(<SiteAccessLogPage />, ['/monitor/site/access-log?host=bad_host&from=2026-07-22T09:50:00.000Z&to=2026-07-22T10:00:00.000Z'])
    expect(await screen.findByText('请输入有效的域名。')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/logs/access'))).toHaveLength(0)
  })

  it('sends a prefix URI path match selected beside the path filter (FX29/NF17)', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.type(screen.getByLabelText('路径'), '/asset')
    await user.click(screen.getByRole('combobox', { name: '路径匹配', hidden: true }))
    await user.click(screen.getByRole('option', { name: '前缀匹配' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(new URL(String(logCalls(fetchSpy).at(-1)![0]), 'https://cdnca.test')
      .searchParams.get('uri_path_match')).toBe('prefix'))
    expect(new URL(String(logCalls(fetchSpy).at(-1)![0]), 'https://cdnca.test').searchParams.get('uri_path')).toBe('/asset')
  }, 45_000)

  it('queries real tenant filters, pages with the opaque cursor, and opens exact event details', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    // #48②：有下一页时不是精确总数，写明总数未统计。
    expect(screen.getByText('已加载 1 条，还有更多，总数未统计')).toBeInTheDocument()
    await user.type(screen.getByLabelText('站点 ID'), siteId)
    await user.type(screen.getByLabelText('客户端 IP'), '192.0.2.10')
    await user.type(screen.getByLabelText('路径'), '/asset.js')
    await user.type(screen.getByLabelText('状态码'), '200')
    await user.type(screen.getByLabelText('请求方法'), 'get')
    await user.type(screen.getByLabelText('JA4'), 't13d1516h2_8daaf6152771')
    await user.click(screen.getByRole('button', { name: '查询' }))

    await waitFor(() => expect(logCalls(fetchSpy)).toHaveLength(2))
    const filtered = new URL(String(logCalls(fetchSpy).at(-1)![0]), 'https://cdnca.test')
    expect(filtered.pathname).toBe('/v1/analytics/logs/access')
    expect(filtered.searchParams.get('site_id')).toBe(siteId)
    expect(filtered.searchParams.get('client_ip')).toBe('192.0.2.10')
    expect(filtered.searchParams.get('uri_path')).toBe('/asset.js')
    expect(filtered.searchParams.has('uri_path_match')).toBe(false)
    expect(filtered.searchParams.get('status_code')).toBe('200')
    expect(filtered.searchParams.get('method')).toBe('GET')
    expect(filtered.searchParams.get('ja4')).toBe('t13d1516h2_8daaf6152771')
    expect(filtered.searchParams.has('tenant_id')).toBe(false)

    await user.click(screen.getAllByRole('button', { name: '详情' })[0])
    expect(await screen.findByText('access-page-1')).toBeInTheDocument()
    expect(within(screen.getByTestId('analytics-log-table')).getByText('HTTP/2')).toBeInTheDocument()
    expect(screen.getByText('access-page-1-request')).toBeInTheDocument()
    expect(screen.getByText('0af7651916cd43dd8448eb211c80319c')).toBeInTheDocument()
    expect(screen.getByText('018f0000-0000-7000-8000-000000000040')).toBeInTheDocument()
    expect(screen.getByText('access-page-1-task')).toBeInTheDocument()
    expect(screen.getByText(/X-Request-Class/)).toBeInTheDocument()
    expect(screen.getByText(/"name":"alice"/)).toBeInTheDocument()
    expect(within(screen.getByTestId('analytics-log-table')).getByText('t13d1516h2_8daaf6152771')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('/second.js')).toBeInTheDocument()
    const second = new URL(String(logCalls(fetchSpy).at(-1)![0]), 'https://cdnca.test')
    expect(second.searchParams.get('cursor')).toBe('cursor-page-2')
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '上一页' }))
    expect((await screen.findAllByText('/asset.js')).length).toBeGreaterThan(0)
    expect(logCalls(fetchSpy)).toHaveLength(3)
  })

  it('shows no always-empty L1/L2 cache-tier columns to any audience', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)
    fireEvent.change(screen.getByLabelText('租户 ID'), { target: { value: '018f0000-0000-7000-8000-000000000010' } })
    fireEvent.change(screen.getByLabelText('域名'), { target: { value: 'cdn.example.test' } })
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    for (const name of ['L1缓存命中', 'L2缓存命中', 'L2 IP']) {
      expect(screen.queryByRole('columnheader', { name })).not.toBeInTheDocument()
    }
  })

  it('recursively redacts sensitive capture keys before details enter the DOM', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const rawPage = await page('/v1/analytics/logs/access?from=2026-07-28T07%3A00%3A00Z&to=2026-07-28T08%3A00%3A00Z').json() as {
      data: Array<Record<string, unknown>>
      meta: Record<string, unknown>
    }
    Object.assign(rawPage.data[0]!, {
      request_headers: { Authorization: 'Bearer raw-access-secret', 'X-Benign-Fact': 'asset' },
      response_headers: { 'Set-Cookie': 'session=raw-cookie', 'X-Cache-Fact': 'HIT' },
      request_body: {
        accessToken: 'raw-access-token',
        profile: { name: 'alice', password: 'raw-password' },
        facts: { rule: 'asset' },
      },
      response_body: { api_key: 'raw-api-key', cached: true },
    })
    vi.spyOn(analyticsLogsApi, 'listAccess').mockResolvedValue(rawPage as never)
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))

    expect(await screen.findByText(/"X-Benign-Fact":"asset"/)).toBeInTheDocument()
    expect(screen.getByText(/"name":"alice"/)).toBeInTheDocument()
    expect(screen.getByText(/"rule":"asset"/)).toBeInTheDocument()
    expect(screen.getByText(/"cached":true/)).toBeInTheDocument()
    expect(screen.getAllByText(/已脱敏/).length).toBeGreaterThanOrEqual(4)
    expect(document.body).not.toHaveTextContent(/raw-access-secret|raw-cookie|raw-access-token|raw-password|raw-api-key/)
  })

  it('closes stale detail when filters or cursor pages change', async () => {
    authenticate()
    const filteredSiteId = '018f0000-0000-7000-8000-000000000021'
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.searchParams.get('cursor') === 'cursor-page-2') {
        return Promise.resolve(json({ data: [event('access-page-2', '/second.js')], meta: meta(input) }))
      }
      return Promise.resolve(json({ data: [event('access-page-1', '/asset.js')], meta: meta(input, 'cursor-page-2') }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByRole('dialog', { name: '日志详情' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('/second.js')).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: '日志详情' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '上一页' }))
    expect((await screen.findAllByText('/asset.js')).length).toBeGreaterThan(0)
    expect(screen.getByRole('dialog', { name: '日志详情' })).toBeInTheDocument()

    await user.clear(screen.getByLabelText('站点 ID'))
    await user.type(screen.getByLabelText('站点 ID'), filteredSiteId)
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect((await screen.findAllByText('/asset.js')).length).toBeGreaterThan(0)
    expect(screen.queryByRole('dialog', { name: '日志详情' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByRole('dialog', { name: '日志详情' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('站点 ID'), { target: { value: filteredSiteId } })
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(screen.queryByRole('dialog', { name: '日志详情' })).not.toBeInTheDocument()
  })

  it('keeps the table mounted through localized loading and empty states', async () => {
    authenticate()
    let resolve!: (response: Response) => void
    let input!: RequestInfo | URL
    vi.spyOn(globalThis, 'fetch').mockImplementation((request) => {
      input = request
      return new Promise((done) => { resolve = done })
    })
    renderWithProviders(<SiteAccessLogPage />)

    expect(screen.getByTestId('analytics-log-table')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByTestId('analytics-log-table')).toHaveAttribute('aria-label', '正在加载日志')
    await act(async () => resolve(json({ data: [], meta: meta(input) })))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(screen.getByTestId('analytics-log-table')).toHaveAttribute('aria-busy', 'false')
  })

  it.each([
    [400, 'analytics_logs_invalid_request', '筛选条件或分页游标无效。'],
    [404, 'analytics_logs_route_not_found', '日志查询接口不存在。'],
    [422, 'analytics_logs_capability_unsupported', '当前日志能力不可用。'],
    [503, 'analytics_logs_storage_unavailable', '日志存储暂不可用，请稍后重试。'],
    [504, 'analytics_logs_query_timeout', '查询超时，请缩小时间范围后重试。'],
    [500, 'request_failed', '日志加载失败，请稍后重试。'],
  ])('maps status %s without leaking server messages', async (status, errorCode, expected) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: errorCode, message: 'private storage detail', request_id: `request-${status}` },
    }, status))
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(screen.queryByText('private storage detail')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()
  })

  it('localizes a network failure and recovers through retry without exposing private details', async () => {
    authenticate()
    let retryInput!: RequestInfo | URL
    let resolveRetry!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new Error('private ClickHouse host'))
      .mockImplementationOnce((input) => {
        retryInput = input
        return new Promise((resolve) => { resolveRetry = resolve })
      })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('日志加载失败，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByText('private ClickHouse host')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))

    await waitFor(() => expect(screen.getByTestId('analytics-log-table')).toHaveAttribute('aria-busy', 'true'))
    await act(async () => resolveRetry(page(retryInput)))
    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    expect(logCalls(fetchSpy)).toHaveLength(2)
    expect(screen.queryByText('日志加载失败，请稍后重试。')).not.toBeInTheDocument()
  })

  it.each(['en-US', 'qps-ploc'] as const)('keeps the stable invalid-request code local in %s', async (locale) => {
    await changeLocale(locale)
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'analytics_logs_invalid_request', message: 'private English validator detail' },
    }, 400))
    renderWithProviders(<SiteAccessLogPage />)

    const t = i18n.getFixedT(locale, 'analyticsLogs')
    expect(await screen.findByText(t('states.invalidRequest'))).toBeInTheDocument()
    expect(screen.queryByText('private English validator detail')).not.toBeInTheDocument()
    expect(screen.queryByText(t('states.empty'))).not.toBeInTheDocument()
  })

  it('renders API permission denial separately', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'analytics_logs_permission_denied', message: 'private permission detail', request_id: 'request-403' },
    }, 403))
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('无权查看日志')).toBeInTheDocument()
    expect(screen.getByText('当前账户没有此范围的日志读取权限。')).toBeInTheDocument()
    expect(screen.queryByText('private permission detail')).not.toBeInTheDocument()
  })

  it('rejects status zero for access logs before fetch', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: [], meta: {} }))
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    await waitFor(() => expect(logCalls(fetchSpy)).toHaveLength(1))
    fetchSpy.mockClear()
    await user.type(screen.getByLabelText('状态码'), '0')
    await user.click(screen.getByRole('button', { name: '查询' }))

    expect(screen.getByText('状态码必须是 100 到 599 的整数。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each(['/private?token=secret', '/private#fragment', 'private'])('rejects invalid URI filter %s before fetch', async (uriPath) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(analyticsLogsApi.listAccess('access-token', 'tenant', {
      from: '2026-07-28T07:00:00Z', to: '2026-07-28T08:00:00Z', uriPath,
    }, 20)).rejects.toMatchObject({ status: 400, code: 'analytics_logs_invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('serializes JA4 and all origin timing ranges without changing the opaque cursor', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(page(input)))
    const filters = {
      from: '2026-07-28T07:00:00Z', to: '2026-07-28T08:00:00Z', ja4: 't13d1516h2_8daaf6152771',
      originConnectUsMin: 100, originConnectUsMax: 200,
      originFirstByteUsMin: 250, originFirstByteUsMax: 300,
      originTotalUsMin: 400, originTotalUsMax: 500,
    }

    await expect(analyticsLogsApi.listAccess('access-token', 'tenant', filters, 20, 'cursor +/=='))
      .resolves.toMatchObject({ data: [{ installation_id: 'installation-authority-1', response_body: { cached: true } }] })
    const url = new URL(String(logCalls(fetchSpy)[0][0]), 'https://cdnca.test')
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      ja4: filters.ja4, origin_connect_us_min: '100', origin_connect_us_max: '200',
      origin_first_byte_us_min: '250', origin_first_byte_us_max: '300',
      origin_total_us_min: '400', origin_total_us_max: '500', cursor: 'cursor +/==',
    })
  })

  it.each([
    ['negative origin minimum', { originConnectUsMin: -1 }],
    ['fractional origin minimum', { originConnectUsMin: 1.5 }],
    ['reversed origin range', { originConnectUsMin: 2, originConnectUsMax: 1 }],
    ['overlong JA4', { ja4: 'x'.repeat(129) }],
  ])('rejects %s before fetch', async (_name, replacement) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(analyticsLogsApi.listAccess('access-token', 'tenant', {
      from: '2026-07-28T07:00:00Z', to: '2026-07-28T08:00:00Z', ...replacement,
    }, 20)).rejects.toMatchObject({ status: 400, code: 'analytics_logs_invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['non-IP client address', { client_ip: 'not-an-ip' }],
    ['invalid calendar date', { occurred_at: '2026-02-30T07:59:00Z' }],
    ['URI query string', { uri_path: '/private?token=secret' }],
    ['URI fragment', { uri_path: '/private#token=secret' }],
    ['non-string captured header', { request_headers: { Authorization: 7 } }],
    ['array captured body', { request_body: ['not', 'an', 'object'] }],
    ['unsafe origin timing', { origin_total_us: Number.MAX_SAFE_INTEGER + 1 }],
    ['missing installation authority', { installation_id: undefined }],
  ])('rejects a %s in an otherwise valid API response', async (_name, replacement) => {
    const filters = { from: '2026-07-28T07:00:00Z', to: '2026-07-28T08:00:00Z' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [{ ...event('invalid-event', '/invalid'), ...replacement }],
      meta: {
        from: filters.from, to: filters.to, timezone: 'UTC', consistency: 'snapshot',
        replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset',
      },
    }))

    await expect(analyticsLogsApi.listAccess('access-token', 'tenant', filters, 20))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('creates a durable export from the applied filters and renders its downloadable status', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const exportID = '018f0000-0000-7000-8000-000000000077'
    const job = {
      id: exportID, status: 'completed', reason: 'completed', snapshot_at: '2026-07-28T08:00:00Z',
      row_count: 1, byte_count: 256, sha256: 'a'.repeat(64), created_at: '2026-07-28T08:00:01Z',
      expires_at: '2999-07-28T09:00:01Z', downloadable: true,
      filter: { from: '2026-07-28T00:00:00Z', to: '2026-07-29T00:00:00Z', host: 'a.example', client_ip: '203.0.113.7', status_code: 404 },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/access/exports') && init?.method === 'POST') return Promise.resolve(json(job, 202))
      if (url.pathname.endsWith('/access/exports')) return Promise.resolve(json({ data: [job] }))
      return Promise.resolve(page(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '时间' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '申请下载' }))
    expect(await screen.findByText('可下载')).toBeInTheDocument()
    // live-click-B W3：申请记录首列是导出 ID，不是日志事件 ID。
    expect(screen.getByRole('columnheader', { name: '导出 ID' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: i18n.t('analyticsLogs:detail.eventId') })).not.toBeInTheDocument()
    // LOG-02：短编号可辨认（不再是破折号），完整编号在提示与无障碍名称里
    const exportReference = screen.getByLabelText(exportID)
    expect(exportReference).toHaveTextContent(exportID.slice(0, 8))
    expect(exportReference).toHaveAttribute('title', exportID)
    // LOG-02：原查询摘要来自服务端冻结的条件，不是当前页面条件
    expect(screen.getByRole('columnheader', { name: '原查询条件' })).toBeInTheDocument()
    expect(screen.getByText('域名：a.example；客户端 IP：203.0.113.7；状态码：404')).toBeInTheDocument()
    const create = fetchSpy.mock.calls.find(([input, init]) => String(input).includes('/access/exports') && init?.method === 'POST')
    expect(create).toBeDefined()
    expect(new Headers(create?.[1]?.headers).get('Idempotency-Key')).toMatch(/^access-export-/)
  })

  // fp-site LOG-01：申请结果未知时在日志视图就地显示，只能原请求重试（同一幂等键、同一条件），双击也只发一份
  it('shows an unknown export request in the log view and retries it with the same key', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const job = {
      id: '018f0000-0000-7000-8000-000000000078', status: 'pending', reason: 'created', snapshot_at: null,
      row_count: null, byte_count: null, created_at: '2026-07-28T08:00:01Z', expires_at: null, downloadable: false, filter: null,
    }
    let posts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/access/exports') && init?.method === 'POST') {
        posts += 1
        return posts === 1 ? Promise.reject(new TypeError('network down')) : Promise.resolve(json(job, 202))
      }
      if (url.pathname.endsWith('/access/exports')) return Promise.resolve(json({ data: [job] }))
      return Promise.resolve(page(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)
    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '申请下载' }))
    expect(await screen.findByText(/申请结果未知/)).toBeInTheDocument()
    expect(screen.getByText('/asset.js')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '申请下载' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '用原请求重试' }))
    expect(await screen.findByText('等待处理')).toBeInTheDocument()
    const creates = fetchSpy.mock.calls.filter(([input, init]) => String(input).includes('/access/exports') && init?.method === 'POST')
    expect(creates).toHaveLength(2)
    expect(new Headers(creates[1]?.[1]?.headers).get('Idempotency-Key')).toBe(new Headers(creates[0]?.[1]?.headers).get('Idempotency-Key'))
    expect(creates[1]?.[1]?.body).toBe(creates[0]?.[1]?.body)
  })

  // fp-site LOG-02：申请记录显示申请时间、条数/大小、到期；失败给原因和重新申请
  it('lists export time, size, expiry and a failure reason with a request-again action', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const failed = {
      id: '018f0000-0000-7000-8000-000000000079', status: 'failed', reason: 'invalid_filter', snapshot_at: null,
      row_count: null, byte_count: null, created_at: '2026-07-28T08:00:01Z', expires_at: null, downloadable: false, filter: null,
    }
    const done = {
      id: '018f0000-0000-7000-8000-000000000080', status: 'completed', reason: 'completed', snapshot_at: '2026-07-28T08:00:00Z',
      row_count: 1200, byte_count: 2048, created_at: '2026-07-28T08:00:01Z', expires_at: '2999-01-01T00:00:00Z', downloadable: true, filter: null,
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/access/exports') && init?.method === 'POST') return Promise.resolve(json(done, 202))
      if (url.pathname.endsWith('/access/exports')) return Promise.resolve(json({ data: [failed, done] }))
      return Promise.resolve(page(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)
    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '申请下载' }))
    expect(await screen.findByText('查询条件无效，请调整后重新申请')).toBeInTheDocument()
    for (const name of ['申请时间', '条数 / 大小', '下载到期']) expect(screen.getByRole('columnheader', { name })).toBeInTheDocument()
    expect(screen.getByText(/1,200 \//)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '按当前条件重新申请' })).toBeInTheDocument()
  })

  // 重新登录（全新页面、无内存状态）后日志视图按当前条件找回原申请，就地显示失败原因；
  // 重试用同一幂等键（由原申请编号决定）与同一条件，再次重试也不换键。
  it('finds the existing export for the applied filters after relogin and retries a failure in place with one key', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const failedID = '018f0000-0000-7000-8000-000000000081'
    const failed = {
      id: failedID, status: 'failed', reason: 'export_rejected', snapshot_at: null,
      row_count: null, byte_count: null, created_at: '2026-07-28T08:00:01Z', expires_at: null, downloadable: false,
      // 导出记录带回原查询条件（null 表示旧记录无摘要）。
      filter: null,
    }
    let posts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/access/exports') && init?.method === 'POST') {
        posts += 1
        return posts === 1 ? Promise.resolve(json({ error: { code: 'unavailable', message: 'down' } }, 503))
          : Promise.resolve(json({ ...failed, status: 'pending', reason: 'retried' }, 202))
      }
      if (url.pathname.endsWith('/access/exports')) {
        return Promise.resolve(json({ data: url.searchParams.has('from') ? [failed] : [] }))
      }
      return Promise.resolve(page(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)
    expect(await screen.findByText('/asset.js')).toBeInTheDocument()
    const status = await screen.findByText(/当前条件已有下载申请/)
    expect(status.closest('[role="status"]')).toHaveTextContent('生成被拒绝（超出范围或数据不可用），请缩小时间范围后重试')
    const lookup = fetchSpy.mock.calls.find(([input, init]) => String(input).includes('/access/exports?') && init?.method === undefined)
    const lookupURL = new URL(String(lookup?.[0]), 'https://cdnca.test')
    expect(lookupURL.searchParams.get('from')).not.toBeNull()
    expect(lookupURL.searchParams.has('limit')).toBe(false)

    await user.click(screen.getByRole('button', { name: '重试这次申请' }))
    expect(await screen.findByText(/申请结果未知/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '用原请求重试' }))
    await waitFor(() => expect(posts).toBe(2))
    const creates = fetchSpy.mock.calls.filter(([input, init]) => String(input).includes('/access/exports') && init?.method === 'POST')
    const keys = creates.map(([, init]) => new Headers(init?.headers).get('Idempotency-Key'))
    expect(keys).toEqual([`access-export-${failedID}`, `access-export-${failedID}`])
    expect(creates[1]?.[1]?.body).toBe(creates[0]?.[1]?.body)
  })

  // live-click-B E3：平台视角未选租户时，导出接口必须带 tenant_id，按钮禁用并提示。
  it('disables the platform export until a tenant is applied and explains why', async () => {
    await changeLocale('zh-CN')
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/access/exports') && init?.method === 'POST') {
        return Promise.resolve(json({
          id: '018f0000-0000-7000-8000-000000000078', status: 'pending', reason: 'queued', snapshot_at: null,
          row_count: null, byte_count: null, created_at: '2026-07-28T08:00:01Z', expires_at: null, downloadable: false, filter: null,
        }, 202))
      }
      if (url.pathname.endsWith('/access/exports')) return Promise.resolve(json({ data: [] }))
      return Promise.resolve(page(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAccessLogPage />)

    // ui-errmsg-1024: no tenant hint until the download is clicked; the click sends nothing.
    const exportButton = screen.getByRole('button', { name: '申请下载' })
    const hint = '下载前请先在高级筛选中填写租户 ID 并查询'
    expect(screen.queryByText(hint)).not.toBeInTheDocument()
    await user.click(exportButton)
    expect(screen.getByText(hint)).toBeInTheDocument()
    expect(exportButton).toHaveAccessibleDescription(hint)
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/access/exports'))).toBe(false)

    fireEvent.change(screen.getByLabelText('租户 ID'), { target: { value: '018f0000-0000-7000-8000-000000000010' } })
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(screen.queryByText(hint)).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: '申请下载' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input, init]) =>
      String(input).includes('/access/exports?tenant_id=018f0000-0000-7000-8000-000000000010') && init?.method === 'POST')).toBe(true))
  })

  it('keeps export copy available through the case-insensitive qps-Ploc alias', () => {
    expect(analyticsLogExportMessages['qps-Ploc']).toEqual(analyticsLogExportMessages['qps-ploc'])
    expect(analyticsLogExportMessage('QPS-PLOC', 'title'))
      .toBe(analyticsLogExportMessage('qps-Ploc', 'title'))
  })
})
