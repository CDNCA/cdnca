import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { analyticsLogsApi, type AnalyticsLogFilters } from '../api/analyticsLogs'
import { useSessionStore } from '../auth/session'
import SiteBlockEventLogPage from '../pages/SiteBlockEventLogPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'
const siteId = '018f0000-0000-7000-8000-000000000020'
const nodeId = '018f0000-0000-7000-8000-000000000030'

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function jsonStatus(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function blockPage(input: RequestInfo | URL, replacement: Record<string, unknown> = {}): Response {
  const url = new URL(String(input), 'https://cdnca.test')
  return json({
    data: [{
      event_id: 'security-1', occurred_at: '2026-07-28T07:58:00Z', site_id: siteId, node_id: nodeId,
      request_id: 'security-request', trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      config_version_id: '018f0000-0000-7000-8000-000000000040',
      host: 'cdn.example.test', uri_path: '/blocked', client_ip: '192.0.2.11', country_code: 'CN', carrier: 'CMCC',
      event_type: 'waf', action: 'block', severity: 'high', rule_id: 'rule-1', status_code: 403,
      request_bytes: 256, response_bytes: 64,
      task_id: 'security-task', installation_id: 'installation-authority-1',
      request_headers: { Authorization: '[REDACTED]', 'X-WAF-Request': 'observed' },
      response_headers: { 'Set-Cookie': '[REDACTED]', 'X-WAF-Response': 'blocked' },
      request_body: { api_key: '[REDACTED]', attack: { kind: 'sqli' } }, response_body: { blocked: true },
      ja4: 't13d1516h2_8daaf6152771', origin_connect_us: 100, origin_first_byte_us: 250, origin_total_us: 400,
      policy_id: '', detector: '', matched: '', user_agent: '', request_body_excerpt: '', count: 1, uri_query: '', site_domain: '', rule_name: '',
      ...replacement,
    }],
    meta: {
      from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC',
      snapshot_at: '2026-07-28T08:00:00Z', consistency: 'snapshot',
      replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset',
    },
  })
}

describe('SiteBlockEventLogPage', () => {
  it.each([
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

    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('无权查看日志')).toBeInTheDocument()
    expect(screen.getByText('当前账户没有此范围的日志读取权限。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  // stats-platform-l7：进入即按发生时间倒序拉取全平台拦截事件；租户只是可选筛选。
  it('loads every tenant newest first on entry and keeps tenant as an optional filter', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      permissions: ['sites.read', 'platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const response = blockPage(input)
      return response.json().then((body) => {
        const older = { ...body.data[0], event_id: 'security-0', occurred_at: '2026-07-28T07:10:00Z', uri_path: '/older' }
        return json({ ...body, data: [body.data[0], older] })
      })
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(screen.getByRole('heading', { name: '原始拦截事件' })).toBeInTheDocument()
    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const initial = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(initial.pathname).toBe('/v1/admin/analytics/logs/block-events')
    expect(initial.searchParams.has('tenant_id')).toBe(false)
    expect(initial.searchParams.has('site_id')).toBe(false)
    expect(screen.queryByText('请先选择租户再查询。')).not.toBeInTheDocument()
    // Rows keep the server's newest-first order.
    const paths = within(screen.getByTestId('analytics-log-table')).getAllByText(/^\/(blocked|older)$/).map((cell) => cell.textContent)
    expect(paths).toEqual(['/blocked', '/older'])

    await user.type(screen.getByLabelText('租户 ID'), tenantId)
    await user.type(screen.getByLabelText('路径'), '/blocked')
    await user.type(screen.getByLabelText('状态码'), '0')
    await user.click(screen.getByRole('button', { name: '查询' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const url = new URL(String(fetchSpy.mock.calls[1][0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/logs/block-events')
    expect(url.searchParams.get('tenant_id')).toBe(tenantId)
    expect(url.searchParams.get('status_code')).toBe('0')
    expect(url.searchParams.get('uri_path')).toBe('/blocked')
    expect(url.searchParams.has('method')).toBe(false)
  })

  // stats-platform-l7：平台运营不带 tenant_id 即查全平台；租户身份仍不能指定租户。
  it('queries platform-wide when an admin caller omits tenant_id and rejects a tenant naming one', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      data: [], meta: { from: '2026-07-28T07:00:00Z', to: '2026-07-28T08:00:00Z', timezone: 'UTC', consistency: 'snapshot',
        replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset' },
    })))
    const filters: AnalyticsLogFilters = {
      from: '2026-07-28T07:00:00Z',
      to: '2026-07-28T08:00:00Z',
    }
    await analyticsLogsApi.listBlocks('access-token', 'admin', filters, 20)
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/logs/block-events')
    expect(url.searchParams.has('tenant_id')).toBe(false)

    await expect(analyticsLogsApi.listBlocks('access-token', 'tenant', { ...filters, tenantId }, 20))
      .rejects.toMatchObject({ status: 400, code: 'analytics_logs_invalid_request' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('keeps loading and empty states distinct', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    let resolve!: (response: Response) => void
    let input!: RequestInfo | URL
    vi.spyOn(globalThis, 'fetch').mockImplementation((request) => {
      input = request
      return new Promise((done) => { resolve = done })
    })
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(screen.getByTestId('analytics-log-table')).toHaveAttribute('aria-busy', 'true')
    expect(screen.queryByText('当前筛选范围内暂无日志')).not.toBeInTheDocument()
    resolve(json({
      data: [],
      meta: {
        from: new URL(String(input), 'https://cdnca.test').searchParams.get('from'),
        to: new URL(String(input), 'https://cdnca.test').searchParams.get('to'),
        timezone: 'UTC', consistency: 'snapshot', replacement_consistency: 'latest_event_id_at_snapshot',
        pagination: 'keyset',
      },
    }))
    expect(await screen.findByText('当前筛选范围内暂无日志')).toBeInTheDocument()
    expect(screen.getByTestId('analytics-log-table')).toHaveAttribute('aria-busy', 'false')
  })

  it('maps a stable 400 locally and retries a 5xx without exposing either server message', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonStatus({
        error: { code: 'analytics_logs_invalid_request', message: 'private block validator detail' },
      }, 400))
      .mockResolvedValueOnce(jsonStatus({
        error: { code: 'request_failed', message: 'private block gateway detail' },
      }, 500))
      .mockImplementationOnce((input) => Promise.resolve(blockPage(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('筛选条件或分页游标无效。')).toBeInTheDocument()
    expect(screen.queryByText('private block validator detail')).not.toBeInTheDocument()
    expect(screen.queryByText('当前筛选范围内暂无日志')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('日志加载失败，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByText('private block gateway detail')).not.toBeInTheDocument()
    expect(screen.queryByText('当前筛选范围内暂无日志')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))

    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(3)
    expect(screen.queryByText('日志加载失败，请稍后重试。')).not.toBeInTheDocument()
  })

  it('renders a local 403 permission state without exposing the server detail', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonStatus({
      error: { code: 'analytics_logs_permission_denied', message: 'private permission detail' },
    }, 403))
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('无权查看日志')).toBeInTheDocument()
    expect(screen.getByText('当前账户没有此范围的日志读取权限。')).toBeInTheDocument()
    expect(screen.queryByText('private permission detail')).not.toBeInTheDocument()
  })

  it('rejects a non-integer status before fetch', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    // A valid empty page: `{ data: [], meta: {} }` is rejected as invalid and now opens the
    // load-failure feedback dialog, which takes focus and races the typing below.
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const page = blockPage(input)
      return page.json().then((body: { meta: unknown }) => json({ data: [], meta: body.meta }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('当前筛选范围内暂无日志')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    fetchSpy.mockClear()
    await user.type(screen.getByLabelText('状态码'), '200.5')
    await user.click(screen.getByRole('button', { name: '查询' }))

    expect(screen.getByText('状态码必须是 0 或 100 到 599 的整数。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('opens security-specific raw event details', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    expect(screen.queryByLabelText('请求方法')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('security-1')).toBeInTheDocument()
    expect(screen.getAllByText('Web 应用防火墙')).not.toHaveLength(0)
    expect(screen.getAllByText('拦截')).not.toHaveLength(0)
    expect(screen.getAllByText('高')).not.toHaveLength(0)
    expect(screen.getAllByText('rule-1')).not.toHaveLength(0)
    expect(screen.getByText('security-request')).toBeInTheDocument()
    expect(screen.getByText('018f0000-0000-7000-8000-000000000040')).toBeInTheDocument()
    expect(screen.getByText('security-task')).toBeInTheDocument()
    expect(screen.getByText(/X-WAF-Request/)).toBeInTheDocument()
    expect(screen.getByText(/"kind":"sqli"/)).toBeInTheDocument()
    expect(screen.getByText('t13d1516h2_8daaf6152771')).toBeInTheDocument()
  })

  it('names the site and rule, falls back to a copyable short ID, and shows the redacted query (P14)', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const ruleId = '018f0000-0000-7000-8000-0000000000b1'
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      site_domain: 'www.example.test', rule_name: '拦截 SQL 注入', rule_id: ruleId, uri_query: 'id=1&token=***',
    })))
    const user = userEvent.setup()
    const view = renderWithProviders(<SiteBlockEventLogPage />)

    const table = await screen.findByTestId('analytics-log-table')
    expect(await within(table).findByText('www.example.test')).toHaveAttribute('title', siteId)
    expect(within(table).getByText('拦截 SQL 注入')).toHaveAttribute('title', ruleId)
    expect(within(table).getByText('/blocked?id=1&token=***')).toBeInTheDocument()
    expect(within(table).queryByText('—')).not.toBeInTheDocument()
    expect(within(table).getAllByRole('button', { name: /复制/ }).length).toBeGreaterThanOrEqual(2)
    await user.click(within(table).getByRole('button', { name: '详情' }))
    expect(await screen.findByText('规则名称')).toBeInTheDocument()
    expect(screen.getByText('站点域名')).toBeInTheDocument()
    view.unmount()

    // Names unknown: the first 8 characters of each ID, the full ID in the title.
    fetchSpy.mockImplementation((input) => Promise.resolve(blockPage(input, { rule_id: ruleId })))
    renderWithProviders(<SiteBlockEventLogPage />)
    const fallback = await screen.findByTestId('analytics-log-table')
    // 夹具里站点 ID 与规则 ID 前 8 位相同（018f0000），按完整 ID 的 title 区分两个短 ID。
    expect(await within(fallback).findByTitle(siteId)).toHaveTextContent(`${siteId.slice(0, 8)}…`)
    expect(within(fallback).getByTitle(ruleId)).toHaveTextContent(`${ruleId.slice(0, 8)}…`)
    expect(within(fallback).getByText('/blocked')).toBeInTheDocument()
  })

  it('shows the WAF attack evidence: policy, detector, matched content, User-Agent and body excerpt (ge-waf)', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      policy_id: '018f0000-0000-7000-8000-0000000000e5', detector: 'sqli', matched: "q=1' or '1'='1",
      user_agent: 'sqlmap/1.7', request_body_excerpt: 'q=1%27+or',
    })))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('命中策略')).toBeInTheDocument()
    expect(screen.getByText('018f0000-0000-7000-8000-0000000000e5')).toBeInTheDocument()
    expect(screen.getByText('命中检测器')).toBeInTheDocument()
    expect(screen.getByText('sqli')).toBeInTheDocument()
    expect(screen.getByText("q=1' or '1'='1")).toBeInTheDocument()
    expect(screen.getByText('sqlmap/1.7')).toBeInTheDocument()
    expect(screen.getByText('q=1%27+or')).toBeInTheDocument()
  })

  it('shows the request count of an aggregated CC challenge / 429 line (sec-log-agg)', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      event_type: 'cc', action: 'challenge', count: 12345,
    })))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)
    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '次数' })).toBeInTheDocument()
    expect(screen.getByText('12,345')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findAllByText('12,345')).toHaveLength(2)
  })

  it('lists challenge events with their count and narrows by action (sec-log-agg)', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      event_type: 'cc', action: 'challenge', count: 40,
    })))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)
    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    expect(screen.getByText('人机验证')).toBeInTheDocument()
    expect(screen.getByText('40')).toBeInTheDocument()
    const firstURL = new URL(String(fetchSpy.mock.calls[0][0]), 'http://localhost')
    expect(firstURL.searchParams.has('action')).toBe(false)
    // fix-advfilter: 动作 sits in the 高级筛选 panel.
    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    await user.click(screen.getByRole('combobox', { name: '动作' }))
    // fix-waflogdetail: observed and auto-blocked hits are selectable too; the label matches the table.
    expect(within(await screen.findByRole('listbox')).getAllByRole('option').map((option) => option.textContent))
      .toEqual(['全部', '拦截', '人机验证', '观察', '自动封禁'])
    await user.click(screen.getByTitle('人机验证', { exact: true }))
    await user.click(screen.getByRole('button', { name: '应用' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) =>
      new URL(String(input), 'http://localhost').searchParams.get('action') === 'challenge')).toBe(true))
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('动作：人机验证')
  })

  it('rejects a block event without a positive count', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, { count: 0 })))
    renderWithProviders(<SiteBlockEventLogPage />)
    // Load failures open the shared feedback dialog instead of an in-page Alert.
    expect(await screen.findByRole('dialog')).toHaveTextContent('日志加载失败')
    expect(screen.queryByText('/blocked')).not.toBeInTheDocument()
  })

  it('hides empty attack evidence and rejects a malformed policy ID', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)
    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('security-1')).toBeInTheDocument()
    expect(screen.queryByText('命中策略')).not.toBeInTheDocument()
    expect(screen.queryByText('命中检测器')).not.toBeInTheDocument()
  })

  it('shows the client carrier, region, ASN and IDC from the IP intelligence library (G3-d)', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      country_code: '', carrier: '',
      ip_intel: { carrier: 'carrier:cn-mobile', idc: 'idc:cn', asn: 9808, country: 'CN', province: '440000',
        province_name: '广东省', city: '440300', city_name: '深圳市', revision: 7 },
    })))
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '运营商' })).toBeInTheDocument()
    expect(screen.getAllByText('中国移动').length).toBeGreaterThan(0)
    expect(screen.getAllByText('国内 IDC').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/中国 广东省 深圳市/).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('AS9808')).toBeInTheDocument()
  })

  it('rejects a malformed ip_intel object', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      ip_intel: { carrier: 'carrier:cn-mobile', revision: 0, secret: 'x' },
    })))
    renderWithProviders(<SiteBlockEventLogPage />)
    expect(await screen.findByRole('dialog')).toHaveTextContent('日志加载失败')
    expect(screen.queryByText('/blocked')).not.toBeInTheDocument()
  })

  it('recursively redacts sensitive security capture keys while preserving benign facts', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const rawPage = await blockPage('/v1/analytics/logs/block-events?from=2026-07-28T07%3A00%3A00Z&to=2026-07-28T08%3A00%3A00Z').json() as {
      data: Array<Record<string, unknown>>
      meta: Record<string, unknown>
    }
    Object.assign(rawPage.data[0]!, {
      request_headers: { 'X-Api-Key': 'raw-block-api-key', 'X-WAF-Fact': 'sqli' },
      response_headers: { Cookie: 'raw-block-cookie', 'X-Decision': 'blocked' },
      request_body: { attack: { kind: 'sqli', secret: 'raw-block-secret' }, evidence: ['union', 'select'] },
      response_body: { blocked: true, refresh_token: 'raw-block-token' },
    })
    vi.spyOn(analyticsLogsApi, 'listBlocks').mockResolvedValue(rawPage as never)
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    expect(await screen.findByText('/blocked')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))

    expect(await screen.findByText(/"X-WAF-Fact":"sqli"/)).toBeInTheDocument()
    expect(screen.getByText(/"kind":"sqli"/)).toBeInTheDocument()
    expect(screen.getByText(/"evidence":\["union","select"\]/)).toBeInTheDocument()
    expect(screen.getByText(/"blocked":true/)).toBeInTheDocument()
    expect(screen.getAllByText(/已脱敏/).length).toBeGreaterThanOrEqual(3)
    expect(document.body).not.toHaveTextContent(/raw-block-api-key|raw-block-cookie|raw-block-secret|raw-block-token/)
  })

  it('preserves future security event values instead of collapsing raw data to unknown', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(blockPage(input, {
      event_type: 'bot_challenge_v2', action: 'throttle', severity: 'notice',
    })))
    renderWithProviders(<SiteBlockEventLogPage />)

    expect((await screen.findAllByText('bot_challenge_v2')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('throttle').length).toBeGreaterThan(0)
    expect(screen.getAllByText('notice').length).toBeGreaterThan(0)
  })

  it('shows relayed market supply blocks with the leaf number when the source is switched (ML-21)', async () => {
    const actor = principal({ scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const requests: URL[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://cdnca.test')
      requests.push(url)
      if (url.pathname === '/v1/analytics/market-security') {
        const page = url.searchParams.get('cursor') ? [] : [{
          site_id: siteId, supply_id: '018f0000-0000-7000-8000-000000000050', leaf_ref: '0a1b2c3d',
          occurred_at: '2026-07-28T07:58:00Z', client_ip: '198.51.100.7', host: 'shop.example.test', path: '/login',
          action: 'block', detector: 'sqli', rule_id: 'crs-942100', cursor: 'c1',
        }]
        return Promise.resolve(json({ data: page, meta: url.searchParams.get('cursor') ? {} : { next_cursor: 'c1' } }))
      }
      return Promise.resolve(blockPage(input))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockEventLogPage />)

    const source = screen.getByRole('group', { name: '来源' })
    expect(source).toBeInTheDocument()
    await waitFor(() => expect(requests.some((url) => url.pathname === '/v1/analytics/logs/block-events')).toBe(true))
    expect(requests.some((url) => url.pathname === '/v1/analytics/market-security')).toBe(false)

    await user.click(screen.getByText('市场供给'))
    expect(await screen.findByText('市场供给 · 0a1b2c3d')).toBeInTheDocument()
    expect(screen.getByText('shop.example.test')).toBeInTheDocument()
    expect(screen.getByText('crs-942100')).toBeInTheDocument()
    expect(screen.getByText('拦截')).toBeInTheDocument()
    const first = requests.filter((url) => url.pathname === '/v1/analytics/market-security')
    expect(first).toHaveLength(1)
    expect(first[0].searchParams.has('tenant_id')).toBe(false)
    // fix-rangepicker2：开始/结束时间改用共享 TimeRangeFilter（默认今天，最长 31 天，不可清空，点「查询」才生效）。
    const range = within(screen.getByTestId('market-security-panel')).getByRole('group', { name: '时间范围' })
    expect(within(range).getByRole('radio', { name: '今天' })).toBeChecked()
    expect(within(range).queryByRole('radio', { name: '近30天' })).toBeInTheDocument()
    expect(screen.queryByLabelText('开始时间')).not.toBeInTheDocument()
    expect(new Date(first[0].searchParams.get('to')!).getTime() - new Date(first[0].searchParams.get('from')!).getTime()).toBe(86_400_000)
    await user.click(within(range).getByText('近7天'))
    expect(requests.filter((url) => url.pathname === '/v1/analytics/market-security')).toHaveLength(1)

    // Filter by site and client IP, then page forward with the cursor.
    await user.type(screen.getByLabelText('站点 ID'), siteId)
    await user.type(screen.getByLabelText('客户端 IP'), '198.51.100.7')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => {
      const last = requests.filter((url) => url.pathname === '/v1/analytics/market-security').at(-1)!
      expect(last.searchParams.get('site_id')).toBe(siteId)
      expect(last.searchParams.get('client_ip')).toBe('198.51.100.7')
      expect(new Date(last.searchParams.get('to')!).getTime() - new Date(last.searchParams.get('from')!).getTime()).toBe(7 * 86_400_000)
    })
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    await waitFor(() => {
      const last = requests.filter((url) => url.pathname === '/v1/analytics/market-security').at(-1)!
      expect(last.searchParams.get('cursor')).toBe('c1')
    })

    // Back to local nodes.
    await user.click(screen.getByText('本地节点'))
    expect(screen.queryByTestId('market-security-panel')).not.toBeInTheDocument()
  })
})
