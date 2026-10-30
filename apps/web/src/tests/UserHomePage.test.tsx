import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'

import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { UserHomePage } from '../pages/UserHomePage'
import { defaultThemeLayout, ThemeRuntimeContext } from '../theme/runtime'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const accessToken = 'memory-only-access-token'
const tenantDashboardPermissions = [
  'sites.read',
  'certificates.read',
  'billing.account.read',
  'package_subscriptions.read',
  'traffic_packages.read',
  'announcements.read',
  'jobs.read',
]

function authenticateUser(overrides: Parameters<typeof principal>[0] = {}) {
  const user = principal({ display_name: 'Jason Chen', roles: ['tenant_owner'], permissions: tenantDashboardPermissions, ...overrides })
  useSessionStore.getState().setSession(authResponse(user), user)
  return user
}

function UserHomePageWithQueryClient({ capture }: { capture: (queryClient: QueryClient) => void }) {
  const queryClient = useQueryClient()
  capture(queryClient)
  return <UserHomePage />
}

function renderDashboard() {
  let queryClient: QueryClient | undefined
  const view = renderWithProviders(
    <UserHomePageWithQueryClient capture={(client) => { queryClient = client }} />,
    ['/home'],
  )
  if (!queryClient) throw new Error('Query client was not captured')
  return { ...view, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function dashboardWithFacts(range: string, subscriptionName: string, noticeTitle: string, balanceMinor: number) {
  const dashboard = tenantDashboard(range)
  return {
    ...dashboard,
    billing: { available: true, value: { currency: 'CNY', balance_minor: balanceMinor, revision: 8 } },
    subscriptions: {
      available: true,
      value: { ...dashboard.subscriptions.value, items: [{ ...dashboard.subscriptions.value.items[0], name: subscriptionName }] },
    },
    notices: {
      available: true,
      value: { ...dashboard.notices.value, items: [{ ...dashboard.notices.value.items[0], title: noticeTitle }] },
    },
  }
}

function tenantDashboard(range = 'today', analytics: unknown = {
  available: true,
  value: {
    summary: { metric_version: 1, request_count: '900719925474099312345', request_bytes: '1', response_bytes: '2', total_bytes: '3',
      average_bandwidth_bps: 1250000, status_2xx: '4', status_3xx: '5', status_4xx: '6', status_5xx: '7', security_events: '8' },
    trend: [],
    top: [
      { dimension: 'domain', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
      { dimension: 'region', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
      { dimension: 'carrier', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
    ],
  },
}) {
  return {
    dashboard_version: 2,
    meta: {
      range, timezone: 'Asia/Shanghai', from: '2026-07-30T16:00:00Z', to: '2026-07-31T16:00:00Z',
      generated_at: '2026-07-31T08:00:00Z', snapshot_at: '2026-07-31T08:00:00.000Z', window_complete: false,
    },
    identity_verification: { available: true, value: { verified: false } },
    profile: { available: true, value: { last_login_at: '2026-07-31T07:30:00Z', last_login_ip: '203.0.113.8', last_login_geo: 'CN-BJ' } },
    resources: { available: true, value: { sites_total: 8, sites_active: 7, sites_sync_failed: 1, domains_total: 8, forwards_total: 1, nodes_total: 2 } },
    certificates: { available: true, value: { total: 6, valid: 5, expiring_30d: 1 } },
    billing: { available: true, value: { currency: 'CNY', balance_minor: 123456, revision: 7, updated_at: '2026-07-31T07:00:00Z' } },
    subscriptions: { available: true, value: { active: 1, items: [{
      id: '018f0000-0000-7000-8000-000000000001', name: '企业套餐', ends_at: '2026-12-31T16:00:00Z',
      timezone: 'Asia/Shanghai', site_limit: '-1', domain_limit: '100', node_limit: '10', traffic_limit_bytes: '900719925474099312345',
      traffic_progress: { available: true, value: { period_key: '2026-07', used_bytes: '1024', finalized_through: '2026-07-31T07:00:00Z', source_watermark: '9', source_evidence_sha256: 'a'.repeat(64) } },
    }] } },
    traffic_packages: { available: true, value: { active: 2, granted_bytes: '900719925474099312345', remaining_bytes: '800719925474099312345', used_bytes: '100000000000000000000' } },
    operations: { available: true, value: { cache_total: 3, cache_open: 1, cache_failed: 0, jobs_total: 4, jobs_open: 1, jobs_failed: 0 } },
    notices: { available: true, value: { unread: 1, items: [{ id: '018f0000-0000-7000-8000-000000000002', title: '维护通知', published_at: '2026-07-31T07:00:00Z' }] } },
    account_security: { available: true, value: { active_sessions: 2, users_with_mfa: 1, active_api_keys: 1, recovery_codes_remaining: 5 } },
    network: { available: true, value: { nodes_total: 2, nodes_active: 2, nodes_online: 1, nodes_stale: 1, freshness_cutoff_seconds: 45, regions: [{ region: 'cn-east', nodes_total: 2, nodes_online: 1 }] } },
    analytics,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('UserHomePage', () => {
  it('renders the six community modules with authoritative tenant facts', async () => {
    authenticateUser()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard()))
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '监控趋势' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'TOP10 数据 (近30分钟)' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '系统公告' })).toBeInTheDocument()
    // 社区版：没有套餐流量卡片与账户余额。
    expect(screen.queryByRole('heading', { name: '套餐流量' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '使用统计' })).toBeInTheDocument()
    expect(screen.getByLabelText('账户概览')).not.toHaveTextContent('¥1,234.56')
    expect(screen.getByLabelText('账户概览')).toHaveTextContent('未认证')
    expect(screen.getByLabelText('账户概览')).toHaveTextContent('2026-07-31 15:30:00')
    expect(screen.getByLabelText('账户概览')).toHaveTextContent('203.0.113.8 (CN-BJ)')
    expect(screen.queryByText(/企业套餐/)).not.toBeInTheDocument()
    expect(screen.getByText('维护通知')).toBeInTheDocument()
    expect(screen.getAllByRole('radiogroup')).toHaveLength(2)
    expect(document.querySelectorAll('.user-dashboard-card')).toHaveLength(6)

    const [url, init] = fetchSpy.mock.calls[0]
    const parsed = new URL(String(url), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/dashboard')
    expect(Object.fromEntries(parsed.searchParams)).toEqual({ range: 'today', timezone: 'Asia/Shanghai' })
    expect(init).toEqual(expect.objectContaining({
      credentials: 'include', headers: { Authorization: `Bearer ${accessToken}` }, signal: expect.any(AbortSignal),
    }))
  })

  it('shows the same approved overview to a viewer without resource-management controls', async () => {
    authenticateUser({ roles: ['tenant_viewer'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard()))
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '监控趋势' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'TOP10 数据 (近30分钟)' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '系统公告' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '使用统计' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '应用筛选' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '任务状态' })).not.toBeInTheDocument()
  })

  // PA-17 layout slot user_home_blocks: the theme picks and orders the blocks.
  it('shows only the theme-selected home blocks in the theme order', async () => {
    authenticateUser()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard()))
    renderWithProviders(
      <ThemeRuntimeContext.Provider value={{ document: null, layout: { ...defaultThemeLayout, user_home_blocks: ['usage', 'network', 'notices'] } }}>
        <UserHomePage />
      </ThemeRuntimeContext.Provider>,
      ['/home'],
    )

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '监控趋势' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '套餐流量' })).not.toBeInTheDocument()
    const side = screen.getByRole('heading', { name: '使用统计' }).closest('aside')!
    const sideHeadings = within(side).getAllByRole('heading').map((heading) => heading.textContent)
    expect(sideHeadings.indexOf('使用统计')).toBeLessThan(sideHeadings.indexOf('系统公告'))
  })

  it('shows the 5-minute peak bandwidth instead of the hourly average (FX36)', async () => {
    authenticateUser()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...tenantDashboard('today', {
        available: true,
        value: {
          summary: { metric_version: 1, request_count: '0', request_bytes: '0', response_bytes: '0', total_bytes: '0',
            average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0' },
          blocked_ip_count: '3',
          peak_bandwidth_bps: '2000000',
          trend: [],
          top: [
            { dimension: 'domain', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
            { dimension: 'region', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
            { dimension: 'carrier', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
          ],
        },
      }),
      identity_verification: { available: true, value: { verified: false } },
      resources: { available: true, value: { sites_total: 0, sites_active: 0, sites_sync_failed: 0, domains_total: 0, forwards_total: 0, nodes_total: 0 } },
      certificates: { available: true, value: { total: 0, valid: 0, expiring_30d: 0 } },
      billing: { available: true, value: { currency: 'CNY', balance_minor: 0, revision: 0 } },
      subscriptions: { available: true, value: { active: 0, items: [] } },
      traffic_packages: { available: true, value: { active: 0, granted_bytes: '0', remaining_bytes: '0', used_bytes: '0' } },
      operations: { available: true, value: { cache_total: 0, cache_open: 0, cache_failed: 0, jobs_total: 0, jobs_open: 0, jobs_failed: 0 } },
      notices: { available: true, value: { unread: 0, items: [] } },
      account_security: { available: true, value: { active_sessions: 0, users_with_mfa: 0, active_api_keys: 0, recovery_codes_remaining: 0 } },
      network: { available: true, value: { nodes_total: 0, nodes_active: 0, nodes_online: 0, nodes_stale: 0, freshness_cutoff_seconds: 45, regions: [] } },
    }))
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(screen.getByText('带宽峰值', { selector: 'dt' }).parentElement).toHaveTextContent('2Mbps')
    expect(screen.getByText('拉黑IP数', { selector: 'dt' }).parentElement).toHaveTextContent('3个')
  })

  it('renders available all-zero aggregates and empty collections as localized facts', async () => {
    authenticateUser()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...tenantDashboard('today', {
        available: true,
        value: {
          summary: { metric_version: 1, request_count: '0', request_bytes: '0', response_bytes: '0', total_bytes: '0',
            average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0' },
          blocked_ip_count: '0',
          peak_bandwidth_bps: '0',
          trend: [],
          top: [
            { dimension: 'domain', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
            { dimension: 'region', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
            { dimension: 'carrier', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
          ],
        },
      }),
      identity_verification: { available: true, value: { verified: false } },
      resources: { available: true, value: { sites_total: 0, sites_active: 0, sites_sync_failed: 0, domains_total: 0, forwards_total: 0, nodes_total: 0 } },
      certificates: { available: true, value: { total: 0, valid: 0, expiring_30d: 0 } },
      billing: { available: true, value: { currency: 'CNY', balance_minor: 0, revision: 0 } },
      subscriptions: { available: true, value: { active: 0, items: [] } },
      traffic_packages: { available: true, value: { active: 0, granted_bytes: '0', remaining_bytes: '0', used_bytes: '0' } },
      operations: { available: true, value: { cache_total: 0, cache_open: 0, cache_failed: 0, jobs_total: 0, jobs_open: 0, jobs_failed: 0 } },
      notices: { available: true, value: { unread: 0, items: [] } },
      account_security: { available: true, value: { active_sessions: 0, users_with_mfa: 0, active_api_keys: 0, recovery_codes_remaining: 0 } },
      network: { available: true, value: { nodes_total: 0, nodes_active: 0, nodes_online: 0, nodes_stale: 0, freshness_cutoff_seconds: 45, regions: [] } },
    }))
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(screen.getByLabelText('账户概览')).not.toHaveTextContent('¥0.00')
    expect(screen.getByLabelText('账户概览')).toHaveTextContent('未认证')
    expect(screen.queryByText('暂无生效套餐')).not.toBeInTheDocument()
    expect(screen.getByText('暂无公告')).toBeInTheDocument()
    expect(screen.getByText('带宽峰值', { selector: 'dt' }).parentElement).toHaveTextContent('0Kbps')
    expect(screen.getByText('请求数', { selector: 'dt' }).parentElement).toHaveTextContent('0次')
    expect(screen.getByText('总流量', { selector: 'dt' }).parentElement).toHaveTextContent('0KB')
    expect(screen.getByText('拉黑IP数', { selector: 'dt' }).parentElement).toHaveTextContent('0个')
    const usageCard = screen.getByRole('heading', { name: '使用统计' }).closest('section')
    expect(usageCard).not.toBeNull()
    expect(within(usageCard!).getAllByText('0')).toHaveLength(3)
    expect(screen.queryByText('依赖服务暂不可用')).not.toBeInTheDocument()
    expect(screen.queryByText('权威数据尚未就绪')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  // 结算水位落后只在卡片上提示，数据照常展示。
  it('shows analytics with a settling hint instead of blocking the cards', async () => {
    authenticateUser()
    const analytics = tenantDashboard().analytics as { value: Record<string, unknown> }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard('today', {
      available: true, value: { ...analytics.value, settling_minutes: 3 },
    })))
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(screen.getAllByText('最近 3 分钟数据仍在结算').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('总流量', { selector: 'dt' }).parentElement).toHaveTextContent('3B')
    expect(screen.queryByText('权威数据尚未就绪')).not.toBeInTheDocument()
  })

  it('shows analytics unavailability locally without hiding authoritative resource facts', async () => {
    authenticateUser()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard('today', {
      available: false, reason: 'dependency_unavailable',
    })))
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findAllByText('依赖服务暂不可用')).toHaveLength(3)
    expect(screen.getByText('维护通知')).toBeInTheDocument()
  })

  it('aborts a superseded range and does not serialize tenant identity parameters', async () => {
    authenticateUser()
    let firstSignal: AbortSignal | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => {
      if (fetchSpy.mock.calls.length === 1) {
        firstSignal = init?.signal ?? undefined
        return new Promise<Response>((_resolve, reject) => {
          firstSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        })
      }
      return Promise.resolve(json(tenantDashboard('thirty_days')))
    })
    const user = userEvent.setup()
    renderWithProviders(<UserHomePage />, ['/home'])

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    const range = screen.getByRole('radiogroup', { name: '网络概览时间范围' })
    await user.click(within(range).getByText('近30日'))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(firstSignal?.aborted).toBe(true)
    const second = new URL(String(fetchSpy.mock.calls[1][0]), 'https://web.test')
    expect(second.searchParams.get('range')).toBe('thirty_days')
    expect(second.searchParams.has('tenant_id')).toBe(false)
  })

  it('keeps the network and monitoring time controls synchronized', async () => {
    authenticateUser()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(tenantDashboard()))
      .mockResolvedValueOnce(json(tenantDashboard('thirty_days')))
    const user = userEvent.setup()
    renderWithProviders(<UserHomePage />, ['/home'])

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    const networkRange = screen.getByRole('radiogroup', { name: '网络概览时间范围' })
    const monitorRange = screen.getByRole('radiogroup', { name: '监控趋势时间范围' })
    await user.click(within(networkRange).getByRole('radio', { name: '近30日' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(within(networkRange).getByRole('radio', { name: '近30日' })).toBeChecked()
    expect(within(monitorRange).getByRole('radio', { name: '近30日' })).toBeChecked()
    const url = new URL(String(fetchSpy.mock.calls[1][0]), 'https://web.test')
    expect(url.searchParams.get('range')).toBe('thirty_days')
    expect(url.searchParams.has('tenant_id')).toBe(false)
  })

  it('uses a flat token-free owner key and preserves range and cache identity across token refresh', async () => {
    const user = authenticateUser()
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(tenantDashboard()))
      .mockResolvedValueOnce(json(tenantDashboard('thirty_days')))
      .mockResolvedValueOnce(json(tenantDashboard('yesterday')))
    const ui = userEvent.setup()
    const { queryClient } = renderDashboard()

    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    const range = screen.getByRole('radiogroup', { name: '网络概览时间范围' })
    await ui.click(within(range).getByText('近30日'))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))

    const ownerPrefix = [
      'dashboard', 'tenant', user.scope_id, user.tenant_id, user.user_id, sessionEpoch,
    ]
    const currentKey = [...ownerPrefix, 'thirty_days', 'Asia/Shanghai', {}]
    await waitFor(() => {
      expect(queryClient.getQueryCache().find({ queryKey: currentKey, exact: true })?.state.status).toBe('success')
    })
    const currentQuery = queryClient.getQueryCache().find({ queryKey: currentKey, exact: true })
    const currentData = currentQuery?.state.data
    expect(currentQuery?.queryKey).toEqual(currentKey)
    expect(currentData).toEqual(tenantDashboard('thirty_days'))
    expect(queryClient.getQueryCache().getAll()
      .filter((query) => query.queryKey[0] === 'dashboard')
      .flatMap((query) => query.queryKey)).not.toContain(accessToken)

    act(() => {
      useSessionStore.getState().setSession(
        { ...authResponse(user), access_token: 'refreshed-dashboard-token' },
        user,
        'refresh',
      )
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(within(range).getByRole('radio', { name: '近30日' })).toBeChecked()
    const refreshedQuery = queryClient.getQueryCache().find({ queryKey: currentKey, exact: true })
    expect(refreshedQuery).toBe(currentQuery)
    expect(refreshedQuery?.queryKey).toEqual(currentKey)
    expect(refreshedQuery?.state.data).toBe(currentData)
    const refreshedDashboardKeys = queryClient.getQueryCache().getAll()
      .filter((query) => query.queryKey[0] === 'dashboard')
      .flatMap((query) => query.queryKey)
    expect(refreshedDashboardKeys).not.toContain(accessToken)
    expect(refreshedDashboardKeys).not.toContain('refreshed-dashboard-token')

    await ui.click(within(range).getByText('昨日'))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(fetchSpy.mock.calls[2][1]).toEqual(expect.objectContaining({
      headers: { Authorization: 'Bearer refreshed-dashboard-token' },
    }))
  })

  it('resets range and removes old financial and tenant caches for a new session with the same IDs', async () => {
    const user = authenticateUser()
    const oldEpoch = useSessionStore.getState().sessionEpoch
    const nextDashboard = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(dashboardWithFacts('today', '旧会话套餐', '旧会话公告', 654321)))
      .mockResolvedValueOnce(json(dashboardWithFacts('thirty_days', '旧会话套餐', '旧会话公告', 654321)))
      .mockImplementationOnce(() => nextDashboard.promise)
    const ui = userEvent.setup()
    const { queryClient } = renderDashboard()

    expect(await screen.findByText('旧会话公告')).toBeInTheDocument()
    const range = screen.getByRole('radiogroup', { name: '网络概览时间范围' })
    await ui.click(within(range).getByText('近30日'))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))

    act(() => {
      useSessionStore.getState().setSession(
        { ...authResponse(user), access_token: 'new-session-dashboard-token' },
        user,
      )
    })

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(new URL(String(fetchSpy.mock.calls[2][0]), 'https://web.test').searchParams.get('range')).toBe('today')
    expect(screen.queryByText(/旧会话套餐/)).not.toBeInTheDocument()
    expect(screen.queryByText('旧会话公告')).not.toBeInTheDocument()
    expect(screen.queryByText('¥6,543.21')).not.toBeInTheDocument()
    expect(screen.getByLabelText('服务数据加载中')).toBeInTheDocument()
    await waitFor(() => {
      expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey.includes(oldEpoch))).toBe(false)
    })

    await act(async () => {
      nextDashboard.resolve(json(dashboardWithFacts('today', '新会话套餐', '新会话公告', 123456)))
    })
    expect(await screen.findByText('新会话公告')).toBeInTheDocument()
  })

  it.each(['success', 'error'] as const)(
    'does not let a delayed old-session %s repopulate the new session UI or cache',
    async (outcome) => {
      const user = authenticateUser()
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const oldRequest = deferred<Response>()
      const oldJSON = deferred<unknown>()
      const newRequest = deferred<Response>()
      const continuation = { observed: false }
      const oldResponse = json({}, outcome === 'success' ? 200 : 500)
      const oldJSONSpy = vi.spyOn(oldResponse, 'json').mockImplementation(() => oldJSON.promise)
      let oldBody: unknown
      if (outcome === 'success') {
        const dashboard = dashboardWithFacts('today', '迟到旧套餐', '迟到旧公告', 999999)
        const dashboardVersion = dashboard.dashboard_version
        Object.defineProperty(dashboard, 'dashboard_version', {
          configurable: true,
          enumerable: true,
          get: () => {
            continuation.observed = true
            return dashboardVersion
          },
        })
        oldBody = dashboard
      } else {
        const error = { message: 'private stale dashboard failure', request_id: 'stale-dashboard-request' }
        Object.defineProperty(error, 'code', {
          configurable: true,
          enumerable: true,
          get: () => {
            continuation.observed = true
            return 'request_failed'
          },
        })
        oldBody = { error }
      }
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
        .mockImplementationOnce(() => oldRequest.promise)
        .mockImplementationOnce(() => newRequest.promise)
      const { queryClient } = renderDashboard()

      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
      act(() => {
        useSessionStore.getState().setSession(
          { ...authResponse(user), access_token: 'replacement-session-token' },
          user,
        )
      })
      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))

      await act(async () => {
        oldRequest.resolve(oldResponse)
      })
      await waitFor(() => expect(oldJSONSpy).toHaveBeenCalledOnce())
      expect(continuation.observed).toBe(false)
      await act(async () => { oldJSON.resolve(oldBody) })
      await waitFor(() => expect(continuation.observed).toBe(true))
      expect(screen.queryByText(/迟到旧套餐/)).not.toBeInTheDocument()
      expect(screen.queryByText('迟到旧公告')).not.toBeInTheDocument()
      expect(screen.queryByText('¥9,999.99')).not.toBeInTheDocument()
      expect(screen.queryByText(/private stale dashboard failure/i)).not.toBeInTheDocument()
      expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey.includes(oldEpoch))).toBe(false)

      await act(async () => {
        newRequest.resolve(json(dashboardWithFacts('today', '当前会话套餐', '当前会话公告', 123456)))
      })
      expect(await screen.findByText('当前会话公告')).toBeInTheDocument()
      expect(screen.queryByText(/迟到旧套餐/)).not.toBeInTheDocument()
      expect(screen.queryByText('迟到旧公告')).not.toBeInTheDocument()
      expect(screen.queryByText('¥9,999.99')).not.toBeInTheDocument()
      expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey.includes(oldEpoch))).toBe(false)
    },
  )

  it('retains account context during loading and hides raw server errors', async () => {
    authenticateUser()
    const pending = vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<Response>(() => undefined))
    const first = renderWithProviders(<UserHomePage />, ['/home'])
    expect(screen.getByLabelText('账户概览')).toHaveTextContent('jason')
    expect(screen.getByLabelText('服务数据加载中')).toBeInTheDocument()
    first.unmount()
    pending.mockRestore()

    authenticateUser()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'dashboard_query_timeout', message: 'private database query', request_id: 'dashboard-safe-3' },
    }, 504))
    renderWithProviders(<UserHomePage />, ['/home'])
    expect(await screen.findByText('服务数据查询超时，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText(/private database/i)).not.toBeInTheDocument()
    expect(screen.getByLabelText('账户概览')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '重试' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
  })

  it.each(['en-US', 'qps-ploc'] as const)(
    'renders localized loading, generic error, retry, and recovered status in %s',
    async (locale) => {
      await changeLocale(locale)
      const t = i18n.getFixedT(locale, 'userHome')
      const commonT = i18n.getFixedT(locale, 'common')
      authenticateUser()
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(json({
          error: { code: 'request_failed', message: 'private generic dashboard failure', request_id: 'dashboard-generic-error' },
        }, 500))
        .mockResolvedValueOnce(json(tenantDashboard('today', {
          available: false,
          reason: 'dependency_unavailable',
        })))
      renderWithProviders(<UserHomePage />, ['/home'])

      expect(screen.getByLabelText(t('states.loading'))).toBeInTheDocument()
      expect(await screen.findByText(t('errors.request_failed'))).toBeInTheDocument()
      expect(screen.queryByText(/private generic dashboard failure/i)).not.toBeInTheDocument()
      const retry = screen.getByRole('button', { name: commonT('retry') })
      expect(retry).toHaveTextContent(commonT('retry'))
      await userEvent.setup().click(retry)

      const statuses = await screen.findAllByRole('status')
      expect(statuses).toHaveLength(3)
      for (const status of statuses) expect(status).toHaveTextContent(t('unavailable.dependency_unavailable'))
      expect(screen.getByRole('heading', { name: t('sections.network') })).toBeInTheDocument()
      expect(screen.queryByText(t('errors.request_failed'))).not.toBeInTheDocument()
      expect(fetchSpy).toHaveBeenCalledTimes(2)
    },
  )

  it('uses the existing localized 403 surface for a server denial without leaking its raw message', async () => {
    authenticateUser()
    const deniedFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'dashboard_scope_forbidden', message: 'private scope', request_id: 'dashboard-safe-4' },
    }, 403))
    renderWithProviders(<UserHomePage />, ['/home'])
    expect(await screen.findByText('无权查看服务概览')).toBeInTheDocument()
    expect(screen.queryByText('账户概览')).not.toBeInTheDocument()
    expect(screen.queryByText('企业套餐')).not.toBeInTheDocument()
    expect(screen.queryByText(/private scope/i)).not.toBeInTheDocument()
    expect(deniedFetch).toHaveBeenCalledOnce()
  })

  it('accepts distinct tenant resource and access-scope IDs', async () => {
    authenticateUser({
      scope_id: '22222222-2222-4222-8222-222222222222',
      tenant_id: '33333333-3333-4333-8333-333333333333',
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard()))
    renderWithProviders(<UserHomePage />, ['/home'])
    expect(await screen.findByRole('heading', { name: '网络概览' })).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it.each([
    ['platform scope', { scope_kind: 'platform' as const, tenant_id: null }],
    ['missing scope ID', { scope_id: '' }],
    ['missing tenant ID', { tenant_id: null }],
    ['missing user ID', { user_id: '' }],
  ])('rejects %s locally before fetching', (_label, overrides) => {
    authenticateUser(overrides)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<UserHomePage />, ['/home'])
    expect(screen.getByText('无权查看服务概览')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects a zero session epoch locally before fetching', () => {
    authenticateUser()
    useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<UserHomePage />, ['/home'])
    expect(screen.getByText('无权查看服务概览')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each(tenantDashboardPermissions)(
    'rejects a tenant missing %s locally before fetching',
    (missingPermission) => {
      authenticateUser({ permissions: tenantDashboardPermissions.filter((permission) => permission !== missingPermission) })
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
      renderWithProviders(<UserHomePage />, ['/home'])
      expect(screen.getByText('无权查看服务概览')).toBeInTheDocument()
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )

  it('keeps pseudo-locale controls and the six-module surface available at 390px', async () => {
    await changeLocale('qps-ploc')
    authenticateUser()
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantDashboard()))
    renderWithProviders(<UserHomePage />, ['/home'])

    await waitFor(() => expect(document.querySelectorAll('.user-dashboard-card')).toHaveLength(6))
    expect(screen.getAllByRole('radiogroup')).toHaveLength(2)
    expect(document.querySelector('.user-dashboard-layout')).toBeInTheDocument()
    expect(document.querySelector('.user-dashboard-main')).toBeInTheDocument()
    expect(document.querySelector('.user-dashboard-side')).toBeInTheDocument()
    expect(document.querySelectorAll('.user-dashboard-card-extra')).toHaveLength(2)
  })
})
