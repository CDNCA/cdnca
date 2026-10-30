import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useLocation } from 'react-router-dom'

import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { DashboardAnalyticsView } from '../components/DashboardOverview'
import { RouteErrorBoundary } from '../components/RouteErrorBoundary'
import { AdminHomePage } from '../pages/AdminHomePage'
import { peakHourlyBandwidth } from '../pages/adminHomeMetrics'
import type { AdminDashboard, DashboardAnalyticsOverview } from '../api/dashboard'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultLookCSS } from '../test/defaultLookCSS'

const accessToken = 'memory-only-access-token'

const styles = defaultLookCSS(Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)
const referenceStyles = defaultLookCSS(Object.values(import.meta.glob('../styles/adminHomeReference.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)
const adminHomeSource = Object.values(import.meta.glob('../pages/AdminHomePage.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string
const dashboardOverviewSource = Object.values(import.meta.glob('../components/DashboardOverview.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string

function lastStyleRule(selector: string): CSSStyleRule {
  const style = document.createElement('style')
  style.textContent = `${styles}\n${referenceStyles}`
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
  style.remove()
  const matches = rules
    .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    .filter((rule) => !rule.selectorText.includes('.app-shell.is-dark'))
    .filter((rule) => rule.selectorText.split(',').some((part) => part.trim() === selector || part.trim().endsWith(` ${selector}`)))
  expect(matches.at(-1), `missing CSS rule ${selector}`).toBeDefined()
  return matches.at(-1) as CSSStyleRule
}

function lastStyleRuleWithProperty(selector: string, property: string): CSSStyleRule {
  const style = document.createElement('style')
  style.textContent = `${styles}\n${referenceStyles}`
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
  style.remove()
  const matches = rules
    .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    .filter((rule) => !rule.selectorText.includes('.app-shell.is-dark'))
    .filter((rule) => rule.selectorText.split(',').some((part) => part.trim() === selector || part.trim().endsWith(` ${selector}`)))
    .filter((rule) => rule.style.getPropertyValue(property) !== '')
  expect(matches.at(-1), `missing CSS rule ${selector} with ${property}`).toBeDefined()
  return matches.at(-1) as CSSStyleRule
}

const echartsMock = vi.hoisted(() => {
  const setOption = vi.fn()
  const chart = { setOption, resize: vi.fn(), dispose: vi.fn() }
  const LinearGradient = vi.fn((...args: unknown[]) => ({ args }))
  return { init: vi.fn(() => chart), setOption, LinearGradient }
})

vi.mock('../components/echartsRuntime', () => ({ init: echartsMock.init, graphic: { LinearGradient: echartsMock.LinearGradient } }))

function authenticateAdmin(overrides: Parameters<typeof principal>[0] = {}) {
  const admin = principal({
    scope_kind: 'platform', tenant_id: null, username: 'admin', display_name: 'Administrator', roles: ['platform_admin'],
    permissions: ['platform.admin'], display_id: '1',
    ...overrides,
  } as Parameters<typeof principal>[0] & { display_id?: string })
  useSessionStore.getState().setSession(authResponse(admin), admin)
  return admin
}

function AdminHomePageWithQueryClient({ capture }: { capture: (queryClient: QueryClient) => void }) {
  const queryClient = useQueryClient()
  capture(queryClient)
  return <AdminHomePage />
}

function LocationProbe() {
  return <output data-testid="location-path">{useLocation().pathname}</output>
}

function renderDashboard() {
  let queryClient: QueryClient | undefined
  const view = renderWithProviders(
    <AdminHomePageWithQueryClient capture={(client) => { queryClient = client }} />,
    ['/admin-home'],
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

function adminDashboard(range = 'seven_days', analytics: unknown = { available: false, reason: 'dependency_timeout' }) {
  return {
    dashboard_version: 2,
    meta: {
      range, timezone: 'Asia/Shanghai', from: '2026-07-24T16:00:00Z', to: '2026-07-31T16:00:00Z',
      generated_at: '2026-07-31T08:00:00Z', snapshot_at: '2026-07-31T08:00:00.000Z', window_complete: false,
    },
    accounts: { available: true, value: { tenants_total: 12, tenants_active: 10, tenant_users_total: 3456, tenant_users_active: 3000 } },
    subscriptions: { available: true, value: { active: 23 } },
    billing: { available: true, value: { currency: 'CNY', gross_settled_debit_minor: '900719925474099312345', reversed_credit_minor: '12345', net_settled_minor: '900719925474099300000' } },
    resources: { available: true, value: { sites_total: 88, sites_active: 80, sites_sync_failed: 2, domains_total: 96, forwards_total: 24, nodes_total: 6, certificates_total: 72, certificates_valid: 70, certificates_expiring_30d: 3 } },
    operations: { available: true, value: { cache_total: 9, cache_open: 2, cache_failed: 1, jobs_total: 10, jobs_open: 3, jobs_failed: 1 } },
    profile: { available: true, value: { last_login_at: '2026-07-31T07:45:00Z', last_login_ip: '192.0.2.10', last_login_geo: 'CN' } },
    entitlement: { available: true, value: { installation_id: 'control-primary', status: 'uninstalled', node_limit: 30, lease_status: null } },
    node_health: { available: true, value: { total: 6, online_fresh: 5, stale_or_offline: 1, presence_missing: 0, freshness_cutoff_seconds: 45 } },
    analytics_health: { available: true, value: { active_streams: 4, unprepared_stream_gap: '900719925474099312345' } },
    account_security: { available: true, value: { active_sessions: 3, users_with_mfa: 2, active_api_keys: 1, recovery_codes_remaining: 6 } },
    network: { available: true, value: { nodes_total: 6, nodes_active: 5, nodes_online: 5, nodes_stale: 1, freshness_cutoff_seconds: 45, regions: [{ region: 'cn-east', nodes_total: 6, nodes_online: 5 }] } },
    analytics,
  }
}

function dashboardWithFacts(
  range: string,
  installationId: string,
  tenantUsersTotal: number,
  netSettledMinor: string,
  certificatesTotal: number,
  nodesTotal: number,
) {
  const dashboard = adminDashboard(range)
  return {
    ...dashboard,
    accounts: { available: true, value: { ...dashboard.accounts.value, tenant_users_total: tenantUsersTotal } },
    billing: { available: true, value: { ...dashboard.billing.value, net_settled_minor: netSettledMinor } },
    resources: { available: true, value: { ...dashboard.resources.value, certificates_total: certificatesTotal } },
    entitlement: { available: true, value: { ...dashboard.entitlement.value, installation_id: installationId } },
    node_health: { available: true, value: { ...dashboard.node_health.value, total: nodesTotal } },
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function analyticsFallbackResponse() {
  return json({ error: { code: 'analytics_storage_unavailable', message: 'private analytics storage', request_id: 'analytics-test' } }, 503)
}

function analyticsFixtures() {
  const meta = { from: '2026-07-31T00:00:00Z', to: '2026-08-01T00:00:00Z', timezone: 'UTC', metric_version: 1 as const }
  const summary = {
    metric_version: 1 as const, request_count: 42, request_bytes: 100, response_bytes: 200, total_bytes: 300,
    average_bandwidth_bps: 4096, status_2xx: 40, status_3xx: 1, status_4xx: 1, status_5xx: 0, security_events: 2, security_event_rows: 2, cache_hit_requests: 0, cache_hit_bytes: 0, unique_client_ips: 0,
  }
  const trend = [{ ...summary, hour: '2026-07-31T00:00:00Z' }]
  const rank = (dimension: string) => json({
    data: [], dimension, page: { snapshot_at: meta.to, source: 'history' }, meta,
  })
  return { meta, summary, trend, rank }
}

function dashboardFetchCalls(fetchSpy: { mock: { calls: Array<[unknown, unknown?]> } }) {
  return fetchSpy.mock.calls.filter(([input]) => new URL(String(input), 'https://web.test').pathname === '/v1/admin/dashboard')
}

function analyticsFetchCalls(fetchSpy: { mock: { calls: Array<[unknown, unknown?]> } }) {
  return fetchSpy.mock.calls.filter(([input]) => new URL(String(input), 'https://web.test').pathname.startsWith('/v1/admin/analytics/'))
}

function mockDashboardFetch(dashboard: unknown = adminDashboard()) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const pathname = new URL(String(input), 'https://web.test').pathname
    if (pathname === '/v1/admin/dashboard') return json(dashboard)
    if (pathname.includes('/v1/admin/analytics/')) return analyticsFallbackResponse()
    throw new Error(`Unexpected request: ${pathname}`)
  })
}

describe('AdminHomePage', () => {
  it('keeps React status nodes outside the renderer-owned DOM when ranges change', async () => {
    authenticateAdmin()
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname !== '/v1/admin/dashboard') return analyticsFallbackResponse()
      const range = url.searchParams.get('range') ?? 'seven_days'
      const populated = range === 'thirty_days'
      return json({
        ...adminDashboard(range),
        operation_charts: { available: true, value: {
          new_users: populated ? [{ time: '2026-07-30T00:00:00Z', count: 1 }] : [],
          package_sold: populated ? [{ time: '2026-07-30T00:00:00Z', count: 1 }] : [],
          recharge: populated ? [{ time: '2026-07-30T00:00:00Z', sum_minor: '100' }] : [],
        } },
      })
    })
    const view = renderWithProviders(<RouteErrorBoundary><AdminHomePage /></RouteErrorBoundary>, ['/admin-home'])
    await screen.findByText('3,456')
    const wrappers = [...view.container.querySelectorAll('.dashboard-operation-chart__canvas')]
    // 社区版：运营数据只剩注册用户一张图（开通套餐、充值金额已删）。
    expect(wrappers).toHaveLength(1)
    // ECharts clears its host; simulate that DOM ownership without requiring a canvas renderer in jsdom.
    for (const wrapper of wrappers) {
      const host = wrapper.querySelector('.dashboard-operation-chart__plot') ?? wrapper
      host.replaceChildren(document.createElement('canvas'))
    }
    const user = userEvent.setup()
    const rangeGroup = screen.getByRole('radiogroup', { name: '运营数据时间范围' })
    await user.click(within(rangeGroup).getByRole('radio', { name: '近30日' }))
    await waitFor(() => expect(screen.queryByText('服务异常')).not.toBeInTheDocument())
    expect(within(screen.getByRole('radiogroup', { name: '运营数据时间范围' })).getByRole('radio', { name: '近30日' })).toHaveAttribute('aria-checked', 'true')
    await user.click(within(screen.getByRole('radiogroup', { name: '运营数据时间范围' })).getByRole('radio', { name: '近7日' }))
    await waitFor(() => expect(screen.queryByText('服务异常')).not.toBeInTheDocument())
    expect(view.container.querySelectorAll('.dashboard-operation-chart__plot > canvas')).toHaveLength(1)
    expect(view.container.querySelectorAll('.dashboard-operation-chart__canvas > h3')).toHaveLength(1)
  })

  it('locks the observed compact dashboard geometry and final visual layer', () => {
    const layout = lastStyleRule('.dashboard-reference-layout')
    expect(layout.style.getPropertyValue('grid-template-columns')).toBe('minmax(0, calc(66.666667% - 5.333333px)) minmax(0, calc(33.333333% - 10.666667px))')
    expect(layout.style.getPropertyValue('gap')).toBe('16px')
    expect(referenceStyles).not.toContain('@media (min-width: 761px) and (max-width: 1340px)')
    expect(referenceStyles).toContain('@media (max-width: 767px)')

    const card = lastStyleRuleWithProperty('.dashboard-reference-operations', 'border')
    expect(card.style.getPropertyValue('border')).toBe('1px solid #e5eaf3')
    expect(lastStyleRuleWithProperty('.dashboard-reference-operations', 'border-radius').style.getPropertyValue('border-radius')).toBe('8px')
    expect(lastStyleRuleWithProperty('.dashboard-reference-operations', 'box-shadow').style.getPropertyValue('box-shadow')).toBe('0 1px 2px rgb(15 23 42 / 4%)')
    expect(lastStyleRuleWithProperty('.dashboard-reference-network', 'box-shadow').style.getPropertyValue('box-shadow')).toBe('0 1px 2px rgb(15 23 42 / 4%)')
    expect(lastStyleRuleWithProperty('.dashboard-reference-operations', 'min-height').style.getPropertyValue('min-height')).toBe('312px')
    expect(lastStyleRuleWithProperty('.dashboard-reference-network', 'min-height').style.getPropertyValue('min-height')).toBe('166px')

    expect(lastStyleRuleWithProperty('.dashboard-reference-main', 'gap').style.getPropertyValue('gap')).toBe('16px')
    expect(lastStyleRuleWithProperty('.dashboard-reference-side', 'gap').style.getPropertyValue('gap')).toBe('16px')

    const chart = lastStyleRule('.dashboard-operation-chart__canvas')
    expect(chart.style.getPropertyValue('height')).toBe('220px')
    expect(chart.style.getPropertyValue('min-height')).toBe('220px')
    expect(chart.style.getPropertyValue('border')).toBe('1px solid #edf1f7')
    expect(chart.style.getPropertyValue('border-radius')).toBe('6px')
    expect(chart.style.getPropertyValue('background')).toBe('#f8fafc')

    const operationPanel = lastStyleRuleWithProperty('.dashboard-operation-panel', 'border')
    expect(operationPanel.style.getPropertyValue('border')).toBe('0')
    expect(lastStyleRuleWithProperty('.dashboard-operation-panel', 'border-radius').style.getPropertyValue('border-radius')).toBe('0')
    expect(lastStyleRuleWithProperty('.dashboard-operation-panel', 'background').style.getPropertyValue('background')).toBe('transparent')
    expect(lastStyleRuleWithProperty('.dashboard-operation-panel', 'padding').style.getPropertyValue('padding')).toBe('0 6px')

    expect(lastStyleRuleWithProperty('.dashboard-profile-card', 'height').style.getPropertyValue('height')).toBe('auto')
    expect(lastStyleRuleWithProperty('.dashboard-profile-card', 'min-height').style.getPropertyValue('min-height')).toBe('0')
    expect(lastStyleRuleWithProperty('.dashboard-profile-content', 'min-height').style.getPropertyValue('min-height')).toBe('0')
    expect(lastStyleRuleWithProperty('.dashboard-profile-title-row', 'height').style.getPropertyValue('height')).toBe('auto')
    expect(lastStyleRuleWithProperty('.dashboard-profile-meta', 'display').style.getPropertyValue('display')).toBe('block')
    expect(lastStyleRuleWithProperty('.dashboard-profile-meta .resource-id', 'display').style.getPropertyValue('display')).toBe('inline-block')
    expect(lastStyleRuleWithProperty('.dashboard-status-list', 'margin-top').style.getPropertyValue('margin-top')).toBe('16px')
    expect(lastStyleRuleWithProperty('.dashboard-info-rows', 'margin-top').style.getPropertyValue('margin-top')).toBe('16px')

    const metricBand = lastStyleRuleWithProperty('.dashboard-reference-network .dashboard-metric-band', 'min-height')
    expect(metricBand.style.getPropertyValue('min-height')).toBe('84px')
    const metric = lastStyleRuleWithProperty('.dashboard-reference-network .dashboard-metric', 'border')
    expect(metric.style.getPropertyValue('border')).toBe('1px solid #edf1f7')
    expect(lastStyleRuleWithProperty('.dashboard-reference-network .dashboard-metric', 'border-radius').style.getPropertyValue('border-radius')).toBe('6px')
    expect(lastStyleRuleWithProperty('.dashboard-reference-network .dashboard-metric', 'background').style.getPropertyValue('background')).toBe('#f8fafc')

    const tab = lastStyleRule('.dashboard-trend-tablist button')
    expect(tab.style.getPropertyValue('margin-right')).toBe('6px')
    expect(tab.style.getPropertyValue('padding')).toBe('6px 16px')
    expect(tab.style.getPropertyValue('line-height')).toBe('21px')
    expect(tab.style.getPropertyValue('border-radius')).toBe('8px')

    const activeTab = lastStyleRule('.dashboard-trend-tablist button.is-active')
    expect(activeTab.style.getPropertyValue('font-weight')).toBe('600')
    expect(activeTab.style.getPropertyValue('background')).toBe('rgb(45 140 240 / 12%)')
    expect(activeTab.style.getPropertyValue('box-shadow')).toBe('none')

    const hoverTab = lastStyleRule('.dashboard-trend-tablist button:not(.is-disabled):hover')
    expect(hoverTab.style.getPropertyValue('color')).toBe('var(--cdnca-color-primary)')
    expect(hoverTab.style.getPropertyValue('background')).toBe('#f5f7fa')

    const activeHoverTab = lastStyleRule('.dashboard-trend-tablist button.is-active:hover')
    expect(activeHoverTab.style.getPropertyValue('background')).toBe('rgb(45 140 240 / 12%)')
  })

  it('wires operation chart container resizing and cleanup for sidebar transitions', () => {
    const panel = adminHomeSource.slice(adminHomeSource.indexOf('function DashboardOperationPanel('), adminHomeSource.indexOf('function DashboardBlock('))
    expect(panel).toContain('observer = new ResizeObserver(() => chart?.resize())')
    expect(panel).toContain('observer.observe(containerRef.current)')
    expect(panel).toContain('observer?.disconnect()')
  })

  it('keeps axes, tooltip configuration, and an empty graphic when chart series have no points', () => {
    expect(adminHomeSource).toContain("xAxis: { type: 'category'")
    expect(adminHomeSource).toContain("yAxis: { type: 'value'")
    expect(adminHomeSource).toContain("tooltip: {\n          trigger: 'axis'")
    expect(adminHomeSource).toContain("title: { text: title, left: 16, top: 12, padding: 0,")
    expect(adminHomeSource).toContain('graphic: chartPoints.length === 0 ? {')
    expect(dashboardOverviewSource).toContain("xAxis: {\n          type: 'category'")
    expect(dashboardOverviewSource).toContain("yAxis: {\n          type: 'value'")
    expect(dashboardOverviewSource).toContain("tooltip: {\n          trigger: 'axis'")
    expect(dashboardOverviewSource).toContain('showAllSymbol: true')
    expect(dashboardOverviewSource).toContain('graphic: analytics.trend.length === 0 ? {')
  })

  it('requests the exact administrator route and renders authoritative values with local analytics degradation', async () => {
    const admin = authenticateAdmin()
    const fetchSpy = mockDashboardFetch()
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    expect(screen.getAllByRole('status').length).toBeGreaterThan(0)
    expect(screen.queryByText('¥9,007,199,254,740,993,123.45')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '系统状态' })).toBeInTheDocument()
    expect(screen.queryByText('Elasticsearch')).toBeNull()
    expect(screen.getByRole('heading', { name: '系统授权' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '使用统计' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'TOP10 数据 (近30分钟)' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '上一组排行' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下一组排行' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '注册用户', level: 3 })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '开通套餐', level: 3 })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '充值金额', level: 3 })).not.toBeInTheDocument()
    expect(screen.getAllByText('无数据')).toHaveLength(1)
    expect(screen.getByText('域名数').parentElement).toHaveTextContent('96')
    expect(screen.getByText('转发数').parentElement).toHaveTextContent('24')
    expect(screen.getByText('授权节点').parentElement).toHaveTextContent('30')
    expect(screen.getByText('当前节点').parentElement).toHaveTextContent('6')
    expect(document.querySelectorAll('.dashboard-operation-panel')).toHaveLength(1)
    expect(document.querySelectorAll('.dashboard-monitoring-grid > .dashboard-block')).toHaveLength(2)
    expect(document.querySelectorAll('.dashboard-card-title')).toHaveLength(7)
    expect(document.querySelectorAll('.dashboard-info-rows')).toHaveLength(2)
    expect(document.querySelectorAll('.dashboard-status-value')).toHaveLength(3)
    expect(document.querySelectorAll('.dashboard-range-control')).toHaveLength(3)
    expect(screen.getByRole('radiogroup', { name: '运营数据时间范围' }).querySelector('[aria-checked="true"]')).toHaveTextContent('近7日')
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByLabelText('1')).toHaveTextContent('1')
    expect(screen.getByText('账号ID:').parentElement).not.toHaveTextContent(admin.user_id)
    expect(screen.getByText('2026-07-31 15:45:00')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.10 (中国)')).toBeInTheDocument()
    expect(dashboardFetchCalls(fetchSpy)).toHaveLength(1)
    const [url, init] = dashboardFetchCalls(fetchSpy)[0]
    const parsed = new URL(String(url), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/admin/dashboard')
    expect(Object.fromEntries(parsed.searchParams)).toEqual({ range: 'seven_days', timezone: 'Asia/Shanghai' })
    expect(init).toEqual(expect.objectContaining({
      credentials: 'include', headers: { Authorization: `Bearer ${accessToken}` }, signal: expect.any(AbortSignal),
    }))
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: '运营数据' })).toHaveAttribute('data-dashboard-state', 'ready')
    expect(screen.getByRole('region', { name: '运营数据' })).toHaveAttribute('aria-busy', 'false')
  })

  it('shows an unlimited licensed-node count as 不限 (W1)', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard() as { entitlement: { value: Record<string, unknown> } }
    dashboard.entitlement.value.node_limit = 9007199254740991
    mockDashboardFetch(dashboard)
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('授权节点')).toBeInTheDocument()
    expect(screen.getByText('授权节点').parentElement).toHaveTextContent('不限')
    expect(screen.queryByText('9,007,199,254,740,991')).not.toBeInTheDocument()
  })

  it('renders the login source as country name, region and city like the reference overview', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard() as unknown as AdminDashboard
    dashboard.profile = { available: true, value: {
      last_login_at: '2026-07-31T07:45:00Z', last_login_ip: '203.0.113.61',
      last_login_geo: 'CN', last_login_region: '山东省', last_login_city: '潍坊市',
    } }
    mockDashboardFetch(dashboard)
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('203.0.113.61 (中国-山东省-潍坊市)')).toBeInTheDocument()
  })

  it('hides the profile edit affordance without identity.self.read', async () => {
    authenticateAdmin()
    mockDashboardFetch()
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑个人资料' })).not.toBeInTheDocument()
  })

  it('keeps the profile edit affordance accessible and routes admins to their own profile', async () => {
    authenticateAdmin({ permissions: ['platform.admin', 'identity.self.read'] })
    mockDashboardFetch()
    renderWithProviders(<><AdminHomePage /><LocationProbe /></>, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const edit = screen.getByRole('button', { name: '编辑个人资料' })
    expect(edit).toHaveClass('dashboard-profile-edit')
    await userEvent.setup().click(edit)
    // fp-role ID-02：编辑个人资料进自己的资料页，不是用户列表。
    expect(screen.getByTestId('location-path')).toHaveTextContent('/account/user')
  })

  it('keeps operation charts visible when an unrelated summary section is unavailable', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard() as unknown as AdminDashboard
    dashboard.accounts = { available: false, reason: 'dependency_unavailable' }
    dashboard.subscriptions = { available: false, reason: 'dependency_unavailable' }
    dashboard.billing = { available: false, reason: 'dependency_unavailable' }
    dashboard.operation_charts = {
      available: true,
      value: { new_users: [], package_sold: [], recharge: [] },
    }
    mockDashboardFetch(dashboard)

    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findAllByText('无数据')).toHaveLength(1)
    const operations = document.querySelector('.dashboard-reference-operations')
    expect(operations).not.toBeNull()
    expect(within(operations as HTMLElement).queryByText('依赖服务暂不可用')).not.toBeInTheDocument()
  })

  it('keeps the control-plane status healthy when only node network facts are unavailable', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard('seven_days', { available: false, reason: 'authoritative_fact_missing' }) as unknown as AdminDashboard
    dashboard.network = { available: false, reason: 'dependency_unavailable' }
    dashboard.node_health = { available: true, value: { total: 6, online_fresh: 6, stale_or_offline: 0, presence_missing: 0, freshness_cutoff_seconds: 45 } }
    dashboard.analytics_health = { available: true, value: { active_streams: 4, unprepared_stream_gap: '0' } }
    mockDashboardFetch(dashboard)
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const statusCard = screen.getByRole('heading', { name: '系统状态' }).closest('section')
    expect(statusCard).not.toBeNull()
    expect(within(statusCard as HTMLElement).getAllByLabelText('正常')).toHaveLength(3)
    expect(within(statusCard as HTMLElement).getByText('主控状态').parentElement).not.toHaveTextContent('正常')
  })

  it('loads the default today analytics when the seven-day dashboard snapshot is unavailable', async () => {
    authenticateAdmin()
    const analyticsMeta = { from: '2026-07-31T00:00:00Z', to: '2026-08-01T00:00:00Z', timezone: 'UTC', metric_version: 1 as const }
    const summary = {
      metric_version: 1 as const, request_count: 42, request_bytes: 100, response_bytes: 200, total_bytes: 300,
      average_bandwidth_bps: 4096, status_2xx: 40, status_3xx: 1, status_4xx: 1, status_5xx: 0, security_events: 2, security_event_rows: 2, cache_hit_requests: 0, cache_hit_bytes: 0, unique_client_ips: 0,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (url.pathname.endsWith('/analytics/summary')) return json({ data: summary, meta: analyticsMeta })
      if (url.pathname.endsWith('/analytics/hourly-trend')) return json({ data: [], meta: analyticsMeta })
      if (url.pathname.endsWith('/analytics/blocked-ip-count')) return json({ blocked_ip_count: 0, meta: analyticsMeta })
      if (url.pathname.endsWith('/analytics/blocked-ip-trend')) return json({ data: [], meta: analyticsMeta })
      const dimension = url.pathname.match(/\/analytics\/top\/(domain|url|ip|region|carrier)$/)?.[1]
      if (dimension) return json({ data: [], dimension, page: { snapshot_at: analyticsMeta.to, source: 'history' }, meta: analyticsMeta })
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsFetchCalls(fetchSpy)).toHaveLength(9))
    expect(screen.queryByText('依赖服务暂不可用')).not.toBeInTheDocument()
    const blockedTab = screen.getByRole('tab', { name: '拉黑IP数' })
    expect(blockedTab).toHaveAttribute('aria-disabled', 'false')
    await userEvent.setup().click(blockedTab)
    expect(blockedTab).toHaveAttribute('aria-selected', 'true')
  })

  function mockFullAnalyticsFetch(dashboardFor: (range: string) => unknown = (range) => adminDashboard(range)) {
    const fixture = analyticsFixtures()
    return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(dashboardFor(url.searchParams.get('range') ?? 'seven_days'))
      if (url.pathname.endsWith('/analytics/summary')) return json({ data: fixture.summary, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/hourly-trend')) return json({ data: fixture.trend, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/blocked-ip-count')) return json({ blocked_ip_count: 0, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/blocked-ip-trend')) return json({ data: [], meta: fixture.meta })
      const dimension = url.pathname.match(/\/analytics\/top\/(domain|url|ip|region|carrier)$/)?.[1]
      if (dimension) return fixture.rank(dimension)
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
  }

  function analyticsWindows(fetchSpy: { mock: { calls: Array<[unknown, unknown?]> } }, suffix: string) {
    return analyticsFetchCalls(fetchSpy)
      .map(([input]) => new URL(String(input), 'https://web.test'))
      .filter((url) => url.pathname.endsWith(suffix))
      .map((url) => ({ from: url.searchParams.get('from'), to: url.searchParams.get('to') }))
  }

  it('requests the default network and monitor analytics once when both ranges are equal', async () => {
    authenticateAdmin()
    const fetchSpy = mockFullAnalyticsFetch()
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsFetchCalls(fetchSpy)).toHaveLength(9))
    expect(analyticsWindows(fetchSpy, '/analytics/summary')).toEqual([
      { from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T16:00:00.000Z' },
    ])
    expect(analyticsFetchCalls(fetchSpy).filter(([input]) => String(input).includes('/analytics/top/carrier'))).toHaveLength(0)
  })

  it('keeps the network today window when the operations range moves to the previous month', async () => {
    authenticateAdmin()
    const fetchSpy = mockFullAnalyticsFetch((range) => range === 'previous_month'
      ? { ...adminDashboard(range), meta: { ...adminDashboard(range).meta, from: '2026-05-31T16:00:00Z', to: '2026-06-30T16:00:00Z' } }
      : adminDashboard(range))
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsWindows(fetchSpy, '/analytics/summary')).toHaveLength(1))
    await userEvent.setup().click(within(screen.getByRole('radiogroup', { name: '运营数据时间范围' })).getByText('上个月'))
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))
    await waitFor(() => expect(screen.getByRole('radiogroup', { name: '运营数据时间范围' }).querySelector('[aria-checked="true"]')).toHaveTextContent('上个月'))
    const windows = analyticsWindows(fetchSpy, '/analytics/summary')
    expect(new Set(windows.map((window) => JSON.stringify(window)))).toEqual(new Set([
      JSON.stringify({ from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T16:00:00.000Z' }),
    ]))
  })

  it('reads a real seven-day network window instead of the thirty-day operations baseline', async () => {
    authenticateAdmin()
    const baseline = {
      summary: { metric_version: 1, request_count: '999', request_bytes: '0', response_bytes: '0', total_bytes: '0',
        average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0' },
      trend: [], top: ['domain', 'region', 'carrier'].map((dimension) => ({ dimension, snapshot_at: '2026-07-31T08:00:00Z', items: [] })),
    }
    const fetchSpy = mockFullAnalyticsFetch((range) => adminDashboard(range, { available: true, value: baseline }))
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const user = userEvent.setup()
    await user.click(within(screen.getByRole('radiogroup', { name: '运营数据时间范围' })).getByText('近30日'))
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))
    await user.click(within(screen.getByRole('radiogroup', { name: '网络概览时间范围' })).getByText('近7日'))
    await waitFor(() => expect(analyticsWindows(fetchSpy, '/analytics/summary')).toContainEqual(
      { from: '2026-07-24T16:00:00.000Z', to: '2026-07-31T16:00:00.000Z' }))
    await waitFor(() => expect(screen.getByText('请求数', { selector: 'dt' }).parentElement).toHaveTextContent('42次'))
  })

  it('reuses the seven-day dashboard analytics only when both ranges are seven days', async () => {
    authenticateAdmin()
    const baseline = {
      summary: { metric_version: 1, request_count: '999', request_bytes: '0', response_bytes: '0', total_bytes: '0',
        average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0' },
      trend: [], top: ['domain', 'region', 'carrier'].map((dimension) => ({ dimension, snapshot_at: '2026-07-31T08:00:00Z', items: [] })),
    }
    const fetchSpy = mockFullAnalyticsFetch((range) => adminDashboard(range, { available: true, value: baseline }))
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsWindows(fetchSpy, '/analytics/summary')).toHaveLength(1))
    await userEvent.setup().click(within(screen.getByRole('radiogroup', { name: '网络概览时间范围' })).getByText('近7日'))
    await waitFor(() => expect(screen.getByText('请求数', { selector: 'dt' }).parentElement).toHaveTextContent('999次'))
    expect(analyticsWindows(fetchSpy, '/analytics/summary')).toHaveLength(1)
  })

  it('reads TOP10 from a fixed minute-aligned last-30-minutes window independent of the monitor range', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard()
    const fetchSpy = mockFullAnalyticsFetch(() => ({ ...dashboard, meta: { ...dashboard.meta, generated_at: '2026-07-31T08:17:42.512Z' } }))
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsFetchCalls(fetchSpy)).toHaveLength(9))
    const expected = { from: '2026-07-31T07:47:00.000Z', to: '2026-07-31T08:17:00.000Z' }
    for (const dimension of ['domain', 'url', 'ip', 'region']) {
      expect(analyticsWindows(fetchSpy, `/analytics/top/${dimension}`)).toEqual([expected])
    }
    await userEvent.setup().click(within(screen.getByRole('radiogroup', { name: '监控趋势时间范围' })).getByText('近30日'))
    await waitFor(() => expect(analyticsWindows(fetchSpy, '/analytics/summary')).toHaveLength(2))
    expect(analyticsFetchCalls(fetchSpy).filter(([input]) => String(input).includes('/analytics/top/'))).toHaveLength(4)
    expect(screen.getByRole('tab', { name: '国家' })).toHaveAttribute('aria-disabled', 'false')
  })

  it('shows the TOP10 URL as scheme://host:port/path from the analytics rank address (AUDIT-FINAL-1027 P8)', async () => {
    authenticateAdmin()
    const fixture = analyticsFixtures()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (url.pathname.endsWith('/analytics/summary')) return json({ data: fixture.summary, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/hourly-trend')) return json({ data: fixture.trend, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/blocked-ip-count') || url.pathname.endsWith('/analytics/blocked-ip-trend')) return analyticsFallbackResponse()
      if (url.pathname.endsWith('/analytics/top/url')) {
        return json({ data: [{ key: 'www.example.test:8443/a', request_count: 3, response_bytes: 9, host: 'www.example.test', port: 8443, path: '/a', scheme: 'https' }],
          dimension: 'url', page: { snapshot_at: fixture.meta.to, source: 'history' }, meta: fixture.meta })
      }
      const dimension = url.pathname.match(/\/analytics\/top\/(domain|ip|region|carrier)$/)?.[1]
      if (dimension) return fixture.rank(dimension)
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    await userEvent.setup().click(await screen.findByRole('tab', { name: 'URL' }))
    expect(await screen.findByText('https://www.example.test:8443/a')).toBeInTheDocument()
    // 列头与页签一致（10-27 用户：列名跟下面显示的不是一个东西）。
    const top = screen.getByRole('region', { name: 'TOP10 数据 (近30分钟)' })
    expect(within(top).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['URL', '请求数', '响应流量'])
  })

  it('derives the Agent and analytics indicators from real health facts', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard('seven_days', { available: false, reason: 'dependency_unavailable' }) as unknown as AdminDashboard
    dashboard.node_health = { available: true, value: { total: 6, online_fresh: 5, stale_or_offline: 1, presence_missing: 0, freshness_cutoff_seconds: 45 } }
    dashboard.analytics_health = { available: true, value: { active_streams: 4, unprepared_stream_gap: '0' } }
    mockDashboardFetch(dashboard)
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const statusCard = screen.getByRole('heading', { name: '系统状态' }).closest('section') as HTMLElement
    expect(within(statusCard).getByText('分析服务').parentElement).toHaveTextContent('暂不可用')
    expect(within(statusCard).getByText('Agent状态').parentElement).toHaveTextContent('暂不可用')
    expect(within(statusCard).getByText('主控状态').parentElement).not.toHaveTextContent('暂不可用')
    expect(within(statusCard).getByText('1 个节点离线或超过 45 秒未上报心跳，请到节点列表查看')).toBeInTheDocument()
  })

  it('reports analytics as unavailable while acknowledged history is not yet prepared', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard('seven_days', { available: false, reason: 'authoritative_fact_missing' }) as unknown as AdminDashboard
    dashboard.node_health = { available: true, value: { total: 0, online_fresh: 0, stale_or_offline: 0, presence_missing: 0, freshness_cutoff_seconds: 45 } }
    dashboard.analytics_health = { available: true, value: { active_streams: 1, unprepared_stream_gap: '12' } }
    mockDashboardFetch(dashboard)
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const statusCard = screen.getByRole('heading', { name: '系统状态' }).closest('section') as HTMLElement
    expect(within(statusCard).getByText('分析服务').parentElement).toHaveTextContent('暂不可用')
    expect(within(statusCard).getByText('Agent状态').parentElement).not.toHaveTextContent('暂不可用')
  })

  it('keeps core trend and TOP10 data when optional analytics dependencies fail', async () => {
    authenticateAdmin()
    const fixture = analyticsFixtures()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (url.pathname.endsWith('/analytics/summary')) return json({ data: fixture.summary, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/hourly-trend')) return json({ data: fixture.trend, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/blocked-ip-count') || url.pathname.endsWith('/analytics/blocked-ip-trend') ||
        url.pathname.endsWith('/analytics/top/url') || url.pathname.endsWith('/analytics/top/ip')) return analyticsFallbackResponse()
      const dimension = url.pathname.match(/\/analytics\/top\/(domain|region|carrier)$/)?.[1]
      if (dimension) return fixture.rank(dimension)
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsFetchCalls(fetchSpy)).toHaveLength(9))
    expect(screen.queryByText('依赖服务暂不可用')).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '拉黑IP数' })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('tab', { name: 'URL' })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('tab', { name: 'IP' })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('tab', { name: '国家' })).toHaveAttribute('aria-disabled', 'false')
  })

  it('shows a known blocked-IP count but keeps its trend tab disabled when the trend dependency fails', async () => {
    authenticateAdmin()
    const fixture = analyticsFixtures()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (url.pathname.endsWith('/analytics/summary')) return json({ data: fixture.summary, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/hourly-trend')) return json({ data: fixture.trend, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/blocked-ip-count')) return json({ blocked_ip_count: 7, meta: fixture.meta })
      if (url.pathname.endsWith('/analytics/blocked-ip-trend')) return analyticsFallbackResponse()
      const dimension = url.pathname.match(/\/analytics\/top\/(domain|url|ip|region|carrier)$/)?.[1]
      if (dimension) return fixture.rank(dimension)
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await waitFor(() => expect(analyticsFetchCalls(fetchSpy)).toHaveLength(9))
    expect(screen.getByText('拉黑IP数', { selector: 'dt' }).parentElement).toHaveTextContent('7个')
    expect(screen.getByRole('tab', { name: '拉黑IP数' })).toHaveAttribute('aria-disabled', 'true')
  })

  it.each([
    { bytes: 0, peak: 0, trafficLabel: '0KB', bandwidthLabel: '0Kbps' },
    { bytes: 300, peak: 500, trafficLabel: '0.29KB', bandwidthLabel: '0.5Kbps' },
    { bytes: 1024, peak: 1000, trafficLabel: '1KB', bandwidthLabel: '1Kbps' },
    { bytes: 1048576, peak: 1000000, trafficLabel: '1MB', bandwidthLabel: '1Mbps' },
  ])('queries real analytics with reference minimum units ($trafficLabel / $bandwidthLabel)', async ({ bytes, peak, trafficLabel, bandwidthLabel }) => {
    authenticateAdmin()
    const analyticsMeta = { from: '2026-07-31T00:00:00Z', to: '2026-08-01T00:00:00Z', timezone: 'UTC', metric_version: 1 as const }
    const summary = {
      metric_version: 1 as const, request_count: 42, request_bytes: 0, response_bytes: bytes, total_bytes: bytes,
      average_bandwidth_bps: peak, status_2xx: 40, status_3xx: 1, status_4xx: 1, status_5xx: 0, security_events: 2, security_event_rows: 2, cache_hit_requests: 0, cache_hit_bytes: 0, unique_client_ips: 0,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (url.pathname.endsWith('/analytics/summary')) return json({ data: summary, meta: analyticsMeta })
      if (url.pathname.endsWith('/analytics/hourly-trend')) return json({ data: [{ ...summary, hour: analyticsMeta.from }], meta: analyticsMeta })
      if (url.pathname.endsWith('/analytics/blocked-ip-count')) return json({ blocked_ip_count: 7, meta: analyticsMeta })
      if (url.pathname.endsWith('/analytics/blocked-ip-trend')) return json({ data: [], meta: analyticsMeta })
      const dimension = url.pathname.match(/\/analytics\/top\/(domain|url|ip|region|carrier)$/)?.[1]
      if (dimension) return json({ data: [], dimension, page: { snapshot_at: analyticsMeta.to, source: 'history' }, meta: analyticsMeta })
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(within(screen.getByRole('radiogroup', { name: '网络概览时间范围' })).getByText('昨日'))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/v1/admin/analytics/')).length).toBe(14))
    const networkRequest = fetchSpy.mock.calls.find(([input]) => {
      const url = new URL(String(input), 'https://web.test')
      return url.pathname.endsWith('/analytics/summary') && url.searchParams.get('from') === '2026-07-29T16:00:00.000Z'
    })
    expect(networkRequest).toBeDefined()
    const networkQuery = new URL(String(networkRequest?.[0]), 'https://web.test').searchParams
    expect(networkQuery.get('from')).toBe('2026-07-29T16:00:00.000Z')
    expect(networkQuery.get('to')).toBe('2026-07-30T16:00:00.000Z')
    expect(screen.getByText('带宽峰值').parentElement).toHaveTextContent(bandwidthLabel)
    expect(screen.getByText('请求数', { selector: 'dt' }).parentElement).toHaveTextContent('42次')
    expect(screen.getByText('总流量', { selector: 'dt' }).parentElement).toHaveTextContent(trafficLabel)
    expect(screen.getByText('拉黑IP数', { selector: 'dt' }).parentElement).toHaveTextContent('7个')

    await userEvent.setup().click(within(screen.getByRole('radiogroup', { name: '监控趋势时间范围' })).getByText('昨日'))
    // The monitor panel now shares the network panel's cached yesterday read.
    await waitFor(() => expect(screen.getByRole('radiogroup', { name: '监控趋势时间范围' }).querySelector('[aria-checked="true"]')).toHaveTextContent('昨日'))
    expect(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/v1/admin/analytics/')).length).toBe(14)
  })

  it('derives the network peak from the same hourly analytics snapshot', () => {
    const analytics = { trend: [
      { average_bandwidth_bps: 4096 },
      { average_bandwidth_bps: 8192 },
      { average_bandwidth_bps: 2048 },
    ] } as unknown as DashboardAnalyticsOverview
    expect(peakHourlyBandwidth(analytics)).toBe(8192)
    expect(peakHourlyBandwidth({ trend: [] } as unknown as DashboardAnalyticsOverview)).toBeNull()
    // FX36: the 5-minute peak wins over the hourly average when present.
    expect(peakHourlyBandwidth({ ...analytics, peak_bandwidth_bps: '20000' } as DashboardAnalyticsOverview)).toBe(20000)
  })

  it('rebuilds the trend chart when its metric tab changes', async () => {
    echartsMock.setOption.mockClear()
    echartsMock.init.mockClear()
    const analytics = {
      summary: { request_count: '2', total_bytes: '3' },
      trend: [{ hour: '2026-07-31T00:00:00Z', average_bandwidth_bps: 10, request_count: '2', total_bytes: '3' }],
      top: [{ dimension: 'domain', snapshot_at: '2026-07-31T00:00:00Z', items: [] }],
      top_extended: [{ dimension: 'domain', snapshot_at: '2026-07-31T00:00:00Z', items: [] }],
    } as unknown as DashboardAnalyticsOverview
    renderWithProviders(<DashboardAnalyticsView analytics={analytics} locale="zh-CN" variant="admin" />, ['/admin-home'])

    expect(screen.getByText('TOP10 数据 (近30分钟)')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'IP' })).toBeInTheDocument()
    await waitFor(() => expect(echartsMock.setOption).toHaveBeenCalledTimes(1))
    const firstOptions = echartsMock.setOption.mock.calls[0][0] as { series: Array<{ data: unknown[] }> }
    expect(firstOptions.series[0].data).toEqual([10])
    await userEvent.setup().click(screen.getByRole('tab', { name: '请求数' }))
    await waitFor(() => expect(echartsMock.setOption).toHaveBeenCalledTimes(2))
    const secondOptions = echartsMock.setOption.mock.calls[1][0] as { series: Array<{ data: unknown[] }> }
    expect(secondOptions.series[0].data).toEqual([2])
  })

  it('enables the blocked-IP trend for an authoritative empty analytics snapshot', async () => {
    const emptySummary = {
      metric_version: 1 as const,
      request_count: '0', request_bytes: '0', response_bytes: '0', total_bytes: '0',
      average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0',
    }
    const analytics = {
      summary: emptySummary,
      trend: [],
      top: [
        { dimension: 'domain', snapshot_at: '2026-07-31T00:00:00Z', items: [] },
        { dimension: 'region', snapshot_at: '2026-07-31T00:00:00Z', items: [] },
        { dimension: 'carrier', snapshot_at: '2026-07-31T00:00:00Z', items: [] },
      ],
    } as unknown as DashboardAnalyticsOverview

    renderWithProviders(<DashboardAnalyticsView analytics={analytics} locale="zh-CN" variant="admin" mode="trend" />, ['/admin-home'])

    expect(screen.getByRole('tab', { name: '拉黑IP数' })).toHaveAttribute('aria-disabled', 'false')
    await userEvent.setup().click(screen.getByRole('tab', { name: '拉黑IP数' }))
    expect(screen.getByRole('tab', { name: '拉黑IP数' })).toHaveAttribute('aria-selected', 'true')
  })

  it('maps analytics dependency failures to a localized unavailable state', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (url.pathname.includes('/v1/admin/analytics/')) {
        return json({ error: { code: 'analytics_storage_unavailable', message: 'internal storage details', request_id: 'req-test' } }, 503)
      }
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(within(screen.getByRole('radiogroup', { name: '网络概览时间范围' })).getByText('昨日'))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/v1/admin/analytics/'))).toBe(true))
    expect((await screen.findAllByRole('status')).length).toBeGreaterThan(0)
    expect(screen.queryByText('internal storage details')).not.toBeInTheDocument()
    // ui-click F3：数据不可用时不渲染点了没反应的趋势/排行标签按钮。
    const placeholders = document.querySelectorAll('.dashboard-analytics-unavailable')
    expect(placeholders.length).toBeGreaterThan(0)
    placeholders.forEach((placeholder) => {
      expect(within(placeholder as HTMLElement).queryAllByRole('tab')).toEqual([])
      expect(within(placeholder as HTMLElement).queryAllByRole('button')).toEqual([])
    })
  })

  it('keeps the profile title anchored to the username when the display name is the platform admin label', async () => {
    authenticateAdmin({ display_name: 'Platform Administrator' })
    mockDashboardFetch()
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByRole('heading', { name: 'admin', level: 2 })).toBeInTheDocument()
    expect(screen.queryByText('Platform Administrator')).not.toBeInTheDocument()
  })

  it('renders available all-zero aggregates as localized facts', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return json({
      ...adminDashboard('seven_days', {
        available: true,
        value: {
          summary: { metric_version: 1, request_count: '0', request_bytes: '0', response_bytes: '0', total_bytes: '0',
            average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0' },
          trend: [],
          top: [
            { dimension: 'domain', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
            { dimension: 'region', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
            { dimension: 'carrier', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
          ],
        },
      }),
      accounts: { available: true, value: { tenants_total: 0, tenants_active: 0, tenant_users_total: 0, tenant_users_active: 0 } },
      subscriptions: { available: true, value: { active: 0 } },
      billing: { available: true, value: { currency: 'CNY', gross_settled_debit_minor: '0', reversed_credit_minor: '0', net_settled_minor: '0' } },
      resources: { available: true, value: { sites_total: 0, sites_active: 0, sites_sync_failed: 0, nodes_total: 0, certificates_total: 0, certificates_valid: 0, certificates_expiring_30d: 0 } },
      operations: { available: true, value: { cache_total: 0, cache_open: 0, cache_failed: 0, jobs_total: 0, jobs_open: 0, jobs_failed: 0 } },
      entitlement: { available: true, value: { installation_id: '', status: 'uninstalled', lease_status: null } },
      node_health: { available: true, value: { total: 0, online_fresh: 0, stale_or_offline: 0, presence_missing: 0, freshness_cutoff_seconds: 45 } },
      analytics_health: { available: true, value: { active_streams: 0, unprepared_stream_gap: '0' } },
      account_security: { available: true, value: { active_sessions: 0, users_with_mfa: 0, active_api_keys: 0, recovery_codes_remaining: 0 } },
      network: { available: true, value: { nodes_total: 0, nodes_active: 0, nodes_online: 0, nodes_stale: 0, freshness_cutoff_seconds: 45, regions: [] } },
      operation_charts: { available: true, value: { new_users: [], package_sold: [], recharge: [] } },
      })
      if (pathname.endsWith('/analytics/summary')) return json({ data: { metric_version: 1, request_count: 0, request_bytes: 0, response_bytes: 0, total_bytes: 0, average_bandwidth_bps: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, security_events: 0, security_event_rows: 0, cache_hit_requests: 0, cache_hit_bytes: 0, unique_client_ips: 0 }, meta: { from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T16:00:00.000Z', timezone: 'UTC', metric_version: 1 } })
      if (pathname.endsWith('/analytics/blocked-ip-count')) return json({ blocked_ip_count: 0, meta: { from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T16:00:00.000Z', timezone: 'UTC', metric_version: 1 } })
      if (pathname.endsWith('/analytics/blocked-ip-trend')) return json({ data: [], meta: { from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T00:00:00.000Z', timezone: 'UTC', metric_version: 1 } })
      if (pathname.endsWith('/analytics/hourly-trend')) return json({ data: [], meta: { from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T00:00:00.000Z', timezone: 'UTC', metric_version: 1 } })
      if (pathname.includes('/analytics/top/')) return json({ data: [], dimension: pathname.match(/\/analytics\/top\/(domain|url|ip|region|carrier)$/)?.[1] ?? 'domain', page: { snapshot_at: '2026-07-31T00:00:00.000Z', source: 'history' }, meta: { from: '2026-07-30T16:00:00.000Z', to: '2026-07-31T00:00:00.000Z', timezone: 'UTC', metric_version: 1 } })
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByRole('heading', { name: '网络概览', level: 2 })).toBeInTheDocument()
    expect(screen.queryByText('流量趋势')).not.toBeInTheDocument()
    expect(screen.queryByText('¥0.00')).not.toBeInTheDocument()
    expect(await screen.findByText('0KB')).toBeInTheDocument()
    expect(screen.getByText('带宽峰值', { selector: 'dt' }).parentElement).toHaveTextContent('0Kbps')
    expect(screen.getByText('请求数', { selector: 'dt' }).parentElement).toHaveTextContent('0次')
    expect(screen.getByText('拉黑IP数', { selector: 'dt' }).parentElement).toHaveTextContent('0个')
    expect(screen.queryByText('依赖服务暂不可用')).not.toBeInTheDocument()
    expect(screen.queryByText('权威数据尚未就绪')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    const countryTab = screen.getByRole('tab', { name: '国家' })
    expect(screen.getByRole('tab', { name: '拉黑IP数' })).toHaveAttribute('aria-disabled', 'false')
    expect(screen.queryByRole('tab', { name: '运营商' })).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'URL' })).toHaveAttribute('aria-disabled', 'false')
    const user = userEvent.setup()
    await user.click(countryTab)
    expect(countryTab).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '带宽' })).toHaveAttribute('aria-selected', 'true')
    const requestsTrendTab = screen.getByRole('tab', { name: '请求数' })
    await user.click(requestsTrendTab)
    expect(requestsTrendTab).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '流量' })).toHaveAttribute('aria-disabled', 'false')
    expect(screen.getByRole('tab', { name: '拉黑IP数' })).toHaveAttribute('aria-disabled', 'false')
  })

  it('aborts the superseded range request and issues one request for the new cache key', async () => {
    authenticateAdmin()
    let supersededSignal: AbortSignal | undefined
    let dashboardCalls = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => {
      const pathname = new URL(String(url), 'https://web.test').pathname
      if (pathname.startsWith('/v1/admin/analytics/')) return Promise.resolve(analyticsFallbackResponse())
      if (pathname !== '/v1/admin/dashboard') return Promise.reject(new Error(`Unexpected request: ${pathname}`))
      dashboardCalls += 1
      if (dashboardCalls === 2) {
        supersededSignal = init?.signal ?? undefined
        return new Promise<Response>((_resolve, reject) => {
          supersededSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        })
      }
      return Promise.resolve(json(dashboardCalls === 1 ? adminDashboard() : adminDashboard('previous_month')))
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    await screen.findByText('3,456')
    const range = screen.getByRole('radiogroup', { name: '运营数据时间范围' })
    fireEvent.click(within(range).getByText('近30日'))
    fireEvent.click(within(range).getByText('上个月'))
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(3))
    expect(supersededSignal?.aborted).toBe(true)
    expect(new URL(String(dashboardFetchCalls(fetchSpy)[1][0]), 'https://web.test').searchParams.get('range')).toBe('thirty_days')
    expect(new URL(String(dashboardFetchCalls(fetchSpy)[2][0]), 'https://web.test').searchParams.get('range')).toBe('previous_month')
    expect(await screen.findByText('3,456')).toBeInTheDocument()
  })

  it('keeps the baseline overview free of non-reference drilldown controls', async () => {
    authenticateAdmin()
    const fetchSpy = mockDashboardFetch()
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    expect(screen.queryByLabelText('网站 ID')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '应用筛选' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '清除筛选' })).not.toBeInTheDocument()
    expect(dashboardFetchCalls(fetchSpy)).toHaveLength(1)
  })

  it('keeps platform diagnostics available and refreshes the real dashboard read', async () => {
    authenticateAdmin()
    const fetchSpy = mockDashboardFetch()
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    expect(screen.queryByText('平台增强数据')).not.toBeInTheDocument()
    const checkButton = screen.getByRole('button', { name: '立即检查' })
    expect(checkButton).toHaveClass('ant-btn-primary')
    await userEvent.setup().click(checkButton)
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))
    expect(new URL(String(dashboardFetchCalls(fetchSpy)[1][0]), 'https://web.test').pathname).toBe('/v1/admin/dashboard')
  })

  // LIC-REC-02: the lease times alone do not say why renewal failed, so the
  // warning states the fact (expired, in grace, days left) and what still works.
  it('states that the lease expired and is in grace, without blaming the license center', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard()
    const day = 86_400_000
    const inGrace = { ...dashboard, entitlement: { available: true, value: {
      ...dashboard.entitlement.value, status: 'valid', lease_status: 'valid',
      expires_at: new Date(Date.now() - day).toISOString(), grace_until: new Date(Date.now() + 2.5 * day).toISOString(),
    } } }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return json(inGrace)
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    const warning = await screen.findByText(/本地租约已过期，仍在宽限期，剩余 3 天/)
    expect(warning).toHaveAttribute('role', 'alert')
    expect(warning).toHaveTextContent('升级需要有效租约')
    expect(warning).toHaveTextContent('宽限期结束后，新建、扩容和功能变更会被拒绝')
    expect(warning).toHaveTextContent('刷新授权')
    expect(screen.queryByText(/授权中心不可达/)).not.toBeInTheDocument()
  })

  it('shows no grace warning for a valid lease', async () => {
    authenticateAdmin()
    const dashboard = adminDashboard()
    const valid = { ...dashboard, entitlement: { available: true, value: {
      ...dashboard.entitlement.value, status: 'valid', lease_status: 'valid',
      expires_at: new Date(Date.now() + 86_400_000).toISOString(), grace_until: new Date(Date.now() + 2 * 86_400_000).toISOString(),
    } } }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return json(valid)
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    expect(screen.queryByText(/本地租约已过期/)).not.toBeInTheDocument()
  })

  it('runs the real entitlement refresh action and re-reads the dashboard', async () => {
    authenticateAdmin()
    const entitlementRefresh = json({
        schema: 'cdnca.entitlement-refresh/v1', request_id: 'entitlement-refresh-test',
        snapshot: { installation_id: 'control-primary', serial: 8, key_id: 'key-1', status: 'valid', verified_at: '2026-07-31T08:00:00Z' },
      })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (pathname === '/v1/admin/entitlement/refresh') return entitlementRefresh
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const refreshButton = screen.getByRole('button', { name: '刷新授权' })
    expect(screen.getByText('操作')).toBeInTheDocument()
    expect(refreshButton).toHaveClass('dashboard-action-button')
    expect(refreshButton).toHaveClass('ant-btn-primary')
    await userEvent.setup().click(refreshButton)
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))
    const refreshCall = fetchSpy.mock.calls.find(([input]) => new URL(String(input), 'https://web.test').pathname === '/v1/admin/entitlement/refresh')
    expect(refreshCall).toBeDefined()
    expect(refreshCall?.[1]).toEqual(expect.objectContaining({ method: 'POST', body: '{}' }))
    expect(await screen.findByText('授权已刷新')).toBeInTheDocument()
  })

  // B18 (LIC-REC-03): in progress, definite failure and unknown result are
  // told apart; unknown re-reads the dashboard and shows the request ID.
  it.each([
    [409, 'entitlement_refresh_in_progress', undefined, '授权刷新正在进行，请等候并查看最新状态', false],
    [502, 'entitlement_refresh_failed', 'not_applied', '授权检查未完成，当前授权未改变，可以重试', false],
    [502, 'entitlement_refresh_failed', undefined, '授权检查结果待确认，请以重新读取到的序列号与状态为准核对，不要重复提交', true],
    [503, 'entitlement_refresh_audit_failed', 'unknown', '授权检查结果待确认，请以重新读取到的序列号与状态为准核对，不要重复提交', true],
    [504, 'entitlement_refresh_timeout', 'unknown', '授权检查结果待确认，请以重新读取到的序列号与状态为准核对，不要重复提交', true],
  ])('explains a %s %s (%s) refresh outcome', async (status, code, outcome, text, rereads) => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return json(adminDashboard())
      if (pathname === '/v1/admin/entitlement/refresh') {
        return json({ error: { code, message: 'x', request_id: 'entitlement-refresh-b18', ...(outcome ? { outcome } : {}) } }, status)
      }
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新授权' }))
    const alert = (await screen.findByText(text)).closest('p')
    expect(alert).toHaveAttribute('role', 'alert')
    expect(screen.queryByText('授权刷新失败，请稍后重试')).not.toBeInTheDocument()
    expect(alert).toHaveTextContent('请求 ID：entitlement-refresh-b18')
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(rereads ? 2 : 1))
  })

  // LIC-REC-03 (report B): only a refresh the server proved was not applied
  // may say "unchanged". A lost COMMIT answer is pending: the card re-reads and
  // shows the serial, state and check time it read; a failed re-read stays
  // pending instead of claiming it was checked.
  function installedDashboard(serial: number, verifiedAt: string) {
    const dashboard = adminDashboard()
    return { ...dashboard, entitlement: { available: true, value: {
      ...dashboard.entitlement.value, status: 'valid', lease_status: 'valid', current_serial: serial, last_verified_at: verifiedAt,
    } } }
  }

  function mockRefresh(refresh: () => Response, dashboards: Array<() => Response>) {
    let reads = 0
    return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return dashboards[Math.min(reads++, dashboards.length - 1)]()
      if (pathname === '/v1/admin/entitlement/refresh') return refresh()
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
  }

  it('treats a lost commit answer as pending, re-reads and shows the persisted serial', async () => {
    authenticateAdmin()
    const fetchSpy = mockRefresh(
      () => json({ error: { code: 'entitlement_refresh_unknown', message: 'x', request_id: 'refresh-lost-ack', outcome: 'unknown' } }, 502),
      [() => json(installedDashboard(1, '2026-07-31T07:00:00Z')), () => json(installedDashboard(2, '2026-07-31T08:05:00Z'))],
    )
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新授权' }))
    const alert = (await screen.findByText(/授权检查结果待确认/)).closest('p')
    expect(alert).toHaveAttribute('role', 'alert')
    expect(screen.queryByText(/当前授权未改变/)).not.toBeInTheDocument()
    expect(alert).toHaveTextContent('请求 ID：refresh-lost-ack')
    expect(await screen.findByText(/已重新读取当前授权：序列号 2/)).toBeInTheDocument()
    expect(screen.getByText(/本次检查已生效/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '收起授权详情' })).toHaveAttribute('aria-expanded', 'true')
    const details = screen.getByRole('region', { name: '授权详情' })
    expect(within(details).getByText('2')).toBeInTheDocument()
    expect(within(details).getByText('有效')).toBeInTheDocument()
    expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2)
  })

  it('keeps the result pending when the re-read fails', async () => {
    authenticateAdmin()
    mockRefresh(
      () => json({ error: { code: 'entitlement_refresh_timeout', message: 'x', request_id: 'refresh-timeout', outcome: 'unknown' } }, 504),
      [() => json(installedDashboard(1, '2026-07-31T07:00:00Z')), () => json({ error: { code: 'dashboard_storage_unavailable', message: 'x' } }, 503)],
    )
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新授权' }))
    expect(await screen.findByText(/重新读取当前授权失败，结果仍待确认/)).toBeInTheDocument()
    expect(screen.queryByText(/已重新读取当前授权/)).not.toBeInTheDocument()
    expect(screen.getByText('3,456')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重新读取' })).toBeInTheDocument()
  })

  it('says unchanged only for a refresh the server proved was not applied', async () => {
    authenticateAdmin()
    const fetchSpy = mockRefresh(
      () => json({ error: { code: 'entitlement_refresh_failed', message: 'x', request_id: 'refresh-failed', outcome: 'not_applied' } }, 502),
      [() => json(installedDashboard(1, '2026-07-31T07:00:00Z'))],
    )
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新授权' }))
    expect(await screen.findByText(/当前授权未改变/)).toBeInTheDocument()
    expect(dashboardFetchCalls(fetchSpy)).toHaveLength(1)
  })

  it('reports an installed lease whose audit failed and re-reads it', async () => {
    authenticateAdmin()
    mockRefresh(
      () => json({ error: { code: 'entitlement_refresh_audit_failed', message: 'x', request_id: 'refresh-audit', outcome: 'applied' } }, 503),
      [() => json(installedDashboard(1, '2026-07-31T07:00:00Z')), () => json(installedDashboard(2, '2026-07-31T08:05:00Z'))],
    )
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新授权' }))
    expect(await screen.findByText(/授权已更新，但审计记录未写入/)).toBeInTheDocument()
    expect(await screen.findByText(/已重新读取当前授权：序列号 2/)).toBeInTheDocument()
  })

  it('shows serial, state and last check time in the collapsible card details', async () => {
    authenticateAdmin()
    mockRefresh(() => json({}), [() => json(installedDashboard(7, '2026-07-31T07:00:00Z'))])
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const toggle = screen.getByRole('button', { name: '查看授权详情' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('region', { name: '授权详情' })).not.toBeInTheDocument()
    await userEvent.setup().click(toggle)
    const details = screen.getByRole('region', { name: '授权详情' })
    expect(within(details).getByText('当前序列号')).toBeInTheDocument()
    expect(within(details).getByText('7')).toBeInTheDocument()
    expect(within(details).getByText('最近检查时间')).toBeInTheDocument()
    expect(within(details).getByText('2026-07-31 15:00:00')).toBeInTheDocument()
  })

  // The home card and the lock banner share one recovery action: while locked
  // the refresh API answers 423, so the card runs the lock check instead.
  it('runs the shared lock check while the controller is locked', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') return json(installedDashboard(1, '2026-07-31T07:00:00Z'))
      if (pathname === '/v1/admin/entitlement/refresh') return json({ error: { code: 'installation_locked', message: 'x', request_id: 'locked-1' } }, 423)
      if (pathname === '/v1/installation-lock/check' && init?.method === 'POST') return json({ locked: false })
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新授权' }))
    expect(await screen.findByText('授权已恢复')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input, init]) => new URL(String(input), 'https://web.test').pathname === '/v1/installation-lock/check' && init?.method === 'POST')).toBe(true)
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))
  })

  it('uses a flat token-free owner key and preserves range and cache identity across token refresh', async () => {
    const admin = authenticateAdmin()
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/dashboard') {
        const requestedRange = url.searchParams.get('range')
        return json(adminDashboard(requestedRange === 'thirty_days' ? 'thirty_days' : requestedRange === 'previous_month' ? 'previous_month' : 'seven_days'))
      }
      if (url.pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${url.pathname}`)
    })
    const user = userEvent.setup()
    const { queryClient } = renderDashboard()

    expect(await screen.findByText('3,456')).toBeInTheDocument()
    const range = screen.getByRole('radiogroup', { name: '运营数据时间范围' })
    await user.click(within(range).getByText('近30日'))
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))

    const ownerPrefix = [
      'dashboard', 'admin', 'platform', admin.scope_id, null, admin.user_id, sessionEpoch,
    ]
    const currentKey = [...ownerPrefix, 'thirty_days', 'Asia/Shanghai']
    await waitFor(() => {
      expect(queryClient.getQueryCache().find({ queryKey: currentKey, exact: true })?.state.status).toBe('success')
    })
    const currentQuery = queryClient.getQueryCache().find({ queryKey: currentKey, exact: true })
    const currentData = currentQuery?.state.data
    expect(currentQuery?.queryKey).toEqual(currentKey)
    expect(currentData).toEqual(adminDashboard('thirty_days'))
    expect(queryClient.getQueryCache().getAll()
      .filter((query) => query.queryKey[0] === 'dashboard')
      .flatMap((query) => query.queryKey)).not.toContain(accessToken)

    act(() => {
      useSessionStore.getState().setSession(
        { ...authResponse(admin), access_token: 'refreshed-admin-dashboard-token' },
        admin,
        'refresh',
      )
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2)
    const refreshedQuery = queryClient.getQueryCache().find({ queryKey: currentKey, exact: true })
    expect(refreshedQuery).toBe(currentQuery)
    expect(refreshedQuery?.state.data).toBe(currentData)
    const refreshedKeys = queryClient.getQueryCache().getAll()
      .filter((query) => query.queryKey[0] === 'dashboard')
      .flatMap((query) => query.queryKey)
    expect(refreshedKeys).not.toContain(accessToken)
    expect(refreshedKeys).not.toContain('refreshed-admin-dashboard-token')

    const refreshedRange = screen.getByRole('radiogroup', { name: '运营数据时间范围' })
    await user.click(within(refreshedRange).getByText('上个月'))
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(3))
    expect(dashboardFetchCalls(fetchSpy)[2][1]).toEqual(expect.objectContaining({
      headers: { Authorization: 'Bearer refreshed-admin-dashboard-token' },
    }))
  })

  it('resets range and removes old dashboard facts for a new session with the same IDs', async () => {
    const admin = authenticateAdmin()
    const oldEpoch = useSessionStore.getState().sessionEpoch
    const nextDashboard = deferred<Response>()
    let dashboardCalls = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname.startsWith('/v1/admin/analytics/')) return Promise.resolve(analyticsFallbackResponse())
      if (pathname !== '/v1/admin/dashboard') return Promise.reject(new Error(`Unexpected request: ${pathname}`))
      dashboardCalls += 1
      if (dashboardCalls === 1) return Promise.resolve(json(dashboardWithFacts('seven_days', 'old-control', 7777, '777700', 77, 71)))
      if (dashboardCalls === 2) return Promise.resolve(json(dashboardWithFacts('thirty_days', 'old-control', 7777, '777700', 77, 71)))
      return nextDashboard.promise
    })
    const user = userEvent.setup()
    const { queryClient } = renderDashboard()

    expect(await screen.findByText('7,777')).toBeInTheDocument()
    const range = screen.getByRole('radiogroup', { name: '运营数据时间范围' })
    await user.click(within(range).getByText('近30日'))
    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2))

    act(() => {
      useSessionStore.getState().setSession(
        { ...authResponse(admin), access_token: 'new-admin-session-token' },
        admin,
      )
    })

    await waitFor(() => expect(dashboardFetchCalls(fetchSpy)).toHaveLength(3))
    expect(new URL(String(dashboardFetchCalls(fetchSpy)[2][0]), 'https://web.test').searchParams.get('range')).toBe('seven_days')
    expect(screen.queryByText('7,777')).not.toBeInTheDocument()
    expect(screen.queryByText('7,777')).not.toBeInTheDocument()
    expect(screen.queryByText('¥7,777.00')).not.toBeInTheDocument()
    expect(screen.queryByText('77')).not.toBeInTheDocument()
    expect(screen.queryByText('71')).not.toBeInTheDocument()
    expect(screen.getByLabelText('运营数据加载中')).toBeInTheDocument()
    await waitFor(() => {
      expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey.includes(oldEpoch))).toBe(false)
    })

    await act(async () => {
      nextDashboard.resolve(json(dashboardWithFacts('seven_days', 'current-control', 4567, '123456', 62, 9)))
    })
  })

  it.each(['success', 'error'] as const)(
    'does not let a delayed old-session %s repopulate the new session UI or cache',
    async (outcome) => {
      const admin = authenticateAdmin()
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const oldRequest = deferred<Response>()
      const oldJSON = deferred<unknown>()
      const newRequest = deferred<Response>()
      const continuation = { observed: false }
      const oldResponse = json({}, outcome === 'success' ? 200 : 500)
      const oldJSONSpy = vi.spyOn(oldResponse, 'json').mockImplementation(() => oldJSON.promise)
      let oldBody: unknown
      if (outcome === 'success') {
        const dashboard = dashboardWithFacts('seven_days', 'stale-control', 8888, '888800', 78, 81)
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
        const error = { message: 'private stale admin dashboard failure', request_id: 'stale-admin-dashboard-request' }
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
          { ...authResponse(admin), access_token: 'replacement-admin-session-token' },
          admin,
        )
      })
      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))

      await act(async () => { oldRequest.resolve(oldResponse) })
      await waitFor(() => expect(oldJSONSpy).toHaveBeenCalledOnce())
      expect(continuation.observed).toBe(false)
      await act(async () => { oldJSON.resolve(oldBody) })
      await waitFor(() => expect(continuation.observed).toBe(true))
      expect(screen.queryByText('stale-control')).not.toBeInTheDocument()
      expect(screen.queryByText('8,888')).not.toBeInTheDocument()
      expect(screen.queryByText('¥8,888.00')).not.toBeInTheDocument()
      expect(screen.queryByText(/private stale admin dashboard failure/i)).not.toBeInTheDocument()
      expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey.includes(oldEpoch))).toBe(false)

      await act(async () => {
        newRequest.resolve(json(dashboardWithFacts('seven_days', 'current-control', 4567, '123456', 62, 9)))
      })
      expect(screen.queryByText('stale-control')).not.toBeInTheDocument()
      expect(screen.queryByText('8,888')).not.toBeInTheDocument()
      expect(screen.queryByText('¥8,888.00')).not.toBeInTheDocument()
      expect(screen.queryByText(/private stale admin dashboard failure/i)).not.toBeInTheDocument()
      expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey.includes(oldEpoch))).toBe(false)
    },
  )

  it('shows loading and localized failures without exposing server messages', async () => {
    authenticateAdmin()
    const pending = vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<Response>(() => undefined))
    const first = renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(screen.getByLabelText('运营数据加载中')).toBeInTheDocument()
    first.unmount()
    pending.mockRestore()

    authenticateAdmin()
    let dashboardAttempts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const pathname = new URL(String(input), 'https://web.test').pathname
      if (pathname === '/v1/admin/dashboard') {
        dashboardAttempts += 1
        return dashboardAttempts === 1
          ? json({ error: { code: 'dashboard_storage_unavailable', message: 'private postgres hostname', request_id: 'dashboard-safe-1' } }, 503)
          : json(adminDashboard())
      }
      if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
      throw new Error(`Unexpected request: ${pathname}`)
    })
    renderWithProviders(<AdminHomePage />, ['/admin-home'])

    expect(await screen.findByText('运营数据存储暂不可用，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText(/private postgres/i)).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('3,456')).toBeInTheDocument()
    expect(screen.queryByText('运营数据存储暂不可用，请稍后重试')).not.toBeInTheDocument()
    expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2)
  })

  it.each([
    ['tenant scope', { scope_kind: 'tenant' as const, tenant_id: '22222222-2222-4222-8222-222222222222' }],
    ['missing scope ID', { scope_id: '' }],
    ['non-null tenant ID', { tenant_id: '22222222-2222-4222-8222-222222222222' }],
    ['missing user ID', { user_id: '' }],
    ['missing permission', { permissions: [] }],
  ])('rejects %s locally before fetching', (_label, overrides) => {
    authenticateAdmin(overrides)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(screen.getByText('无权查看运营数据')).toBeInTheDocument()
    expect(screen.getByText('当前账号无权查看运营数据')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects a zero session epoch locally before fetching', () => {
    authenticateAdmin()
    useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(screen.getByText('无权查看运营数据')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('uses the localized 403 surface for a server denial without leaking its raw message', async () => {
    authenticateAdmin()
    const deniedFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'dashboard_permission_denied', message: 'private policy', request_id: 'dashboard-safe-2' },
    }, 403))
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByText('无权查看运营数据')).toBeInTheDocument()
    expect(screen.getByText('当前账号无权查看运营数据')).toBeInTheDocument()
    expect(screen.queryByText('3,456')).not.toBeInTheDocument()
    expect(screen.queryByText(/private policy/i)).not.toBeInTheDocument()
    expect(deniedFetch).toHaveBeenCalledOnce()
  })

  it.each(['en-US', 'qps-ploc'] as const)(
    'renders localized loading, generic error, retry, and recovered status in %s',
    async (locale) => {
      await changeLocale(locale)
      const t = i18n.getFixedT(locale, 'adminHome')
      const commonT = i18n.getFixedT(locale, 'common')
      authenticateAdmin()
      let dashboardAttempts = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
        const pathname = new URL(String(input), 'https://web.test').pathname
        if (pathname === '/v1/admin/dashboard') {
          dashboardAttempts += 1
          return dashboardAttempts === 1
            ? json({ error: { code: 'request_failed', message: 'private generic admin failure', request_id: 'admin-generic-error' } }, 500)
            : json(adminDashboard('seven_days', { available: false, reason: 'dependency_unavailable' }))
        }
        if (pathname.startsWith('/v1/admin/analytics/')) return analyticsFallbackResponse()
        throw new Error(`Unexpected request: ${pathname}`)
      })
      renderWithProviders(<AdminHomePage />, ['/admin-home'])

      expect(screen.getByLabelText(t('states.loading'))).toBeInTheDocument()
      expect(await screen.findByText(t('errors.request_failed'))).toBeInTheDocument()
      expect(screen.queryByText(/private generic admin failure/i)).not.toBeInTheDocument()
      const retry = screen.getByRole('button', { name: commonT('retry') })
      expect(retry).toHaveTextContent(commonT('retry'))
      await userEvent.setup().click(retry)

      await waitFor(() => expect(document.body.textContent).toContain(t('unavailable.dependency_unavailable')))
      expect(screen.getByRole('heading', { name: t('title'), level: 2 })).toBeInTheDocument()
      expect(screen.queryByText(t('errors.request_failed'))).not.toBeInTheDocument()
      expect(dashboardFetchCalls(fetchSpy)).toHaveLength(2)
    },
  )

  it('keeps the compact controls available in English and the expanded pseudo locale', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json(adminDashboard())))
    const first = renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByRole('heading', { name: 'Operations data' })).toBeInTheDocument()
    expect(await screen.findByRole('radiogroup', { name: 'Operations data time range' })).toBeInTheDocument()
    first.unmount()

    await changeLocale('qps-ploc')
    authenticateAdmin()
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))
    renderWithProviders(<AdminHomePage />, ['/admin-home'])
    expect(await screen.findByRole('radiogroup', { name: '［运~营~数~据~时~间~范~围~］' })).toBeInTheDocument()
    await waitFor(() => expect(document.querySelectorAll('.dashboard-metric-band').length).toBeGreaterThan(0))
    expect(document.querySelectorAll('.dashboard-block-extra')).toHaveLength(3)
  })
})
