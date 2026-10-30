import { ApiError } from '../api/auth'
import { dashboardApi } from '../api/dashboard'

const meta = {
  range: 'seven_days',
  timezone: 'Asia/Shanghai',
  from: '2026-07-24T16:00:00Z',
  to: '2026-07-31T16:00:00Z',
  generated_at: '2026-07-31T08:00:00Z',
  snapshot_at: '2026-07-31T08:00:00.000Z',
  window_complete: false,
}

const analytics = {
  metric_version: 1,
  request_count: '900719925474099312345',
  request_bytes: '1',
  response_bytes: '2',
  total_bytes: '3',
  average_bandwidth_bps: 1250000,
  status_2xx: '4',
  status_3xx: '5',
  status_4xx: '6',
  status_5xx: '7',
  security_events: '8',
}

const analyticsOverview = {
  blocked_ip_trend_available: true,
  summary: analytics,
  trend: [{ hour: '2026-07-31T07:00:00Z', ...analytics }],
  top: [
    { dimension: 'domain', snapshot_at: '2026-07-31T08:00:00Z', items: [{ key: 'example.test', request_count: '4', response_bytes: '2' }] },
    { dimension: 'region', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
    { dimension: 'carrier', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
  ],
}

const accountSecurity = { active_sessions: 3, users_with_mfa: 2, active_api_keys: 1, recovery_codes_remaining: 6 }
const network = {
  nodes_total: 2, nodes_active: 2, nodes_online: 1, nodes_stale: 1, freshness_cutoff_seconds: 45,
  regions: [{ region: 'cn-east', nodes_total: 2, nodes_online: 1 }],
}

const adminResponse = {
  dashboard_version: 2,
  meta,
  accounts: { available: true, value: { tenants_total: 12, tenants_active: 10, tenant_users_total: 3456, tenant_users_active: 3000 } },
  subscriptions: { available: true, value: { active: 23 } },
  billing: { available: true, value: { currency: 'CNY', gross_settled_debit_minor: '900719925474099312345', reversed_credit_minor: '12345', net_settled_minor: '900719925474099300000' } },
  resources: { available: true, value: { sites_total: 88, sites_active: 80, sites_sync_failed: 2, nodes_total: 6, certificates_total: 72, certificates_valid: 70, certificates_expiring_30d: 3 } },
  operations: { available: true, value: { cache_total: 9, cache_open: 2, cache_failed: 1, jobs_total: 10, jobs_open: 3, jobs_failed: 1 } },
  entitlement: { available: true, value: { installation_id: 'control-primary', status: 'uninstalled', lease_status: null } },
  node_health: { available: true, value: { total: 6, online_fresh: 5, stale_or_offline: 1, presence_missing: 0, freshness_cutoff_seconds: 45 } },
  analytics_health: { available: true, value: { active_streams: 4, unprepared_stream_gap: '900719925474099312345' } },
  account_security: { available: true, value: accountSecurity },
  network: { available: true, value: network },
  analytics: { available: true, value: analyticsOverview },
}

const tenantResponse = {
  dashboard_version: 2,
  meta: { ...meta, range: 'today', from: '2026-07-30T16:00:00Z' },
  identity_verification: { available: true, value: { verified: false } },
  profile: { available: true, value: { last_login_at: '2026-07-31T07:30:00Z', last_login_ip: '203.0.113.8', last_login_geo: 'CN-BJ' } },
  resources: { available: true, value: { sites_total: 8, sites_active: 7, sites_sync_failed: 1, domains_total: 8, forwards_total: 1, nodes_total: 2 } },
  certificates: { available: true, value: { total: 6, valid: 5, expiring_30d: 1 } },
  billing: { available: true, value: { currency: 'CNY', balance_minor: 123456, revision: 7, updated_at: '2026-07-31T07:00:00Z' } },
  subscriptions: { available: true, value: { active: 1, items: [{ id: '018f0000-0000-7000-8000-000000000001', name: 'Business', ends_at: '2026-12-31T16:00:00Z', timezone: 'Asia/Shanghai', site_limit: '-1', domain_limit: '100', node_limit: '10', traffic_limit_bytes: '900719925474099312345', traffic_progress: { available: true, value: { period_key: '2026-07', used_bytes: '100', finalized_through: '2026-07-31T07:00:00Z', source_watermark: '9', source_evidence_sha256: 'a'.repeat(64) } } }] } },
  traffic_packages: { available: true, value: { active: 2, granted_bytes: '900719925474099312345', remaining_bytes: '800719925474099312345', used_bytes: '100000000000000000000' } },
  operations: { available: true, value: { cache_total: 3, cache_open: 1, cache_failed: 0, jobs_total: 4, jobs_open: 1, jobs_failed: 0 } },
  notices: { available: true, value: { unread: 1, items: [{ id: '018f0000-0000-7000-8000-000000000002', title: 'Maintenance', published_at: '2026-07-31T07:00:00Z' }] } },
  account_security: { available: true, value: accountSecurity },
  network: { available: true, value: network },
  analytics: { available: true, value: analyticsOverview },
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('dashboard API', () => {
  it('uses exact scoped routes, query parameters, credentials, bearer auth, and abort signals', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(adminResponse))
      .mockResolvedValueOnce(json(tenantResponse))
    const adminAbort = new AbortController()
    const tenantAbort = new AbortController()

    await dashboardApi.admin('admin-token', 'seven_days', 'Asia/Shanghai', adminAbort.signal)
    await dashboardApi.tenant('tenant-token', 'today', 'Asia/Shanghai', tenantAbort.signal)

    const [adminURL, adminInit] = fetchSpy.mock.calls[0]
    const [tenantURL, tenantInit] = fetchSpy.mock.calls[1]
    expect(String(adminURL)).toBe('/v1/admin/dashboard?range=seven_days&timezone=Asia%2FShanghai')
    expect(String(tenantURL)).toBe('/v1/dashboard?range=today&timezone=Asia%2FShanghai')
    expect(adminInit).toEqual(expect.objectContaining({ credentials: 'include', headers: { Authorization: 'Bearer admin-token' }, signal: adminAbort.signal }))
    expect(tenantInit).toEqual(expect.objectContaining({ credentials: 'include', headers: { Authorization: 'Bearer tenant-token' }, signal: tenantAbort.signal }))
  })

  it('adds only canonical site and node drill-down filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tenantResponse))
    await dashboardApi.tenant('token', 'today', 'Asia/Shanghai', undefined, {
      siteId: '018f0000-0000-7000-8000-000000000001',
      nodeId: '018f0000-0000-7000-8000-000000000002',
    })
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://dashboard.test')
    expect(url.searchParams.get('site_id')).toBe('018f0000-0000-7000-8000-000000000001')
    expect(url.searchParams.get('node_id')).toBe('018f0000-0000-7000-8000-000000000002')
    await expect(dashboardApi.tenant('token', 'today', 'UTC', undefined, { siteId: '018F0000-0000-7000-8000-000000000001' }))
      .rejects.toMatchObject({ status: 400, code: 'dashboard_invalid_request' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('accepts the login region and city and rejects oversized geo text', async () => {
    const profile = { last_login_ip: '203.0.113.61', last_login_geo: 'CN', last_login_region: '山东省', last_login_city: '潍坊市' }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...tenantResponse, profile: { available: true, value: profile } }))
      .mockResolvedValueOnce(json({ ...tenantResponse, profile: { available: true, value: { ...profile, last_login_city: 'x'.repeat(129) } } }))
    const tenant = await dashboardApi.tenant('token', 'today', 'Asia/Shanghai')
    expect(tenant.profile.available && tenant.profile.value).toEqual(profile)
    await expect(dashboardApi.tenant('token', 'today', 'Asia/Shanghai')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('keeps the rank address parts so the home page shows host:port and full URLs (AUDIT-FINAL-1027 P8)', async () => {
    const domain = { key: 'www.example.test:8080', request_count: '4', response_bytes: '2', host: 'www.example.test', port: 8080 }
    const url = { key: 'www.example.test:443/a', request_count: '4', response_bytes: '2', host: 'www.example.test', port: 443, path: '/a', scheme: 'https' }
    const top_extended = [
      { dimension: 'domain', snapshot_at: '2026-07-31T08:00:00Z', items: [domain] },
      { dimension: 'url', snapshot_at: '2026-07-31T08:00:00Z', items: [url] },
      { dimension: 'ip', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
      { dimension: 'region', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
      { dimension: 'carrier', snapshot_at: '2026-07-31T08:00:00Z', items: [] },
    ]
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...tenantResponse, analytics: { available: true, value: { ...analyticsOverview, top_extended } } }))
      .mockResolvedValueOnce(json({ ...tenantResponse, analytics: { available: true, value: { ...analyticsOverview, top_extended: [
        { ...top_extended[0], items: [{ ...domain, scheme: 'ftp' }] }, ...top_extended.slice(1)] } } }))
    const tenant = await dashboardApi.tenant('token', 'today', 'Asia/Shanghai')
    expect(tenant.analytics.available && tenant.analytics.value.top_extended?.[1].items[0]).toEqual(url)
    await expect(dashboardApi.tenant('token', 'today', 'Asia/Shanghai')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('preserves canonical decimal strings beyond Number.MAX_SAFE_INTEGER', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(adminResponse))
      .mockResolvedValueOnce(json(tenantResponse))

    const admin = await dashboardApi.admin('token', 'seven_days', 'Asia/Shanghai')
    const tenant = await dashboardApi.tenant('token', 'today', 'Asia/Shanghai')

    expect(admin.billing.available && admin.billing.value.gross_settled_debit_minor).toBe('900719925474099312345')
    expect(tenant.analytics.available && tenant.analytics.value.summary.request_count).toBe('900719925474099312345')
    expect(tenant.subscriptions.available && tenant.subscriptions.value.items[0].site_limit).toBe('-1')
  })

  it.each([
    ['extra property', { ...adminResponse, private_sql: 'secret' }],
    ['missing property', { ...adminResponse, accounts: undefined }],
    ['missing snapshot boundary', { ...adminResponse, meta: { ...adminResponse.meta, snapshot_at: undefined } }],
    ['invalid decimal', { ...adminResponse, billing: { available: true, value: { ...adminResponse.billing.value, net_settled_minor: '01' } } }],
    ['unsafe numeric count', { ...adminResponse, accounts: { available: true, value: { ...adminResponse.accounts.value, tenants_total: Number.MAX_SAFE_INTEGER + 1 } } }],
    ['unknown section reason', { ...adminResponse, analytics: { available: false, reason: 'private_failure' } }],
    ['unknown entitlement status', { ...adminResponse, entitlement: { available: true, value: { ...adminResponse.entitlement.value, status: 'future_state' } } }],
    ['invalid blocked-IP trend availability', { ...adminResponse, analytics: { available: true, value: { ...analyticsOverview, blocked_ip_trend_available: 'yes' } } }],
  ])('fails closed for an admin response with %s', async (_label, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(dashboardApi.admin('token', 'seven_days', 'Asia/Shanghai'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response', message: 'API response was invalid' })
  })

  it.each([
    ['number in a decimal field', { ...tenantResponse, analytics: { available: true, value: { ...analyticsOverview, summary: { ...analytics, request_count: 9007199254740992 } } } }],
    ['invalid unlimited value', { ...tenantResponse, subscriptions: { available: true, value: { ...tenantResponse.subscriptions.value, items: [{ ...tenantResponse.subscriptions.value.items[0], site_limit: '-2' }] } } }],
    ['missing identity verification', { ...tenantResponse, identity_verification: undefined }],
    ['invalid identity verification', { ...tenantResponse, identity_verification: { available: true, value: { verified: 'no' } } }],
    ['missing profile', { ...tenantResponse, profile: undefined }],
    ['invalid profile IP', { ...tenantResponse, profile: { available: true, value: { last_login_ip: 'x'.repeat(65) } } }],
    ['missing forwarding total', { ...tenantResponse, resources: { available: true, value: { ...tenantResponse.resources.value, forwards_total: undefined } } }],
    ['range mismatch', { ...tenantResponse, meta: { ...tenantResponse.meta, range: 'yesterday' } }],
    ['unknown analytics enum', { ...tenantResponse, analytics: { available: false, reason: 'unknown' } }],
  ])('fails closed for a tenant response with %s', async (_label, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(dashboardApi.tenant('token', 'today', 'Asia/Shanghai'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('maps stable HTTP and network errors without exposing raw server messages', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: { code: 'dashboard_permission_denied', message: 'private policy', request_id: 'dashboard-1' } }, 403))
      .mockRejectedValueOnce(new Error('private hostname'))

    await expect(dashboardApi.admin('token', 'seven_days', 'Asia/Shanghai')).rejects.toMatchObject({
      status: 403, code: 'dashboard_permission_denied', message: 'API request failed', requestId: 'dashboard-1',
    })
    await expect(dashboardApi.tenant('token', 'today', 'Asia/Shanghai')).rejects.toMatchObject({
      status: 0, code: 'network_error', message: 'Network request failed',
    })
  })

  it('normalizes malformed JSON as invalid_response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{', { status: 200 }))

    await expect(dashboardApi.tenant('token', 'today', 'Asia/Shanghai')).rejects.toBeInstanceOf(ApiError)
    await expect(dashboardApi.tenant('token', 'today', 'Asia/Shanghai')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
