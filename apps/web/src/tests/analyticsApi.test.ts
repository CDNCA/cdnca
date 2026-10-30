import { ApiError } from '../api/auth'
import {
  analyticsApi,
  type AnalyticsFilter,
  type AnalyticsRankDimension,
  type AnalyticsSummary,
} from '../api/analytics'

const meta = {
  from: '2026-07-22T00:00:00Z',
  to: '2026-07-22T02:00:00Z',
  timezone: 'UTC',
  metric_version: 1,
} as const

const summary: AnalyticsSummary = {
  metric_version: 1,
  request_count: 12,
  request_bytes: 120,
  response_bytes: 240,
  total_bytes: 360,
  average_bandwidth_bps: 0.25,
  status_2xx: 10,
  status_3xx: 1,
  status_4xx: 1,
  status_5xx: 0,
  security_events: 2, security_event_rows: 2,
  cache_hit_requests: 3,
  cache_hit_bytes: 400,
  unique_client_ips: 2,
}

const filters: AnalyticsFilter = {
  from: meta.from,
  to: meta.to,
  siteId: '018f0000-0000-7000-8000-000000000001',
  nodeId: '018f0000-0000-7000-8000-000000000002',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function expectApiError(error: unknown, status: number, code: string): boolean {
  expect(error).toBeInstanceOf(ApiError)
  expect(error).toMatchObject({ message: 'API request failed', status, code })
  return true
}

describe('analytics API', () => {
  it('reads the distinct blocked-IP count without changing the summary contract', async () => {
    const response = { blocked_ip_count: 3, meta }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(analyticsApi.blockedIPCount('admin-token', 'admin', {
      ...filters,
      tenantId: '018f0000-0000-7000-8000-000000000003',
    })).resolves.toEqual(response)

    const parsed = new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/admin/analytics/blocked-ip-count')
    expect(parsed.searchParams.get('tenant_id')).toBe('018f0000-0000-7000-8000-000000000003')
  })

  it('reads the busiest 5-minute peak bandwidth (FX36)', async () => {
    const response = { data: { peak_bandwidth_bps: 8000, bucket_seconds: 300 }, meta }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    await expect(analyticsApi.peakBandwidth('tenant-token', 'tenant', filters)).resolves.toEqual(response)
    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test').pathname).toBe('/v1/analytics/peak-bandwidth')
    fetchSpy.mockResolvedValue(json({ data: { peak_bandwidth_bps: -1, bucket_seconds: 300 }, meta }))
    await expect(analyticsApi.peakBandwidth('tenant-token', 'tenant', filters)).rejects.toBeInstanceOf(ApiError)
  })

  it('reads the hourly blocked-IP series with the same filters', async () => {
    const response = { data: [{ hour: meta.from, blocked_ip_count: 2 }], meta }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(analyticsApi.blockedIPTrend('tenant-token', 'tenant', filters)).resolves.toEqual(response)

    const parsed = new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/analytics/blocked-ip-trend')
    expect(parsed.searchParams.get('site_id')).toBe(filters.siteId)
    expect(parsed.searchParams.get('node_id')).toBe(filters.nodeId)
  })

  it('reads the WAF-only overview and forwards the domain filter', async () => {
    const response = {
      data: {
        attacks: 8, blocked: 5, intercepted: 2, observed: 1, auto_blocked: 1, clients: 3,
        trend: [{ hour: meta.from, attacks: 8, blocked: 5, intercepted: 2, observed: 1, auto_blocked: 1, clients: 3 }],
        attack_types: [{ key: 'sql-injection', count: 5 }, { key: 'xss', count: 3 }],
        top_domains: [{ key: 'cdn.example.test', count: 8 }],
        top_clients: [{ key: '203.0.113.7', count: 3 }],
        top_countries: [{ key: 'CN', count: 8 }],
        top_provinces: [],
        top_carriers: [{ key: 'CMCC', count: 8 }],
        top_uris: [{ key: '/login', count: 4 }],
      },
      meta,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(analyticsApi.wafOverview('tenant-token', 'tenant', {
      ...filters,
      domain: 'cdn.example.test static.example.test',
    })).resolves.toEqual(response)

    const parsed = new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/analytics/waf-overview')
    expect(parsed.searchParams.get('domain')).toBe('cdn.example.test static.example.test')
  })

  it.each([
    {
      label: 'missing auto-block counter',
      mutate: (data: Record<string, unknown>) => { delete data.auto_blocked },
    },
    {
      label: 'unsorted attack types',
      mutate: (data: Record<string, unknown>) => {
        data.attack_types = [{ key: 'low', count: 1 }, { key: 'high', count: 2 }]
      },
    },
    {
      label: 'zero rank count',
      mutate: (data: Record<string, unknown>) => { data.top_domains = [{ key: 'cdn.example.test', count: 0 }] },
    },
  ])('rejects a WAF overview with $label', async ({ mutate }) => {
    const data: Record<string, unknown> = {
      attacks: 1, blocked: 1, intercepted: 0, observed: 0, auto_blocked: 0, clients: 1,
      trend: [], attack_types: [], top_domains: [], top_clients: [], top_countries: [], top_provinces: [], top_carriers: [], top_uris: [],
    }
    mutate(data)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data, meta }))

    await expect(analyticsApi.wafOverview('token', 'tenant', filters)).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it('maps admin filters to the admin summary route and preserves encoded values', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: summary, meta }))

    await analyticsApi.summary('admin-token', 'admin', {
      ...filters,
      tenantId: '018f0000-0000-7000-8000-000000000003',
      siteId: 'site id/+',
    })

    const [url, init] = fetchSpy.mock.calls[0]
    const parsed = new URL(String(url), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/admin/analytics/summary')
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      from: meta.from,
      to: meta.to,
      tenant_id: '018f0000-0000-7000-8000-000000000003',
      site_id: 'site id/+',
      node_id: filters.nodeId,
    })
    expect(init).toEqual(expect.objectContaining({
      credentials: 'include',
      headers: { Authorization: 'Bearer admin-token' },
    }))
  })

  it('uses tenant routes and never serializes tenant_id, including runtime-forged filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: summary, meta }))
      .mockResolvedValueOnce(json({ data: [{ hour: meta.from, ...summary }], meta }))
    const forged = { ...filters, tenantId: 'private-tenant' } as AnalyticsFilter

    await analyticsApi.summary('tenant-token', 'tenant', forged)
    await analyticsApi.trend('tenant-token', 'tenant', filters)

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      expect.stringContaining('/v1/analytics/summary?'),
      expect.stringContaining('/v1/analytics/hourly-trend?'),
    ])
    for (const [url] of fetchSpy.mock.calls) {
      expect(new URL(String(url), 'https://web.test').searchParams.has('tenant_id')).toBe(false)
      expect(String(url)).not.toContain('/v1/admin/')
    }
  })

  it('maps rank dimension, limit, cursor, and exposes the stable snapshot page', async () => {
    const cursor = 'cursor +/=='
    const response = {
      data: [{ key: '/asset.js', request_count: 3, response_bytes: 900 }],
      dimension: 'url',
      page: { next_cursor: 'next-page', snapshot_at: '2026-07-22T02:00:00.123Z', source: 'history' },
      meta,
    } as const
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(analyticsApi.rank('token', 'tenant', 'url', filters, 20, cursor)).resolves.toEqual(response)

    const parsed = new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test')
    expect(parsed.pathname).toBe('/v1/analytics/top/url')
    expect(parsed.searchParams.get('limit')).toBe('20')
    expect(parsed.searchParams.get('cursor')).toBe(cursor)
  })

  it('accepts a strict JA4 rank response', async () => {
    const response = {
      data: [
        { key: 't13d1516h2_8daaf6152771_b0da82dd1658', request_count: 3, response_bytes: 900 },
        { key: '__unknown__', request_count: 2, response_bytes: 600 },
      ],
      dimension: 'ja4',
      page: { snapshot_at: meta.to, source: 'history' },
      meta,
    } as const
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(analyticsApi.rank('token', 'tenant', 'ja4', filters, 20)).resolves.toEqual(response)
    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test').pathname).toBe('/v1/analytics/top/ja4')
  })

  it('sends referer rank domain sets and listen ports only to the rank contract', async () => {
    const rankResponse = {
      data: [{ key: '__unknown__', request_count: 2, response_bytes: 600 }],
      dimension: 'referer',
      page: { snapshot_at: meta.to, source: 'history' },
      meta,
    } as const
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(rankResponse))
      .mockResolvedValueOnce(json({ data: summary, meta }))
    const rankFilters = {
      ...filters,
      domain: 'cdn.example.test static.example.test',
      listenPort: 443,
    }

    await expect(analyticsApi.rank('token', 'tenant', 'referer', rankFilters, 20)).resolves.toEqual(rankResponse)
    await analyticsApi.summary('token', 'tenant', rankFilters)

    const rankURL = new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test')
    expect(rankURL.pathname).toBe('/v1/analytics/top/referer')
    expect(rankURL.searchParams.get('domain')).toBe(rankFilters.domain)
    expect(rankURL.searchParams.get('listen_port')).toBe('443')
    const summaryURL = new URL(String(fetchSpy.mock.calls[1][0]), 'https://web.test')
    expect(summaryURL.searchParams.has('domain')).toBe(false)
    expect(summaryURL.searchParams.has('listen_port')).toBe(false)
  })

  it.each([
    { label: 'extra top-level property', response: { data: summary, meta, internal: 'secret' }, call: 'summary' },
    { label: 'missing summary property', response: { data: { ...summary, request_count: undefined }, meta }, call: 'summary' },
    { label: 'wrong metric version', response: { data: { ...summary, metric_version: 2 }, meta }, call: 'summary' },
    { label: 'negative metric', response: { data: { ...summary, total_bytes: -1 }, meta }, call: 'summary' },
    { label: 'extra trend property', response: { data: [{ hour: meta.from, ...summary, sql: 'secret' }], meta }, call: 'trend' },
  ])('rejects a strict response with $label', async ({ response, call }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    const request = call === 'trend'
      ? analyticsApi.trend('token', 'tenant', filters)
      : analyticsApi.summary('token', 'tenant', filters)

    await expect(request).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    await expect(request).rejects.not.toThrow('secret')
  })

  it.each([
    { dimension: 'domain', responseDimension: 'ip', page: { snapshot_at: meta.to, source: 'history' } },
    { dimension: 'url', responseDimension: 'url', page: { snapshot_at: 'not-a-date', source: 'history' } },
    { dimension: 'ip', responseDimension: 'ip', page: { snapshot_at: meta.to, source: 'history', next_cursor: 9 } },
  ])('rejects an invalid rank response for $dimension', async ({ dimension, responseDimension, page }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [{ key: 'value', request_count: 1, response_bytes: 2 }],
      dimension: responseDimension,
      page,
      meta,
    }))

    await expect(analyticsApi.rank(
      'token',
      'tenant',
      dimension as AnalyticsRankDimension,
      filters,
      20,
    )).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    { status: 403, code: 'analytics_permission_denied' },
    { status: 422, code: 'analytics_dimension_unsupported' },
    { status: 503, code: 'analytics_storage_unavailable' },
  ])('keeps the stable $status error without leaking the server message', async ({ status, code }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code, message: 'private ClickHouse response', request_id: 'analytics-request-1' },
    }, status))

    await expect(analyticsApi.rank('token', 'tenant', 'url', filters, 20)).rejects.toSatisfy(
      (error: unknown) => expectApiError(error, status, code),
    )
  })

  it('normalizes malformed errors and network failures without leaking their detail', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: { code: 'NOT STABLE', message: 'private SQL' } }, 503))
      .mockRejectedValueOnce(new Error('private ClickHouse hostname'))

    await expect(analyticsApi.summary('token', 'tenant', filters)).rejects.toMatchObject({
      message: 'API request failed', status: 503, code: 'request_failed',
    })
    await expect(analyticsApi.summary('token', 'tenant', filters)).rejects.toMatchObject({
      message: 'Network request failed', status: 0, code: 'network_error',
    })
  })
})
