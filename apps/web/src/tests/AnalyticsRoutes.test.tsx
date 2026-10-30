import { screen, waitFor } from '@testing-library/react'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function analyticsResponse(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'https://cdnca.test')
  if (url.pathname.endsWith('/site-realtime')) {
    const from = url.searchParams.get('from')!
    const to = url.searchParams.get('to')!
    return json({
      data: {
        metric_version: 1, series_bucket_seconds: Math.ceil((Date.parse(to) - Date.parse(from)) / 60_000 / 744) * 60,
        summary: {
          requests: 1, traffic_bytes: 20, bandwidth_bps: 1, connections: 1,
          status_2xx: 1, status_3xx: 0, status_4xx: 0, status_5xx: 0,
          cache_hits: 1, cache_misses: 0, errors: 0, average_duration_us: 900,
          origin_connect_us: 100, origin_first_byte_us: 200, origin_total_us: 300,
        },
        series: [{ bucket: from, requests: 1, traffic_bytes: 20, bandwidth_bps: 1, connections: 1,
          cache_hits: 1, cache_misses: 0, cache_hit_bytes: 20, status_4xx: 0, status_5xx: 0,
          origin_total_us: 300, origin_traffic_bytes: null, origin_bandwidth_bps: null }],
        top: [{ host: 'cdn.example.test', listen_port: 443, requests: 1, traffic_bytes: 20 }],
        evidence: {
          access_source_count: 1, connection_source_count: 1,
          expected_events: 0, observed_events: 1, error_ppm: 0,
          finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z',
          coverage_from: from, coverage_to: to, snapshot_at: to,
          coverage_complete: true, covered_windows: (Date.parse(to) - Date.parse(from)) / 3_600_000,
          requested_windows: (Date.parse(to) - Date.parse(from)) / 3_600_000, missing_windows: [],
        },
      },
      meta: { from, to, timezone: 'UTC', metric_version: 1, query_version: 4 },
    })
  }
  if (url.pathname.includes('/analytics/logs/')) {
    const meta = {
      from: url.searchParams.get('from'),
      to: url.searchParams.get('to'),
      timezone: 'UTC',
      snapshot_at: '2026-07-28T08:00:00Z',
      consistency: 'snapshot',
      replacement_consistency: 'latest_event_id_at_snapshot',
      pagination: 'keyset',
    }
    if (url.pathname.endsWith('/access')) {
      return json({
        data: [{
          event_id: 'access-route', occurred_at: '2026-07-28T07:59:00Z',
          site_id: '018f0000-0000-7000-8000-000000000020', node_id: '018f0000-0000-7000-8000-000000000030',
          request_id: 'access-route-request', trace_id: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
          config_version_id: '018f0000-0000-7000-8000-000000000040',
          host: 'cdn.example.test', uri_path: '/asset.js', client_ip: '192.0.2.10', country_code: 'CN', carrier: 'CMCC',
          method: 'GET', protocol: 'HTTP/2', cache_status: 'HIT', upstream_result: 'ok', upstream_addr: '', status_code: 200,
          request_bytes: 128, response_bytes: 1024, duration_us: 900,
          task_id: null, installation_id: 'installation-route', request_headers: {}, response_headers: {},
          request_body: null, response_body: null, ja4: null,
          origin_connect_us: null, origin_first_byte_us: null, origin_total_us: null,
        }],
        meta,
      })
    }
    return json({
      data: [{
        event_id: 'block-route', occurred_at: '2026-07-28T07:58:00Z',
        site_id: '018f0000-0000-7000-8000-000000000020', node_id: '018f0000-0000-7000-8000-000000000030',
        request_id: 'block-route-request', trace_id: '', config_version_id: '018f0000-0000-7000-8000-000000000040',
        host: 'cdn.example.test', uri_path: '/blocked', client_ip: '192.0.2.11', country_code: 'CN', carrier: 'CMCC',
        event_type: 'waf', action: 'block', severity: 'high', rule_id: 'rule-1', status_code: 403,
        request_bytes: 256, response_bytes: 64,
        task_id: null, installation_id: 'installation-route', request_headers: {}, response_headers: {},
        request_body: null, response_body: null, ja4: null,
        origin_connect_us: null, origin_first_byte_us: null, origin_total_us: null,
        policy_id: '', detector: '', matched: '', user_agent: '', request_body_excerpt: '', count: 1, uri_query: '', site_domain: '', rule_name: '',
      }],
      meta,
    })
  }
  const meta = {
    from: url.searchParams.get('from'),
    to: url.searchParams.get('to'),
    timezone: 'UTC',
    metric_version: 1,
  }
  if (url.pathname.endsWith('/summary')) {
    return json({
      data: {
        metric_version: 1,
        request_count: 1,
        request_bytes: 10,
        response_bytes: 20,
        total_bytes: 30,
        average_bandwidth_bps: 1,
        status_2xx: 1,
        status_3xx: 0,
        status_4xx: 0,
        status_5xx: 0,
        security_events: 0, security_event_rows: 0,
        cache_hit_requests: 0,
        cache_hit_bytes: 0,
        unique_client_ips: 1,
      },
      meta,
    })
  }
  if (url.pathname.endsWith('/hourly-trend')) {
    return json({ data: [], meta })
  }
  return json({
    data: [{ key: 'cdn.example.test', request_count: 1, response_bytes: 20 }],
    dimension: url.pathname.split('/').at(-1),
    page: { snapshot_at: '2026-07-23T00:00:00Z', source: 'history' },
    meta,
  })
}

describe('analytics routes', () => {
  it('does not mount the unobserved stream analysis route', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/monitor/stream/analysis'])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('loads tenant real-time monitoring without sending tenant_id', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      (input) => Promise.resolve(analyticsResponse(input)),
    )

    renderWithProviders(<AppRoutes />, ['/monitor/site/realtime'])

    expect(await screen.findByRole('tab', { name: '基础数据' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/统计分析/实时监控')
    expect(pageRequests(fetchSpy)).toHaveLength(1)
    for (const input of pageRequests(fetchSpy)) {
      const url = new URL(String(input), 'https://cdnca.test')
      expect(url.pathname).toBe('/v1/analytics/site-realtime')
      expect(url.searchParams.has('tenant_id')).toBe(false)
    }
  })

  it('loads platform site analysis from the admin analytics domain', async () => {
    const actor = principal({
      scope_kind: 'platform',
      scope_id: 'platform',
      tenant_id: null,
      permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      (input) => Promise.resolve(analyticsResponse(input)),
    )

    renderWithProviders(<AppRoutes />, ['/monitor/site/analysis'])

    expect(await screen.findByRole('heading', { name: '网站统计分析' })).toBeInTheDocument()
    expect(await screen.findByText('cdn.example.test')).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/统计分析/数据分析')
    const url = new URL(pageRequests(fetchSpy)[0], 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/top/domain')
  })

  it.each([
    ['/monitor/site/access-log', '访问日志', '/v1/analytics/logs/access'],
    ['/monitor/site/block-event-log', '原始拦截事件', '/v1/analytics/logs/block-events'],
  ])('mounts %s behind sites.read', async (path, heading, apiPath) => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      (input) => Promise.resolve(analyticsResponse(input)),
    )

    renderWithProviders(<AppRoutes />, [path])

    if (path.endsWith('/access-log')) {
      expect(await screen.findByRole('region', { name: heading })).toBeInTheDocument()
    } else {
      expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    }
    expect(new URL(pageRequests(fetchSpy)[0], 'https://cdnca.test').pathname).toBe(apiPath)
  })

  // 当前拉黑列表进入页面即加载（不再要求先填网站），只有这一条请求。
  it('mounts /monitor/site/block-log behind sites.read and loads only the current block list', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      (input) => Promise.resolve(analyticsResponse(input)),
    )

    renderWithProviders(<AppRoutes />, ['/monitor/site/block-log'])

    expect(await screen.findByRole('heading', { name: '拉黑日志' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '当前拉黑', selected: true })).toBeInTheDocument()
    await waitFor(() => expect(pageRequests(fetchSpy)).not.toHaveLength(0))
    expect(pageRequests(fetchSpy).map((url) => new URL(url, 'https://cdnca.test').pathname))
      .toEqual(['/v1/analytics/logs/blocks/current'])
  })

  it('rejects analytics logs before mounting the lazy page when sites.read is absent', async () => {
    const actor = principal({ permissions: [] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/monitor/site/access-log'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(screen.queryByLabelText('页面加载中')).not.toBeInTheDocument()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('accepts the platform.admin wildcard before mounting an analytics log page', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/monitor/site/access-log'])

    expect(await screen.findByRole('region', { name: '访问日志' })).toBeInTheDocument()
    expect(screen.queryByText('无权访问')).not.toBeInTheDocument()
    // 统计分析进入即拉全平台，不等租户输入；请求不带 tenant_id。
    await waitFor(() => expect(pageRequests(fetchSpy).some((url) => url.startsWith('/v1/admin/analytics/logs/access?'))).toBe(true))
    expect(pageRequests(fetchSpy).every((url) => !url.includes('tenant_id='))).toBe(true)
  })
})
