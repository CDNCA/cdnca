import { siteRealtimeApi } from './siteRealtime'

const filters = { from: '2026-08-07T00:00:00.000Z', to: '2026-08-07T01:00:00.000Z' }

function response(errorPPM = 0) {
  return {
    data: {
      metric_version: 1, series_bucket_seconds: 60,
      summary: {
        requests: 1, traffic_bytes: 8, bandwidth_bps: 1, connections: 1,
        status_2xx: 1, status_3xx: 0, status_4xx: 0, status_5xx: 0, cache_hits: 1, cache_misses: 0,
        errors: 0, average_duration_us: 1, origin_connect_us: 1, origin_first_byte_us: 1, origin_total_us: 1,
      },
      series: [{ bucket: filters.from, requests: 1, traffic_bytes: 8, bandwidth_bps: 1, connections: 1,
        cache_hits: 1, cache_misses: 0, cache_hit_bytes: 8, status_4xx: 0, status_5xx: 0,
        origin_total_us: 1, origin_traffic_bytes: null, origin_bandwidth_bps: null }],
      top: [{ host: 'cdn.example.test', listen_port: 443, requests: 1, traffic_bytes: 8 }],
      evidence: { access_source_count: 1, connection_source_count: 1, expected_events: 0, observed_events: 1, error_ppm: errorPPM, finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z',
        coverage_from: filters.from, coverage_to: filters.to, snapshot_at: filters.to,
        coverage_complete: true, requested_windows: 1, covered_windows: 1, missing_windows: [] as string[] },
    },
    meta: { ...filters, timezone: 'UTC', metric_version: 1, query_version: 4 },
  }
}

describe('siteRealtimeApi', () => {
  it('uses one tenant-scoped live request (query_version=4) and accepts live evidence', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(response())))
    const result = await siteRealtimeApi.read('token', 'tenant', filters)
    expect(result.data.summary.requests).toBe(1)
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/site-realtime')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(url.searchParams.get('query_version')).toBe('4')
  })

  it('uses a platform-wide request by default and optionally narrows to one tenant', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify(response()))))
    await siteRealtimeApi.read('token', 'admin', filters)
    await siteRealtimeApi.read('token', 'admin', { ...filters, tenantId: '018f0000-0000-7000-8000-000000000010' })

    const globalURL = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(globalURL.pathname).toBe('/v1/admin/analytics/site-realtime')
    expect(globalURL.searchParams.has('tenant_id')).toBe(false)
    const tenantURL = new URL(String(fetchSpy.mock.calls[1][0]), 'http://cdnca.test')
    expect(tenantURL.searchParams.get('tenant_id')).toBe('018f0000-0000-7000-8000-000000000010')
  })

  it('rejects inconsistent evidence as an invalid response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(response(1))))
    await expect(siteRealtimeApi.read('token', 'tenant', filters)).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    ['summary and series drift', (value: ReturnType<typeof response>) => { value.data.series[0].requests = 2 }],
    ['live evidence claiming an expected count', (value: ReturnType<typeof response>) => { value.data.evidence.expected_events = 1 }],
    ['live evidence claiming finalization', (value: ReturnType<typeof response>) => { value.data.evidence.finalized_through = filters.to }],
    ['observed fewer than summarized', (value: ReturnType<typeof response>) => { value.data.evidence.observed_events = 0 }],
    ['series bucket outside the requested range', (value: ReturnType<typeof response>) => { value.data.series[0].bucket = '2026-08-06T23:59:00.000Z' }],
    ['ranking exceeds the summary', (value: ReturnType<typeof response>) => { value.data.top[0].requests = 2 }],
    ['ranking tie is not canonical', (value: ReturnType<typeof response>) => {
      value.data.top = [
        { host: 'z.example.test', listen_port: 443, requests: 1, traffic_bytes: 8 },
        { host: 'a.example.test', listen_port: 443, requests: 1, traffic_bytes: 8 },
      ]
    }],
  ])('rejects %s', async (_name, mutate) => {
    const value = response()
    mutate(value)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))
    await expect(siteRealtimeApi.read('token', 'tenant', filters)).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })
})
