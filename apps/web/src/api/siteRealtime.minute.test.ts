import { siteRealtimeApi } from './siteRealtime'

const filters = { from: '2026-09-25T12:17:00.000Z', to: '2026-09-25T12:19:00.000Z' }

function minuteResponse() {
  return {
    data: {
      metric_version: 1, series_bucket_seconds: 60,
      summary: {
        requests: 2, traffic_bytes: 120, bandwidth_bps: 8, connections: 1,
        status_2xx: 1, status_3xx: 0, status_4xx: 1, status_5xx: 0, cache_hits: 1, cache_misses: 1,
        errors: 0, average_duration_us: 1, origin_connect_us: 1, origin_first_byte_us: 2, origin_total_us: 3,
      },
      series: [{
        bucket: filters.from, requests: 2, traffic_bytes: 120, bandwidth_bps: 16, connections: 1,
        cache_hits: 1, cache_misses: 1, cache_hit_bytes: 40, status_4xx: 1, status_5xx: 0,
        origin_total_us: 3 as number | null, origin_traffic_bytes: null, origin_bandwidth_bps: null,
      }],
      top: [{ host: 'cdn.example.test', listen_port: 443, requests: 2, traffic_bytes: 120 }],
      evidence: {
        access_source_count: 2, connection_source_count: 1, expected_events: 0, observed_events: 100, error_ppm: 0,
        finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z',
        coverage_from: '2026-09-25T12:00:00Z', coverage_to: '2026-09-25T13:00:00Z', snapshot_at: '2026-09-25T12:19:00Z',
        coverage_complete: true, requested_windows: 1, covered_windows: 1, missing_windows: [] as string[],
      },
    },
    meta: { ...filters, timezone: 'UTC', metric_version: 1, query_version: 4 },
  }
}

it('preserves exact minutes and reads the live enclosing-hour envelope', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(minuteResponse())))
  const result = await siteRealtimeApi.read('token', 'admin', filters)
  expect(result.data.summary.requests).toBe(2)
  expect(result.data.evidence.observed_events).toBe(100)
  expect(result.data.series_bucket_seconds).toBe(60)
  const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdn.test')
  expect(url.searchParams.get('from')).toBe(filters.from)
  expect(url.searchParams.get('to')).toBe(filters.to)
  expect(url.searchParams.get('query_version')).toBe('4')
  expect(result.data.series[0].origin_traffic_bytes).toBeNull()
})

it('does not turn missing upstream latency into a zero measurement', async () => {
  const value = minuteResponse()
  value.data.series[0].origin_total_us = null
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))
  expect((await siteRealtimeApi.read('token', 'tenant', filters)).data.series[0].origin_total_us).toBeNull()
})

it.each([
  ['coverage starts after the enclosing hour', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.coverage_from = filters.from }],
  ['coverage ends before the enclosing hour', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.coverage_to = filters.to }],
  ['live read claims a watermark', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.source_watermark = filters.to }],
  ['live read claims an expected count', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.expected_events = 100 }],
  ['observed fewer than summarized', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.observed_events = 1 }],
  ['noncanonical bucket width', (v: ReturnType<typeof minuteResponse>) => { v.data.series_bucket_seconds = 120 }],
  ['bucket off its minute grid', (v: ReturnType<typeof minuteResponse>) => { v.data.series[0].bucket = '2026-09-25T12:17:01Z' }],
  ['cache bytes exceed traffic', (v: ReturnType<typeof minuteResponse>) => { v.data.series[0].cache_hit_bytes = 121 }],
  ['quality series does not reconcile', (v: ReturnType<typeof minuteResponse>) => { v.data.series[0].status_4xx = 0 }],
  ['incomplete coverage without missing hours', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.coverage_complete = false }],
  ['covered windows do not add up', (v: ReturnType<typeof minuteResponse>) => { v.data.evidence.covered_windows = 0 }],
  ['missing hour outside coverage', (v: ReturnType<typeof minuteResponse>) => {
    Object.assign(v.data.evidence, { coverage_complete: false, covered_windows: 0, missing_windows: ['2026-09-25T13:00:00Z'] })
  }],
  ['missing hour not aligned', (v: ReturnType<typeof minuteResponse>) => {
    Object.assign(v.data.evidence, { coverage_complete: false, covered_windows: 0, missing_windows: ['2026-09-25T12:30:00Z'] })
  }],
])('rejects %s', async (_, mutate) => {
  const value = minuteResponse()
  mutate(value)
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))
  await expect(siteRealtimeApi.read('token', 'admin', filters)).rejects.toMatchObject({ code: 'invalid_response' })
})
