import { siteRealtimeApi } from './siteRealtime'

const filters = { from: '2026-09-25T12:00:00.000Z', to: '2026-09-25T13:00:00.000Z' }

function liveZero() {
  return {
    data: {
      metric_version: 1, series_bucket_seconds: 60,
      summary: {
        requests: 0, traffic_bytes: 0, bandwidth_bps: 0, connections: 3,
        status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, cache_hits: 0, cache_misses: 0,
        errors: 0, average_duration_us: 0, origin_connect_us: 0, origin_first_byte_us: 0, origin_total_us: 0,
      },
      series: [], top: [],
      evidence: {
        access_source_count: 0, connection_source_count: 1432, expected_events: 0, observed_events: 0,
        error_ppm: 0, finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z',
        coverage_from: filters.from, coverage_to: filters.to, snapshot_at: filters.to,
        coverage_complete: true, requested_windows: 1, covered_windows: 1, missing_windows: [] as string[],
      },
    },
    meta: { from: '2026-09-25T12:00:00Z', to: '2026-09-25T13:00:00Z', timezone: 'UTC', metric_version: 1, query_version: 4 },
  }
}

it('accepts live zero traffic with independent connection observations and equivalent UTC timestamps', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(liveZero())))
  const result = await siteRealtimeApi.read('token', 'admin', filters)
  expect(result.data.summary.requests).toBe(0)
  expect(result.data.summary.connections).toBe(3)
})

it.each([
  ['finalization claimed by a live read', (v: ReturnType<typeof liveZero>) => { v.data.evidence.finalized_through = filters.from }],
  ['missing watermark', (v: ReturnType<typeof liveZero>) => { v.data.evidence.source_watermark = '' }],
  ['mismatched window', (v: ReturnType<typeof liveZero>) => { v.meta.to = '2026-09-25T13:01:00Z' }],
  ['expected count claimed by a live read', (v: ReturnType<typeof liveZero>) => { v.data.evidence.expected_events = 1 }],
  ['connection value without observations', (v: ReturnType<typeof liveZero>) => { v.data.evidence.connection_source_count = 0 }],
])('rejects invalid zero response: %s', async (_, mutate) => {
  const value = liveZero()
  mutate(value)
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))
  await expect(siteRealtimeApi.read('token', 'admin', filters)).rejects.toMatchObject({ code: 'invalid_response' })
})
