import { ApiError, networkApiError, responseApiError } from './auth'

export type SiteRealtimeAudience = 'admin' | 'tenant'

export interface SiteRealtimeFilters {
  from: string
  to: string
  tenantId?: string
  siteId?: string
  host?: string
  listenPort?: number
}

export interface SiteRealtimeMetrics {
  requests: number
  traffic_bytes: number
  bandwidth_bps: number
  connections: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  cache_hits: number
  cache_misses: number
  errors: number
  average_duration_us: number
  origin_connect_us: number
  origin_first_byte_us: number
  origin_total_us: number
}

export interface SiteRealtimePoint {
  bucket: string
  requests: number
  traffic_bytes: number
  bandwidth_bps: number
  connections: number
  cache_hits: number
  cache_misses: number
  cache_hit_bytes: number
  status_4xx: number
  status_5xx: number
  origin_total_us: number | null
  origin_traffic_bytes: null
  origin_bandwidth_bps: null
}

export interface SiteRealtimeTopItem {
  host: string
  listen_port: number
  requests: number
  traffic_bytes: number
}

export interface SiteRealtimeEvidence {
  access_source_count: number
  connection_source_count: number
  expected_events: number
  observed_events: number
  error_ppm: number
  finalized_through: string
  source_watermark: string
  coverage_from: string
  coverage_to: string
  snapshot_at: string
  /** False when some enclosing hours are not settled yet; their facts are excluded. */
  coverage_complete: boolean
  requested_windows: number
  covered_windows: number
  /** Unsettled enclosing hour starts, ascending. */
  missing_windows: string[]
}

export interface SiteRealtimeResponse {
  data: {
    metric_version: 1
    series_bucket_seconds: number
    summary: SiteRealtimeMetrics
    series: SiteRealtimePoint[]
    top: SiteRealtimeTopItem[]
    evidence: SiteRealtimeEvidence
  }
  meta: { from: string; to: string; timezone: 'UTC'; metric_version: 1; query_version: 3 }
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const metricsKeys = [
  'requests', 'traffic_bytes', 'bandwidth_bps', 'connections', 'status_2xx', 'status_3xx', 'status_4xx',
  'status_5xx', 'cache_hits', 'cache_misses', 'errors', 'average_duration_us', 'origin_connect_us',
  'origin_first_byte_us', 'origin_total_us',
]

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && keys.every((key) => key in value)
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function metric(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

function dateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function metrics(value: unknown): value is SiteRealtimeMetrics {
  if (!record(value) || !exact(value, metricsKeys)) return false
  const counts = ['requests', 'traffic_bytes', 'connections', 'status_2xx', 'status_3xx', 'status_4xx', 'status_5xx', 'cache_hits', 'cache_misses', 'errors']
  const durations = ['bandwidth_bps', 'average_duration_us', 'origin_connect_us', 'origin_first_byte_us', 'origin_total_us']
  if (!counts.every((key) => count(value[key])) || !durations.every((key) => metric(value[key]))) return false
  const typed = value as unknown as SiteRealtimeMetrics
  return typed.status_2xx + typed.status_3xx + typed.status_4xx + typed.status_5xx <= typed.requests &&
    typed.cache_hits + typed.cache_misses <= typed.requests && typed.errors <= typed.requests &&
    typed.origin_connect_us <= typed.origin_first_byte_us && typed.origin_first_byte_us <= typed.origin_total_us
}

function point(value: unknown): value is SiteRealtimePoint {
  if (!record(value) || !exact(value, ['bucket', 'requests', 'traffic_bytes', 'bandwidth_bps', 'connections',
    'cache_hits', 'cache_misses', 'cache_hit_bytes', 'status_4xx', 'status_5xx', 'origin_total_us', 'origin_traffic_bytes', 'origin_bandwidth_bps'])) return false
  return dateTime(value.bucket) && count(value.requests) && count(value.traffic_bytes) && metric(value.bandwidth_bps) && count(value.connections) &&
    count(value.cache_hits) && count(value.cache_misses) && value.cache_hits + value.cache_misses <= value.requests &&
    count(value.cache_hit_bytes) && value.cache_hit_bytes <= value.traffic_bytes &&
    count(value.status_4xx) && count(value.status_5xx) && value.status_4xx + value.status_5xx <= value.requests &&
    (value.origin_total_us === null || metric(value.origin_total_us)) && value.origin_traffic_bytes === null && value.origin_bandwidth_bps === null
}

function topItem(value: unknown): value is SiteRealtimeTopItem {
  return record(value) && exact(value, ['host', 'listen_port', 'requests', 'traffic_bytes']) &&
    typeof value.host === 'string' && value.host.length > 0 && value.host.length <= 253 && value.host === value.host.toLowerCase() &&
    count(value.listen_port) && value.listen_port <= 65535 && count(value.requests) && value.requests > 0 && count(value.traffic_bytes)
}

// Live evidence (query_version=4): every enclosing hour is read as ingested,
// so coverage is complete and no expected count, accuracy or finalization is claimed.
function evidence(value: unknown, from: string, to: string): value is SiteRealtimeEvidence {
  if (!record(value) || !exact(value, ['access_source_count', 'connection_source_count', 'expected_events', 'observed_events', 'error_ppm', 'finalized_through', 'source_watermark', 'coverage_from', 'coverage_to', 'snapshot_at',
    'coverage_complete', 'requested_windows', 'covered_windows', 'missing_windows']) ||
    !count(value.access_source_count) || !count(value.connection_source_count) || !count(value.observed_events) ||
    !dateTime(value.finalized_through) || !dateTime(value.source_watermark) ||
    !dateTime(value.coverage_from) || !dateTime(value.coverage_to) || !dateTime(value.snapshot_at) ||
    !Array.isArray(value.missing_windows)) return false
  const coverageFrom = Math.floor(Date.parse(from) / 3_600_000) * 3_600_000
  const coverageTo = Math.ceil(Date.parse(to) / 3_600_000) * 3_600_000
  const windows = (coverageTo - coverageFrom) / 3_600_000
  return value.expected_events === 0 && value.error_ppm === 0 && value.coverage_complete === true &&
    value.missing_windows.length === 0 && value.requested_windows === windows && value.covered_windows === windows &&
    Date.parse(value.finalized_through) === 0 && Date.parse(value.source_watermark) === 0 &&
    Date.parse(value.coverage_from) === coverageFrom && Date.parse(value.coverage_to) === coverageTo
}

function parseResponse(value: unknown, filters: SiteRealtimeFilters): SiteRealtimeResponse {
  const from = Date.parse(filters.from)
  const to = Date.parse(filters.to)
  const window = to - from
  const bucketSeconds = Math.ceil(window / 60_000 / 744) * 60
  if (!Number.isFinite(window) || window <= 0 || window > 31 * 86_400_000 || from % 60_000 !== 0 || to % 60_000 !== 0) throw invalidResponse()
  if (!record(value) || !exact(value, ['data', 'meta']) || !record(value.meta) ||
    !exact(value.meta, ['from', 'to', 'timezone', 'metric_version', 'query_version']) || !dateTime(value.meta.from) || !dateTime(value.meta.to) ||
    Date.parse(value.meta.from) !== Date.parse(filters.from) || Date.parse(value.meta.to) !== Date.parse(filters.to) ||
    value.meta.timezone !== 'UTC' || value.meta.metric_version !== 1 || value.meta.query_version !== realtimeQueryVersion || !record(value.data) ||
    !exact(value.data, ['metric_version', 'series_bucket_seconds', 'summary', 'series', 'top', 'evidence']) || value.data.metric_version !== 1 ||
    value.data.series_bucket_seconds !== bucketSeconds ||
    !metrics(value.data.summary) || !Array.isArray(value.data.series) || value.data.series.length > 744 || !value.data.series.every(point) ||
    !Array.isArray(value.data.top) || value.data.top.length > 10 || !value.data.top.every(topItem) || !evidence(value.data.evidence, filters.from, filters.to)) {
    throw invalidResponse()
  }
  const series = value.data.series as SiteRealtimePoint[]
  const top = value.data.top as SiteRealtimeTopItem[]
  const summary = value.data.summary as SiteRealtimeMetrics
  const reconciled = value.data.evidence as SiteRealtimeEvidence
  let seriesRequests = 0
  let seriesTraffic = 0
  const quality = { cache_hits: 0, cache_misses: 0, status_4xx: 0, status_5xx: 0 }
  for (const [index, item] of series.entries()) {
    const bucket = Date.parse(item.bucket)
    seriesRequests += item.requests
    seriesTraffic += item.traffic_bytes
    for (const key of Object.keys(quality) as Array<keyof typeof quality>) quality[key] += item[key]
    if (bucket < from || bucket >= to || (bucket - from) % (bucketSeconds * 1000) !== 0 ||
      index > 0 && Date.parse(series[index - 1].bucket) >= bucket ||
      !Number.isSafeInteger(seriesRequests) || !Number.isSafeInteger(seriesTraffic)) throw invalidResponse()
  }
  const seenTop = new Set<string>()
  for (const [index, item] of top.entries()) {
    const identity = `${item.host}:${item.listen_port}`
    const previous = top[index - 1]
    if (seenTop.has(identity) || item.requests > summary.requests || item.traffic_bytes > summary.traffic_bytes ||
      previous && (previous.traffic_bytes < item.traffic_bytes ||
        previous.traffic_bytes === item.traffic_bytes && (previous.requests < item.requests ||
          previous.requests === item.requests && (previous.host > item.host ||
            previous.host === item.host && previous.listen_port >= item.listen_port)))) throw invalidResponse()
    seenTop.add(identity)
  }
  if (seriesRequests !== summary.requests || seriesTraffic !== summary.traffic_bytes ||
    Object.entries(quality).some(([key, total]) => !Number.isSafeInteger(total) || total !== summary[key as keyof typeof quality]) ||
    reconciled.access_source_count !== summary.requests || reconciled.observed_events < summary.requests ||
    (Date.parse(reconciled.coverage_from) === from && Date.parse(reconciled.coverage_to) === to && reconciled.observed_events !== summary.requests) ||
    (reconciled.connection_source_count === 0 && summary.connections !== 0)) {
    throw invalidResponse()
  }
  return value as unknown as SiteRealtimeResponse
}

// The realtime monitor reads live facts (query_version=4): the current,
// not yet settled hour included. Settled reconciliation is the analysis page's job.
const realtimeQueryVersion = 4

function queryString(audience: SiteRealtimeAudience, filters: SiteRealtimeFilters): string {
  const query = new URLSearchParams({ from: filters.from, to: filters.to, query_version: String(realtimeQueryVersion) })
  if (audience === 'admin' && filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.host) query.set('host', filters.host)
  if (filters.listenPort) query.set('listen_port', String(filters.listenPort))
  return query.toString()
}

async function read(
  accessToken: string,
  audience: SiteRealtimeAudience,
  filters: SiteRealtimeFilters,
  signal?: AbortSignal,
): Promise<SiteRealtimeResponse> {
  const base = audience === 'admin' ? '/v1/admin/analytics' : '/v1/analytics'
  let response: Response
  try {
    response = await fetch(`${apiRoot}${base}/site-realtime?${queryString(audience, filters)}`, {
      credentials: 'include', signal, headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let raw: unknown
  try {
    raw = await response.json()
  } catch {
    throw invalidResponse()
  }
  return parseResponse(raw, filters)
}

export const siteRealtimeApi = { read }
