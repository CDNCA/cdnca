import { ApiError, networkApiError, responseApiError } from './auth'

export type AnalyticsAudience = 'admin' | 'tenant'
export type AnalyticsRankDimension = 'url' | 'ip' | 'domain' | 'region' | 'carrier' | 'ja4' | 'referer' | 'province' | 'browser' | 'os'
export type AnalyticsSupportedRankDimension = AnalyticsRankDimension

export interface AnalyticsFilter {
  from: string
  to: string
  siteId?: string
  domain?: string
  nodeId?: string
  listenPort?: number
}

export interface AdminAnalyticsFilter extends AnalyticsFilter {
  tenantId?: string
}

export type AnalyticsFilters<A extends AnalyticsAudience = AnalyticsAudience> =
  A extends 'admin' ? AdminAnalyticsFilter : AnalyticsFilter & { tenantId?: never }

export interface AnalyticsQueryMetadata {
  from: string
  to: string
  timezone: 'UTC'
  metric_version: 1
}

export interface AnalyticsSummary {
  metric_version: 1
  request_count: number
  request_bytes: number
  response_bytes: number
  total_bytes: number
  average_bandwidth_bps: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  /** Security events in requests (an aggregated CC challenge / 429 event counts its requests). */
  security_events: number
  /** Security event records (an aggregated event is one). */
  security_event_rows: number
  /** Requests answered from the edge cache; hit ratio = cache_hit_requests / request_count. */
  cache_hit_requests: number
  cache_hit_bytes: number
  /** Distinct client addresses (per trend point: in that hour). */
  unique_client_ips: number
}

export interface AnalyticsSummaryResponse {
  data: AnalyticsSummary
  meta: AnalyticsQueryMetadata
}

export interface AnalyticsPeakBandwidthResponse {
  data: { peak_bandwidth_bps: number; bucket_seconds: number }
  meta: AnalyticsQueryMetadata
}

export interface AnalyticsBlockedIPCountResponse {
  blocked_ip_count: number
  meta: AnalyticsQueryMetadata
}

export interface AnalyticsBlockedIPTrendPoint {
  hour: string
  blocked_ip_count: number
}

export interface AnalyticsBlockedIPTrendResponse {
  data: AnalyticsBlockedIPTrendPoint[]
  meta: AnalyticsQueryMetadata
}

export interface AnalyticsWAFTrendPoint {
  hour: string
  attacks: number
  blocked: number
  intercepted: number
  observed: number
  auto_blocked: number
  clients: number
}

export interface AnalyticsWAFRankItem {
  key: string
  count: number
  /** attack_types only: the rule name (policy rule or OWASP CRS), when known. */
  name?: string
}

export interface AnalyticsWAFOverview {
  attacks: number
  blocked: number
  intercepted: number
  observed: number
  auto_blocked: number
  clients: number
  trend: AnalyticsWAFTrendPoint[]
  attack_types: AnalyticsWAFRankItem[]
  top_domains: AnalyticsWAFRankItem[]
  top_clients: AnalyticsWAFRankItem[]
  top_countries: AnalyticsWAFRankItem[]
  top_provinces: AnalyticsWAFRankItem[]
  top_carriers: AnalyticsWAFRankItem[]
  top_uris: AnalyticsWAFRankItem[]
}

export interface AnalyticsWAFOverviewResponse {
  data: AnalyticsWAFOverview
  meta: AnalyticsQueryMetadata
}

export interface AnalyticsTrendPoint extends AnalyticsSummary {
  hour: string
}

export interface AnalyticsTrendResponse {
  data: AnalyticsTrendPoint[]
  meta: AnalyticsQueryMetadata
}

export interface AnalyticsRankItem {
  key: string
  request_count: number
  response_bytes: number
  /** Domain and URL rankings: the key's address parts; port 0 or absent is unknown. */
  host?: string
  port?: number
  path?: string
  /** URL ranking: https when the site serves HTTPS on port, http otherwise; absent when unknown. */
  scheme?: 'http' | 'https'
}

export interface AnalyticsRankResponse {
  data: AnalyticsRankItem[]
  dimension: AnalyticsSupportedRankDimension
  page: {
    next_cursor?: string
    snapshot_at: string
    /** history: hourly facts (bandwidth_history_days); access_log: raw logs (access_logs_days). */
    source: 'history' | 'access_log'
    /** Set when the range starts before the source's oldest data: the ranking covers [retained_from, to). */
    retained_from?: string
  }
  meta: AnalyticsQueryMetadata
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const supportedRankDimensions = new Set<AnalyticsSupportedRankDimension>([
  'url',
  'ip',
  'domain',
  'region',
  'carrier',
  'ja4',
  'referer',
  'province',
  'browser',
  'os',
])
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

async function request(path: string, accessToken: string): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

function queryString<A extends AnalyticsAudience>(
  audience: A,
  filters: AnalyticsFilters<A>,
  options?: {
    includeDomain?: boolean
    includeListenPort?: boolean
    rank?: { limit: number; cursor?: string }
  },
): string {
  const query = new URLSearchParams({ from: filters.from, to: filters.to })
  if (audience === 'admin') {
    const tenantId = (filters as AdminAnalyticsFilter).tenantId
    if (tenantId) query.set('tenant_id', tenantId)
  }
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (options?.includeDomain && filters.domain) query.set('domain', filters.domain)
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (options?.includeListenPort && filters.listenPort) query.set('listen_port', String(filters.listenPort))
  if (options?.rank) {
    query.set('limit', String(options.rank.limit))
    if (options.rank.cursor) query.set('cursor', options.rank.cursor)
  }
  return query.toString()
}

function basePath(audience: AnalyticsAudience): string {
  return audience === 'admin' ? '/v1/admin/analytics' : '/v1/analytics'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const keys = Object.keys(value)
  return required.every((key) => key in value) && keys.every((key) => required.includes(key) || optional.includes(key))
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && Number.isInteger(value) && value >= 0
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0
    return code <= 0x1f || code === 0x7f
  })
}

function isMetric(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

const summaryKeys = [
  'metric_version',
  'request_count',
  'request_bytes',
  'response_bytes',
  'total_bytes',
  'average_bandwidth_bps',
  'status_2xx',
  'status_3xx',
  'status_4xx',
  'status_5xx',
  'security_events',
  'security_event_rows',
  'cache_hit_requests',
  'cache_hit_bytes',
  'unique_client_ips',
]

function hasSummaryValues(value: Record<string, unknown>): boolean {
  if (value.metric_version !== 1) return false
  return isCount(value.request_count) && isCount(value.request_bytes) &&
    isCount(value.response_bytes) && isCount(value.total_bytes) &&
    isMetric(value.average_bandwidth_bps) && isCount(value.status_2xx) &&
    isCount(value.status_3xx) && isCount(value.status_4xx) &&
    isCount(value.status_5xx) && isCount(value.security_events) && isCount(value.security_event_rows) &&
    isCount(value.cache_hit_requests) && isCount(value.cache_hit_bytes) && isCount(value.unique_client_ips) &&
    value.cache_hit_requests <= value.request_count && value.unique_client_ips <= value.request_count
}

function isSummary(value: unknown): value is AnalyticsSummary {
  return isRecord(value) && hasExactKeys(value, summaryKeys) && hasSummaryValues(value)
}

function isMetadata(value: unknown): value is AnalyticsQueryMetadata {
  return isRecord(value) && hasExactKeys(value, ['from', 'to', 'timezone', 'metric_version']) &&
    isDateTime(value.from) && isDateTime(value.to) && value.timezone === 'UTC' && value.metric_version === 1
}

function parseSummary(value: unknown): AnalyticsSummaryResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'meta']) ||
    !isSummary(value.data) || !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsSummaryResponse
}

function parsePeakBandwidth(value: unknown): AnalyticsPeakBandwidthResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'meta']) || !isRecord(value.data) ||
    !hasExactKeys(value.data, ['peak_bandwidth_bps', 'bucket_seconds']) || !isCount(value.data.peak_bandwidth_bps) ||
    value.data.bucket_seconds !== 300 || !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsPeakBandwidthResponse
}

function parseBlockedIPCount(value: unknown): AnalyticsBlockedIPCountResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['blocked_ip_count', 'meta']) ||
    !isCount(value.blocked_ip_count) || !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsBlockedIPCountResponse
}

function isBlockedIPTrendPoint(value: unknown): value is AnalyticsBlockedIPTrendPoint {
  return isRecord(value) && hasExactKeys(value, ['hour', 'blocked_ip_count']) &&
    isDateTime(value.hour) && isCount(value.blocked_ip_count)
}

function parseBlockedIPTrend(value: unknown): AnalyticsBlockedIPTrendResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'meta']) || !Array.isArray(value.data) ||
    value.data.length > 744 || !value.data.every(isBlockedIPTrendPoint) || !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsBlockedIPTrendResponse
}

function isWAFTrendPoint(value: unknown): value is AnalyticsWAFTrendPoint {
  return isRecord(value) && hasExactKeys(value, ['hour', 'attacks', 'blocked', 'intercepted', 'observed', 'auto_blocked', 'clients']) &&
    isDateTime(value.hour) && isCount(value.attacks) && isCount(value.blocked) &&
    isCount(value.intercepted) && isCount(value.observed) && isCount(value.auto_blocked) && isCount(value.clients)
}

function isWAFRank(value: unknown): value is AnalyticsWAFRankItem[] {
  if (!Array.isArray(value) || value.length > 10) return false
  const keys = new Set<string>()
  return value.every((item, index) => {
    const named = isRecord(item) && 'name' in item
    if (!isRecord(item) || !hasExactKeys(item, named ? ['key', 'count', 'name'] : ['key', 'count']) || typeof item.key !== 'string' ||
      named && (typeof item.name !== 'string' || item.name.length > 256 || hasControlCharacter(item.name)) ||
      item.key.length === 0 || item.key.length > 4096 || item.key.trim() !== item.key || hasControlCharacter(item.key) ||
    !isCount(item.count) || item.count === 0 || keys.has(item.key)) return false
    keys.add(item.key)
    if (index === 0) return true
    const previous = value[index - 1] as AnalyticsWAFRankItem
    return previous.count > item.count || previous.count === item.count && previous.key < item.key
  })
}

function parseWAFOverview(value: unknown): AnalyticsWAFOverviewResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'meta']) || !isRecord(value.data) ||
    !hasExactKeys(value.data, [
      'attacks', 'blocked', 'intercepted', 'observed', 'auto_blocked', 'clients', 'trend',
      'attack_types', 'top_domains', 'top_clients', 'top_countries', 'top_provinces', 'top_carriers', 'top_uris',
    ]) ||
    !isCount(value.data.attacks) || !isCount(value.data.blocked) || !isCount(value.data.intercepted) ||
    !isCount(value.data.observed) || !isCount(value.data.auto_blocked) || !isCount(value.data.clients) ||
    !Array.isArray(value.data.trend) || value.data.trend.length > 744 || !value.data.trend.every(isWAFTrendPoint) ||
    !isWAFRank(value.data.attack_types) || !isWAFRank(value.data.top_domains) ||
    !isWAFRank(value.data.top_clients) || !isWAFRank(value.data.top_countries) ||
    !isWAFRank(value.data.top_provinces) || !isWAFRank(value.data.top_carriers) ||
    !isWAFRank(value.data.top_uris) || !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsWAFOverviewResponse
}

function isTrendPoint(value: unknown): value is AnalyticsTrendPoint {
  return isRecord(value) && hasExactKeys(value, ['hour', ...summaryKeys]) &&
    isDateTime(value.hour) && hasSummaryValues(value)
}

function parseTrend(value: unknown): AnalyticsTrendResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'meta']) || !Array.isArray(value.data) ||
    value.data.length > 744 || !value.data.every(isTrendPoint) || !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsTrendResponse
}

function isRankItem(value: unknown): value is AnalyticsRankItem {
  return isRecord(value) && hasExactKeys(value, ['key', 'request_count', 'response_bytes'], ['host', 'port', 'path', 'scheme']) &&
    typeof value.key === 'string' && value.key.length <= 4355 &&
    isCount(value.request_count) && isCount(value.response_bytes) &&
    (value.host === undefined || typeof value.host === 'string' && value.host.length <= 253) &&
    (value.port === undefined || Number.isInteger(value.port) && (value.port as number) >= 0 && (value.port as number) <= 65535) &&
    (value.path === undefined || typeof value.path === 'string' && value.path.startsWith('/') && value.path.length <= 4096) &&
    (value.scheme === undefined || value.scheme === 'http' || value.scheme === 'https')
}

function parseRank(value: unknown, requested: AnalyticsRankDimension): AnalyticsRankResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'dimension', 'page', 'meta']) ||
    !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isRankItem) ||
    typeof value.dimension !== 'string' || !supportedRankDimensions.has(value.dimension as AnalyticsSupportedRankDimension) ||
    value.dimension !== requested || !isRecord(value.page) ||
    !hasExactKeys(value.page, ['snapshot_at', 'source'], ['next_cursor', 'retained_from']) || !isDateTime(value.page.snapshot_at) ||
    (value.page.source !== 'history' && value.page.source !== 'access_log') ||
    ('retained_from' in value.page && !isDateTime(value.page.retained_from)) ||
    ('next_cursor' in value.page && (typeof value.page.next_cursor !== 'string' || value.page.next_cursor.length > 8192)) ||
    !isMetadata(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsRankResponse
}

async function summary<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  filters: AnalyticsFilters<NoInfer<A>>,
): Promise<AnalyticsSummaryResponse> {
  const raw = await request(`${basePath(audience)}/summary?${queryString(audience, filters)}`, accessToken)
  return parseSummary(raw)
}

async function trend<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  filters: AnalyticsFilters<NoInfer<A>>,
): Promise<AnalyticsTrendResponse> {
  const raw = await request(`${basePath(audience)}/hourly-trend?${queryString(audience, filters)}`, accessToken)
  return parseTrend(raw)
}

async function blockedIPCount<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  filters: AnalyticsFilters<NoInfer<A>>,
): Promise<AnalyticsBlockedIPCountResponse> {
  const raw = await request(`${basePath(audience)}/blocked-ip-count?${queryString(audience, filters)}`, accessToken)
  return parseBlockedIPCount(raw)
}

// FX36: busiest 5-minute window, which the hourly trend average flattens.
async function peakBandwidth<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  filters: AnalyticsFilters<NoInfer<A>>,
): Promise<AnalyticsPeakBandwidthResponse> {
  const raw = await request(`${basePath(audience)}/peak-bandwidth?${queryString(audience, filters)}`, accessToken)
  return parsePeakBandwidth(raw)
}

async function blockedIPTrend<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  filters: AnalyticsFilters<NoInfer<A>>,
): Promise<AnalyticsBlockedIPTrendResponse> {
  const raw = await request(`${basePath(audience)}/blocked-ip-trend?${queryString(audience, filters)}`, accessToken)
  return parseBlockedIPTrend(raw)
}

async function wafOverview<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  filters: AnalyticsFilters<NoInfer<A>>,
): Promise<AnalyticsWAFOverviewResponse> {
  const raw = await request(`${basePath(audience)}/waf-overview?${queryString(audience, filters, { includeDomain: true })}`, accessToken)
  return parseWAFOverview(raw)
}

async function rank<A extends AnalyticsAudience>(
  accessToken: string,
  audience: A,
  dimension: AnalyticsRankDimension,
  filters: AnalyticsFilters<NoInfer<A>>,
  limit: number,
  cursor?: string,
): Promise<AnalyticsRankResponse> {
  const query = queryString(audience, filters, {
    includeDomain: true,
    includeListenPort: true,
    rank: { limit, cursor },
  })
  const raw = await request(`${basePath(audience)}/top/${encodeURIComponent(dimension)}?${query}`, accessToken)
  return parseRank(raw, dimension)
}

export const analyticsApi = { blockedIPCount, blockedIPTrend, peakBandwidth, rank, summary, trend, wafOverview }
