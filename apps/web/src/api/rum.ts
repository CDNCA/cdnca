import { ApiError, networkApiError } from './auth'

// 真实用户体验: GET /v1/analytics/rum (tenant session) or
// /v1/admin/analytics/rum (platform admin, with the site's tenant scope).

export type RUMRange = '1h' | '24h' | '7d' | '30d'
export type RUMMetric = 'lcp' | 'inp' | 'cls' | 'fcp' | 'ttfb'
export type RUMP75 = Partial<Record<RUMMetric, number>>

export interface RUMMetricSummary {
  p75: number
  samples: number
  good: number
  needs_improvement: number
  poor: number
}

export interface RUMPoint { at: string; views: number; p75: RUMP75 }
export interface RUMBreakdown { value: string; views: number; p75: RUMP75 }
export interface RUMErrorTotal { kind: 'resource' | 'navigation' | 'fetch' | 'xhr'; element: string; target: string; status: number; count: number }

export interface RUMReport {
  tenant_scope_id: string
  range: RUMRange
  rum_sample_percent: number | null
  site_id: string
  from: string
  to: string
  step_seconds: number
  views: number
  dropped: number
  thresholds: Record<RUMMetric, [number, number]>
  summary: Partial<Record<RUMMetric, RUMMetricSummary>>
  series: RUMPoint[]
  pages: RUMBreakdown[]
  countries: RUMBreakdown[]
  devices: RUMBreakdown[]
  errors: RUMErrorTotal[]
}

export const rumMetrics: readonly RUMMetric[] = ['lcp', 'inp', 'cls', 'fcp', 'ttfb']
export const rumRanges: readonly RUMRange[] = ['1h', '24h', '7d', '30d']

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const codePattern = /^[a-z][a-z0-9_]{0,63}$/

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function count(value: unknown): boolean {
  return Number.isSafeInteger(value) && Number(value) >= 0
}

function p75(value: unknown): boolean {
  return record(value) && Object.entries(value).every(([key, item]) =>
    rumMetrics.includes(key as RUMMetric) && typeof item === 'number' && Number.isFinite(item) && item >= 0)
}

function breakdowns(value: unknown): boolean {
  return Array.isArray(value) && value.length <= 50 &&
    value.every((item) => record(item) && typeof item.value === 'string' && count(item.views) && p75(item.p75))
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid RUM report response', 502, 'invalid_response')
}

export function parseRUMReport(value: unknown, siteID: string): RUMReport {
  if (!record(value) || value.site_id !== siteID || typeof value.tenant_scope_id !== 'string' || !uuidPattern.test(value.tenant_scope_id) ||
    !rumRanges.includes(value.range as RUMRange) || !count(value.views) || !count(value.dropped) || !count(value.step_seconds) ||
    !(value.rum_sample_percent === null || count(value.rum_sample_percent)) || !record(value.thresholds) || !record(value.summary) ||
    !Array.isArray(value.series) || !value.series.every((point) => record(point) && typeof point.at === 'string' && count(point.views) && p75(point.p75)) ||
    !breakdowns(value.pages) || !breakdowns(value.countries) || !breakdowns(value.devices) ||
    !Array.isArray(value.errors) || !value.errors.every((item) => record(item) && typeof item.target === 'string' && count(item.count) && count(item.status))) {
    throw invalidResponse()
  }
  return value as unknown as RUMReport
}

export async function getRUMReport(token: string, query: { siteID: string; range: RUMRange; tenantScopeID?: string }): Promise<RUMReport> {
  if (!token || /\s/.test(token) || !uuidPattern.test(query.siteID) ||
    (query.tenantScopeID !== undefined && !uuidPattern.test(query.tenantScopeID))) {
    throw new ApiError('Invalid RUM report request', 400, 'invalid_request')
  }
  const params = new URLSearchParams({ site_id: query.siteID, range: query.range })
  let path = '/v1/analytics/rum'
  if (query.tenantScopeID) {
    params.set('tenant_scope_id', query.tenantScopeID)
    path = '/v1/admin/analytics/rum'
  }
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}?${params}`, {
      credentials: 'include', cache: 'no-store', headers: { Authorization: `Bearer ${token}` },
    })
  } catch { throw networkApiError() }
  let body: unknown
  try { body = await response.json() } catch { throw invalidResponse() }
  if (!response.ok) {
    const error = record(body) && record(body.error) ? body.error : undefined
    if (!error || typeof error.code !== 'string' || !codePattern.test(error.code)) throw invalidResponse()
    throw new ApiError('API request failed', response.status, error.code, typeof error.request_id === 'string' ? error.request_id : undefined)
  }
  return parseRUMReport(body, query.siteID)
}
