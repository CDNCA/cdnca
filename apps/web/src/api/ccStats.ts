import { ApiError, networkApiError } from './auth'

// CC rule statistics of a site: GET /v1/security/cc-stats
// (tenant session) or /v1/admin/security/cc-stats (platform admin, with the
// site's tenant scope). Nodes report every 10 seconds.

export type CCStatsRange = '1h' | '6h' | '24h'

export interface CCCounts {
  matched: number
  triggered: number
  challenged: number
  blocked: number
  passed: number
  ja4_unavailable: number
}

export interface CCStatPoint extends CCCounts {
  at: string
}

export interface CCRuleTotal extends CCCounts {
  rule_id: string | null
  policy_id: string
}

export interface CCTopValue {
  value: string
  count: number
}

export interface CCSiteStats {
  tenant_scope_id: string
  range: CCStatsRange
  site_id: string
  from: string
  to: string
  step_seconds: number
  series: CCStatPoint[]
  rules: CCRuleTotal[]
  top_clients: CCTopValue[]
  top_paths: CCTopValue[]
}

export const ccStatsRanges: readonly CCStatsRange[] = ['1h', '6h', '24h']

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const codePattern = /^[a-z][a-z0-9_]{0,63}$/
const countFields = ['matched', 'triggered', 'challenged', 'blocked', 'passed', 'ja4_unavailable'] as const

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid CC statistics response', 502, 'invalid_response')
}

function counts(value: unknown): boolean {
  return record(value) && countFields.every((field) => Number.isSafeInteger(value[field]) && Number(value[field]) >= 0)
}

function time(value: unknown): boolean {
  return typeof value === 'string' && Number.isFinite(Date.parse(value))
}

function tops(value: unknown): boolean {
  return Array.isArray(value) && value.length <= 20 &&
    value.every((item) => record(item) && typeof item.value === 'string' && Number.isSafeInteger(item.count))
}

export function parseCCSiteStats(value: unknown, siteID: string): CCSiteStats {
  if (!record(value) || value.site_id !== siteID || typeof value.tenant_scope_id !== 'string' || !uuidPattern.test(value.tenant_scope_id) ||
    !ccStatsRanges.includes(value.range as CCStatsRange) || !time(value.from) || !time(value.to) ||
    ![60, 300, 900].includes(value.step_seconds as number) ||
    !Array.isArray(value.series) || !value.series.every((point) => counts(point) && time((point as Record<string, unknown>).at)) ||
    !Array.isArray(value.rules) || !value.rules.every((rule) => counts(rule) && record(rule) &&
      (rule.rule_id === null || (typeof rule.rule_id === 'string' && uuidPattern.test(rule.rule_id))) && typeof rule.policy_id === 'string') ||
    !tops(value.top_clients) || !tops(value.top_paths)) throw invalidResponse()
  return value as unknown as CCSiteStats
}

export async function getCCSiteStats(
  token: string,
  query: { siteID: string; range: CCStatsRange; tenantScopeID?: string },
): Promise<CCSiteStats> {
  if (!token || /\s/.test(token) || !uuidPattern.test(query.siteID) ||
    (query.tenantScopeID !== undefined && !uuidPattern.test(query.tenantScopeID))) {
    throw new ApiError('Invalid CC statistics request', 400, 'invalid_request')
  }
  const params = new URLSearchParams({ site_id: query.siteID, range: query.range })
  let path = '/v1/security/cc-stats'
  if (query.tenantScopeID) {
    params.set('tenant_scope_id', query.tenantScopeID)
    path = '/v1/admin/security/cc-stats'
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
    throw new ApiError('API request failed', response.status, error.code,
      typeof error.request_id === 'string' ? error.request_id : undefined)
  }
  return parseCCSiteStats(body, query.siteID)
}
