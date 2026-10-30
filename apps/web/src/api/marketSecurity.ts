import type { AnalyticsAudience } from './analytics'
import { ApiError, networkApiError, responseApiError } from './auth'

// Attack log lines a market leaf supplier relayed for this controller's
// market-supplied sites (ADR 0012 §19.1, ML-21): GET
// /v1/analytics/market-security (tenant session) or
// /v1/admin/analytics/market-security?tenant_id= (platform admin).

export interface MarketSecurityLog {
  site_id: string
  supply_id: string
  /** The leaf supplier's short display number. */
  leaf_ref: string
  occurred_at: string
  client_ip: string
  host: string
  path: string
  action: string
  detector: string
  rule_id: string
  cursor: string
}

export interface MarketSecurityPage {
  data: MarketSecurityLog[]
  meta: { next_cursor?: string }
}

export interface MarketSecurityFilters {
  from: string
  to: string
  tenantId?: string
  siteId?: string
  clientIp?: string
  host?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function invalidResponse(): ApiError {
  return new ApiError('Invalid market security response', 502, 'invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function text(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length <= maximum
}

function isLog(value: unknown): value is MarketSecurityLog {
  return record(value) && text(value.site_id, 36) && uuidPattern.test(value.site_id) &&
    text(value.supply_id, 36) && text(value.leaf_ref, 64) && text(value.occurred_at, 64) &&
    Number.isFinite(Date.parse(value.occurred_at)) && text(value.client_ip, 64) && text(value.host, 253) &&
    text(value.path, 4096) && text(value.action, 64) && text(value.detector, 64) && text(value.rule_id, 128) &&
    text(value.cursor, 256) && value.cursor !== ''
}

export function parseMarketSecurityPage(value: unknown): MarketSecurityPage {
  if (!record(value) || !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isLog) ||
    !record(value.meta) || (value.meta.next_cursor !== undefined && !text(value.meta.next_cursor, 256))) {
    throw invalidResponse()
  }
  return value as unknown as MarketSecurityPage
}

export async function listMarketSecurityLogs(
  token: string,
  audience: AnalyticsAudience,
  filters: MarketSecurityFilters,
  limit: number,
  cursor?: string,
): Promise<MarketSecurityPage> {
  if (!token || /\s/.test(token) || (audience === 'admin' && !uuidPattern.test(filters.tenantId ?? '')) ||
    (filters.siteId !== undefined && !uuidPattern.test(filters.siteId))) {
    throw new ApiError('Invalid market security request', 400, 'analytics_logs_invalid_request')
  }
  const params = new URLSearchParams({ from: filters.from, to: filters.to, limit: String(limit) })
  if (audience === 'admin') params.set('tenant_id', filters.tenantId!)
  if (filters.siteId) params.set('site_id', filters.siteId)
  if (filters.clientIp) params.set('client_ip', filters.clientIp)
  if (filters.host) params.set('host', filters.host)
  if (cursor) params.set('cursor', cursor)
  const path = audience === 'admin' ? '/v1/admin/analytics/market-security' : '/v1/analytics/market-security'
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}?${params}`, {
      credentials: 'include', cache: 'no-store', headers: { Authorization: `Bearer ${token}` },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw invalidResponse() }
  return parseMarketSecurityPage(body)
}
