import { ApiError, networkApiError, responseApiError } from './auth'

export type SiteDiagnosticAudience = 'admin' | 'tenant'
export type SiteDiagnosticCategory = 'upstream_5xx' | 'config_mismatch' | 'no_host' | 'unknown'
export type SiteDiagnosticReason =
  | 'upstream_reported_no_host'
  | 'host_missing'
  | 'upstream_reported_config_mismatch'
  | 'status_530'
  | 'status_5xx_with_upstream_result'
  | 'status_5xx_unclassified'

export interface SiteDiagnosticsFilters {
  from: string
  to: string
  tenantId?: string
  siteId?: string
  nodeId?: string
  limit?: number
  cursor?: string
}

export interface SiteDiagnosticItem {
  event_id: string
  occurred_at: string
  site_id: string
  node_id: string
  request_id: string
  trace_id: string
  config_version_id: string
  host: string
  uri_path: string
  status_code: number
  category: SiteDiagnosticCategory
  reason_code: SiteDiagnosticReason
}

export interface SiteDiagnosticsResponse {
  data: {
    items: SiteDiagnosticItem[]
    next_cursor: string | null
    snapshot_at: string | null
  }
  meta: { from: string; to: string; timezone: 'UTC' }
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const eventPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const cursorPattern = /^[A-Za-z0-9_-]{1,2048}$/

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

function dateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function identity(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 && value.trim() === value &&
    [...value].every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127)
}

function reasonMatches(category: SiteDiagnosticCategory, reason: unknown): reason is SiteDiagnosticReason {
  if (category === 'no_host') return reason === 'upstream_reported_no_host' || reason === 'host_missing'
  if (category === 'config_mismatch') return reason === 'upstream_reported_config_mismatch' || reason === 'status_530'
  if (category === 'upstream_5xx') return reason === 'status_5xx_with_upstream_result'
  return reason === 'status_5xx_unclassified'
}

function item(value: unknown, filters: SiteDiagnosticsFilters): value is SiteDiagnosticItem {
  if (!record(value) || !exact(value, ['event_id', 'occurred_at', 'site_id', 'node_id', 'request_id', 'trace_id',
    'config_version_id', 'host', 'uri_path', 'status_code', 'category', 'reason_code']) ||
    typeof value.event_id !== 'string' || !eventPattern.test(value.event_id) || !dateTime(value.occurred_at) ||
    typeof value.site_id !== 'string' || !uuidPattern.test(value.site_id) || typeof value.node_id !== 'string' || !uuidPattern.test(value.node_id) ||
    !identity(value.request_id) || !identity(value.trace_id) || !identity(value.config_version_id) ||
    typeof value.host !== 'string' || value.host.length > 253 || value.host.trim() !== value.host ||
    typeof value.uri_path !== 'string' || value.uri_path.length > 4096 || value.uri_path !== '' && !value.uri_path.startsWith('/') ||
    !Number.isInteger(value.status_code) || Number(value.status_code) < 100 || Number(value.status_code) > 599 ||
    !['upstream_5xx', 'config_mismatch', 'no_host', 'unknown'].includes(String(value.category)) ||
    !reasonMatches(value.category as SiteDiagnosticCategory, value.reason_code)) return false
  if (value.category !== 'no_host' && value.host === '') return false
  if (value.category === 'upstream_5xx' && (Number(value.status_code) < 500 || Number(value.status_code) > 599)) return false
  if (value.category === 'config_mismatch' && value.reason_code === 'status_530' && value.status_code !== 530) return false
  if (filters.siteId && value.site_id !== filters.siteId || filters.nodeId && value.node_id !== filters.nodeId) return false
  const occurred = Date.parse(value.occurred_at)
  return occurred >= Date.parse(filters.from) && occurred < Date.parse(filters.to)
}

function parseResponse(value: unknown, filters: SiteDiagnosticsFilters): SiteDiagnosticsResponse {
  if (!record(value) || !exact(value, ['data', 'meta']) || !record(value.data) || !record(value.meta) ||
    !exact(value.data, ['items', 'next_cursor', 'snapshot_at']) || !exact(value.meta, ['from', 'to', 'timezone']) ||
    !dateTime(value.meta.from) || !dateTime(value.meta.to) || Date.parse(value.meta.from) !== Date.parse(filters.from) ||
    Date.parse(value.meta.to) !== Date.parse(filters.to) || value.meta.timezone !== 'UTC' ||
    !Array.isArray(value.data.items) || value.data.items.length > (filters.limit ?? 20) ||
    !value.data.items.every((entry) => item(entry, filters)) ||
    value.data.next_cursor !== null && (typeof value.data.next_cursor !== 'string' || !cursorPattern.test(value.data.next_cursor)) ||
    value.data.snapshot_at !== null && !dateTime(value.data.snapshot_at) || value.data.next_cursor !== null && value.data.snapshot_at === null) {
    throw invalidResponse()
  }
  const items = value.data.items as SiteDiagnosticItem[]
  const seen = new Set<string>()
  for (const [index, entry] of items.entries()) {
    if (seen.has(entry.event_id) || index > 0 && (Date.parse(items[index - 1].occurred_at) < Date.parse(entry.occurred_at) ||
      items[index - 1].occurred_at === entry.occurred_at && items[index - 1].event_id <= entry.event_id)) throw invalidResponse()
    seen.add(entry.event_id)
  }
  return value as unknown as SiteDiagnosticsResponse
}

function queryString(audience: SiteDiagnosticAudience, filters: SiteDiagnosticsFilters): string {
  if (audience === 'admin' && !filters.tenantId) throw new ApiError('Tenant is required', 400, 'analytics_diagnostic_invalid_request')
  const query = new URLSearchParams({ from: filters.from, to: filters.to, limit: String(filters.limit ?? 20) })
  if (audience === 'admin') query.set('tenant_id', filters.tenantId!)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (filters.cursor) query.set('cursor', filters.cursor)
  return query.toString()
}

async function read(accessToken: string, audience: SiteDiagnosticAudience, filters: SiteDiagnosticsFilters, signal?: AbortSignal): Promise<SiteDiagnosticsResponse> {
  const base = audience === 'admin' ? '/v1/admin/analytics' : '/v1/analytics'
  const query = queryString(audience, filters)
  let response: Response
  try {
    response = await fetch(`${apiRoot}${base}/site-quality-diagnostics?${query}`, {
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

export const siteDiagnosticsApi = { read }
