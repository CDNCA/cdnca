import { ApiError, networkApiError, responseApiError } from './auth'

export type QualityDiagnosticsAudience = 'admin' | 'tenant'
export type QualityDiagnosticsCategory = 'upstream_5xx' | 'edge_530' | 'no_host' | 'config_mismatch'
export type QualityDiagnosticsCause = 'upstream_failure' | 'upstream_result_empty' | 'upstream_result_unknown' |
  'edge_status_530' | 'upstream_reported_no_host' | 'host_missing' | 'upstream_reported_config_mismatch'
export type QualityDiagnosticsAction = 'inspect_upstream' | 'inspect_edge_route' | 'configure_host' | 'reconcile_config'

export interface QualityDiagnosticsFilters {
  from: string
  to: string
  tenantId?: string
  siteId?: string
  nodeId?: string
  category?: QualityDiagnosticsCategory
  limit?: number
  cursor?: string
}

export interface QualityDiagnostic {
  event_id: string
  occurred_at: string
  site_id: string
  node_id: string
  category: QualityDiagnosticsCategory
  cause_code: QualityDiagnosticsCause
  action_code: QualityDiagnosticsAction
  status_code: number
  config_version_id: string
  installation_id: string
  request_id: string
  task_id: string | null
  trace_id: string
}

export interface QualityDiagnosticsSnapshot {
  at: string
  source_watermark: number
  finalized_through: string
  expires_at: string
}

export interface QualityDiagnosticsResponse {
  items: QualityDiagnostic[]
  next_cursor: string | null
  snapshot: QualityDiagnosticsSnapshot
  effective_tenant_id?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const utcPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/
const cursorPattern = /^[A-Za-z0-9_-]{1,4096}$/
const categories: QualityDiagnosticsCategory[] = ['upstream_5xx', 'edge_530', 'no_host', 'config_mismatch']
const itemKeys = ['event_id', 'occurred_at', 'site_id', 'node_id', 'category', 'cause_code', 'action_code',
  'status_code', 'config_version_id', 'installation_id', 'request_id', 'task_id', 'trace_id']

function invalidResponse(): ApiError {
  return new ApiError('Quality diagnostics response was invalid', 502, 'invalid_response')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && keys.every((key) => key in value)
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && utcPattern.test(value) && Number.isFinite(Date.parse(value))
}

function isIdentity(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 && value.trim() === value &&
    [...value].every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127)
}

function isDiagnostic(value: unknown, filters: QualityDiagnosticsFilters): value is QualityDiagnostic {
  if (!isRecord(value) || !hasExactKeys(value, itemKeys) || !isIdentity(value.event_id) ||
    !isDateTime(value.occurred_at) || typeof value.site_id !== 'string' || !uuidPattern.test(value.site_id) ||
    typeof value.node_id !== 'string' || !uuidPattern.test(value.node_id) ||
    !categories.includes(value.category as QualityDiagnosticsCategory) ||
    !Number.isInteger(value.status_code) || Number(value.status_code) < 100 || Number(value.status_code) > 599 ||
    typeof value.config_version_id !== 'string' || !uuidPattern.test(value.config_version_id) ||
    typeof value.installation_id !== 'string' || !uuidPattern.test(value.installation_id) ||
    !isIdentity(value.request_id) || value.task_id !== null &&
      (typeof value.task_id !== 'string' || !uuidPattern.test(value.task_id)) || !isIdentity(value.trace_id)) return false

  const category = value.category as QualityDiagnosticsCategory
  const classificationValid = category === 'upstream_5xx' &&
      ['upstream_failure', 'upstream_result_empty', 'upstream_result_unknown'].includes(String(value.cause_code)) &&
      value.action_code === 'inspect_upstream' && Number(value.status_code) >= 500 && Number(value.status_code) <= 599 && value.status_code !== 530 ||
    category === 'edge_530' && value.cause_code === 'edge_status_530' && value.action_code === 'inspect_edge_route' && value.status_code === 530 ||
    category === 'no_host' && ['upstream_reported_no_host', 'host_missing'].includes(String(value.cause_code)) && value.action_code === 'configure_host' ||
    category === 'config_mismatch' && value.cause_code === 'upstream_reported_config_mismatch' && value.action_code === 'reconcile_config'
  if (!classificationValid || filters.siteId && value.site_id !== filters.siteId ||
    filters.nodeId && value.node_id !== filters.nodeId || filters.category && category !== filters.category) return false

  const occurredAt = Date.parse(value.occurred_at)
  return occurredAt >= Date.parse(filters.from) && occurredAt < Date.parse(filters.to)
}

function parseQualityDiagnosticsResponse(
  raw: unknown,
  audience: QualityDiagnosticsAudience,
  filters: QualityDiagnosticsFilters,
): QualityDiagnosticsResponse {
  const responseKeys = audience === 'admin'
    ? ['items', 'next_cursor', 'snapshot', 'effective_tenant_id']
    : ['items', 'next_cursor', 'snapshot']
  if (!isRecord(raw) || !hasExactKeys(raw, responseKeys) || !Array.isArray(raw.items) ||
    raw.items.length > (filters.limit ?? 50) || !raw.items.every((item) => isDiagnostic(item, filters)) ||
    raw.next_cursor !== null && (typeof raw.next_cursor !== 'string' || !cursorPattern.test(raw.next_cursor)) ||
    raw.next_cursor !== null && raw.items.length === 0 || !isRecord(raw.snapshot) ||
    !hasExactKeys(raw.snapshot, ['at', 'source_watermark', 'finalized_through', 'expires_at']) ||
    !isDateTime(raw.snapshot.at) || !Number.isSafeInteger(raw.snapshot.source_watermark) ||
    Number(raw.snapshot.source_watermark) < 1 || !isDateTime(raw.snapshot.finalized_through) ||
    !isDateTime(raw.snapshot.expires_at) || Date.parse(raw.snapshot.finalized_through) < Date.parse(filters.to) ||
    Date.parse(raw.snapshot.finalized_through) > Date.parse(raw.snapshot.at) ||
    Date.parse(raw.snapshot.expires_at) <= Date.parse(raw.snapshot.at) ||
    audience === 'admin' && (typeof raw.effective_tenant_id !== 'string' ||
      !uuidPattern.test(raw.effective_tenant_id) || raw.effective_tenant_id !== filters.tenantId)) throw invalidResponse()

  const items = raw.items as QualityDiagnostic[]
  const seen = new Set<string>()
  for (const [index, item] of items.entries()) {
    if (seen.has(item.event_id) || index > 0 && (Date.parse(items[index - 1].occurred_at) < Date.parse(item.occurred_at) ||
      items[index - 1].occurred_at === item.occurred_at && items[index - 1].event_id <= item.event_id)) throw invalidResponse()
    seen.add(item.event_id)
  }
  return raw as unknown as QualityDiagnosticsResponse
}

function validateFilters(accessToken: string, audience: QualityDiagnosticsAudience, filters: QualityDiagnosticsFilters): void {
  const from = Date.parse(filters.from)
  const to = Date.parse(filters.to)
  if (!accessToken || !isDateTime(filters.from) || !isDateTime(filters.to) || from >= to || to - from > 31 * 24 * 60 * 60 * 1000 ||
    audience === 'admin' && (!filters.tenantId || !uuidPattern.test(filters.tenantId)) ||
    audience === 'tenant' && filters.tenantId !== undefined || filters.siteId !== undefined && !uuidPattern.test(filters.siteId) ||
    filters.nodeId !== undefined && !uuidPattern.test(filters.nodeId) ||
    filters.category !== undefined && !categories.includes(filters.category) || filters.limit !== undefined &&
      (!Number.isInteger(filters.limit) || filters.limit < 1 || filters.limit > 100) ||
    filters.cursor !== undefined && !cursorPattern.test(filters.cursor)) {
    throw new ApiError('Quality diagnostics request was invalid', 400, 'quality_diagnostics_invalid_request')
  }
}

async function readQualityDiagnostics(
  accessToken: string,
  audience: QualityDiagnosticsAudience,
  filters: QualityDiagnosticsFilters,
  signal?: AbortSignal,
): Promise<QualityDiagnosticsResponse> {
  validateFilters(accessToken, audience, filters)
  const query = new URLSearchParams({ from: filters.from, to: filters.to, limit: String(filters.limit ?? 50) })
  if (audience === 'admin') query.set('tenant_id', filters.tenantId!)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (filters.category) query.set('category', filters.category)
  if (filters.cursor) query.set('cursor', filters.cursor)
  const base = audience === 'admin' ? '/v1/admin/analytics' : '/v1/analytics'

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
  return parseQualityDiagnosticsResponse(raw, audience, filters)
}

export const qualityDiagnosticsApi = { read: readQualityDiagnostics }
