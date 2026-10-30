import { ApiError, networkApiError, responseApiError } from './auth'

export type ObservabilityLogKind = 'login' | 'operation' | 'notification' | 'frontend'

export interface ObservabilityLogFact {
  event_id: string
  scope_id?: string
  occurred_at: string
  kind: ObservabilityLogKind
  actor_user_id?: string
  actor_user_display_id?: string
  subject_user_id?: string
  action: string
  reason_code: string
  result_code: string
  resource_type?: string
  resource_id?: string
  /** Current object name looked up at query time (site domain, node name, ...). */
  resource_name?: string
  /** The object no longer exists in this scope. */
  resource_deleted?: boolean
  user_agent?: string
  change_summary?: string
  request_id?: string
  source_ip: string
  geo_code: string
  geo_region?: string
  geo_city?: string
  geo_resolution?: 'matched' | 'unknown'
  /** Audit catalog category (audit rows only). */
  category?: ObservabilityLogCategory
}

export const observabilityLogCategories = ['admin', 'user', 'auth', 'site', 'security', 'rule', 'finance', 'package', 'plugin', 'node', 'dns', 'cert', 'system', 'other'] as const
export type ObservabilityLogCategory = typeof observabilityLogCategories[number]

export interface ObservabilityLogPage {
  items: ObservabilityLogFact[]
  next_cursor?: string
  snapshot_at: string
  total_count?: number
}

export interface ObservabilityLogFilters {
  targetScopeId?: string
  kinds?: ObservabilityLogKind[]
  results?: string[]
  action?: string
  actionVerb?: 'create' | 'update' | 'delete'
  category?: ObservabilityLogCategory
  actorUserId?: string
  resourceType?: string
  resourceId?: string
  change?: string
  sourceIp?: string
  from?: string
  to?: string
  limit?: number
  cursor?: string
}

export interface FrontendEventInput {
  event_code: 'route_error' | 'api_error' | 'render_error'
  route: string
  reason_code: string
  result_code: 'success' | 'denied' | 'failure'
  release: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const codePattern = /^[a-z][a-z0-9._-]{0,95}$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const maxExportBytes = 8 << 20
const kinds = new Set<ObservabilityLogKind>(['login', 'operation', 'notification', 'frontend'])
const factKeys = new Set(['event_id', 'scope_id', 'occurred_at', 'kind', 'actor_user_id', 'actor_user_display_id', 'subject_user_id', 'action', 'reason_code', 'result_code', 'resource_type', 'resource_id', 'resource_name', 'resource_deleted', 'user_agent', 'change_summary', 'request_id', 'source_ip', 'geo_code', 'geo_region', 'geo_city', 'geo_resolution', 'category'])
const categories = new Set<string>(observabilityLogCategories)

function invalid(): never { throw new ApiError('Invalid observability log request', 400, 'observability_logs_invalid_request') }
function validInstant(value: string): boolean { return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) }
function validFact(value: unknown): value is ObservabilityLogFact {
  if (!value || typeof value !== 'object') return false
  const fact = value as Record<string, unknown>
  return Object.keys(fact).every((key) => factKeys.has(key)) &&
    typeof fact.event_id === 'string' && fact.event_id.length > 0 && fact.event_id.length <= 128 &&
    typeof fact.occurred_at === 'string' && validInstant(fact.occurred_at) && kinds.has(fact.kind as ObservabilityLogKind) &&
    typeof fact.action === 'string' && codePattern.test(fact.action) && typeof fact.reason_code === 'string' && codePattern.test(fact.reason_code) &&
    typeof fact.result_code === 'string' && codePattern.test(fact.result_code) && typeof fact.source_ip === 'string' && fact.source_ip.length > 0 && fact.source_ip.length <= 64 &&
    typeof fact.geo_code === 'string' && (fact.geo_code === 'unknown' || /^[A-Z]{2}$/.test(fact.geo_code)) &&
    // eslint-disable-next-line no-control-regex
    (fact.geo_region === undefined || typeof fact.geo_region === 'string' && fact.geo_region.length <= 128 && fact.geo_region === fact.geo_region.trim() && !/[\u0000-\u001f\u007f]/.test(fact.geo_region)) &&
    // eslint-disable-next-line no-control-regex
    (fact.geo_city === undefined || typeof fact.geo_city === 'string' && fact.geo_city.length <= 128 && fact.geo_city === fact.geo_city.trim() && !/[\u0000-\u001f\u007f]/.test(fact.geo_city)) &&
    (fact.geo_resolution === undefined || fact.geo_resolution === 'matched' || fact.geo_resolution === 'unknown') &&
    (fact.category === undefined || typeof fact.category === 'string' && categories.has(fact.category)) &&
    (fact.scope_id === undefined || typeof fact.scope_id === 'string' && uuidPattern.test(fact.scope_id)) &&
    (fact.actor_user_id === undefined || typeof fact.actor_user_id === 'string' && uuidPattern.test(fact.actor_user_id)) &&
    (fact.actor_user_display_id === undefined || typeof fact.actor_user_display_id === 'string' && /^[1-9][0-9]{0,18}$/.test(fact.actor_user_display_id)) &&
    (fact.subject_user_id === undefined || typeof fact.subject_user_id === 'string' && uuidPattern.test(fact.subject_user_id)) &&
    (fact.resource_type === undefined || typeof fact.resource_type === 'string' && codePattern.test(fact.resource_type)) &&
    // eslint-disable-next-line no-control-regex
    (fact.resource_id === undefined || typeof fact.resource_id === 'string' && fact.resource_id.length <= 256 && !/[\u0000-\u001f\u007f]/.test(fact.resource_id)) &&
    // eslint-disable-next-line no-control-regex
    (fact.resource_name === undefined || typeof fact.resource_name === 'string' && fact.resource_name.length > 0 && fact.resource_name.length <= 256 && !/[\u0000-\u001f\u007f]/.test(fact.resource_name)) &&
    (fact.resource_deleted === undefined || fact.resource_deleted === true) &&
    // eslint-disable-next-line no-control-regex
    (fact.user_agent === undefined || typeof fact.user_agent === 'string' && fact.user_agent.length <= 512 && !/[\u0000-\u001f\u007f]/.test(fact.user_agent)) &&
    // eslint-disable-next-line no-control-regex
    (fact.change_summary === undefined || typeof fact.change_summary === 'string' && fact.change_summary.length <= 2048 && !/[\u0000-\u001f\u007f]/.test(fact.change_summary)) &&
    (fact.request_id === undefined || typeof fact.request_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(fact.request_id))
}

function query(filters: ObservabilityLogFilters): string {
  const params = new URLSearchParams()
  if (filters.targetScopeId) { if (!uuidPattern.test(filters.targetScopeId)) invalid(); params.set('target_scope_id', filters.targetScopeId) }
  const selectedKinds = filters.kinds ?? []
  if (new Set(selectedKinds).size !== selectedKinds.length || selectedKinds.some((kind) => !kinds.has(kind))) invalid()
  selectedKinds.forEach((kind) => params.append('kind', kind))
  ;(filters.results ?? []).forEach((result) => { if (!codePattern.test(result)) invalid(); params.append('result', result) })
  if (filters.action) { if (!codePattern.test(filters.action)) invalid(); params.set('action', filters.action) }
  if (filters.actionVerb) { if (!['create', 'update', 'delete'].includes(filters.actionVerb)) invalid(); params.set('action_verb', filters.actionVerb) }
  if (filters.category) { if (!categories.has(filters.category)) invalid(); params.set('category', filters.category) }
  if (filters.actorUserId) {
    if (uuidPattern.test(filters.actorUserId)) params.set('actor_user_id', filters.actorUserId)
    else if (/^[1-9][0-9]{0,18}$/.test(filters.actorUserId)) params.set('actor_user_display_id', filters.actorUserId)
    else invalid()
  }
  if (filters.resourceType) { if (!codePattern.test(filters.resourceType)) invalid(); params.set('resource_type', filters.resourceType) }
  // eslint-disable-next-line no-control-regex
  if (filters.resourceId) { if (filters.resourceId.length > 256 || /[\u0000-\u001f\u007f]/.test(filters.resourceId)) invalid(); params.set('resource_id', filters.resourceId) }
  // eslint-disable-next-line no-control-regex
  if (filters.change) { if (filters.change.length > 256 || /[\u0000-\u001f\u007f]/.test(filters.change)) invalid(); params.set('change', filters.change) }
  if (filters.sourceIp) { if (filters.sourceIp.length > 64) invalid(); params.set('source_ip', filters.sourceIp) }
  if (filters.from) { if (!validInstant(filters.from)) invalid(); params.set('from', filters.from) }
  if (filters.to) { if (!validInstant(filters.to)) invalid(); params.set('to', filters.to) }
  if (filters.from && filters.to && filters.from > filters.to) invalid()
  if (filters.limit !== undefined) { if (!Number.isInteger(filters.limit) || filters.limit < 1 || filters.limit > 300) invalid(); params.set('limit', String(filters.limit)) }
  if (filters.cursor !== undefined) { if (!filters.cursor || filters.cursor.length > 4096) invalid(); params.set('cursor', filters.cursor) }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

async function fetchResponse(path: string, token: string, init: RequestInit = {}): Promise<Response> {
  if (!token || /\s/.test(token)) invalid()
  try {
    return await fetch(`${apiRoot}${path}`, { ...init, credentials: 'include', headers: { Authorization: `Bearer ${token}`, ...init.headers } })
  } catch { throw networkApiError() }
}

function invalidExport(): never { throw new ApiError('Invalid export response', 502, 'invalid_response') }

async function readExport(response: Response): Promise<Uint8Array> {
  const declaredLength = response.headers.get('Content-Length')
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maxExportBytes)) invalidExport()
  if (!response.body) return new Uint8Array()

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > maxExportBytes) {
        await reader.cancel()
        invalidExport()
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  const bytes = new Uint8Array(length)
  let offset = 0
  chunks.forEach((chunk) => { bytes.set(chunk, offset); offset += chunk.byteLength })
  return bytes
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) invalidExport()
  const input = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(input).set(bytes)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input)
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

export const observabilityLogsApi = {
  async list(token: string, filters: ObservabilityLogFilters): Promise<ObservabilityLogPage> {
    const response = await fetchResponse(`/v1/observability/logs${query(filters)}`, token)
    if (!response.ok) throw await responseApiError(response)
    const value = await response.json().catch(() => null) as Record<string, unknown> | null
    if (!value || !Array.isArray(value.items) || value.items.length > 300 || !value.items.every(validFact) ||
      typeof value.snapshot_at !== 'string' || !validInstant(value.snapshot_at) ||
      (value.total_count !== undefined && (typeof value.total_count !== 'number' || !Number.isSafeInteger(value.total_count) || value.total_count < 0)) ||
      (value.next_cursor !== undefined && (typeof value.next_cursor !== 'string' || !value.next_cursor || value.next_cursor.length > 4096))) {
      throw new ApiError('Invalid observability log response', 502, 'invalid_response')
    }
    return value as unknown as ObservabilityLogPage
  },
  async exportCSV(token: string, filters: ObservabilityLogFilters, options: { signal?: AbortSignal } = {}): Promise<{ content: string; sha256: string }> {
    const response = await fetchResponse(`/v1/observability/logs/export${query(filters)}`, token, { signal: options.signal })
    if (!response.ok) throw await responseApiError(response)
    const sha256 = response.headers.get('X-Content-SHA256') ?? ''
    if (!response.headers.get('Content-Type')?.startsWith('text/csv') || !/^[0-9a-f]{64}$/.test(sha256)) invalidExport()
    const bytes = await readExport(response)
    if (await sha256Hex(bytes) !== sha256) invalidExport()
    let content: string
    try { content = new TextDecoder('utf-8', { fatal:true }).decode(bytes) } catch { invalidExport() }
    return { content, sha256 }
  },
  async recordFrontend(token: string, input: FrontendEventInput, targetScopeId?: string): Promise<void> {
    if (targetScopeId !== undefined && (!uuidPattern.test(targetScopeId) || targetScopeId === '00000000-0000-0000-0000-000000000000')) invalid()
    const target = targetScopeId === undefined ? '' : `?target_scope_id=${encodeURIComponent(targetScopeId)}`
    const response = await fetchResponse(`/v1/observability/frontend-events${target}`, token, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) })
    if (!response.ok) throw await responseApiError(response)
    if (response.status !== 202) throw new ApiError('Invalid frontend event response', 502, 'invalid_response')
  },
}
