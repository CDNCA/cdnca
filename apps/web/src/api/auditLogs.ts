import { ApiError, networkApiError, responseApiError } from './auth'

// Log center (unified-log): GET /v1/audit-logs{,/export,/categories}. The
// server renders every sentence; the browser only shows the fields.

export type AuditLogCategory =
  | 'admin' | 'user' | 'auth' | 'site' | 'security' | 'rule' | 'finance'
  | 'package' | 'plugin' | 'node' | 'dns' | 'cert' | 'system' | 'other'

export const auditLogCategories: readonly AuditLogCategory[] = [
  'admin', 'user', 'auth', 'site', 'security', 'rule', 'finance', 'package', 'plugin', 'node', 'dns', 'cert', 'system', 'other',
]

export interface AuditLogChange { field: string; label: string; before: string; after: string }
export interface AuditLogField { key: string; label: string; value: string }

export interface AuditLogItem {
  id: string
  occurred_at: string
  time: string
  category: AuditLogCategory
  category_label: string
  action: string
  catalogued: boolean
  actor: string
  actor_kind: 'user' | 'system' | 'plugin' | 'node'
  actor_user_id?: string
  actor_ref?: string
  source_ip: string
  scope_id: string
  resource_type: string
  resource_id: string
  resource: string
  /** The object no longer exists in the row's scope (B6b lookup). */
  resource_deleted?: boolean
  /** log-merge: admin columns. tenant_name is absent for the platform scope. */
  tenant_name?: string
  actor_username?: string
  user_agent?: string
  /** 国家-省-市 of source_ip from the control IP library (B6). */
  geo_code?: string
  geo_region?: string
  geo_city?: string
  result: 'success' | 'denied' | 'failure'
  result_label: string
  reason_code?: string
  reason?: string
  request_id: string
  summary: string
  changes: AuditLogChange[]
  fields: AuditLogField[]
}

export interface AuditLogPage { items: AuditLogItem[]; next_cursor?: string }

export interface AuditLogCategoryInfo { category: AuditLogCategory; label: string; default_retention_days: number; actions: number }

export interface AuditLogFilters {
  category?: AuditLogCategory | 'all'
  /** Drop one category (the 操作 tab excludes auth). */
  excludeCategory?: AuditLogCategory
  scopeId?: string
  actor?: string
  actorUserId?: string
  sourceIp?: string
  resourceType?: string
  resourceId?: string
  result?: 'success' | 'denied' | 'failure'
  action?: string
  since?: string
  until?: string
  limit?: number
  cursor?: string
  lang?: 'zh' | 'en'
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const categorySet = new Set<string>(auditLogCategories)

function invalid(): never { throw new ApiError('Invalid audit log request', 400, 'audit_log_invalid_request') }
function invalidResponse(): never { throw new ApiError('Invalid API response', 0, 'invalid_response') }
// eslint-disable-next-line no-control-regex
function plain(value: string, max = 256) { return value.length <= max && !/[\u0000-\u001f\u007f]/.test(value) }

export function auditLogQuery(filters: AuditLogFilters): string {
  const params = new URLSearchParams()
  if (filters.category && filters.category !== 'all') { if (!categorySet.has(filters.category)) invalid(); params.set('category', filters.category) }
  if (filters.excludeCategory) { if (!categorySet.has(filters.excludeCategory)) invalid(); params.set('exclude_category', filters.excludeCategory) }
  if (filters.scopeId) { if (!uuidPattern.test(filters.scopeId)) invalid(); params.set('scope_id', filters.scopeId) }
  if (filters.actorUserId) { if (!uuidPattern.test(filters.actorUserId)) invalid(); params.set('actor_user_id', filters.actorUserId) }
  const texts: Array<[keyof AuditLogFilters, string]> = [['actor', 'actor'], ['sourceIp', 'source_ip'], ['resourceType', 'resource_type'], ['resourceId', 'resource_id'], ['action', 'action']]
  for (const [key, param] of texts) {
    const value = (filters[key] as string | undefined)?.trim()
    if (!value) continue
    if (!plain(value)) invalid()
    params.set(param, value)
  }
  if (filters.result) { if (!['success', 'denied', 'failure'].includes(filters.result)) invalid(); params.set('result', filters.result) }
  for (const [key, param] of [['since', 'since'], ['until', 'until']] as const) {
    const value = filters[key]
    if (!value) continue
    if (!Number.isFinite(Date.parse(value))) invalid()
    params.set(param, value)
  }
  if (filters.since && filters.until && Date.parse(filters.until) < Date.parse(filters.since)) invalid()
  if (filters.limit !== undefined) { if (!Number.isInteger(filters.limit) || filters.limit < 1 || filters.limit > 200) invalid(); params.set('limit', String(filters.limit)) }
  if (filters.cursor) { if (filters.cursor.length > 1024) invalid(); params.set('cursor', filters.cursor) }
  if (filters.lang) params.set('lang', filters.lang)
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

function validItem(value: unknown): value is AuditLogItem {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return typeof item.id === 'string' && typeof item.summary === 'string' && typeof item.time === 'string' &&
    typeof item.category === 'string' && categorySet.has(item.category) && typeof item.action === 'string' &&
    typeof item.actor === 'string' && typeof item.source_ip === 'string' && typeof item.resource === 'string' &&
    ['success', 'denied', 'failure'].includes(item.result as string) && typeof item.request_id === 'string' &&
    Array.isArray(item.changes) && Array.isArray(item.fields) &&
    (item.resource_deleted === undefined || typeof item.resource_deleted === 'boolean') &&
    ['tenant_name', 'actor_username', 'user_agent', 'geo_region', 'geo_city'].every((key) => item[key] === undefined || typeof item[key] === 'string') &&
    (item.geo_code === undefined || typeof item.geo_code === 'string' && /^[A-Z]{2}$/.test(item.geo_code))
}

async function send(token: string, path: string, signal?: AbortSignal): Promise<Response> {
  if (!token || /\s/.test(token)) invalid()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, { signal, credentials: 'include', headers: { Authorization: `Bearer ${token}`, 'X-Request-ID': `audit-log-${crypto.randomUUID()}` } })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  return response
}

async function json(response: Response): Promise<unknown> {
  try { return await response.json() } catch { invalidResponse() }
}

export const auditLogsApi = {
  async list(token: string, filters: AuditLogFilters): Promise<AuditLogPage> {
    const body = await json(await send(token, `/v1/audit-logs${auditLogQuery(filters)}`)) as Record<string, unknown> | null
    if (!body || !Array.isArray(body.items) || !body.items.every(validItem) ||
      (body.next_cursor !== undefined && typeof body.next_cursor !== 'string')) invalidResponse()
    return body as unknown as AuditLogPage
  },
  async categories(token: string, lang?: 'zh' | 'en'): Promise<AuditLogCategoryInfo[]> {
    const body = await json(await send(token, `/v1/audit-logs/categories${lang ? `?lang=${lang}` : ''}`)) as Record<string, unknown> | null
    if (!body || !Array.isArray(body.items) || !body.items.every((item) => item && typeof item === 'object' &&
      categorySet.has((item as AuditLogCategoryInfo).category) && Number.isInteger((item as AuditLogCategoryInfo).default_retention_days))) invalidResponse()
    return body.items as AuditLogCategoryInfo[]
  },
  // export returns the CSV; the server writes the export audit event first.
  async export(token: string, filters: AuditLogFilters, options: { signal?: AbortSignal } = {}): Promise<Blob> {
    const rest = { ...filters, cursor: undefined, limit: undefined }
    const response = await send(token, `/v1/audit-logs/export${auditLogQuery(rest)}`, options.signal)
    if (!(response.headers.get('Content-Type') ?? '').startsWith('text/csv')) invalidResponse()
    return response.blob()
  },
}
