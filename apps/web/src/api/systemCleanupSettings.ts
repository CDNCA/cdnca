import { ApiError, networkApiError, responseApiError } from './auth'
import { auditLogCategories, type AuditLogCategory } from './auditLogs'

export interface PlatformSystemCleanupSettings {
  cleanup_cache_days: number
  // Operation-log retention per event category (unified-log); 0 keeps forever.
  audit_retention_days: Record<AuditLogCategory, number>
  access_logs_days: number
  node_metrics_days: number
  bandwidth_history_days: number
  blacklist_history_days: number
  node_traffic_history_days: number
}

export interface PlatformSystemCleanupDocument {
  schema: 'cdnca.platform-system-cleanup-settings/v1'
  revision: number
  updated_at?: string
  value: PlatformSystemCleanupSettings
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const keys = ['cleanup_cache_days', 'audit_retention_days', 'access_logs_days', 'node_metrics_days', 'bandwidth_history_days', 'blacklist_history_days', 'node_traffic_history_days'] as const
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function exact(value: Record<string, unknown>, expected: readonly string[]) { const actual = Object.keys(value); return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key)) }
function settings(value: unknown): value is PlatformSystemCleanupSettings {
  if (!record(value) || !exact(value, keys)) return false
  const dayKeys = ['cleanup_cache_days', 'access_logs_days', 'node_metrics_days', 'bandwidth_history_days', 'blacklist_history_days', 'node_traffic_history_days'] as const
  return auditRetention(value.audit_retention_days) && dayKeys.every((key) => Number.isSafeInteger(value[key]) && (value[key] as number) >= 0 && (value[key] as number) <= 3650)
}
function validDays(value: unknown) { return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 3650 }
function auditRetention(value: unknown): value is Record<AuditLogCategory, number> {
  return record(value) && exact(value, auditLogCategories) && auditLogCategories.every((category) => validDays(value[category]))
}
function document(value: unknown): value is PlatformSystemCleanupDocument {
  if (!record(value) || Object.keys(value).some((key) => !['schema', 'revision', 'updated_at', 'value'].includes(key)) ||
    value.schema !== 'cdnca.platform-system-cleanup-settings/v1' || !Number.isSafeInteger(value.revision) || (value.revision as number) < 0 || !settings(value.value)) return false
  return !Object.hasOwn(value, 'updated_at') || (typeof value.updated_at === 'string' && Number.isFinite(Date.parse(value.updated_at)))
}

async function request(accessToken: string, method: 'GET' | 'PUT', value?: PlatformSystemCleanupSettings, revision?: number, requestId?: string, idempotencyKey?: string) {
  const requestID = requestId ?? `system-cleanup-settings-${crypto.randomUUID()}`
  const writeIdempotencyKey = idempotencyKey ?? requestID
  let response: Response
  try { response = await fetch(`${apiRoot}/v1/admin/system-cleanup-settings`, { method, credentials: 'include', headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': requestID, ...(method === 'PUT' ? { 'Content-Type': 'application/json', 'If-Match': `"${revision}"`, 'Idempotency-Key': writeIdempotencyKey } : {}) }, ...(method === 'PUT' ? { body: JSON.stringify({ value }) } : {}) }) } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown; try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
  if (!document(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return body
}

export const systemCleanupSettingsApi = {
  get(accessToken: string) { return request(accessToken, 'GET') },
  put(accessToken: string, revision: number, value: PlatformSystemCleanupSettings, requestId?: string, idempotencyKey?: string) { return request(accessToken, 'PUT', value, revision, requestId, idempotencyKey) },
}
