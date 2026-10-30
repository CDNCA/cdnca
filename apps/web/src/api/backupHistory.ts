import { ApiError, networkApiError, responseApiError } from './auth'

export type BackupHistoryState = 'succeeded' | 'failed' | 'unknown'

export interface BackupHistoryRecord {
  backup_id: string
  started_at?: string
  completed_at?: string
  state: BackupHistoryState
  result_code: string
  manifest_sha256?: string
  recovery_point_at?: string
  observed_rpo_seconds?: number
  outcome_unknown: boolean
  signature_valid: boolean
  terminal_state: string
  reason_code: string
}

export interface BackupHistoryPage {
  schema: 'cdnca.control-backup-history/v1'
  items: BackupHistoryRecord[]
  total_count: number
  next_cursor?: string
  snapshot_at: string
  // No backup runner is bound to this control plane: no target, no history.
  unconfigured?: boolean
}

export interface BackupHistoryFilters {
  backupId?: string
  state?: BackupHistoryState
  from?: string
  to?: string
  limit?: 10 | 30 | 100 | 300
  cursor?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const instantPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/
const states = new Set<BackupHistoryState>(['succeeded', 'failed', 'unknown'])
const limits = new Set([10, 30, 100, 300])

function invalid(): never { throw new ApiError('Invalid backup history request', 400, 'backup_history_invalid_request') }
function validInstant(value: string): boolean { return instantPattern.test(value) && Number.isFinite(Date.parse(value)) }

function buildQuery(filters: BackupHistoryFilters): string {
  const params = new URLSearchParams()
  if (filters.backupId !== undefined) { if (!idPattern.test(filters.backupId)) invalid(); params.set('backup_id', filters.backupId) }
  if (filters.state !== undefined) { if (!states.has(filters.state)) invalid(); params.set('state', filters.state) }
  if (filters.from !== undefined) { if (!validInstant(filters.from)) invalid(); params.set('from', filters.from) }
  if (filters.to !== undefined) { if (!validInstant(filters.to)) invalid(); params.set('to', filters.to) }
  if (filters.from && filters.to && Date.parse(filters.from) > Date.parse(filters.to)) invalid()
  if (filters.limit !== undefined) { if (!limits.has(filters.limit)) invalid(); params.set('limit', String(filters.limit)) }
  if (filters.cursor !== undefined) { if (!filters.cursor || filters.cursor.length > 4096) invalid(); params.set('cursor', filters.cursor) }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

function validRecord(value: unknown): value is BackupHistoryRecord {
  if (!value || typeof value !== 'object') return false
  const record = value as Record<string, unknown>
  return typeof record.backup_id === 'string' && idPattern.test(record.backup_id) &&
    (record.started_at === undefined || validInstant(record.started_at as string)) &&
    (record.completed_at === undefined || validInstant(record.completed_at as string)) &&
    states.has(record.state as BackupHistoryState) && typeof record.result_code === 'string' && idPattern.test(record.result_code) &&
    (record.manifest_sha256 === undefined || /^[0-9a-f]{64}$/.test(record.manifest_sha256 as string)) &&
    (record.recovery_point_at === undefined || validInstant(record.recovery_point_at as string)) &&
    (record.observed_rpo_seconds === undefined || Number.isSafeInteger(record.observed_rpo_seconds) && (record.observed_rpo_seconds as number) >= 0) &&
    typeof record.outcome_unknown === 'boolean' && typeof record.signature_valid === 'boolean' &&
    typeof record.terminal_state === 'string' && idPattern.test(record.terminal_state) && typeof record.reason_code === 'string' && idPattern.test(record.reason_code)
}

function validPage(value: unknown): value is BackupHistoryPage {
  if (!value || typeof value !== 'object') return false
  const page = value as Record<string, unknown>
  return page.schema === 'cdnca.control-backup-history/v1' && Array.isArray(page.items) && page.items.length <= 300 && page.items.every(validRecord) &&
    Number.isSafeInteger(page.total_count) && (page.total_count as number) >= 0 && typeof page.snapshot_at === 'string' && validInstant(page.snapshot_at) &&
    (page.next_cursor === undefined || typeof page.next_cursor === 'string' && page.next_cursor.length > 0 && page.next_cursor.length <= 4096) &&
    (page.unconfigured === undefined || typeof page.unconfigured === 'boolean')
}

async function request(token: string, filters: BackupHistoryFilters): Promise<Response> {
  if (!token || /\s/.test(token)) invalid()
  const query = buildQuery(filters)
  try {
    return await fetch(`${apiRoot}/v1/admin/system-backup-runs${query}`, { credentials: 'include', headers: { Authorization: `Bearer ${token}` } })
  } catch { throw networkApiError() }
}

export const backupHistoryApi = {
  async list(token: string, filters: BackupHistoryFilters): Promise<BackupHistoryPage> {
    const response = await request(token, filters)
    if (!response.ok) throw await responseApiError(response)
    const value = await response.json().catch(() => null)
    if (!validPage(value)) throw new ApiError('Invalid backup history response', 502, 'invalid_response')
    return value
  },
}
