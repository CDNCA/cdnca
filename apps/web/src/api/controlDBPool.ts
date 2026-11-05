import { ApiError, networkApiError, responseApiError } from './auth'

// GET /v1/admin/system-db-pool, the database pool of the
// control-api process that answers (services/control-api/internal/poolmon).
export type DBPoolReason = 'saturated' | 'slow_acquire' | 'canceled_acquire'

export interface DBPoolSample {
  at: string
  max_conns: number
  total_conns: number
  in_use: number
  idle: number
  constructing: number
  resident_conns: number
  request_capacity: number
  acquires: number
  queued: number
  canceled: number
  avg_wait_ms: number
  reasons: DBPoolReason[]
}

export interface DBPoolResident {
  name: string
  in_pool: boolean
  since: string
}

export interface DBPoolStatus {
  instance: string
  interval_seconds: number
  thresholds: { enter_cycles: number; recover_cycles: number; saturation_margin: number; slow_acquire_ms: number; dedup_minutes: number }
  current: DBPoolSample | null
  series: DBPoolSample[]
  residents: DBPoolResident[]
  firing: boolean
  firing_since: string | null
  firing_reasons: DBPoolReason[]
  notified: boolean
  last_notified_at: string | null
  pending_notifications: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function count(value: unknown) { return Number.isSafeInteger(value) && (value as number) >= 0 }
function time(value: unknown) { return typeof value === 'string' && Number.isFinite(Date.parse(value)) }
function sample(value: unknown): value is DBPoolSample {
  return record(value) && time(value.at) && ['max_conns', 'total_conns', 'in_use', 'idle', 'constructing', 'resident_conns',
    'request_capacity', 'acquires', 'queued', 'canceled'].every((key) => count(value[key])) &&
    typeof value.avg_wait_ms === 'number' && Number.isFinite(value.avg_wait_ms) && Array.isArray(value.reasons)
}
function status(value: unknown): value is DBPoolStatus {
  return record(value) && typeof value.instance === 'string' && count(value.interval_seconds) && record(value.thresholds) &&
    (value.current === null || sample(value.current)) && Array.isArray(value.series) && value.series.every(sample) &&
    Array.isArray(value.residents) && value.residents.every((r) => record(r) && typeof r.name === 'string' && typeof r.in_pool === 'boolean') &&
    typeof value.firing === 'boolean' && (value.firing_since === null || time(value.firing_since)) && Array.isArray(value.firing_reasons) &&
    typeof value.notified === 'boolean' && (value.last_notified_at === null || time(value.last_notified_at)) && count(value.pending_notifications)
}

export const controlDBPoolApi = {
  async get(accessToken: string): Promise<DBPoolStatus> {
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/admin/system-db-pool`, { credentials: 'include',
        headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `system-db-pool-${crypto.randomUUID()}` } })
    } catch { throw networkApiError() }
    if (!response.ok) throw await responseApiError(response)
    let body: unknown
    try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
    if (!status(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
    return body
  },
}
