import { ApiError, networkApiError, responseApiError } from './auth'

export type OriginProbeStatus = 'healthy' | 'unhealthy' | 'unknown'

/** A site's origin probe state and active level (GET /v1/sites/{id}/origin-status). */
export interface SiteOriginPoolStatus {
  site_id: string
  failback_mode: 'auto' | 'manual'
  active_level: number
  overall: OriginProbeStatus
  failback_ready: boolean
  levels: Array<{ level: number; status: OriginProbeStatus }>
  origins: Array<{
    position: number
    host: string
    port: number
    level: number
    enabled: boolean
    status: OriginProbeStatus
    reason: string
    checked_at: string | null
  }>
  switched_at: string | null
  checked_at: string | null
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return (await response.json()) as T
}

const statuses = new Set(['healthy', 'unhealthy', 'unknown'])

function poolStatus(body: unknown, siteID: string): SiteOriginPoolStatus {
  const value = body as SiteOriginPoolStatus
  if (typeof body !== 'object' || body === null || value.site_id !== siteID ||
    (value.failback_mode !== 'auto' && value.failback_mode !== 'manual') ||
    !Number.isInteger(value.active_level) || !statuses.has(value.overall) || typeof value.failback_ready !== 'boolean' ||
    !Array.isArray(value.levels) || !value.levels.every((level) => Number.isInteger(level?.level) && statuses.has(level.status)) ||
    !Array.isArray(value.origins) || !value.origins.every((origin) => typeof origin?.host === 'string' &&
      Number.isInteger(origin.port) && Number.isInteger(origin.level) && typeof origin.enabled === 'boolean' &&
      statuses.has(origin.status) && typeof origin.reason === 'string')) {
    throw new ApiError('Invalid origin status response', 502, 'invalid_response')
  }
  return value
}

async function get(accessToken: string, siteID: string, signal?: AbortSignal): Promise<SiteOriginPoolStatus> {
  return poolStatus(await request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/origin-status`, { signal }), siteID)
}

async function failback(accessToken: string, siteID: string, idempotencyKey: string): Promise<SiteOriginPoolStatus> {
  return poolStatus(await request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/origin-failback`, {
    method: 'POST', headers: { 'Idempotency-Key': idempotencyKey },
  }), siteID)
}

export const siteOriginStatusApi = { get, failback }
