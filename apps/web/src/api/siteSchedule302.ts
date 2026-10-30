import { ApiError, networkApiError, responseApiError } from './auth'

// 网站 HTTP 302 调度：GET/PUT /v1/sites/{id}/schedule302.

export type Schedule302Target = 'address' | 'hostname'

export interface Schedule302Settings {
  enabled: boolean
  target: Schedule302Target
  keep_path: boolean
  keep_query: boolean
  signature_ttl_seconds: number
  https_to_http: boolean
  extensions: string[]
  path_prefixes: string[]
  min_size_bytes: number
}

export interface Schedule302State {
  site_id: string
  version: number
  settings: Schedule302Settings
  plain_http: boolean
  updated_at: string | null
}

export const SCHEDULE302_TTL_MIN = 10
export const SCHEDULE302_TTL_MAX = 3600

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/u, '')

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isSettings(value: unknown): value is Schedule302Settings {
  return isRecord(value) && typeof value.enabled === 'boolean' && (value.target === 'address' || value.target === 'hostname') &&
    typeof value.keep_path === 'boolean' && typeof value.keep_query === 'boolean' &&
    typeof value.signature_ttl_seconds === 'number' && typeof value.https_to_http === 'boolean' &&
    isStringList(value.extensions) && isStringList(value.path_prefixes) && typeof value.min_size_bytes === 'number'
}

export function isSchedule302State(value: unknown): value is Schedule302State {
  return isRecord(value) && typeof value.site_id === 'string' && typeof value.version === 'number' && value.version >= 1 &&
    isSettings(value.settings) && typeof value.plain_http === 'boolean' &&
    (value.updated_at === null || typeof value.updated_at === 'string')
}

async function request(token: string, path: string, init: RequestInit = {}): Promise<Schedule302State> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { value = undefined }
  if (!isSchedule302State(value)) throw new ApiError('Invalid 302 scheduling response', 0, 'invalid_response')
  return value
}

/** Splits a free-text list ("mp4, .zip\niso") into trimmed non-empty items. */
export function splitList(value: string): string[] {
  return value.split(/[\s,，、]+/u).map((item) => item.trim()).filter(Boolean)
}

export const siteSchedule302Api = {
  get(token: string, siteId: string, signal?: AbortSignal): Promise<Schedule302State> {
    return request(token, `/v1/sites/${encodeURIComponent(siteId)}/schedule302`, { signal })
  },
  replace(token: string, siteId: string, expectedVersion: number, settings: Schedule302Settings, idempotencyKey: string): Promise<Schedule302State> {
    return request(token, `/v1/sites/${encodeURIComponent(siteId)}/schedule302`, {
      method: 'PUT',
      headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${expectedVersion}"` },
      body: JSON.stringify(settings),
    })
  },
}
