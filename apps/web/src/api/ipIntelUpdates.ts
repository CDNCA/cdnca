import { ApiError, attachFieldRefusal, networkApiError } from './auth'

// Official plugin module.ipintel.dnspup (control-api internal/ipintelupdate,
// PA-16). Platform scope + system.ip_intel_updates.manage; enabling, testing
// and "check now" also need the module in the licence.

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export const ipIntelUpdatesPermission = 'system.ip_intel_updates.manage'
export const ipIntelUpdatesModule = 'module.ipintel.dnspup'

export interface IPIntelLibrary {
  artifact_id: 'ipintel/base' | 'ipintel/local'
  revision: number
  version: string
  source_release: string
  data_updated_at: string
  usable: boolean
}

export interface IPIntelUpdateStatus {
  licensed: boolean
  enabled: boolean
  url: string
  api_key: string
  secret_configured: boolean
  secret_fingerprint?: string
  interval_minutes: number
  anchor_minute: number
  time_zone: string
  revision: number
  settings_updated_at: string
  running: boolean
  check_requested: boolean
  last_checked_at: string | null
  last_success_at: string | null
  last_outcome: '' | 'published' | 'unchanged' | 'not_modified' | 'pending' | 'failed'
  last_release: string
  last_http_status: number
  last_error_code: string
  last_error: string
  next_check_at: string | null
  base: IPIntelLibrary | null
  local: IPIntelLibrary | null
  node_uses: '' | 'ipintel/base' | 'ipintel/local'
  use_reason?: string
}

/** api_secret omitted keeps the stored secret (same API key and URL origin only); "" clears it. */
export interface IPIntelUpdateInput {
  enabled: boolean
  url: string
  api_key: string
  api_secret?: string
  interval_minutes: number
  anchor_minute: number
  time_zone: string
}

export interface IPIntelUpdateTestResult {
  ok: boolean
  http_status: number
  release?: string
  state?: string
  bytes?: number
  error_code?: string
  source_error_code?: string
  error?: string
}

async function call<T>(token: string, path: string, init: RequestInit = {}, key?: string): Promise<T> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(key ? { 'Idempotency-Key': key } : {}),
      },
    })
  } catch {
    throw networkApiError()
  }
  const text = await response.text()
  let body: unknown
  try { body = text ? JSON.parse(text) : undefined } catch { throw new ApiError('Invalid response', 502, 'response_invalid') }
  if (!response.ok) {
    const error = (body as { error?: { code?: unknown; request_id?: unknown; details?: unknown } } | undefined)?.error
    const code = typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,95}$/.test(error.code) ? error.code : 'request_failed'
    throw attachFieldRefusal(new ApiError('IP intelligence update request failed', response.status, code,
      typeof error?.request_id === 'string' ? error.request_id : undefined), error?.details)
  }
  return body as T
}

const path = '/v1/admin/ip-intel-updates'

export const ipIntelUpdatesApi = {
  status: (token: string) => call<IPIntelUpdateStatus>(token, path),
  save: (token: string, input: IPIntelUpdateInput, key: string) =>
    call<IPIntelUpdateStatus>(token, path, { method: 'PUT', body: JSON.stringify(input) }, key),
  test: (token: string, input: IPIntelUpdateInput, key: string) =>
    call<IPIntelUpdateTestResult>(token, `${path}/tests`, { method: 'POST', body: JSON.stringify(input) }, key),
  check: (token: string, key: string) => call<IPIntelUpdateStatus>(token, `${path}/checks`, { method: 'POST' }, key),
}
