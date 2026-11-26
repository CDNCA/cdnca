import { ApiError, networkApiError, responseApiError } from './auth'

// CDN-ORIGIN-AUTH-HINT: GET /v1/admin/control-origin-auth tells whether the
// console behind a CDN gets the visitor address, from 源IP请求头 or origin
// authentication (services/control-api/internal/httpapi/control_origin_auth.go).
export interface ControlOriginAuthStatus {
  /** A CDN request without a confirmed visitor address came within the hour, and no confirmed one since. */
  cdn_without_origin_auth: boolean
  /** install-control.sh origin-auth is configured on the control host. */
  origin_auth_enabled: boolean
  /** A BaoTa host: its site proxy rewrites X-Real-IP / X-Forwarded-For, so 源IP请求头 reads only CF-Connecting-IP or True-Client-IP. */
  baota: boolean
  /** The console nginx passes the client's own X-Real-IP / X-Forwarded-For to control-api (missing from an older control-api: false). */
  client_headers_forwarded: boolean
  /** The --real-ip-header in use ('' while origin authentication is off). */
  real_ip_header: string
  /** The last unconfirmed CDN request carried the origin key but real_ip_header held no visitor IP. */
  key_only: boolean
  /** A request carried the origin key within the hour (nginx X-Cdnca-Origin-Verified), no unconfirmed CDN request since. */
  visitor_ip_confirmed: boolean
  /** The visitor address header of the last unconfirmed CDN request ('' none). */
  header: string
  last_seen_at: string | null
  last_confirmed_at: string | null
}

/** The 源IP请求头 values besides '' (direct), as system other settings source_ip_header takes them (internal/clientip). */
export const sourceIPHeaders = ['CF-Connecting-IP', 'True-Client-IP', 'X-Forwarded-For', 'X-Real-IP'] as const
export type SourceIPHeader = typeof sourceIPHeaders[number]

/**
 * Whether control-api can read header on this console: X-Forwarded-For and X-Real-IP only when the
 * console nginx passes the client's own values and no BaoTa site proxy rewrote them. Unknown status: yes.
 */
export function sourceIPHeaderReadable(header: string, status?: ControlOriginAuthStatus): boolean {
  if (header !== 'X-Forwarded-For' && header !== 'X-Real-IP') return true
  return !status || (status.client_headers_forwarded && !status.baota)
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function status(value: unknown): value is ControlOriginAuthStatus {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const body = value as Record<string, unknown>
  const time = (value: unknown) => value === null || (typeof value === 'string' && Number.isFinite(Date.parse(value)))
  return typeof body.cdn_without_origin_auth === 'boolean' && typeof body.origin_auth_enabled === 'boolean' &&
    typeof body.baota === 'boolean' && (body.client_headers_forwarded === undefined || typeof body.client_headers_forwarded === 'boolean') &&
    typeof body.real_ip_header === 'string' && typeof body.key_only === 'boolean' &&
    typeof body.visitor_ip_confirmed === 'boolean' && typeof body.header === 'string' && time(body.last_seen_at) && time(body.last_confirmed_at)
}

export const controlOriginAuthApi = {
  async get(accessToken: string, signal?: AbortSignal): Promise<ControlOriginAuthStatus> {
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/admin/control-origin-auth`, { credentials: 'include', signal,
        headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `control-origin-auth-${crypto.randomUUID()}` } })
    } catch { throw networkApiError() }
    if (!response.ok) throw await responseApiError(response)
    let body: unknown
    try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
    if (!status(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
    return { ...body, client_headers_forwarded: body.client_headers_forwarded ?? false }
  },
}

