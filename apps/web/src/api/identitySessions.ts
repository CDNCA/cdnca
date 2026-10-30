import { ApiError, networkApiError, responseApiError } from './auth'

export interface IdentitySessionFamily {
  family_id: string
  device_label: string
  ip_prefix?: string
  created_at: string
  last_used_at: string
  expires_at: string
  revoked_at?: string
  current: boolean
  active: boolean
  session_count: number
  revision: number
}

export interface IdentitySessionFamilyPage {
  items: IdentitySessionFamily[]
  next_cursor?: string
}

export interface IdentitySessionRevokeResult {
  family_id: string
  revision: number
  revoked_at: string
  current: boolean
  replayed?: boolean
}

export interface IdentitySessionRevokeAttempt {
  familyID: string
  revision: number
  idempotencyKey: string
  requestID: string
}

export interface IdentitySessionListParams {
  limit?: number
  cursor?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const writeKeyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false
  const match = timestampPattern.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)))
  return calendar.getUTCFullYear() === Number(year) &&
    calendar.getUTCMonth() === Number(month) - 1 && calendar.getUTCDate() === Number(day) &&
    Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) &&
    Number.isFinite(Date.parse(value))
}

function maskedIPPrefix(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 64) return false
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/.exec(value)
  if (ipv4) return ipv4.slice(1).every((part) => Number(part) <= 255)
  return /^[0-9a-f:]+\/64$/.test(value) && value.includes(':') &&
    !value.includes(':::') && !value.includes('%')
}

function sessionFamily(value: unknown): value is IdentitySessionFamily {
  if (!record(value) || !exact(value, [
    'family_id', 'device_label', 'created_at', 'last_used_at', 'expires_at',
    'current', 'active', 'session_count', 'revision',
  ], ['ip_prefix', 'revoked_at'])) return false
  return typeof value.family_id === 'string' && uuidPattern.test(value.family_id) &&
    typeof value.device_label === 'string' && value.device_label.length >= 1 &&
    [...value.device_label].length <= 64 && ![...value.device_label].some((character) => {
      const code = character.charCodeAt(0)
      return code <= 31 || code === 127
    }) &&
    (value.ip_prefix === undefined || maskedIPPrefix(value.ip_prefix)) &&
    timestamp(value.created_at) && timestamp(value.last_used_at) && timestamp(value.expires_at) &&
    (value.revoked_at === undefined || timestamp(value.revoked_at)) &&
    typeof value.current === 'boolean' && typeof value.active === 'boolean' &&
    integer(value.session_count, 1) && integer(value.revision, 1)
}

function familyPage(value: unknown): value is IdentitySessionFamilyPage {
  return record(value) && exact(value, ['items'], ['next_cursor']) &&
    Array.isArray(value.items) && value.items.length <= 100 && value.items.every(sessionFamily) &&
    (value.next_cursor === undefined || (
      typeof value.next_cursor === 'string' && value.next_cursor.length >= 1 && value.next_cursor.length <= 2048
    ))
}

function revokeResult(value: unknown, attempt: IdentitySessionRevokeAttempt): value is IdentitySessionRevokeResult {
  return record(value) && exact(value, [
    'family_id', 'revision', 'revoked_at', 'current',
  ], ['replayed']) && value.family_id === attempt.familyID &&
    integer(value.revision, attempt.revision + 1) && timestamp(value.revoked_at) &&
    typeof value.current === 'boolean' &&
    (value.replayed === undefined || typeof value.replayed === 'boolean')
}

function validationError(): ApiError {
  return new ApiError('Invalid identity session request', 400, 'identity_session_validation_error')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid identity session response', 502, 'identity_session_invalid_response')
}

function validAttempt(value: IdentitySessionRevokeAttempt): boolean {
  return uuidPattern.test(value.familyID) && integer(value.revision, 1) &&
    writeKeyPattern.test(value.idempotencyKey) && uuidPattern.test(value.requestID)
}

async function send(path: string, accessToken: string, init: RequestInit): Promise<Response> {
  try {
    const response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...init.headers,
      },
    })
    if (!response.ok) throw await responseApiError(response)
    return response
  } catch (error) {
    if (error instanceof ApiError || error instanceof DOMException && error.name === 'AbortError') throw error
    throw networkApiError()
  }
}

async function strictJSON<T>(response: Response, validate: (value: unknown) => value is T): Promise<T> {
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponse()
  }
  if (!validate(value)) throw invalidResponse()
  return value
}

export function createIdentitySessionRevokeAttempt(
  familyID: string,
  revision: number,
): IdentitySessionRevokeAttempt {
  const attempt = {
    familyID,
    revision,
    idempotencyKey: globalThis.crypto.randomUUID(),
    requestID: globalThis.crypto.randomUUID(),
  }
  if (!validAttempt(attempt)) throw validationError()
  return Object.freeze(attempt)
}

export const identitySessionsApi = {
  async list(
    accessToken: string,
    params: IdentitySessionListParams = {},
    signal?: AbortSignal,
  ): Promise<IdentitySessionFamilyPage> {
    const limit = params.limit ?? 20
    if (!integer(limit, 1, 100) || params.cursor !== undefined && (
      params.cursor.length < 1 || params.cursor.length > 2048
    )) throw validationError()
    const query = new URLSearchParams({ limit: String(limit) })
    if (params.cursor !== undefined) query.set('cursor', params.cursor)
    const response = await send(`/v1/identity/sessions?${query}`, accessToken, {
      method: 'GET', signal, headers: { 'X-Request-ID': globalThis.crypto.randomUUID() },
    })
    return strictJSON(response, familyPage)
  },

  async revoke(
    accessToken: string,
    attempt: IdentitySessionRevokeAttempt,
    signal?: AbortSignal,
  ): Promise<IdentitySessionRevokeResult> {
    if (!validAttempt(attempt)) throw validationError()
    const response = await send(
      `/v1/identity/session-families/${encodeURIComponent(attempt.familyID)}`,
      accessToken,
      {
        method: 'DELETE', signal,
        headers: {
          'If-Match': `"${attempt.revision}"`,
          'Idempotency-Key': attempt.idempotencyKey,
          'X-Request-ID': attempt.requestID,
        },
      },
    )
    return strictJSON(response, (value): value is IdentitySessionRevokeResult => revokeResult(value, attempt))
  },
}
