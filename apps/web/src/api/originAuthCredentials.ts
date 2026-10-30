import { ApiError, networkApiError, responseApiError } from './auth'

export type OriginAuthProvider = 's3' | 'oss' | 'cos'
export type OriginAuthCredentialStatus = 'pending' | 'verified' | 'disabled' | 'deleted'

export interface OriginAuthCredential {
  id: string
  tenant_scope_id: string
  provider: OriginAuthProvider
  name: string
  status: OriginAuthCredentialStatus
  revision: number
  revision_ref: string
  not_before: string
  expires_at: string
  verified_at?: string
  created_at: string
  updated_at: string
}

export interface OriginAuthCredentialSecret {
  access_key_id: string
  secret_access_key: string
  session_token?: string
  not_before: string
  expires_at: string
}

export interface OriginAuthCredentialPage {
  items: OriginAuthCredential[]
  next_cursor?: string
}

export interface OriginAuthCredentialListParams {
  provider?: OriginAuthProvider
  status?: OriginAuthCredentialStatus
  limit?: number
  cursor?: string
}

export interface OriginAuthCredentialWriteMetadata {
  idempotencyKey: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const providers = new Set<OriginAuthProvider>(['s3', 'oss', 'cos'])
const statuses = new Set<OriginAuthCredentialStatus>(['pending', 'verified', 'disabled', 'deleted'])

function invalidRequest(): ApiError {
  return new ApiError('Origin authentication request was invalid', 400, 'origin_auth_validation_error')
}

function invalidResponse(): ApiError {
  return new ApiError('Origin authentication response was invalid', 502, 'origin_auth_invalid_response')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function isInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)))
  return calendar.getUTCFullYear() === Number(year) &&
    calendar.getUTCMonth() === Number(month) - 1 &&
    calendar.getUTCDate() === Number(day) &&
    Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) &&
    Number.isFinite(Date.parse(value))
}

function isCredential(value: unknown, scopeID: string): value is OriginAuthCredential {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'tenant_scope_id', 'provider', 'name', 'status', 'revision', 'revision_ref',
    'not_before', 'expires_at', 'created_at', 'updated_at',
  ], ['verified_at'])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    value.tenant_scope_id === scopeID &&
    typeof value.provider === 'string' && providers.has(value.provider as OriginAuthProvider) &&
    typeof value.name === 'string' && value.name.length >= 1 && value.name.length <= 128 &&
    value.name.trim() === value.name &&
    typeof value.status === 'string' && statuses.has(value.status as OriginAuthCredentialStatus) &&
    isInteger(value.revision, 1) && typeof value.revision_ref === 'string' &&
    uuidPattern.test(value.revision_ref) && isTimestamp(value.not_before) &&
    isTimestamp(value.expires_at) && Date.parse(value.not_before) < Date.parse(value.expires_at) &&
    (value.verified_at === undefined || isTimestamp(value.verified_at)) &&
    isTimestamp(value.created_at) && isTimestamp(value.updated_at) &&
    Date.parse(value.created_at) <= Date.parse(value.updated_at)
}

function isPage(value: unknown, scopeID: string): value is OriginAuthCredentialPage {
  return isRecord(value) && exactKeys(value, ['items'], ['next_cursor']) &&
    Array.isArray(value.items) && value.items.length <= 100 &&
    value.items.every((item) => isCredential(item, scopeID)) &&
    (value.next_cursor === undefined || (
      typeof value.next_cursor === 'string' &&
      value.next_cursor.length >= 1 && value.next_cursor.length <= 512
    ))
}

function validToken(value: string): boolean {
  return value.length >= 1 && value.length <= 8192 && !/\s/.test(value)
}

function validMetadata(value: OriginAuthCredentialWriteMetadata): boolean {
  return isRecord(value) && exactKeys(value, ['idempotencyKey']) &&
    typeof value.idempotencyKey === 'string' && metadataPattern.test(value.idempotencyKey)
}

function validSecret(value: OriginAuthCredentialSecret): boolean {
  return isRecord(value) && exactKeys(value, [
    'access_key_id', 'secret_access_key', 'not_before', 'expires_at',
  ], ['session_token']) &&
    typeof value.access_key_id === 'string' && value.access_key_id.length >= 1 &&
    value.access_key_id.length <= 256 &&
    typeof value.secret_access_key === 'string' && value.secret_access_key.length >= 1 &&
    value.secret_access_key.length <= 512 &&
    (value.session_token === undefined || (
      typeof value.session_token === 'string' && value.session_token.length >= 1 &&
      value.session_token.length <= 4096
    )) && isTimestamp(value.not_before) && isTimestamp(value.expires_at) &&
    Date.parse(value.not_before) < Date.parse(value.expires_at)
}

function validateBase(accessToken: string, scopeID: string): void {
  if (!validToken(accessToken) || !uuidPattern.test(scopeID)) throw invalidRequest()
}

function validateCredentialID(credentialID: string): void {
  if (!uuidPattern.test(credentialID)) throw invalidRequest()
}

function writeHeaders(
  accessToken: string,
  metadata: OriginAuthCredentialWriteMetadata,
  revision?: number,
): HeadersInit {
  if (!validMetadata(metadata) || (revision !== undefined && !isInteger(revision, 1))) {
    throw invalidRequest()
  }
  return {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': metadata.idempotencyKey,
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

async function request(
  accessToken: string,
  scopeID: string,
  path: string,
  expectedStatus: number,
  init: RequestInit,
  requireETag: boolean,
): Promise<OriginAuthCredential> {
  validateBase(accessToken, scopeID)
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
  if (response.status !== expectedStatus ||
    response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponse()
  }
  if (!isCredential(value, scopeID) || (requireETag && response.headers.get('ETag') !== `"${value.revision}"`)) {
    throw invalidResponse()
  }
  return value
}

function basePath(scopeID: string): string {
  return `/v1/tenant-scopes/${scopeID}/origin-auth/credentials`
}

function randomSuffix(): string {
  if (!globalThis.crypto?.getRandomValues) throw invalidRequest()
  if (globalThis.crypto.randomUUID) return globalThis.crypto.randomUUID()
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function createOriginAuthCredentialWriteMetadata(): OriginAuthCredentialWriteMetadata {
  return { idempotencyKey: `origin-auth-credential-${randomSuffix()}` }
}

function transitionCredential(
  accessToken: string,
  scopeID: string,
  credentialID: string,
  revision: number,
  operation: 'verify' | 'disable',
  metadata: OriginAuthCredentialWriteMetadata,
) {
  validateCredentialID(credentialID)
  return request(accessToken, scopeID, `${basePath(scopeID)}/${credentialID}/${operation}`, 200, {
    method: 'POST', headers: writeHeaders(accessToken, metadata, revision), body: '{}',
  }, true)
}

export const originAuthCredentialsApi = {
  async list(
    accessToken: string,
    scopeID: string,
    params: OriginAuthCredentialListParams = {},
    signal?: AbortSignal,
  ): Promise<OriginAuthCredentialPage> {
    validateBase(accessToken, scopeID)
    if ((params.provider !== undefined && !providers.has(params.provider)) ||
      (params.status !== undefined && !statuses.has(params.status)) ||
      (params.limit !== undefined && !isInteger(params.limit, 1, 100)) ||
      (params.cursor !== undefined && (params.cursor.length < 1 || params.cursor.length > 512))) {
      throw invalidRequest()
    }
    const query = new URLSearchParams()
    if (params.provider !== undefined) query.set('provider', params.provider)
    if (params.status !== undefined) query.set('status', params.status)
    if (params.limit !== undefined) query.set('limit', String(params.limit))
    if (params.cursor !== undefined) query.set('cursor', params.cursor)
    let response: Response
    try {
      response = await fetch(`${apiRoot}${basePath(scopeID)}${query.size ? `?${query}` : ''}`, {
        method: 'GET', credentials: 'include', signal,
        headers: { Authorization: `Bearer ${accessToken}` },
      })
    } catch {
      throw networkApiError()
    }
    if (!response.ok) throw await responseApiError(response)
    if (response.status !== 200 || response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
      throw invalidResponse()
    }
    let value: unknown
    try {
      value = await response.json()
    } catch {
      throw invalidResponse()
    }
    if (!isPage(value, scopeID)) throw invalidResponse()
    return value
  },

  async get(accessToken: string, scopeID: string, credentialID: string, signal?: AbortSignal) {
    validateCredentialID(credentialID)
    return request(accessToken, scopeID, `${basePath(scopeID)}/${credentialID}`, 200, {
      method: 'GET', signal,
    }, true)
  },

  async create(
    accessToken: string,
    scopeID: string,
    input: { provider: OriginAuthProvider; name: string; secret: OriginAuthCredentialSecret },
    metadata: OriginAuthCredentialWriteMetadata,
  ) {
    if (!isRecord(input) || !exactKeys(input, ['provider', 'name', 'secret']) ||
      !providers.has(input.provider) || typeof input.name !== 'string' ||
      input.name.length < 1 || input.name.length > 128 || input.name.trim() !== input.name ||
      !validSecret(input.secret)) throw invalidRequest()
    return request(accessToken, scopeID, basePath(scopeID), 201, {
      method: 'POST', headers: writeHeaders(accessToken, metadata), body: JSON.stringify(input),
    }, true)
  },

  async replace(
    accessToken: string,
    scopeID: string,
    credentialID: string,
    revision: number,
    input: { secret: OriginAuthCredentialSecret },
    metadata: OriginAuthCredentialWriteMetadata,
  ) {
    validateCredentialID(credentialID)
    if (!isRecord(input) || !exactKeys(input, ['secret']) || !validSecret(input.secret)) throw invalidRequest()
    return request(accessToken, scopeID, `${basePath(scopeID)}/${credentialID}/replace`, 200, {
      method: 'POST', headers: writeHeaders(accessToken, metadata, revision), body: JSON.stringify(input),
    }, true)
  },

  async verify(accessToken: string, scopeID: string, credentialID: string, revision: number, metadata: OriginAuthCredentialWriteMetadata) {
    return transitionCredential(accessToken, scopeID, credentialID, revision, 'verify', metadata)
  },

  async disable(accessToken: string, scopeID: string, credentialID: string, revision: number, metadata: OriginAuthCredentialWriteMetadata) {
    return transitionCredential(accessToken, scopeID, credentialID, revision, 'disable', metadata)
  },

  async delete(accessToken: string, scopeID: string, credentialID: string, revision: number, metadata: OriginAuthCredentialWriteMetadata) {
    validateCredentialID(credentialID)
    return request(accessToken, scopeID, `${basePath(scopeID)}/${credentialID}`, 200, {
      method: 'DELETE', headers: writeHeaders(accessToken, metadata, revision), body: '{}',
    }, true)
  },
}
