import type { Principal } from './auth'
import { ApiError, networkApiError, responseApiError } from './auth'

export interface ImpersonationWriteMetadata {
  requestId: string
  idempotencyKey: string
  traceparent: string
}

export interface CreateImpersonationGrantInput {
  tenant_id: string
  tenant_scope_id: string
  subject_user_id: string
}

export interface ImpersonationGrant {
  id: string
  tenant_id: string
  tenant_scope_id: string
  actor_user_id: string
  actor_scope_id: string
  subject_user_id: string
  created_at: string
  expires_at: string
}

export interface CreateImpersonationGrantResult {
  grant: ImpersonationGrant
  authorization_code: string
  replayed: boolean
}

export interface ExchangeImpersonationInput {
  tenant_id: string
  tenant_scope_id: string
  authorization_code: string
}

export interface ImpersonationBannerClaims {
  grant_id: string
  actor_user_id: string
  actor_display_name: string
  subject_user_id: string
  subject_display_name: string
  tenant_id: string
  expires_at: string
}

export interface ImpersonationSessionView {
  principal: Principal
  banner: ImpersonationBannerClaims
  expires_at: string
  refreshable: false
  replayed: boolean
}

export interface RevokeImpersonationInput {
  tenant_id: string
  tenant_scope_id: string
  reason: string
}

export interface ImpersonationRevocation {
  id: string
  grant_id: string
  revoked_by: string
  reason: string
  revoked_at: string
  replayed: boolean
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const traceparentPattern = /^00-((?!0{32})[0-9a-f]{32})-((?!0{16})[0-9a-f]{16})-(00|01)$/

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && actual.every((key) => keys.includes(key))
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && /^\d{4}-\d{2}-\d{2}T/.test(value) &&
    !Number.isNaN(Date.parse(value))
}

function safeText(value: unknown, maximum: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || value.trim() !== value) return false
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0
    if (codePoint < 0x20 || codePoint === 0x7f || codePoint === 0x2028 || codePoint === 0x2029) return false
  }
  return true
}

function invalidRequest(): ApiError {
  return new ApiError('Invalid impersonation request', 400, 'invalid_request')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid impersonation response', 502, 'invalid_response')
}

function metadataHeaders(metadata: ImpersonationWriteMetadata): Record<string, string> {
  if (!record(metadata) || !exactKeys(metadata, ['requestId', 'idempotencyKey', 'traceparent']) ||
    typeof metadata.requestId !== 'string' || !metadataPattern.test(metadata.requestId) ||
    typeof metadata.idempotencyKey !== 'string' || !idempotencyPattern.test(metadata.idempotencyKey) ||
    typeof metadata.traceparent !== 'string' || !traceparentPattern.test(metadata.traceparent)) throw invalidRequest()
  return {
    'Content-Type': 'application/json',
    'Idempotency-Key': metadata.idempotencyKey,
    'X-Request-ID': metadata.requestId,
    Traceparent: metadata.traceparent,
  }
}

async function send(path: string, init: RequestInit): Promise<Response> {
  try {
    const response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      cache: 'no-store',
    })
    if (!response.ok) throw await responseApiError(response)
    return response
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw networkApiError()
  }
}

async function body(response: Response): Promise<unknown> {
  if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/json') throw invalidResponse()
  try { return await response.json() } catch { throw invalidResponse() }
}

function parseGrant(value: unknown): ImpersonationGrant {
  if (!record(value) || !exactKeys(value, [
    'id', 'tenant_id', 'tenant_scope_id', 'actor_user_id', 'actor_scope_id', 'subject_user_id',
    'created_at', 'expires_at',
  ]) || !uuid(value.id) || !uuid(value.tenant_id) || !uuid(value.tenant_scope_id) ||
    !uuid(value.actor_user_id) || !uuid(value.actor_scope_id) || !uuid(value.subject_user_id) ||
    !timestamp(value.created_at) || !timestamp(value.expires_at) ||
    Date.parse(value.expires_at) <= Date.parse(value.created_at) ||
    Date.parse(value.expires_at) - Date.parse(value.created_at) > 120_000) throw invalidResponse()
  return value as unknown as ImpersonationGrant
}

function parsePrincipal(value: unknown): Principal {
  // display_id 可选：旧主控的代登录响应没有它。
  const keys = ['user_id', 'scope_id', 'scope_kind', 'tenant_id', 'username', 'display_name', 'roles', 'permissions']
  if (!record(value) || !exactKeys(value, 'display_id' in value ? [...keys, 'display_id'] : keys) ||
    ('display_id' in value && (typeof value.display_id !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.display_id))) ||
    !uuid(value.user_id) || !uuid(value.scope_id) || value.scope_kind !== 'tenant' ||
    !uuid(value.tenant_id) || !safeText(value.username, 128) || !safeText(value.display_name, 256) ||
    !Array.isArray(value.roles) || !value.roles.every((item) => safeText(item, 128)) ||
    !Array.isArray(value.permissions) || !value.permissions.every((item) => safeText(item, 128))) throw invalidResponse()
  return value as unknown as Principal
}

function parseBanner(value: unknown): ImpersonationBannerClaims {
  if (!record(value) || !exactKeys(value, [
    'grant_id', 'actor_user_id', 'actor_display_name', 'subject_user_id', 'subject_display_name',
    'tenant_id', 'expires_at',
  ]) || !uuid(value.grant_id) || !uuid(value.actor_user_id) || !safeText(value.actor_display_name, 256) ||
    !uuid(value.subject_user_id) || !safeText(value.subject_display_name, 256) ||
    !uuid(value.tenant_id) || !timestamp(value.expires_at)) throw invalidResponse()
  return value as unknown as ImpersonationBannerClaims
}

function validateCreateInput(value: CreateImpersonationGrantInput): void {
  if (!record(value) || !exactKeys(value, ['tenant_id', 'tenant_scope_id', 'subject_user_id']) ||
    !uuid(value.tenant_id) || !uuid(value.tenant_scope_id) || !uuid(value.subject_user_id)) {
    throw invalidRequest()
  }
}

function validateExchangeInput(value: ExchangeImpersonationInput): void {
  if (!record(value) || !exactKeys(value, ['tenant_id', 'tenant_scope_id', 'authorization_code']) ||
    !uuid(value.tenant_id) || !uuid(value.tenant_scope_id) || !safeText(value.authorization_code, 256)) {
    throw invalidRequest()
  }
}

function randomHex(bytes: number): string {
  if (!globalThis.crypto?.getRandomValues) throw new ApiError('Web Crypto unavailable', 400, 'crypto_unavailable')
  const value = new Uint8Array(bytes)
  globalThis.crypto.getRandomValues(value)
  if (value.every((item) => item === 0)) value[value.length - 1] = 1
  return [...value].map((item) => item.toString(16).padStart(2, '0')).join('')
}

function suffix(): string {
  return globalThis.crypto?.randomUUID?.() ?? randomHex(16)
}

export function createImpersonationWriteMetadata(action: 'create' | 'exchange' | 'revoke'): ImpersonationWriteMetadata {
  return {
    requestId: `impersonation-${action}-${suffix()}`,
    idempotencyKey: `impersonation-${action}-${suffix()}`,
    traceparent: `00-${randomHex(16)}-${randomHex(8)}-01`,
  }
}

export const impersonationApi = {
  async createGrant(accessToken: string, input: CreateImpersonationGrantInput, metadata: ImpersonationWriteMetadata): Promise<CreateImpersonationGrantResult> {
    if (!accessToken) throw invalidRequest()
    validateCreateInput(input)
    const response = await send('/v1/admin/impersonation/grants', {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, ...metadataHeaders(metadata) },
      body: JSON.stringify(input),
    })
    const value = await body(response)
    if ((response.status !== 200 && response.status !== 201) || !record(value) ||
      !exactKeys(value, ['grant', 'authorization_code', 'replayed']) ||
      !safeText(value.authorization_code, 256) || typeof value.replayed !== 'boolean' ||
      value.replayed !== (response.status === 200)) throw invalidResponse()
    const grant = parseGrant(value.grant)
    if (grant.tenant_id !== input.tenant_id || grant.tenant_scope_id !== input.tenant_scope_id ||
      grant.subject_user_id !== input.subject_user_id) throw invalidResponse()
    return { grant, authorization_code: value.authorization_code, replayed: value.replayed }
  },

  async exchange(input: ExchangeImpersonationInput, metadata: ImpersonationWriteMetadata): Promise<ImpersonationSessionView> {
    validateExchangeInput(input)
    const response = await send('/v1/admin/impersonation/exchanges', {
      method: 'POST', headers: metadataHeaders(metadata), body: JSON.stringify(input),
    })
    const value = await body(response)
    if ((response.status !== 200 && response.status !== 201) || !record(value) || !exactKeys(value, [
      'principal', 'banner', 'expires_at', 'refreshable', 'replayed',
    ]) || !timestamp(value.expires_at) || value.refreshable !== false || typeof value.replayed !== 'boolean' ||
      value.replayed !== (response.status === 200)) throw invalidResponse()
    const principal = parsePrincipal(value.principal)
    const banner = parseBanner(value.banner)
    if (principal.scope_id !== input.tenant_scope_id || principal.tenant_id !== input.tenant_id ||
      banner.tenant_id !== input.tenant_id || principal.user_id !== banner.subject_user_id ||
      principal.tenant_id !== banner.tenant_id ||
      banner.expires_at !== value.expires_at || Date.parse(value.expires_at) <= Date.now()) throw invalidResponse()
    return { principal, banner, expires_at: value.expires_at, refreshable: false, replayed: value.replayed }
  },

  async revoke(accessToken: string, grantID: string, input: RevokeImpersonationInput, metadata: ImpersonationWriteMetadata): Promise<ImpersonationRevocation> {
    if (!accessToken || !uuid(grantID) || !record(input) || !exactKeys(input, ['tenant_id', 'tenant_scope_id', 'reason']) ||
      !uuid(input.tenant_id) || !uuid(input.tenant_scope_id) || !safeText(input.reason, 512)) throw invalidRequest()
    const response = await send(`/v1/admin/impersonation/grants/${grantID}/revocations`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, ...metadataHeaders(metadata) },
      body: JSON.stringify(input),
    })
    const value = await body(response)
    if (response.status !== 200 || !record(value) || !exactKeys(value, [
      'id', 'grant_id', 'revoked_by', 'reason', 'revoked_at', 'replayed',
    ]) || !uuid(value.id) || !uuid(value.grant_id) || value.grant_id !== grantID || !uuid(value.revoked_by) ||
      !safeText(value.reason, 512) || !timestamp(value.revoked_at) || typeof value.replayed !== 'boolean') throw invalidResponse()
    return value as unknown as ImpersonationRevocation
  },
}
