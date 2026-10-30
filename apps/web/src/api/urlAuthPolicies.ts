import { ApiError, networkApiError, responseApiError } from './auth'

export interface URLAuthPolicyFields {
  site_id: string
  name: string
  enabled: boolean
  algorithm: 'hmac-sha256'
  signature_parameter: string
  expiration_parameter: string
  key_id_parameter: string
  bind_client_ip: boolean
  max_clock_skew_seconds: number
  max_validity_seconds: number
  max_signature_uses: number
  excluded_query_parameters: string[]
  trusted_proxy_cidrs: string[]
}

export interface URLAuthKeyMetadata {
  key_id: string
  created_at: string
}

export type URLAuthPolicy = Omit<URLAuthPolicyFields, 'site_id'> & {
  id: string
  scope_id: string
  owner?: { id: string; display_name: string }
  site: { id: string; domain: string }
  migration_marker?: 'cdnfly_type_a_md5' | 'cdnfly_type_b_md5'
  current_key: URLAuthKeyMetadata
  previous_key?: URLAuthKeyMetadata
  version: number
  created_at: string
  updated_at: string
}

export interface URLAuthPolicyList {
  items: URLAuthPolicy[]
  total: number
  page: number
  limit: number
}

export interface URLAuthPolicyFilters {
  page: number
  limit: number
  name?: string
  status?: 'enabled' | 'disabled'
  site_id?: string
}

export interface URLAuthWriteResult {
  policy: URLAuthPolicy
  replayed: boolean
}

export interface URLAuthSecretWriteResult extends URLAuthWriteResult {
  secret?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const parameterPattern = /^[A-Za-z0-9_.~-]{1,64}$/
const keyIDPattern = /^[A-Za-z0-9._:-]{1,64}$/
const secretPattern = /^[A-Za-z0-9_-]{43}$/

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key))
}

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value))
}

function validStringList(value: unknown, pattern: RegExp, maxItems: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems &&
    value.every((item) => typeof item === 'string' && pattern.test(item)) &&
    new Set(value).size === value.length
}

function validKeyMetadata(value: unknown): value is URLAuthKeyMetadata {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['key_id', 'created_at', 'revoked_at']))) return false
  return typeof value.key_id === 'string' && keyIDPattern.test(value.key_id) &&
    validTimestamp(value.created_at) && (value.revoked_at === undefined || validTimestamp(value.revoked_at))
}

function parsePolicy(value: unknown): URLAuthPolicy {
  const allowed = new Set([
    'id', 'scope_id', 'owner', 'site', 'name', 'enabled', 'algorithm', 'migration_marker',
    'signature_parameter', 'expiration_parameter', 'key_id_parameter', 'bind_client_ip',
    'max_clock_skew_seconds', 'max_validity_seconds', 'max_signature_uses',
    'excluded_query_parameters', 'trusted_proxy_cidrs', 'current_key', 'previous_key',
    'version', 'created_at', 'updated_at',
  ])
  const owner = isRecord(value) ? value.owner : undefined
  const site = isRecord(value) ? value.site : undefined
  if (!isRecord(value) || !hasOnlyKeys(value, allowed) ||
    typeof value.id !== 'string' || !uuidPattern.test(value.id) ||
    typeof value.scope_id !== 'string' || !uuidPattern.test(value.scope_id) ||
    (owner !== undefined && (!isRecord(owner) || !hasOnlyKeys(owner, new Set(['id', 'display_name'])) ||
      typeof owner.id !== 'string' || !uuidPattern.test(owner.id) || typeof owner.display_name !== 'string')) ||
    !isRecord(site) || !hasOnlyKeys(site, new Set(['id', 'domain'])) ||
    typeof site.id !== 'string' || !uuidPattern.test(site.id) || typeof site.domain !== 'string' || site.domain.length < 1 || site.domain.length > 253 ||
    typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 128 ||
    typeof value.enabled !== 'boolean' || value.algorithm !== 'hmac-sha256' ||
    (value.migration_marker !== undefined && value.migration_marker !== 'cdnfly_type_a_md5' && value.migration_marker !== 'cdnfly_type_b_md5') ||
    typeof value.signature_parameter !== 'string' || !parameterPattern.test(value.signature_parameter) ||
    typeof value.expiration_parameter !== 'string' || !parameterPattern.test(value.expiration_parameter) ||
    typeof value.key_id_parameter !== 'string' || !parameterPattern.test(value.key_id_parameter) ||
    typeof value.bind_client_ip !== 'boolean' ||
    !Number.isInteger(value.max_clock_skew_seconds) || Number(value.max_clock_skew_seconds) < 0 || Number(value.max_clock_skew_seconds) > 300 ||
    !Number.isInteger(value.max_validity_seconds) || Number(value.max_validity_seconds) < 1 || Number(value.max_validity_seconds) > 86400 ||
    !Number.isInteger(value.max_signature_uses) || Number(value.max_signature_uses) < 0 || Number(value.max_signature_uses) > 1000000 ||
    !validStringList(value.excluded_query_parameters, parameterPattern, 64) ||
    !validStringList(value.trusted_proxy_cidrs, /^.{3,64}$/, 64) ||
    !validKeyMetadata(value.current_key) ||
    (value.previous_key !== undefined && !validKeyMetadata(value.previous_key)) ||
    !Number.isInteger(value.version) || Number(value.version) < 1 ||
    !validTimestamp(value.created_at) || !validTimestamp(value.updated_at)) {
    throw invalidResponse()
  }
  return value as URLAuthPolicy
}

function parseList(value: unknown): URLAuthPolicyList {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['items', 'total', 'page', 'limit'])) ||
    !Array.isArray(value.items) || value.items.length > 100 ||
    !Number.isInteger(value.total) || Number(value.total) < 0 ||
    !Number.isInteger(value.page) || Number(value.page) < 1 ||
    !Number.isInteger(value.limit) || Number(value.limit) < 1 || Number(value.limit) > 100) {
    throw invalidResponse()
  }
  return { items: value.items.map(parsePolicy), total: Number(value.total), page: Number(value.page), limit: Number(value.limit) }
}

function parseWrite(value: unknown): URLAuthWriteResult {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['policy', 'replayed'])) || typeof value.replayed !== 'boolean') {
    throw invalidResponse()
  }
  return { policy: parsePolicy(value.policy), replayed: value.replayed }
}

function parseSecretWrite(value: unknown): URLAuthSecretWriteResult {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['policy', 'secret', 'replayed'])) || typeof value.replayed !== 'boolean' ||
    value.replayed && value.secret !== undefined || !value.replayed && (typeof value.secret !== 'string' || !secretPattern.test(value.secret))) {
    throw invalidResponse()
  }
  return { policy: parsePolicy(value.policy), replayed: value.replayed, ...(typeof value.secret === 'string' ? { secret: value.secret } : {}) }
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) {
    throw await responseApiError(response)
  }
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

function query(filters: URLAuthPolicyFilters): string {
  const values = new URLSearchParams({ page: String(filters.page), limit: String(filters.limit) })
  if (filters.name) values.set('name', filters.name)
  if (filters.status) values.set('status', filters.status)
  if (filters.site_id) values.set('site_id', filters.site_id)
  return values.toString()
}

function headers(idempotencyKey: string, version?: number): HeadersInit {
  return {
    'Idempotency-Key': idempotencyKey,
    ...(version ? { 'If-Match': `"${version}"` } : {}),
  }
}

async function list(accessToken: string, filters: URLAuthPolicyFilters): Promise<URLAuthPolicyList> {
  return parseList(await request(accessToken, `/v1/url-auth-policies?${query(filters)}`))
}

async function create(
  accessToken: string,
  input: URLAuthPolicyFields & { target_scope_id?: string; owner_id?: string },
  idempotencyKey: string,
): Promise<URLAuthSecretWriteResult> {
  return parseSecretWrite(await request(accessToken, '/v1/url-auth-policies', {
    method: 'POST', headers: headers(idempotencyKey), body: JSON.stringify(input),
  }))
}

async function update(
  accessToken: string, id: string, version: number, input: URLAuthPolicyFields,
  idempotencyKey: string,
): Promise<URLAuthWriteResult> {
  return parseWrite(await request(accessToken, `/v1/url-auth-policies/${encodeURIComponent(id)}`, {
    method: 'PATCH', headers: headers(idempotencyKey, version), body: JSON.stringify(input),
  }))
}

async function rotate(
  accessToken: string, id: string, version: number, idempotencyKey: string,
): Promise<URLAuthSecretWriteResult> {
  return parseSecretWrite(await request(accessToken, `/v1/url-auth-policies/${encodeURIComponent(id)}/rotate`, {
    method: 'POST', headers: headers(idempotencyKey, version), body: '{}',
  }))
}

async function revoke(
  accessToken: string, id: string, version: number, keyID: string, idempotencyKey: string,
): Promise<URLAuthWriteResult> {
  return parseWrite(await request(accessToken, `/v1/url-auth-policies/${encodeURIComponent(id)}/revoke`, {
    method: 'POST', headers: headers(idempotencyKey, version), body: JSON.stringify({ key_id: keyID }),
  }))
}

async function setEnabled(
  accessToken: string, id: string, version: number, enabled: boolean, idempotencyKey: string,
): Promise<URLAuthWriteResult> {
  const action = enabled ? 'enable' : 'disable'
  return parseWrite(await request(accessToken, `/v1/url-auth-policies/${encodeURIComponent(id)}/${action}`, {
    method: 'POST', headers: headers(idempotencyKey, version), body: '{}',
  }))
}

const enable = (accessToken: string, id: string, version: number, idempotencyKey: string) =>
  setEnabled(accessToken, id, version, true, idempotencyKey)
const disable = (accessToken: string, id: string, version: number, idempotencyKey: string) =>
  setEnabled(accessToken, id, version, false, idempotencyKey)

export const urlAuthPoliciesApi = { create, disable, enable, list, revoke, rotate, update }
