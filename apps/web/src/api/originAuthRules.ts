import { ApiError, networkApiError } from './auth'

export type OriginAuthProvider = 's3' | 'oss' | 'cos'
export type OriginAuthAlgorithm = 'aws4-hmac-sha256' | 'oss4-hmac-sha256' | 'cos-hmac-sha1'

export interface OriginAuthCredentialReference {
  credential_id: string
  revision: number
}

export interface OriginAuthRuleConfig {
  provider: OriginAuthProvider
  algorithm: OriginAuthAlgorithm
  endpoint: string
  bucket: string
  path_prefix: string
  region: string
  service: string
  signature_ttl_seconds: number
  egress_policy_reference?: string
  current_credential: OriginAuthCredentialReference
  previous_credential?: OriginAuthCredentialReference
  activate_current_at?: string
}

export interface OriginAuthRule extends OriginAuthRuleConfig {
  id: string
  tenant_scope_id: string
  site_id: string
  source_position: number
  enabled: boolean
  deleted: boolean
  revision: number
  created_at: string
  updated_at: string
}

export interface OriginAuthRulePage {
  items: OriginAuthRule[]
  next_cursor?: string
}

export interface OriginAuthRuleListParams {
  siteID?: string
  enabled?: boolean
  limit?: number
  cursor?: string
}

export interface CreateOriginAuthRuleInput {
  site_id: string
  source_position: number
  config: OriginAuthRuleConfig
  enabled: boolean
}

export interface UpdateOriginAuthRuleInput {
  config: OriginAuthRuleConfig
}

export interface RotateOriginAuthRuleInput {
  current_credential: OriginAuthCredentialReference
  activate_current_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const stableCodePattern = /^[a-z][a-z0-9_]{0,63}$/
const requestIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key))
}

function positiveInteger(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= max
}

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)) && /(?:Z|[+-]\d\d:\d\d)$/.test(value)
}

function validToken(value: string) {
  return value.length >= 1 && value.length <= 8192 && !/\s/.test(value)
}

function isProvider(value: unknown): value is OriginAuthProvider {
  return value === 's3' || value === 'oss' || value === 'cos'
}

function isAlgorithm(value: unknown): value is OriginAuthAlgorithm {
  return value === 'aws4-hmac-sha256' || value === 'oss4-hmac-sha256' || value === 'cos-hmac-sha1'
}

function isCredentialReference(value: unknown): value is OriginAuthCredentialReference {
  return isRecord(value) && exactKeys(value, ['credential_id', 'revision']) &&
    typeof value.credential_id === 'string' && uuidPattern.test(value.credential_id) &&
    positiveInteger(value.revision)
}

function isEndpoint(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 512) return false
  try {
    const endpoint = new URL(value)
    return endpoint.protocol === 'https:' && endpoint.username === '' && endpoint.password === '' &&
      (endpoint.port === '' || endpoint.port === '443') && endpoint.pathname === '/' &&
      endpoint.search === '' && endpoint.hash === ''
  } catch {
    return false
  }
}

function isConfig(value: unknown): value is OriginAuthRuleConfig {
  if (!isRecord(value) || !exactKeys(value, [
    'provider', 'algorithm', 'endpoint', 'bucket', 'path_prefix', 'region', 'service',
    'signature_ttl_seconds', 'current_credential',
  ], ['egress_policy_reference', 'previous_credential', 'activate_current_at'])) return false
  return isProvider(value.provider) && isAlgorithm(value.algorithm) && isEndpoint(value.endpoint) &&
    typeof value.bucket === 'string' && value.bucket.length <= 63 &&
    typeof value.path_prefix === 'string' && value.path_prefix.length >= 1 && value.path_prefix.length <= 2048 &&
    typeof value.region === 'string' && value.region.length >= 2 && value.region.length <= 64 &&
    typeof value.service === 'string' && value.service.length >= 2 && value.service.length <= 64 &&
    positiveInteger(value.signature_ttl_seconds, 3600) && isCredentialReference(value.current_credential) &&
    (value.egress_policy_reference === undefined || (
      typeof value.egress_policy_reference === 'string' && value.egress_policy_reference.length <= 128
    )) && (value.previous_credential === undefined || isCredentialReference(value.previous_credential)) &&
    (value.activate_current_at === undefined || validTimestamp(value.activate_current_at))
}

function isRule(value: unknown): value is OriginAuthRule {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'tenant_scope_id', 'site_id', 'source_position', 'provider', 'algorithm', 'endpoint',
    'bucket', 'path_prefix', 'region', 'service', 'signature_ttl_seconds', 'current_credential',
    'enabled', 'deleted', 'revision', 'created_at', 'updated_at',
  ], ['egress_policy_reference', 'previous_credential', 'activate_current_at'])) return false
  const config = {
    provider: value.provider,
    algorithm: value.algorithm,
    endpoint: value.endpoint,
    bucket: value.bucket,
    path_prefix: value.path_prefix,
    region: value.region,
    service: value.service,
    signature_ttl_seconds: value.signature_ttl_seconds,
    ...(value.egress_policy_reference === undefined ? {} : { egress_policy_reference: value.egress_policy_reference }),
    current_credential: value.current_credential,
    ...(value.previous_credential === undefined ? {} : { previous_credential: value.previous_credential }),
    ...(value.activate_current_at === undefined ? {} : { activate_current_at: value.activate_current_at }),
  }
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    positiveInteger(value.source_position, 32) && isConfig(config) &&
    typeof value.enabled === 'boolean' && typeof value.deleted === 'boolean' &&
    positiveInteger(value.revision) && validTimestamp(value.created_at) && validTimestamp(value.updated_at)
}

function validationError() {
  return new ApiError('Invalid origin authentication request', 400, 'origin_auth_validation_error')
}

function invalidResponse(code = 'origin_auth_invalid_response') {
  return new ApiError('Invalid origin authentication response', 502, code)
}

async function responseError(response: Response): Promise<ApiError> {
  const body: unknown = await response.json().catch(() => null)
  if (!isRecord(body) || !exactKeys(body, ['error']) || !isRecord(body.error) ||
    !exactKeys(body.error, ['code', 'message', 'request_id', 'trace_id']) ||
    typeof body.error.code !== 'string' || !stableCodePattern.test(body.error.code) ||
    typeof body.error.request_id !== 'string' || !requestIDPattern.test(body.error.request_id)) {
    return new ApiError('API request failed', response.status, 'request_failed')
  }
  return new ApiError('API request failed', response.status, body.error.code, body.error.request_id)
}

async function requestOriginAuthRule(path: string, token: string, init: RequestInit = {}): Promise<unknown> {
  if (!validToken(token)) throw validationError()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseError(response)
  return response.json().catch(() => { throw invalidResponse() })
}

function assertScope(scopeID: string) {
  if (!uuidPattern.test(scopeID)) throw validationError()
}

function assertRule(rule: unknown, scopeID: string, ruleID?: string): OriginAuthRule {
  if (!isRule(rule)) throw invalidResponse()
  if (rule.tenant_scope_id !== scopeID || (ruleID !== undefined && rule.id !== ruleID)) {
    throw invalidResponse('origin_auth_scope_mismatch')
  }
  return rule
}

export async function listOriginAuthRules(
  token: string,
  scopeID: string,
  params: OriginAuthRuleListParams = {},
): Promise<OriginAuthRulePage> {
  assertScope(scopeID)
  const rawParams = params as unknown as Record<string, unknown>
  if (!exactKeys(rawParams, [], ['siteID', 'enabled', 'limit', 'cursor']) ||
    (params.siteID !== undefined && !uuidPattern.test(params.siteID)) ||
    (params.enabled !== undefined && typeof params.enabled !== 'boolean') ||
    (params.limit !== undefined && !positiveInteger(params.limit, 100)) ||
    (params.cursor !== undefined && (params.cursor.length < 1 || params.cursor.length > 512))) throw validationError()
  const query = new URLSearchParams()
  if (params.siteID) query.set('site_id', params.siteID)
  if (params.enabled !== undefined) query.set('enabled', String(params.enabled))
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.cursor) query.set('cursor', params.cursor)
  const suffix = query.size ? `?${query}` : ''
  const body = await requestOriginAuthRule(`/v1/tenant-scopes/${scopeID}/origin-auth/rules${suffix}`, token)
  if (!isRecord(body) || !exactKeys(body, ['items'], ['next_cursor']) || !Array.isArray(body.items) ||
    body.items.length > 100 || (body.next_cursor !== undefined && (
      typeof body.next_cursor !== 'string' || body.next_cursor.length < 1 || body.next_cursor.length > 512
    ))) throw invalidResponse()
  return {
    items: body.items.map((item) => assertRule(item, scopeID)),
    ...(typeof body.next_cursor === 'string' ? { next_cursor: body.next_cursor } : {}),
  }
}

export async function getOriginAuthRule(token: string, scopeID: string, ruleID: string) {
  assertScope(scopeID)
  if (!uuidPattern.test(ruleID)) throw validationError()
  return assertRule(await requestOriginAuthRule(
    `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}`, token,
  ), scopeID, ruleID)
}

function writeHeaders(key: string, revision?: number) {
  if (!requestIDPattern.test(key) || (revision !== undefined && !positiveInteger(revision))) throw validationError()
  return { 'Idempotency-Key': key, ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }) }
}

export async function createOriginAuthRule(
  token: string, scopeID: string, input: CreateOriginAuthRuleInput, key: string,
) {
  assertScope(scopeID)
  if (!isRecord(input) || !exactKeys(input, ['site_id', 'source_position', 'config', 'enabled']) ||
    !uuidPattern.test(input.site_id) || !positiveInteger(input.source_position, 32) ||
    !isConfig(input.config) || typeof input.enabled !== 'boolean') throw validationError()
  return assertRule(await requestOriginAuthRule(`/v1/tenant-scopes/${scopeID}/origin-auth/rules`, token, {
    method: 'POST', headers: writeHeaders(key), body: JSON.stringify(input),
  }), scopeID)
}

export async function updateOriginAuthRule(
  token: string, scopeID: string, ruleID: string, input: UpdateOriginAuthRuleInput,
  revision: number, key: string,
) {
  assertScope(scopeID)
  if (!uuidPattern.test(ruleID) || !isRecord(input) || !exactKeys(input, ['config']) || !isConfig(input.config)) {
    throw validationError()
  }
  return assertRule(await requestOriginAuthRule(`/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}`, token, {
    method: 'PATCH', headers: writeHeaders(key, revision), body: JSON.stringify(input),
  }), scopeID, ruleID)
}

export async function deleteOriginAuthRule(
  token: string, scopeID: string, ruleID: string, revision: number, key: string,
) {
  assertScope(scopeID)
  if (!uuidPattern.test(ruleID)) throw validationError()
  return assertRule(await requestOriginAuthRule(`/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}`, token, {
    method: 'DELETE', headers: writeHeaders(key, revision), body: '{}',
  }), scopeID, ruleID)
}

export async function setOriginAuthRuleEnabled(
  token: string, scopeID: string, ruleID: string, enabled: boolean, revision: number, key: string,
) {
  assertScope(scopeID)
  if (!uuidPattern.test(ruleID) || typeof enabled !== 'boolean') throw validationError()
  return assertRule(await requestOriginAuthRule(
    `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}/${enabled ? 'enable' : 'disable'}`, token, {
      method: 'POST', headers: writeHeaders(key, revision), body: '{}',
    },
  ), scopeID, ruleID)
}

export async function rotateOriginAuthRuleCredential(
  token: string, scopeID: string, ruleID: string, input: RotateOriginAuthRuleInput,
  revision: number, key: string,
) {
  assertScope(scopeID)
  if (!uuidPattern.test(ruleID) || !isRecord(input) ||
    !exactKeys(input, ['current_credential', 'activate_current_at']) ||
    !isCredentialReference(input.current_credential) || !validTimestamp(input.activate_current_at)) throw validationError()
  return assertRule(await requestOriginAuthRule(
    `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}/rotate`, token, {
      method: 'POST', headers: writeHeaders(key, revision), body: JSON.stringify(input),
    },
  ), scopeID, ruleID)
}

export const originAuthRulesApi = {
  list: listOriginAuthRules,
  get: getOriginAuthRule,
  create: createOriginAuthRule,
  update: updateOriginAuthRule,
  remove: deleteOriginAuthRule,
  setEnabled: setOriginAuthRuleEnabled,
  rotate: rotateOriginAuthRuleCredential,
}
