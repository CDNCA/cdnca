import { ApiError, networkApiError } from './auth'

export type CnameAllocationMode = 'site' | 'package'
export type CnameAllocationState = 'pending' | 'failed' | 'done'
export type CnameAllocationAudience = { kind: 'tenant' } | { kind: 'platform'; scopeID: string }

export interface CnameAllocation {
  id: string
  mode: CnameAllocationMode
  owner_id: string
  provider_id: string
  zone_id: string
  domain: string
  hostname: string
  explicit_hostname: boolean
  state: CnameAllocationState
  failure_code?: string
  job_id: string
  generation: number
  current_revision: number
  lkg_revision?: number
  created_at: string
  updated_at: string
}

export interface CnameAllocationPage {
  items: CnameAllocation[]
  next_cursor?: string
}

export interface CnameAllocationDiagnosis {
  site_id: string
  mode?: CnameAllocationMode
  owner_id?: string
  allocation_id?: string
  binding_allocation_id?: string
  lkg_allocation_id?: string
  provider_id?: string
  zone_id?: string
  domain?: string
  hostname?: string
  state?: CnameAllocationState
  ready: boolean
  reason_codes: string[]
}

export interface CnameAllocationListParams {
  limit?: number
  cursor?: string
}

export interface CnameAllocationDiagnosisParams {
  siteID: string
  domain?: string
  hostname?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/
const codePattern = /^[a-z][a-z0-9_]{0,127}$/
const requestIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const errorCodes = new Set([
  'validation_error', 'invalid_session', 'permission_denied', 'cname_allocation_not_found',
  'method_not_allowed', 'request_timeout', 'cname_allocation_unavailable',
])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function isUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
}

function isName(value: unknown, required = false): value is string {
  return typeof value === 'string' && (!required || value.length > 0) && value.length <= 253 &&
    value === value.trim() && value === value.toLowerCase() && !/[\s]/.test(value) &&
    !value.startsWith('.') && !value.endsWith('.')
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false
  const match = timestampPattern.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)))
  return calendar.getUTCFullYear() === Number(year) && calendar.getUTCMonth() === Number(month) - 1 &&
    calendar.getUTCDate() === Number(day) && Number(hour) <= 23 && Number(minute) <= 59 &&
    Number(second) <= 59 && Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) && Number.isFinite(Date.parse(value))
}

function isMode(value: unknown): value is CnameAllocationMode {
  return value === 'site' || value === 'package'
}

function isState(value: unknown): value is CnameAllocationState {
  return value === 'pending' || value === 'failed' || value === 'done'
}

function isAllocation(value: unknown): value is CnameAllocation {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'mode', 'owner_id', 'provider_id', 'zone_id', 'domain', 'hostname',
    'explicit_hostname', 'state', 'job_id', 'generation', 'current_revision', 'created_at', 'updated_at',
  ], ['failure_code', 'lkg_revision'])) return false
  return isUUID(value.id) && isMode(value.mode) && isUUID(value.owner_id) && isUUID(value.provider_id) &&
    isUUID(value.zone_id) && isName(value.domain, true) && isName(value.hostname, true) &&
    typeof value.explicit_hostname === 'boolean' && isState(value.state) &&
    (value.failure_code === undefined || (typeof value.failure_code === 'string' && codePattern.test(value.failure_code))) &&
    isUUID(value.job_id) && isPositiveInteger(value.generation) && isPositiveInteger(value.current_revision) &&
    (value.lkg_revision === undefined || (isPositiveInteger(value.lkg_revision) && value.lkg_revision <= value.current_revision)) &&
    isTimestamp(value.created_at) && isTimestamp(value.updated_at) &&
    Date.parse(value.updated_at) >= Date.parse(value.created_at)
}

function isPage(value: unknown): value is CnameAllocationPage {
  return isRecord(value) && exactKeys(value, ['items'], ['next_cursor']) && Array.isArray(value.items) &&
    value.items.length <= 100 && value.items.every(isAllocation) &&
    (value.next_cursor === undefined || isUUID(value.next_cursor))
}

function isDiagnosis(value: unknown): value is CnameAllocationDiagnosis {
  if (!isRecord(value) || !exactKeys(value, ['site_id', 'ready', 'reason_codes'], [
    'mode', 'owner_id', 'allocation_id', 'binding_allocation_id', 'lkg_allocation_id',
    'provider_id', 'zone_id', 'domain', 'hostname', 'state',
  ])) return false
  const ids = ['owner_id', 'allocation_id', 'binding_allocation_id', 'lkg_allocation_id', 'provider_id', 'zone_id'] as const
  return isUUID(value.site_id) && (value.mode === undefined || isMode(value.mode)) &&
    ids.every((key) => value[key] === undefined || isUUID(value[key])) &&
    (value.domain === undefined || isName(value.domain)) && (value.hostname === undefined || isName(value.hostname)) &&
    (value.state === undefined || isState(value.state)) && typeof value.ready === 'boolean' &&
    Array.isArray(value.reason_codes) && value.reason_codes.length >= 1 && value.reason_codes.length <= 32 &&
    value.reason_codes.every((code) => typeof code === 'string' && codePattern.test(code))
}

function validationError() {
  return new ApiError('Invalid CNAME allocation request', 400, 'cname_allocation_validation_error')
}

function invalidResponse() {
  return new ApiError('Invalid CNAME allocation response', 502, 'cname_allocation_invalid_response')
}

function validToken(value: string) {
  return value.length >= 1 && value.length <= 8192 && !/\s/.test(value)
}

function audiencePath(audience: CnameAllocationAudience): { path: string; scope?: string } {
  if (!isRecord(audience)) throw validationError()
  if (audience.kind === 'tenant' && exactKeys(audience, ['kind'])) return { path: '/v1/cname-allocations' }
  if (audience.kind === 'platform' && exactKeys(audience, ['kind', 'scopeID']) && isUUID(audience.scopeID)) {
    return { path: '/v1/admin/cname-allocations', scope: audience.scopeID }
  }
  throw validationError()
}

function queryFor(audience: CnameAllocationAudience, values: Array<[string, string | number | undefined]>) {
  const target = audiencePath(audience)
  const query = new URLSearchParams()
  if (target.scope) query.set('scope_id', target.scope)
  for (const [key, value] of values) if (value !== undefined) query.set(key, String(value))
  return { path: target.path, query: query.size ? `?${query}` : '' }
}

async function responseError(response: Response): Promise<ApiError> {
  if (response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    return new ApiError('API request failed', response.status, 'request_failed')
  }
  const body: unknown = await response.json().catch(() => null)
  if (!isRecord(body) || !exactKeys(body, ['error']) || !isRecord(body.error) ||
    !exactKeys(body.error, ['code', 'message', 'request_id']) ||
    typeof body.error.code !== 'string' || !errorCodes.has(body.error.code) ||
    typeof body.error.message !== 'string' || typeof body.error.request_id !== 'string' ||
    !requestIDPattern.test(body.error.request_id)) {
    return new ApiError('API request failed', response.status, 'request_failed')
  }
  return new ApiError('API request failed', response.status, body.error.code, body.error.request_id)
}

async function request<T>(token: string, path: string, validator: (value: unknown) => value is T): Promise<T> {
  if (!validToken(token)) throw validationError()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseError(response)
  if (response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') throw invalidResponse()
  const value: unknown = await response.json().catch(() => null)
  if (!validator(value)) throw invalidResponse()
  return value
}

export const cnameAllocationsApi = {
  async list(token: string, audience: CnameAllocationAudience, params: CnameAllocationListParams = {}) {
    if (!isRecord(params) || !exactKeys(params, [], ['limit', 'cursor']) ||
      (params.limit !== undefined && (!isPositiveInteger(params.limit) || params.limit > 100)) ||
      (params.cursor !== undefined && !isUUID(params.cursor))) throw validationError()
    const target = queryFor(audience, [['limit', params.limit], ['cursor', params.cursor]])
    return request(token, `${target.path}${target.query}`, isPage)
  },
  async get(token: string, audience: CnameAllocationAudience, allocationID: string) {
    if (!isUUID(allocationID)) throw validationError()
    const target = queryFor(audience, [])
    return request(token, `${target.path}/${allocationID}${target.query}`, isAllocation)
  },
  async diagnose(token: string, audience: CnameAllocationAudience, params: CnameAllocationDiagnosisParams) {
    if (!isRecord(params) || !exactKeys(params, ['siteID'], ['domain', 'hostname']) || !isUUID(params.siteID) ||
      (params.domain !== undefined && !isName(params.domain, true)) ||
      (params.hostname !== undefined && !isName(params.hostname, true))) throw validationError()
    const target = queryFor(audience, [
      ['site_id', params.siteID], ['domain', params.domain], ['hostname', params.hostname],
    ])
    return request(token, `${target.path}/diagnose${target.query}`, isDiagnosis)
  },
}
