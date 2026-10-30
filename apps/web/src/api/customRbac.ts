import { ApiError, networkApiError } from './auth'

export interface CustomRbacRole {
  id: string
  name: string
  current_revision: number
  permissions: string[]
  deactivated_at?: string
  created_at: string
  replayed?: boolean
}

export interface CustomRbacPermission {
  name: string
  step_up_required: boolean
}

export interface CustomRbacGrant {
  id: string
  role_id: string
  role_revision: number
  subject_user_id: string
  granted_by_user_id: string
  granted_at: string
  revoked_at?: string
  replayed?: boolean
}

export interface CustomRbacRevocation {
  id: string
  grant_id: string
  revoked_by_user_id: string
  revoked_at: string
  replayed?: boolean
}

export interface CustomRbacPage { next_cursor?: string }
export interface CustomRbacRolePage { data: CustomRbacRole[]; page: CustomRbacPage }
export interface CustomRbacPermissionCatalog { data: CustomRbacPermission[] }
export interface CustomRbacGrantPage { data: CustomRbacGrant[]; page: CustomRbacPage }
export interface CustomRbacRoleListParams { limit?: number; cursor?: string; includeDeactivated?: boolean }
export interface CustomRbacGrantListParams {
  limit?: number
  cursor?: string
  roleId?: string
  subjectUserId?: string
  state?: 'active' | 'revoked' | 'all'
}
export interface CustomRbacWriteMetadata {
  idempotencyKey: string
  requestId: string
  traceparent: string
  stepUpProof?: string
}
export interface CustomRbacRoleInput { name: string; permissions: readonly string[] }
export interface CustomRbacRenameInput { name: string }
export interface CustomRbacPublishInput { permissions: readonly string[] }
export interface CustomRbacAssignInput { role_id: string; subject_user_id: string }

interface RoleEnvelope { data: CustomRbacRole }
interface GrantEnvelope { data: CustomRbacGrant }
interface RevocationEnvelope { data: CustomRbacRevocation }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const permissionPattern = /^[a-z][a-z0-9._:-]{0,127}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const requestIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const traceparentPattern = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/
const stepUpPattern = /^[A-Za-z0-9_-]{43}$/
const customErrorPattern = /^custom_rbac_[a-z0-9_]+$/
const grantStates = new Set(['active', 'revoked', 'all'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (!isRecord(value)) return false
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function optional(value: Record<string, unknown>, key: string, validate: (item: unknown) => boolean): boolean {
  return !Object.prototype.hasOwnProperty.call(value, key) || validate(value[key])
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function dateTime(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value)
  if (!match) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const offsetHour = match[8] === undefined ? 0 : Number(match[8])
  const offsetMinute = match[9] === undefined ? 0 : Number(match[9])
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return month >= 1 && month <= 12 && day >= 1 && day <= monthDays[month - 1]! &&
    hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59 &&
    Number.isFinite(Date.parse(value))
}

function permissionList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= 128 &&
    value.every((item) => typeof item === 'string' && permissionPattern.test(item)) &&
    new Set(value).size === value.length
}

function isRole(value: unknown): value is CustomRbacRole {
  return exactRecord(value, ['id', 'name', 'current_revision', 'permissions', 'created_at'], ['deactivated_at', 'replayed']) &&
    uuid(value.id) && typeof value.name === 'string' && value.name.length >= 1 && value.name.length <= 128 &&
    positiveInteger(value.current_revision) && permissionList(value.permissions) && dateTime(value.created_at) &&
    optional(value, 'deactivated_at', dateTime) && optional(value, 'replayed', (item) => typeof item === 'boolean')
}

function isPermission(value: unknown): value is CustomRbacPermission {
  return exactRecord(value, ['name', 'step_up_required']) && typeof value.name === 'string' &&
    permissionPattern.test(value.name) && typeof value.step_up_required === 'boolean'
}

function isGrant(value: unknown): value is CustomRbacGrant {
  return exactRecord(value, [
    'id', 'role_id', 'role_revision', 'subject_user_id', 'granted_by_user_id', 'granted_at',
  ], ['revoked_at', 'replayed']) && uuid(value.id) && uuid(value.role_id) && positiveInteger(value.role_revision) &&
    uuid(value.subject_user_id) && uuid(value.granted_by_user_id) && dateTime(value.granted_at) &&
    optional(value, 'revoked_at', dateTime) && optional(value, 'replayed', (item) => typeof item === 'boolean')
}

function isRevocation(value: unknown): value is CustomRbacRevocation {
  return exactRecord(value, ['id', 'grant_id', 'revoked_by_user_id', 'revoked_at'], ['replayed']) &&
    uuid(value.id) && uuid(value.grant_id) && uuid(value.revoked_by_user_id) && dateTime(value.revoked_at) &&
    optional(value, 'replayed', (item) => typeof item === 'boolean')
}

function isPage(value: unknown): value is CustomRbacPage {
  return exactRecord(value, [], ['next_cursor']) && optional(value, 'next_cursor', (item) => (
    typeof item === 'string' && item.length >= 1 && item.length <= 4096
  ))
}

function isRoleEnvelope(value: unknown): value is RoleEnvelope {
  return exactRecord(value, ['data']) && isRole(value.data)
}

function isRolePage(value: unknown): value is CustomRbacRolePage {
  return exactRecord(value, ['data', 'page']) && Array.isArray(value.data) && value.data.every(isRole) && isPage(value.page)
}

function isPermissionCatalog(value: unknown): value is CustomRbacPermissionCatalog {
  return exactRecord(value, ['data']) && Array.isArray(value.data) && value.data.every(isPermission)
}

function isGrantEnvelope(value: unknown): value is GrantEnvelope {
  return exactRecord(value, ['data']) && isGrant(value.data)
}

function isGrantPage(value: unknown): value is CustomRbacGrantPage {
  return exactRecord(value, ['data', 'page']) && Array.isArray(value.data) && value.data.every(isGrant) && isPage(value.page)
}

function isRevocationEnvelope(value: unknown): value is RevocationEnvelope {
  return exactRecord(value, ['data']) && isRevocation(value.data)
}

function validationError(): ApiError {
  return new ApiError('Invalid custom RBAC request', 400, 'custom_rbac_validation_error')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid custom RBAC response', 502, 'custom_rbac_invalid_response')
}

function unknownWrite(status: number, requestId?: string): ApiError {
  return new ApiError('Custom RBAC write outcome is unknown', status, 'custom_rbac_write_unknown', requestId)
}

function confirmedWrite<T>(value: T, matchesRequest: (value: T) => boolean): T {
  if (!matchesRequest(value)) throw unknownWrite(502)
  return value
}

function samePermissions(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && expected.every((permission) => actual.includes(permission))
}

function validateToken(token: string): void {
  if (typeof token !== 'string' || token.length < 1 || /\s/.test(token)) throw validationError()
}

function validateMetadata(value: unknown): asserts value is CustomRbacWriteMetadata {
  if (!exactRecord(value, ['idempotencyKey', 'requestId', 'traceparent'], ['stepUpProof']) ||
    typeof value.idempotencyKey !== 'string' || !idempotencyPattern.test(value.idempotencyKey) ||
    typeof value.requestId !== 'string' || !requestIDPattern.test(value.requestId) ||
    typeof value.traceparent !== 'string' || !traceparentPattern.test(value.traceparent) ||
    !optional(value, 'stepUpProof', (item) => typeof item === 'string' && stepUpPattern.test(item))) {
    throw validationError()
  }
}

function validatePagination(limit: unknown, cursor: unknown): void {
  if (limit !== undefined && (!Number.isSafeInteger(limit) || Number(limit) < 1 || Number(limit) > 100)) throw validationError()
  if (cursor !== undefined && (typeof cursor !== 'string' || cursor.length < 1 || cursor.length > 4096)) throw validationError()
}

function validateRoleInput(value: unknown): asserts value is CustomRbacRoleInput {
  if (!exactRecord(value, ['name', 'permissions']) || typeof value.name !== 'string' ||
    value.name.length < 1 || value.name.length > 128 || !permissionList(value.permissions)) throw validationError()
}

function validateRenameInput(value: unknown): asserts value is CustomRbacRenameInput {
  if (!exactRecord(value, ['name']) || typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 128) {
    throw validationError()
  }
}

function validatePublishInput(value: unknown): asserts value is CustomRbacPublishInput {
  if (!exactRecord(value, ['permissions']) || !permissionList(value.permissions)) throw validationError()
}

function validateAssignInput(value: unknown): asserts value is CustomRbacAssignInput {
  if (!exactRecord(value, ['role_id', 'subject_user_id']) || !uuid(value.role_id) || !uuid(value.subject_user_id)) {
    throw validationError()
  }
}

async function apiError(response: Response): Promise<ApiError> {
  const value: unknown = await response.json().catch(() => undefined)
  if (!exactRecord(value, ['error']) || !exactRecord(value.error, ['code', 'message', 'request_id']) ||
    typeof value.error.code !== 'string' || !customErrorPattern.test(value.error.code) ||
    typeof value.error.message !== 'string' || value.error.message.length < 1 || value.error.message.length > 256) {
    return new ApiError('API request failed', response.status, 'request_failed')
  }
  const requestId = typeof value.error.request_id === 'string' && requestIDPattern.test(value.error.request_id)
    ? value.error.request_id
    : undefined
  return new ApiError('API request failed', response.status, value.error.code, requestId)
}

function headers(token: string, metadata?: CustomRbacWriteMetadata, body = false, revision?: number): HeadersInit {
  return {
    Authorization: `Bearer ${token}`,
    ...(body ? { 'Content-Type': 'application/json' } : {}),
    ...(metadata ? {
      'Idempotency-Key': metadata.idempotencyKey,
      'X-Request-ID': metadata.requestId,
      Traceparent: metadata.traceparent,
      ...(metadata.stepUpProof === undefined ? {} : { 'X-Step-Up-Proof': metadata.stepUpProof }),
    } : {}),
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

function isJSON(response: Response): boolean {
  return response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json'
}

async function read<T>(token: string, path: string, validate: (value: unknown) => value is T): Promise<T> {
  validateToken(token)
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, { credentials: 'include', headers: headers(token) })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await apiError(response)
  if (response.status !== 200 || !isJSON(response)) throw invalidResponse()
  const value: unknown = await response.json().catch(() => undefined)
  if (!validate(value)) throw invalidResponse()
  return value
}

async function write<T>(
  token: string,
  path: string,
  expectedStatus: number,
  validate: (value: unknown) => value is T,
  metadata: CustomRbacWriteMetadata,
  body?: unknown,
  revision?: number,
): Promise<T> {
  validateToken(token)
  validateMetadata(metadata)
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: headers(token, metadata, body !== undefined, revision),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  } catch {
    throw unknownWrite(0)
  }
  if (!response.ok) {
    const error = await apiError(response)
    if (response.status === 408 || response.status >= 500) throw unknownWrite(response.status, error.requestId)
    throw error
  }
  if (response.status !== expectedStatus || !isJSON(response)) throw unknownWrite(502)
  const value: unknown = await response.json().catch(() => undefined)
  if (!validate(value)) throw unknownWrite(502)
  return value
}

function pathWithQuery(path: string, query: URLSearchParams): string {
  const suffix = query.toString()
  return suffix ? `${path}?${suffix}` : path
}

export const customRbacApi = {
  async listRoles(token: string, params: CustomRbacRoleListParams = {}): Promise<CustomRbacRolePage> {
    if (!exactRecord(params as unknown, [], ['limit', 'cursor', 'includeDeactivated'])) throw validationError()
    validatePagination(params.limit, params.cursor)
    if (params.includeDeactivated !== undefined && typeof params.includeDeactivated !== 'boolean') throw validationError()
    const query = new URLSearchParams()
    if (params.limit !== undefined) query.set('limit', String(params.limit))
    if (params.cursor !== undefined) query.set('cursor', params.cursor)
    if (params.includeDeactivated !== undefined) query.set('include_deactivated', String(params.includeDeactivated))
    return read(token, pathWithQuery('/v1/custom-rbac/roles', query), isRolePage)
  },

  async listPermissions(token: string): Promise<CustomRbacPermissionCatalog> {
    return read(token, '/v1/custom-rbac/permissions', isPermissionCatalog)
  },

  async getRole(token: string, roleID: string): Promise<CustomRbacRole> {
    if (!uuid(roleID)) throw validationError()
    return (await read(token, `/v1/custom-rbac/roles/${encodeURIComponent(roleID)}`, isRoleEnvelope)).data
  },

  async createRole(token: string, input: CustomRbacRoleInput, metadata: CustomRbacWriteMetadata): Promise<CustomRbacRole> {
    validateRoleInput(input)
    const result = (await write(token, '/v1/custom-rbac/roles', 201, isRoleEnvelope, metadata, input)).data
    return confirmedWrite(result, (role) => role.name === input.name.trim().toLowerCase() &&
      role.current_revision === 1 && role.deactivated_at === undefined &&
      samePermissions(role.permissions, input.permissions))
  },

  async renameRole(token: string, roleID: string, revision: number, input: CustomRbacRenameInput, metadata: CustomRbacWriteMetadata): Promise<CustomRbacRole> {
    if (!uuid(roleID) || !positiveInteger(revision)) throw validationError()
    validateRenameInput(input)
    const result = (await write(token, `/v1/custom-rbac/roles/${encodeURIComponent(roleID)}/rename`, 200, isRoleEnvelope, metadata, input, revision)).data
    return confirmedWrite(result, (role) => role.id === roleID && role.current_revision === revision + 1 &&
      role.name === input.name.trim().toLowerCase() && role.deactivated_at === undefined)
  },

  async publishRole(token: string, roleID: string, revision: number, input: CustomRbacPublishInput, metadata: CustomRbacWriteMetadata): Promise<CustomRbacRole> {
    if (!uuid(roleID) || !positiveInteger(revision)) throw validationError()
    validatePublishInput(input)
    const result = (await write(token, `/v1/custom-rbac/roles/${encodeURIComponent(roleID)}/publish`, 200, isRoleEnvelope, metadata, input, revision)).data
    return confirmedWrite(result, (role) => role.id === roleID && role.current_revision === revision + 1 &&
      role.deactivated_at === undefined && samePermissions(role.permissions, input.permissions))
  },

  async deactivateRole(token: string, roleID: string, revision: number, metadata: CustomRbacWriteMetadata): Promise<CustomRbacRole> {
    if (!uuid(roleID) || !positiveInteger(revision)) throw validationError()
    const result = (await write(token, `/v1/custom-rbac/roles/${encodeURIComponent(roleID)}/deactivate`, 200, isRoleEnvelope, metadata, undefined, revision)).data
    return confirmedWrite(result, (role) => role.id === roleID && role.current_revision === revision &&
      role.deactivated_at !== undefined)
  },

  async listGrants(token: string, params: CustomRbacGrantListParams = {}): Promise<CustomRbacGrantPage> {
    if (!exactRecord(params as unknown, [], ['limit', 'cursor', 'roleId', 'subjectUserId', 'state'])) throw validationError()
    validatePagination(params.limit, params.cursor)
    if (params.roleId !== undefined && !uuid(params.roleId)) throw validationError()
    if (params.subjectUserId !== undefined && !uuid(params.subjectUserId)) throw validationError()
    if (params.state !== undefined && !grantStates.has(params.state)) throw validationError()
    const query = new URLSearchParams()
    if (params.limit !== undefined) query.set('limit', String(params.limit))
    if (params.cursor !== undefined) query.set('cursor', params.cursor)
    if (params.roleId !== undefined) query.set('role_id', params.roleId)
    if (params.subjectUserId !== undefined) query.set('subject_user_id', params.subjectUserId)
    if (params.state !== undefined) query.set('state', params.state)
    return read(token, pathWithQuery('/v1/custom-rbac/grants', query), isGrantPage)
  },

  async assignGrant(token: string, revision: number, input: CustomRbacAssignInput, metadata: CustomRbacWriteMetadata): Promise<CustomRbacGrant> {
    if (!positiveInteger(revision)) throw validationError()
    validateAssignInput(input)
    const result = (await write(token, '/v1/custom-rbac/grants', 201, isGrantEnvelope, metadata, input, revision)).data
    return confirmedWrite(result, (grant) => grant.role_id === input.role_id &&
      grant.role_revision === revision && grant.subject_user_id === input.subject_user_id &&
      grant.revoked_at === undefined)
  },

  async revokeGrant(token: string, grantID: string, metadata: CustomRbacWriteMetadata): Promise<CustomRbacRevocation> {
    if (!uuid(grantID)) throw validationError()
    const result = (await write(token, `/v1/custom-rbac/grants/${encodeURIComponent(grantID)}/revoke`, 200, isRevocationEnvelope, metadata)).data
    return confirmedWrite(result, (revocation) => revocation.grant_id === grantID)
  },
}
