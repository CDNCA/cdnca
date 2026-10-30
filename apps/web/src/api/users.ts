import { ApiError, networkApiError, responseApiError } from './auth'
import { checkPassword } from '@cdnca/ui/password-policy'

export type UserStatus = 'active' | 'disabled'
export type UserRole = 'tenant_owner' | 'tenant_viewer'
// Platform-scope administrators are listed (include_platform_admins) but never re-typed.
export type PlatformUserRole = 'platform_owner' | 'platform_admin'
export type ManagedUserRole = UserRole | PlatformUserRole
export type UserRealNameStatus = 'verified' | 'unverified'

export interface ManagedUserMetadata {
  remark: string | null
  qq: string | null
}

export interface ManagedUserLoginSecurity {
  user_id: string
  tenant_scope_id: string
  revision: number
  login_verification: 'none' | 'sms' | 'email'
  login_allowlist: string[]
}

export interface UpdateUserLoginSecurityRequest {
  expected_revision: number
  login_verification: ManagedUserLoginSecurity['login_verification']
  login_allowlist: string[]
}

// Secondary identity verification (FX57); deadline/requested_at are RFC 3339.
export interface ManagedUserSecondaryVerification {
  user_id: string
  tenant_scope_id: string
  revision: number
  enabled: boolean
  deadline: string | null
  expiry_action: 'none' | 'lock_sites'
  requested_at: string | null
  completed: boolean
  enforced_at: string | null
}

export interface UpdateUserSecondaryVerificationRequest {
  expected_revision: number
  enabled: boolean
  deadline: string | null
  expiry_action: ManagedUserSecondaryVerification['expiry_action']
}

export interface ManagedUser {
  id: string
  display_id: string
  scope_id: string
  tenant_id: string
  username: string
  display_name: string
  email: string | null
  phone: string | null
  status: UserStatus
  role: UserRole
  group_id: string | null
  group_name: string | null
  revision: number
  created_at: string
  updated_at: string
  metadata?: ManagedUserMetadata
  verification?: { personal_verified: boolean; company_verified: boolean }
}

// A platform-scope administrator row of the management user list.
export interface PlatformAdministratorUser extends Omit<ManagedUser, 'tenant_id' | 'role'> {
  tenant_id: null
  role: PlatformUserRole
}

// ListedUser is what the management user list, detail and write responses carry.
export type ListedUser = ManagedUser | PlatformAdministratorUser

export interface ListedUserListResponse {
  items: ListedUser[]
  page: number
  limit: number
  total: number
}

export interface AccountProfile {
  id: string
  username: string
  display_name: string
  email: string | null
  phone: string | null
  revision: number
  created_at: string
  updated_at: string
}

export interface UserListResponse {
  items: ManagedUser[]
  page: number
  limit: number
  total: number
}

export interface UserListParams {
  page: number
  limit: number
  display_id?: string
  search?: string
  username?: string
  display_name?: string
  email?: string
  phone?: string
  status?: UserStatus
  role?: UserRole
  group_id?: string
  remark?: string
  qq?: string
  include_verification?: boolean
  real_name_status?: UserRealNameStatus
  // Management user list only: also project platform-scope administrators.
  include_platform_admins?: boolean
}

export interface CreateUserRequest {
  username: string
  password: string
  display_name: string
  email: string | null
  phone: string | null
  role: UserRole
  group_id: string | null
  remark?: string | null
  qq?: string | null
}

export interface UpdateUserRequest {
  expected_revision: number
  display_name: string
  email: string | null
  phone: string | null
  status: UserStatus
  role: ManagedUserRole
  group_id: string | null
  remark?: string | null
  qq?: string | null
}

export interface ResetManagedUserPasswordRequest {
  user_id: string
  tenant_id: string
  tenant_scope_id: string
  expected_revision: number
  new_password: string
  step_up_token: string
}

export interface UserGroup {
  id: string
  scope_id: string
  name: string
  revision: number
  member_count: number
  created_at: string
  updated_at: string
}

export interface UserGroupListResponse {
  items: UserGroup[]
  page: number
  limit: number
  total: number
}

export interface BatchUpdateUserRequest extends UpdateUserRequest {
  id: string
}

export interface BatchUpdateUserResponse {
  items: ListedUser[]
}

export interface UserWriteMetadata {
  idempotencyKey: string
  requestId: string
  traceparent: string
}

export interface UpdateProfileRequest {
  expected_revision: number
  display_name: string
  // 2026-09-19：联系方式改为部分更新语义，未出现的字段由服务端沿用现值。
  email?: string | null
  phone?: string | null
  current_password?: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const displayIDPattern = /^[1-9][0-9]{0,18}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const traceparentPattern = /^00-(?!0{32}-)[0-9a-f]{32}-(?!0{16}-)[0-9a-f]{16}-(?:00|01)$/
const usernamePattern = /^[a-z0-9][a-z0-9._-]{2,127}$/
const phonePattern = /^\+?[0-9]{6,20}$/

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code <= 0x1f || code >= 0x7f && code <= 0x9f) return true
  }
  return false
}

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('User request was invalid', 400, 'validation_error')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && actual.every((key) => keys.includes(key))
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    !Number.isNaN(Date.parse(value))
}

function nullableEmail(value: unknown): value is string | null {
  return value === null || typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(value)
}

function nullablePhone(value: unknown): value is string | null {
  return value === null || typeof value === 'string' && phonePattern.test(value)
}

export function validUserMetadataValue(value: unknown, field: keyof ManagedUserMetadata): value is string | null {
  if (value === null) return true
  return typeof value === 'string' && [...value.trim()].length <= (field === 'remark' ? 512 : 32) &&
    !hasControlCharacter(field === 'remark' ? value.replace(/[\t\n\r]/g, '') : value)
}

function isPlatformUserRole(value: unknown): value is PlatformUserRole {
  return value === 'platform_owner' || value === 'platform_admin'
}

// Platform-scope administrators carry no tenant and are protected from re-typing,
// grouping, password reset, login-security and impersonation flows.
export function isPlatformAdministrator(user: ListedUser): user is PlatformAdministratorUser {
  return isPlatformUserRole(user.role)
}

function parseManagedUser(value: unknown, expectedID?: string): ManagedUser {
  return parseListedUser(value, expectedID, false) as ManagedUser
}

function parseListedUser(value: unknown, expectedID?: string, allowPlatform = true): ListedUser {
  const keys = [
    'id', 'display_id', 'scope_id', 'tenant_id', 'username', 'display_name', 'email', 'phone', 'status', 'role',
    'group_id', 'group_name', 'revision', 'created_at', 'updated_at',
  ] as const
  if (!record(value) || !(exactKeys(value, keys) || exactKeys(value, [...keys, 'metadata'])) || typeof value.id !== 'string' ||
    !uuidPattern.test(value.id) || expectedID !== undefined && value.id !== expectedID ||
    typeof value.display_id !== 'string' || !displayIDPattern.test(value.display_id) ||
    typeof value.scope_id !== 'string' || !uuidPattern.test(value.scope_id) ||
    !(isPlatformUserRole(value.role) ? value.tenant_id === null
      : typeof value.tenant_id === 'string' && uuidPattern.test(value.tenant_id)) ||
    typeof value.username !== 'string' || !usernamePattern.test(value.username) ||
    typeof value.display_name !== 'string' || !value.display_name.trim() || value.display_name.length > 128 ||
    !nullableEmail(value.email) || !nullablePhone(value.phone) ||
    value.status !== 'active' && value.status !== 'disabled' ||
    value.role !== 'tenant_owner' && value.role !== 'tenant_viewer' && !(allowPlatform && isPlatformUserRole(value.role)) ||
    isPlatformUserRole(value.role) && value.group_id !== null ||
    value.group_id !== null && (typeof value.group_id !== 'string' || !uuidPattern.test(value.group_id)) ||
    value.group_name !== null && (typeof value.group_name !== 'string' || !value.group_name.trim() || value.group_name.length > 128) ||
    (value.group_id === null) !== (value.group_name === null) ||
    typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
    !timestamp(value.created_at) || !timestamp(value.updated_at)) throw invalidResponse()
  let metadata: ManagedUserMetadata | undefined
  if ('metadata' in value) {
    if (!record(value.metadata) || !exactKeys(value.metadata, ['remark', 'qq']) ||
      !validUserMetadataValue(value.metadata.remark, 'remark') || !validUserMetadataValue(value.metadata.qq, 'qq')) throw invalidResponse()
    metadata = { remark: value.metadata.remark, qq: value.metadata.qq }
  }
  return {
    id: value.id,
    display_id: value.display_id,
    scope_id: value.scope_id,
    tenant_id: value.tenant_id,
    username: value.username,
    display_name: value.display_name,
    email: value.email,
    phone: value.phone,
    status: value.status,
    role: value.role,
    group_id: value.group_id,
    group_name: value.group_name,
    revision: value.revision,
    created_at: value.created_at,
    updated_at: value.updated_at,
    ...(metadata ? { metadata } : {}),
  } as ListedUser
}

function parseListedResponse(
  value: unknown, params: UserListParams, status: number, allowPlatform: boolean,
): ListedUserListResponse {
  if (status !== 200 || !record(value) || !exactKeys(value, ['items', 'page', 'limit', 'total']) ||
    !Array.isArray(value.items) || value.page !== params.page || value.limit !== params.limit ||
    typeof value.total !== 'number' || !Number.isSafeInteger(value.total) || value.total < 0 ||
    value.items.length > params.limit || value.total < value.items.length) throw invalidResponse()
  const items = value.items.map((item) => {
    if (!params.include_verification) return parseListedUser(item, undefined, allowPlatform)
    if (!record(item)) throw invalidResponse()
    const { verification, ...user } = item
    const parsed: ListedUser = parseListedUser(user, undefined, allowPlatform)
    if (params.include_verification) {
      if (!record(verification) || !exactKeys(verification, ['personal_verified', 'company_verified']) ||
        typeof verification.personal_verified !== 'boolean' || typeof verification.company_verified !== 'boolean') throw invalidResponse()
      parsed.verification = { personal_verified: verification.personal_verified, company_verified: verification.company_verified }
    }
    return parsed
  })
  return { items, page: params.page, limit: params.limit, total: value.total }
}

function parseBatchResponse(value: unknown, input: readonly BatchUpdateUserRequest[], status: number): BatchUpdateUserResponse {
  if (status !== 200 || !record(value) || !exactKeys(value, ['items']) || !Array.isArray(value.items) ||
    value.items.length !== input.length) throw invalidResponse()
  return { items: value.items.map((item, index) => parseListedUser(item, input[index].id)) }
}

function parseUserGroup(value: unknown, expectedID?: string): UserGroup {
  if (!record(value) || !exactKeys(value, [
    'id', 'scope_id', 'name', 'revision', 'member_count', 'created_at', 'updated_at',
  ]) || typeof value.id !== 'string' || !uuidPattern.test(value.id) || expectedID !== undefined && value.id !== expectedID ||
    typeof value.scope_id !== 'string' || !uuidPattern.test(value.scope_id) ||
    typeof value.name !== 'string' || value.name !== value.name.trim() || !value.name || value.name.length > 128 ||
    hasControlCharacter(value.name) ||
    typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
    typeof value.member_count !== 'number' || !Number.isSafeInteger(value.member_count) || value.member_count < 0 ||
    !timestamp(value.created_at) || !timestamp(value.updated_at)) throw invalidResponse()
  return {
    id: value.id, scope_id: value.scope_id, name: value.name, revision: value.revision,
    member_count: value.member_count, created_at: value.created_at, updated_at: value.updated_at,
  }
}

function parseUserGroupList(value: unknown, page: number, limit: number, status: number): UserGroupListResponse {
  if (status !== 200 || !record(value) || !exactKeys(value, ['items', 'page', 'limit', 'total']) ||
    !Array.isArray(value.items) || value.page !== page || value.limit !== limit ||
    typeof value.total !== 'number' || !Number.isSafeInteger(value.total) || value.total < value.items.length ||
    value.items.length > limit) throw invalidResponse()
  return { items: value.items.map((item) => parseUserGroup(item)), page, limit, total: value.total }
}

async function request<T>(
  accessToken: string,
  path: string,
  init: RequestInit = {},
  parse?: (value: unknown, status: number) => T,
): Promise<T> {
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
  if (response.status === 204) return parse ? parse(undefined, response.status) : undefined as T
  if (parse && response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    throw invalidResponse()
  }
  let value: unknown
  try {
    value = await response.json()
  } catch (error) {
    if (parse) throw invalidResponse()
    throw error
  }
  return parse ? parse(value, response.status) : value as T
}

function idempotencyHeaders(key: string) {
  return { 'Idempotency-Key': key }
}

function writeHeaders(metadata: UserWriteMetadata) {
  if (!record(metadata) || !exactKeys(metadata, ['idempotencyKey', 'requestId', 'traceparent']) ||
    typeof metadata.idempotencyKey !== 'string' || !idempotencyPattern.test(metadata.idempotencyKey) ||
    typeof metadata.requestId !== 'string' || !metadataPattern.test(metadata.requestId) ||
    typeof metadata.traceparent !== 'string' || !traceparentPattern.test(metadata.traceparent)) throw invalidRequest()
  return {
    'Idempotency-Key': metadata.idempotencyKey,
    'X-Request-ID': metadata.requestId,
    Traceparent: metadata.traceparent,
  }
}

function randomHex(bytes: number): string {
  if (!globalThis.crypto?.getRandomValues) throw invalidRequest()
  const values = new Uint8Array(bytes)
  globalThis.crypto.getRandomValues(values)
  if (values.every((value) => value === 0)) values[values.length - 1] = 1
  return [...values].map((value) => value.toString(16).padStart(2, '0')).join('')
}

export function createUserWriteMetadata(operation: string): UserWriteMetadata {
  if (!/^[a-z][a-z0-9-]{0,47}$/.test(operation)) throw invalidRequest()
  const suffix = randomHex(12)
  return {
    idempotencyKey: `${operation}-${suffix}`,
    requestId: `${operation}-request-${suffix}`,
    traceparent: `00-${randomHex(16)}-${randomHex(8)}-01`,
  }
}

// Owner pickers omit include_platform_admins and keep receiving tenant users
// only; the management user list opts in and receives ListedUser rows.
function list(accessToken: string, params: UserListParams & { include_platform_admins: true }): Promise<ListedUserListResponse>
function list(accessToken: string, params: UserListParams): Promise<UserListResponse>
function list(accessToken: string, params: UserListParams): Promise<UserListResponse | ListedUserListResponse> {
  const platformAdmins = params.include_platform_admins === true
  return request(accessToken, `/v1/admin/users?${listQuery(params)}`, {},
    (value, status) => parseListedResponse(value, params, status, platformAdmins))
}

function listQuery(params: UserListParams): URLSearchParams {
  const include = ['user_metadata']
  if (params.include_verification) include.push('user_verification')
  if (params.include_platform_admins) include.push('platform_admins')
  const query = new URLSearchParams({ page: String(params.page), limit: String(params.limit), include: include.join(',') })
  if (params.real_name_status) query.set('real_name_status', params.real_name_status)
  if (params.display_id) query.set('display_id', params.display_id)
  if (params.search) query.set('search', params.search)
  for (const field of ['username', 'display_name', 'email', 'phone'] as const) {
    const value = params[field]?.trim()
    if (value) query.set(field, value)
  }
  if (params.status) query.set('status', params.status)
  if (params.role) query.set('role', params.role)
  if (params.group_id) query.set('group_id', params.group_id)
  if (params.remark?.trim()) query.set('remark', params.remark.trim())
  if (params.qq?.trim()) query.set('qq', params.qq.trim())
  return query
}

function get(accessToken: string, id: string): Promise<ListedUser> {
  if (!uuidPattern.test(id)) throw invalidRequest()
  return request(accessToken, `/v1/admin/users/${encodeURIComponent(id)}?include=user_metadata`, {}, (value, status) => {
    if (status !== 200) throw invalidResponse()
    return parseListedUser(value, id)
  })
}

function validLoginSecurityFields(value: Record<string, unknown>): boolean {
  return typeof value.login_verification === 'string' && ['none', 'sms', 'email'].includes(value.login_verification) &&
    Array.isArray(value.login_allowlist) && value.login_allowlist.length <= 32 &&
    value.login_allowlist.every((ip: unknown) => typeof ip === 'string' && ip.length <= 64 && /^[0-9a-f:.]+(?:\/\d{1,3})?$/i.test(ip))
}

function parseLoginSecurity(value: unknown, status: number, userID: string, scopeID: string): ManagedUserLoginSecurity {
  if (status !== 200 || !record(value) ||
    !exactKeys(value, ['user_id', 'tenant_scope_id', 'revision', 'login_verification', 'login_allowlist']) ||
    value.user_id !== userID || value.tenant_scope_id !== scopeID ||
    !Number.isSafeInteger(value.revision) || Number(value.revision) < 0 || !validLoginSecurityFields(value)) {
    throw invalidResponse()
  }
  return value as unknown as ManagedUserLoginSecurity
}

function loginSecurityPath(userID: string, scopeID: string): string {
  if (!uuidPattern.test(userID) || !uuidPattern.test(scopeID)) throw invalidRequest()
  return `/v1/admin/users/${userID}/login-security?tenant_scope_id=${scopeID}`
}

function getLoginSecurity(accessToken: string, userID: string, scopeID: string): Promise<ManagedUserLoginSecurity> {
  return request(accessToken, loginSecurityPath(userID, scopeID), {},
    (value, status) => parseLoginSecurity(value, status, userID, scopeID))
}

function updateLoginSecurity(
  accessToken: string,
  userID: string,
  scopeID: string,
  input: UpdateUserLoginSecurityRequest,
  metadata: UserWriteMetadata,
): Promise<ManagedUserLoginSecurity> {
  if (!record(input) || !exactKeys(input, ['expected_revision', 'login_verification', 'login_allowlist']) ||
    !Number.isSafeInteger(input.expected_revision) || input.expected_revision < 0 || !validLoginSecurityFields(input)) {
    throw invalidRequest()
  }
  return request(accessToken, loginSecurityPath(userID, scopeID), {
    method: 'PUT', headers: writeHeaders(metadata), body: JSON.stringify(input),
  }, (value, status) => parseLoginSecurity(value, status, userID, scopeID))
}

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/
const optionalTimestamp = (value: unknown) => value === null || typeof value === 'string' && timestampPattern.test(value)

function parseSecondaryVerification(value: unknown, status: number, userID: string, scopeID: string): ManagedUserSecondaryVerification {
  if (status !== 200 || !record(value) || !exactKeys(value, ['user_id', 'tenant_scope_id', 'revision', 'enabled', 'deadline',
    'expiry_action', 'requested_at', 'completed', 'enforced_at']) ||
    value.user_id !== userID || value.tenant_scope_id !== scopeID || !Number.isSafeInteger(value.revision) || Number(value.revision) < 0 ||
    typeof value.enabled !== 'boolean' || typeof value.completed !== 'boolean' ||
    (value.expiry_action !== 'none' && value.expiry_action !== 'lock_sites') ||
    !optionalTimestamp(value.deadline) || !optionalTimestamp(value.requested_at) || !optionalTimestamp(value.enforced_at)) {
    throw invalidResponse()
  }
  return value as unknown as ManagedUserSecondaryVerification
}

function secondaryVerificationPath(userID: string, scopeID: string): string {
  if (!uuidPattern.test(userID) || !uuidPattern.test(scopeID)) throw invalidRequest()
  return `/v1/admin/users/${userID}/secondary-verification?tenant_scope_id=${scopeID}`
}

function getSecondaryVerification(accessToken: string, userID: string, scopeID: string): Promise<ManagedUserSecondaryVerification> {
  return request(accessToken, secondaryVerificationPath(userID, scopeID), {},
    (value, status) => parseSecondaryVerification(value, status, userID, scopeID))
}

function updateSecondaryVerification(
  accessToken: string,
  userID: string,
  scopeID: string,
  input: UpdateUserSecondaryVerificationRequest,
  metadata: UserWriteMetadata,
): Promise<ManagedUserSecondaryVerification> {
  if (!record(input) || !exactKeys(input, ['expected_revision', 'enabled', 'deadline', 'expiry_action']) ||
    !Number.isSafeInteger(input.expected_revision) || input.expected_revision < 0 || typeof input.enabled !== 'boolean' ||
    (input.expiry_action !== 'none' && input.expiry_action !== 'lock_sites') || !optionalTimestamp(input.deadline) ||
    input.expiry_action === 'lock_sites' && input.deadline === null ||
    !input.enabled && (input.deadline !== null || input.expiry_action !== 'none')) {
    throw invalidRequest()
  }
  return request(accessToken, secondaryVerificationPath(userID, scopeID), {
    method: 'PUT', headers: writeHeaders(metadata), body: JSON.stringify(input),
  }, (value, status) => parseSecondaryVerification(value, status, userID, scopeID))
}

function listGroups(accessToken: string, page: number, limit: number, search = ''): Promise<UserGroupListResponse> {
  const query = new URLSearchParams({ page: String(page), limit: String(limit) })
  if (search) query.set('search', search)
  return request(accessToken, `/v1/admin/user-groups?${query}`, {},
    (value, status) => parseUserGroupList(value, page, limit, status))
}

function createGroup(accessToken: string, name: string, metadata: UserWriteMetadata): Promise<UserGroup> {
  return request(accessToken, '/v1/admin/user-groups', {
    method: 'POST', headers: writeHeaders(metadata), body: JSON.stringify({ name }),
  }, (value, status) => {
    if (status !== 201) throw invalidResponse()
    return parseUserGroup(value)
  })
}

function updateGroup(
  accessToken: string,
  group: Pick<UserGroup, 'id' | 'revision'> & { name: string },
  metadata: UserWriteMetadata,
): Promise<UserGroup> {
  return request(accessToken, `/v1/admin/user-groups/${encodeURIComponent(group.id)}`, {
    method: 'PATCH', headers: writeHeaders(metadata),
    body: JSON.stringify({ expected_revision: group.revision, name: group.name }),
  }, (value, status) => {
    if (status !== 200) throw invalidResponse()
    return parseUserGroup(value, group.id)
  })
}

function deleteGroup(
  accessToken: string,
  group: Pick<UserGroup, 'id' | 'revision'>,
  metadata: UserWriteMetadata,
): Promise<void> {
  return request(accessToken, `/v1/admin/user-groups/${encodeURIComponent(group.id)}`, {
    method: 'DELETE', headers: writeHeaders(metadata), body: JSON.stringify({ expected_revision: group.revision }),
  }, (_value, status) => {
    if (status !== 204) throw invalidResponse()
  })
}

function create(
  accessToken: string,
  input: CreateUserRequest,
  metadata: UserWriteMetadata,
): Promise<ManagedUser> {
  return request(accessToken, '/v1/admin/users?include=user_metadata', {
    method: 'POST',
    headers: writeHeaders(metadata),
    body: JSON.stringify(input),
  }, (value, status) => {
    if (status !== 201) throw invalidResponse()
    return parseManagedUser(value)
  })
}

function update(
  accessToken: string,
  id: string,
  input: UpdateUserRequest,
  metadata: UserWriteMetadata,
): Promise<ListedUser> {
  return request(accessToken, `/v1/admin/users/${encodeURIComponent(id)}?include=user_metadata`, {
    method: 'PATCH',
    headers: writeHeaders(metadata),
    body: JSON.stringify(input),
  }, (value, status) => {
    if (status !== 200) throw invalidResponse()
    return parseListedUser(value, id)
  })
}

function deleteUser(
  accessToken: string,
  id: string,
  expectedRevision: number,
  metadata: UserWriteMetadata,
): Promise<void> {
  if (!uuidPattern.test(id) || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
    throw invalidRequest()
  }
  return request(accessToken, `/v1/admin/users/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: writeHeaders(metadata),
    body: JSON.stringify({ expected_revision: expectedRevision }),
  }, (_value, status) => {
    if (status !== 204) throw invalidResponse()
  })
}

function resetPassword(
  accessToken: string,
  input: ResetManagedUserPasswordRequest,
  metadata: UserWriteMetadata,
): Promise<ManagedUser> {
  if (!uuidPattern.test(input.user_id) || !uuidPattern.test(input.tenant_id) ||
    !uuidPattern.test(input.tenant_scope_id) || !Number.isSafeInteger(input.expected_revision) ||
    input.expected_revision < 1 || checkPassword(input.new_password).length > 0 ||
    !input.step_up_token || input.step_up_token !== input.step_up_token.trim()) throw invalidRequest()
  return request(accessToken, `/v1/admin/users/${encodeURIComponent(input.user_id)}?include=user_metadata`, {
    method: 'PATCH',
    headers: writeHeaders(metadata),
    body: JSON.stringify({
      expected_revision: input.expected_revision,
      password_reset: {
        tenant_scope_id: input.tenant_scope_id,
        new_password: input.new_password,
        step_up_token: input.step_up_token,
      },
    }),
  }, (value, status) => {
    if (status !== 200) throw invalidResponse()
    const result = parseManagedUser(value, input.user_id)
    if (result.tenant_id !== input.tenant_id || result.scope_id !== input.tenant_scope_id ||
      result.revision !== input.expected_revision + 1) throw invalidResponse()
    return result
  })
}

function batchUpdate(
  accessToken: string,
  input: BatchUpdateUserRequest[],
  metadata: UserWriteMetadata,
): Promise<BatchUpdateUserResponse> {
  if (input.length < 1 || input.length > 100 || new Set(input.map((item) => item.id)).size !== input.length) {
    throw invalidRequest()
  }
  return request(accessToken, '/v1/admin/users?include=user_metadata', {
    method: 'PATCH',
    headers: writeHeaders(metadata),
    body: JSON.stringify(input),
  }, (value, status) => parseBatchResponse(value, input, status))
}

function profile(accessToken: string): Promise<AccountProfile> {
  return request(accessToken, '/v1/account/profile')
}

function updateProfile(
  accessToken: string,
  input: UpdateProfileRequest,
  idempotencyKey: string,
): Promise<AccountProfile> {
  return request(accessToken, '/v1/account/profile', {
    method: 'PATCH',
    headers: idempotencyHeaders(idempotencyKey),
    body: JSON.stringify(input),
  })
}

// 2026-09-19 安全设置行内表单：只提交要改的联系方式，另一项由服务端沿用现值。
function bindContact(
  accessToken: string,
  input: { expected_revision: number; display_name: string; current_password: string; phone?: string; email?: string },
  idempotencyKey: string,
): Promise<AccountProfile> {
  return updateProfile(accessToken, input, idempotencyKey)
}

function changePassword(accessToken: string, input: ChangePasswordRequest): Promise<void> {
  return request(accessToken, '/v1/account/password', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export const usersApi = {
  batchUpdate, bindContact, changePassword, create, createGroup, deleteGroup, deleteUser, get, list, listGroups, profile,
  resetPassword, update, updateGroup, updateProfile, getLoginSecurity, updateLoginSecurity,
  getSecondaryVerification, updateSecondaryVerification,
}
