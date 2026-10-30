import { ApiError, networkApiError, responseApiError } from './auth'

export type PluginInstallationStatus =
  | 'pending_confirmation'
  | 'authorized'
  | 'installing'
  | 'enabled'
  | 'disabled'
  | 'upgrade_failed_lkg_preserved'
  | 'uninstalled'

export type PluginInstallationResourceScope = 'platform' | 'tenant'

/** Plugin type: the verified manifest entrypoint type, signed by the license service next to resource_scope. */
export type PluginInstallationEntrypointType = 'theme' | 'rule_pack' | 'external_https' | 'ui_page'

const entrypointScopes: Record<PluginInstallationEntrypointType, PluginInstallationResourceScope> = {
  theme: 'platform', rule_pack: 'platform', external_https: 'tenant', ui_page: 'tenant',
}

export interface PluginInstallation {
  schema: 'cdnca.control.plugin-installation/v1'
  tenant_scope_id: string
  authorization_id: string
  installation_id: string
  verification_id: string
  plugin_id: string
  version: string
  /**
   * Signed by the license service from the verified manifest: platform (themes, rule data packs, confirmed by
   * the controller's platform administrator under /v1/platform) or tenant (other plugins).
   */
  resource_scope: PluginInstallationResourceScope
  entrypoint_type: PluginInstallationEntrypointType
  manifest_sha256: string
  configuration_schema_sha256: string
  manifest_scopes: string[]
  approved_scopes: string[]
  sensitive_scopes: string[]
  new_scopes: string[]
  status: PluginInstallationStatus
  revision: number
  identity_generation: number
  lkg_verification_id: string | null
  lkg_version: string | null
  stable_reason_code: string | null
  updated_at: string
  /**
   * Platform authorization state; omitted when the license service was not reachable. pending_confirmation is
   * a purchased market plugin waiting for this controller's administrator: confirm sends the confirmation to
   * the license service and installs it.
   */
  authorization_status?: 'pending_confirmation' | 'authorized' | 'enabled' | 'disabled'
  /**
   * Who paused a disabled authorization (signed license snapshot): installation is this controller's own pause
   * and can be resumed here; operator (platform operator) and service (market delisting or security advisory)
   * are platform pauses. A disabled authorization without it is treated as a platform pause.
   */
  paused_by?: PluginInstallationPausedBy
  paused_reason?: string
  /** A newer version the platform already authorized for this installation. */
  available_upgrade?: PluginInstallationAvailableUpgrade
}

export type PluginInstallationPausedBy = 'installation' | 'operator' | 'service'

export interface PluginInstallationAvailableUpgrade {
  verification_id: string
  version: string
  manifest_scopes: string[]
  approved_scopes: string[]
  sensitive_scopes: string[]
  new_scopes: string[]
}

export interface PluginInstallationPage {
  items: PluginInstallation[]
  next_cursor?: string
}

export interface PluginInstallationMutationResult {
  installation: PluginInstallation
}

export interface PluginInstallationListQuery {
  limit?: number
  cursor?: string
  status?: PluginInstallationStatus
  plugin_id?: string
}

export interface PluginInstallationApprovalInput {
  verification_id: string
  approved_scopes: string[]
  sensitive_permissions_confirmed: boolean
  new_permissions_confirmed: boolean
}

export interface PluginInstallationReasonInput {
  reason: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digestPattern = /^[0-9a-f]{64}$/
const pluginFilterPattern = /^[a-z0-9][a-z0-9.-]{0,127}$/
const pluginIDPattern = /^[a-z0-9]+(?:[.-][a-z0-9]+)+$/
const versionPattern = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
const scopePattern = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)+$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const stableReasonPattern = /^[a-z][a-z0-9_]{0,127}$/
const statuses = new Set<PluginInstallationStatus>([
  'pending_confirmation', 'authorized', 'installing', 'enabled', 'disabled',
  'upgrade_failed_lkg_preserved', 'uninstalled',
])

function invalidRequest(): ApiError {
  return new ApiError('Invalid plugin installation request', 400, 'invalid_request')
}

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, allowed: string[], required = allowed): boolean {
  const keys = new Set(Object.keys(value))
  return Object.keys(value).every((key) => allowed.includes(key)) && required.every((key) => keys.has(key))
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function uint(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && value.trim() === value && !Number.isNaN(Date.parse(value))
}

function sortedScopes(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length > 128 || !value.every((item) => typeof item === 'string' && scopePattern.test(item))) return false
  return value.every((item, index) => index === 0 || value[index - 1]! < item)
}

const installationKeys = [
  'schema', 'tenant_scope_id', 'authorization_id', 'installation_id', 'verification_id',
  'plugin_id', 'version', 'resource_scope', 'entrypoint_type', 'manifest_sha256', 'configuration_schema_sha256', 'manifest_scopes',
  'approved_scopes', 'sensitive_scopes', 'new_scopes', 'status', 'revision', 'identity_generation',
  'lkg_verification_id', 'lkg_version', 'stable_reason_code', 'updated_at',
]
const authorizationStatuses = new Set(['pending_confirmation', 'authorized', 'enabled', 'disabled'])
const pausedByValues = new Set(['installation', 'operator', 'service'])

function validPause(value: Record<string, unknown>): boolean {
  if (value.paused_by === undefined) return value.paused_reason === undefined
  return pausedByValues.has(value.paused_by as string) && (value.paused_reason === undefined ||
    (typeof value.paused_reason === 'string' && value.paused_reason.trim() === value.paused_reason &&
      [...value.paused_reason].length >= 1 && [...value.paused_reason].length <= 500))
}

function validUpgrade(value: unknown): boolean {
  return record(value) && exactKeys(value, ['verification_id', 'version', 'manifest_scopes', 'approved_scopes',
    'sensitive_scopes', 'new_scopes']) && uuid(value.verification_id) && typeof value.version === 'string' &&
    versionPattern.test(value.version) && sortedScopes(value.manifest_scopes) && sortedScopes(value.approved_scopes) &&
    sortedScopes(value.sensitive_scopes) && sortedScopes(value.new_scopes)
}

function parseInstallation(value: unknown, expected: ScopeTarget): PluginInstallation {
  if (!record(value) || value.resource_scope !== expected.resourceScope ||
    typeof value.entrypoint_type !== 'string' || !Object.hasOwn(entrypointScopes, value.entrypoint_type) ||
    entrypointScopes[value.entrypoint_type as PluginInstallationEntrypointType] !== value.resource_scope ||
    (expected.scopeID !== undefined && value.tenant_scope_id !== expected.scopeID) || !exactKeys(value, [...installationKeys, 'authorization_status', 'available_upgrade',
    'paused_by', 'paused_reason'], installationKeys) || !validPause(value) ||
    (value.authorization_status !== undefined && !authorizationStatuses.has(value.authorization_status as string)) ||
    (value.available_upgrade !== undefined && !validUpgrade(value.available_upgrade)) || value.schema !== 'cdnca.control.plugin-installation/v1' || !uuid(value.tenant_scope_id) ||
    !uuid(value.authorization_id) ||
    !uuid(value.installation_id) || !uuid(value.verification_id) || typeof value.plugin_id !== 'string' ||
    value.plugin_id.length < 3 || value.plugin_id.length > 128 || !pluginIDPattern.test(value.plugin_id) ||
    typeof value.version !== 'string' || value.version.length > 128 || !versionPattern.test(value.version) ||
    typeof value.manifest_sha256 !== 'string' || !digestPattern.test(value.manifest_sha256) ||
    typeof value.configuration_schema_sha256 !== 'string' || !digestPattern.test(value.configuration_schema_sha256) ||
    !sortedScopes(value.manifest_scopes) || !sortedScopes(value.approved_scopes) ||
    !sortedScopes(value.sensitive_scopes) || !sortedScopes(value.new_scopes) ||
    typeof value.status !== 'string' || !statuses.has(value.status as PluginInstallationStatus) ||
    !uint(value.revision, 1) || !uint(value.identity_generation) ||
    (value.lkg_verification_id !== null && !uuid(value.lkg_verification_id)) ||
    (value.lkg_version !== null && (typeof value.lkg_version !== 'string' || !versionPattern.test(value.lkg_version))) ||
    (value.stable_reason_code !== null && (typeof value.stable_reason_code !== 'string' || !stableReasonPattern.test(value.stable_reason_code))) ||
    !timestamp(value.updated_at)) {
    throw invalidResponse()
  }
  return value as unknown as PluginInstallation
}

function parsePage(value: unknown, target: ScopeTarget): PluginInstallationPage {
  if (!record(value) || !exactKeys(value, ['items', 'next_cursor'], ['items']) || !Array.isArray(value.items) ||
    value.items.length > 100 || (value.next_cursor !== undefined &&
      (typeof value.next_cursor !== 'string' || value.next_cursor.length < 1 || value.next_cursor.length > 1024))) {
    throw invalidResponse()
  }
  return {
    items: value.items.map((item) => parseInstallation(item, target)),
    ...(value.next_cursor === undefined ? {} : { next_cursor: value.next_cursor }),
  }
}

function parseMutation(value: unknown, target: ScopeTarget): PluginInstallationMutationResult {
  if (!record(value) || !exactKeys(value, ['installation'])) throw invalidResponse()
  return { installation: parseInstallation(value.installation, target) }
}

async function request<T>(accessToken: string, path: string, init: RequestInit, requestID: string,
  parse: (value: unknown) => T): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  try {
    return parse(await response.json())
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidResponse()
  }
}

function pluginInstallationRequestID(action: string): string {
  const random = typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '')
    : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`
  return `plugin-installation-${action}-${random}`.slice(0, 128)
}

/**
 * Where installations live: a tenant scope (path carries its UUID), or the controller's platform scope
 * (/v1/platform, the scope comes from the session; scopeID unknown to the client).
 */
interface ScopeTarget {
  resourceScope: PluginInstallationResourceScope
  scopeID?: string
}

function tenantTarget(scopeID: string): ScopeTarget {
  if (!uuid(scopeID)) throw invalidRequest()
  return { resourceScope: 'tenant', scopeID }
}

const platformTarget: ScopeTarget = { resourceScope: 'platform' }

function basePath(target: ScopeTarget): string {
  return target.resourceScope === 'platform' ? '/v1/platform/plugin-installations'
    : `/v1/tenant-scopes/${target.scopeID}/plugin-installations`
}

function itemPath(target: ScopeTarget, authorizationID: string, action?: string): string {
  if (!uuid(authorizationID)) throw invalidRequest()
  return `${basePath(target)}/${authorizationID}${action ? `/${action}` : ''}`
}

function validCursor(value: string): boolean {
  return value.length >= 1 && value.length <= 1024 && ![...value].some((character) => {
    const code = character.charCodeAt(0)
    return code < 0x20 || code === 0x7f
  })
}

function listQuery(values: PluginInstallationListQuery): string {
  const params = new URLSearchParams()
  if (values.limit !== undefined) {
    if (!Number.isInteger(values.limit) || values.limit < 1 || values.limit > 100) throw invalidRequest()
    params.set('limit', String(values.limit))
  }
  if (values.cursor !== undefined) {
    if (!validCursor(values.cursor)) throw invalidRequest()
    params.set('cursor', values.cursor)
  }
  if (values.status !== undefined) {
    if (!statuses.has(values.status)) throw invalidRequest()
    params.set('status', values.status)
  }
  if (values.plugin_id !== undefined) {
    if (!pluginFilterPattern.test(values.plugin_id)) throw invalidRequest()
    params.set('plugin_id', values.plugin_id)
  }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

function writeHeaders(revision: number, idempotencyKey: string): HeadersInit {
  if (!uint(revision, 1) || !idempotencyPattern.test(idempotencyKey)) throw invalidRequest()
  return { 'If-Match': `"${revision}"`, 'Idempotency-Key': idempotencyKey }
}

function validApproval(input: PluginInstallationApprovalInput): boolean {
  return uuid(input.verification_id) && sortedScopes(input.approved_scopes) &&
    typeof input.sensitive_permissions_confirmed === 'boolean' && typeof input.new_permissions_confirmed === 'boolean'
}

function validReason(input: PluginInstallationReasonInput): boolean {
  return typeof input.reason === 'string' && input.reason.trim() === input.reason &&
    [...input.reason].length >= 1 && [...input.reason].length <= 500
}

function mutation<T extends PluginInstallationApprovalInput | PluginInstallationReasonInput | Record<string, never>>(
  action: 'confirm' | 'upgrade' | 'disable' | 'resume' | 'uninstall', accessToken: string, target: ScopeTarget,
  authorizationID: string, revision: number, input: T, idempotencyKey: string,
): Promise<PluginInstallationMutationResult> {
  const valid = action === 'resume' ? Object.keys(input).length === 0
    : action === 'confirm' || action === 'upgrade'
      ? validApproval(input as PluginInstallationApprovalInput)
      : validReason(input as PluginInstallationReasonInput)
  if (!valid) throw invalidRequest()
  return request(accessToken, itemPath(target, authorizationID, action), {
    method: 'POST', headers: writeHeaders(revision, idempotencyKey), body: JSON.stringify(input),
  }, idempotencyKey, (value) => parseMutation(value, target))
}

function scopedApi(resolve: (scopeID: string) => ScopeTarget) {
  return {
    async list(accessToken: string, scopeID: string, values: PluginInstallationListQuery = {}) {
      const target = resolve(scopeID)
      return request(accessToken, `${basePath(target)}${listQuery(values)}`, {}, pluginInstallationRequestID('list'),
        (body) => parsePage(body, target))
    },
    async get(accessToken: string, scopeID: string, authorizationID: string) {
      const target = resolve(scopeID)
      return request(accessToken, itemPath(target, authorizationID), {}, pluginInstallationRequestID('get'),
        (body) => parseInstallation(body, target))
    },
    async confirm(accessToken: string, scopeID: string, authorizationID: string, revision: number,
      input: PluginInstallationApprovalInput, idempotencyKey: string) {
      return mutation('confirm', accessToken, resolve(scopeID), authorizationID, revision, input, idempotencyKey)
    },
    async upgrade(accessToken: string, scopeID: string, authorizationID: string, revision: number,
      input: PluginInstallationApprovalInput, idempotencyKey: string) {
      return mutation('upgrade', accessToken, resolve(scopeID), authorizationID, revision, input, idempotencyKey)
    },
    async disable(accessToken: string, scopeID: string, authorizationID: string, revision: number,
      input: PluginInstallationReasonInput, idempotencyKey: string) {
      return mutation('disable', accessToken, resolve(scopeID), authorizationID, revision, input, idempotencyKey)
    },
    /** Resumes a plugin this controller paused itself; a platform pause is refused (plugin_installation_platform_paused). */
    async resume(accessToken: string, scopeID: string, authorizationID: string, revision: number, idempotencyKey: string) {
      return mutation('resume', accessToken, resolve(scopeID), authorizationID, revision, {}, idempotencyKey)
    },
    async uninstall(accessToken: string, scopeID: string, authorizationID: string, revision: number,
      input: PluginInstallationReasonInput, idempotencyKey: string) {
      return mutation('uninstall', accessToken, resolve(scopeID), authorizationID, revision, input, idempotencyKey)
    },
  }
}

export function newPluginInstallationIdempotencyKey(action: string): string {
  const safeAction = action.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 24) || 'action'
  const random = typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '')
    : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`
  return `plugin-installation-${safeAction}-${random}`.slice(0, 128)
}

/** Tenant plugins of one tenant scope (/v1/tenant-scopes/{scope}/plugin-installations). */
export const pluginInstallationsApi = scopedApi(tenantTarget)

/**
 * Instance-wide plugins (themes, rule data packs) of this controller, confirmed by its platform administrator
 * (/v1/platform/plugin-installations). The scope argument is ignored: the server takes it from the session.
 */
export const platformPluginInstallationsApi = scopedApi(() => platformTarget)
