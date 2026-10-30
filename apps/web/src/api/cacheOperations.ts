import { ApiError, networkApiError, responseApiError } from './auth'

export type CacheOperationAction = 'purge' | 'prewarm'
export type CacheTargetType = 'exact_url' | 'directory_prefix' | 'whole_site'
export type CacheOperationState =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'partial_failed'
  | 'failed'
  | 'cancelled'
export type CacheItemState = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export interface CacheProgress {
  total: number
  completed: number
  succeeded: number
  failed: number
  cancelled: number
}

export interface CacheOperationTarget {
  ordinal: number
  display_url: string
  canonical_path: string
  target_sha256: string
  query_redacted: boolean
}

export interface CacheTargetProjection {
  target_ordinal: number
  state: CacheItemState
  attempt: number
  sequence: number
  error_code?: string
  completed_at?: string
}

export interface CacheNodeProjection {
  node_id: string
  node_display_id: string
  state: CacheOperationState
  attempt: number
  progress: CacheProgress
  last_error_code?: string
  targets: CacheTargetProjection[]
  updated_at: string
  completed_at?: string
  /** The node's answer to the task's cancel when it was running there (CACHE-ADD-07). */
  cancel_confirmation?: CacheCancelConfirmation
}

export type CacheCancelConfirmation = 'pending' | 'cancelled' | 'completed' | 'unresponsive' | 'unsupported'
const cancelConfirmations = new Set<CacheCancelConfirmation>(['pending', 'cancelled', 'completed', 'unresponsive', 'unsupported'])

interface CacheOperationFacts {
  /** Created without node_ids: every node carrying the site (a re-submit goes to the carrying nodes then). */
  auto_nodes: boolean
  /** Set on a system follow-up for a node that started carrying the site: the user's operation it follows up. */
  parent_operation_id?: string
  id: string
  display_id: string
  site_id: string
  site_display_id: string
  action: CacheOperationAction
  target_type: CacheTargetType
  state: CacheOperationState
  max_attempts: number
  progress: CacheProgress
  created_at: string
  started_at?: string
  updated_at: string
  completed_at?: string
  cancel_requested_at?: string
}

export interface CacheOperation extends CacheOperationFacts {
  targets: CacheOperationTarget[]
  nodes: CacheNodeProjection[]
}

export interface CacheOperationSummary extends CacheOperationFacts {
  target_count: number
  node_count: number
  /** The first target as the detail shows it (query redacted). */
  first_target: CacheOperationTarget
}

export type CacheOperationStateCounts = Record<CacheOperationState, number>

export interface CacheOperationPage {
  items: CacheOperationSummary[]
  next_cursor?: string
  /** First page only: operations per state under every filter but state. */
  state_counts?: CacheOperationStateCounts
}

export interface CreateCacheOperationInput {
  site_id: string
  action: CacheOperationAction
  target_type: CacheTargetType
  targets: string[]
  node_ids: string[]
  max_retries: number
}

export interface CacheOperationListParams {
  limit?: number
  cursor?: string
  // Task display ID, site display ID, or a substring of a target URL (server side).
  search?: string
  site_id?: string
  action?: CacheOperationAction
  target_type?: CacheTargetType
  /** Any of these states (state pills are multi-select). */
  states?: CacheOperationState[]
}

export type CacheOperationScope =
  | { kind: 'tenant' }
  | { kind: 'admin'; scopeId: string }

/** A cache write named by its action, operation (none for a create) and Idempotency-Key. */
export type CacheWriteRef =
  | { action: 'create'; key: string }
  | { action: 'retry' | 'cancel' | 'resubmit'; operationID: string; key: string }

/** fix-cacheflow5: what the server did with a write; null from writeReceipt = not received. */
export type CacheWriteReceipt =
  | { status: 'accepted'; decided_at: string; operation: CacheOperation }
  | {
    status: 'rejected'
    decided_at: string
    rejection: { code: string; details?: { field: 'targets'; target_ordinal: number; stage: 'target_validation'; reason: string } }
  }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const sha256Pattern = /^[0-9a-f]{64}$/
const stableCodePattern = /^[a-z][a-z0-9._-]{0,127}$/
// cachecontrolhttp displayIDPattern: the bigint display IDs rendered as text.
const displayIDPattern = /^[1-9][0-9]{0,18}$/
const operationActions = new Set<CacheOperationAction>(['purge', 'prewarm'])
const targetTypes = new Set<CacheTargetType>(['exact_url', 'directory_prefix', 'whole_site'])
const operationStates = new Set<CacheOperationState>([
  'queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled',
])
const itemStates = new Set<CacheItemState>(['queued', 'running', 'succeeded', 'failed', 'cancelled'])

function invalidResponse(): ApiError {
  return new ApiError('Invalid cache operation response', 502, 'invalid_response')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value)
  return required.every((key) => key in value) &&
    keys.every((key) => required.includes(key) || optional.includes(key))
}

function isInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && Number.isFinite(Date.parse(value))
}

function isOptionalDateTime(value: unknown): value is string | undefined {
  return value === undefined || isDateTime(value)
}

function isProgress(value: unknown): value is CacheProgress {
  if (!isRecord(value) || !hasExactKeys(value, [
    'total', 'completed', 'succeeded', 'failed', 'cancelled',
  ])) return false
  const { total, completed, succeeded, failed, cancelled } = value
  return isInteger(total, 0) && isInteger(completed, 0, total) &&
    isInteger(succeeded, 0, completed) && isInteger(failed, 0, completed) &&
    isInteger(cancelled, 0, completed) && succeeded + failed + cancelled === completed
}

function isTarget(value: unknown): value is CacheOperationTarget {
  return isRecord(value) && hasExactKeys(value, [
    'ordinal', 'display_url', 'canonical_path', 'target_sha256', 'query_redacted',
  ]) && isInteger(value.ordinal, 1, 1000) && typeof value.display_url === 'string' &&
    typeof value.canonical_path === 'string' && value.canonical_path.length > 0 &&
    value.canonical_path.length <= 8192 && typeof value.target_sha256 === 'string' &&
    sha256Pattern.test(value.target_sha256) && typeof value.query_redacted === 'boolean'
}

function isTargetProjection(value: unknown): value is CacheTargetProjection {
  return isRecord(value) && hasExactKeys(
    value,
    ['target_ordinal', 'state', 'attempt', 'sequence'],
    ['error_code', 'completed_at'],
  ) && isInteger(value.target_ordinal, 1, 1000) && typeof value.state === 'string' &&
    itemStates.has(value.state as CacheItemState) && isInteger(value.attempt, 0, 11) &&
    isInteger(value.sequence, 0) &&
    (value.error_code === undefined || (
      typeof value.error_code === 'string' && stableCodePattern.test(value.error_code)
    )) && isOptionalDateTime(value.completed_at)
}

function isNodeProjection(value: unknown): value is CacheNodeProjection {
  return isRecord(value) && hasExactKeys(
    value,
    ['node_id', 'node_display_id', 'state', 'attempt', 'progress', 'targets', 'updated_at'],
    ['last_error_code', 'completed_at', 'cancel_confirmation'],
  ) && typeof value.node_id === 'string' && uuidPattern.test(value.node_id) &&
    typeof value.node_display_id === 'string' && displayIDPattern.test(value.node_display_id) &&
    typeof value.state === 'string' && operationStates.has(value.state as CacheOperationState) &&
    isInteger(value.attempt, 0, 11) && isProgress(value.progress) &&
    Array.isArray(value.targets) && value.targets.length <= 1000 &&
    value.targets.every(isTargetProjection) &&
    (value.last_error_code === undefined || (
      typeof value.last_error_code === 'string' && stableCodePattern.test(value.last_error_code)
    )) && isDateTime(value.updated_at) && isOptionalDateTime(value.completed_at) &&
    (value.cancel_confirmation === undefined || (
      typeof value.cancel_confirmation === 'string' && cancelConfirmations.has(value.cancel_confirmation as CacheCancelConfirmation)
    ))
}

function hasOperationFacts(value: Record<string, unknown>): boolean {
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.display_id === 'string' && displayIDPattern.test(value.display_id) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    typeof value.site_display_id === 'string' && displayIDPattern.test(value.site_display_id) &&
    typeof value.action === 'string' && operationActions.has(value.action as CacheOperationAction) &&
    typeof value.target_type === 'string' && targetTypes.has(value.target_type as CacheTargetType) &&
    typeof value.state === 'string' && operationStates.has(value.state as CacheOperationState) &&
    isInteger(value.max_attempts, 1, 11) && isProgress(value.progress) && typeof value.auto_nodes === 'boolean' &&
    isDateTime(value.created_at) && isDateTime(value.updated_at) &&
    isOptionalDateTime(value.started_at) && isOptionalDateTime(value.completed_at) &&
    isOptionalDateTime(value.cancel_requested_at) &&
    (value.parent_operation_id === undefined || (
      typeof value.parent_operation_id === 'string' && uuidPattern.test(value.parent_operation_id) &&
      value.parent_operation_id !== value.id && value.auto_nodes === true
    ))
}

function isOperation(value: unknown): value is CacheOperation {
  return isRecord(value) && hasExactKeys(
    value,
    [
      'id', 'display_id', 'site_id', 'site_display_id', 'action', 'target_type', 'state', 'max_attempts', 'progress',
      'auto_nodes', 'targets', 'nodes', 'created_at', 'updated_at',
    ],
    ['started_at', 'completed_at', 'cancel_requested_at', 'parent_operation_id'],
  ) && hasOperationFacts(value) && Array.isArray(value.targets) && value.targets.length <= 1000 &&
    value.targets.every(isTarget) && Array.isArray(value.nodes) && value.nodes.length <= 1000 &&
    value.nodes.every(isNodeProjection)
}

function isWriteReceipt(value: unknown): value is CacheWriteReceipt {
  if (!isRecord(value) || !isDateTime(value.decided_at)) return false
  if (value.status === 'accepted') {
    return hasExactKeys(value, ['status', 'decided_at', 'operation']) && isOperation(value.operation)
  }
  if (value.status !== 'rejected' || !hasExactKeys(value, ['status', 'decided_at', 'rejection'])) return false
  const rejection = value.rejection
  if (!isRecord(rejection) || !hasExactKeys(rejection, ['code'], ['details']) ||
    typeof rejection.code !== 'string' || !stableCodePattern.test(rejection.code)) return false
  const details = rejection.details
  return details === undefined || (isRecord(details) &&
    hasExactKeys(details, ['field', 'target_ordinal', 'stage', 'reason']) && details.field === 'targets' &&
    isInteger(details.target_ordinal, 1) && details.stage === 'target_validation' &&
    typeof details.reason === 'string' && stableCodePattern.test(details.reason))
}

function isOperationSummary(value: unknown): value is CacheOperationSummary {
  return isRecord(value) && hasExactKeys(
    value,
    [
      'id', 'display_id', 'site_id', 'site_display_id', 'action', 'target_type', 'state', 'max_attempts', 'target_count',
      'node_count', 'first_target', 'auto_nodes', 'progress', 'created_at', 'updated_at',
    ],
    ['completed_at', 'parent_operation_id'],
  ) && hasOperationFacts(value) && isInteger(value.target_count, 1, 1000) &&
    isInteger(value.node_count, 1, 1000) && isTarget(value.first_target) && value.first_target.ordinal === 1
}

function isStateCounts(value: unknown): value is CacheOperationStateCounts {
  return isRecord(value) && hasExactKeys(value, [...operationStates]) &&
    [...operationStates].every((state) => isInteger(value[state], 0))
}

function isOperationPage(value: unknown): value is CacheOperationPage {
  return isRecord(value) && hasExactKeys(value, ['items'], ['next_cursor', 'state_counts']) &&
    (value.state_counts === undefined || isStateCounts(value.state_counts)) &&
    Array.isArray(value.items) && value.items.length <= 100 && value.items.every(isOperationSummary) &&
    (value.next_cursor === undefined || (
      typeof value.next_cursor === 'string' && value.next_cursor.length > 0 && value.next_cursor.length <= 4096
    ))
}

/**
 * One quota of an account's UTC+8 day (CACHE-01, fix-cachequota: per account, shared by its sites):
 * the limit a create is checked against, the system setting default and the account's own limit (null = default).
 */
export interface CacheDailyQuota {
  limit: number
  used: number
  remaining: number
  default_limit: number
  override: number | null
}

export interface CacheDailyUsage {
  scope_id: string
  url_purge: CacheDailyQuota
  directory_purge: CacheDailyQuota
  prewarm: CacheDailyQuota
  resets_at: string
  /** Revision of the account's own limits (0 = never set): expected_revision of the next setAccountLimits. */
  revision: number
}

/** An account's own daily limits; null follows the system setting default. */
export interface CacheAccountLimits {
  url_purge_limit: number | null
  directory_purge_limit: number | null
  prewarm_limit: number | null
}

// fix-cachedlg：按 URL 主机名匹配网站，一批 URL 按网站拆分。
export type CacheUnmatchedReason = 'target_site_not_found' | 'target_url_invalid' | 'target_wildcard_prewarm'
const unmatchedReasons = new Set<CacheUnmatchedReason>(['target_site_not_found', 'target_url_invalid', 'target_wildcard_prewarm'])

export interface CacheTargetSiteGroup {
  site_id: string
  scope_id: string
  site_display_id: string
  domain: string
  target_ordinals: number[]
}

export interface CacheTargetSites {
  groups: CacheTargetSiteGroup[]
  unmatched: Array<{ target_ordinal: number; reason: CacheUnmatchedReason }>
}

export interface ResolveCacheTargetSitesInput {
  action: CacheOperationAction
  target_type: Exclude<CacheTargetType, 'whole_site'>
  targets: string[]
}

/** The tenant's own sites, one tenant's (admin + scopeId), or every tenant's (admin-all). */
export type CacheTargetSiteScope = CacheOperationScope | { kind: 'admin-all' }

export interface CacheCarryingNode {
  id: string
  display_id: string
  name: string
  ipv4?: string
  ipv6?: string
}

function isTargetSites(value: unknown): value is CacheTargetSites {
  return isRecord(value) && hasExactKeys(value, ['groups', 'unmatched']) &&
    Array.isArray(value.groups) && value.groups.every((group) => isRecord(group) &&
      hasExactKeys(group, ['site_id', 'scope_id', 'site_display_id', 'domain', 'target_ordinals']) &&
      typeof group.site_id === 'string' && uuidPattern.test(group.site_id) &&
      typeof group.scope_id === 'string' && uuidPattern.test(group.scope_id) &&
      typeof group.site_display_id === 'string' && typeof group.domain === 'string' &&
      Array.isArray(group.target_ordinals) && group.target_ordinals.length > 0 &&
      group.target_ordinals.every((ordinal) => isInteger(ordinal, 1, 500))) &&
    Array.isArray(value.unmatched) && value.unmatched.every((item) => isRecord(item) &&
      hasExactKeys(item, ['target_ordinal', 'reason']) && isInteger(item.target_ordinal, 1, 500) &&
      unmatchedReasons.has(item.reason as CacheUnmatchedReason))
}

function isCarryingNodes(value: unknown): value is { items: CacheCarryingNode[] } {
  return isRecord(value) && hasExactKeys(value, ['items']) && Array.isArray(value.items) &&
    value.items.every((item) => isRecord(item) && hasExactKeys(item, ['id', 'display_id', 'name'], ['ipv4', 'ipv6']) &&
      typeof item.id === 'string' && uuidPattern.test(item.id) && typeof item.display_id === 'string' &&
      typeof item.name === 'string' && (item.ipv4 === undefined || typeof item.ipv4 === 'string') &&
      (item.ipv6 === undefined || typeof item.ipv6 === 'string'))
}

function isQuota(value: unknown): value is CacheDailyQuota {
  return isRecord(value) && hasExactKeys(value, ['limit', 'used', 'remaining', 'default_limit', 'override']) &&
    isInteger(value.limit, 0) && isInteger(value.used, 0) && isInteger(value.remaining, 0) &&
    isInteger(value.default_limit, 0) && (value.override === null || isInteger(value.override, 0))
}

function isDailyUsage(value: unknown): value is CacheDailyUsage {
  return isRecord(value) && hasExactKeys(value, ['scope_id', 'url_purge', 'directory_purge', 'prewarm', 'resets_at', 'revision']) &&
    typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) && isInteger(value.revision, 0) &&
    isQuota(value.url_purge) && isQuota(value.directory_purge) && isQuota(value.prewarm) && isDateTime(value.resets_at)
}

function requestID(action: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `cache-${action}-${suffix}`
}

function operationPath(scope: CacheOperationScope, suffix = ''): string {
  if (scope.kind === 'admin' && !uuidPattern.test(scope.scopeId)) {
    throw new ApiError('Invalid tenant scope', 400, 'validation_error')
  }
  return `${scope.kind === 'admin' ? '/v1/admin' : '/v1'}/cache-operations${suffix}`
}

function addScope(query: URLSearchParams, scope: CacheOperationScope): void {
  if (scope.kind === 'admin') query.set('scope_id', scope.scopeId)
}

async function request<T>(
  accessToken: string,
  path: string,
  action: string,
  isExpected: (value: unknown) => value is T,
  init: RequestInit = {},
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID(action),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponse()
  }
  if (!isExpected(value)) throw invalidResponse()
  return value
}

function commandHeaders(idempotencyKey: string): HeadersInit {
  return { 'Idempotency-Key': idempotencyKey }
}

async function sendCommand(
  accessToken: string,
  scope: CacheOperationScope,
  operationID: string,
  command: 'retry' | 'cancel' | 'resubmit',
  idempotencyKey: string,
): Promise<CacheOperation> {
  const query = new URLSearchParams()
  addScope(query, scope)
  const path = operationPath(scope, `/${encodeURIComponent(operationID)}/${command}`)
  return request(accessToken, `${path}${query.size ? `?${query}` : ''}`, command, isOperation, {
    method: 'POST',
    headers: commandHeaders(idempotencyKey),
    body: '{}',
  })
}

export const cacheOperationsApi = {
  async list(
    accessToken: string,
    scope: CacheOperationScope,
    params: CacheOperationListParams,
  ): Promise<CacheOperationPage> {
    const path = operationPath(scope)
    const query = new URLSearchParams()
    addScope(query, scope)
    if (params.limit !== undefined) query.set('limit', String(params.limit))
    if (params.cursor) query.set('cursor', params.cursor)
    if (params.search) query.set('search', params.search)
    if (params.site_id) query.set('site_id', params.site_id)
    if (params.action) query.set('action', params.action)
    if (params.target_type) query.set('target_type', params.target_type)
    if (params.states?.length) query.set('state', [...new Set(params.states)].sort().join(','))
    return request(accessToken, `${path}${query.size ? `?${query}` : ''}`, 'list', isOperationPage)
  },

  async create(
    accessToken: string,
    scope: CacheOperationScope,
    input: CreateCacheOperationInput,
    idempotencyKey: string,
  ): Promise<CacheOperation> {
    const query = new URLSearchParams()
    addScope(query, scope)
    const path = operationPath(scope)
    return request(accessToken, `${path}${query.size ? `?${query}` : ''}`, 'create', isOperation, {
      method: 'POST',
      headers: commandHeaders(idempotencyKey),
      body: JSON.stringify(input),
    })
  },

  async get(
    accessToken: string,
    scope: CacheOperationScope,
    operationID: string,
  ): Promise<CacheOperation> {
    const query = new URLSearchParams()
    addScope(query, scope)
    const path = operationPath(scope, `/${encodeURIComponent(operationID)}`)
    return request(accessToken, `${path}${query.size ? `?${query}` : ''}`, 'detail', isOperation)
  },

  /** The account's quotas of today; an administrator names the account with an admin scope. */
  async dailyUsage(
    accessToken: string,
    scope: CacheOperationScope,
  ): Promise<CacheDailyUsage> {
    const query = new URLSearchParams()
    addScope(query, scope)
    return request(accessToken, `${operationPath(scope, '/daily-usage')}${query.size ? `?${query}` : ''}`, 'daily-usage', isDailyUsage)
  },

  /** Administrator: set a tenant account's own daily limits (identity.users.manage); audited. */
  async setAccountLimits(
    accessToken: string,
    tenantScopeID: string,
    expectedRevision: number,
    limits: CacheAccountLimits,
  ): Promise<CacheDailyUsage> {
    const scope: CacheOperationScope = { kind: 'admin', scopeId: tenantScopeID }
    const query = new URLSearchParams()
    addScope(query, scope)
    return request(accessToken, `${operationPath(scope, '/daily-usage')}?${query}`, 'account-limits', isDailyUsage, {
      method: 'PUT',
      body: JSON.stringify({ expected_revision: expectedRevision, ...limits }),
    })
  },

  // Writes nothing: groups the URLs by the sites serving their hosts.
  async targetSites(
    accessToken: string,
    scope: CacheTargetSiteScope,
    input: ResolveCacheTargetSitesInput,
  ): Promise<CacheTargetSites> {
    const query = new URLSearchParams()
    let path = '/v1/admin/cache-operations/target-sites'
    if (scope.kind !== 'admin-all') {
      addScope(query, scope)
      path = operationPath(scope, '/target-sites')
    }
    return request(accessToken, `${path}${query.size ? `?${query}` : ''}`, 'target-sites', isTargetSites, {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async carryingNodes(accessToken: string, scope: CacheOperationScope): Promise<CacheCarryingNode[]> {
    const query = new URLSearchParams()
    addScope(query, scope)
    const page = await request(accessToken, `${operationPath(scope, '/carrying-nodes')}${query.size ? `?${query}` : ''}`,
      'carrying-nodes', isCarryingNodes)
    return page.items
  },

  /**
   * fix-cacheflow5: the server's record of a write sent with `ref.key` by this
   * session's principal. null: never received (also another principal's key),
   * so the same request may be sent again with the same key.
   */
  async writeReceipt(
    accessToken: string,
    scope: CacheOperationScope,
    ref: CacheWriteRef,
  ): Promise<CacheWriteReceipt | null> {
    if (scope.kind === 'admin' && !uuidPattern.test(scope.scopeId)) {
      throw new ApiError('Invalid tenant scope', 400, 'validation_error')
    }
    const query = new URLSearchParams({ action: ref.action })
    if (ref.action !== 'create') query.set('operation_id', ref.operationID)
    addScope(query, scope)
    const path = `${scope.kind === 'admin' ? '/v1/admin' : '/v1'}/cache-operation-requests/${encodeURIComponent(ref.key)}?${query}`
    let response: Response
    try {
      response = await fetch(`${apiRoot}${path}`, {
        credentials: 'include',
        headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': requestID('receipt') },
      })
    } catch {
      throw networkApiError()
    }
    // 404 is the answer "not received", not a failure to report.
    if (response.status === 404) return null
    if (!response.ok) throw await responseApiError(response)
    let value: unknown
    try {
      value = await response.json()
    } catch {
      throw invalidResponse()
    }
    if (!isWriteReceipt(value)) throw invalidResponse()
    return value
  },

  async retry(
    accessToken: string,
    scope: CacheOperationScope,
    operationID: string,
    idempotencyKey: string,
  ): Promise<CacheOperation> {
    return sendCommand(accessToken, scope, operationID, 'retry', idempotencyKey)
  },

  /**
   * 重新提交: a new operation with the original's targets, retry budget and nodes (or
   * the carrying nodes for an automatic one). One batch (re-submit selected) shares one
   * key; retrying the batch with the key replays instead of creating more operations.
   */
  async resubmit(
    accessToken: string,
    scope: CacheOperationScope,
    operationID: string,
    batchKey: string,
  ): Promise<CacheOperation> {
    return sendCommand(accessToken, scope, operationID, 'resubmit', batchKey)
  },

  async cancel(
    accessToken: string,
    scope: CacheOperationScope,
    operationID: string,
    idempotencyKey: string,
  ): Promise<CacheOperation> {
    return sendCommand(accessToken, scope, operationID, 'cancel', idempotencyKey)
  },
}
