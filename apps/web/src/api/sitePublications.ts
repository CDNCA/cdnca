import { ApiError, networkApiError, responseApiError } from './auth'

export type SitePublicationAudience =
  | { kind: 'tenant' }
  | { kind: 'platform'; targetScopeId: string }

export interface SitePublicationListQuery {
  cursor?: string
  limit?: number
}

export interface TenantPublicationTarget {
  kind: 'nodes' | 'line_group_snapshot'
}

export type AdminPublicationTarget =
  | { kind: 'nodes'; resolved_sha256: string }
  | {
      kind: 'line_group_snapshot'
      snapshot_id: string
      revision: number
      resolver_sha256: string
      resolved_sha256: string
    }

interface PublicationBase {
  id: string
  source_revision: number
  config_version_id: string
  rollout_id: string
  node_count: number
  created_at: string
}

export interface TenantSitePublication extends PublicationBase {
  target: TenantPublicationTarget
}

export interface AdminSitePublication extends PublicationBase {
  configuration_scope_id: string
  canonical_source_sha256: string
  artifact_sha256: string
  target: AdminPublicationTarget
  replayed?: boolean
}

/** A revoked module the scope's published release uses: pending republication. */
export interface PendingModule {
  module: string
  source_revision: number
}

/**
 * The scope's latest automatic publication published nothing: no node serves
 * its line groups, or every target node lacks what the release needs. It is
 * republished automatically once that changes.
 */
export interface AutomaticPublicationFailure {
  reason: 'no_target_nodes' | 'node_capability_unavailable' | 'node_artifacts_syncing' | 'node_scope_conflict'
  source_revision: number
  failed_at: string
  /** node_artifacts_syncing: segments the refused nodes have received of their node artifact sets; omitted before any node has one. */
  artifact_sync?: NodeArtifactSyncProgress
}

export interface NodeArtifactSyncProgress {
  received_segments: number
  total_segments: number
  remaining_minutes: number
}

export interface TenantSitePublicationPage {
  items: TenantSitePublication[]
  current_source_revision: number
  next_cursor?: string
  pending_modules?: PendingModule[]
  automatic_failure?: AutomaticPublicationFailure
}

export interface AdminSitePublicationPage {
  items: AdminSitePublication[]
  current_source_revision: number
  next_cursor?: string
  pending_modules?: PendingModule[]
  automatic_failure?: AutomaticPublicationFailure
}

export type RolloutState = 'queued' | 'running' | 'paused' | 'succeeded' | 'partial_failed' | 'failed' | 'cancelled'
export type RolloutAction = 'apply' | 'rollback'

export interface RolloutProgress {
  total: number
  pending: number
  running: number
  succeeded: number
  failed: number
  cancelled: number
  /** Nodes that ignored this old release (they already run a newer one); not a failure. */
  superseded: number
  /** Nodes that refused it while frozen (expired service ticket); redelivered once they renew it. Not a failure. */
  frozen: number
}

interface RolloutBase {
  id: string
  config_version_id: string
  action: RolloutAction
  state: RolloutState
  revision: number
  max_attempts: number
  progress: RolloutProgress
  can_cancel: boolean
  can_retry: boolean
  can_start?: boolean
  can_pause?: boolean
  can_resume?: boolean
  rollout?: RolloutPolicy
  pause_reason?: '' | 'operator' | 'failure_threshold'
  created_at: string
  updated_at: string
}

export interface RolloutPolicy {
  strategy: 'canary'
  canary_size: number
  batch_size: number
  failure_threshold: number
  cohort_count: number
  released_cohort: number
}

export type TenantSiteRollout = RolloutBase

export interface AdminSiteRollout extends RolloutBase {
  configuration_scope_id: string
  replayed?: boolean
}

export interface TenantSiteRolloutPage {
  items: TenantSiteRollout[]
  next_cursor?: string
}

export interface AdminSiteRolloutPage {
  items: AdminSiteRollout[]
  next_cursor?: string
}

export type DeploymentState =
  | 'queued'
  | 'delivered'
  | 'staged'
  | 'prechecked'
  | 'activated'
  | 'healthy'
  | 'failed'
  | 'reverting'
  | 'reverted'
  | 'rollback_failed'
  | 'cancelled'

interface DeploymentBase {
  id: string
  attempt: number
  max_attempts: number
  state: DeploymentState
  error_code?: string
  created_at: string
  updated_at: string
  can_retry: boolean
  cohort?: number
  released?: boolean
  /** The node ignored this old release (already on a newer one, or it was rolled back); not a failure. */
  superseded?: boolean
  /** The node refused it while frozen (expired service ticket): waiting for redelivery, not a failure. */
  frozen?: boolean
  /** Platform only: faults the node reported with a successful deployment (the release runs). */
  warnings?: DeploymentWarning[]
}

export type DeploymentWarning = 'ddos_protection_fault' | 'post_activation_maintenance_failed'
const deploymentWarnings: readonly DeploymentWarning[] = ['ddos_protection_fault', 'post_activation_maintenance_failed']

export type TenantSiteDeployment = DeploymentBase

export interface AdminSiteDeployment extends DeploymentBase {
  node_id: string
}

export interface TenantSiteDeploymentPage {
  items: TenantSiteDeployment[]
  next_cursor?: string
}

export interface AdminSiteDeploymentPage {
  items: AdminSiteDeployment[]
  next_cursor?: string
}

export type LineGroupSnapshotPublicationTarget = Extract<AdminPublicationTarget, { kind: 'line_group_snapshot' }>

export type SitePublicationWriteTarget =
  | { kind: 'nodes'; node_ids: string[] }
  | {
      kind: 'line_group_snapshot'
      snapshot_id: string
      revision: number
      resolver_sha256: string
    }

export interface PublishSiteConfigurationInput {
  configuration_scope_id: string
  expected_source_revision: number
  target: SitePublicationWriteTarget
  health_check: {
    activation_timeout_ms: number
    observation_window_ms: number
    required_consecutive_successes: number
  }
  max_attempts: number
  deadline: string
  rollout?: RolloutPolicyInput
}

export interface RolloutPolicyInput {
  strategy: 'canary'
  canary_size: number
  batch_size: number
  failure_threshold: number
  auto_start: boolean
}

export interface RollbackSitePublicationInput {
  configuration_scope_id: string
  target: SitePublicationWriteTarget
  health_check: PublishSiteConfigurationInput['health_check']
  max_attempts: number
  deadline: string
  rollout?: RolloutPolicyInput
}

export interface AdminSiteRollback {
  publication_id: string
  configuration_scope_id: string
  config_version_id: string
  rollout_id: string
  action: 'rollback'
  target: AdminPublicationTarget
  node_count: number
  created_at: string
  replayed?: boolean
}

export interface SiteRolloutCommandInput {
  configuration_scope_id: string
  expected_revision: number
}

export interface SitePublicationWriteMetadata {
  requestId: string
  idempotencyKey: string
  traceparent: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const canonicalUUIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const sha256Pattern = /^(?!0{64}$)[0-9a-f]{64}$/
const cursorPattern = /^[A-Za-z0-9_-]{1,4096}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const traceparentPattern = /^00-(?!0{32}-)[0-9a-f]{32}-(?!0{16}-)[0-9a-f]{16}-[0-9a-f]{2}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/
const errorCodePattern = /^[A-Z0-9_]{1,128}$/
const moduleCodePattern = /^(module|pack|theme)\.[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$/

const rolloutStates = new Set<RolloutState>([
  'queued', 'running', 'paused', 'succeeded', 'partial_failed', 'failed', 'cancelled',
])
const deploymentStates = new Set<DeploymentState>([
  'queued', 'delivered', 'staged', 'prechecked', 'activated', 'healthy', 'failed',
  'reverting', 'reverted', 'rollback_failed', 'cancelled',
])

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('Invalid site publication request', 400, 'invalid_request')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function canonicalUUID(value: unknown): value is string {
  return typeof value === 'string' && canonicalUUIDPattern.test(value)
}

function sha256(value: unknown): value is string {
  return typeof value === 'string' && sha256Pattern.test(value)
}

function uint(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false
  const match = timestampPattern.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)))
  if (date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== Number(month) - 1 ||
    date.getUTCDate() !== Number(day) || Number(hour) > 23 || Number(minute) > 59 ||
    Number(second) > 59 || Number(offsetHour ?? 0) > 14 || Number(offsetMinute ?? 0) > 59 ||
    (Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0)) return false
  return !Number.isNaN(Date.parse(value))
}

function cursor(value: unknown): value is string {
  return typeof value === 'string' && cursorPattern.test(value)
}

function parseTenantTarget(value: unknown): TenantPublicationTarget {
  if (!record(value) || !exactKeys(value, ['kind']) ||
    (value.kind !== 'nodes' && value.kind !== 'line_group_snapshot')) throw invalidResponse()
  return { kind: value.kind }
}

function parseAdminTarget(value: unknown): AdminPublicationTarget {
  if (!record(value)) throw invalidResponse()
  if (value.kind === 'nodes') {
    if (!exactKeys(value, ['kind', 'resolved_sha256']) || !sha256(value.resolved_sha256)) {
      throw invalidResponse()
    }
    return { kind: 'nodes', resolved_sha256: value.resolved_sha256 }
  }
  if (value.kind === 'line_group_snapshot') {
    if (!exactKeys(value, [
      'kind', 'snapshot_id', 'revision', 'resolver_sha256', 'resolved_sha256',
    ]) || !canonicalUUID(value.snapshot_id) || !uint(value.revision, 1) ||
      !sha256(value.resolver_sha256) || !sha256(value.resolved_sha256)) throw invalidResponse()
    return {
      kind: 'line_group_snapshot',
      snapshot_id: value.snapshot_id,
      revision: value.revision,
      resolver_sha256: value.resolver_sha256,
      resolved_sha256: value.resolved_sha256,
    }
  }
  throw invalidResponse()
}

function parseTenantPublication(value: unknown): TenantSitePublication {
  const required = ['id', 'source_revision', 'config_version_id', 'rollout_id', 'target', 'node_count', 'created_at']
  if (!record(value) || !exactKeys(value, required) || !canonicalUUID(value.id) ||
    !uint(value.source_revision, 1) || !canonicalUUID(value.config_version_id) ||
    !canonicalUUID(value.rollout_id) || !uint(value.node_count, 1, 10_000) || !timestamp(value.created_at)) {
    throw invalidResponse()
  }
  return { ...value, target: parseTenantTarget(value.target) } as unknown as TenantSitePublication
}

function parseAdminPublication(
  value: unknown,
  expectedScopeID?: string,
  expectedPublicationID?: string,
): AdminSitePublication {
  const required = [
    'id', 'configuration_scope_id', 'source_revision', 'config_version_id', 'rollout_id',
    'canonical_source_sha256', 'artifact_sha256', 'target', 'node_count', 'created_at',
  ]
  if (!record(value) || !exactKeys(value, required, ['replayed']) || !canonicalUUID(value.id) ||
    !canonicalUUID(value.configuration_scope_id) || !uint(value.source_revision, 1) ||
    !canonicalUUID(value.config_version_id) || !canonicalUUID(value.rollout_id) ||
    !sha256(value.canonical_source_sha256) || !sha256(value.artifact_sha256) ||
    !uint(value.node_count, 1, 10_000) || !timestamp(value.created_at) ||
    (value.replayed !== undefined && typeof value.replayed !== 'boolean') ||
    (expectedScopeID !== undefined && value.configuration_scope_id !== expectedScopeID) ||
    (expectedPublicationID !== undefined && value.id !== expectedPublicationID)) throw invalidResponse()
  return { ...value, target: parseAdminTarget(value.target) } as unknown as AdminSitePublication
}

function parseProgress(value: unknown): RolloutProgress {
  const keys = ['total', 'pending', 'running', 'succeeded', 'failed', 'cancelled', 'superseded', 'frozen']
  if (!record(value) || !exactKeys(value, keys) || !uint(value.total, 1, 10_000) ||
    !keys.slice(1).every((key) => uint(value[key], 0, 10_000)) ||
    keys.slice(1).reduce((sum, key) => sum + Number(value[key]), 0) !== value.total) throw invalidResponse()
  return value as unknown as RolloutProgress
}

function parseRolloutBase(
  value: unknown,
  platform: boolean,
  expectedScopeID?: string,
  expectedRolloutID?: string,
): TenantSiteRollout | AdminSiteRollout {
  if (!record(value)) throw invalidResponse()
  const state = value.state === 'completed' ? 'succeeded' : value.state
  const required = [
    'id', 'config_version_id', 'action', 'state', 'revision', 'max_attempts', 'progress',
    'can_cancel', 'can_retry', 'created_at', 'updated_at',
  ]
  if (platform) required.push('configuration_scope_id')
  const optional = [
    'can_start', 'can_pause', 'can_resume', 'rollout', 'pause_reason',
    ...(platform ? ['replayed'] : []),
  ]
  if (!exactKeys(value, required, optional) || !canonicalUUID(value.id) ||
    !canonicalUUID(value.config_version_id) || (platform && !canonicalUUID(value.configuration_scope_id)) ||
    (value.action !== 'apply' && value.action !== 'rollback') ||
    typeof state !== 'string' || !rolloutStates.has(state as RolloutState) ||
    !uint(value.revision, 1) || !uint(value.max_attempts, 1, 10) ||
    typeof value.can_cancel !== 'boolean' || typeof value.can_retry !== 'boolean' ||
    !timestamp(value.created_at) || !timestamp(value.updated_at) ||
    (value.replayed !== undefined && typeof value.replayed !== 'boolean') ||
    (expectedScopeID !== undefined && value.configuration_scope_id !== expectedScopeID) ||
    (expectedRolloutID !== undefined && value.id !== expectedRolloutID)) throw invalidResponse()
  const progressive = value.rollout !== undefined
  if (progressive) {
    if (!record(value.rollout) || !exactKeys(value.rollout, [
      'strategy', 'canary_size', 'batch_size', 'failure_threshold', 'cohort_count', 'released_cohort',
    ]) || value.rollout.strategy !== 'canary' || !uint(value.rollout.canary_size, 1, 1000) ||
      !uint(value.rollout.batch_size, 1, 1000) || !uint(value.rollout.failure_threshold, 1, 10_000) ||
	  !uint(value.rollout.cohort_count, 1, 10_000) || !uint(value.rollout.released_cohort, -1, 10_000) ||
      typeof value.can_start !== 'boolean' || typeof value.can_pause !== 'boolean' ||
      typeof value.can_resume !== 'boolean' || typeof value.pause_reason !== 'string' ||
      !['', 'operator', 'failure_threshold'].includes(value.pause_reason)) throw invalidResponse()
  } else if (state === 'paused' ||
    (value.can_start !== undefined && value.can_start !== false) ||
    (value.can_pause !== undefined && value.can_pause !== false) ||
    (value.can_resume !== undefined && value.can_resume !== false) ||
    (value.pause_reason !== undefined && value.pause_reason !== '')) throw invalidResponse()
  return { ...value, state, progress: parseProgress(value.progress) } as unknown as TenantSiteRollout | AdminSiteRollout
}

function parseDeployment(value: unknown, platform: boolean): TenantSiteDeployment | AdminSiteDeployment {
  const required = ['id', 'attempt', 'max_attempts', 'state', 'created_at', 'updated_at', 'can_retry']
  if (platform) required.push('node_id')
  if (!record(value) || !exactKeys(value, required, platform ? ['error_code', 'cohort', 'released', 'superseded', 'frozen', 'warnings'] : ['error_code', 'cohort', 'released', 'superseded', 'frozen']) || !canonicalUUID(value.id) ||
    (platform && !canonicalUUID(value.node_id)) || !uint(value.attempt, 1, 10) ||
    !uint(value.max_attempts, 1, 10) || Number(value.attempt) > Number(value.max_attempts) ||
    typeof value.state !== 'string' || !deploymentStates.has(value.state as DeploymentState) ||
    (value.error_code !== undefined && (typeof value.error_code !== 'string' || !errorCodePattern.test(value.error_code))) ||
    !timestamp(value.created_at) || !timestamp(value.updated_at) || typeof value.can_retry !== 'boolean' ||
    (value.superseded !== undefined && (value.superseded !== true || value.state !== 'failed' || value.can_retry !== false)) ||
    (value.frozen !== undefined && (value.frozen !== true || value.superseded !== undefined || value.state !== 'failed' || value.can_retry !== false)) ||
    (value.warnings !== undefined && (!Array.isArray(value.warnings) || value.warnings.length === 0 ||
      value.warnings.length > deploymentWarnings.length || new Set(value.warnings).size !== value.warnings.length ||
      !value.warnings.every((warning) => deploymentWarnings.includes(warning as DeploymentWarning)))) ||
    (value.cohort === undefined) !== (value.released === undefined) ||
    (value.cohort !== undefined && (!uint(value.cohort, 0, 10_000) || typeof value.released !== 'boolean'))) {
    throw invalidResponse()
  }
  return value as unknown as TenantSiteDeployment | AdminSiteDeployment
}

function parsePage<T>(
  value: unknown,
  parseItem: (item: unknown) => T,
  includesRevision: boolean,
): {
  items: T[]; current_source_revision?: number; next_cursor?: string; pending_modules?: PendingModule[]
  automatic_failure?: AutomaticPublicationFailure
} {
  const required = includesRevision ? ['items', 'current_source_revision'] : ['items']
  const optional = includesRevision ? ['next_cursor', 'pending_modules', 'automatic_failure'] : ['next_cursor']
  if (!record(value) || !exactKeys(value, required, optional) || !Array.isArray(value.items) ||
    value.items.length > 100 || (includesRevision && !uint(value.current_source_revision, 1)) ||
    (value.next_cursor !== undefined && !cursor(value.next_cursor)) ||
    (value.pending_modules !== undefined && !pendingModules(value.pending_modules)) ||
    (value.automatic_failure !== undefined && !automaticFailure(value.automatic_failure))) throw invalidResponse()
  return {
    items: value.items.map(parseItem),
    ...(includesRevision ? { current_source_revision: value.current_source_revision as number } : {}),
    ...(value.next_cursor === undefined ? {} : { next_cursor: value.next_cursor }),
    ...(value.pending_modules === undefined ? {} : { pending_modules: value.pending_modules as PendingModule[] }),
    ...(value.automatic_failure === undefined ? {} : { automatic_failure: value.automatic_failure as AutomaticPublicationFailure }),
  }
}

function automaticFailure(value: unknown): value is AutomaticPublicationFailure {
  return record(value) && exactKeys(value, ['reason', 'source_revision', 'failed_at'], ['artifact_sync']) &&
    (value.reason === 'no_target_nodes' || value.reason === 'node_capability_unavailable' ||
      value.reason === 'node_artifacts_syncing' || value.reason === 'node_scope_conflict') &&
    uint(value.source_revision, 1) && timestamp(value.failed_at) &&
    (value.artifact_sync === undefined || (value.reason === 'node_artifacts_syncing' && artifactSync(value.artifact_sync)))
}

function artifactSync(value: unknown): value is NodeArtifactSyncProgress {
  return record(value) && exactKeys(value, ['received_segments', 'total_segments', 'remaining_minutes']) &&
    uint(value.total_segments, 1) && uint(value.received_segments, 0, value.total_segments as number) &&
    uint(value.remaining_minutes, 1)
}

function pendingModules(value: unknown): value is PendingModule[] {
  return Array.isArray(value) && value.length <= 256 && value.every((item) => record(item) &&
    exactKeys(item, ['module', 'source_revision']) && typeof item.module === 'string' && item.module.length <= 128 &&
    moduleCodePattern.test(item.module) && uint(item.source_revision, 1))
}

function validateAudience(audience: SitePublicationAudience): void {
  if (!record(audience) || (audience.kind === 'tenant'
    ? !exactKeys(audience, ['kind'])
    : audience.kind !== 'platform' || !exactKeys(audience, ['kind', 'targetScopeId']) ||
      !canonicalUUID(audience.targetScopeId))) throw invalidRequest()
}

function listQuery(values: SitePublicationListQuery, audience: SitePublicationAudience): string {
  validateAudience(audience)
  const params = new URLSearchParams()
  if (audience.kind === 'platform') params.set('scope_id', audience.targetScopeId)
  if (values.limit !== undefined) {
    if (!uint(values.limit, 1, 100)) throw invalidRequest()
    params.set('limit', String(values.limit))
  }
  if (values.cursor !== undefined) {
    if (!cursor(values.cursor)) throw invalidRequest()
    params.set('cursor', values.cursor)
  }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

function readPath(audience: SitePublicationAudience, resource: string, id?: string): string {
  validateAudience(audience)
  if (id !== undefined && !canonicalUUID(id)) throw invalidRequest()
  const prefix = audience.kind === 'platform' ? '/v1/admin' : '/v1'
  const suffix = id === undefined ? '' : `/${encodeURIComponent(id)}`
  const scope = audience.kind === 'platform' ? `?scope_id=${encodeURIComponent(audience.targetScopeId)}` : ''
  return `${prefix}/${resource}${suffix}${scope}`
}

async function request<T>(
  accessToken: string,
  path: string,
  parse: (value: unknown) => T,
  init: RequestInit = {},
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
  if (!response.ok) throw await responseApiError(response)
  try {
    return parse(await response.json())
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidResponse()
  }
}

function parsePublicationFor(audience: SitePublicationAudience, expectedPublicationID?: string) {
  return audience.kind === 'platform'
    ? (value: unknown) => parseAdminPublication(value, audience.targetScopeId, expectedPublicationID)
    : (value: unknown) => {
        const parsed = parseTenantPublication(value)
        if (expectedPublicationID !== undefined && parsed.id !== expectedPublicationID) throw invalidResponse()
        return parsed
      }
}

function parseRolloutFor(audience: SitePublicationAudience, expectedRolloutID?: string) {
  return (value: unknown) => parseRolloutBase(
    value,
    audience.kind === 'platform',
    audience.kind === 'platform' ? audience.targetScopeId : undefined,
    expectedRolloutID,
  )
}

function parseDeploymentFor(audience: SitePublicationAudience) {
  return (value: unknown) => parseDeployment(value, audience.kind === 'platform')
}

function writeHeaders(metadata: SitePublicationWriteMetadata): HeadersInit {
  if (!record(metadata) || !exactKeys(metadata, ['requestId', 'idempotencyKey', 'traceparent']) ||
    !canonicalUUID(metadata.requestId) || typeof metadata.idempotencyKey !== 'string' ||
    !idempotencyPattern.test(metadata.idempotencyKey) || typeof metadata.traceparent !== 'string' ||
    !traceparentPattern.test(metadata.traceparent)) throw invalidRequest()
  return {
    'X-Request-ID': metadata.requestId,
    'Idempotency-Key': metadata.idempotencyKey,
    Traceparent: metadata.traceparent,
  }
}

function validateResponseTarget(value: unknown): asserts value is AdminPublicationTarget {
  if (!record(value)) throw invalidRequest()
  if (value.kind === 'nodes') {
    if (!exactKeys(value, ['kind', 'resolved_sha256']) || !sha256(value.resolved_sha256)) {
      throw invalidRequest()
    }
    return
  }
  if (value.kind === 'line_group_snapshot' && exactKeys(value, [
    'kind', 'snapshot_id', 'revision', 'resolver_sha256', 'resolved_sha256',
  ]) && canonicalUUID(value.snapshot_id) && uint(value.revision, 1) &&
    sha256(value.resolver_sha256) && sha256(value.resolved_sha256)) return
  throw invalidRequest()
}

function validateWriteTarget(value: unknown): asserts value is SitePublicationWriteTarget {
  if (!record(value)) throw invalidRequest()
  if (value.kind === 'nodes' && exactKeys(value, ['kind', 'node_ids']) &&
    Array.isArray(value.node_ids) && value.node_ids.length >= 1 && value.node_ids.length <= 10_000 &&
    value.node_ids.every(canonicalUUID) && new Set(value.node_ids).size === value.node_ids.length) return
  if (value.kind === 'line_group_snapshot' && exactKeys(value, [
    'kind', 'snapshot_id', 'revision', 'resolver_sha256',
  ]) && canonicalUUID(value.snapshot_id) && uint(value.revision, 1) && sha256(value.resolver_sha256)) return
  throw invalidRequest()
}

function validatePublishInput(value: PublishSiteConfigurationInput): void {
  if (!record(value) || !exactKeys(value, [
    'configuration_scope_id', 'expected_source_revision', 'target', 'health_check',
    'max_attempts', 'deadline',
  ], ['rollout']) || !canonicalUUID(value.configuration_scope_id) || !uint(value.expected_source_revision, 1) ||
    !record(value.health_check) || !exactKeys(value.health_check, [
      'activation_timeout_ms', 'observation_window_ms', 'required_consecutive_successes',
    ]) || !uint(value.health_check.activation_timeout_ms, 1, 86_400_000) ||
    !uint(value.health_check.observation_window_ms, 1, 86_400_000) ||
    !uint(value.health_check.required_consecutive_successes, 1, 100) ||
    !uint(value.max_attempts, 1, 10) || !timestamp(value.deadline) || !validRolloutInput(value.rollout)) throw invalidRequest()
  validateWriteTarget(value.target)
}

function validateRollbackInput(value: RollbackSitePublicationInput): void {
  if (!record(value) || !exactKeys(value, [
    'configuration_scope_id', 'target', 'health_check', 'max_attempts', 'deadline',
  ], ['rollout']) || !canonicalUUID(value.configuration_scope_id) ||
    !record(value.health_check) || !exactKeys(value.health_check, [
      'activation_timeout_ms', 'observation_window_ms', 'required_consecutive_successes',
    ]) || !uint(value.health_check.activation_timeout_ms, 1, 86_400_000) ||
    !uint(value.health_check.observation_window_ms, 1, 86_400_000) ||
    !uint(value.health_check.required_consecutive_successes, 1, 100) ||
    !uint(value.max_attempts, 1, 10) || !timestamp(value.deadline) || !validRolloutInput(value.rollout)) throw invalidRequest()
  validateWriteTarget(value.target)
}

function validRolloutInput(value: unknown): boolean {
  return value === undefined || record(value) && exactKeys(value, [
    'strategy', 'canary_size', 'batch_size', 'failure_threshold', 'auto_start',
  ]) && value.strategy === 'canary' && uint(value.canary_size, 1, 1000) &&
    uint(value.batch_size, 1, 1000) && uint(value.failure_threshold, 1, 10_000) &&
    typeof value.auto_start === 'boolean'
}

function validateCommandInput(value: SiteRolloutCommandInput): void {
  if (!record(value) || !exactKeys(value, ['configuration_scope_id', 'expected_revision']) ||
    !canonicalUUID(value.configuration_scope_id) || !uint(value.expected_revision, 1)) throw invalidRequest()
}

function listPublications(
  accessToken: string,
  audience: { kind: 'tenant' },
  values?: SitePublicationListQuery,
): Promise<TenantSitePublicationPage>
function listPublications(
  accessToken: string,
  audience: { kind: 'platform'; targetScopeId: string },
  values?: SitePublicationListQuery,
): Promise<AdminSitePublicationPage>
async function listPublications(
  accessToken: string,
  audience: SitePublicationAudience,
  values: SitePublicationListQuery = {},
): Promise<TenantSitePublicationPage | AdminSitePublicationPage> {
  const path = `${audience.kind === 'platform' ? '/v1/admin' : '/v1'}/site-publications${listQuery(values, audience)}`
  return request(accessToken, path, (value) => parsePage(value, parsePublicationFor(audience), true)) as
    Promise<TenantSitePublicationPage | AdminSitePublicationPage>
}

async function getPublication(accessToken: string, audience: SitePublicationAudience, publicationID: string) {
  return request(accessToken, readPath(audience, 'site-publications', publicationID),
    parsePublicationFor(audience, publicationID))
}

async function listRollouts(accessToken: string, audience: SitePublicationAudience, values: SitePublicationListQuery = {}) {
  const path = `${audience.kind === 'platform' ? '/v1/admin' : '/v1'}/site-rollouts${listQuery(values, audience)}`
  return request(accessToken, path, (value) => parsePage(value, parseRolloutFor(audience), false))
}

async function getRollout(accessToken: string, audience: SitePublicationAudience, rolloutID: string) {
  return request(accessToken, readPath(audience, 'site-rollouts', rolloutID),
    parseRolloutFor(audience, rolloutID))
}

async function listDeployments(
  accessToken: string,
  audience: SitePublicationAudience,
  rolloutID: string,
  values: SitePublicationListQuery = {},
) {
  if (!canonicalUUID(rolloutID)) throw invalidRequest()
  const prefix = audience.kind === 'platform' ? '/v1/admin' : '/v1'
  const path = `${prefix}/site-rollouts/${encodeURIComponent(rolloutID)}/deployments${listQuery(values, audience)}`
  return request(accessToken, path, (value) => parsePage(value, parseDeploymentFor(audience), false))
}

async function publish(
  accessToken: string,
  input: PublishSiteConfigurationInput,
  metadata: SitePublicationWriteMetadata,
): Promise<AdminSitePublication> {
  validatePublishInput(input)
  return request(accessToken, '/v1/admin/site-publications',
    (value) => parseAdminPublication(value, input.configuration_scope_id), {
    method: 'POST', headers: writeHeaders(metadata), body: JSON.stringify(input),
  })
}

async function rollback(
  accessToken: string,
  publicationID: string,
  input: RollbackSitePublicationInput,
  metadata: SitePublicationWriteMetadata,
): Promise<AdminSiteRollback> {
  if (!canonicalUUID(publicationID)) throw invalidRequest()
  validateRollbackInput(input)
  return request(accessToken, `/v1/admin/site-publications/${encodeURIComponent(publicationID)}/rollback`, (value) => {
    if (!record(value) || !exactKeys(value, [
      'publication_id', 'configuration_scope_id', 'config_version_id', 'rollout_id',
      'action', 'target', 'node_count', 'created_at',
    ], ['replayed']) || value.publication_id !== publicationID ||
      value.configuration_scope_id !== input.configuration_scope_id || !canonicalUUID(value.config_version_id) ||
      !canonicalUUID(value.rollout_id) || value.action !== 'rollback' || !uint(value.node_count, 1, 10_000) ||
      !timestamp(value.created_at) || value.replayed !== undefined && typeof value.replayed !== 'boolean') {
      throw invalidResponse()
    }
    validateResponseTarget(value.target)
    return value as unknown as AdminSiteRollback
  }, {
    method: 'POST', headers: writeHeaders(metadata), body: JSON.stringify(input),
  })
}

async function rolloutCommand(
  accessToken: string,
  rolloutID: string,
  suffix: 'start' | 'pause' | 'resume' | 'cancel' | 'retry-failed',
  input: SiteRolloutCommandInput,
  metadata: SitePublicationWriteMetadata,
): Promise<AdminSiteRollout> {
  if (!canonicalUUID(rolloutID)) throw invalidRequest()
  validateCommandInput(input)
  return request(accessToken, `/v1/admin/site-rollouts/${encodeURIComponent(rolloutID)}/${suffix}`,
    (value) => parseRolloutBase(
      value, true, input.configuration_scope_id, rolloutID,
    ) as AdminSiteRollout, {
      method: 'POST', headers: writeHeaders(metadata), body: JSON.stringify(input),
    })
}

export const sitePublicationsApi = {
  listPublications,
  getPublication,
  listRollouts,
  getRollout,
  listDeployments,
  publish,
  rollback,
  startRollout: (
    accessToken: string, rolloutID: string, input: SiteRolloutCommandInput, metadata: SitePublicationWriteMetadata,
  ) => rolloutCommand(accessToken, rolloutID, 'start', input, metadata),
  pauseRollout: (
    accessToken: string, rolloutID: string, input: SiteRolloutCommandInput, metadata: SitePublicationWriteMetadata,
  ) => rolloutCommand(accessToken, rolloutID, 'pause', input, metadata),
  resumeRollout: (
    accessToken: string, rolloutID: string, input: SiteRolloutCommandInput, metadata: SitePublicationWriteMetadata,
  ) => rolloutCommand(accessToken, rolloutID, 'resume', input, metadata),
  cancelRollout: (
    accessToken: string,
    rolloutID: string,
    input: SiteRolloutCommandInput,
    metadata: SitePublicationWriteMetadata,
  ) => rolloutCommand(accessToken, rolloutID, 'cancel', input, metadata),
  retryFailedRollout: (
    accessToken: string,
    rolloutID: string,
    input: SiteRolloutCommandInput,
    metadata: SitePublicationWriteMetadata,
  ) => rolloutCommand(accessToken, rolloutID, 'retry-failed', input, metadata),
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  if (!globalThis.crypto?.getRandomValues) throw new ApiError('Secure request metadata unavailable', 0, 'request_metadata_unavailable')
  globalThis.crypto.getRandomValues(bytes)
  if (bytes.every((byte) => byte === 0)) bytes[0] = 1
  return bytes
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function randomUUID(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID().toLowerCase()
  const bytes = randomBytes(16)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const encoded = hex(bytes)
  return `${encoded.slice(0, 8)}-${encoded.slice(8, 12)}-${encoded.slice(12, 16)}-${encoded.slice(16, 20)}-${encoded.slice(20)}`
}

export function newSitePublicationWriteMetadata(operation: 'publish' | 'rollback' | 'start' | 'pause' | 'resume' | 'cancel' | 'retry'): SitePublicationWriteMetadata {
  const requestId = randomUUID()
  return {
    requestId,
    idempotencyKey: `site-publication-${operation}-${requestId}`,
    traceparent: `00-${hex(randomBytes(16))}-${hex(randomBytes(8))}-01`,
  }
}

export function sitePublicationOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

export function lineGroupTargetFromSnapshot(
  value: unknown,
  targetScopeID: string,
  lineGroupID: string,
  sourceRevision: number,
): Extract<SitePublicationWriteTarget, { kind: 'line_group_snapshot' }> {
  const required = [
    'id', 'revision', 'tenant_scope_id', 'source_line_group_id', 'source_revision',
    'source_configuration_digest', 'node_set_digest', 'node_ids',
  ]
  if (!canonicalUUID(targetScopeID) || !canonicalUUID(lineGroupID) || !uint(sourceRevision, 1) ||
    !record(value) || !exactKeys(value, required) || !canonicalUUID(value.id) ||
    !uint(value.revision, 1) || value.tenant_scope_id !== targetScopeID ||
    value.source_line_group_id !== lineGroupID || value.source_revision !== sourceRevision ||
    !sha256(value.source_configuration_digest) || !sha256(value.node_set_digest) ||
    !Array.isArray(value.node_ids) || value.node_ids.length < 1 || value.node_ids.length > 10_000 ||
    !value.node_ids.every(canonicalUUID) || new Set(value.node_ids).size !== value.node_ids.length) throw invalidRequest()
  return {
    kind: 'line_group_snapshot',
    snapshot_id: value.id,
    revision: value.revision,
    resolver_sha256: value.node_set_digest,
  }
}
