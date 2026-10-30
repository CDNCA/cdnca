import { ApiError, networkApiError, responseApiError } from './auth'

export const controlUpgradeReasons = [
  'eligible',
  'entitlement_unavailable',
  'entitlement_invalid',
  'entitlement_state_denied',
  'entitlement_channel_mismatch',
  'entitlement_version_denied',
  'platform_policy_stale',
  'release_channel_denied',
] as const

export const controlUpgradePlanStates = [
  'queued',
  'canary',
  'running',
  'paused',
  'rolling_back',
  'completed',
  'failed',
] as const

export type ControlUpgradeReason = (typeof controlUpgradeReasons)[number]
export type ControlUpgradePlanState = (typeof controlUpgradePlanStates)[number]
export type ControlUpgradeRolloutAction = 'start' | 'pause' | 'resume' | 'rollback'
export type ControlUpgradeNodeState = 'pending' | 'dispatched' | 'healthy' | 'failed' | 'rolled_back'
export type ControlUpgradeStatusState =
  | 'accepted'
  | 'claimed'
  | 'installing'
  | 'healthy'
  | 'failed'
  | 'rolling_back'
  | 'rolled_back'
  | 'uncertain'

export interface ControlUpgradeCheckInput {
  component: string
  current_version: string
  channel: string
}

export interface ControlUpgradeEntitlementDecision {
  serial: number
  channel: string
  min_version: string
  max_version: string
}

export interface ControlUpgradePolicyDecision {
  source: 'default' | 'global' | 'installation'
  target_revision_id?: string
  stale: boolean
}

export interface ControlUpgradeCheckResponse extends ControlUpgradeCheckInput {
  eligible: boolean
  reason: ControlUpgradeReason
  entitlement?: ControlUpgradeEntitlementDecision
  policy: ControlUpgradePolicyDecision
}

export interface ControlUpgradeRequestMetadata {
  requestId: string
  idempotencyKey: string
}

export interface ControlUpgradeListParams {
  page: number
  pageSize: number
  state?: ControlUpgradePlanState
  nodeId?: string
}

export interface ControlUpgradeCreateInput {
  schema: 'cdnca.control-upgrade-rollout.create/v1'
  node_ids: string[]
  canary_node_ids: string[]
  batch_size: number
  automatic_rollback: true
}

export interface ControlUpgradeActionInput {
  expected_revision: string
  reason: string
}

export interface ControlUpgradeBlocker {
  code: 'irreversible_migration' | 'rollback_unavailable' | 'agent_incompatible' | 'protocol_incompatible'
  node_id?: string
}

export interface ControlUpgradeRolloutSummary {
  id: string
  schema_version: 2
  installation_id: string
  component: string
  current_version: string
  target_version: string
  state: ControlUpgradePlanState
  completion: '' | 'upgraded' | 'rolled_back'
  revision: string
  automatic_rollback: true
  parent_grant_id: string
  artifact_id: string
  artifact_sha256: string
  artifact_size_bytes: number
  rollback_artifact_id: string
  rollback_artifact_sha256: string
  rollback_artifact_size_bytes: number
  active_batch: number
  total_nodes: number
  pending_nodes: number
  dispatched_nodes: number
  healthy_nodes: number
  failed_nodes: number
  rolled_back_nodes: number
  blockers: ControlUpgradeBlocker[]
  created_at: string
  updated_at: string
}

export interface ControlUpgradeRolloutBatch {
  id: string
  group_id: string
  canary: boolean
  node_ids: string[]
}

export interface ControlUpgradeRolloutNode {
  node_id: string
  agent_version: string
  protocol_version: number
  state: ControlUpgradeNodeState
  dispatch_revision: string
}

export interface ControlUpgradeRolloutEvent {
  id: string
  revision: string
  from: ControlUpgradePlanState
  to: ControlUpgradePlanState
  action: 'start' | 'pause' | 'resume' | 'rollback' | 'health_failed' | 'health_succeeded' | 'outcome_uncertain'
  reason: string
  batch_id: string
  node_id: string
  /** When the event was committed; present on detail reads only. */
  occurred_at?: string
}

export interface ControlUpgradeActiveProbeEvidence {
  schema: 'cdnca.edge.upgrade.active-probe/v1'
  active_artifact_sha256: string
  active_config_sha256: string
  last_known_good_artifact_sha256: string
  last_known_good_config_sha256: string
  probe_observed_at: string
  probe_deadline: string
  evidence_sha256: string
}

export interface ControlUpgradeStatusReceipt {
  schema: 'cdnca.edge.upgrade.status/v1' | 'cdnca.edge.upgrade.status/v2'
  status_id: string
  status_revision: string
  command_id: string
  plan_id: string
  plan_revision: string
  batch_id: string
  installation_id: string
  node_id: string
  action: 'upgrade' | 'rollback'
  command_sha256: string
  status_sha256: string
  state: ControlUpgradeStatusState
  observed_at: string
  delivery_stream: string
  delivery_consumer: string
  delivery_sequence: string
  active_evidence?: ControlUpgradeActiveProbeEvidence
  /** Stable node updater failure code, e.g. DOWNLOAD_FAILED. */
  error_code?: string
  current_version?: string
  previous_version?: string
}

export interface ControlUpgradeRolloutDetail extends ControlUpgradeRolloutSummary {
  batches: ControlUpgradeRolloutBatch[]
  nodes: ControlUpgradeRolloutNode[]
  events: ControlUpgradeRolloutEvent[]
  status_receipts: ControlUpgradeStatusReceipt[]
}

export interface ControlUpgradeRolloutListResponse {
  data: ControlUpgradeRolloutSummary[]
  page: number
  page_size: number
  total: number
}

export interface ControlUpgradeRolloutDetailResponse {
  data: ControlUpgradeRolloutDetail
}

export interface ControlUpgradeRolloutWriteResponse {
  data: ControlUpgradeRolloutDetail
  replayed: boolean
}

export const maintenanceUpgradeReasons = [
  'eligible', 'ready', 'version_unavailable', 'protocol_unavailable',
  'candidate_service_unconfigured', 'candidate_service_unavailable', 'candidate_expired',
  'candidate_not_authorized', ...controlUpgradeReasons.slice(1),
  'control_upgrade_execution_unavailable', 'node_upgrade_runtime_unavailable',
  'control_upgrade_plan_writer_unconfigured', 'control_upgrade_state_unavailable',
  'control_upgrade_ha_unavailable', 'control_upgrade_runner_unconfirmed', 'control_upgrade_draining',
  'node_disabled', 'node_offline', 'node_capability_unavailable',
  'upgrade_available', 'same_version', 'target_is_older', 'target_unset',
  'license_inactive', 'customer_inactive', 'channel_inactive', 'target_not_allowed',
  'artifact_unavailable', 'artifact_unverified', 'protocol_incompatible',
  'version_not_allowed', 'signing_key_unavailable',
] as const

export interface MaintenanceUpgradeCandidate {
  state: 'available' | 'up_to_date' | 'rollback_required' | 'unavailable'
  reason: string
  version: string | null
  expires_at: string | null
}

export interface MaintenanceUpgradeRuntime {
  ready: boolean
  reason: string
}

export interface MaintenanceUpgradeBuild {
  source_commit: string | null
  source_tree: string | null
  built_at: string | null
  binary_sha256: string | null
}

export interface MaintenanceUpgradeNode {
  node_id: string
  current_version: string | null
  candidate: MaintenanceUpgradeCandidate
  runtime: MaintenanceUpgradeRuntime
  reason: string
  eligible: boolean
}

export interface MaintenanceUpgradeStatus {
  schema: 'cdnca.maintenance-upgrade-status/v1'
  observed_at: string
  control: {
    component: 'control-api'
    current_version: string | null
    build?: MaintenanceUpgradeBuild
    configured_version_matches: boolean | null
    authorization: {
      state: 'valid' | 'unavailable' | 'invalid' | 'denied'
      reason: string
      channel?: string
    }
    candidate: MaintenanceUpgradeCandidate
    runtime: MaintenanceUpgradeRuntime
  }
  nodes: MaintenanceUpgradeNode[]
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const codePattern = /^[a-z][a-z0-9._-]{0,95}$/
const actionReasonPattern = /^[a-z][a-z0-9_]{0,95}$/
const versionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/
const metadataPattern = /^[A-Za-z0-9._-]{1,128}$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const revisionPattern = /^(0|[1-9][0-9]{0,18})$/
const maxRevision = '9223372036854775807'
const digestPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const reasonSet = new Set<string>(controlUpgradeReasons)
const stateSet = new Set<string>(controlUpgradePlanStates)
const policySources = new Set(['default', 'global', 'installation'])
const completions = new Set(['', 'upgraded', 'rolled_back'])
const blockerCodes = new Set(['irreversible_migration', 'rollback_unavailable', 'agent_incompatible', 'protocol_incompatible'])
const nodeStates = new Set(['pending', 'dispatched', 'healthy', 'failed', 'rolled_back'])
const eventActions = new Set(['start', 'pause', 'resume', 'rollback', 'health_failed', 'health_succeeded', 'outcome_uncertain'])
const statusSchemas = new Set(['cdnca.edge.upgrade.status/v1', 'cdnca.edge.upgrade.status/v2'])
const statusActions = new Set(['upgrade', 'rollback'])
const statusStates = new Set(['accepted', 'claimed', 'installing', 'healthy', 'failed', 'rolling_back', 'rolled_back', 'uncertain'])
const hexDigestPattern = /^[0-9a-f]{64}$/

function invalidResponse(status = 502): ApiError {
  return new ApiError('API response was invalid', status, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('Control upgrade request was invalid', 400, 'invalid_request')
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

function integer(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function revision(value: unknown, allowZero = false): value is string {
  if (typeof value !== 'string' || !revisionPattern.test(value) || (!allowZero && value === '0')) return false
  return value.length < maxRevision.length || value.length === maxRevision.length && value <= maxRevision
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function dateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function validVersion(version: string): boolean {
  if (!versionPattern.test(version) || version.includes('+')) return false
  const separator = version.indexOf('-')
  return separator === -1 || version.slice(separator + 1).split('.').every((part) =>
    !/^\d+$/.test(part) || part === '0' || !part.startsWith('0'),
  )
}

function validInput(input: ControlUpgradeCheckInput): boolean {
  return codePattern.test(input.component) && codePattern.test(input.channel) && validVersion(input.current_version)
}

function sortedUniqueUUIDs(values: unknown): values is string[] {
  return Array.isArray(values) && values.length > 0 && values.length <= 1000 && values.every((value, index) =>
    uuid(value) && (index === 0 || values[index - 1] < value),
  )
}

function validMetadata(metadata: ControlUpgradeRequestMetadata): boolean {
  return metadataPattern.test(metadata.requestId) && metadataPattern.test(metadata.idempotencyKey)
}

function validCreate(input: ControlUpgradeCreateInput): boolean {
	if (input.schema !== 'cdnca.control-upgrade-rollout.create/v1' || !sortedUniqueUUIDs(input.node_ids) ||
		!sortedUniqueUUIDs(input.canary_node_ids) || input.canary_node_ids.length > 2 ||
		!integer(input.batch_size, 1) || input.batch_size > 100 ||
    input.automatic_rollback !== true) return false
  const nodes = new Set(input.node_ids)
  return input.canary_node_ids.every((nodeID) => nodes.has(nodeID))
}

function validAction(input: ControlUpgradeActionInput): boolean {
  return revision(input.expected_revision) && actionReasonPattern.test(input.reason)
}

function parseEntitlement(value: unknown): ControlUpgradeEntitlementDecision | undefined {
  if (value === undefined) return undefined
  if (!isRecord(value) || !hasExactKeys(value, ['serial', 'channel', 'min_version', 'max_version']) ||
    !integer(value.serial, 1) || typeof value.channel !== 'string' ||
    typeof value.min_version !== 'string' || typeof value.max_version !== 'string') throw invalidResponse()
  return value as unknown as ControlUpgradeEntitlementDecision
}

function parsePolicy(value: unknown): ControlUpgradePolicyDecision {
  if (!isRecord(value) || !hasExactKeys(value, ['source', 'stale'], ['target_revision_id']) ||
    typeof value.source !== 'string' || !policySources.has(value.source) || typeof value.stale !== 'boolean' ||
    (value.target_revision_id !== undefined && !uuid(value.target_revision_id))) throw invalidResponse()
  return value as unknown as ControlUpgradePolicyDecision
}

function parseCheck(value: unknown, input: ControlUpgradeCheckInput, status: number): ControlUpgradeCheckResponse {
  if (!isRecord(value) ||
    !hasExactKeys(value, ['eligible', 'reason', 'component', 'current_version', 'channel', 'policy'], ['entitlement']) ||
    typeof value.eligible !== 'boolean' || typeof value.reason !== 'string' || !reasonSet.has(value.reason) ||
    value.component !== input.component || value.current_version !== input.current_version || value.channel !== input.channel ||
    value.eligible !== (value.reason === 'eligible')) throw invalidResponse(status)
  return {
    eligible: value.eligible,
    reason: value.reason as ControlUpgradeReason,
    component: input.component,
    current_version: input.current_version,
    channel: input.channel,
    ...(value.entitlement === undefined ? {} : { entitlement: parseEntitlement(value.entitlement) }),
    policy: parsePolicy(value.policy),
  }
}

function blocker(value: unknown): value is ControlUpgradeBlocker {
  return isRecord(value) && hasExactKeys(value, ['code'], ['node_id']) &&
    typeof value.code === 'string' && blockerCodes.has(value.code) &&
    (value.node_id === undefined || uuid(value.node_id))
}

const summaryKeys = [
  'id', 'schema_version', 'installation_id', 'component', 'current_version', 'target_version', 'state',
  'completion', 'revision', 'automatic_rollback', 'parent_grant_id', 'artifact_id', 'artifact_sha256',
  'artifact_size_bytes', 'rollback_artifact_id', 'rollback_artifact_sha256', 'rollback_artifact_size_bytes',
  'active_batch', 'total_nodes', 'pending_nodes', 'dispatched_nodes', 'healthy_nodes', 'failed_nodes',
  'rolled_back_nodes', 'blockers', 'created_at', 'updated_at',
] as const

function summary(value: unknown): value is ControlUpgradeRolloutSummary {
  if (!isRecord(value) || !hasExactKeys(value, summaryKeys) || !uuid(value.id) || value.schema_version !== 2 ||
    !uuid(value.installation_id) || typeof value.component !== 'string' || !codePattern.test(value.component) ||
    typeof value.current_version !== 'string' || !validVersion(value.current_version) ||
    typeof value.target_version !== 'string' || !validVersion(value.target_version) ||
    typeof value.state !== 'string' || !stateSet.has(value.state) ||
    typeof value.completion !== 'string' || !completions.has(value.completion) || !revision(value.revision) ||
    value.automatic_rollback !== true || !uuid(value.parent_grant_id) || !uuid(value.artifact_id) ||
    typeof value.artifact_sha256 !== 'string' || !digestPattern.test(value.artifact_sha256) ||
    !integer(value.artifact_size_bytes, 1) || typeof value.rollback_artifact_id !== 'string' ||
    typeof value.rollback_artifact_sha256 !== 'string' || !integer(value.rollback_artifact_size_bytes) ||
    !integer(value.active_batch, -1) || !integer(value.total_nodes, 1) || !integer(value.pending_nodes) ||
    !integer(value.dispatched_nodes) || !integer(value.healthy_nodes) || !integer(value.failed_nodes) ||
    !integer(value.rolled_back_nodes) || !Array.isArray(value.blockers) || !value.blockers.every(blocker) ||
    !dateTime(value.created_at) || !dateTime(value.updated_at)) return false
  const hasRollback = uuid(value.rollback_artifact_id) && digestPattern.test(value.rollback_artifact_sha256) &&
    value.rollback_artifact_size_bytes > 0
  const noRollback = value.rollback_artifact_id === '' && value.rollback_artifact_sha256 === '' &&
    value.rollback_artifact_size_bytes === 0
  return (hasRollback || noRollback) &&
    value.pending_nodes + value.dispatched_nodes + value.healthy_nodes + value.failed_nodes + value.rolled_back_nodes === value.total_nodes &&
    Date.parse(value.updated_at) >= Date.parse(value.created_at)
}

function batch(value: unknown): value is ControlUpgradeRolloutBatch {
  return isRecord(value) && hasExactKeys(value, ['id', 'group_id', 'canary', 'node_ids']) && uuid(value.id) &&
    typeof value.group_id === 'string' && codePattern.test(value.group_id) && typeof value.canary === 'boolean' &&
    sortedUniqueUUIDs(value.node_ids)
}

function node(value: unknown): value is ControlUpgradeRolloutNode {
  return isRecord(value) && hasExactKeys(value, [
    'node_id', 'agent_version', 'protocol_version', 'state', 'dispatch_revision',
  ]) && uuid(value.node_id) && typeof value.agent_version === 'string' && validVersion(value.agent_version) &&
    integer(value.protocol_version, 1) && typeof value.state === 'string' && nodeStates.has(value.state) &&
    revision(value.dispatch_revision, true)
}

function event(value: unknown): value is ControlUpgradeRolloutEvent {
  return isRecord(value) && hasExactKeys(value, [
    'id', 'revision', 'from', 'to', 'action', 'reason', 'batch_id', 'node_id',
  ], ['occurred_at']) && (value.occurred_at === undefined || dateTime(value.occurred_at)) && uuid(value.id) && revision(value.revision) && typeof value.from === 'string' && stateSet.has(value.from) &&
    typeof value.to === 'string' && stateSet.has(value.to) && typeof value.action === 'string' && eventActions.has(value.action) &&
    typeof value.reason === 'string' && actionReasonPattern.test(value.reason) && typeof value.batch_id === 'string' &&
    uuid(value.batch_id) && typeof value.node_id === 'string' && (value.node_id === '' || uuid(value.node_id))
}

function activeEvidence(value: unknown): value is ControlUpgradeActiveProbeEvidence {
  if (!isRecord(value) || !hasExactKeys(value, [
    'schema', 'active_artifact_sha256', 'active_config_sha256', 'last_known_good_artifact_sha256',
    'last_known_good_config_sha256', 'probe_observed_at', 'probe_deadline', 'evidence_sha256',
  ]) || value.schema !== 'cdnca.edge.upgrade.active-probe/v1' ||
    typeof value.active_artifact_sha256 !== 'string' ||
    !(hexDigestPattern.test(value.active_artifact_sha256) || digestPattern.test(value.active_artifact_sha256)) ||
    typeof value.active_config_sha256 !== 'string' ||
    !(hexDigestPattern.test(value.active_config_sha256) || digestPattern.test(value.active_config_sha256)) ||
    typeof value.last_known_good_artifact_sha256 !== 'string' ||
    !(hexDigestPattern.test(value.last_known_good_artifact_sha256) || digestPattern.test(value.last_known_good_artifact_sha256)) ||
    typeof value.last_known_good_config_sha256 !== 'string' ||
    !(hexDigestPattern.test(value.last_known_good_config_sha256) || digestPattern.test(value.last_known_good_config_sha256)) ||
    typeof value.evidence_sha256 !== 'string' ||
    !(hexDigestPattern.test(value.evidence_sha256) || digestPattern.test(value.evidence_sha256)) ||
    !dateTime(value.probe_observed_at) || !dateTime(value.probe_deadline)) return false
  return Date.parse(value.probe_observed_at) <= Date.parse(value.probe_deadline)
}

function statusReceipt(value: unknown): value is ControlUpgradeStatusReceipt {
  if (!isRecord(value) || !hasExactKeys(value, [
    'schema', 'status_id', 'status_revision', 'command_id', 'plan_id', 'plan_revision', 'batch_id',
    'installation_id', 'node_id', 'action', 'command_sha256', 'status_sha256', 'state', 'observed_at',
    'delivery_stream', 'delivery_consumer', 'delivery_sequence',
  ], ['active_evidence', 'error_code', 'current_version', 'previous_version']) || typeof value.schema !== 'string' || !statusSchemas.has(value.schema) ||
    value.error_code !== undefined && (typeof value.error_code !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.error_code)) ||
    !['current_version', 'previous_version'].every((key) => value[key] === undefined || typeof value[key] === 'string' && (value[key] as string).length <= 128) ||
    !uuid(value.status_id) || !revision(value.status_revision) || !uuid(value.command_id) || !uuid(value.plan_id) ||
    !revision(value.plan_revision) || !uuid(value.batch_id) || !uuid(value.installation_id) || !uuid(value.node_id) ||
    typeof value.action !== 'string' || !statusActions.has(value.action) ||
    typeof value.command_sha256 !== 'string' || !hexDigestPattern.test(value.command_sha256) ||
    typeof value.status_sha256 !== 'string' || !hexDigestPattern.test(value.status_sha256) ||
    typeof value.state !== 'string' || !statusStates.has(value.state) || !dateTime(value.observed_at) ||
    typeof value.delivery_stream !== 'string' || value.delivery_stream.length < 1 || value.delivery_stream.length > 128 ||
    typeof value.delivery_consumer !== 'string' || value.delivery_consumer.length < 1 || value.delivery_consumer.length > 128 ||
    !revision(value.delivery_sequence)) return false
  const expectsEvidence = value.schema === 'cdnca.edge.upgrade.status/v2' &&
    (value.state === 'healthy' || value.state === 'rolled_back')
  return expectsEvidence ? activeEvidence(value.active_evidence) : value.active_evidence === undefined
}

function detail(value: unknown): value is ControlUpgradeRolloutDetail {
  if (!isRecord(value) || !hasExactKeys(value, [...summaryKeys, 'batches', 'nodes', 'events', 'status_receipts'])) return false
  const summaryValue = Object.fromEntries(summaryKeys.map((key) => [key, value[key]]))
  if (!summary(summaryValue) ||
    !Array.isArray(value.batches) || !value.batches.every(batch) || !Array.isArray(value.nodes) ||
    !value.nodes.every(node) || !Array.isArray(value.events) || !value.events.every(event) ||
    !Array.isArray(value.status_receipts) || !value.status_receipts.every(statusReceipt)) return false
  const nodeIDs = new Set(value.nodes.map((item) => item.node_id))
  const batchIDs = new Set(value.batches.map((item) => item.id))
  return value.nodes.length === value.total_nodes && nodeIDs.size === value.nodes.length &&
    new Set(value.status_receipts.map((item) => item.status_id)).size === value.status_receipts.length &&
    value.status_receipts.every((item) => item.plan_id === value.id && item.installation_id === value.installation_id &&
      nodeIDs.has(item.node_id) && batchIDs.has(item.batch_id))
}

function parseList(value: unknown, params: ControlUpgradeListParams): ControlUpgradeRolloutListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'page', 'page_size', 'total']) ||
    !Array.isArray(value.data) || value.data.length > params.pageSize || !value.data.every(summary) ||
    value.page !== params.page || value.page_size !== params.pageSize || !integer(value.total) ||
    value.data.length > value.total) throw invalidResponse()
  return value as unknown as ControlUpgradeRolloutListResponse
}

function parseDetail(value: unknown, planID: string): ControlUpgradeRolloutDetailResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data']) || !detail(value.data) || value.data.id !== planID) {
    throw invalidResponse()
  }
  return value as unknown as ControlUpgradeRolloutDetailResponse
}

function parseWrite(value: unknown, planID?: string): ControlUpgradeRolloutWriteResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'replayed']) || !detail(value.data) ||
    typeof value.replayed !== 'boolean' || (planID !== undefined && value.data.id !== planID)) throw invalidResponse()
  return value as unknown as ControlUpgradeRolloutWriteResponse
}

function nullableVersion(value: unknown): value is string | null {
  return value === null || typeof value === 'string' && validVersion(value)
}

function maintenanceReason(value: unknown): value is string {
  return typeof value === 'string' && actionReasonPattern.test(value)
}

function maintenanceCandidate(value: unknown): value is MaintenanceUpgradeCandidate {
  if (!isRecord(value) || !hasExactKeys(value, ['state', 'reason', 'version', 'expires_at']) ||
    !maintenanceReason(value.reason)) return false
  if (value.state === 'unavailable') return value.version === null &&
    (value.expires_at === null || dateTime(value.expires_at))
  return typeof value.state === 'string' && ['available', 'up_to_date', 'rollback_required'].includes(value.state) &&
    typeof value.version === 'string' && validVersion(value.version) && dateTime(value.expires_at)
}

function versionOrder(left: string, right: string): number {
  const parts = (value: string) => value.match(/^([0-9]+)[.]([0-9]+)[.]([0-9]+)(?:-(.*))?$/)!
  const a = parts(left)
  const b = parts(right)
  const numericOrder = (x: string, y: string) => x.length - y.length || (x < y ? -1 : x > y ? 1 : 0)
  for (let index = 1; index <= 3; index++) {
    const order = numericOrder(a[index], b[index])
    if (order) return order
  }
  if (a[4] === undefined || b[4] === undefined) return a[4] === b[4] ? 0 : a[4] === undefined ? 1 : -1
  const prereleaseA = a[4].split('.')
  const prereleaseB = b[4].split('.')
  for (let index = 0; index < Math.min(prereleaseA.length, prereleaseB.length); index++) {
    const x = prereleaseA[index]
    const y = prereleaseB[index]
    const xNumeric = /^[0-9]+$/.test(x)
    const yNumeric = /^[0-9]+$/.test(y)
    const order = xNumeric && yNumeric ? numericOrder(x, y) : xNumeric !== yNumeric ? xNumeric ? -1 : 1 : x < y ? -1 : x > y ? 1 : 0
    if (order) return order
  }
  return prereleaseA.length - prereleaseB.length
}

function candidateMatchesVersion(candidate: MaintenanceUpgradeCandidate, current: string | null): boolean {
  if (candidate.state === 'unavailable') return true
  if (current === null || candidate.version === null) return false
  const order = versionOrder(candidate.version, current)
  return candidate.state === 'available' ? order > 0 : candidate.state === 'up_to_date' ? order === 0 : order < 0
}

function maintenanceRuntime(value: unknown): value is MaintenanceUpgradeRuntime {
  return isRecord(value) && hasExactKeys(value, ['ready', 'reason']) &&
    typeof value.ready === 'boolean' && maintenanceReason(value.reason)
}

function maintenanceBuild(value: unknown): value is MaintenanceUpgradeBuild {
  const gitObject = (item: unknown) => item === null || typeof item === 'string' && /^[0-9a-f]{40}$/.test(item)
  return isRecord(value) && hasExactKeys(value, ['source_commit', 'source_tree', 'built_at', 'binary_sha256']) &&
    gitObject(value.source_commit) && gitObject(value.source_tree) &&
    (value.built_at === null || dateTime(value.built_at)) &&
    (value.binary_sha256 === null || typeof value.binary_sha256 === 'string' && hexDigestPattern.test(value.binary_sha256))
}

function parseMaintenanceStatus(value: unknown, nodeIDs: string[]): MaintenanceUpgradeStatus {
  if (!isRecord(value) || !hasExactKeys(value, ['data']) || !isRecord(value.data)) throw invalidResponse()
  const data = value.data
  if (!hasExactKeys(data, ['schema', 'observed_at', 'control', 'nodes']) ||
    data.schema !== 'cdnca.maintenance-upgrade-status/v1' || !dateTime(data.observed_at) ||
    !isRecord(data.control) || !Array.isArray(data.nodes)) throw invalidResponse()
  const control = data.control
  if (!hasExactKeys(control, ['component', 'current_version', 'configured_version_matches', 'authorization', 'candidate', 'runtime'], ['build']) ||
    control.component !== 'control-api' || !nullableVersion(control.current_version) ||
    (control.build !== undefined && !maintenanceBuild(control.build)) ||
    (control.configured_version_matches !== null && typeof control.configured_version_matches !== 'boolean') ||
    !isRecord(control.authorization) ||
    !hasExactKeys(control.authorization, ['state', 'reason'], ['channel']) ||
    typeof control.authorization.state !== 'string' || !['valid', 'unavailable', 'invalid', 'denied'].includes(control.authorization.state) ||
    !maintenanceReason(control.authorization.reason) ||
    (control.authorization.channel !== undefined &&
      (typeof control.authorization.channel !== 'string' || !codePattern.test(control.authorization.channel))) ||
    !maintenanceCandidate(control.candidate) || !candidateMatchesVersion(control.candidate, control.current_version) ||
    (control.candidate.state !== 'unavailable' && control.authorization.state !== 'valid') ||
    !maintenanceRuntime(control.runtime)) throw invalidResponse()
  const requested = new Set(nodeIDs)
  const received = new Set<string>()
  for (const node of data.nodes) {
    if (!isRecord(node) || !hasExactKeys(node, ['node_id', 'current_version', 'candidate', 'runtime', 'reason', 'eligible']) ||
      !uuid(node.node_id) || !requested.has(node.node_id) || received.has(node.node_id) ||
      !nullableVersion(node.current_version) || !maintenanceCandidate(node.candidate) ||
      !candidateMatchesVersion(node.candidate, node.current_version) ||
      !maintenanceRuntime(node.runtime) || !maintenanceReason(node.reason) || typeof node.eligible !== 'boolean' ||
      (node.eligible && (node.current_version === null || node.candidate.state !== 'available' ||
        !node.runtime.ready || node.reason !== 'eligible'))) throw invalidResponse()
    received.add(node.node_id)
  }
  return data as unknown as MaintenanceUpgradeStatus
}

async function maintenanceStatus(accessToken: string, nodeIDs: string[] = []): Promise<MaintenanceUpgradeStatus> {
  if (!accessToken || nodeIDs.length > 100 || nodeIDs.some((id) => !uuid(id)) ||
    new Set(nodeIDs).size !== nodeIDs.length) throw invalidRequest()
  const query = new URLSearchParams()
  for (const id of [...nodeIDs].sort()) query.append('node_id', id)
  const path = `/v1/admin/maintenance-upgrade-status${nodeIDs.length ? `?${query}` : ''}`
  return parseMaintenanceStatus(await request(path, accessToken, 200), nodeIDs)
}

function metadataSuffix(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

export function createControlUpgradeRequestMetadata(operation = 'rollout'): ControlUpgradeRequestMetadata {
  const suffix = metadataSuffix()
  return {
    requestId: `control-upgrade-request-${suffix}`,
    idempotencyKey: `control-upgrade-${operation}-${suffix}`,
  }
}

async function request(path: string, accessToken: string, expectedStatus: number, init: RequestInit = {}): Promise<unknown> {
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
  if (response.status !== expectedStatus) throw invalidResponse(response.status)
  try {
    return await response.json()
  } catch {
    throw invalidResponse(response.status)
  }
}

async function check(
  accessToken: string,
  input: ControlUpgradeCheckInput,
  metadata: ControlUpgradeRequestMetadata,
): Promise<ControlUpgradeCheckResponse> {
  if (!accessToken || !validInput(input) || !validMetadata(metadata)) throw invalidRequest()
  const value = await request('/v1/admin/control-upgrade-checks', accessToken, 200, {
    method: 'POST',
    headers: { 'Idempotency-Key': metadata.idempotencyKey, 'X-Request-ID': metadata.requestId },
    body: JSON.stringify(input),
  })
  return parseCheck(value, input, 200)
}

function list(accessToken: string, params: ControlUpgradeListParams): Promise<ControlUpgradeRolloutListResponse> {
  if (!accessToken || !integer(params.page, 1) || !integer(params.pageSize, 1) || params.pageSize > 100 ||
    (params.state !== undefined && !stateSet.has(params.state)) ||
    (params.nodeId !== undefined && !uuid(params.nodeId))) return Promise.reject(invalidRequest())
  const query = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
  if (params.state) query.set('state', params.state)
  if (params.nodeId) query.set('node_id', params.nodeId)
  return request(`/v1/admin/control-upgrade-rollouts?${query}`, accessToken, 200).then((value) => parseList(value, params))
}

function getDetail(accessToken: string, planID: string): Promise<ControlUpgradeRolloutDetailResponse> {
  if (!accessToken || !uuid(planID)) return Promise.reject(invalidRequest())
  return request(`/v1/admin/control-upgrade-rollouts/${planID}`, accessToken, 200).then((value) => parseDetail(value, planID))
}

function create(
  accessToken: string,
  input: ControlUpgradeCreateInput,
  metadata: ControlUpgradeRequestMetadata,
): Promise<ControlUpgradeRolloutWriteResponse> {
  if (!accessToken || !validCreate(input) || !validMetadata(metadata)) return Promise.reject(invalidRequest())
  return request('/v1/admin/control-upgrade-rollouts', accessToken, 201, {
    method: 'POST',
    headers: { 'Idempotency-Key': metadata.idempotencyKey, 'X-Request-ID': metadata.requestId },
    body: JSON.stringify(input),
  }).then((value) => parseWrite(value))
}

function actionRequest(
  accessToken: string,
  planID: string,
  action: ControlUpgradeRolloutAction,
  input: ControlUpgradeActionInput,
  metadata: ControlUpgradeRequestMetadata,
): Promise<ControlUpgradeRolloutWriteResponse> {
  if (!accessToken || !uuid(planID) || !validAction(input) || !validMetadata(metadata)) {
    return Promise.reject(invalidRequest())
  }
  return request(`/v1/admin/control-upgrade-rollouts/${planID}/${action}`, accessToken, 200, {
    method: 'POST',
    headers: { 'Idempotency-Key': metadata.idempotencyKey, 'X-Request-ID': metadata.requestId },
    body: JSON.stringify(input),
  }).then((value) => parseWrite(value, planID))
}

export const controlUpgradesApi = {
  maintenanceStatus,
  check,
  list,
  detail: getDetail,
  create,
  start: (token: string, id: string, input: ControlUpgradeActionInput, meta: ControlUpgradeRequestMetadata) =>
    actionRequest(token, id, 'start', input, meta),
  pause: (token: string, id: string, input: ControlUpgradeActionInput, meta: ControlUpgradeRequestMetadata) =>
    actionRequest(token, id, 'pause', input, meta),
  resume: (token: string, id: string, input: ControlUpgradeActionInput, meta: ControlUpgradeRequestMetadata) =>
    actionRequest(token, id, 'resume', input, meta),
  rollback: (token: string, id: string, input: ControlUpgradeActionInput, meta: ControlUpgradeRequestMetadata) =>
    actionRequest(token, id, 'rollback', input, meta),
}
