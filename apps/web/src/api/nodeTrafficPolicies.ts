import { ApiError, networkApiError, responseApiError } from './auth'

export type NodeTrafficOverrideMode = 'none' | 'force_enabled' | 'force_disabled'
export type NodeTrafficSyncStatus = 'queued' | 'running' | 'succeeded' | 'failed'

export interface NodeTrafficScheduleWindow {
  weekday: number
  start_minute: number
  end_minute: number
}

export interface NodeTrafficManualOverride {
  mode: NodeTrafficOverrideMode
  revision: number
  expires_at: string | null
}

export interface NodeTrafficPolicy {
  id: string
  scope_id: string
  node_id: string
  monthly_limit_bytes: number
  timezone: string
  windows: NodeTrafficScheduleWindow[]
  manual_override: NodeTrafficManualOverride
  revision: number
  created_at: string
  updated_at: string
}

export interface NodeTrafficEvaluationSnapshot {
  period_key: string
  suppressed: boolean
  reason_code: string
  override_revision: number
}

export interface NodeTrafficPolicyState {
  policy: NodeTrafficPolicy
  admin_state: string
  current_config_version_id: string | null
  last_evaluation: NodeTrafficEvaluationSnapshot | null
}

export interface NodeTrafficDecision {
  period_key: string
  period_start: string
  period_end: string
  usage_bytes: number
  monthly_limit_bytes: number
  suppressed: boolean
  sync_required: boolean
  reason_code: string
  override_revision: number
  evaluated_at: string
  source_snapshot_at: string
  source_finalized_through: string
  source_digest: string
}

export interface NodeTrafficSyncTask {
  id: string
  scope_id: string
  node_id: string
  config_version_id: string
  status: NodeTrafficSyncStatus
  error_code: string | null
  rollout_id: string | null
  created_at: string
  updated_at: string
}

export interface NodeTrafficEvaluationRecord {
  id: string
  scope_id: string
  node_id: string
  decision: NodeTrafficDecision
  sync_task: NodeTrafficSyncTask | null
  replayed: boolean
}

export type NodeTrafficPolicyInput = Pick<
  NodeTrafficPolicy,
  'monthly_limit_bytes' | 'timezone' | 'windows' | 'manual_override'
>

export interface NodeTrafficWriteIdentity {
  requestId: string
  idempotencyKey: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const periodPattern = /^\d{4}-(0[1-9]|1[0-2])$/
const digestPattern = /^[0-9a-f]{64}$/

function invalidRequest(): ApiError {
  return new ApiError('Invalid node traffic policy request', 400, 'node_traffic_policy_validation_error')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid node traffic policy response', 502, 'node_traffic_policy_invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return keys.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => keys.includes(key))
}

function safeInteger(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 40 && Number.isFinite(Date.parse(value))
}

function nullableUUID(value: unknown): value is string | null {
  return value === null || typeof value === 'string' && uuidPattern.test(value)
}

function isWindow(value: unknown): value is NodeTrafficScheduleWindow {
  return record(value) && exactKeys(value, ['weekday', 'start_minute', 'end_minute']) &&
    safeInteger(value.weekday) && value.weekday <= 6 && safeInteger(value.start_minute) && value.start_minute < 1_440 &&
    safeInteger(value.end_minute) && value.end_minute < 1_440 && value.start_minute !== value.end_minute
}

function isOverride(value: unknown): value is NodeTrafficManualOverride {
  if (!record(value) || !exactKeys(value, ['mode', 'revision', 'expires_at']) ||
    !['none', 'force_enabled', 'force_disabled'].includes(String(value.mode)) || !safeInteger(value.revision) ||
    !(value.expires_at === null || timestamp(value.expires_at))) return false
  return value.mode === 'none'
    ? value.expires_at === null
    : value.revision > 0 && value.expires_at !== null
}

function isPolicy(value: unknown): value is NodeTrafficPolicy {
  return record(value) && exactKeys(value, [
    'id', 'scope_id', 'node_id', 'monthly_limit_bytes', 'timezone', 'windows', 'manual_override',
    'revision', 'created_at', 'updated_at',
  ]) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.node_id === 'string' && uuidPattern.test(value.node_id) && safeInteger(value.monthly_limit_bytes) &&
    typeof value.timezone === 'string' && value.timezone.length > 0 && value.timezone.length <= 128 &&
    Array.isArray(value.windows) && value.windows.length <= 32 && value.windows.every(isWindow) &&
    isOverride(value.manual_override) && safeInteger(value.revision) && timestamp(value.created_at) && timestamp(value.updated_at)
}

function isEvaluationSnapshot(value: unknown): value is NodeTrafficEvaluationSnapshot {
  return record(value) && exactKeys(value, ['period_key', 'suppressed', 'reason_code', 'override_revision']) &&
    typeof value.period_key === 'string' && periodPattern.test(value.period_key) && typeof value.suppressed === 'boolean' &&
    typeof value.reason_code === 'string' && value.reason_code.length > 0 && value.reason_code.length <= 64 &&
    safeInteger(value.override_revision)
}

function isState(value: unknown): value is NodeTrafficPolicyState {
  return record(value) && exactKeys(value, ['policy', 'admin_state', 'current_config_version_id', 'last_evaluation']) &&
    isPolicy(value.policy) && typeof value.admin_state === 'string' &&
    ['pending', 'active', 'draining', 'disabled', 'retired'].includes(value.admin_state) &&
    nullableUUID(value.current_config_version_id) && (value.last_evaluation === null || isEvaluationSnapshot(value.last_evaluation))
}

function isDecision(value: unknown): value is NodeTrafficDecision {
  return record(value) && exactKeys(value, [
    'period_key', 'period_start', 'period_end', 'usage_bytes', 'monthly_limit_bytes', 'suppressed', 'sync_required',
    'reason_code', 'override_revision', 'evaluated_at', 'source_snapshot_at', 'source_finalized_through', 'source_digest',
  ]) && typeof value.period_key === 'string' && periodPattern.test(value.period_key) && timestamp(value.period_start) &&
    timestamp(value.period_end) && safeInteger(value.usage_bytes) && safeInteger(value.monthly_limit_bytes) &&
    typeof value.suppressed === 'boolean' && typeof value.sync_required === 'boolean' &&
    typeof value.reason_code === 'string' && value.reason_code.length > 0 && value.reason_code.length <= 64 &&
    safeInteger(value.override_revision) && timestamp(value.evaluated_at) && timestamp(value.source_snapshot_at) &&
    timestamp(value.source_finalized_through) && typeof value.source_digest === 'string' && digestPattern.test(value.source_digest)
}

function isSyncTask(value: unknown): value is NodeTrafficSyncTask {
  return record(value) && exactKeys(value, [
    'id', 'scope_id', 'node_id', 'config_version_id', 'status', 'error_code', 'rollout_id', 'created_at', 'updated_at',
  ]) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.node_id === 'string' && uuidPattern.test(value.node_id) &&
    typeof value.config_version_id === 'string' && uuidPattern.test(value.config_version_id) &&
    typeof value.status === 'string' && ['queued', 'running', 'succeeded', 'failed'].includes(value.status) &&
    (value.error_code === null || typeof value.error_code === 'string' && value.error_code.length <= 128) &&
    nullableUUID(value.rollout_id) && timestamp(value.created_at) && timestamp(value.updated_at)
}

function isEvaluation(value: unknown): value is NodeTrafficEvaluationRecord {
  return record(value) && exactKeys(value, ['id', 'scope_id', 'node_id', 'decision', 'sync_task', 'replayed']) &&
    typeof value.id === 'string' && uuidPattern.test(value.id) && typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.node_id === 'string' && uuidPattern.test(value.node_id) && isDecision(value.decision) &&
    (value.sync_task === null || isSyncTask(value.sync_task)) && typeof value.replayed === 'boolean'
}

function validIdentity(identity: NodeTrafficWriteIdentity): boolean {
  return metadataPattern.test(identity.requestId) && metadataPattern.test(identity.idempotencyKey)
}

function validInput(input: NodeTrafficPolicyInput): boolean {
  return safeInteger(input.monthly_limit_bytes) && typeof input.timezone === 'string' && input.timezone.length > 0 &&
    input.timezone.length <= 128 && Array.isArray(input.windows) && input.windows.length <= 32 && input.windows.every(isWindow) &&
    isOverride(input.manual_override)
}

async function requestJSON(accessToken: string, path: string, init: RequestInit): Promise<{ response: Response; value: unknown }> {
  if (!accessToken.trim()) throw invalidRequest()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status !== 200 || response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  try {
    return { response, value: await response.json() }
  } catch {
    throw invalidResponse()
  }
}

function policyPath(scopeId: string, nodeId: string): string {
  return `/v1/admin/node-traffic-policies/${nodeId}?scope_id=${scopeId}`
}

export const nodeTrafficPoliciesApi = {
  async get(accessToken: string, scopeId: string, nodeId: string, signal?: AbortSignal): Promise<NodeTrafficPolicyState> {
    if (!uuidPattern.test(scopeId) || !uuidPattern.test(nodeId)) throw invalidRequest()
    const { response, value } = await requestJSON(accessToken, policyPath(scopeId, nodeId), { method: 'GET', signal })
    if (!isState(value) || value.policy.scope_id !== scopeId || value.policy.node_id !== nodeId ||
      response.headers.get('ETag') !== `"${value.policy.revision}"`) throw invalidResponse()
    return value
  },
  async put(
    accessToken: string,
    scopeId: string,
    nodeId: string,
    expectedRevision: number,
    input: NodeTrafficPolicyInput,
    identity: NodeTrafficWriteIdentity,
  ): Promise<NodeTrafficPolicyState> {
    if (!uuidPattern.test(scopeId) || !uuidPattern.test(nodeId) || !safeInteger(expectedRevision) ||
      !validInput(input) || !validIdentity(identity)) throw invalidRequest()
    const { response, value } = await requestJSON(accessToken, policyPath(scopeId, nodeId), {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json', 'If-Match': `"${expectedRevision}"`,
        'Idempotency-Key': identity.idempotencyKey, 'X-Request-ID': identity.requestId,
      },
      body: JSON.stringify(input),
    })
    if (!isState(value) || value.policy.scope_id !== scopeId || value.policy.node_id !== nodeId ||
      response.headers.get('ETag') !== `"${value.policy.revision}"` ||
      !['true', 'false'].includes(response.headers.get('Idempotency-Replayed') ?? '')) throw invalidResponse()
    return value
  },
  async evaluate(
    accessToken: string,
    scopeId: string,
    nodeId: string,
    identity: NodeTrafficWriteIdentity,
  ): Promise<NodeTrafficEvaluationRecord> {
    if (!uuidPattern.test(scopeId) || !uuidPattern.test(nodeId) || !validIdentity(identity)) throw invalidRequest()
    const { response, value } = await requestJSON(
      accessToken,
      `/v1/admin/node-traffic-policies/${nodeId}/evaluate?scope_id=${scopeId}`,
      { method: 'POST', headers: { 'Idempotency-Key': identity.idempotencyKey, 'X-Request-ID': identity.requestId } },
    )
    if (!isEvaluation(value) || value.scope_id !== scopeId || value.node_id !== nodeId ||
      value.sync_task !== null && (value.sync_task.scope_id !== scopeId || value.sync_task.node_id !== nodeId) ||
      response.headers.get('Idempotency-Replayed') !== String(value.replayed)) throw invalidResponse()
    return value
  },
  async getSyncTask(accessToken: string, taskId: string, signal?: AbortSignal): Promise<NodeTrafficSyncTask> {
    if (!uuidPattern.test(taskId)) throw invalidRequest()
    const { value } = await requestJSON(accessToken, `/v1/admin/node-traffic-sync-tasks/${taskId}`, { method: 'GET', signal })
    if (!isSyncTask(value) || value.id !== taskId) throw invalidResponse()
    return value
  },
}
