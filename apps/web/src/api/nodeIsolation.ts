import { ApiError, networkApiError, responseApiError } from './auth'

export type NodeIsolationStatus = 'active' | 'isolated'
export type NodeSyncOutcome = 'succeeded' | 'failed' | 'unknown'

export interface ActiveConfigIdentity {
  schema: 1
  config_version_id: string
  artifact_sha256: string
}

export interface NodeIsolationState {
  scope_id: string
  node_id: string
  status: NodeIsolationStatus
  desired: ActiveConfigIdentity
  consecutive_failures: number
  consecutive_healthy: number
  last_session_epoch: number
  last_health_sequence: number
  last_report_id: string
  last_outcome: NodeSyncOutcome
  last_error_code: string
  reason_code: string
  revision: number
  isolated_at: string | null
  recovered_at: string | null
  updated_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digestPattern = /^[0-9a-f]{64}$/
const codePattern = /^[a-z][a-z0-9_.-]{0,63}$/
const reasons = new Set([
  'healthy', 'sync_failure_pending', 'sync_failure_threshold', 'sync_outcome_unknown',
  'active_config_identity_mismatch', 'health_evidence_stale',
  'recovery_confirmation_pending', 'recovered', 'operation_outcome_uncertain',
])

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length && actual.every((key, index) => key === expected[index])
}

function safeInteger(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value))
}

function identity(value: unknown): value is ActiveConfigIdentity {
  return record(value) && exactKeys(value, ['schema', 'config_version_id', 'artifact_sha256']) &&
    value.schema === 1 && typeof value.config_version_id === 'string' && uuidPattern.test(value.config_version_id) &&
    typeof value.artifact_sha256 === 'string' && digestPattern.test(value.artifact_sha256)
}

function state(value: unknown): value is NodeIsolationState {
  if (!record(value) || !exactKeys(value, [
    'scope_id', 'node_id', 'status', 'desired', 'consecutive_failures', 'consecutive_healthy',
    'last_session_epoch', 'last_health_sequence', 'last_report_id', 'last_outcome',
    'last_error_code', 'reason_code', 'revision', 'isolated_at', 'recovered_at', 'updated_at',
  ])) return false
  return typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.node_id === 'string' && uuidPattern.test(value.node_id) &&
    (value.status === 'active' || value.status === 'isolated') && identity(value.desired) &&
    safeInteger(value.consecutive_failures, 0, 100) && safeInteger(value.consecutive_healthy, 0, 100) &&
    safeInteger(value.last_session_epoch) && safeInteger(value.last_health_sequence) &&
    typeof value.last_report_id === 'string' && uuidPattern.test(value.last_report_id) &&
    (value.last_outcome === 'succeeded' || value.last_outcome === 'failed' || value.last_outcome === 'unknown') &&
    typeof value.last_error_code === 'string' && (value.last_error_code === '' || codePattern.test(value.last_error_code)) &&
    typeof value.reason_code === 'string' && reasons.has(value.reason_code) && safeInteger(value.revision, 1) &&
    (value.isolated_at === null || timestamp(value.isolated_at)) &&
    (value.recovered_at === null || timestamp(value.recovered_at)) && timestamp(value.updated_at)
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid node isolation response', 502, 'invalid_response')
}

function parseList(value: unknown): NodeIsolationState[] {
  if (!record(value) || !exactKeys(value, ['items']) || !Array.isArray(value.items) ||
    value.items.length > 4096 || !value.items.every(state)) throw invalidResponse()
  const nodeIDs = new Set(value.items.map((item) => item.node_id))
  if (nodeIDs.size !== value.items.length) throw invalidResponse()
  return value.items
}

async function list(accessToken: string, nodeIDs: string[] = []): Promise<NodeIsolationState[]> {
  if (!accessToken || nodeIDs.length > 100 || nodeIDs.some((nodeID) => !uuidPattern.test(nodeID)) ||
    new Set(nodeIDs).size !== nodeIDs.length) {
    throw new ApiError('Invalid node isolation query', 0, 'validation_error')
  }
  const query = new URLSearchParams()
  nodeIDs.forEach((nodeID) => query.append('node_id', nodeID))
  const suffix = query.size > 0 ? `?${query}` : ''
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/node-isolations${suffix}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return parseList(await response.json().catch(() => { throw invalidResponse() }))
}

export const nodeIsolationApi = { list }
