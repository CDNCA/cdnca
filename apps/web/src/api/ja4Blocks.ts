import { ApiError, networkApiError } from './auth'

export type JA4BlockPhase = 'queued' | 'policy_ready' | 'edge_pending' | 'active' | 'failed' | 'expired'
export type JA4BlockEdgeState = '' | 'pending' | 'active' | 'failed' | 'rolled_back'

export interface JA4BlockCreateInput {
  site_id: string
  ja4: string
  snapshot_at: string
  duration_seconds: number
  reason: string
}

export interface AdminJA4BlockCreateInput extends JA4BlockCreateInput {
  tenant_scope_id: string
}

export interface JA4BlockWriteMetadata {
  requestId: string
  idempotencyKey: string
  stepUpToken: string
}

export interface JA4BlockWorkflow {
  id: string
  tenant_scope_id: string
  site_id: string
  ja4_sha256: string
  snapshot_at: string
  duration_seconds: number
  reason: string
  phase: JA4BlockPhase
  revision: number
  policy_id?: string
  policy_revision?: number
  binding_id?: string
  binding_revision?: number
  edge_publication_id?: string
  rollout_id: string
  edge_state: JA4BlockEdgeState
  attempt_count: number
  last_error_code?: string
  replayed?: boolean
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const ja4Pattern = /^[A-Za-z0-9_+.-]{1,128}$/
const stableCodePattern = /^[a-z][a-z0-9_]{0,63}$/
const sha256Pattern = /^[0-9a-f]{64}$/
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const phases = new Set<JA4BlockPhase>(['queued', 'policy_ready', 'edge_pending', 'active', 'failed', 'expired'])
const edgeStates = new Set<JA4BlockEdgeState>(['', 'pending', 'active', 'failed', 'rolled_back'])

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (!record(value)) return false
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function invalidRequest(): ApiError {
  return new ApiError('Invalid JA4 block request', 400, 'invalid_request')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid JA4 block response', 502, 'invalid_response')
}

function validateInput(value: unknown, admin: boolean): asserts value is JA4BlockCreateInput | AdminJA4BlockCreateInput {
  const required = ['site_id', 'ja4', 'snapshot_at', 'duration_seconds', 'reason']
  if (admin) required.push('tenant_scope_id')
  if (!exact(value, required) || !uuid(value.site_id) || typeof value.ja4 !== 'string' || !ja4Pattern.test(value.ja4) ||
    !timestamp(value.snapshot_at) || !integer(value.duration_seconds, 60, 2_592_000) ||
    typeof value.reason !== 'string' || !stableCodePattern.test(value.reason) ||
    (admin && !uuid(value.tenant_scope_id))) throw invalidRequest()
}

function validateMetadata(value: unknown): asserts value is JA4BlockWriteMetadata {
  if (!exact(value, ['requestId', 'idempotencyKey', 'stepUpToken']) ||
    typeof value.requestId !== 'string' || !metadataPattern.test(value.requestId) ||
    typeof value.idempotencyKey !== 'string' || !metadataPattern.test(value.idempotencyKey) ||
    typeof value.stepUpToken !== 'string' || value.stepUpToken.length < 1 || value.stepUpToken.length > 8192) {
    throw invalidRequest()
  }
}

function parseWorkflow(value: unknown, expectedID?: string, expectedScopeID?: string): JA4BlockWorkflow {
  const required = [
    'id', 'tenant_scope_id', 'site_id', 'ja4_sha256', 'snapshot_at', 'duration_seconds', 'reason',
    'phase', 'revision', 'rollout_id', 'edge_state', 'attempt_count',
  ]
  const optional = [
    'policy_id', 'policy_revision', 'binding_id', 'binding_revision', 'edge_publication_id',
    'last_error_code', 'replayed',
  ]
  if (!exact(value, required, optional) || !uuid(value.id) || (expectedID !== undefined && value.id !== expectedID) ||
    !uuid(value.tenant_scope_id) || (expectedScopeID !== undefined && value.tenant_scope_id !== expectedScopeID) ||
    !uuid(value.site_id) || typeof value.ja4_sha256 !== 'string' || !sha256Pattern.test(value.ja4_sha256) ||
    !timestamp(value.snapshot_at) || !integer(value.duration_seconds, 60, 2_592_000) ||
    typeof value.reason !== 'string' || value.reason.length < 1 || value.reason.length > 256 ||
    typeof value.phase !== 'string' || !phases.has(value.phase as JA4BlockPhase) || !integer(value.revision, 1) ||
    !uuid(value.rollout_id) || typeof value.edge_state !== 'string' || !edgeStates.has(value.edge_state as JA4BlockEdgeState) ||
    !integer(value.attempt_count, 0, 100) ||
    (value.policy_id === undefined) !== (value.policy_revision === undefined) ||
    (value.binding_id === undefined) !== (value.binding_revision === undefined) ||
    (value.policy_id !== undefined && (!uuid(value.policy_id) || !integer(value.policy_revision, 1))) ||
    (value.binding_id !== undefined && (!uuid(value.binding_id) || !integer(value.binding_revision, 1))) ||
    (value.edge_publication_id !== undefined && !uuid(value.edge_publication_id)) ||
    (value.last_error_code !== undefined && (typeof value.last_error_code !== 'string' || !stableCodePattern.test(value.last_error_code))) ||
    (value.replayed !== undefined && typeof value.replayed !== 'boolean')) throw invalidResponse()
  return value as unknown as JA4BlockWorkflow
}

function bindCreate(workflow: JA4BlockWorkflow, input: JA4BlockCreateInput, expectedScopeID?: string): JA4BlockWorkflow {
  if ((expectedScopeID !== undefined && workflow.tenant_scope_id !== expectedScopeID) || workflow.site_id !== input.site_id ||
    workflow.snapshot_at !== input.snapshot_at || workflow.duration_seconds !== input.duration_seconds ||
    workflow.reason !== input.reason) throw invalidResponse()
  return workflow
}

async function apiError(response: Response): Promise<ApiError> {
  let value: unknown
  try { value = await response.json() } catch { return invalidResponse() }
  if (!exact(value, ['error']) || !exact(value.error, ['code', 'request_id']) ||
    typeof value.error.code !== 'string' || !stableCodePattern.test(value.error.code) ||
    typeof value.error.request_id !== 'string' || !metadataPattern.test(value.error.request_id)) return invalidResponse()
  return new ApiError('API request failed', response.status, value.error.code, value.error.request_id)
}

async function send(path: string, token: string, init: RequestInit): Promise<Response> {
  if (!token || token.length > 8192 || /\s/.test(token)) throw invalidRequest()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token}`, ...init.headers },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await apiError(response)
  if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/json') throw invalidResponse()
  return response
}

async function responseBody(response: Response): Promise<unknown> {
  try { return await response.json() } catch { throw invalidResponse() }
}

function readRequestID(value: string): string {
  if (!metadataPattern.test(value)) throw invalidRequest()
  return value
}

function suffix(): string {
  return globalThis.crypto.randomUUID()
}

export function createJA4BlockWriteMetadata(stepUpToken: string): JA4BlockWriteMetadata {
  const id = suffix()
  const metadata = {
    requestId: `ja4-block-request-${id}`,
    idempotencyKey: `ja4-block-create-${id}`,
    stepUpToken,
  }
  validateMetadata(metadata)
  return metadata
}

async function create(
  path: string,
  token: string,
  input: JA4BlockCreateInput | AdminJA4BlockCreateInput,
  metadata: JA4BlockWriteMetadata,
  admin: boolean,
): Promise<JA4BlockWorkflow> {
  validateInput(input, admin)
  validateMetadata(metadata)
  const response = await send(path, token, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'If-Match': '"0"',
      'Idempotency-Key': metadata.idempotencyKey, 'X-Request-ID': metadata.requestId,
      'X-Step-Up-Token': metadata.stepUpToken,
    },
    body: JSON.stringify(input),
  })
  if (response.status !== 202) throw invalidResponse()
  const expectedScopeID = admin ? (input as AdminJA4BlockCreateInput).tenant_scope_id : undefined
  return bindCreate(parseWorkflow(await responseBody(response), undefined, expectedScopeID), input, expectedScopeID)
}

async function get(
  path: string,
  token: string,
  workflowID: string,
  requestID: string,
  expectedScopeID?: string,
): Promise<JA4BlockWorkflow> {
  if (!uuid(workflowID) || (expectedScopeID !== undefined && !uuid(expectedScopeID))) throw invalidRequest()
  const response = await send(path, token, {
    method: 'GET',
    headers: { 'X-Request-ID': readRequestID(requestID) },
  })
  if (response.status !== 200) throw invalidResponse()
  return parseWorkflow(await responseBody(response), workflowID, expectedScopeID)
}

export const ja4BlocksApi = {
  createTenant(token: string, input: JA4BlockCreateInput, metadata: JA4BlockWriteMetadata): Promise<JA4BlockWorkflow> {
    return create('/v1/security/ja4-blocks', token, input, metadata, false)
  },
  getTenant(token: string, workflowID: string, requestID = `ja4-block-read-${suffix()}`): Promise<JA4BlockWorkflow> {
    return get(`/v1/security/ja4-blocks/${encodeURIComponent(workflowID)}`, token, workflowID, requestID)
  },
  createAdmin(token: string, input: AdminJA4BlockCreateInput, metadata: JA4BlockWriteMetadata): Promise<JA4BlockWorkflow> {
    return create('/v1/admin/security/ja4-blocks', token, input, metadata, true)
  },
  getAdmin(token: string, tenantScopeID: string, workflowID: string, requestID = `ja4-block-read-${suffix()}`): Promise<JA4BlockWorkflow> {
    if (!uuid(tenantScopeID)) return Promise.reject(invalidRequest())
    const path = `/v1/admin/security/ja4-blocks/${encodeURIComponent(workflowID)}?tenant_scope_id=${encodeURIComponent(tenantScopeID)}`
    return get(path, token, workflowID, requestID, tenantScopeID)
  },
}
