import { ApiError, networkApiError, responseApiError } from './auth'

export type OriginAuthProvider = 's3' | 'oss' | 'cos'
export type OriginAuthAlgorithm = 'aws4-hmac-sha256' | 'oss4-hmac-sha256' | 'cos-hmac-sha1'

export interface OriginAuthPublicationRule {
  rule_id: string
  site_id: string
  source_position: number
  provider: OriginAuthProvider
  algorithm: OriginAuthAlgorithm
  endpoint: string
  bucket: string
  path_prefix: string
  region: string
  service: string
  signature_ttl_seconds: number
  current_credential_revision_ref: string
  previous_credential_revision_ref?: string
  activate_current_at_unix: number
}

export interface OriginAuthPublicationSnapshot {
  schema_version: 'cdnca.control.originauth-publication/v1'
  tenant_scope_id: string
  publication_revision: number
  rules: OriginAuthPublicationRule[]
}

export interface OriginAuthPublication {
  id: string
  tenant_scope_id: string
  revision: number
  snapshot_hash: string
  previous_hash?: string
  snapshot: OriginAuthPublicationSnapshot
  created_at: string
}

export interface OriginAuthPublicationWriteMetadata {
  idempotencyKey: string
  requestID: string
  traceID: string
}

export interface OriginAuthEdgePublicationHealthCheck {
  activation_timeout_ms: number
  observation_window_ms: number
  required_consecutive_successes: number
}

export interface PublishOriginAuthEdgePublicationInput {
  node_ids: readonly string[]
  health_check: OriginAuthEdgePublicationHealthCheck
  deadline: string
}

export interface OriginAuthEdgePublicationWriteMetadata {
  idempotencyKey: string
  requestID: string
  correlationID: string
  traceparent: string
  taskID?: string
}

export interface OriginAuthEdgePublication {
  tenant_id: string
  tenant_scope_id: string
  publication_id: string
  source_publication_id: string
  source_revision: number
  config_version_id: string
  rollout_id: string
  config_snapshot_sha256: string
  artifact_manifest_sha256: string
  recipient_binding_sha256: string
  node_count: number
  created_at: string
  replayed?: boolean
}

export interface OriginAuthEdgePublicationRetryBinding {
  method: 'POST'
  path: string
  if_match: string
  idempotency_key: string
  body_sha256: string
  request_id: string
  correlation_id: string
  traceparent: string
  task_id?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const schemaVersion = 'cdnca.control.originauth-publication/v1'
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digestPattern = /^[a-f0-9]{64}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const traceparentPattern = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/
const stableErrorCodePattern = /^[a-z][a-z0-9_]{0,127}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function isSafeInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false
  const match = timestampPattern.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)))
  return calendar.getUTCFullYear() === Number(year) &&
    calendar.getUTCMonth() === Number(month) - 1 && calendar.getUTCDate() === Number(day) &&
    Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) &&
    Number.isFinite(Date.parse(value))
}

function isProvider(value: unknown): value is OriginAuthProvider {
  return value === 's3' || value === 'oss' || value === 'cos'
}

function isAlgorithm(value: unknown): value is OriginAuthAlgorithm {
  return value === 'aws4-hmac-sha256' || value === 'oss4-hmac-sha256' || value === 'cos-hmac-sha1'
}

function isEndpoint(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 512) return false
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' && Boolean(parsed.hostname) && !parsed.username && !parsed.password
  } catch {
    return false
  }
}

function isPublicationRule(value: unknown): value is OriginAuthPublicationRule {
  if (!isRecord(value) || !exactKeys(value, [
    'rule_id', 'site_id', 'source_position', 'provider', 'algorithm', 'endpoint', 'bucket',
    'path_prefix', 'region', 'service', 'signature_ttl_seconds',
    'current_credential_revision_ref', 'activate_current_at_unix',
  ], ['previous_credential_revision_ref'])) return false
  return typeof value.rule_id === 'string' && uuidPattern.test(value.rule_id) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    isSafeInteger(value.source_position, 1, 32) && isProvider(value.provider) &&
    isAlgorithm(value.algorithm) && isEndpoint(value.endpoint) &&
    typeof value.bucket === 'string' && value.bucket.length <= 63 &&
    typeof value.path_prefix === 'string' && value.path_prefix.length >= 1 && value.path_prefix.length <= 2048 &&
    typeof value.region === 'string' && value.region.length >= 2 && value.region.length <= 64 &&
    typeof value.service === 'string' && value.service.length >= 2 && value.service.length <= 64 &&
    isSafeInteger(value.signature_ttl_seconds, 1, 3600) &&
    typeof value.current_credential_revision_ref === 'string' &&
    uuidPattern.test(value.current_credential_revision_ref) &&
    (value.previous_credential_revision_ref === undefined || (
      typeof value.previous_credential_revision_ref === 'string' &&
      uuidPattern.test(value.previous_credential_revision_ref)
    )) && isSafeInteger(value.activate_current_at_unix, 0)
}

function isPublicationSnapshot(value: unknown): value is OriginAuthPublicationSnapshot {
  return isRecord(value) && exactKeys(value, [
    'schema_version', 'tenant_scope_id', 'publication_revision', 'rules',
  ]) && value.schema_version === schemaVersion &&
    typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) &&
    isSafeInteger(value.publication_revision, 1) && Array.isArray(value.rules) &&
    value.rules.length <= 10_000 && value.rules.every(isPublicationRule)
}

function isPublication(value: unknown): value is OriginAuthPublication {
  return isRecord(value) && exactKeys(value, [
    'id', 'tenant_scope_id', 'revision', 'snapshot_hash', 'snapshot', 'created_at',
  ], ['previous_hash']) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) &&
    isSafeInteger(value.revision, 1) && typeof value.snapshot_hash === 'string' &&
    digestPattern.test(value.snapshot_hash) &&
    (value.previous_hash === undefined || (
      typeof value.previous_hash === 'string' && digestPattern.test(value.previous_hash)
    )) && isPublicationSnapshot(value.snapshot) &&
    value.snapshot.tenant_scope_id === value.tenant_scope_id &&
    value.snapshot.publication_revision === value.revision && isTimestamp(value.created_at)
}

function freezePublication(value: OriginAuthPublication): OriginAuthPublication {
  for (const rule of value.snapshot.rules) Object.freeze(rule)
  Object.freeze(value.snapshot.rules)
  Object.freeze(value.snapshot)
  return Object.freeze(value)
}

function isEdgePublication(value: unknown): value is OriginAuthEdgePublication {
  return isRecord(value) && exactKeys(value, [
    'tenant_id', 'tenant_scope_id', 'publication_id', 'source_publication_id', 'source_revision',
    'config_version_id', 'rollout_id', 'config_snapshot_sha256', 'artifact_manifest_sha256',
    'recipient_binding_sha256', 'node_count', 'created_at',
  ], ['replayed']) && typeof value.tenant_id === 'string' && uuidPattern.test(value.tenant_id) &&
    typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) &&
    typeof value.publication_id === 'string' && uuidPattern.test(value.publication_id) &&
    typeof value.source_publication_id === 'string' && uuidPattern.test(value.source_publication_id) &&
    isSafeInteger(value.source_revision, 1) &&
    typeof value.config_version_id === 'string' && uuidPattern.test(value.config_version_id) &&
    typeof value.rollout_id === 'string' && uuidPattern.test(value.rollout_id) &&
    typeof value.config_snapshot_sha256 === 'string' && digestPattern.test(value.config_snapshot_sha256) &&
    typeof value.artifact_manifest_sha256 === 'string' && digestPattern.test(value.artifact_manifest_sha256) &&
    typeof value.recipient_binding_sha256 === 'string' && digestPattern.test(value.recipient_binding_sha256) &&
    isSafeInteger(value.node_count, 1, 10_000) && isTimestamp(value.created_at) &&
    (value.replayed === undefined || typeof value.replayed === 'boolean')
}

function edgeInvalidRequest(): ApiError {
  return new ApiError('Invalid origin authentication edge publication request', 400, 'origin_auth_edge_publication_invalid_request')
}

function edgeInvalidResponse(): ApiError {
  return new ApiError('Invalid origin authentication edge publication response', 502, 'origin_auth_edge_publication_invalid_response')
}

function edgeCollectionPath(scopeID: string): string {
  if (!uuidPattern.test(scopeID)) throw edgeInvalidRequest()
  return `/v1/tenant-scopes/${encodeURIComponent(scopeID)}/origin-auth/edge-publications`
}

function isEdgeInput(value: unknown): value is PublishOriginAuthEdgePublicationInput {
  if (!isRecord(value) || !exactKeys(value, ['node_ids', 'health_check', 'deadline']) ||
    !Array.isArray(value.node_ids) || value.node_ids.length < 1 || value.node_ids.length > 10_000 ||
    !value.node_ids.every((nodeID) => typeof nodeID === 'string' && uuidPattern.test(nodeID)) ||
    new Set(value.node_ids).size !== value.node_ids.length || !isRecord(value.health_check) ||
    !exactKeys(value.health_check, [
      'activation_timeout_ms', 'observation_window_ms', 'required_consecutive_successes',
    ])) return false
  return isSafeInteger(value.health_check.activation_timeout_ms, 1, 300_000) &&
    isSafeInteger(value.health_check.observation_window_ms, 1, 300_000) &&
    isSafeInteger(value.health_check.required_consecutive_successes, 1, 100) &&
    isTimestamp(value.deadline)
}

function isEdgeMetadata(value: unknown): value is OriginAuthEdgePublicationWriteMetadata {
  return isRecord(value) && exactKeys(value, [
    'idempotencyKey', 'requestID', 'correlationID', 'traceparent',
  ], ['taskID']) && typeof value.idempotencyKey === 'string' && idempotencyPattern.test(value.idempotencyKey) &&
    typeof value.requestID === 'string' && uuidPattern.test(value.requestID) &&
    typeof value.correlationID === 'string' && uuidPattern.test(value.correlationID) &&
    typeof value.traceparent === 'string' && traceparentPattern.test(value.traceparent) &&
    (value.taskID === undefined || (typeof value.taskID === 'string' && metadataPattern.test(value.taskID)))
}

function isRetryBinding(value: unknown): value is OriginAuthEdgePublicationRetryBinding {
  return isRecord(value) && exactKeys(value, [
    'method', 'path', 'if_match', 'idempotency_key', 'body_sha256', 'request_id',
    'correlation_id', 'traceparent',
  ], ['task_id']) && value.method === 'POST' && typeof value.path === 'string' && value.path.startsWith('/') &&
    typeof value.if_match === 'string' && /^"[1-9][0-9]*"$/.test(value.if_match) &&
    typeof value.idempotency_key === 'string' && idempotencyPattern.test(value.idempotency_key) &&
    typeof value.body_sha256 === 'string' && digestPattern.test(value.body_sha256) &&
    typeof value.request_id === 'string' && uuidPattern.test(value.request_id) &&
    typeof value.correlation_id === 'string' && uuidPattern.test(value.correlation_id) &&
    typeof value.traceparent === 'string' && traceparentPattern.test(value.traceparent) &&
    (value.task_id === undefined || (typeof value.task_id === 'string' && metadataPattern.test(value.task_id)))
}

async function edgeResponseError(response: Response): Promise<ApiError> {
  const body = await response.json().catch(() => null)
  const envelope = isRecord(body) && isRecord(body.error) ? body.error : null
  const code = typeof envelope?.code === 'string' && stableErrorCodePattern.test(envelope.code)
    ? envelope.code
    : response.status === 503
      ? 'origin_auth_edge_publication_unavailable'
      : 'origin_auth_edge_publication_request_failed'
  const requestID = typeof envelope?.request_id === 'string' && uuidPattern.test(envelope.request_id)
    ? envelope.request_id
    : undefined
  const error = new ApiError('API request failed', response.status, code, requestID)
  if (code === 'origin_auth_edge_publication_outcome_unknown' && isRetryBinding(envelope?.retry)) {
    Object.assign(error, { retry: Object.freeze({ ...envelope.retry }) })
  }
  return error
}

async function parseEdgeResponse(
  response: Response,
  scopeID: string,
  publicationID?: string,
  sourceRevision?: number,
  requireLocation = false,
): Promise<OriginAuthEdgePublication> {
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw edgeInvalidResponse()
  }
  if (!isEdgePublication(value) || value.tenant_scope_id !== scopeID ||
    (publicationID !== undefined && value.publication_id !== publicationID) ||
    (sourceRevision !== undefined && value.source_revision !== sourceRevision)) throw edgeInvalidResponse()
  const expectedLocation = `${edgeCollectionPath(scopeID)}/${value.publication_id}`
  if (response.headers.get('ETag') !== `"sha256-${value.artifact_manifest_sha256}"` ||
    (requireLocation && response.headers.get('Location') !== expectedLocation)) throw edgeInvalidResponse()
  return Object.freeze({ ...value })
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid origin authentication publication response', 0, 'invalid_response')
}

export function parseOriginAuthPublication(value: unknown): OriginAuthPublication {
  if (!isPublication(value)) throw invalidResponse()
  return freezePublication(value)
}

function validateScopeID(scopeID: string): void {
  if (!uuidPattern.test(scopeID)) throw new ApiError('Invalid tenant scope', 0, 'invalid_request')
}

function publicationPath(scopeID: string): string {
  validateScopeID(scopeID)
  return `/v1/tenant-scopes/${encodeURIComponent(scopeID)}/origin-auth/publications`
}

async function request(
  accessToken: string,
  scopeID: string,
  init: RequestInit = {},
): Promise<OriginAuthPublication> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${publicationPath(scopeID)}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...init.headers },
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
  return parseOriginAuthPublication(value)
}

function validMetadata(metadata: OriginAuthPublicationWriteMetadata): boolean {
  return metadataPattern.test(metadata.idempotencyKey) && metadataPattern.test(metadata.requestID) &&
    metadataPattern.test(metadata.traceID)
}

export function createOriginAuthPublicationWriteMetadata(): OriginAuthPublicationWriteMetadata {
  return {
    idempotencyKey: crypto.randomUUID(),
    requestID: crypto.randomUUID(),
    traceID: crypto.randomUUID(),
  }
}

export function createOriginAuthEdgePublicationWriteMetadata(): OriginAuthEdgePublicationWriteMetadata {
  const traceID = crypto.randomUUID().replaceAll('-', '')
  const spanID = crypto.randomUUID().replaceAll('-', '').slice(0, 16)
  return {
    idempotencyKey: crypto.randomUUID(),
    requestID: crypto.randomUUID(),
    correlationID: crypto.randomUUID(),
    traceparent: `00-${traceID}-${spanID}-01`,
    taskID: `origin-edge-${crypto.randomUUID()}`,
  }
}

export const originAuthPublicationsApi = {
  getLatest(accessToken: string, scopeID: string, signal?: AbortSignal): Promise<OriginAuthPublication> {
    return request(accessToken, scopeID, { signal })
  },
  create(
    accessToken: string,
    scopeID: string,
    expectedRevision: number,
    metadata: OriginAuthPublicationWriteMetadata,
  ): Promise<OriginAuthPublication> {
    if (!isSafeInteger(expectedRevision, 0) || !validMetadata(metadata)) {
      return Promise.reject(new ApiError('Invalid publication request', 0, 'invalid_request'))
    }
    return request(accessToken, scopeID, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': `"${expectedRevision}"`,
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestID,
        'X-Trace-ID': metadata.traceID,
      },
      body: '{}',
    })
  },
  async publishToNodes(
    accessToken: string,
    scopeID: string,
    expectedRevision: number,
    input: PublishOriginAuthEdgePublicationInput,
    metadata: OriginAuthEdgePublicationWriteMetadata,
  ): Promise<OriginAuthEdgePublication> {
    if (!isSafeInteger(expectedRevision, 1) || !isEdgeInput(input) || !isEdgeMetadata(metadata)) {
      throw edgeInvalidRequest()
    }
    const path = edgeCollectionPath(scopeID)
    let response: Response
    try {
      response = await fetch(`${apiRoot}${path}`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'If-Match': `"${expectedRevision}"`,
          'Idempotency-Key': metadata.idempotencyKey,
          'X-Request-ID': metadata.requestID,
          'X-Correlation-ID': metadata.correlationID,
          Traceparent: metadata.traceparent,
          ...(metadata.taskID ? { 'X-Task-ID': metadata.taskID } : {}),
        },
        body: JSON.stringify(input),
      })
    } catch {
      throw new ApiError('API request failed', 0, 'origin_auth_edge_publication_outcome_unknown')
    }
    if (!response.ok) throw await edgeResponseError(response)
    return parseEdgeResponse(response, scopeID, undefined, expectedRevision, true)
  },
  async getEdgePublication(
    accessToken: string,
    scopeID: string,
    publicationID: string,
    requestID?: string,
    signal?: AbortSignal,
  ): Promise<OriginAuthEdgePublication> {
    const path = edgeCollectionPath(scopeID)
    if (!uuidPattern.test(publicationID) || (requestID !== undefined && !uuidPattern.test(requestID))) {
      throw edgeInvalidRequest()
    }
    let response: Response
    try {
      response = await fetch(`${apiRoot}${path}/${encodeURIComponent(publicationID)}`, {
        credentials: 'include',
        signal,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          ...(requestID ? { 'X-Request-ID': requestID } : {}),
        },
      })
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new ApiError('API request failed', 0, 'origin_auth_edge_publication_request_canceled')
      }
      throw new ApiError('API request failed', 0, 'origin_auth_edge_publication_unavailable')
    }
    if (!response.ok) throw await edgeResponseError(response)
    return parseEdgeResponse(response, scopeID, publicationID)
  },
}
