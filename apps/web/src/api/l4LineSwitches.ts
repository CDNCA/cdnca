import { ApiError, networkApiError, responseApiError } from './auth'

export type L4LineSwitchState =
  | 'preparing'
  | 'health_gate'
  | 'draining_old'
  | 'compensating_old'
  | 'completed'
  | 'rolled_back'
  | 'needs_attention'

export interface L4LineSnapshotReference {
  id: string
  revision: number
  sha256: string
}

export interface L4LineSwitchPublication {
  id?: string
  rollout_id?: string
  config_version_id?: string
}

export interface L4LineSwitch {
  id: string
  configuration_scope_id: string
  expected_source_revision: number
  from: L4LineSnapshotReference
  to: L4LineSnapshotReference
  prepare_node_count: number
  retiring_node_count: number
  state: L4LineSwitchState
  state_revision: number
  prepare_publication: L4LineSwitchPublication
  compensation_publication: L4LineSwitchPublication
  drain_command_count: number
  error_code?: string
  dns_gate?: L4LineSwitchDNSGate
  deadline: string
  created_at: string
  updated_at: string
  replayed?: boolean
}

export type L4LineSwitchDNSGateState = 'ready' | 'retarget_pending' | 'propagation_wait'

// Reported while a healthy switch waits for DNS to leave the retiring nodes.
export interface L4LineSwitchDNSGate {
  state: L4LineSwitchDNSGateState
  owners: number
  pending_owners: number
  ready_at?: string
}

export interface CreateL4LineSwitchInput {
  expected_source_revision: number
  from: L4LineSnapshotReference
  to: L4LineSnapshotReference
  health: {
    activation_timeout_ms: number
    observation_window_ms: number
    required_consecutive_successes: number
  }
  drain: {
    health_timeout_ms: number
    max_drain_ms: number
  }
  max_attempts: number
  deadline: string
}

export interface L4LineSwitchWriteMetadata {
  requestId: string
  correlationId: string
  idempotencyKey: string
  traceparent: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const shaPattern = /^(?!0{64}$)[0-9a-f]{64}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const traceparentPattern = /^00-(?!0{32}-)[0-9a-f]{32}-(?!0{16}-)[0-9a-f]{16}-[0-9a-f]{2}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/
const errorCodePattern = /^[A-Z0-9_]{1,128}$/
const states = new Set<L4LineSwitchState>([
  'preparing', 'health_gate', 'draining_old', 'compensating_old', 'completed', 'rolled_back', 'needs_attention',
])

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key))
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

function parseSnapshot(value: unknown): L4LineSnapshotReference {
  if (!record(value) || !exactKeys(value, ['id', 'revision', 'sha256']) || !uuidPattern.test(String(value.id)) ||
    !uint(value.revision, 1) || !shaPattern.test(String(value.sha256))) throw invalidResponse()
  return value as unknown as L4LineSnapshotReference
}

function parsePublication(value: unknown): L4LineSwitchPublication {
  if (!record(value) || !exactKeys(value, [], ['id', 'rollout_id', 'config_version_id'])) throw invalidResponse()
  for (const key of ['id', 'rollout_id', 'config_version_id']) {
    if (value[key] !== undefined && !uuidPattern.test(String(value[key]))) throw invalidResponse()
  }
  return value as L4LineSwitchPublication
}

const dnsGateStates = new Set<string>(['ready', 'retarget_pending', 'propagation_wait'])

function parseDNSGate(value: unknown): L4LineSwitchDNSGate {
  if (!record(value) || !exactKeys(value, ['state', 'owners', 'pending_owners'], ['ready_at']) ||
    typeof value.state !== 'string' || !dnsGateStates.has(value.state) || !uint(value.owners, 0) ||
    !uint(value.pending_owners, 0) || (value.ready_at !== undefined && !timestamp(value.ready_at))) throw invalidResponse()
  return value as unknown as L4LineSwitchDNSGate
}

function parseSwitch(value: unknown, scopeID: string, switchID?: string): L4LineSwitch {
  const required = [
    'id', 'configuration_scope_id', 'expected_source_revision', 'from', 'to', 'prepare_node_count',
    'retiring_node_count', 'state', 'state_revision', 'prepare_publication', 'compensation_publication',
    'drain_command_count', 'deadline', 'created_at', 'updated_at',
  ]
  if (!record(value) || !exactKeys(value, required, ['error_code', 'dns_gate', 'replayed']) || !uuidPattern.test(String(value.id)) ||
    value.configuration_scope_id !== scopeID || (switchID !== undefined && value.id !== switchID) ||
    !uint(value.expected_source_revision, 1) || !uint(value.prepare_node_count, 1, 10_000) ||
    !uint(value.retiring_node_count, 0, 10_000) || typeof value.state !== 'string' ||
    !states.has(value.state as L4LineSwitchState) || !uint(value.state_revision, 1) ||
    !uint(value.drain_command_count, 0, 10_000) || !timestamp(value.deadline) || !timestamp(value.created_at) ||
    !timestamp(value.updated_at) || (value.error_code !== undefined &&
      (typeof value.error_code !== 'string' || !errorCodePattern.test(value.error_code))) ||
    (value.replayed !== undefined && typeof value.replayed !== 'boolean')) throw invalidResponse()
  return {
    ...value,
    from: parseSnapshot(value.from),
    to: parseSnapshot(value.to),
    prepare_publication: parsePublication(value.prepare_publication),
    compensation_publication: parsePublication(value.compensation_publication),
    ...(value.dns_gate === undefined ? {} : { dns_gate: parseDNSGate(value.dns_gate) }),
  } as L4LineSwitch
}

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function validMetadata(scopeID: string, accessToken: string, metadata?: L4LineSwitchWriteMetadata): boolean {
  return uuidPattern.test(scopeID) && accessToken.length > 0 && accessToken.length <= 8192 && !/[\s]/.test(accessToken) &&
    (metadata === undefined || uuidPattern.test(metadata.requestId) && uuidPattern.test(metadata.correlationId) &&
      metadataPattern.test(metadata.idempotencyKey) && traceparentPattern.test(metadata.traceparent))
}

async function request(
  path: string,
  accessToken: string,
  scopeID: string,
  method: 'GET' | 'POST',
  switchID?: string,
  input?: CreateL4LineSwitchInput,
  metadata?: L4LineSwitchWriteMetadata,
  requestID?: string,
): Promise<L4LineSwitch> {
  if (!validMetadata(scopeID, accessToken, metadata) || (switchID !== undefined && !uuidPattern.test(switchID)) ||
    method === 'POST' && metadata === undefined) {
    throw new ApiError('Invalid L4 line switch request', 400, 'invalid_request')
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${accessToken}`,
    'X-Request-ID': metadata?.requestId ?? requestID ?? randomUUID(),
  }
  if (metadata) {
    headers['X-Correlation-ID'] = metadata.correlationId
    headers['Idempotency-Key'] = metadata.idempotencyKey
    headers.Traceparent = metadata.traceparent
  }
  if (input !== undefined) headers['Content-Type'] = 'application/json'
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, { method, headers, body: input === undefined ? undefined : JSON.stringify(input) })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw invalidResponse()
  }
  return parseSwitch(payload, scopeID, switchID)
}

export function createL4LineSwitch(
  accessToken: string,
  scopeID: string,
  input: CreateL4LineSwitchInput,
  metadata: L4LineSwitchWriteMetadata,
): Promise<L4LineSwitch> {
  return request(`/v1/tenant-scopes/${encodeURIComponent(scopeID)}/l4-line-switches`, accessToken, scopeID, 'POST', undefined, input, metadata)
}

export function getL4LineSwitch(accessToken: string, scopeID: string, switchID: string): Promise<L4LineSwitch> {
  return request(`/v1/tenant-scopes/${encodeURIComponent(scopeID)}/l4-line-switches/${encodeURIComponent(switchID)}`, accessToken, scopeID, 'GET', switchID)
}

export async function getCurrentL4LineSwitch(accessToken: string, scopeID: string): Promise<L4LineSwitch | null> {
  try {
    return await request(`/v1/tenant-scopes/${encodeURIComponent(scopeID)}/l4-line-switches/current`, accessToken, scopeID, 'GET')
  } catch (error) {
    if (error instanceof ApiError && error.status === 404 && error.code === 'l4_line_switch_not_found') return null
    throw error
  }
}

export function reconcileL4LineSwitch(
  accessToken: string,
  scopeID: string,
  switchID: string,
  metadata: L4LineSwitchWriteMetadata,
): Promise<L4LineSwitch> {
  return request(
    `/v1/tenant-scopes/${encodeURIComponent(scopeID)}/l4-line-switches/${encodeURIComponent(switchID)}/reconcile`,
    accessToken,
    scopeID,
    'POST',
    switchID,
    undefined,
    metadata,
  )
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

export function newL4LineSwitchWriteMetadata(): L4LineSwitchWriteMetadata {
  const requestId = randomUUID()
  return {
    requestId,
    correlationId: requestId,
    idempotencyKey: `l4-line-switch-${requestId}`,
    traceparent: `00-${hex(randomBytes(16))}-${hex(randomBytes(8))}-01`,
  }
}
