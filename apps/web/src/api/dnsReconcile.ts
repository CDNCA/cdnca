import { ApiError, networkApiError } from './auth'

export type DNSReconcileRecordType = 'A' | 'AAAA' | 'CNAME'
export type DNSReconcileStatus =
  | 'dry_run'
  | 'applying'
  | 'propagating'
  | 'ready_to_commit'
  | 'committed'
  | 'failed'
  | 'cancelled'
  | 'timed_out'
  | 'commit_failed'
export type DNSReconcileErrorClass = '' | 'transient' | 'permanent' | 'revision_conflict' | 'cancelled' | 'timeout'
export type DNSReconcileOperationStatus =
  | 'planned'
  | 'deferred_until_commit'
  | 'running'
  | 'succeeded'
  | 'transient_failed'
  | 'permanent_failed'
  | 'revision_conflict'
  | 'cancelled'
  | 'skipped'

export interface DNSReconcileExpectedRecord {
  type: DNSReconcileRecordType
  values: string[]
}

export interface DNSReconcileProviderRecord {
  record_id: string
  name: string
  type: DNSReconcileRecordType
  value: string
  ttl: number
  line?: string
  weight?: number
}

export interface DNSReconcileCheckRequest {
  name: string
  expected: DNSReconcileExpectedRecord[]
  authoritative_ns: string[]
  ttl: number
  line?: string
  weight?: number
  propagation_started_at?: string
  propagation_window_seconds: number
  provider: {
    zone_id: string
    revision: number
    records: DNSReconcileProviderRecord[]
  }
}

export interface DNSReconcileProviderOperation {
  sequence: number
  action: 'create' | 'update' | 'delete'
  record_id?: string
  name: string
  type: DNSReconcileRecordType
  value: string
  ttl: number
  line?: string
  weight?: number
  previous_value?: string
  previous_ttl?: number
  previous_line?: string
  previous_weight?: number
  reason: string
}

export interface DNSReconcileRepairPlan {
  tenant_id: string
  site_id: string
  zone_id: string
  precondition_revision: number
  digest: string
  operations: DNSReconcileProviderOperation[]
}

export interface DNSReconcileOperationResult {
  source_sequence: number
  operation: DNSReconcileProviderOperation
  client_request_id: string
  provider_request_id?: string
  provider_record_id?: string
  provider_revision: number
  status: DNSReconcileOperationStatus
  attempts: number
  error_class: DNSReconcileErrorClass
  error_code: string
  report_sequence: number
}

export interface DNSReconcilePropagationAttempt {
  number: number
  checked_at: string
  status: string
  consecutive_healthy: number
}

export interface DNSReconcileObservation {
  role: 'authoritative' | 'public_recursive'
  resolver: string
  record_type: DNSReconcileRecordType
  status: string
  values: string[]
  cname_chain: string[]
  attempts: number
  minimum_ttl: number
  error_code: string
}

export interface DNSReconcileCheckResult {
  name: string
  status: string
  compliant: boolean
  checked_at: string
  observations: DNSReconcileObservation[]
  repair_plan: DNSReconcileRepairPlan
}

export interface DNSReconcileResult {
  tenant_id: string
  site_id: string
  zone_id: string
  payload_digest: string
  plan: DNSReconcileRepairPlan
  status: DNSReconcileStatus
  replayed: boolean
  started_at: string
  updated_at: string
  ready_at?: string
  initial_revision: number
  provider_revision: number
  operations: DNSReconcileOperationResult[]
  deferred_deletes: DNSReconcileOperationResult[]
  compensation_plan: DNSReconcileProviderOperation[]
  propagation: DNSReconcilePropagationAttempt[]
  last_check?: DNSReconcileCheckResult
  error_class: DNSReconcileErrorClass
  error_code: string
}

export interface DNSReconcileTask {
  id: string
  tenant_id: string
  site_id: string
  revision: number
  required_consecutive: number
  job: {
    id: string
    kind: 'dns_reconcile'
    subject: string
    state: 'queued' | 'running' | 'succeeded' | 'partial_failed' | 'failed' | 'cancelled'
    attempt: number
    max_attempts: number
    cancel_requested_at?: string
    progress: {
      total: number
      completed: number
      succeeded: number
      failed: number
      cancelled: number
      pending: number
    }
    last_error_code?: string
    created_at: string
    started_at?: string
    updated_at: string
    completed_at?: string
  }
  request: DNSReconcileCheckRequest
  result: DNSReconcileResult
  created_at: string
  updated_at: string
  replayed: boolean
}

export interface DNSReconcileRequestIdentity {
  requestID: string
  traceparent: string
}

export interface DNSReconcileCommandIdentity extends DNSReconcileRequestIdentity {
  idempotencyKey: string
  expectedRevision: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const idempotencyKeyPattern = /^[A-Za-z0-9._-]{1,128}$/
const traceparentPattern = /^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-(?:00|01)$/
const providerIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/
const digestPattern = /^[0-9a-f]{64}$/
const errorCodePattern = /^[a-z][a-z0-9_]{0,63}$/
const utf8Encoder = new TextEncoder()
const recordTypes = new Set<DNSReconcileRecordType>(['A', 'AAAA', 'CNAME'])
const reconcileStatuses = new Set<DNSReconcileStatus>([
  'dry_run', 'applying', 'propagating', 'ready_to_commit', 'committed',
  'failed', 'cancelled', 'timed_out', 'commit_failed',
])
const operationStatuses = new Set<DNSReconcileOperationStatus>([
  'planned', 'deferred_until_commit', 'running', 'succeeded', 'transient_failed',
  'permanent_failed', 'revision_conflict', 'cancelled', 'skipped',
])
const errorClasses = new Set<DNSReconcileErrorClass>([
  '', 'transient', 'permanent', 'revision_conflict', 'cancelled', 'timeout',
])

function responseInvalid(): ApiError {
  return new ApiError('DNS reconcile response is invalid', 0, 'response_invalid')
}

function requestInvalid(): ApiError {
  return new ApiError('DNS reconcile request is invalid', 400, 'invalid_request')
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key))
}

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function text(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is string {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum
}

function validLineWeight(line: unknown, weight: unknown): boolean {
  return (line === undefined || (typeof line === 'string' && utf8Encoder.encode(line).length <= 64 &&
    line === line.trim() && ![...line].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint <= 0x1f || codePoint === 0x7f
    }))) &&
    (weight === undefined || integer(weight, 0, 100))
}

function dateTime(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value)
  if (!match) return false
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const offsetHour = Number(match[7] ?? 0)
  const offsetMinute = Number(match[8] ?? 0)
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] &&
    hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function validExpectedRecord(value: unknown): value is DNSReconcileExpectedRecord {
  if (!isObject(value) || !exactKeys(value, ['type', 'values']) ||
    !recordTypes.has(value.type as DNSReconcileRecordType) || !Array.isArray(value.values) ||
    value.values.length < 1 || value.values.length > 32 ||
    !value.values.every((item) => text(item, 1, 255))) return false
  return new Set(value.values).size === value.values.length
}

function validProviderRecord(value: unknown): value is DNSReconcileProviderRecord {
  return isObject(value) && exactKeys(value, ['record_id', 'name', 'type', 'value', 'ttl'], ['line', 'weight']) &&
    text(value.record_id, 1, 256) && providerIDPattern.test(value.record_id) &&
    text(value.name, 1, 255) && recordTypes.has(value.type as DNSReconcileRecordType) &&
    text(value.value, 1, 255) && integer(value.ttl, 1, 604800) && validLineWeight(value.line, value.weight)
}

function validCheckRequest(value: unknown): value is DNSReconcileCheckRequest {
  if (!isObject(value) || !exactKeys(value, [
    'name', 'expected', 'authoritative_ns', 'ttl', 'propagation_window_seconds', 'provider',
  ], ['propagation_started_at', 'line', 'weight']) || !text(value.name, 1, 255) ||
    !Array.isArray(value.expected) || value.expected.length < 1 || value.expected.length > 3 ||
    !value.expected.every(validExpectedRecord) || !Array.isArray(value.authoritative_ns) ||
    value.authoritative_ns.length > 32 || !value.authoritative_ns.every((item) => text(item, 1, 255)) ||
    !integer(value.ttl, 1, 604800) || !validLineWeight(value.line, value.weight) ||
    !integer(value.propagation_window_seconds, 1, 604800) ||
    (value.propagation_started_at !== undefined && !dateTime(value.propagation_started_at)) ||
    !isObject(value.provider) || !exactKeys(value.provider, ['zone_id', 'revision', 'records'])) return false
  return typeof value.provider.zone_id === 'string' && uuidPattern.test(value.provider.zone_id) &&
    integer(value.provider.revision, 1) && Array.isArray(value.provider.records) &&
    value.provider.records.length <= 128 && value.provider.records.every(validProviderRecord)
}

function validProviderOperation(value: unknown): value is DNSReconcileProviderOperation {
  return isObject(value) && exactKeys(value, [
    'sequence', 'action', 'name', 'type', 'value', 'ttl', 'reason',
  ], ['record_id', 'line', 'weight', 'previous_value', 'previous_ttl', 'previous_line', 'previous_weight']) &&
    integer(value.sequence, 1) &&
    (value.action === 'create' || value.action === 'update' || value.action === 'delete') &&
    (value.record_id === undefined || (text(value.record_id, 1, 256) && providerIDPattern.test(value.record_id))) &&
    typeof value.name === 'string' && recordTypes.has(value.type as DNSReconcileRecordType) &&
    typeof value.value === 'string' && integer(value.ttl, 1, 604800) && validLineWeight(value.line, value.weight) &&
    (value.previous_value === undefined || typeof value.previous_value === 'string') &&
    (value.previous_ttl === undefined || integer(value.previous_ttl, 1, 604800)) && typeof value.reason === 'string' &&
    validLineWeight(value.previous_line, value.previous_weight)
}

function validRepairPlan(value: unknown): value is DNSReconcileRepairPlan {
  return isObject(value) && exactKeys(value, [
    'tenant_id', 'site_id', 'zone_id', 'precondition_revision', 'digest', 'operations',
  ]) && typeof value.tenant_id === 'string' && uuidPattern.test(value.tenant_id) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    typeof value.zone_id === 'string' && uuidPattern.test(value.zone_id) &&
    integer(value.precondition_revision, 1) && typeof value.digest === 'string' && digestPattern.test(value.digest) &&
    Array.isArray(value.operations) && value.operations.every(validProviderOperation)
}

function validOperationResult(value: unknown): value is DNSReconcileOperationResult {
  return isObject(value) && exactKeys(value, [
    'source_sequence', 'operation', 'client_request_id', 'provider_revision', 'status',
    'attempts', 'error_class', 'error_code', 'report_sequence',
  ], ['provider_request_id', 'provider_record_id']) && integer(value.source_sequence, 1) &&
    validProviderOperation(value.operation) && typeof value.client_request_id === 'string' &&
    (value.provider_request_id === undefined || (text(value.provider_request_id, 1, 256) && providerIDPattern.test(value.provider_request_id))) &&
    (value.provider_record_id === undefined || (text(value.provider_record_id, 1, 256) && providerIDPattern.test(value.provider_record_id))) &&
    integer(value.provider_revision, 0) && operationStatuses.has(value.status as DNSReconcileOperationStatus) &&
    integer(value.attempts, 0) && errorClasses.has(value.error_class as DNSReconcileErrorClass) &&
    typeof value.error_code === 'string' && integer(value.report_sequence, 0)
}

function validPropagation(value: unknown): value is DNSReconcilePropagationAttempt {
  return isObject(value) && exactKeys(value, ['number', 'checked_at', 'status', 'consecutive_healthy']) &&
    integer(value.number, 1) && dateTime(value.checked_at) && typeof value.status === 'string' &&
    integer(value.consecutive_healthy, 0)
}

function validObservation(value: unknown): value is DNSReconcileObservation {
  return isObject(value) && exactKeys(value, [
    'role', 'resolver', 'record_type', 'status', 'values', 'cname_chain',
    'attempts', 'minimum_ttl', 'error_code',
  ]) && (value.role === 'authoritative' || value.role === 'public_recursive') &&
    typeof value.resolver === 'string' && recordTypes.has(value.record_type as DNSReconcileRecordType) &&
    typeof value.status === 'string' && stringArray(value.values) && stringArray(value.cname_chain) &&
    integer(value.attempts, 0) && integer(value.minimum_ttl, 0) && typeof value.error_code === 'string'
}

function validCheckResult(value: unknown): value is DNSReconcileCheckResult {
  return isObject(value) && exactKeys(value, [
    'name', 'status', 'compliant', 'checked_at', 'observations', 'repair_plan',
  ]) && typeof value.name === 'string' && typeof value.status === 'string' &&
    typeof value.compliant === 'boolean' && dateTime(value.checked_at) &&
    Array.isArray(value.observations) && value.observations.every(validObservation) && validRepairPlan(value.repair_plan)
}

function validResult(value: unknown): value is DNSReconcileResult {
  return isObject(value) && exactKeys(value, [
    'tenant_id', 'site_id', 'zone_id', 'payload_digest', 'plan', 'status', 'replayed',
    'started_at', 'updated_at', 'initial_revision', 'provider_revision', 'operations',
    'deferred_deletes', 'compensation_plan', 'propagation', 'error_class', 'error_code',
  ], ['ready_at', 'last_check']) && typeof value.tenant_id === 'string' && uuidPattern.test(value.tenant_id) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    typeof value.zone_id === 'string' && uuidPattern.test(value.zone_id) &&
    typeof value.payload_digest === 'string' && digestPattern.test(value.payload_digest) && validRepairPlan(value.plan) &&
    value.plan.tenant_id === value.tenant_id && value.plan.site_id === value.site_id && value.plan.zone_id === value.zone_id &&
    reconcileStatuses.has(value.status as DNSReconcileStatus) && typeof value.replayed === 'boolean' &&
    dateTime(value.started_at) && dateTime(value.updated_at) && (value.ready_at === undefined || dateTime(value.ready_at)) &&
    integer(value.initial_revision, 1) && integer(value.provider_revision, 1) &&
    Array.isArray(value.operations) && value.operations.every(validOperationResult) &&
    Array.isArray(value.deferred_deletes) && value.deferred_deletes.every(validOperationResult) &&
    Array.isArray(value.compensation_plan) && value.compensation_plan.every(validProviderOperation) &&
    Array.isArray(value.propagation) && value.propagation.every(validPropagation) &&
    (value.last_check === undefined || (validCheckResult(value.last_check) &&
      value.last_check.repair_plan.tenant_id === value.tenant_id &&
      value.last_check.repair_plan.site_id === value.site_id &&
      value.last_check.repair_plan.zone_id === value.zone_id)) &&
    errorClasses.has(value.error_class as DNSReconcileErrorClass) && text(value.error_code, 0, 64)
}

function validProgress(value: unknown): boolean {
  return isObject(value) && exactKeys(value, ['total', 'completed', 'succeeded', 'failed', 'cancelled', 'pending']) &&
    ['total', 'completed', 'succeeded', 'failed', 'cancelled', 'pending'].every((key) => integer(value[key], 0))
}

function validJob(value: unknown): value is DNSReconcileTask['job'] {
  return isObject(value) && exactKeys(value, [
    'id', 'kind', 'subject', 'state', 'attempt', 'max_attempts', 'progress', 'created_at', 'updated_at',
  ], ['cancel_requested_at', 'last_error_code', 'started_at', 'completed_at']) &&
    typeof value.id === 'string' && uuidPattern.test(value.id) && value.kind === 'dns_reconcile' && text(value.subject, 1) &&
    ['queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled'].includes(String(value.state)) &&
    integer(value.attempt, 0) && integer(value.max_attempts, 1) && validProgress(value.progress) &&
    (value.cancel_requested_at === undefined || dateTime(value.cancel_requested_at)) &&
    (value.last_error_code === undefined || text(value.last_error_code, 0, 64)) && dateTime(value.created_at) &&
    (value.started_at === undefined || dateTime(value.started_at)) && dateTime(value.updated_at) &&
    (value.completed_at === undefined || dateTime(value.completed_at))
}

function validTask(value: unknown): value is DNSReconcileTask {
  return isObject(value) && exactKeys(value, [
    'id', 'tenant_id', 'site_id', 'revision', 'required_consecutive', 'job', 'request',
    'result', 'created_at', 'updated_at', 'replayed',
  ]) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.tenant_id === 'string' && uuidPattern.test(value.tenant_id) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) && integer(value.revision, 1) &&
    integer(value.required_consecutive, 1, 5) && validJob(value.job) && value.job.id === value.id &&
    validCheckRequest(value.request) &&
    validResult(value.result) && value.result.tenant_id === value.tenant_id && value.result.site_id === value.site_id &&
    value.result.zone_id === value.request.provider.zone_id && dateTime(value.created_at) && dateTime(value.updated_at) &&
    typeof value.replayed === 'boolean'
}

function hasDuplicateJSONKeys(source: string): boolean {
  let index = 0
  const whitespace = () => { while (/\s/.test(source[index] ?? '')) index += 1 }
  const parseString = (): string => {
    const start = index
    index += 1
    while (index < source.length) {
      if (source[index] === '\\') index += 2
      else if (source[index++] === '"') break
    }
    return JSON.parse(source.slice(start, index)) as string
  }
  const parseValue = (): boolean => {
    whitespace()
    if (source[index] === '{') {
      index += 1
      const keys = new Set<string>()
      whitespace()
      while (source[index] !== '}') {
        const key = parseString()
        if (keys.has(key)) return true
        keys.add(key)
        whitespace()
        index += 1
        if (parseValue()) return true
        whitespace()
        if (source[index] !== ',') break
        index += 1
        whitespace()
      }
      index += 1
      return false
    }
    if (source[index] === '[') {
      index += 1
      whitespace()
      while (source[index] !== ']') {
        if (parseValue()) return true
        whitespace()
        if (source[index] !== ',') break
        index += 1
        whitespace()
      }
      index += 1
      return false
    }
    if (source[index] === '"') {
      parseString()
      return false
    }
    while (index < source.length && !/[\s,\]}]/.test(source[index])) index += 1
    return false
  }
  return parseValue()
}

async function jsonBody(response: Response): Promise<unknown> {
  if (response.headers.get('Content-Type') !== 'application/json') throw responseInvalid()
  try {
    const source = await response.text()
    if (hasDuplicateJSONKeys(source)) throw responseInvalid()
    return JSON.parse(source) as unknown
  } catch {
    throw responseInvalid()
  }
}

function validIdentity(identity: DNSReconcileRequestIdentity): boolean {
  return metadataPattern.test(identity.requestID) && traceparentPattern.test(identity.traceparent)
}

function validCommandIdentity(identity: DNSReconcileCommandIdentity): boolean {
  return validIdentity(identity) && idempotencyKeyPattern.test(identity.idempotencyKey) && integer(identity.expectedRevision, 1)
}

async function request(
  accessToken: string,
  path: string,
  expectedStatus: number,
  identity: DNSReconcileRequestIdentity,
  init: RequestInit,
): Promise<{ body: unknown; response: Response }> {
  if (!accessToken || !validIdentity(identity)) throw requestInvalid()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': identity.requestID,
        traceparent: identity.traceparent,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (response.headers.get('X-Request-ID') !== identity.requestID) throw responseInvalid()
  const body = await jsonBody(response)
  if (!response.ok) {
    if (!isObject(body) || !exactKeys(body, ['error']) || !isObject(body.error) ||
      !exactKeys(body.error, ['code', 'message', 'request_id']) ||
      typeof body.error.code !== 'string' || !errorCodePattern.test(body.error.code) ||
      !text(body.error.message, 1, 1024) || body.error.request_id !== identity.requestID) throw responseInvalid()
    throw new ApiError('DNS reconcile API request failed', response.status, body.error.code, identity.requestID)
  }
  if (response.status !== expectedStatus) throw responseInvalid()
  return { body, response }
}

function taskResponse(value: { body: unknown; response: Response }, siteID: string, taskID?: string): DNSReconcileTask {
  if (!validTask(value.body) || value.body.site_id !== siteID || (taskID !== undefined && value.body.id !== taskID) ||
    value.response.headers.get('ETag') !== `"${value.body.revision}"`) throw responseInvalid()
  const replay = value.response.headers.get('X-Idempotent-Replay')
  if ((value.body.replayed && replay !== 'true') || (!value.body.replayed && replay !== null)) throw responseInvalid()
  return value.body
}

function validateTarget(siteID: string, taskID?: string): void {
  if (!uuidPattern.test(siteID) || (taskID !== undefined && !uuidPattern.test(taskID))) throw requestInvalid()
}

async function dryRun(
  accessToken: string,
  siteID: string,
  input: DNSReconcileCheckRequest,
  identity: DNSReconcileRequestIdentity,
): Promise<DNSReconcileResult> {
  validateTarget(siteID)
  if (!validCheckRequest(input)) throw requestInvalid()
  const value = await request(accessToken, `/v1/sites/${siteID}/dns-reconcile/dry-run`, 200, identity, {
    method: 'POST', body: JSON.stringify(input),
  })
  if (!validResult(value.body) || value.body.status !== 'dry_run' || value.body.site_id !== siteID ||
    value.body.zone_id !== input.provider.zone_id ||
    value.body.plan.precondition_revision !== input.provider.revision) throw responseInvalid()
  return value.body
}

async function apply(
  accessToken: string,
  siteID: string,
  input: DNSReconcileCheckRequest,
  identity: DNSReconcileCommandIdentity,
): Promise<DNSReconcileTask> {
  validateTarget(siteID)
  if (!validCheckRequest(input) || !validCommandIdentity(identity) || identity.expectedRevision !== input.provider.revision) {
    throw requestInvalid()
  }
  const value = await request(accessToken, `/v1/sites/${siteID}/dns-reconcile/apply`, 202, identity, {
    method: 'POST',
    headers: { 'Idempotency-Key': identity.idempotencyKey, 'If-Match': `"${identity.expectedRevision}"` },
    body: JSON.stringify(input),
  })
  const task = taskResponse(value, siteID)
  if (task.request.provider.zone_id !== input.provider.zone_id || task.request.provider.revision !== input.provider.revision) {
    throw responseInvalid()
  }
  return task
}

async function get(
  accessToken: string,
  siteID: string,
  taskID: string,
  identity: DNSReconcileRequestIdentity,
): Promise<DNSReconcileTask> {
  validateTarget(siteID, taskID)
  return taskResponse(await request(
    accessToken, `/v1/sites/${siteID}/dns-reconcile/tasks/${taskID}`, 200, identity, { method: 'GET' },
  ), siteID, taskID)
}

async function command(
  action: 'commit' | 'cancel',
  accessToken: string,
  siteID: string,
  taskID: string,
  identity: DNSReconcileCommandIdentity,
): Promise<DNSReconcileTask> {
  validateTarget(siteID, taskID)
  if (!validCommandIdentity(identity)) throw requestInvalid()
  return taskResponse(await request(
    accessToken,
    `/v1/sites/${siteID}/dns-reconcile/tasks/${taskID}/${action}`,
    200,
    identity,
    {
      method: 'POST',
      headers: { 'Idempotency-Key': identity.idempotencyKey, 'If-Match': `"${identity.expectedRevision}"` },
      body: '{}',
    },
  ), siteID, taskID)
}

export function hasVerifiedDNSPropagation(task: DNSReconcileTask): boolean {
  const latest = task.result.propagation.at(-1)
  return task.result.status === 'committed' && task.result.last_check?.compliant === true &&
    latest?.status === 'healthy' && latest.consecutive_healthy >= task.required_consecutive
}

export const dnsReconcileApi = {
  dryRun,
  apply,
  get,
  commit: (
    accessToken: string, siteID: string, taskID: string, identity: DNSReconcileCommandIdentity,
  ) => command('commit', accessToken, siteID, taskID, identity),
  cancel: (
    accessToken: string, siteID: string, taskID: string, identity: DNSReconcileCommandIdentity,
  ) => command('cancel', accessToken, siteID, taskID, identity),
}
