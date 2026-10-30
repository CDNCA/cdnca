import { ApiError, networkApiError, responseApiError } from './auth'

export type JobState =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'partial_failed'
  | 'failed'
  | 'cancelled'

export type JobAttemptState =
  | 'running'
  | 'succeeded'
  | 'partial_failed'
  | 'failed'
  | 'cancelled'
  | 'lease_expired'

export type JobResultState = 'pending' | 'succeeded' | 'failed' | 'cancelled'
export type JobAudience = 'platform' | 'tenant'
export type JobCommand = 'cancel' | 'retry'

export interface JobProgress {
  total: number
  completed: number
  succeeded: number
  failed: number
  cancelled: number
  pending: number
}

export interface BackgroundJob {
  task_id: string
  tenant_id: string
  kind: string
  related_resource: { reference: string }
  request_id: string
  trace_id?: string
  status: JobState
  attempt: number
  max_attempts: number
  progress: JobProgress
  failure_code?: string
  created_at: string
  started_at?: string
  updated_at: string
  completed_at?: string
	revision: string
}

export interface JobAttempt {
  number: number
  status: JobAttemptState
  started_at: string
  last_heartbeat_at: string
  lease_expires_at: string
  completed_at?: string
  failure_code?: string
}

export interface JobItemResult {
  ordinal: number
  item_id: string
  node_id?: string
  status: JobResultState
  attempt: number
  sequence: number
  failure_code?: string
  completed_at?: string
  /** Start of the attempt that settled this item; absent while pending. */
  started_at?: string
  /** Recorded failed settlement receipts for this item. */
  failure_count?: number
}

export interface JobListResponse {
  data: BackgroundJob[]
  page: { next_cursor?: string } | JobNumberedPage
  query: { from: string; to: string }
  task_metadata?: JobTaskMetadata[]
}

export interface JobNumberedPage {
  number: number
  limit: number
  total: number
  total_pages: number
  consistency: 'request_snapshot'
}

export interface JobTaskMetadata {
  task_id: string
  name: { name_key: string; resource: string; source: 'derived' }
  priority: { policy: 'ready_fifo' | 'producer_managed' | 'unknown' }
  dependencies: {
    state: 'observed' | 'none' | 'unknown'
    items: Array<{ task_id: string; relation: 'completion'; status: JobState }>
  }
}

export interface JobKindDefinition {
  kind: string
  name_key: string
  integration: 'integrated'
  runtime_status: 'unknown'
}

export interface JobKindListResponse {
  data: JobKindDefinition[]
}

export interface JobDetailResponse {
  data: BackgroundJob
}

export interface JobAttemptListResponse {
  data: JobAttempt[]
  page: { next_cursor?: string }
}

export interface JobResultListResponse {
  data: JobItemResult[]
  page: { next_cursor?: string }
}

export type JobSettlementSource = 'worker' | 'system'

export interface JobSettlementReceipt {
  ordinal: number
  item_id: string
  node_id?: string
  status: Extract<JobResultState, 'succeeded' | 'failed'>
  attempt: number
  sequence: number
  failure_code?: string
  source: JobSettlementSource
  reported_at: string
}

export interface JobDeadLetter {
  attempt: number
  reason_code: string
  failed_item_count: number
  source: 'worker' | 'lease_expiry'
  created_at: string
}

export interface JobSettlementReceiptListResponse {
  data: JobSettlementReceipt[]
  page: { next_cursor?: string }
}

export interface JobDeadLetterListResponse {
  data: JobDeadLetter[]
  page: { next_cursor?: string }
}

export interface JobCommandResponse {
  data: BackgroundJob
  replayed: boolean
}

export interface AdminJobListParams {
  from: string
  to: string
  taskID?: string
  statuses?: JobState[]
  kind?: string
  resource?: string
  limit: number
  cursor?: string
  page?: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const codePattern = /^[a-z][a-z0-9._-]{0,127}$/
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const jobRevisionPattern = /^(?:[1-9][0-9]{0,19}|[0-9a-f]{64})$/
const jobStates = new Set<JobState>([
  'queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled',
])
const attemptStates = new Set<JobAttemptState>([
  'running', 'succeeded', 'partial_failed', 'failed', 'cancelled', 'lease_expired',
])
const resultStates = new Set<JobResultState>(['pending', 'succeeded', 'failed', 'cancelled'])
export const kindNameKeys: Record<string, string> = {
  'analytics.log_export': 'jobs.kindNames.analyticsLogExport',
  'cache.operation': 'jobs.kindNames.cacheOperation',
  'dns.cleanup.v1': 'jobs.kindNames.dnsCleanup',
  'dns.repair.v1': 'jobs.kindNames.dnsRepair',
  dns_reconcile: 'jobs.kindNames.dnsReconcile',
  'dns.cname.allocation': 'jobs.kindNames.cnameAllocation',
  'dns.cname.intent': 'jobs.kindNames.cnameIntent',
  'dns.cname.stream_intent': 'jobs.kindNames.cnameStreamIntent',
  'edge.publication': 'jobs.kindNames.edgePublication',
  'site.status_recovery': 'jobs.kindNames.siteStatusRecovery',
}

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
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

function isInteger(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function isString(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function isUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function isOptionalCode(value: unknown): value is string {
  return typeof value === 'string' && codePattern.test(value)
}

function isPage(value: unknown): value is { next_cursor?: string } {
  return isRecord(value) && hasExactKeys(value, [], ['next_cursor']) &&
    (!('next_cursor' in value) || isString(value.next_cursor, 1, 8192))
}

function isNumberedPage(value: unknown): value is JobNumberedPage {
  return isRecord(value) &&
    hasExactKeys(value, ['number', 'limit', 'total', 'total_pages', 'consistency']) &&
    isInteger(value.number, 1) && isInteger(value.limit, 1, 100) && isInteger(value.total) &&
    isInteger(value.total_pages) && value.total_pages === Math.ceil(value.total / value.limit) &&
    value.consistency === 'request_snapshot'
}

function isTaskMetadata(value: unknown, job: BackgroundJob): value is JobTaskMetadata {
  if (!isRecord(value) || !hasExactKeys(value, ['task_id', 'name', 'priority', 'dependencies']) ||
    value.task_id !== job.task_id ||
    !isRecord(value.name) || !hasExactKeys(value.name, ['name_key', 'resource', 'source']) ||
    value.name.name_key !== (Object.hasOwn(kindNameKeys, job.kind) ? kindNameKeys[job.kind] : 'jobs.kindNames.unknown') ||
    value.name.resource !== job.related_resource.reference || value.name.source !== 'derived' ||
    !isRecord(value.priority) || !hasExactKeys(value.priority, ['policy']) ||
    !['ready_fifo', 'producer_managed', 'unknown'].includes(String(value.priority.policy)) ||
    !isRecord(value.dependencies) || !hasExactKeys(value.dependencies, ['state', 'items']) ||
    !Array.isArray(value.dependencies.items) || value.dependencies.items.length > 1) return false
  const { state, items } = value.dependencies
  if (state === 'unknown') return items.length === 0
  if (state === 'none') return items.length === 0 && Object.hasOwn(kindNameKeys, job.kind) && job.kind !== 'dns.cname.allocation'
  return state === 'observed' && job.kind === 'dns.cname.allocation' && items.length > 0 &&
    items.every((item) => isRecord(item) && hasExactKeys(item, ['task_id', 'relation', 'status']) &&
      isUUID(item.task_id) && item.task_id !== job.task_id && item.relation === 'completion' &&
      jobStates.has(item.status as JobState))
}

function parseKinds(value: unknown): JobKindListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data']) || !Array.isArray(value.data) ||
    value.data.length > 100 || !value.data.every((entry) => isRecord(entry) &&
      hasExactKeys(entry, ['kind', 'name_key', 'integration', 'runtime_status']) &&
      typeof entry.kind === 'string' && codePattern.test(entry.kind) &&
      Object.hasOwn(kindNameKeys, entry.kind) && entry.name_key === kindNameKeys[entry.kind] &&
      entry.integration === 'integrated' && entry.runtime_status === 'unknown') ||
    new Set(value.data.map((entry) => (entry as Record<string, unknown>).kind)).size !== value.data.length) {
    throw invalidResponse()
  }
  return value as unknown as JobKindListResponse
}

function isProgress(value: unknown): value is JobProgress {
  return isRecord(value) &&
    hasExactKeys(value, ['total', 'completed', 'succeeded', 'failed', 'cancelled', 'pending']) &&
    isInteger(value.total, 1) && isInteger(value.completed) && isInteger(value.succeeded) &&
    isInteger(value.failed) && isInteger(value.cancelled) && isInteger(value.pending)
}

function isJob(value: unknown): value is BackgroundJob {
  if (!isRecord(value) || !hasExactKeys(value, [
    'task_id', 'tenant_id', 'kind', 'related_resource', 'request_id', 'status', 'attempt',
		'max_attempts', 'progress', 'created_at', 'updated_at', 'revision',
  ], ['trace_id', 'failure_code', 'started_at', 'completed_at'])) return false
  if (!isRecord(value.related_resource) ||
    !hasExactKeys(value.related_resource, ['reference']) ||
    !isString(value.related_resource.reference, 1, 512)) return false
  if (!(isUUID(value.task_id) && isUUID(value.tenant_id) &&
    typeof value.kind === 'string' && codePattern.test(value.kind) &&
    isString(value.request_id, 1, 128) && jobStates.has(value.status as JobState) &&
    isInteger(value.attempt) && isInteger(value.max_attempts, 1, 1001) && isProgress(value.progress) &&
    typeof value.revision === 'string' && jobRevisionPattern.test(value.revision) &&
    isDateTime(value.created_at) && isDateTime(value.updated_at) &&
    (!('trace_id' in value) || isString(value.trace_id, 1, 512)) &&
    (!('failure_code' in value) || isOptionalCode(value.failure_code)) &&
    (!('started_at' in value) || isDateTime(value.started_at)) &&
    (!('completed_at' in value) || isDateTime(value.completed_at)))) return false

  const job = value as unknown as BackgroundJob
  const terminal = job.status !== 'queued' && job.status !== 'running'
  const failureCodeValid = job.status === 'cancelled'
    ? job.failure_code === 'cancelled'
    : job.status === 'partial_failed' || job.status === 'failed'
      ? job.failure_code !== undefined
      : job.failure_code === undefined
  return job.attempt <= job.max_attempts &&
    job.progress.completed === job.progress.succeeded + job.progress.failed + job.progress.cancelled &&
    job.progress.total === job.progress.completed + job.progress.pending &&
    Date.parse(job.updated_at) >= Date.parse(job.created_at) &&
    (job.started_at === undefined || Date.parse(job.started_at) >= Date.parse(job.created_at)) &&
    terminal === (job.completed_at !== undefined) &&
    (job.completed_at === undefined || Date.parse(job.completed_at) >= Date.parse(job.updated_at)) &&
    (job.status !== 'running' || job.attempt > 0) && failureCodeValid
}

function isAttempt(value: unknown): value is JobAttempt {
  return isRecord(value) &&
    hasExactKeys(value, [
      'number', 'status', 'started_at', 'last_heartbeat_at', 'lease_expires_at',
    ], ['completed_at', 'failure_code']) &&
    isInteger(value.number, 1) && attemptStates.has(value.status as JobAttemptState) &&
    isDateTime(value.started_at) && isDateTime(value.last_heartbeat_at) &&
    isDateTime(value.lease_expires_at) &&
    (!('completed_at' in value) || isDateTime(value.completed_at)) &&
    (!('failure_code' in value) || isOptionalCode(value.failure_code))
}

function isItemResult(value: unknown): value is JobItemResult {
  return isRecord(value) &&
    hasExactKeys(value, ['ordinal', 'item_id', 'status', 'attempt', 'sequence'], [
      'node_id', 'failure_code', 'completed_at', 'started_at', 'failure_count',
    ]) &&
    isInteger(value.ordinal, 1) && isString(value.item_id, 1, 256) &&
    resultStates.has(value.status as JobResultState) && isInteger(value.attempt) &&
    isInteger(value.sequence) && (!('node_id' in value) || isUUID(value.node_id)) &&
    (!('failure_code' in value) || isOptionalCode(value.failure_code)) &&
    (!('completed_at' in value) || isDateTime(value.completed_at)) &&
    (!('failure_count' in value) || isInteger(value.failure_count)) &&
    (!('started_at' in value) || (isDateTime(value.started_at) && value.status !== 'pending' &&
      (!('completed_at' in value) || Date.parse(value.started_at) <= Date.parse(String(value.completed_at)))))
}

function isSettlementReceipt(value: unknown): value is JobSettlementReceipt {
  return isRecord(value) && hasExactKeys(value, [
    'ordinal', 'item_id', 'status', 'attempt', 'sequence', 'source', 'reported_at',
  ], ['node_id', 'failure_code']) &&
    isInteger(value.ordinal, 1) && isString(value.item_id, 1, 256) &&
    (value.status === 'succeeded' || value.status === 'failed') && isInteger(value.attempt, 1) &&
    isInteger(value.sequence) && (value.status === 'succeeded'
      ? value.sequence > 0 && !('failure_code' in value)
      : value.sequence >= 0 && isOptionalCode(value.failure_code)) &&
    (value.status === 'failed' ? Boolean(value.failure_code) : true) &&
    (!('node_id' in value) || isUUID(value.node_id)) &&
    (value.source === 'worker' || value.source === 'system') && isDateTime(value.reported_at)
}

function isDeadLetter(value: unknown): value is JobDeadLetter {
  return isRecord(value) && hasExactKeys(value, [
    'attempt', 'reason_code', 'failed_item_count', 'source', 'created_at',
  ]) && isInteger(value.attempt, 1) && isOptionalCode(value.reason_code) &&
    isInteger(value.failed_item_count, 1) &&
    (value.source === 'worker' || value.source === 'lease_expiry') && isDateTime(value.created_at)
}

async function request(path: string, accessToken: string, init: RequestInit = {}): Promise<unknown> {
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
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

function parseList(value: unknown, params: AdminJobListParams): JobListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'page', 'query'], ['task_metadata']) ||
    !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isJob) ||
    !isRecord(value.query) ||
    !hasExactKeys(value.query, ['from', 'to']) ||
    !isDateTime(value.query.from) || !isDateTime(value.query.to)) throw invalidResponse()
  if (isNumberedPage(value.page)) {
    if (params.page === undefined || value.page.number !== params.page || value.page.limit !== params.limit ||
      value.data.length > value.page.limit || value.data.length > value.page.total ||
      !Array.isArray(value.task_metadata) || value.task_metadata.length !== value.data.length) throw invalidResponse()
    const metadata = new Map(value.task_metadata.map((item) => [isRecord(item) ? item.task_id : undefined, item]))
    if (metadata.size !== value.data.length ||
      !value.data.every((job) => isTaskMetadata(metadata.get(job.task_id), job))) throw invalidResponse()
  } else if (!isPage(value.page) || 'task_metadata' in value) {
    throw invalidResponse()
  }
  return value as unknown as JobListResponse
}

function parseDetail(value: unknown): JobDetailResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data']) || !isJob(value.data)) throw invalidResponse()
  return value as unknown as JobDetailResponse
}

function parseAttempts(value: unknown): JobAttemptListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'page']) ||
    !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isAttempt) ||
    !isPage(value.page)) throw invalidResponse()
  return value as unknown as JobAttemptListResponse
}

function parseResults(value: unknown): JobResultListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'page']) ||
    !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isItemResult) ||
    !isPage(value.page)) throw invalidResponse()
  return value as unknown as JobResultListResponse
}

function parseSettlementReceipts(value: unknown): JobSettlementReceiptListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'page']) ||
    !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isSettlementReceipt) ||
    !isPage(value.page)) throw invalidResponse()
  return value as unknown as JobSettlementReceiptListResponse
}

function parseDeadLetters(value: unknown): JobDeadLetterListResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'page']) ||
    !Array.isArray(value.data) || value.data.length > 100 || !value.data.every(isDeadLetter) ||
    !isPage(value.page)) throw invalidResponse()
  return value as unknown as JobDeadLetterListResponse
}

function parseCommand(
  value: unknown,
  action: JobCommand,
  taskID: string,
  expectedAttempt?: number,
): JobCommandResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'replayed']) ||
    !isJob(value.data) || typeof value.replayed !== 'boolean') throw invalidResponse()
  const response = value as unknown as JobCommandResponse
  if (response.data.task_id !== taskID ||
    (action === 'cancel' && response.data.status !== 'cancelled') ||
    (action === 'retry' && (
      expectedAttempt === undefined || response.data.status !== 'queued' ||
      response.data.attempt !== expectedAttempt
    ))) throw invalidResponse()
  return response
}

function basePath(audience: JobAudience): string {
  return audience === 'platform' ? '/v1/admin/jobs' : '/v1/jobs'
}

function list(
  accessToken: string,
  audience: JobAudience,
  params: AdminJobListParams,
): Promise<JobListResponse> {
  if (params.page !== undefined && (!isInteger(params.page, 1) || params.cursor !== undefined)) {
    return Promise.reject(new ApiError('Job pagination was invalid', 400, 'job_invalid_request'))
  }
  const query = new URLSearchParams({
    from: params.from,
    to: params.to,
    limit: String(params.limit),
  })
  if (params.taskID) query.set('task_id', params.taskID)
  if (params.statuses?.length) query.set('status', params.statuses.join(','))
  if (params.kind) query.set('kind', params.kind)
  if (params.resource) query.set('resource', params.resource)
  if (params.cursor) query.set('cursor', params.cursor)
  if (params.page !== undefined) query.set('page', String(params.page))
  return request(`${basePath(audience)}?${query}`, accessToken).then((value) => parseList(value, params))
}

function kinds(accessToken: string, audience: JobAudience): Promise<JobKindListResponse> {
  return request(`${basePath(audience)}/kinds`, accessToken).then(parseKinds)
}

function detail(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
): Promise<JobDetailResponse> {
  return request(`${basePath(audience)}/${encodeURIComponent(taskID)}`, accessToken).then(parseDetail)
}

function attempts(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  limit: number,
  cursor?: string,
): Promise<JobAttemptListResponse> {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor) query.set('cursor', cursor)
  return request(
    `${basePath(audience)}/${encodeURIComponent(taskID)}/attempts?${query}`,
    accessToken,
  ).then(parseAttempts)
}

function results(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  limit: number,
  cursor?: string,
): Promise<JobResultListResponse> {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor) query.set('cursor', cursor)
  return request(
    `${basePath(audience)}/${encodeURIComponent(taskID)}/results?${query}`,
    accessToken,
  ).then(parseResults)
}

function receipts(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  limit: number,
  cursor?: string,
): Promise<JobSettlementReceiptListResponse> {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor) query.set('cursor', cursor)
  return request(
    `${basePath(audience)}/${encodeURIComponent(taskID)}/receipts?${query}`,
    accessToken,
  ).then(parseSettlementReceipts)
}

function deadLetters(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  limit: number,
  cursor?: string,
): Promise<JobDeadLetterListResponse> {
  const query = new URLSearchParams({ limit: String(limit) })
  if (cursor) query.set('cursor', cursor)
  return request(
    `${basePath(audience)}/${encodeURIComponent(taskID)}/dead-letters?${query}`,
    accessToken,
  ).then(parseDeadLetters)
}

function command(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  action: JobCommand,
  idempotencyKey: string,
	expectedRevision: string,
  expectedAttempt?: number,
): Promise<JobCommandResponse> {
  return request(`${basePath(audience)}/${encodeURIComponent(taskID)}/${action}`, accessToken, {
    method: 'POST',
	headers: {
		'Idempotency-Key': idempotencyKey,
		'If-Match': `"${expectedRevision}"`,
	},
    body: '{}',
  }).then((value) => parseCommand(value, action, taskID, expectedAttempt))
}

function cancel(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  idempotencyKey: string,
	expectedRevision: string,
): Promise<JobCommandResponse> {
	return command(accessToken, audience, taskID, 'cancel', idempotencyKey, expectedRevision)
}

function retry(
  accessToken: string,
  audience: JobAudience,
  taskID: string,
  idempotencyKey: string,
  expectedAttempt: number,
	expectedRevision: string,
): Promise<JobCommandResponse> {
	return command(accessToken, audience, taskID, 'retry', idempotencyKey, expectedRevision, expectedAttempt)
}

export const jobsApi = { attempts, cancel, deadLetters, detail, kinds, list, receipts, results, retry }
