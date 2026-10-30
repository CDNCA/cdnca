import { ApiError, networkApiError, responseApiError } from './auth'

export type IdentityVerificationKind = 'personal_initial' | 'personal_reverification' | 'enterprise'
export type IdentityVerificationStatus =
  | 'draft'
  | 'submitted'
  | 'reviewing'
  | 'approved'
  | 'rejected'
  | 'withdrawn'
  | 'expired'

export type IdentityVerificationDecisionReasonCode =
  | 'evidence_verified'
  | 'identity_mismatch'
  | 'evidence_incomplete'
  | 'evidence_unreadable'
  | 'organization_mismatch'
  | 'authorization_invalid'
  | 'suspected_fraud'

export type IdentityVerificationMaterialKind =
  | 'identity_document'
  | 'liveness_evidence'
  | 'business_license'
  | 'legal_person_identity'
  | 'agent_identity'
  | 'authorization_letter'
  | 'supplementary'

export interface IdentityVerificationMaterial {
  id: string
  kind: IdentityVerificationMaterialKind
  encrypted_envelope_present: boolean
  mime_type: 'image/jpeg' | 'image/png' | 'application/pdf'
  size_bytes: number
  created_at: string
}

export interface IdentityVerificationCase {
  id: string
  applicant_user_id: string
  kind: IdentityVerificationKind
  status: IdentityVerificationStatus
  decision_reason_code?: IdentityVerificationDecisionReasonCode
  agent_relationship?: 'legal_person' | 'employee' | 'authorized_representative'
  reviewer_user_id?: string
  revision: number
  created_at: string
  state_changed_at: string
  submitted_at?: string
  expires_at?: string
  terminal_at?: string
  retention: {
    eligible: boolean
    eligible_at: string
    reason_code: 'case_not_terminal' | 'retention_period_active' | 'eligible_for_evidence_erasure'
  }
  materials: IdentityVerificationMaterial[]
  replayed: boolean
}

export type IdentityVerificationSelfStatusValue = 'unverified' | 'pending' | 'verified' | 'rejected'

// GET /v1/identity-verification/status：本人的实名状态，只含非敏感字段。
export interface IdentityVerificationSelfStatus {
  status: IdentityVerificationSelfStatusValue
  verified_at?: string
  latest_case?: {
    id: string
    kind: IdentityVerificationKind
    status: IdentityVerificationStatus
    decision_reason_code?: IdentityVerificationDecisionReasonCode
    revision: number
    created_at: string
    state_changed_at: string
    submitted_at?: string
  }
}

export interface IdentityVerificationCreateInput {
  kind: IdentityVerificationKind
  evidence_token: string
}

export type IdentityVerificationProviderState =
  | 'creating'
  | 'pending'
  | 'processing'
  | 'succeeded'
  | 'failed'
  | 'canceled'
  | 'expired'
  | 'unknown'

export interface IdentityVerificationProviderSession {
  id: string
  kind: IdentityVerificationKind
  provider: string
  state: IdentityVerificationProviderState
  revision: number
  evidence_token?: string
  expires_at: string
  updated_at: string
  replayed: boolean
}

export type IdentityVerificationProviderUploadState =
  | 'issued'
  | 'finalized'
  | 'erase_pending'
  | 'erased'

export type IdentityVerificationProviderContentType =
  | 'image/jpeg'
  | 'image/png'
  | 'application/pdf'
  | 'video/mp4'

export interface IdentityVerificationProviderUploadInput {
  material_kind: IdentityVerificationMaterialKind
  content_type: IdentityVerificationProviderContentType
  size_bytes: number
  sha256: string
}

export interface IdentityVerificationProviderUpload {
  id: string
  session_id: string
  material_kind: IdentityVerificationMaterialKind
  state: IdentityVerificationProviderUploadState
  revision: number
  upload_url?: string
  required_headers?: Record<string, string>
  expires_at: string
  replayed: boolean
}

export interface IdentityVerificationWriteMetadata {
  requestId: string
  idempotencyKey: string
}

type WriteAction =
  | 'create'
  | 'submit'
  | 'withdraw'
  | 'expire'
  | 'provider-session'
  | 'provider-upload'
  | 'provider-finalize'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const evidencePattern = /^[A-Za-z0-9][A-Za-z0-9._~-]{31,511}$/
const providerPattern = /^[a-z][a-z0-9._-]{0,63}$/
const sha256Pattern = /^[a-f0-9]{64}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/
const kinds = new Set<IdentityVerificationKind>([
  'personal_initial', 'personal_reverification', 'enterprise',
])
const statuses = new Set<IdentityVerificationStatus>([
  'draft', 'submitted', 'reviewing', 'approved', 'rejected', 'withdrawn', 'expired',
])
const materialKinds = new Set<IdentityVerificationMaterialKind>([
  'identity_document', 'liveness_evidence', 'business_license', 'legal_person_identity',
  'agent_identity', 'authorization_letter', 'supplementary',
])
const relationships = new Set(['legal_person', 'employee', 'authorized_representative'])
const mimeTypes = new Set(['image/jpeg', 'image/png', 'application/pdf'])
const providerMimeTypes = new Set<IdentityVerificationProviderContentType>([
  'image/jpeg', 'image/png', 'application/pdf', 'video/mp4',
])
const providerStates = new Set<IdentityVerificationProviderState>([
  'creating', 'pending', 'processing', 'succeeded', 'failed', 'canceled', 'expired', 'unknown',
])
const providerUploadStates = new Set<IdentityVerificationProviderUploadState>([
  'issued', 'finalized', 'erase_pending', 'erased',
])
const forbiddenUploadHeaders = new Set([
  'authorization', 'cookie', 'proxy-authorization', 'set-cookie',
])
const retentionReasons = new Set([
  'case_not_terminal', 'retention_period_active', 'eligible_for_evidence_erasure',
])
const rejectionReasons = new Set<IdentityVerificationDecisionReasonCode>([
  'identity_mismatch', 'evidence_incomplete', 'evidence_unreadable',
  'organization_mismatch', 'authorization_invalid', 'suspected_fraud',
])

function invalidRequest(): ApiError {
  return new ApiError('Invalid identity verification request', 400, 'invalid_request')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid identity verification response', 502, 'invalid_response')
}

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

function isInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false
  const match = timestampPattern.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)))
  return calendar.getUTCFullYear() === Number(year) &&
    calendar.getUTCMonth() === Number(month) - 1 &&
    calendar.getUTCDate() === Number(day) &&
    Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) &&
    Number.isFinite(Date.parse(value))
}

function isMaterial(value: unknown): value is IdentityVerificationMaterial {
  return isRecord(value) && exactKeys(value, [
    'id', 'kind', 'encrypted_envelope_present', 'mime_type', 'size_bytes', 'created_at',
  ]) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.kind === 'string' && materialKinds.has(value.kind as IdentityVerificationMaterialKind) &&
    typeof value.encrypted_envelope_present === 'boolean' &&
    typeof value.mime_type === 'string' && mimeTypes.has(value.mime_type) &&
    isInteger(value.size_bytes, 1, 20 * 1024 * 1024) && isTimestamp(value.created_at)
}

function isRetention(value: unknown): value is IdentityVerificationCase['retention'] {
  return isRecord(value) && exactKeys(value, ['eligible', 'eligible_at', 'reason_code']) &&
    typeof value.eligible === 'boolean' && isTimestamp(value.eligible_at) &&
    typeof value.reason_code === 'string' && retentionReasons.has(value.reason_code)
}

function isDecisionReason(status: IdentityVerificationStatus, value: unknown): boolean {
  if (status === 'approved') return value === 'evidence_verified'
  if (status === 'rejected') {
    return typeof value === 'string' && rejectionReasons.has(value as IdentityVerificationDecisionReasonCode)
  }
  return value === undefined
}

function isCase(value: unknown): value is IdentityVerificationCase {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'applicant_user_id', 'kind', 'status', 'revision', 'created_at',
    'state_changed_at', 'retention', 'materials', 'replayed',
  ], [
    'decision_reason_code', 'agent_relationship', 'reviewer_user_id', 'submitted_at', 'expires_at', 'terminal_at',
  ])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.applicant_user_id === 'string' && uuidPattern.test(value.applicant_user_id) &&
    typeof value.kind === 'string' && kinds.has(value.kind as IdentityVerificationKind) &&
    typeof value.status === 'string' && statuses.has(value.status as IdentityVerificationStatus) &&
    isDecisionReason(value.status as IdentityVerificationStatus, value.decision_reason_code) &&
    (value.agent_relationship === undefined || (
      typeof value.agent_relationship === 'string' && relationships.has(value.agent_relationship)
    )) &&
    (value.reviewer_user_id === undefined || (
      typeof value.reviewer_user_id === 'string' && uuidPattern.test(value.reviewer_user_id)
    )) &&
    isInteger(value.revision, 1) && isTimestamp(value.created_at) &&
    isTimestamp(value.state_changed_at) &&
    (value.submitted_at === undefined || isTimestamp(value.submitted_at)) &&
    (value.expires_at === undefined || isTimestamp(value.expires_at)) &&
    (value.terminal_at === undefined || isTimestamp(value.terminal_at)) &&
    isRetention(value.retention) && Array.isArray(value.materials) &&
    value.materials.length <= 16 && value.materials.every(isMaterial) &&
    typeof value.replayed === 'boolean'
}

const selfStatuses = new Set<IdentityVerificationSelfStatusValue>(['unverified', 'pending', 'verified', 'rejected'])

function isStatusCase(value: unknown): value is NonNullable<IdentityVerificationSelfStatus['latest_case']> {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'kind', 'status', 'revision', 'created_at', 'state_changed_at',
  ], ['decision_reason_code', 'submitted_at'])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.kind === 'string' && kinds.has(value.kind as IdentityVerificationKind) &&
    typeof value.status === 'string' && statuses.has(value.status as IdentityVerificationStatus) &&
    isDecisionReason(value.status as IdentityVerificationStatus, value.decision_reason_code) &&
    isInteger(value.revision, 1) && isTimestamp(value.created_at) && isTimestamp(value.state_changed_at) &&
    (value.submitted_at === undefined || isTimestamp(value.submitted_at))
}

// 徽章状态必须与最新案件、已认证事实一致，否则视为无效响应而不是猜一个状态。
function isSelfStatus(value: unknown): value is IdentityVerificationSelfStatus {
  if (!isRecord(value) || !exactKeys(value, ['status'], ['verified_at', 'latest_case'])) return false
  if (typeof value.status !== 'string' || !selfStatuses.has(value.status as IdentityVerificationSelfStatusValue)) {
    return false
  }
  if (value.latest_case !== undefined && !isStatusCase(value.latest_case)) return false
  const latest = value.latest_case as IdentityVerificationSelfStatus['latest_case']
  if (value.status === 'verified') return isTimestamp(value.verified_at)
  if (value.verified_at !== undefined) return false
  if (value.status === 'pending') return latest?.status === 'submitted' || latest?.status === 'reviewing'
  if (value.status === 'rejected') return latest?.status === 'rejected'
  return latest === undefined || ['draft', 'withdrawn', 'expired'].includes(latest.status)
}

function isProviderSession(value: unknown): value is IdentityVerificationProviderSession {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'kind', 'provider', 'state', 'revision', 'expires_at', 'updated_at', 'replayed',
  ], ['evidence_token'])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.kind === 'string' && kinds.has(value.kind as IdentityVerificationKind) &&
    typeof value.provider === 'string' && providerPattern.test(value.provider) &&
    typeof value.state === 'string' && providerStates.has(value.state as IdentityVerificationProviderState) &&
    isInteger(value.revision, 1) &&
    (value.evidence_token === undefined || (
      value.state === 'succeeded' && typeof value.evidence_token === 'string' && evidencePattern.test(value.evidence_token)
    )) &&
    isTimestamp(value.expires_at) && isTimestamp(value.updated_at) &&
    typeof value.replayed === 'boolean'
}

function validUploadHeaders(value: unknown): value is Record<string, string> {
  if (!isRecord(value) || Object.keys(value).length === 0 || Object.keys(value).length > 32) return false
  return Object.entries(value).every(([name, headerValue]) => (
    name.length > 0 && name.length <= 128 && !forbiddenUploadHeaders.has(name.toLowerCase()) &&
    typeof headerValue === 'string' && headerValue.length <= 4096 && !/[\r\n]/.test(headerValue)
  ))
}

function safeUploadURL(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 4096) return false
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' && !parsed.username && !parsed.password
  } catch {
    return false
  }
}

function isProviderUpload(
  value: unknown,
  expectedSessionID: string,
  expectedUploadID?: string,
): value is IdentityVerificationProviderUpload {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'session_id', 'material_kind', 'state', 'revision', 'expires_at', 'replayed',
  ], ['upload_url', 'required_headers'])) return false
  const issued = value.state === 'issued'
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    (expectedUploadID === undefined || value.id === expectedUploadID) &&
    value.session_id === expectedSessionID &&
    typeof value.material_kind === 'string' &&
    materialKinds.has(value.material_kind as IdentityVerificationMaterialKind) &&
    typeof value.state === 'string' &&
    providerUploadStates.has(value.state as IdentityVerificationProviderUploadState) &&
    isInteger(value.revision, 1) &&
    (issued
      ? safeUploadURL(value.upload_url) && validUploadHeaders(value.required_headers)
      : value.upload_url === undefined && value.required_headers === undefined) &&
    isTimestamp(value.expires_at) && typeof value.replayed === 'boolean'
}

function validAccessToken(value: string): boolean {
  return value.length >= 1 && value.length <= 8192 && !/[\s]/.test(value)
}

function validMetadata(value: IdentityVerificationWriteMetadata): boolean {
  return isRecord(value) && exactKeys(value, ['requestId', 'idempotencyKey']) &&
    typeof value.requestId === 'string' && metadataPattern.test(value.requestId) &&
    typeof value.idempotencyKey === 'string' && metadataPattern.test(value.idempotencyKey)
}

function randomSuffix(): string {
  if (!globalThis.crypto?.getRandomValues) throw invalidRequest()
  if (globalThis.crypto.randomUUID) return globalThis.crypto.randomUUID()
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  if (bytes.every((value) => value === 0)) bytes[bytes.length - 1] = 1
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')
}

export function createIdentityVerificationWriteMetadata(
  action: WriteAction,
): IdentityVerificationWriteMetadata {
  if (![
    'create', 'submit', 'withdraw', 'expire',
    'provider-session', 'provider-upload', 'provider-finalize',
  ].includes(action)) throw invalidRequest()
  return {
    requestId: `identity-${action}-${randomSuffix()}`,
    idempotencyKey: `identity-${action}-${randomSuffix()}`,
  }
}

async function sendProvider<T>(
  accessToken: string,
  path: string,
  init: RequestInit,
  validate: (value: unknown) => value is T,
): Promise<T> {
  if (!validAccessToken(accessToken)) throw invalidRequest()
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
  if (![200, 201].includes(response.status) ||
    response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponse()
  }
  if (!validate(value)) throw invalidResponse()
  return value
}

function validProviderUploadInput(value: unknown): value is IdentityVerificationProviderUploadInput {
  return isRecord(value) && exactKeys(value, [
    'material_kind', 'content_type', 'size_bytes', 'sha256',
  ]) && typeof value.material_kind === 'string' &&
    materialKinds.has(value.material_kind as IdentityVerificationMaterialKind) &&
    typeof value.content_type === 'string' &&
    providerMimeTypes.has(value.content_type as IdentityVerificationProviderContentType) &&
    isInteger(value.size_bytes, 1, 20 * 1024 * 1024) &&
    typeof value.sha256 === 'string' && sha256Pattern.test(value.sha256)
}

async function fileBytes(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(invalidRequest())
    reader.onload = () => reader.result instanceof ArrayBuffer ? resolve(reader.result) : reject(invalidRequest())
    reader.readAsArrayBuffer(file)
  })
}

async function sha256File(file: File): Promise<string> {
  if (!globalThis.crypto?.subtle) throw invalidRequest()
  const digest = await globalThis.crypto.subtle.digest('SHA-256', await fileBytes(file))
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, '0')).join('')
}

async function sendCase(
  accessToken: string,
  path: string,
  init: RequestInit,
  expectedStatuses: readonly number[],
  expectedCaseID?: string,
): Promise<IdentityVerificationCase> {
  if (!validAccessToken(accessToken)) throw invalidRequest()
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
  if (!expectedStatuses.includes(response.status) ||
    response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponse()
  }
  if (!isCase(value) || (expectedCaseID !== undefined && value.id !== expectedCaseID) ||
    response.headers.get('ETag') !== `"${value.revision}"`) {
    throw invalidResponse()
  }
  return value
}

function writeHeaders(
  metadata: IdentityVerificationWriteMetadata,
  revision?: number,
): HeadersInit {
  if (!validMetadata(metadata) || (revision !== undefined && !isInteger(revision, 1))) {
    throw invalidRequest()
  }
  return {
    'Idempotency-Key': metadata.idempotencyKey,
    'X-Request-ID': metadata.requestId,
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

function transition(
  action: Exclude<WriteAction, 'create'>,
  accessToken: string,
  caseID: string,
  revision: number,
  metadata: IdentityVerificationWriteMetadata,
): Promise<IdentityVerificationCase> {
  if (!uuidPattern.test(caseID)) throw invalidRequest()
  return sendCase(
    accessToken,
    `/v1/identity-verification/cases/${caseID}/${action}`,
    { method: 'POST', headers: writeHeaders(metadata, revision) },
    [200],
    caseID,
  )
}

export const identityVerificationApi = {
  getStatus(accessToken: string, signal?: AbortSignal) {
    return sendProvider(
      accessToken,
      '/v1/identity-verification/status',
      { method: 'GET', signal },
      isSelfStatus,
    )
  },
  startProviderSession(
    accessToken: string,
    input: { kind: IdentityVerificationKind; provider: string },
    metadata: IdentityVerificationWriteMetadata,
  ) {
    if (!isRecord(input) || !exactKeys(input, ['kind', 'provider']) ||
      typeof input.kind !== 'string' || !kinds.has(input.kind as IdentityVerificationKind) ||
      typeof input.provider !== 'string' || !providerPattern.test(input.provider)) {
      return Promise.reject(invalidRequest())
    }
    let headers: HeadersInit
    try {
      headers = { ...writeHeaders(metadata), 'Content-Type': 'application/json' }
    } catch (error) {
      return Promise.reject(error)
    }
    return sendProvider(
      accessToken,
      '/v1/identity-verification/provider-sessions',
      { method: 'POST', headers, body: JSON.stringify(input) },
      isProviderSession,
    )
  },
  createProviderUpload(
    accessToken: string,
    sessionID: string,
    input: IdentityVerificationProviderUploadInput,
    metadata: IdentityVerificationWriteMetadata,
  ) {
    if (!uuidPattern.test(sessionID) || !validProviderUploadInput(input)) {
      return Promise.reject(invalidRequest())
    }
    let headers: HeadersInit
    try {
      headers = { ...writeHeaders(metadata), 'Content-Type': 'application/json' }
    } catch (error) {
      return Promise.reject(error)
    }
    return sendProvider(
      accessToken,
      `/v1/identity-verification/provider-sessions/${sessionID}/uploads`,
      { method: 'POST', headers, body: JSON.stringify(input) },
      (value): value is IdentityVerificationProviderUpload =>
        isProviderUpload(value, sessionID) && value.material_kind === input.material_kind,
    )
  },
  async putProviderUpload(
    upload: IdentityVerificationProviderUpload,
    input: IdentityVerificationProviderUploadInput,
    file: File,
  ): Promise<void> {
    if (!isProviderUpload(upload, upload.session_id, upload.id) || upload.state !== 'issued' ||
      !validProviderUploadInput(input) || !(file instanceof File) ||
      upload.material_kind !== input.material_kind ||
      file.size !== input.size_bytes || file.type !== input.content_type ||
      await sha256File(file) !== input.sha256) {
      throw invalidRequest()
    }
    let response: Response
    try {
      response = await fetch(upload.upload_url!, {
        method: 'PUT',
        credentials: 'omit',
        redirect: 'error',
        headers: upload.required_headers!,
        body: file,
      })
    } catch {
      throw networkApiError()
    }
    if (!response.ok || ![200, 201, 204].includes(response.status)) throw invalidResponse()
  },
  finalizeProviderUpload(
    accessToken: string,
    sessionID: string,
    uploadID: string,
    revision: number,
    metadata: IdentityVerificationWriteMetadata,
  ) {
    if (!uuidPattern.test(sessionID) || !uuidPattern.test(uploadID)) {
      return Promise.reject(invalidRequest())
    }
    let headers: HeadersInit
    try {
      headers = writeHeaders(metadata, revision)
    } catch (error) {
      return Promise.reject(error)
    }
    return sendProvider(
      accessToken,
      `/v1/identity-verification/provider-sessions/${sessionID}/uploads/${uploadID}/finalize`,
      { method: 'POST', headers },
      (value): value is IdentityVerificationProviderUpload => isProviderUpload(value, sessionID, uploadID),
    )
  },
  getCase(accessToken: string, caseID: string, signal?: AbortSignal) {
    if (!uuidPattern.test(caseID)) return Promise.reject(invalidRequest())
    return sendCase(
      accessToken,
      `/v1/identity-verification/cases/${caseID}`,
      { method: 'GET', signal },
      [200],
      caseID,
    )
  },
  createDraft(
    accessToken: string,
    input: IdentityVerificationCreateInput,
    metadata: IdentityVerificationWriteMetadata,
  ) {
    if (!isRecord(input) || !exactKeys(input, ['kind', 'evidence_token']) ||
      typeof input.kind !== 'string' || !kinds.has(input.kind as IdentityVerificationKind) ||
      typeof input.evidence_token !== 'string' || !evidencePattern.test(input.evidence_token)) {
      return Promise.reject(invalidRequest())
    }
    let headers: HeadersInit
    try {
      headers = { ...writeHeaders(metadata), 'Content-Type': 'application/json' }
    } catch (error) {
      return Promise.reject(error)
    }
    return sendCase(
      accessToken,
      '/v1/identity-verification/cases',
      { method: 'POST', headers, body: JSON.stringify(input) },
      [200, 201],
    )
  },
  submit(
    accessToken: string,
    caseID: string,
    revision: number,
    metadata: IdentityVerificationWriteMetadata,
  ) {
    try {
      return transition('submit', accessToken, caseID, revision, metadata)
    } catch (error) {
      return Promise.reject(error)
    }
  },
  withdraw(
    accessToken: string,
    caseID: string,
    revision: number,
    metadata: IdentityVerificationWriteMetadata,
  ) {
    try {
      return transition('withdraw', accessToken, caseID, revision, metadata)
    } catch (error) {
      return Promise.reject(error)
    }
  },
  expire(
    accessToken: string,
    caseID: string,
    revision: number,
    metadata: IdentityVerificationWriteMetadata,
  ) {
    try {
      return transition('expire', accessToken, caseID, revision, metadata)
    } catch (error) {
      return Promise.reject(error)
    }
  },
}
