import { ApiError, networkApiError } from './auth'
import type {
  IdentityVerificationCase,
  IdentityVerificationMaterial,
  IdentityVerificationMaterialKind,
  IdentityVerificationKind,
  IdentityVerificationStatus,
} from './identityVerification'

export type IdentityVerificationReviewCase = IdentityVerificationCase
export type IdentityVerificationReviewMaterial = IdentityVerificationMaterial
export interface IdentityVerificationReviewWriteMetadata {
  requestId: string
  idempotencyKey: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
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
const retentionReasons = new Set([
  'case_not_terminal', 'retention_period_active', 'eligible_for_evidence_erasure',
])
const errorCodesByStatus = new Map<number, ReadonlySet<string>>([
  [400, new Set(['identity_verification_invalid_request'])],
  [401, new Set(['identity_verification_unauthenticated'])],
  [403, new Set([
    'identity_verification_permission_denied', 'identity_verification_self_review_forbidden',
    'identity_verification_review_assignment_required',
  ])],
  [404, new Set(['identity_verification_not_found'])],
  [405, new Set(['identity_verification_method_not_allowed'])],
  [408, new Set(['identity_verification_request_canceled'])],
  [409, new Set([
    'identity_verification_revision_conflict', 'identity_verification_idempotency_conflict',
    'identity_verification_active_review', 'identity_verification_invalid_transition',
    'identity_verification_initial_approval_required', 'identity_verification_already_verified',
    'identity_verification_case_expired', 'identity_verification_case_not_expired',
    'identity_verification_evidence_settlement_pending',
  ])],
  [422, new Set([
    'identity_verification_identity_mismatch', 'identity_verification_evidence_invalid',
  ])],
  [503, new Set([
    'identity_verification_trusted_resolver_required', 'identity_verification_evidence_unavailable',
    'identity_verification_response_too_large', 'identity_verification_unavailable',
  ])],
  [504, new Set(['identity_verification_request_timeout'])],
])

function invalidRequest(): ApiError {
  return new ApiError('Invalid identity verification review request', 400, 'invalid_request')
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid identity verification review response', 502, 'invalid_response')
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
    calendar.getUTCMonth() === Number(month) - 1 && calendar.getUTCDate() === Number(day) &&
    Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) &&
    Number.isFinite(Date.parse(value))
}

function isMaterial(value: unknown): value is IdentityVerificationReviewMaterial {
  return isRecord(value) && exactKeys(value, [
    'id', 'kind', 'encrypted_envelope_present', 'mime_type', 'size_bytes', 'created_at',
  ]) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.kind === 'string' && materialKinds.has(value.kind as IdentityVerificationMaterialKind) &&
    typeof value.encrypted_envelope_present === 'boolean' &&
    typeof value.mime_type === 'string' && mimeTypes.has(value.mime_type) &&
    isInteger(value.size_bytes, 1, 20 * 1024 * 1024) && isTimestamp(value.created_at)
}

function isRetention(value: unknown): value is IdentityVerificationReviewCase['retention'] {
  return isRecord(value) && exactKeys(value, ['eligible', 'eligible_at', 'reason_code']) &&
    typeof value.eligible === 'boolean' && isTimestamp(value.eligible_at) &&
    typeof value.reason_code === 'string' && retentionReasons.has(value.reason_code)
}

function isCase(value: unknown): value is IdentityVerificationReviewCase {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'applicant_user_id', 'kind', 'status', 'revision', 'created_at',
    'state_changed_at', 'retention', 'materials', 'replayed',
  ], [
    'agent_relationship', 'reviewer_user_id', 'submitted_at', 'expires_at', 'terminal_at',
  ])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.applicant_user_id === 'string' && uuidPattern.test(value.applicant_user_id) &&
    typeof value.kind === 'string' && kinds.has(value.kind as IdentityVerificationKind) &&
    typeof value.status === 'string' && statuses.has(value.status as IdentityVerificationStatus) &&
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

function validAccessToken(value: string): boolean {
  return value.length >= 1 && value.length <= 8192 && !/\s/.test(value)
}

function validMetadata(value: IdentityVerificationReviewWriteMetadata): boolean {
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

async function serviceError(response: Response): Promise<ApiError> {
  const allowedCodes = errorCodesByStatus.get(response.status)
  if (!allowedCodes || response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    return invalidResponse()
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return invalidResponse()
  }
  if (!isRecord(body) || !exactKeys(body, ['error']) || !isRecord(body.error) ||
    !exactKeys(body.error, ['code', 'message', 'request_id']) ||
    typeof body.error.code !== 'string' || !allowedCodes.has(body.error.code) ||
    typeof body.error.message !== 'string' || body.error.message.length > 1024 ||
    typeof body.error.request_id !== 'string' || !metadataPattern.test(body.error.request_id)) {
    return invalidResponse()
  }
  return new ApiError('API request failed', response.status, body.error.code, body.error.request_id)
}

async function sendCase(
  accessToken: string,
  path: string,
  init: RequestInit,
  expectedCaseID: string,
): Promise<IdentityVerificationReviewCase> {
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
  if (!response.ok) throw await serviceError(response)
  if (response.status !== 200 ||
    response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponse()
  }
  if (!isCase(value) || value.id !== expectedCaseID ||
    response.headers.get('ETag') !== `"${value.revision}"`) {
    throw invalidResponse()
  }
  return value
}

export function createIdentityVerificationReviewWriteMetadata(): IdentityVerificationReviewWriteMetadata {
  return {
    requestId: `identity-review-claim-${randomSuffix()}`,
    idempotencyKey: `identity-review-claim-${randomSuffix()}`,
  }
}

export const identityVerificationReviewCaseApi = {
  getCase(accessToken: string, caseID: string, signal?: AbortSignal) {
    if (!uuidPattern.test(caseID)) return Promise.reject(invalidRequest())
    return sendCase(
      accessToken,
      `/v1/identity-verification/reviewer/cases/${caseID}`,
      { method: 'GET', signal },
      caseID,
    )
  },
  claim(
    accessToken: string,
    caseID: string,
    revision: number,
    metadata: IdentityVerificationReviewWriteMetadata,
  ) {
    if (!uuidPattern.test(caseID) || !isInteger(revision, 1) || !validMetadata(metadata)) {
      return Promise.reject(invalidRequest())
    }
    return sendCase(
      accessToken,
      `/v1/identity-verification/reviewer/cases/${caseID}/claim`,
      {
        method: 'POST',
        headers: {
          'If-Match': `"${revision}"`,
          'Idempotency-Key': metadata.idempotencyKey,
          'X-Request-ID': metadata.requestId,
        },
      },
      caseID,
    )
  },
}
