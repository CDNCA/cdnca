import { ApiError, networkApiError, responseApiError } from './auth'

export type IdentityVerificationReviewDecision = 'approved' | 'rejected'
export type IdentityVerificationReviewReason =
  | 'evidence_verified'
  | 'identity_mismatch'
  | 'evidence_incomplete'
  | 'evidence_unreadable'
  | 'organization_mismatch'
  | 'authorization_invalid'
  | 'suspected_fraud'

export interface IdentityVerificationReviewCase {
  id: string
  applicant_user_id: string
  kind: 'personal_initial' | 'personal_reverification' | 'enterprise'
  status: 'draft' | 'submitted' | 'reviewing' | 'approved' | 'rejected' | 'withdrawn' | 'expired'
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
  materials: Array<{
    id: string
    kind: 'identity_document' | 'liveness_evidence' | 'business_license' |
      'legal_person_identity' | 'agent_identity' | 'authorization_letter' | 'supplementary'
    encrypted_envelope_present: boolean
    mime_type: 'image/jpeg' | 'image/png' | 'application/pdf'
    size_bytes: number
    created_at: string
  }>
  replayed: boolean
}

export interface IdentityVerificationReviewDecisionInput {
  decision: IdentityVerificationReviewDecision
  reason_code: IdentityVerificationReviewReason
}

export interface IdentityVerificationReviewDecisionMetadata {
  requestId: string
  idempotencyKey: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/
const kinds = new Set(['personal_initial', 'personal_reverification', 'enterprise'])
const statuses = new Set(['draft', 'submitted', 'reviewing', 'approved', 'rejected', 'withdrawn', 'expired'])
const relationships = new Set(['legal_person', 'employee', 'authorized_representative'])
const materialKinds = new Set([
  'identity_document', 'liveness_evidence', 'business_license', 'legal_person_identity',
  'agent_identity', 'authorization_letter', 'supplementary',
])
const mimeTypes = new Set(['image/jpeg', 'image/png', 'application/pdf'])
const retentionReasons = new Set([
  'case_not_terminal', 'retention_period_active', 'eligible_for_evidence_erasure',
])
const rejectionReasons = new Set<IdentityVerificationReviewReason>([
  'identity_mismatch', 'evidence_incomplete', 'evidence_unreadable',
  'organization_mismatch', 'authorization_invalid', 'suspected_fraud',
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
    calendar.getUTCMonth() === Number(month) - 1 &&
    calendar.getUTCDate() === Number(day) &&
    Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 14 && Number(offsetMinute ?? 0) <= 59 &&
    !(Number(offsetHour ?? 0) === 14 && Number(offsetMinute ?? 0) !== 0) &&
    Number.isFinite(Date.parse(value))
}

function isMaterial(value: unknown): value is IdentityVerificationReviewCase['materials'][number] {
  return isRecord(value) && exactKeys(value, [
    'id', 'kind', 'encrypted_envelope_present', 'mime_type', 'size_bytes', 'created_at',
  ]) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.kind === 'string' && materialKinds.has(value.kind) &&
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
    typeof value.kind === 'string' && kinds.has(value.kind) &&
    typeof value.status === 'string' && statuses.has(value.status) &&
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

function validMetadata(value: IdentityVerificationReviewDecisionMetadata): boolean {
  return isRecord(value) && exactKeys(value, ['requestId', 'idempotencyKey']) &&
    typeof value.requestId === 'string' && metadataPattern.test(value.requestId) &&
    typeof value.idempotencyKey === 'string' && metadataPattern.test(value.idempotencyKey)
}

function validDecision(value: IdentityVerificationReviewDecisionInput): boolean {
  if (!isRecord(value) || !exactKeys(value, ['decision', 'reason_code'])) return false
  return value.decision === 'approved'
    ? value.reason_code === 'evidence_verified'
    : value.decision === 'rejected' && rejectionReasons.has(value.reason_code)
}

function randomSuffix(): string {
  if (!globalThis.crypto?.getRandomValues) throw invalidRequest()
  if (globalThis.crypto.randomUUID) return globalThis.crypto.randomUUID()
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  if (bytes.every((value) => value === 0)) bytes[bytes.length - 1] = 1
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')
}

export function createIdentityVerificationReviewDecisionMetadata(): IdentityVerificationReviewDecisionMetadata {
  return {
    requestId: `identity-review-${randomSuffix()}`,
    idempotencyKey: `identity-review-${randomSuffix()}`,
  }
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
  if (!response.ok) throw await responseApiError(response)
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

export const identityVerificationReviewDecisionApi = {
  getCase(accessToken: string, caseID: string, signal?: AbortSignal) {
    if (!uuidPattern.test(caseID)) return Promise.reject(invalidRequest())
    return sendCase(
      accessToken,
      `/v1/identity-verification/reviewer/cases/${caseID}`,
      { method: 'GET', signal },
      caseID,
    )
  },
  decide(
    accessToken: string,
    caseID: string,
    revision: number,
    input: IdentityVerificationReviewDecisionInput,
    metadata: IdentityVerificationReviewDecisionMetadata,
  ) {
    if (!uuidPattern.test(caseID) || !isInteger(revision, 1) ||
      !validDecision(input) || !validMetadata(metadata)) {
      return Promise.reject(invalidRequest())
    }
    return sendCase(
      accessToken,
      `/v1/identity-verification/reviewer/cases/${caseID}/decision`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'If-Match': `"${revision}"`,
          'Idempotency-Key': metadata.idempotencyKey,
          'X-Request-ID': metadata.requestId,
        },
        body: JSON.stringify(input),
      },
      caseID,
    )
  },
}
