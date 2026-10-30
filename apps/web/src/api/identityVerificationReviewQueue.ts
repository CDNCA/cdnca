import { ApiError, networkApiError } from './auth'

export type IdentityVerificationReviewKind =
  | 'personal_initial'
  | 'personal_reverification'
  | 'enterprise'

export type IdentityVerificationReviewStatus =
  | 'draft'
  | 'submitted'
  | 'reviewing'
  | 'approved'
  | 'rejected'
  | 'withdrawn'
  | 'expired'

export interface IdentityVerificationReviewCase {
  id: string
  applicant_user_id: string
  kind: IdentityVerificationReviewKind
  status: IdentityVerificationReviewStatus
  reviewer_user_id?: string
  revision: number
  created_at: string
  state_changed_at: string
  submitted_at?: string
  expires_at?: string
}

export interface IdentityVerificationReviewQueueResult {
  items: IdentityVerificationReviewCase[]
  next_cursor?: string
}

export interface IdentityVerificationReviewQueueParams {
  kind?: IdentityVerificationReviewKind
  status?: IdentityVerificationReviewStatus
  limit?: 20 | 50 | 100
  cursor?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/
const safeRequestIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const errorCodePattern = /^identity_verification_[a-z0-9_]+$/
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

function isKind(value: unknown): value is IdentityVerificationReviewKind {
  return value === 'personal_initial' || value === 'personal_reverification' || value === 'enterprise'
}

function isStatus(value: unknown): value is IdentityVerificationReviewStatus {
  return value === 'draft' || value === 'submitted' || value === 'reviewing' ||
    value === 'approved' || value === 'rejected' || value === 'withdrawn' || value === 'expired'
}

function isLimit(value: unknown): value is 20 | 50 | 100 {
  return value === 20 || value === 50 || value === 100
}

function isReviewCase(value: unknown): value is IdentityVerificationReviewCase {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'applicant_user_id', 'kind', 'status', 'revision', 'created_at', 'state_changed_at',
  ], ['reviewer_user_id', 'submitted_at', 'expires_at'])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.applicant_user_id === 'string' && uuidPattern.test(value.applicant_user_id) &&
    isKind(value.kind) && isStatus(value.status) &&
    (value.reviewer_user_id === undefined || (
      typeof value.reviewer_user_id === 'string' && uuidPattern.test(value.reviewer_user_id)
    )) &&
    typeof value.revision === 'number' && Number.isSafeInteger(value.revision) && value.revision >= 1 &&
    isTimestamp(value.created_at) && isTimestamp(value.state_changed_at) &&
    (value.submitted_at === undefined || isTimestamp(value.submitted_at)) &&
    (value.expires_at === undefined || isTimestamp(value.expires_at))
}

function isPage(value: unknown): value is IdentityVerificationReviewQueueResult {
  return isRecord(value) && exactKeys(value, ['items'], ['next_cursor']) &&
    Array.isArray(value.items) && value.items.length <= 100 && value.items.every(isReviewCase) &&
    (value.next_cursor === undefined || (
      typeof value.next_cursor === 'string' && value.next_cursor.length >= 1 && value.next_cursor.length <= 4096
    ))
}

function validationError(): ApiError {
  return new ApiError(
    'Invalid identity verification review queue request',
    400,
    'identity_verification_validation_error',
  )
}

function invalidResponse(): ApiError {
  return new ApiError(
    'Invalid identity verification review queue response',
    502,
    'identity_verification_invalid_response',
  )
}

function validAccessToken(value: string): boolean {
  return value.length >= 1 && value.length <= 8192 && !/\s/.test(value)
}

function validParams(value: IdentityVerificationReviewQueueParams): boolean {
  if (!isRecord(value) || !exactKeys(value, [], ['kind', 'status', 'limit', 'cursor'])) return false
  return (value.kind === undefined || isKind(value.kind)) &&
    (value.status === undefined || isStatus(value.status)) &&
    (value.limit === undefined || isLimit(value.limit)) &&
    (value.cursor === undefined || (
      typeof value.cursor === 'string' && value.cursor.length >= 1 && value.cursor.length <= 4096
    ))
}

async function responseError(response: Response): Promise<ApiError> {
  if (response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    return new ApiError('API request failed', response.status, 'request_failed')
  }
  const body: unknown = await response.json().catch(() => null)
  if (!isRecord(body) || !exactKeys(body, ['error']) || !isRecord(body.error) ||
    !exactKeys(body.error, ['code', 'message', 'request_id']) ||
    typeof body.error.code !== 'string' || !errorCodePattern.test(body.error.code) ||
    typeof body.error.message !== 'string' ||
    typeof body.error.request_id !== 'string' || !safeRequestIDPattern.test(body.error.request_id)) {
    return new ApiError('API request failed', response.status, 'request_failed')
  }
  return new ApiError('API request failed', response.status, body.error.code, body.error.request_id)
}

export const identityVerificationReviewQueueApi = {
  async list(
    accessToken: string,
    params: IdentityVerificationReviewQueueParams = {},
  ): Promise<IdentityVerificationReviewQueueResult> {
    if (!validAccessToken(accessToken) || !validParams(params)) throw validationError()
    const query = new URLSearchParams()
    if (params.kind) query.set('kind', params.kind)
    if (params.status) query.set('status', params.status)
    if (params.limit !== undefined) query.set('limit', String(params.limit))
    if (params.cursor) query.set('cursor', params.cursor)
    const suffix = query.size > 0 ? `?${query.toString()}` : ''

    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/identity-verification/reviewer/cases${suffix}`, {
        credentials: 'include',
        headers: { Authorization: `Bearer ${accessToken}` },
      })
    } catch {
      throw networkApiError()
    }
    if (!response.ok) throw await responseError(response)
    if (response.status !== 200 ||
      response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
      throw invalidResponse()
    }
    const body: unknown = await response.json().catch(() => null)
    if (!isPage(body)) throw invalidResponse()
    return body
  },
}
