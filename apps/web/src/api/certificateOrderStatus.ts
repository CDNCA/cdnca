import { ApiError, networkApiError, responseApiError } from './auth'

export type CertificateOrderChallenge = 'http-01' | 'dns-01'
export type CertificateOrderLifecycle =
  | 'pending'
  | 'validating'
  | 'issuing'
  | 'issued'
  | 'deploying'
  | 'active'
  | 'renewal_due'
  | 'failed'
  | 'revoked'

export interface CertificateOrderStatusItem {
  id: string
  scope_id: string
  dns_provider_id?: string
  domains: string[]
  challenge_type: CertificateOrderChallenge
  status: CertificateOrderLifecycle
  auto_renew: boolean
  renewal_of_order_id?: string
  not_after?: string
  failure_code?: string
  /** The CA's redacted explanation (≤512 characters) beside failure_code. */
  failure_reason?: string
  retry_error_code?: string
  retry_error_reason?: string
  issued_asset_id?: string
  issued_version_id?: string
  issued_at?: string
  version: number
  created_at: string
  updated_at: string
}

export interface CertificateOrderStatusList {
  items: CertificateOrderStatusItem[]
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const failureCodePattern = /^[a-z][a-z0-9_]{0,127}$/
// The CA reason the server redacted (acmeworker.PublicReason): 1–512 characters, trimmed, no control characters.
// eslint-disable-next-line no-control-regex
const reasonControlPattern = /[\u0000-\u001f\u007f-\u009f]/u

function isReason(value: unknown): boolean {
  return typeof value === 'string' && value.length >= 1 && [...value].length <= 512 && value === value.trim() &&
    !reasonControlPattern.test(value)
}
const challenges = new Set<CertificateOrderChallenge>(['http-01', 'dns-01'])
const statuses = new Set<CertificateOrderLifecycle>([
  'pending', 'validating', 'issuing', 'issued', 'deploying', 'active',
  'renewal_due', 'failed', 'revoked',
])
const orderKeys = new Set([
  'id', 'scope_id', 'dns_provider_id', 'domains', 'challenge_type', 'status',
  'auto_renew', 'renewal_of_order_id', 'not_after', 'failure_code', 'failure_reason', 'retry_error_code', 'retry_error_reason',
  'issued_asset_id', 'issued_version_id', 'issued_at', 'version', 'created_at', 'updated_at',
])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && value.includes('T') && Number.isFinite(Date.parse(value))
}

function optional(value: unknown, check: (candidate: unknown) => boolean): boolean {
  return value === undefined || check(value)
}

function isOrder(value: unknown): value is CertificateOrderStatusItem {
  return isRecord(value) && Object.keys(value).every((key) => orderKeys.has(key)) &&
    isUUID(value.id) && isUUID(value.scope_id) && optional(value.dns_provider_id, isUUID) &&
    Array.isArray(value.domains) && value.domains.length >= 1 && value.domains.length <= 100 &&
    value.domains.every((domain) => typeof domain === 'string' && domain.length >= 1 && domain.length <= 253) &&
    challenges.has(value.challenge_type as CertificateOrderChallenge) &&
    statuses.has(value.status as CertificateOrderLifecycle) && typeof value.auto_renew === 'boolean' &&
    optional(value.renewal_of_order_id, isUUID) && optional(value.not_after, isDateTime) &&
    optional(value.failure_code, (code) => typeof code === 'string' && failureCodePattern.test(code)) &&
    optional(value.retry_error_code, (code) => typeof code === 'string' && failureCodePattern.test(code)) &&
    optional(value.failure_reason, isReason) && optional(value.retry_error_reason, isReason) &&
    optional(value.issued_asset_id, isUUID) && optional(value.issued_version_id, isUUID) &&
    optional(value.issued_at, isDateTime) && Number.isSafeInteger(value.version) && Number(value.version) >= 1 &&
    isDateTime(value.created_at) && isDateTime(value.updated_at)
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid certificate order response', 502, 'invalid_response')
}

export const certificateOrderStatusApi = {
  async list(accessToken: string, signal?: AbortSignal): Promise<CertificateOrderStatusList> {
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/certificate-orders`, {
        credentials: 'include',
        headers: { Authorization: `Bearer ${accessToken}` },
        signal,
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
    if (!isRecord(value) || Object.keys(value).some((key) => key !== 'items') ||
      !Array.isArray(value.items) || !value.items.every(isOrder)) {
      throw invalidResponse()
    }
    return { items: value.items }
  },
}
