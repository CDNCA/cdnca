import { networkApiError, responseApiError } from './auth'
import type { IdentityVerificationReviewKind, IdentityVerificationReviewStatus } from './identityVerificationReviewQueue'

/**
 * Admin console identity review (fix-decide1027b item 3): the platform
 * administrator lists every tenant's cases (GET /v1/identity-verification/admin/cases)
 * and reviews one through the reviewer routes with ?tenant_scope_id=.
 */
export interface AdminIdentityReviewSummary {
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
  tenant_scope_id: string
  tenant_name: string
  applicant_username: string
}

export interface AdminIdentityReviewPage {
  items: AdminIdentityReviewSummary[]
  next_cursor?: string
}

export interface AdminIdentityReviewCase {
  id: string
  applicant_user_id: string
  kind: IdentityVerificationReviewKind
  status: IdentityVerificationReviewStatus
  reviewer_user_id?: string
  decision_reason_code?: string
  revision: number
  materials: Array<{ id: string; kind: string; mime_type: string; size_bytes: number }>
}

export type AdminIdentityReviewDecision =
  | { decision: 'approved'; reason_code: 'evidence_verified' }
  | { decision: 'rejected'; reason_code: AdminIdentityRejectReason }

export type AdminIdentityRejectReason =
  | 'identity_mismatch' | 'evidence_incomplete' | 'evidence_unreadable'
  | 'organization_mismatch' | 'authorization_invalid' | 'suspected_fraud'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const base = `${apiRoot}/v1/identity-verification`

function writeKey(): string {
  return `admin-identity-review-${globalThis.crypto.randomUUID()}`
}

async function request<T>(accessToken: string, url: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(url, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return await response.json() as T
}

function caseURL(caseID: string, tenantScopeID: string, action = ''): string {
  const query = new URLSearchParams({ tenant_scope_id: tenantScopeID })
  return `${base}/reviewer/cases/${encodeURIComponent(caseID)}${action}?${query.toString()}`
}

function write(accessToken: string, url: string, revision: number, body?: unknown) {
  const key = writeKey()
  const headers: Record<string, string> = { 'If-Match': `"${revision}"`, 'Idempotency-Key': key, 'X-Request-ID': key }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  return request<AdminIdentityReviewCase>(accessToken, url, {
    method: 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body),
  })
}

export const adminIdentityReviewApi = {
  list(accessToken: string, params: { status?: IdentityVerificationReviewStatus; cursor?: string; limit?: number }) {
    const query = new URLSearchParams()
    if (params.status) query.set('status', params.status)
    if (params.limit) query.set('limit', String(params.limit))
    if (params.cursor) query.set('cursor', params.cursor)
    const suffix = query.size > 0 ? `?${query.toString()}` : ''
    return request<AdminIdentityReviewPage>(accessToken, `${base}/admin/cases${suffix}`)
  },
  get(accessToken: string, caseID: string, tenantScopeID: string) {
    return request<AdminIdentityReviewCase>(accessToken, caseURL(caseID, tenantScopeID))
  },
  claim(accessToken: string, caseID: string, tenantScopeID: string, revision: number) {
    return write(accessToken, caseURL(caseID, tenantScopeID, '/claim'), revision)
  },
  decide(accessToken: string, caseID: string, tenantScopeID: string, revision: number, decision: AdminIdentityReviewDecision) {
    return write(accessToken, caseURL(caseID, tenantScopeID, '/decision'), revision, decision)
  },
}
