import { ApiError, networkApiError, responseApiError } from './auth'

// 平台审批中心：受管操作被拦下后的待审单、批准即执行、驳回与开关设置。
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export const approvalRules = [
  'site.batch_delete', 'cache.whole_site_purge', 'firewall.policy', 'control.upgrade',
  'site.batch_disable', 'node.batch_disable', 'stream.batch_delete', 'user.delete',
] as const
export type ApprovalRule = typeof approvalRules[number]
export const approvalStates = ['pending', 'expired', 'rejected', 'executing', 'unknown', 'executed', 'failed'] as const
export type ApprovalState = typeof approvalStates[number]

export interface ApprovalCatalogEntry { name: ApprovalRule; default: boolean; grouped: boolean; target_path: string }
export interface ApprovalSettings { enabled: boolean; rules: ApprovalRule[]; revision: number; catalog: ApprovalCatalogEntry[] }
export interface ApprovalStep { method: string; path: string; query?: string; body?: string }
export interface ApprovalStepResult { status: number; body: string }
export interface ApprovalRequest {
  id: string
  rule: ApprovalRule
  step_count: number
  steps: ApprovalStep[]
  reason: string
  requested_by_user_id: string
  requested_by_name: string
  requested_at: string
  expires_at: string
  state: ApprovalState
  decided_by_user_id?: string
  decided_by_name?: string
  decided_at?: string
  decision_note: string
  step_up?: 'mfa' | 'none'
  self_approved: boolean
  results?: ApprovalStepResult[]
  executed_at?: string
  revision: number
}

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
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

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
}

function validRequest(value: unknown): value is ApprovalRequest {
  const item = record(value)
  return Boolean(item && typeof item.id === 'string' && approvalRules.includes(item.rule as ApprovalRule) &&
    approvalStates.includes(item.state as ApprovalState) && Array.isArray(item.steps) && typeof item.revision === 'number')
}

function approval(value: unknown): ApprovalRequest {
  const approvalValue = record(value)?.approval
  if (!validRequest(approvalValue)) throw invalidResponse()
  return approvalValue
}

function settings(value: unknown): ApprovalSettings {
  const body = record(value)
  if (!body || typeof body.enabled !== 'boolean' || !Array.isArray(body.rules) || typeof body.revision !== 'number' ||
    !Array.isArray(body.catalog)) throw invalidResponse()
  return body as unknown as ApprovalSettings
}

export const approvalCenterApi = {
  settings: async (token: string) => settings(await request(token, '/v1/admin/approval-center/settings')),
  saveSettings: async (token: string, input: { enabled: boolean; rules: ApprovalRule[]; revision: number }) =>
    settings(await request(token, '/v1/admin/approval-center/settings', { method: 'PUT', body: JSON.stringify(input) })),
  list: async (token: string, state?: ApprovalState) => {
    const query = new URLSearchParams({ limit: '100' })
    if (state) query.set('state', state)
    const body = record(await request(token, `/v1/admin/approval-requests?${query}`))
    if (!body || !Array.isArray(body.items) || !body.items.every(validRequest)) throw invalidResponse()
    return body.items as ApprovalRequest[]
  },
  get: async (token: string, id: string) => {
    const body = await request(token, `/v1/admin/approval-requests/${encodeURIComponent(id)}`)
    const stepUp = record(body)?.step_up_required
    if (typeof stepUp !== 'boolean') throw invalidResponse()
    return { approval: approval(body), stepUpRequired: stepUp }
  },
  decide: async (token: string, id: string, decision: 'approve' | 'reject', input: { expected_revision: number; note: string; step_up_token?: string }) =>
    approval(await request(token, `/v1/admin/approval-requests/${encodeURIComponent(id)}/${decision}`, {
      method: 'POST', body: JSON.stringify(input),
    })),
}

export const approvalStepUp = { audience: 'approval-center', action: 'approval_center.approve' } as const

// createApprovalStepUp issues the platform-scoped step-up proof an approver
// with MFA needs (Q3); the server binds it to the request when consuming it.
export async function createApprovalStepUp(token: string, code: string): Promise<string> {
  const body = record(await request(token, '/v1/account/mfa/step-up-proofs', {
    method: 'POST',
    headers: { 'Idempotency-Key': `ac-step-up-${globalThis.crypto.randomUUID()}` },
    body: JSON.stringify({ ...approvalStepUp, authentication: { method: 'totp', code }, ttl_seconds: 300, max_uses: 1 }),
  }))
  if (typeof body?.token !== 'string' || body.token === '') throw invalidResponse()
  return body.token
}
