import { ApiError, networkApiError, responseApiError } from './auth'

export type FirewallNormalAction = 'disconnect' | 'return_page'
export type FirewallEscalatedAction = 'nftables'
export type FirewallActionState = 'pending' | 'active' | 'failed'
// Where the nftables escalation runs (A08): only on nodes the tenant owns.
export type FirewallHostEscalation = 'owned' | 'shared_unsupported'

export interface FirewallReturnPage {
  status: number
  content_type: 'text/html; charset=utf-8' | 'text/plain; charset=utf-8'
  body: string
}

export interface FirewallTrustedCrawler {
  name: string
  networks: string[]
  user_agent_prefixes: string[]
}

export interface FirewallActionPolicyInput {
  normal_action: FirewallNormalAction
  escalated_action: FirewallEscalatedAction
  engage_threshold: number
  recover_threshold: number
  recovery_windows: number
  block_networks: string[]
  trusted_proxies: string[]
  trusted_crawlers: FirewallTrustedCrawler[]
  return_page: FirewallReturnPage
}

export interface FirewallActionPolicy extends FirewallActionPolicyInput {
  id: string
  tenant_scope_id: string
  site_id: string
  revision: number
  active_revision: number
  lkg_revision: number
  deployment_state: FirewallActionState
  host_escalation: FirewallHostEscalation
  document_sha256: string
  created_at: string
  updated_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length && actual.every((key, index) => key === expected[index])
}

function isStringArray(value: unknown, allowEmpty = true): value is string[] {
  return Array.isArray(value) && (allowEmpty || value.length > 0) && value.every((item) => typeof item === 'string')
}

function isCrawler(value: unknown): value is FirewallTrustedCrawler {
  return isRecord(value) && exactKeys(value, ['name', 'networks', 'user_agent_prefixes']) && typeof value.name === 'string' &&
    isStringArray(value.networks, false) && isStringArray(value.user_agent_prefixes, false)
}

function isReturnPage(value: unknown): value is FirewallReturnPage {
  return isRecord(value) && exactKeys(value, ['status', 'content_type', 'body']) && Number.isSafeInteger(value.status) &&
    (value.content_type === 'text/html; charset=utf-8' || value.content_type === 'text/plain; charset=utf-8') && typeof value.body === 'string'
}

function isPolicy(value: unknown): value is FirewallActionPolicy {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'tenant_scope_id', 'site_id', 'normal_action', 'escalated_action', 'engage_threshold', 'recover_threshold',
    'recovery_windows', 'block_networks', 'trusted_proxies', 'trusted_crawlers', 'return_page', 'revision', 'active_revision',
    'lkg_revision', 'deployment_state', 'host_escalation', 'document_sha256', 'created_at', 'updated_at',
  ])) return false
  if (value.host_escalation !== 'owned' && value.host_escalation !== 'shared_unsupported') return false
  if (![value.id, value.tenant_scope_id, value.site_id].every((item) => typeof item === 'string' && uuidPattern.test(item))) return false
  if (value.normal_action !== 'disconnect' && value.normal_action !== 'return_page' || value.escalated_action !== 'nftables') return false
  if (![value.engage_threshold, value.recover_threshold, value.recovery_windows, value.revision, value.active_revision, value.lkg_revision]
    .every((item) => Number.isSafeInteger(item) && Number(item) >= 0)) return false
  if (Number(value.engage_threshold) < 1 || Number(value.recover_threshold) >= Number(value.engage_threshold) || Number(value.recovery_windows) < 1 || Number(value.recovery_windows) > 60) return false
  if (!isStringArray(value.block_networks, false) || !isStringArray(value.trusted_proxies) || !Array.isArray(value.trusted_crawlers) || !value.trusted_crawlers.every(isCrawler) || !isReturnPage(value.return_page)) return false
  if (!['pending', 'active', 'failed'].includes(String(value.deployment_state)) || Number(value.revision) < 1 || Number(value.active_revision) > Number(value.revision) || Number(value.lkg_revision) > Number(value.active_revision)) return false
  return typeof value.document_sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.document_sha256) &&
    typeof value.created_at === 'string' && !Number.isNaN(Date.parse(value.created_at)) && typeof value.updated_at === 'string' && !Number.isNaN(Date.parse(value.updated_at))
}

function invalidResponse(): ApiError { return new ApiError('Invalid firewall action response', 0, 'invalid_response') }

async function request(token: string, path: string, init: RequestInit = {}): Promise<FirewallActionPolicy> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, { ...init, credentials: 'include', headers: {
      Authorization: `Bearer ${token}`, 'X-Request-ID': crypto.randomUUID(),
      ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }), ...init.headers,
    } })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw invalidResponse() }
  if (!isPolicy(value)) throw invalidResponse()
  return value
}

function policyPath(scopeId: string, siteId: string): string {
  const query = new URLSearchParams({ target_scope_id: scopeId, site_id: siteId })
  return `/v1/firewall-actions/policy?${query.toString()}`
}

function recoveryPath(scopeId: string, siteId: string): string {
  const query = new URLSearchParams({ target_scope_id: scopeId, site_id: siteId })
  return `/v1/firewall-actions/policy/recover?${query.toString()}`
}

function serializePolicy(policy: FirewallActionPolicyInput): FirewallActionPolicyInput {
  return {
    normal_action: policy.normal_action, escalated_action: policy.escalated_action,
    engage_threshold: policy.engage_threshold, recover_threshold: policy.recover_threshold, recovery_windows: policy.recovery_windows,
    block_networks: policy.block_networks, trusted_proxies: policy.trusted_proxies, trusted_crawlers: policy.trusted_crawlers,
    return_page: policy.return_page,
  }
}

export const firewallActionApi = {
  get(token: string, scopeId: string, siteId: string): Promise<FirewallActionPolicy> {
    return request(token, policyPath(scopeId, siteId))
  },
  put(token: string, input: { scopeId: string; siteId: string; expectedRevision: number; policy: FirewallActionPolicyInput; idempotencyKey?: string; requestId?: string }): Promise<FirewallActionPolicy> {
    return request(token, policyPath(input.scopeId, input.siteId), {
      method: 'PUT', headers: { 'If-Match': `"${input.expectedRevision}"`, 'Idempotency-Key': input.idempotencyKey ?? crypto.randomUUID(),
        ...(input.requestId ? { 'X-Request-ID': input.requestId } : {}) },
      body: JSON.stringify(serializePolicy(input.policy)),
    })
  },
  recover(token: string, input: { scopeId: string; siteId: string; expectedRevision: number; idempotencyKey?: string; requestId?: string }): Promise<FirewallActionPolicy> {
    return request(token, recoveryPath(input.scopeId, input.siteId), {
      method: 'POST', headers: { 'If-Match': `"${input.expectedRevision}"`, 'Idempotency-Key': input.idempotencyKey ?? crypto.randomUUID(),
        ...(input.requestId ? { 'X-Request-ID': input.requestId } : {}) }, body: '{}',
    })
  },
}
