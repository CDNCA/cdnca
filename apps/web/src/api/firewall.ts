import { ApiError, networkApiError, responseApiError } from './auth'

export type FirewallAction = 'allow' | 'deny'
export type FirewallProtocol = 'any' | 'tcp' | 'udp' | 'icmp'
export type FirewallDeploymentState = 'pending' | 'canary' | 'active' | 'partial' | 'failed' | 'rolled_back'

export interface FirewallRule {
  id?: string
  priority: number
  action: FirewallAction
  cidrs: string[]
  protocol: FirewallProtocol
  port_start?: number
  port_end?: number
  site_ids: string[]
  expires_at?: string
}

export interface FirewallPolicyInput {
  enabled: boolean
  default_action: FirewallAction
  rules: FirewallRule[]
}

export interface FirewallPolicy extends FirewallPolicyInput {
  id: string
  tenant_scope_id: string
  revision: number
  active_revision: number
  deployment_state: FirewallDeploymentState
  active_sha256?: string
  created_at?: string
  updated_at: string
}

export interface FirewallHit {
  id: string
  occurred_at: string
  tenant_scope_id: string
  site_id?: string
  node_id: string
  rule_id?: string
  client_ip: string
  protocol: FirewallProtocol
  destination_port?: number
  action: FirewallAction
  reason_code: string
}

export interface FirewallHitPage { items: FirewallHit[]; next_cursor?: string }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const timestampPattern = /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && timestampPattern.test(value) && !Number.isNaN(Date.parse(value))
}

function isRule(value: unknown): value is FirewallRule {
  return isRecord(value) && (value.id === undefined || typeof value.id === 'string' && uuidPattern.test(value.id)) &&
    typeof value.priority === 'number' && Number.isSafeInteger(value.priority) && value.priority >= 1 && value.priority <= 1_000_000 &&
    (value.action === 'allow' || value.action === 'deny') && Array.isArray(value.cidrs) && value.cidrs.length > 0 &&
    value.cidrs.length <= 256 && value.cidrs.every((item) => typeof item === 'string') && new Set(value.cidrs).size === value.cidrs.length &&
    (value.protocol === 'any' || value.protocol === 'tcp' || value.protocol === 'udp' || value.protocol === 'icmp') &&
    (value.port_start === undefined || typeof value.port_start === 'number' && Number.isSafeInteger(value.port_start) && value.port_start >= 1 && value.port_start <= 65535) &&
    (value.port_end === undefined || typeof value.port_end === 'number' && Number.isSafeInteger(value.port_end) && value.port_end >= 1 && value.port_end <= 65535) &&
    Array.isArray(value.site_ids) && value.site_ids.length <= 128 &&
    value.site_ids.every((item) => typeof item === 'string' && uuidPattern.test(item)) && new Set(value.site_ids).size === value.site_ids.length &&
    (value.expires_at === undefined || isTimestamp(value.expires_at))
}

function isPolicy(value: unknown): value is FirewallPolicy {
  return isRecord(value) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) && typeof value.enabled === 'boolean' &&
    (value.default_action === 'allow' || value.default_action === 'deny') && Array.isArray(value.rules) && value.rules.every(isRule) &&
    Number.isSafeInteger(value.revision) && (value.revision as number) > 0 && Number.isSafeInteger(value.active_revision) &&
    ['pending', 'canary', 'active', 'partial', 'failed', 'rolled_back'].includes(String(value.deployment_state)) &&
    (value.active_sha256 === undefined || typeof value.active_sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.active_sha256)) &&
    typeof value.updated_at === 'string'
}

function isHit(value: unknown): value is FirewallHit {
  return isRecord(value) && typeof value.id === 'string' && typeof value.occurred_at === 'string' &&
    typeof value.tenant_scope_id === 'string' && typeof value.node_id === 'string' && typeof value.client_ip === 'string' &&
    ['any', 'tcp', 'udp', 'icmp'].includes(String(value.protocol)) && (value.action === 'allow' || value.action === 'deny') &&
    typeof value.reason_code === 'string'
}

function isHitPage(value: unknown): value is FirewallHitPage {
  return isRecord(value) && Array.isArray(value.items) && value.items.every(isHit) &&
    (value.next_cursor === undefined || typeof value.next_cursor === 'string')
}

function invalidResponse(): ApiError { return new ApiError('Invalid firewall response', 0, 'invalid_response') }

async function request<T>(token: string, path: string, validate: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
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
  if (!validate(value)) throw invalidResponse()
  return value
}

const policyPath = (scopeId: string) => `/v1/firewall/policy?target_scope_id=${encodeURIComponent(scopeId)}`

export const firewallApi = {
  get(token: string, scopeId: string): Promise<FirewallPolicy> {
    return request(token, policyPath(scopeId), isPolicy)
  },
  put(token: string, input: { scopeId: string; expectedRevision: number; policy: FirewallPolicyInput }): Promise<FirewallPolicy> {
    return request(token, policyPath(input.scopeId), isPolicy, { method: 'PUT', headers: {
      'If-Match': `"${input.expectedRevision}"`, 'Idempotency-Key': crypto.randomUUID(),
    }, body: JSON.stringify(input.policy) })
  },
  recover(token: string, input: { scopeId: string; expectedRevision: number; recoverRevision: number; reason: 'false_positive' | 'health_failure' | 'operator_request' }): Promise<FirewallPolicy> {
    return request(token, `/v1/firewall/policy/recover?target_scope_id=${encodeURIComponent(input.scopeId)}`, isPolicy, {
      method: 'POST', headers: { 'If-Match': `"${input.expectedRevision}"`, 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({ recover_revision: input.recoverRevision, reason: input.reason }),
    })
  },
  hits(token: string, input: { scopeId: string; cursor?: string; limit?: number }): Promise<FirewallHitPage> {
    const query = new URLSearchParams({ target_scope_id: input.scopeId, limit: String(input.limit ?? 50) })
    if (input.cursor) query.set('cursor', input.cursor)
    return request(token, `/v1/firewall/hits?${query.toString()}`, isHitPage)
  },
}
