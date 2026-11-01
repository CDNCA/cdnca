import { ApiError, networkApiError, responseApiError } from './auth'

export type FirewallNormalAction = 'disconnect' | 'return_page'
export type FirewallEscalatedAction = 'nftables'
// 'inherited' = 本站没有自有策略，用租户默认/系统默认。
export type FirewallActionState = 'pending' | 'active' | 'failed' | 'inherited'
export type FirewallActionSource = 'site' | 'tenant_default' | 'system_default'
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
  /** 迁移 608：false = 本站自有策略已停用（不下发到节点，修订与 LKG 保留）；继承中恒 true。 */
  enabled: boolean
  host_escalation: FirewallHostEscalation
  document_sha256: string
  /** 继承系统默认时为 null。 */
  created_at: string | null
  updated_at: string | null
  /** true：本站没有自有策略，字段是当前有效的租户默认/系统默认；revision 是本站自有修订计数（PUT 的 If-Match）。 */
  inherited: boolean
  source: FirewallActionSource
  /** 是否下发到节点：系统默认（文档网段占位）与停用的自有策略为 false。 */
  delivered: boolean
}

/** 租户默认（GET/PUT /v1/firewall-actions/default）：没有自有策略的站点都用它。 */
export interface FirewallActionDefault extends FirewallActionPolicyInput {
  tenant_scope_id: string
  source: 'tenant_default' | 'system_default'
  /** 0 = 从未保存（系统默认）；PUT 的 If-Match。 */
  revision: number
  inheriting_site_count: number
  updated_at: string | null
}

/** A new site policy's defaults (防火墙动作页「新建」与自动防御标签「打开」共用). */
export const defaultFirewallActionPolicy: FirewallActionPolicyInput = {
  normal_action: 'return_page', escalated_action: 'nftables', engage_threshold: 100, recover_threshold: 20,
  recovery_windows: 3, block_networks: ['198.51.100.0/24'], trusted_proxies: [], trusted_crawlers: [],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8', body: 'Request limited' },
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

function isTime(value: unknown, nullable: boolean): boolean {
  return value === null ? nullable : typeof value === 'string' && !Number.isNaN(Date.parse(value))
}

/** The 9 policy fields, as the site PUT validates them. */
function isPolicyInput(value: Record<string, unknown>): boolean {
  if (value.normal_action !== 'disconnect' && value.normal_action !== 'return_page' || value.escalated_action !== 'nftables') return false
  if (![value.engage_threshold, value.recover_threshold, value.recovery_windows].every((item) => Number.isSafeInteger(item) && Number(item) >= 0)) return false
  if (Number(value.engage_threshold) < 1 || Number(value.recover_threshold) >= Number(value.engage_threshold) || Number(value.recovery_windows) < 1 || Number(value.recovery_windows) > 60) return false
  return isStringArray(value.block_networks, false) && isStringArray(value.trusted_proxies) && Array.isArray(value.trusted_crawlers) &&
    value.trusted_crawlers.every(isCrawler) && isReturnPage(value.return_page)
}

const policyInputKeys = ['normal_action', 'escalated_action', 'engage_threshold', 'recover_threshold', 'recovery_windows',
  'block_networks', 'trusted_proxies', 'trusted_crawlers', 'return_page'] as const

function isPolicy(value: unknown): value is FirewallActionPolicy {
  if (!isRecord(value) || !exactKeys(value, [
    'id', 'tenant_scope_id', 'site_id', ...policyInputKeys, 'revision', 'active_revision',
    'lkg_revision', 'deployment_state', 'enabled', 'host_escalation', 'document_sha256', 'created_at', 'updated_at',
    'inherited', 'source', 'delivered',
  ])) return false
  if (typeof value.enabled !== 'boolean' || typeof value.inherited !== 'boolean' || typeof value.delivered !== 'boolean') return false
  if (value.host_escalation !== 'owned' && value.host_escalation !== 'shared_unsupported') return false
  if (![value.id, value.tenant_scope_id, value.site_id].every((item) => typeof item === 'string' && uuidPattern.test(item))) return false
  if (!isPolicyInput(value)) return false
  if (![value.revision, value.active_revision, value.lkg_revision].every((item) => Number.isSafeInteger(item) && Number(item) >= 0)) return false
  if (typeof value.document_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.document_sha256)) return false
  if (value.inherited) {
    // 契约 §3：继承视图 active/lkg=0、deployment_state=inherited；系统默认不下发、时间为 null。
    if (value.deployment_state !== 'inherited' || value.active_revision !== 0 || value.lkg_revision !== 0 || !value.enabled) return false
    if (value.source === 'system_default') return !value.delivered && value.created_at === null && value.updated_at === null
    return value.source === 'tenant_default' && value.delivered === true && isTime(value.created_at, false) && isTime(value.updated_at, false)
  }
  if (value.source !== 'site' || value.delivered !== value.enabled) return false
  if (!['pending', 'active', 'failed'].includes(String(value.deployment_state)) || Number(value.revision) < 1 || Number(value.active_revision) > Number(value.revision) || Number(value.lkg_revision) > Number(value.active_revision)) return false
  return isTime(value.created_at, false) && isTime(value.updated_at, false)
}

function isDefault(value: unknown): value is FirewallActionDefault {
  if (!isRecord(value) || !exactKeys(value, ['tenant_scope_id', 'source', 'revision', ...policyInputKeys, 'inheriting_site_count', 'updated_at'])) return false
  if (typeof value.tenant_scope_id !== 'string' || !uuidPattern.test(value.tenant_scope_id) || !isPolicyInput(value)) return false
  if (![value.revision, value.inheriting_site_count].every((item) => Number.isSafeInteger(item) && Number(item) >= 0)) return false
  if (value.source === 'system_default') return value.revision === 0 && value.updated_at === null
  return value.source === 'tenant_default' && Number(value.revision) >= 1 && isTime(value.updated_at, false)
}

function invalidResponse(): ApiError { return new ApiError('Invalid firewall action response', 0, 'invalid_response') }

async function request(token: string, path: string, init?: RequestInit): Promise<FirewallActionPolicy>
async function request<T>(token: string, path: string, init: RequestInit, valid: (value: unknown) => value is T): Promise<T>
async function request(token: string, path: string, init: RequestInit = {}, valid: (value: unknown) => boolean = isPolicy): Promise<unknown> {
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
  if (!valid(value)) throw invalidResponse()
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

function defaultPath(scopeId: string): string {
  return `/v1/firewall-actions/default?${new URLSearchParams({ target_scope_id: scopeId }).toString()}`
}

function writeHeaders(expectedRevision: number, idempotencyKey?: string, requestId?: string): Record<string, string> {
  return { 'If-Match': `"${expectedRevision}"`, 'Idempotency-Key': idempotencyKey ?? crypto.randomUUID(), ...(requestId ? { 'X-Request-ID': requestId } : {}) }
}

/** The policy input fields of a policy or default (what the page edits). */
export function policyInputOf(policy: FirewallActionPolicyInput): FirewallActionPolicyInput {
  return serializePolicy(policy)
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
  /** PATCH 启停（迁移 608）：If-Match 当前 revision，revision 不变。 */
  setEnabled(token: string, input: { scopeId: string; siteId: string; expectedRevision: number; enabled: boolean; idempotencyKey?: string; requestId?: string }): Promise<FirewallActionPolicy> {
    return request(token, policyPath(input.scopeId, input.siteId), {
      method: 'PATCH', headers: { 'If-Match': `"${input.expectedRevision}"`, 'Idempotency-Key': input.idempotencyKey ?? crypto.randomUUID(),
        ...(input.requestId ? { 'X-Request-ID': input.requestId } : {}) },
      body: JSON.stringify({ enabled: input.enabled }),
    })
  },
  /** DELETE = 恢复继承：If-Match 当前 revision（≥1），返回继承视图。 */
  inherit(token: string, input: { scopeId: string; siteId: string; expectedRevision: number; idempotencyKey?: string; requestId?: string }): Promise<FirewallActionPolicy> {
    return request(token, policyPath(input.scopeId, input.siteId), {
      method: 'DELETE', headers: writeHeaders(input.expectedRevision, input.idempotencyKey, input.requestId),
    })
  },
  getDefault(token: string, scopeId: string): Promise<FirewallActionDefault> {
    return request(token, defaultPath(scopeId), {}, isDefault)
  },
  putDefault(token: string, input: { scopeId: string; expectedRevision: number; policy: FirewallActionPolicyInput; idempotencyKey?: string; requestId?: string }): Promise<FirewallActionDefault> {
    return request(token, defaultPath(input.scopeId), {
      method: 'PUT', headers: writeHeaders(input.expectedRevision, input.idempotencyKey, input.requestId), body: JSON.stringify(serializePolicy(input.policy)),
    }, isDefault)
  },
  recover(token: string, input: { scopeId: string; siteId: string; expectedRevision: number; idempotencyKey?: string; requestId?: string }): Promise<FirewallActionPolicy> {
    return request(token, recoveryPath(input.scopeId, input.siteId), {
      method: 'POST', headers: { 'If-Match': `"${input.expectedRevision}"`, 'Idempotency-Key': input.idempotencyKey ?? crypto.randomUUID(),
        ...(input.requestId ? { 'X-Request-ID': input.requestId } : {}) }, body: '{}',
    })
  },
}
