import { ApiError, networkApiError, responseApiError } from './auth'

export type ChallengeMode = 'delay' | 'click' | 'slider' | 'captcha' | 'external'
export type IPBinding = 'none' | 'exact'

export interface ChallengeBypassRoute {
  kind: 'exact' | 'prefix'
  path: string
}

export interface ExternalProviderReference {
  provider: 'tencent' | 'geetest-v4'
  app_reference: string
}

export interface ChallengePolicyConfig {
  priority: number
  mode: ChallengeMode
  min_delay_seconds: number
  challenge_ttl_seconds: number
  pass_ttl_seconds: number
  clock_skew_seconds: number
  attempts_per_nonce: 1
  failure_window_seconds: number
  max_failures_per_window: number
  ip_binding: IPBinding
  bind_user_agent: boolean
  bypass_routes: ChallengeBypassRoute[]
  key_reference: string
  external_provider?: ExternalProviderReference
}

export interface ChallengePolicy {
  id: string
  tenant_scope_id: string
  site_id: string
  host: string
  priority: number
  mode: ChallengeMode
  min_delay_seconds: number
  challenge_ttl_seconds: number
  pass_ttl_seconds: number
  clock_skew_seconds: number
  attempts_per_nonce: 1
  failure_window_seconds: number
  max_failures_per_window: number
  ip_binding: IPBinding
  bind_user_agent: boolean
  bypass_routes: ChallengeBypassRoute[]
  key_reference_configured: boolean
  external_provider_configured: boolean
  enabled: boolean
  deleted: boolean
  revision: number
  created_at: string
  updated_at: string
}

export interface ChallengePolicyPage {
  items: ChallengePolicy[]
  next_cursor?: string
}

export type ChallengePublicationState = 'queued' | 'running' | 'healthy' | 'failed' | 'active'
export type ChallengePublicationReason = '-' | 'waiting_for_nodes' | 'node_apply_failed' |
  'external_adapter_missing' | 'configuration_publish_failed'

export interface ChallengePublicationStatus {
  policy_id: string
  policy_revision: number
  rollout_id: string
  config_version_id: string
  state: ChallengePublicationState
  reason: ChallengePublicationReason
  total: number
  pending: number
  running: number
  healthy: number
  failed: number
  cancelled: number
  /** Nodes that ignored the secret as an old release (they already run a newer revision); not failed. */
  superseded: number
  config_publication?: { publication_id: string; revision: number }
}

export interface ChallengePolicyFilters {
  limit: number
  cursor?: string
  site_id?: string
  host?: string
  enabled?: boolean
}

export interface CreateChallengePolicyInput {
  site_id: string
  host: string
  enabled: boolean
  config: ChallengePolicyConfig
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const hostPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/
const cursorPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
const modes = new Set<ChallengeMode>(['delay', 'click', 'slider', 'captcha', 'external'])
const bindings = new Set<IPBinding>(['none', 'exact'])
const responseKeys = new Set([
  'id', 'tenant_scope_id', 'site_id', 'host', 'priority', 'mode', 'min_delay_seconds',
  'challenge_ttl_seconds', 'pass_ttl_seconds', 'clock_skew_seconds', 'attempts_per_nonce',
  'failure_window_seconds', 'max_failures_per_window', 'ip_binding', 'bind_user_agent',
  'bypass_routes', 'key_reference_configured', 'external_provider_configured', 'enabled',
  'deleted', 'revision', 'created_at', 'updated_at',
])

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('Challenge policy request was invalid', 400, 'validation_error')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => key in value) && Object.keys(value).every((key) => allowed.has(key))
}

function integer(value: unknown, minimum: number, maximum: number): boolean {
  return Number.isInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 64 && !Number.isNaN(Date.parse(value))
}

function validCursor(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 1024 && cursorPattern.test(value)
}

function validBypassRoute(value: unknown): value is ChallengeBypassRoute {
  if (!record(value) || !exactKeys(value, ['kind', 'path']) ||
    (value.kind !== 'exact' && value.kind !== 'prefix') || typeof value.path !== 'string' ||
    value.path.length < 1 || value.path.length > 512 || !value.path.startsWith('/') ||
    value.path.startsWith('//') || value.path.includes('//') || /[?%#\\]/.test(value.path) ||
    !/^[\x20-\x7e]+$/.test(value.path)) return false
  const segments = value.path.split('/')
  if (segments.some((segment) => segment === '.' || segment === '..')) return false
  return value.kind !== 'prefix' || value.path !== '/' && value.path.endsWith('/')
}

function parsePolicy(value: unknown): ChallengePolicy {
  if (!record(value) || !exactKeys(value, [...responseKeys]) ||
    typeof value.id !== 'string' || !uuidPattern.test(value.id) ||
    typeof value.tenant_scope_id !== 'string' || !uuidPattern.test(value.tenant_scope_id) ||
    typeof value.site_id !== 'string' || !uuidPattern.test(value.site_id) ||
    typeof value.host !== 'string' || value.host.length > 253 || !hostPattern.test(value.host) ||
    !integer(value.priority, 1, 1_000_000) || !modes.has(value.mode as ChallengeMode) ||
    !integer(value.min_delay_seconds, 0, 10) ||
    (value.mode === 'delay' ? Number(value.min_delay_seconds) < 5 : value.min_delay_seconds !== 0) ||
    !integer(value.challenge_ttl_seconds, 10, 300) || !integer(value.pass_ttl_seconds, 1, 3600) ||
    !integer(value.clock_skew_seconds, 0, 30) || value.attempts_per_nonce !== 1 ||
    Number(value.challenge_ttl_seconds) <= Number(value.min_delay_seconds) + Number(value.clock_skew_seconds) ||
    !integer(value.failure_window_seconds, 1, 3600) || !integer(value.max_failures_per_window, 1, 20) ||
    !bindings.has(value.ip_binding as IPBinding) || typeof value.bind_user_agent !== 'boolean' ||
    !Array.isArray(value.bypass_routes) || value.bypass_routes.length > 32 ||
    !value.bypass_routes.every(validBypassRoute) ||
    new Set(value.bypass_routes.map((route) => route.path)).size !== value.bypass_routes.length ||
    typeof value.key_reference_configured !== 'boolean' ||
    typeof value.external_provider_configured !== 'boolean' ||
    (value.mode === 'external') !== value.external_provider_configured ||
    typeof value.enabled !== 'boolean' || typeof value.deleted !== 'boolean' ||
    !integer(value.revision, 1, Number.MAX_SAFE_INTEGER) ||
    !timestamp(value.created_at) || !timestamp(value.updated_at)) throw invalidResponse()
  return value as unknown as ChallengePolicy
}

function parsePublication(value: unknown, scopeID: string, policyID: string): ChallengePublicationStatus {
  if (!record(value) || !exactKeys(value, [
    'policy_id', 'policy_revision', 'rollout_id', 'config_version_id', 'state', 'reason',
    'total', 'pending', 'running', 'healthy', 'failed', 'cancelled', 'superseded',
  ], ['config_publication']) || value.policy_id !== policyID || !uuidPattern.test(value.policy_id) ||
    !integer(value.policy_revision, 1, Number.MAX_SAFE_INTEGER) ||
    typeof value.rollout_id !== 'string' || !uuidPattern.test(value.rollout_id) ||
    typeof value.config_version_id !== 'string' || !uuidPattern.test(value.config_version_id) ||
    !['queued', 'running', 'healthy', 'failed', 'active'].includes(String(value.state)) ||
    !['-', 'waiting_for_nodes', 'node_apply_failed', 'external_adapter_missing', 'configuration_publish_failed'].includes(String(value.reason)) ||
    !integer(value.total, 1, 10_000) || !integer(value.pending, 0, 10_000) ||
    !integer(value.running, 0, 10_000) || !integer(value.healthy, 0, 10_000) ||
    !integer(value.failed, 0, 10_000) || !integer(value.cancelled, 0, 10_000) || !integer(value.superseded, 0, 10_000) ||
    Number(value.pending) + Number(value.running) + Number(value.healthy) + Number(value.failed) + Number(value.cancelled) +
      Number(value.superseded) !== Number(value.total) ||
    (value.state === 'active') !== record(value.config_publication) ||
    (record(value.config_publication) && (!exactKeys(value.config_publication, ['publication_id', 'revision']) ||
      typeof value.config_publication.publication_id !== 'string' || !uuidPattern.test(value.config_publication.publication_id) ||
      !integer(value.config_publication.revision, 1, Number.MAX_SAFE_INTEGER))) || !uuidPattern.test(scopeID)) {
    throw invalidResponse()
  }
  return value as unknown as ChallengePublicationStatus
}

function parsePage(
  value: unknown, expectedScopeID: string, filters: ChallengePolicyFilters,
): ChallengePolicyPage {
  if (!record(value) || !exactKeys(value, ['items'], ['next_cursor']) ||
    !Array.isArray(value.items) || value.items.length > filters.limit ||
    (value.items.length === 0 && value.next_cursor !== undefined) ||
    (value.next_cursor !== undefined && !validCursor(value.next_cursor))) throw invalidResponse()
  const items = value.items.map(parsePolicy)
  if (items.some((item) => item.tenant_scope_id !== expectedScopeID || item.deleted ||
    filters.site_id !== undefined && item.site_id !== filters.site_id ||
    filters.host !== undefined && item.host !== filters.host ||
    filters.enabled !== undefined && item.enabled !== filters.enabled) ||
    new Set(items.map((item) => item.id)).size !== items.length) throw invalidResponse()
  return { items, ...(typeof value.next_cursor === 'string' ? { next_cursor: value.next_cursor } : {}) }
}

function requestMetadata(): { requestID: string; traceID: string } {
  const next = () => globalThis.crypto?.randomUUID?.() ?? `web-${Date.now()}-${Math.random().toString(16).slice(2)}`
  return { requestID: next(), traceID: next() }
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
  const metadata = requestMetadata()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': metadata.requestID,
        'X-Trace-ID': metadata.traceID,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
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

function writeHeaders(idempotencyKey: string, revision?: number): HeadersInit {
  return {
    'Idempotency-Key': idempotencyKey,
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

function collectionPath(scopeID: string): string {
  return `/v1/tenant-scopes/${encodeURIComponent(scopeID)}/challenge-policies`
}

function resourcePath(scopeID: string, policyID: string): string {
  return `${collectionPath(scopeID)}/${encodeURIComponent(policyID)}`
}

function publicationPath(scopeID: string, policyID: string, rolloutID?: string): string {
  const base = `${resourcePath(scopeID, policyID)}/publications`
  return rolloutID === undefined ? base : `${base}/${encodeURIComponent(rolloutID)}`
}

function matchesConfig(policy: ChallengePolicy, config: ChallengePolicyConfig, enabled: boolean): boolean {
  return policy.priority === config.priority && policy.mode === config.mode &&
    policy.min_delay_seconds === config.min_delay_seconds &&
    policy.challenge_ttl_seconds === config.challenge_ttl_seconds &&
    policy.pass_ttl_seconds === config.pass_ttl_seconds &&
    policy.clock_skew_seconds === config.clock_skew_seconds &&
    policy.attempts_per_nonce === config.attempts_per_nonce &&
    policy.failure_window_seconds === config.failure_window_seconds &&
    policy.max_failures_per_window === config.max_failures_per_window &&
    policy.ip_binding === config.ip_binding && policy.bind_user_agent === config.bind_user_agent &&
    policy.bypass_routes.length === config.bypass_routes.length &&
    policy.bypass_routes.every((route, index) => route.kind === config.bypass_routes[index]?.kind &&
      route.path === config.bypass_routes[index]?.path) &&
    policy.key_reference_configured &&
    policy.external_provider_configured === Boolean(config.external_provider) &&
    policy.enabled === enabled
}

async function list(
  accessToken: string, scopeID: string, filters: ChallengePolicyFilters, signal?: AbortSignal,
): Promise<ChallengePolicyPage> {
  if (!integer(filters.limit, 1, 100) ||
    (filters.cursor !== undefined && !validCursor(filters.cursor))) throw invalidRequest()
  const query = new URLSearchParams({ limit: String(filters.limit) })
  if (filters.cursor !== undefined) query.set('cursor', filters.cursor)
  if (filters.site_id) query.set('site_id', filters.site_id)
  if (filters.host) query.set('host', filters.host)
  if (filters.enabled !== undefined) query.set('enabled', String(filters.enabled))
  return parsePage(await request(accessToken, `${collectionPath(scopeID)}?${query}`, { signal }), scopeID, filters)
}

async function create(
  accessToken: string, scopeID: string, input: CreateChallengePolicyInput, idempotencyKey: string,
): Promise<ChallengePolicy> {
  const policy = parsePolicy(await request(accessToken, collectionPath(scopeID), {
    method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input),
  }))
  if (policy.deleted || policy.revision !== 1 || policy.tenant_scope_id !== scopeID ||
    policy.site_id !== input.site_id || policy.host !== input.host ||
    !matchesConfig(policy, input.config, input.enabled)) throw invalidResponse()
  return policy
}

async function update(
  accessToken: string, scopeID: string, policyID: string, revision: number,
  config: ChallengePolicyConfig, expectedEnabled: boolean, idempotencyKey: string,
): Promise<ChallengePolicy> {
  const policy = parsePolicy(await request(accessToken, resourcePath(scopeID, policyID), {
    method: 'PATCH', headers: writeHeaders(idempotencyKey, revision), body: JSON.stringify({ config }),
  }))
  if (policy.deleted || policy.revision !== revision + 1 || policy.tenant_scope_id !== scopeID ||
    policy.id !== policyID || !matchesConfig(policy, config, expectedEnabled)) throw invalidResponse()
  return policy
}

async function remove(
  accessToken: string, scopeID: string, policyID: string, revision: number, idempotencyKey: string,
): Promise<ChallengePolicy> {
  const policy = parsePolicy(await request(accessToken, resourcePath(scopeID, policyID), {
    method: 'DELETE', headers: writeHeaders(idempotencyKey, revision),
  }))
  if (!policy.deleted || policy.revision !== revision + 1 || policy.tenant_scope_id !== scopeID || policy.id !== policyID) throw invalidResponse()
  return policy
}

async function setEnabled(
  accessToken: string, scopeID: string, policyID: string, revision: number,
  enabled: boolean, idempotencyKey: string,
): Promise<ChallengePolicy> {
  const policy = parsePolicy(await request(
    accessToken, `${resourcePath(scopeID, policyID)}/${enabled ? 'enable' : 'disable'}`,
    { method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: '{}' },
  ))
  if (policy.deleted || policy.revision !== revision + 1 || policy.tenant_scope_id !== scopeID ||
    policy.id !== policyID || policy.enabled !== enabled) throw invalidResponse()
  return policy
}

async function publish(
  accessToken: string, scopeID: string, policyID: string, revision: number, idempotencyKey: string,
): Promise<ChallengePublicationStatus> {
  return parsePublication(await request(accessToken, publicationPath(scopeID, policyID), {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: '{}',
  }), scopeID, policyID)
}

async function publicationStatus(
  accessToken: string, scopeID: string, policyID: string, rolloutID: string,
): Promise<ChallengePublicationStatus> {
  if (!uuidPattern.test(rolloutID)) throw invalidRequest()
  return parsePublication(await request(accessToken, publicationPath(scopeID, policyID, rolloutID)), scopeID, policyID)
}

async function promote(
  accessToken: string, scopeID: string, policyID: string, rolloutID: string, revision: number, idempotencyKey: string,
): Promise<ChallengePublicationStatus> {
  if (!uuidPattern.test(rolloutID)) throw invalidRequest()
  return parsePublication(await request(accessToken, `${publicationPath(scopeID, policyID, rolloutID)}/promote`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: '{}',
  }), scopeID, policyID)
}

export const challengePoliciesApi = {
  create,
  disable: (accessToken: string, scopeID: string, policyID: string, revision: number, key: string) =>
    setEnabled(accessToken, scopeID, policyID, revision, false, key),
  enable: (accessToken: string, scopeID: string, policyID: string, revision: number, key: string) =>
    setEnabled(accessToken, scopeID, policyID, revision, true, key),
  list,
  promote,
  publicationStatus,
  publish,
  remove,
  update,
}
