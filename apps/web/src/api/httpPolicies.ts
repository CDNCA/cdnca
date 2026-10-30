import { ApiError, networkApiError, responseApiError } from './auth'

export const MAX_HTTP_POLICY_UPLOAD_BYTES = 1073741824

export interface HeaderAction {
  kind: 'add' | 'set' | 'delete'
  name: string
  values: string[]
  // 允许重复 (add only): true appends to a header of that
  // name, absent/false adds only when it is absent. Values may reference
  // headerVariables as $name ("$$" is a literal "$").
  allow_duplicate?: boolean
}

// edgeconfig.HeaderVariables: the node expands them per request.
export const headerVariables = [
  'remote_addr', 'tls_fp', 'isp', 'areacode', 'country', 'province', 'city',
  'host', 'scheme', 'request_uri', 'uri', 'args', 'request_method', 'server_port', 'http_user_agent', 'http_referer',
] as const

// validHeaderVariables mirrors edgeconfig.ValidHeaderValueVariables.
export function validHeaderVariables(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '$') continue
    if (value[index + 1] === '$') { index += 1; continue }
    const name = /^[a-z][a-z0-9_]*/.exec(value.slice(index + 1))?.[0] ?? ''
    if (!(headerVariables as readonly string[]).includes(name)) return false
    index += name.length
  }
  return true
}

// 高级条件 of a URL 转向 / 内部重写 (edgeconfig.RuleCondition).
export type RuleConditionSource = 'host' | 'user_agent' | 'referer' | 'country' | 'accept_language' | 'province' | 'city' | 'isp' | 'asn' | 'header'
export const ruleConditionSources: RuleConditionSource[] = ['host', 'user_agent', 'referer', 'country', 'accept_language', 'province', 'city', 'isp', 'asn', 'header']
export const maxRuleConditions = 8

export interface RuleCondition {
  source: RuleConditionSource
  name?: string
  pattern: string
}

export type HttpPolicyMatchKind = 'exact' | 'prefix' | 'regex'

export interface RewriteRule {
  rule_id: string
  priority: number
  match_kind: HttpPolicyMatchKind
  match_path: string
  target_path: string
  preserve_query: boolean
  preserve_cookie: boolean
  conditions?: RuleCondition[]
}

export interface RedirectRule {
  rule_id: string
  priority: number
  match_kind: HttpPolicyMatchKind
  match_path: string
  status: 301 | 302 | 307 | 308
  target_url: string
  preserve_query: boolean
  // Prefix rules: append the path after match_path to the target directory.
  preserve_path: boolean
  conditions?: RuleCondition[]
}

export interface HttpPolicyConfig {
  max_upload_bytes: number
  request_headers: HeaderAction[]
  response_headers: HeaderAction[]
  rewrites: RewriteRule[]
  redirect_allowed_hosts: string[]
  redirects: RedirectRule[]
  cors: {
    allowed_origins: string[]
    allowed_methods: string[]
    allowed_headers: string[]
    exposed_headers: string[]
    allow_credentials: boolean
    max_age_seconds: number
  } | null
  /** Hotlink protection (防盗链); null is no check. */
  referer_check: HttpPolicyRefererCheck | null
}

/** Hotlink protection: domains are a host or "*.example.com"; extensions limit the check to those files. */
export interface HttpPolicyRefererCheck {
  allow_empty: boolean
  allow_same_domain: boolean
  allowed_domains: string[]
  denied_domains: string[]
  check_origin: boolean
  extensions: string[]
}

export interface HttpPolicy extends HttpPolicyConfig {
  id: string
  tenant_scope_id: string
  site_id: string
  site_owner_user_id: string
  enabled: boolean
  deleted: boolean
  revision: number
  publication_revision: number
  created_at: string
  updated_at: string
}

export interface HttpPolicyPage { items: HttpPolicy[]; next_cursor?: string }
export interface HttpPolicyWriteMetadata { idempotencyKey: string; requestID: string; traceID: string }
export interface HttpPolicyIdentity { scopeId: string; siteId?: string; ownerUserId?: string }
export interface HttpPolicyPublicationPreview {
  state: 'preview'
  sha256: string
  snapshot: {
    schema_version: 'cdnca.edge.http-policy/v1'
    policy_version: number
    sites: Array<{ site_id: string } & HttpPolicyConfig>
  }
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const ruleIDPattern = /^[A-Za-z0-9._:-]{1,128}$/
const headerNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/
const printablePattern = /^[\x20-\x7E]+$/
const policyPathPattern = /^\/(?!\/)(?!.*\/\/)(?!.*[?%#\\])[\x20-\x7E]{0,2047}$/
const regexPathPattern = /^\^\/[\x20-\x7E]{0,510}$/
const matchPathValid = (kind: unknown, value: unknown) => typeof value === 'string' &&
  (kind === 'regex' ? regexPathPattern.test(value) : (kind === 'exact' || kind === 'prefix') && policyPathPattern.test(value))
const redirectAuthorityPattern = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::[0-9]{1,5})?$/
const configKeys = ['max_upload_bytes', 'request_headers', 'response_headers', 'rewrites', 'redirect_allowed_hosts', 'redirects', 'cors', 'referer_check'] as const
export const refererDomainPattern = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/
export const refererExtensionPattern = /^[a-z0-9]{1,16}$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys)
  return Object.keys(value).every((key) => allowed.has(key))
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return hasOnlyKeys(value, keys) && keys.every((key) => Object.hasOwn(value, key))
}

function integerBetween(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum
}

function stringArray(value: unknown, maximum: number, itemMaximum: number, minimum = 0): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum &&
    value.every((item) => typeof item === 'string' && item.length >= 1 && item.length <= itemMaximum)
}

function conditionsValid(value: Record<string, unknown>): boolean {
  if (!Object.hasOwn(value, 'conditions')) return true
  const list = value.conditions
  return Array.isArray(list) && list.length >= 1 && list.length <= maxRuleConditions && list.every((item) =>
    isRecord(item) && (hasExactKeys(item, ['source', 'pattern']) && item.source !== 'header' ||
      hasExactKeys(item, ['source', 'name', 'pattern']) && item.source === 'header' &&
        typeof item.name === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(item.name)) &&
    ruleConditionSources.includes(item.source as RuleConditionSource) &&
    typeof item.pattern === 'string' && item.pattern.length >= 1 && item.pattern.length <= 256)
}

function withoutKey(value: Record<string, unknown>, key: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key))
}

function isHeaderAction(value: unknown): value is HeaderAction {
  if (isRecord(value) && Object.hasOwn(value, 'allow_duplicate')) {
    return typeof value.allow_duplicate === 'boolean' && value.kind === 'add' && isHeaderAction(withoutKey(value, 'allow_duplicate'))
  }
  if (!isRecord(value) || !hasExactKeys(value, ['kind', 'name', 'values']) ||
    (value.kind !== 'add' && value.kind !== 'set' && value.kind !== 'delete') ||
    typeof value.name !== 'string' || !headerNamePattern.test(value.name) || !stringArray(value.values, 16, 1024) ||
    value.values.some((item) => !printablePattern.test(item))) return false
  return value.kind === 'delete' ? value.values.length === 0 : value.values.length > 0
}

function isRewriteRule(value: unknown): value is RewriteRule {
  if (isRecord(value) && Object.hasOwn(value, 'conditions')) return conditionsValid(value) && isRewriteRule(withoutKey(value, 'conditions'))
  return isRecord(value) && hasExactKeys(value, ['rule_id', 'priority', 'match_kind', 'match_path', 'target_path', 'preserve_query', 'preserve_cookie']) &&
    typeof value.rule_id === 'string' && ruleIDPattern.test(value.rule_id) && integerBetween(value.priority, 0, 4294967295) &&
    matchPathValid(value.match_kind, value.match_path) &&
    typeof value.target_path === 'string' && policyPathPattern.test(value.target_path) && typeof value.preserve_query === 'boolean' &&
    typeof value.preserve_cookie === 'boolean'
}

function isRedirectRule(value: unknown): value is RedirectRule {
  if (isRecord(value) && Object.hasOwn(value, 'conditions')) return conditionsValid(value) && isRedirectRule(withoutKey(value, 'conditions'))
  return isRecord(value) && hasExactKeys(value, ['rule_id', 'priority', 'match_kind', 'match_path', 'status', 'target_url', 'preserve_query', 'preserve_path']) &&
    typeof value.rule_id === 'string' && ruleIDPattern.test(value.rule_id) && integerBetween(value.priority, 0, 4294967295) &&
    matchPathValid(value.match_kind, value.match_path) &&
    (value.status === 301 || value.status === 302 || value.status === 307 || value.status === 308) && typeof value.target_url === 'string' &&
    value.target_url.length >= 1 && value.target_url.length <= 4096 && typeof value.preserve_query === 'boolean' &&
    typeof value.preserve_path === 'boolean' && (!value.preserve_path || value.match_kind === 'prefix')
}

function isCors(value: unknown): value is NonNullable<HttpPolicyConfig['cors']> {
  return isRecord(value) && hasExactKeys(value, ['allowed_origins', 'allowed_methods', 'allowed_headers', 'exposed_headers', 'allow_credentials', 'max_age_seconds']) &&
    stringArray(value.allowed_origins, 64, 512, 1) && stringArray(value.allowed_methods, 64, 128, 1) &&
    stringArray(value.allowed_headers, 64, 128) && stringArray(value.exposed_headers, 64, 128) &&
    typeof value.allow_credentials === 'boolean' && integerBetween(value.max_age_seconds, 0, 86400)
}

function isRefererCheck(value: unknown): value is HttpPolicyRefererCheck {
  return isRecord(value) && hasExactKeys(value, ['allow_empty', 'allow_same_domain', 'allowed_domains', 'denied_domains', 'check_origin', 'extensions']) &&
    typeof value.allow_empty === 'boolean' && typeof value.allow_same_domain === 'boolean' && typeof value.check_origin === 'boolean' &&
    stringArray(value.allowed_domains, 64, 255) && value.allowed_domains.every((domain) => refererDomainPattern.test(domain)) &&
    stringArray(value.denied_domains, 64, 255) && value.denied_domains.every((domain) => refererDomainPattern.test(domain)) &&
    stringArray(value.extensions, 32, 16) && value.extensions.every((extension) => refererExtensionPattern.test(extension))
}

function hasConfig(value: Record<string, unknown>): boolean {
  return integerBetween(value.max_upload_bytes, 1, MAX_HTTP_POLICY_UPLOAD_BYTES) &&
    Array.isArray(value.request_headers) && value.request_headers.length <= 64 && value.request_headers.every(isHeaderAction) &&
    Array.isArray(value.response_headers) && value.response_headers.length <= 64 && value.response_headers.every(isHeaderAction) &&
    Array.isArray(value.rewrites) && value.rewrites.length <= 128 && value.rewrites.every(isRewriteRule) &&
    stringArray(value.redirect_allowed_hosts, 64, 512) && value.redirect_allowed_hosts.every((host) => redirectAuthorityPattern.test(host)) &&
    Array.isArray(value.redirects) && value.redirects.length <= 128 && value.redirects.every(isRedirectRule) &&
    (value.cors === null || isCors(value.cors)) && (value.referer_check === null || isRefererCheck(value.referer_check))
}

function isPolicy(value: unknown): value is HttpPolicy {
  const keys = ['id', 'tenant_scope_id', 'site_id', 'site_owner_user_id', 'enabled', 'deleted', 'revision', 'publication_revision', 'created_at', 'updated_at', ...configKeys]
  return isRecord(value) && hasExactKeys(value, keys) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) && typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    typeof value.site_owner_user_id === 'string' && uuidPattern.test(value.site_owner_user_id) && hasConfig(value) &&
    typeof value.enabled === 'boolean' && typeof value.deleted === 'boolean' && integerBetween(value.revision, 1, Number.MAX_SAFE_INTEGER) &&
    integerBetween(value.publication_revision, 1, Number.MAX_SAFE_INTEGER) && typeof value.created_at === 'string' && !Number.isNaN(Date.parse(value.created_at)) &&
    typeof value.updated_at === 'string' && !Number.isNaN(Date.parse(value.updated_at))
}

function matchesIdentity(policy: HttpPolicy, identity: HttpPolicyIdentity, policyID?: string): boolean {
  return policy.tenant_scope_id === identity.scopeId && (identity.siteId === undefined || policy.site_id === identity.siteId) &&
    (identity.ownerUserId === undefined || policy.site_owner_user_id === identity.ownerUserId) &&
    (policyID === undefined || policy.id === policyID)
}

function isPage(value: unknown, identity: HttpPolicyIdentity): value is HttpPolicyPage {
  return isRecord(value) && hasOnlyKeys(value, ['items', 'next_cursor']) && Object.hasOwn(value, 'items') &&
    Array.isArray(value.items) && value.items.length <= 1 && value.items.every((item) => isPolicy(item) && matchesIdentity(item, identity)) &&
    (value.next_cursor === undefined || typeof value.next_cursor === 'string' && value.next_cursor.length <= 1024)
}

function isPreview(value: unknown): value is HttpPolicyPublicationPreview {
  if (!isRecord(value) || !hasExactKeys(value, ['state', 'sha256', 'snapshot']) || value.state !== 'preview' ||
    typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.sha256) || !isRecord(value.snapshot) ||
    !hasExactKeys(value.snapshot, ['schema_version', 'policy_version', 'sites']) || value.snapshot.schema_version !== 'cdnca.edge.http-policy/v1' ||
    !integerBetween(value.snapshot.policy_version, 1, Number.MAX_SAFE_INTEGER) || !Array.isArray(value.snapshot.sites) ||
    value.snapshot.sites.length < 1 || value.snapshot.sites.length > 128) return false
  return value.snapshot.sites.every((site) => isRecord(site) && hasExactKeys(site, ['site_id', ...configKeys]) &&
    typeof site.site_id === 'string' && uuidPattern.test(site.site_id) && hasConfig(site))
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid HTTP policy response', 0, 'invalid_response')
}

async function request<T>(token: string, path: string, validate: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        'X-Trace-ID': crypto.randomUUID(),
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw invalidResponse() }
  if (!validate(value)) throw invalidResponse()
  return value
}

function normalizedMetadata(value: string | HttpPolicyWriteMetadata): HttpPolicyWriteMetadata {
  if (typeof value !== 'string') return value
  const suffix = crypto.randomUUID()
  return { idempotencyKey: value, requestID: `request-${suffix}`, traceID: `trace-${suffix}` }
}

function writeHeaders(value: string | HttpPolicyWriteMetadata, revision?: number): HeadersInit {
  const metadata = normalizedMetadata(value)
  if (![metadata.idempotencyKey, metadata.requestID, metadata.traceID].every((item) => metadataPattern.test(item))) {
    throw new ApiError('Invalid HTTP policy request metadata', 400, 'invalid_request')
  }
  return {
    'Idempotency-Key': metadata.idempotencyKey,
    'X-Request-ID': metadata.requestID,
    'X-Trace-ID': metadata.traceID,
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

const policyPath = (scopeID: string) => `/v1/tenant-scopes/${encodeURIComponent(scopeID)}/http-policies`
const policyValidator = (identity: HttpPolicyIdentity, policyID?: string) =>
  (value: unknown): value is HttpPolicy => isPolicy(value) && matchesIdentity(value, identity, policyID)

export const httpPoliciesApi = {
  list(token: string, scopeID: string, siteID: string, ownerUserID?: string): Promise<HttpPolicyPage> {
    const identity = { scopeId: scopeID, siteId: siteID, ownerUserId: ownerUserID }
    return request(token, `${policyPath(scopeID)}?site_id=${encodeURIComponent(siteID)}`, (value): value is HttpPolicyPage => isPage(value, identity))
  },
  create(token: string, scopeID: string, siteID: string, config: HttpPolicyConfig, metadata: string | HttpPolicyWriteMetadata, ownerUserID?: string): Promise<HttpPolicy> {
    return request(token, policyPath(scopeID), policyValidator({ scopeId: scopeID, siteId: siteID, ownerUserId: ownerUserID }), {
      method: 'POST', headers: writeHeaders(metadata), body: JSON.stringify({ site_id: siteID, enabled: true, config }),
    })
  },
  update(token: string, scopeID: string, policyID: string, revision: number, config: HttpPolicyConfig, metadata: string | HttpPolicyWriteMetadata, identity?: HttpPolicyIdentity): Promise<HttpPolicy> {
    return request(token, `${policyPath(scopeID)}/${encodeURIComponent(policyID)}`, policyValidator(identity ?? { scopeId: scopeID }, policyID), {
      method: 'PATCH', headers: writeHeaders(metadata, revision), body: JSON.stringify({ config }),
    })
  },
  setEnabled(token: string, scopeID: string, policyID: string, revision: number, enabled: boolean, metadata: string | HttpPolicyWriteMetadata, identity?: HttpPolicyIdentity): Promise<HttpPolicy> {
    return request(token, `${policyPath(scopeID)}/${encodeURIComponent(policyID)}/${enabled ? 'enable' : 'disable'}`, policyValidator(identity ?? { scopeId: scopeID }, policyID), {
      method: 'POST', headers: writeHeaders(metadata, revision), body: '{}',
    })
  },
  delete(token: string, scopeID: string, policyID: string, revision: number, metadata: string | HttpPolicyWriteMetadata, identity?: HttpPolicyIdentity): Promise<HttpPolicy> {
    return request(token, `${policyPath(scopeID)}/${encodeURIComponent(policyID)}`, policyValidator(identity ?? { scopeId: scopeID }, policyID), {
      method: 'DELETE', headers: writeHeaders(metadata, revision),
    })
  },
  preview(token: string, scopeID: string): Promise<HttpPolicyPublicationPreview> {
    return request(token, `${policyPath(scopeID)}/publication-preview`, isPreview)
  },
}

export const emptyHttpPolicyConfig = (): HttpPolicyConfig => ({
  max_upload_bytes: MAX_HTTP_POLICY_UPLOAD_BYTES,
  request_headers: [], response_headers: [], rewrites: [], redirect_allowed_hosts: [], redirects: [], cors: null, referer_check: null,
})

export function configFromHttpPolicy(policy: HttpPolicy): HttpPolicyConfig {
  return {
    max_upload_bytes: policy.max_upload_bytes,
    request_headers: policy.request_headers,
    response_headers: policy.response_headers,
    rewrites: policy.rewrites,
    redirect_allowed_hosts: policy.redirect_allowed_hosts,
    redirects: policy.redirects,
    cors: policy.cors,
    referer_check: policy.referer_check,
  }
}
