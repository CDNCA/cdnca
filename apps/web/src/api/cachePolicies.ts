import { ApiError, networkApiError, responseApiError } from './auth'

export type CachePolicyMode = 'disabled' | 'follow_origin' | 'override'
export type CacheQueryMode = 'preserve' | 'ignore' | 'include' | 'exclude'
// cachecontrol.BindingMode: inherit a shared definition or own a site override.
export type CachePolicyBindingMode = 'inherit' | 'override'
// cachecontrol.RuleAction (schema v2 only).
export type CacheRuleAction = 'cache' | 'no_cache'
export const cachePolicySchemaV2 = 2

export interface CachePolicyRule {
  order: number
  extensions?: string[]
  path_prefix?: string
  status_codes?: number[]
  // Schema v2: required on every rule. no_cache needs ttl_seconds and
  // browser_ttl_seconds 0; cache needs 0 <= browser_ttl_seconds <= ttl_seconds.
  action?: CacheRuleAction
  ttl_seconds: number
  browser_ttl_seconds?: number
  // Site runtime v2: a regular expression the path must also match,
  // and the response Content-Types the rule applies to (exact or "x/*").
  path_regex?: string
  content_types?: string[]
  // Schema v2 (edgeconfig.CacheRuleExtras): 单个路径,
  // 忽略 URL 参数, 分片回源 (absent = the policy's), 强制 CDN 缓存 (absent =
  // the policy's mode), 忽略 Vary, 不缓存条件. Omitted when unset.
  path_exact?: string
  ignore_query?: boolean
  slice_bytes?: number
  force_cache?: boolean
  ignore_vary?: boolean
  no_cache?: CacheNoCacheCondition[]
}

// 不缓存条件 sources (edgeconfig CacheCondition*); header needs a name.
export type CacheConditionSource = 'uri' | 'path' | 'client_ip' | 'scheme' | 'args' | 'host' | 'header'
export const cacheConditionSources: CacheConditionSource[] = ['uri', 'path', 'client_ip', 'scheme', 'args', 'host', 'header']
export const cacheNoCacheConditionsMax = 8

export interface CacheNoCacheCondition {
  source: CacheConditionSource
  name?: string
  pattern: string
}

export interface CachePolicyDocument {
  // Present (always 2) only on a schema v2 document; absent means v1.
  schema_version?: typeof cachePolicySchemaV2
  mode: CachePolicyMode
  rules: CachePolicyRule[]
  query_mode: CacheQueryMode
  query_names: string[]
  vary_headers: string[]
  disk_quota_bytes: number
  // Site runtime v2 extensions (omitted when off/zero).
  stale_if_error?: boolean
  background_update?: boolean
  min_object_bytes?: number
  max_object_bytes?: number
  slice_bytes?: number
}

export interface CachePolicyView {
  site_id: string
  revision: number
  binding_mode: CachePolicyBindingMode
  definition_id: string
  definition_revision: number
  document: CachePolicyDocument
  created_by_user_id: string
  request_id: string
  created_at: string
}

export interface CachePolicyPage {
  items: CachePolicyView[]
  next_cursor?: string
}

export interface PublishCachePolicyInput {
  expected_revision: number
  document: CachePolicyDocument
}

export interface CachePolicyHistoryParams {
  limit?: number
  cursor?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const extensionPattern = /^\.[a-z0-9][a-z0-9_+-]{0,15}$/
const queryNamePattern = /^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$/
const headerNamePattern = /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/
// edgeconfig cacheContentTypePattern: type/subtype or a prefix ending in "*"
const contentTypePattern = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}(?:\/[a-z0-9!#$&^_.+-]{0,64})?\*?$/
export const cachePathRegexMaxLength = 256
export const cacheContentTypesMax = 16
export const cacheConditionalRulesMax = 8
const policyModes = new Set<CachePolicyMode>(['disabled', 'follow_origin', 'override'])
const queryModes = new Set<CacheQueryMode>(['preserve', 'ignore', 'include', 'exclude'])
const bindingModes = new Set<CachePolicyBindingMode>(['inherit', 'override'])
const ruleActions = new Set<CacheRuleAction>(['cache', 'no_cache'])
const maxTTLSeconds = 31_536_000
const forbiddenVaryHeaders = new Set(['authorization', 'cookie', 'proxy-authorization', 'set-cookie'])
const documentKeys = ['mode', 'rules', 'query_mode', 'query_names', 'vary_headers', 'disk_quota_bytes']
const extensionKeys = ['stale_if_error', 'background_update', 'min_object_bytes', 'max_object_bytes', 'slice_bytes']
// Bounds of the extensions (edgeconfig.ValidateCachePolicyExtensions).
export const cacheSliceBytesRange = { min: 256 << 10, max: 64 << 20, step: 64 << 10 }
export const cacheMaxObjectBytesLimit = 2 ** 40
// cachecontrolhttp.PolicyView (all fields always present).
const viewKeys = ['site_id', 'revision', 'binding_mode', 'definition_id', 'definition_revision', 'document', 'created_by_user_id', 'request_id', 'created_at']

function invalidResponse(status: number): ApiError {
  return new ApiError('Cache policy API response was invalid', status, 'invalid_response')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => key in value) && Object.keys(value).every((key) => allowed.has(key))
}

function isInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function isUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 64 && !Number.isNaN(Date.parse(value))
}

function isMetadata(value: unknown): value is string {
  return typeof value === 'string' && metadataPattern.test(value)
}

// parseRule mirrors cachecontrol decodeRuleJSON/normalizeRule: v1 rules carry
// no action or browser TTL; v2 rules carry both (validate.go:100-108, 460-477).
function parseRule(value: unknown, expectedOrder: number, v2: boolean): CachePolicyRule | undefined {
  const conditions = ['extensions', 'path_prefix', 'status_codes', 'path_regex', 'content_types',
    ...(v2 ? ruleExtraKeys : [])]
  if (!isRecord(value) || value.order !== expectedOrder) return undefined
  if (v2) {
    if (!hasExactKeys(value, ['order', 'action', 'ttl_seconds', 'browser_ttl_seconds'], conditions) ||
      !ruleActions.has(value.action as CacheRuleAction)) return undefined
    if (value.action === 'cache'
      ? !isInteger(value.ttl_seconds, 1, maxTTLSeconds) || !isInteger(value.browser_ttl_seconds, 0, value.ttl_seconds)
      : value.ttl_seconds !== 0 || value.browser_ttl_seconds !== 0) return undefined
  } else if (!hasExactKeys(value, ['order', 'ttl_seconds'], conditions) || !isInteger(value.ttl_seconds, 1, maxTTLSeconds)) {
    return undefined
  }

  if (value.extensions !== undefined && (!Array.isArray(value.extensions) || value.extensions.length > 32 ||
    !value.extensions.every((item) => typeof item === 'string' && extensionPattern.test(item)) ||
    new Set(value.extensions).size !== value.extensions.length)) return undefined
  if (value.path_prefix !== undefined && (typeof value.path_prefix !== 'string' ||
    !value.path_prefix.startsWith('/') || !value.path_prefix.endsWith('/') || value.path_prefix.length > 8192)) return undefined
  if (value.status_codes !== undefined && (!Array.isArray(value.status_codes) || value.status_codes.length > 32 ||
    !value.status_codes.every((item) => isInteger(item, 100, 599)) ||
    new Set(value.status_codes).size !== value.status_codes.length)) return undefined
  if (value.path_regex !== undefined && (typeof value.path_regex !== 'string' || value.path_regex.length === 0 ||
    value.path_regex.length > cachePathRegexMaxLength)) return undefined
  if (value.content_types !== undefined && !validContentTypes(value.content_types)) return undefined
  if (!validRuleExtras(value)) return undefined
  return value as unknown as CachePolicyRule
}

// ruleExtraFields: a rule's set per-rule settings in wire order (unset ones
// omitted, as the server marshals them).
export function ruleExtraFields(rule: CachePolicyRule): Partial<CachePolicyRule> {
  return {
    ...(rule.path_exact ? { path_exact: rule.path_exact } : {}),
    ...(rule.ignore_query ? { ignore_query: true } : {}),
    ...(rule.slice_bytes === undefined ? {} : { slice_bytes: rule.slice_bytes }),
    ...(rule.force_cache === undefined ? {} : { force_cache: rule.force_cache }),
    ...(rule.ignore_vary ? { ignore_vary: true } : {}),
    ...(rule.no_cache?.length ? { no_cache: rule.no_cache.map((item) => ({ ...item })) } : {}),
  }
}

const ruleExtraKeys = ['path_exact', 'ignore_query', 'slice_bytes', 'force_cache', 'ignore_vary', 'no_cache']
const conditionNamePattern = /^[a-z0-9][a-z0-9-]{0,63}$/

// validRuleExtras mirrors edgeconfig.ValidateCacheRuleExtras (the server
// checks the regular expressions' backtracking bounds).
export function validRuleExtras(value: Record<string, unknown>): boolean {
  if (value.path_exact !== undefined && (typeof value.path_exact !== 'string' || !validExactPath(value.path_exact) ||
    value.path_prefix)) return false
  if (value.ignore_query !== undefined && typeof value.ignore_query !== 'boolean') return false
  if (value.force_cache !== undefined && typeof value.force_cache !== 'boolean') return false
  if (value.ignore_vary !== undefined && typeof value.ignore_vary !== 'boolean') return false
  if (value.slice_bytes !== undefined && (!isInteger(value.slice_bytes, 0, cacheSliceBytesRange.max) ||
    value.slice_bytes !== 0 && (value.slice_bytes < cacheSliceBytesRange.min || value.slice_bytes % cacheSliceBytesRange.step !== 0))) return false
  if (value.no_cache !== undefined && (!Array.isArray(value.no_cache) || value.no_cache.length === 0 ||
    value.no_cache.length > cacheNoCacheConditionsMax || !value.no_cache.every((item) => isRecord(item) &&
      hasExactKeys(item, ['source', 'pattern'], ['name']) &&
      cacheConditionSources.includes(item.source as CacheConditionSource) &&
      typeof item.pattern === 'string' && item.pattern.length > 0 && item.pattern.length <= cachePathRegexMaxLength &&
      (item.source === 'header') === (item.name !== undefined) &&
      (item.name === undefined || typeof item.name === 'string' && conditionNamePattern.test(item.name))))) return false
  return true
}

// validExactPath: edgeconfig.ValidCacheExactPath.
export function validExactPath(value: string): boolean {
  return value.startsWith('/') && value.length <= 2048 && !/[?#\\%\s]/.test(value) && !value.includes('//') &&
    /^[\x21-\x7e]+$/.test(value) && !value.slice(1).split('/').some((part) => part === '.' || part === '..')
}

function parseDocument(value: unknown): CachePolicyDocument | undefined {
  // PolicyDocument.MarshalJSON emits schema_version only for v2 (validate.go:131-135).
  const v2 = isRecord(value) && 'schema_version' in value
  if (!isRecord(value) || v2 && value.schema_version !== cachePolicySchemaV2 ||
    !hasExactKeys(value, documentKeys, [...extensionKeys, ...(v2 ? ['schema_version'] : [])]) || !validExtensions(value) ||
    !policyModes.has(value.mode as CachePolicyMode) || !Array.isArray(value.rules) || value.rules.length > 100 ||
    !queryModes.has(value.query_mode as CacheQueryMode) || !Array.isArray(value.query_names) ||
    value.query_names.length > 64 || !value.query_names.every((name) => typeof name === 'string' && queryNamePattern.test(name)) ||
    new Set(value.query_names).size !== value.query_names.length || !Array.isArray(value.vary_headers) ||
    value.vary_headers.length > 16 || !value.vary_headers.every((name) => typeof name === 'string' &&
      headerNamePattern.test(name) && name !== '*' && !forbiddenVaryHeaders.has(name)) ||
    new Set(value.vary_headers).size !== value.vary_headers.length ||
    !isInteger(value.disk_quota_bytes, 0, 17_592_186_044_416)) return undefined

  if (!value.rules.every((rule, index) => parseRule(rule, index + 1, v2) !== undefined)) return undefined
  if ((value.query_mode === 'preserve' || value.query_mode === 'ignore') && value.query_names.length !== 0 ||
    (value.query_mode === 'include' || value.query_mode === 'exclude') && value.query_names.length === 0) return undefined
  if (value.mode === 'disabled' && (value.rules.length !== 0 || value.disk_quota_bytes !== 0) ||
    value.mode === 'follow_origin' && (value.rules.length !== 0 || value.disk_quota_bytes < 67_108_864) ||
    value.mode === 'override' && (value.rules.length === 0 || value.disk_quota_bytes < 67_108_864)) return undefined
  return value as unknown as CachePolicyDocument
}

// validContentTypes mirrors edgeconfig validateCacheContentTypes (lower case,
// sorted, unique, exact type/subtype or a prefix ending in "*").
export function validContentTypes(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.length <= cacheContentTypesMax &&
    value.every((item, index) => typeof item === 'string' && contentTypePattern.test(item) &&
      (item.endsWith('*') || item.includes('/') && !item.endsWith('/')) &&
      (index === 0 || (value[index - 1] as string) < item))
}

// normalizeContentTypes: lower case, trimmed, unique, sorted (the server's
// NormalizeCacheContentTypes order).
export function normalizeContentTypes(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean))].sort()
}

// validExtensions mirrors edgeconfig.ValidateCachePolicyExtensions.
export function validExtensions(value: Partial<CachePolicyDocument>): boolean {
  const stale = value.stale_if_error ?? false
  const background = value.background_update ?? false
  const min = value.min_object_bytes ?? 0
  const max = value.max_object_bytes ?? 0
  const slice = value.slice_bytes ?? 0
  if (typeof stale !== 'boolean' || typeof background !== 'boolean' || !isInteger(min, 0, cacheMaxObjectBytesLimit) ||
    !isInteger(max, 0, cacheMaxObjectBytesLimit) || !isInteger(slice, 0)) return false
  if (background && !stale) return false
  if (max !== 0 && min >= max) return false
  if (slice !== 0 && (slice < cacheSliceBytesRange.min || slice > cacheSliceBytesRange.max || slice % cacheSliceBytesRange.step !== 0)) return false
  if (value.mode === 'disabled' && (stale || background || min !== 0 || max !== 0 || slice !== 0)) return false
  return true
}

function parseView(value: unknown, status: number, expectedSiteID: string, expectedRevision?: number): CachePolicyView {
  if (!isRecord(value) || !hasExactKeys(value, viewKeys) || value.site_id !== expectedSiteID ||
    !isUUID(value.site_id) || !isInteger(value.revision, 1) ||
    expectedRevision !== undefined && value.revision !== expectedRevision ||
    !bindingModes.has(value.binding_mode as CachePolicyBindingMode) || !isUUID(value.definition_id) ||
    !isInteger(value.definition_revision, 1) ||
    parseDocument(value.document) === undefined || !isUUID(value.created_by_user_id) ||
    !isMetadata(value.request_id) || !isTimestamp(value.created_at)) throw invalidResponse(status)
  return value as unknown as CachePolicyView
}

function parsePage(
  value: unknown,
  status: number,
  siteID: string,
  limit: number,
): CachePolicyPage {
  if (!isRecord(value) || !hasExactKeys(value, ['items'], ['next_cursor']) || !Array.isArray(value.items) ||
    value.items.length > limit || value.next_cursor !== undefined &&
    (typeof value.next_cursor !== 'string' || value.next_cursor.length === 0 || value.next_cursor.length > 4096 || value.items.length === 0)) {
    throw invalidResponse(status)
  }
  const items = value.items.map((item) => parseView(item, status, siteID))
  if (new Set(items.map((item) => item.revision)).size !== items.length ||
    items.some((item, index) => index > 0 && item.revision >= items[index - 1]!.revision)) throw invalidResponse(status)
  return { items, ...(typeof value.next_cursor === 'string' ? { next_cursor: value.next_cursor } : {}) }
}

function requestID(action: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `cache-policy-${action}-${suffix}`
}

async function request(
  accessToken: string,
  path: string,
  action: string,
  init: RequestInit = {},
): Promise<{ value: unknown; status: number }> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID(action),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  try {
    return { value: await response.json(), status: response.status }
  } catch {
    throw invalidResponse(response.status)
  }
}

function policyPath(siteID: string, tenantScopeID?: string): string {
  // A platform administrator addresses the site's tenant scope on the admin
  // route; a tenant session the session's own.
  return `${tenantScopeID ? '/v1/admin' : '/v1'}/cache-policies/${encodeURIComponent(siteID)}`
}

function withScope(path: string, tenantScopeID?: string): string {
  if (!tenantScopeID) return path
  return `${path}${path.includes('?') ? '&' : '?'}scope_id=${encodeURIComponent(tenantScopeID)}`
}

export const cachePoliciesApi = {
  async get(accessToken: string, siteID: string, tenantScopeID?: string): Promise<CachePolicyView> {
    const response = await request(accessToken, withScope(policyPath(siteID, tenantScopeID), tenantScopeID), 'get')
    return parseView(response.value, response.status, siteID)
  },

  async history(
    accessToken: string,
    siteID: string,
    params: CachePolicyHistoryParams,
    tenantScopeID?: string,
  ): Promise<CachePolicyPage> {
    const query = new URLSearchParams()
    if (params.limit !== undefined) query.set('limit', String(params.limit))
    if (params.cursor !== undefined) query.set('cursor', params.cursor)
    const response = await request(
      accessToken,
      withScope(`${policyPath(siteID, tenantScopeID)}/revisions${query.size ? `?${query}` : ''}`, tenantScopeID),
      'history',
    )
    return parsePage(response.value, response.status, siteID, params.limit ?? 50)
  },

  async getRevision(accessToken: string, siteID: string, revision: number, tenantScopeID?: string): Promise<CachePolicyView> {
    const response = await request(
      accessToken,
      withScope(`${policyPath(siteID, tenantScopeID)}/revisions/${encodeURIComponent(String(revision))}`, tenantScopeID),
      'revision',
    )
    return parseView(response.value, response.status, siteID, revision)
  },

  async publish(
    accessToken: string,
    siteID: string,
    input: PublishCachePolicyInput,
    idempotencyKey: string,
    serializedBody?: string,
    tenantScopeID?: string,
  ): Promise<CachePolicyView> {
    // A v2 document keeps schema_version and every rule's action and browser
    // TTL (the server requires them, validate.go:161-169, 467); v1 sends neither.
    const v2 = input.document.schema_version === cachePolicySchemaV2
    const canonicalBody = JSON.stringify({
      expected_revision: input.expected_revision,
      document: {
        ...(v2 ? { schema_version: cachePolicySchemaV2 } : {}),
        mode: input.document.mode,
        rules: input.document.rules.map((rule) => ({
          order: rule.order,
          ...(rule.extensions === undefined ? {} : { extensions: rule.extensions }),
          ...(rule.path_prefix === undefined ? {} : { path_prefix: rule.path_prefix }),
          ...(rule.status_codes === undefined ? {} : { status_codes: rule.status_codes }),
          ...(v2 ? { action: rule.action ?? 'cache' } : {}),
          ttl_seconds: rule.ttl_seconds,
          ...(v2 ? { browser_ttl_seconds: rule.browser_ttl_seconds ?? 0 } : {}),
          ...(rule.path_regex ? { path_regex: rule.path_regex } : {}),
          ...(rule.content_types?.length ? { content_types: rule.content_types } : {}),
          ...ruleExtraFields(rule),
        })),
        query_mode: input.document.query_mode,
        query_names: input.document.query_names,
        vary_headers: input.document.vary_headers,
        disk_quota_bytes: input.document.disk_quota_bytes,
        ...(input.document.stale_if_error ? { stale_if_error: true } : {}),
        ...(input.document.background_update ? { background_update: true } : {}),
        ...(input.document.min_object_bytes ? { min_object_bytes: input.document.min_object_bytes } : {}),
        ...(input.document.max_object_bytes ? { max_object_bytes: input.document.max_object_bytes } : {}),
        ...(input.document.slice_bytes ? { slice_bytes: input.document.slice_bytes } : {}),
      },
    })
    if (serializedBody !== undefined && serializedBody !== canonicalBody) {
      throw new ApiError('Cache policy request body was invalid', 400, 'invalid_request')
    }
    const response = await request(accessToken, withScope(policyPath(siteID, tenantScopeID), tenantScopeID), 'publish', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: canonicalBody,
    })
    return parseView(response.value, response.status, siteID, input.expected_revision + 1)
  },

}
