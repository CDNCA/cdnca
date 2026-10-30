import { ApiError, networkApiError, responseApiError } from './auth'

export interface ErrorPageAsset {
  id: string
  scope_id: string
  tenant_id?: string
  /** be-gap-2 (migration 509): display name given at upload; '' for an asset uploaded before names. */
  name: string
  mime_type: string
  size_bytes: number
  sha256: string
  status: string
  scan_status: string
  revision: number
  created_by: string
  created_at: string
  updated_at: string
  deleted_at?: string
}

export interface ErrorPageRule {
  id: string
  target: { kind: string; scope_id: string; site_id?: string }
  tenant_id?: string
  fields: {
    category: string
    match: { kind: string; from: number; to: number }
    asset_id: string
    enabled: boolean
  }
  priority: number
  revision: number
  deleted: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface ErrorPage<T> { items: T[]; next_cursor?: string }
export interface ErrorPageWrite<T> { value: T; replayed: boolean }
export interface ErrorPagePagination { limit?: number; cursor?: string }

export const errorPageScopeOverrideSlotKeys = [
  'http_400',
  'http_403',
  'http_502',
  'http_504',
  'traffic_exceeded',
  'package_expired',
  'site_locked',
  'domain_unconfigured',
  'node_ip_access',
  'connection_limit',
] as const

export type ErrorPageScopeOverrideSlotKey = typeof errorPageScopeOverrideSlotKeys[number]
export type ErrorPageScopeOverrideTarget =
  | { kind: 'node'; node_display_id: string; node_name: string; node_ip?: string }
  | { kind: 'region'; region: string }
export interface ErrorPageScopeOverrideItem {
  key: ErrorPageScopeOverrideSlotKey
  content?: string
}
export interface ErrorPageScopeOverride {
  display_id: string
  target: ErrorPageScopeOverrideTarget
  items: ErrorPageScopeOverrideItem[]
  revision: number
  updated_at: string
  deleted?: boolean
}
export interface ErrorPageScopeOverridePage {
  items: ErrorPageScopeOverride[]
  total: number
}
export type ErrorPageScopeOverrideTargetInput =
  | { kind: 'node'; node_display_id: string; region: '' }
  | { kind: 'region'; node_display_id: ''; region: string }
export interface ErrorPageScopeOverrideBindingInput {
  key: ErrorPageScopeOverrideSlotKey
  asset_id: string
}

export const errorPageSlotKeys = [
  'blacklist',
  'http_400',
  'http_403',
  'waf_block',
  'http_502',
  'http_504',
  'traffic_exceeded',
  'package_expired',
  'site_locked',
  'domain_unconfigured',
  'node_ip_access',
  'connection_limit',
] as const

export type ErrorPageSlotKey = typeof errorPageSlotKeys[number]
export interface ErrorPageSlotBinding {
  key: ErrorPageSlotKey
  asset_id?: string
  revision: number
  mime_type?: string
  size_bytes?: number
  sha256?: string
  updated_at?: string
  // Set on a bind/unbind that changed a slot a node page reads.
  publication?: ErrorPageSlotPublication
}
export interface ErrorPageSlotPublication { revision: number; queued_scopes: number }
export interface ErrorPageSlotPage { items: ErrorPageSlotBinding[] }
// errpage-content: source says whether content is the bound asset or the
// built-in page in effect; delivery what a node answers while unbound.
export type ErrorPageSlotDelivery = 'theme' | 'fallback' | 'none'
export interface ErrorPageSlotDocument {
  binding: ErrorPageSlotBinding
  content: string
  source: 'override' | 'builtin'
  delivery: ErrorPageSlotDelivery
}

export type ErrorPageEdgeCategory = 'origin_response' | 'edge_route' | 'edge_connect' | 'no_host' | 'unknown_site'
export type ErrorPageEdgeMime = 'text/html' | 'text/plain' | 'application/json'
export type ErrorPageEdgeMatch = { codes: [number] } | { ranges: [{ from: number; to: number }] }
export interface ErrorPageEdgeResource {
  mime_type: ErrorPageEdgeMime
  size_bytes: number
  sha256: string
  file: string
}
export interface ErrorPageEdgeRule {
  id: string
  category: ErrorPageEdgeCategory
  match: ErrorPageEdgeMatch
  resource: ErrorPageEdgeResource
}
export interface ErrorPageEdgeScope { rules: ErrorPageEdgeRule[] }
export interface ErrorPageEdgeSiteScope extends ErrorPageEdgeScope { site_key: string }
export interface ErrorPagePublicationPolicy {
  schema: 'cdnca.error-pages/v1'
  version: string
  revision: number
  global: ErrorPageEdgeScope
  sites: ErrorPageEdgeSiteScope[]
  // errorpagecontrol.Snapshot: the theme pinned at this revision; omitted before any theme activation.
  theme_package_sha256?: string
}
export interface ErrorPagePublicationSnapshot {
  policy: ErrorPagePublicationPolicy
  snapshot_sha256: string
  created_at: string
}

export type ErrorPagePublicationTargetRequest =
  | { kind: 'nodes'; node_ids: string[] }
  | { kind: 'line_group_snapshot'; snapshot_id: string; revision: number; resolver_sha256: string }

export interface ErrorPagePublicationRequest {
  target: ErrorPagePublicationTargetRequest
  health_check: {
    activation_timeout_ms: number
    observation_window_ms: number
    required_consecutive_successes: number
  }
  max_attempts: number
  deadline: string
}

export interface ErrorPagePublicationWriteMetadata {
  requestId: string
  correlationId?: string
  idempotencyKey: string
  traceparent: string
  taskId?: string
}

export type ErrorPagePublicationTarget =
  | { kind: 'explicit'; resolved_sha256: string }
  | { kind: 'resolver'; snapshot_id: string; revision: number; resolver_sha256: string; resolved_sha256: string }

export interface ErrorPagePublicationReceipt {
  tenant_id: string
  tenant_scope_id: string
  publication_id: string
  source_revision: number
  error_page_publication_revision: number
  config_version_id: string
  rollout_id: string
  artifact_sha256: string
  target: ErrorPagePublicationTarget
  node_count: number
  created_at: string
  replayed?: boolean
}

export interface ErrorPagePublicationRetryBinding {
  method: 'POST'
  path: string
  if_match: string
  idempotency_key: string
  body_sha256: string
}

export class ErrorPagePublicationOutcomeUnknown extends ApiError {
  readonly retry: ErrorPagePublicationRetryBinding

  constructor(requestId: string, retry: ErrorPagePublicationRetryBinding) {
    super('API request failed', 503, 'error_page_publication_outcome_unknown', requestId)
    this.retry = retry
  }
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const assetMimes = new Set(['text/html', 'text/plain', 'application/json'])
const assetStatuses = new Set(['initiated', 'staged', 'scan_failed', 'finalizing', 'ready', 'rejected', 'delete_pending', 'deleted', 'orphaned'])
const scanStatuses = new Set(['pending', 'passed', 'rejected', 'error'])
const edgeCategories = new Set(['origin_response', 'edge_route', 'edge_connect', 'no_host', 'unknown_site'])
const scopeOverrideSlotKeys = new Set<string>(errorPageScopeOverrideSlotKeys)
const slotKeys = new Set<string>(errorPageSlotKeys)
const digestPattern = /^[0-9a-f]{64}$/
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const taskPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const traceparentPattern = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/
const stableErrorCodePattern = /^[a-z][a-z0-9_]{0,63}$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return isRecord(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
}

function hasAllowedKeys(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  if (!isRecord(value)) return false
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function isPositiveInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1 && Number(value) <= maximum
}

function isCanonicalUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function isStatusCode(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 400 && Number(value) <= 599
}

function isEdgeMatch(value: unknown): value is ErrorPageEdgeMatch {
  if (hasExactKeys(value, ['codes'])) {
    return Array.isArray(value.codes) && value.codes.length === 1 && isStatusCode(value.codes[0])
  }
  if (!hasExactKeys(value, ['ranges']) || !Array.isArray(value.ranges) || value.ranges.length !== 1) return false
  const range = value.ranges[0]
  return hasExactKeys(range, ['from', 'to']) && isStatusCode(range.from) && isStatusCode(range.to)
}

function isEdgeResource(value: unknown): value is ErrorPageEdgeResource {
  return hasExactKeys(value, ['mime_type', 'size_bytes', 'sha256', 'file']) &&
    typeof value.mime_type === 'string' && assetMimes.has(value.mime_type) &&
    Number.isSafeInteger(value.size_bytes) && Number(value.size_bytes) >= 1 && Number(value.size_bytes) <= 1048576 &&
    typeof value.sha256 === 'string' && digestPattern.test(value.sha256) &&
    value.file === `sha256/${value.sha256}`
}

function isEdgeRule(value: unknown): value is ErrorPageEdgeRule {
  return hasExactKeys(value, ['id', 'category', 'match', 'resource']) &&
    typeof value.id === 'string' && value.id.length >= 1 && value.id.length <= 128 &&
    typeof value.category === 'string' && edgeCategories.has(value.category) &&
    isEdgeMatch(value.match) && isEdgeResource(value.resource)
}

function isEdgeScope(value: unknown): value is ErrorPageEdgeScope {
  return hasExactKeys(value, ['rules']) && Array.isArray(value.rules) &&
    value.rules.length <= 128 && value.rules.every(isEdgeRule)
}

function isEdgeSiteScope(value: unknown): value is ErrorPageEdgeSiteScope {
  return hasExactKeys(value, ['site_key', 'rules']) &&
    typeof value.site_key === 'string' && value.site_key.length >= 1 && value.site_key.length <= 128 &&
    Array.isArray(value.rules) && value.rules.length <= 128 && value.rules.every(isEdgeRule)
}

function isPublicationPolicy(value: unknown): value is ErrorPagePublicationPolicy {
  return hasAllowedKeys(value, ['schema', 'version', 'revision', 'global', 'sites'], ['theme_package_sha256']) &&
    (value.theme_package_sha256 === undefined ||
      typeof value.theme_package_sha256 === 'string' && digestPattern.test(value.theme_package_sha256)) &&
    value.schema === 'cdnca.error-pages/v1' && typeof value.version === 'string' && versionPattern.test(value.version) &&
    Number.isSafeInteger(value.revision) && Number(value.revision) >= 1 && isEdgeScope(value.global) &&
    Array.isArray(value.sites) && value.sites.length <= 256 && value.sites.every(isEdgeSiteScope)
}

function isPublicationSnapshot(value: unknown): value is ErrorPagePublicationSnapshot {
  return hasExactKeys(value, ['policy', 'snapshot_sha256', 'created_at']) && isPublicationPolicy(value.policy) &&
    typeof value.snapshot_sha256 === 'string' && digestPattern.test(value.snapshot_sha256) &&
    typeof value.created_at === 'string' && dateTimePattern.test(value.created_at) && Number.isFinite(Date.parse(value.created_at))
}

function isPublicationTargetRequest(value: unknown): value is ErrorPagePublicationTargetRequest {
  if (hasExactKeys(value, ['kind', 'node_ids']) && value.kind === 'nodes' && Array.isArray(value.node_ids)) {
    return value.node_ids.length >= 1 && value.node_ids.length <= 10_000 &&
      value.node_ids.every(isCanonicalUUID) && new Set(value.node_ids).size === value.node_ids.length
  }
  return hasExactKeys(value, ['kind', 'snapshot_id', 'revision', 'resolver_sha256']) &&
    value.kind === 'line_group_snapshot' && isCanonicalUUID(value.snapshot_id) &&
    isPositiveInteger(value.revision) && typeof value.resolver_sha256 === 'string' && digestPattern.test(value.resolver_sha256)
}

function isPublicationRequest(value: unknown): value is ErrorPagePublicationRequest {
  return hasExactKeys(value, ['target', 'health_check', 'max_attempts', 'deadline']) &&
    isPublicationTargetRequest(value.target) &&
    hasExactKeys(value.health_check, ['activation_timeout_ms', 'observation_window_ms', 'required_consecutive_successes']) &&
    isPositiveInteger(value.health_check.activation_timeout_ms, 300_000) &&
    isPositiveInteger(value.health_check.observation_window_ms, 300_000) &&
    isPositiveInteger(value.health_check.required_consecutive_successes, 100) &&
    isPositiveInteger(value.max_attempts, 10) && isDateTime(value.deadline)
}

function isPublicationTarget(value: unknown): value is ErrorPagePublicationTarget {
  if (hasExactKeys(value, ['kind', 'resolved_sha256']) && value.kind === 'explicit') {
    return typeof value.resolved_sha256 === 'string' && digestPattern.test(value.resolved_sha256)
  }
  return hasExactKeys(value, ['kind', 'snapshot_id', 'revision', 'resolver_sha256', 'resolved_sha256']) &&
    value.kind === 'resolver' && isCanonicalUUID(value.snapshot_id) && isPositiveInteger(value.revision) &&
    typeof value.resolver_sha256 === 'string' && digestPattern.test(value.resolver_sha256) &&
    typeof value.resolved_sha256 === 'string' && digestPattern.test(value.resolved_sha256)
}

function isPublicationReceipt(value: unknown, scopeId: string, publicationId?: string): value is ErrorPagePublicationReceipt {
  return hasAllowedKeys(value, [
    'tenant_id', 'tenant_scope_id', 'publication_id', 'source_revision', 'error_page_publication_revision',
    'config_version_id', 'rollout_id', 'artifact_sha256', 'target', 'node_count', 'created_at',
  ], ['replayed']) && isCanonicalUUID(value.tenant_id) && value.tenant_scope_id === scopeId &&
    isCanonicalUUID(value.publication_id) && (publicationId === undefined || value.publication_id === publicationId) &&
    isPositiveInteger(value.source_revision) && isPositiveInteger(value.error_page_publication_revision) &&
    isCanonicalUUID(value.config_version_id) && isCanonicalUUID(value.rollout_id) &&
    typeof value.artifact_sha256 === 'string' && digestPattern.test(value.artifact_sha256) &&
    isPublicationTarget(value.target) && isPositiveInteger(value.node_count) && isDateTime(value.created_at) &&
    (value.replayed === undefined || typeof value.replayed === 'boolean')
}

function isPublicationMetadata(value: unknown): value is ErrorPagePublicationWriteMetadata {
  return hasAllowedKeys(value, ['requestId', 'idempotencyKey', 'traceparent'], ['correlationId', 'taskId']) &&
    isCanonicalUUID(value.requestId) && typeof value.idempotencyKey === 'string' && idempotencyPattern.test(value.idempotencyKey) &&
    typeof value.traceparent === 'string' && traceparentPattern.test(value.traceparent) &&
    (value.correlationId === undefined || isCanonicalUUID(value.correlationId)) &&
    (value.taskId === undefined || typeof value.taskId === 'string' && taskPattern.test(value.taskId))
}

function isRetryBinding(value: unknown): value is ErrorPagePublicationRetryBinding {
  return hasExactKeys(value, ['method', 'path', 'if_match', 'idempotency_key', 'body_sha256']) &&
    value.method === 'POST' && typeof value.path === 'string' && typeof value.if_match === 'string' &&
    typeof value.idempotency_key === 'string' && typeof value.body_sha256 === 'string' && digestPattern.test(value.body_sha256)
}

export interface ErrorPageAssetContent {
  asset: ErrorPageAsset
  content: string
}

function isAssetContent(value: unknown): value is ErrorPageAssetContent {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    Object.keys(value).every((key) => key === 'asset' || key === 'content') &&
    isAsset((value as { asset?: unknown }).asset) && typeof (value as { content?: unknown }).content === 'string' &&
    (value as { content: string }).content.length <= 1048576
}

function isAsset(value: unknown): value is ErrorPageAsset {
  return isRecord(value) && typeof value.id === 'string' && typeof value.scope_id === 'string' &&
    typeof value.name === 'string' && value.name.length <= 128 &&
    typeof value.mime_type === 'string' && assetMimes.has(value.mime_type) && typeof value.size_bytes === 'number' && Number.isSafeInteger(value.size_bytes) && value.size_bytes >= 1 && value.size_bytes <= 1048576 &&
    typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256) && typeof value.status === 'string' && assetStatuses.has(value.status) && typeof value.scan_status === 'string' && scanStatuses.has(value.scan_status) &&
    Number.isSafeInteger(value.revision) && typeof value.created_by === 'string' &&
    typeof value.created_at === 'string' && typeof value.updated_at === 'string'
}

function isRule(value: unknown): value is ErrorPageRule {
  if (!isRecord(value) || !isRecord(value.target) || !isRecord(value.fields) ||
    typeof value.id !== 'string' || typeof value.target.kind !== 'string' || typeof value.target.scope_id !== 'string' ||
    typeof value.fields.category !== 'string' || !isRecord(value.fields.match) || typeof value.fields.asset_id !== 'string' ||
    typeof value.fields.enabled !== 'boolean') return false
  return typeof value.fields.match.kind === 'string' && Number.isSafeInteger(value.fields.match.from) &&
    Number.isSafeInteger(value.fields.match.to) && Number.isSafeInteger(value.priority) &&
    Number.isSafeInteger(value.revision) && typeof value.deleted === 'boolean' && typeof value.created_by === 'string' &&
    typeof value.created_at === 'string' && typeof value.updated_at === 'string'
}

function isPositiveDisplayID(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value)
}

function isScopeOverrideTarget(value: unknown): value is ErrorPageScopeOverrideTarget {
  if (!isRecord(value) || value.kind === 'node' && !hasAllowedKeys(value, ['kind', 'node_display_id', 'node_name'], ['node_ip']) ||
    value.kind === 'region' && !hasExactKeys(value, ['kind', 'region'])) return false
  if (value.kind === 'node') {
    return isPositiveDisplayID(value.node_display_id) && typeof value.node_name === 'string' &&
      value.node_name.length >= 1 && value.node_name.length <= 128 &&
      (value.node_ip === undefined || typeof value.node_ip === 'string' && value.node_ip.length >= 1 && value.node_ip.length <= 64)
  }
  return value.kind === 'region' && typeof value.region === 'string' && value.region.trim() === value.region &&
    value.region.length >= 1 && value.region.length <= 64
}

function isScopeOverrideItem(value: unknown): value is ErrorPageScopeOverrideItem {
  return hasAllowedKeys(value, ['key'], ['content']) && typeof value.key === 'string' && scopeOverrideSlotKeys.has(value.key) &&
    (value.content === undefined || typeof value.content === 'string' && value.content.length >= 1 && value.content.length <= 1048576)
}

function isScopeOverride(value: unknown): value is ErrorPageScopeOverride {
  if (!hasAllowedKeys(value, ['display_id', 'target', 'items', 'revision', 'updated_at'], ['deleted']) ||
    !isPositiveDisplayID(value.display_id) || !isScopeOverrideTarget(value.target) || !Array.isArray(value.items) ||
    value.items.length > errorPageScopeOverrideSlotKeys.length || !value.items.every(isScopeOverrideItem) ||
    new Set(value.items.map((item) => item.key)).size !== value.items.length || !isPositiveInteger(value.revision) ||
    !isDateTime(value.updated_at) || (value.deleted !== undefined && typeof value.deleted !== 'boolean')) return false
  return true
}

function isScopeOverridePage(value: unknown): value is ErrorPageScopeOverridePage {
  return hasExactKeys(value, ['items', 'total']) && Array.isArray(value.items) && value.items.length <= 10_000 &&
    value.items.every(isScopeOverride) && Number.isSafeInteger(value.total) && Number(value.total) === value.items.length
}

function isSlotPublication(value: unknown): value is ErrorPageSlotPublication {
  return hasExactKeys(value, ['revision', 'queued_scopes']) && isPositiveInteger(value.revision) &&
    typeof value.queued_scopes === 'number' && Number.isSafeInteger(value.queued_scopes) && value.queued_scopes >= 0
}

function isSlotBinding(value: unknown): value is ErrorPageSlotBinding {
  return hasAllowedKeys(value, ['key', 'revision'], ['asset_id', 'mime_type', 'size_bytes', 'sha256', 'updated_at', 'publication']) &&
    (value.publication === undefined || isSlotPublication(value.publication)) &&
    typeof value.key === 'string' && slotKeys.has(value.key) && typeof value.revision === 'number' && Number.isSafeInteger(value.revision) && value.revision >= 0 &&
    (value.asset_id === undefined || isCanonicalUUID(value.asset_id)) &&
    (value.mime_type === undefined || typeof value.mime_type === 'string' && assetMimes.has(value.mime_type)) &&
    (value.size_bytes === undefined || isPositiveInteger(value.size_bytes, 1048576)) &&
    (value.sha256 === undefined || typeof value.sha256 === 'string' && digestPattern.test(value.sha256)) &&
    (value.updated_at === undefined || isDateTime(value.updated_at))
}

function isSlotPage(value: unknown): value is ErrorPageSlotPage {
  return hasExactKeys(value, ['items']) && Array.isArray(value.items) && value.items.length === errorPageSlotKeys.length &&
    value.items.every(isSlotBinding) && new Set(value.items.map((item) => item.key)).size === value.items.length
}

function isSlotDocument(value: unknown): value is ErrorPageSlotDocument {
  return hasExactKeys(value, ['binding', 'content', 'source', 'delivery']) && isSlotBinding(value.binding) &&
    typeof value.content === 'string' && value.content.length <= 1048576 &&
    (value.source === 'override' || value.source === 'builtin') &&
    (value.delivery === 'theme' || value.delivery === 'fallback' || value.delivery === 'none')
}

function validScopeOverrideBindings(items: ErrorPageScopeOverrideBindingInput[]): boolean {
  return items.length >= 1 && items.length <= errorPageScopeOverrideSlotKeys.length &&
    new Set(items.map((item) => item.key)).size === items.length &&
    items.every((item) => scopeOverrideSlotKeys.has(item.key) && isCanonicalUUID(item.asset_id))
}

function validScopeOverrideTargetInput(target: ErrorPageScopeOverrideTargetInput): boolean {
  if (target.kind === 'node') return isPositiveDisplayID(target.node_display_id) && target.region === ''
  return target.node_display_id === '' && target.region.trim() === target.region && target.region.length >= 1 && target.region.length <= 64
}

function page<T>(validate: (value: unknown) => value is T) {
  return (value: unknown): value is ErrorPage<T> => isRecord(value) && Array.isArray(value.items) && value.items.every(validate) &&
    (value.next_cursor === undefined || typeof value.next_cursor === 'string')
}

function write<T>(validate: (value: unknown) => value is T) {
  return (value: unknown): value is ErrorPageWrite<T> => isRecord(value) && validate(value.value) && typeof value.replayed === 'boolean'
}

function invalidResponse(): ApiError { return new ApiError('Invalid error page response', 0, 'invalid_response') }
function invalidRequest(): ApiError { return new ApiError('Invalid error page request', 400, 'invalid_request') }

async function textSha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function publicationError(response: Response, expected?: ErrorPagePublicationRetryBinding): Promise<ApiError> {
  let body: unknown
  try { body = await response.json() } catch { return invalidResponse() }
  if (!hasExactKeys(body, ['error']) || !hasAllowedKeys(body.error, ['code', 'message', 'request_id'], ['retry']) ||
    typeof body.error.code !== 'string' || !stableErrorCodePattern.test(body.error.code) ||
    typeof body.error.message !== 'string' || !isCanonicalUUID(body.error.request_id)) return invalidResponse()
  if (body.error.code !== 'error_page_publication_outcome_unknown') {
    return new ApiError('API request failed', response.status, body.error.code, body.error.request_id)
  }
  if (response.status !== 503 || !expected || !isRetryBinding(body.error.retry) ||
    body.error.retry.method !== expected.method || body.error.retry.path !== expected.path ||
    body.error.retry.if_match !== expected.if_match || body.error.retry.idempotency_key !== expected.idempotency_key ||
    body.error.retry.body_sha256 !== expected.body_sha256) return invalidResponse()
  return new ErrorPagePublicationOutcomeUnknown(body.error.request_id, body.error.retry)
}

async function publicationRequest(
  token: string,
  path: string,
  scopeId: string,
  publicationId: string | undefined,
  init: RequestInit,
  retryBinding?: ErrorPagePublicationRetryBinding,
): Promise<ErrorPagePublicationReceipt> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}`, ...init.headers },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await publicationError(response, retryBinding)
  let value: unknown
  try { value = await response.json() } catch { throw invalidResponse() }
  if (!isPublicationReceipt(value, scopeId, publicationId)) throw invalidResponse()
  return value
}

async function request<T>(token: string, path: string, validate: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body !== undefined && !(init.body instanceof Blob) ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw invalidResponse() }
  if (!validate(value)) throw invalidResponse()
  return value
}

function writeHeaders(key: string, revision?: number): HeadersInit {
  return {
    'Idempotency-Key': key,
    'X-Request-ID': crypto.randomUUID(),
    'X-Trace-ID': crypto.randomUUID(),
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

function appendPagination(query: URLSearchParams, pagination?: ErrorPagePagination): void {
  if (!pagination) return
  if (pagination.limit !== undefined) {
    if (!Number.isSafeInteger(pagination.limit) || pagination.limit < 1 || pagination.limit > 100) {
      throw new ApiError('Invalid pagination limit', 400, 'validation')
    }
    query.set('limit', String(pagination.limit))
  }
  if (pagination.cursor !== undefined) {
    if (!pagination.cursor || pagination.cursor.length > 512) {
      throw new ApiError('Invalid pagination cursor', 400, 'validation')
    }
    query.set('cursor', pagination.cursor)
  }
}

const assetPath = '/v1/error-pages/assets'
const rulePath = '/v1/error-pages/rules'
const scopeOverridePath = '/v1/error-pages/scope-overrides'
const slotPath = '/v1/error-pages/slots'
const publicationSnapshotPath = '/v1/error-pages/publication-snapshot'

export const errorPagesApi = {
  listSlots(token: string): Promise<ErrorPageSlotPage> {
    return request(token, slotPath, isSlotPage)
  },
  getSlot(token: string, key: ErrorPageSlotKey): Promise<ErrorPageSlotDocument> {
    if (!slotKeys.has(key)) return Promise.reject(invalidRequest())
    return request(token, `${slotPath}/${encodeURIComponent(key)}`, isSlotDocument)
  },
  bindSlot(token: string, key: ErrorPageSlotKey, assetId: string, revision: number, operationKeyValue: string): Promise<ErrorPageWrite<ErrorPageSlotBinding>> {
    if (!slotKeys.has(key) || !isCanonicalUUID(assetId) || !Number.isSafeInteger(revision) || revision < 0) return Promise.reject(invalidRequest())
    return request(token, `${slotPath}/${encodeURIComponent(key)}`, write(isSlotBinding), {
      method: 'PUT', headers: writeHeaders(operationKeyValue, revision), body: JSON.stringify({ asset_id: assetId }),
    })
  },
  unbindSlot(token: string, key: ErrorPageSlotKey, revision: number, operationKeyValue: string): Promise<ErrorPageWrite<ErrorPageSlotBinding>> {
    if (!slotKeys.has(key) || !Number.isSafeInteger(revision) || revision < 0) return Promise.reject(invalidRequest())
    return request(token, `${slotPath}/${encodeURIComponent(key)}`, write(isSlotBinding), {
      method: 'DELETE', headers: writeHeaders(operationKeyValue, revision),
    })
  },
  listScopeOverrides(token: string): Promise<ErrorPageScopeOverridePage> {
    return request(token, scopeOverridePath, isScopeOverridePage)
  },
  getScopeOverride(token: string, displayId: string): Promise<ErrorPageScopeOverride> {
    if (!isPositiveDisplayID(displayId)) return Promise.reject(invalidRequest())
    return request(token, `${scopeOverridePath}/${displayId}`, isScopeOverride)
  },
  createScopeOverride(token: string, target: ErrorPageScopeOverrideTargetInput, items: ErrorPageScopeOverrideBindingInput[], key: string): Promise<ErrorPageWrite<ErrorPageScopeOverride>> {
    if (!validScopeOverrideTargetInput(target) || !validScopeOverrideBindings(items)) return Promise.reject(invalidRequest())
    return request(token, scopeOverridePath, write(isScopeOverride), {
      method: 'POST', headers: writeHeaders(key), body: JSON.stringify({ target, items }),
    })
  },
  updateScopeOverride(token: string, displayId: string, items: ErrorPageScopeOverrideBindingInput[], revision: number, key: string): Promise<ErrorPageWrite<ErrorPageScopeOverride>> {
    if (!isPositiveDisplayID(displayId) || !validScopeOverrideBindings(items) || !isPositiveInteger(revision)) return Promise.reject(invalidRequest())
    return request(token, `${scopeOverridePath}/${displayId}`, write(isScopeOverride), {
      method: 'PATCH', headers: writeHeaders(key, revision), body: JSON.stringify({ items }),
    })
  },
  deleteScopeOverride(token: string, displayId: string, revision: number, key: string): Promise<ErrorPageWrite<ErrorPageScopeOverride>> {
    if (!isPositiveDisplayID(displayId) || !isPositiveInteger(revision)) return Promise.reject(invalidRequest())
    return request(token, `${scopeOverridePath}/${displayId}`, write(isScopeOverride), {
      method: 'DELETE', headers: writeHeaders(key, revision),
    })
  },
  listAssets(token: string, scopeId: string, status?: string, pagination?: ErrorPagePagination): Promise<ErrorPage<ErrorPageAsset>> {
    const query = new URLSearchParams({ scope_id: scopeId })
    if (status) query.set('status', status)
    appendPagination(query, pagination)
    return request(token, `${assetPath}?${query}`, page(isAsset))
  },
  getAsset(token: string, assetId: string): Promise<ErrorPageAsset> {
    return request(token, `${assetPath}/${encodeURIComponent(assetId)}`, isAsset)
  },
  // A ready asset's body, to edit a site error page as text.
  getAssetContent(token: string, assetId: string): Promise<ErrorPageAssetContent> {
    return request(token, `${assetPath}/${encodeURIComponent(assetId)}/content`, isAssetContent)
  },
  initiateAsset(token: string, scopeId: string, mimeType: string, sizeBytes: number, sha256: string, key: string, name = ''): Promise<ErrorPageWrite<ErrorPageAsset>> {
    return request(token, `${assetPath}/initiate`, write(isAsset), {
      method: 'POST', headers: writeHeaders(key),
      body: JSON.stringify({ scope_id: scopeId, ...(name ? { name } : {}), mime_type: mimeType, size_bytes: sizeBytes, sha256 }),
    })
  },
  uploadAssetContent(token: string, assetId: string, body: Blob, mimeType: string, key: string): Promise<ErrorPageWrite<ErrorPageAsset>> {
    return request(token, `${assetPath}/${encodeURIComponent(assetId)}/content`, write(isAsset), {
      method: 'PUT', body, headers: { ...writeHeaders(key), 'Content-Type': mimeType },
    })
  },
  finalizeAsset(token: string, assetId: string, key: string): Promise<ErrorPageWrite<ErrorPageAsset>> {
    return request(token, `${assetPath}/${encodeURIComponent(assetId)}/finalize`, write(isAsset), { method: 'POST', headers: writeHeaders(key) })
  },
  deleteAsset(token: string, assetId: string, revision: number, key: string): Promise<ErrorPageWrite<ErrorPageAsset>> {
    return request(token, `${assetPath}/${encodeURIComponent(assetId)}`, write(isAsset), { method: 'DELETE', headers: writeHeaders(key, revision) })
  },
  listRules(token: string, scopeId: string, siteId?: string, pagination?: ErrorPagePagination): Promise<ErrorPage<ErrorPageRule>> {
    const query = new URLSearchParams({ scope_id: scopeId })
    if (siteId) query.set('site_id', siteId)
    appendPagination(query, pagination)
    return request(token, `${rulePath}?${query}`, page(isRule))
  },
  getRule(token: string, ruleId: string): Promise<ErrorPageRule> {
    return request(token, `${rulePath}/${encodeURIComponent(ruleId)}`, isRule)
  },
  createRule(token: string, input: Omit<ErrorPageRule, 'id' | 'priority' | 'revision' | 'deleted' | 'created_by' | 'created_at' | 'updated_at'>, key: string): Promise<ErrorPageWrite<ErrorPageRule>> {
    return request(token, rulePath, write(isRule), { method: 'POST', headers: writeHeaders(key), body: JSON.stringify(input) })
  },
  updateRule(token: string, ruleId: string, fields: ErrorPageRule['fields'], revision: number, key: string): Promise<ErrorPageWrite<ErrorPageRule>> {
    return request(token, `${rulePath}/${encodeURIComponent(ruleId)}`, write(isRule), { method: 'PATCH', headers: writeHeaders(key, revision), body: JSON.stringify(fields) })
  },
  deleteRule(token: string, ruleId: string, revision: number, key: string): Promise<ErrorPageWrite<ErrorPageRule>> {
    return request(token, `${rulePath}/${encodeURIComponent(ruleId)}`, write(isRule), { method: 'DELETE', headers: writeHeaders(key, revision) })
  },
  setRuleEnabled(token: string, ruleId: string, revision: number, enabled: boolean, key: string): Promise<ErrorPageWrite<ErrorPageRule>> {
    return request(token, `${rulePath}/${encodeURIComponent(ruleId)}/${enabled ? 'enable' : 'disable'}`, write(isRule), { method: 'POST', headers: writeHeaders(key, revision) })
  },
  getPublicationSnapshot(token: string): Promise<ErrorPagePublicationSnapshot> {
    return request(token, publicationSnapshotPath, isPublicationSnapshot)
  },
  async publishErrorPageConfiguration(token: string, scopeId: string, sourceRevision: number, input: ErrorPagePublicationRequest, metadata: ErrorPagePublicationWriteMetadata): Promise<ErrorPagePublicationReceipt> {
    if (!isCanonicalUUID(scopeId) || !isPositiveInteger(sourceRevision) || !isPublicationRequest(input) || !isPublicationMetadata(metadata)) throw invalidRequest()
    const path = `/v1/tenant-scopes/${encodeURIComponent(scopeId)}/error-page-publications`
    const body = JSON.stringify(input)
    const retryBinding: ErrorPagePublicationRetryBinding = {
      method: 'POST', path, if_match: `"${sourceRevision}"`, idempotency_key: metadata.idempotencyKey,
      body_sha256: await textSha256(body),
    }
    return publicationRequest(token, path, scopeId, undefined, {
      method: 'POST',
      body,
      headers: {
        'Content-Type': 'application/json',
        'If-Match': retryBinding.if_match,
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
        Traceparent: metadata.traceparent,
        ...(metadata.correlationId ? { 'X-Correlation-ID': metadata.correlationId } : {}),
        ...(metadata.taskId ? { 'X-Task-ID': metadata.taskId } : {}),
      },
    }, retryBinding)
  },
  getErrorPagePublication(token: string, scopeId: string, publicationId: string, requestId = crypto.randomUUID()): Promise<ErrorPagePublicationReceipt> {
    if (!isCanonicalUUID(scopeId) || !isCanonicalUUID(publicationId) || !isCanonicalUUID(requestId)) return Promise.reject(invalidRequest())
    const path = `/v1/tenant-scopes/${encodeURIComponent(scopeId)}/error-page-publications/${encodeURIComponent(publicationId)}`
    return publicationRequest(token, path, scopeId, publicationId, { method: 'GET', headers: { 'X-Request-ID': requestId } })
  },
}
