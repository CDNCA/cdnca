import type { AnalyticsAudience } from './analytics'
import { ApiError, networkApiError, responseApiError } from './auth'

export interface AnalyticsLogFilters {
  from: string
  to: string
  tenantId?: string
  siteId?: string
  host?: string
  nodeId?: string
  clientIp?: string
  uriPath?: string
  /** FX29/NF17: how uriPath matches; omitted means exact. */
  uriPathMatch?: 'exact' | 'prefix'
  statusCode?: number
  countryCode?: string
  carrier?: string
  /** Block events only: one action; omitted lists every hit the WAF overview counts. */
  action?: 'block' | 'challenge' | 'log' | 'temporary_ban'
  /** Block events only: one event type (waf, cc, ...). */
  eventType?: string
  method?: string
  protocol?: string
  cacheStatus?: string
  upstreamResult?: string
  contentType?: string
  userAgent?: string
  requestBytesMin?: number
  requestBytesMax?: number
  responseBytesMin?: number
  responseBytesMax?: number
  ja4?: string
  originConnectUsMin?: number
  originConnectUsMax?: number
  originFirstByteUsMin?: number
  originFirstByteUsMax?: number
  originTotalUsMin?: number
  originTotalUsMax?: number
}

export type AdminAnalyticsLogFilters = AnalyticsLogFilters

export interface AnalyticsLogPageMeta {
  from: string
  to: string
  timezone: 'UTC'
  snapshot_at?: string
  next_cursor?: string
  consistency: 'snapshot'
  replacement_consistency: 'latest_event_id_at_snapshot'
  pagination: 'keyset'
}

/**
 * The client address in the control plane's IP intelligence library, looked
 * up when the page is served (G3-d). Absent without a library or for
 * an unknown address; absent fields are unknown.
 */
export interface ClientIPIntel {
  carrier?: string
  idc?: 'idc:cn' | 'idc:global'
  asn?: number
  country?: string
  province?: string
  province_name?: string
  city?: string
  city_name?: string
  revision: number
}

interface CommonLogEvent {
  event_id: string
  occurred_at: string
  site_id: string
  node_id: string
  request_id: string
  trace_id: string
  config_version_id: string
  host: string
  uri_path: string
  client_ip: string
  country_code: string
  carrier: string
  status_code: number
  request_bytes: number
  response_bytes: number
  task_id: string | null
  installation_id: string
  request_headers: Record<string, string>
  response_headers: Record<string, string>
  request_body: Record<string, unknown> | null
  response_body: Record<string, unknown> | null
  ja4: string | null
  origin_connect_us: number | null
  origin_first_byte_us: number | null
  origin_total_us: number | null
  ip_intel?: ClientIPIntel
}

export interface AccessLogEvent extends CommonLogEvent {
  /** 平台视角：节点名称（节点已删除时为空串）；租户视角没有此字段。 */
  node_name?: string
  listen_port: number
  method: string
  protocol: string
  cache_status: string
  /** 回源诊断码（no_host/config_mismatch/timeout…），不是地址。 */
  upstream_result: string
  /** 回源地址（$upstream_addr，≤64 字节）；未回源、平台未勾选或 CH 028 之前的事件为空串。 */
  upstream_addr: string
  duration_us: number
}

export interface BlockLogEvent extends CommonLogEvent {
  event_type: string
  action: string
  severity: string
  rule_id: string
  /** Attack evidence (WAF / ACL events); "" when not recorded. */
  policy_id: string
  detector: string
  matched: string
  user_agent: string
  request_body_excerpt: string
  /** Requests the event stands for: a CC challenge page / 429 is logged once per minute with its count; otherwise 1. */
  count: number
  /** Query as the node logged it (no "?"): sensitive values are ***, at most 512 bytes; "" for none. */
  uri_query: string
  /** Domain of site_id; "" when unknown. */
  site_domain: string
  /** Name of rule_id in the deciding policy; "" for a policy default, managed / CRS rule or a deleted policy. */
  rule_name: string
}

export interface BlockEdgeProgress {
  candidate_id: string
  state: 'claimed' | 'canary' | 'expanding' | 'healthy' | 'failed' | 'cancelled' | 'expired' | 'promoted'
  total_nodes: number
  ready_nodes: number
  failed_nodes: number
  /** Nodes that ignored the unlock as an old release (they already run a newer revision); not failed. */
  superseded_nodes: number
}

export interface CurrentBlock {
  id: string
  tenant_id: string
  site_id: string
  site_display_id: number
  domain: string
  position: string
  policy_id: string
  policy_version: number
  cidr: string
  reason_code: 'acl_policy_block'
  blocked_at: string
  unlockable: boolean
  edge_progress?: BlockEdgeProgress
}

export interface BlockHistory {
  id: string
  block_id: string
  tenant_id: string
  site_id: string
  site_display_id: number
  domain: string
  position: string
  policy_id: string
  cidr: string
  reason_code: 'false_positive_confirmed'
  result_code: 'recovery_claimed' | 'recovery_replayed'
  auto_unlock: boolean
  requested_at: string
  unlocked_at: string | null
  edge_progress: BlockEdgeProgress
}

export interface SiteBlacklistCount {
  tenant_id: string
  site_id: string
  site_display_id: number
  domain: string
  count: number
}

export interface BlockStatePage<T> {
  data: T[]
  total_count: number
  snapshot_at: string
}

export interface BlockUnlockResult {
  block_id: string
  candidate_id: string
  progress: BlockEdgeProgress['state']
  reason_code: 'recovery_claimed' | 'recovery_replayed'
  replayed: boolean
}

export interface BlockStateFilters {
  tenantId?: string
  siteId?: string
  policyId?: string
  cidr?: string
  limit?: number
  offset?: number
  /** Epoch seconds; only the block-history endpoint narrows by occurrence window. */
  start?: number
  end?: number
}

export type AdminBlockStateFilters = BlockStateFilters

export interface BlockUnlockInput {
  blockId: string
  idempotencyKey: string
  tenantId?: string
}

export type AdminBlockUnlockInput = BlockUnlockInput & { tenantId: string }

export type CCCoordinationStateName = 'block_pending' | 'blocked' | 'release_pending' | 'failed'
export type CCCoordinationReason =
  | 'cc_cross_node_threshold_reached'
  | 'cc_coordination_dependency_unavailable'
  | 'false_positive_confirmed'

export interface CCCoordinationState {
  id: string
  tenant_scope_id: string
  tenant_id: string
  site_id: string
  source_cc_policy_id: string
  rule_id: string
  client_cidr: string
  host: string
  path: string
  method: string
  listen_port: number
  protocol: 'http' | 'https'
  request_class: 'standard'
  generation: number
  state: CCCoordinationStateName
  reason_code: CCCoordinationReason
  hit_count: number
  node_count: number
  current_policy_version: number
  lkg_policy_version: number
  expires_at: string
  release_hold_until: string
  updated_at: string
}

export interface CCCoordinationStatePage {
  items: CCCoordinationState[]
}

export interface CCCoordinationFilters {
  siteId?: string
  tenantId?: string
  limit?: number
}

export type AdminCCCoordinationFilters = CCCoordinationFilters

export interface CCCoordinationReleaseInput {
  stateId: string
  siteId: string
  expectedGeneration: number
  idempotencyKey: string
  requestId: string
  tenantId?: string
}

export type AdminCCCoordinationReleaseInput = CCCoordinationReleaseInput & { tenantId: string }

export interface CCCoordinationReleaseResult {
  state: CCCoordinationState
  replayed: boolean
}

export interface AnalyticsLogPage<T> {
  data: T[]
  meta: AnalyticsLogPageMeta
}

export type AnalyticsLogExportStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface AnalyticsLogExport {
  id: string
  status: AnalyticsLogExportStatus
  reason: string
  snapshot_at: string | null
  row_count: number | null
  byte_count: number | null
  sha256?: string
  created_at: string
  expires_at: string | null
  downloadable: boolean
  /** LOG-02：申请时服务端冻结的原查询条件（字段同创建请求）；null 为存储版本不可识别。 */
  filter: AnalyticsLogExportFilter | null
}

/** 导出申请的原查询条件，键与创建请求 body.filter 相同。 */
export interface AnalyticsLogExportFilter {
  from: string
  to: string
  [key: string]: string | number
}

export interface AnalyticsLogExportGrant {
  export_id: string
  token: string
  expires_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const dateTimePattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const maximumWindowMilliseconds = 31 * 24 * 60 * 60 * 1000
const maximumCapturedHeaders = 128
const maximumCapturedHeaderNameBytes = 128
const maximumCapturedHeaderValueBytes = 16 << 10
const maximumCapturedBodyBytes = 1 << 20
const maximumCapturedBodyDepth = 8
const maximumCapturedBodyNodes = 2048
const maximumCapturedBodyKeyBytes = 128
const maximumCapturedBodyValueBytes = 64 << 10
const redactedCaptureValue = '[REDACTED]'
const captureEncoder = new TextEncoder()
const sensitiveCaptureParts = new Set([
  'authorization', 'cookie', 'password', 'passwd', 'token', 'key', 'apikey', 'secret',
  'certificate', 'cert', 'privatekey', 'setcookie',
])

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('Analytics log request was invalid', 400, 'analytics_logs_invalid_request')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const keys = Object.keys(value)
  return required.every((key) => key in value) && keys.every((key) => required.includes(key) || optional.includes(key))
}

function isDateTime(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = dateTimePattern.exec(value)
  if (!match || !Number.isFinite(Date.parse(value))) return false
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number)
  const local = new Date(0)
  local.setUTCFullYear(year, month - 1, day)
  local.setUTCHours(hour, minute, second, 0)
  return year > 0 && local.getUTCFullYear() === year && local.getUTCMonth() === month - 1 &&
    local.getUTCDate() === day && local.getUTCHours() === hour && local.getUTCMinutes() === minute &&
    local.getUTCSeconds() === second
}

function isUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function isIPAddress(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) return false
  if (!value.includes(':')) {
    const parts = value.split('.')
    return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
  }
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith('[')
  } catch {
    return false
  }
}

function isText(value: unknown, maximum: number, allowEmpty = true): value is string {
  return typeof value === 'string' && value.length <= maximum && (allowEmpty || value.length > 0)
}

function isURIPathFilter(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 4096 || !value.startsWith('/') || value.trim() !== value ||
    value.includes('?') || value.includes('#')) return false
  return !Array.from(value).some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f)
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isCIDR(value: unknown): value is string {
  if (typeof value !== 'string' || value !== value.toLowerCase()) return false
  const parts = value.split('/')
  if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1]!)) return false
  const address = parts[0]!
  const prefix = Number(parts[1])
  if (!isIPAddress(address) || !Number.isInteger(prefix)) return false
  if (!address.includes(':')) {
    if (prefix < 0 || prefix > 32) return false
    const numeric = address.split('.').reduce((result, part) => (result << 8n) | BigInt(part), 0n)
    const hostBits = BigInt(32 - prefix)
    const mask = prefix === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << hostBits) - 1n)
    return (numeric & mask) === numeric
  }
  if (prefix < 0 || prefix > 128 || address.includes('%')) return false
  try {
    return new URL(`http://[${address}]/`).hostname.slice(1, -1) === address
  } catch {
    return false
  }
}

function isNullableText(value: unknown, maximum: number): value is string | null {
  return value === null || isText(value, maximum)
}

function captureBytes(value: string): number {
  return captureEncoder.encode(value).byteLength
}

export function isSensitiveAnalyticsCaptureName(value: string): boolean {
  const tokenized = value.replace(/([a-z\d])([A-Z])|([A-Z])([A-Z][a-z])/g, '$1$3 $2$4').toLowerCase()
  const parts = tokenized.split(/[-_.\s]+|\[|\]/).filter(Boolean)
  return parts.some((part) => sensitiveCaptureParts.has(part)) || tokenized.includes('authorization')
}

function isCapturedHeaderName(value: string): boolean {
  return captureBytes(value) <= maximumCapturedHeaderNameBytes && /^[!#$%&'*+\-.^_`|~\dA-Za-z]+$/.test(value)
}

function isCapturedHeaders(value: unknown): value is Record<string, string> {
  if (!isRecord(value)) return false
  const entries = Object.entries(value)
  return entries.length <= maximumCapturedHeaders && entries.every(([name, item]) => (
    isCapturedHeaderName(name) && typeof item === 'string' && captureBytes(item) <= maximumCapturedHeaderValueBytes &&
    (!isSensitiveAnalyticsCaptureName(name) || item === redactedCaptureValue)
  ))
}

function isCapturedBody(value: unknown): value is Record<string, unknown> | null {
  if (value === null) return true
  if (!isRecord(value)) return false
  let encoded: string
  try {
    encoded = JSON.stringify(value)
  } catch {
    return false
  }
  if (captureBytes(encoded) > maximumCapturedBodyBytes) return false
  const state = { keys: 0, nodes: 1 }
  return isCapturedObject(value, 0, state)
}

function isCapturedObject(value: Record<string, unknown>, depth: number, state: { keys: number; nodes: number }): boolean {
  const entries = Object.entries(value)
  state.keys += entries.length
  if (state.keys > maximumCapturedHeaders) return false
  return entries.every(([name, item]) => (
    name.length > 0 && name.trim() === name && !/[\r\n\0]/.test(name) &&
    captureBytes(name) <= maximumCapturedBodyKeyBytes &&
    (!isSensitiveAnalyticsCaptureName(name) || item === redactedCaptureValue) &&
    isCapturedValue(item, depth, state)
  ))
}

function isCapturedValue(value: unknown, depth: number, state: { keys: number; nodes: number }): boolean {
  state.nodes += 1
  if (state.nodes > maximumCapturedBodyNodes || depth > maximumCapturedBodyDepth) return false
  if (value === null || typeof value === 'boolean') return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (typeof value === 'string') return captureBytes(value) <= maximumCapturedBodyValueBytes
  if (Array.isArray(value)) return value.every((item) => isCapturedValue(item, depth + 1, state))
  return isRecord(value) && isCapturedObject(value, depth + 1, state)
}

function isNullableCount(value: unknown): value is number | null {
  return value === null || isCount(value)
}

function commonEvent(value: Record<string, unknown>, kind: 'access' | 'block'): boolean {
  return isText(value.event_id, 128, false) && isDateTime(value.occurred_at) &&
    typeof value.site_id === 'string' && uuidPattern.test(value.site_id) &&
    typeof value.node_id === 'string' && uuidPattern.test(value.node_id) &&
    isText(value.request_id, 128) && isText(value.trace_id, 128) &&
    typeof value.config_version_id === 'string' && uuidPattern.test(value.config_version_id) &&
    isText(value.host, 253) && isText(value.uri_path, 4096) && value.uri_path.startsWith('/') &&
    !value.uri_path.includes('?') && !value.uri_path.includes('#') &&
    isIPAddress(value.client_ip) && isText(value.country_code, 8) && isText(value.carrier, 128) &&
    typeof value.status_code === 'number' && Number.isInteger(value.status_code) &&
    (kind === 'block' ? value.status_code === 0 || value.status_code >= 100 && value.status_code <= 599 : value.status_code >= 100 && value.status_code <= 599) &&
    isCount(value.request_bytes) && isCount(value.response_bytes) &&
    isNullableText(value.task_id, 128) && isText(value.installation_id, 128) &&
    isCapturedHeaders(value.request_headers) && isCapturedHeaders(value.response_headers) &&
    isCapturedBody(value.request_body) && isCapturedBody(value.response_body) && isNullableText(value.ja4, 128) &&
    isNullableCount(value.origin_connect_us) && isNullableCount(value.origin_first_byte_us) && isNullableCount(value.origin_total_us)
}

const ipIntelTag = /^carrier:[a-z0-9-]{1,32}$/

function isClientIPIntel(value: unknown): value is ClientIPIntel {
  if (!isRecord(value) || !hasExactKeys(value, ['revision'],
    ['carrier', 'idc', 'asn', 'country', 'province', 'province_name', 'city', 'city_name'])) return false
  const optionalText = (key: string, max: number, pattern?: RegExp) => !(key in value) ||
    isText(value[key], max, false) && (!pattern || pattern.test(value[key] as string))
  return isCount(value.revision) && value.revision > 0 &&
    optionalText('carrier', 64, ipIntelTag) && (!('idc' in value) || value.idc === 'idc:cn' || value.idc === 'idc:global') &&
    (!('asn' in value) || isCount(value.asn) && value.asn > 0 && value.asn <= 4294967295) &&
    optionalText('country', 2, /^[A-Z]{2}$/) && optionalText('province', 6, /^\d{2}0000$/) && optionalText('city', 6, /^\d{6}$/) &&
    optionalText('province_name', 64) && optionalText('city_name', 64)
}

function validIPIntel(value: Record<string, unknown>): boolean {
  return !('ip_intel' in value) || isClientIPIntel(value.ip_intel)
}

function isAccessEvent(value: unknown): value is AccessLogEvent {
  if (!isRecord(value) || !hasExactKeys(value, [
    'event_id', 'occurred_at', 'site_id', 'node_id', 'request_id', 'trace_id', 'config_version_id',
    'host', 'listen_port', 'uri_path', 'client_ip', 'country_code', 'carrier',
    'method', 'protocol', 'cache_status', 'upstream_result', 'upstream_addr', 'status_code', 'request_bytes', 'response_bytes', 'duration_us',
    'task_id', 'installation_id', 'request_headers', 'response_headers', 'request_body', 'response_body',
    'ja4', 'origin_connect_us', 'origin_first_byte_us', 'origin_total_us',
  ], ['ip_intel', 'node_name'])) return false
  return commonEvent(value, 'access') && validIPIntel(value) && (!('node_name' in value) || isText(value.node_name, 255)) &&
    isCount(value.listen_port) && value.listen_port <= 65535 &&
    isText(value.method, 32) && isText(value.protocol, 32) &&
    isText(value.cache_status, 32) && isText(value.upstream_result, 64) && isText(value.upstream_addr, 64) && isCount(value.duration_us)
}

function isBlockEvent(value: unknown): value is BlockLogEvent {
  if (!isRecord(value) || !hasExactKeys(value, [
    'event_id', 'occurred_at', 'site_id', 'node_id', 'request_id', 'trace_id', 'config_version_id',
    'host', 'uri_path', 'client_ip', 'country_code', 'carrier',
    'event_type', 'action', 'severity', 'rule_id', 'status_code', 'request_bytes', 'response_bytes',
    'task_id', 'installation_id', 'request_headers', 'response_headers', 'request_body', 'response_body',
    'ja4', 'origin_connect_us', 'origin_first_byte_us', 'origin_total_us',
    'policy_id', 'detector', 'matched', 'user_agent', 'request_body_excerpt', 'count',
    'uri_query', 'site_domain', 'rule_name',
  ], ['ip_intel'])) return false
  return commonEvent(value, 'block') && validIPIntel(value) && isText(value.event_type, 64) && isText(value.action, 64) &&
    isText(value.severity, 32) && isText(value.rule_id, 128) &&
    (value.policy_id === '' || isUUID(value.policy_id)) && isText(value.detector, 16) && isText(value.matched, 256) &&
    isText(value.user_agent, 512) && isText(value.request_body_excerpt, 1024) &&
    isCount(value.count) && value.count >= 1 && value.count <= 1_000_000_000 &&
    isText(value.uri_query, 512) && /^[!-"$-~]*$/.test(value.uri_query) &&
    isText(value.site_domain, 253) && isText(value.rule_name, 128)
}

function isMeta(value: unknown): value is AnalyticsLogPageMeta {
  return isRecord(value) && hasExactKeys(value,
    ['from', 'to', 'timezone', 'consistency', 'replacement_consistency', 'pagination'],
    ['snapshot_at', 'next_cursor']) &&
    isDateTime(value.from) && isDateTime(value.to) && value.timezone === 'UTC' &&
    value.consistency === 'snapshot' && value.replacement_consistency === 'latest_event_id_at_snapshot' &&
    value.pagination === 'keyset' &&
    (!('snapshot_at' in value) || isDateTime(value.snapshot_at)) &&
    (!('next_cursor' in value) || isText(value.next_cursor, 2048, false))
}

function parsePage<T>(value: unknown, item: (value: unknown) => value is T): AnalyticsLogPage<T> {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'meta']) || !Array.isArray(value.data) ||
    value.data.length > 100 || !value.data.every(item) || !isMeta(value.meta)) {
    throw invalidResponse()
  }
  return value as unknown as AnalyticsLogPage<T>
}

const blockProgressStates = new Set([
  'claimed', 'canary', 'expanding', 'healthy', 'failed', 'cancelled', 'expired', 'promoted',
])

function isBlockProgress(value: unknown): value is BlockEdgeProgress {
  if (!isRecord(value) || !hasExactKeys(value, [
    'candidate_id', 'state', 'total_nodes', 'ready_nodes', 'failed_nodes', 'superseded_nodes',
  ])) return false
  return isUUID(value.candidate_id) && typeof value.state === 'string' && blockProgressStates.has(value.state) &&
    isCount(value.total_nodes) && isCount(value.ready_nodes) && isCount(value.failed_nodes) &&
    isCount(value.superseded_nodes) &&
    value.ready_nodes + value.failed_nodes + value.superseded_nodes <= value.total_nodes
}

function isSiteDisplayID(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
}

function isCurrentBlock(value: unknown): value is CurrentBlock {
  if (!isRecord(value) || !hasExactKeys(value, [
    'id', 'tenant_id', 'site_id', 'site_display_id', 'domain', 'position', 'policy_id', 'policy_version',
    'cidr', 'reason_code', 'blocked_at', 'unlockable',
  ], ['edge_progress'])) return false
  return isUUID(value.id) && isUUID(value.tenant_id) && isUUID(value.site_id) && isSiteDisplayID(value.site_display_id) &&
    typeof value.domain === 'string' && typeof value.position === 'string' &&
    isUUID(value.policy_id) &&
    typeof value.policy_version === 'number' && Number.isSafeInteger(value.policy_version) && value.policy_version >= 1 &&
    isCIDR(value.cidr) && value.reason_code === 'acl_policy_block' && isDateTime(value.blocked_at) &&
    typeof value.unlockable === 'boolean' && (!('edge_progress' in value) || isBlockProgress(value.edge_progress))
}

function isBlockHistory(value: unknown): value is BlockHistory {
  if (!isRecord(value) || !hasExactKeys(value, [
    'id', 'block_id', 'tenant_id', 'site_id', 'site_display_id', 'domain', 'position', 'policy_id', 'cidr',
    'reason_code', 'result_code', 'auto_unlock', 'requested_at', 'unlocked_at', 'edge_progress',
  ])) return false
  return isUUID(value.id) && isUUID(value.block_id) && isUUID(value.tenant_id) && isUUID(value.site_id) &&
    isSiteDisplayID(value.site_display_id) && typeof value.domain === 'string' &&
    typeof value.position === 'string' && isUUID(value.policy_id) &&
    isCIDR(value.cidr) && value.reason_code === 'false_positive_confirmed' &&
    (value.result_code === 'recovery_claimed' || value.result_code === 'recovery_replayed') &&
    typeof value.auto_unlock === 'boolean' &&
    isDateTime(value.requested_at) && (value.unlocked_at === null || isDateTime(value.unlocked_at)) &&
    isBlockProgress(value.edge_progress)
}

function isSiteBlacklistCount(value: unknown): value is SiteBlacklistCount {
  if (!isRecord(value) || !hasExactKeys(value, ['tenant_id', 'site_id', 'site_display_id', 'domain', 'count'])) return false
  return isUUID(value.tenant_id) && isUUID(value.site_id) && isSiteDisplayID(value.site_display_id) &&
    typeof value.domain === 'string' && isCount(value.count)
}

function parseBlockStatePage<T>(value: unknown, item: (value: unknown) => value is T): BlockStatePage<T> {
  if (!isRecord(value) || !hasExactKeys(value, ['data', 'total_count', 'snapshot_at']) || !Array.isArray(value.data) ||
    value.data.length > 100 || !value.data.every(item) || !isCount(value.total_count) ||
    value.total_count < value.data.length || !isDateTime(value.snapshot_at)) {
    throw invalidResponse()
  }
  return value as unknown as BlockStatePage<T>
}

function parseBlockUnlockResult(value: unknown): BlockUnlockResult {
  if (!isRecord(value) || !hasExactKeys(value, [
    'block_id', 'candidate_id', 'progress', 'reason_code', 'replayed',
  ]) || !isUUID(value.block_id) || !isUUID(value.candidate_id) ||
    typeof value.progress !== 'string' || !blockProgressStates.has(value.progress) ||
    (value.reason_code !== 'recovery_claimed' && value.reason_code !== 'recovery_replayed') ||
    typeof value.replayed !== 'boolean') {
    throw invalidResponse()
  }
  return value as unknown as BlockUnlockResult
}

const ccCoordinationStates = new Set(['block_pending', 'blocked', 'release_pending', 'failed'])
const ccCoordinationReasons = new Set([
  'cc_cross_node_threshold_reached', 'cc_coordination_dependency_unavailable', 'false_positive_confirmed',
])

function isCCCoordinationState(value: unknown): value is CCCoordinationState {
  if (!isRecord(value) || !hasExactKeys(value, [
    'id', 'tenant_scope_id', 'tenant_id', 'site_id', 'source_cc_policy_id', 'rule_id', 'client_cidr', 'host', 'path',
    'method', 'listen_port', 'protocol', 'request_class', 'generation', 'state', 'reason_code', 'hit_count',
    'node_count', 'current_policy_version', 'lkg_policy_version', 'expires_at', 'release_hold_until', 'updated_at',
  ])) return false
  return isUUID(value.id) && isUUID(value.tenant_scope_id) && isUUID(value.tenant_id) && isUUID(value.site_id) &&
    isUUID(value.source_cc_policy_id) && isUUID(value.rule_id) && isCIDR(value.client_cidr) &&
    isText(value.host, 253, false) && value.host === value.host.toLowerCase() && value.host.trim() === value.host &&
    !value.host.includes('/') && !Array.from(value.host).some((character) => {
      const code = character.charCodeAt(0)
      return code < 0x20 || code === 0x7f
    }) && isURIPathFilter(value.path) &&
    typeof value.method === 'string' && /^[A-Z]{1,16}$/.test(value.method) &&
    typeof value.listen_port === 'number' && Number.isSafeInteger(value.listen_port) &&
    value.listen_port >= 1 && value.listen_port <= 65535 &&
    (value.protocol === 'http' || value.protocol === 'https') && value.request_class === 'standard' &&
    typeof value.generation === 'number' && Number.isSafeInteger(value.generation) && value.generation >= 1 &&
    typeof value.state === 'string' && ccCoordinationStates.has(value.state) &&
    typeof value.reason_code === 'string' && ccCoordinationReasons.has(value.reason_code) &&
    isCount(value.hit_count) && isCount(value.node_count) && isCount(value.current_policy_version) &&
    isCount(value.lkg_policy_version) && isDateTime(value.expires_at) && isDateTime(value.release_hold_until) &&
    isDateTime(value.updated_at)
}

function parseCCCoordinationPage(value: unknown): CCCoordinationStatePage {
  if (!isRecord(value) || !hasExactKeys(value, ['items']) || !Array.isArray(value.items) ||
    value.items.length > 100 || !value.items.every(isCCCoordinationState)) {
    throw invalidResponse()
  }
  return value as unknown as CCCoordinationStatePage
}

function parseCCCoordinationRelease(value: unknown): CCCoordinationReleaseResult {
  if (!isRecord(value) || !hasExactKeys(value, ['state', 'replayed']) ||
    !isCCCoordinationState(value.state) || typeof value.replayed !== 'boolean') {
    throw invalidResponse()
  }
  return value as unknown as CCCoordinationReleaseResult
}

function queryString(
  audience: AnalyticsAudience,
  kind: 'access' | 'block',
  filters: AnalyticsLogFilters,
  limit: number,
  cursor?: string,
): string {
  const from = isDateTime(filters.from) ? Date.parse(filters.from) : Number.NaN
  const to = isDateTime(filters.to) ? Date.parse(filters.to) : Number.NaN
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to || to - from > maximumWindowMilliseconds) {
    throw invalidRequest()
  }
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw invalidRequest()
  if (cursor !== undefined && !isText(cursor, 2048, false)) throw invalidRequest()
  // The platform reads every tenant unless tenantId narrows it; a tenant never names one.
  if (audience === 'admin' ? filters.tenantId !== undefined && !isUUID(filters.tenantId) : filters.tenantId !== undefined) {
    throw invalidRequest()
  }
  if (filters.siteId !== undefined && !isUUID(filters.siteId)) throw invalidRequest()
  // Access and block logs take the WAF overview's space-separated domain list (≤ 64, distinct).
  const hosts = filters.host?.split(' ') ?? []
  if (filters.host !== undefined && (hosts.length > 64 || new Set(hosts).size !== hosts.length ||
    hosts.some((host) => !isText(host, 253, false) ||
      !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+$/.test(host)))) {
    throw invalidRequest()
  }
  if (filters.action !== undefined && (kind !== 'block' || !['block', 'challenge', 'log', 'temporary_ban'].includes(filters.action))) throw invalidRequest()
  if (filters.eventType !== undefined && (kind !== 'block' || !/^[a-z0-9_]{1,64}$/u.test(filters.eventType))) throw invalidRequest()
  if (filters.nodeId !== undefined && !isUUID(filters.nodeId)) throw invalidRequest()
  if (filters.clientIp !== undefined && !isIPAddress(filters.clientIp)) throw invalidRequest()
  if (filters.statusCode !== undefined && (!Number.isSafeInteger(filters.statusCode) ||
    (kind === 'block' ? filters.statusCode !== 0 && (filters.statusCode < 100 || filters.statusCode > 599) :
      filters.statusCode < 100 || filters.statusCode > 599))) throw invalidRequest()
  if (filters.countryCode !== undefined && !isText(filters.countryCode, 8, false)) throw invalidRequest()
  if (filters.carrier !== undefined && !isText(filters.carrier, 128, false)) throw invalidRequest()
  if (filters.method !== undefined && !isText(filters.method, 32, false)) throw invalidRequest()
  if (filters.protocol !== undefined && !isText(filters.protocol, 32, false)) throw invalidRequest()
  if (filters.cacheStatus !== undefined && !isText(filters.cacheStatus, 32, false)) throw invalidRequest()
  if (filters.upstreamResult !== undefined && !isText(filters.upstreamResult, 64, false)) throw invalidRequest()
  if (filters.contentType !== undefined && (!/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(filters.contentType) || filters.contentType.length > 128)) throw invalidRequest()
  if (filters.userAgent !== undefined && !isText(filters.userAgent, 512, false)) throw invalidRequest()
  if (filters.uriPath !== undefined && !isURIPathFilter(filters.uriPath)) {
    throw invalidRequest()
  }
  if (filters.uriPathMatch !== undefined && (!['exact', 'prefix'].includes(filters.uriPathMatch) ||
    filters.uriPathMatch === 'prefix' && !filters.uriPath)) {
    throw invalidRequest()
  }
  if (filters.ja4 !== undefined && (!isText(filters.ja4, 128, false) || filters.ja4.trim() !== filters.ja4)) {
    throw invalidRequest()
  }
  const timingRanges = [
    [filters.requestBytesMin, filters.requestBytesMax],
    [filters.responseBytesMin, filters.responseBytesMax],
    [filters.originConnectUsMin, filters.originConnectUsMax],
    [filters.originFirstByteUsMin, filters.originFirstByteUsMax],
    [filters.originTotalUsMin, filters.originTotalUsMax],
  ]
  if (timingRanges.some(([minimum, maximum]) =>
    minimum !== undefined && !isCount(minimum) || maximum !== undefined && !isCount(maximum) ||
    minimum !== undefined && maximum !== undefined && minimum > maximum)) {
    throw invalidRequest()
  }
  const query = new URLSearchParams({ from: filters.from, to: filters.to, limit: String(limit) })
  if (audience === 'admin' && filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.host) query.set('host', filters.host.toLowerCase())
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (filters.clientIp) query.set('client_ip', filters.clientIp)
  if (filters.uriPath) query.set('uri_path', filters.uriPath)
  if (filters.uriPath && filters.uriPathMatch === 'prefix') query.set('uri_path_match', 'prefix')
  if (filters.statusCode !== undefined) query.set('status_code', String(filters.statusCode))
  if (filters.countryCode) query.set('country_code', filters.countryCode)
  if (filters.carrier) query.set('carrier', filters.carrier)
  if (filters.action) query.set('action', filters.action)
  if (filters.eventType) query.set('event_type', filters.eventType)
  if (filters.method) query.set('method', filters.method)
  if (filters.protocol) query.set('protocol', filters.protocol)
  if (filters.cacheStatus) query.set('cache_status', filters.cacheStatus)
  if (filters.upstreamResult) query.set('upstream_result', filters.upstreamResult)
  if (filters.contentType) query.set('content_type', filters.contentType.toLowerCase())
  if (filters.userAgent) query.set('user_agent', filters.userAgent)
  if (filters.requestBytesMin !== undefined) query.set('request_bytes_min', String(filters.requestBytesMin))
  if (filters.requestBytesMax !== undefined) query.set('request_bytes_max', String(filters.requestBytesMax))
  if (filters.responseBytesMin !== undefined) query.set('response_bytes_min', String(filters.responseBytesMin))
  if (filters.responseBytesMax !== undefined) query.set('response_bytes_max', String(filters.responseBytesMax))
  if (filters.ja4) query.set('ja4', filters.ja4)
  if (filters.originConnectUsMin !== undefined) query.set('origin_connect_us_min', String(filters.originConnectUsMin))
  if (filters.originConnectUsMax !== undefined) query.set('origin_connect_us_max', String(filters.originConnectUsMax))
  if (filters.originFirstByteUsMin !== undefined) query.set('origin_first_byte_us_min', String(filters.originFirstByteUsMin))
  if (filters.originFirstByteUsMax !== undefined) query.set('origin_first_byte_us_max', String(filters.originFirstByteUsMax))
  if (filters.originTotalUsMin !== undefined) query.set('origin_total_us_min', String(filters.originTotalUsMin))
  if (filters.originTotalUsMax !== undefined) query.set('origin_total_us_max', String(filters.originTotalUsMax))
  if (cursor) query.set('cursor', cursor)
  return query.toString()
}

async function request(path: string, accessToken: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response
  try {
    const headers = new Headers(init.headers)
    headers.set('Authorization', `Bearer ${accessToken}`)
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers,
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

function basePath(audience: AnalyticsAudience): string {
  return audience === 'admin' ? '/v1/admin/analytics/logs' : '/v1/analytics/logs'
}

function blockStateQuery(audience: AnalyticsAudience, filters: BlockStateFilters,
  windowed: boolean = false): string {
  if (audience === 'admin' && filters.tenantId !== undefined && !isUUID(filters.tenantId)) throw invalidRequest()
  if (filters.siteId !== undefined && !isUUID(filters.siteId)) throw invalidRequest()
  if (filters.policyId !== undefined && !isUUID(filters.policyId)) throw invalidRequest()
  if (filters.cidr !== undefined && !isCIDR(filters.cidr)) throw invalidRequest()
  const limit = filters.limit ?? 50
  const offset = filters.offset ?? 0
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
    !Number.isSafeInteger(offset) || offset < 0 || offset > 1_000_000) throw invalidRequest()
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  if (audience === 'admin' && filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.policyId) query.set('policy_id', filters.policyId)
  if (filters.cidr) query.set('cidr', filters.cidr)
  if (windowed) {
    for (const key of ['start', 'end'] as const) {
      const value = filters[key]
      if (value === undefined) continue
      if (!Number.isSafeInteger(value) || value < 0) throw invalidRequest()
      query.set(key, String(value))
    }
  }
  return query.toString()
}

function blockUnlockQuery(audience: AnalyticsAudience, tenantId: string | undefined): string {
  if (audience === 'admin') {
    if (!isUUID(tenantId)) throw invalidRequest()
    return `?${new URLSearchParams({ tenant_id: tenantId }).toString()}`
  }
  if (tenantId !== undefined) throw invalidRequest()
  return ''
}

function ccCoordinationQuery(
  audience: AnalyticsAudience,
  filters: CCCoordinationFilters,
  includeLimit: boolean,
): string {
  // Listing: site and (platform) tenant only narrow. A release names both.
  const listing = includeLimit
  if (filters.siteId !== undefined ? !isUUID(filters.siteId) : !listing) throw invalidRequest()
  if (audience === 'admin'
    ? filters.tenantId !== undefined ? !isUUID(filters.tenantId) : !listing
    : filters.tenantId !== undefined) {
    throw invalidRequest()
  }
  const query = new URLSearchParams()
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (audience === 'admin' && filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (includeLimit) {
    const limit = filters.limit ?? 50
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw invalidRequest()
    query.set('limit', String(limit))
  } else if (filters.limit !== undefined) {
    throw invalidRequest()
  }
  return query.toString()
}

function listAccess(
  accessToken: string,
  audience: 'admin',
  filters: AdminAnalyticsLogFilters,
  limit: number,
  cursor?: string,
): Promise<AnalyticsLogPage<AccessLogEvent>>
function listAccess(
  accessToken: string,
  audience: 'tenant',
  filters: AnalyticsLogFilters,
  limit: number,
  cursor?: string,
): Promise<AnalyticsLogPage<AccessLogEvent>>
async function listAccess(
  accessToken: string,
  audience: AnalyticsAudience,
  filters: AnalyticsLogFilters,
  limit: number,
  cursor?: string,
): Promise<AnalyticsLogPage<AccessLogEvent>> {
  const raw = await request(`${basePath(audience)}/access?${queryString(audience, 'access', filters, limit, cursor)}`, accessToken)
  return parsePage(raw, isAccessEvent)
}

function listBlocks(
  accessToken: string,
  audience: 'admin',
  filters: AdminAnalyticsLogFilters,
  limit: number,
  cursor?: string,
): Promise<AnalyticsLogPage<BlockLogEvent>>
function listBlocks(
  accessToken: string,
  audience: 'tenant',
  filters: AnalyticsLogFilters,
  limit: number,
  cursor?: string,
): Promise<AnalyticsLogPage<BlockLogEvent>>
async function listBlocks(
  accessToken: string,
  audience: AnalyticsAudience,
  filters: AnalyticsLogFilters,
  limit: number,
  cursor?: string,
): Promise<AnalyticsLogPage<BlockLogEvent>> {
  const raw = await request(`${basePath(audience)}/block-events?${queryString(audience, 'block', filters, limit, cursor)}`, accessToken)
  return parsePage(raw, isBlockEvent)
}

function exportScopeQuery(audience: AnalyticsAudience, tenantId?: string): string {
  if (audience === 'admin') {
    if (!isUUID(tenantId)) throw invalidRequest()
    return `?${new URLSearchParams({ tenant_id: tenantId }).toString()}`
  }
  if (tenantId !== undefined) throw invalidRequest()
  return ''
}

const exportFilterTextKeys = ['site_id', 'host', 'node_id', 'client_ip', 'uri_path', 'uri_path_match', 'country_code', 'carrier',
  'method', 'protocol', 'cache_status', 'upstream_result', 'content_type', 'user_agent', 'ja4'] as const
const exportFilterCountKeys = ['status_code', 'request_bytes_min', 'request_bytes_max', 'response_bytes_min', 'response_bytes_max',
  'origin_connect_us_min', 'origin_connect_us_max', 'origin_first_byte_us_min', 'origin_first_byte_us_max',
  'origin_total_us_min', 'origin_total_us_max'] as const

function isExportFilter(value: unknown): value is AnalyticsLogExportFilter {
  if (!isRecord(value) || !hasExactKeys(value, ['from', 'to'], [...exportFilterTextKeys, ...exportFilterCountKeys])) return false
  return isDateTime(value.from) && isDateTime(value.to) &&
    exportFilterTextKeys.every((key) => value[key] === undefined || isText(value[key], 4096, false)) &&
    exportFilterCountKeys.every((key) => value[key] === undefined || isCount(value[key]))
}

function isAccessExport(value: unknown): value is AnalyticsLogExport {
  if (!isRecord(value) || !hasExactKeys(value,
    ['id', 'status', 'reason', 'snapshot_at', 'row_count', 'byte_count', 'created_at', 'expires_at', 'downloadable', 'filter'], ['sha256'])) return false
  if (value.filter !== null && !isExportFilter(value.filter)) return false
  return isUUID(value.id) && ['pending', 'running', 'completed', 'failed'].includes(String(value.status)) &&
    isText(value.reason, 64, false) && (value.snapshot_at === null || isDateTime(value.snapshot_at)) &&
    (value.row_count === null || isCount(value.row_count)) && (value.byte_count === null || isCount(value.byte_count)) &&
    (value.sha256 === undefined || typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256)) &&
    isDateTime(value.created_at) && (value.expires_at === null || isDateTime(value.expires_at)) && typeof value.downloadable === 'boolean'
}

function parseAccessExport(value: unknown): AnalyticsLogExport {
  if (!isAccessExport(value)) throw invalidResponse()
  return value
}

async function createAccessExport(
  accessToken: string,
  audience: AnalyticsAudience,
  filters: AnalyticsLogFilters,
  idempotencyKey: string,
): Promise<AnalyticsLogExport> {
  if (!/^[A-Za-z0-9._:-]{16,128}$/.test(idempotencyKey)) throw invalidRequest()
  queryString(audience, 'access', filters, 1)
  const raw = await request(`${basePath(audience)}/access/exports${exportScopeQuery(audience, filters.tenantId)}`, accessToken, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify({ filter: {
      from: filters.from, to: filters.to, site_id: filters.siteId, host: filters.host ? filters.host.toLowerCase() : undefined,
      node_id: filters.nodeId, client_ip: filters.clientIp, uri_path: filters.uriPath,
      uri_path_match: filters.uriPath && filters.uriPathMatch === 'prefix' ? 'prefix' : undefined,
      status_code: filters.statusCode,
      country_code: filters.countryCode, carrier: filters.carrier, method: filters.method,
      protocol: filters.protocol, cache_status: filters.cacheStatus, upstream_result: filters.upstreamResult,
      content_type: filters.contentType, user_agent: filters.userAgent,
      request_bytes_min: filters.requestBytesMin, request_bytes_max: filters.requestBytesMax,
      response_bytes_min: filters.responseBytesMin, response_bytes_max: filters.responseBytesMax,
      ja4: filters.ja4, origin_connect_us_min: filters.originConnectUsMin,
      origin_connect_us_max: filters.originConnectUsMax, origin_first_byte_us_min: filters.originFirstByteUsMin,
      origin_first_byte_us_max: filters.originFirstByteUsMax, origin_total_us_min: filters.originTotalUsMin,
      origin_total_us_max: filters.originTotalUsMax,
    } }),
  })
  return parseAccessExport(raw)
}

async function listAccessExports(accessToken: string, audience: AnalyticsAudience, tenantId?: string): Promise<AnalyticsLogExport[]> {
  const raw = await request(`${basePath(audience)}/access/exports${exportScopeQuery(audience, tenantId)}`, accessToken)
  if (!isRecord(raw) || !hasExactKeys(raw, ['data']) || !Array.isArray(raw.data) || !raw.data.every(isAccessExport)) throw invalidResponse()
  return raw.data
}

// LOG-01：按当前查询范围找回本账号最新一代申请（与登录会话无关），没有则为 null。
async function findAccessExportForScope(
  accessToken: string, audience: AnalyticsAudience, filters: AnalyticsLogFilters,
): Promise<AnalyticsLogExport | null> {
  if (audience === 'admin' && !filters.tenantId) throw invalidRequest()
  const query = new URLSearchParams(queryString(audience, 'access', filters, 1))
  query.delete('limit')
  const raw = await request(`${basePath(audience)}/access/exports?${query.toString()}`, accessToken)
  if (!isRecord(raw) || !hasExactKeys(raw, ['data']) || !Array.isArray(raw.data) || raw.data.length > 1 ||
    !raw.data.every(isAccessExport)) throw invalidResponse()
  return raw.data[0] ?? null
}

async function grantAccessExportDownload(
  accessToken: string, audience: AnalyticsAudience, exportId: string, tenantId?: string,
): Promise<AnalyticsLogExportGrant> {
  if (!isUUID(exportId)) throw invalidRequest()
  const raw = await request(`${basePath(audience)}/access/exports/${exportId}/download-grants${exportScopeQuery(audience, tenantId)}`, accessToken, { method: 'POST' })
  if (!isRecord(raw) || !hasExactKeys(raw, ['export_id', 'token', 'expires_at']) || raw.export_id !== exportId ||
    typeof raw.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(raw.token) || !isDateTime(raw.expires_at)) throw invalidResponse()
  return raw as unknown as AnalyticsLogExportGrant
}

async function downloadAccessExport(
  accessToken: string, audience: AnalyticsAudience, exportId: string, grantToken: string, tenantId?: string,
): Promise<Blob> {
  if (!isUUID(exportId) || !/^[A-Za-z0-9_-]{43}$/.test(grantToken)) throw invalidRequest()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${basePath(audience)}/access/exports/${exportId}/download${exportScopeQuery(audience, tenantId)}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'X-Analytics-Download-Token': grantToken },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const disposition = response.headers.get('Content-Disposition') ?? ''
  const contentLength = Number(response.headers.get('Content-Length') ?? '0')
  if (disposition !== `attachment; filename="analytics-access-${exportId}.csv"` ||
    !response.headers.get('Content-Type')?.startsWith('text/csv') ||
    !/^sha-256=[0-9a-f]{64}$/.test(response.headers.get('Digest') ?? '') ||
    !Number.isSafeInteger(contentLength) || contentLength < 0 || contentLength > 8 << 20) throw invalidResponse()
  const result = await response.blob()
  if (result.size < 1 || result.size > 8 << 20) throw invalidResponse()
  return result
}

function listCurrentBlocks(
  accessToken: string,
  audience: 'admin',
  filters: AdminBlockStateFilters,
): Promise<BlockStatePage<CurrentBlock>>
function listCurrentBlocks(
  accessToken: string,
  audience: 'tenant',
  filters: BlockStateFilters,
): Promise<BlockStatePage<CurrentBlock>>
async function listCurrentBlocks(
  accessToken: string,
  audience: AnalyticsAudience,
  filters: BlockStateFilters,
): Promise<BlockStatePage<CurrentBlock>> {
  const raw = await request(`${basePath(audience)}/blocks/current?${blockStateQuery(audience, filters)}`, accessToken)
  return parseBlockStatePage(raw, isCurrentBlock)
}

function listBlockHistory(
  accessToken: string,
  audience: 'admin',
  filters: AdminBlockStateFilters,
): Promise<BlockStatePage<BlockHistory>>
function listBlockHistory(
  accessToken: string,
  audience: 'tenant',
  filters: BlockStateFilters,
): Promise<BlockStatePage<BlockHistory>>
async function listBlockHistory(
  accessToken: string,
  audience: AnalyticsAudience,
  filters: BlockStateFilters,
): Promise<BlockStatePage<BlockHistory>> {
  const raw = await request(`${basePath(audience)}/blocks/history?${blockStateQuery(audience, filters, true)}`, accessToken)
  return parseBlockStatePage(raw, isBlockHistory)
}

/** NF34: one site + client IP + CC rule that auto-banned the client in the window. */
export interface CCBan {
  site_id: string
  host: string
  client_ip: string
  rule_id: string
  ban_count: number
  first_banned_at: string
  last_banned_at: string
}

export interface CCBanFilters {
  from: string
  to: string
  tenantId?: string
  siteId?: string
  clientIp?: string
}

export interface CCBanPage {
  data: CCBan[]
  truncated: boolean
}

function isCCBan(value: unknown): value is CCBan {
  return isRecord(value) && hasExactKeys(value, ['site_id', 'host', 'client_ip', 'rule_id', 'ban_count', 'first_banned_at', 'last_banned_at']) &&
    isUUID(value.site_id) && isText(value.host, 253) && isIPAddress(value.client_ip) && isText(value.rule_id, 128) &&
    isCount(value.ban_count) && value.ban_count > 0 && isDateTime(value.first_banned_at) && isDateTime(value.last_banned_at) &&
    Date.parse(value.first_banned_at) <= Date.parse(value.last_banned_at)
}

async function listCCBans(accessToken: string, audience: AnalyticsAudience, filters: CCBanFilters): Promise<CCBanPage> {
  const from = isDateTime(filters.from) ? Date.parse(filters.from) : Number.NaN
  const to = isDateTime(filters.to) ? Date.parse(filters.to) : Number.NaN
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to || to - from > maximumWindowMilliseconds ||
    (audience === 'admin' ? filters.tenantId !== undefined && !isUUID(filters.tenantId) : filters.tenantId !== undefined) ||
    (filters.siteId !== undefined && !isUUID(filters.siteId)) ||
    (filters.clientIp !== undefined && !isIPAddress(filters.clientIp))) {
    throw invalidRequest()
  }
  const query = new URLSearchParams({ from: filters.from, to: filters.to, limit: '100' })
  if (audience === 'admin' && filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.clientIp) query.set('client_ip', filters.clientIp)
  const raw = await request(`${basePath(audience)}/cc-bans?${query.toString()}`, accessToken)
  if (!isRecord(raw) || !hasExactKeys(raw, ['data', 'truncated', 'meta']) || !Array.isArray(raw.data) ||
    raw.data.length > 100 || !raw.data.every(isCCBan) || typeof raw.truncated !== 'boolean' || !isMeta(raw.meta)) {
    throw invalidResponse()
  }
  return { data: raw.data, truncated: raw.truncated }
}

function listSiteBlacklistCounts(
  accessToken: string,
  audience: 'admin',
  tenantId?: string,
): Promise<BlockStatePage<SiteBlacklistCount>>
function listSiteBlacklistCounts(
  accessToken: string,
  audience: 'tenant',
): Promise<BlockStatePage<SiteBlacklistCount>>
async function listSiteBlacklistCounts(
  accessToken: string,
  audience: AnalyticsAudience,
  tenantId?: string,
): Promise<BlockStatePage<SiteBlacklistCount>> {
  if (audience === 'admin' && tenantId !== undefined && !isUUID(tenantId)) throw invalidRequest()
  const scope = audience === 'admin' && tenantId
    ? `?${new URLSearchParams({ tenant_id: tenantId }).toString()}`
    : ''
  const raw = await request(`${basePath(audience)}/blocks/current-count${scope}`, accessToken)
  return parseBlockStatePage(raw, isSiteBlacklistCount)
}

function unlockCurrentBlock(
  accessToken: string,
  audience: 'admin',
  input: AdminBlockUnlockInput,
): Promise<BlockUnlockResult>
function unlockCurrentBlock(
  accessToken: string,
  audience: 'tenant',
  input: BlockUnlockInput,
): Promise<BlockUnlockResult>
async function unlockCurrentBlock(
  accessToken: string,
  audience: AnalyticsAudience,
  input: BlockUnlockInput,
): Promise<BlockUnlockResult> {
  if (!isUUID(input.blockId) || !/^[A-Za-z0-9._-]{1,128}$/.test(input.idempotencyKey)) throw invalidRequest()
  const raw = await request(
    `${basePath(audience)}/blocks/current/${input.blockId}/unlock${blockUnlockQuery(audience, input.tenantId)}`,
    accessToken,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': input.idempotencyKey },
      body: JSON.stringify({ reason_code: 'false_positive_confirmed' }),
    },
  )
  return parseBlockUnlockResult(raw)
}

function listCCCoordinationStates(
  accessToken: string,
  audience: 'admin',
  filters: AdminCCCoordinationFilters,
): Promise<CCCoordinationStatePage>
function listCCCoordinationStates(
  accessToken: string,
  audience: 'tenant',
  filters: CCCoordinationFilters,
): Promise<CCCoordinationStatePage>
async function listCCCoordinationStates(
  accessToken: string,
  audience: AnalyticsAudience,
  filters: CCCoordinationFilters,
): Promise<CCCoordinationStatePage> {
  const raw = await request(
    `${basePath(audience)}/cc-coordination?${ccCoordinationQuery(audience, filters, true)}`,
    accessToken,
  )
  return parseCCCoordinationPage(raw)
}

function releaseCCCoordinationState(
  accessToken: string,
  audience: 'admin',
  input: AdminCCCoordinationReleaseInput,
): Promise<CCCoordinationReleaseResult>
function releaseCCCoordinationState(
  accessToken: string,
  audience: 'tenant',
  input: CCCoordinationReleaseInput,
): Promise<CCCoordinationReleaseResult>
async function releaseCCCoordinationState(
  accessToken: string,
  audience: AnalyticsAudience,
  input: CCCoordinationReleaseInput,
): Promise<CCCoordinationReleaseResult> {
  if (!isUUID(input.stateId) || !Number.isSafeInteger(input.expectedGeneration) || input.expectedGeneration < 1 ||
    !/^[A-Za-z0-9._:-]{1,128}$/.test(input.idempotencyKey) ||
    !/^[A-Za-z0-9._:-]{1,128}$/.test(input.requestId)) {
    throw invalidRequest()
  }
  const raw = await request(
    `${basePath(audience)}/cc-coordination/${input.stateId}/release?${ccCoordinationQuery(audience, input, false)}`,
    accessToken,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': input.idempotencyKey,
        'X-Request-ID': input.requestId,
      },
      body: JSON.stringify({
        reason_code: 'false_positive_confirmed',
        expected_generation: input.expectedGeneration,
      }),
    },
  )
  return parseCCCoordinationRelease(raw)
}

export const analyticsLogsApi = {
  listAccess,
  listBlocks,
  listCurrentBlocks,
  listBlockHistory,
  listCCBans,
  listSiteBlacklistCounts,
  unlockCurrentBlock,
  listCCCoordinationStates,
  releaseCCCoordinationState,
  createAccessExport,
  listAccessExports,
  findAccessExportForScope,
  grantAccessExportDownload,
  downloadAccessExport,
}
