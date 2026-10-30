import { ApiError, networkApiError, responseApiError } from './auth'

export type AdminDashboardRange = 'seven_days' | 'thirty_days' | 'previous_month'
export type TenantDashboardRange = 'today' | 'yesterday' | 'seven_days' | 'thirty_days'
export type DashboardRange = AdminDashboardRange | TenantDashboardRange
export type DashboardUnavailableReason =
  | 'dependency_unavailable'
  | 'dependency_timeout'
  | 'authoritative_fact_missing'

export type DashboardSection<T> =
  | { available: true; value: T }
  | { available: false; reason: DashboardUnavailableReason }

export interface DashboardMeta {
  range: DashboardRange
  timezone: string
  from: string
  to: string
  generated_at: string
  snapshot_at: string
  window_complete: boolean
}

export interface OperationStats {
  cache_total: number
  cache_open: number
  cache_failed: number
  cache_updated_at?: string
  jobs_total: number
  jobs_open: number
  jobs_failed: number
  jobs_updated_at?: string
}

export interface OperationCountPoint {
  time: string
  count: number
}

export interface OperationAmountPoint {
  time: string
  sum_minor: string
}

export interface OperationCharts {
  new_users: OperationCountPoint[]
  package_sold: OperationCountPoint[]
  recharge: OperationAmountPoint[]
}

export interface AnalyticsStats {
  metric_version: 1
  request_count: string
  request_bytes: string
  response_bytes: string
  total_bytes: string
  average_bandwidth_bps: number
  status_2xx: string
  status_3xx: string
  status_4xx: string
  status_5xx: string
  security_events: string
  /** Security event records; summary only (security_events counts requests). */
  security_event_rows?: string
  blocked_ip_count?: string
}

export interface DashboardAnalyticsOverview {
  blocked_ip_count?: string
  /** FX36: busiest 5-minute bandwidth; absent when the analytics store cannot provide it. */
  peak_bandwidth_bps?: string
  blocked_ip_trend_available?: boolean
  /** 最近 N 分钟数据仍在结算（只作提示，不拦截展示）；无需提示时省略。 */
  settling_minutes?: number
  summary: AnalyticsStats
  trend: Array<AnalyticsStats & { hour: string }>
  top: Array<{
    dimension: 'domain' | 'region' | 'carrier'
    snapshot_at: string
    items: DashboardRankItem[]
  }>
  top_extended?: Array<{
    dimension: 'domain' | 'url' | 'ip' | 'region' | 'carrier'
    snapshot_at: string
    items: DashboardRankItem[]
  }>
}

/** host/port/path/scheme: domain and URL ranks' address parts (as in analytics ranks). */
export interface DashboardRankItem {
  key: string
  request_count: string
  response_bytes: string
  host?: string
  port?: number
  path?: string
  scheme?: 'http' | 'https'
}

export interface AccountSecurityStats {
  active_sessions: number
  users_with_mfa: number
  active_api_keys: number
  recovery_codes_remaining: number
  last_security_event_at?: string
}

export interface NetworkStats {
  nodes_total: number
  nodes_active: number
  nodes_online: number
  nodes_stale: number
  freshness_cutoff_seconds: 45
  regions: Array<{ region: string; nodes_total: number; nodes_online: number }>
}

export interface AdminProfileStats {
	last_login_at?: string
	last_login_ip?: string
	last_login_geo?: string
	last_login_region?: string
	last_login_city?: string
}

export interface DashboardFilters {
  siteId?: string
  nodeId?: string
}

export interface AdminDashboard {
  dashboard_version: 2
  meta: DashboardMeta
  accounts: DashboardSection<{
    tenants_total: number
    tenants_active: number
    tenant_users_total: number
    tenant_users_active: number
  }>
  subscriptions: DashboardSection<{ active: number }>
  billing: DashboardSection<{
    currency: 'CNY'
    gross_settled_debit_minor: string
    reversed_credit_minor: string
    net_settled_minor: string
  }>
  resources: DashboardSection<{
    sites_total: number
    sites_active: number
    sites_sync_failed: number
    domains_total?: number
    forwards_total?: number
    nodes_total: number
    certificates_total: number
    certificates_valid: number
    certificates_expiring_30d: number
  }>
  operations: DashboardSection<OperationStats>
  operation_charts?: DashboardSection<OperationCharts>
  profile?: DashboardSection<AdminProfileStats>
  entitlement: DashboardSection<{
    installation_id: string
    status: 'uninstalled' | 'valid' | 'grace' | 'expired' | 'revoked' | 'invalid'
    current_serial?: number
    node_limit?: number
    lease_status: 'valid' | 'grace' | 'expired' | 'revoked' | null
    expires_at?: string
    grace_until?: string
    last_verified_at?: string
  }>
  node_health: DashboardSection<{
    total: number
    online_fresh: number
    stale_or_offline: number
    presence_missing: number
    latest_last_seen_at?: string
    freshness_cutoff_seconds: 45
  }>
  analytics_health: DashboardSection<{
    active_streams: number
    latest_reconciled_at?: string
    latest_updated_at?: string
    unprepared_stream_gap: string
  }>
  account_security: DashboardSection<AccountSecurityStats>
  network: DashboardSection<NetworkStats>
  analytics: DashboardSection<DashboardAnalyticsOverview>
}

export interface EntitlementRefreshResult {
	 schema: 'cdnca.entitlement-refresh/v1'
	 request_id: string
	 snapshot: {
		installation_id: string
		serial: number
		key_id: string
		status: 'uninstalled' | 'valid' | 'grace' | 'expired' | 'revoked' | 'invalid'
		verified_at: string
	}
}

export interface TenantSubscriptionItem {
  id: string
  name: string
  ends_at: string
  timezone: string
  site_limit: string
  domain_limit: string
  node_limit: string
  traffic_limit_bytes: string
  traffic_progress: DashboardSection<{
    period_key: string
    used_bytes: string
    finalized_through: string
    source_watermark: string
    source_evidence_sha256: string
  }>
}

export interface TenantDashboard {
  dashboard_version: 2
  meta: DashboardMeta
  identity_verification: DashboardSection<{ verified: boolean }>
  profile: DashboardSection<AdminProfileStats>
  resources: DashboardSection<{
    sites_total: number
    sites_active: number
    sites_sync_failed: number
    domains_total: number
    forwards_total: number
    nodes_total: number
  }>
  certificates: DashboardSection<{ total: number; valid: number; expiring_30d: number }>
  billing: DashboardSection<{
    currency: 'CNY'
    balance_minor: number
    revision: number
    updated_at?: string
  }>
  subscriptions: DashboardSection<{ active: number; items: TenantSubscriptionItem[] }>
  traffic_packages: DashboardSection<{
    active: number
    granted_bytes: string
    remaining_bytes: string
    used_bytes: string
  }>
  operations: DashboardSection<OperationStats>
  notices: DashboardSection<{
    unread: number
    items: Array<{ id: string; title: string; published_at: string; read_at?: string }>
  }>
  account_security: DashboardSection<AccountSecurityStats>
  network: DashboardSection<NetworkStats>
  analytics: DashboardSection<DashboardAnalyticsOverview>
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const unsignedDecimalPattern = /^(0|[1-9]\d*)$/
const signedDecimalPattern = /^(0|[1-9]\d*|-[1-9]\d*)$/
const limitPattern = /^(-1|0|[1-9]\d*)$/
const unavailableReasons = new Set<DashboardUnavailableReason>([
  'dependency_unavailable',
  'dependency_timeout',
  'authoritative_fact_missing',
])
const entitlementStatuses = new Set(['uninstalled', 'valid', 'grace', 'expired', 'revoked', 'invalid'])
const leaseStatuses = new Set(['valid', 'grace', 'expired', 'revoked'])

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function isEntitlementRefreshResult(value: unknown): value is EntitlementRefreshResult {
	if (!isRecord(value) || !hasExactKeys(value, ['schema', 'request_id', 'snapshot']) ||
		value.schema !== 'cdnca.entitlement-refresh/v1' || typeof value.request_id !== 'string' || !safeRequestID(value.request_id) ||
		!isRecord(value.snapshot) || !hasExactKeys(value.snapshot, ['installation_id', 'serial', 'key_id', 'status', 'verified_at']) ||
		typeof value.snapshot.installation_id !== 'string' || value.snapshot.installation_id.length === 0 ||
		typeof value.snapshot.serial !== 'number' || !Number.isSafeInteger(value.snapshot.serial) || value.snapshot.serial < 1 ||
		typeof value.snapshot.key_id !== 'string' || value.snapshot.key_id.length === 0 ||
		typeof value.snapshot.status !== 'string' || !entitlementStatuses.has(value.snapshot.status) ||
		!isDateTime(value.snapshot.verified_at)) return false
	return true
}

function safeRequestID(value: string): boolean {
	return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value)
  return required.every((key) => key in value) &&
    keys.every((key) => required.includes(key) || optional.includes(key))
}

function isDateTime(value: unknown): value is string {
  return typeof value === 'string' && dateTimePattern.test(value) && Number.isFinite(Date.parse(value))
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value)
}

function isUnsignedDecimal(value: unknown): value is string {
  return typeof value === 'string' && unsignedDecimalPattern.test(value)
}

function isSignedDecimal(value: unknown): value is string {
  return typeof value === 'string' && signedDecimalPattern.test(value)
}

function isLimit(value: unknown): value is string {
  return typeof value === 'string' && limitPattern.test(value)
}

function isOptionalDate(value: Record<string, unknown>, key: string): boolean {
  return !(key in value) || isDateTime(value[key])
}

function isSection<T>(value: unknown, validate: (candidate: unknown) => candidate is T): value is DashboardSection<T> {
  if (!isRecord(value) || typeof value.available !== 'boolean') return false
  if (value.available) {
    return hasExactKeys(value, ['available', 'value']) && validate(value.value)
  }
  return hasExactKeys(value, ['available', 'reason']) &&
    typeof value.reason === 'string' && unavailableReasons.has(value.reason as DashboardUnavailableReason)
}

function parseSection<T>(value: unknown, validate: (candidate: unknown) => candidate is T): DashboardSection<T> {
  if (!isSection(value, validate)) throw invalidResponse()
  return value
}

function isMeta(value: unknown, range: DashboardRange, timezone: string): value is DashboardMeta {
  if (!isRecord(value) || !hasExactKeys(value, ['range', 'timezone', 'from', 'to', 'generated_at', 'snapshot_at', 'window_complete']) ||
    value.range !== range || value.timezone !== timezone || !isDateTime(value.from) || !isDateTime(value.to) ||
    !isDateTime(value.generated_at) || !isDateTime(value.snapshot_at) || typeof value.window_complete !== 'boolean') return false
  return Date.parse(value.from) < Date.parse(value.to)
}

function isAdminAccounts(value: unknown): value is AdminDashboard['accounts'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['tenants_total', 'tenants_active', 'tenant_users_total', 'tenant_users_active']) &&
    isCount(value.tenants_total) && isCount(value.tenants_active) && isCount(value.tenant_users_total) && isCount(value.tenant_users_active)
}

function isAdminSubscriptions(value: unknown): value is { active: number } {
  return isRecord(value) && hasExactKeys(value, ['active']) && isCount(value.active)
}

function isSettlement(value: unknown): value is AdminDashboard['billing'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['currency', 'gross_settled_debit_minor', 'reversed_credit_minor', 'net_settled_minor']) &&
    value.currency === 'CNY' && isSignedDecimal(value.gross_settled_debit_minor) &&
    isSignedDecimal(value.reversed_credit_minor) && isSignedDecimal(value.net_settled_minor)
}

function isAdminResources(value: unknown): value is AdminDashboard['resources'] extends DashboardSection<infer T> ? T : never {
  const keys = ['sites_total', 'sites_active', 'sites_sync_failed', 'nodes_total', 'certificates_total', 'certificates_valid', 'certificates_expiring_30d']
  return isRecord(value) && hasExactKeys(value, keys, ['domains_total', 'forwards_total']) && keys.every((key) => isCount(value[key])) &&
    (!('domains_total' in value) || isCount(value.domains_total)) && (!('forwards_total' in value) || isCount(value.forwards_total))
}

function isOperations(value: unknown): value is OperationStats {
  const required = ['cache_total', 'cache_open', 'cache_failed', 'jobs_total', 'jobs_open', 'jobs_failed']
  return isRecord(value) && hasExactKeys(value, required, ['cache_updated_at', 'jobs_updated_at']) &&
    required.every((key) => isCount(value[key])) && isOptionalDate(value, 'cache_updated_at') && isOptionalDate(value, 'jobs_updated_at')
}

function isOperationCountPoint(value: unknown): value is OperationCountPoint {
  return isRecord(value) && hasExactKeys(value, ['time', 'count']) && isDateTime(value.time) && isCount(value.count)
}

function isOperationAmountPoint(value: unknown): value is OperationAmountPoint {
  return isRecord(value) && hasExactKeys(value, ['time', 'sum_minor']) && isDateTime(value.time) && isUnsignedDecimal(value.sum_minor)
}

function isOperationCharts(value: unknown): value is OperationCharts {
  return isRecord(value) && hasExactKeys(value, ['new_users', 'package_sold', 'recharge']) &&
    Array.isArray(value.new_users) && value.new_users.length <= 744 && value.new_users.every(isOperationCountPoint) &&
    Array.isArray(value.package_sold) && value.package_sold.length <= 744 && value.package_sold.every(isOperationCountPoint) &&
    Array.isArray(value.recharge) && value.recharge.length <= 744 && value.recharge.every(isOperationAmountPoint)
}

function isAdminProfile(value: unknown): value is AdminProfileStats {
  return isRecord(value) && hasExactKeys(value, [], ['last_login_at', 'last_login_ip', 'last_login_geo', 'last_login_region', 'last_login_city']) &&
    isOptionalDate(value, 'last_login_at') &&
    (!('last_login_ip' in value) || typeof value.last_login_ip === 'string' && value.last_login_ip.length <= 64) &&
    (!('last_login_geo' in value) || typeof value.last_login_geo === 'string' && value.last_login_geo.length <= 64) &&
    (!('last_login_region' in value) || typeof value.last_login_region === 'string' && value.last_login_region.length <= 128) &&
    (!('last_login_city' in value) || typeof value.last_login_city === 'string' && value.last_login_city.length <= 128)
}

function isEntitlement(value: unknown): value is AdminDashboard['entitlement'] extends DashboardSection<infer T> ? T : never {
  if (!isRecord(value) || !hasExactKeys(value, ['installation_id', 'status', 'lease_status'], [
    'current_serial', 'node_limit', 'expires_at', 'grace_until', 'last_verified_at',
  ]) || typeof value.installation_id !== 'string' || value.installation_id.length > 256 ||
    typeof value.status !== 'string' || !entitlementStatuses.has(value.status) ||
    !(value.lease_status === null || typeof value.lease_status === 'string' && leaseStatuses.has(value.lease_status)) ||
    !isOptionalDate(value, 'expires_at') || !isOptionalDate(value, 'grace_until') || !isOptionalDate(value, 'last_verified_at')) return false
  return (!('current_serial' in value) || isCount(value.current_serial) && value.current_serial > 0) &&
    (!('node_limit' in value) || isCount(value.node_limit))
}

function isNodeHealth(value: unknown): value is AdminDashboard['node_health'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['total', 'online_fresh', 'stale_or_offline', 'presence_missing', 'freshness_cutoff_seconds'], ['latest_last_seen_at']) &&
    isCount(value.total) && isCount(value.online_fresh) && isCount(value.stale_or_offline) &&
    isCount(value.presence_missing) && value.freshness_cutoff_seconds === 45 && isOptionalDate(value, 'latest_last_seen_at')
}

function isAnalyticsHealth(value: unknown): value is AdminDashboard['analytics_health'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['active_streams', 'unprepared_stream_gap'], ['latest_reconciled_at', 'latest_updated_at']) &&
    isCount(value.active_streams) && isUnsignedDecimal(value.unprepared_stream_gap) &&
    isOptionalDate(value, 'latest_reconciled_at') && isOptionalDate(value, 'latest_updated_at')
}

function isAnalytics(value: unknown): value is AnalyticsStats {
  const decimalKeys = ['request_count', 'request_bytes', 'response_bytes', 'total_bytes', 'status_2xx', 'status_3xx', 'status_4xx', 'status_5xx', 'security_events']
  return isRecord(value) && hasExactKeys(value, ['metric_version', ...decimalKeys, 'average_bandwidth_bps'], ['blocked_ip_count', 'security_event_rows']) &&
    (!('blocked_ip_count' in value) || isUnsignedDecimal(value.blocked_ip_count)) &&
    (!('security_event_rows' in value) || isUnsignedDecimal(value.security_event_rows)) &&
    value.metric_version === 1 && decimalKeys.every((key) => isUnsignedDecimal(value[key])) &&
    typeof value.average_bandwidth_bps === 'number' && Number.isFinite(value.average_bandwidth_bps) && value.average_bandwidth_bps >= 0
}

function isAccountSecurity(value: unknown): value is AccountSecurityStats {
  const required = ['active_sessions', 'users_with_mfa', 'active_api_keys', 'recovery_codes_remaining']
  return isRecord(value) && hasExactKeys(value, required, ['last_security_event_at']) &&
    required.every((key) => isCount(value[key])) && isOptionalDate(value, 'last_security_event_at')
}

function isNetwork(value: unknown): value is NetworkStats {
  if (!isRecord(value) || !hasExactKeys(value, [
    'nodes_total', 'nodes_active', 'nodes_online', 'nodes_stale', 'freshness_cutoff_seconds', 'regions',
  ]) || !isCount(value.nodes_total) || !isCount(value.nodes_active) || !isCount(value.nodes_online) ||
    !isCount(value.nodes_stale) || value.freshness_cutoff_seconds !== 45 ||
    value.nodes_active > value.nodes_total || value.nodes_online + value.nodes_stale !== value.nodes_total ||
    !Array.isArray(value.regions) || value.regions.length > 10) return false
  return value.regions.every((region) => isRecord(region) &&
    hasExactKeys(region, ['region', 'nodes_total', 'nodes_online']) &&
    typeof region.region === 'string' && region.region.length > 0 && region.region.length <= 128 &&
    isCount(region.nodes_total) && isCount(region.nodes_online) && region.nodes_online <= region.nodes_total)
}

function isTrendPoint(value: unknown): value is AnalyticsStats & { hour: string } {
  if (!isRecord(value) || !isDateTime(value.hour)) return false
  const metrics = { ...value }
  delete metrics.hour
  return isAnalytics(metrics)
}

function isRankSnapshot(value: unknown): value is NonNullable<DashboardAnalyticsOverview['top_extended']>[number] {
  if (!isRecord(value) || !hasExactKeys(value, ['dimension', 'snapshot_at', 'items']) ||
    !['domain', 'url', 'ip', 'region', 'carrier'].includes(String(value.dimension)) || !isDateTime(value.snapshot_at) ||
    !Array.isArray(value.items) || value.items.length > 10) return false
  return value.items.every((item) => isRecord(item) &&
    hasExactKeys(item, ['key', 'request_count', 'response_bytes'], ['host', 'port', 'path', 'scheme']) &&
    typeof item.key === 'string' && item.key.length > 0 && item.key.length <= 4355 &&
    isUnsignedDecimal(item.request_count) && isUnsignedDecimal(item.response_bytes) &&
    (item.host === undefined || (typeof item.host === 'string' && item.host.length > 0 && item.host.length <= 253)) &&
    (item.port === undefined || (Number.isInteger(item.port) && Number(item.port) >= 1 && Number(item.port) <= 65535)) &&
    (item.path === undefined || (typeof item.path === 'string' && item.path.length <= 4096)) &&
    (item.scheme === undefined || item.scheme === 'http' || item.scheme === 'https'))
}

function isAnalyticsOverview(value: unknown): value is DashboardAnalyticsOverview {
  if (!isRecord(value) || !hasExactKeys(value, ['summary', 'trend', 'top'], ['blocked_ip_count', 'blocked_ip_trend_available', 'peak_bandwidth_bps', 'top_extended', 'settling_minutes']) ||
    ('settling_minutes' in value && (!isCount(value.settling_minutes) || value.settling_minutes === 0)) ||
    ('blocked_ip_count' in value && !isUnsignedDecimal(value.blocked_ip_count)) ||
    ('peak_bandwidth_bps' in value && !isUnsignedDecimal(value.peak_bandwidth_bps)) ||
    ('blocked_ip_trend_available' in value && typeof value.blocked_ip_trend_available !== 'boolean') || !isAnalytics(value.summary) ||
    !Array.isArray(value.trend) || value.trend.length > 744 || !value.trend.every(isTrendPoint) ||
    !Array.isArray(value.top) || value.top.length !== 3 ||
    !value.top.every((snapshot) => isRankSnapshot(snapshot) && ['domain', 'region', 'carrier'].includes(snapshot.dimension))) return false
  const dimensions = value.top.map((snapshot) => snapshot.dimension)
  if (new Set(dimensions).size !== dimensions.length || !(['domain', 'region', 'carrier'] as const).every((dimension) => dimensions.includes(dimension))) return false
  if (!('top_extended' in value)) return true
  if (!Array.isArray(value.top_extended) || value.top_extended.length !== 5 || !value.top_extended.every(isRankSnapshot)) return false
  const extendedDimensions = value.top_extended.map((snapshot) => snapshot.dimension)
  return new Set(extendedDimensions).size === extendedDimensions.length &&
    (['domain', 'url', 'ip', 'region', 'carrier'] as const).every((dimension) => extendedDimensions.includes(dimension))
}

function isIdentityVerification(value: unknown): value is { verified: boolean } {
  return isRecord(value) && hasExactKeys(value, ['verified']) && typeof value.verified === 'boolean'
}

function isTenantResources(value: unknown): value is TenantDashboard['resources'] extends DashboardSection<infer T> ? T : never {
  const keys = ['sites_total', 'sites_active', 'sites_sync_failed', 'domains_total', 'forwards_total', 'nodes_total']
  return isRecord(value) && hasExactKeys(value, keys) && keys.every((key) => isCount(value[key]))
}

function isCertificates(value: unknown): value is TenantDashboard['certificates'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['total', 'valid', 'expiring_30d']) &&
    isCount(value.total) && isCount(value.valid) && isCount(value.expiring_30d)
}

function isBalance(value: unknown): value is TenantDashboard['billing'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['currency', 'balance_minor', 'revision'], ['updated_at']) &&
    value.currency === 'CNY' && isSafeInteger(value.balance_minor) && isCount(value.revision) && isOptionalDate(value, 'updated_at')
}

function isSubscriptionItem(value: unknown): value is TenantSubscriptionItem {
  return isRecord(value) && hasExactKeys(value, [
    'id', 'name', 'ends_at', 'timezone', 'site_limit', 'domain_limit', 'node_limit', 'traffic_limit_bytes', 'traffic_progress',
  ]) &&
    typeof value.id === 'string' && uuidPattern.test(value.id) && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 512 &&
    isDateTime(value.ends_at) && typeof value.timezone === 'string' && value.timezone.length > 0 && value.timezone.length <= 128 &&
    isLimit(value.site_limit) && isLimit(value.domain_limit) && isLimit(value.node_limit) && isLimit(value.traffic_limit_bytes) &&
    isSection(value.traffic_progress, isSubscriptionTrafficProgress)
}

function isSubscriptionTrafficProgress(value: unknown): value is TenantSubscriptionItem['traffic_progress'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, [
    'period_key', 'used_bytes', 'finalized_through', 'source_watermark', 'source_evidence_sha256',
  ]) && typeof value.period_key === 'string' && value.period_key.length > 0 && value.period_key.length <= 256 &&
    isUnsignedDecimal(value.used_bytes) && isDateTime(value.finalized_through) &&
    isUnsignedDecimal(value.source_watermark) && typeof value.source_evidence_sha256 === 'string' &&
    /^[0-9a-f]{64}$/.test(value.source_evidence_sha256)
}

function isTenantSubscriptions(value: unknown): value is TenantDashboard['subscriptions'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['active', 'items']) && isCount(value.active) &&
    Array.isArray(value.items) && value.items.length <= 10 && value.items.every(isSubscriptionItem)
}

function isTrafficPackages(value: unknown): value is TenantDashboard['traffic_packages'] extends DashboardSection<infer T> ? T : never {
  return isRecord(value) && hasExactKeys(value, ['active', 'granted_bytes', 'remaining_bytes', 'used_bytes']) &&
    isCount(value.active) && isUnsignedDecimal(value.granted_bytes) && isUnsignedDecimal(value.remaining_bytes) && isUnsignedDecimal(value.used_bytes)
}

function isNotices(value: unknown): value is TenantDashboard['notices'] extends DashboardSection<infer T> ? T : never {
  if (!isRecord(value) || !hasExactKeys(value, ['unread', 'items']) || !isCount(value.unread) ||
    !Array.isArray(value.items) || value.items.length > 5) return false
  return value.items.every((item) => isRecord(item) && hasExactKeys(item, ['id', 'title', 'published_at'], ['read_at']) &&
    typeof item.id === 'string' && uuidPattern.test(item.id) && typeof item.title === 'string' && item.title.length > 0 && item.title.length <= 512 &&
    isDateTime(item.published_at) && isOptionalDate(item, 'read_at'))
}

function parseAdmin(value: unknown, range: AdminDashboardRange, timezone: string): AdminDashboard {
  const keys = [
    'dashboard_version', 'meta', 'accounts', 'subscriptions', 'billing', 'resources', 'operations',
    'entitlement', 'node_health', 'analytics_health', 'account_security', 'network', 'analytics',
  ]
  if (!isRecord(value) || !hasExactKeys(value, keys, ['profile', 'operation_charts']) || value.dashboard_version !== 2 || !isMeta(value.meta, range, timezone)) throw invalidResponse()
  return {
    dashboard_version: 2,
    meta: value.meta,
    accounts: parseSection(value.accounts, isAdminAccounts),
    subscriptions: parseSection(value.subscriptions, isAdminSubscriptions),
    billing: parseSection(value.billing, isSettlement),
    resources: parseSection(value.resources, isAdminResources),
    operations: parseSection(value.operations, isOperations),
    operation_charts: value.operation_charts === undefined ? undefined : parseSection(value.operation_charts, isOperationCharts),
    profile: value.profile === undefined ? undefined : parseSection(value.profile, isAdminProfile),
    entitlement: parseSection(value.entitlement, isEntitlement),
    node_health: parseSection(value.node_health, isNodeHealth),
    analytics_health: parseSection(value.analytics_health, isAnalyticsHealth),
    account_security: parseSection(value.account_security, isAccountSecurity),
    network: parseSection(value.network, isNetwork),
    analytics: parseSection(value.analytics, isAnalyticsOverview),
  }
}

function parseTenant(value: unknown, range: TenantDashboardRange, timezone: string): TenantDashboard {
  const keys = [
    'dashboard_version', 'meta', 'identity_verification', 'profile', 'resources', 'certificates', 'billing', 'subscriptions',
    'traffic_packages', 'operations', 'notices', 'account_security', 'network', 'analytics',
  ]
  if (!isRecord(value) || !hasExactKeys(value, keys) || value.dashboard_version !== 2 || !isMeta(value.meta, range, timezone)) throw invalidResponse()
  return {
    dashboard_version: 2,
    meta: value.meta,
    identity_verification: parseSection(value.identity_verification, isIdentityVerification),
    profile: parseSection(value.profile, isAdminProfile),
    resources: parseSection(value.resources, isTenantResources),
    certificates: parseSection(value.certificates, isCertificates),
    billing: parseSection(value.billing, isBalance),
    subscriptions: parseSection(value.subscriptions, isTenantSubscriptions),
    traffic_packages: parseSection(value.traffic_packages, isTrafficPackages),
    operations: parseSection(value.operations, isOperations),
    notices: parseSection(value.notices, isNotices),
    account_security: parseSection(value.account_security, isAccountSecurity),
    network: parseSection(value.network, isNetwork),
    analytics: parseSection(value.analytics, isAnalyticsOverview),
  }
}

async function request(path: string, accessToken: string, signal?: AbortSignal): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}` },
      signal,
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

function query(range: DashboardRange, timezone: string, filters: DashboardFilters): string {
  const parameters = new URLSearchParams({ range, timezone })
  if (filters.siteId) {
    if (!uuidPattern.test(filters.siteId)) throw new ApiError('Dashboard filter was invalid', 400, 'dashboard_invalid_request')
    parameters.set('site_id', filters.siteId)
  }
  if (filters.nodeId) {
    if (!uuidPattern.test(filters.nodeId)) throw new ApiError('Dashboard filter was invalid', 400, 'dashboard_invalid_request')
    parameters.set('node_id', filters.nodeId)
  }
  return parameters.toString()
}

async function admin(
  accessToken: string,
  range: AdminDashboardRange,
  timezone: string,
  signal?: AbortSignal,
  filters: DashboardFilters = {},
): Promise<AdminDashboard> {
  const raw = await request(`/v1/admin/dashboard?${query(range, timezone, filters)}`, accessToken, signal)
  return parseAdmin(raw, range, timezone)
}

async function tenant(
  accessToken: string,
  range: TenantDashboardRange,
  timezone: string,
  signal?: AbortSignal,
  filters: DashboardFilters = {},
): Promise<TenantDashboard> {
  const raw = await request(`/v1/dashboard?${query(range, timezone, filters)}`, accessToken, signal)
  return parseTenant(raw, range, timezone)
}

async function refreshEntitlement(accessToken: string, signal?: AbortSignal): Promise<EntitlementRefreshResult> {
	const requestID = `entitlement-refresh-${Date.now().toString(36)}`
	let response: Response
	try {
		response = await fetch(`${apiRoot}/v1/admin/entitlement/refresh`, {
			method: 'POST',
			credentials: 'include',
			headers: {
				Authorization: `Bearer ${accessToken}`,
				'Content-Type': 'application/json',
				'X-Request-ID': requestID,
				'Idempotency-Key': requestID,
			},
			body: '{}',
			signal,
		})
	} catch {
		throw networkApiError()
	}
	if (!response.ok) throw await responseApiError(response)
	try {
		const value: unknown = await response.json()
		if (!isEntitlementRefreshResult(value)) throw invalidResponse()
		return value
	} catch (error) {
		if (error instanceof ApiError) throw error
		throw invalidResponse()
	}
}

function intlLocale(locale: string | undefined): 'zh-CN' | 'en-US' {
  return locale === 'en-US' ? 'en-US' : 'zh-CN'
}

export function formatDashboardInteger(value: string, locale?: string): string {
  return new Intl.NumberFormat(intlLocale(locale), { maximumFractionDigits: 0 }).format(BigInt(value))
}

export function formatDashboardBytes(value: string, locale?: string): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB'] as const
  const raw = BigInt(value)
  let divisor = 1n
  let unit = 0
  while (raw >= divisor * 1024n && unit < units.length - 1) {
    divisor *= 1024n
    unit += 1
  }
  const hundredths = (raw * 100n + divisor / 2n) / divisor
  const whole = hundredths / 100n
  const fraction = hundredths % 100n
  const formattedWhole = new Intl.NumberFormat(intlLocale(locale), { maximumFractionDigits: 0 }).format(whole)
  if (fraction === 0n) return `${formattedWhole} ${units[unit]}`
  const decimal = new Intl.NumberFormat(intlLocale(locale)).formatToParts(1.1)
    .find((part) => part.type === 'decimal')?.value ?? '.'
  return `${formattedWhole}${decimal}${fraction.toString().padStart(2, '0')} ${units[unit]}`
}

export function formatDashboardCurrencyMinor(value: string, locale?: string): string {
  const minor = BigInt(value)
  const absolute = minor < 0n ? -minor : minor
  const major = absolute / 100n
  const fraction = (absolute % 100n).toString().padStart(2, '0')
  const parts = new Intl.NumberFormat(intlLocale(locale), {
    style: 'currency',
    currency: 'CNY',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).formatToParts(major).map((part) => part.type === 'fraction' ? fraction : part.value).join('')
  return minor < 0n ? `-${parts}` : parts
}

// Renders "IP (国家-省-市)" like the reference overview. Only a two-letter
// country code is localized; any other stored geo value is shown verbatim.
export function formatDashboardLoginSource(profile: AdminProfileStats, locale?: string): string | undefined {
  const ip = profile.last_login_ip
  if (!ip || ip === 'unknown') return undefined
  const geo = profile.last_login_geo && profile.last_login_geo !== 'unknown' ? profile.last_login_geo : ''
  let country = geo
  if (/^[A-Z]{2}$/.test(geo)) {
    try {
      country = new Intl.DisplayNames([intlLocale(locale)], { type: 'region' }).of(geo) ?? geo
    } catch {
      country = geo
    }
  }
  const parts = [country, profile.last_login_region ?? '', profile.last_login_city ?? '']
    .filter((part, index, all) => part !== '' && part !== all[index - 1])
  return parts.length === 0 ? ip : `${ip} (${parts.join('-')})`
}

export const dashboardApi = { admin, tenant, refreshEntitlement }
