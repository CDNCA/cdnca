import { ApiError, networkApiError, responseApiError } from './auth'

export type SiteStatus =
  | 'active'
  | 'disabled'
  | 'package_expired'
  | 'traffic_exceeded'
  | 'locked'
  | 'syncing'
  | 'sync_failed'

export type SiteOperationalStatus =
  | 'normal'
  | 'package_expired'
  | 'traffic_exceeded'
  | 'locked'

export type SiteStatusCompatibilityCode = 200 | 512 | 513 | 514

export type SiteIPv6RuntimeState = 'disabled' | 'pending' | 'active' | 'failed'

export interface SiteListenerState {
  ipv6_desired_enabled: boolean
  ipv6_runtime_state: SiteIPv6RuntimeState
}

const statusByCompatibilityCode: Record<SiteStatusCompatibilityCode, SiteOperationalStatus> = {
  200: 'normal',
  512: 'package_expired',
  513: 'traffic_exceeded',
  514: 'locked',
}

export function siteStatusFromCompatibilityCode(code: number): SiteOperationalStatus | null {
  return statusByCompatibilityCode[code as SiteStatusCompatibilityCode] ?? null
}

export function compatibilityCodeForSiteStatus(status: SiteOperationalStatus): SiteStatusCompatibilityCode {
  const entry = Object.entries(statusByCompatibilityCode).find(([, value]) => value === status)
  return Number(entry?.[0]) as SiteStatusCompatibilityCode
}

export interface SiteStatusRecovery {
  task_id: string
  task_state: 'queued' | 'running' | 'succeeded' | 'partial_failed' | 'failed' | 'cancelled'
  trigger: 'renewal' | 'traffic_top_up' | 'unlock'
  site_revision: number
  edge_source_revision: number
  desired_edge_version_id: string | null
  active_edge_version_id: string | null
  healthy: boolean
  attempt: number
  sequence: number
}

export interface SiteTrafficEnforcement {
  state: 'suspended' | 'recovered'
  subscription_id: string
  suspended_at: string
  recovered_at: string | null
  recovered_reason: string | null
}

export const safeSiteTLSProtocols = ['TLSv1.2', 'TLSv1.3'] as const
// SSLv2/SSLv3 are never accepted; TLSv1/TLSv1.1 only with the legacy cipher
// preset.
export const legacySiteTLSProtocols = ['SSLv2', 'SSLv3'] as const
export const siteTLSProtocolOrder = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const
export type SafeSiteTLSProtocol = (typeof safeSiteTLSProtocols)[number]
export type LegacySiteTLSProtocol = (typeof legacySiteTLSProtocols)[number]
export type SiteTLSProtocol = string
export const siteTLSCipherPresets = ['modern', 'compatible', 'legacy', 'custom'] as const
export type SiteTLSCipherPreset = (typeof siteTLSCipherPresets)[number]
// The custom preset's whitelist, equal to
// edgeconfig.TLSCustomCipherSuites (libs/edgeconfig/site_tls_profile.go,
// the OpenAPI enum of tls_cipher_suites). TLS 1.2 suites only.
export const siteTLSCustomCipherSuites = [
  'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384',
  'ECDHE-ECDSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA', 'ECDHE-ECDSA-AES256-SHA', 'ECDHE-RSA-AES256-SHA',
  'AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'AES128-SHA256', 'AES256-SHA256', 'AES128-SHA', 'AES256-SHA',
] as const

function aeadSuite(suite: string): boolean {
  return suite.includes('-GCM-') || suite.includes('CHACHA20-POLY1305')
}

/** The control plane's rule (edgeconfig.ValidateTLSCipherSuites): 1..20
 * whitelisted names without repeats, among them an ECDHE-ECDSA and an
 * ECDHE-RSA AEAD suite (a handshake for either certificate type). */
export function validSiteTLSCipherSuites(value: readonly string[] | undefined): boolean {
  if (!value || value.length === 0 || value.length > siteTLSCustomCipherSuites.length) return false
  if (new Set(value).size !== value.length) return false
  if (!value.every((suite) => (siteTLSCustomCipherSuites as readonly string[]).includes(suite))) return false
  return value.some((suite) => suite.startsWith('ECDHE-ECDSA-') && aeadSuite(suite)) &&
    value.some((suite) => suite.startsWith('ECDHE-RSA-') && aeadSuite(suite))
}
export const siteTLSClientAuthModes = ['off', 'optional', 'required'] as const
export type SiteTLSClientAuth = (typeof siteTLSClientAuthModes)[number]

// TLS version presets the page offers; any ascending contiguous range is
// valid on the wire.
export const siteTLSVersionPresets = {
  tls13: ['TLSv1.3'],
  recommended: ['TLSv1.2', 'TLSv1.3'],
  compatible: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
} as const satisfies Record<string, readonly string[]>
export type SiteTLSVersionPreset = keyof typeof siteTLSVersionPresets

/** The preset whose protocols equal value, or null for another range. */
export function siteTLSVersionPreset(value: readonly string[] | undefined): SiteTLSVersionPreset | null {
  const protocols = value ?? safeSiteTLSProtocols
  for (const [name, preset] of Object.entries(siteTLSVersionPresets)) {
    if (sameStrings(protocols, preset)) return name as SiteTLSVersionPreset
  }
  return null
}

/** An ascending contiguous range of TLSv1..TLSv1.3. */
export function validSiteTLSProtocolRange(value: readonly string[]): boolean {
  const first = siteTLSProtocolOrder.indexOf(value[0] as (typeof siteTLSProtocolOrder)[number])
  return value.length > 0 && first >= 0 && value.every((protocol, index) => siteTLSProtocolOrder[first + index] === protocol)
}

export function siteTLSNeedsLegacyCiphers(value: readonly string[] | undefined): boolean {
  return (value ?? []).some((protocol) => protocol === 'TLSv1' || protocol === 'TLSv1.1')
}

export interface SiteLockState {
  locked: boolean
  reason: string | null
  locked_at: string | null
  operator: { display_name: string } | null
}

export interface SiteListItem {
  id: string
  display_id: string
  version: number
  owner: { id: string; display_id?: string; display_name: string } | null
  domain: string
  domains?: string[]
  listen_ports: string[]
  origins: string[]
  cname: string
  package_subscription_id?: string | null
  cname_state?: 'pending' | 'failed' | 'done' | null
  // Why the current CNAME task failed (cname_state=failed), e.g. cname_zone_not_configured.
  cname_failure_code?: string | null
  // The CNAME domain of the site ('' = the default CNAME domain).
  cname_domain?: string | null
  cname_task_id?: string | null
  cname_current_revision?: number | null
  cname_lkg_revision?: number | null
  https_enabled: boolean
  /** WEB-C01/C05: the site's current certificate binding is a bind. */
  https_certificate_bound?: boolean
  package: { id: string; name: string } | null
  group_name: string | null
  region: { name: string; node_group_name: string } | null
  status: SiteStatus
  status_state?: SiteOperationalStatus
  status_code?: SiteStatusCompatibilityCode
  status_recovery?: SiteStatusRecovery | null
  traffic_enforcement?: SiteTrafficEnforcement | null
  listener_state: SiteListenerState
  lock: SiteLockState
  created_at: string
  // 建站「DNS API（自动添加记录）」任务；null/缺省表示没有选择 DNS API
  auto_dns?: SiteAutoDNSStatus | null
  /** 服务端接入状态（缺省表示旧服务端，前端退回 FLOW001 的本地判定）。 */
  access_readiness?: SiteAccessReadiness | null
  // 网站因没有有效套餐而不下发的原因；套餐有效时为 null。
  package_unavailable_reason?: SitePackageUnavailableReason | null
}

// package 检查项（无有效套餐不下发）排第一。
export type SiteAccessCheckCode = 'package' | 'line_group' | 'cname_generated' | 'dns_resolved' | 'https_cert' | 'published'

/** 接入状态：ready 全部通过；blocked 需要有人处理；pending 等生成/解析/发布。 */
export interface SiteAccessReadiness {
  state: 'ready' | 'pending' | 'blocked'
  checks: Array<{ code: SiteAccessCheckCode; ok: boolean; detail: string; checked_at: string | null }>
}

/** Why a site is not served for lack of a valid package. */
export type SitePackageUnavailableReason = 'no_package' | 'package_disabled' | 'package_deleted'

export interface SiteAutoDNSStatus {
  provider_id: string
  provider_name: string
  state: 'pending' | 'done' | 'failed'
  failure_code: string | null
  attempts: number
  results: Array<{ domain: string; before?: string; code?: string }>
  updated_at: string
}

export interface SiteListResponse {
  items: SiteListItem[]
  total: number
  page: number
  limit: number
}

export interface SiteListParams {
  page: number
  limit: number
  domain?: string
  domains?: string
  origin_ip?: string
  site_ids?: string
  owner?: string
  package_id?: string
  /** Package name substring (name form of package_id). */
  package?: string
  /** Domain substring or exact display ID (name form of site_ids). */
  site?: string
  group_id?: string
  region_id?: string
  node_group_id?: string
  cname_domain?: string
  cname_hostname?: string
  http_port?: string
  https_port?: string
  https_enabled?: string
  enabled?: string
  status?: string
  is_default?: string
  sync_status?: string
}

export type SiteDomainExportParams = Omit<SiteListParams, 'page' | 'limit'> & {
  target_scope_id?: string
}

export interface SiteDomainExport {
  blob: Blob
  filename: string
  snapshotID: string
}

export interface SiteBasicConfig {
  package_id: string | null
  package_subscription_id?: string | null
  cname_mode?: 'site' | 'package' | ''
  cname_domain?: string
  cname_hostname?: string
  cname_regenerate?: boolean
  package_name: string | null
  group_id: string | null
  group_name: string | null
  domains: string[]
  http_enabled: boolean
  http_listen_ports: string[]
  https_listen_ports: string[]
  ipv6_enabled: boolean
  tls_protocols?: SiteTLSProtocol[]
  // TLS profile. Omitted on create: the system default (cipher
  // preset, OCSP stapling); omitted on update: unchanged.
  tls_cipher_preset?: SiteTLSCipherPreset
  // The custom preset's ordered list (sent with
  // tls_cipher_preset custom; a response carries it only then).
  tls_cipher_suites?: string[]
  tls_ocsp_stapling?: boolean
  tls_client_auth?: SiteTLSClientAuth
  // The client CA bundle (PEM CA certificates); sent with tls_client_auth.
  tls_client_ca_pem?: string
  // HTTP/2 and HTTP/3 per site (omitted on create: the
  // owner's default, else on; on update: unchanged). HTTP/3 needs TLSv1.3.
  http2_enabled?: boolean
  http3_enabled?: boolean
  // ssl_prefer_server_ciphers: null by the cipher preset (modern off,
  // compatible/legacy on); null on update restores that.
  tls_prefer_server_ciphers?: boolean | null
  origins: string[]
  cname: string
  cname_state?: 'pending' | 'failed' | 'done' | null
  // Why the current CNAME task failed (cname_state=failed), e.g. cname_zone_not_configured.
  cname_failure_code?: string | null
  cname_task_id?: string | null
  cname_current_revision?: number | null
  cname_lkg_revision?: number | null
  https_enabled: boolean
  // FX07: plain HTTP redirects to https_redirect_port (0: the lowest HTTPS
  // port). Omitted on create: the site follows the system default.
  force_https?: boolean
  https_redirect_port?: number
  // 所有域名共用缓存. Off (or omitted): each host caches its own objects.
  cache_shared_across_domains?: boolean
  // 响应头显示缓存状态 (X-CDN-Cache). The server
  // defaults it on; hidden by the node while the site is at attack
  // escalation level B or above. Omitted on update: unchanged.
  cache_status_header?: boolean
  enabled: boolean
  status: SiteStatus
  // Response only (PJ-C02): the server derives it from the site's latest
  // automatic publication and refuses a write carrying it; writeBody drops it.
  sync_status?: 'synced' | 'pending' | 'failed'
  is_default: boolean
}

// A create leaves out the listen ports, IPv6, TLS protocols, load balancing,
// origin timeouts and origin protocol the user did not set (CU-SITE-02): the
// server fills them from the owner's 默认设置 (group over global), then the
// platform's, then its built-in defaults. A value the create names wins.
export type CreateSiteBasic = Omit<SiteBasicConfig, 'http_listen_ports' | 'https_listen_ports' | 'ipv6_enabled'> &
  Partial<Pick<SiteBasicConfig, 'http_listen_ports' | 'https_listen_ports' | 'ipv6_enabled'>>
export type CreateSiteOriginPool = Omit<SiteOriginPool, 'balance_method' | 'connect_timeout_ms' | 'read_timeout_ms'> &
  Partial<Pick<SiteOriginPool, 'balance_method' | 'connect_timeout_ms' | 'read_timeout_ms'>>

export interface CreateSiteRequest {
  target_scope_id?: string
  owner_id?: string
  basic: CreateSiteBasic
  origin_pool?: CreateSiteOriginPool
  // 建站「DNS API（自动添加记录）」：本人已验证的 DNS 账号，建站后自动添加业务域名 CNAME
  dns_provider_id?: string
}

export type OriginBalanceMethod =
  | 'round_robin'
  | 'ip_hash'
  | 'url_hash'
  | 'least_conn'
  | 'random'
  | 'hash'
  | 'sticky'

export interface SiteOrigin {
  host: string
  port: number
  weight: number
  enabled: boolean
  // 0 is the primary, n backup n (switched to in order when every origin of
  // the levels before it is down). Absent: a primary.
  level?: number
  max_conns?: number
  // No port of its own: the pool's HTTP (HTTPS for scheme https) 回源端口;
  // the server then returns that port in port (migration 490).
  port_inherited?: boolean
}

export type OriginScheme = 'http' | 'https' | 'follow'
// visitor_port: 访问域名+端口 (the visitor's host with the visited port).
export type OriginRequestHostMode = 'visitor' | 'visitor_port' | 'origin' | 'custom'
// 'none': 不校验源站证书 (nodes need ORIGIN_TLS_NO_VERIFY)
export type OriginTLSTrust = 'system' | 'custom' | 'none'
export type OriginStickySource = 'cookie' | 'header' | 'arg'

export interface OriginForwarding {
  hash_key?: string
  sticky?: { source: OriginStickySource; name: string } | null
  request_host?: { mode: OriginRequestHostMode; value?: string }
  scheme?: OriginScheme
  // HTTP 回源端口 / HTTPS 回源端口 (pool defaults, 80 / 443)
  http_port?: number
  https_port?: number
  tls?: { sni?: string; trust: OriginTLSTrust; ca_pem?: string }
  // follow + follow_port is 跟随协议和端口
  follow_port?: boolean
  websocket?: { enabled: boolean; allowed_origins: string[] } | null
  trusted_proxy_cidrs?: string[]
  // Follow the origin's 301/302/303/307/308 for a bodyless GET/HEAD
  // (absent: off; max_hops 1..5, 0 = default 3). Needs ORIGIN_FOLLOW_REDIRECT.
  follow_redirect?: OriginFollowRedirect
  // site-backend6 (SITE_EDGE_OPTIONS): 搜索引擎回源 host[:port] ('' off),
  // 源站申请证书, 数据实时返回/发送 (false: unbuffered, uncached requests
  // only) and 网站 L2 配置 (platform only).
  search_engine_origin?: string
  acme_passthrough?: boolean
  response_buffering?: boolean
  request_buffering?: boolean
  l2_mode?: 'package' | 'off' | 'custom'
  l2_config_id?: string | null
  // 回源鉴权开关: false keeps the rules but signs nothing (absent: on).
  origin_auth_enabled?: boolean
}

export interface OriginFollowRedirect {
  enabled: boolean
  max_hops: number
  cross_origin: boolean
}

export const defaultFollowRedirectHops = 3
export const maxFollowRedirectHops = 5

export interface SiteOriginPoolBase {
  origins: SiteOrigin[]
  balance_method: OriginBalanceMethod
  failover_tries: number
  connect_timeout_ms: number
  read_timeout_ms: number
  // Absent in requests saved before origin keepalive existed: the server
  // then keeps its default (on, 60 s).
  keepalive_enabled?: boolean
  keepalive_idle_timeout_ms?: number
  // After a higher level recovers: auto switches back, manual waits for
  // the user's switch back (origin-failback). Absent: auto.
  failback_mode?: OriginFailbackMode
  health_check_path?: string
  // Write only: backup origins in switch order, one host[:port] each (entry
  // n is level n); origins then carries only the primaries.
  backup_origins?: string[]
}

export type OriginFailbackMode = 'auto' | 'manual'

export type SiteOriginPool = SiteOriginPoolBase & OriginForwarding

export const defaultKeepaliveIdleTimeoutMs = 60_000

// originForwarding is the pool's forwarding settings with the server's
// defaults filled in.
export interface EffectiveOriginForwarding {
  hash_key?: string
  sticky?: { source: OriginStickySource; name: string }
  request_host: { mode: OriginRequestHostMode; value?: string }
  scheme: OriginScheme
  http_port: number
  https_port: number
  tls: { sni?: string; trust: OriginTLSTrust; ca_pem?: string }
  follow_port: boolean
  origin_auth_enabled: boolean
  websocket: { enabled: boolean; allowed_origins: string[] }
  trusted_proxy_cidrs: string[]
  follow_redirect: OriginFollowRedirect
}

export function originForwarding(pool: SiteOriginPool): EffectiveOriginForwarding {
  return {
    hash_key: pool.hash_key || undefined,
    sticky: pool.sticky ?? undefined,
    request_host: pool.request_host ?? { mode: 'visitor', value: '' },
    scheme: pool.scheme ?? 'http',
    http_port: pool.http_port ?? 80,
    https_port: pool.https_port ?? 443,
    tls: pool.tls ?? { trust: 'system' },
    follow_port: pool.follow_port ?? false,
    origin_auth_enabled: pool.origin_auth_enabled ?? true,
    websocket: pool.websocket ?? { enabled: true, allowed_origins: [] },
    trusted_proxy_cidrs: pool.trusted_proxy_cidrs ?? [],
    follow_redirect: {
      enabled: pool.follow_redirect?.enabled ?? false,
      max_hops: pool.follow_redirect?.max_hops || defaultFollowRedirectHops,
      cross_origin: pool.follow_redirect?.cross_origin ?? false,
    },
  }
}

// inheritedOriginPort mirrors the server: origins without their own port use
// the pool's HTTPS port for scheme https, else its HTTP port.
export function inheritedOriginPort(pool: SiteOriginPool): number {
  const forwarding = originForwarding(pool)
  return forwarding.scheme === 'https' ? forwarding.https_port : forwarding.http_port
}

// withInheritedOriginPorts sets every port_inherited origin's port to the
// pool's, as the server stores it.
export function withInheritedOriginPorts<T extends SiteOriginPool>(pool: T): T {
  if (!pool.origins.some((origin) => origin.port_inherited)) return pool
  const port = inheritedOriginPort(pool)
  return { ...pool, origins: pool.origins.map((origin) => origin.port_inherited ? { ...origin, port } : origin) }
}

export function originKeepalive(pool: SiteOriginPool): { enabled: boolean; idleTimeoutMs: number } {
  return { enabled: pool.keepalive_enabled ?? true, idleTimeoutMs: pool.keepalive_idle_timeout_ms ?? defaultKeepaliveIdleTimeoutMs }
}

export interface SiteDetail {
  id: string
  scope_id?: string
  version: number
  owner: { id: string; display_id?: string; display_name: string } | null
  created_at: string
  updated_at: string
  lock: SiteLockState
  status_state?: SiteOperationalStatus
  status_code?: SiteStatusCompatibilityCode
  status_recovery?: SiteStatusRecovery | null
  traffic_enforcement?: SiteTrafficEnforcement | null
  listener_state: SiteListenerState
  /** be-gap-2: the site has a bound certificate (HTTPS / forced HTTPS can only be turned on with one). */
  https_certificate_bound?: boolean
  /** 与列表项同一字段。 */
  access_readiness?: SiteAccessReadiness | null
  basic: SiteBasicConfig
  origin_pool: SiteOriginPool
  // The package subscription's period end, whole days since it passed (0
  // while valid) and days left (rounded up, 0 once passed; tp-b3a-be); null
  // without a subscription (site-backend6).
  package_expires_at?: string | null
  package_expired_days?: number | null
  package_remaining_days?: number | null
  package_unavailable_reason?: SitePackageUnavailableReason | null
}

export function operationalSiteStatus(value: Pick<SiteListItem, 'status' | 'status_state' | 'lock'>): SiteOperationalStatus {
  if (value.status_state) return value.status_state
  if (value.lock.locked) return 'locked'
  if (value.status === 'package_expired' || value.status === 'traffic_exceeded') return value.status
  return 'normal'
}

export interface PatchSiteBasicRequest {
  expected_version: number
  section: 'basic'
  changes: SiteBasicConfig
}

export interface PatchSiteOriginRequest {
  expected_version: number
  section: 'origin'
  changes: SiteOriginPool
}

export interface LockSiteRequest {
  expected_version: number
  reason: string
}

export interface UnlockSiteRequest {
  expected_version: number
}

export type BatchSiteAction = 'enable' | 'disable' | 'delete' | 'regenerate_cname' | 'set_protocols'

// set_protocols: what every selected site gets; an omitted key keeps each
// site's value, tls_prefer_server_ciphers null is "by the cipher preset".
export interface BatchSiteProtocols {
  http2_enabled?: boolean
  http3_enabled?: boolean
  tls_prefer_server_ciphers?: boolean | null
}

export type BatchSiteActionErrorCode =
  | 'site_not_found'
  | 'site_locked'
  | 'version_conflict'
  | 'entitlement_unavailable'
  | 'entitlement_state_denied'
  | 'entitlement_feature_denied'
  | 'entitlement_quota_denied'
  | 'entitlement_quota_exceeded'
  | 'cname_not_configured'
  | 'cname_not_failed'
  | 'cname_not_regenerable'
  | 'permission_denied'
  | 'site_domain_claim_suspended'
  | 'package_subscription_inactive'
  | 'package_resource_quota_exceeded'
  | 'package_feature_denied'

export interface BatchSiteActionRequest {
  action: BatchSiteAction
  items: Array<{ id: string; expected_version: number }>
  protocols?: BatchSiteProtocols
}

export type BatchSiteActionItemResult =
  | { id: string; status: 'updated'; site: SiteDetail }
  | { id: string; status: 'deleted' }
  | { id: string; status: 'queued'; site: SiteDetail }
  | { id: string; status: 'failed'; error: { code: BatchSiteActionErrorCode } }

export interface BatchSiteActionResponse {
  items: BatchSiteActionItemResult[]
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

const batchErrorCodes = new Set<BatchSiteActionErrorCode>([
  'site_not_found',
  'site_locked',
  'version_conflict',
  'entitlement_unavailable',
  'entitlement_state_denied',
  'entitlement_feature_denied',
  'entitlement_quota_denied',
  'entitlement_quota_exceeded',
  'cname_not_configured',
  'cname_not_failed',
  'cname_not_regenerable',
  'permission_denied',
  'site_domain_claim_suspended',
  'package_subscription_inactive',
  'package_resource_quota_exceeded',
  'package_feature_denied',
])

async function request<T>(
  accessToken: string,
  path: string,
  init: RequestInit = {},
  expectedStatus?: number,
): Promise<T> {
  let response: Response

  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }

  if (!response.ok) {
    throw await responseApiError(response)
  }
  if (expectedStatus !== undefined && response.status !== expectedStatus) {
    throw new ApiError('Unexpected success response', 502, 'invalid_response')
  }

  if (response.status === 204) return null as T
  return (await response.json()) as T
}

function queryString(params: SiteListParams): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') query.set(key, String(value))
  }
  return query.toString()
}

async function list(accessToken: string, params: SiteListParams): Promise<SiteListResponse> {
  const raw = await request<unknown>(accessToken, `/v1/sites?${queryString(params)}`)
  if (
    typeof raw !== 'object' ||
    raw === null ||
    !('items' in raw) ||
    !('total' in raw) ||
    !('page' in raw) ||
    !('limit' in raw) ||
    !Array.isArray(raw.items) ||
    typeof raw.total !== 'number' ||
    typeof raw.page !== 'number' ||
    typeof raw.limit !== 'number' ||
    !raw.items.every(
      (item) =>
        typeof item === 'object' &&
        item !== null &&
        'version' in item &&
        'lock' in item &&
        Number.isInteger(item.version) &&
        Number(item.version) > 0 &&
        validLockState(item.lock) &&
        validListenerState(item.listener_state) &&
        validStatusProjection(item as Record<string, unknown>),
    )
  ) {
    throw new ApiError('网站列表响应格式无效', 502, 'invalid_response')
  }
  return raw as SiteListResponse
}

function validLockState(value: unknown): value is SiteLockState {
  if (typeof value !== 'object' || value === null) return false
  const lock = value as SiteLockState
  return (
    typeof lock.locked === 'boolean' &&
    (typeof lock.reason === 'string' || lock.reason === null) &&
    (typeof lock.locked_at === 'string' || lock.locked_at === null) &&
    (lock.operator === null ||
      (typeof lock.operator === 'object' &&
        lock.operator !== null &&
        typeof lock.operator.display_name === 'string'))
  )
}

const siteIPv6RuntimeStates = new Set<SiteIPv6RuntimeState>(['disabled', 'pending', 'active', 'failed'])

function validListenerState(value: unknown, desired?: boolean): value is SiteListenerState {
  if (typeof value !== 'object' || value === null) return false
  const state = value as SiteListenerState
  return typeof state.ipv6_desired_enabled === 'boolean' &&
    (desired === undefined || state.ipv6_desired_enabled === desired) &&
    typeof state.ipv6_runtime_state === 'string' &&
    siteIPv6RuntimeStates.has(state.ipv6_runtime_state)
}

const operationalSiteStatuses = new Set<SiteOperationalStatus>([
  'normal',
  'package_expired',
  'traffic_exceeded',
  'locked',
])

function validStatusProjection(value: Record<string, unknown>): boolean {
  if (value.status_state === undefined && value.status_code === undefined && value.status_recovery === undefined) {
    return true
  }
  if (
    typeof value.status_state !== 'string' ||
    !operationalSiteStatuses.has(value.status_state as SiteOperationalStatus) ||
    typeof value.status_code !== 'number' ||
    siteStatusFromCompatibilityCode(value.status_code) !== value.status_state
  ) {
    return false
  }
  if (value.status_recovery === null) return true
  if (typeof value.status_recovery !== 'object' || value.status_recovery === null) return false
  const recovery = value.status_recovery as Record<string, unknown>
  return (
    typeof recovery.task_id === 'string' &&
    typeof recovery.task_state === 'string' &&
    typeof recovery.trigger === 'string' &&
    Number.isInteger(recovery.site_revision) && Number(recovery.site_revision) > 0 &&
    Number.isInteger(recovery.edge_source_revision) && Number(recovery.edge_source_revision) > 0 &&
    (typeof recovery.desired_edge_version_id === 'string' || recovery.desired_edge_version_id === null) &&
    (typeof recovery.active_edge_version_id === 'string' || recovery.active_edge_version_id === null) &&
    typeof recovery.healthy === 'boolean' &&
    Number.isInteger(recovery.attempt) && Number(recovery.attempt) >= 0 &&
    Number.isInteger(recovery.sequence) && Number(recovery.sequence) >= 0
  )
}

const originBalanceMethods = new Set<OriginBalanceMethod>([
  'round_robin',
  'ip_hash',
  'url_hash',
  'least_conn',
  'random',
  'hash',
  'sticky',
])

const siteTLSProtocolPattern = /^(?:SSLv2|SSLv3|TLSv[0-9]+(?:\.[0-9]+)?)$/

function canonicalSiteDomain(raw: string): string | null {
  let value = raw.trim().toLowerCase()
  const wildcard = value.startsWith('*.')
  if (value.includes('*') && !wildcard) return null
  if (wildcard) value = value.slice(2)
  if (value.endsWith('.')) value = value.slice(0, -1)
  if (!value || /[\s/:@\\[\]?#]/u.test(value)) return null

  let hostname: string
  try {
    const parsed = new URL(`http://${value}/`)
    if (
      parsed.username || parsed.password || parsed.port || parsed.pathname !== '/' ||
      parsed.search || parsed.hash
    ) return null
    hostname = parsed.hostname.toLowerCase()
  } catch {
    return null
  }
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1)
  const labels = hostname.split('.')
  if (
    labels.length < 2 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  ) return null
  const canonical = wildcard ? `*.${hostname}` : hostname
  return canonical.length <= 253 ? canonical : null
}

export function canonicalSiteDomains(values: readonly string[]): string[] | null {
  if (values.length < 1 || values.length > 100) return null
  const canonical = values.map(canonicalSiteDomain)
  if (canonical.some((value) => value === null)) return null
  return [...new Set(canonical as string[])].sort((left, right) => left < right ? -1 : left > right ? 1 : 0)
}

export function safeSiteTLSProtocolSelection(value: readonly string[] | undefined): boolean {
  if (value === undefined) return true
  return validSiteTLSProtocolRange(value)
}

/** The TLS profile of a write is consistent (the control plane checks again). */
export function validSiteTLSProfile(value: Pick<SiteBasicConfig, 'tls_protocols' | 'tls_cipher_preset' |
  'tls_cipher_suites' | 'tls_client_auth' | 'tls_client_ca_pem'>): boolean {
  if (value.tls_cipher_preset !== undefined && !siteTLSCipherPresets.includes(value.tls_cipher_preset)) return false
  if (siteTLSNeedsLegacyCiphers(value.tls_protocols) && value.tls_cipher_preset !== undefined &&
    value.tls_cipher_preset !== 'legacy') return false
  if (value.tls_cipher_preset === 'custom') {
    if (!validSiteTLSCipherSuites(value.tls_cipher_suites)) return false
    if (value.tls_protocols !== undefined && !value.tls_protocols.includes('TLSv1.2')) return false
  } else if (value.tls_cipher_suites != null) {
    return false
  }
  if (value.tls_client_auth === undefined) return value.tls_client_ca_pem === undefined
  if (!siteTLSClientAuthModes.includes(value.tls_client_auth)) return false
  if (value.tls_client_auth === 'off') return !value.tls_client_ca_pem
  return typeof value.tls_client_ca_pem === 'string' && value.tls_client_ca_pem.includes('-----BEGIN CERTIFICATE-----') &&
    value.tls_client_ca_pem.length <= 262_144
}

export function canonicalSiteTLSProtocolSelection(
  value: readonly string[],
): SafeSiteTLSProtocol[] {
  return safeSiteTLSProtocols.filter((safe) => value.some((protocol) => protocol === safe))
}

function validSiteTLSProtocolFacts(value: unknown): value is SiteTLSProtocol[] {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 8 &&
    new Set(value).size === value.length &&
    value.every((protocol) =>
      typeof protocol === 'string' &&
      protocol.length >= 5 &&
      protocol.length <= 16 &&
      siteTLSProtocolPattern.test(protocol),
    )
}

// Fields a site write never carries: sync_status is derived by the server
// (PJ-C02; drafts spread from a read detail carry it, and a stored retry body
// may predate 497), and the community edition binds no package to a site, so
// package_id / package_subscription_id / package_name are left out as well.
const serverOnlyBasicKeys = ['sync_status', 'package_id', 'package_subscription_id', 'package_name'] as const

function writeBody(serializedBody: string): string {
  const body = JSON.parse(serializedBody) as { basic?: Record<string, unknown>; changes?: Record<string, unknown> }
  const basic = body.basic ?? body.changes
  if (!basic || !serverOnlyBasicKeys.some((key) => key in basic)) return serializedBody
  for (const key of serverOnlyBasicKeys) delete basic[key]
  return JSON.stringify(body)
}

function assertSafeBasicWrite(value: CreateSiteBasic): void {
  const domains = canonicalSiteDomains(value.domains)
  if (!domains || !sameStrings(value.domains, domains)) {
    throw new ApiError('Site domains are invalid', 400, 'validation_error')
  }
  if (!safeSiteTLSProtocolSelection(value.tls_protocols) || !validSiteTLSProfile(value)) {
    throw new ApiError('Site TLS protocols are invalid', 400, 'validation_error')
  }
  if (value.ipv6_enabled !== undefined && typeof value.ipv6_enabled !== 'boolean') {
    throw new ApiError('Site IPv6 desired state is invalid', 400, 'validation_error')
  }
}

function validOriginPool(value: unknown): value is SiteOriginPool {
  if (typeof value !== 'object' || value === null) return false
  const pool = value as SiteOriginPool
  if (
    !Array.isArray(pool.origins) ||
    pool.origins.length < 1 ||
    pool.origins.length > 32 ||
    !originBalanceMethods.has(pool.balance_method) ||
    !Number.isInteger(pool.failover_tries) ||
    pool.failover_tries < 1 ||
    !Number.isInteger(pool.connect_timeout_ms) ||
    pool.connect_timeout_ms < 50 ||
    pool.connect_timeout_ms > 30_000 ||
    !Number.isInteger(pool.read_timeout_ms) ||
    pool.read_timeout_ms < 100 ||
    pool.read_timeout_ms > 300_000 ||
    (pool.keepalive_enabled !== undefined && typeof pool.keepalive_enabled !== 'boolean') ||
    (pool.keepalive_idle_timeout_ms !== undefined && (!Number.isInteger(pool.keepalive_idle_timeout_ms) ||
      pool.keepalive_idle_timeout_ms < 1_000 || pool.keepalive_idle_timeout_ms > 300_000))
  ) {
    return false
  }
  const endpoints = new Set<string>()
  let enabled = 0
  for (const origin of pool.origins) {
    if (
      typeof origin !== 'object' ||
      origin === null ||
      typeof origin.host !== 'string' ||
      origin.host.length < 1 ||
      origin.host.length > 253 ||
      !Number.isInteger(origin.port) ||
      origin.port < 1 ||
      origin.port > 65_535 ||
      !Number.isInteger(origin.weight) ||
      origin.weight < 1 ||
      origin.weight > 100 ||
      typeof origin.enabled !== 'boolean' ||
      (origin.level !== undefined && (!Number.isInteger(origin.level) || origin.level < 0 || origin.level > 15)) ||
      (origin.max_conns !== undefined && (!Number.isInteger(origin.max_conns) || origin.max_conns < 0 || origin.max_conns > 100_000)) ||
      (origin.port_inherited !== undefined && typeof origin.port_inherited !== 'boolean')
    ) {
      return false
    }
    const endpoint = `${origin.host.toLowerCase()}:${origin.port}`
    if (endpoints.has(endpoint)) return false
    endpoints.add(endpoint)
    if (origin.enabled) enabled += 1
  }
  return enabled > 0 && pool.failover_tries <= enabled && validOriginForwarding(pool) &&
    (pool.failback_mode === undefined || pool.failback_mode === 'auto' || pool.failback_mode === 'manual') &&
    (pool.health_check_path === undefined || typeof pool.health_check_path === 'string') &&
    (pool.backup_origins === undefined || (Array.isArray(pool.backup_origins) &&
      pool.backup_origins.every((origin) => typeof origin === 'string')))
}

function validOriginForwarding(pool: SiteOriginPool): boolean {
  const forwarding = originForwarding(pool)
  return (pool.hash_key === undefined || typeof pool.hash_key === 'string') &&
    (forwarding.sticky === undefined || (typeof forwarding.sticky.name === 'string' &&
      ['cookie', 'header', 'arg'].includes(forwarding.sticky.source))) &&
    ['visitor', 'visitor_port', 'origin', 'custom'].includes(forwarding.request_host.mode) &&
    ['http', 'https', 'follow'].includes(forwarding.scheme) &&
    Number.isInteger(forwarding.http_port) && forwarding.http_port >= 1 && forwarding.http_port <= 65_535 &&
    Number.isInteger(forwarding.https_port) && forwarding.https_port >= 1 && forwarding.https_port <= 65_535 &&
    typeof forwarding.origin_auth_enabled === 'boolean' &&
    ['system', 'custom', 'none'].includes(forwarding.tls.trust) &&
    typeof forwarding.follow_port === 'boolean' &&
    typeof forwarding.websocket.enabled === 'boolean' && Array.isArray(forwarding.websocket.allowed_origins) &&
    forwarding.websocket.allowed_origins.every((origin) => typeof origin === 'string') &&
    Array.isArray(forwarding.trusted_proxy_cidrs) && forwarding.trusted_proxy_cidrs.every((cidr) => typeof cidr === 'string') &&
    typeof forwarding.follow_redirect.enabled === 'boolean' && typeof forwarding.follow_redirect.cross_origin === 'boolean' &&
    Number.isInteger(forwarding.follow_redirect.max_hops) && forwarding.follow_redirect.max_hops >= 1 &&
    forwarding.follow_redirect.max_hops <= maxFollowRedirectHops
}

function originForwardingKey(pool: SiteOriginPool): string {
  const forwarding = originForwarding(pool)
  return JSON.stringify([forwarding.hash_key ?? '', forwarding.sticky?.source ?? '', forwarding.sticky?.name?.toLowerCase() ?? '',
    forwarding.request_host.mode, (forwarding.request_host.value ?? '').toLowerCase(), forwarding.scheme,
    forwarding.http_port, forwarding.https_port, forwarding.origin_auth_enabled,
    (forwarding.tls.sni ?? '').toLowerCase(), forwarding.tls.trust, forwarding.follow_port, forwarding.websocket.enabled,
    [...forwarding.websocket.allowed_origins].sort().join(','), forwarding.trusted_proxy_cidrs.length,
    forwarding.follow_redirect.enabled, forwarding.follow_redirect.max_hops, forwarding.follow_redirect.cross_origin])
}

// backupOriginLines are the backup origins as the console's text box lists
// them: one host[:port] per line, in switch order (level 1, 2, ...).
export function backupOriginLines(origins: SiteOrigin[]): string[] {
  return origins
    .map((origin, index) => ({ origin, index }))
    .filter(({ origin }) => (origin.level ?? 0) > 0)
    .sort((left, right) => (left.origin.level ?? 0) - (right.origin.level ?? 0) || left.index - right.index)
    .map(({ origin }) => originCompatibilityEndpoint(origin))
}

// expandBackupOrigins mirrors the server: blank lines ignored, repeats
// (and primaries) dropped, line n becomes a level n origin after the
// primaries.
export function expandBackupOrigins<T extends Pick<SiteOriginPool, 'origins' | 'backup_origins'>>(pool: T): Omit<T, 'backup_origins'> {
  if (pool.backup_origins === undefined) return pool
  const { backup_origins: lines, ...rest } = pool
  const seen = new Set(pool.origins.map((origin) => originCompatibilityEndpoint({ ...origin, host: origin.host.toLowerCase() })))
  const origins = [...pool.origins]
  for (const raw of lines) {
    const parsed = parseOriginLine(raw)
    if (!parsed) continue
    const endpoint = originCompatibilityEndpoint(parsed)
    if (seen.has(endpoint)) continue
    seen.add(endpoint)
    origins.push({ ...parsed, weight: 1, enabled: true, level: origins.length - pool.origins.length + 1, max_conns: 0 })
  }
  return { ...rest, origins }
}

// parseOriginLine reads host, host:port, IPv6 or [IPv6]:port (port 80
// when absent); null for a blank or malformed line.
export function parseOriginLine(raw: string): Pick<SiteOrigin, 'host' | 'port'> | null {
  const value = raw.trim().toLowerCase()
  if (!value || value.length > 512 || /[\s/?#@]/.test(value)) return null
  const bracketed = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/.exec(value)
  if (bracketed) return portOf(bracketed[1], bracketed[2])
  if ((value.match(/:/g) ?? []).length > 1) return /^[0-9a-f:.]+$/.test(value) ? { host: value, port: 80 } : null
  const [host, port] = value.split(':')
  if (!/^[a-z0-9.-]+$/.test(host) || host.startsWith('.') || host.endsWith('.')) return null
  return portOf(host, port)
}

function portOf(host: string, raw: string | undefined): Pick<SiteOrigin, 'host' | 'port'> | null {
  if (raw === undefined) return { host, port: 80 }
  const port = Number(raw)
  return Number.isInteger(port) && port >= 1 && port <= 65_535 ? { host, port } : null
}

function originPoolEquals(actual: SiteOriginPool, requested: SiteOriginPool | CreateSiteOriginPool): boolean {
  // A create without a load balancing, timeouts, keepalive, WebSocket or
  // origin protocol takes the owner's defaults (user_defaults.go applyPool,
  // CU-SITE-02); the pool ports follow the protocol then.
  const schemeDefaulted = requested.scheme === undefined
  const filled: SiteOriginPool = {
    ...requested,
    balance_method: requested.balance_method ?? actual.balance_method,
    connect_timeout_ms: requested.connect_timeout_ms ?? actual.connect_timeout_ms,
    read_timeout_ms: requested.read_timeout_ms ?? actual.read_timeout_ms,
    keepalive_enabled: requested.keepalive_enabled ?? actual.keepalive_enabled,
    keepalive_idle_timeout_ms: requested.keepalive_idle_timeout_ms ?? actual.keepalive_idle_timeout_ms,
    websocket: requested.websocket ?? actual.websocket,
    ...(schemeDefaulted ? {
      scheme: actual.scheme,
      http_port: requested.http_port ?? actual.http_port,
      https_port: requested.https_port ?? actual.https_port,
    } : {}),
  }
  const expected = withInheritedOriginPorts(expandBackupOrigins(filled))
  return actual.balance_method === expected.balance_method &&
    actual.failover_tries === expected.failover_tries &&
    actual.connect_timeout_ms === expected.connect_timeout_ms &&
    actual.read_timeout_ms === expected.read_timeout_ms &&
    originKeepalive(actual).enabled === originKeepalive(expected).enabled &&
    originKeepalive(actual).idleTimeoutMs === originKeepalive(expected).idleTimeoutMs &&
    actual.origins.length === expected.origins.length &&
    actual.origins.every((origin, index) => {
      const wanted = expected.origins[index]
      return wanted !== undefined &&
        origin.host === wanted.host &&
        origin.port === wanted.port &&
        origin.weight === wanted.weight &&
        origin.enabled === wanted.enabled &&
        (origin.level ?? 0) === (wanted.level ?? 0) &&
        (origin.max_conns ?? 0) === (wanted.max_conns ?? 0) &&
        (origin.port_inherited ?? false) === (wanted.port_inherited ?? false)
    }) &&
    originForwardingKey(actual) === originForwardingKey(expected) &&
    (actual.failback_mode ?? 'auto') === (expected.failback_mode ?? 'auto')
}

function originCompatibilityEndpoint(origin: Pick<SiteOrigin, 'host' | 'port'>): string {
  if (origin.port === 80) return origin.host
  return origin.host.includes(':') ? `[${origin.host}]:${origin.port}` : `${origin.host}:${origin.port}`
}

function siteDetail(body: unknown): SiteDetail {
  const rawDomains = typeof body === 'object' && body !== null && (body as SiteDetail).basic
    ? (body as SiteDetail).basic.domains
    : null
  const domains = Array.isArray(rawDomains) ? canonicalSiteDomains(rawDomains) : null
  if (
    typeof body !== 'object' ||
    body === null ||
    typeof (body as SiteDetail).id !== 'string' ||
    ((body as SiteDetail).scope_id !== undefined && (
      typeof (body as SiteDetail).scope_id !== 'string' ||
      !uuidPattern.test((body as SiteDetail).scope_id ?? '')
    )) ||
    !Number.isInteger((body as SiteDetail).version) ||
    (body as SiteDetail).version < 1 ||
    !(body as SiteDetail).basic ||
    typeof (body as SiteDetail).basic.ipv6_enabled !== 'boolean' ||
    !validListenerState(
      (body as SiteDetail).listener_state,
      (body as SiteDetail).basic.ipv6_enabled,
    ) ||
    !domains ||
    !sameStrings(rawDomains, domains) ||
    !Array.isArray((body as SiteDetail).basic.origins) ||
    !validSiteTLSProtocolFacts((body as SiteDetail).basic.tls_protocols) ||
    !validOriginPool((body as SiteDetail).origin_pool) ||
    !validLockState((body as SiteDetail).lock) ||
    !validStatusProjection(body as Record<string, unknown>)
  ) {
    throw new ApiError('网站详情响应格式无效', 502, 'invalid_response')
  }
  return body as SiteDetail
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const siteTLSProfileKeys = ['tls_cipher_preset', 'tls_cipher_suites', 'tls_ocsp_stapling', 'tls_client_auth', 'tls_client_ca_pem',
  'http2_enabled', 'http3_enabled', 'tls_prefer_server_ciphers']
const siteBasicKeys = [
  'cname',
  'cname_current_revision',
  'cname_domain',
  'cname_hostname',
  'cname_lkg_revision',
  'cname_mode',
  'cname_state',
  'cname_task_id',
  'domains',
  'enabled',
  'group_id',
  'group_name',
  'http_enabled',
  'http_listen_ports',
  'https_enabled',
  'https_listen_ports',
  'ipv6_enabled',
  'is_default',
  'origins',
  'package_id',
  'package_name',
  'package_subscription_id',
  'status',
  'sync_status',
  'tls_protocols',
]

function validPortList(value: unknown): boolean {
  return Array.isArray(value) && value.every((port) => typeof port === 'string' && /^\d{1,5}$/u.test(port) &&
    Number(port) >= 1 && Number(port) <= 65_535)
}

function sameStrings(actual: unknown, expected: readonly string[]): boolean {
  return Array.isArray(actual) &&
    actual.length === expected.length &&
    actual.every((value, index) => value === expected[index])
}

function packageDerivedMatches(actual: unknown, expected: string | undefined): boolean {
  return expected ? actual === expected : typeof actual === 'string'
}

// A request that does not carry the CNAME allocation facts accepts either no
// allocation or the one the server starts for a package-bound site: pending,
// with a task and the first revision, never a last-known-good one.
function cnameAllocationMatches(value: Record<string, unknown>, expected: CreateSiteBasic): boolean {
  const unspecified = expected.cname_state === undefined && expected.cname_task_id === undefined &&
    expected.cname_current_revision === undefined && expected.cname_lkg_revision === undefined
  if (unspecified && value.cname_state === 'pending') {
    return typeof value.cname_task_id === 'string' && uuidPattern.test(value.cname_task_id) &&
      value.cname_current_revision === 1 && value.cname_lkg_revision === null
  }
  return value.cname_state === (expected.cname_state ?? null) &&
    value.cname_task_id === (expected.cname_task_id ?? null) &&
    value.cname_current_revision === (expected.cname_current_revision ?? null) &&
    value.cname_lkg_revision === (expected.cname_lkg_revision ?? null)
}

function matchesCreatedBasic(actual: unknown, expected: CreateSiteBasic): boolean {
  if (typeof actual !== 'object' || actual === null) return false
  const value = actual as Record<string, unknown>
  // Servers since 1.0.35 add the forced HTTPS facts.
  const keys = Object.keys(value).filter((key) =>
    key !== 'force_https' && key !== 'https_redirect_port' && key !== 'cache_shared_across_domains' &&
    key !== 'cache_status_header' && key !== 'cname_failure_code' && !siteTLSProfileKeys.includes(key))
  if (keys.sort().join(',') !== siteBasicKeys.join(',')) return false
  if (value.force_https !== undefined && typeof value.force_https !== 'boolean') return false
  if (value.cache_shared_across_domains !== undefined && typeof value.cache_shared_across_domains !== 'boolean') return false
  if (value.cache_status_header !== undefined && typeof value.cache_status_header !== 'boolean') return false
  if (value.https_redirect_port !== undefined && !Number.isInteger(value.https_redirect_port)) return false
  return (
    value.package_id === expected.package_id &&
    value.package_subscription_id === (expected.package_subscription_id ?? null) &&
    // An empty CNAME mode/domain/hostname means 「按套餐自动」: the server fills
    // them from the package snapshot, so only an explicit value must match.
    packageDerivedMatches(value.cname_mode, expected.cname_mode) &&
    packageDerivedMatches(value.cname_domain, expected.cname_domain) &&
    packageDerivedMatches(value.cname_hostname, expected.cname_hostname) &&
    value.package_name === expected.package_name &&
    value.group_id === expected.group_id &&
    value.group_name === expected.group_name &&
    sameStrings(value.domains, expected.domains) &&
    value.http_enabled === expected.http_enabled &&
    // Ports the create left out come from the defaults: any valid list.
    (expected.http_listen_ports ? sameStrings(value.http_listen_ports, expected.http_listen_ports)
      : validPortList(value.http_listen_ports) && (value.http_listen_ports as string[]).length > 0) &&
    (expected.https_listen_ports ? sameStrings(value.https_listen_ports, expected.https_listen_ports)
      : validPortList(value.https_listen_ports) && (value.https_listen_ports as string[]).length > 0 === expected.https_enabled) &&
    // IPv6 and TLS protocols the create left out come from the defaults:
    // any valid value; a value the create named must come back unchanged.
    (expected.ipv6_enabled === undefined ? typeof value.ipv6_enabled === 'boolean' : value.ipv6_enabled === expected.ipv6_enabled) &&
    (expected.tls_protocols === undefined ? validSiteTLSProtocolFacts(value.tls_protocols) : sameStrings(value.tls_protocols, expected.tls_protocols)) &&
    sameStrings(value.origins, expected.origins) &&
    value.cname === expected.cname &&
    cnameAllocationMatches(value, expected) &&
    value.https_enabled === expected.https_enabled &&
    value.enabled === expected.enabled &&
    value.status === expected.status &&
    value.is_default === expected.is_default
  )
}

function createdSiteDetail(body: unknown, input: CreateSiteRequest): SiteDetail {
  const saved = siteDetail(body)
  const owner = saved.owner
  const validOwner = input.owner_id === undefined
    ? owner === null
    : owner !== null &&
      typeof owner === 'object' &&
      owner.id === input.owner_id &&
      uuidPattern.test(owner.id) &&
      typeof owner.display_name === 'string' &&
      owner.display_name.length > 0
  if (
    !uuidPattern.test(saved.id) ||
    !validOwner ||
    typeof saved.created_at !== 'string' ||
    Number.isNaN(Date.parse(saved.created_at)) ||
    typeof saved.updated_at !== 'string' ||
    Number.isNaN(Date.parse(saved.updated_at)) ||
    !matchesCreatedBasic(saved.basic, input.basic) ||
    (input.origin_pool !== undefined && !originPoolEquals(saved.origin_pool, input.origin_pool))
  ) {
    throw new ApiError('Invalid site creation response', 502, 'invalid_response')
  }
  return saved
}

async function create(
  accessToken: string,
  input: CreateSiteRequest,
  idempotencyKey: string,
  serializedBody = JSON.stringify(input),
): Promise<SiteDetail> {
  assertSafeBasicWrite(input.basic)
  if (input.origin_pool !== undefined && (
    !validOriginPool({
      ...input.origin_pool,
      balance_method: input.origin_pool.balance_method ?? 'round_robin',
      connect_timeout_ms: input.origin_pool.connect_timeout_ms ?? 3000,
      read_timeout_ms: input.origin_pool.read_timeout_ms ?? 30000,
    }) ||
    !sameStrings(input.basic.origins, input.origin_pool.origins.map(originCompatibilityEndpoint))
  )) {
    throw new ApiError('Invalid site origin pool', 400, 'validation_error')
  }
  const targetScopeProvided = input.target_scope_id !== undefined
  const ownerProvided = input.owner_id !== undefined
  if (
    targetScopeProvided !== ownerProvided ||
    (input.target_scope_id !== undefined && !uuidPattern.test(input.target_scope_id)) ||
    (input.owner_id !== undefined && !uuidPattern.test(input.owner_id))
  ) {
    throw new ApiError('Invalid site creation target', 400, 'validation_error')
  }
  const body = await request<unknown>(
    accessToken,
    '/v1/sites',
    {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: writeBody(serializedBody),
    },
    201,
  )
  return createdSiteDetail(body, input)
}

async function detail(accessToken: string, id: string): Promise<SiteDetail | null> {
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}`)
  if (body === null) return null
  return siteDetail(body)
}

async function patchBasic(
  accessToken: string,
  id: string,
  input: PatchSiteBasicRequest,
  idempotencyKey: string,
  serializedBody = JSON.stringify(input),
): Promise<SiteDetail> {
  assertSafeBasicWrite(input.changes)
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: writeBody(serializedBody),
  })
  const saved = siteDetail(body)
  if (
    !sameStrings(saved.basic.domains, input.changes.domains) ||
    !sameStrings(saved.basic.tls_protocols, input.changes.tls_protocols ?? safeSiteTLSProtocols)
  ) {
    throw new ApiError('Invalid site TLS protocol response', 502, 'invalid_response')
  }
  return saved
}

async function patchOrigin(
  accessToken: string,
  id: string,
  input: PatchSiteOriginRequest,
  idempotencyKey: string,
  serializedBody = JSON.stringify(input),
): Promise<SiteDetail> {
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: serializedBody,
  })
  return siteDetail(body)
}

async function lock(
  accessToken: string,
  id: string,
  input: LockSiteRequest,
  idempotencyKey: string,
): Promise<SiteDetail> {
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}/lock`, {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  })
  return siteDetail(body)
}

async function unlock(
  accessToken: string,
  id: string,
  input: UnlockSiteRequest,
  idempotencyKey: string,
): Promise<SiteDetail> {
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}/unlock`, {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  })
  return siteDetail(body)
}

function batchItemResult(value: unknown): BatchSiteActionItemResult | null {
  if (typeof value !== 'object' || value === null) return null
  const result = value as Record<string, unknown>
  if (typeof result.id !== 'string') return null

  if (result.status === 'updated') {
    if (result.error !== undefined) return null
    try {
      const site = siteDetail(result.site)
      return site.id === result.id ? { id: result.id, status: 'updated', site } : null
    } catch {
      return null
    }
  }
  if (result.status === 'queued') {
    if (result.error !== undefined) return null
    try {
      const site = siteDetail(result.site)
      const taskID = site.basic.cname_task_id
      return site.id === result.id &&
        site.basic.cname_state === 'pending' &&
        typeof taskID === 'string' &&
        uuidPattern.test(taskID) &&
        taskID === taskID.toLowerCase()
        ? { id: result.id, status: 'queued', site }
        : null
    } catch {
      return null
    }
  }
  if (result.status === 'deleted') {
    return result.site === undefined && result.error === undefined
      ? { id: result.id, status: 'deleted' }
      : null
  }
  if (result.status === 'failed') {
    const error = result.error
    if (result.site !== undefined || typeof error !== 'object' || error === null) return null
    const code = (error as { code?: unknown }).code
    return typeof code === 'string' && batchErrorCodes.has(code as BatchSiteActionErrorCode)
      ? { id: result.id, status: 'failed', error: { code: code as BatchSiteActionErrorCode } }
      : null
  }
  return null
}

async function batchAction(
  accessToken: string,
  input: BatchSiteActionRequest,
  idempotencyKey: string,
  serializedBody = JSON.stringify(input),
): Promise<BatchSiteActionResponse> {
  const body = await request<unknown>(accessToken, '/v1/sites/batch-action', {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: serializedBody,
  })
  if (typeof body !== 'object' || body === null || !Array.isArray((body as { items?: unknown }).items)) {
    throw new ApiError('网站批量操作响应格式无效', 502, 'invalid_response')
  }
  const items = (body as { items: unknown[] }).items.map(batchItemResult)
  if (
    items.length !== input.items.length ||
    items.some(
      (item, index) =>
        item === null ||
        item.id !== input.items[index]?.id ||
        (item.status !== 'failed' && (
          input.action === 'regenerate_cname'
            ? item.status !== 'queued'
            : input.action === 'delete'
              ? item.status !== 'deleted'
              : item.status !== 'updated'
        )),
    )
  ) {
    throw new ApiError('网站批量操作响应格式无效', 502, 'invalid_response')
  }
  return { items: items as BatchSiteActionItemResult[] }
}

async function exportDomains(
  accessToken: string,
  params: SiteDomainExportParams,
): Promise<SiteDomainExport> {
  const query = new URLSearchParams()
  if (params.target_scope_id !== undefined) {
    const targetScopeID = params.target_scope_id.trim().toLowerCase()
    if (!uuidPattern.test(targetScopeID) || targetScopeID === '00000000-0000-0000-0000-000000000000') {
      throw new ApiError('Invalid site export target', 400, 'validation_error')
    }
    query.set('target_scope_id', targetScopeID)
  }
  if (params.domain !== undefined) {
    let domain = params.domain.trim().toLowerCase()
    if (domain.endsWith('.')) domain = domain.slice(0, -1)
    const hasControlCharacter = Array.from(domain).some((character) => {
      const code = character.charCodeAt(0)
      return code <= 0x1f || code === 0x7f
    })
    if (!domain || domain.length > 253 || hasControlCharacter) {
      throw new ApiError('Invalid site export domain', 400, 'validation_error')
    }
    query.set('domain', domain)
  }
  for (const [key, raw] of Object.entries(params)) {
    if (key === 'target_scope_id' || key === 'domain' || raw === undefined) continue
    const value = raw.trim()
    if (value) query.set(key, value)
  }

  let response: Response
  try {
    const suffix = query.size ? `?${query.toString()}` : ''
    response = await fetch(`${apiRoot}/v1/sites/export${suffix}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const contentType = response.headers.get('Content-Type')?.toLowerCase()
  const disposition = response.headers.get('Content-Disposition') ?? ''
  const snapshotID = response.headers.get('X-Site-Domain-Export-Snapshot-ID') ?? ''
  const filenameMatch = /^attachment;\s*filename="([A-Za-z0-9._-]+\.csv)"$/u.exec(disposition)
  if (
    response.status !== 200 ||
    contentType !== 'text/csv; charset=utf-8' ||
    !filenameMatch ||
    !uuidPattern.test(snapshotID) ||
    snapshotID !== snapshotID.toLowerCase()
  ) {
    throw new ApiError('Invalid site domain export response', 502, 'invalid_response')
  }
  return { blob: await response.blob(), filename: filenameMatch[1], snapshotID }
}

export interface TransferSiteRequest {
  expected_version: number
  target_user_id: string
  target_package_subscription_id: string | null
}

// Items carried to the new site / released (configure again), see site.TransferItem*.
export type SiteTransferItem =
  | 'http_policy' | 'cache_policy' | 'certificate' | 'waf_policy' | 'cc_policy' | 'acl_policy'
  | 'auto_defense' | 'js_challenge'

export interface TransferSiteResult {
  site: SiteDetail
  from_site_id: string
  from_cname: string
  copied: SiteTransferItem[]
  released: SiteTransferItem[]
}

// 更换所属用户 (platform administrator): the site is re-created in the target
// user's tenant (new ID and CNAME) and the old one deleted, in one request.
async function transfer(
  accessToken: string,
  id: string,
  input: TransferSiteRequest,
  idempotencyKey: string,
): Promise<TransferSiteResult> {
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}/transfer`, {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  }, 201)
  if (typeof body !== 'object' || body === null) throw new ApiError('Invalid transfer response', 502, 'invalid_response')
  const value = body as Record<string, unknown>
  const strings = (raw: unknown) => Array.isArray(raw) && raw.every((item) => typeof item === 'string')
    ? raw as SiteTransferItem[] : []
  if (typeof value.from_site_id !== 'string' || typeof value.from_cname !== 'string') {
    throw new ApiError('Invalid transfer response', 502, 'invalid_response')
  }
  return { site: siteDetail(value.site), from_site_id: value.from_site_id, from_cname: value.from_cname,
    copied: strings(value.copied), released: strings(value.released) }
}

/** 接入状态 > 立即检查：同站 1 分钟一次，429 带 retryAfter（秒）。 */
async function checkAccess(accessToken: string, id: string): Promise<SiteAccessReadiness> {
  const body = await request<unknown>(accessToken, `/v1/sites/${encodeURIComponent(id)}/access-check`, { method: 'POST' }, 200)
  if (!validAccessReadiness(body)) throw new ApiError('Invalid access check response', 502, 'invalid_response')
  return body
}

function validAccessReadiness(value: unknown): value is SiteAccessReadiness {
  if (typeof value !== 'object' || value === null) return false
  const readiness = value as SiteAccessReadiness
  return ['ready', 'pending', 'blocked'].includes(readiness.state) && Array.isArray(readiness.checks) &&
    readiness.checks.every((check) => typeof check === 'object' && check !== null && typeof check.code === 'string' &&
      typeof check.ok === 'boolean' && typeof check.detail === 'string')
}

export const sitesApi = { batchAction, checkAccess, create, detail, exportDomains, list, lock, patchBasic, patchOrigin, transfer, unlock }
