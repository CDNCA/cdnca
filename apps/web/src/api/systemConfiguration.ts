import { ApiError, networkApiError, responseApiError } from './auth'

export const systemConfigurationCategories = [
  'nginx',
  'defaults',
  'resources',
  'error_pages',
  'secrets',
  'node_monitoring',
  'ddos_protection',
  'access_log_fields',
] as const

export type SystemConfigurationCategory = typeof systemConfigurationCategories[number]
export type SystemConfigurationStatus = 'draft' | 'validated' | 'active' | 'superseded' | 'rejected'

export type NginxProxyCacheMethod = 'GET' | 'HEAD'
export type NginxProxyNextUpstream =
  | 'error'
  | 'timeout'
  | 'invalid_header'
  | 'http_500'
  | 'http_502'
  | 'http_503'
  | 'http_504'
  | 'http_403'
  | 'http_404'
  | 'http_429'
  | 'non_idempotent'
  | 'off'

export interface NginxWorkerConfiguration {
  worker_processes: number
  worker_connections: number
  worker_rlimit_nofile: number
  worker_shutdown_timeout_ms: number
  logs_dir: string
}

export interface LargeClientHeaderBuffersConfiguration {
  count: number
  size_bytes: number
}

export interface NginxHttpConfiguration {
  gzip_comp_level: number
  gzip_http_version: '1.0' | '1.1'
  gzip_min_length_bytes: number
  gzip_vary: boolean
  server_addr_outgoing: boolean
  proxy_request_buffering: boolean
  proxy_buffering: boolean
  proxy_cache_max_size_bytes: number
  // proxy_cache_min_free_bytes: keep the node's cache file system this free
  // (nginx min_free, whole MiB; 0: none). The cache lives under the node's
  // state root.
  proxy_cache_min_free_bytes: number
  proxy_cache_methods: NginxProxyCacheMethod[]
  proxy_http_version: '1.0' | '1.1'
  proxy_max_temp_file_size_bytes: number
  proxy_next_upstream: NginxProxyNextUpstream[]
  proxy_connect_timeout_ms: number
  proxy_send_timeout_ms: number
  proxy_read_timeout_ms: number
  client_body_buffer_size_bytes: number
  server: string
  client_max_body_size_bytes: number
  default_type: string
  keepalive_requests: number
  keepalive_timeout_ms: number
  log_not_found: boolean
  server_tokens: boolean
  large_client_header_buffers: LargeClientHeaderBuffersConfiguration
  server_names_hash_max_size: number
  server_names_hash_bucket_size: number
}

export interface NginxStreamConfiguration {
  proxy_connect_timeout_ms: number
  proxy_timeout_ms: number
}

export type NginxWorkerOverride = Partial<NginxWorkerConfiguration>
export type NginxHttpOverride = Partial<NginxHttpConfiguration>
export type NginxStreamOverride = Partial<NginxStreamConfiguration>

export interface NginxOverride {
  worker?: NginxWorkerOverride
  http?: NginxHttpOverride
  stream?: NginxStreamOverride
}

export interface ScopedNginxOverride {
  id: string
  scope: 'region' | 'node'
  scope_id: string
  values: NginxOverride
}

export interface NginxConfiguration {
  worker: NginxWorkerConfiguration
  http: NginxHttpConfiguration
  stream: NginxStreamConfiguration
  overrides: ScopedNginxOverride[]
}

export type TLSProtocol = 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3'
export type DefaultWafModuleMode = 'off' | 'detect' | 'on'

export interface DefaultSslConfiguration {
  mode: 'recommended' | 'legacy_tls12' | 'legacy_full'
  protocols: TLSProtocol[]
  cipher_suites: string
  prefer_server_ciphers: boolean
}

export interface DefaultCacheNoCacheCondition {
  variable: string
  string: string
}

export interface DefaultCacheRuleConfiguration {
  id: string
  match: string
  content: string | null
  ttl_seconds: number
  ignore_query: boolean
  force_cache: boolean
  range: boolean
  ignore_vary: boolean
  no_cache: DefaultCacheNoCacheCondition[]
  enabled: boolean
  position: number
}

export interface DefaultOriginRequestHeaderConfiguration {
  id: string
  name: string
  value: string | null
  action: 'set' | 'append' | 'delete'
  allow_duplicate: boolean
  enabled: boolean
  position: number
}

export interface DefaultWafModulesConfiguration {
  sqli: DefaultWafModuleMode
  xss: DefaultWafModuleMode
  upload: DefaultWafModuleMode
  fi: DefaultWafModuleMode
  cmdi: DefaultWafModuleMode
  java: DefaultWafModuleMode
  jdeser: DefaultWafModuleMode
  php: DefaultWafModuleMode
  phpdeser: DefaultWafModuleMode
  ssti: DefaultWafModuleMode
}

export interface DefaultWebsiteOtherConfiguration {
  load_balancing: 'round_robin' | 'ip_hash' | 'url_hash' | 'least_conn' | 'random'
  gzip_enabled: boolean
  gzip_types: string[]
  websocket_enabled: boolean
}

export interface DefaultWebsiteConfiguration {
  http: {
    listen_ports: number[]
  }
  https: {
    listen_ports: number[]
    hsts_enabled: boolean
    http2_enabled: boolean
    http3_enabled: boolean
    force_https: boolean
    ssl: DefaultSslConfiguration
    ocsp_stapling_enabled: boolean
  }
  origin: {
    scheme: 'http' | 'https' | 'follow' | 'follow_with_port'
    http_port: number
    https_port: number
    response_timeout_seconds: number
    connect_timeout_seconds: number
    ssl_protocols: TLSProtocol[]
    http_version: '1.0' | '1.1'
    keepalive_enabled: boolean
    post_body_limit_bytes: number
  }
  cache_rules: DefaultCacheRuleConfiguration[]
  origin_request_headers: DefaultOriginRequestHeaderConfiguration[]
  access_log: {
    capture_request_headers: boolean
    capture_response_headers: boolean
    capture_request_body: boolean
    request_body_limit_kb: number
  }
  security: {
    default_cc_policy_id: string | null
    waf_enabled: boolean
    waf_auto_block: {
      enabled: boolean
      window_seconds: number
      hit_threshold: number
      block_seconds: number
    }
    waf_modules: DefaultWafModulesConfiguration
  }
  other: DefaultWebsiteOtherConfiguration
}

export interface DefaultStreamConfiguration {
  protocol: 'tcp' | 'udp'
  load_balancing: 'round_robin' | 'ip_hash'
  proxy_protocol_enabled: boolean
}

export interface DefaultCertificateConfiguration {
  issuer: 'zerossl' | 'lets_encrypt' | 'google_trust'
}

// 区域覆盖只允许 website.other 的 GZIP 开关与类型（节点按节点渲染）；
// load_balancing、websocket_enabled 由服务端归一为全局值。
export interface DefaultOverride {
  website: { other: DefaultWebsiteOtherConfiguration }
}

export interface ScopedDefaultOverride {
  id: string
  scope: 'region'
  scope_id: string
  values: DefaultOverride
}

export interface DefaultConfiguration {
  website: DefaultWebsiteConfiguration
  stream: DefaultStreamConfiguration
  certificate: DefaultCertificateConfiguration
  overrides: ScopedDefaultOverride[]
}

export interface PortRange {
  from: number
  to: number
}

export interface ResourceSiteConfiguration {
  related_config_min_limit: number
  related_config_max_times_limit: number
  black_ip_limit: number
  white_ip_limit: number
  daily_clean_url_limit: number
  daily_clean_dir_limit: number
  daily_pre_cache_url_limit: number
  daily_ip_unlock_limit: number
  ip_unlock_per_request_limit: number
  cc_rule_max_limit: number
  max_domains_per_site: number
  listen_default_http_80: boolean
  daily_access_log_download_limit: number
  access_log_tmp_dir: string
  access_log_retain_hours: number
}

export interface ResourceStreamConfiguration {
  custom_port_not_allow: PortRange[]
  related_config_min_limit: number
  related_config_max_times_limit: number
  acl_max_limit: number
}

export interface ResourceSiteStreamConfiguration {
  custom_port_not_allow: PortRange[]
  custom_port_allow: PortRange[]
}

export interface ResourceConfiguration {
  site: ResourceSiteConfiguration
  stream: ResourceStreamConfiguration
  site_stream: ResourceSiteStreamConfiguration
  // 资源配置没有区域覆盖（都在建站/建转发时取值），服务端只接受空数组。
  overrides: []
}

export interface ErrorPageConfiguration {
  status_code: number
  mime_type: 'application/json' | 'text/html' | 'text/plain'
  size_bytes: number
  sha256: string
  storage_object_key: string
}

export interface MaskedSecretReference {
  provider: 'vault' | 'kms-envelope'
  reference: string
  key_id: string
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305' | 'kms-managed'
  ciphertext_sha256: string
  masked: true
}

export interface SecretsConfiguration {
  error_page_storage?: MaskedSecretReference
}

export interface NodeMonitoringConfiguration {
  port_mode: 'default' | 'custom'
  custom_port?: number
  monitor_enabled?: boolean
  protocol?: 'http' | 'tcp' | 'ping'
  monitor_port?: number
  monitor_groups?: Array<'domestic' | 'telecom' | 'unicom' | 'mobile' | 'overseas'>
  monitor_action?: 'none' | 'pause'
  failure_ratio?: number
  bandwidth_over_limit?: number
  probe_interval_ms: number
  probe_timeout_ms: number
  failure_threshold: number
  recovery_threshold: number
  failure_debounce_ms: number
  recovery_debounce_ms: number
  recovery_notification_enabled: boolean
}

export type CCKernelBanMode = 'off' | 'exclusive_ports' | 'site_ports'

/** TCP malformed flag classes, in the canonical order the server writes. */
export const tcpFlagTypes = ['null', 'xmas', 'syn_fin', 'syn_rst', 'fin', 'all'] as const
export type TCPFlagType = typeof tcpFlagTypes[number]

/** Node-level kernel connection protection (api/control-system-configuration.openapi.yaml DDoSProtection). */
export interface DDoSProtectionConfiguration {
  max_connections_per_ip: number
  new_connections_per_second: number
  new_connections_per_minute: number
  rate_ban_seconds: number
  max_connections_per_port: number
  empty_connection?: {
    idle_seconds: number
    threshold: number
    window_seconds: number
    ban_seconds: number
  }
  allow_networks: string[]
  cc_kernel_ban: CCKernelBanMode
  /** Absent: off. */
  tcp_flag_filter?: true
  /** Canonical order, kept while the filter is off; absent when none. */
  tcp_flag_types?: TCPFlagType[]
  /** Absent: off. */
  drop_invalid?: true
}

/** Optional access log fields, in the catalog order the server writes (libs/edgeconfig AccessLogFieldCatalog). */
export const accessLogFieldKeys = [
  'client_family', 'client_geo', 'referer', 'user_agent', 'accept_language', 'content_type', 'content_encoding',
  'origin_timing', 'upstream_addr', 'cache_control', 'x_forwarded_for', 'x_real_ip', 'block_page', 'ja4',
] as const
export type AccessLogFieldKey = typeof accessLogFieldKeys[number]

/** api/control-system-configuration.openapi.yaml AccessLogFields. */
export interface AccessLogFieldsConfiguration {
  fields: AccessLogFieldKey[]
}

export interface SecretReplacement {
  provider: MaskedSecretReference['provider']
  reference: string
  key_id: string
  algorithm: MaskedSecretReference['algorithm']
  ciphertext_sha256: string
}

export type SecretsConfigurationWrite = {
  error_page_storage: {
    intent: 'replace'
    replacement: SecretReplacement
  } | {
    intent: 'clear'
  }
}

export interface SystemConfigurationValueMap {
  nginx: NginxConfiguration
  defaults: DefaultConfiguration
  resources: ResourceConfiguration
  error_pages: ErrorPageConfiguration[]
  secrets: SecretsConfiguration
  node_monitoring: NodeMonitoringConfiguration
  ddos_protection: DDoSProtectionConfiguration
  access_log_fields: AccessLogFieldsConfiguration
}

export interface SystemConfigurationWriteValueMap {
  nginx: NginxConfiguration
  defaults: DefaultConfiguration
  resources: ResourceConfiguration
  error_pages: ErrorPageConfiguration[]
  secrets: SecretsConfigurationWrite
  node_monitoring: NodeMonitoringConfiguration
  ddos_protection: DDoSProtectionConfiguration
  access_log_fields: AccessLogFieldsConfiguration
}

export interface SystemConfigurationDocument<C extends SystemConfigurationCategory> {
  schema: 'cdnca.system-configuration/v2'
  category: C
  head_revision: number
  active_revision: number
  revision: number
  status: SystemConfigurationStatus
  snapshot_sha256: string
  /** Categories whose head value differs from the active revision; activating makes all of them effective. */
  pending_categories: SystemConfigurationCategory[]
  value: SystemConfigurationValueMap[C]
}

export interface SystemConfigurationLifecycleResult {
  revision: number
  status: 'validated' | 'active'
  snapshot_sha256: string
  replayed: boolean
}

export interface SystemConfigurationRollbackResult {
  revision: number
  status: 'draft'
  snapshot_sha256: string
  source_revision: number
  replayed: boolean
}

export type SystemConfigurationRolloutState =
  | 'queued'
  | 'running'
  | 'paused'
  | 'succeeded'
  | 'partial_failed'
  | 'failed'
  | 'cancelled'

export interface SystemConfigurationActivationPublication {
  tenant_scope_id: string
  tenant_source_revision: number
  publication_id: string
  config_version_id: string
  rollout_id: string
  rollout_state: SystemConfigurationRolloutState
  artifact_sha256: string
  reason_code: 'system_configuration_activated'
  created_at: string
}

export interface SystemConfigurationActivationPublicationPage {
  revision: number
  publications: SystemConfigurationActivationPublication[]
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const systemConfigurationRequestTimeoutMs = 15_000
const sha256Pattern = /^[0-9a-f]{64}$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const shortConfigurationIDPattern = /^[a-z0-9][a-z0-9_-]{7,31}$/
const safeLabelPattern = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/
const serverHeaderPattern = /^$|^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/
const httpTokenPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const mimeTypePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const statuses = new Set<SystemConfigurationStatus>(['draft', 'validated', 'active', 'superseded', 'rejected'])
const rolloutStates = new Set<SystemConfigurationRolloutState>([
  'queued', 'running', 'paused', 'succeeded', 'partial_failed', 'failed', 'cancelled',
])
const mimeTypes = new Set(['application/json', 'text/html', 'text/plain'])
const secretProviders = new Set(['vault', 'kms-envelope'])
const secretAlgorithms = new Set(['aes-256-gcm', 'chacha20-poly1305', 'kms-managed'])
const errorStatusCodes = new Set([400, 401, 403, 404, 405, 408, 413, 429, 500, 501, 502, 503, 504])
const tlsProtocolValues = new Set<TLSProtocol>(['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'])
const proxyCacheMethodValues = new Set<NginxProxyCacheMethod>(['GET', 'HEAD'])
const proxyNextUpstreamValues = new Set<NginxProxyNextUpstream>([
  'error', 'timeout', 'invalid_header', 'http_500', 'http_502', 'http_503', 'http_504',
  'http_403', 'http_404', 'http_429', 'non_idempotent', 'off',
])
const recommendedCipherSuites = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
const legacyTLS12CipherSuites = `${recommendedCipherSuites}:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA`

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('System configuration request was invalid', 400, 'validation_error')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value)
  return required.every((key) => key in value) &&
    keys.every((key) => required.includes(key) || optional.includes(key))
}

function isInteger(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function isString(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean'
}

function codePointLength(value: string): number {
  return [...value].length
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code <= 0x1f || code >= 0x7f && code <= 0x9f) return true
  }
  return false
}

function isSafeText(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === 'string' && codePointLength(value) >= minimum && codePointLength(value) <= maximum &&
    !hasControlCharacter(value)
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === 'string' && safeLabelPattern.test(value)
}

function isControlledPath(value: unknown, root: string): value is string {
  if (typeof value !== 'string' || value.trim() !== value || hasControlCharacter(value) ||
    value.includes('\\')) return false
  if (value === root) return true
  if (!value.startsWith(`${root}/`)) return false
  return value.slice(root.length + 1).split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
}

function isResourceAccessLogPath(value: unknown): value is string {
  if (typeof value !== 'string' || value.trim() !== value || hasControlCharacter(value) ||
    value.includes('\\') || !value.startsWith('/')) return false
  const normalized = value.endsWith('/') ? value.slice(0, -1) : value
  if (normalized === '' || normalized.endsWith('/')) return false
  for (const root of ['/data/download-temp', '/var/lib/cdnca']) {
    if (normalized === root) return true
    if (normalized.startsWith(`${root}/`) && normalized.slice(root.length + 1).split('/')
      .every((segment) => segment !== '' && segment !== '.' && segment !== '..')) return true
  }
  return false
}

function isPowerOfTwo(value: number): boolean {
  return (value & (value - 1)) === 0
}

function isUniqueStringArray(
  value: unknown,
  minimum: number,
  maximum: number,
  valid: (item: string) => boolean,
): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum &&
    value.every((item) => typeof item === 'string' && valid(item)) && new Set(value).size === value.length
}

function isPortList(value: unknown): value is number[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= 64 &&
    value.every((port) => isInteger(port, 1, 65_535)) && new Set(value).size === value.length
}

function portListsOverlap(left: number[], right: number[]): boolean {
  const selected = new Set(left)
  return right.some((port) => selected.has(port))
}

function isPortRange(value: unknown): value is PortRange {
  return isRecord(value) && hasExactKeys(value, ['from', 'to']) &&
    isInteger(value.from, 1, 65_535) && isInteger(value.to, value.from, 65_535)
}

function isPortRanges(value: unknown): value is PortRange[] {
  if (!Array.isArray(value) || value.length > 256 || !value.every(isPortRange)) return false
  return value.every((item, index) => index === 0 || value[index - 1]!.to < item.from)
}

function portRangesOverlap(left: PortRange[], right: PortRange[]): boolean {
  return left.some((leftRange) => right.some((rightRange) =>
    leftRange.from <= rightRange.to && rightRange.from <= leftRange.to))
}

function isLargeClientHeaderBuffers(value: unknown): value is LargeClientHeaderBuffersConfiguration {
  return isRecord(value) && hasExactKeys(value, ['count', 'size_bytes']) &&
    isInteger(value.count, 1, 32) && isInteger(value.size_bytes, 1_024, 2 ** 20)
}

function isNginxWorkerConfiguration(value: unknown): value is NginxWorkerConfiguration {
  return isRecord(value) && hasExactKeys(value, [
    'worker_processes', 'worker_connections', 'worker_rlimit_nofile', 'worker_shutdown_timeout_ms', 'logs_dir',
  ]) && isInteger(value.worker_processes, 0, 256) &&
    isInteger(value.worker_rlimit_nofile, 1_024, 1_048_576) &&
    isInteger(value.worker_connections, 128, value.worker_rlimit_nofile) &&
    isInteger(value.worker_shutdown_timeout_ms, 1_000, 300_000) &&
    isControlledPath(value.logs_dir, '/var/log/cdnca')
}

function isNginxHttpConfiguration(value: unknown): value is NginxHttpConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'gzip_comp_level', 'gzip_http_version', 'gzip_min_length_bytes', 'gzip_vary', 'server_addr_outgoing',
    'proxy_request_buffering', 'proxy_buffering', 'proxy_cache_min_free_bytes', 'proxy_cache_max_size_bytes',
    'proxy_cache_methods', 'proxy_http_version', 'proxy_max_temp_file_size_bytes', 'proxy_next_upstream',
    'proxy_connect_timeout_ms', 'proxy_send_timeout_ms', 'proxy_read_timeout_ms', 'client_body_buffer_size_bytes',
    'server', 'client_max_body_size_bytes', 'default_type', 'keepalive_requests', 'keepalive_timeout_ms',
    'log_not_found', 'server_tokens', 'large_client_header_buffers', 'server_names_hash_max_size',
    'server_names_hash_bucket_size',
  ])) return false
  if (!isUniqueStringArray(value.proxy_cache_methods, 1, 2,
    (item) => proxyCacheMethodValues.has(item as NginxProxyCacheMethod)) ||
    !isUniqueStringArray(value.proxy_next_upstream, 1, proxyNextUpstreamValues.size,
      (item) => proxyNextUpstreamValues.has(item as NginxProxyNextUpstream))) return false
  if (value.proxy_next_upstream.includes('off') && value.proxy_next_upstream.length !== 1) return false
  return isInteger(value.gzip_comp_level, 1, 9) &&
    (value.gzip_http_version === '1.0' || value.gzip_http_version === '1.1') &&
    isInteger(value.gzip_min_length_bytes, 0, 2 ** 30) && isBoolean(value.gzip_vary) &&
    isBoolean(value.server_addr_outgoing) && isBoolean(value.proxy_request_buffering) &&
    isBoolean(value.proxy_buffering) && isInteger(value.proxy_cache_min_free_bytes, 0, 2 ** 44) &&
    value.proxy_cache_min_free_bytes % 2 ** 20 === 0 &&
    isInteger(value.proxy_cache_max_size_bytes, 0, 2 ** 50) &&
    (value.proxy_http_version === '1.0' || value.proxy_http_version === '1.1') &&
    isInteger(value.proxy_max_temp_file_size_bytes, 0, 2 ** 40) &&
    isInteger(value.proxy_connect_timeout_ms, 100, 75_000) &&
    isInteger(value.proxy_send_timeout_ms, 100, 3_600_000) &&
    isInteger(value.proxy_read_timeout_ms, 100, 3_600_000) &&
    isInteger(value.client_body_buffer_size_bytes, 1_024, 2 ** 30) &&
    typeof value.server === 'string' && serverHeaderPattern.test(value.server) &&
    typeof value.default_type === 'string' && value.default_type.length <= 128 && mimeTypePattern.test(value.default_type) &&
    isInteger(value.client_max_body_size_bytes, 1_024, 10 * 2 ** 30) &&
    isInteger(value.keepalive_requests, 1, 1_000_000) &&
    isInteger(value.keepalive_timeout_ms, 100, 3_600_000) &&
    isBoolean(value.log_not_found) && isBoolean(value.server_tokens) &&
    isLargeClientHeaderBuffers(value.large_client_header_buffers) &&
    isInteger(value.server_names_hash_max_size, 512, 65_536) && isPowerOfTwo(value.server_names_hash_max_size) &&
    isInteger(value.server_names_hash_bucket_size, 32, 1_024) && isPowerOfTwo(value.server_names_hash_bucket_size)
}

function isNginxStreamConfiguration(value: unknown): value is NginxStreamConfiguration {
  return isRecord(value) && hasExactKeys(value, ['proxy_connect_timeout_ms', 'proxy_timeout_ms']) &&
    isInteger(value.proxy_connect_timeout_ms, 100, 75_000) &&
    isInteger(value.proxy_timeout_ms, 100, 86_400_000)
}

function isNginxWorkerOverride(value: unknown, base: NginxWorkerConfiguration): value is NginxWorkerOverride {
  return isRecord(value) && Object.keys(value).length > 0 && hasExactKeys(value, [], [
    'worker_processes', 'worker_connections', 'worker_rlimit_nofile', 'worker_shutdown_timeout_ms', 'logs_dir',
  ]) && isNginxWorkerConfiguration({ ...base, ...value })
}

function isNginxHttpOverride(value: unknown, base: NginxHttpConfiguration): value is NginxHttpOverride {
  return isRecord(value) && Object.keys(value).length > 0 && hasExactKeys(value, [], [
    'gzip_comp_level', 'gzip_http_version', 'gzip_min_length_bytes', 'gzip_vary', 'server_addr_outgoing',
    'proxy_request_buffering', 'proxy_buffering', 'proxy_cache_min_free_bytes', 'proxy_cache_max_size_bytes',
    'proxy_cache_methods', 'proxy_http_version', 'proxy_max_temp_file_size_bytes', 'proxy_next_upstream',
    'proxy_connect_timeout_ms', 'proxy_send_timeout_ms', 'proxy_read_timeout_ms', 'client_body_buffer_size_bytes',
    'server', 'client_max_body_size_bytes', 'default_type', 'keepalive_requests', 'keepalive_timeout_ms',
    'log_not_found', 'server_tokens', 'large_client_header_buffers', 'server_names_hash_max_size',
    'server_names_hash_bucket_size',
  ]) && isNginxHttpConfiguration({ ...base, ...value })
}

function isNginxStreamOverride(value: unknown, base: NginxStreamConfiguration): value is NginxStreamOverride {
  return isRecord(value) && Object.keys(value).length > 0 &&
    hasExactKeys(value, [], ['proxy_connect_timeout_ms', 'proxy_timeout_ms']) &&
    isNginxStreamConfiguration({ ...base, ...value })
}

function isNginxOverride(value: unknown, base: NginxConfiguration): value is NginxOverride {
  if (!isRecord(value) || Object.keys(value).length === 0 ||
    !hasExactKeys(value, [], ['worker', 'http', 'stream'])) return false
  return (!('worker' in value) || isNginxWorkerOverride(value.worker, base.worker)) &&
    (!('http' in value) || isNginxHttpOverride(value.http, base.http)) &&
    (!('stream' in value) || isNginxStreamOverride(value.stream, base.stream))
}

function isNginxConfiguration(value: unknown): value is NginxConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, ['worker', 'http', 'stream', 'overrides']) ||
    !isNginxWorkerConfiguration(value.worker) || !isNginxHttpConfiguration(value.http) ||
    !isNginxStreamConfiguration(value.stream) || !Array.isArray(value.overrides)) return false
  const configuration = value as unknown as NginxConfiguration
  const seenIDs = new Set<string>()
  const seenScopes = new Set<string>()
  for (const override of value.overrides) {
    if (!isRecord(override) || !hasExactKeys(override, ['id', 'scope', 'scope_id', 'values']) ||
      typeof override.id !== 'string' || !shortConfigurationIDPattern.test(override.id) ||
      (override.scope !== 'region' && override.scope !== 'node') || !isSafeLabel(override.scope_id) ||
      !isNginxOverride(override.values, configuration) || seenIDs.has(override.id)) return false
    const scopeKey = `${override.scope}\u0000${override.scope_id}`
    if (seenScopes.has(scopeKey)) return false
    seenIDs.add(override.id)
    seenScopes.add(scopeKey)
  }
  return true
}

function isTLSProtocols(value: unknown): value is TLSProtocol[] {
  return isUniqueStringArray(value, 1, tlsProtocolValues.size,
    (item) => tlsProtocolValues.has(item as TLSProtocol))
}

function arraysEqual(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index])
}

function isDefaultSslConfiguration(value: unknown): value is DefaultSslConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, ['mode', 'protocols', 'cipher_suites', 'prefer_server_ciphers']) ||
    !isTLSProtocols(value.protocols) || typeof value.cipher_suites !== 'string' ||
    value.cipher_suites.length > 4_096 || hasControlCharacter(value.cipher_suites) ||
    !isBoolean(value.prefer_server_ciphers)) return false
  switch (value.mode) {
    case 'recommended':
      return arraysEqual(value.protocols, ['TLSv1.2', 'TLSv1.3']) &&
        value.cipher_suites === recommendedCipherSuites && !value.prefer_server_ciphers
    case 'legacy_tls12':
      return arraysEqual(value.protocols, ['TLSv1.2', 'TLSv1.3']) &&
        value.cipher_suites === legacyTLS12CipherSuites && value.prefer_server_ciphers
    case 'legacy_full':
      return arraysEqual(value.protocols, ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']) &&
        value.cipher_suites === 'DEFAULT:@SECLEVEL=0' && value.prefer_server_ciphers
    default: return false
  }
}

function isDefaultCacheRule(value: unknown): value is DefaultCacheRuleConfiguration {
  return isRecord(value) && hasExactKeys(value, [
    'id', 'match', 'content', 'ttl_seconds', 'ignore_query', 'force_cache', 'range', 'ignore_vary',
    'no_cache', 'enabled', 'position',
  ]) && typeof value.id === 'string' && shortConfigurationIDPattern.test(value.id) &&
    isSafeText(value.match, 1, 64) && (value.content === null || isSafeText(value.content, 0, 2_048)) &&
    isInteger(value.ttl_seconds, 0, 31_536_000) && isBoolean(value.ignore_query) &&
    isBoolean(value.force_cache) && isBoolean(value.range) && isBoolean(value.ignore_vary) &&
    Array.isArray(value.no_cache) && value.no_cache.length <= 100 && value.no_cache.every((condition) =>
      isRecord(condition) && hasExactKeys(condition, ['variable', 'string']) &&
      isSafeText(condition.variable, 1, 256) && isSafeText(condition.string, 1, 2_048)) &&
    isBoolean(value.enabled) && isInteger(value.position, 0, 99)
}

function isDefaultCacheRules(value: unknown): value is DefaultCacheRuleConfiguration[] {
  if (!Array.isArray(value) || value.length > 100 || !value.every(isDefaultCacheRule)) return false
  return new Set(value.map((item) => item.id)).size === value.length &&
    new Set(value.map((item) => item.position)).size === value.length
}

function isDefaultOriginRequestHeader(value: unknown): value is DefaultOriginRequestHeaderConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'id', 'name', 'value', 'action', 'allow_duplicate', 'enabled', 'position',
  ]) || typeof value.id !== 'string' || !shortConfigurationIDPattern.test(value.id) ||
    !isString(value.name, 1, 256) || !httpTokenPattern.test(value.name) ||
    (value.action !== 'set' && value.action !== 'append' && value.action !== 'delete') ||
    !isBoolean(value.allow_duplicate) || !isBoolean(value.enabled) || !isInteger(value.position, 0, 99)) return false
  return value.action === 'delete' ? value.value === null : isSafeText(value.value, 0, 4_096)
}

function isDefaultOriginRequestHeaders(value: unknown): value is DefaultOriginRequestHeaderConfiguration[] {
  if (!Array.isArray(value) || value.length > 100 || !value.every(isDefaultOriginRequestHeader)) return false
  return new Set(value.map((item) => item.id)).size === value.length &&
    new Set(value.map((item) => item.position)).size === value.length
}

function isDefaultWafModules(value: unknown): value is DefaultWafModulesConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'sqli', 'xss', 'upload', 'fi', 'cmdi', 'java', 'jdeser', 'php', 'phpdeser', 'ssti',
  ])) return false
  return Object.values(value).every((mode) => mode === 'off' || mode === 'detect' || mode === 'on')
}

function isDefaultWebsiteOther(value: unknown): value is DefaultWebsiteOtherConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'load_balancing', 'gzip_enabled', 'gzip_types', 'websocket_enabled',
  ]) || !['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random'].includes(String(value.load_balancing)) ||
    !isBoolean(value.gzip_enabled) ||
    !isUniqueStringArray(value.gzip_types, 0, 128,
      (item) => item.length <= 128 && mimeTypePattern.test(item)) ||
    !isBoolean(value.websocket_enabled)) return false
  return !value.gzip_enabled || value.gzip_types.length > 0
}

function isDefaultWebsiteConfiguration(value: unknown): value is DefaultWebsiteConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'http', 'https', 'origin', 'cache_rules', 'origin_request_headers', 'access_log', 'security', 'other',
  ]) || !isRecord(value.http) || !hasExactKeys(value.http, ['listen_ports']) || !isPortList(value.http.listen_ports) ||
    !isRecord(value.https) || !hasExactKeys(value.https, [
      'listen_ports', 'hsts_enabled', 'http2_enabled', 'http3_enabled', 'force_https', 'ssl', 'ocsp_stapling_enabled',
    ]) || !isPortList(value.https.listen_ports) || portListsOverlap(value.http.listen_ports, value.https.listen_ports) ||
    !isBoolean(value.https.hsts_enabled) || !isBoolean(value.https.http2_enabled) ||
    !isBoolean(value.https.http3_enabled) || !isBoolean(value.https.force_https) ||
    !isDefaultSslConfiguration(value.https.ssl) || !isBoolean(value.https.ocsp_stapling_enabled) ||
    !isRecord(value.origin) || !hasExactKeys(value.origin, [
      'scheme', 'http_port', 'https_port', 'response_timeout_seconds', 'connect_timeout_seconds',
      'ssl_protocols', 'http_version', 'keepalive_enabled', 'post_body_limit_bytes',
    ]) || !['http', 'https', 'follow', 'follow_with_port'].includes(String(value.origin.scheme)) ||
    !isInteger(value.origin.http_port, 1, 65_535) || !isInteger(value.origin.https_port, 1, 65_535) ||
    !isInteger(value.origin.response_timeout_seconds, 1, 3_600) ||
    !isInteger(value.origin.connect_timeout_seconds, 1, 75) || !isTLSProtocols(value.origin.ssl_protocols) ||
    (value.origin.http_version !== '1.0' && value.origin.http_version !== '1.1') ||
    !isBoolean(value.origin.keepalive_enabled) || !isInteger(value.origin.post_body_limit_bytes, 1_024, 10 * 2 ** 30) ||
    !isDefaultCacheRules(value.cache_rules) || !isDefaultOriginRequestHeaders(value.origin_request_headers) ||
    !isRecord(value.access_log) || !hasExactKeys(value.access_log, [
      'capture_request_headers', 'capture_response_headers', 'capture_request_body', 'request_body_limit_kb',
    ]) || !isBoolean(value.access_log.capture_request_headers) || !isBoolean(value.access_log.capture_response_headers) ||
    !isBoolean(value.access_log.capture_request_body) || !isInteger(value.access_log.request_body_limit_kb, 0, 10_240) ||
    value.access_log.capture_request_body && value.access_log.request_body_limit_kb === 0 ||
    !isRecord(value.security) || !hasExactKeys(value.security, [
      'default_cc_policy_id', 'waf_enabled', 'waf_auto_block', 'waf_modules',
    ]) || !(value.security.default_cc_policy_id === null || isSafeLabel(value.security.default_cc_policy_id)) ||
    !isBoolean(value.security.waf_enabled) || !isRecord(value.security.waf_auto_block) ||
    !hasExactKeys(value.security.waf_auto_block, ['enabled', 'window_seconds', 'hit_threshold', 'block_seconds']) ||
    !isBoolean(value.security.waf_auto_block.enabled) ||
    !isInteger(value.security.waf_auto_block.window_seconds, 1, 86_400) ||
    !isInteger(value.security.waf_auto_block.hit_threshold, 1, 1_000_000) ||
    !isInteger(value.security.waf_auto_block.block_seconds, 1, 604_800) ||
    !isDefaultWafModules(value.security.waf_modules) || !isDefaultWebsiteOther(value.other)) return false
  return true
}

function isDefaultStreamConfiguration(value: unknown): value is DefaultStreamConfiguration {
  return isRecord(value) && hasExactKeys(value, ['protocol', 'load_balancing', 'proxy_protocol_enabled']) &&
    (value.protocol === 'tcp' || value.protocol === 'udp') &&
    (value.load_balancing === 'round_robin' || value.load_balancing === 'ip_hash') &&
    isBoolean(value.proxy_protocol_enabled)
}

function isDefaultCertificateConfiguration(value: unknown): value is DefaultCertificateConfiguration {
  return isRecord(value) && hasExactKeys(value, ['issuer']) &&
    (value.issuer === 'zerossl' || value.issuer === 'lets_encrypt' || value.issuer === 'google_trust')
}

function isDefaultOverride(value: unknown): value is DefaultOverride {
  return isRecord(value) && hasExactKeys(value, ['website']) &&
    isRecord(value.website) && hasExactKeys(value.website, ['other']) && isDefaultWebsiteOther(value.website.other)
}

function isDefaultConfiguration(value: unknown): value is DefaultConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, ['website', 'stream', 'certificate', 'overrides']) ||
    !isDefaultWebsiteConfiguration(value.website) || !isDefaultStreamConfiguration(value.stream) ||
    !isDefaultCertificateConfiguration(value.certificate) || !Array.isArray(value.overrides)) return false
  const seenIDs = new Set<string>()
  const seenScopes = new Set<string>()
  for (const override of value.overrides) {
    if (!isRecord(override) || !hasExactKeys(override, ['id', 'scope', 'scope_id', 'values']) ||
      typeof override.id !== 'string' || !shortConfigurationIDPattern.test(override.id) ||
      override.scope !== 'region' || !isSafeLabel(override.scope_id) ||
      !isDefaultOverride(override.values) || seenIDs.has(override.id) || seenScopes.has(override.scope_id)) {
      return false
    }
    seenIDs.add(override.id)
    seenScopes.add(override.scope_id)
  }
  return true
}

function isResourceSiteConfiguration(value: unknown): value is ResourceSiteConfiguration {
  return isRecord(value) && hasExactKeys(value, [
    'related_config_min_limit', 'related_config_max_times_limit', 'black_ip_limit', 'white_ip_limit',
    'daily_clean_url_limit', 'daily_clean_dir_limit', 'daily_pre_cache_url_limit', 'daily_ip_unlock_limit',
    'ip_unlock_per_request_limit', 'cc_rule_max_limit', 'max_domains_per_site', 'listen_default_http_80',
    'daily_access_log_download_limit', 'access_log_tmp_dir', 'access_log_retain_hours',
  ]) && isInteger(value.related_config_min_limit, 1, 100_000) &&
    isInteger(value.related_config_max_times_limit, 1, 1_000) &&
    isInteger(value.black_ip_limit, 1, 1_000_000) && isInteger(value.white_ip_limit, 1, 1_000_000) &&
    isInteger(value.daily_clean_url_limit, 1, 10_000_000) &&
    isInteger(value.daily_clean_dir_limit, 1, 1_000_000) &&
    isInteger(value.daily_pre_cache_url_limit, 1, 10_000_000) &&
    isInteger(value.daily_ip_unlock_limit, 1, 10_000_000) &&
    isInteger(value.ip_unlock_per_request_limit, 1, 100_000) &&
    isInteger(value.cc_rule_max_limit, 1, 100_000) && isInteger(value.max_domains_per_site, 1, 100) &&
    isBoolean(value.listen_default_http_80) &&
    isInteger(value.daily_access_log_download_limit, 1, 100_000) &&
    isResourceAccessLogPath(value.access_log_tmp_dir) && isInteger(value.access_log_retain_hours, 1, 720)
}

function isResourceStreamConfiguration(value: unknown): value is ResourceStreamConfiguration {
  return isRecord(value) && hasExactKeys(value, [
    'custom_port_not_allow', 'related_config_min_limit', 'related_config_max_times_limit', 'acl_max_limit',
  ]) && isPortRanges(value.custom_port_not_allow) && isInteger(value.related_config_min_limit, 1, 100_000) &&
    isInteger(value.related_config_max_times_limit, 1, 100) && isInteger(value.acl_max_limit, 1, 100_000)
}

function isResourceSiteStreamConfiguration(value: unknown): value is ResourceSiteStreamConfiguration {
  return isRecord(value) && hasExactKeys(value, ['custom_port_not_allow', 'custom_port_allow']) &&
    isPortRanges(value.custom_port_not_allow) && isPortRanges(value.custom_port_allow) &&
    !portRangesOverlap(value.custom_port_not_allow, value.custom_port_allow)
}

function isResourceConfiguration(value: unknown): value is ResourceConfiguration {
  return isRecord(value) && hasExactKeys(value, ['site', 'stream', 'site_stream', 'overrides']) &&
    isResourceSiteConfiguration(value.site) && isResourceStreamConfiguration(value.stream) &&
    isResourceSiteStreamConfiguration(value.site_stream) && Array.isArray(value.overrides) && value.overrides.length === 0
}

function isErrorPagesConfiguration(value: unknown): value is ErrorPageConfiguration[] {
  if (!Array.isArray(value) || value.length > errorStatusCodes.size) return false
  const statusesSeen = new Set<number>()
  return value.every((item) => {
    if (!isRecord(item) || !hasExactKeys(item, [
      'status_code', 'mime_type', 'size_bytes', 'sha256', 'storage_object_key',
    ]) || !isInteger(item.status_code, 400, 504) || !errorStatusCodes.has(item.status_code) ||
      statusesSeen.has(item.status_code) || typeof item.mime_type !== 'string' || !mimeTypes.has(item.mime_type) ||
      !isInteger(item.size_bytes, 1, 2 ** 20) || typeof item.sha256 !== 'string' || !sha256Pattern.test(item.sha256) ||
      !isString(item.storage_object_key, 1, 512)) return false
    statusesSeen.add(item.status_code)
    return true
  })
}

function isSecretsConfiguration(value: unknown): value is SecretsConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [], ['error_page_storage'])) return false
  if (!('error_page_storage' in value)) return true
  const secret = value.error_page_storage
  return isRecord(secret) && hasExactKeys(secret, [
    'provider', 'reference', 'key_id', 'algorithm', 'ciphertext_sha256', 'masked',
  ]) && typeof secret.provider === 'string' && secretProviders.has(secret.provider) &&
    isString(secret.reference, 1, 256) && isString(secret.key_id, 1, 256) &&
    typeof secret.algorithm === 'string' && secretAlgorithms.has(secret.algorithm) &&
    typeof secret.ciphertext_sha256 === 'string' && sha256Pattern.test(secret.ciphertext_sha256) &&
    secret.masked === true
}

function isNodeMonitoringConfiguration(value: unknown): value is NodeMonitoringConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'port_mode', 'probe_interval_ms', 'probe_timeout_ms', 'failure_threshold',
    'recovery_threshold', 'failure_debounce_ms', 'recovery_debounce_ms',
    'recovery_notification_enabled',
  ], ['custom_port', 'monitor_enabled', 'protocol', 'monitor_port', 'monitor_groups', 'monitor_action', 'failure_ratio', 'bandwidth_over_limit'])) return false
  const validPort = value.port_mode === 'default'
    ? !('custom_port' in value)
    : value.port_mode === 'custom' && isInteger(value.custom_port, 1, 65_535)
  const validCompatibility = (!('monitor_enabled' in value) || typeof value.monitor_enabled === 'boolean') &&
    (!('protocol' in value) || value.protocol === 'http' || value.protocol === 'tcp' || value.protocol === 'ping') &&
    (!('monitor_port' in value) || isInteger(value.monitor_port, 1, 65_535)) &&
    (!('monitor_groups' in value) || Array.isArray(value.monitor_groups) && value.monitor_groups.length > 0 &&
      value.monitor_groups.every((group) => ['domestic', 'telecom', 'unicom', 'mobile', 'overseas'].includes(group))) &&
    (!('monitor_action' in value) || value.monitor_action === 'none' || value.monitor_action === 'pause') &&
    (!('failure_ratio' in value) || isInteger(value.failure_ratio, 1, 100)) &&
    (!('bandwidth_over_limit' in value) || isInteger(value.bandwidth_over_limit, 1, 20))
  return validPort && isInteger(value.probe_interval_ms, 1_000, 300_000) &&
    isInteger(value.probe_timeout_ms, 100, 60_000) && value.probe_timeout_ms <= value.probe_interval_ms &&
    isInteger(value.failure_threshold, 1, 20) && isInteger(value.recovery_threshold, 1, 20) &&
    isInteger(value.failure_debounce_ms, 0, 3_600_000) &&
    isInteger(value.recovery_debounce_ms, 0, 3_600_000) && validCompatibility &&
    typeof value.recovery_notification_enabled === 'boolean'
}

function isDDoSProtectionConfiguration(value: unknown): value is DDoSProtectionConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, [
    'max_connections_per_ip', 'new_connections_per_second', 'new_connections_per_minute',
    'rate_ban_seconds', 'max_connections_per_port', 'allow_networks', 'cc_kernel_ban',
  ], ['empty_connection', 'tcp_flag_filter', 'tcp_flag_types', 'drop_invalid'])) return false
  const types = value.tcp_flag_types
  const validFlags = (!('tcp_flag_filter' in value) || value.tcp_flag_filter === true) &&
    (!('drop_invalid' in value) || value.drop_invalid === true) &&
    (types === undefined ? !('tcp_flag_filter' in value) : Array.isArray(types) && types.length > 0 &&
      types.every((kind, index) => tcpFlagTypes.includes(kind as TCPFlagType) &&
        (index === 0 || tcpFlagTypes.indexOf(kind as TCPFlagType) > tcpFlagTypes.indexOf(types[index - 1] as TCPFlagType))))
  const empty = value.empty_connection
  const validEmpty = !('empty_connection' in value) || isRecord(empty) &&
    hasExactKeys(empty, ['idle_seconds', 'threshold', 'window_seconds', 'ban_seconds']) &&
    isInteger(empty.idle_seconds, 5, 600) && isInteger(empty.threshold, 3, 10_000) &&
    isInteger(empty.window_seconds, 10, 3_600) && isInteger(empty.ban_seconds, 1, 604_800)
  return isInteger(value.max_connections_per_ip, 0, 1_000_000) &&
    isInteger(value.new_connections_per_second, 0, 1_000_000) &&
    isInteger(value.new_connections_per_minute, 0, 60_000_000) &&
    isInteger(value.rate_ban_seconds, 0, 604_800) &&
    isInteger(value.max_connections_per_port, 0, 10_000_000) &&
    Array.isArray(value.allow_networks) && value.allow_networks.length <= 256 &&
    value.allow_networks.every((network) => isString(network, 1, 64)) &&
    (value.cc_kernel_ban === 'off' || value.cc_kernel_ban === 'exclusive_ports' || value.cc_kernel_ban === 'site_ports') &&
    validEmpty && validFlags
}

function isAccessLogFieldsConfiguration(value: unknown): value is AccessLogFieldsConfiguration {
  if (!isRecord(value) || !hasExactKeys(value, ['fields']) || !Array.isArray(value.fields)) return false
  const fields = value.fields
  return fields.every((key, index) => accessLogFieldKeys.includes(key as AccessLogFieldKey) &&
    (index === 0 || accessLogFieldKeys.indexOf(key as AccessLogFieldKey) > accessLogFieldKeys.indexOf(fields[index - 1] as AccessLogFieldKey)))
}

function isCategoryValue<C extends SystemConfigurationCategory>(
  category: C,
  value: unknown,
): value is SystemConfigurationValueMap[C] {
  switch (category) {
    case 'nginx': return isNginxConfiguration(value)
    case 'defaults': return isDefaultConfiguration(value)
    case 'resources': return isResourceConfiguration(value)
    case 'error_pages': return isErrorPagesConfiguration(value)
    case 'secrets': return isSecretsConfiguration(value)
    case 'node_monitoring': return isNodeMonitoringConfiguration(value)
    case 'ddos_protection': return isDDoSProtectionConfiguration(value)
    case 'access_log_fields': return isAccessLogFieldsConfiguration(value)
  }
}

function parseDocument<C extends SystemConfigurationCategory>(
  category: C,
  value: unknown,
): SystemConfigurationDocument<C> {
  if (!isRecord(value) || !hasExactKeys(value, [
    'schema', 'category', 'head_revision', 'active_revision', 'revision', 'status', 'snapshot_sha256',
    'pending_categories', 'value',
  ]) || !isPendingCategories(value.pending_categories) || value.schema !== 'cdnca.system-configuration/v2' || value.category !== category ||
    !isInteger(value.head_revision, 0, Number.MAX_SAFE_INTEGER) ||
    !isInteger(value.active_revision, 0, value.head_revision) ||
    !isInteger(value.revision, 0, value.head_revision) ||
    (value.head_revision === 0
      ? value.active_revision !== 0 || value.revision !== 0 || value.status !== 'draft'
      : value.revision === 0) ||
    typeof value.status !== 'string' || !statuses.has(value.status as SystemConfigurationStatus) ||
    typeof value.snapshot_sha256 !== 'string' || !sha256Pattern.test(value.snapshot_sha256) ||
    !isCategoryValue(category, value.value)) throw invalidResponse()
  return value as unknown as SystemConfigurationDocument<C>
}

function isPendingCategories(value: unknown): value is SystemConfigurationCategory[] {
  return Array.isArray(value) && value.length <= systemConfigurationCategories.length &&
    new Set(value).size === value.length &&
    value.every((item) => (systemConfigurationCategories as readonly unknown[]).includes(item))
}

function parseLifecycleResult(value: unknown): SystemConfigurationLifecycleResult {
  if (!isRecord(value) || !hasExactKeys(value, [
    'revision', 'status', 'snapshot_sha256', 'replayed',
  ]) || !isInteger(value.revision, 1, Number.MAX_SAFE_INTEGER) ||
    (value.status !== 'validated' && value.status !== 'active') ||
    typeof value.snapshot_sha256 !== 'string' || !sha256Pattern.test(value.snapshot_sha256) ||
    typeof value.replayed !== 'boolean') throw invalidResponse()
  return value as unknown as SystemConfigurationLifecycleResult
}

function parseRollbackResult(value: unknown, targetRevision: number): SystemConfigurationRollbackResult {
  if (!isRecord(value) || !hasExactKeys(value, [
    'revision', 'status', 'snapshot_sha256', 'source_revision', 'replayed',
  ]) || !isInteger(value.revision, 1, Number.MAX_SAFE_INTEGER) || value.status !== 'draft' ||
    typeof value.snapshot_sha256 !== 'string' || !sha256Pattern.test(value.snapshot_sha256) ||
    value.source_revision !== targetRevision || value.revision <= targetRevision ||
    typeof value.replayed !== 'boolean') throw invalidResponse()
  return value as unknown as SystemConfigurationRollbackResult
}

function isActivationPublication(value: unknown): value is SystemConfigurationActivationPublication {
  return isRecord(value) && hasExactKeys(value, [
    'tenant_scope_id', 'tenant_source_revision', 'publication_id', 'config_version_id', 'rollout_id',
    'rollout_state', 'artifact_sha256', 'reason_code', 'created_at',
  ]) && typeof value.tenant_scope_id === 'string' && uuidPattern.test(value.tenant_scope_id) &&
    isInteger(value.tenant_source_revision, 1, Number.MAX_SAFE_INTEGER) &&
    typeof value.publication_id === 'string' && uuidPattern.test(value.publication_id) &&
    typeof value.config_version_id === 'string' && uuidPattern.test(value.config_version_id) &&
    typeof value.rollout_id === 'string' && uuidPattern.test(value.rollout_id) &&
    typeof value.rollout_state === 'string' && rolloutStates.has(value.rollout_state as SystemConfigurationRolloutState) &&
    typeof value.artifact_sha256 === 'string' && sha256Pattern.test(value.artifact_sha256) &&
    value.reason_code === 'system_configuration_activated' &&
    typeof value.created_at === 'string' && timestampPattern.test(value.created_at) && Number.isFinite(Date.parse(value.created_at))
}

function parseActivationPublicationPage(value: unknown, revision: number): SystemConfigurationActivationPublicationPage {
  if (!isRecord(value) || !hasExactKeys(value, ['revision', 'publications']) ||
    value.revision !== revision || !Array.isArray(value.publications) ||
    value.publications.length > 10_000 || !value.publications.every(isActivationPublication)) throw invalidResponse()
  return value as unknown as SystemConfigurationActivationPublicationPage
}

async function lifecycleRequest(
  accessToken: string,
  revision: number,
  action: 'preflight' | 'activate' | 'publications',
  init: RequestInit = {},
): Promise<unknown> {
  if (!isInteger(revision, 1, Number.MAX_SAFE_INTEGER)) throw invalidRequest()
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-configuration/revisions/${revision}/${action}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...init.headers },
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

async function rollbackRequest(
  accessToken: string,
  targetRevision: number,
  expectedHeadRevision: number,
  expectedActiveRevision: number,
  idempotencyKey: string,
  requestId: string,
): Promise<SystemConfigurationRollbackResult> {
  if (!isInteger(targetRevision, 1, Number.MAX_SAFE_INTEGER) ||
    !isInteger(expectedHeadRevision, 1, Number.MAX_SAFE_INTEGER) ||
    !isInteger(expectedActiveRevision, 1, expectedHeadRevision) ||
    targetRevision > expectedHeadRevision || !idempotencyPattern.test(idempotencyKey) ||
    !idempotencyPattern.test(requestId)) throw invalidRequest()
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-configuration/revisions/${targetRevision}/rollback`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'If-Match': `"${expectedHeadRevision}"`,
        'Idempotency-Key': idempotencyKey,
        'X-Request-ID': requestId,
      },
      body: JSON.stringify({ expected_active_revision: expectedActiveRevision }),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw invalidResponse()
  }
  const result = parseRollbackResult(body, targetRevision)
  const replayedHeader = response.headers.get('Idempotency-Replayed')
  if (response.headers.get('ETag') !== `"${result.revision}"` ||
    (result.replayed ? replayedHeader !== 'true' : replayedHeader !== null)) throw invalidResponse()
  return result
}

async function request<C extends SystemConfigurationCategory>(
  accessToken: string,
  category: C,
  init: RequestInit = {},
): Promise<SystemConfigurationDocument<C>> {
  let response: Response
  const controller = new AbortController()
  const timeout = globalThis.setTimeout(() => controller.abort(), systemConfigurationRequestTimeoutMs)
  const externalSignal = init.signal
  const abortFromCaller = () => controller.abort()
  if (externalSignal?.aborted) controller.abort()
  else externalSignal?.addEventListener('abort', abortFromCaller, { once: true })
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-configuration/categories/${encodeURIComponent(category)}`, {
      ...init,
      signal: controller.signal,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  } finally {
    globalThis.clearTimeout(timeout)
    externalSignal?.removeEventListener('abort', abortFromCaller)
  }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw invalidResponse()
  }
  const document = parseDocument(category, body)
  if (response.headers.get('ETag') !== `"${document.head_revision}"`) throw invalidResponse()
  return document
}

export function newSystemConfigurationIdempotencyKey(category: SystemConfigurationCategory): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `system-configuration-${category}-${suffix}`
}

export function newSystemConfigurationRequestId(category: SystemConfigurationCategory): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `system-configuration-${category}-request-${suffix}`
}

export const systemConfigurationApi = {
  get<C extends SystemConfigurationCategory>(
    accessToken: string,
    category: C,
  ): Promise<SystemConfigurationDocument<C>> {
    return request(accessToken, category)
  },

  put<C extends SystemConfigurationCategory>(
    accessToken: string,
    category: C,
    value: SystemConfigurationWriteValueMap[C],
    expectedHeadRevision: number,
    idempotencyKey: string,
    requestId: string,
  ): Promise<SystemConfigurationDocument<C>> {
    if (!isInteger(expectedHeadRevision, 0, Number.MAX_SAFE_INTEGER) ||
      !idempotencyPattern.test(idempotencyKey) || !idempotencyPattern.test(requestId)) {
      return Promise.reject(invalidRequest())
    }
    return request(accessToken, category, {
      method: 'PUT',
      headers: {
        'Idempotency-Key': idempotencyKey,
        'X-Request-ID': requestId,
        'If-Match': `"${expectedHeadRevision}"`,
      },
      body: JSON.stringify({ value }),
    })
  },

  async preflight(
    accessToken: string,
    revision: number,
    snapshotSHA256: string,
    idempotencyKey: string,
    requestId: string,
    expectedPendingCategories?: readonly SystemConfigurationCategory[],
  ): Promise<SystemConfigurationLifecycleResult> {
    if (!sha256Pattern.test(snapshotSHA256) || !idempotencyPattern.test(idempotencyKey) ||
      !idempotencyPattern.test(requestId) ||
      (expectedPendingCategories !== undefined && !isPendingCategories([...expectedPendingCategories]))) throw invalidRequest()
    return parseLifecycleResult(await lifecycleRequest(accessToken, revision, 'preflight', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'X-Request-ID': requestId,
      },
      body: JSON.stringify(expectedPendingCategories === undefined
        ? { snapshot_sha256: snapshotSHA256 }
        : { snapshot_sha256: snapshotSHA256, expected_pending_categories: expectedPendingCategories }),
    }))
  },

  async activate(
    accessToken: string,
    revision: number,
    expectedActiveRevision: number,
    idempotencyKey: string,
    requestId: string,
    expectedPendingCategories?: readonly SystemConfigurationCategory[],
  ): Promise<SystemConfigurationLifecycleResult> {
    if (!isInteger(expectedActiveRevision, 0, Number.MAX_SAFE_INTEGER) ||
      !idempotencyPattern.test(idempotencyKey) || !idempotencyPattern.test(requestId) ||
      (expectedPendingCategories !== undefined && !isPendingCategories([...expectedPendingCategories]))) throw invalidRequest()
    return parseLifecycleResult(await lifecycleRequest(accessToken, revision, 'activate', {
      method: 'POST',
      headers: {
        'If-Match': `"${expectedActiveRevision}"`,
        'Idempotency-Key': idempotencyKey,
        'X-Request-ID': requestId,
        ...(expectedPendingCategories === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(expectedPendingCategories === undefined
        ? {}
        : { body: JSON.stringify({ expected_pending_categories: expectedPendingCategories }) }),
    }))
  },

  rollback(
    accessToken: string,
    targetRevision: number,
    expectedHeadRevision: number,
    expectedActiveRevision: number,
    idempotencyKey: string,
    requestId: string,
  ): Promise<SystemConfigurationRollbackResult> {
    return rollbackRequest(
      accessToken, targetRevision, expectedHeadRevision, expectedActiveRevision, idempotencyKey, requestId,
    )
  },

  async listPublications(
    accessToken: string,
    revision: number,
  ): Promise<SystemConfigurationActivationPublicationPage> {
    return parseActivationPublicationPage(
      await lifecycleRequest(accessToken, revision, 'publications'),
      revision,
    )
  },
}
