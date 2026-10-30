import { ApiError, networkApiError, responseApiError } from './auth'

export type StreamProtocol = 'tcp' | 'udp'
export type StreamBalanceWay = 'rr' | 'ip_hash'
export type StreamSettingName = 'proxy_protocol' | 'listen_protocol' | 'balance_way'
export type StreamSettingScope = 'global' | 'group'
export type StreamPublicationState = 'unknown' | 'pending' | 'leased' | 'retrying' | 'reconciling' | 'succeeded' | 'failed' | 'superseded'
export type StreamGeoAction = 'allow' | 'block'
export type StreamEligibilityState = 'eligible' | 'ineligible'

export interface StreamAdditionalListener {
  id: string
  protocol: StreamProtocol
  address: '*'
  port: number
  // 端口范围 port..port_end（节点需 tcp/udp v9），单端口时省略。
  port_end?: number
}

export interface StreamDNSPolicy {
  positive_min_ttl_seconds: number
  positive_max_ttl_seconds: number
  negative_ttl_seconds: number
  stale_if_error_seconds: number
  allow_private_addresses: boolean
}

export interface StreamGeoRegionCIDRs {
  region: string
  cidrs: string[]
}

export interface StreamGeoPolicy {
  enabled: boolean
  unknown_region_action: StreamGeoAction
  trusted_proxy_cidrs: string[]
  blocked_regions: string[]
  region_cidrs: StreamGeoRegionCIDRs[]
}

// 四层防护规则（guard_rules，节点需 tcp/udp v10；geo 条件另需节点已加载 IP 情报库）。
// 按顺序判定，第一条全部条件满足的规则生效。
export type StreamGuardAction = 'drop' | 'ban' | 'allow'
export type StreamGuardMatch = 'prefix_hex' | 'contains' | 'regex'
export type StreamGuardGeoField = 'tag' | 'asn' | 'country' | 'province' | 'city'

export interface StreamGuardGeo {
  field: StreamGuardGeoField
  negate?: boolean
  values: string[]
}

export interface StreamGuardRule {
  id: string
  action: StreamGuardAction
  first_packet?: { match: StreamGuardMatch; value: string }
  server_names?: string[]
  client_ip?: { cidrs: string[]; negate?: boolean }
  geo?: StreamGuardGeo[]
  // 仅 ban：拉黑秒数、命中次数阈值、计数窗口（阈值为 1 时没有窗口）。
  ban_seconds?: number
  threshold?: number
  window_seconds?: number
}

export const streamGuardRulesMax = 64

// 转发是独立资源（迁移 506），不属于任何网站。社区版不绑定套餐，写入不带套餐订阅。
export interface StreamFields {
  name: string
  remark: string
  protocol: StreamProtocol
  listen_address: '*'
  listen_port: number
  additional_listeners?: StreamAdditionalListener[]
  upstream_address: string
  upstream_host: string
  upstream_port: number
  dns_policy: StreamDNSPolicy
  geo_policy: StreamGeoPolicy
  connect_timeout_ms: number
  response_timeout_ms: number
  max_connections_per_client: number
  proxy_protocol_inbound: boolean
  proxy_protocol_v1: boolean
  balance_way: StreamBalanceWay
  enabled: boolean
  // TLS 透传：按 ClientHello 的 SNI 分流，仅 TCP；关闭时 server_names 必须为空。
  tls_passthrough: boolean
  server_names: string[]
  // 单 IP 新建连接速率（节点需 tcp/udp v6）：每秒新建连接数，0 为不限；突发与拉黑秒数仅在限速时可非 0。
  max_new_connections_per_client_per_second: number
  new_connection_burst: number
  new_connection_ban_seconds: number
  // 回源携带客户端 IP = TOA（节点需 L4_TOA）：仅 TCP，与 PROXY（入站/出站）互斥。
  toa: boolean
  // 会话日志（节点需 tcp/udp v7）：逐会话访问日志（含被拒记录）与实时连接的真实客户端。
  session_log_enabled: boolean
  // 端口范围 listen_port..listen_port_end（最多 1000 个端口，0/省略为单端口）与跟随端口回源（节点需 tcp/udp v9）。
  // 跟随端口时 upstream_port 由服务端存为 listen_port。请求里未用时省略。
  listen_port_end?: number
  upstream_follow_port?: boolean
  // 防护规则；请求里没有规则时省略。
  guard_rules?: StreamGuardRule[]
  // 源站列表（源地址/权重/上下线）：多个时只能是 IP，单个可为域名；提交时以第一个为 upstream_address。
  origins?: StreamOrigin[]
  // IPv6开启（节点需 tcp/udp v11）。
  listen_ipv6?: boolean
  // 访问控制：ACL 默认行为与 IP 规则。省略即默认允许、无规则。
  acl?: StreamACL
}

export interface StreamOrigin {
  address: string
  weight: number
  down: boolean
}

export type StreamACLAction = 'allow' | 'deny'
export interface StreamACL {
  default_action: StreamACLAction
  rules: Array<{ cidr: string; action: StreamACLAction }>
}

export type StreamAdminStatus = 'normal' | 'locked' | 'traffic_exceeded' | 'package_expired'
export type StreamSyncState = 'done' | 'pending' | 'failed'

// 线路列：所属站点（未指定时为套餐）的区域、线路分组与备用线路组。
export interface StreamLine {
  region_id: string | null
  region_name: string
  node_group_id: string | null
  node_group_name: string
  backup_node_group_id: string | null
  backup_node_group_name: string
}

// 转发自有 CNAME域名/CNAME模式/线路（更多操作）：null 跟随所属套餐。
export interface StreamOverrides {
  cname_domain: string | null
  cname_mode: 'site' | 'package' | null
  region_id: string | null
  node_group_id: string | null
  backup_node_group_id: string | null
}

export type BatchStreamActionValue =
  | { action: 'set_status'; admin_status: StreamAdminStatus }
  | { action: 'cname_domain'; cname_domain: string }
  | { action: 'cname_mode'; cname_mode: '' | 'site' | 'package' }
  | { action: 'line_group'; region_id?: string; node_group_id?: string; backup_node_group_id?: string }
  | { action: 'cname_regenerate' }
export type BatchStreamActionInput = BatchStreamActionValue & { items: Array<{ id: string; expected_revision: number }> }

export interface StreamGroupReference {
  id: string
  name: string
  remark: string
}

export interface StreamResponseFields extends StreamFields {
  cname?: string | null
  cname_domain?: string | null
  cname_hostname?: string | null
  cname_state?: string | null
  /** Why the stream's own CNAME failed (cname_state failed, migration 505). */
  cname_failure_code?: string | null
  groups: StreamGroupReference[]
}

export interface StreamRuntimeGeoPolicy extends StreamGeoPolicy {
  tenant_id: string
  stream_id: string
  revision: number
}

export interface StreamRuntimeSpecV2 {
  schema_version: 'cdnca.edge.l4/v2'
  tenant_id: string
  stream_id: string
  revision: number
  listener: { protocol: StreamProtocol; address: '*'; port: number; port_end?: number }
  additional_listeners?: StreamAdditionalListener[]
  endpoint: { address?: string; host?: string; port: number; follow_port?: true; origins?: Array<{ address: string; weight: number; down?: true }>; balance?: 'ip_hash' }
  dns: StreamDNSPolicy
  geo: StreamRuntimeGeoPolicy
  connect_timeout_ms: number
  response_timeout_ms: number
  max_connections_per_client: number
  drain_timeout_ms: number
  proxy_protocol_inbound: boolean
  proxy_protocol_outbound: boolean
  // 仅在透传开启时出现。
  tls_passthrough?: true
  server_names?: string[]
  // 仅在限速时出现。
  new_conn_rate?: { rate_per_second: number; burst: number; ban_seconds: number }
  // 仅在开启会话日志时出现。
  session_log?: true
  // 仅在有防护规则时出现（ACL 规则在前，转发自有规则在后）。
  guard_rules?: StreamGuardRule[]
  listen_ipv6?: true
}

export type StreamRuntimeSpec = StreamRuntimeSpecV2

export interface StreamPublishIntent {
  id: string
  version: number
  operation: 'create' | 'update' | 'delete'
  desired_state: 'enabled' | 'disabled' | 'deleted'
  resource_revision: number
  configuration_source_revision: number
  runtime_spec: StreamRuntimeSpec
  state: StreamPublicationState
  automatic_request_id: string | null
  publication_id: string | null
  rollout_id: string | null
  created_at: string
}

export interface Stream extends StreamResponseFields {
  id: string
  display_id: string
  scope_id: string
  /** 旧数据可能仍绑定套餐订阅（只读展示用，写入不再提交）。 */
  package_subscription_id?: string | null
  package_name?: string | null
  package_expires_at?: string | null
  eligibility_state: StreamEligibilityState
  owner: { id: string; display_name: string } | null
  origins: StreamOrigin[]
  listen_ipv6: boolean
  acl: StreamACL
  admin_status: StreamAdminStatus
  overrides: StreamOverrides
  line: StreamLine
  sync_state: StreamSyncState
  revision: number
  publish_intent: StreamPublishIntent
  created_at: string
  updated_at: string
}

export interface StreamListResponse {
  items: Stream[]
  total: number
  page: number
  limit: number
}

export interface StreamListParams {
  page: number
  limit: number
  search?: string
  protocol?: StreamProtocol
  enabled?: boolean
  listen_port?: number
  upstream?: string
  display_id?: string
  owner_display_id?: string
  publication_state?: StreamPublicationState
	group_id?: string
	cname_domain?: string
	cname_hostname?: string
	region_id?: string
	node_group_id?: string
	sync_state?: StreamSyncState
	admin_status?: StreamAdminStatus
}

export interface CreateStreamRequest extends StreamFields {
  target_scope_id?: string
  owner_id?: string
  // 转发列表的「所属分组」，可不选。
  group_ids?: string[]
}

export interface UpdateStreamRequest extends StreamFields {
  expected_revision: number
  // 不提交表示保持原有分组，提交空数组表示清空。
  group_ids?: string[]
}

// 批量添加：每行「监听端口|IP|回源端口」；template 为各行共用字段（备注、超时等）。
export interface BatchCreateStreamsRequest {
  target_scope_id?: string
  owner_id?: string
  group_ids?: string[]
  template: StreamFields
  lines: string[]
  ignore_errors: boolean
}

export interface BatchCreateStreamsResult {
  items: Array<{ line: number; text: string; status: 'created' | 'failed' | 'skipped'; error?: { code: string } }>
  created: number
  failed: number
  committed: boolean
}

export interface BatchStreamActionResult {
  items: Array<{ id: string; status: 'updated' | 'failed'; error?: { code: string } }>
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

const serverNameLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u

// 精确主机名或 `*.` 前缀通配，二者的主机部分都至少两级标签。
export function validStreamServerName(value: string): boolean {
  const host = value.startsWith('*.') ? value.slice(2) : value
  const labels = host.split('.')
  return host.length <= 253 && labels.length >= 2 && labels.every((label) => serverNameLabel.test(label))
}

// validStreamNewConnectionRate mirrors the server (migration 299): 0 = unlimited
// with no burst or ban; otherwise 1–100000/s, burst 0–100000, ban 0–86400 s.
export function validStreamNewConnectionRate(rate: unknown, burst: unknown, banSeconds: unknown): boolean {
  if (!integer(rate, 0, 100000) || !integer(burst, 0, 100000) || !integer(banSeconds, 0, 86400)) return false
  return rate !== 0 || (burst === 0 && banSeconds === 0)
}

export function validStreamServerNames(enabled: boolean, names: readonly string[]): boolean {
  if (!enabled) return names.length === 0
  return names.length >= 1 && names.length <= 32 && new Set(names).size === names.length && names.every(validStreamServerName)
}

function serverNameSignature(value: readonly string[]): string {
  return JSON.stringify([...value].sort())
}

function parseDNSPolicy(value: unknown): StreamDNSPolicy | null {
  const policy = record(value)
  if (!policy ||
    !integer(policy.positive_min_ttl_seconds, 0, 300) ||
    !integer(policy.positive_max_ttl_seconds, 0, 86400) ||
    !integer(policy.negative_ttl_seconds, 0, 3600) ||
    !integer(policy.stale_if_error_seconds, 0, 86400) ||
    typeof policy.allow_private_addresses !== 'boolean') return null
  return value as StreamDNSPolicy
}

function parseGeoPolicy(value: unknown, runtime = false): StreamGeoPolicy | StreamRuntimeGeoPolicy | null {
  const policy = record(value)
  if (!policy || typeof policy.enabled !== 'boolean' ||
    (policy.unknown_region_action !== 'allow' && policy.unknown_region_action !== 'block') ||
    !stringArray(policy.trusted_proxy_cidrs) || !stringArray(policy.blocked_regions) ||
    !Array.isArray(policy.region_cidrs) || !policy.region_cidrs.every((entry) => {
      const region = record(entry)
      return region && typeof region.region === 'string' && stringArray(region.cidrs)
    })) return null
  if (runtime && (!uuidPattern.test(String(policy.tenant_id)) || policy.site_id !== undefined ||
    !uuidPattern.test(String(policy.stream_id)) || !integer(policy.revision, 1))) return null
  return value as StreamGeoPolicy | StreamRuntimeGeoPolicy
}

function sameDNS(left: StreamDNSPolicy, right: StreamDNSPolicy): boolean {
  return left.positive_min_ttl_seconds === right.positive_min_ttl_seconds &&
    left.positive_max_ttl_seconds === right.positive_max_ttl_seconds &&
    left.negative_ttl_seconds === right.negative_ttl_seconds &&
    left.stale_if_error_seconds === right.stale_if_error_seconds &&
    left.allow_private_addresses === right.allow_private_addresses
}

function sameGeo(left: StreamGeoPolicy, right: StreamGeoPolicy): boolean {
  return left.enabled === right.enabled && left.unknown_region_action === right.unknown_region_action &&
    JSON.stringify(left.trusted_proxy_cidrs) === JSON.stringify(right.trusted_proxy_cidrs) &&
    JSON.stringify(left.blocked_regions) === JSON.stringify(right.blocked_regions) &&
    JSON.stringify(left.region_cidrs) === JSON.stringify(right.region_cidrs)
}

const guardRuleKeys = new Set(['id', 'action', 'first_packet', 'server_names', 'client_ip', 'geo', 'ban_seconds', 'threshold', 'window_seconds'])

// validStreamGuardRules checks the shape the server guarantees (migration 335
// and edgeconfig.NormalizeL4GuardRules); the conditions are the server's.
export function validStreamGuardRules(value: unknown): value is StreamGuardRule[] {
  if (!Array.isArray(value) || value.length > streamGuardRulesMax) return false
  const ids = new Set<string>()
  return value.every((entry) => {
    const rule = record(entry)
    if (!rule || Object.keys(rule).some((key) => !guardRuleKeys.has(key)) || typeof rule.id !== 'string' ||
      !uuidPattern.test(rule.id) || ids.has(rule.id) || !['drop', 'ban', 'allow'].includes(String(rule.action)) ||
      !['first_packet', 'server_names', 'client_ip', 'geo'].some((key) => rule[key] !== undefined)) return false
    ids.add(rule.id)
    const first = record(rule.first_packet)
    const client = record(rule.client_ip)
    if ((rule.first_packet !== undefined && (!first || !['prefix_hex', 'contains', 'regex'].includes(String(first.match)) ||
      typeof first.value !== 'string' || first.value === '')) ||
      (rule.server_names !== undefined && (!stringArray(rule.server_names) || !rule.server_names.every(validStreamServerName))) ||
      (rule.client_ip !== undefined && (!client || !stringArray(client.cidrs) || client.cidrs.length === 0 ||
        !(client.negate === undefined || typeof client.negate === 'boolean'))) ||
      (rule.geo !== undefined && (!Array.isArray(rule.geo) || rule.geo.length === 0 || !rule.geo.every((item) => {
        const condition = record(item)
        return condition && ['tag', 'asn', 'country', 'province', 'city'].includes(String(condition.field)) &&
          stringArray(condition.values) && condition.values.length > 0
      })))) return false
    if (rule.action !== 'ban') return rule.ban_seconds === undefined && rule.threshold === undefined && rule.window_seconds === undefined
    return integer(rule.ban_seconds, 1, 86400) && integer(rule.threshold, 1, 10000) &&
      (rule.threshold === 1 ? rule.window_seconds === undefined : integer(rule.window_seconds, 1, 3600))
  })
}

// 端口范围：结束端口大于起始端口，最多 1000 个端口（服务端另查节点保留端口与冲突）。
function validPortEnd(port: unknown, end: unknown): boolean {
  return integer(port, 1, 65535) && integer(end, 2, 65535) && (end as number) > (port as number) &&
    (end as number) - (port as number) < 1000
}

function validAdditionalListeners(value: unknown, streamID: string, protocol: unknown, port: unknown): boolean {
  if (value === undefined) return true
  if (!Array.isArray(value) || value.length > 63) return false
  const ids = new Set([streamID.toLowerCase()])
  const sockets = new Set([`${protocol}:${port}`])
  return value.every((entry) => {
    const item = record(entry)
    if (!item || typeof item.id !== 'string' || !uuidPattern.test(item.id) || ids.has(item.id.toLowerCase()) ||
      (item.protocol !== 'tcp' && item.protocol !== 'udp') || item.address !== '*' || !integer(item.port, 1, 65535) ||
      (item.port_end !== undefined && !validPortEnd(item.port, item.port_end))) return false
    const socket = `${item.protocol}:${item.port}`
    if (sockets.has(socket)) return false
    ids.add(item.id.toLowerCase())
    sockets.add(socket)
    return true
  })
}

function listenerSignature(value: StreamAdditionalListener[] | undefined): string {
  return JSON.stringify((value ?? []).map(({ id, protocol, address, port, port_end }) => [id, protocol, address, port, port_end ?? 0]).sort())
}

function parseRuntimeSpecV2(
  value: Record<string, unknown>,
  streamID: string,
  scopeID: string,
  resourceRevision: number,
  fields: StreamResponseFields,
): StreamRuntimeSpecV2 | null {
  const listener = record(value.listener)
  const endpoint = record(value.endpoint)
  const dns = parseDNSPolicy(value.dns)
  const geo = parseGeoPolicy(value.geo, true) as StreamRuntimeGeoPolicy | null
  if (value.schema_version !== 'cdnca.edge.l4/v2' ||
    value.tenant_id !== scopeID || value.site_id !== undefined ||
    value.stream_id !== streamID || value.revision !== resourceRevision || !listener ||
    listener.protocol !== fields.protocol || listener.address !== fields.listen_address || listener.port !== fields.listen_port ||
    !validAdditionalListeners(value.additional_listeners, streamID, fields.protocol, fields.listen_port) ||
    listenerSignature(value.additional_listeners as StreamAdditionalListener[] | undefined) !== listenerSignature(fields.additional_listeners) ||
    !endpoint || endpoint.address !== (fields.upstream_address || undefined) || endpoint.host !== (fields.upstream_host || undefined) ||
    endpoint.port !== fields.upstream_port || !dns || !sameDNS(dns, fields.dns_policy) || !geo ||
    geo.tenant_id !== scopeID || geo.stream_id !== streamID ||
    geo.revision !== resourceRevision || !sameGeo(geo, fields.geo_policy) ||
    value.connect_timeout_ms !== fields.connect_timeout_ms || value.response_timeout_ms !== fields.response_timeout_ms ||
    value.max_connections_per_client !== fields.max_connections_per_client || !integer(value.drain_timeout_ms, 1) ||
    value.proxy_protocol_inbound !== fields.proxy_protocol_inbound || value.proxy_protocol_outbound !== fields.proxy_protocol_v1) return null
  if (fields.tls_passthrough
    ? value.tls_passthrough !== true || !stringArray(value.server_names) ||
      serverNameSignature(value.server_names) !== serverNameSignature(fields.server_names)
    : value.tls_passthrough !== undefined || value.server_names !== undefined) return null
  const rate = record(value.new_conn_rate)
  if (fields.max_new_connections_per_client_per_second > 0
    ? !rate || Object.keys(rate).length !== 3 || rate.rate_per_second !== fields.max_new_connections_per_client_per_second ||
      rate.burst !== fields.new_connection_burst || rate.ban_seconds !== fields.new_connection_ban_seconds
    : value.new_conn_rate !== undefined) return null
  if (fields.toa ? value.toa !== true : value.toa !== undefined) return null
  if (fields.session_log_enabled ? value.session_log !== true : value.session_log !== undefined) return null
  if ((fields.listen_port_end ? listener.port_end !== fields.listen_port_end : listener.port_end !== undefined) ||
    (fields.upstream_follow_port ? endpoint.follow_port !== true : endpoint.follow_port !== undefined)) return null
  // 有规则时意图里的规则以资源的规则结尾（ACL 转成的规则在前）；ACL 与规则都没有时意图里不出现。
  const own = JSON.stringify(fields.guard_rules ?? []).slice(1, -1)
  const published = Array.isArray(value.guard_rules) ? JSON.stringify(value.guard_rules).slice(1, -1) : ''
  const aclRules = (fields.acl?.rules.length ?? 0) > 0 || fields.acl?.default_action === 'deny'
  if (value.guard_rules !== undefined
    ? !validStreamGuardRules(value.guard_rules) || !published.endsWith(own) || (!aclRules && published !== own)
    : (fields.guard_rules?.length ?? 0) > 0) return null
  if ((fields.listen_ipv6 ? value.listen_ipv6 !== true : value.listen_ipv6 !== undefined) ||
    (fields.balance_way === 'ip_hash' ? endpoint.balance !== 'ip_hash' : endpoint.balance !== undefined) ||
    ((fields.origins?.length ?? 0) > 1
      ? !Array.isArray(endpoint.origins) || endpoint.origins.length !== fields.origins!.length
      : endpoint.origins !== undefined)) return null
  return value as unknown as StreamRuntimeSpecV2
}

function parsePublishIntent(
  value: unknown,
  streamID: string,
  scopeID: string,
  streamRevision: number,
  fields: StreamResponseFields,
): StreamPublishIntent | null {
  const intent = record(value)
  const runtime = record(intent?.runtime_spec)
  if (!intent || !runtime || !uuidPattern.test(String(intent.id)) || !integer(intent.version, 1) ||
    (intent.operation !== 'create' && intent.operation !== 'update' && intent.operation !== 'delete') ||
    (intent.desired_state !== 'enabled' && intent.desired_state !== 'disabled' && intent.desired_state !== 'deleted') ||
    !integer(intent.resource_revision, 1) || intent.resource_revision !== streamRevision ||
    !integer(intent.configuration_source_revision, 1) ||
    !['unknown', 'pending', 'leased', 'retrying', 'reconciling', 'succeeded', 'failed', 'superseded'].includes(String(intent.state)) ||
    ![intent.automatic_request_id, intent.publication_id, intent.rollout_id]
      .every((id) => id === null || (typeof id === 'string' && uuidPattern.test(id))) || typeof intent.created_at !== 'string') return null
  const parsedRuntime = parseRuntimeSpecV2(runtime, streamID, scopeID, intent.resource_revision as number, fields)
  return parsedRuntime ? value as StreamPublishIntent : null
}

function validOrigins(value: unknown): value is StreamOrigin[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= 64 && value.every((entry) => {
    const origin = record(entry)
    return origin && typeof origin.address === 'string' && origin.address !== '' && integer(origin.weight, 1, 100) &&
      typeof origin.down === 'boolean'
  })
}

function validACL(value: unknown): value is StreamACL {
  const acl = record(value)
  return Boolean(acl) && (acl!.default_action === 'allow' || acl!.default_action === 'deny') && Array.isArray(acl!.rules) &&
    acl!.rules.every((entry) => {
      const rule = record(entry)
      return rule && typeof rule.cidr === 'string' && (rule.action === 'allow' || rule.action === 'deny')
    })
}

function validLine(value: unknown): value is StreamLine {
  const line = record(value)
  const id = (entry: unknown) => entry === null || (typeof entry === 'string' && uuidPattern.test(entry))
  return Boolean(line) && id(line!.region_id) && id(line!.node_group_id) && id(line!.backup_node_group_id) &&
    typeof line!.region_name === 'string' && typeof line!.node_group_name === 'string' && typeof line!.backup_node_group_name === 'string'
}

function validOverrides(value: unknown): value is StreamOverrides {
  const overrides = record(value)
  const id = (entry: unknown) => entry === null || (typeof entry === 'string' && uuidPattern.test(entry))
  return Boolean(overrides) && (overrides!.cname_domain === null || typeof overrides!.cname_domain === 'string') &&
    [null, 'site', 'package'].includes(overrides!.cname_mode as string | null) &&
    id(overrides!.region_id) && id(overrides!.node_group_id) && id(overrides!.backup_node_group_id)
}

function parseGroupReferences(value: unknown): value is StreamGroupReference[] {
  return Array.isArray(value) && value.every((entry) => {
    const group = record(entry)
    return group !== null && uuidPattern.test(String(group.id)) &&
      typeof group.name === 'string' && typeof group.remark === 'string'
  })
}

function parseStream(value: unknown): Stream {
  const item = record(value)
  const dns = parseDNSPolicy(item?.dns_policy)
  const geo = parseGeoPolicy(item?.geo_policy) as StreamGeoPolicy | null
  if (!item || !uuidPattern.test(String(item.id)) || typeof item.display_id !== 'string' ||
    !/^[1-9][0-9]{0,18}$/u.test(item.display_id) || !uuidPattern.test(String(item.scope_id)) ||
    (item.package_subscription_id !== undefined && item.package_subscription_id !== null &&
      !uuidPattern.test(String(item.package_subscription_id))) ||
    (item.package_name !== undefined && item.package_name !== null && typeof item.package_name !== 'string') ||
    (item.package_expires_at !== undefined && item.package_expires_at !== null &&
      (typeof item.package_expires_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u.test(item.package_expires_at) ||
        !Number.isFinite(Date.parse(item.package_expires_at)))) ||
    ![item.cname, item.cname_domain, item.cname_hostname, item.cname_state, item.cname_failure_code].every((entry) =>
      entry === undefined || entry === null || typeof entry === 'string') ||
    (item.eligibility_state !== 'eligible' && item.eligibility_state !== 'ineligible') ||
    typeof item.name !== 'string' || typeof item.remark !== 'string' ||
    (item.protocol !== 'tcp' && item.protocol !== 'udp') || item.listen_address !== '*' || !integer(item.listen_port, 1, 65535) ||
    !validAdditionalListeners(item.additional_listeners, item.id as string, item.protocol, item.listen_port) ||
    typeof item.upstream_address !== 'string' || typeof item.upstream_host !== 'string' ||
    (item.upstream_address === '') === (item.upstream_host === '') || !integer(item.upstream_port, 1, 65535) || !dns || !geo ||
    !integer(item.connect_timeout_ms, 50, 30000) || !integer(item.response_timeout_ms, 100, 600000) ||
    !integer(item.max_connections_per_client, 1, 10000) || typeof item.proxy_protocol_inbound !== 'boolean' ||
    typeof item.proxy_protocol_v1 !== 'boolean' ||
    (item.balance_way !== 'rr' && item.balance_way !== 'ip_hash') || !parseGroupReferences(item.groups) ||
    typeof item.tls_passthrough !== 'boolean' || !stringArray(item.server_names) ||
    !validStreamNewConnectionRate(item.max_new_connections_per_client_per_second, item.new_connection_burst, item.new_connection_ban_seconds) ||
    typeof item.toa !== 'boolean' ||
    typeof item.session_log_enabled !== 'boolean' ||
    !(item.listen_port_end === undefined || item.listen_port_end === 0 || validPortEnd(item.listen_port, item.listen_port_end)) ||
    !(item.upstream_follow_port === undefined || typeof item.upstream_follow_port === 'boolean') ||
    !(item.guard_rules === undefined || validStreamGuardRules(item.guard_rules)) ||
    !validOrigins(item.origins) || typeof item.listen_ipv6 !== 'boolean' || !validACL(item.acl) ||
    !['normal', 'locked', 'traffic_exceeded', 'package_expired'].includes(String(item.admin_status)) ||
    !validLine(item.line) || !validOverrides(item.overrides) || !['done', 'pending', 'failed'].includes(String(item.sync_state)) ||
    typeof item.enabled !== 'boolean' || !integer(item.revision, 1) ||
    typeof item.created_at !== 'string' || typeof item.updated_at !== 'string') throw invalidResponse()
  const fields = item as unknown as StreamResponseFields
  const hasDomain = fields.upstream_host !== ''
  const validDNS = hasDomain
    ? dns.positive_min_ttl_seconds >= 1 && dns.positive_max_ttl_seconds >= dns.positive_min_ttl_seconds &&
      dns.negative_ttl_seconds >= 1 && dns.stale_if_error_seconds >= dns.positive_max_ttl_seconds && !dns.allow_private_addresses
    : Object.values(dns).every((entry) => entry === 0 || entry === false)
  const validGeo = geo.enabled
    ? fields.proxy_protocol_inbound === (geo.trusted_proxy_cidrs.length > 0)
    : geo.unknown_region_action === 'allow' && geo.trusted_proxy_cidrs.length === 0 &&
      geo.blocked_regions.length === 0 && geo.region_cidrs.length === 0 && !fields.proxy_protocol_inbound
  const hasUDP = fields.protocol === 'udp' || fields.additional_listeners?.some((listener) => listener.protocol === 'udp')
  if (!validDNS || !validGeo || (hasUDP && (fields.proxy_protocol_inbound || fields.proxy_protocol_v1 || fields.tls_passthrough || fields.toa)) ||
    (fields.toa && (fields.proxy_protocol_inbound || fields.proxy_protocol_v1)) ||
    !validStreamServerNames(fields.tls_passthrough, fields.server_names) ||
    !parsePublishIntent(item.publish_intent, item.id as string, item.scope_id as string, item.revision as number, fields)) {
    throw invalidResponse()
  }
  return value as Stream
}

function parseListResponse(value: unknown): StreamListResponse {
  const response = record(value)
  if (!response || !Array.isArray(response.items) ||
    !Number.isInteger(response.total) || !Number.isInteger(response.page) || !Number.isInteger(response.limit)) {
    throw invalidResponse()
  }
  return { ...response, items: response.items.map(parseStream) } as unknown as StreamListResponse
}

// stream_port_conflict 附带的冲突位置（协议、端口段、对象类型与名称），见 control-l4-forward.openapi.yaml ErrorEnvelope.details。
export interface StreamPortConflict {
  protocol: StreamProtocol
  port: number
  port_end?: number
  with: 'reserved' | 'self' | 'stream' | 'site'
  name?: string
}

const portConflicts = new WeakMap<ApiError, StreamPortConflict>()

export function streamPortConflict(error: ApiError): StreamPortConflict | undefined {
  return portConflicts.get(error)
}

function portConflictDetails(body: unknown): StreamPortConflict | null {
  const details = record(record(record(body)?.error)?.details)
  if (!details || (details.protocol !== 'tcp' && details.protocol !== 'udp') || !integer(details.port, 1, 65535) ||
    (details.port_end !== undefined && !integer(details.port_end, 2, 65535)) ||
    !['reserved', 'self', 'stream', 'site'].includes(String(details.with)) ||
    (details.name !== undefined && typeof details.name !== 'string')) return null
  return details as unknown as StreamPortConflict
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
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
    const details = response.status === 409 ? await response.clone().json().then(portConflictDetails, () => null) : null
    const error = await responseApiError(response)
    if (details && error.code === 'stream_port_conflict') portConflicts.set(error, details)
    throw error
  }
  if (response.status === 204) return undefined
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

async function list(accessToken: string, params: StreamListParams): Promise<StreamListResponse> {
  const query = new URLSearchParams({ page: String(params.page), limit: String(params.limit) })
  if (params.search) query.set('search', params.search)
  if (params.protocol) query.set('protocol', params.protocol)
  if (params.enabled !== undefined) query.set('enabled', String(params.enabled))
  if (params.listen_port !== undefined) query.set('listen_port', String(params.listen_port))
  if (params.upstream) query.set('upstream', params.upstream)
  if (params.display_id) query.set('display_id', params.display_id)
  if (params.owner_display_id) query.set('owner_display_id', params.owner_display_id)
  if (params.publication_state) query.set('publication_state', params.publication_state)
	if (params.group_id) query.set('group_id', params.group_id)
	if (params.cname_domain) query.set('cname_domain', params.cname_domain)
	if (params.cname_hostname) query.set('cname_hostname', params.cname_hostname)
	if (params.region_id) query.set('region_id', params.region_id)
	if (params.node_group_id) query.set('node_group_id', params.node_group_id)
	if (params.sync_state) query.set('sync_state', params.sync_state)
	if (params.admin_status) query.set('admin_status', params.admin_status)
  return parseListResponse(await request(accessToken, `/v1/streams?${query}`))
}

async function create(accessToken: string, input: CreateStreamRequest, key: string): Promise<Stream> {
  return parseStream(await request(accessToken, '/v1/streams', {
    method: 'POST',
    headers: { 'Idempotency-Key': key },
    body: JSON.stringify(input),
  }))
}

async function update(accessToken: string, id: string, input: UpdateStreamRequest, key: string): Promise<Stream> {
  return parseStream(await request(accessToken, `/v1/streams/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Idempotency-Key': key, 'If-Match': `"${input.expected_revision}"` },
    body: JSON.stringify(input),
  }))
}

async function remove(accessToken: string, item: Stream, key: string): Promise<void> {
  await request(accessToken, `/v1/streams/${encodeURIComponent(item.id)}`, {
    method: 'DELETE',
    headers: { 'Idempotency-Key': key, 'If-Match': `"${item.revision}"` },
  })
}

async function get(accessToken: string, id: string): Promise<Stream> {
  const item = parseStream(await request(accessToken, `/v1/streams/${encodeURIComponent(id)}`))
  if (item.id !== id) throw invalidResponse()
  return item
}

// 批量添加：未开忽略错误时有失败行返回 422（整批未写入），同样带逐行结果。
async function batchCreate(accessToken: string, input: BatchCreateStreamsRequest, key: string): Promise<BatchCreateStreamsResult> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/streams/batch`, {
      method: 'POST', credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'Idempotency-Key': key },
      body: JSON.stringify(input),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok && response.status !== 422) throw await responseApiError(response)
  const body = record(await response.json().catch(() => null))
  if (!body || !Array.isArray(body.items) || !integer(body.created, 0) || !integer(body.failed, 0) || typeof body.committed !== 'boolean' ||
    !body.items.every((entry) => {
      const line = record(entry)
      return line && integer(line.line, 1) && typeof line.text === 'string' && ['created', 'failed', 'skipped'].includes(String(line.status))
    })) throw invalidResponse()
  return body as unknown as BatchCreateStreamsResult
}

// 更多操作（平台）：设置状态、修改CNAME域名/CNAME生成模式/线路分组，逐条带 expected_revision，冲突行返回该行结果。
async function batchAction(accessToken: string, input: BatchStreamActionInput, key: string): Promise<BatchStreamActionResult> {
  const body = record(await request(accessToken, '/v1/streams/batch-action', {
    method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(input),
  }))
  if (!body || !Array.isArray(body.items) || !body.items.every((entry) => {
    const item = record(entry)
    return item && uuidPattern.test(String(item.id)) && (item.status === 'updated' || item.status === 'failed')
  })) throw invalidResponse()
  return body as unknown as BatchStreamActionResult
}

export const streamsApi = { create, get, list, remove, update, batchCreate, batchAction }
