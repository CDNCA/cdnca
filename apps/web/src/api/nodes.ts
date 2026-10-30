import { ApiError, networkApiError, responseApiError } from './auth'

export type NodeAdminState = 'pending' | 'active' | 'draining' | 'disabled' | 'retired'
export type ManagedNodeAdminState = Exclude<NodeAdminState, 'pending'>
export type EnrollmentPurpose = 'initial_enrollment' | 're_enrollment'
export type NodePresenceStatus = 'online' | 'offline' | 'unknown'
export type NodeProjectionFreshness = 'fresh' | 'stale' | 'never'
export type NodeLeaseSignal = 'present' | 'absent' | 'unavailable'
export type NodeType = 'L1' | 'L2'
export type NodeBandwidthUnit = 'Mbps' | 'Gbps'
export type NodeTrafficType = 'outbound' | 'inbound'

export interface NodeIPLocation {
  country: string
  province: string
  city: string
  isp: string
  country_code: string
}

export const nodeIPLocationFields = ['country', 'province', 'city', 'isp', 'country_code'] as const
export type NodeIPLocationField = typeof nodeIPLocationFields[number]

/** 编辑节点 → IP 归属: effective values, manual fields, the automatic resolution. */
export interface NodeIPLocationView {
  node_id: string
  effective: NodeIPLocation
  manual_fields: NodeIPLocationField[]
  resolution: {
    node_id: string
    outcome: 'resolved' | 'unresolved' | 'no_library'
    address?: string
    automatic: NodeIPLocation
    library_revision: number
    library_version: string
    resolved_at: string
  } | null
}

export interface NodeManagementSettings {
  schema_version: 1
  sort: number
  node_type: NodeType
  cache_directory: string
  cache_limit_gb: number
  log_directory: string
  ip_location: NodeIPLocation
  // Fields an administrator corrected; the others follow the IP library.
  ip_location_manual?: NodeIPLocationField[]
  auto_disable: {
    bandwidth_limit: number
    bandwidth_unit: NodeBandwidthUnit
    traffic_enabled: boolean
    traffic_from_day: number
    traffic_from_time: string
    traffic_total_gb: number
    traffic_types: NodeTrafficType[]
    excluded_interfaces: string
    disabled_periods: string
  }
  secondary_ips: string[]
  // Votes as a peer in external probing (probe only; never joins the node market).
  external_probe: boolean
  /** HTTP 302 scheduling direct hostname (sites redirecting to node hostnames). */
  schedule302_hostname?: string
}

export interface NodeRecord {
  id: string
  display_id: string
  name: string
  description: string
  region: string
  ipv4?: string
  ipv6?: string
  admin_state: NodeAdminState
  management_settings: NodeManagementSettings
  revision: number
  created_at: string
  updated_at: string
}

export interface NodePresence {
  status: NodePresenceStatus
  last_heartbeat_at?: string
  agent_version?: string
  session_epoch?: number
  heartbeat_sequence?: number
  projection_freshness: NodeProjectionFreshness
  lease_signal: NodeLeaseSignal
  projected_at?: string
  // Market probe role of the latest heartbeat; omitted when not reported.
  market_probe_role?: NodeMarketProbeRole
  // OpenResty runtime version of the confirmed session; a native node
  // reports the runtime it switched to with its Agent release.
  openresty_version?: string
  // Native runtime switch outcome of the latest heartbeat (native nodes):
  // the runtime manifest sha256 it targeted, the one active before and the
  // RUNTIME_* code of a rollback.
  native_runtime_state?: NodeNativeRuntimeState
  native_runtime_release?: string
  native_runtime_previous_release?: string
  native_runtime_error_code?: string
}

export type NodeMarketProbeRole = 'probe_only' | 'join_market' | 'disabled'
export type NodeNativeRuntimeState = 'switched' | 'unchanged' | 'rolled_back'

const nativeRuntimeStates = new Set<NodeNativeRuntimeState>(['switched', 'unchanged', 'rolled_back'])
const nativeRuntimeReleasePattern = /^[0-9a-f]{64}$/
const nativeRuntimeCodePattern = /^[A-Z][A-Z0-9_]{0,63}$/

// nativeRuntimeSummary: "<release 12> (<previous label> <previous 12>) <code>"
// after the translated state; the console shows it per node.
export function nativeRuntimeSummary(presence: NodePresence, stateText: string, previousLabel: string): string {
  const parts = [stateText]
  if (presence.native_runtime_release) parts.push(presence.native_runtime_release.slice(0, 12))
  if (presence.native_runtime_previous_release) {
    parts.push(`(${previousLabel} ${presence.native_runtime_previous_release.slice(0, 12)})`)
  }
  if (presence.native_runtime_error_code) parts.push(presence.native_runtime_error_code)
  return parts.join(' ')
}

function nativeRuntime(presence: Record<string, unknown>): boolean {
  const state = presence.native_runtime_state
  const release = presence.native_runtime_release
  const previous = presence.native_runtime_previous_release
  const code = presence.native_runtime_error_code
  if (state === undefined) return release === undefined && previous === undefined && code === undefined
  return nativeRuntimeStates.has(state as NodeNativeRuntimeState) &&
    (release === undefined || (typeof release === 'string' && nativeRuntimeReleasePattern.test(release))) &&
    (previous === undefined || (typeof previous === 'string' && nativeRuntimeReleasePattern.test(previous))) &&
    (code === undefined || (state === 'rolled_back' && typeof code === 'string' && nativeRuntimeCodePattern.test(code)))
}

export interface NodeInventoryItem extends NodeRecord {
  presence: NodePresence
  network_inventory?: NodeNetworkInventory
}

export type NodeNetworkInventoryState = 'not_reported' | 'verified' | 'address_conflict' | 'peer_mismatch' |
  'no_default_route' | 'no_global_address' | 'ambiguous_route' | 'unavailable'

export interface NodeNetworkInventory {
  schema_version: 1
  ipv4_state: NodeNetworkInventoryState
  ipv6_state: NodeNetworkInventoryState
  received_at?: string
}

export interface NodeListParams {
  order?: 'management_sort_desc'
  status?: NodeAdminState
  presence?: NodePresenceStatus
  search?: string
  cursor?: string
  limit: number
}

export interface NodeListResponse {
  order?: 'management_sort_desc'
  items: NodeInventoryItem[]
  next_cursor?: string
}

export interface RegionRecord {
  id: string
  name: string
  /** Stable lower-case ASCII code: what nodes and origin routes' node_regions match on. */
  code: string
  /** ISO 3166-1 alpha-2, '' = not set. */
  country_code: string
  /** GB/T 2260 province-level code (CN only), '' = whole country / not set. */
  province_code: string
  description: string
  l2_check_port: number
  sort: number
  revision: number
  created_at: string
  updated_at: string
}

export interface RegionListParams {
  page: number
  page_size: number
  search?: string
}

export interface RegionListResponse {
  count: number
  data: RegionRecord[]
}

export interface RegionInput {
  name: string
  country_code: string
  province_code: string
  description: string
  l2_check_port: number
  sort: number
}

export interface NodeRecoveryEvidence {
  config_revision: number
  publication_sequence: number
  recovered_at: string
  reason_code: 'probe_recovered'
  puback_stream: 'NODE_MONITORING_STATUS'
  puback_sequence: number
}

export interface NodeMetricsLatest {
  record_kind?: 'metric' | 'host_metric'
  node_id: string
  node_name: string
  config_revision: number
  active_config_revision: number
  publication_sequence: number
  observed_at: string
  probe_port: number
  healthy: boolean
  probe_succeeded: boolean
  consecutive_failures: number
  consecutive_successes: number
  probes_total: number
  probe_failures_total: number
  recovered: boolean
  recovery_notified: boolean
  rolled_back: boolean
  known: boolean
  cpu_percent: number | null
  memory_used_bytes: number | null
  memory_total_bytes: number | null
  active_connections: number | null
  rx_bandwidth_bps: number | null
  tx_bandwidth_bps: number | null
  telemetry?: NodeTelemetry
  total_rx_bytes: number | null
  total_tx_bytes: number | null
  puback_stream: 'NODE_MONITORING_STATUS'
  puback_sequence: number
  consumer_durable: 'control_api_node_metrics'
  consumer_sequence: number
  ingested_at: string
  latest_recovery?: NodeRecoveryEvidence
  monthly_traffic?: NodeMonthlyTraffic
  /** The node's latest session declares NODE_TELEMETRY_DETAIL v1 (mounts, port group override receipts). */
  telemetry_detail?: boolean
  /** The node's latest session declares NODE_STORAGE v1: its cache directory, cache limit and log directory are editable. */
  storage_supported?: boolean
}

export interface NodeMonthlyTraffic {
  state: 'available' | 'insufficient_data' | 'stale' | 'incomplete' | 'counter_reset'
  period_key: string
  period_start: string
  period_end: string
  timezone: string
  usage_bytes: number
  source_finalized_through: string | null
  samples: number
  // Counter restarts in the period (node reboot); usage_bytes includes the
  // traffic after each one. Absent from older control APIs.
  counter_resets?: number
}

export interface NodeMetricsLatestBatch {
  observed_at: string
  items: NodeMetricsLatest[]
  not_reported_node_ids: string[]
}

export interface NodeNetworkInterface {
  name: string
  rx_bytes: number
  tx_bytes: number
  rx_bandwidth_bps: number
  tx_bandwidth_bps: number
}

export interface NodeSystemLoad {
  one_minute: number
  five_minutes: number
  fifteen_minutes: number
  running_processes: number
  total_processes: number
}

export interface NodeDiskUsage {
  path: string
  total_bytes: number
  used_bytes: number
  total_inodes: number
  used_inodes: number
  space_percent: number
  inode_percent: number
}

export type NodeDDoSDropKind = 'ct_invalid' | 'tcp_all' | 'tcp_fin' | 'tcp_null' | 'tcp_syn_fin' | 'tcp_syn_rst' | 'tcp_xmas'

/** One node DDoS packet filter's cumulative drops since it was turned on. */
export interface NodeDDoSDrop {
  kind: NodeDDoSDropKind
  packets: number
  bytes: number
}

export const nodeDDoSDropKinds: readonly NodeDDoSDropKind[] = ['ct_invalid', 'tcp_all', 'tcp_fin', 'tcp_null', 'tcp_syn_fin', 'tcp_syn_rst', 'tcp_xmas']

export type NodeXDPMode = 'native' | 'generic' | 'nftables' | 'disabled'
export type NodeXDPReason = 'attach_failed' | 'bpf_unavailable' | 'disabled' | 'kernel_too_old' | 'load_failed' |
  'no_interface' | 'self_test_failed' | 'unsupported_os' | 'update_failed' | 'verify_failed'
export type NodeXDPDropKind = 'tcp_all' | 'tcp_null' | 'tcp_syn_fin' | 'tcp_syn_rst' | 'tcp_xmas' | 'xdp_ban' | 'xdp_block' | 'xdp_port_ban' | 'xdp_rate'

/** The node XDP kernel filter: attached (native/generic) or not, and why. */
export interface NodeXDPStatus {
  mode: NodeXDPMode
  reason?: NodeXDPReason
  detail?: string
  /** "<nic>=<native|generic>", sorted. */
  interfaces?: string[]
  drops?: { kind: NodeXDPDropKind; packets: number; bytes: number }[]
}

export const nodeXDPReasons: readonly NodeXDPReason[] = ['attach_failed', 'bpf_unavailable', 'disabled', 'kernel_too_old', 'load_failed',
  'no_interface', 'self_test_failed', 'unsupported_os', 'update_failed', 'verify_failed']
export const nodeXDPDropKinds: readonly NodeXDPDropKind[] = ['tcp_all', 'tcp_null', 'tcp_syn_fin', 'tcp_syn_rst', 'tcp_xmas', 'xdp_ban', 'xdp_block', 'xdp_port_ban', 'xdp_rate']

export type NodeDDoSProtectionState = 'applied' | 'off' | 'pending' | 'failed' | 'unavailable'
export type NodeDDoSProtectionReason = 'nft_missing' | 'nft_unusable' | 'init_failed' | 'unsupported_os'

/** The node DDoS protection table (nftables): failed / unavailable is a protection fault. */
export interface NodeDDoSProtection {
  state: NodeDDoSProtectionState
  reason?: NodeDDoSProtectionReason
  detail?: string
}

export const nodeDDoSProtectionStates: readonly NodeDDoSProtectionState[] = ['applied', 'failed', 'off', 'pending', 'unavailable']
export const nodeDDoSProtectionReasons: readonly NodeDDoSProtectionReason[] = ['init_failed', 'nft_missing', 'nft_unusable', 'unsupported_os']

export interface NodeTelemetry {
  schema_version: number
  network_selection?: { source: 'default_route' | 'unavailable'; interfaces: string[] }
  network_interfaces: NodeNetworkInterface[]
  system_load?: NodeSystemLoad
  disks: NodeDiskUsage[]
  total_rx_bytes: number
  total_tx_bytes: number
  ddos_drops?: NodeDDoSDrop[]
  xdp?: NodeXDPStatus
  /** Level D site drops since the node's previous sample, shared by site_ids. */
  site_drop?: { site_ids: string[]; packets: number; bytes: number }
  ddos_protection?: NodeDDoSProtection
  /** Every mount (NODE_TELEMETRY_DETAIL v1); missing on old Agents. */
  mounts?: NodeMount[]
  /** Layer 4 port group override receipts (NODE_TELEMETRY_DETAIL v1); missing on old Agents. */
  port_group_overrides?: NodePortGroupOverride[]
  /** The node storage in effect (NODE_STORAGE v1); missing on old Agents. */
  storage?: NodeStorageStatus
}

export type NodeStorageState = 'applied' | 'default' | 'failed' | 'restart_pending'

/** What the node runs: cache directory and limit (reload) and the log directory of the running Agent. */
export interface NodeStorageStatus {
  cache_directory: string
  cache_max_bytes: number
  log_directory: string
  state: NodeStorageState
  reason?: string
  requested_log_directory?: string
}

/** The roots a node storage directory must lie strictly below (siteobject.NodeStoragePrefixes). */
export const nodeStoragePrefixes = ['/data', '/var/cache', '/var/lib', '/var/log', '/opt', '/srv', '/mnt'] as const
/** cache_limit_gb bound when it is set (siteobject.NodeStorageMaxCacheBytes, 1 PiB). */
export const nodeStorageMaxCacheGB = 1_048_576
/**
 * What an installed node runs with nothing set, before it reports: the shared
 * root is <parent of deployment_root>/dynroute/shared (edge-agent
 * dynamicRoutingRoots; install-node.sh fixes deployment_root to
 * /var/lib/cdnca-edge), the cache under its cache/ (dynroute cacheRoot) and
 * the logs in the shared root itself (dynroute logRootFor). The default cache
 * limit is not a constant (edge-agent defaultCacheBytes).
 */
export const nodeStorageInstallDefaults = {
  cacheDirectory: '/var/lib/dynroute/shared/cache',
  logDirectory: '/var/lib/dynroute/shared',
} as const

/** siteobject.ValidNodeStorageDirectory: absolute, clean, [A-Za-z0-9._/-], ≤256 bytes, strictly below an allowed root. */
export function validNodeStorageDirectory(value: string): boolean {
  if (value.length < 2 || value.length > 256 || !/^\/[A-Za-z0-9._/-]+$/.test(value) || value.endsWith('/') || value.includes('//')) return false
  if (value.slice(1).split('/').some((segment) => segment === '.' || segment === '..')) return false
  return nodeStoragePrefixes.some((prefix) => value.startsWith(`${prefix}/`))
}

export function nodeStorageDirectoriesOverlap(left: string, right: string): boolean {
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`)
}

function nodeStorageStatus(value: unknown): value is NodeStorageStatus {
  return record(value) && exactKeys(value, ['cache_directory', 'cache_max_bytes', 'log_directory', 'state'], ['reason', 'requested_log_directory']) &&
    boundedString(value.cache_directory, 1, 4096) && boundedString(value.log_directory, 1, 4096) && nonNegativeInteger(value.cache_max_bytes) &&
    ['applied', 'default', 'failed', 'restart_pending'].includes(String(value.state)) &&
    (value.reason === undefined || boundedString(value.reason, 1, 512)) &&
    (value.requested_log_directory === undefined || boundedString(value.requested_log_directory, 1, 256))
}

export type NodeMountFilterReason = 'bind_duplicate' | 'read_only' | 'squashfs' | 'stat_failed' | 'system_path'
export const nodeMountFilterReasons: readonly NodeMountFilterReason[] = ['bind_duplicate', 'read_only', 'squashfs', 'stat_failed', 'system_path']

/** One mount of the node; filter_reason says why the disk ranking leaves it out (absent: it is a disk row). */
export interface NodeMount {
  path: string
  device: string
  fstype: string
  read_only: boolean
  bind: boolean
  filter_reason?: NodeMountFilterReason
}

export type NodePortGroupOverrideState = 'applied' | 'failed' | 'inactive' | 'standby'
export type NodePortGroupOverrideReason = 'auto_mitigation_off' | 'manual' | 'shared_ports' | 'suggest'
export const nodePortGroupOverrideStates: readonly NodePortGroupOverrideState[] = ['applied', 'failed', 'inactive', 'standby']
export const nodePortGroupOverrideReasons: readonly NodePortGroupOverrideReason[] = ['auto_mitigation_off', 'manual', 'shared_ports', 'suggest']

/** Whether one layer 4 auto defense port group override is in effect on the node. */
export interface NodePortGroupOverride {
  port_group_id: string
  state: NodePortGroupOverrideState
  reason?: NodePortGroupOverrideReason
}

export interface NodeMetricsHistoryPoint {
  node_id: string
  node_name: string
  publication_sequence: number
  observed_at: string
  known: boolean
  cpu_percent: number | null
  memory_used_bytes: number | null
  memory_total_bytes: number | null
  active_connections: number | null
  rx_bandwidth_bps: number | null
  tx_bandwidth_bps: number | null
  telemetry?: NodeTelemetry
  total_rx_bytes: number | null
  total_tx_bytes: number | null
}

export interface NodeMetricsHistoryResponse {
  items: NodeMetricsHistoryPoint[]
}

export interface NodeMetricsHistoryParams {
  from: string
  to: string
  limit: number
}

export type NodeRealtimeMetric = 'bandwidth' | 'connections' | 'load' | 'disk'

export interface NodeRealtimeTopParams {
  externalOnly?: boolean
  recentTime?: string
  type: NodeRealtimeMetric
  limit?: number
}

export interface NodeRealtimeTopItem {
  inbound: number
  nic: string
  node_id: string
  node_name: string
  outbound: number
}

export interface NodeRealtimeTopResponse {
  data: NodeRealtimeTopItem[]
  msg: string
  code: 0
}

export interface NodeRealtimeSeries {
  data: Array<[number, number]>
  name: string
}

export interface NodeRealtimeResponse {
  data: Record<string, NodeRealtimeSeries[]>
  msg: string
  code: 0
}

export interface NodeRealtimeSeriesParams {
  externalOnly?: boolean
  type: NodeRealtimeMetric
  start: string
  end: string
  node: string
  limit?: number
}

export interface NodeTrafficItem {
  bytes_received: number
  bytes_sent: number
  create_at: string
}

export interface NodeTrafficResponse {
  count: number
  data: NodeTrafficItem[]
  msg: string
  code: 0
}

export interface NodeTrafficParams {
  externalOnly?: boolean
  start: string
  end: string
  node: string
  excludedNIC?: string
  limit?: number
}

export interface CreateNodeRequest {
  name: string
  description?: string
  region?: string
  ipv4?: string
  ipv6?: string
  issue_enrollment_token?: boolean
  enrollment_purpose?: EnrollmentPurpose
  enrollment_token_ttl_seconds?: number
}

export interface IssuedEnrollmentToken {
  id: string
  node_id: string
  purpose: EnrollmentPurpose
  created_at: string
  expires_at: string
  token: string
}

// Scope-level credential embedded in the reusable node install command.
export interface NodeRegistrationCredential {
  key_id: string
  credential: string
  issued_at: string
}

export interface CreateNodeResponse {
  node: NodeRecord
  enrollment_token?: IssuedEnrollmentToken
}

export interface IssueEnrollmentTokenRequest {
  purpose?: EnrollmentPurpose
  ttl_seconds?: number
}

export interface UpdateNodeRequest {
  name?: string
  description?: string
  region?: string
  ipv4?: string
  ipv6?: string
  admin_state?: ManagedNodeAdminState
  management_settings?: NodeManagementSettings
}

export interface BatchNodeAdminStateRequest {
  admin_state: ManagedNodeAdminState
  items: Array<{ id: string; expected_revision: number }>
}

export interface BatchNodeAdminStateItemResult {
  id: string
  status: 'updated' | 'failed'
  node?: NodeRecord
  error?: {
    code:
      | 'node_not_found'
      | 'version_conflict'
      | 'node_state_transition_denied'
      | 'node_identity_required'
      | 'node_ip_conflict'
      | 'node_retired'
  }
}

export interface BatchNodeAdminStateResponse {
  items: BatchNodeAdminStateItemResult[]
}

export type NodeGatewayPortTransitionState =
  | 'preparing' | 'switching' | 'switched' | 'failed' | 'rolled_back' | 'finalized'

export interface NodeGatewayEndpoint {
  address: string
  server_name: string
  listen_address: string
}

export interface CreateNodeGatewayPortTransitionRequest {
  expected_node_revision: number
  old_endpoint: NodeGatewayEndpoint
  new_endpoint: NodeGatewayEndpoint
  compatibility_deadline: string
  rollback_deadline: string
}

export interface NodeGatewayPortTransition {
  id: string
  scope_id: string
  node_id: string
  revision: number
  expected_node_revision: number
  old_endpoint: NodeGatewayEndpoint
  new_endpoint: NodeGatewayEndpoint
  compatibility_deadline: string
  rollback_deadline: string
  state: NodeGatewayPortTransitionState
  status_revision: number
  active_endpoint: NodeGatewayEndpoint
  error_code: string
  created_at: string
  updated_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/
const agentVersionPattern = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$/
const adminStates = new Set<NodeAdminState>(['pending', 'active', 'draining', 'disabled', 'retired'])
const presenceStates = new Set<NodePresenceStatus>(['online', 'offline', 'unknown'])
const marketProbeRoles = new Set<NodeMarketProbeRole>(['probe_only', 'join_market', 'disabled'])
const projectionStates = new Set<NodeProjectionFreshness>(['fresh', 'stale', 'never'])
const leaseSignals = new Set<NodeLeaseSignal>(['present', 'absent', 'unavailable'])
const gatewayPortTransitionStates = new Set<NodeGatewayPortTransitionState>([
  'preparing', 'switching', 'switched', 'failed', 'rolled_back', 'finalized',
])

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function boundedString(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum
}

function boundedUnicodeString(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === 'string' && [...value].length >= minimum && [...value].length <= maximum
}

function timestamp(value: unknown): value is string {
  return boundedString(value, 20, 40) && timestampPattern.test(value) && Number.isFinite(Date.parse(value))
}

function ipv4(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const parts = value.split('.')
  return parts.length === 4 && parts.every((part) =>
    /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255,
  )
}

function ipv6(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 2 || value.length > 45 || !value.includes(':')) return false
  let candidate = value
  if (candidate.includes('.')) {
    const separator = candidate.lastIndexOf(':')
    if (separator < 0 || !ipv4(candidate.slice(separator + 1))) return false
    candidate = `${candidate.slice(0, separator)}:0:0`
  }
  const halves = candidate.split('::')
  if (halves.length > 2) return false
  const groups = halves.flatMap((half) => half ? half.split(':') : [])
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return false
  return halves.length === 2 ? groups.length < 8 : groups.length === 8
}

function positiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function recoveryEvidence(value: unknown): value is NodeRecoveryEvidence {
  return record(value) && exactKeys(value, [
    'config_revision', 'publication_sequence', 'recovered_at', 'reason_code',
    'puback_stream', 'puback_sequence',
  ]) && positiveInteger(value.config_revision) && positiveInteger(value.publication_sequence) &&
    timestamp(value.recovered_at) && value.reason_code === 'probe_recovered' &&
    value.puback_stream === 'NODE_MONITORING_STATUS' && positiveInteger(value.puback_sequence)
}

function metricNumber(value: unknown, maximum?: number): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 &&
    (maximum === undefined || value <= maximum)
}

function nodeXDPStatus(value: unknown): value is NodeXDPStatus {
  if (!record(value) || !exactKeys(value, ['mode'], ['reason', 'detail', 'interfaces', 'drops']) ||
    !['native', 'generic', 'nftables', 'disabled'].includes(value.mode as string)) return false
  const attached = value.mode === 'native' || value.mode === 'generic'
  const interfaces = value.interfaces ?? []
  const drops = value.drops ?? []
  if (!Array.isArray(interfaces) || !Array.isArray(drops) || interfaces.length > 64 ||
    (value.detail !== undefined && !boundedString(value.detail, 1, 256)) ||
    attached !== (value.reason === undefined) || attached !== (interfaces.length > 0) ||
    (!attached && (drops.length > 0 || !nodeXDPReasons.includes(value.reason as NodeXDPReason)))) return false
  let previous = ''
  for (const nic of interfaces) {
    if (typeof nic !== 'string' || !/^[^/= ]{1,15}=(native|generic)$/.test(nic) || nic <= previous) return false
    previous = nic
  }
  previous = ''
  for (const drop of drops) {
    if (!record(drop) || !exactKeys(drop, ['kind', 'packets', 'bytes']) || !nodeXDPDropKinds.includes(drop.kind as NodeXDPDropKind) ||
      (drop.kind as string) <= previous || !nonNegativeInteger(drop.packets) || !nonNegativeInteger(drop.bytes)) return false
    previous = drop.kind as string
  }
  return true
}

function nodeDDoSProtection(value: unknown): value is NodeDDoSProtection {
  if (!record(value) || !exactKeys(value, ['state'], ['reason', 'detail']) ||
    !nodeDDoSProtectionStates.includes(value.state as NodeDDoSProtectionState)) return false
  const unavailable = value.state === 'unavailable'
  if (unavailable !== (value.reason !== undefined) ||
    (value.reason !== undefined && !nodeDDoSProtectionReasons.includes(value.reason as NodeDDoSProtectionReason))) return false
  if (value.detail === undefined) return true
  return (unavailable || value.state === 'failed') && typeof value.detail === 'string' && value.detail.length <= 256 &&
    !/[\r\n]/.test(value.detail) && !value.detail.includes('\u0000')
}

function nodeMounts(value: unknown): value is NodeMount[] {
  if (!Array.isArray(value) || value.length > 256) return false
  let previous = ''
  for (const mount of value) {
    if (!record(mount) || !exactKeys(mount, ['path', 'device', 'fstype', 'read_only', 'bind'], ['filter_reason']) ||
      !boundedString(mount.path, 1, 4096) || mount.path[0] !== '/' || mount.path <= previous ||
      typeof mount.device !== 'string' || !/^[0-9]{1,10}:[0-9]{1,10}$/.test(mount.device) ||
      typeof mount.fstype !== 'string' || mount.fstype.length > 64 || typeof mount.read_only !== 'boolean' ||
      typeof mount.bind !== 'boolean' ||
      (mount.filter_reason !== undefined && !nodeMountFilterReasons.includes(mount.filter_reason as NodeMountFilterReason))) return false
    previous = mount.path
  }
  return true
}

function nodePortGroupOverrides(value: unknown): value is NodePortGroupOverride[] {
  if (!Array.isArray(value) || value.length > 256) return false
  let previous = ''
  for (const item of value) {
    if (!record(item) || !exactKeys(item, ['port_group_id', 'state'], ['reason']) ||
      typeof item.port_group_id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(item.port_group_id) ||
      item.port_group_id <= previous || !nodePortGroupOverrideStates.includes(item.state as NodePortGroupOverrideState) ||
      (item.state === 'inactive') !== (item.reason !== undefined) ||
      (item.reason !== undefined && !nodePortGroupOverrideReasons.includes(item.reason as NodePortGroupOverrideReason))) return false
    previous = item.port_group_id
  }
  return true
}

function nodeTelemetry(value: unknown): value is NodeTelemetry {
  if (!record(value) || !exactKeys(value, ['schema_version', 'network_interfaces', 'disks', 'total_rx_bytes', 'total_tx_bytes'], ['system_load', 'network_selection', 'ddos_drops', 'xdp', 'site_drop', 'ddos_protection', 'mounts', 'port_group_overrides', 'storage']) ||
    value.schema_version !== 1 || !Array.isArray(value.network_interfaces) || value.network_interfaces.length > 128 ||
    !Array.isArray(value.disks) || value.disks.length > 128 || !nonNegativeInteger(value.total_rx_bytes) ||
    !nonNegativeInteger(value.total_tx_bytes)) return false
  let previousName = ''
  for (const item of value.network_interfaces) {
    if (!record(item) || !exactKeys(item, ['name', 'rx_bytes', 'tx_bytes', 'rx_bandwidth_bps', 'tx_bandwidth_bps']) ||
      !boundedString(item.name, 1, 128) || item.name <= previousName || !nonNegativeInteger(item.rx_bytes) ||
      !nonNegativeInteger(item.tx_bytes) || !nonNegativeInteger(item.rx_bandwidth_bps) || !nonNegativeInteger(item.tx_bandwidth_bps)) return false
    previousName = item.name
  }
  if (value.network_selection !== undefined) {
    const selection = value.network_selection
    if (!record(selection) || !exactKeys(selection, ['source', 'interfaces']) ||
      !['default_route', 'unavailable'].includes(selection.source as string) || !Array.isArray(selection.interfaces) ||
      selection.interfaces.length > 128 || (selection.source === 'default_route') !== (selection.interfaces.length > 0)) return false
    let previous = ''
    for (const name of selection.interfaces) {
      if (typeof name !== 'string' || name <= previous || !value.network_interfaces.some((nic) => record(nic) && nic.name === name)) return false
      previous = name
    }
  }
  if (value.ddos_drops !== undefined) {
    if (!Array.isArray(value.ddos_drops) || value.ddos_drops.length > nodeDDoSDropKinds.length) return false
    let previousKind = ''
    for (const drop of value.ddos_drops) {
      if (!record(drop) || !exactKeys(drop, ['kind', 'packets', 'bytes']) ||
        !nodeDDoSDropKinds.includes(drop.kind as NodeDDoSDropKind) || (drop.kind as string) <= previousKind ||
        !nonNegativeInteger(drop.packets) || !nonNegativeInteger(drop.bytes)) return false
      previousKind = drop.kind as string
    }
  }
  if (value.xdp !== undefined && !nodeXDPStatus(value.xdp)) return false
  if (value.ddos_protection !== undefined && !nodeDDoSProtection(value.ddos_protection)) return false
  if (value.mounts !== undefined && !nodeMounts(value.mounts)) return false
  if (value.port_group_overrides !== undefined && !nodePortGroupOverrides(value.port_group_overrides)) return false
  if (value.storage !== undefined && !nodeStorageStatus(value.storage)) return false
  if (value.site_drop !== undefined) {
    const drop = value.site_drop
    if (!record(drop) || !exactKeys(drop, ['site_ids', 'packets', 'bytes']) || !Array.isArray(drop.site_ids) ||
      drop.site_ids.length < 1 || drop.site_ids.length > 256 || !nonNegativeInteger(drop.packets) || !nonNegativeInteger(drop.bytes)) return false
    let previousSite = ''
    for (const id of drop.site_ids) {
      if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || id <= previousSite) return false
      previousSite = id
    }
  }
  if (value.system_load !== undefined) {
    const load = value.system_load
    if (!record(load) || !exactKeys(load, ['one_minute', 'five_minutes', 'fifteen_minutes', 'running_processes', 'total_processes']) ||
      !metricNumber(load.one_minute) || !metricNumber(load.five_minutes) || !metricNumber(load.fifteen_minutes) ||
      !nonNegativeInteger(load.running_processes) || !positiveInteger(load.total_processes) || load.running_processes > load.total_processes) return false
  }
  let previousPath = ''
  for (const item of value.disks) {
    if (!record(item) || !exactKeys(item, ['path', 'total_bytes', 'used_bytes', 'total_inodes', 'used_inodes', 'space_percent', 'inode_percent']) ||
      !boundedString(item.path, 1, 4096) || item.path[0] !== '/' || item.path <= previousPath ||
      !nonNegativeInteger(item.total_bytes) || !nonNegativeInteger(item.used_bytes) || item.used_bytes > item.total_bytes ||
      !nonNegativeInteger(item.total_inodes) || !nonNegativeInteger(item.used_inodes) || item.used_inodes > item.total_inodes ||
      !metricNumber(item.space_percent, 100) || !metricNumber(item.inode_percent, 100)) return false
    previousPath = item.path
  }
  return true
}

function metricsLatest(value: unknown, nodeID: string): NodeMetricsLatest {
  const required = [
    'node_id', 'node_name', 'config_revision', 'active_config_revision', 'publication_sequence',
    'observed_at', 'probe_port', 'healthy', 'probe_succeeded', 'consecutive_failures',
    'consecutive_successes', 'probes_total', 'probe_failures_total', 'recovered',
    'recovery_notified', 'rolled_back', 'known', 'cpu_percent', 'memory_used_bytes',
    'memory_total_bytes', 'active_connections', 'rx_bandwidth_bps', 'tx_bandwidth_bps', 'total_rx_bytes', 'total_tx_bytes',
    'puback_stream', 'puback_sequence', 'consumer_durable', 'consumer_sequence', 'ingested_at',
  ] as const
  if (!record(value) || !exactKeys(value, required, ['latest_recovery', 'telemetry', 'record_kind', 'monthly_traffic', 'telemetry_detail', 'storage_supported']) || value.node_id !== nodeID ||
    (value.telemetry_detail !== undefined && typeof value.telemetry_detail !== 'boolean') ||
    (value.storage_supported !== undefined && typeof value.storage_supported !== 'boolean') ||
    !uuidPattern.test(nodeID) || !boundedString(value.node_name, 1, 128) ||
    (value.record_kind !== undefined && value.record_kind !== 'metric' && value.record_kind !== 'host_metric') ||
    !nonNegativeInteger(value.config_revision) || !nonNegativeInteger(value.active_config_revision) ||
    !positiveInteger(value.publication_sequence) || !timestamp(value.observed_at) ||
    !nonNegativeInteger(value.probe_port) || value.probe_port > 65535 || typeof value.healthy !== 'boolean' ||
    typeof value.probe_succeeded !== 'boolean' || !nonNegativeInteger(value.consecutive_failures) ||
    value.consecutive_failures > 20 || !nonNegativeInteger(value.consecutive_successes) ||
    value.consecutive_successes > 20 || value.consecutive_failures > 0 && value.consecutive_successes > 0 ||
    !nonNegativeInteger(value.probes_total) || !nonNegativeInteger(value.probe_failures_total) ||
    value.probe_failures_total > value.probes_total || typeof value.recovered !== 'boolean' ||
    typeof value.recovery_notified !== 'boolean' || typeof value.rolled_back !== 'boolean' ||
    value.recovered && (!value.healthy || !value.probe_succeeded) ||
    value.rolled_back && (value.active_config_revision >= value.config_revision || value.probe_succeeded) ||
    typeof value.known !== 'boolean' || value.puback_stream !== 'NODE_MONITORING_STATUS' ||
    (value.total_rx_bytes !== null && !nonNegativeInteger(value.total_rx_bytes)) ||
    (value.total_tx_bytes !== null && !nonNegativeInteger(value.total_tx_bytes)) ||
    (value.telemetry !== undefined && !nodeTelemetry(value.telemetry)) ||
    !positiveInteger(value.puback_sequence) || value.consumer_durable !== 'control_api_node_metrics' ||
    !positiveInteger(value.consumer_sequence) || !timestamp(value.ingested_at) ||
    (value.latest_recovery !== undefined && !recoveryEvidence(value.latest_recovery)) ||
    (value.monthly_traffic !== undefined && !monthlyTraffic(value.monthly_traffic))) {
    throw invalidInventoryResponse()
  }
  if (value.record_kind === 'host_metric') {
    if (value.config_revision !== 0 || value.active_config_revision !== 0 || value.probe_port !== 0 ||
      value.healthy || value.probe_succeeded || value.consecutive_failures !== 0 || value.consecutive_successes !== 0 ||
      value.probes_total !== 0 || value.probe_failures_total !== 0 || value.recovered || value.recovery_notified ||
      value.rolled_back || !value.known) throw invalidInventoryResponse()
  } else if (value.config_revision === 0 || value.active_config_revision === 0 || value.probe_port === 0) {
    throw invalidInventoryResponse()
  }
  const load = [value.cpu_percent, value.memory_used_bytes, value.memory_total_bytes,
    value.active_connections, value.rx_bandwidth_bps, value.tx_bandwidth_bps]
  if (!value.known && (value.telemetry !== undefined || value.total_rx_bytes !== null || value.total_tx_bytes !== null)) throw invalidInventoryResponse()
  if (!value.known ? load.some((item) => item !== null) :
    !metricNumber(value.cpu_percent, 100) || !nonNegativeInteger(value.memory_used_bytes) ||
    !positiveInteger(value.memory_total_bytes) || value.memory_used_bytes > value.memory_total_bytes ||
    !nonNegativeInteger(value.active_connections) || !nonNegativeInteger(value.rx_bandwidth_bps) ||
    !nonNegativeInteger(value.tx_bandwidth_bps)) throw invalidInventoryResponse()
  return value as unknown as NodeMetricsLatest
}

function monthlyTraffic(value: unknown): value is NodeMonthlyTraffic {
  return record(value) && exactKeys(value,
    ['state', 'period_key', 'period_start', 'period_end', 'timezone', 'usage_bytes', 'source_finalized_through', 'samples'],
    ['counter_resets']) && (value.counter_resets === undefined || nonNegativeInteger(value.counter_resets)) &&
    ['available', 'insufficient_data', 'stale', 'incomplete', 'counter_reset'].includes(value.state as string) &&
    typeof value.period_key === 'string' && /^\d{4}-\d{2}$/.test(value.period_key) && timestamp(value.period_start) &&
    timestamp(value.period_end) && typeof value.timezone === 'string' && value.timezone.length > 0 &&
    nonNegativeInteger(value.usage_bytes) && (value.source_finalized_through === null || timestamp(value.source_finalized_through)) &&
    nonNegativeInteger(value.samples)
}

function metricsHistoryPoint(value: unknown, nodeID: string): value is NodeMetricsHistoryPoint {
  if (!record(value) || !exactKeys(value, [
    'node_id', 'node_name', 'publication_sequence', 'observed_at', 'known', 'cpu_percent',
    'memory_used_bytes', 'memory_total_bytes', 'active_connections', 'rx_bandwidth_bps',
    'tx_bandwidth_bps', 'total_rx_bytes', 'total_tx_bytes',
  ], ['telemetry']) || value.node_id !== nodeID || !uuidPattern.test(nodeID) ||
    !boundedString(value.node_name, 1, 128) || !positiveInteger(value.publication_sequence) ||
    !timestamp(value.observed_at) || typeof value.known !== 'boolean') return false

  const load = [value.cpu_percent, value.memory_used_bytes, value.memory_total_bytes,
    value.active_connections, value.rx_bandwidth_bps, value.tx_bandwidth_bps]
  if ((value.total_rx_bytes !== null && !nonNegativeInteger(value.total_rx_bytes)) ||
    (value.total_tx_bytes !== null && !nonNegativeInteger(value.total_tx_bytes)) ||
    (value.telemetry !== undefined && !nodeTelemetry(value.telemetry)) ||
    !value.known && (value.telemetry !== undefined || value.total_rx_bytes !== null || value.total_tx_bytes !== null)) return false
  return !value.known ? load.every((item) => item === null) :
    metricNumber(value.cpu_percent, 100) && nonNegativeInteger(value.memory_used_bytes) &&
    positiveInteger(value.memory_total_bytes) && value.memory_used_bytes <= value.memory_total_bytes &&
    nonNegativeInteger(value.active_connections) && nonNegativeInteger(value.rx_bandwidth_bps) &&
    nonNegativeInteger(value.tx_bandwidth_bps)
}

function metricsHistory(value: unknown, nodeID: string, limit: number): NodeMetricsHistoryResponse {
  if (!record(value) || !exactKeys(value, ['items']) || !Array.isArray(value.items) ||
    value.items.length > limit || value.items.some((item) => !metricsHistoryPoint(item, nodeID))) {
    throw invalidInventoryResponse()
  }
  const items = value.items as NodeMetricsHistoryPoint[]
  if (items.some((item, index) => index > 0 && (
    items[index - 1]!.observed_at > item.observed_at ||
    items[index - 1]!.observed_at === item.observed_at &&
      items[index - 1]!.publication_sequence >= item.publication_sequence
  ))) throw invalidInventoryResponse()
  return { items }
}

function nonNegativeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

function realtimeTopItem(value: unknown): value is NodeRealtimeTopItem {
  return record(value) && exactKeys(value, ['inbound', 'nic', 'node_id', 'node_name', 'outbound']) &&
    nonNegativeNumber(value.inbound) && boundedString(value.nic, 0, 128) &&
    typeof value.node_id === 'string' && uuidPattern.test(value.node_id) &&
    boundedString(value.node_name, 1, 128) && nonNegativeNumber(value.outbound)
}

function realtimeTop(value: unknown, limit: number): NodeRealtimeTopResponse {
  if (!record(value) || !exactKeys(value, ['data', 'msg', 'code']) || value.code !== 0 ||
    typeof value.msg !== 'string' || !Array.isArray(value.data) || value.data.length > limit ||
    value.data.some((item) => !realtimeTopItem(item))) throw invalidInventoryResponse()
  return value as unknown as NodeRealtimeTopResponse
}

function realtimeSeries(value: unknown): value is NodeRealtimeSeries {
  if (!record(value) || !exactKeys(value, ['data', 'name']) || !boundedString(value.name, 1, 32) ||
    !Array.isArray(value.data)) return false
  let previousTimestamp = -1
  for (const point of value.data) {
    if (!Array.isArray(point) || point.length !== 2 || !nonNegativeNumber(point[0]) ||
      !nonNegativeNumber(point[1]) || point[0] < previousTimestamp) return false
    previousTimestamp = point[0]
  }
  return true
}

function realtimeResponse(value: unknown, limit: number): NodeRealtimeResponse {
  if (!record(value) || !exactKeys(value, ['data', 'msg', 'code']) || value.code !== 0 ||
    typeof value.msg !== 'string' || !record(value.data)) throw invalidInventoryResponse()
  for (const [key, series] of Object.entries(value.data)) {
    if (!boundedString(key, 0, 128) || !Array.isArray(series) || series.length > 16 ||
      series.some((item) => !realtimeSeries(item) || item.data.length > limit)) {
      throw invalidInventoryResponse()
    }
  }
  return value as unknown as NodeRealtimeResponse
}

const nodeTrafficTimestampPattern = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/

function nodeTrafficItem(value: unknown): value is NodeTrafficItem {
  return record(value) && exactKeys(value, ['bytes_received', 'bytes_sent', 'create_at']) &&
    nonNegativeInteger(value.bytes_received) && nonNegativeInteger(value.bytes_sent) &&
    typeof value.create_at === 'string' && nodeTrafficTimestampPattern.test(value.create_at)
}

function nodeTraffic(value: unknown, limit: number): NodeTrafficResponse {
  if (!record(value) || !exactKeys(value, ['count', 'data', 'msg', 'code']) || value.code !== 0 ||
    typeof value.msg !== 'string' || !nonNegativeInteger(value.count) || !Array.isArray(value.data) ||
    value.count !== value.data.length || value.data.length > limit || value.data.some((item) => !nodeTrafficItem(item))) {
    throw invalidInventoryResponse()
  }
  return value as unknown as NodeTrafficResponse
}

function networkInventory(value: unknown, addresses: Record<string, unknown>): value is NodeNetworkInventory {
  const states = new Set(['not_reported', 'verified', 'address_conflict', 'peer_mismatch',
    'no_default_route', 'no_global_address', 'ambiguous_route', 'unavailable'])
  if (!record(value) || !exactKeys(value, ['schema_version', 'ipv4_state', 'ipv6_state'], ['received_at']) ||
    value.schema_version !== 1 || !states.has(value.ipv4_state as string) || !states.has(value.ipv6_state as string)) return false
  if (value.ipv4_state === 'not_reported' || value.ipv6_state === 'not_reported') {
    return value.ipv4_state === 'not_reported' && value.ipv6_state === 'not_reported' && !Object.hasOwn(value, 'received_at')
  }
  return timestamp(value.received_at) &&
    (value.ipv4_state !== 'verified' || ipv4(addresses.ipv4)) &&
    (value.ipv6_state !== 'verified' || ipv6(addresses.ipv6))
}

function inventoryItem(value: unknown): value is NodeInventoryItem {
  if (!record(value) || !exactKeys(value, [
    'id', 'display_id', 'name', 'description', 'region', 'admin_state', 'management_settings', 'revision', 'created_at', 'updated_at', 'presence',
  ], ['ipv4', 'ipv6', 'network_inventory']) ||
    typeof value.id !== 'string' || !uuidPattern.test(value.id) ||
    typeof value.display_id !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.display_id) ||
    !boundedString(value.name, 1, 128) || !boundedString(value.description, 0, 1024) ||
    !boundedString(value.region, 0, 64) ||
    (value.ipv4 !== undefined && !ipv4(value.ipv4)) ||
    (value.ipv6 !== undefined && !ipv6(value.ipv6)) ||
    (value.network_inventory !== undefined && !networkInventory(value.network_inventory, value)) ||
    !adminStates.has(value.admin_state as NodeAdminState) || !managementSettings(value.management_settings) || !positiveInteger(value.revision) ||
    !timestamp(value.created_at) || !timestamp(value.updated_at) || !record(value.presence)) return false

  const presence = value.presence
  if (!exactKeys(presence, ['status', 'projection_freshness', 'lease_signal'], [
    'last_heartbeat_at', 'agent_version', 'session_epoch', 'heartbeat_sequence', 'projected_at', 'market_probe_role',
    'openresty_version', 'native_runtime_state', 'native_runtime_release', 'native_runtime_previous_release',
    'native_runtime_error_code',
  ]) || !nativeRuntime(presence) || !presenceStates.has(presence.status as NodePresenceStatus) ||
    !projectionStates.has(presence.projection_freshness as NodeProjectionFreshness) ||
    !leaseSignals.has(presence.lease_signal as NodeLeaseSignal) ||
    (presence.last_heartbeat_at !== undefined && !timestamp(presence.last_heartbeat_at)) ||
    (presence.agent_version !== undefined && (
      typeof presence.agent_version !== 'string' || !agentVersionPattern.test(presence.agent_version)
    )) ||
    (presence.projected_at !== undefined && !timestamp(presence.projected_at)) ||
    (presence.market_probe_role !== undefined && !marketProbeRoles.has(presence.market_probe_role as NodeMarketProbeRole)) ||
    (presence.openresty_version !== undefined && (
      typeof presence.openresty_version !== 'string' || presence.openresty_version === '' || presence.openresty_version.length > 128
    ))) return false

  const hasEpoch = presence.session_epoch !== undefined
  const hasSequence = presence.heartbeat_sequence !== undefined
  return hasEpoch === hasSequence && (!hasEpoch || (
    positiveInteger(presence.session_epoch) && positiveInteger(presence.heartbeat_sequence)
  ))
}

function ipLocationFieldList(value: unknown): value is NodeIPLocationField[] {
  return Array.isArray(value) && value.length <= nodeIPLocationFields.length && new Set(value).size === value.length &&
    value.every((field) => (nodeIPLocationFields as readonly unknown[]).includes(field))
}

function ipLocationValue(value: unknown): value is NodeIPLocation {
  return record(value) && exactKeys(value, [...nodeIPLocationFields]) &&
    nodeIPLocationFields.every((field) => boundedString(value[field], 0, 128)) &&
    /^(?:|[A-Z]{2})$/.test(String(value.country_code))
}

function ipLocationView(value: unknown, id: string): value is NodeIPLocationView {
  if (!record(value) || value.node_id !== id || !ipLocationValue(value.effective) ||
    !ipLocationFieldList(value.manual_fields)) return false
  const resolution = value.resolution
  if (resolution === null) return true
  return record(resolution) && resolution.node_id === id &&
    ['resolved', 'unresolved', 'no_library'].includes(String(resolution.outcome)) &&
    (resolution.address === undefined || typeof resolution.address === 'string') &&
    ipLocationValue(resolution.automatic) && nonNegativeInteger(resolution.library_revision) &&
    boundedString(resolution.library_version, 0, 128) && typeof resolution.resolved_at === 'string' &&
    !Number.isNaN(Date.parse(resolution.resolved_at))
}

function managementSettings(value: unknown): value is NodeManagementSettings {
  if (!record(value) || !exactKeys(value, [
    'schema_version', 'sort', 'node_type', 'cache_directory', 'cache_limit_gb', 'log_directory',
    'ip_location', 'auto_disable', 'secondary_ips', 'external_probe',
  ], ['schedule302_hostname', 'ip_location_manual']) || value.schema_version !== 1 || typeof value.external_probe !== 'boolean' || !nonNegativeInteger(value.sort) || value.sort > 999999 ||
    !['L1', 'L2'].includes(String(value.node_type)) || !boundedString(value.cache_directory, 0, 512) ||
    !nonNegativeInteger(value.cache_limit_gb) || value.cache_limit_gb > 1_000_000_000 ||
    !boundedString(value.log_directory, 0, 512) || !record(value.ip_location) ||
    !exactKeys(value.ip_location, ['country', 'province', 'city', 'isp', 'country_code']) ||
    !boundedString(value.ip_location.country, 0, 128) || !boundedString(value.ip_location.province, 0, 128) ||
    !boundedString(value.ip_location.city, 0, 128) || !boundedString(value.ip_location.isp, 0, 128) ||
    typeof value.ip_location.country_code !== 'string' || !/^(?:|[A-Z]{2})$/.test(value.ip_location.country_code) ||
    !record(value.auto_disable) || !exactKeys(value.auto_disable, [
      'bandwidth_limit', 'bandwidth_unit', 'traffic_enabled', 'traffic_from_day', 'traffic_from_time',
      'traffic_total_gb', 'traffic_types', 'excluded_interfaces', 'disabled_periods',
    ]) || !nonNegativeInteger(value.auto_disable.bandwidth_limit) || value.auto_disable.bandwidth_limit > 1_000_000_000 ||
    !['Mbps', 'Gbps'].includes(String(value.auto_disable.bandwidth_unit)) || typeof value.auto_disable.traffic_enabled !== 'boolean' ||
    !positiveInteger(value.auto_disable.traffic_from_day) || value.auto_disable.traffic_from_day > 28 ||
    typeof value.auto_disable.traffic_from_time !== 'string' || !/^(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(value.auto_disable.traffic_from_time) ||
    !nonNegativeInteger(value.auto_disable.traffic_total_gb) || value.auto_disable.traffic_total_gb > 1_000_000_000 ||
    !Array.isArray(value.auto_disable.traffic_types) || value.auto_disable.traffic_types.length < 1 ||
    value.auto_disable.traffic_types.length > 2 || new Set(value.auto_disable.traffic_types).size !== value.auto_disable.traffic_types.length ||
    value.auto_disable.traffic_types.some((type) => !['outbound', 'inbound'].includes(String(type))) ||
    !boundedString(value.auto_disable.excluded_interfaces, 0, 512) ||
    !boundedString(value.auto_disable.disabled_periods, 0, 1024) || !Array.isArray(value.secondary_ips) ||
    value.secondary_ips.length > 64 || new Set(value.secondary_ips).size !== value.secondary_ips.length ||
    value.secondary_ips.some((address) => !ipv4(address) && !ipv6(address)) ||
    (value.schedule302_hostname !== undefined && !isSchedule302Hostname(value.schedule302_hostname)) ||
    (value.ip_location_manual !== undefined && !ipLocationFieldList(value.ip_location_manual))) return false
  return true
}

function nodeRecord(value: unknown): value is NodeRecord {
  return record(value) && exactKeys(value, [
    'id', 'display_id', 'name', 'description', 'region', 'admin_state', 'management_settings',
    'revision', 'created_at', 'updated_at',
  ], ['ipv4', 'ipv6']) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.display_id === 'string' && /^[1-9][0-9]{0,18}$/.test(value.display_id) &&
    boundedString(value.name, 1, 128) && boundedString(value.description, 0, 1024) &&
    boundedString(value.region, 0, 64) && (value.ipv4 === undefined || ipv4(value.ipv4)) &&
    (value.ipv6 === undefined || ipv6(value.ipv6)) && adminStates.has(value.admin_state as NodeAdminState) &&
    managementSettings(value.management_settings) && positiveInteger(value.revision) &&
    timestamp(value.created_at) && timestamp(value.updated_at)
}

function invalidInventoryResponse(): ApiError {
  return new ApiError('Invalid node inventory response', 200, 'invalid_response')
}

function inventoryPage(value: unknown, limit: number): NodeListResponse {
  if (!record(value) || !exactKeys(value, ['items'], ['next_cursor']) ||
    !Array.isArray(value.items) || value.items.length > limit ||
    value.items.some((item) => !inventoryItem(item))) throw invalidInventoryResponse()

  const items = value.items as NodeInventoryItem[]
  if (new Set(items.map((item) => item.id)).size !== items.length ||
    new Set(items.map((item) => item.display_id)).size !== items.length ||
    items.some((item, index) => index > 0 && items[index - 1]!.id >= item.id)) {
    throw invalidInventoryResponse()
  }
  if (value.next_cursor !== undefined && (
    typeof value.next_cursor !== 'string' || !uuidPattern.test(value.next_cursor) ||
    !items.length || value.next_cursor !== items.at(-1)!.id
  )) throw invalidInventoryResponse()
  return value as unknown as NodeListResponse
}

interface InventoryOrderCursor {
  version: 1
  scope_id: string
  order: 'management_sort_desc'
  status: string
  presence: string
  search: string
  last_sort: number
  last_display_id: string
  last_id: string
}

function inventoryOrderCursor(raw: unknown, params: NodeListParams): InventoryOrderCursor {
  if (typeof raw !== 'string' || raw.length > 2048 || !/^nso1\.[A-Za-z0-9_-]+$/.test(raw)) throw invalidInventoryResponse()
  const encoded = raw.slice(5)
  const binary = atob(encoded.replaceAll('-', '+').replaceAll('_', '/'))
  if (btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '') !== encoded) throw invalidInventoryResponse()
  const decoded = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)))
  const value: unknown = JSON.parse(decoded)
  if (!record(value) || !exactKeys(value, [
    'version', 'scope_id', 'order', 'status', 'presence', 'search', 'last_sort', 'last_display_id', 'last_id',
  ]) || value.version !== 1 || typeof value.scope_id !== 'string' || !uuidPattern.test(value.scope_id) ||
    value.scope_id === '00000000-0000-0000-0000-000000000000' || value.order !== 'management_sort_desc' ||
    value.status !== (params.status ?? '') || value.presence !== (params.presence ?? '') || value.search !== (params.search?.trim() ?? '') ||
    !nonNegativeInteger(value.last_sort) || value.last_sort > 999999 ||
    typeof value.last_display_id !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.last_display_id) || BigInt(value.last_display_id) > 9223372036854775807n ||
    typeof value.last_id !== 'string' || !uuidPattern.test(value.last_id) || value.last_id === '00000000-0000-0000-0000-000000000000') throw invalidInventoryResponse()
  // Match Go's canonical struct encoding: duplicates, missing fields, unknown
  // fields, reordered keys and noncanonical JSON must not become valid cursors.
  const canonical = JSON.stringify({ version: value.version, scope_id: value.scope_id, order: value.order,
    status: value.status, presence: value.presence, search: value.search, last_sort: value.last_sort,
    last_display_id: value.last_display_id, last_id: value.last_id,
  }).replace(/[<>&\u2028\u2029]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`)
  if (canonical !== decoded) throw invalidInventoryResponse()
  return value as unknown as InventoryOrderCursor
}

function orderedInventoryPage(value: unknown, params: NodeListParams): NodeListResponse {
  if (!record(value) || !exactKeys(value, ['items', 'order'], ['next_cursor']) || value.order !== params.order ||
    !Array.isArray(value.items) || value.items.length > params.limit || value.items.some((item) => !inventoryItem(item))) throw invalidInventoryResponse()
  const items = value.items as NodeInventoryItem[]
  const after = (item: NodeInventoryItem, sort: number, displayID: string, id: string) => (
    item.management_settings.sort < sort || item.management_settings.sort === sort && (
      BigInt(item.display_id) < BigInt(displayID) || item.display_id === displayID && item.id < id
    )
  )
  if (new Set(items.map((item) => item.id)).size !== items.length || new Set(items.map((item) => item.display_id)).size !== items.length ||
    items.some((item, index) => BigInt(item.display_id) > 9223372036854775807n || index > 0 &&
      !after(item, items[index - 1]!.management_settings.sort, items[index - 1]!.display_id, items[index - 1]!.id))) throw invalidInventoryResponse()
  const previous = params.cursor === undefined ? undefined : inventoryOrderCursor(params.cursor, params)
  if (previous && items.some((item) => !after(item, previous.last_sort, previous.last_display_id, previous.last_id))) throw invalidInventoryResponse()
  if (value.next_cursor !== undefined) {
    const boundary = inventoryOrderCursor(value.next_cursor, params)
    const last = items.at(-1)
    if (!last || boundary.last_id !== last.id || boundary.last_display_id !== last.display_id ||
      boundary.last_sort !== last.management_settings.sort || previous && previous.scope_id !== boundary.scope_id) throw invalidInventoryResponse()
  }
  return value as unknown as NodeListResponse
}

function invalidRegionResponse(): ApiError {
  return new ApiError('Invalid region catalog response', 200, 'invalid_response')
}

function regionRecord(value: unknown): value is RegionRecord {
  return record(value) && exactKeys(value, [
    'id', 'name', 'code', 'country_code', 'province_code', 'description', 'l2_check_port', 'sort', 'revision', 'created_at', 'updated_at',
  ]) && typeof value.id === 'string' && /^[1-9][0-9]{0,18}$/.test(value.id) &&
    typeof value.country_code === 'string' && /^(?:[A-Z]{2})?$/.test(value.country_code) &&
    typeof value.province_code === 'string' && (value.province_code === '' || value.country_code === 'CN' && /^[1-8][0-9]0000$/.test(value.province_code)) &&
    boundedUnicodeString(value.name, 1, 128) && typeof value.code === 'string' && /^[a-z0-9][a-z0-9-]{0,62}$/.test(value.code) && boundedUnicodeString(value.description, 0, 1024) &&
    positiveInteger(value.l2_check_port) && value.l2_check_port <= 65535 &&
    nonNegativeInteger(value.sort) && value.sort <= 999999 && positiveInteger(value.revision) &&
    timestamp(value.created_at) && timestamp(value.updated_at) &&
    Date.parse(value.updated_at) >= Date.parse(value.created_at)
}

function regionPage(value: unknown, pageSize: number): RegionListResponse {
  if (!record(value) || !exactKeys(value, ['count', 'data']) || !nonNegativeInteger(value.count) ||
    !Array.isArray(value.data) || value.data.length > pageSize || value.data.length > value.count ||
    value.data.some((item) => !regionRecord(item))) throw invalidRegionResponse()
  const data = value.data as RegionRecord[]
  if (new Set(data.map((item) => item.id)).size !== data.length || data.some((item, index) => {
    if (index === 0) return false
    const previous = data[index - 1]!
    return previous.sort > item.sort || previous.sort === item.sort && BigInt(previous.id) >= BigInt(item.id)
  })) throw invalidRegionResponse()
  return value as unknown as RegionListResponse
}

function gatewayEndpoint(value: unknown): value is NodeGatewayEndpoint {
  return record(value) && exactKeys(value, ['address', 'server_name', 'listen_address']) &&
    boundedString(value.address, 3, 320) && !/[\s\r\n]/.test(value.address) && value.address.includes(':') &&
    boundedString(value.server_name, 1, 253) && !/[\s\\/]/.test(value.server_name) &&
    boundedString(value.listen_address, 3, 320) && !/[\s\r\n]/.test(value.listen_address) &&
    value.listen_address.includes(':')
}

function gatewayPortTransition(value: unknown, nodeID: string): NodeGatewayPortTransition {
  if (!record(value) || !exactKeys(value, [
    'id', 'scope_id', 'node_id', 'revision', 'expected_node_revision', 'old_endpoint', 'new_endpoint',
    'compatibility_deadline', 'rollback_deadline', 'state', 'status_revision', 'active_endpoint',
    'error_code', 'created_at', 'updated_at',
  ]) || value.node_id !== nodeID || !uuidPattern.test(nodeID) ||
    typeof value.id !== 'string' || !uuidPattern.test(value.id) ||
    typeof value.scope_id !== 'string' || !uuidPattern.test(value.scope_id) ||
    !positiveInteger(value.revision) || !positiveInteger(value.expected_node_revision) ||
    !gatewayEndpoint(value.old_endpoint) || !gatewayEndpoint(value.new_endpoint) ||
    !timestamp(value.compatibility_deadline) || !timestamp(value.rollback_deadline) ||
    !gatewayPortTransitionStates.has(value.state as NodeGatewayPortTransitionState) ||
    !nonNegativeInteger(value.status_revision) || !gatewayEndpoint(value.active_endpoint) ||
    typeof value.error_code !== 'string' || value.error_code.length > 64 || !/^[a-z0-9_]*$/.test(value.error_code) ||
    !timestamp(value.created_at) || !timestamp(value.updated_at)) {
    throw invalidInventoryResponse()
  }
  return value as unknown as NodeGatewayPortTransition
}

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
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
  return (await response.json()) as T
}

async function requestNoContent(accessToken: string, path: string, init: RequestInit): Promise<void> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status !== 204 || await response.text() !== '') throw invalidRegionResponse()
}

async function listRegions(accessToken: string, params: RegionListParams): Promise<RegionListResponse> {
  if (!positiveInteger(params.page) || !positiveInteger(params.page_size) || params.page_size > 300) {
    throw new ApiError('Invalid region list parameters', 400, 'regions_validation_error')
  }
  const query = new URLSearchParams({ page: String(params.page), page_size: String(params.page_size) })
  const search = params.search?.trim()
  if (search) query.set('search', search)
  try {
    return regionPage(await request<unknown>(accessToken, `/v1/regions?${query}`), params.page_size)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidRegionResponse()
  }
}

async function getRegion(accessToken: string, id: string): Promise<RegionRecord> {
  if (!/^[1-9][0-9]{0,18}$/.test(id)) throw new ApiError('Invalid region identifier', 400, 'regions_validation_error')
  try {
    const value = await request<unknown>(accessToken, `/v1/regions/${encodeURIComponent(id)}`)
    if (!regionRecord(value) || value.id !== id) throw invalidRegionResponse()
    return value
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidRegionResponse()
  }
}

async function createRegion(
  accessToken: string,
  input: RegionInput,
  idempotencyKey: string,
): Promise<RegionRecord> {
  try {
    const value = await request<unknown>(accessToken, '/v1/regions', {
      method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(input),
    })
    if (!regionRecord(value)) throw invalidRegionResponse()
    return value
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidRegionResponse()
  }
}

async function updateRegion(
  accessToken: string,
  item: Pick<RegionRecord, 'id' | 'revision'>,
  input: RegionInput,
  idempotencyKey: string,
): Promise<RegionRecord> {
  if (!/^[1-9][0-9]{0,18}$/.test(item.id) || !positiveInteger(item.revision)) {
    throw new ApiError('Invalid region revision', 400, 'regions_validation_error')
  }
  try {
    const value = await request<unknown>(accessToken, `/v1/regions/${encodeURIComponent(item.id)}`, {
      method: 'PATCH',
      headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${item.revision}"` },
      body: JSON.stringify(input),
    })
    if (!regionRecord(value) || value.id !== item.id || value.revision <= item.revision) throw invalidRegionResponse()
    return value
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidRegionResponse()
  }
}

async function deleteRegion(
  accessToken: string,
  item: Pick<RegionRecord, 'id' | 'revision'>,
  idempotencyKey: string,
): Promise<void> {
  if (!/^[1-9][0-9]{0,18}$/.test(item.id) || !positiveInteger(item.revision)) {
    throw new ApiError('Invalid region revision', 400, 'regions_validation_error')
  }
  return requestNoContent(accessToken, `/v1/regions/${encodeURIComponent(item.id)}`, {
    method: 'DELETE',
    headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${item.revision}"` },
  })
}

async function list(accessToken: string, params: NodeListParams): Promise<NodeListResponse> {
  const query = new URLSearchParams({ limit: String(params.limit) })
  if (params.order !== undefined) {
    if (params.order !== 'management_sort_desc') throw new ApiError('Invalid node order', 400, 'validation_error')
    query.set('order', params.order)
  }
  if (params.status) query.set('status', params.status)
  if (params.presence) query.set('presence', params.presence)
  const search = params.search?.trim()
  if (search) query.set('search', search)
  if (params.cursor) query.set('cursor', params.cursor)
  try {
    const value = await request<unknown>(accessToken, `/v1/nodes?${query}`)
    return params.order === undefined ? inventoryPage(value, params.limit) : orderedInventoryPage(value, params)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function get(accessToken: string, id: string): Promise<NodeInventoryItem> {
  if (!uuidPattern.test(id)) throw new ApiError('Invalid node identifier', 400, 'validation_error')
  let value: unknown
  try {
    value = await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(id)}`)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
  if (!inventoryItem(value) || value.id !== id) throw invalidInventoryResponse()
  return value
}

/** One tenant (configuration scope) a node serves, as an administrator sees it. */
export interface NodeConfigurationScope {
  scope_id: string
  scope_kind: 'platform' | 'tenant'
  tenant_id: string | null
  tenant_name: string
  current_config_version_id: string | null
  previous_config_version_id: string | null
  reconciliation_required: boolean
  updated_at: string
  /** The control plane's latest deployment of the scope to this node. */
  latest_deployment: {
    deployment_id: string
    attempt: number
    rollout_id: string
    config_version_id: string
    action: 'apply' | 'rollback'
    state: string
    updated_at: string
  } | null
  /** The agent's last apply of the scope, from its heartbeat; superseded only appears here. */
  last_apply: {
    deployment_id: string
    attempt: number
    config_version_id: string
    state: 'healthy' | 'failed' | 'reverted' | 'rollback_failed' | 'superseded'
    error_code: string | null
    finished_at: string | null
    reported_at: string
  } | null
  /**
   * Why the node's authorization leaves this tenant's telemetry out on a
   * shared node, so the other tenants keep working; '' when it is in.
   */
  telemetry_excluded: '' | 'platform_scope' | 'invalid_config_version' | 'telemetry_site_limit'
}

/** A publication refused because it could not share the node with another tenant. */
export interface NodeScopeRejection {
  scope_id: string
  tenant_name: string
  reason: string
  request_id: string
  occurred_at: string
}

/**
 * A feature the node's latest healthy deployment of a tenant uses that its
 * agent no longer declares, typically after the agent was rolled back.
 */
export interface NodeCapabilityRegression {
  scope_id: string
  deployment_id: string
  config_version_id: string
  feature: NodeRegressionFeature
  capability: string
  required: number
  declared: number
  agent_version: string
}

export type NodeRegressionFeature = 'cc_proof_of_work' | 'waf_crs_module' | 'l4_tls_passthrough' | 'l4_additional_listeners' | 'l4_toa'

export interface NodeConfigurationScopes {
  node_id: string
  scopes: NodeConfigurationScope[]
  rejections: NodeScopeRejection[]
  capability_regressions: NodeCapabilityRegression[]
}

const deploymentStates = new Set(['queued', 'delivered', 'agent_queued', 'started', 'staged', 'prechecked',
  'activated', 'healthy', 'failed', 'reverting', 'reverted', 'rollback_failed', 'cancelled'])
const applyStates = new Set(['healthy', 'failed', 'reverted', 'rollback_failed', 'superseded'])
const telemetryExclusions = new Set(['', 'platform_scope', 'invalid_config_version', 'telemetry_site_limit'])

function optionalUUID(value: unknown): boolean {
  return value === null || (typeof value === 'string' && uuidPattern.test(value))
}

function configurationScope(value: unknown): value is NodeConfigurationScope {
  if (!record(value)) return false
  const deployment = value.latest_deployment
  const apply = value.last_apply
  return typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    (value.scope_kind === 'platform' || value.scope_kind === 'tenant') && optionalUUID(value.tenant_id) &&
    typeof value.tenant_name === 'string' && optionalUUID(value.current_config_version_id) &&
    optionalUUID(value.previous_config_version_id) && typeof value.reconciliation_required === 'boolean' &&
    timestamp(value.updated_at) &&
    typeof value.telemetry_excluded === 'string' && telemetryExclusions.has(value.telemetry_excluded) &&
    (deployment === null || (record(deployment) && typeof deployment.deployment_id === 'string' &&
      uuidPattern.test(deployment.deployment_id) && Number.isInteger(deployment.attempt) &&
      typeof deployment.rollout_id === 'string' && typeof deployment.config_version_id === 'string' &&
      (deployment.action === 'apply' || deployment.action === 'rollback') &&
      typeof deployment.state === 'string' && deploymentStates.has(deployment.state) && timestamp(deployment.updated_at))) &&
    (apply === null || (record(apply) && typeof apply.deployment_id === 'string' && uuidPattern.test(apply.deployment_id) &&
      Number.isInteger(apply.attempt) && typeof apply.config_version_id === 'string' &&
      typeof apply.state === 'string' && applyStates.has(apply.state) &&
      (apply.error_code === null || typeof apply.error_code === 'string') &&
      (apply.finished_at === null || timestamp(apply.finished_at)) && timestamp(apply.reported_at)))
}

const regressionFeatures = new Set<string>(['cc_proof_of_work', 'waf_crs_module', 'l4_tls_passthrough', 'l4_additional_listeners', 'l4_toa'])

function capabilityRegression(value: unknown): value is NodeCapabilityRegression {
  return record(value) && typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.deployment_id === 'string' && uuidPattern.test(value.deployment_id) &&
    typeof value.config_version_id === 'string' && uuidPattern.test(value.config_version_id) &&
    typeof value.feature === 'string' && typeof value.capability === 'string' &&
    Number.isInteger(value.required) && Number.isInteger(value.declared) && typeof value.agent_version === 'string'
}

function scopeRejection(value: unknown): value is NodeScopeRejection {
  return record(value) && typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.tenant_name === 'string' && typeof value.reason === 'string' &&
    typeof value.request_id === 'string' && timestamp(value.occurred_at)
}

async function getIPLocation(accessToken: string, id: string): Promise<NodeIPLocationView> {
  if (!uuidPattern.test(id)) throw new ApiError('Invalid node identifier', 400, 'validation_error')
  let value: unknown
  try {
    value = await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(id)}/ip-location`)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
  if (!ipLocationView(value, id)) throw invalidInventoryResponse()
  return value
}

async function getConfigurationScopes(accessToken: string, id: string): Promise<NodeConfigurationScopes> {
  if (!uuidPattern.test(id)) throw new ApiError('Invalid node identifier', 400, 'validation_error')
  let value: unknown
  try {
    value = await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(id)}/configuration-scopes`)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
  const regressions = record(value) ? value.capability_regressions : undefined
  if (!record(value) || value.node_id !== id || !Array.isArray(value.scopes) || !Array.isArray(value.rejections) ||
    !value.scopes.every(configurationScope) || !value.rejections.every(scopeRejection) ||
    !Array.isArray(regressions) || !regressions.every(capabilityRegression)) {
    throw invalidInventoryResponse()
  }
  // A newer control plane may name features this console cannot explain yet.
  return { ...value, capability_regressions: regressions.filter((item) => regressionFeatures.has(item.feature)) } as unknown as NodeConfigurationScopes
}

async function getLatestMetrics(accessToken: string, id: string): Promise<NodeMetricsLatest> {
  if (!uuidPattern.test(id)) throw new ApiError('Invalid node identifier', 400, 'validation_error')
  let value: unknown
  try {
    value = await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(id)}/metrics/latest`)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
  return metricsLatest(value, id)
}

async function getLatestMetricsBatch(
  accessToken: string,
  ids: readonly string[],
  signal?: AbortSignal,
): Promise<NodeMetricsLatestBatch> {
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 300 ||
    ids.some((id) => typeof id !== 'string' || !uuidPattern.test(id)) || new Set(ids).size !== ids.length) {
    throw new ApiError('Invalid node metrics batch identifiers', 400, 'validation_error')
  }
  const query = new URLSearchParams(ids.map((id) => ['node_id', id]))
  let value: unknown
  try {
    value = await request<unknown>(accessToken, `/v1/nodes/metrics/latest?${query}`, { signal, cache: 'no-store' })
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
  if (!record(value) || !exactKeys(value, ['observed_at', 'items', 'not_reported_node_ids']) ||
    !timestamp(value.observed_at) || !value.observed_at.endsWith('Z') ||
    !Array.isArray(value.items) || !Array.isArray(value.not_reported_node_ids) ||
    value.items.length + value.not_reported_node_ids.length !== ids.length) throw invalidInventoryResponse()
  const remaining = new Set(ids)
  const items = value.items.map((item: unknown) => {
    if (!record(item) || typeof item.node_id !== 'string' || !remaining.delete(item.node_id)) throw invalidInventoryResponse()
    return metricsLatest(item, item.node_id)
  })
  for (const id of value.not_reported_node_ids) {
    if (typeof id !== 'string' || !remaining.delete(id)) throw invalidInventoryResponse()
  }
  if (remaining.size) throw invalidInventoryResponse()
  return { observed_at: value.observed_at, items, not_reported_node_ids: value.not_reported_node_ids as string[] }
}

async function getMetricsHistory(
  accessToken: string,
  id: string,
  params: NodeMetricsHistoryParams,
): Promise<NodeMetricsHistoryResponse> {
  if (!uuidPattern.test(id) || !timestamp(params.from) || !timestamp(params.to) ||
    Date.parse(params.to) < Date.parse(params.from) || !positiveInteger(params.limit) || params.limit > 2000) {
    throw new ApiError('Invalid node metrics history parameters', 400, 'validation_error')
  }
  const query = new URLSearchParams({ from: params.from, to: params.to, limit: String(params.limit) })
  try {
    return metricsHistory(
      await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(id)}/metrics/history?${query}`),
      id,
      params.limit,
    )
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function getNodeRealtimeTop(
  accessToken: string,
  params: NodeRealtimeTopParams,
): Promise<NodeRealtimeTopResponse> {
  const recentTime = params.recentTime ?? '1m'
  if (!/^[1-9][0-9]{0,3}(s|m|h)$/.test(recentTime) || !['bandwidth', 'connections', 'load', 'disk'].includes(params.type) ||
    (params.limit !== undefined && (!positiveInteger(params.limit) || params.limit > 300))) {
    throw new ApiError('Invalid node realtime ranking parameters', 400, 'validation_error')
  }
  const query = new URLSearchParams({ recent_time: recentTime, type: params.type })
  if (params.externalOnly !== undefined) {
    if (typeof params.externalOnly !== 'boolean') throw new ApiError('Invalid network scope', 400, 'validation_error')
    query.set('external_only', String(params.externalOnly))
  }
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  try {
    return realtimeTop(await request<unknown>(accessToken, `/v1/monitor/node/top?${query}`), params.limit ?? 100)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function getNodeRealtimeSeries(
  accessToken: string,
  params: NodeRealtimeSeriesParams,
): Promise<NodeRealtimeResponse> {
  if (!uuidPattern.test(params.node) || !timestamp(params.start) || !timestamp(params.end) ||
    Date.parse(params.end) < Date.parse(params.start) || !['bandwidth', 'connections', 'load', 'disk'].includes(params.type) ||
    (params.limit !== undefined && (!positiveInteger(params.limit) || params.limit > 2000))) {
    throw new ApiError('Invalid node realtime series parameters', 400, 'validation_error')
  }
  const query = new URLSearchParams({ type: params.type, start: params.start, end: params.end, node: params.node })
  if (params.externalOnly !== undefined) {
    if (typeof params.externalOnly !== 'boolean') throw new ApiError('Invalid network scope', 400, 'validation_error')
    query.set('external_only', String(params.externalOnly))
  }
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  try {
    return realtimeResponse(await request<unknown>(accessToken, `/v1/monitor/node/realtime?${query}`), params.limit ?? 2000)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function getNodeTraffic(
  accessToken: string,
  params: NodeTrafficParams,
): Promise<NodeTrafficResponse> {
  if (!uuidPattern.test(params.node) || !timestamp(params.start) || !timestamp(params.end) ||
    Date.parse(params.end) < Date.parse(params.start) ||
    (params.limit !== undefined && (!positiveInteger(params.limit) || params.limit > 2000))) {
    throw new ApiError('Invalid node traffic parameters', 400, 'validation_error')
  }
  const query = new URLSearchParams({ start: params.start, end: params.end, node: params.node })
  if (params.externalOnly !== undefined) {
    if (typeof params.externalOnly !== 'boolean') throw new ApiError('Invalid network scope', 400, 'validation_error')
    query.set('external_only', String(params.externalOnly))
  }
  const excludedNIC = params.excludedNIC?.trim()
  if (excludedNIC) query.set('excl_nic', excludedNIC)
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  try {
    return nodeTraffic(await request<unknown>(accessToken, `/v1/node-traffic?${query}`), params.limit ?? 2000)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function createGatewayPortTransition(
  accessToken: string,
  nodeID: string,
  input: CreateNodeGatewayPortTransitionRequest,
  idempotencyKey: string,
): Promise<NodeGatewayPortTransition> {
  if (!uuidPattern.test(nodeID)) throw new ApiError('Invalid node identifier', 400, 'validation_error')
  try {
    return gatewayPortTransition(await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(nodeID)}/gateway-port-transitions`, {
      method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(input),
    }), nodeID)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function getGatewayPortTransition(
  accessToken: string,
  nodeID: string,
  transitionID: string,
): Promise<NodeGatewayPortTransition> {
  if (!uuidPattern.test(nodeID) || !uuidPattern.test(transitionID)) {
    throw new ApiError('Invalid gateway port transition identifier', 400, 'validation_error')
  }
  try {
    return gatewayPortTransition(await request<unknown>(accessToken,
      `/v1/nodes/${encodeURIComponent(nodeID)}/gateway-port-transitions/${encodeURIComponent(transitionID)}`), nodeID)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

async function gatewayPortTransitionAction(
  accessToken: string,
  nodeID: string,
  transitionID: string,
  action: 'finalize' | 'rollback',
  idempotencyKey: string,
  requestID = idempotencyKey,
): Promise<NodeGatewayPortTransition> {
  if (!uuidPattern.test(nodeID) || !uuidPattern.test(transitionID)) {
    throw new ApiError('Invalid gateway port transition identifier', 400, 'validation_error')
  }
  if (!uuidPattern.test(requestID) || !/^[A-Za-z0-9._-]{1,128}$/.test(idempotencyKey)) {
    throw new ApiError('Invalid gateway port transition request identity', 400, 'validation_error')
  }
  try {
    return gatewayPortTransition(await request<unknown>(accessToken,
      `/v1/nodes/${encodeURIComponent(nodeID)}/gateway-port-transitions/${encodeURIComponent(transitionID)}/${action}`,
      { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID } }), nodeID)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidInventoryResponse()
  }
}

function create(accessToken: string, input: CreateNodeRequest, idempotencyKey: string): Promise<CreateNodeResponse> {
  return request(accessToken, '/v1/nodes', {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  })
}

function issueEnrollmentToken(
  accessToken: string,
  id: string,
  input: IssueEnrollmentTokenRequest,
): Promise<IssuedEnrollmentToken> {
  return request(accessToken, `/v1/nodes/${encodeURIComponent(id)}/enrollment-tokens`, {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

function getRegistrationCredential(accessToken: string): Promise<NodeRegistrationCredential> {
  return request(accessToken, '/v1/nodes/registration-credential')
}

function resetRegistrationCredential(accessToken: string): Promise<NodeRegistrationCredential> {
  return request(accessToken, '/v1/nodes/registration-credential/reset', { method: 'POST' })
}

async function update(
  accessToken: string,
  item: Pick<NodeRecord, 'id' | 'revision'>,
  input: UpdateNodeRequest,
  idempotencyKey: string,
): Promise<NodeRecord> {
  const value = await request<unknown>(accessToken, `/v1/nodes/${encodeURIComponent(item.id)}`, {
    method: 'PATCH',
    headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${item.revision}"` },
    body: JSON.stringify(input),
  })
  if (!nodeRecord(value) || value.id !== item.id) throw invalidInventoryResponse()
  return value
}

function batchAdminState(
  accessToken: string,
  input: BatchNodeAdminStateRequest,
  idempotencyKey: string,
): Promise<BatchNodeAdminStateResponse> {
  return request(accessToken, '/v1/nodes/batch-admin-state', {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  })
}

export const nodesApi = {
  batchAdminState, create, createGatewayPortTransition, gatewayPortTransitionAction, get, getConfigurationScopes,
  getGatewayPortTransition, getIPLocation,
  getLatestMetrics, getLatestMetricsBatch, getMetricsHistory, getNodeRealtimeSeries, getNodeRealtimeTop, getNodeTraffic,
  getRegistrationCredential, issueEnrollmentToken, list, resetRegistrationCredential, update,
}

export const regionsApi = {
  create: createRegion, delete: deleteRegion, get: getRegion, list: listRegions, update: updateRegion,
}

const schedule302HostnamePattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u

/** A node direct hostname for HTTP 302 scheduling: a lower-case hostname, not an IP. */
export function isSchedule302Hostname(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 4 && value.length <= 253 && schedule302HostnamePattern.test(value)
}
