import { ApiError, networkApiError, responseApiError } from './auth'

export type NodeHealthStatus = 'unknown' | 'healthy' | 'unhealthy'
export type NodeLineGroupFailoverMode =
  | 'primary_offline'
  | 'online_less_than_backup_count'
export type SchedulingStrategy = 'weighted_baseline' | 'weighted_rendezvous' | 'p2c_least_loaded'
export type SchedulingReason =
  | 'baseline_weighted_selected'
  | 'weighted_rendezvous_selected'
  | 'p2c_least_loaded_selected'
  | 'telemetry_insufficient'
  | 'telemetry_stale_fallback'
  | 'telemetry_unavailable_fallback'
  | 'single_candidate_fallback'
  | 'no_healthy_endpoint'
export type SchedulingTierReason = 'primary_priority_selected' | 'backup_priority_selected' | 'no_healthy_endpoint'
export type EndpointDisposition =
  | 'candidate'
  | 'standby'
  | 'disabled'
  | 'selector_mismatch'
  | 'less_specific'
  | 'health_unknown'
  | 'health_unhealthy'
  | 'health_stale'

export interface NodeEndpointHealth {
  status: NodeHealthStatus
  consecutive_successes: number
  consecutive_failures: number
  last_sequence: number
  last_observed_at?: string | null
  last_changed_at: string
  row_revision: number
}

export interface NodeLineEndpoint {
  id: string
  display_id?: string
  node_id: string
  address: string
  port: number
  region: string
  carrier: string
  priority: number
  sort_order?: number
  weight: number
  enabled: boolean
  health: NodeEndpointHealth
  /** Whether DNS publishes this IP now (node_line_endpoint_published); absent when unknown. */
  published?: boolean
}

export interface NodeHealthPolicy {
  probe_interval_ms: number
  probe_timeout_ms: number
  failure_threshold: number
  recovery_threshold: number
  failure_debounce_ms: number
  recovery_debounce_ms: number
}

export interface NodeLineGroupStatistics {
  node_count: number
  site_count: number
  forward_count: number
}

/** One address family's backup IP state (node_line_group_backup_states, migration 571). */
export interface NodeLineBackupState {
  address_family: 4 | 6
  /** backup_active: the primary IPs are held out and DNS resolves to the standby IPs. */
  state: 'normal' | 'backup_active'
  backup_addresses: string[]
  changed_at: string
}

export interface NodeLineGroup {
  id: string
  display_id: string
  tenant_scope_id: string
  revision: number
  name: string
  region: string
  resolved_value: string
  ipv4_resolved_value?: string | null
  l2_config_id?: string | null
  failover_mode?: NodeLineGroupFailoverMode
  note: string
  sort_order: number
  health_policy: NodeHealthPolicy
  endpoints: NodeLineEndpoint[]
  statistics?: NodeLineGroupStatistics
  configuration_digest: string
  created_by_user_id: string
  created_at: string
  sealed_at: string
  /** Platform default line group: sites without a package freeze CNAME targets from it. */
  is_platform_default?: boolean
  /** List/current reads only; a family never switched to backup is absent (normal). */
  backup_states?: NodeLineBackupState[]
  /** Optional compatibility projections returned by newer control APIs. */
  mode?: 'cache' | 'global'
  load_method?: 'round-robin' | 'url-hash'
}

export interface NodeLineGroupPage {
  items: NodeLineGroup[]
}

export interface NodeLineGroupSnapshotInput {
  name: string
  region?: string
  resolved_value?: string
  ipv4_resolved_value?: string
  l2_config_id?: string | null
  failover_mode?: NodeLineGroupFailoverMode
  note?: string
  sort_order?: number
  health_policy: NodeHealthPolicy
  endpoints: Array<Omit<NodeLineEndpoint, 'health' | 'display_id' | 'published'>>
}

export interface SchedulingSelector {
  region: string
  carrier: string
}

export interface SchedulingDecisionInput {
  selector: SchedulingSelector
  requested_mode: SchedulingStrategy
  stable_key: string
}

export interface SchedulingDecision {
  endpoint: NodeLineEndpoint
  requested_mode: SchedulingStrategy
  effective_mode: SchedulingStrategy
  reason: SchedulingReason
  fallback: boolean
  priority: number
  candidates: NodeLineEndpoint[]
  standby: NodeLineEndpoint[]
  snapshot: SchedulingDecisionSnapshot
}

export interface SchedulingEndpointEvaluation {
  endpoint: NodeLineEndpoint
  disposition: EndpointDisposition
  health_status: NodeHealthStatus
  health_row_revision: number
  last_observed_at: string | null
  last_received_at: string | null
}

export interface SchedulingDecisionSnapshot {
  tenant_scope_id: string
  group_id: string
  revision: number
  configuration_digest: string
  plan_digest: string
  selector: SchedulingSelector
  evaluated_at: string
  selected_priority: number | null
  tier_reason: SchedulingTierReason
  endpoint_evaluations: SchedulingEndpointEvaluation[]
}

export interface NodeTargetSnapshotInput {
  source_revision: number
  node_ids: string[]
}

export interface NodeTargetSnapshot {
  id: string
  revision: number
  tenant_scope_id: string
  source_line_group_id: string
  source_revision: number
  source_configuration_digest: string
  node_set_digest: string
  node_ids: string[]
}

export interface NodeLineGroupRollbackInput {
  source_revision: number
}

export interface NodeLineGroupWriteResult {
  group: NodeLineGroup
  replayed: boolean
}

export function validateNodeLineGroupResponse(value: unknown): NodeLineGroup {
  const object = (item: unknown): item is Record<string, unknown> =>
    typeof item === 'object' && item !== null && !Array.isArray(item)
  const fields = (item: unknown, required: string[], optional: string[] = []): item is Record<string, unknown> =>
    object(item) && required.every((key) => Object.hasOwn(item, key)) &&
    Object.keys(item).every((key) => required.includes(key) || optional.includes(key))
  const uuid = (item: unknown) => typeof item === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(item)
  const integer = (item: unknown, min: number, max = Number.MAX_SAFE_INTEGER) =>
    typeof item === 'number' && Number.isSafeInteger(item) && item >= min && item <= max
  const text = (item: unknown, min: number, max: number) => typeof item === 'string' &&
    !/\p{Cc}/u.test(item) && Array.from(item.trim()).length >= min && Array.from(item).length <= max
  const label = (item: unknown) => typeof item === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(item)
  const timestamp = (item: unknown) => typeof item === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(item) && Number.isFinite(Date.parse(item))
  const ip = (item: unknown) => {
    if (typeof item !== 'string') return false
    if (item.split('.').length === 4 && item.split('.').every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) return true
    if (!item.includes(':') || !/^[0-9a-f:.]+$/i.test(item)) return false
    try { return Boolean(new URL(`http://[${item}]/`).hostname) } catch { return false }
  }
  const invalid = () => new ApiError('Invalid line group response', 200, 'invalid_response')
  if (!fields(value, ['id', 'display_id', 'tenant_scope_id', 'revision', 'name', 'region', 'resolved_value',
    'note', 'sort_order', 'health_policy', 'endpoints', 'configuration_digest', 'created_by_user_id', 'created_at', 'sealed_at'],
  ['ipv4_resolved_value', 'l2_config_id', 'failover_mode', 'statistics', 'mode', 'load_method', 'is_platform_default', 'backup_states']) ||
    !uuid(value.id) || !uuid(value.tenant_scope_id) || !uuid(value.created_by_user_id) ||
    typeof value.display_id !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.display_id) ||
    !integer(value.revision, 1) || !text(value.name, 1, 128) || !text(value.region, 0, 64) || !text(value.note, 0, 512) ||
    !label(value.resolved_value) || !integer(value.sort_order, 1, 2147483647) ||
    typeof value.configuration_digest !== 'string' || !/^[0-9a-f]{64}$/.test(value.configuration_digest) ||
    !timestamp(value.created_at) || !timestamp(value.sealed_at) ||
    ('ipv4_resolved_value' in value && value.ipv4_resolved_value !== null && !label(value.ipv4_resolved_value)) ||
    ('l2_config_id' in value && value.l2_config_id !== null && !uuid(value.l2_config_id)) ||
    ('failover_mode' in value && !['primary_offline', 'online_less_than_backup_count'].includes(String(value.failover_mode))) ||
    ('mode' in value && !['cache', 'global'].includes(String(value.mode))) ||
    ('is_platform_default' in value && typeof value.is_platform_default !== 'boolean') ||
    ('load_method' in value && !['round-robin', 'url-hash'].includes(String(value.load_method)))) throw invalid()
  const policy = value.health_policy
  if (!fields(policy, ['probe_interval_ms', 'probe_timeout_ms', 'failure_threshold', 'recovery_threshold', 'failure_debounce_ms', 'recovery_debounce_ms']) ||
    !integer(policy.probe_interval_ms, 1000, 300000) || !integer(policy.probe_timeout_ms, 100, 60000) ||
    Number(policy.probe_timeout_ms) > Number(policy.probe_interval_ms) ||
    !integer(policy.failure_threshold, 1, 20) || !integer(policy.recovery_threshold, 1, 20) ||
    !integer(policy.failure_debounce_ms, 0, 3600000) || !integer(policy.recovery_debounce_ms, 0, 3600000)) throw invalid()
  if ('backup_states' in value && (!Array.isArray(value.backup_states) || value.backup_states.length > 2 ||
    !value.backup_states.every((state) => fields(state, ['address_family', 'state', 'backup_addresses', 'changed_at']) &&
      (state.address_family === 4 || state.address_family === 6) && ['normal', 'backup_active'].includes(String(state.state)) &&
      Array.isArray(state.backup_addresses) && state.backup_addresses.length <= 512 && state.backup_addresses.every(ip) &&
      timestamp(state.changed_at)))) throw invalid()
  if ('statistics' in value && (!fields(value.statistics, ['node_count', 'site_count', 'forward_count']) ||
    !Object.values(value.statistics).every((count) => integer(count, 0)))) throw invalid()
  const endpoints = value.endpoints
  if (!Array.isArray(endpoints) || endpoints.length > 512 || !endpoints.every((endpoint) => {
    if (!fields(endpoint, ['id', 'node_id', 'address', 'port', 'region', 'carrier', 'priority', 'weight', 'enabled', 'health'], ['sort_order', 'display_id', 'published']) ||
      !uuid(endpoint.id) || !uuid(endpoint.node_id) || !ip(endpoint.address) || !integer(endpoint.port, 1, 65535) ||
      !text(endpoint.region, 0, 64) || !text(endpoint.carrier, 0, 64) || !integer(endpoint.priority, 0, 65535) ||
      !integer(endpoint.weight, 1, 100) || typeof endpoint.enabled !== 'boolean' ||
      ('sort_order' in endpoint && !integer(endpoint.sort_order, 0, 999999)) ||
      ('published' in endpoint && typeof endpoint.published !== 'boolean') ||
      ('display_id' in endpoint && (typeof endpoint.display_id !== 'string' || !/^[1-9][0-9]{0,18}$/.test(endpoint.display_id) ||
        BigInt(endpoint.display_id) > 9223372036854775807n))) return false
    const health = endpoint.health
    return fields(health, ['status', 'consecutive_successes', 'consecutive_failures', 'last_sequence', 'row_revision'], ['last_observed_at', 'last_changed_at']) &&
      ['unknown', 'healthy', 'unhealthy'].includes(String(health.status)) && integer(health.consecutive_successes, 0) &&
      integer(health.consecutive_failures, 0) && integer(health.last_sequence, 0) && integer(health.row_revision, 1) &&
      (!('last_observed_at' in health) || health.last_observed_at === null || timestamp(health.last_observed_at)) &&
      (!('last_changed_at' in health) || timestamp(health.last_changed_at))
  }) || new Set(endpoints.map((endpoint) => endpoint.id)).size !== endpoints.length ||
    new Set(endpoints.filter((endpoint) => endpoint.display_id !== undefined).map((endpoint) => endpoint.display_id)).size !==
      endpoints.filter((endpoint) => endpoint.display_id !== undefined).length) throw invalid()
  return value as unknown as NodeLineGroup
}

export function validateLineResolutionWriteResponse(value: unknown, groupID: string, scopeID: string, expectedRevision: number): NodeLineGroup {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== 'group,replayed' || !('replayed' in value) || typeof value.replayed !== 'boolean' || !('group' in value))
    throw new ApiError('Invalid line write response', 200, 'invalid_response')
  const group = validateNodeLineGroupResponse(value.group)
  if (group.id !== groupID || group.tenant_scope_id !== scopeID || !Number.isSafeInteger(expectedRevision) ||
    expectedRevision < 1 || expectedRevision >= Number.MAX_SAFE_INTEGER || group.revision !== expectedRevision + 1 ||
    typeof group.ipv4_resolved_value !== 'string' || !Object.hasOwn(group, 'l2_config_id') || !group.failover_mode)
    throw new ApiError('Invalid line write response', 200, 'invalid_response')
  return group
}

export interface L2Config {
  id: string
  display_id: string
  tenant_scope_id: string
  revision: number
  name: string
  region: string
  remark: string
  mode: 'cache' | 'global'
  load_method: 'rr' | 'url_hash'
  created_at: string
  updated_at: string
}

export type L2ConfigInput = Pick<L2Config, 'name' | 'region' | 'remark' | 'mode' | 'load_method'>
export interface L2Rule {
  field: 'host' | 'request_uri' | 'uri' | 'node_country' | 'node_isp' | 'node_province' | 'node_city' | 'node_id' | 'protocol'
  operator: 'eq' | 'neq' | 'contains' | 'not_contains' | 'prefix' | 'suffix' | 'regex' | 'not_regex'
  value: string
}
export interface L2Condition {
  id: string
  display_id: string
  tenant_scope_id: string
  revision: number
  name: string
  remark: string
  rules: L2Rule[]
  created_at: string
  updated_at: string
}
export type L2ConditionInput = Pick<L2Condition, 'name' | 'remark' | 'rules'>
export interface L2NodeCandidate {
  node_id: string
  display_id: string
  name: string
  ip_address: string
  admin_state: string
  online_status: 'online' | 'offline' | 'unknown'
}
export interface L2Node extends L2NodeCandidate {
  id: string
  tenant_scope_id: string
  config_id: string
  condition_id: string | null
  condition_name: string | null
  revision: number
  enabled: boolean
  weight: number
  sort: number
}
export type L2NodeInput = Pick<L2Node, 'condition_id' | 'enabled' | 'weight' | 'sort'>

export type NodeSchedulingScope =
  | { kind: 'tenant' }
  | { kind: 'platform'; targetScopeId: string }

export interface NodeSchedulingCommandMetadata {
  requestId: string
  idempotencyKey: string
}

export interface NodeSchedulingWriteMetadata extends NodeSchedulingCommandMetadata {
  expectedRevision: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function generatedRequestID(action: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `node-scheduling-${action}-${suffix}`
}

async function request<T>(
  accessToken: string,
  path: string,
  action: string,
  init: RequestInit = {},
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': generatedRequestID(action),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError('Invalid API response', response.status, 'invalid_response')
  }
}

function writeHeaders(metadata: NodeSchedulingWriteMetadata): HeadersInit {
  return {
    'X-Request-ID': metadata.requestId,
    'Idempotency-Key': metadata.idempotencyKey,
    'If-Match': `"${metadata.expectedRevision}"`,
  }
}

function commandHeaders(metadata: NodeSchedulingCommandMetadata): HeadersInit {
  return {
    'X-Request-ID': metadata.requestId,
    'Idempotency-Key': metadata.idempotencyKey,
  }
}

function scopedPath(path: string, scope: NodeSchedulingScope): string {
  if (scope.kind === 'tenant') return path
  const query = new URLSearchParams({ target_scope_id: scope.targetScopeId })
  return `${path}?${query}`
}

function list(accessToken: string, scope: NodeSchedulingScope): Promise<NodeLineGroupPage> {
  return request(accessToken, scopedPath('/v1/node-line-groups', scope), 'list')
}

function create(
  accessToken: string,
  input: NodeLineGroupSnapshotInput,
  metadata: NodeSchedulingWriteMetadata,
): Promise<NodeLineGroupWriteResult> {
  return request(accessToken, '/v1/node-line-groups', 'create', {
    method: 'POST',
    headers: writeHeaders(metadata),
    body: JSON.stringify(input),
  })
}

function get(accessToken: string, scope: NodeSchedulingScope, groupID: string): Promise<NodeLineGroup> {
  const path = `/v1/node-line-groups/${encodeURIComponent(groupID)}`
  return request(accessToken, scopedPath(path, scope), 'detail')
}

function update(
  accessToken: string,
  groupID: string,
  input: NodeLineGroupSnapshotInput,
  metadata: NodeSchedulingWriteMetadata,
): Promise<NodeLineGroupWriteResult> {
  return request(accessToken, `/v1/node-line-groups/${encodeURIComponent(groupID)}`, 'update', {
    method: 'PUT',
    headers: writeHeaders(metadata),
    body: JSON.stringify(input),
  })
}

function remove(
  accessToken: string,
  groupID: string,
  metadata: NodeSchedulingWriteMetadata,
): Promise<void> {
  return request(accessToken, `/v1/node-line-groups/${encodeURIComponent(groupID)}`, 'delete', {
    method: 'DELETE',
    headers: writeHeaders(metadata),
  })
}

function getRevision(
  accessToken: string,
  scope: NodeSchedulingScope,
  groupID: string,
  revision: number,
): Promise<NodeLineGroup> {
  const path = `/v1/node-line-groups/${encodeURIComponent(groupID)}/revisions/${revision}`
  return request(
    accessToken,
    scopedPath(path, scope),
    'revision',
  )
}

function getTargetSnapshot(
  accessToken: string,
  scope: NodeSchedulingScope,
  groupID: string,
  sourceRevision: number,
): Promise<NodeTargetSnapshot> {
  const query = new URLSearchParams({ source_revision: String(sourceRevision) })
  if (scope.kind === 'platform') query.set('target_scope_id', scope.targetScopeId)
  const path = `/v1/node-line-groups/${encodeURIComponent(groupID)}/target-snapshots?${query}`
  return request(accessToken, path, 'target-snapshot-detail')
}

function decide(
  accessToken: string,
  scope: NodeSchedulingScope,
  groupID: string,
  input: SchedulingDecisionInput,
): Promise<SchedulingDecision> {
  const path = `/v1/node-line-groups/${encodeURIComponent(groupID)}/decisions`
  return request(accessToken, scopedPath(path, scope), 'decision', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

function createTargetSnapshot(
  accessToken: string,
  groupID: string,
  input: NodeTargetSnapshotInput,
  metadata: NodeSchedulingCommandMetadata,
): Promise<NodeTargetSnapshot> {
  return request(
    accessToken,
    `/v1/node-line-groups/${encodeURIComponent(groupID)}/target-snapshots`,
    'target-snapshot',
    { method: 'POST', headers: commandHeaders(metadata), body: JSON.stringify(input) },
  )
}

function rollback(
  accessToken: string,
  groupID: string,
  input: NodeLineGroupRollbackInput,
  metadata: NodeSchedulingWriteMetadata,
): Promise<NodeLineGroupWriteResult> {
  return request(accessToken, `/v1/node-line-groups/${encodeURIComponent(groupID)}/rollback`, 'rollback', {
    method: 'POST',
    headers: writeHeaders(metadata),
    body: JSON.stringify(input),
  })
}

// Platform scope only; the line group revision does not advance.
function setPlatformDefault(
  accessToken: string,
  groupID: string,
  isPlatformDefault: boolean,
  metadata: NodeSchedulingCommandMetadata,
): Promise<{ group: NodeLineGroup }> {
  return request(accessToken, `/v1/node-line-groups/${encodeURIComponent(groupID)}/platform-default`, 'platform-default', {
    method: 'POST',
    headers: commandHeaders(metadata),
    body: JSON.stringify({ is_platform_default: isPlatformDefault }),
  })
}

export const nodeSchedulingApi = {
  create,
  createTargetSnapshot,
  decide,
  get,
  getRevision,
  getTargetSnapshot,
  list,
  remove,
  rollback,
  setPlatformDefault,
  update,
}

// L2 topology is a separate resource from DNS line groups. The server derives
// the current control scope from the authenticated principal for these calls.
export const l2TopologyApi = {
  configs: (token: string, scope?: NodeSchedulingScope): Promise<{ items: L2Config[] }> => request(token,
    scope ? scopedPath('/v1/l2-configs', scope) : '/v1/l2-configs', 'l2-config-list'),
  config: (token: string, id: string): Promise<L2Config> => request(token, `/v1/l2-configs/${encodeURIComponent(id)}`, 'l2-config'),
  saveConfig: (token: string, id: string | null, input: L2ConfigInput, metadata: NodeSchedulingWriteMetadata): Promise<L2Config> => request(
    token, id ? `/v1/l2-configs/${encodeURIComponent(id)}` : '/v1/l2-configs', 'l2-config-save',
    { method: id ? 'PUT' : 'POST', headers: writeHeaders(metadata), body: JSON.stringify(input) },
  ),
  removeConfig: (token: string, id: string, metadata: NodeSchedulingWriteMetadata): Promise<void> => request(
    token, `/v1/l2-configs/${encodeURIComponent(id)}`, 'l2-config-delete', { method: 'DELETE', headers: writeHeaders(metadata) },
  ),
  conditions: (token: string): Promise<{ items: L2Condition[] }> => request(token, '/v1/l2-conds', 'l2-condition-list'),
  saveCondition: (token: string, id: string | null, input: L2ConditionInput, metadata: NodeSchedulingWriteMetadata): Promise<L2Condition> => request(
    token, id ? `/v1/l2-conds/${encodeURIComponent(id)}` : '/v1/l2-conds', 'l2-condition-save',
    { method: id ? 'PUT' : 'POST', headers: writeHeaders(metadata), body: JSON.stringify(input) },
  ),
  removeCondition: (token: string, id: string, metadata: NodeSchedulingWriteMetadata): Promise<void> => request(
    token, `/v1/l2-conds/${encodeURIComponent(id)}`, 'l2-condition-delete', { method: 'DELETE', headers: writeHeaders(metadata) },
  ),
  nodes: (token: string, configID: string): Promise<{ items: L2Node[] }> => request(
    token, `/v1/l2-nodes?${new URLSearchParams({ config_id: configID })}`, 'l2-node-list',
  ),
  availableNodes: (token: string, configID: string): Promise<{ items: L2NodeCandidate[] }> => request(
    token, `/v1/l2-nodes?${new URLSearchParams({ config_id: configID, available: 'true' })}`, 'l2-node-available',
  ),
  addNodes: (token: string, input: { config_id: string; node_ids: string[]; condition_id: string | null }, metadata: NodeSchedulingWriteMetadata): Promise<{ items: L2Node[] }> => request(
    token, '/v1/l2-nodes', 'l2-node-add', { method: 'POST', headers: writeHeaders(metadata), body: JSON.stringify(input) },
  ),
  saveNode: (token: string, id: string, input: L2NodeInput, metadata: NodeSchedulingWriteMetadata): Promise<L2Node> => request(
    token, `/v1/l2-nodes/${encodeURIComponent(id)}`, 'l2-node-save',
    { method: 'PUT', headers: writeHeaders(metadata), body: JSON.stringify(input) },
  ),
  removeNode: (token: string, id: string, metadata: NodeSchedulingWriteMetadata): Promise<void> => request(
    token, `/v1/l2-nodes/${encodeURIComponent(id)}`, 'l2-node-delete', { method: 'DELETE', headers: writeHeaders(metadata) },
  ),
}
