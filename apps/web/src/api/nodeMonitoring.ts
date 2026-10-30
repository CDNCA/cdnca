import { ApiError, networkApiError, responseApiError } from './auth'

export interface NodeMonitoringPolicy {
  enabled: boolean
  requested_protocol: 'tcp' | 'http' | 'ping'
  requested_port: number | null
  probe_interval_ms: number
  probe_timeout_ms: number
  failure_threshold: number
  recovery_threshold: number
  failure_debounce_ms: number
  recovery_debounce_ms: number
}

export interface NodeMonitoringConfiguration {
  state: 'unconfigured' | 'not_activated' | 'active'
  head_revision: number
  active_revision: number | null
  activated_at: string | null
  policy: NodeMonitoringPolicy | null
}

export interface NodeMonitoringSample {
  source: 'agent_local_tcp' | 'agent_local_http' | 'agent_local_ping'
  config_revision: number
  active_config_revision: number
  publication_sequence: string
  observed_at: string
  ingested_at: string
  probe_port: number
  healthy: boolean
  probe_succeeded: boolean
  consecutive_failures: number
  consecutive_successes: number
  probes_total: string
  probe_failures_total: string
  recovered: boolean
  recovery_notified: boolean
  rolled_back: boolean
}

export interface NodeMonitoringLatest {
  node_id: string
  freshness: 'not_reported' | 'fresh' | 'stale' | 'clock_skew'
  revision_state: 'unknown' | 'current' | 'different' | 'rolled_back'
  stale_after_ms: number | null
  sample: NodeMonitoringSample | null
  apply_receipt?: { state: 'applied'; config_revision: string; observed_at: string }
  delivery_state: 'serving' | 'awaiting_configuration' | 'inactive'
  // Only for a node with a monitoring override under an active policy: the
  // node runs effective_policy at effective_revision instead of the platform's.
  effective_revision?: number
  effective_policy?: NodeMonitoringPolicy
  // Present only while a system hold keeps the node out of customer DNS.
  serving_holds?: NodeServingHold[]
}

export type NodeServingSource = 'availability_monitor' | 'auto_disable' | 'config_sync' | 'external_probe'

export interface NodeServingHold {
  source: NodeServingSource
  reason_code: string
  held_since: string
  // >0: still serving in that many line groups as the last endpoint of its family.
  protected_groups: number
}

const servingSources = ['availability_monitor', 'auto_disable', 'config_sync', 'external_probe'] as const
const servingReasonPattern = /^[a-z][a-z0-9_]{0,63}$/

function nodeServingHold(value: unknown): value is NodeServingHold {
  return nodeMonitoringObject(value, ['source', 'reason_code', 'held_since', 'protected_groups'])
    && (servingSources as readonly unknown[]).includes(value.source) && typeof value.reason_code === 'string'
    && servingReasonPattern.test(value.reason_code) && nodeMonitoringTime(value.held_since)
    && nodeMonitoringInteger(value.protected_groups, 0)
}

export interface NodeMonitoringLatestBatch {
  schema_version: 1
  observed_at: string
  configuration: NodeMonitoringConfiguration
  items: NodeMonitoringLatest[]
}

const nodeIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function nodeMonitoringObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

function nodeMonitoringTime(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 19) === value.slice(0, 19)
}

function nodeMonitoringInteger(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max
}

function nodeMonitoringDecimal(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,18})$/.test(value) && BigInt(value) <= 9223372036854775807n
}

function nodeMonitoringPolicy(policy: unknown): policy is NodeMonitoringPolicy {
  return nodeMonitoringObject(policy, ['enabled', 'requested_protocol', 'requested_port', 'probe_interval_ms', 'probe_timeout_ms',
    'failure_threshold', 'recovery_threshold', 'failure_debounce_ms', 'recovery_debounce_ms'])
    && typeof policy.enabled === 'boolean' && typeof policy.requested_protocol === 'string' && ['tcp', 'http', 'ping'].includes(policy.requested_protocol)
    && (policy.requested_port === null || nodeMonitoringInteger(policy.requested_port, 1, 65535))
    && nodeMonitoringInteger(policy.probe_interval_ms, 1000, 300000)
    && nodeMonitoringInteger(policy.probe_timeout_ms, 100, Math.min(60000, policy.probe_interval_ms))
    && nodeMonitoringInteger(policy.failure_threshold, 1, 20) && nodeMonitoringInteger(policy.recovery_threshold, 1, 20)
    && nodeMonitoringInteger(policy.failure_debounce_ms, 0, 3600000) && nodeMonitoringInteger(policy.recovery_debounce_ms, 0, 3600000)
}

function parseNodeMonitoringBatch(value: unknown, ids: readonly string[]): NodeMonitoringLatestBatch {
  if (!nodeMonitoringObject(value, ['schema_version', 'observed_at', 'configuration', 'items']) || value.schema_version !== 1
    || !nodeMonitoringTime(value.observed_at) || !Array.isArray(value.items) || value.items.length !== ids.length) {
    throw new ApiError('Invalid node monitoring response', 200, 'invalid_response')
  }
  const config = value.configuration
  if (!nodeMonitoringObject(config, ['state', 'head_revision', 'active_revision', 'activated_at', 'policy'])
    || !nodeMonitoringInteger(config.head_revision, 0)) throw new ApiError('Invalid monitoring configuration', 200, 'invalid_response')
  const policy = config.policy
  if (config.state === 'active') {
    if (!nodeMonitoringInteger(config.active_revision, 1, config.head_revision) || !nodeMonitoringTime(config.activated_at)
      || !nodeMonitoringPolicy(policy)) {
      throw new ApiError('Invalid active monitoring policy', 200, 'invalid_response')
    }
  } else if ((config.state !== 'unconfigured' || config.head_revision !== 0) && (config.state !== 'not_activated' || config.head_revision < 1)
    || config.active_revision !== null || config.activated_at !== null || policy !== null) {
    throw new ApiError('Invalid inactive monitoring configuration', 200, 'invalid_response')
  }
  const staleAfterFor = (effective: unknown) => {
    const active = (effective ?? policy) as NodeMonitoringPolicy | null
    return config.state === 'active' && active ? Math.min(active.probe_interval_ms + active.probe_timeout_ms + 30000, 390000) : null
  }
  for (const [index, item] of value.items.entries()) {
    const itemKeys = ['node_id', 'freshness', 'revision_state', 'delivery_state', 'stale_after_ms', 'sample']
    for (const optional of ['apply_receipt', 'effective_revision', 'effective_policy', 'serving_holds']) {
      if (typeof item === 'object' && item !== null && Object.hasOwn(item, optional)) itemKeys.push(optional)
    }
    const overridden = typeof item === 'object' && item !== null && Object.hasOwn(item, 'effective_revision')
    if (!nodeMonitoringObject(item, itemKeys)
      || !['serving', 'awaiting_configuration', 'inactive'].includes(String(item.delivery_state))
      || overridden !== Object.hasOwn(item, 'effective_policy')
      || (Object.hasOwn(item, 'serving_holds') && (!Array.isArray(item.serving_holds) || item.serving_holds.length < 1
        || item.serving_holds.length > 2 || !item.serving_holds.every(nodeServingHold)))
      || (overridden && (config.state !== 'active' || !nodeMonitoringInteger(item.effective_revision, Number(config.active_revision) + 1)
        || !nodeMonitoringPolicy(item.effective_policy) || item.effective_policy.probe_interval_ms !== (policy as NodeMonitoringPolicy).probe_interval_ms))
      || item.node_id !== ids[index] || typeof item.freshness !== 'string' || !['not_reported', 'fresh', 'stale', 'clock_skew'].includes(item.freshness)
      || typeof item.revision_state !== 'string' || !['unknown', 'current', 'different', 'rolled_back'].includes(item.revision_state)
      || item.stale_after_ms !== staleAfterFor(item.effective_policy)) {
      throw new ApiError('Invalid node monitoring item', 200, 'invalid_response')
    }
    const expectedRevision = overridden ? item.effective_revision : config.active_revision
    if (Object.hasOwn(item, 'apply_receipt')) {
      const receipt = item.apply_receipt
      if (!nodeMonitoringObject(receipt, ['state', 'config_revision', 'observed_at']) || receipt.state !== 'applied' ||
        !nodeMonitoringDecimal(receipt.config_revision) || receipt.config_revision === '0' || !nodeMonitoringTime(receipt.observed_at)) {
        throw new ApiError('Invalid node monitoring receipt', 200, 'invalid_response')
      }
    }
    const sample = item.sample
    if (sample === null) {
      if (item.freshness !== 'not_reported' || item.revision_state !== 'unknown') throw new ApiError('Invalid absent probe', 200, 'invalid_response')
      continue
    }
    if (!nodeMonitoringObject(sample, ['source', 'config_revision', 'active_config_revision', 'publication_sequence', 'observed_at', 'ingested_at',
      'probe_port', 'healthy', 'probe_succeeded', 'consecutive_failures', 'consecutive_successes', 'probes_total', 'probe_failures_total',
      'recovered', 'recovery_notified', 'rolled_back']) || !['agent_local_tcp', 'agent_local_http', 'agent_local_ping'].includes(String(sample.source))
      || !nodeMonitoringInteger(sample.config_revision, 1) || !nodeMonitoringInteger(sample.active_config_revision, 1)
      || !nodeMonitoringDecimal(sample.publication_sequence) || sample.publication_sequence === '0'
      || !nodeMonitoringTime(sample.observed_at) || !nodeMonitoringTime(sample.ingested_at) || !nodeMonitoringInteger(sample.probe_port, 1, 65535)
      || !nodeMonitoringInteger(sample.consecutive_failures, 0, 20) || !nodeMonitoringInteger(sample.consecutive_successes, 0, 20)
      || !nodeMonitoringDecimal(sample.probes_total) || !nodeMonitoringDecimal(sample.probe_failures_total)
      || BigInt(sample.probe_failures_total) > BigInt(sample.probes_total)
      || !['healthy', 'probe_succeeded', 'recovered', 'recovery_notified', 'rolled_back'].every((key) => typeof sample[key] === 'boolean')
      || item.freshness === 'not_reported' || (sample.rolled_back !== (item.revision_state === 'rolled_back'))
      || (config.state !== 'active' && (item.freshness === 'fresh' || (!sample.rolled_back && item.revision_state !== 'unknown')))
      || (config.state === 'active' && item.revision_state === 'unknown')
      || (item.revision_state === 'current' && (sample.config_revision !== expectedRevision
        || sample.active_config_revision !== expectedRevision || Date.parse(sample.observed_at) < Date.parse(String(config.activated_at))))) {
      throw new ApiError('Invalid node probe sample', 200, 'invalid_response')
    }
  }
  return value as unknown as NodeMonitoringLatestBatch
}

async function getLatestNodeMonitoring(accessToken: string, ids: readonly string[], signal?: AbortSignal): Promise<NodeMonitoringLatestBatch> {
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 300 || new Set(ids).size !== ids.length
    || ids.some((id) => typeof id !== 'string' || !nodeIDPattern.test(id))) {
    throw new ApiError('Invalid node monitoring identifiers', 400, 'validation_error')
  }
  let response: Response
  try {
    response = await fetch(`/v1/nodes/monitoring/latest?${new URLSearchParams(ids.map((id) => ['node_id', id]))}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid monitoring JSON', 200, 'invalid_response') }
  return parseNodeMonitoringBatch(value, ids)
}

export interface NodeMonitoringHistoryItem {
  observed_at: string
  config_revision: number
  active_config_revision: number
  probe_port: number
  probe_succeeded: boolean
  healthy: boolean
  failed_checks: 0 | 1
  total_checks: 1
}

export interface NodeMonitoringHistoryPage {
  schema_version: 1
  node_id: string
  from: string
  to: string
  page: number
  limit: number
  total: number
  items: NodeMonitoringHistoryItem[]
}

export const nodeMonitoringHistoryMaxWindowMs = 7 * 24 * 60 * 60 * 1000

function parseNodeMonitoringHistory(value: unknown, nodeID: string, page: number, limit: number): NodeMonitoringHistoryPage {
  if (!nodeMonitoringObject(value, ['schema_version', 'node_id', 'from', 'to', 'page', 'limit', 'total', 'items'])
    || value.schema_version !== 1 || value.node_id !== nodeID || value.page !== page || value.limit !== limit
    || !nodeMonitoringTime(value.from) || !nodeMonitoringTime(value.to) || !nodeMonitoringInteger(value.total, 0)
    || !Array.isArray(value.items) || value.items.length > limit) {
    throw new ApiError('Invalid node monitoring history', 200, 'invalid_response')
  }
  for (const item of value.items) {
    if (!nodeMonitoringObject(item, ['observed_at', 'config_revision', 'active_config_revision', 'probe_port',
      'probe_succeeded', 'healthy', 'failed_checks', 'total_checks'])
      || !nodeMonitoringTime(item.observed_at) || !nodeMonitoringInteger(item.config_revision, 1)
      || !nodeMonitoringInteger(item.active_config_revision, 1) || !nodeMonitoringInteger(item.probe_port, 1, 65535)
      || typeof item.probe_succeeded !== 'boolean' || typeof item.healthy !== 'boolean'
      || item.total_checks !== 1 || item.failed_checks !== (item.probe_succeeded ? 0 : 1)) {
      throw new ApiError('Invalid node monitoring history item', 200, 'invalid_response')
    }
  }
  return value as unknown as NodeMonitoringHistoryPage
}

async function getNodeMonitoringHistory(accessToken: string, nodeID: string, query: {
  from: string; to: string; page: number; limit: number
}, signal?: AbortSignal): Promise<NodeMonitoringHistoryPage> {
  const from = Date.parse(query.from)
  const to = Date.parse(query.to)
  if (!nodeIDPattern.test(nodeID) || !Number.isFinite(from) || !Number.isFinite(to) || from >= to
    || to - from > nodeMonitoringHistoryMaxWindowMs || !nodeMonitoringInteger(query.page, 1, 1000)
    || !nodeMonitoringInteger(query.limit, 1, 100)) {
    throw new ApiError('Invalid node monitoring history query', 400, 'validation_error')
  }
  const params = new URLSearchParams({ from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    page: String(query.page), limit: String(query.limit) })
  let response: Response
  try {
    response = await fetch(`/v1/nodes/${nodeID}/monitoring/history?${params}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid monitoring history JSON', 200, 'invalid_response') }
  return parseNodeMonitoringHistory(value, nodeID, query.page, query.limit)
}

export type NodeDNSPupGroup = 'domestic' | 'telecom' | 'unicom' | 'mobile' | 'overseas'
const dnspupGroups: readonly string[] = ['domestic', 'telecom', 'unicom', 'mobile', 'overseas']

export interface NodeDNSPupCheckpoint {
  id: string
  group: NodeDNSPupGroup
  carrier?: string
  region?: string
  location?: string
  ok: boolean
  latency_ms?: number
}

/** One probed node address in one dnspup round. */
export interface NodeDNSPupHistoryItem {
  observed_at: string
  address: string
  port: number
  failed: boolean
  failed_checks: number
  total_checks: number
  checkpoints: NodeDNSPupCheckpoint[]
}

export interface NodeDNSPupHistoryPage {
  schema_version: 1
  source: 'dnspup'
  node_id: string
  group: '' | NodeDNSPupGroup
  from: string
  to: string
  page: number
  limit: number
  total: number
  items: NodeDNSPupHistoryItem[]
}

function optionalString(value: unknown, max: number): boolean {
  return value === undefined || (typeof value === 'string' && value.length <= max)
}

function parseNodeDNSPupHistory(value: unknown, nodeID: string, group: string, page: number, limit: number): NodeDNSPupHistoryPage {
  if (!nodeMonitoringObject(value, ['schema_version', 'source', 'node_id', 'group', 'from', 'to', 'page', 'limit', 'total', 'items'])
    || value.schema_version !== 1 || value.source !== 'dnspup' || value.node_id !== nodeID || value.group !== group
    || value.page !== page || value.limit !== limit || !nodeMonitoringTime(value.from) || !nodeMonitoringTime(value.to)
    || !nodeMonitoringInteger(value.total, 0) || !Array.isArray(value.items) || value.items.length > limit) {
    throw new ApiError('Invalid node dnspup history', 200, 'invalid_response')
  }
  for (const item of value.items) {
    if (!nodeMonitoringObject(item, ['observed_at', 'address', 'port', 'failed', 'failed_checks', 'total_checks', 'checkpoints'])
      || !nodeMonitoringTime(item.observed_at) || typeof item.address !== 'string' || item.address.length > 45
      || !nodeMonitoringInteger(item.port, 1, 65535) || typeof item.failed !== 'boolean'
      || !nodeMonitoringInteger(item.total_checks, 0, 100) || !nodeMonitoringInteger(item.failed_checks, 0, item.total_checks as number)
      || !Array.isArray(item.checkpoints) || item.checkpoints.length > 100) {
      throw new ApiError('Invalid node dnspup history item', 200, 'invalid_response')
    }
    for (const checkpoint of item.checkpoints) {
      if (typeof checkpoint !== 'object' || checkpoint === null || Array.isArray(checkpoint)) {
        throw new ApiError('Invalid node dnspup checkpoint', 200, 'invalid_response')
      }
      const point = checkpoint as Record<string, unknown>
      const allowed = ['id', 'group', 'carrier', 'region', 'location', 'ok', 'latency_ms']
      if (Object.keys(point).some((key) => !allowed.includes(key)) || typeof point.id !== 'string' || point.id.length > 128
        || typeof point.group !== 'string' || !dnspupGroups.includes(point.group) || typeof point.ok !== 'boolean'
        || !optionalString(point.carrier, 16) || !optionalString(point.region, 16) || !optionalString(point.location, 128)
        || (point.latency_ms !== undefined && !nodeMonitoringInteger(point.latency_ms, 0))) {
        throw new ApiError('Invalid node dnspup checkpoint', 200, 'invalid_response')
      }
    }
  }
  return value as unknown as NodeDNSPupHistoryPage
}

async function getNodeDNSPupHistory(accessToken: string, nodeID: string, query: {
  from: string; to: string; page: number; limit: number; group: '' | NodeDNSPupGroup
}, signal?: AbortSignal): Promise<NodeDNSPupHistoryPage> {
  const from = Date.parse(query.from)
  const to = Date.parse(query.to)
  if (!nodeIDPattern.test(nodeID) || !Number.isFinite(from) || !Number.isFinite(to) || from >= to
    || to - from > nodeMonitoringHistoryMaxWindowMs || !nodeMonitoringInteger(query.page, 1, 1000)
    || !nodeMonitoringInteger(query.limit, 1, 100) || (query.group !== '' && !dnspupGroups.includes(query.group))) {
    throw new ApiError('Invalid node monitoring history query', 400, 'validation_error')
  }
  const params = new URLSearchParams({ from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    page: String(query.page), limit: String(query.limit), source: 'dnspup' })
  if (query.group) params.set('group', query.group)
  let response: Response
  try {
    response = await fetch(`/v1/nodes/${nodeID}/monitoring/history?${params}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid monitoring history JSON', 200, 'invalid_response') }
  return parseNodeDNSPupHistory(value, nodeID, query.group, query.page, query.limit)
}

/** One vote of a peer probe round: the controller (id "controller") or a peer node. */
export interface NodePeerCheckpoint {
  id: string
  name?: string
  address?: string
  groups?: NodeDNSPupGroup[]
  ok: boolean
  latency_ms?: number
}

/** One probed node address in one round of controller + peer node probing. */
export interface NodePeerHistoryItem {
  observed_at: string
  address: string
  port: number
  failed: boolean
  controller_ok: boolean | null
  failed_checks: number
  total_checks: number
  checkpoints: NodePeerCheckpoint[]
}

export interface NodePeerHistoryPage {
  schema_version: 1
  source: 'peer'
  node_id: string
  from: string
  to: string
  page: number
  limit: number
  total: number
  items: NodePeerHistoryItem[]
}

function parseNodePeerHistory(value: unknown, nodeID: string, page: number, limit: number): NodePeerHistoryPage {
  if (!nodeMonitoringObject(value, ['schema_version', 'source', 'node_id', 'from', 'to', 'page', 'limit', 'total', 'items'])
    || value.schema_version !== 1 || value.source !== 'peer' || value.node_id !== nodeID
    || value.page !== page || value.limit !== limit || !nodeMonitoringTime(value.from) || !nodeMonitoringTime(value.to)
    || !nodeMonitoringInteger(value.total, 0) || !Array.isArray(value.items) || value.items.length > limit) {
    throw new ApiError('Invalid node peer probe history', 200, 'invalid_response')
  }
  for (const item of value.items) {
    if (!nodeMonitoringObject(item, ['observed_at', 'address', 'port', 'failed', 'controller_ok', 'failed_checks', 'total_checks', 'checkpoints'])
      || !nodeMonitoringTime(item.observed_at) || typeof item.address !== 'string' || item.address.length > 45
      || !nodeMonitoringInteger(item.port, 1, 65535) || typeof item.failed !== 'boolean'
      || (item.controller_ok !== null && typeof item.controller_ok !== 'boolean')
      || !nodeMonitoringInteger(item.total_checks, 1, 100) || !nodeMonitoringInteger(item.failed_checks, 0, item.total_checks as number)
      || !Array.isArray(item.checkpoints) || item.checkpoints.length > 100) {
      throw new ApiError('Invalid node peer probe history item', 200, 'invalid_response')
    }
    for (const checkpoint of item.checkpoints) {
      if (typeof checkpoint !== 'object' || checkpoint === null || Array.isArray(checkpoint)) {
        throw new ApiError('Invalid node peer probe checkpoint', 200, 'invalid_response')
      }
      const point = checkpoint as Record<string, unknown>
      const allowed = ['id', 'name', 'address', 'groups', 'ok', 'latency_ms']
      if (Object.keys(point).some((key) => !allowed.includes(key)) || typeof point.id !== 'string' || point.id.length > 128
        || typeof point.ok !== 'boolean' || !optionalString(point.name, 128) || !optionalString(point.address, 45)
        || (point.groups !== undefined && (!Array.isArray(point.groups)
          || point.groups.some((group) => typeof group !== 'string' || !dnspupGroups.includes(group))))
        || (point.latency_ms !== undefined && !nodeMonitoringInteger(point.latency_ms, 0))) {
        throw new ApiError('Invalid node peer probe checkpoint', 200, 'invalid_response')
      }
    }
  }
  return value as unknown as NodePeerHistoryPage
}

async function getNodePeerHistory(accessToken: string, nodeID: string, query: {
  from: string; to: string; page: number; limit: number
}, signal?: AbortSignal): Promise<NodePeerHistoryPage> {
  const from = Date.parse(query.from)
  const to = Date.parse(query.to)
  if (!nodeIDPattern.test(nodeID) || !Number.isFinite(from) || !Number.isFinite(to) || from >= to
    || to - from > nodeMonitoringHistoryMaxWindowMs || !nodeMonitoringInteger(query.page, 1, 1000)
    || !nodeMonitoringInteger(query.limit, 1, 100)) {
    throw new ApiError('Invalid node monitoring history query', 400, 'validation_error')
  }
  const params = new URLSearchParams({ from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    page: String(query.page), limit: String(query.limit), source: 'peer' })
  let response: Response
  try {
    response = await fetch(`/v1/nodes/${nodeID}/monitoring/history?${params}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid monitoring history JSON', 200, 'invalid_response') }
  return parseNodePeerHistory(value, nodeID, query.page, query.limit)
}

export interface NodeMonitoringOverrideFields {
  monitor_enabled: boolean | null
  protocol: 'tcp' | 'http' | 'ping' | null
  probe_timeout_ms: number | null
  monitor_port: number | null
  monitor_action: 'none' | 'pause' | null
}

export interface NodeMonitoringOverride {
  schema_version: 1
  node_id: string
  revision: number
  updated_at: string | null
  override: NodeMonitoringOverrideFields
  platform_state: 'unconfigured' | 'not_activated' | 'active'
  platform_revision: number | null
  effective_revision: number | null
  effective_policy: NodeMonitoringPolicy | null
  effective_action: '' | 'none' | 'pause'
  delivery_state: 'serving' | 'awaiting_configuration' | 'inactive'
}

function parseNodeMonitoringOverride(value: unknown, nodeID: string): NodeMonitoringOverride {
  const invalid = () => new ApiError('Invalid node monitoring override', 200, 'invalid_response')
  if (!nodeMonitoringObject(value, ['schema_version', 'node_id', 'revision', 'updated_at', 'override', 'platform_state',
    'platform_revision', 'effective_revision', 'effective_policy', 'effective_action', 'delivery_state'])
    || value.schema_version !== 1 || value.node_id !== nodeID || !nodeMonitoringInteger(value.revision, 0, 1048576)
    || (value.revision === 0 ? value.updated_at !== null : !nodeMonitoringTime(value.updated_at))
    || !['unconfigured', 'not_activated', 'active'].includes(String(value.platform_state))
    || !['', 'none', 'pause'].includes(String(value.effective_action))
    || !['serving', 'awaiting_configuration', 'inactive'].includes(String(value.delivery_state))) throw invalid()
  const fields = value.override
  if (!nodeMonitoringObject(fields, ['monitor_enabled', 'protocol', 'probe_timeout_ms', 'monitor_port', 'monitor_action'])
    || !(fields.monitor_enabled === null || typeof fields.monitor_enabled === 'boolean')
    || !(fields.protocol === null || ['tcp', 'http', 'ping'].includes(String(fields.protocol)))
    || !(fields.probe_timeout_ms === null || nodeMonitoringInteger(fields.probe_timeout_ms, 100, 60000))
    || !(fields.monitor_port === null || nodeMonitoringInteger(fields.monitor_port, 1, 65535))
    || !(fields.monitor_action === null || ['none', 'pause'].includes(String(fields.monitor_action)))) throw invalid()
  if (value.platform_state === 'active') {
    if (!nodeMonitoringInteger(value.platform_revision, 1) || value.effective_revision !== Number(value.platform_revision) + Number(value.revision)
      || !nodeMonitoringPolicy(value.effective_policy) || value.effective_action === '') throw invalid()
  } else if (value.platform_revision !== null || value.effective_revision !== null || value.effective_policy !== null
    || value.effective_action !== '') throw invalid()
  return value as unknown as NodeMonitoringOverride
}

async function requestNodeMonitoringOverride(accessToken: string, nodeID: string, init: RequestInit): Promise<NodeMonitoringOverride> {
  if (!nodeIDPattern.test(nodeID)) throw new ApiError('Invalid node identifier', 400, 'validation_error')
  let response: Response
  try {
    response = await fetch(`/v1/nodes/${nodeID}/monitoring/override`, {
      ...init, credentials: 'include', cache: 'no-store',
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json', ...init.headers },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid monitoring override JSON', 200, 'invalid_response') }
  return parseNodeMonitoringOverride(value, nodeID)
}

async function getNodeMonitoringOverride(accessToken: string, nodeID: string, signal?: AbortSignal): Promise<NodeMonitoringOverride> {
  return requestNodeMonitoringOverride(accessToken, nodeID, { method: 'GET', signal })
}

async function putNodeMonitoringOverride(accessToken: string, nodeID: string, expectedRevision: number,
  override: NodeMonitoringOverrideFields, idempotencyKey: string): Promise<NodeMonitoringOverride> {
  if (!nodeMonitoringInteger(expectedRevision, 0, 1048576)) throw new ApiError('Invalid override revision', 400, 'validation_error')
  return requestNodeMonitoringOverride(accessToken, nodeID, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify({ expected_revision: expectedRevision, override }),
  })
}

export interface NodeServingEvent {
  id: string
  source: NodeServingSource
  event: 'held' | 'released' | 'protected' | 'protection_cleared'
  reason_code: string
  hold_revision: number
  detail: Record<string, unknown>
  occurred_at: string
}

export interface NodeServingEventPage {
  schema_version: 1
  node_id: string
  from: string
  to: string
  page: number
  limit: number
  total: number
  items: NodeServingEvent[]
}

export const nodeServingEventsMaxWindowMs = 31 * 24 * 60 * 60 * 1000

function parseNodeServingEvents(value: unknown, nodeID: string, page: number, limit: number): NodeServingEventPage {
  const invalid = () => new ApiError('Invalid node serving events', 200, 'invalid_response')
  if (!nodeMonitoringObject(value, ['schema_version', 'node_id', 'from', 'to', 'page', 'limit', 'total', 'items'])
    || value.schema_version !== 1 || value.node_id !== nodeID || value.page !== page || value.limit !== limit
    || !nodeMonitoringTime(value.from) || !nodeMonitoringTime(value.to) || !nodeMonitoringInteger(value.total, 0)
    || !Array.isArray(value.items) || value.items.length > limit) throw invalid()
  for (const item of value.items) {
    if (!nodeMonitoringObject(item, ['id', 'source', 'event', 'reason_code', 'hold_revision', 'detail', 'occurred_at'])
      || typeof item.id !== 'string' || !nodeIDPattern.test(item.id)
      || !(servingSources as readonly unknown[]).includes(item.source)
      || !['held', 'released', 'protected', 'protection_cleared'].includes(String(item.event))
      || typeof item.reason_code !== 'string' || !servingReasonPattern.test(item.reason_code)
      || !nodeMonitoringInteger(item.hold_revision, 1) || !nodeMonitoringTime(item.occurred_at)
      || typeof item.detail !== 'object' || item.detail === null || Array.isArray(item.detail)) throw invalid()
  }
  return value as unknown as NodeServingEventPage
}

async function getNodeServingEvents(accessToken: string, nodeID: string, query: {
  from: string; to: string; page: number; limit: number
}, signal?: AbortSignal): Promise<NodeServingEventPage> {
  const from = Date.parse(query.from)
  const to = Date.parse(query.to)
  if (!nodeIDPattern.test(nodeID) || !Number.isFinite(from) || !Number.isFinite(to) || from >= to
    || to - from > nodeServingEventsMaxWindowMs || !nodeMonitoringInteger(query.page, 1, 1000)
    || !nodeMonitoringInteger(query.limit, 1, 100)) {
    throw new ApiError('Invalid node serving events query', 400, 'validation_error')
  }
  const params = new URLSearchParams({ from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    page: String(query.page), limit: String(query.limit) })
  let response: Response
  try {
    response = await fetch(`/v1/nodes/${nodeID}/serving/events?${params}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid node serving events JSON', 200, 'invalid_response') }
  return parseNodeServingEvents(value, nodeID, query.page, query.limit)
}

export interface NodeScopeServingEvent extends NodeServingEvent {
  node_id: string
  node_name: string
  ipv4: string
  ipv6: string
}

export interface NodeScopeServingEventPage {
  schema_version: 1
  from: string
  to: string
  page: number
  limit: number
  total: number
  items: NodeScopeServingEvent[]
}

export interface NodeScopeServingEventQuery {
  from: string; to: string; page: number; limit: number
  source?: NodeServingSource; event?: NodeServingEvent['event']; nodeID?: string; ip?: string
}

const servingEventKinds = ['held', 'released', 'protected', 'protection_cleared'] as const

// A10/N06：切换日志，本作用域全部节点的摘除/恢复记录（node_serving_events 真实事实）。
async function listScopeServingEvents(accessToken: string, query: NodeScopeServingEventQuery, signal?: AbortSignal): Promise<NodeScopeServingEventPage> {
  const from = Date.parse(query.from)
  const to = Date.parse(query.to)
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to || to - from > nodeServingEventsMaxWindowMs
    || !nodeMonitoringInteger(query.page, 1, 1000) || !nodeMonitoringInteger(query.limit, 1, 100)
    || (query.source !== undefined && !(servingSources as readonly string[]).includes(query.source))
    || (query.event !== undefined && !(servingEventKinds as readonly string[]).includes(query.event))
    || (query.nodeID !== undefined && !nodeIDPattern.test(query.nodeID))
    || (query.ip !== undefined && (query.ip.length === 0 || query.ip.length > 45))) {
    throw new ApiError('Invalid node serving events query', 400, 'validation_error')
  }
  const params = new URLSearchParams({ from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    page: String(query.page), limit: String(query.limit) })
  if (query.source) params.set('source', query.source)
  if (query.event) params.set('event', query.event)
  if (query.nodeID) params.set('node_id', query.nodeID)
  if (query.ip) params.set('ip', query.ip)
  let response: Response
  try {
    response = await fetch(`/v1/nodes/serving/events?${params}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw new ApiError('Invalid node serving events JSON', 200, 'invalid_response') }
  const invalid = () => new ApiError('Invalid node serving events', 200, 'invalid_response')
  if (!nodeMonitoringObject(value, ['schema_version', 'from', 'to', 'page', 'limit', 'total', 'items'])
    || value.schema_version !== 1 || value.page !== query.page || value.limit !== query.limit
    || !nodeMonitoringTime(value.from) || !nodeMonitoringTime(value.to) || !nodeMonitoringInteger(value.total, 0)
    || !Array.isArray(value.items) || value.items.length > query.limit) throw invalid()
  for (const item of value.items) {
    if (!nodeMonitoringObject(item, ['id', 'source', 'event', 'reason_code', 'hold_revision', 'detail', 'occurred_at', 'node_id', 'node_name', 'ipv4', 'ipv6'])
      || typeof item.id !== 'string' || !nodeIDPattern.test(item.id)
      || !(servingSources as readonly unknown[]).includes(item.source)
      || !(servingEventKinds as readonly unknown[]).includes(item.event)
      || typeof item.reason_code !== 'string' || !servingReasonPattern.test(item.reason_code)
      || !nodeMonitoringInteger(item.hold_revision, 1) || !nodeMonitoringTime(item.occurred_at)
      || typeof item.detail !== 'object' || item.detail === null || Array.isArray(item.detail)
      || typeof item.node_id !== 'string' || !nodeIDPattern.test(item.node_id)
      || typeof item.node_name !== 'string' || item.node_name.length === 0 || item.node_name.length > 128
      || typeof item.ipv4 !== 'string' || item.ipv4.length > 15 || typeof item.ipv6 !== 'string' || item.ipv6.length > 45) throw invalid()
  }
  return value as unknown as NodeScopeServingEventPage
}

export const nodeMonitoringApi = {
  getLatest: getLatestNodeMonitoring, getHistory: getNodeMonitoringHistory, getDNSPupHistory: getNodeDNSPupHistory, getPeerHistory: getNodePeerHistory,
  getOverride: getNodeMonitoringOverride, putOverride: putNodeMonitoringOverride,
  getServingEvents: getNodeServingEvents, listScopeServingEvents,
}
