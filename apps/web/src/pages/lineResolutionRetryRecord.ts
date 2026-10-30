import type { NodeLineGroupSnapshotInput, NodeSchedulingWriteMetadata } from '../api/nodeScheduling'
import { uuidPattern, validCodePointLength, validIPAddress } from './node-scheduling/shared'

export type LineResolutionRetryOwner = readonly ['tenant' | 'platform', string, string]
export type LineResolutionAttempt = { input: NodeLineGroupSnapshotInput; metadata: NodeSchedulingWriteMetadata }
export type LineResolutionAccepted = { revision: number; configurationDigest: string }
interface LineResolutionRetryRecord {
  version: 1 | 2
  owner: LineResolutionRetryOwner
  scopeID: string
  resource: string
  phase: 'unknown' | 'readback'
  attempt: LineResolutionAttempt
  body: string
  accepted?: LineResolutionAccepted | null
}
const maximumRecordLength = 512000

export function lineResolutionRetryStorageKey(owner: LineResolutionRetryOwner, scopeID: string, resource: string): string {
  if (!Array.isArray(owner) || owner.length !== 3 || !['tenant', 'platform'].includes(owner[0]) ||
    ![...owner.slice(1), scopeID, resource].every((value) => typeof value === 'string' && uuidPattern.test(value)) ||
    (owner[0] === 'tenant' && scopeID !== owner[1])) return ''
  return `cdnca:line-resolution-retry:${owner.join(':')}:${scopeID}:${resource}`
}

function validLineResolutionAttempt(value: unknown): value is LineResolutionAttempt {
  const keys = (item: unknown, names: string[], optional: string[] = []): item is Record<string, unknown> =>
    typeof item === 'object' && item !== null && !Array.isArray(item) &&
    names.every((name) => Object.hasOwn(item, name)) &&
    Object.keys(item).every((name) => names.includes(name) || optional.includes(name))
  const uuid = (item: unknown): item is string => typeof item === 'string' && uuidPattern.test(item)
  const integer = (item: unknown, min: number, max: number) => typeof item === 'number' && Number.isSafeInteger(item) && item >= min && item <= max
  const text = (item: unknown, min: number, max: number) => typeof item === 'string' && validCodePointLength(item, min, max)
  const label = (item: unknown) => typeof item === 'string' && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?$/.test(item)
  if (!keys(value, ['input', 'metadata'])) return false
  const metadata = value.metadata
  if (!keys(metadata, ['requestId', 'idempotencyKey', 'expectedRevision']) ||
    !['requestId', 'idempotencyKey'].every((name) => typeof metadata[name] === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(metadata[name])) ||
    !integer(metadata.expectedRevision, 1, Number.MAX_SAFE_INTEGER)) return false
  const input = value.input
  if (!keys(input, ['name', 'region', 'resolved_value', 'ipv4_resolved_value', 'l2_config_id', 'failover_mode', 'note', 'sort_order', 'health_policy', 'endpoints']) ||
    !text(input.name, 1, 128) || !text(input.region, 0, 64) || !text(input.note, 0, 512) ||
    !label(input.resolved_value) || !label(input.ipv4_resolved_value) ||
    (input.l2_config_id !== null && !uuid(input.l2_config_id)) || !integer(input.sort_order, 1, 2147483647) ||
    typeof input.failover_mode !== 'string' || !['primary_offline', 'online_less_than_backup_count'].includes(input.failover_mode)) return false
  const policy = input.health_policy
  if (!keys(policy, ['probe_interval_ms', 'probe_timeout_ms', 'failure_threshold', 'recovery_threshold', 'failure_debounce_ms', 'recovery_debounce_ms']) ||
    !integer(policy.probe_interval_ms, 1000, 300000) || !integer(policy.probe_timeout_ms, 100, 60000) ||
    Number(policy.probe_timeout_ms) > Number(policy.probe_interval_ms) ||
    !integer(policy.failure_threshold, 1, 20) || !integer(policy.recovery_threshold, 1, 20) ||
    !integer(policy.failure_debounce_ms, 0, 3600000) || !integer(policy.recovery_debounce_ms, 0, 3600000)) return false
  const endpoints = input.endpoints
  return Array.isArray(endpoints) && endpoints.length <= 512 && endpoints.every((endpoint) =>
    keys(endpoint, ['id', 'node_id', 'address', 'port', 'region', 'carrier', 'priority', 'weight', 'enabled'], ['sort_order']) &&
    uuid(endpoint.id) && uuid(endpoint.node_id) && typeof endpoint.address === 'string' && validIPAddress(endpoint.address) &&
    integer(endpoint.port, 1, 65535) && text(endpoint.region, 0, 64) && text(endpoint.carrier, 0, 64) &&
    integer(endpoint.priority, 0, 65535) &&
    (!('sort_order' in endpoint) || integer(endpoint.sort_order, 0, 999999)) &&
    integer(endpoint.weight, 1, 100) && typeof endpoint.enabled === 'boolean') &&
    new Set(endpoints.map((endpoint) => endpoint.id)).size === endpoints.length
}

function validLineResolutionAccepted(value: unknown, attempt: LineResolutionAttempt): value is LineResolutionAccepted {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== 'configurationDigest,revision') return false
  const accepted = value as LineResolutionAccepted
  return Number.isSafeInteger(accepted.revision) && accepted.revision === attempt.metadata.expectedRevision + 1 &&
    typeof accepted.configurationDigest === 'string' && /^[0-9a-f]{64}$/.test(accepted.configurationDigest)
}

export function restoreLineResolutionRetry(owner: LineResolutionRetryOwner, scopeID: string, resource: string): { record: LineResolutionRetryRecord | null; blocked: boolean } {
  const key = lineResolutionRetryStorageKey(owner, scopeID, resource)
  if (!key) return { record: null, blocked: true }
  try {
    const raw = sessionStorage.getItem(key)
    if (raw === null) return { record: null, blocked: false }
    if (raw.length > maximumRecordLength) return { record: null, blocked: true }
    const record = JSON.parse(raw) as LineResolutionRetryRecord
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
      ![1, 2].includes(record.version) || Object.keys(record).sort().join(',') !==
        (record.version === 1 ? 'attempt,body,owner,phase,resource,scopeID,version' : 'accepted,attempt,body,owner,phase,resource,scopeID,version') ||
      JSON.stringify(record.owner) !== JSON.stringify(owner) || record.scopeID !== scopeID || record.resource !== resource ||
      !['unknown', 'readback'].includes(record.phase) || !validLineResolutionAttempt(record.attempt) ||
      record.body !== JSON.stringify(record.attempt) || (record.version === 2 &&
        (record.phase === 'unknown' ? record.accepted !== null : !validLineResolutionAccepted(record.accepted, record.attempt))))
      return { record: null, blocked: true }
    return { record, blocked: false }
  } catch { return { record: null, blocked: true } }
}

export function persistLineResolutionRetry(owner: LineResolutionRetryOwner, scopeID: string, resource: string, attempt: LineResolutionAttempt, phase: LineResolutionRetryRecord['phase'], accepted: LineResolutionAccepted | null = null): boolean {
  const key = lineResolutionRetryStorageKey(owner, scopeID, resource)
  if (!key || !validLineResolutionAttempt(attempt) || !['unknown', 'readback'].includes(phase) ||
    (phase === 'unknown' ? accepted !== null : !validLineResolutionAccepted(accepted, attempt))) return false
  try {
    const before = restoreLineResolutionRetry(owner, scopeID, resource)
    const body = JSON.stringify(attempt)
    if (before.blocked || (before.record && (before.record.body !== body ||
      (before.record.phase === 'readback' && (phase !== 'readback' || before.record.version === 1 ||
        JSON.stringify(before.record.accepted) !== JSON.stringify(accepted)))))) return false
    const raw = JSON.stringify({ version: 2, owner, scopeID, resource, phase, attempt, body, accepted })
    if (raw.length > maximumRecordLength) return false
    sessionStorage.setItem(key, raw)
    return sessionStorage.getItem(key) === raw
  } catch { return false }
}

export function clearLineResolutionRetry(owner: LineResolutionRetryOwner, scopeID: string, resource: string, attempt: LineResolutionAttempt, accepted: LineResolutionAccepted | null = null): boolean {
  const key = lineResolutionRetryStorageKey(owner, scopeID, resource)
  if (!key) return false
  try {
    const before = restoreLineResolutionRetry(owner, scopeID, resource)
    if (before.blocked || !before.record || before.record.body !== JSON.stringify(attempt) ||
      (before.record.phase === 'unknown' ? accepted !== null : before.record.version !== 2 ||
        !validLineResolutionAccepted(accepted, attempt) || JSON.stringify(before.record.accepted) !== JSON.stringify(accepted))) return false
    sessionStorage.removeItem(key)
    return sessionStorage.getItem(key) === null
  } catch { return false }
}
