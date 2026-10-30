import { isSchedule302Hostname } from '../api/nodes'
import type { NodeInventoryItem, UpdateNodeRequest } from '../api/nodes'
import { uuidPattern, validIPAddress } from './node-scheduling/shared'

export type NodeUpdateRetryOwner = readonly ['platform', string, string]
export interface NodeUpdateRequestAttempt {
  item: Pick<NodeInventoryItem, 'id' | 'revision'>
  input: UpdateNodeRequest
  key: string
}
export interface NodeUpdateRetryRecord {
  // 2：readback 记录只在服务端回执已校验（同 id、修订号递增；删除时 admin_state=retired）后写入。
  // 1：旧记录，删除回执未校验，须用同幂等键重放取回执后再确认（A17）。
  version: 1 | 2
  owner: NodeUpdateRetryOwner
  phase: 'unknown' | 'readback'
  confirmedRevision: number | null
  attempt: NodeUpdateRequestAttempt
  body: string
}
const maximumRecordLength = 65536

export function nodeUpdateRetryStorageKey(owner: NodeUpdateRetryOwner): string {
  return Array.isArray(owner) && owner.length === 3 && owner[0] === 'platform' &&
    owner.slice(1).every((part) => typeof part === 'string' && uuidPattern.test(part))
    ? `cdnca:node-update-retry:${owner.join(':')}` : ''
}

function validNodeUpdateAttempt(value: unknown): value is NodeUpdateRequestAttempt {
  const keys = (item: unknown, required: string[], optional: string[] = []): item is Record<string, unknown> =>
    typeof item === 'object' && item !== null && !Array.isArray(item) &&
    required.every((key) => Object.hasOwn(item, key)) && Object.keys(item).every((key) => [...required, ...optional].includes(key))
  const integer = (item: unknown, maximum = Number.MAX_SAFE_INTEGER, minimum = 0) =>
    typeof item === 'number' && Number.isSafeInteger(item) && item >= minimum && item <= maximum
  const text = (item: unknown, maximum: number, minimum = 0) => typeof item === 'string' &&
    item.length <= maximum && item.trim().length >= minimum && !/\p{Cc}/u.test(item.replace(/[\n\r\t]/g, ''))
  const address = (item: unknown) => {
    if (typeof item !== 'string' || item !== item.trim() || item.length > 45) return false
    if (!item.includes(':') || !item.includes('.')) return validIPAddress(item)
    const separator = item.lastIndexOf(':')
    return validIPAddress(item.slice(separator + 1)) && validIPAddress(`${item.slice(0, separator)}:0:0`)
  }
  if (!keys(value, ['item', 'input', 'key']) || !keys(value.item, ['id', 'revision']) ||
    typeof value.item.id !== 'string' || !uuidPattern.test(value.item.id) || !integer(value.item.revision, Number.MAX_SAFE_INTEGER, 1) ||
    typeof value.key !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.key)) return false
  const input = value.input
  if (!keys(input, [], ['name', 'description', 'region', 'ipv4', 'ipv6', 'admin_state', 'management_settings']) || Object.keys(input).length === 0 ||
    (Object.hasOwn(input, 'name') && !text(input.name, 128, 1)) ||
    (Object.hasOwn(input, 'description') && !text(input.description, 1024)) ||
    (Object.hasOwn(input, 'region') && !text(input.region, 64)) ||
    (Object.hasOwn(input, 'ipv4') && input.ipv4 !== '' && (!address(input.ipv4) || String(input.ipv4).includes(':'))) ||
    (Object.hasOwn(input, 'ipv6') && input.ipv6 !== '' && (!address(input.ipv6) || !String(input.ipv6).includes(':'))) ||
    (Object.hasOwn(input, 'admin_state') && !['active', 'draining', 'disabled', 'retired'].includes(String(input.admin_state)))) return false
  if (!Object.hasOwn(input, 'management_settings')) return true
  const settings = input.management_settings
  if (!keys(settings, ['schema_version', 'sort', 'node_type', 'cache_directory', 'cache_limit_gb', 'log_directory', 'ip_location', 'auto_disable', 'secondary_ips', 'external_probe'], ['schedule302_hostname', 'ip_location_manual']) ||
    (Object.hasOwn(settings, 'schedule302_hostname') && !isSchedule302Hostname(settings.schedule302_hostname)) ||
    // fix-nodeipgeo: the corrected IP 归属 fields
    (Object.hasOwn(settings, 'ip_location_manual') && (!Array.isArray(settings.ip_location_manual) ||
      new Set(settings.ip_location_manual).size !== settings.ip_location_manual.length ||
      !settings.ip_location_manual.every((field) => ['country', 'province', 'city', 'isp', 'country_code'].includes(String(field))))) ||
    typeof settings.external_probe !== 'boolean' || settings.schema_version !== 1 || !integer(settings.sort, 999999) || !['L1', 'L2'].includes(String(settings.node_type)) ||
    !text(settings.cache_directory, 512) || !integer(settings.cache_limit_gb, 1_000_000_000) || !text(settings.log_directory, 512) ||
    !keys(settings.ip_location, ['country', 'province', 'city', 'isp', 'country_code']) ||
    !['country', 'province', 'city', 'isp'].every((key) => text(settings.ip_location && (settings.ip_location as Record<string, unknown>)[key], 128)) ||
    typeof settings.ip_location.country_code !== 'string' || !/^(?:|[A-Z]{2})$/.test(settings.ip_location.country_code) ||
    !Array.isArray(settings.secondary_ips) || settings.secondary_ips.length > 64 ||
    new Set(settings.secondary_ips).size !== settings.secondary_ips.length || !settings.secondary_ips.every(address)) return false
  const policy = settings.auto_disable
  return keys(policy, ['bandwidth_limit', 'bandwidth_unit', 'traffic_enabled', 'traffic_from_day', 'traffic_from_time', 'traffic_total_gb', 'traffic_types', 'excluded_interfaces', 'disabled_periods']) &&
    integer(policy.bandwidth_limit, 1_000_000_000) && ['Mbps', 'Gbps'].includes(String(policy.bandwidth_unit)) &&
    typeof policy.traffic_enabled === 'boolean' && integer(policy.traffic_from_day, 28, 1) &&
    typeof policy.traffic_from_time === 'string' && /^(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(policy.traffic_from_time) &&
    integer(policy.traffic_total_gb, 1_000_000_000) && Array.isArray(policy.traffic_types) && policy.traffic_types.length >= 1 &&
    policy.traffic_types.length <= 2 && new Set(policy.traffic_types).size === policy.traffic_types.length &&
    policy.traffic_types.every((kind) => ['inbound', 'outbound'].includes(String(kind))) &&
    text(policy.excluded_interfaces, 512) && text(policy.disabled_periods, 1024)
}

export function restoreNodeUpdateRetry(owner: NodeUpdateRetryOwner): { record: NodeUpdateRetryRecord | null; blocked: boolean } {
  const key = nodeUpdateRetryStorageKey(owner)
  if (!key) return { record: null, blocked: true }
  try {
    const raw = sessionStorage.getItem(key)
    if (raw === null) return { record: null, blocked: false }
    if (raw.length > maximumRecordLength) return { record: null, blocked: true }
    const record = JSON.parse(raw) as NodeUpdateRetryRecord
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
      Object.keys(record).sort().join(',') !== 'attempt,body,confirmedRevision,owner,phase,version' || (record.version !== 1 && record.version !== 2) ||
      JSON.stringify(record.owner) !== JSON.stringify(owner) || !validNodeUpdateAttempt(record.attempt) ||
      record.body !== JSON.stringify(record.attempt) ||
      (record.phase === 'unknown' ? record.confirmedRevision !== null : record.phase !== 'readback' ||
        !Number.isSafeInteger(record.confirmedRevision) || Number(record.confirmedRevision) <= record.attempt.item.revision)) {
      return { record: null, blocked: true }
    }
    return { record, blocked: false }
  } catch { return { record: null, blocked: true } }
}

export function persistNodeUpdateRetry(owner: NodeUpdateRetryOwner, attempt: NodeUpdateRequestAttempt, confirmedRevision: number | null = null): NodeUpdateRetryRecord | null {
  const key = nodeUpdateRetryStorageKey(owner)
  if (!key || !validNodeUpdateAttempt(attempt) || (confirmedRevision !== null &&
    (!Number.isSafeInteger(confirmedRevision) || confirmedRevision <= attempt.item.revision))) return null
  try {
    const previous = restoreNodeUpdateRetry(owner)
    const body = JSON.stringify(attempt)
    if (previous.blocked || (previous.record && (previous.record.body !== body ||
      (previous.record.phase === 'readback' && previous.record.confirmedRevision !== confirmedRevision)))) return null
    const record: NodeUpdateRetryRecord = { version: 2, owner, attempt, body, confirmedRevision,
      phase: confirmedRevision === null ? 'unknown' : 'readback' }
    const raw = JSON.stringify(record)
    if (raw.length > maximumRecordLength) return null
    sessionStorage.setItem(key, raw)
    return sessionStorage.getItem(key) === raw ? record : null
  } catch { return null }
}

export function clearNodeUpdateRetry(owner: NodeUpdateRetryOwner, attempt: NodeUpdateRequestAttempt): boolean {
  const key = nodeUpdateRetryStorageKey(owner)
  if (!key) return false
  try {
    const previous = restoreNodeUpdateRetry(owner)
    if (previous.blocked || !previous.record || previous.record.body !== JSON.stringify(attempt)) return false
    sessionStorage.removeItem(key)
    return sessionStorage.getItem(key) === null
  } catch { return false }
}
