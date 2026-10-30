import type { L2ConditionInput, L2ConfigInput, L2NodeInput, NodeSchedulingWriteMetadata } from '../api/nodeScheduling'
import { uuidPattern, validCodePointLength } from './node-scheduling/shared'

export type L2RetryOwner = readonly ['tenant' | 'platform', string, string]
export type L2InventoryAttempt =
  | { kind: 'config'; id: string | null; input: L2ConfigInput; metadata: NodeSchedulingWriteMetadata }
  | { kind: 'condition'; id: string | null; input: L2ConditionInput; metadata: NodeSchedulingWriteMetadata }
  | { kind: 'delete'; inventory: 'configuration' | 'conditions'; targets: Array<{ id: string; metadata: NodeSchedulingWriteMetadata }> }
export type L2NodesAttempt =
  | { kind: 'add'; nodeIDs: string[]; conditionID: string | null; metadata: NodeSchedulingWriteMetadata }
  | { kind: 'update'; id: string; input: L2NodeInput; metadata: NodeSchedulingWriteMetadata }
  | { kind: 'batchUpdate'; targets: Array<{ id: string; input: L2NodeInput; metadata: NodeSchedulingWriteMetadata }> }
  | { kind: 'delete'; targets: Array<{ id: string; metadata: NodeSchedulingWriteMetadata }> }
type Attempt = L2InventoryAttempt | L2NodesAttempt
export interface L2RetryRecord<T extends Attempt> {
  version: 1
  owner: L2RetryOwner
  resource: string
  phase: 'unknown' | 'readback'
  attempt: T
  body: string
}
const maximumRecordLength = 512000

export function l2RetryStorageKey(owner: L2RetryOwner, resource: string): string {
  if (!Array.isArray(owner) || owner.length !== 3 || !['tenant', 'platform'].includes(owner[0]) ||
    !owner.slice(1).every((value) => typeof value === 'string' && uuidPattern.test(value)) ||
    (resource !== 'inventory' && !uuidPattern.test(resource))) return ''
  return `cdnca:l2-retry:${owner.join(':')}:${resource}`
}

function validL2Attempt(value: unknown, resource: string): value is Attempt {
  const object = (item: unknown): item is Record<string, unknown> => typeof item === 'object' && item !== null && !Array.isArray(item)
  const keys = (item: unknown, names: string[]): item is Record<string, unknown> => object(item) &&
    Object.keys(item).length === names.length && names.every((name) => Object.hasOwn(item, name))
  const uuid = (item: unknown): item is string => typeof item === 'string' && uuidPattern.test(item)
  const integer = (item: unknown, min: number, max: number) => typeof item === 'number' && Number.isSafeInteger(item) && item >= min && item <= max
  const text = (item: unknown, min: number, max: number) => typeof item === 'string' && validCodePointLength(item, min, max)
  const metadata = (item: unknown, create = false) => keys(item, ['requestId', 'idempotencyKey', 'expectedRevision']) &&
    ['requestId', 'idempotencyKey'].every((name) => typeof item[name] === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item[name])) &&
    (create ? item.expectedRevision === 0 : integer(item.expectedRevision, 1, Number.MAX_SAFE_INTEGER))
  const nodeInput = (item: unknown) => keys(item, ['condition_id', 'enabled', 'weight', 'sort']) &&
    (item.condition_id === null || uuid(item.condition_id)) && typeof item.enabled === 'boolean' &&
    integer(item.weight, 1, 100) && integer(item.sort, 0, 999999)
  const targets = (items: unknown, update: boolean) => Array.isArray(items) && items.length >= 1 && items.length <= 512 &&
    new Set(items.map((item) => object(item) ? item.id : null)).size === items.length &&
    new Set(items.map((item) => object(item) && object(item.metadata) ? item.metadata.idempotencyKey : null)).size === items.length &&
    items.every((item) => keys(item, update ? ['id', 'input', 'metadata'] : ['id', 'metadata']) && uuid(item.id) &&
      metadata(item.metadata) && (!update || nodeInput(item.input)))
  if (!object(value)) return false
  if (resource === 'inventory') {
    if (value.kind === 'delete') return keys(value, ['kind', 'inventory', 'targets']) &&
      typeof value.inventory === 'string' && ['configuration', 'conditions'].includes(value.inventory) && targets(value.targets, false)
    if (typeof value.kind !== 'string' || !['config', 'condition'].includes(value.kind) || !keys(value, ['kind', 'id', 'input', 'metadata']) ||
      (value.id !== null && !uuid(value.id)) || !metadata(value.metadata, value.id === null)) return false
    const input = value.input
    if (value.kind === 'config') return keys(input, ['name', 'region', 'remark', 'mode', 'load_method']) &&
      text(input.name, 1, 128) && (input.region === '' || text(input.region, 1, 64)) && text(input.remark, 0, 1024) &&
      typeof input.mode === 'string' && ['cache', 'global'].includes(input.mode) && typeof input.load_method === 'string' && ['rr', 'url_hash'].includes(input.load_method)
    return keys(input, ['name', 'remark', 'rules']) && text(input.name, 1, 128) && text(input.remark, 0, 1024) &&
      Array.isArray(input.rules) && input.rules.length >= 1 && input.rules.length <= 32 && input.rules.every((rule) =>
        keys(rule, ['field', 'operator', 'value']) &&
        typeof rule.field === 'string' && ['host', 'request_uri', 'uri', 'node_country', 'node_isp', 'node_province', 'node_city', 'node_id', 'protocol'].includes(rule.field) &&
        typeof rule.operator === 'string' && ['eq', 'neq', 'contains', 'not_contains', 'prefix', 'suffix', 'regex', 'not_regex'].includes(rule.operator) && text(rule.value, 1, 1024))
  }
  if (value.kind === 'add') return keys(value, ['kind', 'nodeIDs', 'conditionID', 'metadata']) &&
    Array.isArray(value.nodeIDs) && value.nodeIDs.length >= 1 && value.nodeIDs.length <= 512 &&
    value.nodeIDs.every(uuid) && new Set(value.nodeIDs).size === value.nodeIDs.length &&
    (value.conditionID === null || uuid(value.conditionID)) && metadata(value.metadata, true)
  if (value.kind === 'update') return keys(value, ['kind', 'id', 'input', 'metadata']) &&
    uuid(value.id) && nodeInput(value.input) && metadata(value.metadata)
  return typeof value.kind === 'string' && ['delete', 'batchUpdate'].includes(value.kind) && keys(value, ['kind', 'targets']) && targets(value.targets, value.kind === 'batchUpdate')
}

export function restoreL2Retry<T extends Attempt>(owner: L2RetryOwner, resource: string): { record: L2RetryRecord<T> | null; blocked: boolean } {
  const key = l2RetryStorageKey(owner, resource)
  if (!key) return { record: null, blocked: true }
  try {
    const raw = sessionStorage.getItem(key)
    if (raw === null) return { record: null, blocked: false }
    if (raw.length > maximumRecordLength) return { record: null, blocked: true }
    const record = JSON.parse(raw) as L2RetryRecord<T>
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
      Object.keys(record).sort().join(',') !== 'attempt,body,owner,phase,resource,version' || record.version !== 1 ||
      JSON.stringify(record.owner) !== JSON.stringify(owner) || record.resource !== resource ||
      !['unknown', 'readback'].includes(record.phase) || !validL2Attempt(record.attempt, resource) ||
      record.body !== JSON.stringify(record.attempt)) return { record: null, blocked: true }
    return { record, blocked: false }
  } catch { return { record: null, blocked: true } }
}

export function persistL2Retry<T extends Attempt>(owner: L2RetryOwner, resource: string, attempt: T, phase: L2RetryRecord<T>['phase']): boolean {
  const key = l2RetryStorageKey(owner, resource)
  if (!key || !validL2Attempt(attempt, resource) || !['unknown', 'readback'].includes(phase)) return false
  try {
    const before = restoreL2Retry<T>(owner, resource)
    const body = JSON.stringify(attempt)
    if (before.blocked || (before.record && (before.record.body !== body ||
      (before.record.phase === 'readback' && phase !== 'readback')))) return false
    const raw = JSON.stringify({ version: 1, owner, resource, phase, attempt, body })
    if (raw.length > maximumRecordLength) return false
    sessionStorage.setItem(key, raw)
    return sessionStorage.getItem(key) === raw
  } catch { return false }
}

export function clearL2Retry<T extends Attempt>(owner: L2RetryOwner, resource: string, attempt: T): boolean {
  const key = l2RetryStorageKey(owner, resource)
  if (!key) return false
  try {
    const before = restoreL2Retry<T>(owner, resource)
    if (before.blocked || (before.record && before.record.body !== JSON.stringify(attempt))) return false
    sessionStorage.removeItem(key)
    return sessionStorage.getItem(key) === null
  } catch { return false }
}
