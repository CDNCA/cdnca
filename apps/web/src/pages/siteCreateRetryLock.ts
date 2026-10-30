import type { CreateSiteRequest } from '../api/sites'

export interface SiteCreateRetryItem {
  input: CreateSiteRequest
  key: string
  body: string
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const keyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const basicKeys = [
  'package_id', 'package_name', 'package_subscription_id', 'group_id', 'group_name',
  'domains', 'http_enabled', 'http_listen_ports', 'https_listen_ports', 'ipv6_enabled',
  'tls_protocols', 'origins', 'cname', 'cname_mode', 'cname_domain', 'cname_hostname',
  'cname_regenerate', 'https_enabled', 'enabled', 'status', 'is_default',
]

export function siteCreateRetryStorageKey(scopeID: string, userID: string): string {
  return `cdnca:site-create-retry:${encodeURIComponent(scopeID)}:${encodeURIComponent(userID)}`
}

function validSiteCreateRequest(value: unknown): value is CreateSiteRequest {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
    Object.keys(value).some((key) => !['basic', 'origin_pool', 'target_scope_id', 'owner_id'].includes(key))) return false
  const input = value as Partial<CreateSiteRequest>
  if ((input.target_scope_id === undefined) !== (input.owner_id === undefined) ||
    (input.target_scope_id !== undefined && (typeof input.target_scope_id !== 'string' || !uuidPattern.test(input.target_scope_id))) ||
    (input.owner_id !== undefined && (typeof input.owner_id !== 'string' || !uuidPattern.test(input.owner_id)))) return false
  const basic = input.basic
  if (typeof basic !== 'object' || basic === null || Array.isArray(basic) ||
    Object.keys(basic).some((key) => !basicKeys.includes(key))) return false
  for (const [id, name] of [['package_id', 'package_name'], ['group_id', 'group_name']] as const) {
    if (basic[id] === null && basic[name] === null) continue
    if (typeof basic[id] !== 'string' || !uuidPattern.test(basic[id]) ||
      typeof basic[name] !== 'string' || !basic[name].trim() || basic[name].length > 128) return false
  }
  for (const [field, limit] of [['domains', 100], ['origins', 32]] as const) {
    if (!Array.isArray(basic[field]) || basic[field].length < 1 || basic[field].length > limit ||
      !basic[field].every((item) => typeof item === 'string' && item.trim().length > 0 && item.length <= 512)) return false
  }
  for (const field of ['http_listen_ports', 'https_listen_ports'] as const) {
    // Left out: the server fills them from the defaults.
    if (basic[field] === undefined) continue
    if (!Array.isArray(basic[field]) || !basic[field].every((port) => typeof port === 'string' &&
      /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) return false
  }
  if (['http_enabled', 'https_enabled', 'enabled', 'is_default']
    .some((field) => typeof basic[field as keyof typeof basic] !== 'boolean') ||
    // CU-SITE-02：IPv6 未选择时不提交，由默认设置决定。
    (basic.ipv6_enabled !== undefined && typeof basic.ipv6_enabled !== 'boolean') ||
    typeof basic.cname !== 'string' ||
    !['active', 'disabled', 'package_expired', 'traffic_exceeded', 'locked', 'syncing', 'sync_failed'].includes(basic.status) ||
    (basic.package_subscription_id !== undefined && basic.package_subscription_id !== null &&
      (typeof basic.package_subscription_id !== 'string' || !uuidPattern.test(basic.package_subscription_id))) ||
    (basic.cname_mode !== undefined && !['', 'site', 'package'].includes(basic.cname_mode)) ||
    (basic.cname_domain !== undefined && typeof basic.cname_domain !== 'string') ||
    (basic.cname_hostname !== undefined && typeof basic.cname_hostname !== 'string') ||
    (basic.cname_regenerate !== undefined && typeof basic.cname_regenerate !== 'boolean') ||
    (basic.tls_protocols !== undefined && (!Array.isArray(basic.tls_protocols) ||
      basic.tls_protocols.length !== 2 || basic.tls_protocols[0] !== 'TLSv1.2' || basic.tls_protocols[1] !== 'TLSv1.3'))) return false
  const pool = input.origin_pool
  if (pool === undefined) return true
  if (typeof pool !== 'object' || pool === null || Array.isArray(pool) ||
    Object.keys(pool).some((key) => !['origins', 'balance_method', 'failover_tries', 'connect_timeout_ms', 'read_timeout_ms', 'scheme', 'request_host'].includes(key)) ||
    !Array.isArray(pool.origins) || pool.origins.length < 1 || pool.origins.length > 32 ||
    (pool.balance_method !== undefined && !['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random'].includes(pool.balance_method)) ||
    !Number.isInteger(pool.failover_tries) || pool.failover_tries < 1 || pool.failover_tries > pool.origins.length ||
    // CU-SITE-02：超时与回源协议未选择时不提交，由默认设置决定。
    (pool.connect_timeout_ms !== undefined && (!Number.isInteger(pool.connect_timeout_ms) || pool.connect_timeout_ms < 50 || pool.connect_timeout_ms > 30000)) ||
    (pool.read_timeout_ms !== undefined && (!Number.isInteger(pool.read_timeout_ms) || pool.read_timeout_ms < 100 || pool.read_timeout_ms > 300000)) ||
    (pool.scheme !== undefined && !['http', 'https', 'follow'].includes(pool.scheme)) ||
    (pool.request_host !== undefined && (typeof pool.request_host !== 'object' || pool.request_host === null ||
      pool.request_host.mode !== 'custom' || typeof pool.request_host.value !== 'string' || pool.request_host.value.length > 259))) return false
  return pool.origins.every((origin) => typeof origin === 'object' && origin !== null && !Array.isArray(origin) &&
    Object.keys(origin).every((key) => ['host', 'port', 'weight', 'enabled'].includes(key)) &&
    typeof origin.host === 'string' && origin.host.trim().length > 0 && origin.host.length <= 253 &&
    Number.isInteger(origin.port) && origin.port >= 1 && origin.port <= 65535 &&
    Number.isInteger(origin.weight) && origin.weight >= 1 && origin.weight <= 100 && typeof origin.enabled === 'boolean')
}

function validSiteCreateRetryItems(value: unknown): value is SiteCreateRetryItem[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) return false
  const keys = new Set<string>()
  for (const item of value) {
    if (typeof item !== 'object' || item === null || Array.isArray(item) ||
      Object.keys(item).some((key) => !['input', 'key', 'body'].includes(key)) ||
      typeof item.key !== 'string' || !keyPattern.test(item.key) || keys.has(item.key) ||
      typeof item.body !== 'string' || !validSiteCreateRequest(item.input) || item.body !== JSON.stringify(item.input)) return false
    keys.add(item.key)
  }
  return true
}

export function restoreSiteCreateRetry(storageKey: string): { items: SiteCreateRetryItem[] | null; corrupted: boolean } {
  if (!storageKey) return { items: null, corrupted: true }
  try {
    const stored = sessionStorage.getItem(storageKey)
    if (stored === null) return { items: null, corrupted: false }
    const items: unknown = JSON.parse(stored)
    return validSiteCreateRetryItems(items) ? { items, corrupted: false } : { items: null, corrupted: true }
  } catch {
    return { items: null, corrupted: true }
  }
}

export function persistSiteCreateRetry(storageKey: string, items: SiteCreateRetryItem[]): boolean {
  if (!storageKey) return false
  try {
    if (!validSiteCreateRetryItems(items)) return false
    const stored = JSON.stringify(items)
    sessionStorage.setItem(storageKey, stored)
    return sessionStorage.getItem(storageKey) === stored
  } catch {
    return false
  }
}

export function clearSiteCreateRetry(storageKey: string): boolean {
  if (!storageKey) return false
  try {
    sessionStorage.removeItem(storageKey)
    return sessionStorage.getItem(storageKey) === null
  } catch {
    return false
  }
}
