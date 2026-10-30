import { ApiError, networkApiError, responseApiError } from './auth'

export const ORIGIN_ROUTING_SCHEMA = 'cdnca.edge.origin-route/v1' as const
export const ORIGIN_BALANCE_METHODS = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random'] as const
export type OriginBalanceMethod = (typeof ORIGIN_BALANCE_METHODS)[number]

export interface OriginEndpoint {
  id: string
  host: string
  port: number
  weight: number
}

export interface OriginPool {
  id: string
  balance_method?: OriginBalanceMethod
  endpoints: OriginEndpoint[]
}

export interface OriginRoute {
  id: string
  priority: number
  path_prefix?: string
  node_regions?: string[]
  client_cidrs?: string[]
  pool_id: string
  fallback_pool_id?: string
}

export interface OriginRetry {
  methods: Array<'GET' | 'HEAD'>
  max_attempts: number
  connect_timeout_ms: number
  read_timeout_ms: number
  total_budget_ms: number
}

export interface OriginRoutingDocument {
  schema: typeof ORIGIN_ROUTING_SCHEMA
  ingress_source_enabled: boolean
  pools: OriginPool[]
  default_pool_id: string
  default_fallback_pool_id?: string
  routes: OriginRoute[]
  retry: OriginRetry
}

export interface OriginRoutingState {
  site_id: string
  version: number
  document: OriginRoutingDocument
  updated_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/u, '')
const tokenPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u
const balanceMethods = new Set<string>(ORIGIN_BALANCE_METHODS)

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isInteger(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max
}

function isUnicastIPv4(value: string): boolean {
  const octets = value.split('.')
  if (octets.length !== 4 || octets.some((part) => !/^\d+$/u.test(part))) return false
  const parsed = octets.map(Number)
  if (parsed.some((part) => part < 0 || part > 255)) return false
  return parsed[0]! < 224 && value === parsed.map(String).join('.')
}

function isUnicastIPv6(value: string): boolean {
  if (!value.includes(':') || value.includes('%') || value.includes('.') || /[^0-9a-f:]/iu.test(value)) return false
  const pieces = value.split('::')
  if (pieces.length > 2) return false
  const left = pieces[0] ? pieces[0].split(':').filter(Boolean) : []
  const right = pieces[1] ? pieces[1].split(':').filter(Boolean) : []
  if (pieces.length === 1 && left.length !== 8) return false
  if (pieces.length === 2 && left.length + right.length >= 8) return false
  if ([...left, ...right].some((part) => part.length < 1 || part.length > 4)) return false
  const normalized = value.toLowerCase()
  return normalized !== '::' && !normalized.startsWith('ff') && !normalized.startsWith('fe8') && !normalized.startsWith('fe9') && !normalized.startsWith('fea') && !normalized.startsWith('feb')
}

function isUnicastHost(value: unknown): value is string {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) return false
  return isUnicastIPv4(value) || isUnicastIPv6(value) || isDNSHostname(value)
}

function isDNSHostname(value: string): boolean {
  const canonical = value.toLowerCase().replace(/\.$/u, '')
  if (canonical.length < 1 || canonical.length > 253 || canonical === 'localhost' ||
    canonical.endsWith('.in-addr.arpa') || canonical.endsWith('.ip6.arpa') || canonical.split('.').length < 2) return false
  if (canonical.split('.').some((label) => label.length < 1 || label.length > 63 ||
    label.startsWith('-') || label.endsWith('-') || !/^[a-z0-9-]+$/u.test(label))) return false
  if (isUnicastIPv4(canonical) || isUnicastIPv6(canonical)) return false
  return /[a-z]/u.test(canonical.split('.').at(-1) ?? '')
}

function isToken(value: unknown): value is string { return typeof value === 'string' && tokenPattern.test(value) }

function isCanonicalCIDR(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const slash = value.lastIndexOf('/')
  if (slash <= 0) return false
  const host = value.slice(0, slash)
  const bits = Number(value.slice(slash + 1))
  if (!Number.isInteger(bits)) return false
  if (isUnicastIPv4(host)) return bits >= 0 && bits <= 32
  if (isUnicastIPv6(host)) return bits >= 0 && bits <= 128
  return false
}

function isEndpoint(value: unknown): value is OriginEndpoint {
  return isRecord(value) && isToken(value.id) && isUnicastHost(value.host) &&
    isInteger(value.port, 1, 65535) && isInteger(value.weight, 1, 100)
}

function isPool(value: unknown): value is OriginPool {
  return isRecord(value) && isToken(value.id) &&
    (value.balance_method === undefined || (typeof value.balance_method === 'string' && balanceMethods.has(value.balance_method))) &&
    Array.isArray(value.endpoints) && value.endpoints.length >= 1 && value.endpoints.length <= 32 && value.endpoints.every(isEndpoint)
}

function isRoute(value: unknown, poolIDs: ReadonlySet<string>): value is OriginRoute {
  if (!isRecord(value) || !isToken(value.id) || !isInteger(value.priority, -1000, 1000) || !isToken(value.pool_id) || !poolIDs.has(value.pool_id)) return false
  if (value.fallback_pool_id !== undefined && (!isToken(value.fallback_pool_id) || !poolIDs.has(value.fallback_pool_id) || value.fallback_pool_id === value.pool_id)) return false
  if (value.path_prefix !== undefined && (typeof value.path_prefix !== 'string' || value.path_prefix.length < 1 || value.path_prefix.length > 2048 || !value.path_prefix.startsWith('/') || value.path_prefix.includes('//') || /[\\?#%]/u.test(value.path_prefix) || [...value.path_prefix].some((character) => character.charCodeAt(0) < 0x20))) return false
  if (value.node_regions !== undefined && (!Array.isArray(value.node_regions) || value.node_regions.length > 32 || value.node_regions.some((item) => !isToken(item)))) return false
  if (value.client_cidrs !== undefined && (!Array.isArray(value.client_cidrs) || value.client_cidrs.length > 32 || value.client_cidrs.some((item) => !isCanonicalCIDR(item)))) return false
  return Boolean(value.path_prefix || (value.node_regions?.length ?? 0) > 0 || (value.client_cidrs?.length ?? 0) > 0)
}

function isRetry(value: unknown): value is OriginRetry {
  if (!isRecord(value) || !Array.isArray(value.methods) || value.methods.length < 1 || value.methods.length > 2 ||
    value.methods.some((item) => item !== 'GET' && item !== 'HEAD') || new Set(value.methods).size !== value.methods.length) return false
  return isInteger(value.max_attempts, 1, 8) && isInteger(value.connect_timeout_ms, 10, 60000) &&
    isInteger(value.read_timeout_ms, 10, 60000) && isInteger(value.total_budget_ms, 20, 120000) &&
    value.total_budget_ms >= value.connect_timeout_ms + value.read_timeout_ms
}

function isDocument(value: unknown): value is OriginRoutingDocument {
  if (!isRecord(value) || value.schema !== ORIGIN_ROUTING_SCHEMA || !Array.isArray(value.pools) || value.pools.length < 1 || value.pools.length > 64 ||
    typeof value.ingress_source_enabled !== 'boolean' || !Array.isArray(value.routes) || value.routes.length > 256 ||
    !isToken(value.default_pool_id) || !isRetry(value.retry)) return false
  if (!value.pools.every(isPool)) return false
  const poolIDs = new Set(value.pools.map((pool) => pool.id))
  if (poolIDs.size !== value.pools.length || !poolIDs.has(value.default_pool_id)) return false
  if (value.default_fallback_pool_id !== undefined && (!isToken(value.default_fallback_pool_id) || !poolIDs.has(value.default_fallback_pool_id) || value.default_fallback_pool_id === value.default_pool_id)) return false
  if (!value.routes.every((route) => isRoute(route, poolIDs))) return false
  const routeIDs = value.routes.map((route) => route.id)
  return new Set(routeIDs).size === routeIDs.length
}

export function validateOriginRoutingState(value: unknown): value is OriginRoutingState {
  return isRecord(value) && typeof value.site_id === 'string' && isInteger(value.version, 1, Number.MAX_SAFE_INTEGER) &&
    typeof value.updated_at === 'string' && isDocument(value.document)
}

function pathSpecificity(value: string | undefined): number { return value === '/' || !value ? 0 : value.length }
function cidrPrefix(value: string | undefined): number {
  if (!value) return -1
  const slash = value.lastIndexOf('/')
  return slash < 0 ? -1 : Number(value.slice(slash + 1))
}

export function sortOriginRoutes<T extends OriginRoute>(routes: readonly T[]): T[] {
  return [...routes].sort((left, right) => {
    if (left.priority !== right.priority) return right.priority - left.priority
    const path = pathSpecificity(right.path_prefix) - pathSpecificity(left.path_prefix)
    if (path !== 0) return path
    const region = Number((right.node_regions?.length ?? 0) > 0) - Number((left.node_regions?.length ?? 0) > 0)
    if (region !== 0) return region
    const cidr = cidrPrefix(right.client_cidrs?.[0]) - cidrPrefix(left.client_cidrs?.[0])
    if (cidr !== 0) return cidr
    return left.id.localeCompare(right.id)
  })
}

export function sortOriginDocument(document: OriginRoutingDocument): OriginRoutingDocument {
  return {
    ...document,
    pools: document.pools.map((pool) => ({ ...pool, endpoints: [...pool.endpoints].sort((left, right) => left.id.localeCompare(right.id)) })).sort((left, right) => left.id.localeCompare(right.id)),
    routes: sortOriginRoutes(document.routes),
    retry: { ...document.retry, methods: [...document.retry.methods].sort() },
  }
}

function invalidResponse(): ApiError { return new ApiError('Invalid origin routing response', 0, 'invalid_response') }

async function request<T>(token: string, path: string, validate: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw invalidResponse() }
  if (!validate(value)) throw invalidResponse()
  return value
}

export const originRoutingApi = {
  get(token: string, siteId: string): Promise<OriginRoutingState> {
    return request(token, `/v1/sites/${encodeURIComponent(siteId)}/origin-routing`, validateOriginRoutingState)
  },
  replace(token: string, siteId: string, expectedVersion: number, document: OriginRoutingDocument, idempotencyKey: string): Promise<OriginRoutingState> {
    const normalized = sortOriginDocument(document)
    return request(token, `/v1/sites/${encodeURIComponent(siteId)}/origin-routing`, validateOriginRoutingState, {
      method: 'PUT',
      headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${expectedVersion}"` },
      body: JSON.stringify(normalized),
    })
  },
}
