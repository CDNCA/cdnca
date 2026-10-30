import { ApiError, networkApiError, responseApiError } from './auth'

export type APIKeyStatus = 'pending_activation' | 'active' | 'revoked'

export interface APIKeyRecord {
  id: string
  key_id: string
  key_prefix: string
  scope_id: string
  tenant_id: string
  user_id: string
  name: string
  scopes: string[]
  ip_allowlist: string[]
  status: APIKeyStatus
  pending_expires_at?: string
  expires_at?: string
  last_used_at?: string
  activated_at?: string
  revoked_at?: string
  revision: number
  created_at: string
  updated_at: string
}

export interface IssuedAPIKey {
  key: APIKeyRecord
  secret: string
}

export interface APIKeyFields {
  name: string
  scopes: string[]
  ip_allowlist: string[]
  expires_at?: string
}

export interface APIKeyListInput {
  limit: number
  status?: APIKeyStatus
  name?: string
  key_id?: string
  cursor?: string
  /** Page-number access (0–10000); cannot be combined with cursor. */
  offset?: number
}

export interface APIKeyListPage {
  items: APIKeyRecord[]
  next_cursor: string
  has_more: boolean
  /** Filtered total; only on the first page and offset pages. */
  total?: number
}

export type APIKeyIPAllowlistErrorCode =
  | 'api_key_ip_allowlist_invalid_cidr'
  | 'api_key_ip_allowlist_unsupported_prefix'
  | 'api_key_ip_allowlist_duplicate'
  | 'api_key_ip_allowlist_overlap'
  | 'api_key_ip_allowlist_too_many'

interface ParsedNetwork {
  family: 4 | 6
  normalized: string
  start: bigint
  end: bigint
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

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
    throw await responseApiError(response)
  }
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value))
}

function parseIPv4(value: string): bigint | null {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) return null
  const octets = value.split('.').map(Number)
  if (octets.some((octet) => octet > 255)) return null
  return octets.reduce((result, octet) => (result << 8n) | BigInt(octet), 0n)
}

function parseIPv6(value: string): bigint | null {
  if (value.includes('%') || value.includes('.')) return null
  try {
    const hostname = new URL(`http://[${value}]/`).hostname
    if (!hostname.startsWith('[') || !hostname.endsWith(']')) return null
    const normalized = hostname.slice(1, -1)
    if (value !== normalized) return null
    const halves = value.split('::')
    if (halves.length > 2) return null
    const left = halves[0] ? halves[0].split(':') : []
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : []
    const groups = halves.length === 2
      ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
      : left
    if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null
    return groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n)
  } catch {
    return null
  }
}

function parseNetwork(value: string): ParsedNetwork | APIKeyIPAllowlistErrorCode {
  const slash = value.lastIndexOf('/')
  if (slash <= 0 || slash === value.length - 1) return 'api_key_ip_allowlist_invalid_cidr'
  const host = value.slice(0, slash)
  const rawPrefix = value.slice(slash + 1)
  if (!/^\d+$/.test(rawPrefix)) return 'api_key_ip_allowlist_invalid_cidr'
  const prefix = Number(rawPrefix)
  const ipv4 = parseIPv4(host)
  const ipv6 = ipv4 === null ? parseIPv6(host) : null
  const family = ipv4 !== null ? 4 : ipv6 !== null ? 6 : null
  const bits = family === 4 ? 32 : family === 6 ? 128 : 0
  if (family === null) return 'api_key_ip_allowlist_invalid_cidr'
  if (prefix < 0 || prefix > bits) return 'api_key_ip_allowlist_unsupported_prefix'
  if (rawPrefix !== String(prefix)) return 'api_key_ip_allowlist_invalid_cidr'
  const address = ipv4 ?? ipv6!
  const width = 1n << BigInt(bits)
  const mask = prefix === 0 ? 0n : ((width - 1n) ^ (1n << BigInt(bits - prefix)) - 1n)
  const start = address & mask
  if (start !== address) return 'api_key_ip_allowlist_invalid_cidr'
  const end = start + (1n << BigInt(bits - prefix)) - 1n
  return {
    family: family as 4 | 6,
    normalized: value,
    start,
    end,
  }
}

export function validateAPIKeyIPAllowlist(values: readonly string[]): APIKeyIPAllowlistErrorCode | null {
  if (values.length > 32) return 'api_key_ip_allowlist_too_many'
  const parsed: ParsedNetwork[] = []
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0) return 'api_key_ip_allowlist_invalid_cidr'
    const network = parseNetwork(value)
    if (typeof network === 'string') return network
    if (parsed.some((other) => other.normalized === network.normalized)) return 'api_key_ip_allowlist_duplicate'
    if (parsed.some((other) => other.family === network.family && other.start <= network.end && network.start <= other.end)) {
      return 'api_key_ip_allowlist_overlap'
    }
    parsed.push(network)
  }
  return null
}

function parseAPIKeyRecord(value: unknown): APIKeyRecord {
  const allowedKeys = new Set([
    'id', 'key_id', 'key_prefix', 'scope_id', 'tenant_id', 'user_id', 'name', 'scopes', 'status',
    'ip_allowlist',
    'pending_expires_at', 'expires_at', 'last_used_at', 'activated_at', 'revoked_at',
    'revision', 'created_at', 'updated_at',
  ])
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  const scopePattern = /^[a-z][a-z0-9_.-]{0,127}$/
  if (!isRecord(value) || Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    typeof value.id !== 'string' || !uuid.test(value.id) ||
    typeof value.key_id !== 'string' || !/^cfk_[A-Za-z0-9_-]{22}$/.test(value.key_id) ||
    typeof value.key_prefix !== 'string' || value.key_prefix !== `${value.key_id}.` ||
    typeof value.scope_id !== 'string' || !uuid.test(value.scope_id) ||
    typeof value.tenant_id !== 'string' || !uuid.test(value.tenant_id) ||
    typeof value.user_id !== 'string' || !uuid.test(value.user_id) ||
    typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 128 ||
    !Array.isArray(value.scopes) || value.scopes.length < 1 || value.scopes.length > 128 ||
    value.scopes.some((scope) => typeof scope !== 'string' || !scopePattern.test(scope)) ||
    new Set(value.scopes).size !== value.scopes.length ||
    !Array.isArray(value.ip_allowlist) || validateAPIKeyIPAllowlist(value.ip_allowlist) !== null ||
    !['pending_activation', 'active', 'revoked'].includes(String(value.status)) ||
    !Number.isInteger(value.revision) || Number(value.revision) < 1 ||
    typeof value.created_at !== 'string' || !isOptionalString(value.created_at) ||
    typeof value.updated_at !== 'string' || !isOptionalString(value.updated_at) ||
    !isOptionalString(value.pending_expires_at) || !isOptionalString(value.expires_at) ||
    !isOptionalString(value.last_used_at) || !isOptionalString(value.activated_at) ||
    !isOptionalString(value.revoked_at)) {
    throw invalidResponse()
  }
  return value as unknown as APIKeyRecord
}

function parseIssuedAPIKey(value: unknown): IssuedAPIKey {
  if (!isRecord(value) || Object.keys(value).some((key) => key !== 'key' && key !== 'secret') ||
    typeof value.secret !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.secret)) {
    throw invalidResponse()
  }
  return { key: parseAPIKeyRecord(value.key), secret: value.secret }
}

function writeHeaders(idempotencyKey: string, revision: number): HeadersInit {
  return {
    'Idempotency-Key': idempotencyKey,
    'If-Match': `"${revision}"`,
  }
}

async function list(
  accessToken: string,
  input: APIKeyListInput,
  signal?: AbortSignal,
): Promise<APIKeyListPage> {
  const query = new URLSearchParams({ limit: String(input.limit) })
  if (input.status) query.set('status', input.status)
  if (input.name) query.set('name', input.name)
  if (input.key_id) query.set('key_id', input.key_id)
  if (input.cursor) query.set('cursor', input.cursor)
  if (input.offset) query.set('offset', String(input.offset))
  const value = await request(accessToken, `/v1/account/api-keys?${query}`, { signal })
  if (!isRecord(value) ||
    Object.keys(value).some((key) => !['items', 'next_cursor', 'has_more', 'total'].includes(key)) ||
    !Array.isArray(value.items) || typeof value.next_cursor !== 'string' || value.next_cursor.length > 4096 ||
    typeof value.has_more !== 'boolean' || value.has_more !== (value.next_cursor !== '') ||
    value.total !== undefined && (!Number.isSafeInteger(value.total) || Number(value.total) < 0)) {
    throw invalidResponse()
  }
  return {
    items: value.items.map(parseAPIKeyRecord),
    next_cursor: value.next_cursor,
    has_more: value.has_more,
    ...(value.total === undefined ? {} : { total: Number(value.total) }),
  }
}

async function get(accessToken: string, id: string): Promise<APIKeyRecord> {
  return parseAPIKeyRecord(await request(accessToken, `/v1/account/api-keys/${encodeURIComponent(id)}`))
}

async function create(accessToken: string, input: APIKeyFields, idempotencyKey: string): Promise<IssuedAPIKey> {
  return parseIssuedAPIKey(await request(accessToken, '/v1/account/api-keys', {
    method: 'POST',
    headers: writeHeaders(idempotencyKey, 0),
    body: JSON.stringify(input),
  }))
}

async function update(
  accessToken: string,
  id: string,
  revision: number,
  input: APIKeyFields,
  idempotencyKey: string,
): Promise<APIKeyRecord> {
  return parseAPIKeyRecord(await request(accessToken, `/v1/account/api-keys/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: writeHeaders(idempotencyKey, revision),
    body: JSON.stringify(input),
  }))
}

async function action(
  accessToken: string,
  id: string,
  revision: number,
  operation: 'activate' | 'rotate' | 'revoke',
  ipAllowlist: string[],
  idempotencyKey: string,
  // fix-smallfu：仅轮换可用——简单版"重置密钥"同时把权限刷新为当前账号可授予的全部。
  options?: { grantAllScopes?: boolean },
): Promise<IssuedAPIKey | APIKeyRecord> {
  const value = await request(accessToken, `/v1/account/api-keys/${encodeURIComponent(id)}/${operation}`, {
    method: 'POST',
    headers: writeHeaders(idempotencyKey, revision),
    body: JSON.stringify({
      ip_allowlist: ipAllowlist,
      ...(operation === 'rotate' && options?.grantAllScopes ? { grant_all_scopes: true } : {}),
    }),
  })
  return operation === 'revoke' ? parseAPIKeyRecord(value) : parseIssuedAPIKey(value)
}

export const apiKeysApi = { action, create, get, list, update }
