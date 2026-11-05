import { ApiError, networkApiError, responseApiError } from './auth'

export const creatableDNSProviderTypes = ['aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dns_la', 'namecom', 'custom_http',
  'dnspod_com', 'godaddy', 'namesilo', 'cloudns', 'namecheap', 'jdcloud'] as const
export type CreatableDNSProviderType = (typeof creatableDNSProviderTypes)[number]
export type DNSProviderType = CreatableDNSProviderType | 'dnsdun'
export type DNSProviderStatus = 'unverified' | 'verified' | 'disabled'
export type DNSProviderCredentials = Record<string, string>

export interface DNSProvider {
  id: string
  scope_id: string
  name: string
  // 备注（迁移 490）；旧服务端不返回时按空处理
  remark?: string
  provider_type: string
  credentials_configured: true
  status: DNSProviderStatus
  // platform：平台 DNS 配置同步来的只读副本（迁移 569）；旧服务端不返回时按 tenant 处理
  managed_by?: 'tenant' | 'platform'
  version: number
  created_at: string
  updated_at: string
  // 仅平台视图的列表返回：scope_id 所属用户（DNS API「用户」列）
  owner?: { id: string; display_id: string; username: string }
}

// 平台视图的 DNS API 列表筛选：scope_id 按用户（仅平台），managed_by=tenant 排除平台 DNS 副本。
export interface DNSProviderListFilter {
  scope_id?: string
  managed_by?: 'tenant' | 'platform'
}

// 平台 DNS 配置同步来的副本只供平台维护网站 CNAME，用户端不可见：
// 租户列表接口已不返回它，用户端各处再按 managed_by 过滤一次以防旧响应。
export function ownDNSProviders(items: DNSProvider[]): DNSProvider[] {
  return items.filter((item) => item.managed_by !== 'platform')
}

export interface DNSProviderList {
  items: DNSProvider[]
  next_cursor?: string
}

export interface DNSProviderPageInput {
  limit: number
  cursor?: string
}

export interface DNSLegacySettings {
  scope_id: string
  ttl: number
  version: number
  updated_at?: string
}

export interface DNSLegacyOperation {
  id: string
  kind: 'dns.repair.v1' | 'dns.cleanup.v1'
  subject: string
  state: 'queued' | 'running' | 'succeeded' | 'partial_failed' | 'failed' | 'cancelled'
  attempt: number
  max_attempts: number
  progress: {
    total: number
    completed: number
    succeeded: number
    failed: number
    cancelled: number
    pending: number
  }
  last_error_code?: string
  created_at: string
  started_at?: string
  updated_at: string
  completed_at?: string
}

export interface DNSLegacyOperationResponse {
  operation: DNSLegacyOperation
  replayed: boolean
}

const providerAuthorityPageLimit = 20
const maxProviderAuthorityPages = 100

function invalidProviderListResponse(): ApiError {
  return new ApiError('DNS provider list response was invalid', 502, 'invalid_response')
}

async function listAllProviders(accessToken: string, filter: DNSProviderListFilter = {}): Promise<DNSProviderList> {
  const items: DNSProvider[] = []
  const seenIDs = new Set<string>()
  const seenCursors = new Set<string>()
  let cursor: string | undefined
  for (let page = 0; page < maxProviderAuthorityPages; page += 1) {
    const query = new URLSearchParams(cursor ? { limit: String(providerAuthorityPageLimit), cursor } : {})
    if (filter.scope_id) query.set('scope_id', filter.scope_id)
    if (filter.managed_by) query.set('managed_by', filter.managed_by)
    const search = query.toString()
    const path = search ? `/v1/dns/providers?${search}` : '/v1/dns/providers'
    const result = await request<DNSProviderList>(accessToken, path)
    if (!Array.isArray(result.items)) throw invalidProviderListResponse()
    for (const item of result.items) {
      if (!item || typeof item.id !== 'string' || !item.id || seenIDs.has(item.id)) {
        throw invalidProviderListResponse()
      }
      seenIDs.add(item.id)
      items.push(item)
    }
    if (result.next_cursor === undefined) return { items }
    if (typeof result.next_cursor !== 'string' || !result.next_cursor ||
      result.next_cursor.length > 4096 || seenCursors.has(result.next_cursor)) {
      throw invalidProviderListResponse()
    }
    seenCursors.add(result.next_cursor)
    cursor = result.next_cursor
  }
  throw invalidProviderListResponse()
}

export interface CreateDNSProviderInput {
  target_scope_id?: string
  name: string
  remark?: string
  provider_type: CreatableDNSProviderType
  credentials: DNSProviderCredentials
}

export interface UpdateDNSProviderInput {
  expected_version: number
  name: string
  remark?: string
  status: 'unverified' | 'disabled'
  credentials?: DNSProviderCredentials
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const utf8Encoder = new TextEncoder()
const credentialKeys: Record<CreatableDNSProviderType, readonly string[]> = {
  aliyun: ['access_key_id', 'access_key_secret'],
  cloudflare: ['api_token'],
  huawei: ['access_key', 'secret_key', 'region', 'project_id'],
  dnspod_cn: ['dp_id', 'dp_key'],
  dns_com: ['api_key', 'api_secret'],
  dns_la: ['api_id', 'api_secret'],
  namecom: ['username', 'api_token'],
  custom_http: ['endpoint', 'secret'],
  dnspod_com: ['dp_id', 'dp_key'],
  godaddy: ['api_key', 'api_secret'],
  namesilo: ['key'],
  cloudns: ['sub_auth_id', 'auth_password'],
  namecheap: ['username', 'api_key', 'source_ip'],
  jdcloud: ['access_key_id', 'access_key_secret'],
}

// 自定义 HTTP 接口: an https endpoint (no credentials, query or fragment;
// internal addresses are refused by the server) and a signing secret.
export function isValidCustomHTTPCredential(name: 'endpoint' | 'secret', value: unknown): boolean {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) return false
  if (name === 'secret') return value.length >= 16 && value.length <= 512
  if (value.length > 2048) return false
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
      parsed.hostname !== 'localhost' && !parsed.hostname.endsWith('.localhost')
  } catch {
    return false
  }
}

export function isValidDNSLACredential(name: 'api_id' | 'api_secret', value: unknown): boolean {
  if (typeof value !== 'string') return false
  for (const character of value) {
    const codePoint = character.codePointAt(0)!
    if (codePoint <= 0x1f || codePoint === 0x7f) return false
  }
  const byteLength = utf8Encoder.encode(value).byteLength
  return byteLength >= 1 && byteLength <= 4096 && (name !== 'api_id' || !value.includes(':'))
}

// name.com: account username and API token for HTTP Basic authentication
// (printable ASCII; the username cannot hold the ':' separator).
export function isValidNameComCredential(name: 'username' | 'api_token', value: unknown): boolean {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) return false
  return name === 'username' ? value.length <= 128 && !value.includes(':') : value.length <= 256
}

// GoDaddy "sso-key KEY:SECRET" (the key cannot hold ':') and Namesilo API
// key: printable ASCII.
export function isValidGoDaddyCredential(name: 'api_key' | 'api_secret', value: unknown): boolean {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) return false
  return name === 'api_key' ? value.length <= 128 && !value.includes(':') : value.length <= 256
}

export function isValidNamesiloCredential(value: unknown): boolean {
  return typeof value === 'string' && /^[\x21-\x7e]{1,128}$/.test(value)
}

// ClouDNS sub-user (sub_auth_id is a number), Namecheap (source_ip is the
// IPv4 address whitelisted in the Namecheap account: the control plane's
// egress IP), JD Cloud AccessKey: printable ASCII as the server checks.
export function isValidKeyedDNSCredential(name: string, value: unknown): boolean {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) return false
  switch (name) {
    case 'sub_auth_id': return /^[1-9][0-9]{0,19}$/.test(value)
    case 'source_ip': return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(value)
    case 'username': return value.length <= 64
    case 'api_key': case 'access_key_id': return value.length <= 128
    default: return value.length <= 256
  }
}

// Providers whose adapter writes carrier lines (dnsproviderremote
// ProviderCapabilityMatrix Line). Cloudflare and name.com answer on the
// default line only; an unknown, unsupported or not yet loaded provider is
// never assumed to split lines.
const carrierLineProviders: readonly string[] = ['aliyun', 'huawei', 'dnspod_cn', 'dns_com', 'dns_la', 'custom_http', 'plugin',
  // JD Cloud viewValue lines (默认/电信/联通/移动/境外; 境外 not on its free plan); ClouDNS and Namecheap: default only.
  'jdcloud']

export function dnsProviderSplitsCarrierLines(providerType: string | undefined): boolean {
  return providerType !== undefined && carrierLineProviders.includes(providerType)
}

// Providers whose adapter writes a per-record weight (matrix Weight).
export function dnsProviderWritesWeights(providerType: string | undefined): boolean {
  return providerType === 'dnspod_cn'
}

function validProviderCredentials(providerType: string, credentials: unknown): boolean {
  const expected = Object.hasOwn(credentialKeys, providerType)
    ? credentialKeys[providerType as CreatableDNSProviderType]
    : undefined
  if (!expected || typeof credentials !== 'object' || credentials === null || Array.isArray(credentials)) return false
  const actual = Object.keys(credentials).sort()
  const exactKeys = actual.length === expected.length
    && [...expected].sort().every((key, index) => key === actual[index])
  if (!exactKeys) return false
  const values = credentials as DNSProviderCredentials
  if (!actual.every((key) => typeof values[key] === 'string')) return false
  if (providerType === 'custom_http') {
    return isValidCustomHTTPCredential('endpoint', values.endpoint) && isValidCustomHTTPCredential('secret', values.secret)
  }
  if (providerType === 'namecom') {
    return isValidNameComCredential('username', values.username) && isValidNameComCredential('api_token', values.api_token)
  }
  if (providerType === 'godaddy') {
    return isValidGoDaddyCredential('api_key', values.api_key) && isValidGoDaddyCredential('api_secret', values.api_secret)
  }
  if (providerType === 'namesilo') return isValidNamesiloCredential(values.key)
  if (providerType === 'cloudns' || providerType === 'namecheap' || providerType === 'jdcloud') {
    return actual.every((key) => isValidKeyedDNSCredential(key, values[key]))
  }
  return providerType !== 'dns_la'
    || (isValidDNSLACredential('api_id', values.api_id)
      && isValidDNSLACredential('api_secret', values.api_secret))
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
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

function writeHeaders(idempotencyKey: string, version?: number): HeadersInit {
  return {
    'Idempotency-Key': idempotencyKey,
    ...(version ? { 'If-Match': `"${version}"` } : {}),
  }
}

export const dnsApi = {
  legacySettings(accessToken: string): Promise<DNSLegacySettings> {
    return request(accessToken, '/v1/dns/settings')
  },
  updateLegacySettings(accessToken: string, input: { ttl: number; expected_version: number }, idempotencyKey: string): Promise<DNSLegacySettings> {
    if (!Number.isSafeInteger(input.ttl) || input.ttl < 1 || input.ttl > 604800 ||
      !Number.isSafeInteger(input.expected_version) || input.expected_version < 1) {
      return Promise.reject(new ApiError('Invalid DNS legacy settings', 400, 'validation_error'))
    }
    return request(accessToken, '/v1/dns/settings', {
      method: 'PATCH', headers: writeHeaders(idempotencyKey, input.expected_version),
      body: JSON.stringify({ ttl: input.ttl }),
    })
  },
  startLegacyOperation(accessToken: string, kind: 'repair' | 'cleanup', idempotencyKey: string): Promise<DNSLegacyOperationResponse> {
    return request(accessToken, `/v1/dns/settings/${kind}`, {
      method: 'POST', headers: writeHeaders(idempotencyKey), body: '{}',
    })
  },
  legacyOperation(accessToken: string, id: string): Promise<DNSLegacyOperation> {
    if (!id || id.length > 128) return Promise.reject(new ApiError('Invalid DNS operation', 400, 'validation_error'))
    return request(accessToken, `/v1/dns/settings/operations/${encodeURIComponent(id)}`)
  },
  list(accessToken: string, input?: DNSProviderPageInput, filter?: DNSProviderListFilter): Promise<DNSProviderList> {
    if (!input) return listAllProviders(accessToken, filter)
    if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100 ||
      (input.cursor !== undefined && (!input.cursor || input.cursor.length > 4096))) {
      return Promise.reject(new ApiError('Invalid DNS provider pagination', 400, 'validation_error'))
    }
    const query = new URLSearchParams({ limit: String(input.limit) })
    if (input.cursor) query.set('cursor', input.cursor)
    return request(accessToken, `/v1/dns/providers?${query.toString()}`)
  },
  create(accessToken: string, input: CreateDNSProviderInput, idempotencyKey: string): Promise<DNSProvider> {
    if (!validProviderCredentials(input.provider_type, input.credentials)) {
      return Promise.reject(new ApiError('Invalid DNS provider credentials', 400, 'validation_error'))
    }
    return request(accessToken, '/v1/dns/providers', {
      method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input),
    })
  },
  update(accessToken: string, id: string, providerType: string, input: UpdateDNSProviderInput, idempotencyKey: string): Promise<DNSProvider> {
    const creatable = Object.hasOwn(credentialKeys, providerType)
    if ((!creatable && input.status !== 'disabled')
      || (input.credentials !== undefined && !validProviderCredentials(providerType, input.credentials))) {
      return Promise.reject(new ApiError('Invalid DNS provider credentials', 400, 'validation_error'))
    }
    return request(accessToken, `/v1/dns/providers/${encodeURIComponent(id)}`, {
      method: 'PATCH', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input),
    })
  },
  verify(accessToken: string, id: string, providerType: string, version: number, idempotencyKey: string): Promise<DNSProvider> {
    if (!Object.hasOwn(credentialKeys, providerType)) {
      return Promise.reject(new ApiError('DNS provider verification is not supported', 400, 'provider_verification_unsupported'))
    }
    return request(accessToken, `/v1/dns/providers/${encodeURIComponent(id)}/verify`, {
      method: 'POST', headers: writeHeaders(idempotencyKey, version),
    })
  },
  remove(accessToken: string, id: string, version: number, idempotencyKey: string): Promise<void> {
    return request(accessToken, `/v1/dns/providers/${encodeURIComponent(id)}`, {
      method: 'DELETE', headers: writeHeaders(idempotencyKey, version),
    })
  },
}
