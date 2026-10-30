import { ApiError, networkApiError, responseApiError } from './auth'

// 节点管理 > DNS配置: the installation-wide DNS configuration and its CNAME
// domains (platform administrator, /v1/dns/platform-*).

export interface PlatformDNSError {
  source: 'platform_sync' | 'cname_allocation' | 'cname_retarget' | 'dns_repair' | 'dns_cleanup' | string
  code: string
  message?: string
  at: string
}

export interface PlatformDNSConfig {
  provider_type?: string
  identifiers: Record<string, string>
  secret_saved: boolean
  ttl: number
  ip_weight: boolean
  weight_supported: boolean
  version: number
  updated_at?: string
  sync: { tenants: number; error?: string; at?: string }
  last_error: PlatformDNSError | null
}

export interface SavePlatformDNSConfigInput {
  provider_type: string
  credentials?: Record<string, string>
  ttl: number
  ip_weight: boolean
}

export interface PlatformDNSOperation {
  id: string
  kind: 'dns.repair.v1' | 'dns.cleanup.v1'
  subject: string
  state: string
  progress: { total: number; completed: number; succeeded: number; failed: number }
}

export interface PlatformDNSConnection {
  provider_type: string
  zones: { name: string; status: 'hosted' | 'not_hosted' | 'unchecked'; apex?: string }[]
}

export interface PlatformDNSZone {
  id: string
  display_id: number
  name: string
  remark: string
  in_use: boolean
  // 参与随机分配: new sites without a CNAME domain draw one of the marked domains.
  random_allocation: boolean
  version: number
  created_at: string
  updated_at: string
}

export interface PlatformDNSZoneInput {
  name: string
  remark: string
  random_allocation: boolean
}

export interface PlatformDNSZonePage {
  items: PlatformDNSZone[]
  total: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

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
  return { 'Idempotency-Key': idempotencyKey, ...(version ? { 'If-Match': `"${version}"` } : {}) }
}

export const dnsPlatformApi = {
  config(accessToken: string): Promise<PlatformDNSConfig> {
    return request(accessToken, '/v1/dns/platform-config')
  },
  save(accessToken: string, input: SavePlatformDNSConfigInput, version: number, idempotencyKey: string): Promise<PlatformDNSConfig> {
    if (!Number.isSafeInteger(input.ttl) || input.ttl < 1 || input.ttl > 86400) {
      return Promise.reject(new ApiError('Invalid TTL', 400, 'validation_error'))
    }
    return request(accessToken, '/v1/dns/platform-config', {
      method: 'PUT', headers: writeHeaders(idempotencyKey, version), body: JSON.stringify(input),
    })
  },
  // 连接测试: read-only; without credentials the saved ones are tested.
  testConnection(accessToken: string, input: { provider_type: string; credentials?: Record<string, string> }): Promise<PlatformDNSConnection> {
    return request(accessToken, '/v1/dns/platform-config/connection-test', { method: 'POST', body: JSON.stringify(input) })
  },
  start(accessToken: string, kind: 'repair' | 'cleanup', idempotencyKey: string): Promise<{ operations: PlatformDNSOperation[]; replayed: boolean }> {
    return request(accessToken, `/v1/dns/platform-config/${kind}`, { method: 'POST', headers: writeHeaders(idempotencyKey), body: '{}' })
  },
  zones(accessToken: string, input: { page: number; limit: number; search: string }): Promise<PlatformDNSZonePage> {
    const query = new URLSearchParams({ page: String(input.page), limit: String(input.limit), search: input.search.trim() })
    return request(accessToken, `/v1/dns/platform-zones?${query}`)
  },
  createZone(accessToken: string, input: PlatformDNSZoneInput, idempotencyKey: string): Promise<PlatformDNSZone> {
    return request(accessToken, '/v1/dns/platform-zones', { method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input) })
  },
  updateZone(accessToken: string, zone: PlatformDNSZone, input: PlatformDNSZoneInput, idempotencyKey: string): Promise<PlatformDNSZone> {
    return request(accessToken, `/v1/dns/platform-zones/${encodeURIComponent(zone.id)}`, {
      method: 'PATCH', headers: writeHeaders(idempotencyKey, zone.version), body: JSON.stringify(input),
    })
  },
  deleteZone(accessToken: string, zone: PlatformDNSZone, idempotencyKey: string): Promise<void> {
    return request(accessToken, `/v1/dns/platform-zones/${encodeURIComponent(zone.id)}`, {
      method: 'DELETE', headers: writeHeaders(idempotencyKey, zone.version),
    })
  },
}
