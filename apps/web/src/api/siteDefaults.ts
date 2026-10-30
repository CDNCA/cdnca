import { ApiError, networkApiError, responseApiError } from './auth'
import type { SiteAutoDNSStatus } from './sites'

// 网站列表 > 默认设置（租户给自己新建网站设的默认值，迁移 490）与 解析检测 > 同步解析。

export const siteDefaultSettingNames = [
  'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port', 'ups_keepalive',
  'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable', 'hsts', 'ocsp_stapling',
  'recv_real_time', 'send_real_time',
  // fp-site3（迁移 513）：36 项第二批简单字段
  'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port', 'origin_connect_timeout', 'origin_read_timeout',
  // fp-site4（迁移 514）：36 项第三批
  'cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable',
  // fp-site5b（迁移 516）：复杂规则按复制快照（规则库 ID，建站时复制一份给新站）、屏蔽透明代理、源站请求头、上传限制
  'cc_policy', 'waf_policy', 'acl_policy', 'block_proxy', 'req_header', 'post_size_limit',
  // fp-site5a（迁移 515）：HTTPS 协议，建站带入站点字段
  'http2', 'http3', 'ssl_prefer_server_ciphers',
  // fp-site6（迁移 518）：独立维护的规则文档（JSON），建站时复制给新站
  'proxy_cache', 'cond_origin',
  // fp-site7（迁移 519）：区域屏蔽快捷预设，建站时一条 country 规则并入新站 WAF
  'block_region',
  // tls-custom（迁移 520）：#11 自定义套件，冒号分隔，取值来自站点同一份白名单（siteTLSCustomCipherSuites）；
  // ssl_cipher_preset 默认为 custom 时随它一起带入新站
  'ssl_cipher_suites',
] as const
export type SiteDefaultSettingName = (typeof siteDefaultSettingNames)[number]

// 取值类型：开关项为 1/0，端口为空格分隔，其余为单值
// 取值为 JSON 规则文档的设置项（上限 65536 字符）
export const siteDefaultDocuments: ReadonlySet<SiteDefaultSettingName> = new Set(['proxy_cache', 'cond_origin'])
// 条件源站默认里代表「新站的默认源站池」的占位（后端 SiteDefaultCondOriginPool）
export const siteDefaultCondOriginPool = '@default'

export const siteDefaultSwitches: ReadonlySet<SiteDefaultSettingName> = new Set([
  'ups_keepalive', 'websocket_enable', 'force_ssl_enable', 'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
  'gzip_enable', 'ipv6_enable', 'block_proxy', 'http2', 'http3', 'ssl_prefer_server_ciphers',
])
// 取值为本人规则库 ID 的设置项与对应规则库类型
export const siteDefaultPolicyKinds: Partial<Record<SiteDefaultSettingName, 'cc' | 'waf' | 'acl'>> = {
  cc_policy: 'cc', waf_policy: 'waf', acl_policy: 'acl',
}

export interface SiteUserDefault {
  id: string
  display_id: string
  scope_id: string
  owner_user_id: string
  setting_name: SiteDefaultSettingName
  setting_value: string
  scope_name: 'global' | 'group'
  group_id: string | null
  group_name: string | null
  enabled: boolean
  version: number
  created_at: string
  updated_at: string
}

export interface SiteUserDefaultList {
  items: SiteUserDefault[]
  total: number
  page: number
  limit: number
}

export interface CreateSiteDefaultInput {
  setting_name: SiteDefaultSettingName
  setting_value: string
  scope_name: 'global' | 'group'
  group_id?: string | null
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit, expected: number): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status !== expected) throw new ApiError('Unexpected success response', 502, 'invalid_response')
  return (expected === 204 ? null : await response.json()) as T
}

function isList(value: unknown): value is SiteUserDefaultList {
  return typeof value === 'object' && value !== null && Array.isArray((value as SiteUserDefaultList).items) &&
    typeof (value as SiteUserDefaultList).total === 'number'
}

async function list(accessToken: string, page: number, limit: number): Promise<SiteUserDefaultList> {
  const raw = await request<unknown>(accessToken, `/v1/site-defaults?page=${page}&limit=${limit}`, { method: 'GET' }, 200)
  if (!isList(raw)) throw new ApiError('Invalid site defaults response', 502, 'invalid_response')
  return raw
}

function create(accessToken: string, input: CreateSiteDefaultInput, key: string): Promise<SiteUserDefault> {
  return request(accessToken, '/v1/site-defaults', {
    method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(input),
  }, 201)
}

function update(accessToken: string, item: SiteUserDefault, changes: { setting_value?: string; enabled?: boolean }, key: string): Promise<SiteUserDefault> {
  return request(accessToken, `/v1/site-defaults/${encodeURIComponent(item.id)}`, {
    method: 'PATCH', headers: { 'Idempotency-Key': key }, body: JSON.stringify({ expected_version: item.version, ...changes }),
  }, 200)
}

async function remove(accessToken: string, item: SiteUserDefault, key: string): Promise<void> {
  await request(accessToken, `/v1/site-defaults/${encodeURIComponent(item.id)}`, {
    method: 'DELETE', headers: { 'Idempotency-Key': key },
  }, 204)
}

function syncAutoDNS(accessToken: string, siteID: string, providerID?: string): Promise<SiteAutoDNSStatus> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/auto-dns/sync`, {
    method: 'POST', body: JSON.stringify(providerID ? { provider_id: providerID } : {}),
  }, 202)
}

export const siteDefaultsApi = { create, list, remove, syncAutoDNS, update }
