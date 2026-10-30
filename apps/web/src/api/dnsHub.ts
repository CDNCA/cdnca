import { ApiError, networkApiError, responseApiError } from './auth'

// ADR 0020 §3.2 用户端「域名解析」：租户自有 DNS 账号（managed_by='tenant'）下全部域名与记录。
// 记录内容不落库，读取实时走 DNS 商，写入经 Mutate 回读确认（后端 fix-dnshub-api）。

export const dnsHubRecordTypes = ['A', 'AAAA', 'CNAME', 'TXT'] as const
export type DNSHubRecordType = (typeof dnsHubRecordTypes)[number]

// 契约 v1（fix-dnshub-api-progress.md）：accounts 每次返回全部自有账号（受 provider_id 影响），带该账号可选线路。
export interface DNSHubAccount {
  provider_id: string
  name: string
  provider_type: string
  status: string
  last_listed_at: string | null
  list_error: string
  domain_count: number
  supported_lines: string[]
  supports_weight: boolean
  record_types: string[]
}

export interface DNSHubDomain {
  provider_id: string
  provider_name: string
  provider_type: string
  apex: string
  record_count: number | null
  last_listed_at?: string
  // DNS 商短码：刷新该账号域名清单时的失败原因（credentials_rejected、rate_limited ...），无失败为 ''
  list_error?: string
}

export interface DNSHubDomainList {
  accounts: DNSHubAccount[]
  items: DNSHubDomain[]
  // '' 表示没有下一页
  next_cursor: string
}

export interface DNSHubDomainQuery {
  provider_id?: string
  q?: string
  cursor?: string
  limit?: number
}

// skipped：账号未验证/已停用/凭据已吊销
export type DNSHubRefreshState = 'refreshed' | 'throttled' | 'failed' | 'skipped'

export interface DNSHubRefreshResult {
  results: { provider_id: string; state: DNSHubRefreshState; domain_count: number; error: string; retry_after_seconds: number }[]
}

// 本平台在用的记录：站点 CNAME、建站自动添加、CDN 供应商验证 TXT、未清理的 ACME DNS-01 挑战（§3.3）
export type DNSHubManagedKind = 'site_cname' | 'site_auto_dns' | 'cdn_validation' | 'acme_challenge'

export interface DNSHubManaged {
  kind: DNSHubManagedKind
  site_id: string
  site_domain: string
}

export interface DNSHubRecordValue {
  // 主机记录（相对域名，@ 为根域）
  name: string
  type: DNSHubRecordType
  value: string
  ttl: number
  // 统一线路名（默认/电信/联通/移动/境外），须在账号 supported_lines 内
  line: string
  // 只有 supports_weight 的账号可非 0；改/删时须原样回传（expected 比较含 weight）
  weight: number
}

export interface DNSHubRecord extends DNSHubRecordValue {
  // 不透明串，后续改/删用
  record_ref: string
  fqdn: string
  managed: DNSHubManaged | null
}

export interface DNSHubRecordList {
  provider_id: string
  apex: string
  // DNS 商列出但无法展示的条数（通配符等非主机名）
  skipped: number
  items: DNSHubRecord[]
}

export interface DNSHubRecordQuery {
  type?: DNSHubRecordType
  q?: string
}

// 201/200 applied（删除 record 为 null）；202 uncertain：已提交但回读未确认
export interface DNSHubMutationResult {
  op_id: string
  state: 'applied' | 'uncertain'
  record?: DNSHubRecord | null
}

export type DNSHubBatchItem =
  | ({ provider_id: string; apex: string; action: 'create' } & DNSHubRecordValue)
  | ({ provider_id: string; apex: string; action: 'update'; record_ref: string; expected: DNSHubRecordValue; confirm_managed?: boolean } & DNSHubRecordValue)
  | { provider_id: string; apex: string; action: 'delete'; record_ref: string; expected: DNSHubRecordValue; confirm_managed?: boolean }

export interface DNSHubBatchItemResult {
  index: number
  status: number
  op_id?: string
  state?: 'applied' | 'uncertain'
  record?: DNSHubRecord | null
  error: { code: string; provider_code?: string } | null
}

export interface DNSHubBatchResult {
  results: DNSHubBatchItemResult[]
}

// dns_provider_error 带 error.provider_code（DNS 商短码）
export type DNSHubApiError = ApiError & { providerCode?: string }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
// 后端每批 1–50 条（handler maxBatchItems）
export const maxBatchItems = 50

function invalid(message: string): Promise<never> {
  return Promise.reject(new ApiError(message, 400, 'validation_error'))
}

function invalidResponse(): ApiError {
  return new ApiError('DNS hub response was invalid', 502, 'invalid_response')
}

const shortCodePattern = /^[a-z][a-z0-9_]{0,63}$/

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
  if (!response.ok) {
    const body = (await response.clone().json().catch(() => null)) as { error?: { provider_code?: unknown } } | null
    const error: DNSHubApiError = await responseApiError(response)
    const providerCode = body?.error?.provider_code
    if (typeof providerCode === 'string' && shortCodePattern.test(providerCode)) error.providerCode = providerCode
    throw error
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

const idPattern = /^[A-Za-z0-9_-]{1,128}$/
// 后端 Idempotency-Key 格式（handler requestIDPattern）；批量还要留出 ".<i>" 后缀，最长 120
const idempotencyKeyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const recordRefPattern = /^[A-Za-z0-9._-]{1,512}$/
const hostLabelPattern = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$/

export function validApex(value: string): boolean {
  return value.length >= 3 && value.length <= 253 && value === value.toLowerCase() &&
    /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(value)
}

// 主机记录：@ 或相对主机名（允许 _ 开头的 TXT 名，如 _acme-challenge）；后端不接受通配符 *（契约 v1）
export function validRecordName(value: string): boolean {
  if (value === '@') return true
  if (value.length > 253 || value !== value.toLowerCase()) return false
  return value.split('.').every((label) => hostLabelPattern.test(label))
}

const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

function validIPv6(value: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(':')) return false
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2
  } catch {
    return false
  }
}

// TXT 新值按契约 v1：1–255 字节，不含控制字符、双引号、反斜杠、首尾空白
export function validRecordValue(type: DNSHubRecordType, value: string): boolean {
  if (!value || value !== value.trim()) return false
  switch (type) {
    case 'A': return ipv4Pattern.test(value)
    case 'AAAA': return validIPv6(value)
    case 'CNAME': return validApex(value.replace(/\.$/, '').toLowerCase()) && value === value.toLowerCase()
    case 'TXT': return new TextEncoder().encode(value).byteLength <= 255 && !/["\\]/.test(value) &&
      [...value].every((character) => { const code = character.codePointAt(0)!; return code > 0x1f && code !== 0x7f })
  }
}

export function validTTL(ttl: number): boolean {
  return Number.isSafeInteger(ttl) && ttl >= 1 && ttl <= 604800
}

export function validRecordInput(input: DNSHubRecordValue): boolean {
  return (dnsHubRecordTypes as readonly string[]).includes(input.type) && validRecordName(input.name) &&
    validRecordValue(input.type, input.value) && validTTL(input.ttl) && typeof input.line === 'string' &&
    input.line.length > 0 && input.line.length <= 64 && Number.isSafeInteger(input.weight) && input.weight >= 0 && input.weight <= 100
}

function validRecordRef(ref: string): boolean {
  return recordRefPattern.test(ref)
}

export function recordValue(record: DNSHubRecordValue): DNSHubRecordValue {
  return { name: record.name, type: record.type, value: record.value, ttl: record.ttl, line: record.line, weight: record.weight }
}

function domainPath(providerID: string, apex: string): string {
  return `/v1/dns/hub/domains/${encodeURIComponent(providerID)}/${encodeURIComponent(apex)}/records`
}

function validDomainList(value: unknown): value is DNSHubDomainList {
  if (!value || typeof value !== 'object') return false
  const list = value as DNSHubDomainList
  return Array.isArray(list.items) && Array.isArray(list.accounts) && typeof list.next_cursor === 'string' &&
    list.items.every((item) => item && typeof item.provider_id === 'string' && typeof item.apex === 'string') &&
    list.accounts.every((item) => item && typeof item.provider_id === 'string' && Array.isArray(item.supported_lines))
}

function validRecordList(value: unknown): value is DNSHubRecordList {
  if (!value || typeof value !== 'object') return false
  const list = value as DNSHubRecordList
  return Array.isArray(list.items) &&
    list.items.every((item) => item && typeof item.record_ref === 'string' && typeof item.name === 'string' &&
      (dnsHubRecordTypes as readonly string[]).includes(item.type))
}

export const dnsHubApi = {
  async domains(accessToken: string, query: DNSHubDomainQuery = {}): Promise<DNSHubDomainList> {
    if ((query.provider_id !== undefined && !idPattern.test(query.provider_id)) ||
      (query.q !== undefined && query.q.length > 253) ||
      (query.cursor !== undefined && (!query.cursor || query.cursor.length > 4096)) ||
      (query.limit !== undefined && (!Number.isInteger(query.limit) || query.limit < 1 || query.limit > 500))) {
      return invalid('Invalid DNS hub domain query')
    }
    const params = new URLSearchParams()
    if (query.provider_id) params.set('provider_id', query.provider_id)
    if (query.q) params.set('q', query.q)
    if (query.cursor) params.set('cursor', query.cursor)
    if (query.limit) params.set('limit', String(query.limit))
    const suffix = params.toString()
    const result = await request<unknown>(accessToken, `/v1/dns/hub/domains${suffix ? `?${suffix}` : ''}`)
    if (!validDomainList(result)) throw invalidResponse()
    return result
  },
  // 不需要 Idempotency-Key；每账号 60 秒内只真正拉一次（其余 throttled）
  refresh(accessToken: string, providerID: string | undefined): Promise<DNSHubRefreshResult> {
    if (providerID !== undefined && !idPattern.test(providerID)) return invalid('Invalid DNS provider')
    return request(accessToken, '/v1/dns/hub/domains/refresh', {
      method: 'POST',
      body: JSON.stringify(providerID ? { provider_id: providerID } : {}),
    })
  },
  async records(accessToken: string, providerID: string, apex: string, query: DNSHubRecordQuery = {}): Promise<DNSHubRecordList> {
    if (!idPattern.test(providerID) || !validApex(apex) ||
      (query.type !== undefined && !(dnsHubRecordTypes as readonly string[]).includes(query.type)) ||
      (query.q !== undefined && query.q.length > 253)) {
      return invalid('Invalid DNS hub record query')
    }
    const params = new URLSearchParams()
    if (query.type) params.set('type', query.type)
    if (query.q) params.set('q', query.q)
    const suffix = params.toString()
    const result = await request<unknown>(accessToken, `${domainPath(providerID, apex)}${suffix ? `?${suffix}` : ''}`)
    if (!validRecordList(result)) throw invalidResponse()
    return result
  },
  create(accessToken: string, providerID: string, apex: string, input: DNSHubRecordValue, idempotencyKey: string): Promise<DNSHubMutationResult> {
    if (!idPattern.test(providerID) || !validApex(apex) || !validRecordInput(input) || !idempotencyKeyPattern.test(idempotencyKey)) {
      return invalid('Invalid DNS record')
    }
    return request(accessToken, domainPath(providerID, apex), {
      method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(recordValue(input)),
    })
  },
  // expected 是改前值：DNS 商上的记录已被他人改动时后端回 409 dns_record_changed，不覆盖。
  // 本平台在用的记录须带 confirm_managed，否则后端回 409 dns_record_managed。
  update(accessToken: string, providerID: string, apex: string, record: DNSHubRecord, input: DNSHubRecordValue, confirmManaged: boolean, idempotencyKey: string): Promise<DNSHubMutationResult> {
    if (!idPattern.test(providerID) || !validApex(apex) || !validRecordRef(record.record_ref) || !validRecordInput(input) ||
      !idempotencyKeyPattern.test(idempotencyKey)) {
      return invalid('Invalid DNS record')
    }
    return request(accessToken, `${domainPath(providerID, apex)}/${encodeURIComponent(record.record_ref)}`, {
      method: 'PATCH',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ ...recordValue(input), expected: recordValue(record), ...(confirmManaged ? { confirm_managed: true } : {}) }),
    })
  },
  remove(accessToken: string, providerID: string, apex: string, record: DNSHubRecord, confirmManaged: boolean, idempotencyKey: string): Promise<DNSHubMutationResult> {
    if (!idPattern.test(providerID) || !validApex(apex) || !validRecordRef(record.record_ref) || !idempotencyKeyPattern.test(idempotencyKey)) {
      return invalid('Invalid DNS record')
    }
    return request(accessToken, `${domainPath(providerID, apex)}/${encodeURIComponent(record.record_ref)}`, {
      method: 'DELETE',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expected: recordValue(record), ...(confirmManaged ? { confirm_managed: true } : {}) }),
    })
  },
  // 1–50 条，逐条独立执行、互不回滚；第 i 条用键 "<Idempotency-Key>.<i>"，整批重试即逐条回放
  batch(accessToken: string, items: DNSHubBatchItem[], idempotencyKey: string): Promise<DNSHubBatchResult> {
    const valid = items.length > 0 && items.length <= maxBatchItems && idempotencyKey.length <= 120 &&
      idempotencyKeyPattern.test(idempotencyKey) &&
      items.every((item) => idPattern.test(item.provider_id) && validApex(item.apex) && (item.action === 'create'
        ? validRecordInput(item)
        : validRecordRef(item.record_ref) && (item.action === 'delete' || validRecordInput(item))))
    if (!valid) return invalid('Invalid DNS batch')
    return request(accessToken, '/v1/dns/hub/records/batch', {
      method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify({ items }),
    })
  },
}
