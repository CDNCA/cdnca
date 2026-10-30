import { ApiError, networkApiError, responseApiError } from './auth'

export interface PlatformSystemOtherSettings {
  source_ip_header: string
	api_key_enabled: boolean
	dns_protection: string
  record_repair_mode: 'off' | 'repair' | 'repair_delete_extra'
  sync_batch: number
  sync_scope: 'region' | 'line_group'
  disable_failed_sync_nodes: boolean
  resource_rank: number
  http_proxy: string
  tcp_factor: number
  /** 四层旧连接排空上限（秒）：配置变更后已有连接最多再保持这么久，0 为不限。 */
  l4_drain_max_seconds: number
  /** 域名所有权验证：不验证 / 只验通配符（默认）/ 全部验证。 */
  domain_ownership_policy: DomainOwnershipPolicy
  /** 证书到期前提醒的天数（降序，1–60，最多 8 个），进通知中心。 */
  certificate_expiry_notice_days: number[]
  /** 向官方贡献规则情报（ADR 0011 §4.3），默认开。 */
  rule_intel_contribution: boolean
}

export type DomainOwnershipPolicy = 'off' | 'wildcard_only' | 'all'

export interface PlatformSystemOtherSettingsDocument {
  schema: 'cdnca.platform-system-other-settings/v1'
  revision: number
  updated_at?: string
  value: PlatformSystemOtherSettings
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const settingKeys = ['source_ip_header', 'api_key_enabled', 'dns_protection', 'record_repair_mode', 'sync_batch', 'sync_scope', 'disable_failed_sync_nodes', 'resource_rank', 'http_proxy', 'tcp_factor', 'l4_drain_max_seconds', 'domain_ownership_policy', 'certificate_expiry_notice_days', 'rule_intel_contribution'] as const
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function exact(value: Record<string, unknown>) { const keys = Object.keys(value); return keys.length === settingKeys.length && settingKeys.every((key) => Object.hasOwn(value, key)) }
function text(value: unknown, max: number) { return typeof value === 'string' && Array.from(value).length <= max && !value.includes(String.fromCharCode(0)) && !value.includes('\r') }
function isSettings(value: unknown): value is PlatformSystemOtherSettings {
  if (!record(value) || !exact(value) || typeof value.api_key_enabled !== 'boolean' || !text(value.dns_protection, 2048) ||
    (value.record_repair_mode !== 'off' && value.record_repair_mode !== 'repair' && value.record_repair_mode !== 'repair_delete_extra') ||
    !Number.isSafeInteger(value.sync_batch) || Number(value.sync_batch) < 1 || Number(value.sync_batch) > 10000 ||
    (value.sync_scope !== 'region' && value.sync_scope !== 'line_group') || typeof value.disable_failed_sync_nodes !== 'boolean' ||
    !Number.isSafeInteger(value.resource_rank) || Number(value.resource_rank) < 1 || Number(value.resource_rank) > 1000 ||
    typeof value.tcp_factor !== 'number' || !Number.isFinite(value.tcp_factor) || value.tcp_factor < 0.01 || value.tcp_factor > 100 ||
    !Number.isSafeInteger(value.l4_drain_max_seconds) || Number(value.l4_drain_max_seconds) < 0 || Number(value.l4_drain_max_seconds) > 604800 ||
    (value.domain_ownership_policy !== 'off' && value.domain_ownership_policy !== 'wildcard_only' && value.domain_ownership_policy !== 'all') ||
    !validCertificateNoticeDays(value.certificate_expiry_notice_days) || typeof value.rule_intel_contribution !== 'boolean') return false
  return text(value.source_ip_header, 256) && text(value.http_proxy, 2048)
}
/** 1–8 days, each 1–60, strictly descending (certnotify.ValidNoticeDays). */
export function validCertificateNoticeDays(value: unknown): value is number[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= 8 &&
    value.every((day, index) => Number.isSafeInteger(day) && day >= 1 && day <= 60 && (index === 0 || value[index - 1] > day))
}
function isDocument(value: unknown): value is PlatformSystemOtherSettingsDocument {
  if (!record(value) || value.schema !== 'cdnca.platform-system-other-settings/v1' || !Number.isSafeInteger(value.revision) || Number(value.revision) < 0 || !isSettings(value.value)) return false
  return !Object.hasOwn(value, 'updated_at') || typeof value.updated_at === 'string' && Number.isFinite(Date.parse(value.updated_at))
}

const legacyDefaults: Pick<PlatformSystemOtherSettings, 'api_key_enabled' | 'record_repair_mode' | 'sync_scope' | 'disable_failed_sync_nodes' | 'l4_drain_max_seconds' | 'domain_ownership_policy' | 'certificate_expiry_notice_days' | 'rule_intel_contribution'> = {
  certificate_expiry_notice_days: [30, 14, 7, 3, 1],
	api_key_enabled: true,
  domain_ownership_policy: 'wildcard_only',
  l4_drain_max_seconds: 86400,
  record_repair_mode: 'repair',
  sync_scope: 'line_group',
  disable_failed_sync_nodes: false,
  rule_intel_contribution: true,
}

function normalizeLegacyDocument(value: unknown): unknown {
  if (!record(value) || !record(value.value)) return value
  const dnsProtection = typeof value.value.dns_protection === 'boolean' ? '' : value.value.dns_protection
  return { ...value, value: { ...legacyDefaults, ...value.value, dns_protection: dnsProtection } }
}

async function request(accessToken: string, method: 'GET' | 'PUT', revision?: number, value?: PlatformSystemOtherSettings, requestId?: string, idempotencyKey?: string) {
  const requestID = requestId ?? `system-other-settings-${crypto.randomUUID()}`
  const writeIdempotencyKey = idempotencyKey ?? requestID
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-other-settings`, {
      method, credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': requestID, ...(method === 'PUT' ? { 'Content-Type': 'application/json', 'If-Match': `"${revision}"`, 'Idempotency-Key': writeIdempotencyKey } : {}) },
      ...(method === 'PUT' ? { body: JSON.stringify({ value }) } : {}),
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown; try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'system_other_settings_invalid_response') }
  const normalized = normalizeLegacyDocument(body)
  if (!isDocument(normalized)) throw new ApiError('Invalid API response', 0, 'system_other_settings_invalid_response')
  return normalized
}

export const systemOtherSettingsApi = {
  get(accessToken: string) { return request(accessToken, 'GET') },
  put(accessToken: string, revision: number, value: PlatformSystemOtherSettings, requestId?: string, idempotencyKey?: string) { return request(accessToken, 'PUT', revision, value, requestId, idempotencyKey) },
}
