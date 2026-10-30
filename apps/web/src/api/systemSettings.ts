import { ApiError, networkApiError, responseApiError } from './auth'

export interface PlatformSystemSettings {
  system_name: string
  user_title: string
  admin_title: string
  footer_links: string
  footer_text: string
  global_js: string
  bound_domains: string
  favicon?: string
  logo?: string
  login_ad?: string
  expiry_close: boolean
  traffic_close: boolean
  allow_upgrade: boolean
  allow_downgrade: boolean
  purchase_notice?: string
  maintenance: boolean
  maintenance_message: string
  auto_upgrade_node: boolean
  certificate?: string
  private_key?: string
  // https hosts the global JS may report to / load images from (container CSP connect-src, img-src).
  global_js_report_hosts?: string[]
}

export interface PlatformSystemSettingsDocument {
  schema: 'cdnca.platform-system-settings/v1'
  revision: number
  updated_at?: string
  value: PlatformSystemSettings
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const settingKeys = [
  'system_name', 'user_title', 'admin_title', 'footer_links', 'footer_text', 'global_js', 'bound_domains',
  'expiry_close', 'traffic_close', 'allow_upgrade', 'allow_downgrade', 'maintenance', 'maintenance_message',
  'auto_upgrade_node',
] as const
const optionalSettingKeys = ['favicon', 'logo', 'login_ad', 'purchase_notice', 'certificate', 'private_key'] as const
const reportHostsKey = 'global_js_report_hosts'
export const maxGlobalJSReportHosts = 20
const reportHostPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/

// Mirrors the control-api rule: plain lowercase hostnames, unique, at most 20.
export function validGlobalJSReportHosts(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= maxGlobalJSReportHosts &&
    value.every((host) => typeof host === 'string' && host.length <= 253 && reportHostPattern.test(host)) &&
    new Set(value).size === value.length
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasRequiredKeys(value: Record<string, unknown>, keys: readonly string[]) {
  return keys.every((key) => Object.hasOwn(value, key))
}

function isSettings(value: unknown): value is PlatformSystemSettings {
  if (!isRecord(value) || !hasRequiredKeys(value, settingKeys) || Object.keys(value).some((key) => !settingKeys.includes(key as typeof settingKeys[number]) && !optionalSettingKeys.includes(key as typeof optionalSettingKeys[number]) && key !== reportHostsKey)) return false
  if (Object.hasOwn(value, reportHostsKey) && !validGlobalJSReportHosts(value[reportHostsKey])) return false
  return ['system_name', 'user_title', 'admin_title', 'footer_links', 'footer_text', 'global_js', 'bound_domains', 'maintenance_message']
    .every((key) => typeof value[key] === 'string') &&
    ['expiry_close', 'traffic_close', 'allow_upgrade', 'allow_downgrade', 'maintenance', 'auto_upgrade_node']
      .every((key) => typeof value[key] === 'boolean') &&
    optionalSettingKeys.every((key) => !Object.hasOwn(value, key) || typeof value[key] === 'string')
}

function isDocument(value: unknown): value is PlatformSystemSettingsDocument {
  if (!isRecord(value) || !['schema', 'revision', 'value', 'updated_at'].every((key) => Object.hasOwn(value, key) || key === 'updated_at') || Object.keys(value).some((key) => !['schema', 'revision', 'value', 'updated_at'].includes(key))) return false
  return value.schema === 'cdnca.platform-system-settings/v1' && Number.isSafeInteger(value.revision) &&
    (value.revision as number) >= 0 && isSettings(value.value) &&
    (!Object.hasOwn(value, 'updated_at') || (typeof value.updated_at === 'string' && Number.isFinite(Date.parse(value.updated_at))))
}

async function request<T>(accessToken: string, method: 'GET' | 'PUT', value?: PlatformSystemSettings, revision?: number, requestId?: string, idempotencyKey?: string): Promise<T> {
  const requestID = requestId ?? `system-settings-${crypto.randomUUID()}`
  const writeIdempotencyKey = idempotencyKey ?? requestID
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-settings`, {
      method,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID,
        ...(method === 'PUT' ? {
          'Content-Type': 'application/json',
          'If-Match': `"${revision}"`,
          'Idempotency-Key': writeIdempotencyKey,
        } : {}),
      },
      ...(method === 'PUT' ? { body: JSON.stringify({ value }) } : {}),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
  if (!isDocument(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return body as T
}

export interface PublicSystemSettings {
  system_name: string
  user_title: string
  admin_title: string
  purchase_notice: string
  global_js: string
}

const publicSettingKeys = ['system_name', 'user_title', 'admin_title', 'purchase_notice', 'global_js'] as const

function isPublicSettings(value: unknown): value is PublicSystemSettings {
  return isRecord(value) && Object.keys(value).length === publicSettingKeys.length &&
    publicSettingKeys.every((key) => typeof value[key] === 'string')
}

async function requestPublic(accessToken: string): Promise<PublicSystemSettings> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/system-settings/public`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `system-settings-public-${crypto.randomUUID()}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
  if (!isPublicSettings(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return body
}

export const systemSettingsApi = {
  get(accessToken: string) { return request<PlatformSystemSettingsDocument>(accessToken, 'GET') },
  /** 系统名称/标题、购买说明与全站 JS：任意已登录会话可读（GET /v1/system-settings/public）。 */
  public(accessToken: string) { return requestPublic(accessToken) },
  put(accessToken: string, revision: number, value: PlatformSystemSettings, requestId?: string, idempotencyKey?: string) {
    return request<PlatformSystemSettingsDocument>(accessToken, 'PUT', value, revision, requestId, idempotencyKey)
  },
}
