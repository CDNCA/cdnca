import { ApiError, networkApiError, responseApiError } from './auth'

export interface PlatformSystemMailSettings {
  smtp_address: string
  smtp_ssl: boolean
  smtp_port: number
  smtp_user: string
  smtp_password_reference: string
  sms_provider: string
  sms_access_key_id: string
  sms_access_key_reference: string
  sms_signature_name: string
  // aliyun/submail only: {"<template id>":{"code":"<provider template>","variables":{"<ours>":"<theirs>"}}}
  sms_template_map: string
  // The one system mail sender: '' (built-in SMTP above, unchanged), an
  // official mail service, or 'plugin:<plugin id>'. The SMTP and official
  // fields are kept whatever is chosen.
  mail_provider: string
  mail_region: string
  mail_access_key_id: string
  mail_from: string
  mail_from_name: string
}

export const nativeSMSProviders = ['aliyun', 'submail'] as const
export const officialMailProviders = ['aliyun', 'sendgrid'] as const
export type OfficialMailProvider = typeof officialMailProviders[number]
export const mailProviderRegions: Record<OfficialMailProvider, readonly string[]> = {
  aliyun: ['cn-hangzhou', 'ap-southeast-1', 'ap-southeast-2'],
  sendgrid: ['global', 'eu'],
}
export const mailPluginPrefix = 'plugin:'

export function mailProviderKind(provider: string): 'smtp' | 'official' | 'plugin' | null {
  if (provider === '' || provider === 'smtp') return 'smtp'
  if ((officialMailProviders as readonly string[]).includes(provider)) return 'official'
  if (/^plugin:[a-z0-9]+([.-][a-z0-9]+)+$/.test(provider) && provider.length <= 136) return 'plugin'
  return null
}

export interface PlatformSystemMailSettingsDocument {
  schema: 'cdnca.platform-system-mail-settings/v1'
  revision: number
  updated_at?: string
  value: PlatformSystemMailSettings
  // The native SMS credential is write-only; only a fingerprint comes back.
  sms_secret_configured?: boolean
  sms_secret_fingerprint?: string
  // The official mail credential, likewise write-only; it belongs to
  // mail_secret_provider and is reused only for that provider.
  mail_secret_configured?: boolean
  mail_secret_provider?: OfficialMailProvider
  mail_secret_fingerprint?: string
}

export interface MailTestResult {
  ok: boolean
  provider: string
  message_id?: string
  code?: string
}

// Write-only secrets of one PUT (omitted keeps the stored ones).
export interface MailSettingsSecrets {
  smsAccessKeySecret?: string
  mailSecret?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const settingKeys = ['smtp_address', 'smtp_ssl', 'smtp_port', 'smtp_user', 'smtp_password_reference', 'sms_provider', 'sms_access_key_id', 'sms_access_key_reference', 'sms_signature_name', 'sms_template_map', 'mail_provider', 'mail_region', 'mail_access_key_id', 'mail_from', 'mail_from_name'] as const

function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function exact(value: Record<string, unknown>) { const keys = Object.keys(value); return keys.length === settingKeys.length && settingKeys.every((key) => Object.hasOwn(value, key)) }
function text(value: unknown, max: number) { return typeof value === 'string' && Array.from(value).length <= max && !value.includes(String.fromCharCode(0)) && !value.includes('\r') }
function reference(value: unknown) { return text(value, 1024) && (value === '' || String(value).startsWith('vault://') && String(value).length > 8 || String(value).startsWith('kms-envelope://') && String(value).length > 15) }
function isSettings(value: unknown): value is PlatformSystemMailSettings {
  if (!record(value) || !exact(value) || typeof value.smtp_ssl !== 'boolean' || !Number.isSafeInteger(value.smtp_port) || Number(value.smtp_port) < 1 || Number(value.smtp_port) > 65535) return false
  return text(value.smtp_address, 512) && text(value.smtp_user, 256) && reference(value.smtp_password_reference) && text(value.sms_provider, 64) && text(value.sms_access_key_id, 256) && reference(value.sms_access_key_reference) && text(value.sms_signature_name, 256) && text(value.sms_template_map, 16384) &&
    mailProviderKind(String(value.mail_provider)) !== null && text(value.mail_region, 32) && text(value.mail_access_key_id, 256) && text(value.mail_from, 254) && text(value.mail_from_name, 64)
}
function isDocument(value: unknown): value is PlatformSystemMailSettingsDocument {
  if (!record(value) || value.schema !== 'cdnca.platform-system-mail-settings/v1' || !Number.isSafeInteger(value.revision) || Number(value.revision) < 0 || !isSettings(value.value)) return false
  if (Object.hasOwn(value, 'sms_secret_configured') && typeof value.sms_secret_configured !== 'boolean') return false
  if (Object.hasOwn(value, 'sms_secret_fingerprint') && !(typeof value.sms_secret_fingerprint === 'string' && /^[0-9a-f]{16}$/.test(value.sms_secret_fingerprint))) return false
  if (Object.hasOwn(value, 'mail_secret_configured') && typeof value.mail_secret_configured !== 'boolean') return false
  if (Object.hasOwn(value, 'mail_secret_provider') && !(officialMailProviders as readonly unknown[]).includes(value.mail_secret_provider)) return false
  if (Object.hasOwn(value, 'mail_secret_fingerprint') && !(typeof value.mail_secret_fingerprint === 'string' && /^[0-9a-f]{16}$/.test(value.mail_secret_fingerprint))) return false
  return !Object.hasOwn(value, 'updated_at') || typeof value.updated_at === 'string' && Number.isFinite(Date.parse(value.updated_at))
}

async function request(accessToken: string, method: 'GET' | 'PUT', revision?: number, value?: PlatformSystemMailSettings, requestId?: string, idempotencyKey?: string, secrets: MailSettingsSecrets = {}) {
  const requestID = requestId ?? `system-mail-settings-${crypto.randomUUID()}`
  const writeIdempotencyKey = idempotencyKey ?? requestID
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-mail-settings`, {
      method,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID,
        ...(method === 'PUT' ? { 'Content-Type': 'application/json', 'If-Match': `"${revision}"`, 'Idempotency-Key': writeIdempotencyKey } : {}),
      },
      ...(method === 'PUT' ? { body: JSON.stringify({ value,
        ...(secrets.smsAccessKeySecret ? { sms_access_key_secret: secrets.smsAccessKeySecret } : {}),
        ...(secrets.mailSecret ? { mail_secret: secrets.mailSecret } : {}) }) } : {}),
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'system_mail_settings_invalid_response') }
  if (!isDocument(body)) throw new ApiError('Invalid API response', 0, 'system_mail_settings_invalid_response')
  return body
}

function isTestResult(value: unknown): value is MailTestResult {
  return record(value) && typeof value.ok === 'boolean' && typeof value.provider === 'string' &&
    (!Object.hasOwn(value, 'message_id') || typeof value.message_id === 'string') && (!Object.hasOwn(value, 'code') || typeof value.code === 'string')
}

async function sendTest(accessToken: string, value: PlatformSystemMailSettings, to: string, mailSecret?: string): Promise<MailTestResult> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-mail-settings/tests`, {
      method: 'POST', credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `system-mail-test-${crypto.randomUUID()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ value, to, ...(mailSecret ? { mail_secret: mailSecret } : {}) }),
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'system_mail_settings_invalid_response') }
  if (!isTestResult(body)) throw new ApiError('Invalid API response', 0, 'system_mail_settings_invalid_response')
  return body
}

export const systemMailSettingsApi = {
  get(accessToken: string) { return request(accessToken, 'GET') },
  put(accessToken: string, revision: number, value: PlatformSystemMailSettings, requestId?: string, idempotencyKey?: string, secrets?: MailSettingsSecrets) { return request(accessToken, 'PUT', revision, value, requestId, idempotencyKey, secrets) },
  test(accessToken: string, value: PlatformSystemMailSettings, to: string, mailSecret?: string) { return sendTest(accessToken, value, to, mailSecret) },
}
