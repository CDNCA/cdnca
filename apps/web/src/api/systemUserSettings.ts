import { ApiError, networkApiError, responseApiError } from './auth'

export type VerificationTemplateChannel = 'email' | 'sms'
export type AntiAbuseMode = 'none' | 'native' | 'tencent' | 'geetest_v4'
export type CaptchaProvider = 'tencent' | 'geetest_v4'
export type IdentityVerificationMethod = 'none' | 'alipay' | 'wechat_face' | 'phone_three_factor'
export type RechargeMethod = 'none' | 'wechat' | 'alipay' | 'bank_transfer'
export type RechargeRestriction = 'none' | 'individual_verified' | 'enterprise_verified'

export interface PlatformSystemUserSettings {
  session_ttl_seconds: number
  user_login_domains: string
  admin_login_domains: string
  email_code_login_enabled: boolean
  sms_code_login_enabled: boolean
  registration_enabled: boolean
  registration_success_subject: string
  registration_success_body: string
  password_reset_subject: string
  password_reset_body: string
  verification_template_channel: VerificationTemplateChannel
  verification_subject: string
  verification_body: string
  verification_sms_body: string
  verification_sms_template_id: string
  terms_title: string
  terms_body: string
  username_required: boolean
  email_required: boolean
  email_verification_required: boolean
  phone_required: boolean
  phone_verification_required: boolean
  qq_required: boolean
  login_failure_limit_per_hour: number
  login_captcha_threshold_per_hour: number
  session_region_check: boolean
  email_anti_abuse_mode: AntiAbuseMode
  sms_anti_abuse_mode: AntiAbuseMode
  captcha_provider: CaptchaProvider
  captcha_secret_id_reference: string
  captcha_secret_key_reference: string
  captcha_app_id: string
  captcha_app_secret_reference: string
  identity_verification_method: IdentityVerificationMethod
  enterprise_verification_enabled: boolean
  enterprise_secret_id_reference: string
  enterprise_secret_key_reference: string
  wechat_payment_enabled: boolean
  alipay_payment_enabled: boolean
  bank_transfer_enabled: boolean
  default_recharge_method: RechargeMethod
  recharge_restriction: RechargeRestriction
  /** FX38: calling code (digits) that completes phone numbers entered without one; default 86. */
  default_phone_country_code: string
}

export interface PlatformSystemUserSettingsDocument {
  schema: 'cdnca.platform-system-user-settings/v1'
  revision: number
  updated_at?: string
  value: PlatformSystemUserSettings
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const settingKeys = [
  'session_ttl_seconds', 'user_login_domains', 'admin_login_domains', 'email_code_login_enabled', 'sms_code_login_enabled',
  'registration_enabled', 'registration_success_subject', 'registration_success_body', 'password_reset_subject', 'password_reset_body',
  'verification_template_channel', 'verification_subject', 'verification_body', 'verification_sms_body', 'verification_sms_template_id', 'terms_title', 'terms_body', 'username_required',
  'email_required', 'email_verification_required', 'phone_required', 'phone_verification_required', 'qq_required',
  'login_failure_limit_per_hour', 'login_captcha_threshold_per_hour', 'session_region_check', 'email_anti_abuse_mode', 'sms_anti_abuse_mode',
  'captcha_provider', 'captcha_secret_id_reference', 'captcha_secret_key_reference', 'captcha_app_id', 'captcha_app_secret_reference',
  'identity_verification_method', 'enterprise_verification_enabled', 'enterprise_secret_id_reference', 'enterprise_secret_key_reference',
  'wechat_payment_enabled', 'alipay_payment_enabled', 'bank_transfer_enabled', 'default_recharge_method', 'recharge_restriction',
  'default_phone_country_code',
] as const

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const actual = Object.keys(value)
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

function member<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && allowed.includes(value as T)
}

function validText(value: unknown, minimum: number, maximum: number) {
  if (typeof value !== 'string') return false
  const length = Array.from(value).length
  return length >= minimum && length <= maximum && !value.includes(String.fromCharCode(0)) && !value.includes('\r') && !/\p{Cf}/u.test(value)
}

function validTemplate(value: unknown) {
  return validText(value, 1, 65536) && !/\{\{\s*\.?password\s*\}\}|\$\{\s*password\s*\}/i.test(String(value))
}

function validReference(value: unknown) {
  return validText(value, 0, 1024) && (value === '' || String(value).startsWith('vault://') && String(value).length > 'vault://'.length || String(value).startsWith('kms-envelope://') && String(value).length > 'kms-envelope://'.length)
}

function externalAntiAbuse(value: AntiAbuseMode) {
  return value === 'tencent' || value === 'geetest_v4'
}

function isSettings(value: unknown): value is PlatformSystemUserSettings {
  if (!isRecord(value) || !hasExactKeys(value, settingKeys)) return false
  const booleanKeys = [
    'email_code_login_enabled', 'sms_code_login_enabled', 'registration_enabled', 'username_required', 'email_required',
    'email_verification_required', 'phone_required', 'phone_verification_required', 'qq_required', 'enterprise_verification_enabled',
    'wechat_payment_enabled', 'alipay_payment_enabled', 'bank_transfer_enabled', 'session_region_check',
  ] as const
  if (!booleanKeys.every((key) => typeof value[key] === 'boolean')) return false
  if (!Number.isSafeInteger(value.session_ttl_seconds) || Number(value.session_ttl_seconds) < 300 || Number(value.session_ttl_seconds) > 31536000 ||
    !Number.isSafeInteger(value.login_failure_limit_per_hour) || Number(value.login_failure_limit_per_hour) < 1 || Number(value.login_failure_limit_per_hour) > 1000 ||
    !Number.isSafeInteger(value.login_captcha_threshold_per_hour) || Number(value.login_captcha_threshold_per_hour) < 1 || Number(value.login_captcha_threshold_per_hour) > Number(value.login_failure_limit_per_hour)) return false
  if (!validText(value.user_login_domains, 0, 4096) || !validText(value.admin_login_domains, 0, 4096) ||
    !validText(value.registration_success_subject, 1, 256) || !validTemplate(value.registration_success_body) ||
    !validText(value.password_reset_subject, 1, 256) || !validTemplate(value.password_reset_body) ||
    !validText(value.verification_subject, 1, 256) || !validTemplate(value.verification_body) ||
    !validText(value.verification_sms_body, 1, 1024) || !validText(value.verification_sms_template_id, 0, 256) ||
    !validText(value.terms_title, 1, 256) || !validText(value.terms_body, 1, 65536) || !validText(value.captcha_app_id, 0, 256) ||
    !validReference(value.captcha_secret_id_reference) || !validReference(value.captcha_secret_key_reference) || !validReference(value.captcha_app_secret_reference) ||
    !validReference(value.enterprise_secret_id_reference) || !validReference(value.enterprise_secret_key_reference)) return false
  if (!member(value.verification_template_channel, ['email', 'sms']) || !member(value.email_anti_abuse_mode, ['none', 'native', 'tencent', 'geetest_v4']) ||
    !member(value.sms_anti_abuse_mode, ['none', 'native', 'tencent', 'geetest_v4']) || !member(value.captcha_provider, ['tencent', 'geetest_v4']) ||
    !member(value.identity_verification_method, ['none', 'alipay', 'wechat_face', 'phone_three_factor']) ||
    !member(value.default_recharge_method, ['none', 'wechat', 'alipay', 'bank_transfer']) ||
    !member(value.recharge_restriction, ['none', 'individual_verified', 'enterprise_verified']) ||
    typeof value.default_phone_country_code !== 'string' || !/^[1-9][0-9]{0,3}$/.test(value.default_phone_country_code)) return false
  const candidate = value as unknown as PlatformSystemUserSettings
  if (candidate.email_verification_required && !candidate.email_required || candidate.phone_verification_required && !candidate.phone_required) return false
  const externalCaptchaConfigured = candidate.captcha_secret_id_reference !== '' && candidate.captcha_secret_key_reference !== '' && candidate.captcha_app_id !== '' && candidate.captcha_app_secret_reference !== ''
  return (!externalAntiAbuse(candidate.email_anti_abuse_mode) || candidate.email_anti_abuse_mode === candidate.captcha_provider && externalCaptchaConfigured) &&
    (!externalAntiAbuse(candidate.sms_anti_abuse_mode) || candidate.sms_anti_abuse_mode === candidate.captcha_provider && externalCaptchaConfigured) &&
    (!candidate.enterprise_verification_enabled || candidate.enterprise_secret_id_reference !== '' && candidate.enterprise_secret_key_reference !== '') &&
    (candidate.default_recharge_method !== 'wechat' || candidate.wechat_payment_enabled) &&
    (candidate.default_recharge_method !== 'alipay' || candidate.alipay_payment_enabled) &&
    (candidate.default_recharge_method !== 'bank_transfer' || candidate.bank_transfer_enabled)
}

function isDocument(value: unknown): value is PlatformSystemUserSettingsDocument {
  if (!isRecord(value) || Object.keys(value).some((key) => !['schema', 'revision', 'updated_at', 'value'].includes(key)) ||
    !['schema', 'revision', 'value'].every((key) => Object.hasOwn(value, key))) return false
  return value.schema === 'cdnca.platform-system-user-settings/v1' && Number.isSafeInteger(value.revision) && Number(value.revision) >= 0 &&
    isSettings(value.value) && (!Object.hasOwn(value, 'updated_at') || typeof value.updated_at === 'string' && Number.isFinite(Date.parse(value.updated_at)))
}

async function request(accessToken: string, method: 'GET' | 'PUT', revision?: number, value?: PlatformSystemUserSettings, requestId?: string, idempotencyKey?: string) {
  const requestID = requestId ?? `system-user-settings-${crypto.randomUUID()}`
  const writeIdempotencyKey = idempotencyKey ?? requestID
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/system-user-settings`, {
      method,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID,
        ...(method === 'PUT' ? { 'Content-Type': 'application/json', 'If-Match': `"${revision}"`, 'Idempotency-Key': writeIdempotencyKey } : {}),
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
  return body
}

export const systemUserSettingsApi = {
  get(accessToken: string) { return request(accessToken, 'GET') },
  put(accessToken: string, revision: number, value: PlatformSystemUserSettings, requestId?: string, idempotencyKey?: string) { return request(accessToken, 'PUT', revision, value, requestId, idempotencyKey) },
}
