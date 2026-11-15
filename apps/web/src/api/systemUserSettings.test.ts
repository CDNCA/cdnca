import { beforeEach, describe, expect, it, vi } from 'vitest'

import { systemUserSettingsApi, type PlatformSystemUserSettings } from './systemUserSettings'

const value: PlatformSystemUserSettings = {
  session_ttl_seconds: 86400,
  user_login_domains: '',
  admin_login_domains: '',
  email_code_login_enabled: true,
  sms_code_login_enabled: false,
  registration_enabled: false,
  registration_success_subject: '用户注册成功',
  registration_success_body: '<p>{{username}}</p>',
  password_reset_subject: '重置密码',
  password_reset_body: '<p>{{username}}</p>',
  verification_template_channel: 'email',
  verification_subject: '用户验证码',
  verification_body: '<p>{{captcha}}</p>',
  verification_sms_body: '您的验证码为${captcha}，在5分钟内有效。',
  verification_sms_template_id: '',
  terms_title: '用户协议',
  terms_body: '协议内容',
  username_required: false,
  email_required: false,
  email_verification_required: false,
  phone_required: false,
  phone_verification_required: false,
  qq_required: false,
  login_failure_limit_per_hour: 30,
  login_captcha_threshold_per_hour: 3,
  session_region_check: true,
  email_anti_abuse_mode: 'none',
  sms_anti_abuse_mode: 'native',
  captcha_provider: 'tencent',
  captcha_secret_id_reference: '',
  captcha_secret_key_reference: '',
  captcha_app_id: '',
  captcha_app_secret_reference: '', captcha_turnstile_site_key: '',
  identity_verification_method: 'none',
  enterprise_verification_enabled: false,
  identity_policy_saved: false, kyc_provider_name: '', kyc_endpoint: '', kyc_callback_key_id: '', kyc_object_endpoint: '', kyc_object_region: '', kyc_object_bucket: '', kyc_object_prefix: '', kyc_object_kms_key_id: '',
  wechat_payment_enabled: false,
  alipay_payment_enabled: false,
  bank_transfer_enabled: false,
  default_recharge_method: 'none',
  recharge_restriction: 'none',
  default_phone_country_code: '86',
}

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('systemUserSettingsApi', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('accepts the exact response contract', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, captcha_turnstile_secret_configured: false, updated_at: '2026-08-14T00:00:00Z', value }))
    await expect(systemUserSettingsApi.get('token')).resolves.toMatchObject({ revision: 4, value })
  })

  it.each([
    ['extra field', { ...value, extra: true }],
    ['invalid session ttl', { ...value, session_ttl_seconds: 299 }],
    ['invalid enum', { ...value, captcha_provider: 'unknown' }],
    ['plaintext secret', { ...value, captcha_secret_key_reference: 'plaintext-secret' }],
    ['empty vault reference', { ...value, captcha_secret_key_reference: 'vault://' }],
    ['verification without email', { ...value, email_required: false, email_verification_required: true }],
    ['disabled default payment', { ...value, default_recharge_method: 'wechat', wechat_payment_enabled: false }],
    ['phone country code with plus', { ...value, default_phone_country_code: '+86' }],
    ['phone country code with leading zero', { ...value, default_phone_country_code: '086' }],
    ['empty phone country code', { ...value, default_phone_country_code: '' }],
  ])('rejects %s', async (_name, invalidValue) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, captcha_turnstile_secret_configured: false, value: invalidValue }))
    await expect(systemUserSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends CAS and idempotency metadata on PUT', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 5, captcha_turnstile_secret_configured: false, value }))
    await systemUserSettingsApi.put('token', 4, value)
    const [, init] = fetchMock.mock.calls[0]
    expect(init).toMatchObject({ method: 'PUT', credentials: 'include' })
    expect(init?.headers).toMatchObject({ Authorization: 'Bearer token', 'If-Match': '"4"' })
    expect((init?.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^system-user-settings-/)
    expect(JSON.parse(String(init?.body))).toEqual({ value })
  })

  // page secrets are sent write-only next to value and
  // come back only as configured flags and fingerprints.
  it('sends page secrets write-only: omitted keeps, empty clears', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 5, value }))
    await systemUserSettingsApi.put('token', 4, value, undefined, undefined, { captcha_secret_key: 'plain-key', captcha_app_secret: '', captcha_secret_id: undefined })
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ value, captcha_secret_key: 'plain-key', captcha_app_secret: '' })
  })

  it('reads the KYC provider fields and sends the object store keys write-only', async () => {
    const kyc = { ...value, kyc_endpoint: 'https://kyc.example.com', kyc_object_bucket: 'kyc-bucket' }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 5, value: kyc,
      kyc_object_secret_access_key_configured: true, kyc_object_secret_access_key_fingerprint: '0123456789abcdef' }))
    await expect(systemUserSettingsApi.put('token', 4, kyc, undefined, undefined, { kyc_object_access_key_id: 'AKIAEXAMPLE', kyc_object_session_token: '' }))
      .resolves.toMatchObject({ kyc_object_secret_access_key_configured: true, value: { kyc_endpoint: 'https://kyc.example.com' } })
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ value: kyc, kyc_object_access_key_id: 'AKIAEXAMPLE', kyc_object_session_token: '' })
    const missing = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'kyc_object_kms_key_id'))
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, value: missing }))
    await expect(systemUserSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts saved secrets in place of the references they stand for', async () => {
    const external = { ...value, sms_anti_abuse_mode: 'tencent' as const, captcha_provider: 'tencent' as const, captcha_app_id: '190000001' }
    const saved = Object.fromEntries(['captcha_secret_id', 'captcha_secret_key', 'captcha_app_secret', 'kyc_api_key', 'kyc_callback_hmac_key']
      .flatMap((name) => [[`${name}_configured`, true], [`${name}_fingerprint`, '0123456789abcdef']]))
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, value: external, ...saved }))
    await expect(systemUserSettingsApi.get('token')).resolves.toMatchObject({ captcha_app_secret_configured: true })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, value: external }))
    await expect(systemUserSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, value, captcha_secret_id_fingerprint: 'not-hex' }))
    await expect(systemUserSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
