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
  captcha_app_secret_reference: '',
  identity_verification_method: 'none',
  enterprise_verification_enabled: false,
  enterprise_secret_id_reference: '',
  enterprise_secret_key_reference: '',
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
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, updated_at: '2026-08-14T00:00:00Z', value }))
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
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 4, value: invalidValue }))
    await expect(systemUserSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends CAS and idempotency metadata on PUT', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ schema: 'cdnca.platform-system-user-settings/v1', revision: 5, value }))
    await systemUserSettingsApi.put('token', 4, value)
    const [, init] = fetchMock.mock.calls[0]
    expect(init).toMatchObject({ method: 'PUT', credentials: 'include' })
    expect(init?.headers).toMatchObject({ Authorization: 'Bearer token', 'If-Match': '"4"' })
    expect((init?.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^system-user-settings-/)
    expect(JSON.parse(String(init?.body))).toEqual({ value })
  })
})
