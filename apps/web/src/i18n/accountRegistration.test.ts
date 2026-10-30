import i18n from './index'
import { accountRegistrationMessages } from './accountRegistration'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))))
}

describe('accountRegistrationMessages', () => {
  it('registers complete Chinese, English, and expanded pseudo-locale resources', () => {
    const zh = flatten(accountRegistrationMessages['zh-CN'])
    const required = [
      'title', 'fields.username', 'fields.displayName', 'fields.password', 'fields.email',
      'fields.phone', 'fields.channel', 'fields.otp', 'fields.terms', 'channels.email', 'channels.sms',
      'actions.sendCode', 'actions.verifyAndRegister', 'actions.retrySame', 'actions.startOver',
      'states.humanRequired', 'states.deliveryQueued', 'states.cooldown', 'states.remainingAttempts',
      'states.expired', 'states.pendingVerification', 'states.replayed',
      'validation.username', 'validation.displayName', 'validation.password',
      'validation.email', 'validation.phone', 'validation.otp', 'validation.terms',
      'errors.account_registration_challenge_invalid',
      'errors.account_registration_challenge_rate_limited',
      'errors.account_registration_challenge_conflict',
      'errors.account_registration_challenge_unavailable',
      'errors.account_registration_invalid_input', 'errors.account_registration_terms_required',
      'errors.account_registration_rate_limited', 'errors.account_registration_idempotency_conflict',
      'errors.account_registration_unavailable', 'errors.permission_denied', 'errors.forbidden',
      'errors.challengeUnknown', 'errors.verificationUnknown', 'errors.registrationUnknown',
      'errors.turnstileUnavailable', 'errors.requestFailed',
    ]
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'accountRegistration')).toBe(true)
      const flat = flatten(accountRegistrationMessages[locale])
      expect(Object.keys(flat).sort()).toEqual(Object.keys(zh).sort())
      for (const key of required) expect(flat[key], `${locale}:${key}`).toEqual(expect.any(String))
    }
    expect(zh.title).toBe('注册账号')
    expect(zh['states.pendingVerification']).toContain('已受理')
    expect(flatten(accountRegistrationMessages['qps-ploc']).title!.length).toBeGreaterThan(zh.title!.length)
    expect(accountRegistrationMessages['qps-Ploc']).toEqual(accountRegistrationMessages['qps-ploc'])
  })

  it('contains no raw server text, proof field, secret, or storage instruction', () => {
    for (const locale of Object.values(accountRegistrationMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|challenge[_ -]?proof|localStorage|sessionStorage|access[_ -]?token|destination/i)
      }
    }
  })
})
