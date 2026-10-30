import i18n from '../../i18n'

const recoveryKeys = [
  'pageTitle', 'requestPageTitle', 'resetPageTitle', 'requestTab', 'confirmTab',
  'usernameLabel', 'usernamePlaceholder', 'usernameRequired', 'usernameTooLong',
  'sendInstructions', 'accepted', 'requestAgain', 'invalidLink', 'requestNewLink',
  'newPasswordLabel', 'newPasswordPlaceholder', 'newPasswordRequired',
  'passwordTooShort', 'passwordTooLong', 'confirmPasswordLabel',
  'confirmPasswordPlaceholder', 'confirmPasswordRequired', 'passwordMismatch',
  'resetPassword', 'returnToLogin', 'footerLinks', 'officialSite', 'community',
  'contactUs', 'copyright',
] as const

const errorKeys = [
  'account_recovery_invalid_request', 'account_recovery_rate_limited',
  'account_recovery_invalid_token', 'account_recovery_password_policy',
  'account_recovery_password_reused', 'account_recovery_principal_changed',
  'account_recovery_idempotency_conflict', 'account_recovery_request_cancelled',
  'account_recovery_timeout', 'account_recovery_unavailable',
] as const

describe('account recovery locale resources', () => {
  it('keeps zh-CN, en-US, and qps-ploc complete without raw server placeholders', () => {
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc'] as const) {
      for (const key of recoveryKeys) {
        const value = i18n.getResource(locale, 'auth', `recovery.${key}`)
        expect(typeof value).toBe('string')
        expect(value).not.toBe('')
      }
      for (const key of errorKeys) {
        const value = i18n.getResource(locale, 'errors', key)
        expect(typeof value).toBe('string')
        expect(value).not.toMatch(/raw|server message|服务端原始/i)
      }
    }
  })

  it('expands the pseudo locale for narrow-screen overflow evidence', () => {
    for (const key of recoveryKeys) {
      const zh = i18n.getResource('zh-CN', 'auth', `recovery.${key}`) as string
      const pseudo = i18n.getResource('qps-ploc', 'auth', `recovery.${key}`) as string
      expect(pseudo.length).toBeGreaterThan(zh.length)
    }
  })
})
