import { describe, expect, it } from 'vitest'

import { ApiError } from '../api/auth'
import i18n from '../i18n'
import { localizedUnknownApiError, mfaStepUpErrorText } from '../i18n/apiError'

// MFA step-up display：POST /v1/account/mfa/step-up-proofs 的确定拒绝要说原因，所有走通用兜底的页面都适用。
const refusal = (status: number, code: string) =>
  new ApiError('API request failed', status, code, 'mfa-step-up-292b6116-0000-4000-8000-000000000000')

describe('MFA step-up refusals', () => {
  it('name the reason instead of a generic request failure', async () => {
    await i18n.changeLanguage('zh-CN')
    const cases: Array<[number, string, string]> = [
      [422, 'mfa_invalid_code', '验证码错误'],
      [409, 'mfa_code_replayed', '该验证码已使用过'],
      [409, 'mfa_recovery_code_used', '该恢复码已使用过'],
      [412, 'mfa_not_active', '还没有启用身份验证器'],
    ]
    for (const [status, code, text] of cases) {
      expect(mfaStepUpErrorText(refusal(status, code))).toContain(text)
      const fallback = localizedUnknownApiError(refusal(status, code), '请求失败，请稍后重试')
      expect(fallback).toContain(text)
      expect(fallback).not.toContain('请求失败')
    }
    await i18n.changeLanguage('en-US')
    expect(mfaStepUpErrorText(refusal(422, 'mfa_invalid_code'))).toContain('Incorrect verification code')
    await i18n.changeLanguage('zh-CN')
  })

  it('leaves other errors to the caller', () => {
    expect(mfaStepUpErrorText(refusal(503, 'mfa_unavailable'))).toBeNull()
    expect(mfaStepUpErrorText(new Error('x'))).toBeNull()
    expect(localizedUnknownApiError(refusal(503, 'mfa_unavailable'), '请求失败，请稍后重试')).toContain('请求失败')
  })
})
