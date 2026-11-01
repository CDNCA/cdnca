import { describe, expect, it } from 'vitest'

import { ApiError } from '../api/auth'
import i18n from '../i18n'
import { isFeatureDisabled, localizedApiError, localizedUnknownApiError } from '../i18n/apiError'
import { originAuthRuleErrorKey } from '../pages/OriginAuthRulesPage'

// omfix-a 5：后端 error.code=feature_disabled（503，control-api origin_auth_disabled.go）
// 表示该功能在主控未启用，不是暂时故障；页面要说「该功能未启用」并给启用办法，不能说「暂不可用，请稍后重试」。
const disabled = () => new ApiError('origin authentication is not enabled', 503, 'feature_disabled')

describe('feature_disabled errors (omfix-a 5)', () => {
  it('say the feature is not enabled and how to enable it, in both languages', async () => {
    await i18n.changeLanguage('zh-CN')
    for (const text of [localizedApiError(disabled()), localizedUnknownApiError(disabled(), '服务暂不可用，请稍后重试')]) {
      expect(text).toContain('该功能未启用')
      expect(text).toContain('/etc/cdnca-control/control.env')
      expect(text).not.toContain('稍后重试')
    }
    await i18n.changeLanguage('en-US')
    expect(localizedApiError(disabled())).toContain('not enabled')
    await i18n.changeLanguage('zh-CN')
  })

  it('origin authentication pages map it before the generic 503', () => {
    expect(isFeatureDisabled(disabled())).toBe(true)
    expect(isFeatureDisabled(new ApiError('x', 503, 'origin_auth_unavailable'))).toBe(false)
    const text = i18n.t(originAuthRuleErrorKey(disabled()), { ns: 'originAuthRules' })
    expect(text).toContain('该功能未启用')
    expect(text).toContain('ORIGIN_AUTH_RUNTIME_ENABLED')
    expect(originAuthRuleErrorKey(new ApiError('x', 503, 'origin_auth_unavailable'))).toBe('errors.unavailable')
  })
})
