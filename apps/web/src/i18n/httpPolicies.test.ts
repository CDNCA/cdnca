import { describe, expect, it } from 'vitest'

import i18n from './index'
import { httpPolicyMessages } from './httpPolicies'

describe('httpPolicyMessages', () => {
  it('registers complete Chinese, English, and expanded pseudo locale resources', () => {
    const keys = Object.keys(httpPolicyMessages['zh-CN']).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'httpPolicies')).toBe(true)
      expect(Object.keys(httpPolicyMessages[locale]).sort()).toEqual(keys)
    }
    expect(httpPolicyMessages['zh-CN'].title).toBe('HTTP 策略')
    expect(httpPolicyMessages['zh-CN'].publicationPreview).toBe('发布预览')
    expect(httpPolicyMessages['qps-ploc'].unknownDescription.length)
      .toBeGreaterThan(httpPolicyMessages['zh-CN'].unknownDescription.length)
  })
})
