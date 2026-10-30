import i18n from './index'
import { sitePolicyMessages } from './sitePolicy'

describe('sitePolicyMessages', () => {
  it('registers matching advanced settings keys for every locale', () => {
    const keys = Object.keys(sitePolicyMessages['zh-CN']).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'sitePolicy')).toBe(true)
      expect(Object.keys(sitePolicyMessages[locale]).sort()).toEqual(keys)
    }
    expect(sitePolicyMessages['zh-CN'].groupAccess).toBe('防盗链与跨域')
    expect(sitePolicyMessages['qps-ploc'].groupAccess.length).toBeGreaterThan(sitePolicyMessages['zh-CN'].groupAccess.length)
  })
})
