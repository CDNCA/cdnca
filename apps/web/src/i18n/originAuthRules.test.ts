import i18n from './index'
import { originAuthRulesMessages } from './originAuthRules'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('originAuthRulesMessages', () => {
  it('registers complete zh-CN, en-US, and expanded pseudo-locale trees', () => {
    const zh = flatten(originAuthRulesMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'originAuthRules')).toBe(true)
      expect(Object.keys(flatten(originAuthRulesMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
    expect(zh.title).toBe('源站鉴权规则')
    expect(flatten(originAuthRulesMessages['qps-ploc']).title!.length).toBeGreaterThan(zh.title!.length)
    expect(originAuthRulesMessages['qps-Ploc']).toEqual(originAuthRulesMessages['qps-ploc'])
  })

  it('contains no raw server wording or secret labels', () => {
    for (const locale of Object.values(originAuthRulesMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|internal service|secret[_ -]?access[_ -]?key|session[_ -]?token/i)
      }
    }
  })
})
