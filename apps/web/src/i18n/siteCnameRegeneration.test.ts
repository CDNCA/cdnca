import i18n from './index'
import { siteCnameRegenerationMessages } from './siteCnameRegeneration'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))))
}

describe('siteCnameRegenerationMessages', () => {
  it('registers complete Chinese, English, and expanded pseudo-locale trees', () => {
    const zh = flatten(siteCnameRegenerationMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'siteCnameRegeneration')).toBe(true)
      expect(Object.keys(flatten(siteCnameRegenerationMessages[locale])).sort()).toEqual(
        Object.keys(zh).sort(),
      )
    }
    expect(zh.action).toBe('重新生成 CNAME')
    expect(zh.queued).toBe('已排队')
    expect(flatten(siteCnameRegenerationMessages['qps-ploc']).action!.length)
      .toBeGreaterThan(zh.action!.length)
    expect(siteCnameRegenerationMessages['qps-Ploc'])
      .toEqual(siteCnameRegenerationMessages['qps-ploc'])
  })

  it('does not expose raw server messages or credential storage instructions', () => {
    for (const locale of Object.values(siteCnameRegenerationMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|localStorage|sessionStorage|access[_ -]?token/i)
      }
    }
  })
})
