import i18n from './index'
import { cnameAllocationsMessages } from './cnameAllocations'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('cnameAllocationsMessages', () => {
  it('registers complete zh-CN, en-US, and expanded pseudo-locale resources', () => {
    const zh = flatten(cnameAllocationsMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'cnameAllocations')).toBe(true)
      expect(Object.keys(flatten(cnameAllocationsMessages[locale])).sort())
        .toEqual(Object.keys(zh).sort())
    }
    expect(zh.title).toBe('CNAME 分配权威')
    expect(flatten(cnameAllocationsMessages['qps-ploc']).title?.length)
      .toBeGreaterThan(zh.title!.length)
    expect(cnameAllocationsMessages['qps-Ploc']).toEqual(cnameAllocationsMessages['qps-ploc'])
  })

  it('contains no raw server wording in any locale', () => {
    for (const locale of Object.values(cnameAllocationsMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|internal service|private message|raw tenant/i)
      }
    }
  })
})
