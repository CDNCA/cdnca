import i18n from './index'
import { certificateOrderStatusMessages } from './certificateOrderStatus'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('certificateOrderStatusMessages', () => {
  it('keeps zh-CN and en-US key-complete and registers both pseudo aliases', () => {
    const zh = flatten(certificateOrderStatusMessages['zh-CN'])
    const en = flatten(certificateOrderStatusMessages['en-US'])

    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort())
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'certificateOrderStatus')).toBe(true)
      expect(Object.keys(flatten(certificateOrderStatusMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
  })

  it('expands pseudo text while preserving interpolation tokens', () => {
    const zh = flatten(certificateOrderStatusMessages['zh-CN'])
    const pseudo = flatten(certificateOrderStatusMessages['qps-ploc'])

    expect(pseudo.title!.length).toBeGreaterThan(zh.title!.length)
    expect(pseudo['summary.count']).toContain('{{count}}')
    expect(certificateOrderStatusMessages['qps-Ploc']).toEqual(certificateOrderStatusMessages['qps-ploc'])
  })
})
