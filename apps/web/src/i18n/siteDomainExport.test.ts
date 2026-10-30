import i18n from './index'
import { siteDomainExportMessages } from './siteDomainExport'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))))
}

describe('site domain export translations', () => {
  it('registers complete Chinese, English, and expanded pseudo-locale contracts', () => {
    const zh = flatten(siteDomainExportMessages['zh-CN'])
    expect(Object.keys(zh).sort()).toEqual([
      'errors.failed',
      'errors.forbidden',
      'errors.platformTargetRequired',
      'errors.unsupportedFilters',
      'progress',
      'success',
      'target.empty',
      'target.label',
      'target.placeholder',
      'target.title',
    ])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'siteDomainExport')).toBe(true)
      expect(Object.keys(flatten(siteDomainExportMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
    expect(siteDomainExportMessages['qps-Ploc']).toEqual(siteDomainExportMessages['qps-ploc'])
    expect(flatten(siteDomainExportMessages['qps-ploc']).success!.length).toBeGreaterThan(zh.success!.length)
  })
})
