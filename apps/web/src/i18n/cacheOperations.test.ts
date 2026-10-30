import i18n from './index'
import { cacheOperationsMessages } from './cacheOperations'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('cacheOperationsMessages', () => {
  it('keeps zh-CN and en-US key-complete and registers both pseudo locale aliases', () => {
    const zh = flatten(cacheOperationsMessages['zh-CN'])
    const en = flatten(cacheOperationsMessages['en-US'])

    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort())
    expect(zh).toEqual(expect.objectContaining({
      'detail.ordinal': '序号',
      'detail.displayUrl': '脱敏目标 URL',
      'detail.canonicalPath': '规范化路径',
      'detail.targetHash': '目标 SHA-256',
      'detail.queryRedacted': '查询参数已脱敏',
      'values.yes': '是',
      'values.no': '否',
    }))
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'cacheOperations')).toBe(true)
      expect(Object.keys(flatten(cacheOperationsMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
  })

  it('expands pseudo locale text while preserving interpolation tokens', () => {
    const zh = flatten(cacheOperationsMessages['zh-CN'])
    const pseudo = flatten(cacheOperationsMessages['qps-ploc'])

    expect(pseudo['title']?.length).toBeGreaterThan(zh['title']!.length)
    expect(pseudo['errors.withRequestId']).toContain('{{message}}')
    expect(pseudo['errors.withRequestId']).toContain('{{requestId}}')
    expect(cacheOperationsMessages['qps-Ploc']).toEqual(cacheOperationsMessages['qps-ploc'])
  })
})
