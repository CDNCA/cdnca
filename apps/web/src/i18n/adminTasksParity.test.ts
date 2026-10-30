import i18n from './index'
import { adminTaskFactMessages } from './adminTasksParity'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('admin task fact translations', () => {
  it('keeps all task directory and metadata keys complete in English and pseudo locales', () => {
    const expected = flatten(adminTaskFactMessages['zh-CN'])
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(Object.keys(flatten(adminTaskFactMessages[locale])).sort()).toEqual(Object.keys(expected).sort())
    }
  })

  it('preserves interpolated facts while expanding pseudo-locale labels', () => {
    const t = i18n.getFixedT('qps-ploc', 'jobs')
    expect(t('taskFacts.name', { kind: 'TYPE', resource: 'site:example.test' })).toContain('site:example.test')
    expect(t('pagination.total', { total: '137' })).toMatch(/共~ 137 条~/)
    expect(t('taskFacts.dependenciesUnknown')).toContain('依~赖~')
  })
})
