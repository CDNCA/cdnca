import i18n from './index'
import { analyticsLogSecurityMessages } from './analyticsLogSecurity'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

describe('analyticsLogSecurityMessages', () => {
  it('registers complete zh-CN, en-US, and pseudo locale resources', () => {
    const zh = flatten(analyticsLogSecurityMessages['zh-CN'])
    const keys = Object.keys(zh).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(analyticsLogSecurityMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(keys)
      for (const key of keys) expect(i18n.getResource(locale, 'analyticsLogSecurity', key)).toBe(messages[key])
    }
  })

  it('expands pseudo locale text without embedding raw diagnostics', () => {
    const zh = flatten(analyticsLogSecurityMessages['zh-CN'])
    const pseudo = flatten(analyticsLogSecurityMessages['qps-ploc'])
    expect(analyticsLogSecurityMessages['qps-Ploc']).toEqual(analyticsLogSecurityMessages['qps-ploc'])
    for (const [key, value] of Object.entries(pseudo)) {
      expect(value).toMatch(/^［.*］$/)
      expect(value.length).toBeGreaterThan(zh[key]!.length)
    }
    expect(JSON.stringify(analyticsLogSecurityMessages)).not.toMatch(/raw-|bearer |password=|cookie=/i)
  })
})
