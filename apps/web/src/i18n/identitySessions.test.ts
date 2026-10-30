import i18n from './index'
import { identitySessionMessages } from './identitySessions'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

describe('identity session translations', () => {
  it('registers identical complete keys for Chinese, English, and pseudo locales', () => {
    const expected = Object.keys(flatten(identitySessionMessages['zh-CN'])).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(identitySessionMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(expected)
      for (const key of expected) {
        expect(i18n.getResource(locale, 'identitySessions', key)).toBe(messages[key])
      }
    }
  })

  it('keeps default copy Chinese, English translated, and pseudo text expanded', () => {
    const zh = flatten(identitySessionMessages['zh-CN'])
    const en = flatten(identitySessionMessages['en-US'])
    expect(Object.values(zh).join('')).toMatch(/[\u3400-\u9fff]/u)
    expect(Object.values(en).join('')).not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    expect(identitySessionMessages['qps-Ploc']).toEqual(identitySessionMessages['qps-ploc'])
    for (const [key, value] of Object.entries(flatten(identitySessionMessages['qps-ploc']))) {
      expect(value.startsWith('［')).toBe(true)
      expect(value.endsWith('］')).toBe(true)
      expect(value.length).toBeGreaterThan(zh[key]!.length)
    }
    expect(JSON.stringify(identitySessionMessages)).not.toMatch(/raw user-agent|token hash|server error/i)
  })
})
