import i18n from './index'
import { certificateAssetsMessages } from './certificateAssets'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

function placeholders(value: string): string[] {
  return value.match(/{{[^}]+}}/g)?.sort() ?? []
}

describe('certificateAssets translations', () => {
  it('registers identical certificate asset keys for every supported locale spelling', () => {
    const zh = flatten(certificateAssetsMessages['zh-CN'])
    const expected = Object.keys(zh).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(certificateAssetsMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(expected)
      for (const key of expected) {
        expect(i18n.getResource(locale, 'certificateAssets', key)).toBe(messages[key])
        expect(placeholders(messages[key]!)).toEqual(placeholders(zh[key]!))
      }
    }
  })

  it('expands pseudo locale text without leaking raw server wording', () => {
    const zh = flatten(certificateAssetsMessages['zh-CN'])
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(certificateAssetsMessages[locale])
      expect(certificateAssetsMessages[locale]).toEqual(certificateAssetsMessages['qps-ploc'])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value.startsWith('［')).toBe(true)
        expect(value.endsWith('］')).toBe(true)
        expect(value.replace(/{{[^}]+}}/g, '').length).toBeGreaterThan(zh[key]!.replace(/{{[^}]+}}/g, '').length)
      }
    }
    expect(JSON.stringify(certificateAssetsMessages)).not.toMatch(/private server|upstream failure|raw message/i)
  })
})
