import i18n from './index'
import { apiKeyAllowlistMessages } from './apiKeyAllowlist'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

describe('API key IP allowlist translations', () => {
  it('registers identical keys for Chinese, English, and both pseudo locale spellings', () => {
    const zh = flatten(apiKeyAllowlistMessages['zh-CN'])
    const expected = Object.keys(zh).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(apiKeyAllowlistMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(expected)
      for (const key of expected) expect(i18n.getResource(locale, 'apiKeyAllowlist', key)).toBe(messages[key])
    }
  })

  it('keeps English complete and pseudo text expanded without raw server data', () => {
    const zh = flatten(apiKeyAllowlistMessages['zh-CN'])
    expect(Object.values(flatten(apiKeyAllowlistMessages['en-US'])).join('')).not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    expect(apiKeyAllowlistMessages['qps-Ploc']).toEqual(apiKeyAllowlistMessages['qps-ploc'])
    for (const [key, value] of Object.entries(flatten(apiKeyAllowlistMessages['qps-ploc']))) {
      expect(value.startsWith('［')).toBe(true)
      expect(value.endsWith('］')).toBe(true)
      expect(value.length).toBeGreaterThan(zh[key]!.length)
    }
    expect(JSON.stringify(apiKeyAllowlistMessages)).not.toMatch(/raw server|matching prefix|private key|secret/i)
  })
})
