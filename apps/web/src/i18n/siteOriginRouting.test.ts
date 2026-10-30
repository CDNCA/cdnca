import { describe, expect, it } from 'vitest'

import i18n from './index'
import { siteOriginRoutingMessages } from './siteOriginRouting'

interface Tree { [key: string]: string | Tree }
function flatten(tree: Tree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

describe('siteOriginRouting translations', () => {
  it('has identical keys in zh-CN, en-US, qps-ploc, and qps-Ploc', () => {
    const expected = Object.keys(flatten(siteOriginRoutingMessages['zh-CN'])).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(siteOriginRoutingMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(expected)
      for (const key of expected) expect(i18n.getResource(locale, 'siteOriginRouting', key)).toBe(messages[key])
    }
  })

  it('keeps English free of Chinese and pseudo locales expanded', () => {
    expect(Object.values(flatten(siteOriginRoutingMessages['en-US'])).join('')).not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    expect(siteOriginRoutingMessages['qps-Ploc']).toEqual(siteOriginRoutingMessages['qps-ploc'])
    for (const value of Object.values(flatten(siteOriginRoutingMessages['qps-ploc']))) {
      expect(value.startsWith('［')).toBe(true)
      expect(value.endsWith('］')).toBe(true)
    }
  })

  it('localizes unknown-write recovery actions in every locale', () => {
    const keys = ['actions.retryExact', 'actions.abandonAndReload', 'states.unknownResult']
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc'] as const) {
      const messages = flatten(siteOriginRoutingMessages[locale])
      for (const key of keys) expect(messages[key]).toEqual(expect.any(String))
    }
    expect(flatten(siteOriginRoutingMessages['qps-ploc'])['states.unknownResult']!.length)
      .toBeGreaterThan(flatten(siteOriginRoutingMessages['zh-CN'])['states.unknownResult']!.length)
  })

  it('localizes the ingress-source origin control in every locale', () => {
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc'] as const) {
      const messages = flatten(siteOriginRoutingMessages[locale])
      expect(messages['fields.ingressSource']).toEqual(expect.any(String))
      expect(messages['hints.ingressSource']).toEqual(expect.any(String))
    }
  })
})
