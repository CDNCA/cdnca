import i18n from './index'
import { siteListenerDomainMessages } from './siteListenerDomains'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

describe('site listener/domain translations', () => {
  it('registers complete Chinese, English, and pseudo-locale contracts', () => {
    const zh = flatten(siteListenerDomainMessages['zh-CN'])
    const expectedKeys = Object.keys(zh).sort()
    expect(expectedKeys).toEqual(expect.arrayContaining([
      'title',
      'fields.domain',
      'fields.httpPorts',
      'fields.httpsPorts',
      'validation.httpsPorts',
      'validation.portConflict',
    ]))
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(siteListenerDomainMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(expectedKeys)
      for (const key of expectedKeys) {
        expect(i18n.getResource(locale, 'siteListenerDomains', key)).toBe(messages[key])
      }
    }
    expect(Object.values(flatten(siteListenerDomainMessages['en-US'])).join(''))
      .not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    expect(siteListenerDomainMessages['qps-Ploc']).toEqual(siteListenerDomainMessages['qps-ploc'])
    for (const value of Object.values(flatten(siteListenerDomainMessages['qps-ploc']))) {
      expect(value).toMatch(/^［.*］$/u)
    }
  })
})
