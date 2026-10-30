import i18n from './index'
import { siteTLSMessages } from './siteTLS'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

describe('site TLS translations', () => {
  it('registers an independent, complete namespace for every supported locale', () => {
    const expectedKeys = [
      'field.help',
      'field.label',
      'versions.tls13',
      'versions.recommended',
      'versions.compatible',
      'versions.legacyWarning',
      'ciphers.label',
      'ciphers.help',
      'ciphers.modern',
      'ciphers.compatible',
      'ciphers.legacy',
      'ocsp.label',
      'ocsp.help',
      'clientAuth.label',
      'clientAuth.help',
      'clientAuth.off',
      'clientAuth.optional',
      'clientAuth.required',
      'clientAuth.ca',
      'legacy.description',
      'legacy.title',
      'unknown.description',
      'unknown.title',
      'validation.safeOnly',
      'validation.clientCA',
      // fp-site5a: per site HTTP/2, HTTP/3, ssl_prefer_server_ciphers; tls-custom: the custom cipher preset.
      'ciphers.custom',
      'ciphers.customHelp',
      'ciphers.customLabel',
      'ciphers.customSafeOnly',
      'http2.help',
      'http2.label',
      'http3.help',
      'http3.label',
      'preferServerCiphers.help',
      'preferServerCiphers.label',
      'preferServerCiphers.off',
      'preferServerCiphers.on',
      'preferServerCiphers.preset',
      'validation.customCiphers',
    ].sort()

    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const leaves = flatten(siteTLSMessages[locale])
      expect(Object.keys(leaves).sort()).toEqual(expectedKeys)
      for (const key of expectedKeys) {
        expect(i18n.getResource(locale, 'siteTLS', key)).toBe(leaves[key])
      }
    }
  })

  it('uses real English and an expanded pseudo locale without Chinese fallback', () => {
    const english = Object.values(flatten(siteTLSMessages['en-US'])).join('')
    expect(english).not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    expect(siteTLSMessages['qps-Ploc']).toEqual(siteTLSMessages['qps-ploc'])

    const chinese = flatten(siteTLSMessages['zh-CN'])
    const pseudo = flatten(siteTLSMessages['qps-ploc'])
    for (const [key, value] of Object.entries(pseudo)) {
      expect(value.startsWith('［')).toBe(true)
      expect(value.endsWith('］')).toBe(true)
      expect(value.length).toBeGreaterThan(chinese[key]!.length)
    }
  })
})
