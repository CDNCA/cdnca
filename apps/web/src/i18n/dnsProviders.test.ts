import i18n from './index'
import { dnsProvidersMessages } from './dnsProviders'

function leafKeys(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) return [prefix]
  return Object.entries(value).flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key))
}

describe('DNS provider local resources', () => {
  it.each(['zh-CN', 'en-US', 'qps-ploc'] as const)('keeps %s complete and registers status mappings', (locale) => {
    expect(i18n.exists(`dnsProviders:errors.notFoundTitle`, { lng: locale })).toBe(true)
    expect(i18n.exists(`dnsProviders:errors.notFoundDescription`, { lng: locale })).toBe(true)
    expect(leafKeys(dnsProvidersMessages[locale]).sort()).toEqual(
      leafKeys(dnsProvidersMessages['zh-CN']).sort(),
    )
  })

  it('keeps pseudo provider messages visibly expanded', () => {
    expect(i18n.t('dnsProviders:errors.notFoundTitle', { lng: 'qps-ploc' })).toMatch(/^［.+］$/)
  })
})
