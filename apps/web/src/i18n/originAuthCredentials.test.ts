import i18n from './index'
import { originAuthCredentialsMessages } from './originAuthCredentials'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('originAuthCredentialsMessages', () => {
  it('registers complete zh-CN, en-US, and expanded pseudo resources', () => {
    const zh = flatten(originAuthCredentialsMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'originAuthCredentials')).toBe(true)
      expect(Object.keys(flatten(originAuthCredentialsMessages[locale])).sort())
        .toEqual(Object.keys(zh).sort())
    }
    expect(zh.title).toBe('源站鉴权凭据')
    expect(flatten(originAuthCredentialsMessages['qps-ploc']).title?.length)
      .toBeGreaterThan(zh.title!.length)
    expect(originAuthCredentialsMessages['qps-Ploc']).toEqual(originAuthCredentialsMessages['qps-ploc'])
    expect(originAuthCredentialsMessages['zh-CN'].actions.abandon).toBe('放弃并刷新')
    expect(originAuthCredentialsMessages['en-US'].actions.abandon).toBe('Abandon and refresh')
    expect(originAuthCredentialsMessages['qps-ploc'].actions.abandon.length)
      .toBeGreaterThan(originAuthCredentialsMessages['zh-CN'].actions.abandon.length)
  })

  it('never contains raw server wording or credential material', () => {
    for (const locale of Object.values(originAuthCredentialsMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|internal service|private message|secret_access_key|session_token/i)
      }
    }
  })
})
