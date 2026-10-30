import i18n from './index'
import { identityVerificationReviewQueueMessages } from './identityVerificationReviewQueue'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('identityVerificationReviewQueueMessages', () => {
  it('registers complete zh-CN, en-US, and pseudo-locale resource trees', () => {
    const zh = flatten(identityVerificationReviewQueueMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'identityVerificationReviewQueue')).toBe(true)
      expect(Object.keys(flatten(identityVerificationReviewQueueMessages[locale])).sort())
        .toEqual(Object.keys(zh).sort())
    }
  })

  it('keeps the canonical Chinese title, expands pseudo text, and excludes raw server wording', () => {
    const zh = flatten(identityVerificationReviewQueueMessages['zh-CN'])
    const pseudo = flatten(identityVerificationReviewQueueMessages['qps-ploc'])

    expect(zh.title).toBe('实名认证审核')
    expect(pseudo.title?.length).toBeGreaterThan(zh.title!.length)
    expect(identityVerificationReviewQueueMessages['qps-Ploc'])
      .toEqual(identityVerificationReviewQueueMessages['qps-ploc'])
    for (const locale of Object.values(identityVerificationReviewQueueMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|internal service|private message/i)
      }
    }
  })
})
