import i18n from './index'
import { identityVerificationReviewCaseMessages } from './identityVerificationReviewCase'

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

describe('identity verification review case translations', () => {
  it('registers complete locale and interpolation parity', () => {
    const zh = flatten(identityVerificationReviewCaseMessages['zh-CN'])
    const keys = Object.keys(zh).sort()

    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(identityVerificationReviewCaseMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(keys)
      for (const key of keys) {
        expect(i18n.getResource(locale, 'identityVerificationReviewCase', key)).toBe(messages[key])
        expect(placeholders(messages[key]!)).toEqual(placeholders(zh[key]!))
      }
    }
    expect(keys).toEqual(expect.arrayContaining([
      'title', 'actions.claim', 'actions.retry', 'actions.retrySameRequest',
      'details.applicant', 'materials.encrypted', 'errors.identity_verification_not_found',
      'errors.identity_verification_revision_conflict', 'states.reviewing',
    ]))
  })

  it('expands pseudo locales and excludes raw server or secret language', () => {
    const zh = flatten(identityVerificationReviewCaseMessages['zh-CN'])
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(identityVerificationReviewCaseMessages[locale])
      expect(identityVerificationReviewCaseMessages[locale])
        .toEqual(identityVerificationReviewCaseMessages['qps-ploc'])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value).toMatch(/^［.*］$/)
        expect(value.replace(/{{[^}]+}}/g, '').length)
          .toBeGreaterThan(zh[key]!.replace(/{{[^}]+}}/g, '').length)
      }
    }
    expect(JSON.stringify(identityVerificationReviewCaseMessages))
      .not.toMatch(/postgres|stack trace|raw server|private topology|document number|access[_ -]?token/i)
  })
})
