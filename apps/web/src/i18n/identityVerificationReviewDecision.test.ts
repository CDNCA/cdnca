import i18n from './index'
import { identityVerificationReviewDecisionMessages } from './identityVerificationReviewDecision'

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

describe('identity verification review decision translations', () => {
  it('registers complete locale and interpolation parity', () => {
    const zh = flatten(identityVerificationReviewDecisionMessages['zh-CN'])
    const keys = Object.keys(zh).sort()

    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(identityVerificationReviewDecisionMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(keys)
      for (const key of keys) {
        expect(i18n.getResource(locale, 'identityVerificationReviewDecision', key)).toBe(messages[key])
        expect(placeholders(messages[key]!)).toEqual(placeholders(zh[key]!))
      }
    }
    expect(keys).toEqual(expect.arrayContaining([
      'title', 'actions.submit', 'actions.retrySameRequest', 'confirmations.submit',
      'decisions.approved', 'reasons.evidence_verified', 'reasons.suspected_fraud',
      'errors.identity_verification_permission_denied',
    ]))
  })

  it('expands pseudo locales and excludes raw server or secret language', () => {
    const zh = flatten(identityVerificationReviewDecisionMessages['zh-CN'])
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(identityVerificationReviewDecisionMessages[locale])
      expect(identityVerificationReviewDecisionMessages[locale])
        .toEqual(identityVerificationReviewDecisionMessages['qps-ploc'])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value).toMatch(/^［.*］$/)
        expect(value.replace(/{{[^}]+}}/g, '').length)
          .toBeGreaterThan(zh[key]!.replace(/{{[^}]+}}/g, '').length)
      }
    }
    expect(JSON.stringify(identityVerificationReviewDecisionMessages))
      .not.toMatch(/postgres|stack trace|raw server|private topology|document number|access[_ -]?token/i)
  })
})
