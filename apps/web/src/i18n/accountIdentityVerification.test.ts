import i18n from './index'
import { accountIdentityVerificationMessages } from './accountIdentityVerification'

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

describe('account identity verification translations', () => {
  it('registers complete locale and interpolation parity', () => {
    const zh = flatten(accountIdentityVerificationMessages['zh-CN'])
    const en = flatten(accountIdentityVerificationMessages['en-US'])
    const keys = Object.keys(zh).sort()

    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(accountIdentityVerificationMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(keys)
      for (const key of keys) {
        expect(i18n.getResource(locale, 'accountIdentityVerification', key)).toBe(messages[key])
        expect(placeholders(messages[key]!)).toEqual(placeholders(zh[key]!))
      }
    }
    expect(keys).toEqual(expect.arrayContaining([
      'title', 'empty.description', 'actions.create', 'actions.retry',
      'actions.retrySameRequest', 'errors.identity_verification_permission_denied',
      'errors.rateLimited', 'states.draft', 'kinds.enterprise', 'materials.identity_document',
      'guidance.personal_reverification', 'materialSummary.custodyEncrypted',
      'details.decisionReason', 'decisionReasons.identity_mismatch',
      'provider.title', 'provider.kind', 'provider.provider', 'provider.start',
      'provider.pending', 'provider.succeeded', 'provider.createDraft',
      'provider.retrySameRequest', 'provider.waiting',
      'provider.states.creating', 'provider.states.pending', 'provider.states.processing',
      'provider.states.succeeded', 'provider.states.failed', 'provider.states.canceled',
      'provider.states.expired', 'provider.states.unknown',
      'upload.kind', 'upload.file', 'upload.submit', 'upload.finalized',
      'upload.states.finalized', 'upload.states.erase_pending', 'upload.states.erased',
      'errors.identity_verification_provider_result_unknown',
    ]))
    expect(zh['errors.rateLimited'])
      .toBe('操作过于频繁，请稍后重试。')
    expect(en['errors.rateLimited'])
      .toBe('Too many operations. Try again later.')
    expect(zh['decisionReasons.identity_mismatch'])
      .toBe('身份信息与可信材料不一致')
  })

  it('expands pseudo locales and excludes raw server or secret language', () => {
    const zh = flatten(accountIdentityVerificationMessages['zh-CN'])
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(accountIdentityVerificationMessages[locale])
      expect(accountIdentityVerificationMessages[locale])
        .toEqual(accountIdentityVerificationMessages['qps-ploc'])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value).toMatch(/^［.*］$/)
        expect(value.replace(/{{[^}]+}}/g, '').length)
          .toBeGreaterThan(zh[key]!.replace(/{{[^}]+}}/g, '').length)
      }
    }
    expect(Object.values(accountIdentityVerificationMessages)
      .flatMap((messages) => Object.values(flatten(messages)))
      .join('\n'))
      .not.toMatch(/postgres|stack trace|raw server|private topology|document number|access[_ -]?token|upload[_ -]?url|kms|evidence[_ -]?token|object[_ -]?version/i)
  })
})
