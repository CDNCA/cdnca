import i18n from './index'
import { systemSettingsMessages } from './systemSettings'

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

describe('systemSettings translations', () => {
  it('registers identical keys and stable server error codes for every supported locale spelling', () => {
    const zh = flatten(systemSettingsMessages['zh-CN'])
    const expected = Object.keys(zh).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(systemSettingsMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(expected)
      for (const key of expected) {
        expect(i18n.getResource(locale, 'systemSettings', key)).toBe(messages[key])
        expect(placeholders(messages[key]!)).toEqual(placeholders(zh[key]!))
      }
    }
    expect(expected).toEqual(expect.arrayContaining([
      'errors.system_configuration_unauthenticated',
      'errors.system_configuration_validation_error',
      'errors.system_configuration_permission_denied',
      'errors.system_configuration_active_not_found',
      'errors.system_configuration_revision_conflict',
      'errors.system_configuration_idempotency_conflict',
      'errors.system_configuration_entitlement_denied',
      'errors.system_configuration_unavailable',
    ]))
  })

  it('expands pseudo locale text without exposing raw server wording', () => {
    const zh = flatten(systemSettingsMessages['zh-CN'])
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(systemSettingsMessages[locale])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value).toMatch(/^［.*］$/)
        expect(value.length).toBeGreaterThan(zh[key]!.length)
        expect(value).not.toMatch(/private|database|credential|stack trace/i)
      }
    }
  })
})
