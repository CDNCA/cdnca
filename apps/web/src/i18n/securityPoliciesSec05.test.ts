import i18n from './index'
import './securityPoliciesSec05'
import './securityPoliciesSec11'

describe('securityPolicies SEC-05 locale bundle', () => {
  it.each(['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'])('contains the complete security policy locale bundle in %s', (locale) => {
    for (const key of [
      'editor.aclImport', 'editor.comment', 'editor.expiresAt', 'editor.expiresPlaceholder',
      'editor.targetScopePlaceholder', 'editor.ownerPlaceholder',
      'evaluate.ja4', 'evaluate.ja4Placeholder',
      'errors.acl_import_invalid', 'import.invalid_cidr',
    ]) {
      const value = i18n.getResource(locale, 'securityPolicies', key)
      expect(typeof value).toBe('string')
      expect(value).not.toBe(key)
    }
  })
})
