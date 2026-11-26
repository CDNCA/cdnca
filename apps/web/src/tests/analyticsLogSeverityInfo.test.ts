import { describe, expect, it } from 'vitest'

import i18n from '../i18n'

// an observed (log-only) WAF event carries severity info; its level reads localized.
describe('analytics log severity', () => {
  it('localizes info next to the other levels', () => {
    expect(i18n.t('analyticsLogs:values.severity.info', { lng: 'zh-CN' })).toBe('信息')
    expect(i18n.t('analyticsLogs:values.severity.info', { lng: 'en-US' })).toBe('Info')
    expect(i18n.t('analyticsLogs:values.severity.high', { lng: 'zh-CN' })).toBe('高')
  })
})
