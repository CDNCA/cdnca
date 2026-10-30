import { changeLocale } from '.'
import i18n from './siteDiagnostics'

describe('siteDiagnostics locale', () => {
  it('provides complete zh-CN and pseudo diagnostic labels', async () => {
    await changeLocale('zh-CN')
    expect(i18n.t('categories.no_host', { ns: 'siteDiagnostics' })).toBe('无 Host')
    await changeLocale('qps-ploc')
    expect(i18n.t('columns.config', { ns: 'siteDiagnostics' })).toMatch(/^［/)
  })
})
