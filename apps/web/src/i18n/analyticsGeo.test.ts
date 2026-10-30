import i18n from './analyticsGeo'

describe('analyticsGeo locale', () => {
  it('registers Chinese, English, and expanded pseudo locale', () => {
    expect(i18n.t('actions.verify', { ns: 'analyticsGeo', lng: 'zh-CN' })).toBe('核验 IP 归属')
    expect(i18n.t('actions.verify', { ns: 'analyticsGeo', lng: 'en-US' })).toBe('Verify IP attribution')
    expect(i18n.t('values.no_prefix_match', { ns: 'analyticsGeo', lng: 'zh-CN' })).toBe('无匹配网段')
    expect(i18n.t('actions.verify', { ns: 'analyticsGeo', lng: 'qps-ploc' }).length).toBeGreaterThan('核验 IP 归属'.length)
  })
})
