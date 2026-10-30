import i18n, { enUS, pseudoCN, zhCN } from './qualityDiagnostics'

function keys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [prefix]
  return Object.entries(value).flatMap(([key, child]) => keys(child, prefix ? `${prefix}.${key}` : key))
}

describe('qualityDiagnostics locale', () => {
  it('keeps Chinese, English, and pseudo surfaces structurally complete', () => {
    expect(keys(enUS).sort()).toEqual(keys(zhCN).sort())
    expect(keys(pseudoCN).sort()).toEqual(keys(zhCN).sort())
  })

  it('registers exact category, action, state, and expanded pseudo labels', () => {
    expect(i18n.t('categories.edge_530', { ns: 'qualityDiagnostics', lng: 'zh-CN' })).toBe('边缘 530')
    expect(i18n.t('categories.edge_530', { ns: 'qualityDiagnostics', lng: 'en-US' })).toBe('Edge 530')
    expect(i18n.t('actions.reconcile_config', { ns: 'qualityDiagnostics', lng: 'zh-CN' })).toBe('对齐配置版本')
    expect(i18n.t('states.permission', { ns: 'qualityDiagnostics', lng: 'zh-CN' })).toBe('无权查看质量诊断')
    expect(i18n.t('categories.edge_530', { ns: 'qualityDiagnostics', lng: 'qps-ploc' }).length)
      .toBeGreaterThan('边缘 530'.length)
  })
})
