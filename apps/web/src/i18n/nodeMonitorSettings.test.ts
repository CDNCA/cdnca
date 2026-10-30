import i18n from './index'
import './nodeMonitorSettings'

describe('node monitor settings translations', () => {
  it.each([
    ['zh-CN', '节点监控设置'],
    ['en-US', 'Node Monitoring Settings'],
  ])('provides a complete %s bundle', (locale, title) => {
    const t = i18n.getFixedT(locale, 'nodeMonitorSettings')
    expect(t('title')).toBe(title)
    expect(t('fields.probeInterval')).not.toContain('fields.')
    expect(t('integration.ready')).toContain('READY_INTEGRATION')
  })

  it('provides visibly expanded pseudo-locale strings', () => {
    const t = i18n.getFixedT('qps-ploc', 'nodeMonitorSettings')
    expect(t('title')).toMatch(/^［.+］$/)
    expect(t('title').length).toBeGreaterThan('节点监控设置'.length)
  })

  it.each([
    ['initialDraft', '尚未配置，当前为默认草稿', 'Not configured; showing the default draft'],
    ['saved', '配置已保存，尚未激活', 'Configuration saved; not activated'],
    ['validated', '预检已通过，尚未激活', 'Preflight passed; not activated'],
    ['newerDraft', '主控已有激活版本，另有未激活修改', 'A controller revision is active; newer changes are not activated'],
    ['activePending', '主控已激活，节点执行待确认', 'Controller activated; node execution is unconfirmed'],
  ])('keeps configuration and node execution distinct for %s in every locale', (key, chinese, english) => {
    expect(i18n.getFixedT('zh-CN', 'nodeMonitorSettings')(`monitoringState.${key}`)).toBe(chinese)
    expect(i18n.getFixedT('en-US', 'nodeMonitorSettings')(`monitoringState.${key}`)).toBe(english)
    const pseudo = i18n.getFixedT('qps-ploc', 'nodeMonitorSettings')(`monitoringState.${key}`)
    expect(pseudo).toMatch(/^［.+］$/)
    expect(pseudo.length).toBeGreaterThan(chinese.length)
  })

  it.each(['zh-CN', 'en-US', 'qps-ploc'])('provides the save-first explanation and controller-only activation label in %s', (locale) => {
    const t = i18n.getFixedT(locale, 'nodeMonitorSettings')
    expect(t('lifecycle.saveFirst')).not.toContain('lifecycle.')
    expect(t('lifecycle.statuses.active')).not.toContain('statuses.')
    expect(t('lifecycle.description')).not.toContain('lifecycle.')
  })

  it.each([
    ['zh-CN', '10秒', '自定义当前值：', '毫秒'],
    ['en-US', '10 seconds', 'Custom current value:', 'ms'],
    ['qps-ploc', '［1~0~秒~］', '［自~定~义~当~前~值~：~］', '［毫~秒~］'],
  ])('localizes every interval label in %s', (locale, preset, custom, unit) => {
    const t = i18n.getFixedT(locale, 'nodeMonitorSettings')
    expect(t('values.tenSeconds')).toBe(preset)
    expect(t('values.customCurrentInterval')).toBe(custom)
    expect(t('values.millisecondsUnit')).toBe(unit)
  })
})
