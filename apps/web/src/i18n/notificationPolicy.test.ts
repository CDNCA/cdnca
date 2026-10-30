import i18n, { changeLocale, userLocales } from './index'
import { notificationPolicyMessages } from './notificationPolicy'

function keys(value: object, prefix = ''): string[] {
  return Object.entries(value).flatMap(([key, child]) => typeof child === 'string' ? [`${prefix}${key}`] : keys(child, `${prefix}${key}.`))
}

describe('notification policy language resources', () => {
  it('keeps Chinese and English keys complete with only three selectable languages', () => {
    expect(keys(notificationPolicyMessages['en-US']).sort()).toEqual(keys(notificationPolicyMessages['zh-CN']).sort())
    expect(userLocales).toEqual(['zh-CN', 'zh-TW', 'en-US'])
    expect(notificationPolicyMessages['zh-CN'].events.expirationTriggered).toBe('套餐到期预警')
  })

  it('converts Traditional Chinese through the shared locale converter', async () => {
    await changeLocale('zh-TW')
    expect(i18n.t('window', { ns: 'notificationPolicy' })).toBe('通知時間段')
    expect(i18n.t('events.certificateExpired', { ns: 'notificationPolicy' })).toBe('證書已過期')
    await changeLocale('zh-CN')
    expect(i18n.t('window', { ns: 'notificationPolicy' })).toBe('通知时间段')
  })

  it('registers text expansion only for test-mode layout checks without damaging interpolation', async () => {
    await changeLocale('qps-ploc')
    expect(i18n.t('title', { ns: 'notificationPolicy' })).toContain('~')
    expect(i18n.t('timezone', { ns: 'notificationPolicy', timezone: 'Asia/Shanghai' })).toContain('Asia/Shanghai')
  })
})
