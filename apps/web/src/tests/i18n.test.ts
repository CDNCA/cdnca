import i18n, { changeLocale, localeStorageKey, userLocales, type UserLocale } from '../i18n'
import { enUS, pseudoCN, zhCN } from '../i18n/resources'
import { getBreadcrumbLabels, getNavigation } from '../routes/navigation'

function leafKeys(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) return [prefix]
  return Object.entries(value).flatMap(([key, child]) =>
    leafKeys(child, prefix ? `${prefix}.${key}` : key),
  )
}

describe('web internationalization', () => {
  it('exposes only the three user-facing locales', () => {
    expect(userLocales).toEqual(['zh-CN', 'zh-TW', 'en-US'])
  })

  it('ships a complete generated pseudo locale for every Chinese key', () => {
    expect(leafKeys(pseudoCN).sort()).toEqual(leafKeys(zhCN).sort())
  })

  it('ships a complete English core locale', () => {
    expect(leafKeys(enUS).sort()).toEqual(leafKeys(zhCN).sort())
  })

  it('ships matching production system-configuration leaf keys', () => {
    expect(zhCN.systemConfiguration).toBeTypeOf('object')
    expect(enUS.systemConfiguration).toBeTypeOf('object')
    expect(leafKeys(enUS.systemConfiguration).sort()).toEqual(
      leafKeys(zhCN.systemConfiguration).sort(),
    )
  })

  it('uses complete Simplified Chinese navigation by default', () => {
    expect(i18n.resolvedLanguage).toBe('zh-CN')
    expect(getNavigation('admin').map((item) => item.label)).toContain('节点管理')
    expect(getBreadcrumbLabels('user', '/account/message')).toEqual([
      '首页',
      '账户中心',
      '消息查询',
    ])
  })

  it('switches navigation and document language to the expanded pseudo locale', async () => {
    await changeLocale('qps-ploc' as UserLocale)

    expect(i18n.resolvedLanguage?.toLowerCase()).toBe('qps-ploc')
    expect(document.documentElement.lang).toBe('qps-ploc')
    expect(localStorage.getItem(localeStorageKey)).toBe('qps-ploc')
    expect(getNavigation('admin')[0].label).toMatch(/^［.+］$/)
    expect(getBreadcrumbLabels('user', '/account/message')).not.toContain('首页')
  })

  it('fails fast for missing keys outside production', () => {
    expect(() => i18n.t('common:__missing_i18n_test_key__')).toThrow(/missing/i)
  })

  it('persists an explicit English selection and updates translated navigation', async () => {
    await changeLocale('en-US')

    expect(localStorage.getItem(localeStorageKey)).toBe('en-US')
    expect(document.documentElement.lang).toBe('en-US')
    expect(getNavigation('admin').map((item) => item.label)).toContain('Nodes')
    expect(getBreadcrumbLabels('user', '/account/message')).toEqual([
      'Home',
      'Account center',
      'Messages',
    ])
  })

  it('keeps Simplified Chinese resources intact after switching to Traditional and back', async () => {
    await changeLocale('zh-TW')
    expect(i18n.t('common:pageLoading')).toBe('頁面加載中')
    expect(document.documentElement.lang).toBe('zh-TW')

    await changeLocale('zh-CN')
    expect(i18n.t('common:pageLoading')).toBe('页面加载中')
    expect(zhCN.common.pageLoading).toBe('页面加载中')
    expect(i18n.getResourceBundle('zh-CN', 'common')).not.toBe(i18n.getResourceBundle('zh-TW', 'common'))
    expect(getNavigation('admin').map((item) => item.label)).toContain('节点管理')
    expect(document.documentElement.lang).toBe('zh-CN')
    expect(localStorage.getItem(localeStorageKey)).toBe('zh-CN')
  })

  it('isolates late registered namespaces across repeated Chinese locale switches', async () => {
    const namespace = '__locale_roundtrip_test__'
    const messages = { nested: { window: '通知时间段', expired: '证书已过期' } }
    try {
      await changeLocale('zh-TW')
      i18n.addResourceBundle('zh-CN', namespace, messages, true, true)
      await vi.waitFor(() => expect(i18n.getResource('zh-TW', namespace, 'nested.window')).toBe('通知時間段'))
      expect(i18n.t('nested.expired', { ns: namespace })).toBe('證書已過期')

      await changeLocale('zh-CN')
      expect(i18n.t('nested.window', { ns: namespace })).toBe('通知时间段')
      expect(messages.nested.expired).toBe('证书已过期')
      await changeLocale('zh-TW')
      await changeLocale('zh-CN')
      expect(i18n.t('nested.expired', { ns: namespace })).toBe('证书已过期')
    } finally {
      i18n.removeResourceBundle('zh-CN', namespace)
      i18n.removeResourceBundle('zh-TW', namespace)
    }
  })
})
