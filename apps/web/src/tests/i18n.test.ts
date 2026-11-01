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

  // dev 下 zh-TW 打开登录页报 Missing translation key: approvalCenter:prompt.title。
  // 模块在繁体转换进行中（changeLocale('zh-TW') 尚未完成）注册简体文案时，也必须得到繁体。
  it('converts namespaces registered right after a Traditional Chinese boot', async () => {
    // 新的一次整页加载：存的语言是 zh-TW，i18n 启动即开始繁体转换，紧接着页面模块注册自己的命名空间。
    vi.resetModules()
    window.localStorage.setItem(localeStorageKey, 'zh-TW')
    try {
      const { default: fresh } = await import('../i18n')
      await import('../i18n/approvalCenter')
      // 注册后同步取值（组件首次渲染即取 Modal 标题）：繁体还没转完时也不能缺键。
      expect(fresh.t('prompt.title', { ns: 'approvalCenter' })).toMatch(/^(该操作需要审批|該操作需要審批)$/)
      await vi.waitFor(() => expect(fresh.resolvedLanguage).toBe('zh-TW'))
      await vi.waitFor(() => expect(fresh.getResource('zh-TW', 'approvalCenter', 'prompt.title')).toBe('該操作需要審批'))
      expect(fresh.t('prompt.title', { ns: 'approvalCenter' })).toBe('該操作需要審批')
    } finally {
      window.localStorage.setItem(localeStorageKey, 'zh-CN')
      vi.resetModules()
    }
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
