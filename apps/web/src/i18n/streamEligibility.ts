import i18n from './index'

// 四层转发的套餐未生效原因，文案与网站一致（site states.packageState）。
const zhCN = { package_suspended: '订阅已暂停', package_cancelled: '订阅已终止' }
const enUS: typeof zhCN = { package_suspended: 'Subscription suspended', package_cancelled: 'Subscription terminated' }
const pseudo = Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, `［${value}］`])) as typeof zhCN
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo })) {
  i18n.addResourceBundle(locale, 'streamEligibility', messages, true, true)
}

export { enUS, zhCN }
