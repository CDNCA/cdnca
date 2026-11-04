import i18n from './index'

// 写操作结果未确认时离开弹窗/放弃重试的共用确认文案（已售套餐、错误页、四层转发等共用）。
const zhCN = {
  title: '操作结果尚未确认',
  content: '结果尚未确认，关闭后请刷新列表核对是否已生效',
  close: '关闭',
  cancel: '取消',
  abandonRefresh: '放弃并刷新',
}
const enUS: typeof zhCN = {
  title: 'Operation result is not yet confirmed',
  content: 'The result is not confirmed yet. After closing, refresh the list to check whether it took effect.',
  close: 'Close',
  cancel: 'Cancel',
  abandonRefresh: 'Abandon and refresh',
}
const pseudo = Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, `［${value} ${value}］`]))
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo })) {
  i18n.addResourceBundle(locale, 'unconfirmedClose', messages, true, true)
}
