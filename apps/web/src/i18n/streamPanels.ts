import i18n from './index'

const zhCN = {
  unknown: '操作结果尚未确认',
  retryExact: '按原请求重试',
  unknownDescription: '请按原请求重试以确认结果；已成功的删除不会重复提交。',
  ownersFailed: '用户列表加载失败',
  ownersForbidden: '当前账号无权读取归属用户列表',
}
const enUS: typeof zhCN = {
  unknown: 'Operation outcome is not confirmed',
  retryExact: 'Retry the exact request',
  unknownDescription: 'Retry the original request to confirm the outcome. Successful deletions are not repeated.',
  ownersFailed: 'Failed to load users',
  ownersForbidden: 'You cannot read the owner list',
}
for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, `［${value} ${value}］`])),
  'qps-Ploc': Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, `［${value} ${value}］`])),
})) i18n.addResourceBundle(locale, 'streamPanels', messages, true, true)
