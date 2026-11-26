import i18n from './index'

// the block event drawer names task_id and tells the request host from a
// different site domain.
const messages = {
  'zh-CN': { detail: { taskId: '任务 ID', requestHost: '请求域名' } },
  'en-US': { detail: { taskId: 'Task ID', requestHost: 'Request host' } },
  'qps-ploc': { detail: { taskId: '[!! Ţåsk ÏÐ !!]', requestHost: '[!! Rêqüêsţ höšţ !!]' } },
} as const

for (const [locale, bundle] of Object.entries({ ...messages, 'qps-Ploc': messages['qps-ploc'] })) {
  i18n.addResourceBundle(locale, 'analyticsLogs', bundle, true, true)
}
