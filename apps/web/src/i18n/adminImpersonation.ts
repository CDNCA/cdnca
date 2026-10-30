import i18n from './index'

// 代登录表单页已删除（「切换」直接登录），这里只剩代登录状态条用到的文案。
const zhCN = {
  actions: { retryExact: '使用完全相同的请求重试', abandon: '放弃本次尝试', exit: '退出代登录' },
  status: {
    unknown: '操作结果尚不确定。',
    banner: '正在代登录：{{actor}} 以 {{subject}} 身份操作，{{expiresAt}} 到期',
    exiting: '正在退出代登录',
  },
  errors: { exit: '退出失败，请重试。' },
}

const enUS: typeof zhCN = {
  actions: { retryExact: 'Retry the exact same request', abandon: 'Abandon attempt', exit: 'Exit impersonation' },
  status: {
    unknown: 'The operation outcome is unknown.',
    banner: 'Impersonating: {{actor}} is acting as {{subject}} until {{expiresAt}}',
    exiting: 'Exiting impersonation',
  },
  errors: { exit: 'Could not exit impersonation. Try again.' },
}

type Messages = typeof zhCN

function pseudoText(value: string): string {
  return `［${value.split(/(\{\{[^{}]+\}\})/g).map((part) => (
    part.startsWith('{{') ? part : part.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')
  )).join('')}］`
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const adminImpersonationMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(adminImpersonationMessages)) {
  i18n.addResourceBundle(locale, 'adminImpersonation', messages, true, true)
}
