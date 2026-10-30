import i18n from './index'

type Tree = { [key: string]: string | Tree }
type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const zhCN = {
  title: '可控日志采集',
  description: '按站点显式启用请求与响应字段采集。敏感字段始终脱敏，未匹配请求保持默认关闭。',
  fields: {
    enabled: '启用采集', methods: '请求方法', uriPrefixes: 'URI 前缀', requestHeaders: '请求头字段',
    responseHeaders: '响应头字段', requestBody: '请求体字段', responseBody: '响应体字段',
    maxValueBytes: '单值上限', maxBodyBytes: '正文上限', maxEventBytes: '事件上限',
  },
  help: { lines: '每行一个字段或前缀。', explicit: '启用后至少选择一个采集字段。' },
  actions: { save: '保存策略', retry: '按原请求重试', refresh: '刷新' },
  states: { loading: '策略加载中', readOnly: '当前账号只有查看权限。', saved: '采集策略已保存。', disabled: '默认关闭', unconfigured: '本网站尚未设置采集策略，当前按默认值（不采集）运行；保存后生效。' },
  errors: {
    load: '采集策略加载失败。', validation: '请检查筛选条件、采集字段与容量上限。',
    authentication_required: '登录状态已失效，请重新登录。', permission_denied: '当前账号没有管理采集策略的权限。',
    site_capture_not_found: '网站不存在或当前账号无权查看。', site_capture_revision_conflict: '策略已更新，请刷新后重试。',
    site_capture_idempotency_conflict: '该请求标识已用于其他策略。', site_capture_unavailable: '采集策略服务暂不可用。',
    site_capture_invalid_request: '采集策略请求无效。', invalid_response: '服务响应无效。', network_error: '网络不可用，结果未知。', unknown: '保存失败，请稍后重试。',
  },
} as const

const enUS = {
  title: 'Controlled log capture', description: 'Explicitly capture selected request and response fields per site. Sensitive fields are always redacted.',
  fields: { enabled: 'Enable capture', methods: 'Request methods', uriPrefixes: 'URI prefixes', requestHeaders: 'Request headers', responseHeaders: 'Response headers', requestBody: 'Request body fields', responseBody: 'Response body fields', maxValueBytes: 'Value limit', maxBodyBytes: 'Body limit', maxEventBytes: 'Event limit' },
  help: { lines: 'Enter one field or prefix per line.', explicit: 'Select at least one captured field before enabling.' },
  actions: { save: 'Save policy', retry: 'Retry exact request', refresh: 'Refresh' },
  states: { loading: 'Loading policy', readOnly: 'The current account has read-only access.', saved: 'Capture policy saved.', disabled: 'Off by default', unconfigured: 'No capture policy has been saved for this site; it runs with the defaults (no capture). Save to apply.' },
  errors: { load: 'Failed to load capture policy.', validation: 'Check filters, selected fields, and size limits.', authentication_required: 'Your session expired. Sign in again.', permission_denied: 'You cannot manage capture policy.', site_capture_not_found: 'The site does not exist or is not visible to this account.', site_capture_revision_conflict: 'The policy changed. Refresh before retrying.', site_capture_idempotency_conflict: 'The request identifier belongs to another policy.', site_capture_unavailable: 'Capture policy service is unavailable.', site_capture_invalid_request: 'The capture policy request is invalid.', invalid_response: 'The service response is invalid.', network_error: 'The network is unavailable and the outcome is unknown.', unknown: 'Saving failed. Try again later.' },
} satisfies MessageShape<typeof zhCN>

function pseudo(value: string): string {
  return `［${[...value].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')}］`
}

function pseudoTree(tree: Tree): Tree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [key, typeof value === 'string' ? pseudo(value) : pseudoTree(value)]))
}

export const siteCapturePolicyMessages: Record<string, Tree> = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoTree(zhCN), 'qps-Ploc': pseudoTree(zhCN) }

for (const [locale, messages] of Object.entries(siteCapturePolicyMessages)) {
  i18n.addResourceBundle(locale, 'siteCapturePolicy', messages, true, true)
}
