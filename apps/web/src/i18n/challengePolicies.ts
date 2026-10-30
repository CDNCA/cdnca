import i18n from './index'

const zhCN = {
  tabs: { rules: 'CC规则', policies: '挑战策略' },
  title: '挑战策略',
  subtitle: '管理租户站点的浏览器挑战方式和通行有效期。',
  actions: {
    create: '新建挑战策略', save: '保存', cancel: '取消', edit: '编辑', delete: '删除',
    enable: '启用', disable: '停用', refresh: '刷新', applyTarget: '应用目标', applyFilters: '筛选',
    resetFilters: '重置', previous: '上一页', next: '下一页', retry: '重试',
    retrySameRequest: '使用同一请求重试', closeAndRefresh: '关闭并刷新', publish: '发布到边缘',
    refreshPublication: '刷新发布状态', activate: '激活配置',
    editNamed: '编辑 {{name}}', deleteNamed: '删除 {{name}}', enableNamed: '启用 {{name}}', disableNamed: '停用 {{name}}',
    publishNamed: '发布 {{name}}', refreshPublicationNamed: '刷新 {{name}} 的发布状态',
  },
  target: { label: '目标租户作用域', placeholder: '小写租户作用域 UUID', required: '请先选择要管理的租户作用域。', invalid: '请输入有效的小写租户作用域 UUID。' },
  filters: { site: '站点 ID', host: '主机名', enabled: '状态', all: '全部状态' },
  states: { enabled: '已启用', disabled: '已停用', configured: '已配置', notConfigured: '未配置' },
  columns: { host: '主机名', site: '站点 ID', mode: '挑战方式', ttl: '挑战/通行 TTL', binding: '绑定', failures: '失败上限', status: '状态', publication: '边缘发布', revision: '修订', updatedAt: '更新时间', actions: '操作' },
  modes: { delay: '延迟验证', click: '点击验证', slider: '滑块验证', captcha: '验证码', external: '外部验证' },
  providers: { tencent: '腾讯云验证码', geetest: '极验 v4' },
  bindings: { none: '不绑定', ip: '仅 IP', userAgent: '仅 User-Agent', both: 'IP + User-Agent' },
  editor: {
    createTitle: '新建挑战策略', editTitle: '编辑挑战策略', site: '站点 ID', host: '主机名', enabled: '立即启用',
    priority: '优先级', mode: '挑战模式', minDelay: '最短延迟（秒）', challengeTTL: '挑战有效期（秒）',
    passTTL: '通行有效期（秒）', clockSkew: '时钟偏差（秒）', failureWindow: '失败窗口（秒）',
    maxFailures: '窗口内失败上限', ipBinding: 'IP 绑定', bindUA: '绑定 User-Agent', bypass: '绕过路径',
    bypassPlaceholder: '每行一条，例如：prefix /health/', keyReference: '密钥引用',
    keyPlaceholder: 'keyref:、vault: 或 kms: 引用', provider: '外部提供商', appReference: '应用引用',
    appPlaceholder: 'appref: 引用', attempts: '每个随机数尝试次数固定为 1',
  },
  validation: {
    required: '此字段不能为空', uuid: '请输入有效的小写 UUID', host: '请输入规范的小写主机名',
    key: '请输入有效的密钥引用', app: '请输入有效的应用引用', ttl: '挑战有效期必须大于最短延迟与时钟偏差之和',
    bypass: '绕过路径必须使用“exact /path”或“prefix /path/”格式',
  },
  confirm: { delete: '确认删除该挑战策略？', enable: '确认启用该挑战策略？', disable: '确认停用该挑战策略？' },
  notices: { create: '挑战策略已创建', update: '挑战策略已更新', delete: '挑战策略已删除', enable: '挑战策略已启用', disable: '挑战策略已停用', conflict: '策略修订已变化，列表已刷新' },
  pagination: { page: '第 {{page}} 页' },
  values: { empty: '暂无挑战策略', ttl: '{{challenge}} / {{pass}} 秒', failures: '{{count}} 次 / {{window}} 秒' },
  publication: {
    notPublished: '尚未发布', progress: '{{healthy}} / {{total}} 节点健康',
    superseded: '已忽略旧发布 {{n}}',
    states: { queued: '等待下发', running: '节点应用中', healthy: '密钥已就绪', failed: '发布失败，保留旧配置', active: '已激活' },
  },
  forbidden: { title: '无权访问挑战策略', description: '当前账号缺少挑战策略查看权限。' },
  uncertainty: { title: '操作结果待确认', description: '写操作已锁定。重试会复用完全相同的请求正文、修订和幂等键；也可关闭并刷新确认结果。' },
  errors: { load: '挑战策略加载失败', invalid_response: '服务响应无效，请刷新后确认结果', permission_denied: '当前账号缺少挑战策略权限', revision_conflict: '策略修订已变化', idempotency_conflict: '幂等键已用于其他请求', validation_error: '策略字段组合无效', request_failed: '请求失败，请稍后重试', forbiddenRules: '当前账号缺少 CC 规则查看权限。' },
}

const enUS = {
  tabs: { rules: 'CC rules', policies: 'Challenge policies' },
  title: 'Challenge policies', subtitle: 'Manage browser challenges and pass lifetimes for tenant sites.',
  actions: {
    create: 'New challenge policy', save: 'Save', cancel: 'Cancel', edit: 'Edit', delete: 'Delete',
    enable: 'Enable', disable: 'Disable', refresh: 'Refresh', applyTarget: 'Apply target', applyFilters: 'Filter',
    resetFilters: 'Reset', previous: 'Previous', next: 'Next', retry: 'Retry', retrySameRequest: 'Retry same request',
    closeAndRefresh: 'Close and refresh', publish: 'Publish to edge', refreshPublication: 'Refresh publication', activate: 'Activate config',
    editNamed: 'Edit {{name}}', deleteNamed: 'Delete {{name}}',
    enableNamed: 'Enable {{name}}', disableNamed: 'Disable {{name}}',
    publishNamed: 'Publish {{name}}', refreshPublicationNamed: 'Refresh publication for {{name}}',
  },
  target: { label: 'Target tenant scope', placeholder: 'Lowercase tenant scope UUID', required: 'Select a tenant scope to manage first.', invalid: 'Enter a valid lowercase tenant scope UUID.' },
  filters: { site: 'Site ID', host: 'Host', enabled: 'Status', all: 'All statuses' },
  states: { enabled: 'Enabled', disabled: 'Disabled', configured: 'Configured', notConfigured: 'Not configured' },
  columns: { host: 'Host', site: 'Site ID', mode: 'Challenge mode', ttl: 'Challenge/pass TTL', binding: 'Binding', failures: 'Failure limit', status: 'Status', publication: 'Edge publication', revision: 'Revision', updatedAt: 'Updated at', actions: 'Actions' },
  modes: { delay: 'Delayed verification', click: 'Click verification', slider: 'Slider verification', captcha: 'CAPTCHA', external: 'External verification' },
  providers: { tencent: 'Tencent Cloud CAPTCHA', geetest: 'GeeTest v4' },
  bindings: { none: 'No binding', ip: 'IP only', userAgent: 'User-Agent only', both: 'IP + User-Agent' },
  editor: {
    createTitle: 'New challenge policy', editTitle: 'Edit challenge policy', site: 'Site ID', host: 'Host', enabled: 'Enable immediately',
    priority: 'Priority', mode: 'Challenge mode', minDelay: 'Minimum delay (seconds)', challengeTTL: 'Challenge TTL (seconds)',
    passTTL: 'Pass TTL (seconds)', clockSkew: 'Clock skew (seconds)', failureWindow: 'Failure window (seconds)',
    maxFailures: 'Failures per window', ipBinding: 'IP binding', bindUA: 'Bind User-Agent', bypass: 'Bypass paths',
    bypassPlaceholder: 'One per line, for example: prefix /health/', keyReference: 'Key reference',
    keyPlaceholder: 'keyref:, vault:, or kms: reference', provider: 'External provider', appReference: 'Application reference',
    appPlaceholder: 'appref: reference', attempts: 'Attempts per nonce are fixed at 1',
  },
  validation: {
    required: 'This field is required', uuid: 'Enter a valid lowercase UUID', host: 'Enter a canonical lowercase host',
    key: 'Enter a valid key reference', app: 'Enter a valid application reference',
    ttl: 'Challenge TTL must exceed the minimum delay plus clock skew',
    bypass: 'Bypass paths must use the format "exact /path" or "prefix /path/"',
  },
  confirm: { delete: 'Delete this challenge policy?', enable: 'Enable this challenge policy?', disable: 'Disable this challenge policy?' },
  notices: { create: 'Challenge policy created', update: 'Challenge policy updated', delete: 'Challenge policy deleted', enable: 'Challenge policy enabled', disable: 'Challenge policy disabled', conflict: 'The policy revision changed; the list was refreshed' },
  pagination: { page: 'Page {{page}}' },
  values: { empty: 'No challenge policies', ttl: '{{challenge}} / {{pass}} seconds', failures: '{{count}} per {{window}} seconds' },
  publication: {
    notPublished: 'Not published', progress: '{{healthy}} / {{total}} nodes healthy',
    superseded: '{{n}} ignored an old release',
    states: { queued: 'Queued', running: 'Applying on nodes', healthy: 'Secret ready', failed: 'Failed; previous config retained', active: 'Active' },
  },
  forbidden: { title: 'Challenge policies unavailable', description: 'This account lacks challenge policy read permission.' },
  uncertainty: { title: 'Operation result is unconfirmed', description: 'Writes are locked. Retry uses the exact same body, revision, and idempotency key; close and refresh to confirm the result instead.' },
  errors: { load: 'Failed to load challenge policies', invalid_response: 'The service response was invalid; refresh to confirm the result', permission_denied: 'This account lacks challenge policy permission', revision_conflict: 'The policy revision changed', idempotency_conflict: 'The idempotency key was used for another request', validation_error: 'The policy field combination is invalid', request_failed: 'The request failed; try again later', forbiddenRules: 'This account lacks CC rule read permission.' },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `[!! ${value} !!]`
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudo(item)]))
  return value
}

i18n.addResourceBundle('zh-CN', 'challengePolicies', zhCN, true, true)
i18n.addResourceBundle('en-US', 'challengePolicies', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'challengePolicies', pseudo(enUS), true, true)
i18n.addResourceBundle('qps-Ploc', 'challengePolicies', pseudo(enUS), true, true)

export { enUS as challengePoliciesEnUS, zhCN as challengePoliciesZhCN }
