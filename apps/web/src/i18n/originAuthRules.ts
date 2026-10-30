import i18n from './index'

const zhCN = {
  title: '源站鉴权规则',
  description: '管理当前租户站点与源站位置绑定的对象存储签名规则。',
  readOnly: '只读模式',
  filters: { site: '站点 ID', provider: '存储提供商', enabled: '启用状态', all: '全部', query: '查询' },
  actions: {
    refresh: '刷新', create: '新建规则', detail: '查看详情', edit: '编辑', enable: '启用', disable: '停用',
    rotate: '轮换凭据', delete: '删除', confirmDelete: '确认删除', cancel: '取消', save: '保存',
    previous: '上一页', next: '下一页', exactRetry: '按原操作重试', abandon: '放弃重试', close: '关闭',
  },
  fields: {
    createSite: '新建站点 ID', sourcePosition: '源站位置', provider: '存储提供商', algorithm: '签名算法',
    endpoint: '端点', bucket: '存储桶', pathPrefix: '路径前缀', region: '区域', service: '服务',
    ttl: '签名有效期（秒）', credentialID: '凭据 ID', credentialRevision: '凭据版本', enabled: '创建后启用',
    activateAt: '切换时间', revision: '规则版本', updatedAt: '更新时间', actions: '操作', site: '站点 ID',
  },
  providers: { s3: 'S3', oss: 'OSS', cos: 'COS' },
  algorithms: { 'aws4-hmac-sha256': 'AWS4 HMAC SHA-256', 'oss4-hmac-sha256': 'OSS4 HMAC SHA-256', 'cos-hmac-sha1': 'COS HMAC SHA-1' },
  states: { enabled: '已启用', disabled: '已停用' },
  data: { loading: '正在加载源站鉴权规则', empty: '暂无源站鉴权规则', detailLoading: '正在加载规则详情' },
  pagination: { page: '第 {{page}} 页' },
  dialogs: {
    create: '新建源站鉴权规则', edit: '编辑源站鉴权规则', rotate: '轮换规则凭据', detail: '规则详情',
    deleteTitle: '删除此源站鉴权规则？', unknownTitle: '写入结果未知',
    unknownDescription: '连接在确认写入结果前中断。可使用原操作和原幂等键精确重试，或放弃并刷新列表确认。',
  },
  validation: { required: '请完整填写有效的规则字段', site: '请输入规范的小写站点 UUID', credential: '请输入规范的小写凭据 UUID' },
  notices: { saved: '规则已保存', deleted: '规则已删除', updated: '规则状态已更新' },
  errors: {
    forbiddenTitle: '无权查看源站鉴权规则', forbiddenDescription: '当前租户身份缺少源站鉴权读取权限。',
    requestFailed: '源站鉴权规则加载失败，请重试', invalidResponse: '源站鉴权服务返回了无效数据',
    notFound: '未找到当前租户内的源站鉴权规则', conflict: '规则与现有资源冲突，请刷新后重试',
    stale: '规则已被其他操作更新，请刷新后重试', validation: '规则字段未通过服务端校验',
    rateLimited: '操作过于频繁，请稍后重试', unavailable: '源站鉴权服务暂不可用，请稍后重试',
    network: '网络连接失败，写入结果可能未知', unknown: '写入结果未知',
  },
}

const enUS: typeof zhCN = {
  title: 'Origin authentication rules',
  description: 'Manage object-storage signing rules bound to tenant sites and origin positions.',
  readOnly: 'Read-only mode',
  filters: { site: 'Site ID', provider: 'Storage provider', enabled: 'Enabled state', all: 'All', query: 'Query' },
  actions: {
    refresh: 'Refresh', create: 'Create rule', detail: 'View detail', edit: 'Edit', enable: 'Enable', disable: 'Disable',
    rotate: 'Rotate credential', delete: 'Delete', confirmDelete: 'Confirm delete', cancel: 'Cancel', save: 'Save',
    previous: 'Previous page', next: 'Next page', exactRetry: 'Retry exact operation', abandon: 'Abandon retry', close: 'Close',
  },
  fields: {
    createSite: 'New site ID', sourcePosition: 'Origin position', provider: 'Storage provider', algorithm: 'Signing algorithm',
    endpoint: 'Endpoint', bucket: 'Bucket', pathPrefix: 'Path prefix', region: 'Region', service: 'Service',
    ttl: 'Signature TTL (seconds)', credentialID: 'Credential ID', credentialRevision: 'Credential revision', enabled: 'Enable after creation',
    activateAt: 'Activation time', revision: 'Rule revision', updatedAt: 'Updated at', actions: 'Actions', site: 'Site ID',
  },
  providers: { s3: 'S3', oss: 'OSS', cos: 'COS' },
  algorithms: { 'aws4-hmac-sha256': 'AWS4 HMAC SHA-256', 'oss4-hmac-sha256': 'OSS4 HMAC SHA-256', 'cos-hmac-sha1': 'COS HMAC SHA-1' },
  states: { enabled: 'Enabled', disabled: 'Disabled' },
  data: { loading: 'Loading origin authentication rules', empty: 'No origin authentication rules', detailLoading: 'Loading rule detail' },
  pagination: { page: 'Page {{page}}' },
  dialogs: {
    create: 'Create origin authentication rule', edit: 'Edit origin authentication rule', rotate: 'Rotate rule credential', detail: 'Rule detail',
    deleteTitle: 'Delete this origin authentication rule?', unknownTitle: 'Write result unknown',
    unknownDescription: 'The connection ended before the write result was confirmed. Retry the exact operation with its original idempotency key, or abandon it and refresh the list.',
  },
  validation: { required: 'Complete every required rule field with a valid value.', site: 'Enter a canonical lowercase site UUID.', credential: 'Enter a canonical lowercase credential UUID.' },
  notices: { saved: 'Rule saved', deleted: 'Rule deleted', updated: 'Rule state updated' },
  errors: {
    forbiddenTitle: 'No permission to view origin authentication rules', forbiddenDescription: 'The current tenant identity lacks origin authentication read permission.',
    requestFailed: 'Could not load origin authentication rules. Try again.', invalidResponse: 'The origin authentication service returned invalid data.',
    notFound: 'No origin authentication rule was found in this tenant.', conflict: 'The rule conflicts with an existing resource. Refresh and try again.',
    stale: 'The rule was updated by another operation. Refresh and try again.', validation: 'The rule fields failed server validation.',
    rateLimited: 'Too many operations. Try again later.', unavailable: 'The origin authentication service is temporarily unavailable. Try again later.',
    network: 'The network request failed and the write result may be unknown.', unknown: 'Write result unknown',
  },
}

type Messages = typeof zhCN

export function buildOriginAuthRulesPseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
      tokens.push(token)
      return `__TOKEN_${tokens.length - 1}__`
    })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
      .replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(
    ([key, child]) => [key, buildOriginAuthRulesPseudo(child)],
  ))
}

const pseudoCN = buildOriginAuthRulesPseudo(zhCN) as Messages

export const originAuthRulesMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(originAuthRulesMessages)) {
  i18n.addResourceBundle(locale, 'originAuthRules', messages, true, true)
}
