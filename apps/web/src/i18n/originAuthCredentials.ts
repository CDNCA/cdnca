import i18n from './index'

const zhCN = {
  title: '源站鉴权凭据',
  description: '管理当前租户的 S3、OSS 与 COS 源站访问凭据。密钥仅用于当前请求，不会回显或保存到浏览器。',
  actions: {
    refresh: '刷新', retry: '重试', exactRetry: '精确重试', abandon: '放弃并刷新',
    previous: '上一页', next: '下一页', create: '新增凭据', detail: '查看详情',
    replace: '替换密钥', verify: '验证', disable: '停用', delete: '删除',
    submit: '提交', cancel: '取消', confirm: '确认',
  },
  filters: { provider: '服务商筛选', status: '状态', allProviders: '全部服务商', allStatuses: '全部状态' },
  fields: {
    provider: '服务商', name: '凭据名称', accessKey: 'Access Key ID', secretKey: 'Secret Access Key',
    sessionToken: 'Session Token（可选）', notBefore: '生效时间', expiresAt: '到期时间',
    timestampPlaceholder: '例如 2026-08-07T08:00:00Z',
  },
  providers: { s3: 'S3 / S3 兼容', oss: '阿里云 OSS', cos: '腾讯云 COS' },
  statuses: { pending: '待验证', verified: '已验证', disabled: '已停用', deleted: '已删除' },
  columns: {
    name: '名称', provider: '服务商', status: '状态', revision: '版本',
    notBefore: '生效时间', expiresAt: '到期时间', updatedAt: '更新时间', actions: '操作',
    id: '凭据 ID', scope: '租户作用域', revisionRef: '版本引用', verifiedAt: '验证时间',
  },
  pagination: { page: '第 {{page}} 页' },
  data: { loading: '正在加载源站鉴权凭据', empty: '暂无源站鉴权凭据', detailLoading: '正在加载凭据详情' },
  dialogs: {
    createTitle: '新增源站鉴权凭据', replaceTitle: '替换凭据密钥',
    disableTitle: '确认停用凭据', disableDescription: '停用后，引用该凭据的启用规则可能无法继续工作。',
    deleteTitle: '确认删除凭据', deleteDescription: '正在被启用规则引用的凭据无法删除。',
    verifyTitle: '确认验证凭据', verifyDescription: '系统将调用真实服务商验证器检查当前凭据。',
  },
  write: {
    pending: '正在提交凭据变更', succeeded: '凭据变更已完成', unknownTitle: '写入结果未知',
    unknownDescription: '请求结果无法确认。精确重试会复用同一请求内容、修订与幂等键；放弃会清除敏感请求并刷新列表和当前详情。',
  },
  validation: {
    required: '此字段不能为空', name: '请输入 1 至 128 个字符的凭据名称',
    accessKey: '请输入有效的 Access Key ID', secretKey: '请输入有效的 Secret Access Key',
    timestamp: '请输入 RFC 3339 时间，例如 2026-08-07T08:00:00Z', interval: '到期时间必须晚于生效时间',
  },
  values: { none: '无' },
  errors: {
    forbiddenTitle: '无权查看源站鉴权凭据', forbiddenDescription: '当前租户身份缺少 origin_auth.read 权限或作用域不匹配。',
    manageForbidden: '当前身份缺少 origin_auth.manage 权限。', requestFailed: '源站鉴权凭据加载失败，请重试',
    invalidResponse: '源站鉴权服务返回了无效数据', notFound: '未找到当前租户中的凭据',
    conflict: '凭据状态冲突或正在被启用规则引用', revisionConflict: '凭据已被其他操作更新，请刷新后重试',
    validation: '凭据内容无效，请检查后重试', rateLimited: '操作过于频繁，请稍后重试',
    unavailable: '源站鉴权服务暂不可用，请稍后重试', network: '网络连接失败，请重试',
  },
}

const enUS: typeof zhCN = {
  title: 'Origin authentication credentials',
  description: 'Manage S3, OSS, and COS origin credentials for the current tenant. Secrets exist only for the current request and are never replayed or stored by the browser.',
  actions: {
    refresh: 'Refresh', retry: 'Retry', exactRetry: 'Retry exactly', abandon: 'Abandon and refresh',
    previous: 'Previous page', next: 'Next page', create: 'Add credential', detail: 'View detail',
    replace: 'Replace secret', verify: 'Verify', disable: 'Disable', delete: 'Delete',
    submit: 'Submit', cancel: 'Cancel', confirm: 'Confirm',
  },
  filters: { provider: 'Provider filter', status: 'Status', allProviders: 'All providers', allStatuses: 'All statuses' },
  fields: {
    provider: 'Provider', name: 'Credential name', accessKey: 'Access Key ID', secretKey: 'Secret Access Key',
    sessionToken: 'Session Token (optional)', notBefore: 'Not before', expiresAt: 'Expires at',
    timestampPlaceholder: 'e.g. 2026-08-07T08:00:00Z',
  },
  providers: { s3: 'S3 / S3-compatible', oss: 'Alibaba Cloud OSS', cos: 'Tencent Cloud COS' },
  statuses: { pending: 'Pending verification', verified: 'Verified', disabled: 'Disabled', deleted: 'Deleted' },
  columns: {
    name: 'Name', provider: 'Provider', status: 'Status', revision: 'Revision',
    notBefore: 'Not before', expiresAt: 'Expires at', updatedAt: 'Updated at', actions: 'Actions',
    id: 'Credential ID', scope: 'Tenant scope', revisionRef: 'Revision reference', verifiedAt: 'Verified at',
  },
  pagination: { page: 'Page {{page}}' },
  data: { loading: 'Loading origin authentication credentials', empty: 'No origin authentication credentials', detailLoading: 'Loading credential detail' },
  dialogs: {
    createTitle: 'Add origin authentication credential', replaceTitle: 'Replace credential secret',
    disableTitle: 'Disable credential?', disableDescription: 'Enabled rules that reference this credential may stop working.',
    deleteTitle: 'Delete credential?', deleteDescription: 'A credential referenced by an enabled rule cannot be deleted.',
    verifyTitle: 'Verify credential?', verifyDescription: 'The real provider verifier will check the current credential.',
  },
  write: {
    pending: 'Submitting credential change', succeeded: 'Credential change completed', unknownTitle: 'Write result is unknown',
    unknownDescription: 'The result could not be confirmed. Exact retry reuses the same request body, revision, and idempotency key; abandoning clears sensitive input and refreshes the list and selected detail.',
  },
  validation: {
    required: 'This field is required', name: 'Enter a credential name between 1 and 128 characters',
    accessKey: 'Enter a valid Access Key ID', secretKey: 'Enter a valid Secret Access Key',
    timestamp: 'Enter an RFC 3339 timestamp, for example 2026-08-07T08:00:00Z', interval: 'Expiry must be later than the start time',
  },
  values: { none: 'None' },
  errors: {
    forbiddenTitle: 'No permission to view origin authentication credentials', forbiddenDescription: 'The current tenant identity lacks origin_auth.read or does not match the tenant scope.',
    manageForbidden: 'The current identity lacks origin_auth.manage.', requestFailed: 'Could not load origin authentication credentials. Try again.',
    invalidResponse: 'The origin authentication service returned invalid data.', notFound: 'The credential was not found in this tenant.',
    conflict: 'The credential state conflicts or an enabled rule still references it.', revisionConflict: 'The credential was updated elsewhere. Refresh and try again.',
    validation: 'The credential input is invalid. Check it and try again.', rateLimited: 'Too many operations. Try again later.',
    unavailable: 'The origin authentication service is temporarily unavailable. Try again later.', network: 'The network request failed. Try again.',
  },
}

type Messages = typeof zhCN

function pseudoText(value: string): string {
  const tokens: string[] = []
  const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
    tokens.push(token)
    return `__TOKEN_${tokens.length - 1}__`
  })
  return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
    .replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string' ? pseudoText(value) : Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]),
  )
}

const pseudoCN = pseudoTree(zhCN) as Messages

export const originAuthCredentialsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(originAuthCredentialsMessages)) {
  i18n.addResourceBundle(locale, 'originAuthCredentials', messages, true, true)
}
