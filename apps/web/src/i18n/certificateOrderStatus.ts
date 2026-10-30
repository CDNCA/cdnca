import i18n from './index'

const zhCN = {
  title: '证书订单与续期状态',
  summary: { count: '共 {{count}} 个订单' },
  filters: {
    domain: '域名', domainPlaceholder: '筛选订单域名', status: '状态', allStatuses: '全部状态',
  },
  columns: {
    domains: '域名', challenge: '验证方式', status: '状态', autoRenew: '自动续期',
    renewal: '订单类型', notAfter: '证书到期时间', issuedAt: '签发时间', version: '版本',
    updatedAt: '更新时间', failure: '失败原因',
  },
  challenges: { http_01: 'HTTP-01', dns_01: 'DNS-01' },
  states: {
    pending: '等待处理', validating: '验证中', issuing: '签发中', issued: '已签发',
    deploying: '部署中', active: '已生效', renewal_due: '待续期', failed: '失败', revoked: '已吊销',
  },
  values: {
    enabled: '已开启', disabled: '已关闭', firstIssue: '首次签发', renewalOrder: '续期订单',
    pending: '暂无', none: '无',
  },
  data: {
    loading: '正在加载证书订单', empty: '暂无证书订单', filteredEmpty: '暂无符合条件的证书订单',
  },
  errors: {
    forbiddenTitle: '无权查看证书订单', forbiddenDescription: '当前账户缺少证书读取权限。',
    authenticationRequired: '登录状态已失效，请重新登录。', notFound: '证书订单接口不存在。',
    conflict: '证书订单状态发生冲突，请刷新后重试。',
    preconditionFailed: '证书订单前置条件已变化，请刷新后重试。',
    rateLimited: '请求过于频繁，请稍后重试。', serviceUnavailable: '证书签发服务暂不可用，请稍后重试。',
    networkError: '无法连接证书签发服务，请稍后重试。', invalidResponse: '服务返回了无效的证书订单数据。',
    requestFailed: '证书订单加载失败，请稍后重试。',
  },
} as const

const enUS = {
  title: 'Certificate orders and renewal status',
  summary: { count: '{{count}} orders' },
  filters: {
    domain: 'Domain', domainPlaceholder: 'Filter order domains', status: 'Status', allStatuses: 'All statuses',
  },
  columns: {
    domains: 'Domains', challenge: 'Challenge', status: 'Status', autoRenew: 'Automatic renewal',
    renewal: 'Order type', notAfter: 'Certificate expiry', issuedAt: 'Issued at', version: 'Version',
    updatedAt: 'Updated at', failure: 'Failure',
  },
  challenges: { http_01: 'HTTP-01', dns_01: 'DNS-01' },
  states: {
    pending: 'Pending', validating: 'Validating', issuing: 'Issuing', issued: 'Issued',
    deploying: 'Deploying', active: 'Active', renewal_due: 'Renewal due', failed: 'Failed', revoked: 'Revoked',
  },
  values: {
    enabled: 'Enabled', disabled: 'Disabled', firstIssue: 'Initial issue', renewalOrder: 'Renewal order',
    pending: 'Pending', none: 'None',
  },
  data: {
    loading: 'Loading certificate orders', empty: 'No certificate orders', filteredEmpty: 'No certificate orders match the filters',
  },
  errors: {
    forbiddenTitle: 'You cannot view certificate orders', forbiddenDescription: 'Your account does not have certificate read permission.',
    authenticationRequired: 'Your session has expired. Sign in again.', notFound: 'The certificate order endpoint is unavailable.',
    conflict: 'The certificate order state changed. Refresh and try again.',
    preconditionFailed: 'The certificate order precondition changed. Refresh and try again.',
    rateLimited: 'Too many requests. Try again later.', serviceUnavailable: 'Certificate issuance is unavailable. Try again later.',
    networkError: 'Certificate issuance cannot be reached. Try again later.', invalidResponse: 'The service returned invalid certificate order data.',
    requestFailed: 'Certificate orders could not be loaded. Try again later.',
  },
} as const

type Messages = { [key: string]: string | Messages }

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')
  )).join('')}］`
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return pseudoText(value)
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(
    ([key, child]) => [key, pseudoTree(child)],
  ))
}

const pseudo = pseudoTree(zhCN) as Messages

export const certificateOrderStatusMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  Messages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(certificateOrderStatusMessages)) {
  i18n.addResourceBundle(locale, 'certificateOrderStatus', messages, true, true)
}
