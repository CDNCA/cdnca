import i18n from './index'

const zhCN = {
  title: '实名认证审核',
  description: '查看当前租户的实名认证审核队列，并进入案件详情处理。',
  actions: {
    refresh: '刷新',
    retry: '重试',
    previous: '上一页',
    next: '下一页',
  },
  filters: {
    kindLabel: '认证类型',
    kindPlaceholder: '全部认证类型',
    statusLabel: '案件状态',
    statusPlaceholder: '全部案件状态',
    limitLabel: '每页数量',
  },
  columns: {
    id: '案件 ID',
    applicant: '申请人 ID',
    kind: '认证类型',
    status: '案件状态',
    reviewer: '审核人 ID',
    revision: '版本',
    changedAt: '状态更新时间',
  },
  kinds: {
    personal_initial: '个人首次认证',
    personal_reverification: '个人重新认证',
    enterprise: '企业认证',
  },
  states: {
    draft: '草稿',
    submitted: '待审核',
    reviewing: '审核中',
    approved: '已通过',
    rejected: '已拒绝',
    withdrawn: '已撤回',
    expired: '已过期',
  },
  values: { unassigned: '未分配' },
  pagination: { page: '第 {{page}} 页' },
  data: {
    loading: '正在加载实名认证审核队列',
    empty: '暂无待处理的实名认证案件',
  },
  errors: {
    forbiddenTitle: '无权审核实名认证',
    forbiddenDescription: '当前身份必须同时具备实名认证读取和审核权限。',
    requestFailed: '实名认证审核队列加载失败，请重试',
    identity_verification_unavailable: '实名认证审核服务暂不可用，请稍后重试',
    identity_verification_request_timeout: '实名认证审核请求超时，请重试',
    identity_verification_request_canceled: '实名认证审核请求已取消，请重试',
    identity_verification_invalid_request: '实名认证审核筛选无效，请重置后重试',
    unauthorized: '会话已失效，请重新登录',
  },
}

const enUS: typeof zhCN = {
  title: 'Identity verification review',
  description: 'View the current tenant identity verification queue and open a case for review.',
  actions: {
    refresh: 'Refresh',
    retry: 'Retry',
    previous: 'Previous page',
    next: 'Next page',
  },
  filters: {
    kindLabel: 'Verification type',
    kindPlaceholder: 'All verification types',
    statusLabel: 'Case status',
    statusPlaceholder: 'All case statuses',
    limitLabel: 'Rows per page',
  },
  columns: {
    id: 'Case ID',
    applicant: 'Applicant ID',
    kind: 'Verification type',
    status: 'Case status',
    reviewer: 'Reviewer ID',
    revision: 'Revision',
    changedAt: 'State updated at',
  },
  kinds: {
    personal_initial: 'Initial personal verification',
    personal_reverification: 'Personal reverification',
    enterprise: 'Enterprise verification',
  },
  states: {
    draft: 'Draft',
    submitted: 'Submitted',
    reviewing: 'In review',
    approved: 'Approved',
    rejected: 'Rejected',
    withdrawn: 'Withdrawn',
    expired: 'Expired',
  },
  values: { unassigned: 'Unassigned' },
  pagination: { page: 'Page {{page}}' },
  data: {
    loading: 'Loading identity verification review queue',
    empty: 'No identity verification cases to review',
  },
  errors: {
    forbiddenTitle: 'No permission to review identity verification',
    forbiddenDescription: 'The current identity needs both identity verification read and review permissions.',
    requestFailed: 'Could not load the identity verification review queue. Try again.',
    identity_verification_unavailable: 'Identity verification review is temporarily unavailable. Try again later.',
    identity_verification_request_timeout: 'The identity verification review request timed out. Try again.',
    identity_verification_request_canceled: 'The identity verification review request was canceled. Try again.',
    identity_verification_invalid_request: 'The identity verification review filter is invalid. Reset it and try again.',
    unauthorized: 'Your session has expired. Sign in again.',
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
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as Messages

export const identityVerificationReviewQueueMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  Messages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(identityVerificationReviewQueueMessages)) {
  i18n.addResourceBundle(locale, 'identityVerificationReviewQueue', messages, true, true)
}
