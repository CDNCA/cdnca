import i18n from './index'

const zhCN = {
  title: '实名认证审批',
  introduction: '审批仅记录稳定决定和原因码，不接受自由文本或敏感身份材料。',
  details: {
    title: '实名认证审批状态', id: '案件 ID', applicant: '申请人 ID', kind: '认证类型',
    status: '状态', revision: '版本', changedAt: '状态更新时间', materialCount: '证据材料数量',
  },
  kinds: { personal_initial: '个人首次认证', personal_reverification: '个人重新认证', enterprise: '企业认证' },
  states: {
    draft: '草稿', submitted: '待审核', reviewing: '审核中', approved: '已通过',
    rejected: '已拒绝', withdrawn: '已撤回', expired: '已过期',
  },
  decision: { title: '审批决定', reason: '审批原因' },
  decisions: { approved: '通过', rejected: '拒绝' },
  reasons: {
    evidence_verified: '证据已核验', identity_mismatch: '身份信息不匹配', evidence_incomplete: '证据不完整',
    evidence_unreadable: '证据无法读取', organization_mismatch: '企业信息不匹配',
    authorization_invalid: '授权材料无效', suspected_fraud: '疑似欺诈',
  },
  actions: {
    refresh: '刷新案件', retry: '重试', submit: '提交审批决定', confirmSubmit: '确认提交',
    retrySameRequest: '使用同一请求重试', abandonRefresh: '放弃并刷新', back: '返回案件详情',
  },
  confirmations: { submit: '确认提交该实名认证审批决定？提交后不可在此页面撤销。' },
  notices: { succeeded: '实名认证审批决定已提交。' },
  uncertainty: {
    title: '审批结果待确认',
    description: '写入结果未知。只能使用完全相同的决定、原因码和幂等键重试，或放弃并刷新确认当前状态。',
  },
  forbidden: { title: '无权审批实名认证', description: '当前租户身份必须同时具备实名认证读取和审批权限。' },
  notFound: { title: '未找到实名认证案件' },
  errors: {
    loadFailed: '实名认证案件加载失败', requestFailed: '实名认证审批请求失败，请稍后重试。',
    network_error: '网络连接失败，请稍后重试。', invalid_response: '服务响应无效，请刷新确认当前状态。',
    invalid_request: '请求参数无效，请检查输入。', identity_verification_invalid_request: '请求参数无效，请检查输入。',
    identity_verification_unauthenticated: '会话已失效，请重新登录。',
    identity_verification_permission_denied: '当前身份缺少实名认证审批权限。',
    identity_verification_not_found: '未找到实名认证案件。',
    identity_verification_revision_conflict: '案件版本已变化，请刷新后重新审批。',
    identity_verification_idempotency_conflict: '幂等请求与原请求不一致，请刷新后重试。',
    identity_verification_invalid_transition: '当前案件状态不允许提交审批决定。',
    identity_verification_review_assignment_mismatch: '该案件未分配给当前审批人。',
    identity_verification_request_canceled: '请求已取消，请重试。',
    identity_verification_request_timeout: '请求超时，请确认当前审批状态。',
    identity_verification_response_too_large: '响应暂不可用，请稍后重试。',
    identity_verification_unavailable: '实名认证服务暂不可用，请稍后重试。',
  },
} as const

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const enUS: MessageShape<typeof zhCN> = {
  title: 'Identity verification decision',
  introduction: 'Reviews record only stable decisions and reason codes. Free text and sensitive identity material are not accepted.',
  details: {
    title: 'Identity review status', id: 'Case ID', applicant: 'Applicant ID', kind: 'Verification type',
    status: 'Status', revision: 'Revision', changedAt: 'State updated at', materialCount: 'Evidence materials',
  },
  kinds: { personal_initial: 'Initial personal verification', personal_reverification: 'Personal reverification', enterprise: 'Enterprise verification' },
  states: {
    draft: 'Draft', submitted: 'Submitted', reviewing: 'In review', approved: 'Approved',
    rejected: 'Rejected', withdrawn: 'Withdrawn', expired: 'Expired',
  },
  decision: { title: 'Decision', reason: 'Reason' },
  decisions: { approved: 'Approve', rejected: 'Reject' },
  reasons: {
    evidence_verified: 'Evidence verified', identity_mismatch: 'Identity mismatch', evidence_incomplete: 'Evidence incomplete',
    evidence_unreadable: 'Evidence unreadable', organization_mismatch: 'Organization mismatch',
    authorization_invalid: 'Authorization invalid', suspected_fraud: 'Suspected fraud',
  },
  actions: {
    refresh: 'Refresh case', retry: 'Retry', submit: 'Submit decision', confirmSubmit: 'Confirm submission',
    retrySameRequest: 'Retry the same request', abandonRefresh: 'Abandon and refresh', back: 'Back to case details',
  },
  confirmations: { submit: 'Submit this identity verification decision? It cannot be undone on this page.' },
  notices: { succeeded: 'The identity verification decision was submitted.' },
  uncertainty: {
    title: 'Decision outcome is unknown',
    description: 'Retry only with the exact same decision, reason code, and idempotency key, or abandon it and refresh the current state.',
  },
  forbidden: { title: 'Identity review unavailable', description: 'This tenant account must have both identity verification read and review permissions.' },
  notFound: { title: 'Identity verification case not found' },
  errors: {
    loadFailed: 'Failed to load the identity verification case', requestFailed: 'The identity review request failed. Try again later.',
    network_error: 'The network request failed. Try again later.', invalid_response: 'The service response was invalid. Refresh to confirm the current state.',
    invalid_request: 'The request is invalid. Check the input.', identity_verification_invalid_request: 'The request is invalid. Check the input.',
    identity_verification_unauthenticated: 'Your session expired. Sign in again.',
    identity_verification_permission_denied: 'This account cannot review identity verification cases.',
    identity_verification_not_found: 'The identity verification case was not found.',
    identity_verification_revision_conflict: 'The case revision changed. Refresh before reviewing again.',
    identity_verification_idempotency_conflict: 'The idempotent request differs from the original request. Refresh and try again.',
    identity_verification_invalid_transition: 'The current case state does not allow a review decision.',
    identity_verification_review_assignment_mismatch: 'This case is not assigned to the current reviewer.',
    identity_verification_request_canceled: 'The request was canceled. Try again.',
    identity_verification_request_timeout: 'The request timed out. Confirm the current review state.',
    identity_verification_response_too_large: 'The response is unavailable. Try again later.',
    identity_verification_unavailable: 'The identity verification service is unavailable. Try again later.',
  },
}

export type IdentityVerificationReviewDecisionMessages = {
  [key: string]: string | IdentityVerificationReviewDecisionMessages
}

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{')
      ? part
      : [...part].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')
  )).join('')}］`
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as IdentityVerificationReviewDecisionMessages

export const identityVerificationReviewDecisionMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  IdentityVerificationReviewDecisionMessages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(identityVerificationReviewDecisionMessages)) {
  i18n.addResourceBundle(locale, 'identityVerificationReviewDecision', messages, true, true)
}
