import i18n from './index'

const zhCN = {
  title: '实名认证案件',
  details: {
    applicant: '申请人 ID', kind: '认证类型', status: '状态', reviewer: '审核人 ID',
    revision: '版本', submittedAt: '提交时间', expiresAt: '审核截止时间',
    retention: '证据保留状态', unassigned: '尚未分配',
  },
  kinds: {
    personal_initial: '个人首次认证', personal_reverification: '个人重新认证', enterprise: '企业认证',
  },
  states: {
    draft: '草稿', submitted: '待审核', reviewing: '审核中', approved: '已通过',
    rejected: '已拒绝', withdrawn: '已撤回', expired: '已过期',
  },
  relationships: {
    legal_person: '法定代表人', employee: '企业员工', authorized_representative: '授权代表',
  },
  retention: {
    case_not_terminal: '案件尚未结束', retention_period_active: '仍在法定保留期',
    eligible_for_evidence_erasure: '证据已可清理',
  },
  materialKinds: {
    identity_document: '身份材料', liveness_evidence: '活体证据', business_license: '营业执照',
    legal_person_identity: '法人身份材料', agent_identity: '经办人身份材料',
    authorization_letter: '授权书', supplementary: '补充材料',
  },
  materials: {
    title: '材料元数据', kind: '材料类型', mime: '文件类型', size: '大小', createdAt: '上传时间',
    custody: '托管状态', encrypted: '加密材料已托管', unavailable: '材料未托管', empty: '暂无材料元数据',
  },
  actions: {
    claim: '认领案件', confirmClaim: '确认认领', retry: '重试', refresh: '刷新',
    retrySameRequest: '使用同一请求重试', abandonRefresh: '放弃并刷新', decision: '进入审核决定',
  },
  confirmations: { claim: '确认认领该实名认证案件？' },
  uncertainty: {
    title: '操作结果待确认',
    description: '认领结果未知。只能使用完全相同的请求和幂等键重试，或放弃并刷新确认当前状态。',
  },
  forbidden: { title: '无权审核实名认证', description: '当前租户身份缺少实名认证读取或审核权限。' },
  notFound: { title: '实名认证案件不存在', description: '该案件不存在或不属于当前租户。' },
  invalidCase: { title: '实名认证案件不存在', description: '案件标识格式无效。' },
  loading: '正在加载实名认证案件',
  errors: {
    requestFailed: '实名认证请求失败，请稍后重试。', network_error: '网络连接失败，请稍后重试。',
    invalid_response: '服务响应无效，请刷新确认当前状态。', invalid_request: '请求参数无效。',
    identity_verification_invalid_request: '请求参数无效。',
    identity_verification_unauthenticated: '会话已失效，请重新登录。',
    identity_verification_permission_denied: '当前身份缺少实名认证审核权限。',
    identity_verification_not_found: '未找到该实名认证案件。',
    identity_verification_revision_conflict: '案件版本已变化，请刷新后重试。',
    identity_verification_idempotency_conflict: '幂等请求与原请求不一致，请刷新后重试。',
    identity_verification_active_review: '该案件已由其他审核人认领。',
    identity_verification_invalid_transition: '当前案件状态不允许认领。',
    identity_verification_self_review_forbidden: '不能审核本人提交的认证案件。',
    identity_verification_review_assignment_required: '请先认领该案件。',
    identity_verification_request_canceled: '请求已取消，请重试。',
    identity_verification_request_timeout: '请求超时，请确认当前状态。',
    identity_verification_response_too_large: '响应暂不可用，请稍后重试。',
    identity_verification_unavailable: '实名认证服务暂不可用，请稍后重试。',
  },
} as const

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const enUS: MessageShape<typeof zhCN> = {
  title: 'Identity verification case',
  details: {
    applicant: 'Applicant ID', kind: 'Verification type', status: 'Status', reviewer: 'Reviewer ID',
    revision: 'Revision', submittedAt: 'Submitted at', expiresAt: 'Review deadline',
    retention: 'Evidence retention', unassigned: 'Unassigned',
  },
  kinds: {
    personal_initial: 'Initial personal verification', personal_reverification: 'Personal reverification', enterprise: 'Enterprise verification',
  },
  states: {
    draft: 'Draft', submitted: 'Submitted', reviewing: 'In review', approved: 'Approved',
    rejected: 'Rejected', withdrawn: 'Withdrawn', expired: 'Expired',
  },
  relationships: {
    legal_person: 'Legal representative', employee: 'Employee', authorized_representative: 'Authorized representative',
  },
  retention: {
    case_not_terminal: 'Case is not terminal', retention_period_active: 'Retention period is active',
    eligible_for_evidence_erasure: 'Evidence is eligible for erasure',
  },
  materialKinds: {
    identity_document: 'Identity evidence', liveness_evidence: 'Liveness evidence', business_license: 'Business license',
    legal_person_identity: 'Legal representative evidence', agent_identity: 'Applicant evidence',
    authorization_letter: 'Authorization letter', supplementary: 'Supplementary evidence',
  },
  materials: {
    title: 'Material metadata', kind: 'Material type', mime: 'File type', size: 'Size', createdAt: 'Uploaded at',
    custody: 'Custody', encrypted: 'Encrypted material is held', unavailable: 'Material is not held', empty: 'No material metadata',
  },
  actions: {
    claim: 'Claim case', confirmClaim: 'Confirm claim', retry: 'Retry', refresh: 'Refresh',
    retrySameRequest: 'Retry the same request', abandonRefresh: 'Abandon and refresh', decision: 'Open review decision',
  },
  confirmations: { claim: 'Claim this identity verification case?' },
  uncertainty: {
    title: 'Operation outcome is unknown',
    description: 'The claim outcome is unknown. Retry only with the exact same request and idempotency key, or abandon it and refresh the current state.',
  },
  forbidden: { title: 'Identity review unavailable', description: 'This tenant account lacks identity verification read or review permission.' },
  notFound: { title: 'Identity verification case not found', description: 'The case does not exist or belongs to another tenant.' },
  invalidCase: { title: 'Identity verification case not found', description: 'The case identifier is invalid.' },
  loading: 'Loading identity verification case',
  errors: {
    requestFailed: 'The identity verification request failed. Try again later.', network_error: 'The network request failed. Try again later.',
    invalid_response: 'The service response was invalid. Refresh to confirm the current state.', invalid_request: 'The request is invalid.',
    identity_verification_invalid_request: 'The request is invalid.',
    identity_verification_unauthenticated: 'Your session has expired. Sign in again.',
    identity_verification_permission_denied: 'This account cannot review identity verification cases.',
    identity_verification_not_found: 'The identity verification case was not found.',
    identity_verification_revision_conflict: 'The case revision changed. Refresh and try again.',
    identity_verification_idempotency_conflict: 'The idempotent request differs from the original request. Refresh and try again.',
    identity_verification_active_review: 'Another reviewer has claimed this case.',
    identity_verification_invalid_transition: 'This case cannot be claimed in its current state.',
    identity_verification_self_review_forbidden: 'You cannot review your own verification case.',
    identity_verification_review_assignment_required: 'Claim this case before reviewing it.',
    identity_verification_request_canceled: 'The request was canceled. Try again.',
    identity_verification_request_timeout: 'The request timed out. Confirm the current state.',
    identity_verification_response_too_large: 'The response is unavailable. Try again later.',
    identity_verification_unavailable: 'The identity verification service is unavailable. Try again later.',
  },
}

export type IdentityVerificationReviewCaseMessages = { [key: string]: string | IdentityVerificationReviewCaseMessages }

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

const pseudoCN = pseudoTree(zhCN) as IdentityVerificationReviewCaseMessages

export const identityVerificationReviewCaseMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  IdentityVerificationReviewCaseMessages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(identityVerificationReviewCaseMessages)) {
  i18n.addResourceBundle(locale, 'identityVerificationReviewCase', messages, true, true)
}
