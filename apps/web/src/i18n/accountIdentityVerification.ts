import i18n from './index'

const zhCN = {
  title: '实名认证',
  introduction: '创建认证草稿需要由可信服务签发的一次性证据令牌；页面只展示脱敏案件状态。',
  lookup: { title: '查询本人案件', caseId: '案件 ID', placeholder: '输入案件 UUID' },
  create: { title: '创建认证草稿', kind: '认证类型', evidenceToken: '可信证据令牌', evidencePlaceholder: '输入可信服务签发的令牌' },
  provider: {
    title: '认证服务与私有材料', kind: '服务认证类型', provider: '认证服务', start: '启动认证服务',
    pending: '认证服务结果待确认', retrySameRequest: '使用同一服务请求重试', succeeded: '认证服务已完成',
    createDraft: '使用服务结果创建草稿', waiting: '等待认证服务处理', failed: '认证服务未完成，请重新发起。',
    states: {
      creating: '正在创建认证服务请求', pending: '等待认证服务处理', processing: '认证服务正在处理',
      succeeded: '认证服务已完成', failed: '认证服务处理失败', canceled: '认证服务请求已取消',
      expired: '认证服务请求已过期', unknown: '认证服务结果待确认',
    },
  },
  upload: {
    kind: '私有材料类型', file: '选择私有材料', submit: '上传并校验材料', finalized: '私有材料已校验并完成托管',
    states: {
      issued: '私有材料上传已签发', finalized: '私有材料已校验并完成托管',
      erase_pending: '私有材料等待清理', erased: '私有材料已清理',
    },
  },
  empty: { description: '尚未选择实名认证案件' },
  details: {
    title: '实名认证案件状态', id: '案件 ID', kind: '认证类型', status: '状态', revision: '版本',
    createdAt: '创建时间', changedAt: '状态更新时间', expiresAt: '审核截止时间',
    decisionReason: '审核原因', retention: '证据保留状态', materialCount: '证据材料数量', relationship: '企业申请人关系',
  },
  kinds: { personal_initial: '个人首次认证', personal_reverification: '个人重新认证', enterprise: '企业认证' },
  guidance: {
    personal_initial: '首次认证建立后续重新认证的一致性基线；页面不显示身份内容。',
    personal_reverification: '服务端会将本次可信身份与首次已通过身份进行一致性校验；页面不显示身份内容。',
    enterprise: '企业认证仅显示材料类型与加密托管状态；企业名称和证件内容不会返回页面。',
  },
  states: {
    draft: '草稿', submitted: '待审核', reviewing: '审核中', approved: '已通过',
    rejected: '已拒绝', withdrawn: '已撤回', expired: '已过期',
  },
  decisionReasons: {
    evidence_verified: '可信材料已核验通过', identity_mismatch: '身份信息与可信材料不一致',
    evidence_incomplete: '可信材料不完整', evidence_unreadable: '可信材料无法识别',
    organization_mismatch: '企业信息与可信材料不一致', authorization_invalid: '企业授权材料无效',
    suspected_fraud: '申请存在风险，需联系人工支持',
  },
  relationships: { legal_person: '法定代表人', employee: '企业员工', authorized_representative: '授权代表' },
  retention: {
    case_not_terminal: '案件尚未结束', retention_period_active: '仍在法定保留期',
    eligible_for_evidence_erasure: '证据已可清理',
  },
  materials: {
    identity_document: '身份材料', liveness_evidence: '活体证据', business_license: '营业执照',
    legal_person_identity: '法人身份材料', agent_identity: '经办人身份材料',
    authorization_letter: '授权书', supplementary: '补充材料',
  },
  materialSummary: {
    title: '脱敏证据摘要', kind: '材料类型', mime: '格式', size: '大小', custody: '托管状态',
    createdAt: '提交时间', custodyEncrypted: '加密材料已托管', custodyUnavailable: '加密材料不可用',
    empty: '当前案件没有可展示的材料元数据',
  },
  actions: {
    lookup: '查询案件', refresh: '刷新案件', create: '创建认证草稿', submit: '提交审核',
    withdraw: '撤回申请', expire: '标记过期', retry: '重试', retrySameRequest: '使用同一请求重试',
    abandonRefresh: '放弃并刷新', confirmSubmit: '确认提交', confirmWithdraw: '确认撤回',
    confirmExpire: '确认标记过期',
  },
  confirmations: {
    submit: '确认提交该实名认证申请？', withdraw: '确认撤回该实名认证申请？',
    expire: '确认将已到截止时间的申请标记为过期？',
  },
  notices: { writeSucceeded: '实名认证状态已更新。' },
  uncertainty: {
    title: '操作结果待确认',
    description: '写入结果未知。只能使用完全相同的请求和幂等键重试，或放弃并刷新确认当前状态。',
  },
  validation: {
    caseIdRequired: '请输入案件 ID', caseIdFormat: '案件 ID 必须是规范 UUID',
    evidenceRequired: '请输入可信证据令牌', evidenceFormat: '证据令牌格式无效',
    providerRequired: '请输入认证服务标识', providerFormat: '认证服务标识格式无效',
  },
  forbidden: { title: '无权管理实名认证', description: '当前身份缺少本人实名认证管理权限。' },
  unauthorized: { title: '会话已失效', description: '请重新登录后管理实名认证。' },
  errors: {
    loadFailed: '实名认证案件加载失败', requestFailed: '实名认证请求失败，请稍后重试。',
    rateLimited: '操作过于频繁，请稍后重试。',
    network_error: '网络连接失败，请稍后重试。', invalid_response: '服务响应无效，请刷新确认当前状态。',
    invalid_request: '请求参数无效，请检查输入。', identity_verification_invalid_request: '请求参数无效，请检查输入。',
    identity_verification_unauthenticated: '会话已失效，请重新登录。',
    identity_verification_permission_denied: '当前身份缺少本人实名认证管理权限。',
    identity_verification_not_found: '未找到该实名认证案件。',
    identity_verification_revision_conflict: '案件版本已变化，请刷新后重试。',
    identity_verification_idempotency_conflict: '幂等请求与原请求不一致，请刷新后重试。',
    identity_verification_active_review: '当前已有进行中的认证审核。',
    identity_verification_invalid_transition: '当前案件状态不允许该操作。',
    identity_verification_initial_approval_required: '请先完成个人首次认证。',
    identity_verification_identity_mismatch: '可信身份信息与已认证信息不一致。',
    identity_verification_already_verified: '该身份已完成认证。',
    identity_verification_case_expired: '该认证案件已过期。',
    identity_verification_case_not_expired: '该认证案件尚未到截止时间。',
    identity_verification_evidence_settlement_pending: '可信证据仍在处理中，请稍后重试。',
    identity_verification_evidence_invalid: '可信证据无效，请重新获取。',
    identity_verification_trusted_resolver_required: '可信证据服务尚未配置。',
    identity_verification_evidence_unavailable: '可信证据服务暂不可用。',
    identity_verification_request_canceled: '请求已取消，请重试。',
    identity_verification_request_timeout: '请求超时，请确认当前状态。',
    identity_verification_response_too_large: '响应暂不可用，请稍后重试。',
    identity_verification_unavailable: '实名认证服务暂不可用，请稍后重试。',
    identity_verification_provider_result_unknown: '认证服务结果未知，请使用同一请求重试或放弃。',
  },
} as const

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const enUS: MessageShape<typeof zhCN> = {
  title: 'Identity verification',
  introduction: 'Creating a draft requires a one-time evidence handle issued by a trusted service. Only sanitized case state is displayed.',
  lookup: { title: 'Find my case', caseId: 'Case ID', placeholder: 'Enter a case UUID' },
  create: { title: 'Create verification draft', kind: 'Verification type', evidenceToken: 'Trusted evidence handle', evidencePlaceholder: 'Enter the handle issued by the trusted service' },
  provider: {
    title: 'Verification service and private material', kind: 'Service verification type', provider: 'Verification service', start: 'Start verification service',
    pending: 'Verification service outcome is unknown', retrySameRequest: 'Retry the same service request', succeeded: 'Verification service completed',
    createDraft: 'Create a draft from the service result', waiting: 'Waiting for verification service', failed: 'Verification service did not complete. Start again.',
    states: {
      creating: 'Creating the verification service request', pending: 'Waiting for verification service', processing: 'Verification service is processing',
      succeeded: 'Verification service completed', failed: 'Verification service failed', canceled: 'Verification service request canceled',
      expired: 'Verification service request expired', unknown: 'Verification service outcome is unknown',
    },
  },
  upload: {
    kind: 'Private material type', file: 'Select private material', submit: 'Upload and verify material', finalized: 'Private material verified and placed in custody',
    states: {
      issued: 'Private material upload issued', finalized: 'Private material verified and placed in custody',
      erase_pending: 'Private material is awaiting erasure', erased: 'Private material was erased',
    },
  },
  empty: { description: 'No identity verification case selected' },
  details: {
    title: 'Identity verification case status', id: 'Case ID', kind: 'Verification type', status: 'Status', revision: 'Revision',
    createdAt: 'Created at', changedAt: 'State updated at', expiresAt: 'Review deadline',
    decisionReason: 'Review reason', retention: 'Evidence retention', materialCount: 'Evidence materials', relationship: 'Enterprise applicant relationship',
  },
  kinds: { personal_initial: 'Initial personal verification', personal_reverification: 'Personal reverification', enterprise: 'Enterprise verification' },
  guidance: {
    personal_initial: 'Initial verification establishes the consistency baseline for later reverification. Identity content is not displayed.',
    personal_reverification: 'The service checks this trusted identity against the initially approved identity. Identity content is not displayed.',
    enterprise: 'Enterprise verification shows only material types and encrypted custody state. Organization and document contents are not returned.',
  },
  states: {
    draft: 'Draft', submitted: 'Submitted', reviewing: 'In review', approved: 'Approved',
    rejected: 'Rejected', withdrawn: 'Withdrawn', expired: 'Expired',
  },
  decisionReasons: {
    evidence_verified: 'Trusted evidence was verified', identity_mismatch: 'Identity information does not match trusted evidence',
    evidence_incomplete: 'Trusted evidence is incomplete', evidence_unreadable: 'Trusted evidence cannot be read',
    organization_mismatch: 'Organization information does not match trusted evidence', authorization_invalid: 'Organization authorization is invalid',
    suspected_fraud: 'The application requires manual support review',
  },
  relationships: { legal_person: 'Legal representative', employee: 'Employee', authorized_representative: 'Authorized representative' },
  retention: {
    case_not_terminal: 'Case is not terminal', retention_period_active: 'Retention period is active',
    eligible_for_evidence_erasure: 'Evidence is eligible for erasure',
  },
  materials: {
    identity_document: 'Identity evidence', liveness_evidence: 'Liveness evidence', business_license: 'Business license',
    legal_person_identity: 'Legal representative evidence', agent_identity: 'Applicant evidence',
    authorization_letter: 'Authorization letter', supplementary: 'Supplementary evidence',
  },
  materialSummary: {
    title: 'Sanitized evidence summary', kind: 'Material type', mime: 'Format', size: 'Size', custody: 'Custody state',
    createdAt: 'Submitted at', custodyEncrypted: 'Encrypted evidence is in custody', custodyUnavailable: 'Encrypted evidence is unavailable',
    empty: 'This case has no displayable material metadata',
  },
  actions: {
    lookup: 'Find case', refresh: 'Refresh case', create: 'Create verification draft', submit: 'Submit for review',
    withdraw: 'Withdraw application', expire: 'Mark expired', retry: 'Retry', retrySameRequest: 'Retry the same request',
    abandonRefresh: 'Abandon and refresh', confirmSubmit: 'Confirm submission', confirmWithdraw: 'Confirm withdrawal',
    confirmExpire: 'Confirm expiration',
  },
  confirmations: {
    submit: 'Submit this identity verification application?', withdraw: 'Withdraw this identity verification application?',
    expire: 'Mark this application as expired after its deadline?',
  },
  notices: { writeSucceeded: 'Identity verification state was updated.' },
  uncertainty: {
    title: 'Operation outcome is unknown',
    description: 'Retry only with the exact same request and idempotency key, or abandon it and refresh the current state.',
  },
  validation: {
    caseIdRequired: 'Enter a case ID', caseIdFormat: 'The case ID must be a canonical UUID',
    evidenceRequired: 'Enter a trusted evidence handle', evidenceFormat: 'The evidence handle format is invalid',
    providerRequired: 'Enter a verification service identifier', providerFormat: 'The verification service identifier is invalid',
  },
  forbidden: { title: 'Identity verification unavailable', description: 'This account cannot manage its identity verification.' },
  unauthorized: { title: 'Session expired', description: 'Sign in again to manage identity verification.' },
  errors: {
    loadFailed: 'Failed to load the identity verification case', requestFailed: 'The identity verification request failed. Try again later.',
    rateLimited: 'Too many operations. Try again later.',
    network_error: 'The network request failed. Try again later.', invalid_response: 'The service response was invalid. Refresh to confirm the current state.',
    invalid_request: 'The request is invalid. Check the input.', identity_verification_invalid_request: 'The request is invalid. Check the input.',
    identity_verification_unauthenticated: 'Your session has expired. Sign in again.',
    identity_verification_permission_denied: 'This account cannot manage its identity verification.',
    identity_verification_not_found: 'The identity verification case was not found.',
    identity_verification_revision_conflict: 'The case revision changed. Refresh and try again.',
    identity_verification_idempotency_conflict: 'The idempotent request differs from the original request. Refresh and try again.',
    identity_verification_active_review: 'An identity review is already active.',
    identity_verification_invalid_transition: 'This operation is not allowed in the current case state.',
    identity_verification_initial_approval_required: 'Complete initial personal verification first.',
    identity_verification_identity_mismatch: 'The trusted identity does not match the verified identity.',
    identity_verification_already_verified: 'This identity is already verified.',
    identity_verification_case_expired: 'This verification case has expired.',
    identity_verification_case_not_expired: 'This verification case has not reached its deadline.',
    identity_verification_evidence_settlement_pending: 'Trusted evidence is still being processed. Try again later.',
    identity_verification_evidence_invalid: 'The trusted evidence is invalid. Obtain a new handle.',
    identity_verification_trusted_resolver_required: 'The trusted evidence service is not configured.',
    identity_verification_evidence_unavailable: 'The trusted evidence service is unavailable.',
    identity_verification_request_canceled: 'The request was canceled. Try again.',
    identity_verification_request_timeout: 'The request timed out. Confirm the current state.',
    identity_verification_response_too_large: 'The response is unavailable. Try again later.',
    identity_verification_unavailable: 'The identity verification service is unavailable. Try again later.',
    identity_verification_provider_result_unknown: 'The verification service outcome is unknown. Retry the same request or abandon it.',
  },
}

export type AccountIdentityVerificationMessages = { [key: string]: string | AccountIdentityVerificationMessages }

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

const pseudoCN = pseudoTree(zhCN) as AccountIdentityVerificationMessages

export const accountIdentityVerificationMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  AccountIdentityVerificationMessages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(accountIdentityVerificationMessages)) {
  i18n.addResourceBundle(locale, 'accountIdentityVerification', messages, true, true)
}
