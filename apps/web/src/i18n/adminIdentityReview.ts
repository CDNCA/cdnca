import i18n from './index'

type TranslationTree = { [key: string]: string | TranslationTree }

export const adminIdentityReviewNamespace = 'adminIdentityReview'

const zhCN = {
  title: '实名审核',
  description: '查看全部租户的实名认证申请，开始审核后可通过或驳回。操作以你的管理员身份记入审计。',
  tabs: { submitted: '待审核', reviewing: '审核中', approved: '已通过', rejected: '已驳回' },
  states: {
    draft: '草稿', submitted: '待审核', reviewing: '审核中', approved: '已通过',
    rejected: '已驳回', withdrawn: '已撤回', expired: '已过期',
  },
  kinds: { personal_initial: '个人首次认证', personal_reverification: '个人重新认证', enterprise: '企业认证' },
  columns: { tenant: '租户', applicant: '申请人', kind: '认证类型', status: '状态', submittedAt: '提交时间', actions: '操作' },
  reasons: {
    evidence_verified: '证据已核验', identity_mismatch: '身份信息不匹配', evidence_incomplete: '证据不完整',
    evidence_unreadable: '证据无法读取', organization_mismatch: '企业信息不匹配',
    authorization_invalid: '授权材料无效', suspected_fraud: '疑似欺诈',
  },
  detail: {
    title: '实名认证申请', tenant: '租户', applicant: '申请人', kind: '认证类型', status: '状态',
    materials: '证据材料', materialCount: '{{count}} 份', reason: '决定原因', rejectReason: '驳回原因',
  },
  actions: { review: '审核', claim: '开始审核', approve: '通过', reject: '驳回', refresh: '刷新', more: '加载更多' },
  notices: { claimed: '已开始审核', approved: '已通过', rejected: '已驳回' },
  empty: '暂无实名认证申请',
  errors: {
    forbidden: '只有平台管理员可以审核实名认证。',
    load: '实名认证申请加载失败',
    action: '操作失败，请刷新后重试',
    identity_verification_revision_conflict: '申请已被他人处理，请刷新后重试',
    identity_verification_review_assignment_required: '该申请正由其他审核人处理',
    identity_verification_self_review_forbidden: '不能审核自己的申请',
    identity_verification_invalid_transition: '当前状态不允许该操作',
  },
}

const enUS: typeof zhCN = {
  title: 'Identity review',
  description: 'Every tenant\'s identity verification requests. Start a review, then approve or reject; actions are audited as you.',
  tabs: { submitted: 'Pending', reviewing: 'In review', approved: 'Approved', rejected: 'Rejected' },
  states: {
    draft: 'Draft', submitted: 'Pending', reviewing: 'In review', approved: 'Approved',
    rejected: 'Rejected', withdrawn: 'Withdrawn', expired: 'Expired',
  },
  kinds: { personal_initial: 'Initial personal', personal_reverification: 'Personal reverification', enterprise: 'Enterprise' },
  columns: { tenant: 'Tenant', applicant: 'Applicant', kind: 'Type', status: 'Status', submittedAt: 'Submitted', actions: 'Actions' },
  reasons: {
    evidence_verified: 'Evidence verified', identity_mismatch: 'Identity mismatch', evidence_incomplete: 'Evidence incomplete',
    evidence_unreadable: 'Evidence unreadable', organization_mismatch: 'Organization mismatch',
    authorization_invalid: 'Authorization invalid', suspected_fraud: 'Suspected fraud',
  },
  detail: {
    title: 'Identity verification request', tenant: 'Tenant', applicant: 'Applicant', kind: 'Type', status: 'Status',
    materials: 'Evidence', materialCount: '{{count}} file(s)', reason: 'Decision reason', rejectReason: 'Reject reason',
  },
  actions: { review: 'Review', claim: 'Start review', approve: 'Approve', reject: 'Reject', refresh: 'Refresh', more: 'Load more' },
  notices: { claimed: 'Review started', approved: 'Approved', rejected: 'Rejected' },
  empty: 'No identity verification requests',
  errors: {
    forbidden: 'Only platform administrators can review identity verification.',
    load: 'Unable to load identity verification requests',
    action: 'The action failed; refresh and try again',
    identity_verification_revision_conflict: 'Someone else changed the request; refresh and try again',
    identity_verification_review_assignment_required: 'Another reviewer is handling this request',
    identity_verification_self_review_forbidden: 'You cannot review your own request',
    identity_verification_invalid_transition: 'The request\'s status does not allow this',
  },
}

function pseudo(value: string | TranslationTree): string | TranslationTree {
  if (typeof value === 'string') return `［${value.replace(/\S/g, '$&~')}］`
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudo(item)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
})) {
  i18n.addResourceBundle(locale, adminIdentityReviewNamespace, messages, true, true)
}

export { enUS, zhCN }
