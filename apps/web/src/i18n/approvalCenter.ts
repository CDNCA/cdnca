import i18n from './index'

const zhCN = {
  title: '审批中心',
  intro: '开启后，平台管理员执行下面勾选的高危操作需要填写原因并由另一位审批人批准，批准后立即用审批人的身份执行。待审申请 24 小时未处理自动过期。API 密钥调用与租户自己的操作不受影响。',
  settingsTitle: '审批中心',
  separateSave: '单独保存，不随上方「保存」提交',
  approvers: '审批人：平台所有者与平台管理员。',
  enabled: '启用审批中心',
  rulesLabel: '需要审批的操作',
  firstBatch: '默认勾选',
  save: '保存',
  saved: '审批中心设置已保存',
  rules: {
    'site.batch_delete': '批量删除网站',
    'cache.whole_site_purge': '整站清除缓存',
    'firewall.policy': '修改或恢复全局防火墙',
    'control.upgrade': '主控升级与回滚',
    'site.batch_disable': '批量停用网站',
    'node.batch_disable': '批量停用节点',
    'stream.batch_delete': '批量删除四层转发',
    'user.delete': '删除用户',
  },
  states: {
    pending: '待审批', expired: '已过期', rejected: '已驳回', executing: '执行中', unknown: '结果未知', executed: '已执行', failed: '执行失败',
  },
  filters: { all: '全部状态' },
  columns: { rule: '操作', reason: '原因', requester: '发起人', requestedAt: '发起时间', expiresAt: '过期时间', state: '状态', actions: '操作' },
  actions: { view: '查看', approve: '批准并执行', reject: '驳回', refresh: '刷新', open: '去处理', cancel: '取消' },
  detail: {
    title: '审批申请', steps: '请求内容（共 {{count}} 步）', decider: '审批人', decidedAt: '审批时间', note: '审批意见',
    results: '执行结果', stepUp: '二次验证', stepUpMfa: '已二次验证', stepUpNone: '未二次验证（审批人未绑定）', selfApproved: '平台管理员自审',
    unknownTitle: '执行结果未知', unknownHint: '执行过程中控制面中断，系统不会自动重试，以免重复执行。请到原页面核实操作是否已生效，必要时重新发起。',
    codeLabel: '二次验证码', codeHint: '你已绑定二次验证，批准前需输入 6 位验证码。', notePlaceholder: '审批意见（可选）',
  },
  prompt: {
    title: '该操作需要审批', description: '「{{rule}}」已纳入审批中心，填写原因后提交，由审批人批准后执行。', reason: '原因',
    reasonPlaceholder: '说明为什么要执行此操作（必填，最多 500 字）', submit: '提交审批', cancel: '取消',
  },
  notices: { submitted: '已提交审批，审批人批准后执行', cancelled: '已取消，操作未执行' },
  errors: {
    approval_same_operator: '发起人不能审批自己的申请。',
    approval_expired: '申请已过期。',
    revision_conflict: '申请已被他人处理，请刷新。',
    mfa_step_up_required: '二次验证码无效或已过期。',
    permission_denied: '没有权限。',
    unknown: '操作失败，请稍后重试。',
  },
  empty: '暂无审批申请',
}

const enUS: typeof zhCN = {
  title: 'Approval center',
  intro: 'When on, platform administrators need a reason and another approver for the checked operations below; an approved request runs at once with the approver\'s identity. Pending requests expire after 24 hours. API keys and tenants\' own operations are not affected.',
  settingsTitle: 'Approval center',
  separateSave: 'Saved on its own, not with the Save button above',
  approvers: 'Approvers: platform owners and platform administrators.',
  enabled: 'Turn on the approval center',
  rulesLabel: 'Operations that need approval',
  firstBatch: 'Checked by default',
  save: 'Save',
  saved: 'Approval center settings saved',
  rules: {
    'site.batch_delete': 'Batch delete sites',
    'cache.whole_site_purge': 'Purge a whole site\'s cache',
    'firewall.policy': 'Change or restore the global firewall',
    'control.upgrade': 'Control plane upgrade and rollback',
    'site.batch_disable': 'Batch disable sites',
    'node.batch_disable': 'Batch disable nodes',
    'stream.batch_delete': 'Batch delete L4 forwards',
    'user.delete': 'Delete users',
  },
  states: {
    pending: 'Pending', expired: 'Expired', rejected: 'Rejected', executing: 'Executing', unknown: 'Outcome unknown', executed: 'Executed', failed: 'Failed',
  },
  filters: { all: 'All states' },
  columns: { rule: 'Operation', reason: 'Reason', requester: 'Requested by', requestedAt: 'Requested at', expiresAt: 'Expires at', state: 'State', actions: 'Actions' },
  actions: { view: 'View', approve: 'Approve and run', reject: 'Reject', refresh: 'Refresh', open: 'Open', cancel: 'Cancel' },
  detail: {
    title: 'Approval request', steps: 'Request ({{count}} steps)', decider: 'Approver', decidedAt: 'Decided at', note: 'Note',
    results: 'Results', stepUp: 'Step-up', stepUpMfa: 'Verified', stepUpNone: 'Not verified (approver has no MFA)', selfApproved: 'Self-approved by a platform administrator',
    unknownTitle: 'Outcome unknown', unknownHint: 'The control plane was interrupted while running this request. It is not retried automatically, so it cannot run twice. Check on the original page whether the operation took effect, and submit it again if needed.',
    codeLabel: 'Verification code', codeHint: 'You have MFA; enter the 6-digit code to approve.', notePlaceholder: 'Note (optional)',
  },
  prompt: {
    title: 'This operation needs approval', description: '"{{rule}}" is managed by the approval center. Give a reason; it runs once an approver approves it.', reason: 'Reason',
    reasonPlaceholder: 'Why this operation is needed (required, up to 500 characters)', submit: 'Submit for approval', cancel: 'Cancel',
  },
  notices: { submitted: 'Submitted; it runs once approved', cancelled: 'Cancelled; the operation did not run' },
  errors: {
    approval_same_operator: 'The requester cannot approve its own request.',
    approval_expired: 'The request has expired.',
    revision_conflict: 'The request was handled by someone else. Refresh.',
    mfa_step_up_required: 'The verification code is invalid or expired.',
    permission_denied: 'Permission is required.',
    unknown: 'The operation failed. Try again later.',
  },
  empty: 'No approval requests',
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') ? part : part.replace(/[A-Za-z一-鿿]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}
export const approvalCenterMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(approvalCenterMessages)) {
  i18n.addResourceBundle(locale, 'approvalCenter', messages, true, true)
}
