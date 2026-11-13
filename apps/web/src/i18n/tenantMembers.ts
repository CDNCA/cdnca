import i18n from './index'

const zhCN = {
  title: '团队成员',
  intro: '子账号只能登录本账号，默认只读；需要更多权限时，在“自定义角色”里创建角色并授予给子账号。',
  add: '新建子账号',
  roles: '自定义角色与授权',
  username: '用户名', displayName: '名称', email: '邮箱（可选）', password: '初始密码（至少 12 位）',
  status: '状态', role: '角色', createdAt: '加入时间', actions: '操作',
  statuses: { active: '正常', suspended: '已停用', disabled: '账号已禁用' },
  roleNames: { tenant_owner: '主账号', tenant_viewer: '只读' },
  owner: '主账号',
  suspend: '停用', resume: '恢复', suspendConfirm: '停用后该成员会立即退出登录，确定停用？',
  created: '子账号已创建', suspended: '已停用', resumed: '已恢复', cancel: '取消', submit: '创建',
  remove: '删除', removeConfirm: '删除后该子账号会立即退出登录且无法再登录；其操作记录保留。确定删除？', removed: '子账号已删除',
  resetPassword: '重置密码', resetConfirm: '将生成新密码，让该子账号立即退出登录，并要求其下次登录时修改密码。确定重置？',
  resetTitle: '新密码（只显示这一次）', resetHint: '请复制后安全地交给该子账号，关闭后无法再次查看。对方用它登录后必须先修改密码。',
  resetUnknownTitle: '没有收到「{{name}}」的重置结果',
  resetUnknownHint: '密码可能已经重置，该子账号也可能已被退出登录。请点「取回结果」用同一次操作取回新密码（10 分钟内有效，只能取回一次），不要再次重置。',
  retrieveReset: '取回结果', abandonRetrieve: '放弃取回',
  copy: '复制', copied: '已复制', close: '关闭',
  invite: '邮件邀请', inviteTitle: '邀请成员', inviteEmail: '被邀请人邮箱', inviteSubmit: '发送邀请',
  inviteHint: '对方会收到一封邮件，72 小时内打开链接设置用户名和密码即成为只读子账号；链接只能用一次。',
  invited: '邀请邮件已发送', invitations: '邀请记录', invitationStatus: '状态', expiresAt: '有效期至',
  invitationStatuses: { pending: '待接受', accepted: '已接受', revoked: '已撤回', expired: '已过期' },
  revoke: '撤回', revoked: '邀请已撤回',
  removeTitle: '删除子账号 {{name}}', suspendTitle: '停用成员 {{name}}',
  transferTo: '名下资源转给', transferNone: '不转移',
  transferHint: '网站、四层转发分组、证书、安全规则、URL 鉴权和 CC 匹配器/过滤器会在同一操作中转给所选成员；套餐、四层转发和绑定套餐的网站无法转移，需先处理。',
  ownsTransferable: '该成员名下还有 {{count}} 项网站、证书或规则，请选择接收的成员后再操作。',
  ownsPinned: '该成员名下有 {{subscriptions}} 个有效套餐、{{forwards}} 个四层转发、{{sites}} 个绑定套餐或 CNAME 的网站，这些无法转移，请先删除或等待到期。',
  requirePasswordChange: '要求改密', requirePasswordChangeConfirm: '该成员下次操作或登录时必须先修改密码，确定？',
  releasePasswordChange: '取消改密要求', passwordChangePending: '待改密',
  passwordChangeRequired: '已要求下次登录改密', passwordChangeReleased: '已取消改密要求',
  errors: {
    tenant_member_protected: '主账号和你自己不能在这里操作。',
    tenant_member_password_reset_result_gone: '重置结果已取回过或已超过 10 分钟，无法再显示；密码没有再次重置。如需新密码请重新重置。',
    tenant_member_password_reset_unavailable: '密码重置暂不可用，请稍后再试。',
    idempotency_conflict: '这次取回与原来的重置不是同一操作者或同一成员，已拒绝。',
    tenant_member_shared: '该成员同时属于其他账号，不能在这里删除或重置密码。',
    tenant_member_owns_resources: '该成员名下还有资源，请选择接收的成员，或先删除无法转移的套餐与四层转发。',
    tenant_member_transfer_target_invalid: '接收资源的成员必须是本账号下其他正常状态的成员。',
    tenant_member_email_taken: '这个邮箱已被其他账号使用。',
    tenant_member_invitation_unavailable: '邮件邀请暂不可用：平台未开启或未配置邮件通道。',
    tenant_member_invitation_not_found: '没有找到待接受的邀请。',
    username_conflict: '用户名已被使用。',
    validation_error: '请检查输入：用户名 3–128 位小写字母数字，密码至少 12 位。',
    permission_denied: '你没有管理成员的权限。',
    tenant_member_outranks: '该成员拥有你没有的权限，不能由你管理。',
  },
}
const enUS: typeof zhCN = {
  title: 'Team members',
  intro: 'Sub-accounts sign in to this account only and are read-only by default; to grant more, create a role under Custom roles and assign it.',
  add: 'Add sub-account',
  roles: 'Custom roles & grants',
  username: 'Username', displayName: 'Name', email: 'Email (optional)', password: 'Initial password (12+ characters)',
  status: 'Status', role: 'Role', createdAt: 'Joined', actions: 'Actions',
  statuses: { active: 'Active', suspended: 'Suspended', disabled: 'Account disabled' },
  roleNames: { tenant_owner: 'Owner', tenant_viewer: 'Read-only' },
  owner: 'Owner',
  suspend: 'Suspend', resume: 'Resume', suspendConfirm: 'The member is signed out at once. Suspend?',
  created: 'Sub-account created', suspended: 'Suspended', resumed: 'Resumed', cancel: 'Cancel', submit: 'Create',
  remove: 'Delete', removeConfirm: 'The sub-account is signed out at once and can no longer sign in; its activity history is kept. Delete?', removed: 'Sub-account deleted',
  resetPassword: 'Reset password', resetConfirm: 'A new password is generated, the sub-account is signed out at once and must change it at the next sign-in. Reset?',
  resetTitle: 'New password (shown only this once)', resetHint: 'Copy it and hand it to the sub-account securely; it cannot be shown again. After signing in with it they must change it first.',
  resetUnknownTitle: 'No reset result was received for "{{name}}"',
  resetUnknownHint: 'The password may already be reset and the sub-account signed out. Use "Retrieve result" to fetch the new password with the same operation (valid for 10 minutes, once). Do not reset again.',
  retrieveReset: 'Retrieve result', abandonRetrieve: 'Give up retrieving',
  copy: 'Copy', copied: 'Copied', close: 'Close',
  invite: 'Invite by email', inviteTitle: 'Invite a member', inviteEmail: 'Invitee email', inviteSubmit: 'Send invitation',
  inviteHint: 'They get an email; opening the link within 72 hours to choose a username and password makes them a read-only sub-account. The link works once.',
  invited: 'Invitation sent', invitations: 'Invitations', invitationStatus: 'Status', expiresAt: 'Valid until',
  invitationStatuses: { pending: 'Pending', accepted: 'Accepted', revoked: 'Withdrawn', expired: 'Expired' },
  revoke: 'Withdraw', revoked: 'Invitation withdrawn',
  removeTitle: 'Delete sub-account {{name}}', suspendTitle: 'Suspend member {{name}}',
  transferTo: 'Hand resources over to', transferNone: 'No handover',
  transferHint: 'Sites, layer-4 forward groups, certificates, security rules, URL authentication and CC matchers/filters go to the chosen member in the same step; packages, layer-4 forwards and package-bound sites cannot move and must be handled first.',
  ownsTransferable: 'The member still owns {{count}} sites, certificates or rules. Choose a member to receive them.',
  ownsPinned: 'The member owns {{subscriptions}} active packages, {{forwards}} layer-4 forwards and {{sites}} package- or CNAME-bound sites, which cannot move. Remove them or let them expire first.',
  requirePasswordChange: 'Require password change', requirePasswordChangeConfirm: 'The member must change the password before doing anything else at the next request or sign-in. Continue?',
  releasePasswordChange: 'Withdraw password change', passwordChangePending: 'Must change password',
  passwordChangeRequired: 'Password change required at next sign-in', passwordChangeReleased: 'Password change requirement withdrawn',
  errors: {
    tenant_member_protected: 'The owner and yourself cannot be changed here.',
    tenant_member_password_reset_result_gone: 'The reset result was already retrieved or is older than 10 minutes; the password was not reset again. Reset again if a new password is needed.',
    tenant_member_password_reset_unavailable: 'Password reset is unavailable right now. Try again later.',
    idempotency_conflict: 'This retrieval does not match the original reset (another administrator or member) and was refused.',
    tenant_member_shared: 'This member also belongs to another account and cannot be deleted or reset here.',
    tenant_member_owns_resources: 'The member still owns resources. Choose a member to receive them, or remove the packages and layer-4 forwards that cannot move.',
    tenant_member_transfer_target_invalid: 'The receiving member must be another active member of this account.',
    tenant_member_email_taken: 'This email already belongs to another account.',
    tenant_member_invitation_unavailable: 'Email invitations are unavailable: the platform email channel is off or not configured.',
    tenant_member_invitation_not_found: 'No pending invitation was found.',
    username_conflict: 'The username is taken.',
    validation_error: 'Check the input: username 3–128 lowercase letters or digits, password 12+ characters.',
    permission_denied: 'You cannot manage members.',
    tenant_member_outranks: 'This member holds permissions you do not have, so you cannot manage them.',
  },
}
function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') ? part : part.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}
export const tenantMembersMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(tenantMembersMessages)) {
  i18n.addResourceBundle(locale, 'tenantMembers', messages, true, true)
}

// Public invitation acceptance page (/accept-invitation).
const acceptZhCN = {
  title: '接受成员邀请',
  intro: '设置用户名和密码后即成为该账号的只读子账号，之后用新账号登录。',
  username: '用户名', displayName: '名称', password: '密码（至少 12 位）', submit: '创建账号',
  done: '账号已创建，请使用新账号登录。', login: '去登录',
  missing: '邀请链接不完整，请从邀请邮件中重新打开。',
  errors: {
    tenant_member_invitation_invalid: '邀请链接无效、已使用、已撤回或已过期，请联系邀请人重新发送。',
    tenant_member_invitation_unavailable: '邀请暂不可用，请稍后再试。',
    tenant_member_email_taken: '被邀请的邮箱已属于其他账号。',
    username_conflict: '用户名已被使用。',
    validation_error: '请检查输入：用户名 3–128 位小写字母数字，密码至少 12 位。',
  },
}
const acceptEnUS: typeof acceptZhCN = {
  title: 'Accept member invitation',
  intro: 'Choose a username and password to become a read-only sub-account of this account, then sign in with it.',
  username: 'Username', displayName: 'Name', password: 'Password (12+ characters)', submit: 'Create account',
  done: 'Your account is ready. Sign in with it.', login: 'Sign in',
  missing: 'The invitation link is incomplete. Open it again from the invitation email.',
  errors: {
    tenant_member_invitation_invalid: 'The invitation link is invalid, used, withdrawn or expired. Ask for a new one.',
    tenant_member_invitation_unavailable: 'Invitations are unavailable right now. Try again later.',
    tenant_member_email_taken: 'The invited email already belongs to another account.',
    username_conflict: 'The username is taken.',
    validation_error: 'Check the input: username 3–128 lowercase letters or digits, password 12+ characters.',
  },
}
export const memberInvitationAcceptMessages = {
  'zh-CN': acceptZhCN, 'en-US': acceptEnUS, 'qps-ploc': pseudo(acceptZhCN), 'qps-Ploc': pseudo(acceptZhCN),
}
for (const [locale, messages] of Object.entries(memberInvitationAcceptMessages)) {
  i18n.addResourceBundle(locale, 'memberInvitationAccept', messages, true, true)
}
