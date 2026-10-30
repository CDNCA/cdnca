import i18n from './index'

const zhCN = {
  title: '自定义角色',
  description: '管理租户可委派权限、自定义角色版本和用户授权。',
  sections: { permissions: '可委派权限', roles: '自定义角色', grants: '用户角色授权' },
  actions: {
    create: '新建角色', rename: '重命名', publish: '发布权限', deactivate: '停用角色', assign: '分配用户', revoke: '撤销授权',
    refresh: '刷新', retry: '重试', save: '保存', cancel: '取消', previous: '上一页', next: '下一页',
    publishConfirm: '发布', deactivateConfirm: '确认停用', assignConfirm: '确认分配', revokeConfirm: '确认撤销',
    exactRetry: '使用同一请求重试', abandon: '放弃并刷新',
  },
  fields: {
    name: '角色名称', permissions: '权限', permission: '权限名称', stepUpRequired: '二次认证要求',
    stepUpProof: '二次认证证明', subjectUserId: '用户 ID', subjectUser: '用户', subjectUserPlaceholder: '搜索用户名、显示名称或邮箱', role: '角色', revision: '版本', status: '状态',
    actions: '操作', includeDeactivated: '包含已停用角色',
  },
  values: { required: '必需', notRequired: '不需要', stepUp: '需二次认证' },
  statuses: { active: '生效中', deactivated: '已停用', revoked: '已撤销' },
  data: {
    loadingRoles: '正在加载自定义角色', emptyPermissions: '暂无可委派权限',
    emptyRoles: '暂无自定义角色', emptyGrants: '暂无用户角色授权',
  },
  dialogs: {
    createTitle: '新建自定义角色', renameTitle: '重命名角色', publishTitle: '发布角色权限',
    deactivateTitle: '停用自定义角色', assignTitle: '分配自定义角色', revokeTitle: '撤销用户角色授权',
    unknownTitle: '操作结果待确认',
    unknownDescription: '连接在确认结果前中断。可使用同一请求精确重试，或放弃并刷新当前事实。',
  },
  notices: { saved: '角色已保存', published: '角色权限已发布', deactivated: '角色已停用', assigned: '角色已分配', revoked: '授权已撤销' },
  errors: {
    forbidden: '无权管理自定义角色', load: '自定义角色加载失败，请重试',
    revisionConflict: '角色版本已变化，请刷新后重试', stepUpRequired: '此操作需要有效且未使用的二次认证证明',
    permissionNotDelegable: '所选权限不能委派给租户自定义角色', serviceUnavailable: '自定义角色服务暂不可用，请稍后重试',
    nameConflict: '角色名称已存在', roleInactive: '该角色已停用', selfAssignment: '不能向当前操作者分配此角色',
    validation: '请填写完整且有效的角色信息',
  },
  pagination: { roles: '角色分页', grants: '授权分页' },
}

const enUS: typeof zhCN = {
  title: 'Custom roles',
  description: 'Manage tenant-delegable permissions, custom role revisions, and user grants.',
  sections: { permissions: 'Delegable permissions', roles: 'Custom roles', grants: 'User role grants' },
  actions: {
    create: 'Create role', rename: 'Rename', publish: 'Publish permissions', deactivate: 'Deactivate role', assign: 'Assign user', revoke: 'Revoke grant',
    refresh: 'Refresh', retry: 'Retry', save: 'Save', cancel: 'Cancel', previous: 'Previous', next: 'Next',
    publishConfirm: 'Publish', deactivateConfirm: 'Confirm deactivation', assignConfirm: 'Confirm assignment', revokeConfirm: 'Confirm revocation',
    exactRetry: 'Retry the same request', abandon: 'Abandon and refresh',
  },
  fields: {
    name: 'Role name', permissions: 'Permissions', permission: 'Permission', stepUpRequired: 'Step-up requirement',
    stepUpProof: 'Step-up proof', subjectUserId: 'User ID', subjectUser: 'User', subjectUserPlaceholder: 'Search username, display name, or email', role: 'Role', revision: 'Revision', status: 'Status',
    actions: 'Actions', includeDeactivated: 'Include deactivated roles',
  },
  values: { required: 'Required', notRequired: 'Not required', stepUp: 'Step-up required' },
  statuses: { active: 'Active', deactivated: 'Deactivated', revoked: 'Revoked' },
  data: {
    loadingRoles: 'Loading custom roles', emptyPermissions: 'No delegable permissions',
    emptyRoles: 'No custom roles', emptyGrants: 'No user role grants',
  },
  dialogs: {
    createTitle: 'Create custom role', renameTitle: 'Rename role', publishTitle: 'Publish role permissions',
    deactivateTitle: 'Deactivate custom role', assignTitle: 'Assign custom role', revokeTitle: 'Revoke user role grant',
    unknownTitle: 'Operation outcome unknown',
    unknownDescription: 'The connection ended before the outcome was confirmed. Retry the same request, or abandon it and refresh current facts.',
  },
  notices: { saved: 'Role saved', published: 'Role permissions published', deactivated: 'Role deactivated', assigned: 'Role assigned', revoked: 'Grant revoked' },
  errors: {
    forbidden: 'You cannot manage custom roles', load: 'Failed to load custom roles. Try again.',
    revisionConflict: 'The role revision changed. Refresh and try again.', stepUpRequired: 'This operation requires a valid unused step-up proof.',
    permissionNotDelegable: 'A selected permission cannot be delegated to a tenant custom role.', serviceUnavailable: 'The custom role service is temporarily unavailable.',
    nameConflict: 'That role name already exists.', roleInactive: 'This role is deactivated.', selfAssignment: 'You cannot assign this role to the current operator.',
    validation: 'Complete the role form with valid values.',
  },
  pagination: { roles: 'Role pagination', grants: 'Grant pagination' },
}

type Messages = typeof zhCN

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => { tokens.push(token); return `__TOKEN_${tokens.length - 1}__` })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`.replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as Messages

export const customRolesPageMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(customRolesPageMessages)) {
  i18n.addResourceBundle(locale, 'customRolesPage', messages, true, true)
}
