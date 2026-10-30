import i18n from './index'

type Messages = Record<string, unknown>

const zhCN = {
  actions: {
    backToSite: '返回网站',
    add: '添加ACL',
    more: '更多操作',
    clear: '清除',
    refresh: '刷新列表',
  },
  filters: {
    status: '所有状态',
    name: 'ACL名称',
    namePlaceholder: '请输入ACL名称,模糊搜索',
    id: 'ACL ID',
    idPlaceholder: '请输入ACL ID',
    ownerPlaceholder: '请输入用户ID',
  },
  columns: {
    id: 'ID',
    owner: '用户',
    name: '名称',
    remark: '备注',
    status: '状态',
    actions: '操作',
  },
  values: {
    empty: '暂无数据',
    unavailable: '—',
    enabled: '启用',
    disabled: '停用',
  },
  editor: {
    createTitle: '添加ACL',
    editTitle: '编辑ACL',
    owner: '用户',
    ownerPlaceholder: '输入ID、邮箱、用户名、手机号搜索',
    targetScope: '目标租户',
    targetScopePlaceholder: '搜索用户名、邮箱、用户ID或粘贴作用域 UUID',
    targetScopeRequired: '请选择目标租户',
    targetScopeEmpty: '没有匹配的用户',
    ownerRequired: '请输入用户',
    matchRequired: '请输入 IP 或 CIDR',
    actionRequired: '请选择行为',
    name: '名称',
    description: '备注',
    defaultAction: '默认行为',
    allow: '允许',
    block: '拒绝',
    enabled: '启用',
    rules: '规则列表',
    addRule: '添加规则',
    match: '匹配',
    cidrPlaceholder: '请输入 IP 或 CIDR，例如 192.0.2.0/24',
    action: '行为',
    removeRule: '删除规则',
    advanced: '高级设置',
    import: '批量导入',
    importHint: '每行一个 CIDR；仅用于兼容导入，不影响默认规则编辑。',
  },
  pagination: {
    total: '共 {{count}} 条',
  },
} as const

const enUS = {
  actions: {
    backToSite: 'Back to the site',
    add: 'Add ACL',
    more: 'More actions',
    clear: 'Clear',
    refresh: 'Refresh list',
  },
  filters: {
    status: 'All statuses',
    name: 'ACL name',
    namePlaceholder: 'Search ACL name',
    id: 'ACL ID',
    idPlaceholder: 'Enter ACL ID',
    ownerPlaceholder: 'Enter user ID',
  },
  columns: {
    id: 'ID',
    owner: 'Owner',
    name: 'Name',
    remark: 'Remark',
    status: 'Status',
    actions: 'Actions',
  },
  values: {
    empty: 'No data',
    unavailable: '—',
    enabled: 'Enabled',
    disabled: 'Disabled',
  },
  editor: {
    createTitle: 'Add ACL',
    editTitle: 'Edit ACL',
    owner: 'User',
    ownerPlaceholder: 'Search ID, email, username, or phone',
    targetScope: 'Target tenant',
    targetScopePlaceholder: 'Search username, email, user ID or paste a scope UUID',
    targetScopeRequired: 'Select the target tenant',
    targetScopeEmpty: 'No matching users',
    ownerRequired: 'Enter the user',
    matchRequired: 'Enter an IP or CIDR',
    actionRequired: 'Select an action',
    name: 'Name',
    description: 'Remark',
    defaultAction: 'Default action',
    allow: 'Allow',
    block: 'Reject',
    enabled: 'Enabled',
    rules: 'Rules',
    addRule: 'Add rule',
    match: 'Match',
    cidrPlaceholder: 'Enter an IP or CIDR, e.g. 192.0.2.0/24',
    action: 'Action',
    removeRule: 'Remove rule',
    advanced: 'Advanced settings',
    import: 'Bulk import',
    importHint: 'One CIDR per line; compatibility import only.',
  },
  pagination: {
    total: '{{count}} total',
  },
} as const

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, pseudo(item)]))
}

const bundles: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN) as Messages,
  'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(bundles)) {
  i18n.addResourceBundle(locale, 'securityPolicies', { acl: messages }, true, true)
}

export { bundles as securityPoliciesAclMessages }
