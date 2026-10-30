import i18n from './index'

type Messages = Record<string, unknown>

const zhCN = {
  actions: { confirm: '确定', cancel: '取消' },
  cc: {
    tabs: { groups: '规则组', matchers: '匹配器', filters: '过滤器' },
    actions: { addGroup: '添加规则组', addMatcher: '添加匹配器', addFilter: '添加过滤器', manage: '管理', view: '查看', more: '批量操作', rowMore: '更多', clear: '清除', enable: '启用', disable: '禁用', enableNamed: '启用{{name}}', disableNamed: '禁用{{name}}', refreshList: '刷新列表', challengePolicies: '挑战策略', backToGroups: '返回规则组' },
    filters: { kind: '规则类型', display: '显示', status: '状态', name: '规则组名称', namePlaceholder: '请输入规则组名称,模糊搜索', id: '规则组ID', idPlaceholder: '请输入规则组ID', owner: '用户ID', ownerPlaceholder: '请输入用户ID', matcherName: '匹配器名称', matcherNamePlaceholder: '请输入匹配器名称,模糊搜索', matcherId: '匹配器ID', matcherIdPlaceholder: '请输入匹配器ID', filterName: '过滤器名称', filterNamePlaceholder: '请输入过滤器名称,模糊搜索', filterId: '过滤器ID', filterIdPlaceholder: '请输入过滤器ID' },
    columns: { id: 'ID', name: '名称', systemRule: '系统规则', type: '类型', display: '显示', status: '状态', sort: '排序', createdAt: '创建时间' },
    values: { allTypes: '所有类型', allVisible: '所有显示', allStatuses: '所有状态', visible: '显示', hidden: '隐藏', normal: '正常', system: '系统规则', custom: '用户规则', unavailable: '—', ruleCount: '{{count}} 条', sortMeta: '排序 {{value}}', empty: '暂无数据' },
    summary: { label: '规则组统计', all: '全部', system: '系统', custom: '自定义', visible: '显示', disabled: '禁用' },
    pagination: { total: '共 {{count}} 条' },
    types: { reqRate: '请求频率', browserVerify: '无感验证', fiveSecond: '5 秒盾', click: '点击验证', simpleClick: '点击验证（简单）', slider: '滑动验证', simpleSlider: '滑动验证（简单）', captcha: '验证码', rotateImage: '旋转图片', redirect: '302 跳转', urlAuth: 'URL 鉴权', challenge: '挑战' },
    editor: { createMatcher: '添加匹配器', editMatcher: '编辑匹配器', createFilter: '添加过滤器', editFilter: '编辑过滤器', name: '名称', nameRequired: '请输入名称', description: '说明', enabled: '启用', field: '匹配字段', operator: '运算符', key: '字段名称', values: '匹配值', valuesPlaceholder: '每行一个值（逗号视为值的一部分，正则可含 {2,}）', type: '类型', parameters: '高级参数（JSON）', parametersInvalid: '请输入有效的 JSON 对象', parametersHint: '上面的常用参数会覆盖这里的同名字段，其它字段按原样保存。', withinSecond: '统计周期（秒）', maxReq: '最大请求次数', maxReqPerUri: '单个网址最大请求次数', maxReqPerUriHint: '0 表示不限制', targetScopePlaceholder: '平台会话必须输入租户作用域 UUID', ownerPlaceholder: '平台会话必须输入所属用户 UUID', editGroup: '编辑规则组', basicInfo: '基础信息', ruleList: '规则列表', addRule: '新增规则', configured: '已配置 {{count}} 条规则', emptyRules: '暂无规则', orderNote: '规则从上往下匹配，可拖动规则来调整顺序。', more: '展开更多', groupId: '规则组ID', sort: '排序', state: '状态', policyNotice: '系统规则由签名平台策略提供，规则内容需要在授权运营端发布。', builtIn: '内置规则', remark: '备注', matcher: '匹配器', filterOne: '过滤器1', filterTwo: '过滤器2', action: '动作', flow: '模式', block: '拉黑', allow: '放行', challenge: '挑战', stop: '停止匹配', continue: '继续下一条规则', matchMode: '匹配模式', flowHelp: '继续下一条规则：执行当前过滤器后继续匹配；停止匹配：执行当前过滤器后不再继续。', matcherBuiltin: '匹配内置资源', matcherStatic: '匹配静态资源', matcherAll: '匹配所有资源', matcherPlaceholder: '请选择匹配器', filterOnePlaceholder: '请选择过滤器1', filterTwoPlaceholder: '请选择过滤器2（可选）', matcherRequired: '请选择匹配器', filterRequired: '请选择过滤器1', unavailable: '—', systemManagedNotice: '系统规则由签名平台策略管理，当前页面只支持启用状态切换。', systemReadOnly: '系统规则组由平台统一启停，当前账号只能查看和在网站中选用。' },
    confirm: { delete: '确认删除该匹配器或过滤器？' },
    notices: { create: '已创建', update: '已更新', delete: '已删除', state: '状态已更新' },
    unavailable: { matcher: '匹配器', filter: '过滤器' },
  },
  waf: {
    title: 'WAF 规则库', count: '{{count}} 个',
    actions: { addRule: '新增规则库', search: '查询', updateSubscription: '立即更新订阅', batch: '批量操作', refresh: '刷新', clear: '清除', deleteSelected: '删除选中（{{count}}）', deleteSelectedConfirm: '删除选中的 {{count}} 个规则库？', enableSelected: '启用选中（{{count}}）', enableSelectedConfirm: '启用选中的 {{count}} 个规则库？', disableSelected: '停用选中（{{count}}）', disableSelectedConfirm: '停用选中的 {{count}} 个规则库？' },
    scopes: { global: '全局', site: '站点', system: '系统' },
    batch: {
      resultTitle: '批量操作结果', result: '结果', close: '知道了',
      status: { ok: '成功', unchanged: '无需变更', version_conflict: '版本已变化，请刷新后重试', system_protected: '系统规则库不能批量修改', not_found: '规则库不存在或已删除', forbidden: '无权限', in_use: '仍有站点在使用，未删除', unsupported_kind: '不是 WAF 规则库', idempotency_conflict: '请求冲突，请刷新后重试', rejected: '未通过校验', error: '执行失败，后续未执行', not_attempted: '未执行' },
    },
    filters: { name: '规则库名称', namePlaceholder: '请输入规则库名称', scope: '规则范围', scopeUnavailable: '规则范围', enable: '启用状态' },
    columns: { id: 'ID', name: '名称', type: '类型', scope: '范围', owner: '归属', status: '状态', subscription: '订阅', updated: '更新时间', actions: '操作' },
    pagination: { total: '共 {{count}} 条' },
    values: { custom: '普通', platform: '平台', globalScope: '全局', platformOwner: '平台授权中心', unavailable: '—', userScope: '用户', enabled: '启用', disabled: '停用', notSubscribed: '未订阅', contractNotice: '规则库订阅、系统规则和全局范围字段尚未在当前 Control API 契约中提供；表格仅展示真实安全策略数据。', scopeUnavailable: '当前后端尚未提供 WAF 规则范围筛选契约', subscriptionUnavailable: '当前后端尚未提供 WAF 规则库订阅更新契约', batchUnavailable: '当前后端未提供 WAF 规则库批量写入契约' },
  },
} as const

const enUS = {
  actions: { confirm: 'Confirm', cancel: 'Cancel' },
  cc: {
    tabs: { groups: 'Rule groups', matchers: 'Matchers', filters: 'Filters' },
    actions: { addGroup: 'Add rule group', addMatcher: 'Add matcher', addFilter: 'Add filter', manage: 'Manage', view: 'View', more: 'Batch actions', rowMore: 'More', clear: 'Clear', enable: 'Enable', disable: 'Disable', enableNamed: 'Enable {{name}}', disableNamed: 'Disable {{name}}', refreshList: 'Refresh list', challengePolicies: 'Challenge policies', backToGroups: 'Back to rule groups' },
    filters: { kind: 'Rule type', display: 'Display', status: 'Status', name: 'Rule group name', namePlaceholder: 'Enter rule group name to search', id: 'Rule group ID', idPlaceholder: 'Enter rule group ID', owner: 'User ID', ownerPlaceholder: 'Enter user ID', matcherName: 'Matcher name', matcherNamePlaceholder: 'Enter matcher name to search', matcherId: 'Matcher ID', matcherIdPlaceholder: 'Enter matcher ID', filterName: 'Filter name', filterNamePlaceholder: 'Enter filter name to search', filterId: 'Filter ID', filterIdPlaceholder: 'Enter filter ID' },
    columns: { id: 'ID', name: 'Name', systemRule: 'System rule', type: 'Type', display: 'Display', status: 'Status', sort: 'Order', createdAt: 'Created at' },
    values: { allTypes: 'All types', allVisible: 'All display states', allStatuses: 'All statuses', visible: 'Visible', hidden: 'Hidden', normal: 'Normal', system: 'System rule', custom: 'User rule', unavailable: '—', ruleCount: '{{count}} rules', sortMeta: 'Order {{value}}', empty: 'No data' },
    summary: { label: 'Rule group summary', all: 'All', system: 'System', custom: 'Custom', visible: 'Visible', disabled: 'Disabled' },
    pagination: { total: '{{count}} total' },
    types: { reqRate: 'Request rate', browserVerify: 'Browser verification', fiveSecond: '5-second challenge', click: 'Click verification', simpleClick: 'Simple click verification', slider: 'Slider verification', simpleSlider: 'Simple slider verification', captcha: 'CAPTCHA', rotateImage: 'Rotating image', redirect: '302 redirect', urlAuth: 'URL authentication', challenge: 'Challenge' },
    editor: { createMatcher: 'Add matcher', editMatcher: 'Edit matcher', createFilter: 'Add filter', editFilter: 'Edit filter', name: 'Name', nameRequired: 'Enter a name', description: 'Description', enabled: 'Enabled', field: 'Field', operator: 'Operator', key: 'Field name', values: 'Values', valuesPlaceholder: 'One value per line (commas are part of the value, so a regex may use {2,})', type: 'Type', parameters: 'Advanced parameters (JSON)', parametersInvalid: 'Enter a valid JSON object', parametersHint: 'The common parameters above override fields with the same name here; other fields are saved as is.', withinSecond: 'Window (seconds)', maxReq: 'Max requests', maxReqPerUri: 'Max requests per URL', maxReqPerUriHint: '0 means no limit', targetScopePlaceholder: 'Platform sessions require a tenant scope UUID', ownerPlaceholder: 'Platform sessions require an owner UUID', editGroup: 'Edit rule group', basicInfo: 'Basic information', ruleList: 'Rule list', addRule: 'Add rule', configured: '{{count}} configured', emptyRules: 'No rules', orderNote: 'Rules are matched from top to bottom. Drag to reorder.', more: 'Show more', groupId: 'Rule group ID', sort: 'Order', state: 'State', policyNotice: 'System rules are provided by signed platform policies and must be published from the operator console.', builtIn: 'Built-in rule', remark: 'Remark', matcher: 'Matcher', filterOne: 'Filter 1', filterTwo: 'Filter 2', action: 'Action', flow: 'Mode', block: 'Block', allow: 'Allow', challenge: 'Challenge', stop: 'Stop matching', continue: 'Continue to next rule', matchMode: 'Match mode', flowHelp: 'Continue to next rule: run this filter and continue. Stop matching: run this filter and stop.', matcherBuiltin: 'Match built-in resources', matcherStatic: 'Match static resources', matcherAll: 'Match all resources', matcherPlaceholder: 'Select a matcher', filterOnePlaceholder: 'Select filter 1', filterTwoPlaceholder: 'Select filter 2 (optional)', matcherRequired: 'Select a matcher', filterRequired: 'Select filter 1', unavailable: '—', systemManagedNotice: 'System rules are managed by signed platform policies; this page only supports changing their enabled state.', systemReadOnly: 'System rule groups are enabled or disabled by the platform; this account can only view them and select them for sites.' },
    confirm: { delete: 'Delete this matcher or filter?' },
    notices: { create: 'Created', update: 'Updated', delete: 'Deleted', state: 'State updated' },
    unavailable: { matcher: 'Matcher', filter: 'Filter' },
  },
  waf: {
    title: 'WAF rule library', count: '{{count}}',
    actions: { addRule: 'Add rule library', search: 'Search', updateSubscription: 'Update subscriptions now', batch: 'Batch actions', refresh: 'Refresh', clear: 'Clear', deleteSelected: 'Delete selected ({{count}})', deleteSelectedConfirm: 'Delete the {{count}} selected rule libraries?', enableSelected: 'Enable selected ({{count}})', enableSelectedConfirm: 'Enable the {{count}} selected rule libraries?', disableSelected: 'Disable selected ({{count}})', disableSelectedConfirm: 'Disable the {{count}} selected rule libraries?' },
    scopes: { global: 'Global', site: 'Site', system: 'System' },
    batch: {
      resultTitle: 'Batch results', result: 'Result', close: 'OK',
      status: { ok: 'Done', unchanged: 'No change needed', version_conflict: 'Version changed; refresh and retry', system_protected: 'System libraries cannot be changed in batch', not_found: 'Not found or deleted', forbidden: 'Permission denied', in_use: 'Still used by a site; not deleted', unsupported_kind: 'Not a WAF rule library', idempotency_conflict: 'Request conflict; refresh and retry', rejected: 'Rejected by validation', error: 'Failed; the rest was not run', not_attempted: 'Not run' },
    },
    filters: { name: 'Rule library name', namePlaceholder: 'Enter rule library name', scope: 'Rule scope', scopeUnavailable: 'Rule scope', enable: 'Enabled status' },
    columns: { id: 'ID', name: 'Name', type: 'Type', scope: 'Scope', owner: 'Owner', status: 'Status', subscription: 'Subscription', updated: 'Updated', actions: 'Actions' },
    pagination: { total: '{{count}} total' },
    values: { custom: 'Custom', platform: 'Platform', globalScope: 'Global', platformOwner: 'Platform license center', unavailable: '—', userScope: 'User', enabled: 'Enabled', disabled: 'Disabled', notSubscribed: 'Not subscribed', contractNotice: 'Subscription, system-rule, and global-scope fields are not provided by the current Control API contract; this table shows real security-policy data only.', scopeUnavailable: 'The current backend does not provide WAF rule-scope filtering', subscriptionUnavailable: 'The current backend does not provide WAF rule-library subscription updates', batchUnavailable: 'The current backend does not provide a WAF rule-library batch-write contract' },
  },
} as const

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, pseudo(item)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
})) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages as Messages, true, true)
}

export { zhCN as securityPoliciesReferenceZhCN, enUS as securityPoliciesReferenceEnUS }
