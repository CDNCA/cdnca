import i18n from './index'

const zhCN = {
  title: '回源设置',
  description: '默认把请求发到默认回源池；添加条件规则后，命中路径、节点区域或访客网段的请求改发到指定回源池。',
  sections: { default: '默认回源', pools: '回源池', routes: '条件规则', retry: '失败重试' },
  fields: {
    ingressSource: '使用入口 IP 回源',
    pool: '默认回源池',
    fallbackPool: '默认备用池',
    balance: '负载方式',
    endpoint: '源站地址',
    port: '端口',
    weight: '权重',
    route: '条件规则',
    routeId: '规则 ID',
    routePool: '回源池',
    routeFallbackPool: '备用回源池',
    priority: '优先级',
    path: '路径前缀',
    regions: '节点区域',
    cidrs: '客户端网段',
    retryMethods: '可重试的请求',
    maxAttempts: '最多尝试',
    connectTimeout: '连接超时',
    readTimeout: '读取超时',
    totalBudget: '总耗时上限',
  },
  columns: { poolName: '名称', conditions: '匹配条件', target: '回源到', actions: '操作' },
  labels: { weight: '权重 {{weight}}', path: '路径 {{value}}', regions: '区域 {{value}}', cidrs: '网段 {{value}}', fallback: '（备用 {{id}}）' },
  units: { ms: '毫秒', times: '次' },
  hints: {
    ingressSource: '开启后，节点用访客访问的那个入口 IP 连接源站，便于源站按 IP 区分来源。节点上没有可用的同类入口 IP 时，本次修改不生效，继续沿用上一版配置。',
    pool: '没有命中任何条件规则的请求发到这里。',
    fallbackPool: '默认回源池全部不可用时改用；不选则不切换。',
    routes: '规则按优先级从高到低匹配，命中第一条即停止。',
    poolInUse: '该回源池正被默认回源、备用池或条件规则使用，或是最后一个回源池，不能删除。',
    retryMethods: '回源失败时，只重试这些请求方法，其它请求不重试。',
    maxAttempts: '含第一次请求在内的总次数。',
    totalBudget: '一次请求所有尝试加起来的最长时间，超过即返回失败。',
  },
  actions: { save: '保存回源设置', retry: '重试', retryExact: '重新提交本次保存', abandonAndReload: '放弃并重新加载', delete: '删除', confirmDeletePool: '删除回源池 {{id}}？', confirmDeleteRoute: '删除条件规则 {{id}}？', deletePool: '删除', addPool: '添加回源池', addRoute: '添加条件规则', edit: '编辑', editRoute: '编辑规则 {{id}}', applyRoute: '应用规则', cancel: '取消', loadLatest: '放弃修改并载入最新', overwriteLatest: '用我的修改覆盖' },
  dialogs: { addRoute: '添加条件规则', editRoute: '编辑条件规则' },
  placeholders: { commaSeparated: '多个值使用英文逗号分隔', none: '不使用' },
  help: { regions: '填区域代号（节点管理 → 区域管理的「代号」列），不是区域名称' },
  algorithms: { round_robin: '轮询', ip_hash: '客户端 IP 哈希', url_hash: 'URL 哈希', least_conn: '最少连接', random: '随机' },
  states: {
    loading: '正在加载回源设置…', empty: '尚未配置回源设置', noRoutes: '暂无条件规则，所有请求都发到默认回源池', forbidden: '当前账号无权查看回源设置',
    loadError: '回源设置加载失败', saved: '回源设置已保存', saveError: '回源设置保存失败', conflict: '配置已被其他人修改，请重新加载后再保存。',
    notFound: '站点不存在或已离开当前租户范围。', validation: '请检查回源设置字段。', unknownResult: '没有收到保存结果。可以重新提交本次保存（不会重复写入），或放弃修改并重新加载。', saving: '正在保存…', readOnly: '当前账号只能查看回源设置。',
    remoteChanged: '其他人已修改了回源设置。你的修改仍保留、暂未保存。可以放弃修改并载入最新配置，或用你的整份修改覆盖对方的修改。',
  },
  errors: { permission: '当前账号无权执行此操作。', notFound: '站点不存在。', conflict: '配置发生冲突，请重试。', precondition: '版本已过期，请重新加载。', validation: '回源设置无效，请检查后重新保存。', request: '请求未完成，请稍后重试。' },
  validation: { required: '请填写必填字段。', host: '请输入合法的单播 IPv4 或 IPv6 地址。', routeId: '规则 ID 仅允许字母、数字、点、下划线和连字符。', path: '路径必须以 / 开头，且不能包含 //、反斜线、问号、井号或百分号。', routePredicate: '规则至少需要路径、区域或客户端网段之一。', duplicateRoute: '规则 ID 已存在。', routeDocument: '规则字段或回源池引用无效。', reference: '回源池引用无效。' },
}

const enUS = {
  title: 'Origin settings',
  description: 'Requests go to the default origin pool. Condition rules send requests that match a path, node region, or visitor network to another pool.',
  sections: { default: 'Default origin', pools: 'Origin pools', routes: 'Condition rules', retry: 'Retry on failure' },
  fields: {
    ingressSource: 'Use ingress IP for origin requests',
    pool: 'Default origin pool', fallbackPool: 'Default fallback pool', balance: 'Load balancing', endpoint: 'Origin address', port: 'Port', weight: 'Weight', route: 'Condition rule', routeId: 'Rule ID', routePool: 'Origin pool', routeFallbackPool: 'Fallback origin pool', priority: 'Priority', path: 'Path prefix', regions: 'Node regions', cidrs: 'Client networks', retryMethods: 'Retryable requests', maxAttempts: 'Maximum attempts', connectTimeout: 'Connect timeout', readTimeout: 'Read timeout', totalBudget: 'Total time limit',
  },
  columns: { poolName: 'Name', conditions: 'Match conditions', target: 'Send to', actions: 'Actions' },
  labels: { weight: 'weight {{weight}}', path: 'Path {{value}}', regions: 'Regions {{value}}', cidrs: 'Networks {{value}}', fallback: ' (fallback {{id}})' },
  units: { ms: 'ms', times: 'times' },
  hints: {
    ingressSource: 'When on, the node connects to the origin from the ingress IP the visitor reached, so the origin can tell sources apart. If the node has no usable ingress IP of that family, the change is not applied and the previous version stays in effect.',
    pool: 'Requests that match no condition rule go here.',
    fallbackPool: 'Used when every origin in the default pool is down. Leave empty to never switch.',
    routes: 'Rules are checked from highest to lowest priority; the first match wins.',
    poolInUse: 'This pool is used by the default origin, the fallback pool, or a condition rule, or it is the last pool, so it cannot be deleted.',
    retryMethods: 'Only these request methods are retried when the origin fails.',
    maxAttempts: 'Total attempts, including the first request.',
    totalBudget: 'Longest time all attempts of one request may take before it fails.',
  },
  actions: { save: 'Save origin settings', retry: 'Retry', retryExact: 'Resubmit this save', abandonAndReload: 'Abandon and reload', delete: 'Delete', confirmDeletePool: 'Delete origin pool {{id}}?', confirmDeleteRoute: 'Delete condition rule {{id}}?', deletePool: 'Delete', addPool: 'Add origin pool', addRoute: 'Add condition rule', edit: 'Edit', editRoute: 'Edit rule {{id}}', applyRoute: 'Apply rule', cancel: 'Cancel', loadLatest: 'Discard my changes and load the latest', overwriteLatest: 'Overwrite with my changes' },
  dialogs: { addRoute: 'Add condition rule', editRoute: 'Edit condition rule' },
  placeholders: { commaSeparated: 'Separate multiple values with commas', none: 'None' },
  help: { regions: 'Enter region codes (the Code column of Nodes → Regions), not region names' },
  algorithms: { round_robin: 'Round robin', ip_hash: 'Client IP hash', url_hash: 'URL hash', least_conn: 'Least connections', random: 'Random' },
  states: {
    loading: 'Loading origin settings…', empty: 'No origin settings configured', noRoutes: 'No condition rules. All requests go to the default origin pool.', forbidden: 'This account cannot view origin settings', loadError: 'Origin settings failed to load', saved: 'Origin settings saved', saveError: 'Origin settings could not be saved', conflict: 'Someone else changed this configuration. Reload before saving.', notFound: 'The site is missing or outside the current tenant scope.', validation: 'Check the origin settings fields.', unknownResult: 'No save result was received. Resubmit this save (it will not be written twice), or abandon your changes and reload.', saving: 'Saving…', readOnly: 'This account can only view origin settings.', remoteChanged: 'Someone else changed the origin settings. Your edits are kept and not saved yet. Discard them and load the latest configuration, or overwrite the other change with your full edits.',
  },
  errors: { permission: 'This account cannot perform this action.', notFound: 'The site was not found.', conflict: 'The configuration conflicts with a newer version.', precondition: 'The version is stale. Reload and try again.', validation: 'The origin settings are invalid. Review them before saving again.', request: 'The request did not complete. Try again later.' },
  validation: { required: 'Complete the required fields.', host: 'Enter a unicast IPv4 or IPv6 address.', routeId: 'Use letters, numbers, periods, underscores, and hyphens only.', path: 'The path must start with / and cannot contain //, backslashes, question marks, hashes, or percent signs.', routePredicate: 'A rule needs a path, region, or client network.', duplicateRoute: 'That rule ID already exists.', routeDocument: 'The rule fields or origin pool reference are invalid.', reference: 'The origin pool reference is invalid.' },
}

type SiteOriginRoutingMessages = typeof zhCN
function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')).join('')
  return `［${expanded}］`
}
function pseudoTree(tree: SiteOriginRoutingMessages): SiteOriginRoutingMessages {
  const mapTree = (value: unknown): unknown => typeof value === 'string' ? pseudoText(value) : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, mapTree(child)]))
  return mapTree(tree) as SiteOriginRoutingMessages
}

const pseudoCN = pseudoTree(zhCN)
export const siteOriginRoutingMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', SiteOriginRoutingMessages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN,
}
for (const [locale, messages] of Object.entries(siteOriginRoutingMessages)) i18n.addResourceBundle(locale, 'siteOriginRouting', messages, true, true)
