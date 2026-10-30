import i18n from './index'

const zhCN = {
  title: '日志中心',
  subtitle: '所有改变配置和数据的操作都会记录在这里：谁、什么时候、从哪个 IP、改了什么。',
  tabs: { all: '全部', operation: '操作', backup: '备份', sent: '发送记录', attack: '攻击日志', access: '访问日志' },
  categories: {
    admin: '管理员操作', user: '用户操作', auth: '登录与安全', site: '网站配置', security: '防御策略', rule: '规则',
    finance: '财务', package: '套餐', plugin: '插件', node: '节点', dns: 'DNS', cert: '证书', system: '系统', other: '其它',
  },
  filters: {
    range: '时间', actor: '操作人用户名', sourceIp: '来源 IP', resourceType: '对象类型', resourceId: '对象 ID',
    result: '结果', scopeId: '租户范围 ID', search: '查询', reset: '重置', export: '导出 CSV', category: '所有分类',
    title: '筛选',
  },
  results: { success: '成功', denied: '被拒绝', failure: '失败' },
  columns: {
    time: '时间', category: '分类', summary: '内容', actor: '操作人', ip: '来源 IP', result: '结果', detail: '详情',
    tenant: '所属租户', platform: '平台', username: '用户名', object: '对象', geo: '地理位置', userAgent: '浏览器UA', source: '来源',
  },
  detail: {
    title: '日志详情', open: '查看', changes: '改动', field: '字段', before: '改前', after: '改后', noChanges: '没有记录字段改动',
    fields: '其它信息', technical: '技术信息', action: '事件', request: '请求 ID', object: '对象', scope: '范围', reason: '原因',
  },
  pager: { previous: '上一页', next: '下一页', count: '本页 {{count}} 条' },
  states: { loading: '加载中', empty: '没有符合条件的日志', error: '日志读取失败，请稍后重试', invalidRequest: '查询条件无效，请检查时间范围、IP 地址和对象 ID', unavailable: '日志服务暂不可用，请稍后重试', exported: '已导出', forbidden: '没有查看日志的权限', deletedObject: '已删除的对象（{{id}}）' },
  retention: {
    title: '操作日志保留天数', hint: '每个分类单独设置，0 表示永久保留，最多 3650 天。过期日志由清理任务自动归档并删除。',
  },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  title: 'Log center',
  subtitle: 'Every change to configuration and data is recorded here: who, when, from which IP, and what changed.',
  tabs: { all: 'All', operation: 'Operations', backup: 'Backups', sent: 'Sent messages', attack: 'Attack log', access: 'Access log' },
  categories: {
    admin: 'Administration', user: 'User account', auth: 'Sign-in & security', site: 'Site configuration', security: 'Protection policies',
    rule: 'Rules', finance: 'Finance', package: 'Packages', plugin: 'Plugins', node: 'Nodes', dns: 'DNS', cert: 'Certificates',
    system: 'System', other: 'Other',
  },
  filters: {
    range: 'Time', actor: 'Actor username', sourceIp: 'Source IP', resourceType: 'Object type', resourceId: 'Object ID',
    result: 'Result', scopeId: 'Tenant scope ID', search: 'Search', reset: 'Reset', export: 'Export CSV', category: 'All categories',
    title: 'Filters',
  },
  results: { success: 'Succeeded', denied: 'Denied', failure: 'Failed' },
  columns: {
    time: 'Time', category: 'Category', summary: 'Event', actor: 'Actor', ip: 'Source IP', result: 'Result', detail: 'Detail',
    tenant: 'Tenant', platform: 'Platform', username: 'Username', object: 'Object', geo: 'Location', userAgent: 'Browser UA', source: 'Source',
  },
  detail: {
    title: 'Log detail', open: 'View', changes: 'Changes', field: 'Field', before: 'Before', after: 'After', noChanges: 'No field changes recorded',
    fields: 'Other information', technical: 'Technical', action: 'Action', request: 'Request ID', object: 'Object', scope: 'Scope', reason: 'Reason',
  },
  pager: { previous: 'Previous', next: 'Next', count: '{{count}} on this page' },
  states: { loading: 'Loading', empty: 'No matching logs', error: 'Could not load logs. Try again later.', invalidRequest: 'Invalid filters. Check the time range, IP address and object ID.', unavailable: 'The log service is unavailable. Try again later.', exported: 'Exported', forbidden: 'You cannot view logs', deletedObject: 'Deleted object ({{id}})' },
  retention: {
    title: 'Operation log retention', hint: 'Set per category; 0 keeps forever, up to 3650 days. The cleanup job archives and removes expired entries.',
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `[!! ${value} !!]`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const logCenterMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(logCenterMessages)) {
  i18n.addResourceBundle(locale, 'logCenter', messages, true, true)
}
