import i18n from './index'

export interface AdminTasksParityText {
  bulkCancelAria: string
  taskID: string
  taskIDPlaceholder: string
  resourcePrefix: string
  invalidTaskID: string
  bulkCancelTitle: string
  bulkCancelDescription: string
  selectTaskFirst: string
  bulkCancelPartial: string
  bulkCancelRetry: string
}

const zhCN: AdminTasksParityText = {
  bulkCancelAria: '批量操作',
  taskID: '任务ID',
  taskIDPlaceholder: '任务ID',
  resourcePrefix: '资源ID',
  invalidTaskID: '任务 ID 必须是有效的 UUID',
  bulkCancelTitle: '确认批量取消任务',
  bulkCancelDescription: '将取消选中的 {{count}} 个任务，取消后不会再派发新的执行步骤。',
  selectTaskFirst: '请先选择要取消的任务。',
  bulkCancelPartial: '已取消 {{cancelled}} 个，失败 {{failed}} 个',
  bulkCancelRetry: '重试失败项',
}

const enUS: AdminTasksParityText = {
  bulkCancelAria: 'Bulk actions',
  taskID: 'Task ID',
  taskIDPlaceholder: 'Task ID',
  resourcePrefix: 'Resource ID',
  invalidTaskID: 'The task ID must be a valid UUID',
  bulkCancelTitle: 'Confirm bulk task cancellation',
  bulkCancelDescription: 'Cancel {{count}} selected tasks. No new execution steps will be dispatched after cancellation.',
  selectTaskFirst: 'Select at least one task to cancel.',
  bulkCancelPartial: '{{cancelled}} cancelled, {{failed}} failed',
  bulkCancelRetry: 'Retry failed',
}

export function adminTasksParityText(locale: string | undefined): AdminTasksParityText {
  return locale?.toLowerCase().startsWith('en') ? enUS : zhCN
}

const taskFactsZhCN = {
  kindNames: {
    analyticsLogExport: '网站日志导出', cacheOperation: '缓存刷新/预热', dnsCleanup: 'DNS 记录清理',
    dnsRepair: 'DNS 记录修复', dnsReconcile: 'DNS 记录同步', cnameAllocation: 'CNAME 分配',
    cnameIntent: 'CNAME 解析配置', cnameStreamIntent: '四层转发 CNAME 解析配置', edgePublication: '节点配置发布',
    siteStatusRecovery: '网站状态恢复', unknown: '未知任务类型',
  },
  taskFacts: {
    name: '{{kind}} · {{resource}}',
    priority: { ready_fifo: '按就绪顺序', producer_managed: '由任务生产方调度', unknown: '调度方式未确认' },
    dependenciesUnknown: '依赖关系未记录', noDependency: '无依赖', completionDependency: '完成依赖',
    catalogHint: '已接入的任务类型；实际运行状态尚未确认。',
    catalogLoadFailed: '任务类型目录加载失败', catalogRetry: '重试类型目录',
  },
  pagination: { total: '共 {{total}} 条', outOfRange: '当前页已无记录，请返回前面的页码。' },
} as const

const taskFactsEnUS = {
  kindNames: {
    analyticsLogExport: 'Site log export', cacheOperation: 'Cache purge/prewarm', dnsCleanup: 'DNS record cleanup',
    dnsRepair: 'DNS record repair', dnsReconcile: 'DNS record synchronization', cnameAllocation: 'CNAME allocation',
    cnameIntent: 'CNAME configuration', cnameStreamIntent: 'L4 forward CNAME configuration', edgePublication: 'Edge configuration publication',
    siteStatusRecovery: 'Site status recovery', unknown: 'Unknown task type',
  },
  taskFacts: {
    name: '{{kind}} · {{resource}}',
    priority: { ready_fifo: 'Ready-time order', producer_managed: 'Scheduled by producer', unknown: 'Scheduling policy unconfirmed' },
    dependenciesUnknown: 'Dependencies not recorded', noDependency: 'No dependency', completionDependency: 'Completion dependency',
    catalogHint: 'Integrated task types; runtime status has not been confirmed.',
    catalogLoadFailed: 'Failed to load the task type directory', catalogRetry: 'Retry type directory',
  },
  pagination: { total: '{{total}} total', outOfRange: 'This page no longer has records. Return to an earlier page.' },
}

function pseudoTaskFacts(value: unknown): unknown {
  if (typeof value !== 'string') return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .map(([key, entry]) => [key, pseudoTaskFacts(entry)]))
  return `［${value.split(/(\{\{[^}]+\}\})/u).map((part) => part.startsWith('{{')
    ? part : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')}］`
}

export const adminTaskFactMessages = {
  'zh-CN': taskFactsZhCN, 'en-US': taskFactsEnUS,
  'qps-ploc': pseudoTaskFacts(taskFactsZhCN), 'qps-Ploc': pseudoTaskFacts(taskFactsZhCN),
}

for (const [locale, messages] of Object.entries(adminTaskFactMessages)) {
  i18n.addResourceBundle(locale, 'jobs', messages, true, true)
}
