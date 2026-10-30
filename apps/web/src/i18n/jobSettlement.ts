import i18n from './index'

type JobSettlementMessageTree = {
  [key: string]: string | JobSettlementMessageTree
}

type MessageShape<T> = {
  [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]>
}

const zhCN = {
  receipts: {
    title: '结算回执',
    loading: '结算回执加载中',
    empty: '暂无结算回执',
    loadFailed: '结算回执加载失败',
    columns: {
      ordinal: '序号', item: '项目 ID', node: '节点 ID', status: '状态', attempt: '尝试次数',
      sequence: '序列号', source: '来源', reportedAt: '回报时间', failureCode: '失败原因',
    },
    previous: '上一页回执',
    next: '下一页回执',
  },
  deadLetters: {
    title: '死信记录',
    loading: '死信记录加载中',
    empty: '暂无死信记录',
    loadFailed: '死信记录加载失败',
    columns: { attempt: '尝试次数', reason: '原因码', failedItems: '失败项目数', source: '来源', createdAt: '记录时间' },
    previous: '上一页死信',
    next: '下一页死信',
  },
  sources: { worker: '工作进程', system: '系统', lease_expiry: '租约到期' },
  states: { succeeded: '已成功', failed: '失败' },
  reasons: { all_items_failed: '全部项目失败', item_failed: '项目失败', retries_exhausted: '重试次数已耗尽' },
  errors: {
    job_permission_denied: '当前账号无权查看任务结算信息',
    job_scope_forbidden: '当前账号不能查看此任务作用域',
    job_not_found: '任务不存在或不可见',
    job_store_unavailable: '任务结算服务暂不可用，请稍后重试',
    job_query_timeout: '任务结算查询超时，请稍后重试',
    invalid_response: '任务结算服务响应无效，请稍后重试',
    network_error: '无法连接任务结算服务，请稍后重试',
    request_failed: '任务结算查询失败，请稍后重试',
  },
} as const

const enUS = {
  receipts: {
    title: 'Settlement receipts',
    loading: 'Loading settlement receipts',
    empty: 'No settlement receipts',
    loadFailed: 'Failed to load settlement receipts',
    columns: {
      ordinal: 'Ordinal', item: 'Item ID', node: 'Node ID', status: 'Status', attempt: 'Attempt',
      sequence: 'Sequence', source: 'Source', reportedAt: 'Reported at', failureCode: 'Failure reason',
    },
    previous: 'Previous receipts page',
    next: 'Next receipts page',
  },
  deadLetters: {
    title: 'Dead-letter records',
    loading: 'Loading dead-letter records',
    empty: 'No dead-letter records',
    loadFailed: 'Failed to load dead-letter records',
    columns: { attempt: 'Attempt', reason: 'Reason code', failedItems: 'Failed items', source: 'Source', createdAt: 'Recorded at' },
    previous: 'Previous dead-letter page',
    next: 'Next dead-letter page',
  },
  sources: { worker: 'Worker', system: 'System', lease_expiry: 'Lease expiry' },
  states: { succeeded: 'Succeeded', failed: 'Failed' },
  reasons: { all_items_failed: 'All items failed', item_failed: 'Item failed', retries_exhausted: 'Retries exhausted' },
  errors: {
    job_permission_denied: 'Your account cannot view task settlement facts',
    job_scope_forbidden: 'Your account cannot view this task scope',
    job_not_found: 'The task does not exist or is not visible',
    job_store_unavailable: 'The task settlement service is unavailable. Try again later.',
    job_query_timeout: 'The task settlement query timed out. Try again later.',
    invalid_response: 'The task settlement service returned invalid data. Try again later.',
    network_error: 'Unable to connect to the task settlement service. Try again later.',
    request_failed: 'The task settlement request failed. Try again later.',
  },
} satisfies MessageShape<typeof zhCN>

function pseudoText(value: string): string {
  return `［${[...value].map((character) => (/\s/u.test(character) ? character : `${character}~`)).join('')}］`
}

function pseudoTree(tree: JobSettlementMessageTree): JobSettlementMessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key, typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudoCN = pseudoTree(zhCN)

export const jobSettlementMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', JobSettlementMessageTree
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(jobSettlementMessages)) {
  i18n.addResourceBundle(locale, 'jobSettlement', messages, true, true)
}
