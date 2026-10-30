import i18n from './index'

type Messages = { [key: string]: string | Messages }

const zhCN = {
  title: '节点同步隔离',
  actions: { refresh: '刷新', retry: '重试' },
  filters: {
    status: '隔离状态', all: '全部', isolated: '已隔离', active: '已恢复',
    search: '搜索节点 ID、配置版本或原因码',
  },
  columns: {
    node: '节点 ID', status: '状态', desired: '期望配置', failures: '连续失败',
    confirmations: '恢复确认', outcome: '最近结果', reason: '原因', updatedAt: '更新时间',
  },
  status: { active: '正常发布', isolated: '已隔离' },
  outcome: { succeeded: '成功', failed: '失败', unknown: '结果未知' },
  reasons: {
    healthy: '健康', sync_failure_pending: '同步失败待确认', sync_failure_threshold: '连续同步失败',
    sync_outcome_unknown: '同步结果未知', active_config_identity_mismatch: '当前配置身份不匹配',
    health_evidence_stale: '健康证据过期或重复', recovery_confirmation_pending: '连续健康确认中',
    recovered: '已恢复', operation_outcome_uncertain: '操作结果待确认',
  },
  summary: { isolated: '{{count}} 个节点已隔离，其他健康节点继续接收配置。' },
  states: { loading: '正在加载节点隔离状态', empty: '暂无节点隔离记录', filteredEmpty: '当前筛选无匹配记录' },
  errors: {
    forbiddenTitle: '无权查看节点隔离状态', forbiddenDescription: '当前账号缺少 nodes.read 权限',
    loadFailed: '节点隔离状态加载失败', node_isolation_unavailable: '隔离状态暂不可用，请稍后重试',
    network_error: '网络连接失败，请检查连接后重试', invalid_response: '服务返回了无法验证的数据',
    request_failed: '请求失败，请稍后重试',
  },
} satisfies Messages

const enUS = {
  title: 'Node Sync Isolation',
  actions: { refresh: 'Refresh', retry: 'Retry' },
  filters: {
    status: 'Isolation status', all: 'All', isolated: 'Isolated', active: 'Recovered',
    search: 'Search node ID, config version, or reason code',
  },
  columns: {
    node: 'Node ID', status: 'Status', desired: 'Desired config', failures: 'Failures',
    confirmations: 'Recovery checks', outcome: 'Latest result', reason: 'Reason', updatedAt: 'Updated',
  },
  status: { active: 'Publishing', isolated: 'Isolated' },
  outcome: { succeeded: 'Succeeded', failed: 'Failed', unknown: 'Unknown result' },
  reasons: {
    healthy: 'Healthy', sync_failure_pending: 'Sync failure pending', sync_failure_threshold: 'Consecutive sync failures',
    sync_outcome_unknown: 'Sync outcome unknown', active_config_identity_mismatch: 'Active config identity mismatch',
    health_evidence_stale: 'Stale or duplicate health evidence', recovery_confirmation_pending: 'Confirming recovery',
    recovered: 'Recovered', operation_outcome_uncertain: 'Operation outcome uncertain',
  },
  summary: { isolated: '{{count}} nodes are isolated. Healthy nodes continue receiving configuration.' },
  states: { loading: 'Loading node isolation state', empty: 'No node isolation records', filteredEmpty: 'No matching records' },
  errors: {
    forbiddenTitle: 'Node isolation access denied', forbiddenDescription: 'This account lacks nodes.read',
    loadFailed: 'Unable to load node isolation state', node_isolation_unavailable: 'Isolation state is temporarily unavailable',
    network_error: 'Network connection failed', invalid_response: 'The service returned unverifiable data',
    request_failed: 'Request failed',
  },
} satisfies Messages

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    typeof item === 'string' ? `[!! ${item} ${'x'.repeat(Math.max(4, Math.ceil(item.length / 3)))} !!]` : pseudo(item),
  ]))
}

export const nodeIsolationResources = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(enUS),
  'qps-Ploc': pseudo(enUS),
}

for (const [locale, messages] of Object.entries(nodeIsolationResources)) {
  i18n.addResourceBundle(locale, 'nodeIsolation', messages, true, true)
}
