import i18n from './index'

// The "control database pool" card of System maintenance → System
// (pages/ControlDBPoolPanel.tsx, GET /v1/admin/system-db-pool).
const zhCN = {
  title: '主控数据库连接池',
  description: '应答本页的主控进程每 {{interval}} 秒采样一次自己的数据库连接池；请求排队等待连接时通知平台管理员（站内消息、邮件/短信）。',
  instance: '实例 {{name}}',
  healthy: '连接池正常',
  firing: '连接池满载：请求在排队等待连接',
  firingSince: '自 {{time}} 起，原因：{{reasons}}',
  folded: '距上次告警不足 {{minutes}} 分钟，本次未重复通知；仍未恢复则窗口过后补发。',
  pending: '{{count}} 条告警通知写入失败，下个周期重试。',
  reasonSeparator: '、',
  reason: { saturated: '连接已用满', slow_acquire: '平均等待超过阈值', canceled_acquire: '请求等不到连接而放弃' },
  inUse: '使用中 / 上限',
  idle: '空闲',
  constructing: '建立中',
  residentConns: '常驻连接',
  requestShare: '留给请求',
  requestShareValue: '空闲 {{free}} / 共 {{capacity}}',
  queued: '本周期排队',
  canceled: '本周期放弃',
  avgWait: '平均等待',
  ms: '{{value}} 毫秒',
  lastHour: '最近 1 小时',
  peakInUse: '峰值使用',
  totalQueued: '累计排队',
  totalCanceled: '累计放弃',
  maxWait: '最长平均等待',
  noSample: '刚启动，{{interval}} 秒后出第一个采样。',
  residents: '常驻连接明细',
  residentsEmpty: '当前没有常驻连接',
  residentInPool: '占用连接池',
  residentOutOfPool: '已移出连接池（只占数据库连接数）',
  residentSince: '自 {{time}}',
  residentName: {
    market_security_listen: '节点市场安全策略监听（LISTEN）',
    node_artifact_delivery_listen: '节点制品下发监听（LISTEN）',
    package_traffic_wake_listen: '套餐流量执行唤醒监听（LISTEN）',
    aggregated_edge_quota_lock: '聚合边缘配额锁（会话锁）',
    dns_credential_rewrap_lock: 'DNS 凭据重新加密任务锁（会话锁）',
  },
  rule: '判定：连续 {{enter}} 次采样满载（使用 ≥ 上限 − {{margin}}）或平均等待超过 {{slow}} 毫秒、或满载/排队时有请求放弃即告警；连续 {{recover}} 次正常即恢复；{{dedup}} 分钟内反复只通知一次。',
  lastNotified: '上次告警通知：{{time}}',
  failed: '连接池状态读取失败',
  forbidden: '没有查看连接池的权限',
  missing: '当前主控版本不提供连接池监控',
  retry: '重试',
}

const enUS: typeof zhCN = {
  title: 'Control database pool',
  description: 'The control-api process answering this page samples its own database pool every {{interval}} seconds and notifies platform administrators (message center, email/SMS) when requests queue for connections.',
  instance: 'Instance {{name}}',
  healthy: 'Pool healthy',
  firing: 'Pool saturated: requests are queueing for connections',
  firingSince: 'Since {{time}}, reasons: {{reasons}}',
  folded: 'Less than {{minutes}} minutes after the last alert, so this one was not notified again; it is sent once the window passes if it has not recovered.',
  pending: '{{count}} alert notification write(s) failed and will be retried next cycle.',
  reasonSeparator: ', ',
  reason: { saturated: 'connections exhausted', slow_acquire: 'average wait over the threshold', canceled_acquire: 'a request gave up waiting' },
  inUse: 'In use / max',
  idle: 'Idle',
  constructing: 'Opening',
  residentConns: 'Resident',
  requestShare: 'Left for requests',
  requestShareValue: '{{free}} free of {{capacity}}',
  queued: 'Queued this cycle',
  canceled: 'Gave up this cycle',
  avgWait: 'Average wait',
  ms: '{{value}} ms',
  lastHour: 'Last hour',
  peakInUse: 'Peak in use',
  totalQueued: 'Total queued',
  totalCanceled: 'Total gave up',
  maxWait: 'Worst average wait',
  noSample: 'Just started; the first sample comes in {{interval}} seconds.',
  residents: 'Resident connections',
  residentsEmpty: 'No resident connections',
  residentInPool: 'Uses the pool',
  residentOutOfPool: 'Out of the pool (database connection only)',
  residentSince: 'since {{time}}',
  residentName: {
    market_security_listen: 'Node market security listener (LISTEN)',
    node_artifact_delivery_listen: 'Node artifact delivery listener (LISTEN)',
    package_traffic_wake_listen: 'Package traffic enforcement wake-up (LISTEN)',
    aggregated_edge_quota_lock: 'Aggregated edge quota lock (session lock)',
    dns_credential_rewrap_lock: 'DNS credential rewrap job lock (session lock)',
  },
  rule: 'Rule: {{enter}} samples in a row saturated (in use ≥ max − {{margin}}) or averaging over {{slow}} ms, or a request giving up while the pool is full or queued, raise the alert; {{recover}} clean samples in a row recover it; repeats within {{dedup}} minutes are notified once.',
  lastNotified: 'Last alert notification: {{time}}',
  failed: 'Could not read the pool status',
  forbidden: 'You are not allowed to view the pool',
  missing: 'This control version has no pool monitor',
  retry: 'Retry',
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map((part) => part.startsWith('{{') ? part : part.replace(/[A-Za-z一-鿿]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const controlDBPoolMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(controlDBPoolMessages)) {
  i18n.addResourceBundle(locale, 'controlDBPool', messages, true, true)
}
