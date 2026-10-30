import i18n from './index'

/* The dashboard is loaded before the page resources in some production
 * bundles.  Register the page-only additions explicitly so a stale base
 * resource cannot render namespace keys as visible labels. */
const zhCN = {
  charts: { registrationTooltip: '{b}: {c} 人' },
  sections: {
    registration: '注册用户',
    usage: '使用统计', enhancements: '平台增强数据', entitlement: '系统授权', monitoring: '监控趋势', systemStatus: '系统状态',
  },
  metrics: { domainsTotal: '域名数', forwardsTotal: '转发数', certificatesShort: '证书', soldPackages: '已售套餐', peakBandwidth: '带宽峰值', blockedIPCount: '拉黑IP数' },
  values: { noData: '无数据' },
  entitlement: {
    refresh: '刷新授权', refreshSuccess: '授权已刷新', refreshFailed: '授权刷新失败，请稍后重试', refreshInProgress: '授权刷新正在进行，请等候并查看最新状态',
    refreshNotDone: '授权检查未完成，当前授权未改变，可以重试', refreshUnknown: '授权检查结果待确认，请以重新读取到的序列号与状态为准核对，不要重复提交',
    refreshApplied: '授权已更新，但审计记录未写入，请以重新读取到的序列号与状态为准', refreshLocked: '主控授权已锁定，已改为执行锁定状态的重新检查',
    refreshRequestId: '请求 ID：{{id}}',
    rereadConfirmed: '已重新读取当前授权：序列号 {{serial}}，状态 {{status}}，最近检查 {{time}}。', rereadEffective: '本次检查已生效。',
    rereadNotSeen: '未看到本次检查写入的新记录，授权仍按上述状态生效，可稍后再检查。', rereadFailed: '重新读取当前授权失败，结果仍待确认，请稍后重新读取，不要重复提交', reread: '重新读取',
    showDetails: '查看授权详情', hideDetails: '收起授权详情', details: '授权详情', serial: '当前序列号', state: '授权状态', lastVerified: '最近检查时间',
    status: { uninstalled: '未安装', valid: '有效', grace: '宽限中', expired: '已过期', revoked: '已吊销', invalid: '无效' },
    graceWarning: '本地租约已过期，仍在宽限期，剩余 {{count}} 天。宽限期内现有套餐与功能照常使用，升级需要有效租约；宽限期结束后，新建、扩容和功能变更会被拒绝，已在运行的边缘服务不会立即中断。请点「刷新授权」并查看结果。',
  },
  authorization: { licensedNodes: '授权节点', currentNode: '当前节点', expiresAt: '到期时间', operation: '操作' },
  usage: { domainsTotal: '域名数', forwardsTotal: '转发数', certificatesShort: '证书' },
  profile: {
    platformAdmin: '平台管理员', accountId: '账号ID', lastLogin: '最近登录', loginIp: '登录IP', notProvided: '当前会话未提供', edit: '编辑个人资料',
    greeting: { lateNight: '凌晨好，夜深了，请注意休息', morning: '早上好，一天之计在于晨', afternoon: '下午好，工作顺利吗？不要忘记休息', evening: '晚上好，放松一下，为自己倒杯茶吧' },
  },
  status: { controlPlane: '主控状态', analytics: '分析服务', agent: 'Agent状态', available: '正常', unavailable: '暂不可用', lastChecked: 'Agent状态上次检查时间 {{date}}。', checkNow: '立即检查', agentStale: '{{count}} 个节点离线或超过 {{seconds}} 秒未上报心跳，请到节点列表查看', agentUnreadable: '节点状态读取失败，请稍后重试' },
  states: { analyticsLoading: '分析数据加载中' },
} as const

const enUS = {
  charts: { registrationTooltip: '{b}: {c} people' },
  sections: {
    registration: 'Registered users',
    usage: 'Usage statistics', enhancements: 'Platform diagnostics', entitlement: 'System authorization', monitoring: 'Monitoring trend', systemStatus: 'System status',
  },
  metrics: { domainsTotal: 'Domains', forwardsTotal: 'Forwards', certificatesShort: 'Certificates', soldPackages: 'Sold packages', peakBandwidth: 'Peak bandwidth', blockedIPCount: 'Blocked IPs' },
  values: { noData: 'No data' },
  entitlement: {
    refresh: 'Refresh authorization', refreshSuccess: 'Authorization refreshed', refreshFailed: 'Authorization refresh failed. Try again later.', refreshInProgress: 'An authorization refresh is in progress. Wait and check the latest status.',
    refreshNotDone: 'The authorization check did not complete. The current authorization is unchanged; you can retry.', refreshUnknown: 'Authorization check result unknown. Check the re-read serial and status before submitting again.',
    refreshApplied: 'The authorization was updated, but the audit record was not written. Rely on the re-read serial and status.', refreshLocked: 'The controller license is locked; ran the lock check instead.',
    refreshRequestId: 'Request ID: {{id}}',
    rereadConfirmed: 'Current authorization re-read: serial {{serial}}, state {{status}}, last checked {{time}}. ', rereadEffective: 'This check took effect.',
    rereadNotSeen: 'No new record from this check was seen; the authorization above stays in effect. You can check again later.', rereadFailed: 'Re-reading the current authorization failed; the result is still unknown. Re-read later instead of submitting again.', reread: 'Re-read',
    showDetails: 'Show authorization details', hideDetails: 'Hide authorization details', details: 'Authorization details', serial: 'Current serial', state: 'Authorization state', lastVerified: 'Last checked',
    status: { uninstalled: 'Not installed', valid: 'Valid', grace: 'In grace', expired: 'Expired', revoked: 'Revoked', invalid: 'Invalid' },
    graceWarning: 'The local lease has expired and is in its grace period: {{count}} days left. Existing plans and features keep working, upgrades need a valid lease; after the grace period, creating, scaling and feature changes are refused, while running edge traffic is not cut off at once. Use "Refresh authorization" to check again and see the result.',
  },
  authorization: { licensedNodes: 'Authorized nodes', currentNode: 'Current node', expiresAt: 'Expiration', operation: 'Operation' },
  usage: { domainsTotal: 'Domains', forwardsTotal: 'Forwards', certificatesShort: 'Certificates' },
  profile: {
    platformAdmin: 'Platform administrator', accountId: 'Account ID', lastLogin: 'Last login', loginIp: 'Login IP', notProvided: 'Not provided by this session', edit: 'Edit profile',
    greeting: { lateNight: 'Good evening. Take some time to unwind.', morning: 'Good morning. A new day has begun.', afternoon: 'Good afternoon. Have a productive day.', evening: 'Good evening. Take some time to unwind.' },
  },
  status: { controlPlane: 'Control plane', analytics: 'Analytics service', agent: 'Agent status', available: 'Healthy', unavailable: 'Unavailable', lastChecked: 'Last checked: {{date}}', checkNow: 'Check now', agentStale: '{{count}} node(s) offline or without a heartbeat for over {{seconds}} seconds; see the node list', agentUnreadable: 'Node status could not be read, please retry later' },
  states: { analyticsLoading: 'Loading analytics data' },
} as const

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{')
    ? part
    : [...part].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')).join('')}］`
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const bundles: Record<string, unknown> = { 'zh-CN': zhCN, 'en-US': enUS }
if (import.meta.env.MODE === 'test') {
  bundles['qps-ploc'] = pseudoTree(zhCN)
  bundles['qps-Ploc'] = bundles['qps-ploc']
}

for (const [locale, messages] of Object.entries(bundles)) {
  i18n.addResourceBundle(locale, 'adminHome', messages, true, true)
}
