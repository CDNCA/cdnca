import i18n from './index'

type Messages = { [key: string]: string | Messages }

const zhCN = {
  actions: { apply: '应用筛选', clear: '清除筛选' },
  filters: {
    site: '网站 ID', node: '节点 ID', sitePlaceholder: '规范小写 UUID', nodePlaceholder: '规范小写 UUID',
    invalid: '请输入规范的小写 UUID',
  },
  sections: {
    accountSecurity: '账户安全', network: '网络概览', trend: '流量趋势', top: 'TOP10', packageProgress: '套餐进度',
  },
  ranges: { networkLabel: '网络概览时间范围', monitorLabel: '监控趋势时间范围', today: '今日', yesterday: '昨日', sevenDays: '近7日', thirtyDays: '近30日' },
  metrics: {
    activeSessions: '有效会话', usersWithMfa: '已启用 MFA 用户', activeApiKeys: '有效 API 密钥',
    recoveryCodes: '剩余恢复码', lastSecurityEvent: '最近安全事件', nodesTotal: '节点总数',
    nodesActive: '启用节点', nodesOnline: '在线节点', nodesStale: '离线或陈旧',
    domainsTotal: '域名总数', packageTrafficUsed: '已用流量', finalizedThrough: '已终结至', sourceWatermark: '来源水位',
  },
  charts: { bandwidth: '带宽', requests: '请求数', traffic: '流量', blocked: '拉黑IP数', empty: '当前筛选范围暂无趋势数据', unavailable: '趋势图加载失败' },
  top: {
    title: 'TOP10 数据', adminTitle: 'TOP10 数据 (近30分钟)', domain: '域名', region: '地区', carrier: '运营商', url: 'URL', ip: 'IP', urlUnavailable: 'URL', ipUnavailable: 'IP', country: '国家',
    key: '项目', requests: '请求数', traffic: '响应流量', empty: '暂无排行数据', previous: '上一组排行', next: '下一组排行',
  },
  network: { region: '地区', nodes: '节点', online: '在线', unassigned: '未分配' },
  values: { placeholder: '—' },
  settling: '最近 {{count}} 分钟数据仍在结算',
} as const

const enUS = {
  actions: { apply: 'Apply filters', clear: 'Clear filters' },
  filters: {
    site: 'Site ID', node: 'Node ID', sitePlaceholder: 'Canonical lowercase UUID', nodePlaceholder: 'Canonical lowercase UUID',
    invalid: 'Enter a canonical lowercase UUID',
  },
  sections: {
    accountSecurity: 'Account security', network: 'Network overview', trend: 'Traffic trend', top: 'TOP10', packageProgress: 'Package progress',
  },
  ranges: { networkLabel: 'Network overview time range', monitorLabel: 'Monitoring trend time range', today: 'Today', yesterday: 'Yesterday', sevenDays: 'Last 7 days', thirtyDays: 'Last 30 days' },
  metrics: {
    activeSessions: 'Active sessions', usersWithMfa: 'Users with MFA', activeApiKeys: 'Active API keys',
    recoveryCodes: 'Recovery codes left', lastSecurityEvent: 'Last security event', nodesTotal: 'Nodes',
    nodesActive: 'Active nodes', nodesOnline: 'Online nodes', nodesStale: 'Offline or stale',
    domainsTotal: 'Domains', packageTrafficUsed: 'Traffic used', finalizedThrough: 'Finalized through', sourceWatermark: 'Source watermark',
  },
  charts: { bandwidth: 'Bandwidth', requests: 'Requests', traffic: 'Traffic', blocked: 'Blocked IP count', empty: 'No trend data for these filters', unavailable: 'Unable to render the trend chart' },
  top: {
    title: 'TOP10 data', adminTitle: 'TOP10 data (last 30 minutes)', domain: 'Domain', region: 'Region', carrier: 'Carrier', url: 'URL', ip: 'IP', urlUnavailable: 'URL', ipUnavailable: 'IP', country: 'Country',
    key: 'Item', requests: 'Requests', traffic: 'Response traffic', empty: 'No ranking data', previous: 'Previous rankings', next: 'Next rankings',
  },
  network: { region: 'Region', nodes: 'Nodes', online: 'Online', unassigned: 'Unassigned' },
  values: { placeholder: '—' },
  settling: 'Data from the last {{count}} minutes is still settling',
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

const pseudo = pseudoTree(zhCN) as Messages

export const dashboardOverviewMessages = {
  'zh-CN': zhCN,
  'en-US': enUS,
} as unknown as Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages>

if (import.meta.env.MODE === 'test') {
  Object.assign(dashboardOverviewMessages, {
    'qps-ploc': pseudo,
    'qps-Ploc': pseudo,
  })
}

for (const [locale, messages] of Object.entries(dashboardOverviewMessages)) {
  i18n.addResourceBundle(locale, 'dashboardOverview', messages, true, true)
}
