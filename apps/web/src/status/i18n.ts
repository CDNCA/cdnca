// 公开状态页 /status/ 的中英词条（独立入口，不加载控制台的 i18next）。
const zhCN = {
  defaultTitle: '服务状态',
  language: 'English',
  languageHref: 'en',
  banner: {
    operational: '所有服务运行正常',
    degraded: '部分服务降级',
    outage: '部分服务中断',
    maintenance: '维护进行中',
  },
  status: { operational: '正常', degraded: '降级', outage: '中断', maintenance: '维护中', no_data: '无数据' },
  impact: { degraded: '降级', outage: '中断', maintenance: '维护' },
  incidentStatus: {
    investigating: '调查中', identified: '已定位', monitoring: '监控中', resolved: '已恢复',
    scheduled: '已计划', in_progress: '进行中', completed: '已完成',
  },
  updatedAt: '更新于 {time}',
  stale: '数据可能已过期',
  active: '正在处理',
  upcoming: '计划维护',
  components: '服务组件',
  recent: '近 14 天',
  noRecent: '近 14 天没有事件。',
  noComponents: '尚未配置组件。',
  uptime90: '90 天可用率 {value}',
  uptimeNone: '90 天可用率 无数据',
  days90: '90 天前',
  days30: '30 天前',
  today: '今天',
  dayDetail: '{day}：{status}',
  dayDetailUptime: '{day}：{status}，可用率 {value}',
  affected: '受影响：{names}',
  listSeparator: '、',
  window: '{start} 至 {end}',
  disabledTitle: '状态页未开启',
  disabledBody: '服务方尚未公开状态页。',
  errorTitle: '暂时无法获取服务状态',
  retry: '重试',
  poweredBy: '由 {title} 提供',
  historyLabel: '{name} 每日状态',
}
type Messages = typeof zhCN
const enUS: Messages = {
  defaultTitle: 'Service status',
  language: '中文',
  languageHref: 'zh',
  banner: {
    operational: 'All systems operational',
    degraded: 'Some services are degraded',
    outage: 'Some services are down',
    maintenance: 'Maintenance in progress',
  },
  status: { operational: 'Operational', degraded: 'Degraded', outage: 'Outage', maintenance: 'Maintenance', no_data: 'No data' },
  impact: { degraded: 'Degraded', outage: 'Outage', maintenance: 'Maintenance' },
  incidentStatus: {
    investigating: 'Investigating', identified: 'Identified', monitoring: 'Monitoring', resolved: 'Resolved',
    scheduled: 'Scheduled', in_progress: 'In progress', completed: 'Completed',
  },
  updatedAt: 'Updated {time}',
  stale: 'Data may be out of date',
  active: 'Ongoing',
  upcoming: 'Scheduled maintenance',
  components: 'Components',
  recent: 'Last 14 days',
  noRecent: 'No incidents in the last 14 days.',
  noComponents: 'No components configured yet.',
  uptime90: '{value} uptime over 90 days',
  uptimeNone: 'No uptime data for 90 days',
  days90: '90 days ago',
  days30: '30 days ago',
  today: 'Today',
  dayDetail: '{day}: {status}',
  dayDetailUptime: '{day}: {status}, {value} uptime',
  affected: 'Affected: {names}',
  listSeparator: ', ',
  window: '{start} to {end}',
  disabledTitle: 'Status page is not enabled',
  disabledBody: 'The provider has not made its status page public.',
  errorTitle: 'Service status is unavailable right now',
  retry: 'Retry',
  poweredBy: 'Provided by {title}',
  historyLabel: 'Daily status of {name}',
}

export type Lang = 'zh' | 'en'

export function pickLang(search: string, languages: readonly string[]): Lang {
  const query = new URLSearchParams(search).get('lang')
  if (query === 'zh' || query === 'en') return query
  return languages.find((value) => /^(zh|en)\b/i.test(value))?.toLowerCase().startsWith('en') ? 'en' : 'zh'
}

export function messages(lang: Lang): Messages {
  return lang === 'en' ? enUS : zhCN
}

export function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (match, key: string) => values[key] ?? match)
}
