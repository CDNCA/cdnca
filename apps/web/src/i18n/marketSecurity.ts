import i18n from './index'

// Attack log page: source filter and the market supply panel (ML-21).
const zhCN = {
  source: { label: '来源', local: '本地节点', market: '市场供给', marketLeaf: '市场供给 · {{leaf}}' },
  table: { detector: '检测器', source: '来源' },
  hint: '经市场供给的站点由供货商节点拦截，拦截与仅记录的事件每 5 分钟回传一次，只含客户端 IP、域名、路径与命中规则。',
  action: { label: '处置', all: '全部', block: '拦截', challenge: '挑战', temporary_ban: '封禁', log: '仅记录' },
  counts: { label: '所选时间与站点内的请求数', hint: '按回传摘要统计，域名、客户端 IP 与处置筛选不影响计数' },
} as const

const enUS = {
  source: { label: 'Source', local: 'Local nodes', market: 'Market supply', marketLeaf: 'Market supply · {{leaf}}' },
  table: { detector: 'Detector', source: 'Source' },
  hint: 'Sites served through market supply are protected on the supplier\'s nodes; blocked and log-only events are relayed every 5 minutes with client IP, host, path and the matched rule only.',
  action: { label: 'Decision', all: 'All', block: 'Blocked', challenge: 'Challenged', temporary_ban: 'Banned', log: 'Log only' },
  counts: { label: 'Requests in the selected time and site', hint: 'From the relayed summaries; host, client IP and decision filters do not change the counts' },
} as const

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'marketSecurity', messages, true, true)
}
