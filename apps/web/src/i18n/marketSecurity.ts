import i18n from './index'

// Attack log page: source filter and the market supply panel (ML-21).
const zhCN = {
  source: { label: '来源', local: '本地节点', market: '市场供给', marketLeaf: '市场供给 · {{leaf}}' },
  table: { detector: '检测器', source: '来源' },
  hint: '经市场供给的站点由供货商节点拦截，拦截记录每 5 分钟回传一次，只含客户端 IP、域名、路径与命中规则。',
} as const

const enUS = {
  source: { label: 'Source', local: 'Local nodes', market: 'Market supply', marketLeaf: 'Market supply · {{leaf}}' },
  table: { detector: 'Detector', source: 'Source' },
  hint: 'Sites served through market supply are blocked on the supplier\'s nodes; their blocks are relayed every 5 minutes with client IP, host, path and the matched rule only.',
} as const

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'marketSecurity', messages, true, true)
}
