import i18n from './index'

type Messages = Record<string, unknown>

// CC rule statistics tab of the CC page.
const zhCN = {
  ccStats: {
    tab: '统计',
    title: 'CC 规则统计',
    help: '节点每 10 秒上报一次，按规则累计命中、触发、挑战、拦截与放行次数，可据此调整阈值。',
    needSite: '请从网站的防护设置进入，查看该网站的 CC 规则统计。',
    needTenant: '平台管理员查看时需要网站所属的租户（链接带 tenant_scope_id）。',
    range: { '1h': '最近 1 小时', '6h': '最近 6 小时', '24h': '最近 24 小时' },
    fields: { matched: '命中', triggered: '触发', challenged: '挑战', blocked: '拦截', passed: '放行', ja4_unavailable: '无 TLS 指纹' },
    columns: { rule: '规则', policy: '策略' },
    siteLevel: '网站级（验证失败封禁）',
    topClients: '触发最多的客户端 IP',
    topPaths: '触发最多的路径',
    count: '次数',
    empty: '这段时间没有 CC 规则活动',
    error: '统计暂不可用，请稍后重试',
    chart: 'CC 规则趋势图',
  },
}

const enUS = {
  ccStats: {
    tab: 'Statistics',
    title: 'CC rule statistics',
    help: 'Nodes report every 10 seconds. Matches, triggers, challenges, blocks and passes are counted per rule to help tune thresholds.',
    needSite: 'Open this page from a site’s protection settings to see its CC rule statistics.',
    needTenant: 'Platform admins need the site’s tenant scope (tenant_scope_id in the link).',
    range: { '1h': 'Last hour', '6h': 'Last 6 hours', '24h': 'Last 24 hours' },
    fields: { matched: 'Matched', triggered: 'Triggered', challenged: 'Challenged', blocked: 'Blocked', passed: 'Passed', ja4_unavailable: 'No TLS fingerprint' },
    columns: { rule: 'Rule', policy: 'Policy' },
    siteLevel: 'Site level (verification ban)',
    topClients: 'Top triggering client IPs',
    topPaths: 'Top triggering paths',
    count: 'Count',
    empty: 'No CC rule activity in this period',
    error: 'Statistics are unavailable, try again later',
    chart: 'CC rule trend chart',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN),
})) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages as Messages, true, true)
}
