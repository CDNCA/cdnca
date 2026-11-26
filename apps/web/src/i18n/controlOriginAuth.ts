import i18n from './index'

// 源IP请求头 in System settings → Other → Access and network and the notice on
// the platform home when the console is behind a CDN without the visitor IP
// (components/ControlOriginAuthNotice.tsx, GET /v1/admin/control-origin-auth).
const zhCN = {
  title: '检测到主控前面有 CDN，但未取得访客 IP',
  homeSummary: '限流和日志会把 CDN 节点当作访客。',
  homeLink: '设置源 IP 请求头',
  keyOnlyTitle: '回源密钥通过，但未取得访客 IP',
  keyOnly: 'CDN 没有把访客 IP 写到 {{header}}：在 CDN 回源请求头里添加名称 {{header}}、值为 CDN 的「访客 IP / 客户端 IP」变量。',
  fieldLabel: '源IP请求头',
  options: { direct: '不设置（直连）', 'X-Forwarded-For': 'X-Forwarded-For（取最左）' },
  status: {
    direct: '访客 IP 取自直连来源',
    header: '访客 IP 取自 {{header}}',
    originAuth: '已应用回源密钥校验',
    originAuthHeader: '已应用回源密钥校验，访客 IP 取自 {{header}}',
    unverifiedDirect: '未通过回源密钥的请求：访客 IP 取自直连来源',
    unverifiedHeader: '未通过回源密钥的请求：访客 IP 取自 {{header}}',
    unresolved: '最近经 CDN 的请求未取得访客 IP',
    keyOnly: '回源密钥已通过，但 {{header}} 里没有访客 IP，检查 CDN 回源请求头',
  },
}

const enUS: typeof zhCN = {
  title: 'The console is behind a CDN and does not get the visitor IP',
  homeSummary: 'Rate limits and logs treat the CDN node as the visitor.',
  homeLink: 'Set the source IP header',
  keyOnlyTitle: 'The origin key matched, but no visitor IP',
  keyOnly: 'The CDN does not write the visitor IP into {{header}}: add an origin request header named {{header}} whose value is the CDN\'s "visitor IP / client IP" variable.',
  fieldLabel: 'Source IP header',
  options: { direct: 'Not set (direct)', 'X-Forwarded-For': 'X-Forwarded-For (leftmost)' },
  status: {
    direct: 'The visitor IP is the direct connection\'s',
    header: 'The visitor IP comes from {{header}}',
    originAuth: 'Origin key check applied',
    originAuthHeader: 'Origin key check applied; the visitor IP comes from {{header}}',
    unverifiedDirect: 'Requests without the origin key: the visitor IP is the direct connection\'s',
    unverifiedHeader: 'Requests without the origin key: the visitor IP comes from {{header}}',
    unresolved: 'Recent requests through the CDN did not give the visitor IP',
    keyOnly: 'The origin key matched but {{header}} held no visitor IP; check the CDN origin request headers',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map((part) => part.startsWith('{{') ? part : part.replace(/[A-Za-z一-鿿]/g, '$&~')).join('')}］`
  if (Array.isArray(value)) return value.map(pseudo)
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const controlOriginAuthMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(controlOriginAuthMessages)) {
  i18n.addResourceBundle(locale, 'controlOriginAuth', messages, true, true)
}
