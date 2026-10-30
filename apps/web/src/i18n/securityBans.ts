import i18n from './index'

// 封禁名单页：手工封禁、节点 WAF/CC 自动封禁、一键解封。
const zhCN = {
  title: '封禁名单',
  description: '手工封禁和节点上的 WAF/CC 自动封禁都在这里，解封后该网站的所有节点立即放行。',
  filters: { site: '网站 ID', ip: '客户端 IP', state: '状态', all: '全部', search: '查询', reset: '重置' },
  columns: {
    site: '网站', ip: '客户端 IP', source: '来源', rule: '规则', reason: '原因', bannedAt: '封禁时间',
    bannedUntil: '封禁到期', state: '状态', releasedAt: '解封时间', actions: '操作',
  },
  source: { waf: 'WAF 自动封禁', cc: 'CC 自动封禁', manual: '手工封禁' },
  state: { active: '封禁中', released: '已解封', expired: '已到期' },
  network: '网段',
  actions: { create: '手工封禁', release: '解封', confirmRelease: '确认解封', cancel: '取消', submit: '封禁', refresh: '刷新' },
  form: {
    site: '网站', sitePlaceholder: '选择网站，可多选，输入域名搜索', noSites: '没有可选的网站', ip: '客户端 IP',
    ipPlaceholder: '每行一个 IPv4 / IPv6 地址或网段（如 203.0.113.0/24），也可以用逗号或空格分隔',
    ipHint: '一次最多 {{max}} 个地址或网段；每个网站都会封禁这些地址。网段最大 IPv4 /8、IPv6 /32。',
    networkHint: '网段封禁只在支持网段封禁的节点生效；节点版本过低时该节点暂不执行网段封禁（单个地址不受影响），请升级节点。',
    duration: '封禁时长', reason: '原因（可选）',
  },
  durations: { m10: '10 分钟', h1: '1 小时', d1: '1 天', d7: '7 天', d30: '30 天（最长）' },
  failureLine: '{{ip}} · {{site}}：{{reason}}',
  releaseConfirm: '解封 {{ip}} 后，网站 {{site}} 的所有节点会立即放行该 IP（节点自己的 WAF/CC 自动封禁一并解除）。',
  empty: '暂无封禁记录',
  total: '共 {{count}} 条',
  success: {
    created: '已封禁 {{ip}}，正在下发到节点', released: '已解封 {{ip}}，正在下发到节点',
    createdMany: '已封禁 {{count}} 条，正在下发到节点', createdPartly: '已封禁 {{count}} 条，失败 {{failed}} 条：',
  },
  errors: {
    load: '封禁名单加载失败，请重试。', invalid: '请检查网站、IP 和时长（1 分钟到 30 天）。', siteRequired: '请至少选择一个网站。',
    network: '网段范围过大或格式不对：IPv4 最大 /8，IPv6 最大 /32。', tooMany: '一次最多封禁 {{max}} 个地址或网段。',
    siteNotFound: '网站不存在或无权访问。', exists: '该 IP 在这个网站已经处于封禁中。',
    notActive: '这条封禁已解封或已到期。', limit: '该网站的封禁数量已达上限。', permission: '没有权限执行此操作。',
    failed: '操作失败，请重试。',
  },
}

const enUS: typeof zhCN = {
  title: 'Ban list',
  description: 'Manual bans and the nodes\' automatic WAF / CC bans. A release lets the IP through on every node of the site at once.',
  filters: { site: 'Site ID', ip: 'Client IP', state: 'State', all: 'All', search: 'Search', reset: 'Reset' },
  columns: {
    site: 'Site', ip: 'Client IP', source: 'Source', rule: 'Rule', reason: 'Reason', bannedAt: 'Banned at',
    bannedUntil: 'Banned until', state: 'State', releasedAt: 'Released at', actions: 'Actions',
  },
  source: { waf: 'WAF automatic ban', cc: 'CC automatic ban', manual: 'Manual ban' },
  state: { active: 'Banned', released: 'Released', expired: 'Expired' },
  network: 'Network',
  actions: { create: 'Ban an IP', release: 'Release', confirmRelease: 'Release', cancel: 'Cancel', submit: 'Ban', refresh: 'Refresh' },
  form: {
    site: 'Sites', sitePlaceholder: 'Choose one or more sites; type to search by domain', noSites: 'No sites to choose', ip: 'Client IP',
    ipPlaceholder: 'One IPv4 / IPv6 address or network (such as 203.0.113.0/24) per line, or separated by commas or spaces',
    ipHint: 'Up to {{max}} addresses or networks at a time; each chosen site bans all of them. Networks up to IPv4 /8, IPv6 /32.',
    networkHint: 'Network bans apply only on nodes that support them; a node whose version is too old does not enforce network bans yet (single addresses are not affected). Upgrade the node.',
    duration: 'Duration', reason: 'Reason (optional)',
  },
  durations: { m10: '10 minutes', h1: '1 hour', d1: '1 day', d7: '7 days', d30: '30 days (longest)' },
  failureLine: '{{ip}} · {{site}}: {{reason}}',
  releaseConfirm: 'Releasing {{ip}} lets it through on every node of site {{site}} at once (the nodes\' own WAF / CC automatic bans are lifted too).',
  empty: 'No bans',
  total: '{{count}} in total',
  success: {
    created: 'Banned {{ip}}; sending to the nodes', released: 'Released {{ip}}; sending to the nodes',
    createdMany: 'Banned {{count}}; sending to the nodes', createdPartly: 'Banned {{count}}, {{failed}} failed:',
  },
  errors: {
    load: 'Could not load the ban list. Try again.', invalid: 'Check the sites, the IP and the duration (1 minute to 30 days).', siteRequired: 'Choose at least one site.',
    network: 'The network is too wide or malformed: IPv4 up to /8, IPv6 up to /32.', tooMany: 'Up to {{max}} addresses or networks at a time.',
    siteNotFound: 'The site does not exist or you cannot access it.', exists: 'The IP is already banned on this site.',
    notActive: 'The ban was already released or has expired.', limit: 'The site has reached its ban limit.',
    permission: 'You are not allowed to do this.', failed: 'The request failed. Try again.',
  },
}

function pseudo(value: unknown): unknown {
  // Brackets only, so {{interpolation}} keeps working.
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const securityBansMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(securityBansMessages)) {
  i18n.addResourceBundle(locale, 'securityBans', messages, true, true)
}
