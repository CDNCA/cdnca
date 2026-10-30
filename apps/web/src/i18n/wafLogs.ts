import i18n from './index'

const zhCN = {
  title: 'WAF日志',
  tabs: { overview: '安全概览', details: '日志明细' },
  filters: {
    advanced: '高级搜索',
    domain: '域名',
    domainPlaceholder: '输入域名，多个空格分隔',
    advancedDomainPlaceholder: '多个域名空格分隔',
    range: '时间范围',
    from: '开始时间',
    to: '结束时间',
    site: '站点',
    sitePlaceholder: '请输入站点 ID',
    node: '节点',
    nodePlaceholder: '请输入节点 ID',
  },
  actions: { query: '查询', advancedSearch: '高级搜索', collapseSearch: '收起搜索', retry: '重试' },
  metrics: {
    attacks: '攻击总数', blocked: '拦截次数', challenged: '人机验证', observed: '观察次数', autoBlocked: '自动封禁', clients: '独立客户端IP',
  },
  charts: { trend: '攻击趋势', attackTypes: '攻击类型分布', legend: '图例' },
  rankings: {
    domains: '域名排行', clients: '客户端IP排行', countries: '国家排行', provinces: '省份排行', carriers: '运营商排行', uris: 'URI排行',
  },
  columns: { attackType: '攻击类型', ratio: '占比', count: '次数', domain: '域名', client: '客户端IP', country: '国家', province: '省份', carrier: '运营商', uri: 'URI' },
  evidence: { snapshot: '查询范围：{{from}} - {{to}}' },
  // fix-waflog：重设计后的筛选区、命中概况、排行下钻、日志表与详情分组。
  redesign: {
    filters: '筛选条件', logFilters: '日志筛选', more: '更多筛选', moreCount: '更多筛选（{{count}}）', reset: '重置',
    summary: '命中概况', share: '占 {{value}}',
    viewLogs: '查看 {{value}} 的日志', viewMetricLogs: '查看{{value}}的日志',
    columns: { time: '时间', site: '网站', source: '来源', rule: '命中规则', disposition: '处置' },
    statusCode: '状态码 {{value}}', count: '共 {{value}} 次',
    groups: { hit: '命中情况', request: '请求信息', trace: '追踪信息' },
  },
  states: {
    unknownRule: '未知规则', unnamedRule: '未命名规则（{{id}}）', unknown: '未知',
    loading: '正在加载 WAF 统计',
    empty: '暂无数据',
    emptyTrend: '暂无攻击趋势数据',
    emptyAttackTypes: '暂无攻击类型数据',
    permissionTitle: '无权查看 WAF 日志',
    permissionDescription: '当前账户没有此范围的日志读取权限。',
    invalidWindow: '请选择整点起止、不超过 31 天且结束时间晚于开始时间的范围。',
    invalidDomain: '请输入最多 64 个有效且不重复的域名，多个域名以空格分隔。',
    invalidSite: '请输入有效的站点 ID。',
    invalidNode: '请输入有效的节点 ID。',
    invalidRequest: '筛选条件无效，请检查后重试。',
    invalidResponse: 'WAF 统计响应不完整，请稍后重试。',
    unavailable: '分析存储暂不可用，请稍后重试。',
    requestFailed: 'WAF 统计加载失败，请稍后重试。',
  },
}

const enUS = {
  title: 'WAF logs',
  tabs: { overview: 'Security overview', details: 'Log details' },
  filters: {
    advanced: 'Advanced search',
    domain: 'Domain',
    domainPlaceholder: 'Enter domains separated by spaces',
    advancedDomainPlaceholder: 'Separate multiple domains with spaces',
    range: 'Time range',
    from: 'Start time',
    to: 'End time',
    site: 'Site',
    sitePlaceholder: 'Enter site ID',
    node: 'Node',
    nodePlaceholder: 'Enter node ID',
  },
  actions: { query: 'Query', advancedSearch: 'Advanced search', collapseSearch: 'Collapse search', retry: 'Retry' },
  metrics: { attacks: 'Total attacks', blocked: 'Blocked', challenged: 'Challenged', observed: 'Observed', autoBlocked: 'Auto blocked', clients: 'Unique client IPs' },
  charts: { trend: 'Attack trend', attackTypes: 'Attack type distribution', legend: 'Legend' },
  rankings: { domains: 'Domain ranking', clients: 'Client IP ranking', countries: 'Country ranking', provinces: 'Province ranking', carriers: 'Carrier ranking', uris: 'URI ranking' },
  columns: { attackType: 'Attack type', ratio: 'Ratio', count: 'Count', domain: 'Domain', client: 'Client IP', country: 'Country', province: 'Province', carrier: 'Carrier', uri: 'URI' },
  evidence: { snapshot: 'Window: {{from}} - {{to}}' },
  redesign: {
    filters: 'Filters', logFilters: 'Log filters', more: 'More filters', moreCount: 'More filters ({{count}})', reset: 'Reset',
    summary: 'Hit summary', share: '{{value}} of total',
    viewLogs: 'View logs for {{value}}', viewMetricLogs: 'View {{value}} logs',
    columns: { time: 'Time', site: 'Site', source: 'Source', rule: 'Matched rule', disposition: 'Action' },
    statusCode: 'Status {{value}}', count: '{{value}} times',
    groups: { hit: 'Match', request: 'Request', trace: 'Trace' },
  },
  states: {
    unknownRule: 'Unknown rule', unnamedRule: 'Unnamed rule ({{id}})', unknown: 'Unknown',
    loading: 'Loading WAF statistics',
    empty: 'No data',
    emptyTrend: 'No attack trend data',
    emptyAttackTypes: 'No attack type data',
    permissionTitle: 'WAF logs unavailable',
    permissionDescription: 'This account cannot read WAF logs in this scope.',
    invalidWindow: 'Choose an hour-aligned range no longer than 31 days with the end after the start.',
    invalidDomain: 'Enter no more than 64 valid, unique domains separated by spaces.',
    invalidSite: 'Enter a valid site ID.',
    invalidNode: 'Enter a valid node ID.',
    invalidRequest: 'The filters are invalid. Check them and try again.',
    invalidResponse: 'The WAF statistics response is incomplete. Try again later.',
    unavailable: 'Analytics storage is temporarily unavailable.',
    requestFailed: 'WAF statistics could not be loaded.',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudo(child)]))
}

i18n.addResourceBundle('zh-CN', 'wafLogs', zhCN, true, true)
i18n.addResourceBundle('en-US', 'wafLogs', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'wafLogs', pseudo(zhCN), true, true)
i18n.addResourceBundle('qps-Ploc', 'wafLogs', pseudo(zhCN), true, true)

export { enUS, zhCN }
