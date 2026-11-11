import i18n from './index'

// 真实用户体验 report page.
const zhCN = {
  title: '真实用户体验',
  description: '访客浏览器实测的加载、交互与稳定性（按 p75 评级）',
  site: '网站',
  sitePlaceholder: '搜索并选择网站',
  range: '时间范围',
  ranges: { '1h': '近 1 小时', '24h': '近 24 小时', '7d': '近 7 天', '30d': '近 30 天' },
  refresh: '刷新',
  asOf: '数据截至 {{time}}，约有 1–2 分钟延迟',
  pickSite: '选择一个网站查看它的真实用户体验数据。',
  off: '本站点未开启真实用户体验上报。',
  goEnable: '去开启',
  empty: '已开启，暂未收到上报。发布生效后有访客浏览才会出现数据；开启前缓存的页面要过期或刷新缓存后才注入脚本。',
  failed: '报表读取失败',
  metric: {
    lcp: '最大内容绘制（LCP）', inp: '交互到下次绘制（INP）', cls: '累计布局偏移（CLS）',
    fcp: '首次内容绘制（FCP）', ttfb: '首字节时间（TTFB）',
  },
  metricShort: { lcp: 'LCP', inp: 'INP', cls: 'CLS', fcp: 'FCP', ttfb: 'TTFB' },
  rating: { good: '良好', ni: '需改进', poor: '差' },
  notMeasured: '此区间没有浏览器上报该指标',
  samples: '{{formatted}} 次测量',
  shares: '良好 {{good}} · 需改进 {{ni}} · 差 {{poor}}',
  trend: 'p75 趋势 · {{metric}}',
  trendSummary: '{{metric}} p75 {{range}} {{value}}，{{rating}}',
  goodLine: '良好 ≤ {{value}}',
  poorLine: '差 > {{value}}',
  fewSamples: '样本少',
  showTable: '查看数据表',
  time: '时间',
  views: '浏览数',
  breakdown: '分布',
  tabs: { pages: '页面', countries: '国家/地区', devices: '设备' },
  other: '超过每分钟上限的值合并到这里',
  otherValue: '（其它）',
  p75: 'p75',
  noCountry: '未知',
  devices: { desktop: '桌面', mobile: '手机', tablet: '平板' },
  errors: '资源与请求错误',
  errorKind: { resource: '资源', navigation: '导航', fetch: 'fetch', xhr: 'XHR' },
  columns: { kind: '类型', element: '元素', target: '目标', status: '状态码', count: '次数', share: '占浏览数' },
  networkFailure: '网络失败',
  noErrors: '此区间没有错误上报',
  footer: '数据来自开启上报的站点里被采样到的浏览；不含 query string、IP、cookie。不支持的浏览器不上报 LCP/INP。被节点限速或校验拒绝的上报 {{dropped}} 次。',
}

const enUS: typeof zhCN = {
  title: 'Real user monitoring',
  description: 'Loading, interactivity and visual stability measured in visitors\' browsers (rated by p75)',
  site: 'Site',
  sitePlaceholder: 'Search and select a site',
  range: 'Time range',
  ranges: { '1h': 'Last hour', '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' },
  refresh: 'Refresh',
  asOf: 'Data as of {{time}}, about 1–2 minutes behind',
  pickSite: 'Select a site to see its real user monitoring data.',
  off: 'Real user monitoring is off for this site.',
  goEnable: 'Turn it on',
  empty: 'On, but no reports yet. Data appears once the publication is live and visitors browse; pages cached before turning it on get the script once they expire or the cache is purged.',
  failed: 'The report could not be read',
  metric: {
    lcp: 'Largest Contentful Paint (LCP)', inp: 'Interaction to Next Paint (INP)', cls: 'Cumulative Layout Shift (CLS)',
    fcp: 'First Contentful Paint (FCP)', ttfb: 'Time to First Byte (TTFB)',
  },
  metricShort: { lcp: 'LCP', inp: 'INP', cls: 'CLS', fcp: 'FCP', ttfb: 'TTFB' },
  rating: { good: 'Good', ni: 'Needs improvement', poor: 'Poor' },
  notMeasured: 'No browser reported this metric in the range',
  samples: '{{formatted}} measurements',
  shares: 'Good {{good}} · Needs improvement {{ni}} · Poor {{poor}}',
  trend: 'p75 trend · {{metric}}',
  trendSummary: '{{metric}} p75 over the {{range}}: {{value}}, {{rating}}',
  goodLine: 'Good ≤ {{value}}',
  poorLine: 'Poor > {{value}}',
  fewSamples: 'few samples',
  showTable: 'Show data table',
  time: 'Time',
  views: 'Page views',
  breakdown: 'Breakdown',
  tabs: { pages: 'Pages', countries: 'Countries/regions', devices: 'Devices' },
  other: 'Values beyond the per minute limit are folded here',
  otherValue: '(other)',
  p75: 'p75',
  noCountry: 'Unknown',
  devices: { desktop: 'Desktop', mobile: 'Mobile', tablet: 'Tablet' },
  errors: 'Resource and request errors',
  errorKind: { resource: 'Resource', navigation: 'Navigation', fetch: 'fetch', xhr: 'XHR' },
  columns: { kind: 'Type', element: 'Element', target: 'Target', status: 'Status', count: 'Count', share: 'Of page views' },
  networkFailure: 'Network failure',
  noErrors: 'No errors reported in the range',
  footer: 'From the sampled page views of sites with reporting on; no query string, IP address or cookie. Browsers without support do not report LCP/INP. Reports refused by node limits or checks: {{dropped}}.',
}

type Messages = { [key: string]: string | Messages }

// interpolation placeholders ({{time}}) stay as they are
function pseudoText(value: string): string {
  const parts = value.split(/(\{\{[^}]+\}\})/u).map((part) => part.startsWith('{{') ? part
    : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join(''))
  return `［${parts.join('')}］`
}

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key, typeof child === 'string' ? pseudoText(child) : pseudo(child),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const rumReportMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(rumReportMessages)) {
  i18n.addResourceBundle(locale, 'rumReport', messages, true, true)
}
