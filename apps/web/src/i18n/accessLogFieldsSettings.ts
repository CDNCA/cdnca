import i18n from './index'

type TranslationTree = { [key: string]: string | TranslationTree }

export const accessLogFieldsNamespace = 'accessLogFieldsSettings'

const zhCN = {
  title: '访问日志字段',
  description: '选择访问日志记录哪些可选字段。未勾选的字段不存储，访问量大时可明显节省 ClickHouse 磁盘。保存后需检查并启用，启用后对全部节点和新写入的日志生效，已存日志不变。',
  loading: '正在加载访问日志字段设置',
  basic: {
    title: '基础字段（始终记录）',
    description: '时间、网站、域名、请求路径、状态码、方法、协议、请求/响应字节数、耗时、客户端 IP、缓存状态。流量统计、计费和数据分析依赖这些字段，不能关闭。每条约 150–300 字节（取决于路径长度）。',
  },
  groups: {
    client: '客户端',
    request_headers: '请求头',
    response_headers: '响应头',
    origin: '回源',
    cache: '缓存',
    security: '安全',
    tls_fingerprint: 'TLS 指纹',
  },
  fields: {
    client_family: { label: '浏览器 / 操作系统', usage: '数据分析"浏览器""操作系统"排行，访问日志对应列。' },
    client_geo: { label: '国家 / 省份 / 运营商', usage: '数据分析地区、省份、运营商排行，访问日志对应列（主控按 IP 库补全）。' },
    referer: { label: 'Referer', usage: '数据分析"热门 Referer"、访问日志来源列；用于排查盗链与流量来源。' },
    user_agent: { label: 'User-Agent', usage: '访问日志 User-Agent 列与按 UA 筛选；排查爬虫和异常客户端。' },
    accept_language: { label: 'Accept-Language', usage: '访客语言偏好；一般只在做内容本地化分析时需要。' },
    content_type: { label: 'Content-Type（响应）', usage: '访问日志内容类型列与按类型筛选。' },
    content_encoding: { label: 'Content-Encoding（响应）', usage: '是否压缩（gzip/br）；排查压缩配置时有用。' },
    origin_timing: { label: '回源耗时', usage: '连接源站、首字节、总耗时三项；访问日志回源耗时列、源站慢的排查。' },
    upstream_addr: { label: '回源地址', usage: '实际回源的源站地址:端口（多次重试时为多个）；访问日志"源地址"列。需节点升级到含此字段的版本后才有值。' },
    cache_control: { label: 'Cache-Control（响应）', usage: '源站或节点下发的缓存头；排查缓存不命中。' },
    x_forwarded_for: { label: 'X-Forwarded-For', usage: '客户端经过的代理链；排查伪造来源和多层代理。' },
    x_real_ip: { label: 'X-Real-IP', usage: '上游代理声明的真实 IP；与 X-Forwarded-For 一起用于来源核对。' },
    block_page: { label: '是否拦截页', usage: '标记节点直接返回的拦截页，访问日志拦截列与“拦截页不计流量”依赖它。关闭后拦截页的流量会计入套餐流量。' },
    ja4: { label: 'JA4 指纹', usage: '数据分析"TLS 指纹"排行、访问日志指纹列；识别自动化客户端。仅 HTTPS 请求有值。' },
  },
  cost: '约 {{bytes}} 字节/条',
  costBasic: '每 1 亿条约 {{size}}（按勾选项估算，未计压缩；ClickHouse 实际压缩后通常为其 1/5–1/10）',
  selectedCount: '已勾选 {{count}} 项',
  resetDefault: '恢复默认',
  retention: {
    title: '保留天数',
    label: '网站访问日志保留（天）',
    help: '与“系统设置 → 清理设置”中的“网站访问日志”是同一个设置；0 表示永久保留。到期的日志由 ClickHouse 自动删除。',
    save: '保存保留天数',
    saved: '保留天数已保存',
    loadError: '无法加载保留天数',
  },
  status: {
    label: '当前版本',
    none: '未保存（使用默认字段）',
    draft: '草稿 r{{revision}}',
    validated: '已检查 r{{revision}}',
    active: '已生效 r{{revision}}',
  },
  actions: { save: '保存草稿', preflight: '检查', activate: '启用下发', refresh: '刷新' },
  notices: { saved: '已保存草稿', validated: '检查通过', activated: '已启用并下发' },
  errors: {
    forbidden: '只有平台管理员可以查看访问日志字段设置。',
    load: '无法加载访问日志字段设置',
    write: '保存失败',
    lifecycle: '操作失败',
    permissionDenied: '没有修改系统配置的权限',
    pendingChanged: '待生效的分类已变化，请刷新后再试',
    conflict: '设置已被他人修改，请刷新后再试',
    invalid: '字段选择无效',
  },
}

const enUS: typeof zhCN = {
  title: 'Access log fields',
  description: 'Choose which optional fields the access log records. Fields not selected are not stored, which saves ClickHouse disk under heavy traffic. After saving, check and activate; activation applies to every node and to logs written from then on. Stored logs are unchanged.',
  loading: 'Loading the access log field settings',
  basic: {
    title: 'Basic fields (always recorded)',
    description: 'Time, site, host, path, status, method, protocol, request/response bytes, duration, client IP, cache status. Traffic, billing and analytics depend on them, so they cannot be turned off. About 150–300 bytes per entry (depends on the path).',
  },
  groups: {
    client: 'Client',
    request_headers: 'Request headers',
    response_headers: 'Response headers',
    origin: 'Origin',
    cache: 'Cache',
    security: 'Security',
    tls_fingerprint: 'TLS fingerprint',
  },
  fields: {
    client_family: { label: 'Browser / OS', usage: 'Browser and OS rankings in analytics; the access log columns.' },
    client_geo: { label: 'Country / province / carrier', usage: 'Region, province and carrier rankings; the access log columns (filled from the IP library).' },
    referer: { label: 'Referer', usage: 'Top referers in analytics and the access log source column; hotlink and traffic source checks.' },
    user_agent: { label: 'User-Agent', usage: 'The access log User-Agent column and filter; crawler and abnormal client checks.' },
    accept_language: { label: 'Accept-Language', usage: 'Visitor language preference; usually only for localization analysis.' },
    content_type: { label: 'Content-Type (response)', usage: 'The access log content type column and filter.' },
    content_encoding: { label: 'Content-Encoding (response)', usage: 'Whether the response was compressed (gzip/br).' },
    origin_timing: { label: 'Origin timing', usage: 'Origin connect, first byte and total time; slow origin checks.' },
    upstream_addr: { label: 'Origin address', usage: 'The origin address:port actually used (several on retries); the access log origin column. Needs nodes on a version that records it.' },
    cache_control: { label: 'Cache-Control (response)', usage: 'The cache header sent; cache miss checks.' },
    x_forwarded_for: { label: 'X-Forwarded-For', usage: 'The proxy chain of the client; spoofed source and multi-proxy checks.' },
    x_real_ip: { label: 'X-Real-IP', usage: 'The real IP an upstream proxy declares.' },
    block_page: { label: 'Block page', usage: 'Marks block pages the node answered itself; the access log block column and "block pages are not counted" depend on it. When off, block page traffic counts toward package traffic.' },
    ja4: { label: 'JA4 fingerprint', usage: 'TLS fingerprint ranking and the access log column; automated client detection. HTTPS only.' },
  },
  cost: 'about {{bytes}} bytes/entry',
  costBasic: 'About {{size}} per 100 million entries (estimated from the selection, uncompressed; ClickHouse usually stores 1/5–1/10 of it)',
  selectedCount: '{{count}} selected',
  resetDefault: 'Restore default',
  retention: {
    title: 'Retention',
    label: 'Keep website access logs (days)',
    help: 'The same setting as "Website access logs" in System settings → Cleanup; 0 keeps them forever. ClickHouse deletes expired logs.',
    save: 'Save retention',
    saved: 'Retention saved',
    loadError: 'Unable to load the retention',
  },
  status: {
    label: 'Revision',
    none: 'Not saved (default fields)',
    draft: 'Draft r{{revision}}',
    validated: 'Checked r{{revision}}',
    active: 'Active r{{revision}}',
  },
  actions: { save: 'Save draft', preflight: 'Check', activate: 'Activate', refresh: 'Refresh' },
  notices: { saved: 'Draft saved', validated: 'Check passed', activated: 'Activated' },
  errors: {
    forbidden: 'Only platform administrators can view the access log field settings.',
    load: 'Unable to load the access log field settings',
    write: 'Save failed',
    lifecycle: 'Operation failed',
    permissionDenied: 'No permission to change the system configuration',
    pendingChanged: 'The pending categories changed; refresh and try again',
    conflict: 'Someone else changed the settings; refresh and try again',
    invalid: 'Invalid field selection',
  },
}

function pseudo(value: string | TranslationTree): string | TranslationTree {
  if (typeof value === 'string') return `［${value.replace(/\S/g, '$&~')}］`
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudo(item)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
})) {
  i18n.addResourceBundle(locale, accessLogFieldsNamespace, messages, true, true)
}

export { enUS, zhCN }
