import i18n from '.'

const zhCN = {
  title: '网站实时监控',
  tabs: { basic: '基础数据', quality: '质量监控', origin: '回源监控' },
  charts: {
    bandwidth: '带宽', traffic: '流量', requests: '访问次数', qps: 'QPS', ranking: '域名端口排行',
    requestHitRatio: '请求命中率', byteHitRatio: '字节命中率', status4xx: '4xx状态码', status5xx: '5xx状态码',
    originBandwidth: '回源带宽', originTraffic: '回源流量', originDuration: '回源耗时',
    countValue: '{{value}} 次', secondsValue: '{{value}} 秒', advancedDiagnostics: '高级质量诊断',
    tooltipValue: '{{metric}}：{{value}}',
    keyboardHint: '使用左右方向键查看相邻数据点，Home 和 End 查看首尾，Escape 关闭提示。',
  },
  actions: { query: '查询', retry: '重试' },
  filters: {
    tenant: '租户 ID', tenantPlaceholder: '输入租户 ID', site: '站点 ID', sitePlaceholder: '输入站点 ID',
    scope: '目标范围', hideScope: '收起范围',
    host: '域名', hostPlaceholder: '输入域名，多个空格分隔', port: '监听端口', portPlaceholder: '输入监听端口', range: '时间范围', from: '开始时间', to: '结束时间',
    invalidUuid: '请输入有效的 UUID。', invalidHost: '请输入规范的小写域名。',
    invalidPort: '监听端口必须为 1 到 65535。', invalidWindow: '请选择有效的分钟时间范围，结束时间须晚于开始时间。', rangeTooLong: '时间范围最长为 31 天。',
    minuteHint: '自定义范围按北京时间精确到分钟，最长 31 天；数据为实时入库数据，快捷范围截至当前分钟。',
  },
  metrics: {
    requests: '请求数', traffic: '流量', bandwidth: '带宽', connections: '窗口内连接数', status: '状态码', cache: '缓存命中',
    errors: '错误请求', duration: '平均请求耗时', originConnect: '回源连接', originFirstByte: '回源首字节', originTotal: '回源总耗时',
  },
  columns: { time: '时间', hostPort: '域名 / 端口', requests: '请求数', traffic: '流量', bandwidth: '带宽', connections: '连接数' },
  evidence: {
    title: '数据快照', finalized: '已结算至 {{time}}', watermark: '来源水位 {{time}}', sources: '访问来源 {{access}} / 连接来源 {{connections}}',
    accuracy: '发生器对账误差 {{ppm}} PPM（{{observed}} / {{expected}}）',
    coverage: '整小时对账范围 {{from}} 至 {{to}}', snapshot: '数据快照 {{time}}', updated: '每 10 秒自动刷新，更新于 {{time}}',
  },
  states: {
    loading: '正在加载实时监控数据', empty: '当前筛选范围内暂无数据', permissionTitle: '无权查看监控数据',
    permissionDescription: '当前账户没有此范围的监控读取权限。', invalidRequest: '筛选条件无效，请检查时间范围和资源标识。',
    unavailable: '实时监控证据尚未结算，请稍后重试。', timeout: '查询超时，请缩小时间范围后重试。',
    invalidResponse: '实时监控数据无法通过完整性校验。', requestFailed: '实时监控加载失败，请稍后重试。',
    originBytesUnavailable: '未采集回源字节，暂无法计算此指标',
    noOriginSamples: '无回源样本',
  },
}

const enUS = {
  title: 'Real-time site monitoring',
  tabs: { basic: 'Core metrics', quality: 'Quality monitoring', origin: 'Origin monitoring' },
  charts: {
    bandwidth: 'Bandwidth', traffic: 'Traffic', requests: 'Requests', qps: 'QPS', ranking: 'Host and port ranking',
    requestHitRatio: 'Request hit ratio', byteHitRatio: 'Byte hit ratio', status4xx: '4xx status codes', status5xx: '5xx status codes',
    originBandwidth: 'Origin bandwidth', originTraffic: 'Origin traffic', originDuration: 'Origin duration',
    countValue: '{{value}} requests', secondsValue: '{{value}} s', advancedDiagnostics: 'Advanced quality diagnostics',
    tooltipValue: '{{metric}}: {{value}}',
    keyboardHint: 'Use arrow keys for adjacent points, Home and End for the first and last point, and Escape to dismiss.',
  },
  actions: { query: 'Query', retry: 'Retry' },
  filters: {
    tenant: 'Tenant ID', tenantPlaceholder: 'Enter tenant ID', site: 'Site ID', sitePlaceholder: 'Enter site ID',
    scope: 'Target scope', hideScope: 'Hide scope',
    host: 'Host', hostPlaceholder: 'Enter hosts separated by spaces', port: 'Listen port', portPlaceholder: 'Enter listen port', range: 'Time range', from: 'From', to: 'To',
    invalidUuid: 'Enter a valid UUID.', invalidHost: 'Enter a canonical lowercase host.',
    invalidPort: 'Listen port must be between 1 and 65535.', invalidWindow: 'Choose a valid minute range with the end after the start.', rangeTooLong: 'The range cannot exceed 31 days.',
    minuteHint: 'Custom ranges use exact Beijing-time minutes, up to 31 days. Data is live as ingested; presets end at the current minute.',
  },
  metrics: {
    requests: 'Requests', traffic: 'Traffic', bandwidth: 'Bandwidth', connections: 'Connections in window', status: 'Status codes', cache: 'Cache hits',
    errors: 'Errors', duration: 'Average duration', originConnect: 'Origin connect', originFirstByte: 'Origin first byte', originTotal: 'Origin total',
  },
  columns: { time: 'Time', hostPort: 'Host / port', requests: 'Requests', traffic: 'Traffic', bandwidth: 'Bandwidth', connections: 'Connections' },
  evidence: {
    title: 'Data snapshot', finalized: 'Finalized through {{time}}', watermark: 'Source watermark {{time}}', sources: 'Access {{access}} / Connections {{connections}}',
    accuracy: 'Generator error {{ppm}} PPM ({{observed}} / {{expected}})',
    coverage: 'Whole-hour reconciliation range {{from}} to {{to}}', snapshot: 'Snapshot {{time}}', updated: 'Refreshes every 10 s, updated {{time}}',
  },
  states: {
    loading: 'Loading real-time monitoring data', empty: 'No data in this range', permissionTitle: 'Monitoring unavailable',
    permissionDescription: 'This account cannot read monitoring data in this scope.', invalidRequest: 'Check the range and resource identifiers.',
    unavailable: 'Realtime evidence is not finalized yet. Try again later.', timeout: 'The query timed out. Use a smaller range.',
    invalidResponse: 'Realtime facts failed integrity validation.', requestFailed: 'Realtime monitoring could not be loaded.',
    originBytesUnavailable: 'Origin bytes are not collected; this metric is unavailable',
    noOriginSamples: 'No origin samples',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudo(child)]))
}

i18n.addResourceBundle('zh-CN', 'siteRealtime', zhCN, true, true)
i18n.addResourceBundle('en-US', 'siteRealtime', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'siteRealtime', pseudo(zhCN), true, true)
i18n.addResourceBundle('qps-Ploc', 'siteRealtime', pseudo(zhCN), true, true)

export { enUS, zhCN }
