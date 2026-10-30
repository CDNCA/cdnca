import i18n from '.'

const zhCN = {
  title: '质量诊断',
  columns: {
    time: '发生时间', category: '分类', status: '状态码', hostPath: '域名 / 路径', config: '配置版本',
    node: '节点 ID', request: '请求 ID', trace: 'Trace ID',
  },
  categories: { upstream_5xx: '源站 5xx', config_mismatch: '配置失配', no_host: '无 Host', unknown: '未分类异常' },
  reasons: {
    upstream_reported_no_host: '上游明确报告无 Host', host_missing: '请求缺少 Host',
    upstream_reported_config_mismatch: '上游明确报告配置失配', status_530: '状态码 530',
    status_5xx_with_upstream_result: '源站返回 5xx', status_5xx_unclassified: '5xx 来源未分类',
  },
  actions: { retry: '重试', previous: '上一页', next: '下一页' },
  states: {
    loading: '正在加载质量诊断', empty: '当前范围内没有诊断事件', permission: '无权查看质量诊断',
    unavailable: '诊断证据暂不可用，请稍后重试。', timeout: '诊断查询超时，请缩小时间范围。',
    invalidResponse: '诊断事实未通过完整性校验。', requestFailed: '质量诊断加载失败，请稍后重试。',
  },
}

const enUS = {
  title: 'Quality diagnostics',
  columns: {
    time: 'Occurred at', category: 'Category', status: 'Status', hostPath: 'Host / path', config: 'Config version',
    node: 'Node ID', request: 'Request ID', trace: 'Trace ID',
  },
  categories: { upstream_5xx: 'Upstream 5xx', config_mismatch: 'Config mismatch', no_host: 'No host', unknown: 'Unclassified error' },
  reasons: {
    upstream_reported_no_host: 'Upstream reported no host', host_missing: 'Request host missing',
    upstream_reported_config_mismatch: 'Upstream reported config mismatch', status_530: 'Status 530',
    status_5xx_with_upstream_result: 'Upstream returned 5xx', status_5xx_unclassified: '5xx source unclassified',
  },
  actions: { retry: 'Retry', previous: 'Previous', next: 'Next' },
  states: {
    loading: 'Loading quality diagnostics', empty: 'No diagnostic events in this range', permission: 'Diagnostics unavailable',
    unavailable: 'Diagnostic evidence is unavailable. Try again later.', timeout: 'The diagnostic query timed out. Use a smaller range.',
    invalidResponse: 'Diagnostic facts failed integrity validation.', requestFailed: 'Quality diagnostics could not be loaded.',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudo(child)]))
}

i18n.addResourceBundle('zh-CN', 'siteDiagnostics', zhCN, true, true)
i18n.addResourceBundle('en-US', 'siteDiagnostics', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'siteDiagnostics', pseudo(zhCN), true, true)
i18n.addResourceBundle('qps-Ploc', 'siteDiagnostics', pseudo(zhCN), true, true)

export { enUS, zhCN }
export default i18n
