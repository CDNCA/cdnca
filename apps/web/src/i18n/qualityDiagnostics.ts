import i18n from '.'

const zhCN = {
  title: '质量诊断',
  columns: {
    time: '发生时间', category: '分类', cause: '原因', action: '建议操作', status: '状态码', site: '站点 ID',
    config: '配置版本', installation: '主控编号', node: '节点 ID', request: '请求 ID', task: '任务 ID', trace: 'Trace ID',
  },
  categories: { upstream_5xx: '源站 5xx', edge_530: '边缘 530', no_host: '无 Host', config_mismatch: '配置失配' },
  causes: {
    upstream_failure: '源站请求失败', upstream_result_empty: '源站结果为空', upstream_result_unknown: '源站结果未知',
    edge_status_530: '边缘返回 530', upstream_reported_no_host: '上游明确报告无 Host', host_missing: '请求缺少 Host',
    upstream_reported_config_mismatch: '上游明确报告配置失配',
  },
  actions: {
    retry: '重试', previous: '上一页', next: '下一页', inspect_upstream: '检查源站', inspect_edge_route: '检查边缘路由',
    configure_host: '配置 Host', reconcile_config: '对齐配置版本',
  },
  evidence: { snapshot: '快照时间：{{time}}', watermark: '来源水位：{{value}}', finalized: '已完成至：{{time}}', expires: '快照失效：{{time}}' },
  values: { none: '无' },
  states: {
    loading: '正在加载质量诊断', empty: '当前范围内没有诊断事件', permission: '无权查看质量诊断',
    unavailable: '诊断证据暂不可用，请稍后重试。', timeout: '诊断查询超时，请缩小时间范围。',
    snapshot: '诊断快照已失效，请重新查询。', invalidResponse: '诊断事实未通过完整性校验。',
    requestFailed: '质量诊断加载失败，请稍后重试。',
  },
}

const enUS = {
  title: 'Quality diagnostics',
  columns: {
    time: 'Occurred at', category: 'Category', cause: 'Cause', action: 'Action', status: 'Status', site: 'Site ID',
    config: 'Config version', installation: 'Control installation ID', node: 'Node ID', request: 'Request ID', task: 'Task ID', trace: 'Trace ID',
  },
  categories: { upstream_5xx: 'Upstream 5xx', edge_530: 'Edge 530', no_host: 'No host', config_mismatch: 'Config mismatch' },
  causes: {
    upstream_failure: 'Upstream request failed', upstream_result_empty: 'Upstream result empty', upstream_result_unknown: 'Upstream result unknown',
    edge_status_530: 'Edge returned 530', upstream_reported_no_host: 'Upstream reported no host', host_missing: 'Request host missing',
    upstream_reported_config_mismatch: 'Upstream reported config mismatch',
  },
  actions: {
    retry: 'Retry', previous: 'Previous', next: 'Next', inspect_upstream: 'Inspect upstream', inspect_edge_route: 'Inspect edge route',
    configure_host: 'Configure host', reconcile_config: 'Reconcile config version',
  },
  evidence: { snapshot: 'Snapshot: {{time}}', watermark: 'Source watermark: {{value}}', finalized: 'Finalized through: {{time}}', expires: 'Snapshot expires: {{time}}' },
  values: { none: 'None' },
  states: {
    loading: 'Loading quality diagnostics', empty: 'No diagnostic events in this range', permission: 'Quality diagnostics unavailable',
    unavailable: 'Diagnostic evidence is unavailable. Try again later.', timeout: 'The diagnostic query timed out. Use a smaller range.',
    snapshot: 'The diagnostic snapshot expired. Run the query again.', invalidResponse: 'Diagnostic facts failed integrity validation.',
    requestFailed: 'Quality diagnostics could not be loaded.',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as typeof zhCN
i18n.addResourceBundle('zh-CN', 'qualityDiagnostics', zhCN, true, true)
i18n.addResourceBundle('en-US', 'qualityDiagnostics', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'qualityDiagnostics', pseudoCN, true, true)
i18n.addResourceBundle('qps-Ploc', 'qualityDiagnostics', pseudoCN, true, true)

export { enUS, pseudoCN, zhCN }
export default i18n
