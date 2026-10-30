import i18n from './index'

const zhCN = {
  title: '自定义错误页',
  heading: '错误页面',
  description: '错误页面配置。',
  tabs: { global: '全局配置', regional: '区域及节点配置' },
  legacy: {
    selectorLabel: '错误页面选择', contentLabel: '页面内容', configured: '已修改 · 修订 {{revision}}', notConfigured: '尚未配置',
    builtin: '系统默认（未修改）',
    delivery: {
      theme: '节点当前使用这份内容；保存后成为平台默认并重新发布到节点，站点自己的错误页设置仍优先。',
      fallback: '当前未启用主题，节点对该错误返回简短文本；这里显示的是默认主题的页面，保存后即发布到节点。',
      none: '该错误页本版本节点侧尚未接入，保存只会存储内容，不会改变节点返回。',
    },
    // 节点自己出的 6 个页面：未保存时节点的实际返回（errpage-4 按节点代码核对）；保存后返回这里的内容。
    ownFallback: {
      blacklist: '未保存时，节点对被拉黑的 IP 返回 403 纯文本 “Forbidden”；保存后返回这里的页面。',
      http_403: '未保存时，非 WAF 的拦截（访问控制、IP 名单、地区、Referer/UA 等）返回与 WAF 拦截页面相同的页面；保存后这类拦截改为返回这里的页面，WAF 拦截仍用 WAF 拦截页面。站点自己设置的 403 错误页优先。',
      traffic_exceeded: '未保存时，节点返回内置的“网站流量已超出限制”页面（状态码 509）；保存后返回这里的页面。站点自己设置的流量超限提示优先。',
      package_expired: '仅在系统设置开启“套餐到期关闭网站”时生效：到期站点不回源、不缓存、不计流量。未保存时节点返回 403 纯文本提示；保存后返回这里的页面。该开关关闭时，到期站点照常访问，不显示此页。',
      node_ip_access: '用节点 IP 直接访问时，未保存则返回“域名未配置”页面；保存后返回这里的页面。',
      connection_limit: '连接数、QPS 或带宽超出限制时，未保存则返回 nginx 默认的 503 页面；保存后返回这里的页面。站点自己设置的 503 错误页优先。',
    },
    siteLocked: '站点锁定不影响访问，此页暂不会被节点返回。保存只会存储内容。',
    variables: '可用变量：无。节点按原样输出页面，不做变量替换（如请求 ID、客户端 IP）；含双花括号、${、<% 等模板标记的内容会被拒绝。',
    publishing: '已保存，正在发布：错误页发布修订 {{revision}}，已为 {{count}} 个租户排队重新发布。',
    previewTitle: '错误页预览',
    actions: { preview: '预览', restore: '恢复系统默认', restoreConfirm: '删除修改，恢复为系统默认内容？', viewPublications: '查看发布记录' },
    validation: { required: '请输入页面内容后再保存' },
    errors: { unknown: '操作结果尚未确认' },
    notices: { saved: '全局错误页已保存', savedPublishing: '已保存，正在发布', restored: '已恢复系统默认', restoredPublishing: '已恢复系统默认，正在发布' },
    options: {
      p456: '拉黑页面', p400: '400错误', p403: '403错误', waf_block: 'WAF拦截页面', p502: '502错误', p504: '504错误',
      p513: '流量超限', p512: '套餐到期', p514: '站点锁定', host_not_found: '域名未配置', access_ip_not_allow: '访问节点IP', p515: '连接数超限',
    },
  },
  regional: {
    count: '覆盖配置 {{count}} 项', empty: '暂无数据', labelSuffix: '：',
    actions: { add: '新增设置', confirm: '确定', removeItem: '删除{{item}}配置项' },
    fields: { scope: '配置范围', node: '节点选择', region: '区域选择', items: '配置项' },
    columns: { scope: '配置范围', items: '配置项', actions: '操作' },
    targets: { node: '节点', region: '区域', nodeValue: '节点 {{id}} · {{name}}', regionValue: '区域 {{region}}' },
    placeholders: { node: '输入ID、节点IP或名称搜索', region: '请选择区域', items: '请选择配置项' },
    noNodePermission: '当前账号没有“节点查看”（nodes.read）权限，无法列出节点和区域。请联系管理员授予该权限。',
    items: {
      http_400: '400错误', http_403: '403错误', http_502: '502错误', http_504: '504错误', traffic_exceeded: '流量超限',
      package_expired: '套餐到期', site_locked: '站点锁定', domain_unconfigured: '域名未配置', node_ip_access: '访问节点IP', connection_limit: '连接数超限',
    },
    dialogs: { add: '新增设置', edit: '编辑设置', deleteConfirm: '删除此覆盖配置？' },
    validation: { required: '请选择配置范围和配置项，并填写每个错误页内容' },
    errors: { unknown: '操作结果尚未确认' },
    notices: { saved: '覆盖配置已保存', deleted: '覆盖配置已删除' },
  },
  sections: { publication: '发布源快照（非激活状态）', publicationReceipt: '不可变发布回执', scope: '租户范围', assets: '错误页资产', rules: '错误页规则' },
  actions: {
    refresh: '刷新', upload: '上传资产', delete: '删除', deleteAsset: '删除资产', deleteRule: '删除规则', confirmDelete: '确认删除', cancel: '取消',
    create: '新建规则', edit: '编辑', enable: '启用', disable: '停用', save: '保存', retry: '重试',
    exactRetry: '按原操作重试', abandon: '放弃并刷新', previous: '上一页', next: '下一页',
    applyScope: '应用范围', retryPublication: '重试发布源快照', publishNodes: '发布到节点', confirmPublication: '确认发布',
    retryReceipt: '重试发布回执', retryExactPublication: '使用同一请求重试', abandonPublication: '放弃并刷新发布结果',
  },
  fields: {
    asset: '资产', status: '状态', mime: '类型', contentType: '内容类型', scanStatus: '扫描状态', size: '大小', revision: '版本', updated: '更新时间', actions: '操作',
    scopeId: '租户作用域 ID', scopePlaceholder: '输入规范的小写租户作用域 UUID', site: '站点 ID（可选）', siteFilter: '按站点 ID 筛选', category: '错误类别', matchKind: '匹配方式', from: '起始状态码', to: '结束状态码',
    assetId: '资产 ID', ruleId: '规则 ID', enabled: '创建后启用', priority: '优先级', scope: '作用域',
    publicationTarget: '发布目标', nodeIds: '节点 ID（每行一个）', snapshotId: '快照 ID', snapshotRevision: '快照修订', resolverSha256: '解析器 SHA-256',
    activationTimeoutMs: '激活超时（毫秒）', observationWindowMs: '观察窗口（毫秒）', requiredConsecutiveSuccesses: '连续健康次数', maxAttempts: '最大尝试次数', deadline: '截止时间（RFC3339）',
    publicationId: '发布 ID', configVersionId: '配置版本 ID', rolloutId: '灰度任务 ID', artifactSha256: '产物 SHA-256',
  },
  match: { exact: '精确状态码', range: '状态码范围' },
  categories: { origin_response: '源站响应', edge_route: '边缘路由', edge_connect: '边缘连接', no_host: '未知主机', unknown_site: '未知站点' },
  statuses: { ready: '可用', staged: '待发布', initiated: '已初始化', scan_failed: '扫描失败', rejected: '已拒绝', deleted: '已删除' },
  scans: { pending: '待扫描', passed: '扫描通过', rejected: '扫描拒绝', error: '扫描异常' },
  targets: { globalDefault: '全局默认', siteOverride: '站点覆盖' },
  publication: {
    loading: '正在加载发布源快照', empty: '尚无发布源快照', loadError: '发布源快照加载失败',
    sourceOnly: '此处仅显示确定性发布源，不代表边缘已激活或最近有效配置。',
    globalRules: '全局规则', siteOverrides: '站点覆盖', revision: '修订 {{revision}}', noRules: '快照中暂无规则',
    receiptLoading: '正在加载发布回执', receiptEmpty: '尚无发布回执', receiptLoadError: '发布回执加载失败',
    receiptOnly: '发布回执仅确认生产发布请求及不可变产物，不代表节点已激活或健康。',
    sourceRevision: '源修订 {{revision}}', publicationRevision: '发布修订 {{revision}}', nodeCount: '节点数 {{count}}', targetExplicit: '指定节点', targetResolver: '线路分组快照',
    targets: { nodes: '指定节点', lineGroupSnapshot: '线路分组快照' },
    validation: { source: '当前发布源快照不可用', nodes: '请输入不重复的规范小写节点 UUID', snapshot: '请填写完整且有效的线路分组快照', health: '请填写有效的健康检查、重试和截止时间' },
  },
  data: { selectScope: '请先应用租户作用域', loadingAssets: '正在加载错误页资产', loadingRules: '正在加载错误页规则', emptyAssets: '暂无错误页资产', emptyRules: '暂无错误页规则' },
  upload: { choose: '选择 HTML、纯文本或 JSON 文件', success: '资产上传成功', invalid: '请选择不超过 1 MiB 的 HTML、纯文本或 JSON 文件' },
  validation: { scope: '请输入规范的小写租户作用域 UUID', required: '请填写完整且有效的规则字段', status: '请输入 100 到 599 的状态码', range: '结束状态码必须不小于起始状态码', uuid: '请输入规范的小写 UUID' },
  dialogs: {
    deleteAsset: '删除此错误页资产？', deleteRule: '删除此错误页规则？', unknownTitle: '写入结果未知',
    unknownDescription: '连接在确认写入结果前中断。可按原操作精确重试，或放弃并刷新列表确认。', publishPublication: '发布错误页配置',
  },
  notices: { saved: '规则已保存', deleted: '规则已删除', enabled: '规则状态已更新' },
  errors: {
    forbiddenTitle: '无权查看错误页面', forbiddenDescription: '当前平台身份缺少 error_pages.read 权限。',
    requestFailed: '错误页服务请求失败，请重试', notFound: '未找到请求的错误页资源', conflict: '资源已存在或发生冲突，请刷新后重试',
    stale: '资源已被其他操作更新，请刷新后重试', validation: '提交内容未通过服务端校验', unavailable: '错误页服务暂不可用，请稍后重试',
    network: '网络连接失败，写入结果可能未知', invalidResponse: '错误页服务返回了无效数据',
    unsafeContent: '内容包含不安全元素，请修改后重试', scanRejected: '内容安全扫描未通过', quotaExceeded: '错误页配额已用尽',
    publicationReadForbidden: '无权查看错误页发布', publicationManageForbidden: '无权发布错误页配置',
    publicationIdempotencyConflict: '发布请求与既有幂等记录冲突，请刷新确认。', publicationRevisionConflict: '错误页发布源修订已变化，请刷新后重试。',
    publicationTargetIneligible: '所选节点当前不允许接收错误页配置。', publicationUnavailable: '错误页发布服务暂不可用，请稍后重试。', publicationOutcomeUnknown: '发布结果待确认',
  },
  pagination: { all: '全部', assets: '错误页资产分页', rules: '错误页规则分页' },
}

const enUS: typeof zhCN = {
  title: 'Custom error pages',
  heading: 'Error pages',
  description: 'Error-page configuration.',
  tabs: { global: 'Global configuration', regional: 'Regional and node configuration' },
  legacy: {
    selectorLabel: 'Error page selection', contentLabel: 'Page content', configured: 'Modified · revision {{revision}}', notConfigured: 'Not configured',
    builtin: 'System default (unmodified)',
    delivery: {
      theme: 'Nodes serve this content now. Saving makes it the platform default and republishes it to nodes; site error page settings still take precedence.',
      fallback: 'No theme is active, so nodes answer this error with a short text. This is the default theme page; saving publishes it to nodes.',
      none: 'Nodes do not serve this error page yet in this release; saving only stores the content.',
    },
    ownFallback: {
      blacklist: 'Until saved, nodes answer a blacklisted IP with a plain-text 403 "Forbidden"; once saved, with this page.',
      http_403: 'Until saved, non-WAF blocks (access control, IP lists, regions, Referer/UA) get the same page as WAF blocks; once saved, they get this page while WAF blocks keep the WAF block page. A site\'s own 403 page takes precedence.',
      traffic_exceeded: 'Until saved, nodes answer with the built-in "traffic limit exceeded" page (status 509); once saved, with this page. A site\'s own traffic limit notice takes precedence.',
      package_expired: 'Applies only with "Close sites after package expiry" on in system settings: expired sites never reach the origin, are not cached and not billed. Until saved, nodes answer with a plain-text 403; once saved, with this page. With the setting off, expired sites keep serving and this page is not shown.',
      node_ip_access: 'For direct access by node IP, nodes answer with the "domain not configured" page until saved; once saved, with this page.',
      connection_limit: 'When connections, QPS or bandwidth exceed the limit, nodes answer with nginx\'s default 503 page until saved; once saved, with this page. A site\'s own 503 page takes precedence.',
    },
    siteLocked: 'Locking a site does not affect access; nodes do not serve this page for now. Saving only stores the content.',
    variables: 'Available variables: none. Nodes serve the page as is without substitution (such as request ID or client IP); content with template markers (double braces, ${, <%) is rejected.',
    publishing: 'Saved and publishing: error page publication revision {{revision}}; {{count}} tenants queued for republication.',
    previewTitle: 'Error page preview',
    actions: { preview: 'Preview', restore: 'Restore system default', restoreConfirm: 'Discard the changes and restore the system default?', viewPublications: 'View publications' },
    validation: { required: 'Enter page content before saving' },
    errors: { unknown: 'The operation result is not confirmed yet' },
    notices: { saved: 'Global error page saved', savedPublishing: 'Saved, publishing', restored: 'System default restored', restoredPublishing: 'System default restored, publishing' },
    options: {
      p456: 'Block page', p400: '400 error', p403: '403 error', waf_block: 'WAF block page', p502: '502 error', p504: '504 error',
      p513: 'Traffic exceeded', p512: 'Package expired', p514: 'Site locked', host_not_found: 'Domain not configured', access_ip_not_allow: 'Access node IP', p515: 'Connections exceeded',
    },
  },
  regional: {
    count: '{{count}} override configurations', empty: 'No data', labelSuffix: ':',
    actions: { add: 'Add setting', confirm: 'Confirm', removeItem: 'Remove {{item}} configuration item' },
    fields: { scope: 'Configuration scope', node: 'Select node', region: 'Select region', items: 'Configuration items' },
    columns: { scope: 'Configuration scope', items: 'Configuration items', actions: 'Actions' },
    targets: { node: 'Node', region: 'Region', nodeValue: 'Node {{id}} · {{name}}', regionValue: 'Region {{region}}' },
    placeholders: { node: 'Search by ID, node IP, or name', region: 'Select a region', items: 'Select configuration items' },
    noNodePermission: 'This account lacks node read access (nodes.read), so nodes and regions cannot be listed. Ask an administrator for it.',
    items: {
      http_400: '400 error', http_403: '403 error', http_502: '502 error', http_504: '504 error', traffic_exceeded: 'Traffic exceeded',
      package_expired: 'Package expired', site_locked: 'Site locked', domain_unconfigured: 'Domain not configured', node_ip_access: 'Access node IP', connection_limit: 'Connection limit exceeded',
    },
    dialogs: { add: 'Add setting', edit: 'Edit setting', deleteConfirm: 'Delete this override configuration?' },
    validation: { required: 'Select a configuration scope and items, then complete each error-page body.' },
    errors: { unknown: 'The operation result is not confirmed yet' },
    notices: { saved: 'Override configuration saved', deleted: 'Override configuration deleted' },
  },
  sections: { publication: 'Publication source snapshot (not activation state)', publicationReceipt: 'Immutable publication receipt', scope: 'Tenant scope', assets: 'Error-page assets', rules: 'Error-page rules' },
  actions: {
    refresh: 'Refresh', upload: 'Upload asset', delete: 'Delete', deleteAsset: 'Delete asset', deleteRule: 'Delete rule', confirmDelete: 'Confirm delete', cancel: 'Cancel',
    create: 'Create rule', edit: 'Edit', enable: 'Enable', disable: 'Disable', save: 'Save', retry: 'Retry',
    exactRetry: 'Retry exact operation', abandon: 'Abandon and refresh', previous: 'Previous', next: 'Next',
    applyScope: 'Apply scope', retryPublication: 'Retry publication source', publishNodes: 'Publish to nodes', confirmPublication: 'Confirm publication',
    retryReceipt: 'Retry publication receipt', retryExactPublication: 'Retry the same request', abandonPublication: 'Abandon and refresh publication result',
  },
  fields: {
    asset: 'Asset', status: 'Status', mime: 'Type', contentType: 'Content type', scanStatus: 'Scan status', size: 'Size', revision: 'Revision', updated: 'Updated at', actions: 'Actions',
    scopeId: 'Tenant Scope ID', scopePlaceholder: 'Enter a canonical lowercase tenant scope UUID', site: 'Site ID (optional)', siteFilter: 'Filter by site ID', category: 'Error category', matchKind: 'Match mode', from: 'From status', to: 'To status',
    assetId: 'Asset ID', ruleId: 'Rule ID', enabled: 'Enable after creation', priority: 'Priority', scope: 'Scope',
    publicationTarget: 'Publication target', nodeIds: 'Node IDs (one per line)', snapshotId: 'Snapshot ID', snapshotRevision: 'Snapshot revision', resolverSha256: 'Resolver SHA-256',
    activationTimeoutMs: 'Activation timeout (milliseconds)', observationWindowMs: 'Observation window (milliseconds)', requiredConsecutiveSuccesses: 'Required consecutive successes', maxAttempts: 'Maximum attempts', deadline: 'Deadline (RFC3339)',
    publicationId: 'Publication ID', configVersionId: 'Configuration version ID', rolloutId: 'Rollout ID', artifactSha256: 'Artifact SHA-256',
  },
  match: { exact: 'Exact status', range: 'Status range' },
  categories: { origin_response: 'Origin response', edge_route: 'Edge route', edge_connect: 'Edge connect', no_host: 'No host', unknown_site: 'Unknown site' },
  statuses: { ready: 'Ready', staged: 'Staged', initiated: 'Initiated', scan_failed: 'Scan failed', rejected: 'Rejected', deleted: 'Deleted' },
  scans: { pending: 'Pending scan', passed: 'Scan passed', rejected: 'Scan rejected', error: 'Scan error' },
  targets: { globalDefault: 'Global default', siteOverride: 'Site override' },
  publication: {
    loading: 'Loading publication source snapshot', empty: 'No publication source snapshot', loadError: 'Failed to load publication source snapshot',
    sourceOnly: 'This shows only the deterministic publication source. It does not prove edge activation or last-known-good state.',
    globalRules: 'Global rules', siteOverrides: 'Site overrides', revision: 'Revision {{revision}}', noRules: 'No rules in this snapshot',
    receiptLoading: 'Loading publication receipt', receiptEmpty: 'No publication receipt', receiptLoadError: 'Failed to load publication receipt',
    receiptOnly: 'The receipt confirms only the production publication request and immutable artifact. It does not prove node activation or health.',
    sourceRevision: 'Source revision {{revision}}', publicationRevision: 'Publication revision {{revision}}', nodeCount: '{{count}} nodes', targetExplicit: 'Explicit nodes', targetResolver: 'Line-group snapshot',
    targets: { nodes: 'Explicit nodes', lineGroupSnapshot: 'Line-group snapshot' },
    validation: { source: 'The current publication source snapshot is unavailable.', nodes: 'Enter unique canonical lowercase node UUIDs.', snapshot: 'Complete the line-group snapshot fields with valid values.', health: 'Enter valid health-check, retry, and deadline values.' },
  },
  data: { selectScope: 'Apply a tenant scope first', loadingAssets: 'Loading error-page assets', loadingRules: 'Loading error-page rules', emptyAssets: 'No error-page assets', emptyRules: 'No error-page rules' },
  upload: { choose: 'Choose an HTML, plain-text, or JSON file', success: 'Asset uploaded', invalid: 'Choose an HTML, plain-text, or JSON file no larger than 1 MiB.' },
  validation: { scope: 'Enter a canonical lowercase tenant scope UUID.', required: 'Complete every required rule field with valid values.', status: 'Enter a status code from 100 to 599.', range: 'The end status must not be below the start status.', uuid: 'Enter a canonical lowercase UUID.' },
  dialogs: {
    deleteAsset: 'Delete this error-page asset?', deleteRule: 'Delete this error-page rule?', unknownTitle: 'Write result unknown',
    unknownDescription: 'The connection ended before the write result was confirmed. Retry the exact operation, or abandon it and refresh to confirm.', publishPublication: 'Publish error-page configuration',
  },
  notices: { saved: 'Rule saved', deleted: 'Rule deleted', enabled: 'Rule state updated' },
  errors: {
    forbiddenTitle: 'No permission to view error pages', forbiddenDescription: 'The current platform identity lacks error_pages.read permission.',
    requestFailed: 'The error-page request failed. Try again.', notFound: 'The requested error-page resource was not found.', conflict: 'The resource already exists or conflicts. Refresh and try again.',
    stale: 'The resource was updated by another operation. Refresh and try again.', validation: 'The submitted values failed server validation.', unavailable: 'The error-page service is temporarily unavailable.',
    network: 'The network request failed and the write result may be unknown.', invalidResponse: 'The error-page service returned invalid data.',
    unsafeContent: 'The content contains unsafe elements. Revise it and try again.', scanRejected: 'The content safety scan was rejected.', quotaExceeded: 'The custom error-page quota is exhausted.',
    publicationReadForbidden: 'You do not have permission to view error-page publications.', publicationManageForbidden: 'You do not have permission to publish error-page configuration.',
    publicationIdempotencyConflict: 'The publication conflicts with an existing idempotency record. Refresh to confirm the result.', publicationRevisionConflict: 'The publication source revision changed. Refresh and try again.',
    publicationTargetIneligible: 'The selected nodes cannot currently receive error-page configuration.', publicationUnavailable: 'The error-page publication service is temporarily unavailable. Try again later.', publicationOutcomeUnknown: 'Publication result pending confirmation',
  },
  pagination: { all: 'All', assets: 'Error-page asset pagination', rules: 'Error-page rule pagination' },
}

type Messages = typeof zhCN

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => { tokens.push(token); return `__TOKEN_${tokens.length - 1}__` })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`.replace(/__TOKEN_(\d+)__/g, (_m, i: string) => tokens[Number(i)] ?? '')
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as Messages

export const errorPagesMessages = {
  'zh-CN': zhCN,
  'en-US': enUS,

} as unknown as Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages>

if (import.meta.env.MODE === 'test') {
  errorPagesMessages['qps-ploc'] = pseudoCN
  errorPagesMessages['qps-Ploc'] = pseudoCN
}

for (const [locale, messages] of Object.entries(errorPagesMessages)) {
  i18n.addResourceBundle(locale, 'errorPagesPage', messages, true, true)
}
