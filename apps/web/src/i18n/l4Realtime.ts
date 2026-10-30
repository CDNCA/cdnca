import i18n from './index'

const zhCN = {
  title: '四层实时监控',
  heading: '四层转发实时监控',
  description: '查看 TCP/UDP 转发的实时连接、流量和错误，并保留节点原始计数。',
  actions: { query: '查询', refresh: '刷新', retry: '重试', previous: '上一页', next: '下一页' },
  pager: { total: '共 {{count}} 条', totalMore: '已加载 {{count}} 条，还有更多，总数未统计' },
  tabs: { traffic: '带宽流量', ranking: '端口排行' },
  filters: {
    tenant: '租户', site: '站点 ID', stream: '流 ID', node: '节点', protocol: '协议', port: '端口', portPlaceholder: '输入端口，如88/TCP 99/UDP', range: '时间范围', rankingRange: '排行时间范围',
    limit: '每页数量', tenantRequired: '平台视图必须指定租户 ID。', allTenants: '全部租户', allNodes: '全部节点',
    invalidUuid: '请输入有效的 UUID。', invalidPort: '请输入 1-65535 的端口。', invalidWindow: '请选择有效的 UTC 时间范围。', rangeTooLong: '时间范围最长为 31 天。',
  },
  ranges: { one: '近1小时', six: '近6小时', twelve: '近12小时', day: '近24小时', custom: '自定义' },
  rankingRanges: { tenMinutes: '10分钟实时', thirtyMinutes: '近30分钟', oneHour: '近1小时' },
  charts: { bandwidth: '带宽', traffic: '流量' },
  protocols: { all: '全部协议', tcp: 'TCP', udp: 'UDP' },
  metrics: { sessions: '连接数', bytesUp: '上行流量', bytesDown: '下行流量', errors: '错误数', watermark: '来源水位', finalized: '结算时间' },
  columns: {
    rank: '排行', time: '时间', node: '节点', site: '站点', stream: '流', listener: '监听器', protocol: '协议', port: '端口',
    sessions: '连接数', traffic: '流量', bytesUp: '上行', bytesDown: '下行', errors: '错误',
  },
  pagination: { page: '第 {{page}} 页' },
  states: {
    loading: '正在加载四层实时监控', empty: '当前筛选范围内暂无四层实时数据', emptyRanking: '暂无数据', unknown: '实时数据结果无法识别，请稍后重试。',
    permissionTitle: '无权查看四层实时监控', permissionDescription: '当前身份缺少四层实时监控读取权限。',
    invalidRequest: '筛选条件无效，请检查时间范围和资源标识。', unavailable: '四层实时数据暂不可用，请稍后重试。',
    timeout: '查询超时，请缩小时间范围后重试。', invalidResponse: '四层实时数据完整性校验失败。', requestFailed: '四层实时监控加载失败，请稍后重试。', incomplete: '结果完整性待确认：数据量超出单次读取上限，请缩小时间范围或增加筛选条件。',
  },
  evidence: { snapshot: '快照 {{time}}', watermark: '来源水位 {{value}}', finalized: '已结算至 {{time}}' },
  sessionLog: {
    heading: '四层访问日志', forbidden: '当前身份缺少网站读取权限，无法查看四层访问日志。',
    noStreamPermission: '当前账号没有“四层转发查看”（streams.read）权限，无法按转发筛选，显示全部转发的日志。',
    stream: '转发', streamPlaceholder: '全部转发', notEnabled: '未开会话日志', client: '客户端 IP', clientPlaceholder: 'IP 或 CIDR', reason: '结束原因',
    invalidClient: '请输入有效的 IP 或 CIDR。', via: '经 {{peer}}', empty: '暂无访问日志（仅开启“会话日志”的转发会记录）',
    storeUnavailable: '访问日志存储未就绪（分析库缺少 l4_session_logs_v1 表），请联系管理员升级主控。',
    help: '每个连接一行，含被地域屏蔽、新建速率、连接数限制、防护规则拒绝的连接；只记录开启了“会话日志”的转发，保留 30 天。“正常结束”也包含空闲超时。',
    columns: { finished: '结束时间', client: '客户端', upstream: '上游', duration: '时长', reason: '结束原因' },
    reasons: {
      closed: '正常结束', killed: '已断开', geo_blocked: '地域屏蔽', rate_limited: '超新建速率', banned: '已拉黑', conn_limited: '超连接数',
      bad_request: 'PROXY 头错误', forbidden: '拒绝访问', upstream_failed: '上游失败', internal_error: '内部错误', config_error: '配置错误',
      guard_blocked: '防护规则拦截',
    },
  },
  live: {
    heading: '四层实时连接', forbidden: '当前身份缺少四层转发读取权限，无法查看实时连接。',
    pickStream: '请选择一个转发后刷新。', empty: '当前没有连接',
    streamsTruncated: '匹配的转发超过 {{count}} 个，只查询了最新的 {{count}} 个，可按租户、转发或端口筛选。',
    help: '打开即从节点实时读取全部转发的 TCP 连接（UDP 不列出），按开始时间倒序；上方条件用于筛选。只有开启“会话日志”的 TCP 转发会登记连接，登记后显示真实客户端（PROXY 协议）和开始时间；未开启的只显示节点看到的对端地址，且与网站或其它转发共用端口时无法归属、不显示。断开需节点 agent 以 root 运行；非 root 安装的节点只能查看。',
    problems: '部分节点没有返回连接：', truncated: '连接数超过显示上限（每个节点每个转发 200 条、总计 1000 条），只显示最新的部分，可按条件筛选。',
    untracked: '未登记', viewOnly: '仅可查看', close: '断开', closeIP: '断开该 IP 全部', confirmClose: '断开这个连接？',
    confirmCloseIP: '断开 {{ip}} 在本页的全部连接？', closed: '已断开 {{count}} 个连接', closeFailed: '断开失败，请稍后重试。',
    ban: '拉黑', confirmBan: '拉黑 {{ip}}？', banSeconds: '拉黑时长（秒）',
    banHelp: '在本转发的防护规则里加入（或并入）一条“断开并拉黑”规则，保存后发布到节点；该 IP 的新连接都会被断开并拉黑，直到在转发详情的防护规则里删除它。可断开的已有连接会一并断开。',
    banned: '已把 {{ip}} 加入防护规则（每次连接拉黑 {{seconds}} 秒），节点生效情况见发布状态', alreadyBanned: '{{ip}} 已在同样时长的拉黑规则里',
    banFailed: '拉黑失败，请稍后重试。', banConflict: '转发刚被修改，请刷新后再拉黑。',
    columns: { started: '开始时间', received: '已接收', sent: '已发送', action: '操作' },
    states: { ok: '正常', unsupported: '节点版本不支持实时连接，升级后自动可用', offline: '节点离线', error: '查询失败' },
  },
}

const enUS = {
  title: 'Layer 4 realtime monitoring',
  heading: 'Layer 4 forwarding realtime monitoring',
  description: 'Inspect realtime TCP/UDP forwarding sessions, traffic, errors, and node-level raw counts.',
  actions: { query: 'Query', refresh: 'Refresh', retry: 'Retry', previous: 'Previous page', next: 'Next page' },
  pager: { total: '{{count}} total', totalMore: '{{count}} loaded, more available (total not counted)' },
  tabs: { traffic: 'Bandwidth and traffic', ranking: 'Port ranking' },
  filters: {
    tenant: 'Tenant', site: 'Site ID', stream: 'Stream ID', node: 'Node', protocol: 'Protocol', port: 'Port', portPlaceholder: 'Enter a port, e.g. 88/TCP 99/UDP', range: 'Time range', rankingRange: 'Ranking time range',
    limit: 'Rows per page', tenantRequired: 'A tenant ID is required for the platform view.', allTenants: 'All tenants', allNodes: 'All nodes',
    invalidUuid: 'Enter a valid UUID.', invalidPort: 'Enter a port from 1 to 65535.', invalidWindow: 'Choose a valid UTC time range.', rangeTooLong: 'The range cannot exceed 31 days.',
  },
  ranges: { one: 'Last hour', six: 'Last 6 hours', twelve: 'Last 12 hours', day: 'Last 24 hours', custom: 'Custom' },
  rankingRanges: { tenMinutes: 'Realtime 10 minutes', thirtyMinutes: 'Last 30 minutes', oneHour: 'Last hour' },
  charts: { bandwidth: 'Bandwidth', traffic: 'Traffic' },
  protocols: { all: 'All protocols', tcp: 'TCP', udp: 'UDP' },
  metrics: { sessions: 'Sessions', bytesUp: 'Bytes up', bytesDown: 'Bytes down', errors: 'Errors', watermark: 'Source watermark', finalized: 'Finalized through' },
  columns: {
    rank: 'Rank', time: 'Time', node: 'Node', site: 'Site', stream: 'Stream', listener: 'Listener', protocol: 'Protocol', port: 'Port',
    sessions: 'Sessions', traffic: 'Traffic', bytesUp: 'Up', bytesDown: 'Down', errors: 'Errors',
  },
  pagination: { page: 'Page {{page}}' },
  states: {
    loading: 'Loading Layer 4 realtime monitoring', empty: 'No Layer 4 realtime data in this range', emptyRanking: 'No data', unknown: 'The realtime result is unknown. Try again later.',
    permissionTitle: 'No permission to view Layer 4 realtime monitoring', permissionDescription: 'The current identity lacks Layer 4 monitoring read permission.',
    invalidRequest: 'Check the range and resource identifiers.', unavailable: 'Layer 4 realtime data is temporarily unavailable.',
    timeout: 'The query timed out. Use a smaller range.', invalidResponse: 'Layer 4 realtime facts failed integrity validation.', requestFailed: 'Layer 4 realtime monitoring could not be loaded.', incomplete: 'Completeness unconfirmed: the result exceeded the read limit. Use a smaller range or add filters.',
  },
  evidence: { snapshot: 'Snapshot {{time}}', watermark: 'Source watermark {{value}}', finalized: 'Finalized through {{time}}' },
  sessionLog: {
    heading: 'Layer 4 access log', forbidden: 'The current identity lacks site read permission for the Layer 4 access log.',
    noStreamPermission: 'This account lacks forward read access (streams.read), so logs cannot be filtered by forward and all forwards are shown.',
    stream: 'Forward', streamPlaceholder: 'All forwards', notEnabled: 'session log off', client: 'Client IP', clientPlaceholder: 'IP or CIDR', reason: 'End reason',
    invalidClient: 'Enter a valid IP or CIDR.', via: 'via {{peer}}', empty: 'No access log (only forwards with Session log on are logged)',
    storeUnavailable: 'The access log store is not ready (the analytics database lacks l4_session_logs_v1); ask the administrator to upgrade the control plane.',
    help: 'One row per connection, including those refused by region blocking, the new connection rate, the connection limit or a guard rule; only forwards with Session log on, kept 30 days. Closed includes idle timeouts.',
    columns: { finished: 'Finished', client: 'Client', upstream: 'Upstream', duration: 'Duration', reason: 'End reason' },
    reasons: {
      closed: 'Closed', killed: 'Disconnected', geo_blocked: 'Region blocked', rate_limited: 'Over new rate', banned: 'Banned', conn_limited: 'Over connection limit',
      bad_request: 'Bad PROXY header', forbidden: 'Forbidden', upstream_failed: 'Upstream failed', internal_error: 'Internal error', config_error: 'Configuration error',
      guard_blocked: 'Guard rule',
    },
  },
  live: {
    heading: 'Layer 4 live connections', forbidden: 'The current identity lacks forwarding read permission for live connections.',
    pickStream: 'Choose a forward, then refresh.', empty: 'No connections',
    streamsTruncated: 'More than {{count}} forwards match; only the newest {{count}} were asked. Filter by tenant, forward or port.',
    help: "Reads the TCP connections of every forward from the nodes when opened (UDP is not listed), newest first; the filters above narrow it. Only TCP forwards with Session log on register their connections, which shows the real client (PROXY protocol) and start; otherwise only the peer the node sees is shown, and connections on a port shared with sites or other forwards cannot be attributed and are not shown. Disconnecting needs the node agent to run as root; non-root installs can only view.",
    problems: 'Some nodes returned no connections:', truncated: 'More connections than shown (200 per node and forward, 1000 in total); only the newest are shown. Use the filters.',
    untracked: 'Not tracked', viewOnly: 'View only', close: 'Disconnect', closeIP: 'Disconnect this IP', confirmClose: 'Disconnect this connection?',
    confirmCloseIP: 'Disconnect all connections of {{ip}} on this page?', closed: 'Disconnected {{count}} connections', closeFailed: 'Disconnecting failed. Try again later.',
    ban: 'Ban', confirmBan: 'Ban {{ip}}?', banSeconds: 'Ban duration (seconds)',
    banHelp: "Adds (or merges into) a 'Disconnect and ban' rule in this forward's guard rules and publishes it; every new connection of the IP is disconnected and banned until you delete it from the forward's guard rules. Open connections that can be disconnected are closed too.",
    banned: 'Added {{ip}} to the guard rules (banned {{seconds}} seconds per connection); see the publication state for the nodes', alreadyBanned: '{{ip}} is already in a ban rule with this duration',
    banFailed: 'Banning failed. Try again later.', banConflict: 'The forward was just changed. Refresh and ban again.',
    columns: { started: 'Started', received: 'Received', sent: 'Sent', action: 'Action' },
    states: { ok: 'OK', unsupported: 'Node version does not support live connections; available after upgrade', offline: 'Node offline', error: 'Query failed' },
  },
}

type Messages = typeof zhCN

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as Messages
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN })) {
  i18n.addResourceBundle(locale, 'l4Realtime', messages, true, true)
}

export { enUS, zhCN }
