import i18n from './index'

const zhCN = {
  title: '节点详情',
  description: '查看节点清单信息与主控确认的在线状态。',
  actions: { view: '查看详情', refresh: '刷新' },
  fields: {
    id: '节点 ID', description: '描述', region: '区域', ipv4: 'IPv4', ipv6: 'IPv6',
    adminState: '管理状态', revision: '版本', createdAt: '创建时间', updatedAt: '更新时间',
    presence: '在线状态', agentVersion: 'Agent 版本', lastHeartbeat: '最近心跳',
    sequence: '会话与心跳序列', projection: '投影状态', lease: '租约信号', projectedAt: '投影时间',
    marketProbe: '市场探测', openRestyVersion: 'OpenResty 运行时', nativeRuntime: '原生运行时', nativeRuntimePrevious: '原',
    ticket: '授权票据',
  },
  protection: {
    title: 'DDoS 防护', state: '防护状态', reason: '原因', detail: '节点说明', observedAt: '上报时间',
    notReported: '节点尚未上报防护状态（离线或 Agent 版本较旧）', loadFailed: '读取防护状态失败',
  },
  marketProbeRoles: { probe_only: '仅探测', join_market: '加入市场', disabled: '关闭' },
  nativeRuntimeStates: { switched: '已切换', unchanged: '未变', rolled_back: '已回滚' },
  states: { pending: '待注册', active: '已启用', draining: '排空中', disabled: '已禁用', retired: '已退役' },
  presence: { online: '在线', offline: '离线', unknown: '未知' },
  freshness: { fresh: '投影新鲜', stale: '投影过期', never: '从未投影' },
  lease: { present: '租约有效', absent: '租约缺失', unavailable: '租约信号不可用' },
  telemetry: {
    sequence: '会话 {{epoch}} / 心跳 {{sequence}}',
    revision: '版本 {{revision}}',
    ticketUntil: '有效至 {{time}}',
    notReported: '未上报',
    notSet: '未设置',
  },
  data: { loading: '正在加载节点详情' },
  errors: {
    forbiddenTitle: '无权查看节点详情',
    forbiddenDescription: '当前平台身份缺少节点读取权限。',
    notFoundTitle: '节点详情不存在',
    notFoundDescription: '请求的节点已不存在或当前作用域不可见。',
    invalidResponse: '节点详情响应无效，请重试',
    unavailable: '节点详情暂不可用，请稍后重试',
    transitionConflict: '端口切换状态已变化，请刷新后重试',
    transitionInvalid: '端口切换参数无效，请检查输入',
    transitionNotFound: '端口切换任务不存在或已不可见',
    transitionUnavailable: '端口切换暂不可用，请稍后重试',
    rollbackWindow: '回滚分钟数必须大于兼容窗口分钟数',
  },
  transition: {
    title: '主控通信端口切换',
    modalTitle: '创建通信端口切换',
    revision: '切换修订 {{revision}}',
    created: '通信端口切换已创建',
    finalized: '通信端口切换已提交最终确认',
    rollbackAccepted: '通信端口回滚已提交',
    actions: { start: '切换通信端口', create: '创建切换', cancel: '取消', finalize: '最终确认', rollback: '回滚' },
    fields: {
      oldEndpoint: '旧公开地址', newEndpoint: '新公开地址', activeEndpoint: '当前公开地址',
      oldAddress: '旧公开地址', oldListenAddress: '旧监听地址', oldServerName: '旧服务名',
      newAddress: '新公开地址', newListenAddress: '新监听地址', newServerName: '新服务名',
      compatibilityDeadline: '兼容窗口截止', rollbackDeadline: '回滚窗口截止', statusRevision: '状态修订',
      compatibilityMinutes: '兼容窗口（分钟）', rollbackMinutes: '回滚窗口（分钟）',
    },
    placeholders: { endpoint: '例如 gateway.example.com:7443', listenAddress: '例如 0.0.0.0:7443' },
    states: { preparing: '准备中', switching: '切换中', switched: '已切换', failed: '失败', rolled_back: '已回滚', finalized: '已最终确认' },
    batch: {
      action: '批量更换通讯端口',
      title: '为 {{count}} 个节点更换主控通讯端口',
      description: '同一组新旧地址会为每个所选节点各创建一个切换任务，节点分别切换、各自确认或回滚（在节点详情页操作）。',
      submit: '创建 {{count}} 个切换',
      node: '节点',
      created: '已创建',
      resultsTitle: '批量创建结果',
      summary: '成功 {{succeeded}} 个，失败 {{failed}} 个',
    },
  },
}

const enUS: typeof zhCN = {
  title: 'Node details',
  description: 'View node inventory and controller-confirmed presence.',
  actions: { view: 'View details', refresh: 'Refresh' },
  fields: {
    id: 'Node ID', description: 'Description', region: 'Region', ipv4: 'IPv4', ipv6: 'IPv6',
    adminState: 'Administrative state', revision: 'Revision', createdAt: 'Created at', updatedAt: 'Updated at',
    presence: 'Presence', agentVersion: 'Agent version', lastHeartbeat: 'Last heartbeat',
    sequence: 'Session and heartbeat sequence', projection: 'Projection status', lease: 'Lease signal', projectedAt: 'Projected at',
    marketProbe: 'Market probe', openRestyVersion: 'OpenResty runtime', nativeRuntime: 'Native runtime', nativeRuntimePrevious: 'was',
    ticket: 'Service ticket',
  },
  protection: {
    title: 'DDoS protection', state: 'Protection state', reason: 'Reason', detail: 'Node detail', observedAt: 'Reported at',
    notReported: 'The node has not reported its protection state (offline or an older Agent)', loadFailed: 'Could not read the protection state',
  },
  marketProbeRoles: { probe_only: 'Probe only', join_market: 'Joined market', disabled: 'Off' },
  nativeRuntimeStates: { switched: 'Switched', unchanged: 'Unchanged', rolled_back: 'Rolled back' },
  states: { pending: 'Pending enrollment', active: 'Enabled', draining: 'Draining', disabled: 'Disabled', retired: 'Retired' },
  presence: { online: 'Online', offline: 'Offline', unknown: 'Unknown' },
  freshness: { fresh: 'Projection fresh', stale: 'Projection stale', never: 'Never projected' },
  lease: { present: 'Lease valid', absent: 'Lease missing', unavailable: 'Lease signal unavailable' },
  telemetry: {
    sequence: 'Session {{epoch}} / heartbeat {{sequence}}',
    revision: 'Revision {{revision}}',
    ticketUntil: 'Valid until {{time}}',
    notReported: 'Not reported',
    notSet: 'Not set',
  },
  data: { loading: 'Loading node details' },
  errors: {
    forbiddenTitle: 'No permission to view node details',
    forbiddenDescription: 'The current platform identity does not have node read permission.',
    notFoundTitle: 'Node details not found',
    notFoundDescription: 'The requested node no longer exists or is not visible in this scope.',
    invalidResponse: 'The node detail response was invalid. Try again.',
    unavailable: 'Node details are temporarily unavailable. Try again later.',
    transitionConflict: 'The transition state changed. Refresh and try again.',
    transitionInvalid: 'The transition input is invalid. Check the values.',
    transitionNotFound: 'The transition does not exist or is not visible.',
    transitionUnavailable: 'The transition is temporarily unavailable. Try again later.',
    rollbackWindow: 'The rollback window must be longer than the compatibility window.',
  },
  transition: {
    title: 'Controller communication-port transition',
    modalTitle: 'Create communication-port transition',
    revision: 'Transition revision {{revision}}',
    created: 'Communication-port transition created',
    finalized: 'Communication-port finalization submitted',
    rollbackAccepted: 'Communication-port rollback submitted',
    actions: { start: 'Switch communication port', create: 'Create transition', cancel: 'Cancel', finalize: 'Finalize', rollback: 'Roll back' },
    fields: {
      oldEndpoint: 'Old public endpoint', newEndpoint: 'New public endpoint', activeEndpoint: 'Active public endpoint',
      oldAddress: 'Old public endpoint', oldListenAddress: 'Old listener address', oldServerName: 'Old server name',
      newAddress: 'New public endpoint', newListenAddress: 'New listener address', newServerName: 'New server name',
      compatibilityDeadline: 'Compatibility deadline', rollbackDeadline: 'Rollback deadline', statusRevision: 'Status revision',
      compatibilityMinutes: 'Compatibility window (minutes)', rollbackMinutes: 'Rollback window (minutes)',
    },
    placeholders: { endpoint: 'For example gateway.example.com:7443', listenAddress: 'For example 0.0.0.0:7443' },
    states: { preparing: 'Preparing', switching: 'Switching', switched: 'Switched', failed: 'Failed', rolled_back: 'Rolled back', finalized: 'Finalized' },
    batch: {
      action: 'Change communication port in bulk',
      title: 'Change the controller communication port of {{count}} nodes',
      description: 'The same old and new endpoints create one transition per selected node; each node switches, finalizes or rolls back on its own (on the node detail page).',
      submit: 'Create {{count}} transitions',
      node: 'Node',
      created: 'Created',
      resultsTitle: 'Bulk creation results',
      summary: '{{succeeded}} succeeded, {{failed}} failed',
    },
  },
}

type Messages = typeof zhCN

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
      tokens.push(token)
      return `§${tokens.length - 1}§`
    })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
      .replace(/§(\d+)§/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as Messages

export const nodeInventoryDetailMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(nodeInventoryDetailMessages)) {
  i18n.addResourceBundle(locale, 'nodeInventoryDetail', messages, true, true)
}
