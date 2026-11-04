import i18n from './index'

// 我的上架 → 可上报节点。每个自有节点组哪些节点会报给市场、其余为什么不报、下一步做什么。
const zhCN = {
  column: '可上报节点',
  columnHelp: '会报给市场、买方能用到的节点数 / 节点组里的节点数。为 0 时买方看到的是"共 0 个节点"。',
  cell: '{{reportable}} / {{total}}',
  none: '—',
  probeOffTag: '未开启上报',
  open: '查看',
  title: '可上报节点：{{name}}',
  help: '主控每 5 分钟把节点组里符合条件的节点报给市场；不符合的不报，买方也就用不到。下面逐个列出每个节点的情况和下一步。',
  groupTitle: '节点组 {{name}}',
  groupSummary: '{{reportable}} / {{total}} 个节点会报给市场',
  loadFailed: '读取失败：{{code}}',
  resale: '转售的部分由上游卖家供货，不在这里显示。',
  probe: {
    disabled: '本主控关闭了节点上报（MARKET_PROBE_ENABLED=false），所有节点组都不会报给市场。请服务器管理员删掉这一行或改为 true 后重启主控。',
    no_edge_nats: '本主控没有连上边缘消息服务（NATS），节点上报没有启动，所有节点组都不会报给市场。请服务器管理员检查边缘部署配置后重启主控。',
    market_off: '本主控未接入节点市场。',
  },
  columns: { node: '节点', address: '地址', location: '地区 / 运营商', role: '市场角色', status: '状态', next: '下一步' },
  location: '{{region}} / {{carrier}}',
  emptyValue: '（空）',
  roles: { join_market: '加入市场', probe_only: '仅探测', disabled: '已关闭', unknown: '未上报' },
  roleSources: { assigned: '主控下发', local_join: '节点本地设为加入', local_leave: '节点本地设为退出' },
  ok: '会上报',
  reasons: {
    node_inactive: '节点已停用', not_serving: '节点当前不在服务',
    agent_lacks_market_probe: '节点 agent 不支持市场拨测', node_not_join_market: '节点未加入市场',
    address_not_public: '地址不是公网地址：{{value}}', region_unmapped: '地区无法识别：{{value}}', carrier_unmapped: '中国大陆节点的运营商无法识别：{{value}}（填电信、联通、移动或 BGP 多线；如果节点其实在港澳台或海外，改地区即可）',
  },
  next: {
    node_inactive: '在节点管理里启用该节点，或把它移出节点组。',
    not_serving: '等节点恢复在线并通过健康检查；长时间不恢复请到节点管理查看。',
    agent_lacks_market_probe: '升级节点 agent，并确认节点配置里 market_probe.enabled 为 true。',
    joinPending: '已下发"加入市场"，等节点下一次心跳（约 1 分钟）。',
    joinOld: '节点 agent 版本较旧，不接受主控下发：请升级节点 agent。',
    joinLeave: '节点本地设了 market_probe.leave_market，主控不能让它加入。需要上架时请在节点上删掉这一项后重启 agent。',
    joinDisabled: '节点关闭了市场拨测（market_probe.enabled=false），请在节点配置里打开后重启 agent。',
    address_not_public: '节点组里只有内网地址：给节点配置公网 IP 后，重新保存节点组。',
    location: '在节点管理 → 编辑节点 → IP 归属里填写，然后点"按当前 IP 归属刷新"。代码不会替你猜测。',
  },
  editLocation: '去编辑 IP 归属',
  refresh: '按当前 IP 归属刷新',
  refreshHelp: '用节点当前的 IP 归属重新保存这个节点组（节点不变）。',
  refreshed: '已按当前 IP 归属刷新节点组',
  refreshFailed: '刷新失败：{{code}}',
  unmapped: {
    title: '以下节点的 IP 归属缺少市场能识别的地区或运营商，不能用于市场供给：',
    item: '{{name}}：缺{{fields}}（地区 {{region}}，运营商 {{carrier}}）',
    fields: { region: '地区', carrier: '运营商' },
    fix: '请到节点管理 → 编辑节点 → IP 归属里补齐后重试。',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  column: 'Reportable nodes',
  columnHelp: 'Nodes reported to the market (usable by buyers) / nodes in the group. At 0 buyers see "0 nodes".',
  cell: '{{reportable}} / {{total}}',
  none: '—',
  probeOffTag: 'Reports off',
  open: 'View',
  title: 'Reportable nodes: {{name}}',
  help: 'Every 5 minutes this controller reports the group\'s eligible nodes to the market; the others are not reported and buyers cannot use them. Each node is listed below with what to do next.',
  groupTitle: 'Node group {{name}}',
  groupSummary: '{{reportable}} / {{total}} nodes are reported',
  loadFailed: 'Could not load: {{code}}',
  resale: 'Resold parts are supplied by the upstream seller and are not shown here.',
  probe: {
    disabled: 'Node reports are off on this controller (MARKET_PROBE_ENABLED=false): no group is reported. Ask the server administrator to remove the line or set it to true and restart the controller.',
    no_edge_nats: 'This controller is not connected to the edge messaging service (NATS), so node reports did not start and no group is reported. Ask the server administrator to check the edge deployment and restart the controller.',
    market_off: 'This controller has not joined the node market.',
  },
  columns: { node: 'Node', address: 'Address', location: 'Region / carrier', role: 'Market role', status: 'Status', next: 'Next step' },
  location: '{{region}} / {{carrier}}',
  emptyValue: '(empty)',
  roles: { join_market: 'Joined', probe_only: 'Probe only', disabled: 'Off', unknown: 'Not reported' },
  roleSources: { assigned: 'set by the controller', local_join: 'joined locally on the node', local_leave: 'left locally on the node' },
  ok: 'Reported',
  reasons: {
    node_inactive: 'Node disabled', not_serving: 'Node not serving now',
    agent_lacks_market_probe: 'Node agent does not support market probes', node_not_join_market: 'Node has not joined the market',
    address_not_public: 'Address is not public: {{value}}', region_unmapped: 'Region not recognized: {{value}}', carrier_unmapped: 'Mainland China node carrier not recognized: {{value}} (use Telecom, Unicom, Mobile or BGP; if the node is really in Hong Kong, Macau, Taiwan or abroad, fix the region instead)',
  },
  next: {
    node_inactive: 'Enable the node under Nodes, or take it out of the group.',
    not_serving: 'Wait until the node is online and passes health checks; check it under Nodes if it does not recover.',
    agent_lacks_market_probe: 'Upgrade the node agent and make sure market_probe.enabled is true in the node configuration.',
    joinPending: 'Join was sent; waiting for the node\'s next heartbeat (about a minute).',
    joinOld: 'The node agent is too old to take the controller\'s role: upgrade the node agent.',
    joinLeave: 'The node sets market_probe.leave_market locally, so the controller cannot join it. To sell it, remove that setting on the node and restart the agent.',
    joinDisabled: 'Market probes are off on the node (market_probe.enabled=false): turn them on in the node configuration and restart the agent.',
    address_not_public: 'The group has only private addresses for this node: give the node a public IP, then save the group again.',
    location: 'Fill it in under Nodes → Edit node → IP location, then click "Refresh from current IP location". It is never guessed.',
  },
  editLocation: 'Edit IP location',
  refresh: 'Refresh from current IP location',
  refreshHelp: 'Save this node group again with each node\'s current IP location (same nodes).',
  refreshed: 'Node group refreshed from the current IP locations',
  refreshFailed: 'Refresh failed: {{code}}',
  unmapped: {
    title: 'These nodes\' IP location lacks a region or carrier the market recognizes, so they cannot supply the market:',
    item: '{{name}}: missing {{fields}} (region {{region}}, carrier {{carrier}})',
    fields: { region: 'region', carrier: 'carrier' },
    fix: 'Complete it under Nodes → Edit node → IP location and try again.',
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  if (Array.isArray(value)) return value.map(pseudoTree)
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}
const pseudoCN = pseudoTree(zhCN) as Messages

export const poolReportMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN }

for (const [locale, messages] of Object.entries(poolReportMessages)) {
  i18n.addResourceBundle(locale, 'poolReport', messages, true, true)
}
