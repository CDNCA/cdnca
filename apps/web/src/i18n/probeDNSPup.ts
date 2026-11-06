import i18n from './index'

const zhCN = {
  title: 'dnspup 拨测',
  intro: '用你自己的 dnspup 客户 API Key，从 dnspup 全国检测点拨测源站与聚合边缘第三方 CDN 接入点，作为节点拨测之外的独立来源。每个检测点算一票，与节点票合并判定；额度不足、限流或 Key 被拒时自动暂停并改用其它来源，同时发告警。dnspup 每次受理扣 1 次月额度（测试连接不计费）。',
  notLicensed: '当前授权不含「dnspup 拨测」模块，可以查看但不能启用或测试。',
  forbidden: '需要 dnspup 拨测管理权限',
  limits: 'dnspup 的 HTTP 拨测只能连接 URL 本身的主机：源站回源 Host 与连接地址不同（如 IP 源站带站点域名）或自定义 CA 的源站不会派给 dnspup；聚合边缘第三方 CDN 接入点用 TCP 连接 443 判定连通。',
  form: {
    enabled: '启用 dnspup 拨测', baseURL: 'dnspup 接口地址', apiKey: 'API Key', apiSecret: 'API Secret',
    secretKeep: '已配置（指纹 {{fingerprint}}），留空保持不变；填新值即换钥', secretUnset: '未配置', clearSecret: '清除已保存的 Secret',
    sourceDomain: '绑定的服务器域名', sourceDomainExtra: 'Key 绑定服务器域名时填写（请求会签名）；绑定固定 IP 时留空',
    originSources: '源站拨测来源顺序', edgeSources: '聚合边缘拨测来源顺序',
    sourcesExtra: '按顺序询问，前一来源票数不足（少于 2 票或平票）时由下一来源补足；未列出的来源不使用',
    save: '保存', test: '测试连接与能力', saved: '已保存',
    testOK: '连接正常：异步拨测可用，本月额度 {{used}} / {{limit}}', testFailed: '测试未通过：{{reason}}',
  },
  sources: { node: '节点拨测', dnspup: 'dnspup 检测点', controller: '主控直拨' },
  node: {
    title: '节点可用性拨测',
    intro: '用 dnspup 运营商检测点按频率拨测每个节点 IP 的端口，结果进节点「监控日志」。本机探测与 dnspup 多数检测点都失败才暂停节点解析；只有 dnspup 失败只告警。未启用插件、频率关闭、暂停或额度用完时只用节点本机探测，不会因缺少拨测数据判节点离线。',
    inactive: 'dnspup 拨测未在使用（未授权、未启用、未配置 Key 或已暂停），节点只由本机探测判定。',
    interval: '拨测频率', intervals: { off: '关闭', every: '每 {{minutes}} 分钟' },
    groups: '检测点运营商/地区', groupNames: { domestic: '国内（不限运营商）', telecom: '电信', unicom: '联通', mobile: '移动', overseas: '海外' },
    pointsPerGroup: '每组检测点数', failurePercent: '失败检测点比例超过（%）', failureRounds: '连续失败次数', recoveryRounds: '连续恢复次数',
    lowBalance: '余额预警线（次）', lowBalanceExtra: '本月剩余次数低于此值时自动降频（频率 ×3）并通知管理员',
    save: '保存节点拨测设置', saved: '节点拨测设置已保存',
    estimate: '预计消耗', estimateValue: '每天约 {{day}} 次 · 每月约 {{month}} 次',
    estimateExtra: 'dnspup 按请求计量：每个节点 IP 每轮扣 1 次，与检测点数无关（当前 {{addresses}} 个节点 IP，每轮 {{points}} 个检测点）。点数请到 dnspup 充值，插件不代收费。',
    rotate: '节点 IP 超过 {{max}} 个时每轮轮流拨测一部分，单个节点的拨测间隔相应变长。',
    balance: 'dnspup 余额', balanceValue: '剩余 {{remaining}} / {{limit}} 次', balanceUnlimited: '不限额（已用 {{used}} 次）',
    balanceUnknown: '尚未读取（测试连接或首轮拨测后显示）',
    budgetLow: '余额低于预警线：节点拨测已降频为每 {{minutes}} 分钟，请到 dnspup 充值。',
    budgetExhausted: '额度已用完：已停止 dnspup 节点拨测，改由节点本机探测判定，告警照常。请到 dnspup 充值。',
  },
  state: {
    title: '运行状态', active: '当前状态', activeYes: '使用中', activeNo: '未使用', accountChecked: '上次能力检测',
    async: '异步拨测', asyncYes: '可用', asyncNo: '不可用', quota: '本月额度', pausedUntil: '暂停至', pauseReason: '暂停原因',
    accountError: '能力检测错误',
    reasons: {
      quota_exceeded: '本月额度已用完', rate_limited: '请求频率超限', unauthorized: 'Key 被拒绝', unavailable: 'dnspup 暂不可用',
    },
  },
  errors: {
    entitlement_feature_denied: '授权不含该模块', probe_dnspup_secret_required: '更换接口地址或 Key 后需重新填写 Secret',
    probe_dnspup_credential_unavailable: '凭据密钥不可用', invalid_input: '输入无效', idempotency_conflict: '请求冲突，请重试',
    permission_denied: '没有权限', request_failed: '请求失败', async_unavailable: 'dnspup 未开放异步拨测',
    tool_not_allowed: '该 Key 未开通 http / tcping 拨测', unauthorized: 'Key 或 Secret 无效、已停用或已到期',
    source_forbidden: '请求来源不符合 Key 的绑定（IP 或域名）', bad_signature: '域名签名校验失败',
    stale_signature: '签名时间戳过期（检查主控时钟）', rate_limited: '请求频率超限', quota_exceeded: '本月额度已用完',
    transport_error: '无法连接 dnspup', service_unavailable: 'dnspup 暂不可用',
    probe_dnspup_node_monitoring_unavailable: '节点拨测暂不可用', not_found: '不存在', probe_dnspup_not_installed: '拨测插件未启用',
    probe_dnspup_not_configured: '拨测插件未开启或未配置 Key', probe_dnspup_paused: 'dnspup 暂停中', probe_dnspup_quota_exceeded: '排障额度已用完',
  },
  unified: {
    failures: { ok: '正常', refused: '连不上', timeout: '超时', reset: '被重置', tls: 'TLS 握手失败', http: 'HTTP 错误', dns: '解析错误', other: '其他' },
    carriers: { telecom: '电信', unicom: '联通', mobile: '移动', edu: '教育网', bgp: 'BGP', other: '其他运营商' },
    areas: { mainland: '中国大陆', hkmotw: '港澳台', overseas: '海外' },
    purposes: {
      title: '按用途的额度与频率',
      intro: '调度、容灾、节点可用性与插件共用同一个 dnspup 额度。每个用途单独计量、可设月上限与最小间隔；本月额度不够时按优先级降频：可用性 > 调度 > 报表（排障）。预计月用量按本月日均推算。智能调度读节点可用性的拨测结果，不单独计量。',
      names: { node_availability: '节点可用性', origin_failover: '回源切换', edge_health: '聚合边缘候选', plugin: '插件拨测接口', diagnose: '排障（mtr）' },
      classes: { 1: '可用性', 2: '调度', 3: '报表' },
      columns: { purpose: '用途', class: '优先级', enabled: '启用', cap: '月上限（0 不限）', interval: '最小间隔（秒，0 跟随）', used: '本月已用', projected: '预计月用量', state: '状态' },
      account: '账户本月 {{used}} / {{limit}} 次，各用途预计合计 {{projected}} 次',
      accountUnlimited: '账户不限额，各用途预计合计 {{projected}} 次',
      gate: { normal: '正常', slowed: '已降频 ×{{factor}}', stopped: '已停用' },
      reasons: { disabled: '已关闭', monthly_cap: '达到月上限', account_budget: '账户额度不足', account_slowdown: '账户额度偏紧' },
      availabilityLocked: '可用性用途不能关闭',
      save: '保存用途设置', saved: '用途设置已保存',
    },
    matrix: {
      title: '地区 × 运营商矩阵',
      intro: '每格为该地区该运营商检测点的可用率、平均延迟与主要故障类型。故障类型只用于诊断展示。',
      subject: '对象', subjects: { node: '节点', edge: '第三方 CDN 候选' },
      nodeID: '节点 ID', edgeHost: '候选主机', window: '时间范围', windows: { '1h': '1 小时', '6h': '6 小时', '24h': '24 小时', '7d': '7 天' },
      load: '查看', empty: '该时间范围内没有拨测结果', area: '地区', unknownArea: '未知',
      cell: '{{availability}} · {{latency}} ms', history: '可用率历史（%）',
      diagnose: '排障（mtr）', diagnoseTarget: '目标 IP 或域名', diagnosePoints: '检测点 ID（最多 2 个，逗号分隔）',
      diagnoseStart: '发起排障', diagnoseRunning: '排障进行中…', diagnoseDone: '排障完成', diagnoseFailed: '排障失败：{{code}}',
    },
    selection: {
      title: '细化选点', enabled: '使用细化选点（代替上面的检测点运营商/地区）',
      areas: '地区', carriers: '运营商', includeProvinces: '只要这些省份/地区', excludeProvinces: '排除这些省份/地区',
      provincesExtra: '大陆写省份简称（如 广东），港澳台与海外写地区码（如 hk、us）；回车添加',
      excludeCheckpoints: '排除检测点 ID', pointsPerGroup: '每组点数（组 = 地区 × 运营商）', rotate: '每轮轮换检测点',
    },
    node: {
      probeType: '拨测类型', probeTypes: { tcping: 'TCP 连接（tcping）', ping: 'ICMP（ping）', http: 'HTTP（有应答即可达）' },
      probeTypeExtra: 'https 不可选：dnspup 不能对节点 IP 指定 SNI，证书必然不匹配',
      lineAlertMinPoints: '线路告警：格内失败点数至少', lineAlertRounds: '线路告警：连续失败轮数',
      lineAlertExtra: '按「运营商 · 地区」统计（例如「移动 · 广东 3 个点连续失败」），进通知中心；只做诊断，不改变节点调度',
      autoDiagnose: '线路告警首次触发时自动 mtr 一次（计入排障额度）',
    },
    overrides: {
      title: '按节点或线路组覆盖',
      intro: '覆盖拨测类型或选点；生效顺序：节点 > 线路组 > 全局。同一节点属于多个线路组时取线路组 ID 最小者。',
      subject: '对象', kinds: { node: '节点', line_group: '线路组' }, inherit: '继承',
      nodeID: '节点 ID', tenantScopeID: '线路组所属租户范围 ID', lineGroupID: '线路组 ID',
      add: '添加覆盖', save: '保存覆盖', saved: '覆盖已保存', remove: '删除', removed: '覆盖已删除', empty: '没有覆盖，全部按全局设置',
    },
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  title: 'dnspup probing',
  intro: 'With your own dnspup customer API key, dnspup checkpoints probe origins and aggregated edge third-party CDN access points as a probe source next to your nodes. Each checkpoint is one vote, counted together with node votes; when the quota runs out, the rate limit is hit or the key is refused, dnspup pauses, the other sources take over and an alert is sent. dnspup charges one monthly unit per accepted probe (the connection test is free).',
  notLicensed: 'The licence lacks the dnspup probing module: you can view but not enable or test.',
  forbidden: 'Requires the dnspup probing permission',
  limits: 'dnspup HTTP probes connect to the URL host itself: origins reached under a different Host (e.g. an IP origin with the site domain) or with a custom CA are not sent to dnspup; aggregated edge third-party CDN access points are judged by a TCP connect to port 443.',
  form: {
    enabled: 'Enable dnspup probing', baseURL: 'dnspup API base URL', apiKey: 'API key', apiSecret: 'API secret',
    secretKeep: 'Set (fingerprint {{fingerprint}}); leave empty to keep, enter a new one to rotate', secretUnset: 'Not set',
    clearSecret: 'Clear the stored secret',
    sourceDomain: 'Bound server domain', sourceDomainExtra: 'For a key bound to a server domain (requests are signed); empty for an IP-bound key',
    originSources: 'Origin probe source order', edgeSources: 'Aggregated edge probe source order',
    sourcesExtra: 'Asked in order; the next source fills up when the votes so far are not enough (fewer than 2 or a tie); unlisted sources are not used',
    save: 'Save', test: 'Test connection and capability', saved: 'Saved',
    testOK: 'Connected: async probes available, monthly quota {{used}} / {{limit}}', testFailed: 'Test failed: {{reason}}',
  },
  sources: { node: 'Node probes', dnspup: 'dnspup checkpoints', controller: 'Control plane direct probe' },
  node: {
    title: 'Node availability probing',
    intro: 'dnspup carrier checkpoints probe every node IP and port at the chosen interval; the results go to the node monitoring log. A node is paused only when the local probe and most dnspup checkpoints both fail; dnspup failing alone only alerts. While the plugin is not in use, the interval is off, the source is paused or the quota is used up, only the local probe decides: missing dnspup data never marks a node offline.',
    inactive: 'dnspup probing is not in use (not licensed, disabled, no key pair or paused): nodes are judged by the local probe only.',
    interval: 'Probe interval', intervals: { off: 'Off', every: 'Every {{minutes}} min' },
    groups: 'Checkpoint carriers / regions', groupNames: { domestic: 'Mainland (any carrier)', telecom: 'China Telecom', unicom: 'China Unicom', mobile: 'China Mobile', overseas: 'Overseas' },
    pointsPerGroup: 'Checkpoints per group', failurePercent: 'Failed checkpoints above (%)', failureRounds: 'Consecutive failures', recoveryRounds: 'Consecutive recoveries',
    lowBalance: 'Low balance threshold (requests)', lowBalanceExtra: 'Below this many requests left this month the interval triples and administrators are notified',
    save: 'Save node probing settings', saved: 'Node probing settings saved',
    estimate: 'Estimated use', estimateValue: 'About {{day}} per day · about {{month}} per month',
    estimateExtra: 'dnspup meters requests: one per node IP and round, whatever the checkpoint count ({{addresses}} node IPs now, {{points}} checkpoints per round). Top up on dnspup; the plugin does not charge.',
    rotate: 'With more than {{max}} node IPs each round probes a share in turn, so each node is probed less often.',
    balance: 'dnspup balance', balanceValue: '{{remaining}} / {{limit}} requests left', balanceUnlimited: 'Unlimited ({{used}} used)',
    balanceUnknown: 'Not read yet (shown after a connection test or the first round)',
    budgetLow: 'Balance below the threshold: node probing slowed to every {{minutes}} min. Top up on dnspup.',
    budgetExhausted: 'Quota used up: dnspup node probing stopped, nodes are judged by the local probe and alerts continue. Top up on dnspup.',
  },
  state: {
    title: 'Status', active: 'State', activeYes: 'In use', activeNo: 'Not in use', accountChecked: 'Last capability check',
    async: 'Async probes', asyncYes: 'Available', asyncNo: 'Unavailable', quota: 'Monthly quota', pausedUntil: 'Paused until',
    pauseReason: 'Pause reason', accountError: 'Capability check error',
    reasons: {
      quota_exceeded: 'Monthly quota used up', rate_limited: 'Rate limited', unauthorized: 'Key refused', unavailable: 'dnspup unavailable',
    },
  },
  errors: {
    entitlement_feature_denied: 'The licence lacks this module', probe_dnspup_secret_required: 'Enter the secret again after changing the URL or key',
    probe_dnspup_credential_unavailable: 'Credential keyring unavailable', invalid_input: 'Invalid input', idempotency_conflict: 'Request conflict; retry',
    permission_denied: 'Permission denied', request_failed: 'Request failed', async_unavailable: 'dnspup async probes are not available',
    tool_not_allowed: 'The key may not run http / tcping probes', unauthorized: 'Key or secret invalid, disabled or expired',
    source_forbidden: 'The request source does not match the key binding (IP or domain)', bad_signature: 'Domain signature rejected',
    stale_signature: 'Signature timestamp stale (check the control plane clock)', rate_limited: 'Rate limited', quota_exceeded: 'Monthly quota used up',
    transport_error: 'Cannot reach dnspup', service_unavailable: 'dnspup unavailable',
    probe_dnspup_node_monitoring_unavailable: 'Node probing unavailable', not_found: 'Not found', probe_dnspup_not_installed: 'The probe plugin is not active',
    probe_dnspup_not_configured: 'The probe plugin is disabled or has no key', probe_dnspup_paused: 'dnspup is paused', probe_dnspup_quota_exceeded: 'Diagnosis quota used up',
  },
  unified: {
    failures: { ok: 'OK', refused: 'Refused', timeout: 'Timeout', reset: 'Reset', tls: 'TLS handshake failed', http: 'HTTP error', dns: 'DNS error', other: 'Other' },
    carriers: { telecom: 'China Telecom', unicom: 'China Unicom', mobile: 'China Mobile', edu: 'CERNET', bgp: 'BGP', other: 'Other carriers' },
    areas: { mainland: 'Mainland China', hkmotw: 'HK / Macau / Taiwan', overseas: 'Overseas' },
    purposes: {
      title: 'Quota and frequency per purpose',
      intro: 'Scheduling, failover, node availability and plugins share one dnspup quota. Each purpose is metered on its own and can have a monthly cap and a minimum interval; when the month cannot be covered, purposes slow down by priority: availability > scheduling > reports (diagnosis). The projection extrapolates this month\'s daily average. Smart scheduling reads the node availability results and is not metered separately.',
      names: { node_availability: 'Node availability', origin_failover: 'Origin failover', edge_health: 'Aggregated edge candidates', plugin: 'Plugin probe API', diagnose: 'Diagnosis (mtr)' },
      classes: { 1: 'Availability', 2: 'Scheduling', 3: 'Reports' },
      columns: { purpose: 'Purpose', class: 'Priority', enabled: 'Enabled', cap: 'Monthly cap (0 none)', interval: 'Minimum interval (s, 0 follows)', used: 'Used this month', projected: 'Projected per month', state: 'State' },
      account: 'Account {{used}} / {{limit}} this month; purposes project {{projected}} in total',
      accountUnlimited: 'Unlimited account; purposes project {{projected}} in total',
      gate: { normal: 'Normal', slowed: 'Slowed ×{{factor}}', stopped: 'Stopped' },
      reasons: { disabled: 'Disabled', monthly_cap: 'Monthly cap reached', account_budget: 'Account quota short', account_slowdown: 'Account quota tight' },
      availabilityLocked: 'Availability purposes cannot be disabled',
      save: 'Save purposes', saved: 'Purposes saved',
    },
    matrix: {
      title: 'Area × carrier matrix',
      intro: 'Each cell is the availability, average latency and main failure category of that area and carrier\'s checkpoints. Failure categories are for diagnosis only.',
      subject: 'Subject', subjects: { node: 'Node', edge: 'Third-party CDN candidate' },
      nodeID: 'Node ID', edgeHost: 'Candidate host', window: 'Window', windows: { '1h': '1 hour', '6h': '6 hours', '24h': '24 hours', '7d': '7 days' },
      load: 'Show', empty: 'No probe results in this window', area: 'Area', unknownArea: 'Unknown',
      cell: '{{availability}} · {{latency}} ms', history: 'Availability history (%)',
      diagnose: 'Diagnosis (mtr)', diagnoseTarget: 'Target IP or domain', diagnosePoints: 'Checkpoint IDs (at most 2, comma separated)',
      diagnoseStart: 'Start diagnosis', diagnoseRunning: 'Diagnosis running…', diagnoseDone: 'Diagnosis finished', diagnoseFailed: 'Diagnosis failed: {{code}}',
    },
    selection: {
      title: 'Detailed checkpoint selection', enabled: 'Use detailed selection (replaces the carriers / regions above)',
      areas: 'Areas', carriers: 'Carriers', includeProvinces: 'Only these provinces / regions', excludeProvinces: 'Exclude these provinces / regions',
      provincesExtra: 'Mainland: province short names (e.g. 广东); HK/MO/TW and abroad: region codes (e.g. hk, us); press Enter to add',
      excludeCheckpoints: 'Exclude checkpoint IDs', pointsPerGroup: 'Points per group (area × carrier)', rotate: 'Rotate checkpoints each round',
    },
    node: {
      probeType: 'Probe type', probeTypes: { tcping: 'TCP connect (tcping)', ping: 'ICMP (ping)', http: 'HTTP (any answer is reachable)' },
      probeTypeExtra: 'https is not offered: dnspup cannot send an SNI to a node IP, so the certificate never matches',
      lineAlertMinPoints: 'Line alert: failed points in a cell at least', lineAlertRounds: 'Line alert: consecutive failed rounds',
      lineAlertExtra: 'Counted per carrier · area (e.g. "China Mobile · 广东 3 points failing"), sent to the notification center; diagnosis only, node scheduling is unchanged',
      autoDiagnose: 'Run one mtr when a line alert first fires (metered as diagnosis)',
    },
    overrides: {
      title: 'Per node or line group overrides',
      intro: 'Override the probe type or selection; precedence: node > line group > global. A node in several line groups takes the smallest line group ID.',
      subject: 'Subject', kinds: { node: 'Node', line_group: 'Line group' }, inherit: 'Inherit',
      nodeID: 'Node ID', tenantScopeID: 'Line group tenant scope ID', lineGroupID: 'Line group ID',
      add: 'Add override', save: 'Save override', saved: 'Override saved', remove: 'Delete', removed: 'Override deleted', empty: 'No overrides: global settings apply everywhere',
    },
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const probeDNSPupMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(probeDNSPupMessages)) {
  i18n.addResourceBundle(locale, 'probeDNSPup', messages, true, true)
}
