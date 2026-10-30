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
