import i18n from './index'

const zhCN = {
  title: 'IP 库实时更新（dnspup）',
  intro: '授权端只免费提供一次基础 IP 库，之后不再刷新。填写你自己的 dnspup 客户 API Key 后，主控按下面的计划拉取最新快照并在本地构建 IP 库，节点自动使用数据较新的一份；拉取失败或授权到期时节点继续使用基础库。dnspup 按次直接向你收费（测试连接不计费）。',
  notLicensed: '当前授权不含「IP 库实时更新」模块，可以查看但不能启用、测试或立即拉取。',
  forbidden: '需要 IP 库更新管理权限',
  form: {
    enabled: '启用定时拉取', url: 'dnspup 接口地址', apiKey: 'API Key', apiSecret: 'API Secret',
    secretKeep: '已配置（指纹 {{fingerprint}}），留空保持不变', secretUnset: '未配置', clearSecret: '清除已保存的 Secret',
    interval: '拉取间隔（小时）', anchor: '对齐时间', timeZone: '时区',
    save: '保存', test: '测试连接', checkNow: '立即拉取', running: '拉取中…',
    saved: '已保存', testOK: '连接正常（快照 {{release}}）', testFailed: '连接失败：{{reason}}',
    checkQueued: '已请求立即拉取',
  },
  state: {
    title: '拉取状态', lastChecked: '上次检查', lastSuccess: '上次成功', lastOutcome: '结果', lastRelease: '快照版本',
    nextCheck: '下次拉取', lastError: '错误',
    outcomes: { '': '尚未拉取', published: '已构建新库', unchanged: '数据未变', not_modified: '没有新快照', pending: 'dnspup 生成中，稍后重试', failed: '失败' },
  },
  libraries: {
    title: 'IP 库', base: '基础库（授权端）', local: '本地库（本插件）', none: '无', revision: '修订 {{revision}}',
    dataUpdated: '数据时间 {{time}}', unusable: '授权不含本模块，节点不使用', nodeUses: '节点当前使用',
    reasons: { only_base: '只有基础库', only_local: '只有本地库', local_newer: '本地库数据较新', base_newer_or_equal: '基础库数据不旧于本地库', local_unreadable: '本地库无法打开，回落基础库' },
  },
  errors: {
    credentials_rejected: 'API Key 或 Secret 不正确', key_domain_bound: '该 Key 需要域名签名，请改用绑定主控出口 IP 的 Key',
    source_ip_forbidden: 'dnspup 拒绝了主控的出口 IP', tool_not_allowed: 'API Key 未开通 IP 情报库快照工具（ip-intel-snapshot）',
    quota_exceeded: 'dnspup 配额已用完', snapshot_too_large: '快照超过大小上限', source_pending: 'dnspup 正在生成快照',
    timeout: '请求超时', source_unreachable: '无法连接 dnspup', license_not_allowed: '快照含不允许再分发的数据源',
    snapshot_older: '快照数据不比本地库新', credential_unavailable: '主控凭据密钥不可用',
    feature_not_licensed: '授权不含本模块', snapshot_invalid: '快照内容无效', build_failed: '构建失败',
    entitlement_feature_denied: '授权不含本模块', ip_intel_update_secret_required: '更换地址或 Key 后需要重新填写 Secret',
    ip_intel_update_disabled: '请先启用并保存', invalid_input: '输入不合法', idempotency_conflict: '请求冲突，请重试',
    ip_intel_update_credential_unavailable: '主控凭据密钥不可用', request_failed: '请求失败',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  title: 'IP intelligence live updates (dnspup)',
  intro: 'The licence service ships the base IP library once, free, and never refreshes it. With your own dnspup customer API key the control plane pulls the latest snapshot on the schedule below and builds the library locally; nodes use whichever library has newer data and keep the base library when a pull fails or the licence ends. dnspup bills you per download (connection tests are free).',
  notLicensed: 'The licence does not include the IP intelligence live updates module: you can view this page but not enable, test or pull.',
  forbidden: 'IP intelligence update management permission required',
  form: {
    enabled: 'Scheduled pulls', url: 'dnspup endpoint', apiKey: 'API key', apiSecret: 'API secret',
    secretKeep: 'Set (fingerprint {{fingerprint}}); leave empty to keep', secretUnset: 'Not set', clearSecret: 'Clear the saved secret',
    interval: 'Interval (hours)', anchor: 'Aligned at', timeZone: 'Time zone',
    save: 'Save', test: 'Test connection', checkNow: 'Pull now', running: 'Pulling…',
    saved: 'Saved', testOK: 'Connection OK (snapshot {{release}})', testFailed: 'Connection failed: {{reason}}',
    checkQueued: 'Pull requested',
  },
  state: {
    title: 'Pull state', lastChecked: 'Last check', lastSuccess: 'Last success', lastOutcome: 'Outcome', lastRelease: 'Snapshot',
    nextCheck: 'Next pull', lastError: 'Error',
    outcomes: { '': 'Not pulled yet', published: 'New library built', unchanged: 'Data unchanged', not_modified: 'No new snapshot', pending: 'dnspup is generating, retrying', failed: 'Failed' },
  },
  libraries: {
    title: 'IP libraries', base: 'Base (licence service)', local: 'Local (this plugin)', none: 'None', revision: 'revision {{revision}}',
    dataUpdated: 'data {{time}}', unusable: 'Not used: the licence lacks this module', nodeUses: 'Nodes use',
    reasons: { only_base: 'Only the base library', only_local: 'Only the local library', local_newer: 'Local data is newer', base_newer_or_equal: 'Base data is not older', local_unreadable: 'Local library unreadable; base used' },
  },
  errors: {
    credentials_rejected: 'Wrong API key or secret', key_domain_bound: 'This key needs domain signatures; use a key bound to the control plane egress IP',
    source_ip_forbidden: 'dnspup refused the control plane egress IP', tool_not_allowed: 'The API key is not granted the IP intelligence snapshot tool (ip-intel-snapshot)',
    quota_exceeded: 'dnspup quota exceeded', snapshot_too_large: 'Snapshot too large', source_pending: 'dnspup is generating the snapshot',
    timeout: 'Timed out', source_unreachable: 'dnspup unreachable', license_not_allowed: 'The snapshot lists a source that may not be redistributed',
    snapshot_older: 'Snapshot data is not newer than the local library', credential_unavailable: 'Credential keyring unavailable',
    feature_not_licensed: 'The licence lacks this module', snapshot_invalid: 'Invalid snapshot', build_failed: 'Build failed',
    entitlement_feature_denied: 'The licence lacks this module', ip_intel_update_secret_required: 'Enter the secret again after changing the endpoint or key',
    ip_intel_update_disabled: 'Enable and save first', invalid_input: 'Invalid input', idempotency_conflict: 'Request conflict; retry',
    ip_intel_update_credential_unavailable: 'Credential keyring unavailable', request_failed: 'Request failed',
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const ipIntelUpdatesMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(ipIntelUpdatesMessages)) {
  i18n.addResourceBundle(locale, 'ipIntelUpdates', messages, true, true)
}
