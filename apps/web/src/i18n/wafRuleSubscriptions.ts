import i18n from './index'

// NF37: WAF rule library subscriptions (admin) and the WAF module states of
// the site WAF tab.
const zhCN = {
  wafSubscriptions: {
    title: 'WAF 规则库订阅',
    open: '规则库订阅',
    intro: '订阅地址由主控按间隔拉取（仅 https、禁止内网地址，JSON ≤ 8 MB），编译成用户层规则包规则；节点不访问订阅地址。拉取或编译失败时保留上次成功的版本。用户订阅后得到自己的规则包（已下载、未启用）；规则内容变化时给每个订阅用户的规则包生成新版本，挂载该包的网站显示“待发布”，重新发布后才生效。',
    limits: '一份订阅最多编译为 100 条规则（每个条件组 1 条，每条最多 4 个条件、每个字段 1 次），并受规则包预算限制（最多 64 个正则）；节点无法精确执行的规则（例如省份/ASN/TLS 指纹匹配、非 403 的处理动作、长度转换）或被前面的终结规则完全遮蔽的规则会使整份订阅更新失败并显示原因。',
    add: '新增订阅',
    edit: '编辑订阅',
    syncNow: '立即更新',
    refresh: '刷新',
    remove: '删除',
    removeConfirm: '删除后不再拉取，已订阅用户的规则包保留最后版本，用户可自行退订或删除规则包。确认删除？',
    columns: { name: '名称', url: '订阅地址', interval: '更新间隔', state: '状态', version: '版本', rules: '规则数', lastSuccess: '上次成功', nextFetch: '下次拉取', subscribers: '订阅用户', pending: '待发布网站', actions: '操作' },
    fields: { name: '名称', description: '备注', url: '订阅地址', urlPlaceholder: 'https://规则源域名/路径.json', interval: '更新间隔（分钟）', intervalHelp: '5–10080 分钟，默认 360', enabled: '自动更新' },
    values: { minutes: '{{count}} 分钟', never: '从未成功', enabled: '自动更新', paused: '已暂停', ok: '正常', failed: '失败', pending: '待拉取', revision: '第 {{revision}} 版', packVersion: '规则包 {{version}}' },
    packs: {
      title: '订阅用户的规则包', none: '还没有用户订阅', tenant: '用户', pack: '规则包', version: '当前 / 最新版本',
      policy: '新版本', auto: '自动采用', manual: '手动采用', pending: '待发布网站', noPending: '无',
      pendingTag: '{{domain}}（已发布 {{version}}）', publish: '去发布',
      pendingAlert: '{{count}} 个网站挂载的订阅规则包有新版本、待发布：新版本不会自动生效，需在规则包页按网站重新发布。',
    },
    urlProblems: { scheme: '必须是 https:// 地址，且不能带 #', credentials: '地址中不能包含用户名或密码', internal: '不能使用本机或内网地址' },
    notices: { created: '已新增订阅，稍后自动拉取', updated: '已保存', removed: '已删除', synced: '已更新到最新版本', syncFailed: '更新失败，已保留上次成功的版本：{{error}}', failed: '操作失败', invalid: '订阅设置未通过服务端校验，请检查订阅地址与更新间隔' },
  },
  wafLibraries: {
    title: '平台 WAF 规则库',
    description: '由授权中心下发的平台规则库。订阅后复制为你的规则库（不能查看规则内容），挂载到网站并发布后才生效；有新版本时显示“可更新”，点“更新”或“刷新订阅”采用新版本。',
    refresh: '刷新订阅',
    subscribe: '订阅',
    update: '更新',
    unsubscribe: '取消订阅',
    unsubscribeConfirm: '取消订阅后删除你的这份规则库副本；仍挂载它的网站需先改用其它规则库。确认取消？',
    empty: '授权中心暂未下发平台规则库',
    loadFailed: '平台规则库读取失败，订阅状态未知，列表中暂不显示平台规则库',
    columns: { name: '名称', description: '说明', revision: '版本', status: '订阅状态', actions: '操作' },
    revision: 'v{{revision}}',
    statuses: { not_subscribed: '未订阅', subscribed: '已订阅', update_available: '可更新', not_applicable: '—' },
    notices: { subscribed: '已订阅', updated: '已更新到最新版本', unsubscribed: '已取消订阅', refreshed: '已刷新全部订阅', failed: '操作失败：{{reason}}' },
  },
  wafPending: {
    title: '订阅已更新、待发布（{{count}} 个网站）',
    description: '下列网站使用的订阅规则库有了新版本，节点仍在执行旧版本。新版本不会自动下发：点“去发布”会打开发布面板并预填网站、规则库和上次发布的节点，确认后再发布。',
    columns: { site: '网站', library: '规则库', version: '版本', actions: '操作' },
    version: 'v{{active}} → v{{latest}}',
    publish: '去发布',
    publishing: '发布中',
    unknownLibrary: '订阅规则库',
    loadFailed: '待发布列表读取失败，无法确认订阅更新是否已发布',
    forbidden: '当前账号无权查看待发布列表',
    siteHint: '当前规则库已更新到 v{{latest}}，本网站仍在执行 v{{active}}，需要重新发布才会生效。',
    siteAction: '去发布',
  },
  wafModules: {
    title: '内置检测模块状态',
    hint: '根据当前生效的 WAF 规则库计算：防护=命中即拦截；仅记录=只写日志不拦截；关闭=未启用该模块。',
    states: { protect: '防护', log: '仅记录', off: '关闭' },
    engines: { self: '自研', crs: 'CRS' },
    engineState: '{{engine}}：{{state}}',
    inspectionLimit: '检查上限命中（参数/JSON 层数/正则步数超限）：{{action}}',
    inspectionLimitActions: { log: '仅记录，不拦截', block: '拦截' },
    noPolicy: '网站未发布 WAF 规则库，全部模块关闭',
    policyDisabled: '当前规则库已停用，全部模块关闭',
    protectedPolicy: '当前生效的是订阅规则库，规则内容不对用户展示，模块状态无法计算',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  wafSubscriptions: {
    title: 'WAF rule library subscriptions',
    open: 'Rule library subscriptions',
    intro: 'The control plane fetches the subscription URL on the interval (https only, no internal addresses, JSON up to 8 MB) and compiles it into user layer rule pack rules; nodes never fetch the URL. A failed fetch or compile keeps the last good version. A subscribing user gets its own rule pack (downloaded, not enabled); when the rules change every subscriber pack gets a new version, and sites mounting it show "waiting to publish" until they are published again.',
    limits: 'A subscription compiles to at most 100 rules (one per condition group, at most 4 conditions, one per field) within the rule pack budget (at most 64 regexes). A rule the node cannot enforce exactly (province/ASN/TLS fingerprint matching, actions other than 403, length transforms) or one fully shadowed by an earlier stopping rule fails the whole update and shows why.',
    add: 'Add subscription',
    edit: 'Edit subscription',
    syncNow: 'Update now',
    refresh: 'Refresh',
    remove: 'Delete',
    removeConfirm: 'Deleting stops fetching. Subscribers keep the last version of their rule pack and can unsubscribe or delete the pack. Delete?',
    columns: { name: 'Name', url: 'Subscription URL', interval: 'Interval', state: 'State', version: 'Version', rules: 'Rules', lastSuccess: 'Last success', nextFetch: 'Next fetch', subscribers: 'Subscribers', pending: 'Sites to publish', actions: 'Actions' },
    fields: { name: 'Name', description: 'Remark', url: 'Subscription URL', urlPlaceholder: 'https://rules-host/path.json', interval: 'Interval (minutes)', intervalHelp: '5–10080 minutes, default 360', enabled: 'Update automatically' },
    values: { minutes: '{{count}} min', never: 'Never succeeded', enabled: 'Automatic', paused: 'Paused', ok: 'OK', failed: 'Failed', pending: 'Pending', revision: 'Revision {{revision}}', packVersion: 'Rule pack {{version}}' },
    packs: {
      title: 'Subscriber rule packs', none: 'No subscriber yet', tenant: 'User', pack: 'Rule pack', version: 'Current / latest',
      policy: 'New versions', auto: 'Automatic', manual: 'Manual', pending: 'Sites to publish', noPending: 'None',
      pendingTag: '{{domain}} (published {{version}})', publish: 'Publish',
      pendingAlert: '{{count}} sites mount a subscription rule pack that has a new version: it does not take effect by itself; publish the site again on the rule pack page.',
    },
    urlProblems: { scheme: 'Must be an https:// URL without #', credentials: 'The URL must not contain a user name or password', internal: 'Local and internal addresses are not allowed' },
    notices: { created: 'Subscription added; it will be fetched shortly', updated: 'Saved', removed: 'Deleted', synced: 'Updated to the latest version', syncFailed: 'Update failed; the last good version is kept: {{error}}', failed: 'Operation failed', invalid: 'The server refused the subscription settings; check the URL and the interval' },
  },
  wafLibraries: {
    title: 'Platform WAF rule libraries',
    description: 'Rule libraries delivered by the license center. Subscribing copies one into your libraries (its rules are not shown); it takes effect once mounted on a site and published. A newer version shows "Update available"; "Update" or "Refresh subscriptions" adopts it.',
    refresh: 'Refresh subscriptions',
    subscribe: 'Subscribe',
    update: 'Update',
    unsubscribe: 'Unsubscribe',
    unsubscribeConfirm: 'Unsubscribing deletes your copy of this library; sites still mounting it must switch to another library first. Unsubscribe?',
    empty: 'The license center has not delivered any platform library yet',
    loadFailed: 'Platform rule libraries failed to load; subscription state is unknown and platform rows are hidden',
    columns: { name: 'Name', description: 'Description', revision: 'Version', status: 'Subscription', actions: 'Actions' },
    revision: 'v{{revision}}',
    statuses: { not_subscribed: 'Not subscribed', subscribed: 'Subscribed', update_available: 'Update available', not_applicable: '—' },
    notices: { subscribed: 'Subscribed', updated: 'Updated to the latest version', unsubscribed: 'Unsubscribed', refreshed: 'All subscriptions refreshed', failed: 'Operation failed: {{reason}}' },
  },
  wafPending: {
    title: 'Subscription updated, waiting to publish ({{count}} sites)',
    description: 'The subscribed rule library of these sites has a new version; nodes still run the old one. New versions are never published automatically: "Publish" opens the publish panel with the site, library and last target nodes filled in, and publishes after you confirm.',
    columns: { site: 'Site', library: 'Rule library', version: 'Version', actions: 'Actions' },
    version: 'v{{active}} → v{{latest}}',
    publish: 'Publish',
    publishing: 'Publishing',
    unknownLibrary: 'Subscribed rule library',
    loadFailed: 'Pending publications failed to load; whether subscription updates are published is unknown',
    forbidden: 'This account cannot view pending publications',
    siteHint: 'The rule library is now v{{latest}}; this site still runs v{{active}} until it is published again.',
    siteAction: 'Publish',
  },
  wafModules: {
    title: 'Built-in detection modules',
    hint: 'Derived from the active WAF rule library: Protect blocks on a match; Log only records without blocking; Off means the module is not enabled.',
    states: { protect: 'Protect', log: 'Log only', off: 'Off' },
    engines: { self: 'Built-in', crs: 'CRS' },
    engineState: '{{engine}}: {{state}}',
    inspectionLimit: 'Inspection limit hits (arguments / JSON depth / regex steps): {{action}}',
    inspectionLimitActions: { log: 'record only, do not block', block: 'block' },
    noPolicy: 'The site has no published WAF rule library; every module is off',
    policyDisabled: 'The active rule library is disabled; every module is off',
    protectedPolicy: 'The active library is a subscribed library whose rules are not shown to users, so module states cannot be derived',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const wafRuleSubscriptionMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as Messages, 'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(wafRuleSubscriptionMessages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
  i18n.addResourceBundle(locale, 'siteProtection', { wafModules: messages.wafModules, wafPending: messages.wafPending }, true, true)
}
