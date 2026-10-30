import i18n from './index'

// Plugin store for platform administrators (/sys/plugin-store): browse, buy,
// licences and security advisories. Installing stays in each tenant's
// /sys/plugin-market (pluginInstallations namespace).
const zhCN = {
  title: '插件商店',
  subtitle: '为本主控购买或试用插件。付款完成后插件会出现在租户的“插件市场”里，由租户管理员确认权限后安装。',
  tabs: { browse: '浏览', licenses: '许可证', advisories: '安全公告' },
  filters: {
    search: '搜索插件名称、ID 或简介', kind: '类型', anyKind: '全部类型', price: '价格', anyPrice: '全部价格', free: '免费', paid: '付费',
    sort: '排序', popular: '最多安装', newest: '最新', name: '名称', allVersions: '显示不兼容本主控的插件', apply: '查询',
    compatHint: '默认只显示兼容本主控版本的插件。',
  },
  kinds: {
    module: '官方模块', rule_pack: '规则包', dataset: '数据集', engine_module: '引擎模块', theme: '主题', provider: '服务商接入',
    external_service: '外部服务', ui_page: '页面扩展',
  },
  card: { developer: '开发者', installs: '{{count}} 次安装', latest: '最新版本 {{version}}', free: '免费', from: '{{price}} 起', privileged: '高权限' },
  detail: {
    summary: '简介', screenshots: '截图', homepage: '主页', support: '支持', license: '许可证协议', compat: '兼容范围',
    permissions: '权限声明', highRisk: '高风险权限', permissionsChanged: '本版本权限有变化', versions: '版本历史', beta: '测试版', changelog: '更新日志',
    plans: '价格计划', noPlans: '这个插件还没有在售的价格计划', privilegedHint: '主控扩展会在主控进程旁运行，权限较高，请确认开发者可信。',
    controlAPI: '主控 {{range}}', edgeAgent: '节点 {{range}}', any: '不限',
  },
  plan: {
    free: '免费', one_time: '一次性买断', subscription: '订阅', month: '每月', year: '每年', trialDays: '可试用 {{days}} 天',
    install: '安装', trial: '试用', buy: '购买', prepaid: '用市场余额支付',
  },
  order: {
    opened: '已在新窗口打开付款页面。付款完成后，租户管理员到“插件市场”确认安装。',
    free: '已领取。安装候选生成后，租户管理员到“插件市场”确认安装。',
    blocked: '收银台地址不安全，已拒绝打开', priceChanged: '价格刚刚改过，已刷新，请重新确认',
    waiting: '订单 {{no}}：等待付款', paid: '订单 {{no}} 已付款，正在生成安装候选', fulfilled: '订单 {{no}} 已完成，许可证已生效；安装候选生成后，租户管理员到“插件市场”确认安装',
    expired: '订单 {{no}} 已过期或取消', reopen: '重新打开付款页面',
    prepaidDone: '已用市场余额付款，许可证已生效。安装候选需平台确认后出现在租户“插件市场”。', insufficientBalance: '市场预付余额不足：可在“节点市场 → 收款与余额”充值，或改用“购买”在门户付款', alreadyLicensed: '本主控已有这个插件的有效许可证',
  },
  licenses: {
    plugin: '插件', kind: '类型', status: '状态', periodEnd: '到期时间', autoRenew: '自动续费', on: '开启', off: '到期后停止',
    cancel: '退订', resume: '恢复续费', renew: '续费', dispute: '申请争议',
    renewConfirm: '用市场预付余额在原许可证上续一个周期（同价、同周期），确认续费？', renewed: '已续费，有效期至 {{end}}',
    resultUnknown: '没有收到市场的应答，结果未知。再点一次会用同一个请求标识查询，不会重复扣款。',
    renewUnconfirmed: '续费结果未能确认，请刷新后核对到期时间', renewNotOnSale: '插件已停售，已过期的许可证不能再续费',
    convert: '转为付费', trialUntil: '试用至 {{end}}', trialCancel: '取消试用', trialResume: '恢复试用转正',
    trialCancelConfirm: '取消后试用到期即停止、不扣费，确认取消试用？', trialCancelled: '已取消，试用到期后停止', cancelled: '已退订，到期后停止', resumed: '已恢复自动续费',
    cancelConfirm: '退订后当前周期结束时停止，确认退订？', fallback: '到期后保留 {{version}}', empty: '还没有许可证',
    disputeTitle: '对这笔订单申请争议', disputeReason: '原因', disputeNote: '说明', disputeOpened: '已提交争议，可在“节点市场 → 争议”查看',
    disputeNotLinked: '这份许可证用市场预付余额购买，没有关联售后订单，不能在这里申请争议；如需售后请联系插件市场平台客服', disputeOpen: '这笔订单已有进行中的争议',
    reasons: { not_as_described: '与描述不符', not_working: '无法使用', duplicate_charge: '重复扣费', other: '其他' },
    kinds: { trial: '试用', one_time: '买断', subscription: '订阅', free: '免费' },
    claims: { free_permanent: '永久免费领取', free_promo: '限免领取', paid_once: '一次性购买', paid_monthly: '按月订阅', paid_yearly: '按年订阅' },
    promoCharge: '限免领取，{{at}} 起按月收费',
    states: { trialing: '试用中', active: '有效', past_due: '欠费宽限中', cancelled: '已退订', expired: '已过期', refunded: '已退款', revoked: '已吊销' },
  },
  advisories: {
    plugin: '插件', severity: '级别', affected: '影响版本', fixed: '修复版本', action: '建议动作', published: '发布时间', status: '处理',
    pending: '待处理', handled: '已处理：{{disposition}}', acknowledge: '我已处理', empty: '没有安全公告',
    dispositionLabel: '处理方式', note: '备注（可选）',
    severities: { critical: '严重', high: '高危', medium: '中危', low: '低危' },
    actions: { notify: '知悉即可', disable: '建议停用', uninstall_recommended: '建议卸载' },
    dispositions: { disabled: '已停用', upgraded: '已升级到修复版', uninstalled: '已卸载', accepted_risk: '评估后继续使用', not_affected: '未受影响' },
    banner: '{{count}} 条安全公告待处理',
  },
  errors: {
    forbidden: '需要插件市场的浏览权限', failed: '操作失败：{{code}}', load: '加载失败：{{code}}',
    unavailable: '市场端还没有开放这个功能，市场升级后自动可用。', notJoined: '本机尚未接入市场。市场接入在服务器部署配置中开启（需要市场地址、公钥和插件客户端证书），控制台里没有这个开关，请联系服务器管理员按部署手册配置并重启主控后再检测。',
  },
  actions: { close: '关闭', confirm: '确定', cancel: '取消', more: '加载更多' },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  title: 'Plugin store',
  subtitle: 'Buy or try plugins for this controller. Once paid, the plugin appears in each tenant\'s Plugin marketplace, where a tenant administrator approves its permissions and installs it.',
  tabs: { browse: 'Browse', licenses: 'Licenses', advisories: 'Security advisories' },
  filters: {
    search: 'Search by name, ID or summary', kind: 'Type', anyKind: 'Any type', price: 'Price', anyPrice: 'Any price', free: 'Free', paid: 'Paid',
    sort: 'Sort', popular: 'Most installed', newest: 'Newest', name: 'Name', allVersions: 'Show plugins incompatible with this controller', apply: 'Search',
    compatHint: 'Only plugins compatible with this controller version are shown by default.',
  },
  kinds: {
    module: 'Official module', rule_pack: 'Rule pack', dataset: 'Dataset', engine_module: 'Engine module', theme: 'Theme', provider: 'Provider',
    external_service: 'External service', ui_page: 'UI page',
  },
  card: { developer: 'Developer', installs: '{{count}} installs', latest: 'Latest {{version}}', free: 'Free', from: 'From {{price}}', privileged: 'Privileged' },
  detail: {
    summary: 'Summary', screenshots: 'Screenshots', homepage: 'Homepage', support: 'Support', license: 'License', compat: 'Compatibility',
    permissions: 'Permissions', highRisk: 'High-risk permission', permissionsChanged: 'Permissions changed in this version', versions: 'Version history', beta: 'Beta', changelog: 'Changelog',
    plans: 'Price plans', noPlans: 'This plugin has no plan on sale yet', privilegedHint: 'Controller extensions run beside the controller with broad access; make sure you trust the developer.',
    controlAPI: 'Controller {{range}}', edgeAgent: 'Node {{range}}', any: 'any',
  },
  plan: {
    free: 'Free', one_time: 'One-time', subscription: 'Subscription', month: 'per month', year: 'per year', trialDays: '{{days}}-day trial',
    install: 'Install', trial: 'Try', buy: 'Buy', prepaid: 'Pay from market balance',
  },
  order: {
    opened: 'The payment page opened in a new window. Once paid, a tenant administrator installs it from Plugin marketplace.',
    free: 'Claimed. Once the install candidate exists, a tenant administrator installs it from Plugin marketplace.',
    blocked: 'The checkout address is not safe and was not opened', priceChanged: 'The price just changed and was reloaded; please confirm again',
    waiting: 'Order {{no}}: waiting for payment', paid: 'Order {{no}} paid; preparing the install candidate', fulfilled: 'Order {{no}} completed and the licence is active; once the install candidate exists, a tenant administrator installs it from Plugin marketplace',
    expired: 'Order {{no}} expired or was cancelled', reopen: 'Open the payment page again',
    prepaidDone: 'Paid from the market balance; the licence is active. The install candidate appears in tenants\' Plugin marketplace once the platform confirms it.', insufficientBalance: 'Not enough market prepaid balance: top up in Node market → Payments & balance, or use Buy to pay in the portal', alreadyLicensed: 'This controller already holds an active licence for this plugin',
  },
  licenses: {
    plugin: 'Plugin', kind: 'Type', status: 'Status', periodEnd: 'Ends', autoRenew: 'Auto-renew', on: 'On', off: 'Stops at period end',
    cancel: 'Cancel', resume: 'Resume', renew: 'Renew', dispute: 'Dispute',
    renewConfirm: 'Renew this licence for one more period from the market prepaid balance (same price and period)?', renewed: 'Renewed until {{end}}',
    resultUnknown: 'The market did not answer; the result is unknown. Clicking again asks with the same request key and never charges twice.',
    renewUnconfirmed: 'The renewal could not be confirmed; refresh and check the end date', renewNotOnSale: 'The plugin is no longer on sale; an expired licence cannot be renewed',
    convert: 'Convert to paid', trialUntil: 'Trial until {{end}}', trialCancel: 'Cancel trial', trialResume: 'Keep trial converting',
    trialCancelConfirm: 'The trial stops at its end without a charge. Cancel the trial?', trialCancelled: 'Cancelled; stops when the trial ends', cancelled: 'Cancelled; stops at period end', resumed: 'Auto-renew resumed',
    cancelConfirm: 'The licence stops at the end of the current period. Cancel?', fallback: 'Keeps {{version}} after it ends', empty: 'No licences yet',
    disputeTitle: 'Dispute this order', disputeReason: 'Reason', disputeNote: 'Details', disputeOpened: 'Dispute opened; follow it in Node market → Disputes',
    disputeNotLinked: 'This licence was paid from the market prepaid balance and has no order to dispute here; contact the plugin market platform for support', disputeOpen: 'This order already has an open dispute',
    reasons: { not_as_described: 'Not as described', not_working: 'Does not work', duplicate_charge: 'Charged twice', other: 'Other' },
    kinds: { trial: 'Trial', one_time: 'One-time', subscription: 'Subscription', free: 'Free' },
    claims: { free_permanent: 'Claimed free for good', free_promo: 'Claimed during a free promo', paid_once: 'One-time purchase', paid_monthly: 'Monthly subscription', paid_yearly: 'Yearly subscription' },
    promoCharge: 'Claimed free, billed monthly from {{at}}',
    states: { trialing: 'Trialing', active: 'Active', past_due: 'Past due (grace)', cancelled: 'Cancelled', expired: 'Expired', refunded: 'Refunded', revoked: 'Revoked' },
  },
  advisories: {
    plugin: 'Plugin', severity: 'Severity', affected: 'Affected', fixed: 'Fixed in', action: 'Recommended', published: 'Published', status: 'Handling',
    pending: 'Pending', handled: 'Handled: {{disposition}}', acknowledge: 'Mark handled', empty: 'No security advisories',
    dispositionLabel: 'What you did', note: 'Note (optional)',
    severities: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' },
    actions: { notify: 'For information', disable: 'Disable', uninstall_recommended: 'Uninstall' },
    dispositions: { disabled: 'Disabled', upgraded: 'Upgraded to the fixed version', uninstalled: 'Uninstalled', accepted_risk: 'Kept after review', not_affected: 'Not affected' },
    banner: '{{count}} security advisories need handling',
  },
  errors: {
    forbidden: 'Plugin marketplace browse permission required', failed: 'Request failed: {{code}}', load: 'Could not load: {{code}}',
    unavailable: 'The market does not offer this yet; it becomes available once the market is upgraded.', notJoined: 'This controller has not joined the market. Joining is set in the server deployment (market URL, public keys and the plugin client certificate), not in the console. Ask the server administrator to configure it as the deployment guide describes and restart the controller, then check again.',
  },
  actions: { close: 'Close', confirm: 'OK', cancel: 'Cancel', more: 'Load more' },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const pluginStoreMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(pluginStoreMessages)) {
  i18n.addResourceBundle(locale, 'pluginStore', messages, true, true)
}
