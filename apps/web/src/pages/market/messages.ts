import i18n from '../../i18n'

// Embedded plugin market (/sys/plugin-store, PA-27): every official and third-party plugin,
// bought, downloaded and enabled from this controller without leaving the page.
const zhCN = {
  subtitle: '官方与第三方插件统一在这里购买、下载和启用。每份购买只绑定本主控；换主控请在授权端改绑。',
  tabs: { browse: '浏览', mine: '我的插件', licenses: '已购', advisories: '安全公告' },
  publisher: { official: '官方', certified: '认证开发者', third_party: '第三方' },
  price: {
    free: '免费', paid: '收费', one_time: '{{price}} 买断', month: '{{price}} / 月', year: '{{price}} / 年', none: '暂未开售',
    promo: '限免至 {{until}}，到期后 {{then}}',
    trial: '可试用 {{days}} 天',
    edition: { community: '按本主控的社区版价格', commercial: '按本主控的商业版价格' },
  },
  state: {
    purchase: '购买', get: '获取', distributing: '使用权已取得，正在同步', enable: '去启用', enabled: '已启用', activating: '授权生效中',
    installed: '已安装，可使用', goManage: '去管理',
    revoked: '授权失效', revokedHint: '这个插件的授权已结束或已改绑到其他主控，本主控不能再启用它。续费或在授权端改绑回来后恢复。',
    activatingHint: '已购买。授权端正在为本主控重签授权，通常一分钟内生效。',
    enableHint: '已到达本主控。到对应页面启用：', enableTenant: '已到达本主控。由主控管理员在“我的插件”核对权限并确认安装，租户无需操作。',
    pendingConfirm: '待主控管理员确认安装',
    distributingHint: '平台正在验证并分发到本主控，到达后这里会显示“去启用”。',
    platformConfirm: '使用权已取得，等待主控管理员确认安装',
    platformConfirmHint: '主控管理员在“我的插件”核对权限并确认安装：主题和规则包装到本主控，确认后到对应页面启用；页面插件和外部服务选择装给哪些租户，确认后这些租户直接可用。租户无需操作。',
    goMine: '去我的插件确认',
    configure: '已启用 · 去配置', unconfigured: '未配置 · 去配置', off: '已关闭 · 去开启', disabled: '已停用',
    noVersionHint: '插件已获取，官方发布版本后会出现在“我的插件”等待确认',
    awaitingSyncHint: '使用权已取得，等待插件发布或同步到本主控，通常约 1 分钟。之后在“我的插件”确认安装。',
  },
  toggle: {
    disable: '停用', resume: '重新启用', disableTitle: '停用 {{name}}', confirmDisable: '确认停用', reason: '停用原因',
    reasonPlaceholder: '写明为什么停用，记入审计（1–500 字）',
    disableEffect: '停用后本主控暂停这个插件：插件运行身份立即作废，对应页面和功能不再可用。购买的使用权和安装记录保留，随时可以重新启用；要彻底移除请在“我的插件”的安装记录里卸载。',
    featureDisableEffect: '停用后本主控所有租户将无法使用该功能，已有配置保留。授权和计费不变，随时可以重新启用。',
    dependents: '会一起失效的插件', dependentsHint: '这些插件依赖它，停用期间不起作用；它们自己的状态不会被改动。',
    disabled: '已停用', resumed: '已重新启用', platformPaused: '平台已暂停，本机不能重新启用',
    unknown: '没有收到结果，可能已经生效。再次操作会用同一个请求标识重试，不会重复执行。', failed: '操作失败：{{code}}',
  },
  acquired: {
    claimedActive: '已领取，已生效', claimedPending: '已领取，待主控管理员在“我的插件”确认安装',
    paidActive: '已付款，已生效', paidPending: '已付款，待主控管理员在“我的插件”确认安装',
    activeHint: '授权端为本主控重签授权后功能即开通，通常几秒内；本页会自动刷新状态。',
    pendingHint: '确认安装前插件不会出现在菜单里。确认时选择装给哪些租户，确认后这些租户直接可用。',
    goMine: '去我的插件', done: '知道了',
  },
  card: { details: '详情', latest: '最新 {{version}}' },
  owned: {
    title: '本主控已拥有的插件', hint: '已购或已领取、授权绑定到本主控的插件。功能类插件由授权自动启用，到对应页面配置，也可以在这里停用（本主控所有租户不可用，授权不变）；主题、规则包、页面插件和外部服务需要主控管理员在下方确认安装（页面插件和外部服务同时选择装给哪些租户）。',
    name: '插件', kind: '类型', status: '状态', actions: '操作', configure: '去配置', noPage: '无独立配置页', confirmBelow: '在下方安装记录里确认', confirmByAdmin: '等待主控管理员确认安装',
    states: {
      enabled: '已启用', activating: '授权生效中', installed: '已安装', enable: '已安装，待启用', distributing: '正在同步到本主控',
      pendingConfirm: '待确认安装', revoked: '授权失效', disabled: '已停用',
      noVersion: '暂无可安装版本', awaitingSync: '等待发布或同步（约 1 分钟）',
    },
    noVersionHint: '插件已获取，官方发布版本后会出现在下方等待确认',
    emptyTitle: '本主控还没有插件', emptyDescription: '在“浏览”里获取或购买插件后会显示在这里。',
    platformTitle: '安装确认与安装记录',
  },
  detail: {
    publisher: '发布者', namespace: '命名空间', kind: '类型', version: '版本', permissions: '权限', noPermissions: '没有声明权限',
    highRisk: '高风险权限', versions: '版本历史', plans: '价格', menus: '页面与菜单', origin: '页面来源',
    originNotice: '启用后，下列菜单会以隔离框架加载 {{origin}} 的页面，插件无法读取你的登录凭据。',
    menuItem: '{{title}}（{{mount}}）', mount: { menu: '菜单', site_tab: '网站详情页签' }, noMenus: '这个插件不添加页面',
    featureCode: '解锁功能', beta: '测试版',
  },
  pay: {
    title: '购买 {{name}}', plan: '选择价格', balance: '余额扣款', qr: '扫码支付', balanceHint: '从本主控在市场的预付余额扣款，页面内完成。',
    qrHint: '用支付宝或微信扫码付款，付款后自动为本主控取得使用权。', confirm: '确认付款', insufficient: '余额不足，已切换为扫码支付',
    scan: '扫描二维码付款', waiting: '订单 {{no}} 等待付款…', paid: '付款成功，正在为本主控取得使用权', expired: '订单已过期，请重新下单',
    openPage: '在新窗口打开收银台', blocked: '收银台地址不安全，已拒绝', priceChanged: '价格刚刚改过，请重新确认',
    already: '本主控已持有这个插件', checkResult: '查询结果', unknownTitle: '结果未知',
    trialUsed: '已经试用过这个插件，不能再次试用', notOnSale: '这个价格已停售，请刷新后重新选择', notRenewable: '这个授权不支持原地续费',
    keyConflict: '请求标识冲突，请重新确认付款', inProgress: '上一次购买还在处理中，请稍后点“查询结果”',
    unknownDetail: '没有收到市场的应答，这笔可能已经扣款或建单。点“查询结果”会用同一个请求标识查询，不会重复扣款。',
    trial: '试用 {{days}} 天',
  },
  download: { done: '已取得使用权，正在同步到本主控', required: '需要先购买' },
  guide: {
    buy: '去购买', feature: '下面是解锁 {{code}} 的插件：购买后授权会绑定到本主控。', notFound: '市场里没有解锁 {{code}} 的插件条目。',
    showAll: '查看全部插件',
  },
  errors: {
    forbidden: '需要插件市场的浏览权限', failed: '操作失败：{{code}}', load: '加载失败：{{code}}',
    unavailable: '市场端还没有开放这个功能，市场升级后自动可用。', notJoined: '本机尚未接入市场。市场接入在服务器部署配置中开启（需要市场地址、公钥和插件客户端证书），控制台里没有这个开关，请联系服务器管理员按部署手册配置并重启主控后再检测。', recheck: '重新检测',
  },
  filters: { search: '搜索插件名称或 ID', apply: '查询', price: '价格', anyPrice: '全部价格' },
  actions: { close: '关闭', cancel: '取消' },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  subtitle: 'Buy, download and enable official and third-party plugins here. Each purchase is bound to this controller; move it to another controller in the license portal.',
  tabs: { browse: 'Browse', mine: 'My plugins', licenses: 'Purchased', advisories: 'Security advisories' },
  publisher: { official: 'Official', certified: 'Certified developer', third_party: 'Third party' },
  price: {
    free: 'Free', paid: 'Paid', one_time: '{{price}} one-time', month: '{{price}} / month', year: '{{price}} / year', none: 'Not on sale',
    promo: 'Free until {{until}}, then {{then}}',
    trial: '{{days}}-day trial',
    edition: { community: 'Community edition price of this controller', commercial: 'Commercial edition price of this controller' },
  },
  state: {
    purchase: 'Buy', get: 'Get', distributing: 'Licence held, syncing', enable: 'Enable', enabled: 'Enabled', activating: 'Activating',
    installed: 'Installed, ready to use', goManage: 'Manage',
    revoked: 'License lost', revokedHint: 'The license ended or was moved to another controller, so this controller can no longer enable it. Renew or move it back in the license portal to restore it.',
    activatingHint: 'Purchased. The license service is re-signing this controller\'s license; it usually takes under a minute.',
    enableHint: 'On this controller. Enable it on:', enableTenant: 'On this controller. The controller administrator reviews its permissions and confirms installation in My plugins; tenants do nothing.',
    pendingConfirm: 'Awaiting the controller administrator\'s installation',
    distributingHint: 'The platform is verifying it and delivering it to this controller. Enable shows up here when it arrives.',
    platformConfirm: 'Licensed, waiting for the controller administrator to confirm installation',
    platformConfirmHint: 'The controller administrator reviews permissions and confirms installation under My plugins: themes and rule packs install on this controller and are then enabled on their pages; UI page plugins and external services are installed for the tenants chosen, who can then use them directly. Tenants do nothing.',
    goMine: 'Confirm in My plugins',
    configure: 'Enabled · Configure', unconfigured: 'Not configured · Configure', off: 'Switched off · Turn on', disabled: 'Disabled',
    noVersionHint: 'The plugin is yours; once a version is released it appears in My plugins for confirmation.',
    awaitingSyncHint: 'Licence held. Waiting for the plugin to be released or synced to this controller, usually about a minute; then confirm installation in My plugins.',
  },
  toggle: {
    disable: 'Disable', resume: 'Enable again', disableTitle: 'Disable {{name}}', confirmDisable: 'Disable', reason: 'Reason for disabling',
    reasonPlaceholder: 'Why it is disabled, recorded in the audit log (1–500 characters)',
    disableEffect: 'This controller pauses the plugin: its runtime identity is revoked at once and its pages and functions stop working. The licence and the installation record are kept, so you can enable it again at any time; to remove it, uninstall it in the installation records under My plugins.',
    featureDisableEffect: 'No tenant of this controller can use the feature while it is disabled; existing settings are kept. The licence and billing do not change, and you can enable it again at any time.',
    dependents: 'Plugins that stop working with it', dependentsHint: 'These plugins depend on it and do nothing while it is disabled; their own state is not changed.',
    disabled: 'Disabled', resumed: 'Enabled again', platformPaused: 'Paused by the platform; it cannot be enabled again here',
    unknown: 'No answer received; it may have taken effect. Doing it again retries with the same request key and does not act twice.', failed: 'Request failed: {{code}}',
  },
  acquired: {
    claimedActive: 'Claimed and active', claimedPending: 'Claimed. Waiting for the controller administrator to confirm installation in My plugins',
    paidActive: 'Paid and active', paidPending: 'Paid. Waiting for the controller administrator to confirm installation in My plugins',
    activeHint: 'The feature turns on once the license service re-signs this controller\'s license, usually within seconds; this page refreshes by itself.',
    pendingHint: 'The plugin stays out of the menus until installation is confirmed. Confirming chooses the tenants, who can then use it directly.',
    goMine: 'Go to My plugins', done: 'Got it',
  },
  card: { details: 'Details', latest: 'Latest {{version}}' },
  owned: {
    title: 'Plugins this controller owns', hint: 'Plugins bought or claimed with a licence bound to this controller. Feature plugins are switched on by the licence and configured on their pages, and can be disabled here (for every tenant of this controller; the licence is kept); themes, rule packs, UI page plugins and external services need the controller administrator to confirm installation below (choosing the tenants for UI page plugins and external services).',
    name: 'Plugin', kind: 'Type', status: 'Status', actions: 'Actions', configure: 'Configure', noPage: 'No settings page', confirmBelow: 'Confirm it in the installations below', confirmByAdmin: 'Waiting for the controller administrator to confirm',
    states: {
      enabled: 'Enabled', activating: 'Activating', installed: 'Installed', enable: 'Installed, not enabled', distributing: 'Syncing to this controller',
      pendingConfirm: 'Awaiting installation confirmation', revoked: 'License lost', disabled: 'Disabled',
      noVersion: 'No installable version yet', awaitingSync: 'Waiting for release or sync (about 1 minute)',
    },
    noVersionHint: 'The plugin is yours; once a version is released it appears below for confirmation.',
    emptyTitle: 'This controller has no plugins yet', emptyDescription: 'Plugins you get or buy in Browse appear here.',
    platformTitle: 'Installation confirmation and records',
  },
  detail: {
    publisher: 'Publisher', namespace: 'Namespace', kind: 'Type', version: 'Version', permissions: 'Permissions', noPermissions: 'No permissions declared',
    highRisk: 'High-risk permission', versions: 'Version history', plans: 'Pricing', menus: 'Pages and menus', origin: 'Page origin',
    originNotice: 'Once enabled, these menus load pages from {{origin}} in an isolated frame; the plugin cannot read your sign-in credentials.',
    menuItem: '{{title}} ({{mount}})', mount: { menu: 'menu', site_tab: 'site detail tab' }, noMenus: 'This plugin adds no pages',
    featureCode: 'Unlocks', beta: 'Beta',
  },
  pay: {
    title: 'Buy {{name}}', plan: 'Plan', balance: 'Pay from balance', qr: 'Scan to pay', balanceHint: 'Charged to this controller\'s market prepaid balance, right here.',
    qrHint: 'Scan with Alipay or WeChat. The licence is taken for this controller once paid.', confirm: 'Pay', insufficient: 'Not enough balance; switched to scan to pay',
    scan: 'Scan the QR code to pay', waiting: 'Order {{no}} waiting for payment…', paid: 'Paid. Taking the licence for this controller', expired: 'The order expired; please order again',
    openPage: 'Open the checkout in a new window', blocked: 'The checkout address is not safe and was refused', priceChanged: 'The price just changed; please confirm again',
    already: 'This controller already holds this plugin', checkResult: 'Check result', unknownTitle: 'Result unknown',
    trialUsed: 'You already used the trial of this plugin', notOnSale: 'This price is no longer on sale; refresh and choose again', notRenewable: 'This licence cannot be renewed in place',
    keyConflict: 'Request key conflict; please confirm the payment again', inProgress: 'The previous purchase is still being processed; choose "Check result" in a moment',
    unknownDetail: 'The market did not answer; the charge or order may exist. "Check result" asks with the same request key and never charges twice.',
    trial: '{{days}}-day trial',
  },
  download: { done: 'Licence held; syncing to this controller', required: 'Buy it first' },
  guide: {
    buy: 'Buy now', feature: 'Plugins that unlock {{code}}: once bought, the licence is bound to this controller.', notFound: 'The market has no entry that unlocks {{code}}.',
    showAll: 'Show all plugins',
  },
  errors: {
    forbidden: 'Plugin marketplace browse permission required', failed: 'Request failed: {{code}}', load: 'Could not load: {{code}}',
    unavailable: 'The market does not offer this yet; it becomes available once the market is upgraded.', notJoined: 'This controller has not joined the market. Joining is set in the server deployment (market URL, public keys and the plugin client certificate), not in the console. Ask the server administrator to configure it as the deployment guide describes and restart the controller, then check again.', recheck: 'Check again',
  },
  filters: { search: 'Search by name or ID', apply: 'Search', price: 'Price', anyPrice: 'Any price' },
  actions: { close: 'Close', cancel: 'Cancel' },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const marketStoreMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(marketStoreMessages)) {
  i18n.addResourceBundle(locale, 'marketStore', messages, true, true)
}
