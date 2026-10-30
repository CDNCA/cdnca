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
  },
  state: {
    purchase: '购买', get: '获取', distributing: '使用权已取得，正在同步', enable: '去启用', enabled: '已启用', activating: '授权生效中',
    revoked: '授权失效', revokedHint: '这个插件的授权已结束或已改绑到其他主控，本主控不能再启用它。续费或在授权端改绑回来后恢复。',
    activatingHint: '已购买。授权端正在为本主控重签授权，通常一分钟内生效。',
    enableHint: '已到达本主控。到对应页面启用：', enableTenant: '已到达本主控。由租户管理员在“插件市场”确认权限后启用。',
    pendingConfirm: '已购买，待你确认',
    distributingHint: '平台正在验证并分发到本主控；需要确认权限时，由对应管理员确认后才会出现在本机。到达后这里会显示“去启用”。',
    platformConfirm: '使用权已取得，等待主控管理员确认安装',
    platformConfirmHint: '主题和规则包对整个主控生效，由主控管理员在“我的插件”核对权限并确认安装；确认后到对应页面启用。',
    goMine: '去我的插件确认',
  },
  card: { details: '详情', latest: '最新 {{version}}' },
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
  },
  state: {
    purchase: 'Buy', get: 'Get', distributing: 'Licence held, syncing', enable: 'Enable', enabled: 'Enabled', activating: 'Activating',
    revoked: 'License lost', revokedHint: 'The license ended or was moved to another controller, so this controller can no longer enable it. Renew or move it back in the license portal to restore it.',
    activatingHint: 'Purchased. The license service is re-signing this controller\'s license; it usually takes under a minute.',
    enableHint: 'On this controller. Enable it on:', enableTenant: 'On this controller. A tenant administrator approves its permissions in Plugin marketplace to enable it.',
    pendingConfirm: 'Purchased, awaiting your confirmation',
    distributingHint: 'The platform is verifying it and delivering it to this controller; where permissions need approval, it appears here once the right administrator approves them. Enable shows up here when it arrives.',
    platformConfirm: 'Licensed, waiting for the controller administrator to confirm installation',
    platformConfirmHint: 'Themes and rule packs apply to the whole controller. The controller administrator reviews permissions and confirms installation under My plugins, then enables it on its page.',
    goMine: 'Confirm in My plugins',
  },
  card: { details: 'Details', latest: 'Latest {{version}}' },
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
