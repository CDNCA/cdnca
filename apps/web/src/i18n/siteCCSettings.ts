import i18n from './index'

// 站点 CC 设置：自动切换（自动防御标签）与黑/白名单时间（CC防护标签）（G1-e，securitypolicy.CCSettings）。
const zhCN = {
  noPolicy: '站点还没有已发布的 CC 规则集。在上方选择默认防护，即为本站建立规则集，之后可在这里设置黑白名单时间（自动切换在「自动防御」标签）。',
  noPolicyAutoSwitch: '站点还没有已发布的 CC 规则集。在「CC防护」标签选择默认防护，即为本站建立规则集，之后可在这里设置自动切换。',
  autoSwitch: {
    label: '自动切换', enabled: '已开启', disabled: '未开启',
    hint: '网站访问量突增时临时切换到更严的防护规则；持续低于阈值达恢复时间后自动恢复默认防护。每个节点各自统计和切换。',
    source: '来源', system: '系统默认', custom: '自定义',
    systemActive: '跟随全局配置：每秒请求 {{qps}}、每秒 5xx {{errors}}，切换到 {{group}}，{{seconds}} 秒后恢复',
    systemOff: '全局自动切换未开启（防火墙配置 → CC 全局配置），站点暂不切换；全局开启后自动生效。',
    qps: '每秒请求', qps5xx: '每秒回源 5xx', zeroDisabled: '0 表示不按该项触发',
    presets: { 20: '20（适合小型网站）', 50: '50', 100: '100（适合中型网站）', 200: '200', 500: '500（适合大型网站）', 1000: '1000' },
    presetCustom: '自定义', ruleGroup: '切换到', ruleGroupPlaceholder: '选择防护规则',
    recover: '恢复时间', seconds: '秒', needThreshold: '至少设置一个阈值', needGroup: '请选择切换到的规则',
  },
  advanced: {
    title: '高级设置',
    ban: '黑名单时间', pass: '白名单时间',
    banHint: '被拉黑后持续拦截的时长，覆盖本站所有封禁规则。',
    passHint: '通过验证后免验证的时长，覆盖本站所有验证规则。',
    modes: { rule: '规则默认', system: '系统默认', custom: '自定义' },
    systemValue: '系统默认（当前 {{seconds}} 秒）',
  },
  crawlers: {
    title: '蜘蛛白名单',
    hint: '确认是搜索引擎蜘蛛的请求不受本站任何 CC 规则、封禁和验证影响。仅凭 User-Agent 不算：还要来自所填网段，或客户端 IP 反查域名（PTR）落在所填后缀下且正向解析回同一 IP。反查在后台进行，结果缓存，首个请求按普通访客处理。',
    empty: '未设置，蜘蛛按普通访客处理。',
    presets: '添加常见爬虫', add: '添加蜘蛛', remove: '删除',
    name: '名称', tokens: 'User-Agent 关键字（每行一个）', networks: '可信网段（每行一个，可选）',
    suffixes: '反查域名后缀（每行一个，可选）', needVerify: '“{{name}}”需要填写可信网段或反查域名后缀，至少一项',
    needName: '每个蜘蛛都需要名称和 User-Agent 关键字',
  },
  cookieDomain: {
    label: '验证 Cookie 域名',
    placeholder: '例如 example.com，留空只对当前域名有效',
    hint: '通过验证后的 Cookie 对该域名及其所有子域名有效（仅当访问的域名在其下时设置）。子域名若不归你所有，Cookie 也会发给它们，只填自己的主域名。',
  },
  v6Capability: '蜘蛛白名单和验证 Cookie 域名需要节点支持 CC v6，未升级的节点发布时会被拒绝并列出。',
  save: '保存设置', saving: '正在保存',
  saved: '已保存为规则集新版本 v{{version}}，发布后在节点生效。',
  publish: '去发布', saveFailed: '保存失败：{{message}}',
  published: '已保存，正在下发到本站节点。',
  publishFailed: '已保存到规则集，但本次下发被拒绝（如节点版本不支持或套餐未开通）；系统会自动重试。',
  capability: '节点需升级到支持自动切换的版本（CC v5），未升级的节点发布时会被拒绝并列出。',
} as const

const enUS = {
  noPolicy: 'The site has no published CC rule set yet. Choosing a default protection above creates one for the site, then set the blacklist/allowlist times here (automatic switching is on the Auto defense tab).',
  noPolicyAutoSwitch: 'The site has no published CC rule set yet. Choosing a default protection on the CC protection tab creates one for the site, then set automatic switching here.',
  autoSwitch: {
    label: 'Automatic switching', enabled: 'On', disabled: 'Off',
    hint: 'When traffic surges the site temporarily runs stricter rules, and returns to its default protection after staying below the threshold for the recovery time. Every node counts and switches on its own.',
    source: 'Source', system: 'System default', custom: 'Custom',
    systemActive: 'Follows the global config: {{qps}} requests/s, {{errors}} 5xx/s, switches to {{group}}, recovers after {{seconds}} s',
    systemOff: 'The global auto switch is off (firewall config → CC global config); the site does not switch until it is turned on.',
    qps: 'Requests per second', qps5xx: 'Origin 5xx per second', zeroDisabled: '0 = not used',
    presets: { 20: '20 (small sites)', 50: '50', 100: '100 (medium sites)', 200: '200', 500: '500 (large sites)', 1000: '1000' },
    presetCustom: 'Custom', ruleGroup: 'Switch to', ruleGroupPlaceholder: 'Choose protection rules',
    recover: 'Recovery time', seconds: 's', needThreshold: 'Set at least one threshold', needGroup: 'Choose the rules to switch to',
  },
  advanced: {
    title: 'Advanced settings',
    ban: 'Blacklist time', pass: 'Allowlist time',
    banHint: 'How long a banned client stays blocked; overrides every ban rule of the site.',
    passHint: 'How long a verified client skips verification; overrides every verification rule of the site.',
    modes: { rule: 'Rule default', system: 'System default', custom: 'Custom' },
    systemValue: 'System default (currently {{seconds}} s)',
  },
  crawlers: {
    title: 'Trusted crawlers',
    hint: 'Requests confirmed to come from a search engine crawler skip every CC rule, ban and verification of the site. The User-Agent alone is not enough: the client must also be in a listed network, or its IP must reverse-resolve (PTR) under a listed suffix and resolve forward to the same IP. The reverse lookup runs in the background and is cached; the first request is treated as an ordinary visitor.',
    empty: 'None; crawlers are treated as ordinary visitors.',
    presets: 'Add common crawlers', add: 'Add crawler', remove: 'Remove',
    name: 'Name', tokens: 'User-Agent tokens (one per line)', networks: 'Trusted networks (one per line, optional)',
    suffixes: 'Reverse DNS suffixes (one per line, optional)', needVerify: '"{{name}}" needs trusted networks or reverse DNS suffixes',
    needName: 'Every crawler needs a name and User-Agent tokens',
  },
  cookieDomain: {
    label: 'Verification cookie domain',
    placeholder: 'For example example.com; empty keeps it to the visited host',
    hint: 'The cookie set after verification is valid for this domain and all its subdomains (set only when the visited host is under it). It is also sent to subdomains you do not own, so enter only your own domain.',
  },
  v6Capability: 'Trusted crawlers and the verification cookie domain need nodes with CC v6; publishing names any node that is not upgraded.',
  save: 'Save settings', saving: 'Saving',
  saved: 'Saved as rule set version v{{version}}; it takes effect on the nodes once published.',
  publish: 'Publish', saveFailed: 'Save failed: {{message}}',
  published: 'Saved; publishing to the site\'s nodes.',
  publishFailed: 'Saved to the rule set, but publishing was refused (for example nodes not upgraded or the plan lacks the feature); it is retried automatically.',
  capability: 'Nodes need an agent with the auto switch (CC v5); publishing names any node that is not upgraded.',
} as const

function pseudo(value: unknown): unknown {
  return typeof value === 'string'
    ? `［${[...value].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
})) i18n.addResourceBundle(locale, 'siteCCSettings', messages, true, true)

export { enUS as siteCCSettingsEnUS, zhCN as siteCCSettingsZhCN }
