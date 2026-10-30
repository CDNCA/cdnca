import i18n from './index'

// Rule packs (ADR 0007 §5.4): list, enable / disable per level, conflicts
// and the final execution order of a site.
const zhCN = {
  title: '规则包',
  intro: '规则包是一组预置的防护规则。在这里选择启用或禁用，网站发布后生效；切换到“网站”可以按网站单独设置。两个规则包冲突时，禁用其中一个即可。',
  tenantIntro: '规则包是一组预置的防护规则，官方规则包默认已启用。“我的账号（全部网站）”里的设置对你名下所有网站生效；切换到“单个网站”可以只给某个网站另外设置，网站的设置优先。两个规则包冲突时，关闭其中一个即可。',
  levels: { platform: '平台', tenant: '租户', site: '网站', default: '系统默认' },
  // 用户端（客户自己的账号）看到的层级名：账号层不叫“租户”。
  tenantLevels: { platform: '平台', tenant: '我的账号', site: '网站', default: '系统默认' },
  modes: { own: '我的账号（全部网站）', site: '单个网站' },
  layers: { system: '官方', developer: '开发者', user: '自定义' },
  layerHint: '规则包来源：官方 = 平台提供的官方规则包；开发者 = 第三方开发者提供；自定义 = 你自己导入或订阅生成的。',
  states: { inherit: '继承', enabled: '启用', disabled: '禁用' },
  tenantStates: { enabled: '启用', disabled: '关闭' },
  follow: '跟随{{level}}（当前：{{state}}）', systemDefault: '系统默认（关闭）',
  columns: { pack: '规则包', layer: '来源', engine: '引擎', version: '当前版本', effective: '生效状态', here: '本层设置', allowLower: '允许下层调整', priority: '优先级', actions: '操作' },
  tenantColumns: { here: '我的设置', allowLower: '允许单个网站单独设置' },
  columnHints: {
    here: '跟随：不单独设置，沿用上一级的结果（括号里是现在的结果）；启用 / 关闭：在这一级单独设置，覆盖上一级。',
    platformHere: '系统默认：未设置的规则包一律关闭；启用 / 禁用：对全部客户生效，客户能否再调整由“允许下层调整”决定。',
    allowLower: '打开后，客户账号及其网站可以在自己的页面里单独启用或关闭这个规则包。',
    tenantAllowLower: '打开后，单个网站可以有自己的设置；关闭则所有网站都按“我的账号”的设置执行。',
    priority: '多个规则包同时生效时的执行先后：数字越小越先匹配，默认 500。',
  },
  values: {
    on: '生效', off: '不生效', from: '来自{{level}}', locked: '上层未允许调整', ignored: '{{count}} 条下层设置被上层锁定而忽略',
    auto: '自动采用新版本', manual: '手动采用新版本', noVersion: '无已下载版本', cost: '{{rules}} 条规则 / {{regexes}} 个正则 / 代价 {{units}}',
    requires: '节点需具备：{{items}}', priorityDefault: '默认 500',
  },
  rules: { title: '可单独开关的规则', none: '该包没有导出规则，只能整包开关', ruleState: '{{state}}（{{source}}）' },
  params: {
    title: '参数', save: '保存参数', invalid: '参数不符合包的 params_schema',
    // enum values of libs/rulepack params.go bindTargets (waf.action, cc.action.kind, cc.challenge.mode)
    values: {
      allow: '放行', block: '拦截', challenge: '挑战', log: '仅记录', reject_429: '返回 429',
      delay: '5 秒盾', js: 'JS 验证', redirect: '跳转验证', click: '点击验证', easy_click: '点击验证（简单）',
      slider: '滑块验证', easy_slider: '滑块验证（简单）', captcha: '验证码', rotate: '图片旋转',
    },
  },
  site: {
    select: '选择网站', placeholder: '输入域名搜索', none: '请选择网站查看最终执行顺序',
    order: '最终执行顺序', orderHint: '顺序 = 层级（用户 → 开发者 → 系统）→ 优先级（小者先）→ 包 ID → 规则 ID；在主控发布时确定，节点只按此执行并校验摘要。',
    position: '#', rule: '规则', action: '动作',
    conflicts: '冲突（{{count}}），不能发布', warnings: '提示（{{count}}）', disableAt: '在{{level}}禁用 {{target}}', switchOffAt: '在{{level}}关闭 {{target}}',
    publish: '发布', published: '已发布第 {{revision}} 版', unpublished: '尚未发布', upToDate: '已是最新', pending: '有未发布的变更',
    digest: 'resolved_sha256：{{digest}}',
  },
  conflictCodes: {
    duplicate_pack: '同一规则包重复挂载', opposite_action: '同层同优先级、相同条件上动作相反', unknown_export: '引用了包未导出的规则',
    params_invalid: '参数超出 params_schema', engine_version: '包需要的引擎版本高于节点', engine_singleton: '一个网站只能运行一个 ModSecurity 包',
    crs_out_of_profile: 'ModSecurity 包超出网站当前 CRS 档位：只能在档位已有的攻击类别和防护等级内关闭部分规则（网站须已启用托管 WAF）',
    budget_exceeded: '超出单站规则预算', shadowed: '规则被更早的终结规则完全遮蔽，永远不会执行',
  },
  import: { open: '导入规则包', title: '导入规则包（cdnca.rule-pack/v1）', hint: '粘贴或选择规则包 JSON。导入即“下载”，不会启用。系统/开发者包由平台导入；租户只能导入 user/<租户 scope>/ 命名空间下的包。', tenantHint: '粘贴或选择规则包 JSON。导入即“下载”，不会启用；只能导入 user/<你的账号 ID>/ 开头的自定义规则包。', file: '选择文件', submit: '导入' },
  version: { use: '设为当前版本', remove: '删除此版本', removeConfirm: '删除本地制品？启用中或被已发布网站挂载的版本不能删除。', policy: '新版本' },
  notices: {
    saved: '已保存', imported: '已导入（未启用）', removed: '已删除', published: '已发布', failed: '操作失败',
    locked: '上层未允许在这一层调整该规则包', inUse: '该规则包仍在某层启用或被已发布的网站挂载，请先禁用', exists: '该版本已下载',
    invalid: '内容未通过校验（格式、参数或代价预算）', conflict: '存在冲突，未发布',
  },
  subscriptions: {
    title: 'WAF 规则库订阅', intro: '订阅后得到你账号下的自定义规则包（已下载、未启用），在上表启用并按网站发布后生效；订阅更新会生成规则包新版本，已发布的网站显示“待发布”，需重新发布才会执行新版本。退订只停止更新，规则包保留。',
    none: '平台暂无可订阅的规则库', name: '规则库', version: '订阅版本', pack: '我的规则包', actions: '操作',
    feed: '{{feed}} · {{rules}} 条规则', deleted: '平台已停止提供', notSubscribed: '未订阅', packVersion: '{{current}}（最新 {{latest}}）',
    subscribe: '订阅', unsubscribe: '退订', unsubscribeConfirm: '退订后不再生成新版本，已有规则包与已发布网站不受影响。确认退订？',
    pending: '待发布：{{domains}}', publish: '去发布', subscribed: '已订阅（规则包未启用）', unsubscribed: '已退订', notReady: '该订阅尚未拉取成功',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  title: 'Rule packs',
  intro: 'A rule pack is a set of ready-made protection rules. Enable or disable it here; it takes effect when a site is published. Switch to "Site" to set it per site. If two packs conflict, disable one of them.',
  tenantIntro: 'A rule pack is a set of ready-made protection rules; official packs are on by default. Settings under "My account (all sites)" apply to every site you own; switch to "Single site" to set one site differently (the site setting wins). If two packs conflict, switch one of them off.',
  levels: { platform: 'Platform', tenant: 'Tenant', site: 'Site', default: 'System default' },
  tenantLevels: { platform: 'Platform', tenant: 'My account', site: 'Site', default: 'System default' },
  modes: { own: 'My account (all sites)', site: 'Single site' },
  layers: { system: 'Official', developer: 'Developer', user: 'Custom' },
  layerHint: 'Where the pack comes from: Official = provided by the platform; Developer = a third-party developer; Custom = imported by you or created by a subscription.',
  states: { inherit: 'Inherit', enabled: 'Enable', disabled: 'Disable' },
  tenantStates: { enabled: 'On', disabled: 'Off' },
  follow: 'Follow {{level}} (now: {{state}})', systemDefault: 'System default (off)',
  columns: { pack: 'Rule pack', layer: 'Source', engine: 'Engine', version: 'Current version', effective: 'Effective', here: 'This level', allowLower: 'Allow lower levels', priority: 'Priority', actions: 'Actions' },
  tenantColumns: { here: 'My setting', allowLower: 'Allow per-site settings' },
  columnHints: {
    here: 'Follow: no own setting, the level above decides (its current result in brackets); On / Off: set here, overriding the level above.',
    platformHere: 'System default: a pack nobody set is off; Enable / Disable: applies to every customer; whether customers may change it is "Allow lower levels".',
    allowLower: 'When on, customer accounts and their sites can switch this pack on or off on their own pages.',
    tenantAllowLower: 'When on, a single site can have its own setting; when off, every site follows "My account".',
    priority: 'Order when several packs apply: lower numbers match first; default 500.',
  },
  values: {
    on: 'On', off: 'Off', from: 'from {{level}}', locked: 'Locked by an upper level', ignored: '{{count}} lower settings ignored (locked above)',
    auto: 'Adopt new versions automatically', manual: 'Adopt new versions manually', noVersion: 'No downloaded version', cost: '{{rules}} rules / {{regexes}} regexes / cost {{units}}',
    requires: 'Nodes need: {{items}}', priorityDefault: 'Default 500',
  },
  rules: { title: 'Individually switchable rules', none: 'This pack exports no rules; it can only be switched as a whole', ruleState: '{{state}} ({{source}})' },
  params: {
    title: 'Parameters', save: 'Save parameters', invalid: 'Parameters do not fit the pack params_schema',
    values: {
      allow: 'Allow', block: 'Block', challenge: 'Challenge', log: 'Log only', reject_429: 'Respond 429',
      delay: '5-second shield', js: 'JS verification', redirect: 'Redirect verification', click: 'Click verification', easy_click: 'Click verification (simple)',
      slider: 'Slider verification', easy_slider: 'Slider verification (simple)', captcha: 'CAPTCHA', rotate: 'Image rotation',
    },
  },
  site: {
    select: 'Site', placeholder: 'Search by domain', none: 'Select a site to see its final execution order',
    order: 'Final execution order', orderHint: 'Order = layer (user → developer → system) → priority (lower first) → pack ID → rule ID; fixed when the control plane publishes, nodes only run it and check the digest.',
    position: '#', rule: 'Rule', action: 'Action',
    conflicts: 'Conflicts ({{count}}): cannot publish', warnings: 'Notes ({{count}})', disableAt: 'Disable {{target}} at {{level}}', switchOffAt: 'Switch {{target}} off at {{level}}',
    publish: 'Publish', published: 'Published revision {{revision}}', unpublished: 'Not published yet', upToDate: 'Up to date', pending: 'Unpublished changes',
    digest: 'resolved_sha256: {{digest}}',
  },
  conflictCodes: {
    duplicate_pack: 'The same pack is mounted twice', opposite_action: 'Opposite actions on the same condition at the same layer and priority', unknown_export: 'References a rule the pack does not export',
    params_invalid: 'Parameters outside params_schema', engine_version: 'The pack needs a newer engine than the nodes run', engine_singleton: 'A site can run only one ModSecurity pack',
    crs_out_of_profile: "The ModSecurity pack is outside the site's CRS profile: it can only switch off rules within the profile's attack classes and level (the site must run a managed WAF)",
    budget_exceeded: 'Over the per-site rule budget', shadowed: 'Fully covered by an earlier terminal rule; it never runs',
  },
  import: { open: 'Import rule pack', title: 'Import rule pack (cdnca.rule-pack/v1)', hint: 'Paste or choose the rule pack JSON. Importing is downloading; nothing is enabled. Platform operators import system / developer packs; a tenant only packs under user/<tenant scope>/.', tenantHint: 'Paste or choose the rule pack JSON. Importing is downloading; nothing is enabled. Only custom packs under user/<your account ID>/ can be imported.', file: 'Choose file', submit: 'Import' },
  version: { use: 'Make current', remove: 'Delete this version', removeConfirm: 'Delete the local artifact? A version that is enabled or mounted by a published site cannot be deleted.', policy: 'New versions' },
  notices: {
    saved: 'Saved', imported: 'Imported (not enabled)', removed: 'Deleted', published: 'Published', failed: 'Operation failed',
    locked: 'An upper level does not allow adjusting this pack here', inUse: 'The pack is still enabled at some level or mounted by a published site; disable it first', exists: 'This version is already downloaded',
    invalid: 'The content did not pass validation (format, parameters or cost budget)', conflict: 'Conflicts found; not published',
  },
  subscriptions: {
    title: 'WAF rule library subscriptions', intro: 'Subscribing gives your account a custom rule pack (downloaded, not enabled); enable it above and publish sites to use it. A subscription update adds a pack version; published sites show "waiting to publish" and run the new version only after they are published again. Unsubscribing stops updates and keeps the pack.',
    none: 'No rule library to subscribe to', name: 'Rule library', version: 'Subscription version', pack: 'My rule pack', actions: 'Actions',
    feed: '{{feed}} · {{rules}} rules', deleted: 'No longer offered', notSubscribed: 'Not subscribed', packVersion: '{{current}} (latest {{latest}})',
    subscribe: 'Subscribe', unsubscribe: 'Unsubscribe', unsubscribeConfirm: 'Unsubscribing stops new versions; the pack and published sites stay as they are. Unsubscribe?',
    pending: 'Waiting to publish: {{domains}}', publish: 'Publish', subscribed: 'Subscribed (the pack is not enabled)', unsubscribed: 'Unsubscribed', notReady: 'The subscription has not been fetched yet',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const rulePackMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as Messages, 'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(rulePackMessages)) {
  i18n.addResourceBundle(locale, 'rulePacks', messages, true, true)
}
