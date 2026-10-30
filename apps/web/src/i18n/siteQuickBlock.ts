import i18n from './index'
import './ipIntel'

// 站点“防护”页“快速屏蔽”卡片（G3-d #13，securitypolicy.QuickBlock）与
// “本站快速屏蔽”覆盖卡片（securitypolicy.QuickBlockOverride）。
const zhCN = {
  title: '规则库快速屏蔽（默认值）',
  hint: '按客户端 IP 的运营商与 IDC 标签一键屏蔽，排在规则库之前执行；放行规则仍可放行被屏蔽的请求。这里改的是规则库，所有应用该规则库且没有单独设置的站点都会跟着变；只改本站请用上方“本站快速屏蔽”。',
  blockIDCCN: '屏蔽国内 IDC', blockIDCCNHint: '国内云厂商和机房的地址（阿里云、腾讯云、华为云等）。',
  blockIDCGlobal: '屏蔽境外 IDC', blockIDCGlobalHint: '境外云厂商和机房的地址（AWS、GCP、Azure 等）。',
  carriers: '屏蔽运营商', carriersPlaceholder: '选择要屏蔽的运营商（可多选）',
  crawlers: '放行搜索引擎蜘蛛',
  crawlersHint: '每行一条：网段,User-Agent 前缀。来自该网段且 User-Agent 以该前缀开头的请求不受快速屏蔽限制（后续规则仍生效）；最多 32 个网段。',
  crawlersPlaceholder: '66.249.64.0/19,Mozilla/5.0 (compatible; Googlebot/2.1',
  crawlersInvalid: '第 {{line}} 行格式应为“网段,User-Agent 前缀”',
  save: '保存', saving: '正在保存',
  saved: '已保存为规则库新版本 v{{version}}，发布后在节点生效。',
  publish: '去发布', openLibraries: '去应用规则库',
  published: '已保存，正在下发到本站节点。',
  publishFailed: '已保存到规则库，但本次下发被拒绝（如节点版本不支持或套餐未开通）；系统会自动重试。',
  pending: '快速屏蔽有未发布的修改（当前生效 v{{active}}，最新 v{{latest}}）。',
  status: { on: '已开启', off: '未开启' },
  noPolicy: '站点还没有生效的 WAF 规则库。打开上方“站点 WAF 规则库”开关，再开启快速屏蔽。',
  unsupported: '当前规则库不支持快速屏蔽：订阅的规则库只读，默认动作为“拦截”的白名单规则库也不能开启。',
  libraryNotReady: '主控还没有同步到 IP 情报库，暂时不能开启快速屏蔽（关闭不受影响）。',
  nodesNotice: '发布时每个目标节点都要已加载已验签的 IP 情报库，未就绪的节点会被拒绝并列出；节点就绪后自动发布。',
  errors: {
    quick_block_ip_intel_unavailable: '主控还没有同步到 IP 情报库，不能开启快速屏蔽。',
    quick_block_unsupported_policy: '当前规则库不支持快速屏蔽。',
    quick_block_last_rules: '规则库只剩快速屏蔽规则，关闭前请先在规则库里添加一条规则。',
    quick_block_rule_budget: '快速屏蔽规则加上规则库已有规则超过 100 条，请减少放行网段或规则。',
    quick_block_site_override_conflict: '有站点单独设置了快速屏蔽，这次修改后这些站点的设置无法生效。请先把这些站点的对应项改回“跟随规则库”，或调整本次修改。',
    version_conflict: '规则库已被修改，请刷新后重试。',
    validation_error: '设置不合法：请检查网段（如 66.249.64.0/19）和 User-Agent 前缀。',
    unknown: '保存失败（{{code}}）',
  },
  override: {
    title: '本站快速屏蔽',
    hint: '每一项可以跟随规则库，也可以只为本站开启或关闭；只影响本站，其他站点继续跟随规则库。',
    inherit: '跟随规则库（{{value}}）', on: '开启', off: '关闭',
    listCount: '{{count}} 项',
    carrierList: '本站屏蔽的运营商',
    carriersHint: '开启：本站只屏蔽这里选的运营商（整体替换规则库的列表）；关闭：本站不按运营商屏蔽。',
    carriersEmpty: '开启时至少选择一个运营商；不想屏蔽请选“关闭”。',
    crawlerList: '本站放行的蜘蛛网段',
    crawlersHint: '开启：本站使用这里的网段列表（整体替换规则库的列表，每行“网段,User-Agent 前缀”，最多 32 个网段）；关闭：本站不放行任何蜘蛛网段。',
    crawlersEmpty: '开启时至少填写一行；不想放行请选“关闭”。',
    saved: '已保存本站设置，正在下发到节点。',
    noLibrary: '站点还没有应用 WAF 规则库，暂时不能单独设置快速屏蔽。先在“规则库防护”里应用一个规则库。',
    unsupported: '本站的规则库不能开启屏蔽（订阅的规则库或默认动作为“拦截”的白名单规则库），本站只能选择关闭或跟随规则库。',
    loadFailed: '读取本站快速屏蔽设置失败。', retry: '重试',
  },
  overrideErrors: {
    quick_block_ip_intel_unavailable: '主控还没有同步到 IP 情报库，不能开启屏蔽。',
    quick_block_unsupported_policy: '本站的规则库不能开启屏蔽，只能选择关闭或跟随规则库。',
    quick_block_last_rules: '规则库只有快速屏蔽规则，本站全部关闭后就没有规则了。请保留一项或在规则库里添加一条规则。',
    quick_block_rule_budget: '快速屏蔽规则加上规则库已有规则超过 100 条，请减少放行网段。',
    quick_block_no_library: '站点还没有应用 WAF 规则库，不能单独设置。',
    version_conflict: '站点设置已被修改，请刷新后重试。',
    idempotency_conflict: '请求重复且内容不同，请刷新后重试。',
    site_locked: '站点已被平台管理员锁定，暂时不能修改。',
    validation_error: '设置不合法：请检查运营商、网段（如 66.249.64.0/19）和 User-Agent 前缀。',
  },
} as const

type Messages = { [Key in keyof typeof zhCN]: typeof zhCN[Key] extends string ? string : { [Child in keyof typeof zhCN[Key]]: string } }

const enUS: Messages = {
  title: 'Rule library quick block (defaults)',
  hint: 'Block clients by their carrier and IDC tags in one click. It runs before the rule libraries; allow rules can still let blocked requests through. This changes the rule library: every site using it without its own setting follows. To change this site only, use "This site\'s quick block" above.',
  blockIDCCN: 'Block China IDC', blockIDCCNHint: 'Addresses of Chinese clouds and data centers (Alibaba Cloud, Tencent Cloud, Huawei Cloud, ...).',
  blockIDCGlobal: 'Block global IDC', blockIDCGlobalHint: 'Addresses of clouds and data centers outside China (AWS, GCP, Azure, ...).',
  carriers: 'Block carriers', carriersPlaceholder: 'Choose carriers to block',
  crawlers: 'Allow search engine crawlers',
  crawlersHint: 'One per line: network,User-Agent prefix. Requests from the network whose User-Agent starts with the prefix skip the quick block (later rules still apply); at most 32 networks.',
  crawlersPlaceholder: '66.249.64.0/19,Mozilla/5.0 (compatible; Googlebot/2.1',
  crawlersInvalid: 'Line {{line}} must be "network,User-Agent prefix"',
  save: 'Save', saving: 'Saving',
  saved: 'Saved as rule library version v{{version}}; it takes effect on the nodes once published.',
  publish: 'Publish', openLibraries: 'Apply a rule library',
  published: 'Saved; publishing to the site\'s nodes.',
  publishFailed: 'Saved to the rule library, but publishing was refused (for example nodes not upgraded or the plan lacks the feature); it is retried automatically.',
  pending: 'The quick block has unpublished changes (active v{{active}}, latest v{{latest}}).',
  status: { on: 'On', off: 'Off' },
  noPolicy: 'The site has no active WAF rule library. Turn on the site WAF rule library above, then turn the quick block on.',
  unsupported: 'This rule library cannot carry a quick block: subscribed libraries are read only, and default-block (allowlist) libraries cannot use it.',
  libraryNotReady: 'The control plane has not synced the IP intelligence library yet, so the quick block cannot be turned on (turning it off still works).',
  nodesNotice: 'Every target node must have loaded a verified IP intelligence library; publishing names the nodes that have not and publishes automatically once they are ready.',
  errors: {
    quick_block_ip_intel_unavailable: 'The control plane has no IP intelligence library yet; the quick block cannot be turned on.',
    quick_block_unsupported_policy: 'This rule library cannot carry a quick block.',
    quick_block_last_rules: 'The library has only quick block rules; add a rule to it before turning the quick block off.',
    quick_block_rule_budget: 'Quick block rules plus the library\'s rules exceed 100; allow fewer networks or remove rules.',
    quick_block_site_override_conflict: 'Some sites have their own quick block settings that would no longer apply after this change. Set those items back to "Follow the rule library" on those sites, or adjust this change.',
    version_conflict: 'The rule library changed; refresh and try again.',
    validation_error: 'Invalid settings: check the networks (for example 66.249.64.0/19) and User-Agent prefixes.',
    unknown: 'Save failed ({{code}})',
  },
  override: {
    title: 'This site\'s quick block',
    hint: 'Each item can follow the rule library, or be turned on or off for this site only. Only this site changes; other sites keep following the rule library.',
    inherit: 'Follow the rule library ({{value}})', on: 'On', off: 'Off',
    listCount: '{{count}} items',
    carrierList: 'Carriers this site blocks',
    carriersHint: 'On: this site blocks only the carriers chosen here (replacing the rule library\'s list). Off: this site blocks no carrier.',
    carriersEmpty: 'Choose at least one carrier when on; choose Off to block none.',
    crawlerList: 'Crawler networks this site allows',
    crawlersHint: 'On: this site uses the networks here (replacing the rule library\'s list; one "network,User-Agent prefix" per line, at most 32 networks). Off: this site allows no crawler network.',
    crawlersEmpty: 'Enter at least one line when on; choose Off to allow none.',
    saved: 'Saved for this site. Deploying to the nodes.',
    noLibrary: 'The site has no WAF rule library yet, so it cannot have its own quick block. Apply one under rule library protection first.',
    unsupported: 'This site\'s rule library cannot block (a subscribed or default-block allowlist library); this site can only turn items off or follow the library.',
    loadFailed: 'Could not load this site\'s quick block settings.', retry: 'Retry',
  },
  overrideErrors: {
    quick_block_ip_intel_unavailable: 'The control plane has no IP intelligence library yet; blocks cannot be turned on.',
    quick_block_unsupported_policy: 'This site\'s rule library cannot block; turn items off or follow the library.',
    quick_block_last_rules: 'The rule library has only quick block rules, so turning everything off leaves this site without rules. Keep an item on or add a rule to the library.',
    quick_block_rule_budget: 'Quick block rules plus the library\'s rules exceed 100; allow fewer networks.',
    quick_block_no_library: 'The site has no WAF rule library, so it cannot have its own setting.',
    version_conflict: 'The site settings changed; refresh and try again.',
    idempotency_conflict: 'A repeated request had different content; refresh and try again.',
    site_locked: 'A platform administrator locked the site; it cannot be changed now.',
    validation_error: 'Invalid settings: check the carriers, networks (for example 66.249.64.0/19) and User-Agent prefixes.',
  },
}

function pseudo(value: unknown): unknown {
  // Brackets only, so {{interpolation}} keeps working.
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const siteQuickBlockMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(siteQuickBlockMessages)) i18n.addResourceBundle(locale, 'siteQuickBlock', messages, true, true)
