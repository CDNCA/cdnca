import i18n from './index'

export const zhCNFirewallAction = {
  title: '防火墙动作策略', loadFailed: '防火墙动作策略加载失败', save: '保存策略', recover: '恢复最近稳定版本',
  normalAction: '常态动作', escalatedAction: '高负载动作', engageThreshold: '触发阈值', recoverThreshold: '恢复阈值',
  recoveryWindows: '连续恢复窗口', blockNetworks: '内核拦截网段', trustedProxies: '可信代理网段', trustedCrawler: '可信爬虫',
  crawlerName: '名称', crawlerNetworks: '可信网段', crawlerPrefixes: 'User-Agent 前缀', addCrawler: '添加可信爬虫', removeCrawler: '删除可信爬虫', returnPage: '受控返回页', statusCode: '状态码',
  contentType: '内容类型', body: '响应正文', currentActive: '当前生效修订：{{revision}}', currentLKG: '最近稳定修订：{{revision}}',
  actions: { disconnect: '断开连接', return_page: '返回受控页面', nftables: 'nftables 自动拦截' },
  states: { pending: '候选策略等待下发，当前稳定版本继续生效', active: '动作策略已生效', failed: '候选策略下发失败，当前稳定版本继续生效' },
  description: '每个网站一份：攻击流量超过触发阈值时自动切换到高负载动作，回落后按恢复窗口自动解除。选择网站进入配置。',
  back: '返回网站列表', siteLabel: '网站：{{domain}}', siteIdLabel: '网站 ID：{{id}}', noCrawler: '未添加可信爬虫',
  stateTags: { pending: '下发中', active: '已生效', failed: '下发失败', inherited: '继承默认' },
  disabled: '本站动作策略已停用，节点不执行（修订与稳定版本保留，可在网站「自动防御」标签重新打开）',
  source: { site: '本站自定义', tenant_default: '继承默认设置', system_default: '继承系统默认' },
  inherit: '恢复继承默认',
  inheritedTenant: '本站正在使用默认设置',
  inheritedSystem: '本站正在使用系统内置默认，尚未下发到节点',
  inheritedHint: '下方为当前生效的默认值。修改并保存后，本站改为使用自己的设置；之后可随时「恢复继承默认」。',
  defaults: {
    title: '默认设置', edit: '编辑默认设置', collapse: '收起', save: '保存默认设置', readOnly: '当前账号没有防火墙管理权限，只能查看。',
    hintSystem: '尚未保存默认设置：没有单独设置的网站（{{count}} 个）使用系统内置默认，不下发到节点。保存后这些网站立即按默认设置生效。',
    hintSaved: '没有单独设置的网站（{{count}} 个）都使用这里的设置；单独设置过的网站不受影响，可在该网站页「恢复继承默认」。',
    saved: '默认设置已保存，{{count}} 个继承中的网站将按新设置下发', saveFailed: '默认设置保存失败', loadFailed: '默认设置加载失败',
    tenant: '默认设置所属用户', tenantPlaceholder: '选择用户后显示并编辑其默认设置', tenantEmpty: '没有匹配的用户',
  },
  sections: { trigger: '动作与阈值', networks: '网段' },
  help: {
    normalAction: '未触发阈值时对被拦截请求的处理方式。', escalatedAction: '仅租户自有节点支持，由节点内核 nftables 拦截下方网段。',
    engageThreshold: '每秒被拦截请求数达到此值即进入高负载动作。', recoverThreshold: '每秒被拦截请求数不超过此值记为一个恢复窗口，须小于触发阈值。',
    recoveryWindows: '连续满足恢复条件的窗口数，达到后解除高负载动作（1–60）。',
    blockNetworks: '高负载时由内核拦截的网段，每行一个 CIDR；与可信代理或可信爬虫重叠的网段不会拦截。',
    trustedProxies: '位于网站前方的代理网段，每行一个 CIDR；来自这些地址的请求按 X-Forwarded-For 识别真实客户端。',
    trustedCrawler: '网段与 User-Agent 前缀同时匹配时放行，不受阈值影响。', returnPage: '常态动作为「返回受控页面」时返回的状态码与正文。',
  },
  picker: {
    search: '按域名搜索网站', empty: '没有网站', loadFailed: '网站列表加载失败', retry: '重试', openFailed: '无法读取该网站的所属用户，请稍后重试',
    configure: '配置动作策略', configureSite: '配置 {{domain}} 的动作策略',
    columns: { domain: '网站', owner: '所属用户', action: '操作' },
  },
  notices: { saved: '动作策略候选已保存', recovered: '已从最近稳定版本创建恢复候选', inherited: '已恢复继承默认设置' },
  errors: { save: '动作策略保存失败', recover: '稳定版本恢复失败', inherit: '恢复继承失败', forbidden: '当前账号无权查看防火墙动作策略' },
} as const

export const enUSFirewallAction = {
  title: 'Firewall action policy', loadFailed: 'Failed to load firewall action policy', save: 'Save policy', recover: 'Restore last known good',
  normalAction: 'Normal action', escalatedAction: 'High-load action', engageThreshold: 'Engage threshold', recoverThreshold: 'Recover threshold',
  recoveryWindows: 'Consecutive recovery windows', blockNetworks: 'Kernel block networks', trustedProxies: 'Trusted proxy networks', trustedCrawler: 'Trusted crawler',
  crawlerName: 'Name', crawlerNetworks: 'Trusted networks', crawlerPrefixes: 'User-Agent prefixes', addCrawler: 'Add trusted crawler', removeCrawler: 'Remove trusted crawler', returnPage: 'Controlled response', statusCode: 'Status code',
  contentType: 'Content type', body: 'Response body', currentActive: 'Active revision: {{revision}}', currentLKG: 'Last known good revision: {{revision}}',
  actions: { disconnect: 'Disconnect', return_page: 'Return controlled page', nftables: 'Automatic nftables block' },
  states: { pending: 'Candidate pending; the stable revision remains active', active: 'Action policy is active', failed: 'Candidate failed; the stable revision remains active' },
  description: 'One policy per site: when attack traffic passes the engage threshold the high-load action starts, and it ends after the recovery windows. Pick a site to configure it.',
  back: 'Back to sites', siteLabel: 'Site: {{domain}}', siteIdLabel: 'Site ID: {{id}}', noCrawler: 'No trusted crawler',
  stateTags: { pending: 'Delivering', active: 'Active', failed: 'Delivery failed', inherited: 'Inherited' },
  disabled: "This site's action policy is disabled; nodes do not apply it (revisions and the stable version are kept; switch it on again on the site's Auto defense tab)",
  source: { site: 'Custom for this site', tenant_default: 'Inherits the default', system_default: 'Inherits the system default' },
  inherit: 'Restore the default',
  inheritedTenant: 'This site uses the default settings',
  inheritedSystem: 'This site uses the built-in system default, which is not delivered to nodes',
  inheritedHint: 'The fields below are the default in force. Saving changes gives this site its own settings; restore the default at any time.',
  defaults: {
    title: 'Default settings', edit: 'Edit default settings', collapse: 'Collapse', save: 'Save default settings', readOnly: 'This account lacks firewall management permission; view only.',
    hintSystem: 'No default saved yet: sites without their own settings ({{count}}) use the built-in system default, which is not delivered. Saving applies it to them at once.',
    hintSaved: 'Sites without their own settings ({{count}}) use these settings; sites with their own are unaffected and can restore the default on their page.',
    saved: 'Default settings saved; {{count}} inheriting sites are delivered the new settings', saveFailed: 'Failed to save the default settings', loadFailed: 'Failed to load the default settings',
    tenant: 'Default settings of user', tenantPlaceholder: 'Pick a user to view and edit their default settings', tenantEmpty: 'No matching users',
  },
  sections: { trigger: 'Actions and thresholds', networks: 'Networks' },
  help: {
    normalAction: 'How blocked requests are handled below the threshold.', escalatedAction: 'Only on nodes the tenant owns: the node kernel (nftables) blocks the networks below.',
    engageThreshold: 'Blocked requests per second at which the high-load action starts.', recoverThreshold: 'A window at or below this many blocked requests per second counts toward recovery; must be below the engage threshold.',
    recoveryWindows: 'Consecutive recovery windows needed to end the high-load action (1–60).',
    blockNetworks: 'Networks the kernel blocks under high load, one CIDR per line; networks overlapping trusted proxies or crawlers are not blocked.',
    trustedProxies: 'Proxy networks in front of the site, one CIDR per line; their requests are attributed by X-Forwarded-For.',
    trustedCrawler: 'Allowed when both the network and the User-Agent prefix match, regardless of thresholds.', returnPage: 'Status and body returned when the normal action is "Return controlled page".',
  },
  picker: {
    search: 'Search sites by domain', empty: 'No sites', loadFailed: 'Failed to load sites', retry: 'Retry', openFailed: 'Could not read the site owner; try again later',
    configure: 'Configure policy', configureSite: 'Configure the action policy of {{domain}}',
    columns: { domain: 'Site', owner: 'Owner', action: 'Action' },
  },
  notices: { saved: 'Action policy candidate saved', recovered: 'Recovery candidate created from the LKG', inherited: 'The default settings apply again' },
  errors: { save: 'Failed to save action policy', recover: 'Failed to restore the LKG', inherit: 'Failed to restore the default', forbidden: 'Firewall action access denied' },
} as const

function pseudo(value: unknown): unknown {
  return typeof value === 'string' ? `［${[...value].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const pseudoFirewallAction = pseudo(zhCNFirewallAction)

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCNFirewallAction, 'en-US': enUSFirewallAction, 'qps-ploc': pseudoFirewallAction, 'qps-Ploc': pseudoFirewallAction })) {
  i18n.addResourceBundle(locale, 'firewallAction', messages, true, true)
}
