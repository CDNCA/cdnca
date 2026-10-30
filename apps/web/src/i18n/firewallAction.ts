import i18n from './index'

export const zhCNFirewallAction = {
  title: '防火墙动作策略', loadFailed: '防火墙动作策略加载失败', empty: '尚未配置动作策略', save: '保存策略', recover: '恢复最近稳定版本',
  normalAction: '常态动作', escalatedAction: '高负载动作', engageThreshold: '触发阈值', recoverThreshold: '恢复阈值',
  recoveryWindows: '连续恢复窗口', blockNetworks: '内核拦截网段', trustedProxies: '可信代理网段', trustedCrawler: '可信爬虫',
  crawlerName: '名称', crawlerNetworks: '可信网段', crawlerPrefixes: 'User-Agent 前缀', addCrawler: '添加可信爬虫', removeCrawler: '删除可信爬虫', returnPage: '受控返回页', statusCode: '状态码',
  contentType: '内容类型', body: '响应正文', currentActive: '当前生效修订：{{revision}}', currentLKG: '最近稳定修订：{{revision}}',
  actions: { disconnect: '断开连接', return_page: '返回受控页面', nftables: 'nftables 自动拦截' },
  states: { pending: '候选策略等待下发，当前稳定版本继续生效', active: '动作策略已生效', failed: '候选策略下发失败，当前稳定版本继续生效' },
  target: { scope: '目标租户作用域', site: '目标站点 ID', apply: '加载策略', invalid: '请输入规范的小写 UUID' },
  notices: { saved: '动作策略候选已保存', recovered: '已从最近稳定版本创建恢复候选' },
  errors: { save: '动作策略保存失败', recover: '稳定版本恢复失败', forbidden: '当前账号无权查看防火墙动作策略' },
} as const

export const enUSFirewallAction = {
  title: 'Firewall action policy', loadFailed: 'Failed to load firewall action policy', empty: 'No action policy configured', save: 'Save policy', recover: 'Restore last known good',
  normalAction: 'Normal action', escalatedAction: 'High-load action', engageThreshold: 'Engage threshold', recoverThreshold: 'Recover threshold',
  recoveryWindows: 'Consecutive recovery windows', blockNetworks: 'Kernel block networks', trustedProxies: 'Trusted proxy networks', trustedCrawler: 'Trusted crawler',
  crawlerName: 'Name', crawlerNetworks: 'Trusted networks', crawlerPrefixes: 'User-Agent prefixes', addCrawler: 'Add trusted crawler', removeCrawler: 'Remove trusted crawler', returnPage: 'Controlled response', statusCode: 'Status code',
  contentType: 'Content type', body: 'Response body', currentActive: 'Active revision: {{revision}}', currentLKG: 'Last known good revision: {{revision}}',
  actions: { disconnect: 'Disconnect', return_page: 'Return controlled page', nftables: 'Automatic nftables block' },
  states: { pending: 'Candidate pending; the stable revision remains active', active: 'Action policy is active', failed: 'Candidate failed; the stable revision remains active' },
  target: { scope: 'Target tenant scope', site: 'Target site ID', apply: 'Load policy', invalid: 'Enter a canonical lowercase UUID' },
  notices: { saved: 'Action policy candidate saved', recovered: 'Recovery candidate created from the LKG' },
  errors: { save: 'Failed to save action policy', recover: 'Failed to restore the LKG', forbidden: 'Firewall action access denied' },
} as const

function pseudo(value: unknown): unknown {
  return typeof value === 'string' ? `［${[...value].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const pseudoFirewallAction = pseudo(zhCNFirewallAction)

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCNFirewallAction, 'en-US': enUSFirewallAction, 'qps-ploc': pseudoFirewallAction, 'qps-Ploc': pseudoFirewallAction })) {
  i18n.addResourceBundle(locale, 'firewallAction', messages, true, true)
}
