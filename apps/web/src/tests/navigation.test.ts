import {
  getBreadcrumbLabels,
  getDeclaredPaths,
  getNavigation,
  getNavigationSelectionKey,
  getParentNavigationKey,
  isImplementedPath,
} from '../routes/navigation'
import {
  adminObservedUserBlockedPaths,
  firewallReadPermission,
  jobsReadPermission,
} from '../routes/routePolicy'
import type { RuntimeFeature } from '../api/runtimeFeatures'

// fp-role ID-06：节点列表要 nodes.read 后，空权限的管理员看不到节点组；角色分组用 platform.admin 比较。
function labels(role: 'admin' | 'user') {
  return getNavigation(role, undefined, role === 'admin' ? ['platform.admin'] : []).map((item) => item.label)
}

function navigationStructureSnapshot(role: 'admin' | 'user') {
  return getNavigation(role).map((item) => ({
    key: item.key,
    children: item.children?.map((child) => child.key) ?? [],
  }))
}

describe('role navigation', () => {
  it('keeps administrator-only and user-only groups separate', () => {
    expect(labels('admin')).toContain('节点管理')
    expect(labels('admin')).not.toContain('财务管理')
    expect(labels('admin')).not.toContain('套餐管理')
    expect(labels('admin')).not.toContain('账户中心')

    expect(labels('user')).toContain('账户中心')
    expect(labels('user')).not.toContain('节点管理')
    expect(labels('user')).not.toContain('财务管理')
  })

  it('keeps the complete role menu structures deterministic', () => {
    expect(navigationStructureSnapshot('admin')).toEqual([
      { key: '/admin-home', children: [] },
      { key: 'monitor', children: [
        '/monitor/site/realtime',
        '/monitor/site/analysis',
        '/monitor/site/block-log',
        '/monitor/site/block-event-log',
        '/monitor/site/cc-coordination',
        '/monitor/site/access-log',
        '/monitor/site/attack-log',
        '/monitor/stream/realtime',
        '/monitor/stream/access-log',
        '/monitor/stream/live-connections',
      ] },
      { key: 'node', children: [
        '/node/list',
        '/node/line-group',
        '/node/l2-config',
        '/node/dns',
        '/node/monitor-setting',
        '/node/ddos-protection',
        '/node/realtime',
      ] },
      { key: 'market', children: ['/sys/node-market', '/sys/plugin-store'] },
      { key: 'site', children: [
        '/site/list',
        '/site/cert',
        '/site/cache-clean',
        '/site/cc-rule',
        '/site/waf-rule',
        '/site/rule-packs',
        '/site/security-bans',
        '/site/ip-lists',
      ] },
      { key: 'stream', children: ['/stream/list'] },
      { key: 'config', children: [
        '/config/waf',
        '/config/firewall-action',
        '/config/nginx',
        '/config/res',
        '/config/default',
        '/config/error',
        '/config/access-log',
      ] },
      { key: 'system', children: [
        '/sys/setting',
        '/sys/task',
        '/sys/user',
        '/sys/log-center',
        '/sys/op',
        '/sys/anno',
        '/sys/message',
        '/sys/tickets',
        '/sys/identity-review',
        '/sys/gateways',
        '/sys/approvals',
      ] },
    ])

    expect(navigationStructureSnapshot('user')).toEqual([
      { key: '/home', children: [] },
      { key: 'monitor', children: [
        '/monitor/site/realtime',
        '/monitor/site/analysis',
        '/monitor/site/block-log',
        '/monitor/site/access-log',
        '/monitor/site/attack-log',
        '/monitor/stream/realtime',
        '/monitor/site/block-event-log',
        '/monitor/stream/access-log',
        '/monitor/stream/live-connections',
      ] },
      { key: 'site', children: [
        '/site/list',
        '/site/cert',
        '/site/cache-clean',
        '/site/cc-rule',
        '/site/waf-rule',
        '/site/rule-packs',
        '/site/security-bans',
        '/site/ip-lists',
        '/site/dns-hub',
      ] },
      { key: 'stream', children: ['/stream/list'] },
      { key: 'account', children: [
        '/account/user',
        '/account/log',
        '/account/message',
        '/account/subscribe',
        '/account/api',
        '/account/tickets',
      ] },
    ])

    const adminPaths = JSON.stringify(navigationStructureSnapshot('admin'))
    const userPaths = JSON.stringify(navigationStructureSnapshot('user'))
    expect(userPaths).not.toContain('/admin-home')
    expect(userPaths).not.toContain('/sys/user')
    expect(userPaths).not.toContain('/finance/recharge')
    expect(adminPaths).not.toContain('/home')
    expect(adminPaths).not.toContain('"account"')
  })

  it('matches the observed administrator labels and current static tenant menu', () => {
    const admin = getNavigation('admin')

    expect(admin.find((item) => item.key === 'monitor')?.children?.map((item) => item.label)).toEqual([
      '实时监控',
      '数据分析',
      '拉黑日志',
      '拦截事件明细',
      '跨节点 CC 状态',
      '访问日志',
      'WAF日志',
      '四层实时监控',      '四层访问日志',
      '四层实时连接',
    ])
    expect(admin.find((item) => item.key === 'node')?.children?.map((item) => item.label)).toEqual([
      '节点列表',
      '线路分组',
      'L2配置',
      'DNS配置',
      '监控配置',
      '连接防护',
      '实时监控',
    ])
    expect(admin.find((item) => item.key === 'config')?.children?.map((item) => item.label)).toEqual([
      '防火墙配置',
      '防火墙动作策略',
      'Nginx配置',
      '资源配置',
      '默认配置',
      '错误页面',
      '访问日志字段',
    ])
    expect(admin.find((item) => item.key === 'system')?.children?.map((item) => item.label)).toEqual([
      '系统配置',
      '后台任务',
      '用户列表',
      '日志中心',
      '维护升级',
      '公告管理',
      '消息查询',
      '工单管理',
      '实名审核',
      '网关管理',
      '审批中心',
    ])

    expect(getNavigation('user').map(({ key, label }) => ({ key, label }))).toEqual([
      { key: '/home', label: '服务概览' },
      { key: 'monitor', label: '统计分析' },
      { key: 'site', label: '网站管理' },
      { key: 'stream', label: '四层转发' },
      { key: 'account', label: '账户中心' },
    ])
    expect(getNavigation('user').map((item) => item.icon)).toEqual([
      'overview',
      'analytics',
      'sites',
      'stream',
      'account',
    ])
    expect(getNavigation('user').find((item) => item.key === 'monitor')?.children?.map((item) => item.label)).toEqual([
      '实时监控',
      '数据分析',
      '拉黑日志',
      '访问日志',
      'WAF日志',
      '四层实时监控',
      '拦截事件明细',
      '四层访问日志',
      '四层实时连接',
    ])
    expect(getNavigation('user').find((item) => item.key === 'account')?.children?.map((item) => item.key)).toEqual([
      '/account/user',
      '/account/log',
      '/account/message',
      '/account/subscribe',
      '/account/api',
      '/account/tickets',
    ])
    // 社区版：账户中心不再有余额与消费记录；套餐页面全部删除。
    expect(isImplementedPath('user', '/account/balance', ['billing.account.read'])).toBe(false)
    expect(isImplementedPath('user', '/account/order', ['billing.account.read'])).toBe(false)
    expect(isImplementedPath('user', '/account/message', ['announcements.read'])).toBe(true)
    expect(isImplementedPath('user', '/user-package/traffic', ['package_subscriptions.read'])).toBe(false)
    expect(isImplementedPath('user', '/monitor/stream/analysis', ['sites.read'])).toBe(false)
  })

  it('keeps the observed icon for each tenant top-level section', () => {
    expect(getNavigation('user').map((item) => item.icon)).toEqual([
      'overview', 'analytics', 'sites', 'stream', 'account',
    ])
  })

  it('declares deferred menu routes without implementing fake pages', () => {
    const paths = getDeclaredPaths()
    // `/config` is a real redirect entry point even though the shell renders
    // the five concrete configuration pages as its second-level items.
    expect(paths).toContain('/config')
    expect(paths).toContain('/site/list')
    expect(paths).toContain('/node/list')
    expect(paths).toContain('/account/api')
    expect(paths).not.toContain('/account/api-key')
    expect(paths).toContain('/site/list/:id')
    expect(paths).toContain('/site/:id/edit')
    expect(paths).toContain('/stream/list')
    expect(paths).not.toContain('/monitor/stream/analysis')
    expect(paths).toEqual(expect.arrayContaining([
      '/forget-password',
      '/forgot-password',
      '/reset-password',
    ]))
  })

  it('keeps canonical guarded routes explicit', () => {
    expect(adminObservedUserBlockedPaths).toContain('/node/list')
    expect(adminObservedUserBlockedPaths).not.toContain('/config/waf')
    expect(jobsReadPermission).toBe('jobs.read')
  })

  it('exposes tenant background tasks only with the exact read permission', () => {
    expect(getDeclaredPaths()).toContain('/task')
    expect(isImplementedPath('user', '/task', [jobsReadPermission])).toBe(true)
    expect(isImplementedPath('user', '/task', [])).toBe(false)
    expect(isImplementedPath('user', '/task', ['jobs.manage'])).toBe(false)
    expect(isImplementedPath('admin', '/task', [jobsReadPermission])).toBe(false)
    expect(getParentNavigationKey('user', '/task')).toBe('system')
    expect(getBreadcrumbLabels('user', '/task')).toEqual(['首页', '系统管理', '后台任务'])
  })

  it('keeps node management absent from tenant navigation and available to exact admin readers', () => {
    const readNavigation = getNavigation('user', undefined, ['node_scheduling.read'])
    const platformNavigation = getNavigation('user', undefined, ['platform.admin'])
    const platformReadNavigation = getNavigation('admin', undefined, ['node_scheduling.read'])
    const platformAdminNavigation = getNavigation('admin', undefined, ['platform.admin'])
    const nodeGroup = readNavigation.find((item) => item.key === 'node')

    expect(nodeGroup).toBeUndefined()
    expect(platformNavigation.find((item) => item.key === 'node')).toBeUndefined()
    expect(platformReadNavigation.find((item) => item.key === 'node')?.children).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: '/node/line-group' }),
        expect.objectContaining({ key: '/node/l2-config' }),
      ]),
    )
    expect(platformAdminNavigation.find((item) => item.key === 'node')?.children?.some((item) =>
      ['/node/line-group', '/node/l2-config'].includes(item.key),
    )).toBe(false)
    expect(getNavigation('user', undefined, []).some((item) => item.key === 'node')).toBe(false)
    expect(getNavigation('user', undefined, ['node_scheduling.manage']).some((item) => item.key === 'node')).toBe(false)
    expect(isImplementedPath('user', '/node/line-group', ['node_scheduling.read'])).toBe(false)
    expect(getParentNavigationKey('user', '/node/line-group')).toBeUndefined()
  })

  it('keeps enhancement node routes available without adding them to the reference menu', () => {
    const nodeChildren = getNavigation('admin', undefined, ['nodes.read', 'platform.admin'])
      .find((item) => item.key === 'node')?.children?.map((item) => item.key)

    expect(nodeChildren).not.toContain('/node/isolation')
    expect(nodeChildren).not.toContain('/node/cname-allocations')
    expect(isImplementedPath('admin', '/node/isolation', ['nodes.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/cname-allocations', ['platform.admin'])).toBe(true)
    expect(getBreadcrumbLabels('admin', '/node/isolation')).toEqual(['首页', '节点管理', '节点同步隔离'])
    expect(getBreadcrumbLabels('admin', '/node/cname-allocations')).toEqual(['首页', '节点管理', 'CNAME 分配权威'])
  })

  it('keeps enhancement site routes available without adding them to the reference menu', () => {
    const permissions = [
      'certificates.read',
      'dns.read',
      'edge_publications.read',
      'origin_auth.read',
      'sites.manage',
      'sites.read',
      'url_auth_policies.read',
    ]
    const adminChildren = getNavigation('admin', undefined, permissions)
      .find((item) => item.key === 'site')?.children?.map((item) => item.key)
    const userChildren = getNavigation('user', undefined, permissions)
      .find((item) => item.key === 'site')?.children?.map((item) => item.key)
    const hiddenEnhancements = [
      '/site/publications',
      '/site/protocols',
      '/site/url-auth',
      '/site/cert/orders',
      '/site/cname-allocations',
      '/site/origin-auth/credentials',
      '/site/origin-auth/rules',
      '/site/origin-auth/publications',
    ]

    for (const path of hiddenEnhancements) {
      expect(adminChildren).not.toContain(path)
      expect(userChildren).not.toContain(path)
    }
    expect(isImplementedPath('admin', '/site/publications', ['edge_publications.read'])).toBe(true)
    expect(isImplementedPath('admin', '/site/protocols', ['sites.manage'])).toBe(true)
    expect(isImplementedPath('user', '/site/cert/orders', ['certificates.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/cname-allocations', ['dns.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/origin-auth/credentials', ['origin_auth.read'])).toBe(true)
    expect(getBreadcrumbLabels('admin', '/site/protocols')).toEqual(['首页', '网站管理', '网站协议批量设置'])
    expect(getBreadcrumbLabels('user', '/site/cname-allocations')).toEqual(['首页', '网站管理', 'CNAME 分配权威'])
  })

  it('exposes the global WAF route only to authorized administrators', () => {
    expect(getDeclaredPaths()).toContain('/config/waf')
    expect(isImplementedPath('admin', '/config/waf', [firewallReadPermission])).toBe(true)
    expect(isImplementedPath('admin', '/config/waf', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/config/waf', [])).toBe(false)
    expect(isImplementedPath('admin', '/config/waf', ['firewall.manage'])).toBe(false)
    expect(isImplementedPath('user', '/config/waf', [firewallReadPermission])).toBe(false)
    expect(getParentNavigationKey('admin', '/config/waf')).toBe('config')
    expect(getDeclaredPaths()).toContain('/config/firewall-action')
    expect(isImplementedPath('admin', '/config/firewall-action', [firewallReadPermission])).toBe(true)
    expect(isImplementedPath('admin', '/config/firewall-action', [])).toBe(false)
    expect(isImplementedPath('user', '/config/firewall-action', [firewallReadPermission])).toBe(false)
    expect(getParentNavigationKey('admin', '/config/firewall-action')).toBe('config')
    expect(getBreadcrumbLabels('admin', '/config/waf')).toEqual(['首页', '全局配置', '防火墙配置'])
  })

  it('uses the firewall read contract for administrator menu visibility and fallback', () => {
    const readNavigation = getNavigation('admin', undefined, [firewallReadPermission])
    const manageOnlyNavigation = getNavigation('admin', undefined, ['firewall.manage'])
    const platformNavigation = getNavigation('admin', undefined, ['platform.admin'])

    expect(readNavigation.find((item) => item.key === 'config')?.children?.map((item) => item.key))
      .toContain('/config/waf')
    expect(manageOnlyNavigation.some((item) => item.key === 'config')).toBe(false)
    expect(platformNavigation.find((item) => item.key === 'config')?.children?.map((item) => item.key))
      .toContain('/config/waf')
    expect(getNavigation('user', undefined, [firewallReadPermission, 'platform.admin']).some((item) => item.key === 'config')).toBe(false)
  })

  it('exposes the WAF rule-library in the website menu for both roles', () => {
    const adminChildren = getNavigation('admin', undefined, ['security_policies.read'])
      .find((item) => item.key === 'site')?.children?.map((item) => item.key)
    expect(adminChildren).toContain('/site/waf-rule')
    expect(isImplementedPath('admin', '/site/waf-rule', ['security_policies.read'])).toBe(true)
    expect(isImplementedPath('admin', '/site/waf-rule', [])).toBe(false)
    expect(getParentNavigationKey('admin', '/site/waf-rule')).toBe('site')
    expect(getBreadcrumbLabels('admin', '/site/waf-rule')).toEqual(['首页', '网站管理', 'WAF规则'])

    const userChildren = getNavigation('user', undefined, ['security_policies.read'])
      .find((item) => item.key === 'site')?.children?.map((item) => item.key)
    expect(userChildren).toContain('/site/waf-rule')
    expect(isImplementedPath('user', '/site/waf-rule', ['security_policies.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/waf-rule', [])).toBe(false)
    expect(getDeclaredPaths()).toContain('/site/waf-rule')
    expect(isImplementedPath('admin', '/site/waf-rule', ['platform.admin'])).toBe(true)
  })

  it('matches the observed website-menu labels and order for both roles', () => {
    const expectedAdmin = [
      { key: '/site/list', label: '网站列表' },
      { key: '/site/cert', label: '证书管理' },
      { key: '/site/cache-clean', label: '刷新预热' },
      { key: '/site/cc-rule', label: 'CC规则' },
      { key: '/site/waf-rule', label: 'WAF规则' },
      // PA-11 rule packs: beyond the reference menu (1.0.35 plugin platform).
      { key: '/site/rule-packs', label: '规则包' },
      // Ban list.
      { key: '/site/security-bans', label: '封禁名单' },
      // Named IP lists.
      { key: '/site/ip-lists', label: 'IP 名单' },
    ]

    for (const role of ['admin', 'user'] as const) {
      const siteChildren = getNavigation(role).find((item) => item.key === 'site')?.children
        ?.map(({ key, label }) => ({ key, label }))
      // ADR 0020 §3.4：域名解析只在用户端。
      expect(siteChildren).toEqual(role === 'user' ? [...expectedAdmin, { key: '/site/dns-hub', label: '域名解析' }] : expectedAdmin)
      expect(isImplementedPath(role, '/site/acl')).toBe(true)
    }
    expect(getDeclaredPaths()).toContain('/site/acl')
    expect(getParentNavigationKey('admin', '/site/acl')).toBe('site')
    expect(getBreadcrumbLabels('user', '/site/acl')).toEqual(['首页', '网站管理', 'ACL规则'])
  })

  it('anchors the hidden ACL route to the website list for either role', () => {
    expect(getNavigationSelectionKey('admin', '/site/acl')).toBe('/site/list')
    expect(getNavigationSelectionKey('user', '/site/acl')).toBe('/site/list')
  })

  it('exposes system configuration categories only to administrators with read permission', () => {
    const routes = [
      ['/config/nginx', 'Nginx配置'],
      ['/config/res', '资源配置'],
      ['/config/default', '默认配置'],
    ] as const

    for (const [path, label] of routes) {
      expect(isImplementedPath('admin', path, ['system_configuration.read'])).toBe(true)
      expect(isImplementedPath('admin', path, ['platform.admin'])).toBe(true)
      expect(isImplementedPath('admin', path, [])).toBe(false)
      expect(isImplementedPath('admin', path, ['system_configuration.manage'])).toBe(false)
      expect(isImplementedPath('user', path, ['system_configuration.read'])).toBe(false)
      expect(getParentNavigationKey('admin', path)).toBe('config')
      expect(getBreadcrumbLabels('admin', path)).toEqual(['首页', '全局配置', label])
    }
  })

  it('restores the canonical system-management configuration entry and shell metadata', () => {
    const systemChildren = getNavigation('admin', undefined, ['system_configuration.read'])
      .find((item) => item.key === 'system')?.children

    expect(systemChildren).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: '/sys/setting', label: '系统配置', implemented: true }),
    ]))
    expect(getDeclaredPaths()).toContain('/sys/setting')
    expect(isImplementedPath('admin', '/sys/setting', ['system_configuration.read'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/setting', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/setting', [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/setting', ['system_configuration.manage'])).toBe(false)
    expect(isImplementedPath('user', '/sys/setting', ['system_configuration.read'])).toBe(false)
    expect(getParentNavigationKey('admin', '/sys/setting')).toBe('system')
    expect(getNavigationSelectionKey('admin', '/sys/setting')).toBe('/sys/setting')
    expect(getBreadcrumbLabels('admin', '/sys/setting')).toEqual(['首页', '系统管理', '系统配置'])
  })

  it('exposes canonical error pages behind the dedicated error-page permission', () => {
    expect(isImplementedPath('admin', '/config/error', ['error_pages.read'])).toBe(true)
    expect(isImplementedPath('admin', '/config/error', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/config/error', ['system_configuration.read'])).toBe(false)
    expect(isImplementedPath('admin', '/config/error', ['error_pages.manage'])).toBe(false)
    expect(isImplementedPath('user', '/config/error', ['error_pages.read'])).toBe(false)
    expect(getParentNavigationKey('admin', '/config/error')).toBe('config')
    expect(getBreadcrumbLabels('admin', '/config/error')).toEqual(['首页', '全局配置', '错误页面'])
  })

  it('exposes exactly the seven canonical global-configuration entries', () => {
    expect(getNavigation('admin', undefined, ['system_configuration.read', firewallReadPermission, 'error_pages.read'])
      .find((item) => item.key === 'config')?.children?.map((item) => item.key)).toEqual([
        '/config/waf',
        '/config/firewall-action',
        '/config/nginx',
        '/config/res',
        '/config/default',
        '/config/error',
        '/config/access-log',
      ])
    for (const path of ['/config/system', '/config/cleanup', '/config/user', '/config/mail', '/config/notification', '/config/other']) {
      expect(isImplementedPath('admin', path, ['system_configuration.read']), path).toBe(false)
      expect(getDeclaredPaths(), path).not.toContain(path)
    }
  })

  it('marks the website list as implemented and resolves its shell metadata', () => {
    expect(isImplementedPath('admin', '/site/list')).toBe(true)
    expect(isImplementedPath('user', '/site/list')).toBe(true)
    expect(getParentNavigationKey('admin', '/site/list')).toBe('site')
    expect(getParentNavigationKey('admin', '/site/site-1/edit')).toBe('site')
    expect(getBreadcrumbLabels('user', '/site/list')).toEqual([
      '首页',
      '网站管理',
      '网站列表',
    ])
    expect(getBreadcrumbLabels('admin', '/site/site-1/edit')).toEqual([
      '首页',
      '网站管理',
      '网站列表',
    ])
    expect(getBreadcrumbLabels('user', '/site/url-auth')).toEqual([
      '首页',
      '网站管理',
      'URL鉴权',
    ])
  })

  it('exposes site publications to each audience only with its read permission', () => {
    expect(getDeclaredPaths()).toContain('/site/publications')
    expect(isImplementedPath('admin', '/site/publications', ['edge_publications.read'])).toBe(true)
    expect(isImplementedPath('admin', '/site/publications', ['edge_publications.manage'])).toBe(false)
    expect(isImplementedPath('admin', '/site/publications', [])).toBe(false)
    expect(isImplementedPath('user', '/site/publications', ['sites.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/publications', ['edge_publications.read'])).toBe(false)
    expect(isImplementedPath('user', '/site/publications', [])).toBe(false)
    expect(getParentNavigationKey('admin', '/site/publications')).toBe('site')
    expect(getBreadcrumbLabels('user', '/site/publications')).toEqual([
      '首页', '网站管理', '配置发布',
    ])
  })

  it('shows URL authentication navigation only with read permission', () => {
    for (const role of ['admin', 'user'] as const) {
      expect(isImplementedPath(role, '/site/url-auth', ['url_auth_policies.read'])).toBe(true)
      expect(isImplementedPath(role, '/site/url-auth', [])).toBe(false)
      expect(isImplementedPath(role, '/site/url-auth', ['url_auth_policies.manage'])).toBe(false)
    }
    expect(getDeclaredPaths()).toContain('/site/url-auth')
    expect(getParentNavigationKey('user', '/site/url-auth')).toBe('site')
    expect(getBreadcrumbLabels('user', '/site/url-auth')).toEqual(['首页', '网站管理', 'URL鉴权'])
  })

  it('marks role-specific identity routes as implemented', () => {
    expect(isImplementedPath('admin', '/sys/user')).toBe(true)
    expect(isImplementedPath('user', '/sys/user')).toBe(false)
    expect(isImplementedPath('user', '/account/user')).toBe(true)
    // fp-role ID-03：管理员自己的资料是直达页（账号菜单/概览进入），需要 identity.self.read，不认 platform.admin 兜底。
    expect(isImplementedPath('admin', '/account/user')).toBe(true)
    expect(isImplementedPath('admin', '/account/user', ['identity.self.read'])).toBe(true)
    expect(isImplementedPath('admin', '/account/user', ['platform.admin'])).toBe(false)
    expect(getBreadcrumbLabels('admin', '/account/user')).toEqual(['个人资料'])
    expect(getBreadcrumbLabels('admin', '/sys/user')).toEqual(['首页', '系统管理', '用户列表'])
    expect(getBreadcrumbLabels('user', '/account/user')).toEqual(['首页', '账户中心', '个人资料'])
  })

  // fp-role ID-06：菜单、路由与页面同一口径（概览要 platform.admin、节点列表要 nodes.read、用户列表要
  // identity.users.manage 或 platform.admin、个人资料要 identity.self.read 且不认 platform.admin 兜底）。
  it('gates the overview, node list, user list and profile entries like their pages', () => {
    const adminKeys = (permissions: string[]) => getNavigation('admin', undefined, permissions)
      .flatMap((item) => [item.key, ...(item.children?.map((child) => child.key) ?? [])])
    expect(adminKeys(['nodes.read'])).toEqual(expect.arrayContaining(['/node/list']))
    expect(adminKeys(['nodes.read'])).not.toEqual(expect.arrayContaining(['/admin-home']))
    expect(adminKeys(['nodes.read'])).not.toEqual(expect.arrayContaining(['/sys/user']))
    expect(adminKeys(['identity.users.manage'])).toEqual(expect.arrayContaining(['/sys/user']))
    expect(adminKeys(['identity.users.manage'])).not.toEqual(expect.arrayContaining(['/node/list']))
    expect(adminKeys(['platform.admin'])).toEqual(expect.arrayContaining(['/admin-home', '/node/list', '/sys/user']))
    const userKeys = (permissions: string[]) => getNavigation('user', undefined, permissions)
      .find((item) => item.key === 'account')?.children?.map((child) => child.key) ?? []
    expect(userKeys(['identity.self.read'])).toContain('/account/user')
    expect(userKeys(['billing.account.read'])).not.toContain('/account/user')
  })

  it('marks the four-layer forwarding list as implemented for both roles', () => {
    expect(isImplementedPath('admin', '/stream/list')).toBe(true)
    expect(isImplementedPath('user', '/stream/list')).toBe(true)
    expect(getParentNavigationKey('admin', '/stream/list')).toBe('stream')
    expect(getBreadcrumbLabels('user', '/stream/list')).toEqual(['首页', '四层转发', '转发列表'])
  })

  // 社区版：计费、套餐、财务、代理商与官方主题页面全部删除，旧地址不再是已实现页面。
  it('declares no billing, package, finance, reseller or theme route', () => {
    const removed = [
      '/finance/recharge', '/finance/billing-admin', '/finance/order', '/finance/recharge-count', '/finance/recharge-orders',
      '/finance/payment-channels', '/package/basic', '/package/sold', '/package/upgrade', '/package/traffic', '/package/marketing',
      '/package/monitor', '/package/traffic/usage/:id', '/user-package/my', '/user-package/buy', '/user-package/traffic',
      '/user-package/usage', '/user-package/monitor', '/user-package/grants', '/user-package/traffic/usage/:id',
      '/account/balance', '/account/order', '/reseller/packages', '/reseller/customers', '/reseller/orders', '/reseller/ledger',
      '/reseller/tickets', '/reseller/billing-bridge', '/sys/billing-bridge', '/sys/tcp-billing', '/sys/themes', '/sys/site-content',
      '/sso/bridge',
    ]
    const declared = getDeclaredPaths()
    for (const path of removed) {
      expect(declared, path).not.toContain(path)
      for (const role of ['admin', 'user'] as const) expect(isImplementedPath(role, path, ['platform.admin']), `${role} ${path}`).toBe(false)
    }
  })

  it('exposes Batch I routes only to their exact audiences and readers', () => {
    expect(isImplementedPath('admin', '/node/realtime', ['nodes.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/realtime', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/node/realtime', ['nodes.manage'])).toBe(false)
    expect(isImplementedPath('user', '/node/realtime', ['nodes.read'])).toBe(false)
    expect(getBreadcrumbLabels('admin', '/node/realtime')).toEqual([
      '首页', '节点管理', '实时监控',
    ])

    expect(isImplementedPath('user', '/account/verification', ['identity_verification.self.manage'])).toBe(true)
    expect(isImplementedPath('user', '/account/verification', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('user', '/account/verification', [])).toBe(false)
    expect(isImplementedPath('admin', '/account/verification', ['identity_verification.self.manage'])).toBe(false)
    expect(getBreadcrumbLabels('user', '/account/verification')).toEqual([
      '首页', '账户中心', '实名认证',
    ])
  })

  it('exposes the tenant identity review workflow only with both reviewer permissions', () => {
    const path = '/sys/identity-verification'
    const casePath = '/sys/identity-verification/:caseId'
    const decisionPath = '/sys/identity-verification/:caseId/decision'
    const permissions = ['identity_verification.read', 'identity_verification.review']

    expect(getDeclaredPaths()).toEqual(expect.arrayContaining([path, casePath, decisionPath]))
    expect(isImplementedPath('user', path, permissions)).toBe(true)
    expect(isImplementedPath('user', path, ['identity_verification.read'])).toBe(false)
    expect(isImplementedPath('user', path, ['identity_verification.review'])).toBe(false)
    expect(isImplementedPath('user', path, ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', path, permissions)).toBe(false)
    expect(getNavigation('user', undefined, permissions)
      .find((item) => item.key === 'system')).toBeUndefined()
    expect(getParentNavigationKey('user', path)).toBe('system')
    expect(getParentNavigationKey('user', '/sys/identity-verification/case-id')).toBe('system')
    expect(getParentNavigationKey('user', '/sys/identity-verification/case-id/decision')).toBe('system')
    expect(getBreadcrumbLabels('user', path)).toEqual(['首页', '系统管理', '实名认证审核'])
    expect(getBreadcrumbLabels('user', '/sys/identity-verification/case-id')).toEqual([
      '首页', '系统管理', '实名认证审核',
    ])
    expect(getBreadcrumbLabels('user', '/sys/identity-verification/case-id/decision')).toEqual([
      '首页', '系统管理', '实名认证审核',
    ])
  })

  it('marks only the administrator node inventory as implemented', () => {
    expect(isImplementedPath('admin', '/node/list')).toBe(true)
    expect(isImplementedPath('user', '/node/list')).toBe(false)
    expect(getParentNavigationKey('admin', '/node/list/node-1')).toBe('node')
    expect(getBreadcrumbLabels('admin', '/node/list/node-1')).toEqual(['首页', '节点管理', '节点列表'])
    expect(getParentNavigationKey('admin', '/node/list')).toBe('node')
    expect(getBreadcrumbLabels('admin', '/node/list')).toEqual(['首页', '节点管理', '节点列表'])
  })

  it('keeps hidden detail routes attached to their observed parent menus', () => {
    expect(getParentNavigationKey('admin', '/node/l2-config/node/node-1')).toBe('node')
    expect(getBreadcrumbLabels('admin', '/node/l2-config/node/node-1')).toEqual(['首页', '节点管理', 'L2配置'])
    expect(getParentNavigationKey('user', '/site/cert/orders')).toBe('site')
    expect(getBreadcrumbLabels('user', '/site/cert/orders')).toEqual([
      '首页', '网站管理', '证书管理', '证书订单与续期状态',
    ])
    expect(getParentNavigationKey('user', '/monitor/site/analysis/ja4-blocks')).toBe('monitor')
    expect(getBreadcrumbLabels('user', '/monitor/site/analysis/ja4-blocks')).toEqual(['首页', '统计分析', '数据分析'])
  })

  it('labels line resolution without changing the selected line-group menu', () => {
    const path = '/node/line-group/line/line-1'
    expect(getBreadcrumbLabels('admin', path)).toEqual(['首页', '节点管理', '设置解析'])
    expect(getBreadcrumbLabels('admin', path, (key) => key)).toEqual([
      'navigation:home', 'navigation:nodes', 'nodeL2Topology:line.title',
    ])
    expect(getBreadcrumbLabels('admin', '/node/line-group')).toEqual(['首页', '节点管理', '线路分组'])
    expect(getNavigationSelectionKey('admin', path)).toBe('/node/line-group')
    expect(getParentNavigationKey('admin', path)).toBe('node')
  })

  it('keeps the visible source menu selected on detail and workflow routes', () => {
    expect(getNavigationSelectionKey('admin', '/site/list/site-1')).toBe('/site/list')
    expect(getNavigationSelectionKey('admin', '/site/site-1/edit')).toBe('/site/list')
    expect(getNavigationSelectionKey('admin', '/site/site-1/dns-reconcile')).toBe('/site/list')
    expect(getNavigationSelectionKey('admin', '/node/list/node-1')).toBe('/node/list')
    expect(getNavigationSelectionKey('admin', '/node/l2-config/node/node-1')).toBe('/node/l2-config')
    expect(getNavigationSelectionKey('admin', '/node/line-group/line/line-1')).toBe('/node/line-group')
    expect(getNavigationSelectionKey('admin', '/stream/list/stream-1')).toBe('/stream/list')
    expect(getNavigationSelectionKey('user', '/site/cert/orders')).toBe('/site/cert')
    expect(getNavigationSelectionKey('user', '/site/cache-clean/history')).toBe('/site/cache-clean')
    expect(getNavigationSelectionKey('user', '/monitor/site/analysis/ja4-blocks')).toBe('/monitor/site/analysis')
    expect(getNavigationSelectionKey('user', '/account/api')).toBe('/account/api')
  })

  it('keeps tenant-only custom roles out of the platform console', () => {
    expect(isImplementedPath('admin', '/sys/custom-roles', ['identity.roles.manage', 'platform.admin'])).toBe(false)
    expect(getDeclaredPaths()).not.toContain('/sys/custom-roles')
    expect(isImplementedPath('user', '/account/custom-roles', ['identity.roles.manage'])).toBe(false)
  })

  it('anchors hidden capability routes to a visible baseline item', () => {
    const adminBaselines: Array<[string, string]> = [
      ['/site/publications', '/site/list'],
      ['/site/protocols', '/site/list'],
      ['/site/url-auth', '/site/list'],
      ['/node/cname-allocations', '/node/list'],
      ['/node/isolation', '/node/list'],
      ['/sys/plugin-webhooks', '/sys/setting'],
    ]
    for (const [path, expected] of adminBaselines) {
      expect(getNavigationSelectionKey('admin', path), path).toBe(expected)
    }

    const userBaselines: Array<[string, string]> = [
      ['/site/publications', '/site/list'],
      ['/site/cname-allocations', '/site/list'],
      ['/site/origin-auth/credentials', '/site/list'],
      ['/site/origin-auth/rules', '/site/list'],
      ['/site/origin-auth/publications', '/site/list'],
      ['/site/cert/orders', '/site/cert'],
      ['/site/cache-clean/history', '/site/cache-clean'],
      ['/account/verification', '/account/user'],
    ]
    for (const [path, expected] of userBaselines) {
      expect(getNavigationSelectionKey('user', path), path).toBe(expected)
    }
  })

  it('marks DNS configuration and certificate management as implemented', () => {
    expect(getDeclaredPaths()).toContain('/node/dns')
    expect(isImplementedPath('admin', '/node/dns', ['dns.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/dns', ['dns.read', 'dns.manage'])).toBe(true)
    expect(isImplementedPath('admin', '/node/dns', ['dns.manage'])).toBe(false)
    expect(isImplementedPath('admin', '/node/dns', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', '/node/dns', [])).toBe(false)
    expect(isImplementedPath('user', '/node/dns', ['dns.read'])).toBe(false)
    expect(getNavigation('admin', undefined, ['dns.read'])
      .find((item) => item.key === 'node')?.children)
      .toEqual(expect.arrayContaining([expect.objectContaining({ key: '/node/dns' })]))
    for (const permissions of [[], ['dns.manage'], ['platform.admin']] as const) {
      expect(Boolean(getNavigation('admin', undefined, permissions)
        .find((item) => item.key === 'node')?.children?.some((item) => item.key === '/node/dns')))
        .toBe(false)
    }
    for (const permissions of [['dns.read'], ['dns.manage'], ['dns.read', 'dns.manage']] as const) {
      expect(Boolean(getNavigation('user', undefined, permissions)
        .find((item) => item.key === 'node')?.children?.some((item) => item.key === '/node/dns')))
        .toBe(false)
    }
    expect(getBreadcrumbLabels('admin', '/node/dns')).toEqual(['首页', '节点管理', 'DNS配置'])
    expect(getDeclaredPaths()).toContain('/site/cert')
    expect(isImplementedPath('admin', '/site/cert', ['certificates.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/cert', ['certificates.read'])).toBe(true)
    expect(isImplementedPath('admin', '/site/cert', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('user', '/site/cert', ['certificates.manage'])).toBe(false)
    expect(isImplementedPath('user', '/site/cert', [])).toBe(false)
    expect(getParentNavigationKey('user', '/site/cert')).toBe('site')
    expect(getBreadcrumbLabels('user', '/site/cert')).toEqual(['首页', '网站管理', '证书管理'])
  })

  it('keeps non-baseline account pages out of the tenant account-centre menu', () => {
    const accountChildren = getNavigation('user', undefined, [])
      .find((item) => item.key === 'account')?.children
    expect(accountChildren?.map((item) => item.key)).not.toContain('/account/balance')
    expect(accountChildren?.map((item) => item.key)).not.toContain('/account/message')
  })

  it('exposes analytics logs only to principals with sites.read', () => {
    for (const path of ['/monitor/site/access-log', '/monitor/site/block-log', '/monitor/site/block-event-log']) {
      expect(isImplementedPath('admin', path, ['sites.read'])).toBe(true)
      expect(isImplementedPath('admin', path, ['platform.admin'])).toBe(true)
      expect(isImplementedPath('user', path, ['sites.read'])).toBe(true)
      expect(isImplementedPath('admin', path, [])).toBe(false)
      expect(isImplementedPath('user', path, [])).toBe(false)
      expect(getParentNavigationKey('user', path)).toBe('monitor')
    }
    expect(getBreadcrumbLabels('user', '/monitor/site/access-log')).toEqual(['首页', '统计分析', '访问日志'])
    expect(getBreadcrumbLabels('admin', '/monitor/site/block-log')).toEqual(['首页', '统计分析', '拉黑日志'])
    expect(getBreadcrumbLabels('admin', '/monitor/site/block-event-log')).toEqual(['首页', '统计分析', '拦截事件明细'])
    expect(getBreadcrumbLabels('admin', '/monitor/site/cc-coordination')).toEqual(['首页', '统计分析', '跨节点 CC 状态'])
  })

  // tp-b1: the tenant console follows the reference user menu (AUDIT §3).
  it('moves operator pages out of the tenant console and keeps them for administrators', () => {
    expect(isImplementedPath('user', '/monitor/site/cc-coordination', ['sites.read'])).toBe(false)
    expect(isImplementedPath('admin', '/monitor/site/cc-coordination', ['sites.read'])).toBe(true)
    expect(isImplementedPath('admin', '/monitor/site/cc-coordination', ['platform.admin'])).toBe(true)
    expect(getDeclaredPaths()).toContain('/monitor/site/cc-coordination')
  })

  it('removes the log centre, balance ledger, members, custom roles and theme from the tenant account centre', () => {
    const all = ['identity.self.read', 'billing.account.read', 'identity.roles.manage', 'announcements.read']
    for (const path of ['/account/log-center', '/account/balance-log', '/account/members', '/account/custom-roles', '/account/theme']) {
      expect(isImplementedPath('user', path, all, [], ['custom_rbac']), path).toBe(false)
      expect(getDeclaredPaths(), path).not.toContain(path)
    }
    expect(isImplementedPath('admin', '/sys/log-center', ['platform.admin'])).toBe(true)
    expect(getNavigation('user', undefined, [...all, 'package_subscriptions.read']).find((item) => item.key === 'account')?.children?.map((item) => item.label))
      .toEqual(['个人资料', '日志查询', '消息查询', '消息订阅', 'API密钥', '工单'])
    expect(getNavigation('user', undefined, ['package_subscriptions.read', 'traffic_packages.read']).some((item) => item.key === 'user-package')).toBe(false)
  })

  // menu-orphans: the old /sys/notification page is now the notification tab of /sys/setting.
  it('does not declare the retired notification page', () => {
    expect(getDeclaredPaths()).not.toContain('/sys/notification')
  })

  it('exposes platform operations routes only with their dedicated permissions', () => {
    expect(isImplementedPath('admin', '/node/isolation', ['nodes.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/isolation', [])).toBe(false)
    expect(isImplementedPath('admin', '/node/isolation', ['platform.admin'])).toBe(false)
    expect(getParentNavigationKey('admin', '/node/isolation')).toBe('node')
    expect(getBreadcrumbLabels('admin', '/node/isolation')).toEqual(['首页', '节点管理', '节点同步隔离'])

    expect(isImplementedPath('admin', '/sys/approvals', ['approvals.read'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/approvals', [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/approvals', ['platform.admin'])).toBe(false)
    expect(getParentNavigationKey('admin', '/sys/approvals')).toBe('system')
    expect(getBreadcrumbLabels('admin', '/sys/approvals')).toEqual(['首页', '系统管理', '审批中心'])
    expect(getNavigationSelectionKey('admin', '/sys/approvals')).toBe('/sys/approvals')
  })

  it('exposes the canonical account log only to tenant site readers', () => {
    expect(getDeclaredPaths()).toContain('/account/log')
    expect(isImplementedPath('user', '/account/log', ['identity.self.read'])).toBe(true)
    expect(isImplementedPath('user', '/account/log', [])).toBe(false)
    expect(isImplementedPath('user', '/account/log', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', '/account/log', ['sites.read'])).toBe(false)
    expect(getNavigation('user', undefined, ['identity.self.read'])
      .find((item) => item.key === 'account')?.children)
      .toEqual(expect.arrayContaining([expect.objectContaining({ key: '/account/log' })]))
    expect(getParentNavigationKey('user', '/account/log')).toBe('account')
    expect(getBreadcrumbLabels('user', '/account/log')).toEqual(['首页', '账户中心', '日志查询'])
  })

  it('exposes administrator announcements only to matching permissions', () => {
    expect(isImplementedPath('admin', '/sys/anno', [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/anno', ['announcements.manage'])).toBe(true)
    expect(isImplementedPath('user', '/sys/anno', [])).toBe(false)
    expect(isImplementedPath('user', '/sys/anno', ['announcements.manage'])).toBe(false)
    expect(getParentNavigationKey('user', '/sys/anno')).toBeUndefined()
    expect(getBreadcrumbLabels('user', '/sys/anno')).toEqual(['首页'])
    expect(isImplementedPath('user', '/account/message', [])).toBe(false)
    expect(isImplementedPath('user', '/account/message', ['announcements.read'])).toBe(true)
  })

  it('does not declare the unobserved four-layer stream analysis route', () => {
    const path = '/monitor/stream/analysis'

    expect(isImplementedPath('user', path, ['sites.read'])).toBe(false)
    expect(isImplementedPath('user', path, ['platform.admin'])).toBe(false)
    expect(isImplementedPath('user', path, ['platform.admin', 'sites.read'])).toBe(false)
  })
})

describe('W8 tenant /log dead entry', () => {
  it('does not declare /log for tenants (App.tsx guards it with platform.admin); tenants use /account/log', () => {
    expect(isImplementedPath('user', '/log', ['identity.self.read'])).toBe(false)
    expect(isImplementedPath('user', '/account/log', ['identity.self.read'])).toBe(true)
    expect(isImplementedPath('admin', '/log', ['platform.admin'])).toBe(true)
  })
})

// C24：市场单列主菜单组，紧跟节点运维；任一市场权限可见，与 MarketRoute 同规则。
describe('market navigation group', () => {
  const marketChildren = (permissions: string[], runtimes: RuntimeFeature[] = ['market']) =>
    getNavigation('admin', undefined, permissions, [], runtimes)
      .find((item) => item.key === 'market')?.children?.map((child) => child.key)

  it('sits right after node operations', () => {
    const keys = getNavigation('admin', undefined, ['platform.admin'], [], ['market']).map((item) => item.key)
    expect(keys.slice(keys.indexOf('node'), keys.indexOf('node') + 2)).toEqual(['node', 'market'])
    expect(getNavigation('admin').find((item) => item.key === 'market')?.label).toBe('市场')
  })

  it('shows both markets for any marketplace code or the legacy gate', () => {
    for (const code of ['marketplace.browse', 'marketplace.purchase', 'marketplace.sell', 'sites.manage', 'platform.admin']) {
      expect(marketChildren([code]), code).toEqual(['/sys/node-market', '/sys/plugin-store'])
      expect(isImplementedPath('admin', '/sys/node-market', [code], [], ['market']), code).toBe(true)
    }
    expect(marketChildren(['sites.read'])).toBeUndefined()
    expect(isImplementedPath('admin', '/sys/plugin-store', ['sites.read'], [], ['market'])).toBe(false)
  })

  it('hides the group while the market runtime is off and never shows it to tenants', () => {
    expect(marketChildren(['platform.admin'], [])).toBeUndefined()
    expect(getNavigation('user', undefined, ['marketplace.browse'], [], ['market']).some((item) => item.key === 'market')).toBe(false)
  })

  it('selects and breadcrumbs the market entries under the market group', () => {
    expect(getNavigationSelectionKey('admin', '/sys/node-market')).toBe('/sys/node-market')
    expect(getParentNavigationKey('admin', '/sys/plugin-store')).toBe('market')
    expect(getBreadcrumbLabels('admin', '/sys/plugin-store')).toEqual(['首页', '市场', '插件商店'])
  })
})
