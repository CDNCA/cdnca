import {
  getBreadcrumbLabels,
  getDeclaredPaths,
  getNavigation,
  getParentNavigationKey,
  isImplementedPath,
} from '../routes/navigation'

describe('Batch K/L navigation', () => {
  it('exposes CNAME authority only to its exact audience permission', () => {
    expect(getDeclaredPaths()).toEqual(expect.arrayContaining([
      '/node/cname-allocations', '/site/cname-allocations',
    ]))
    expect(isImplementedPath('admin', '/node/cname-allocations', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/node/cname-allocations', ['dns.read'])).toBe(false)
    expect(isImplementedPath('user', '/site/cname-allocations', ['dns.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/cname-allocations', ['platform.admin'])).toBe(false)
    expect(isImplementedPath('admin', '/site/cname-allocations', ['dns.read'])).toBe(false)
    expect(getParentNavigationKey('admin', '/node/cname-allocations')).toBe('node')
    expect(getParentNavigationKey('user', '/site/cname-allocations')).toBe('site')
    expect(getBreadcrumbLabels('admin', '/node/cname-allocations')).toEqual([
      '首页', '节点管理', 'CNAME 分配权威',
    ])
    expect(getBreadcrumbLabels('user', '/site/cname-allocations')).toEqual([
      '首页', '网站管理', 'CNAME 分配权威',
    ])
  })

  it('exposes all origin authentication pages only to tenant readers', () => {
    const paths = [
      ['/site/origin-auth/credentials', '源站鉴权凭据'],
      ['/site/origin-auth/rules', '源站鉴权规则'],
      ['/site/origin-auth/publications', '回源鉴权发布'],
    ] as const
    expect(getDeclaredPaths()).toEqual(expect.arrayContaining(paths.map(([path]) => path)))

    for (const [path, label] of paths) {
      expect(isImplementedPath('user', path, ['origin_auth.read'])).toBe(true)
      expect(isImplementedPath('user', path, ['origin_auth.manage'])).toBe(false)
      expect(isImplementedPath('user', path, ['platform.admin'])).toBe(false)
      expect(isImplementedPath('admin', path, ['origin_auth.read'])).toBe(false)
      expect(getParentNavigationKey('user', path)).toBe('site')
      expect(getBreadcrumbLabels('user', path)).toEqual(['首页', '网站管理', label])
    }

    const siteChildren = getNavigation('user', undefined, ['origin_auth.read'])
      .find((item) => item.key === 'site')?.children?.map((item) => item.key)
    // 只有 origin_auth.read 时整个「网站管理」分组都不显示（需要 sites.read），这些页面同样不在菜单里。
    for (const [path] of paths) expect(siteChildren ?? []).not.toContain(path)
  })
})
