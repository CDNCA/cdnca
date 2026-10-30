import {
  getBreadcrumbLabels,
  getDeclaredPaths,
  isImplementedPath,
} from '../routes/navigation'

describe('cache operations navigation', () => {
  it('exposes the real workflow only to cache readers', () => {
    expect(getDeclaredPaths()).toContain('/site/cache-clean')
    for (const role of ['admin', 'user'] as const) {
      expect(isImplementedPath(role, '/site/cache-clean', ['sites.read'])).toBe(true)
      expect(isImplementedPath(role, '/site/cache-clean', ['platform.admin'])).toBe(true)
      expect(isImplementedPath(role, '/site/cache-clean', [])).toBe(false)
    }
    expect(getBreadcrumbLabels('user', '/site/cache-clean')).toEqual(['首页', '网站管理', '刷新预热'])
    expect(getBreadcrumbLabels('user', '/site/cache-clean/history')).toEqual(['首页', '网站管理', '刷新预热'])
  })
})
