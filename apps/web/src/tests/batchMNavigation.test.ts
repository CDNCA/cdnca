import {
  getBreadcrumbLabels,
  getDeclaredPaths,
  getParentNavigationKey,
  isImplementedPath,
} from '../routes/navigation'

describe('Batch M navigation', () => {
  it('exposes error pages only to platform readers', () => {
    expect(getDeclaredPaths()).toContain('/config/error')
    expect(isImplementedPath('admin', '/config/error', ['error_pages.read'])).toBe(true)
    expect(isImplementedPath('admin', '/config/error', [])).toBe(false)
    expect(isImplementedPath('user', '/config/error', ['system_configuration.read'])).toBe(false)
    expect(getParentNavigationKey('admin', '/config/error')).toBe('config')
    expect(getBreadcrumbLabels('admin', '/config/error')).toEqual(['首页', '全局配置', '错误页面'])
  })

  it('keeps DNS reconciliation detail out of the primary navigation', () => {
    expect(getDeclaredPaths()).toContain('/site/:id/dns-reconcile')
    expect(isImplementedPath('user', '/site/:id/dns-reconcile', ['dns.read'])).toBe(false)
  })
})
