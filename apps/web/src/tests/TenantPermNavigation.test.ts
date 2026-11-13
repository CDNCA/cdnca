import { isImplementedPath } from '../routes/navigation'

// 租户侧栏项与路由守卫、后端要求的权限码一致；缺权限码的租户不显示入口。
describe('tenant navigation permission codes', () => {
  it.each([
    ['/stream/list', 'streams.read'],
    ['/account/subscribe', 'announcements.read'],
    ['/account/api', 'api_keys.self.manage'],
    ['/config/firewall-action', 'firewall.read'],
  ])('%s needs %s for a tenant', (path, permission) => {
    expect(isImplementedPath('user', path, [permission])).toBe(true)
    expect(isImplementedPath('user', path, ['sites.read'])).toBe(false)
  })

  it('does not let platform.admin stand in for the tenant firewall entry', () => {
    expect(isImplementedPath('user', '/config/firewall-action', ['platform.admin'])).toBe(false)
  })
})
