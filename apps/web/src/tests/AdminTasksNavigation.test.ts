import { getBreadcrumbLabels, getNavigation, isImplementedPath } from '../routes/navigation'

describe('administrator background task navigation', () => {
  it('keeps the administrator task route implemented without tenant access', () => {
    expect(isImplementedPath('admin', '/sys/task')).toBe(true)
    expect(isImplementedPath('user', '/sys/task')).toBe(false)
    expect(getBreadcrumbLabels('admin', '/sys/task')).toEqual(['首页', '系统管理', '后台任务'])
    expect(getNavigation('admin').flatMap((item) => item.children ?? []).find(
      (item) => item.key === '/sys/task',
    )).toMatchObject({ label: '后台任务', implemented: true })
  })

  it('declares the tenant task route only with jobs.read', () => {
    expect(isImplementedPath('user', '/task', ['jobs.read'])).toBe(true)
    expect(isImplementedPath('user', '/task', [])).toBe(false)
    expect(isImplementedPath('user', '/task', ['jobs.manage'])).toBe(false)
    expect(isImplementedPath('admin', '/task', ['jobs.read'])).toBe(false)
    expect(getBreadcrumbLabels('user', '/task')).toEqual(['首页', '系统管理', '后台任务'])
    expect(getNavigation('user', undefined, ['jobs.read']).flatMap((item) => item.children ?? []).find(
      (item) => item.key === '/task',
    )).toBeUndefined()
  })
})
