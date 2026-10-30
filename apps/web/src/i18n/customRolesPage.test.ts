import i18n from './index'
import { customRolesPageMessages } from './customRolesPage'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('customRolesPageMessages', () => {
  it('registers a complete zh-CN, en-US, and expanded pseudo-locale namespace', () => {
    const required = [
      'title', 'sections.permissions', 'sections.roles', 'sections.grants',
      'actions.create', 'actions.rename', 'actions.publish', 'actions.deactivate',
      'actions.assign', 'actions.revoke', 'actions.retry', 'actions.exactRetry', 'actions.abandon',
      'fields.name', 'fields.permissions', 'fields.stepUpProof', 'fields.subjectUserId',
      'fields.revision', 'fields.includeDeactivated', 'data.loadingRoles', 'data.emptyRoles', 'data.emptyGrants',
      'errors.forbidden', 'errors.load', 'errors.revisionConflict', 'errors.stepUpRequired',
      'errors.permissionNotDelegable', 'errors.serviceUnavailable', 'dialogs.unknownTitle',
      'pagination.roles', 'pagination.grants',
    ]
    const zh = flatten(customRolesPageMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(customRolesPageMessages[locale])
      expect(i18n.hasResourceBundle(locale, 'customRolesPage')).toBe(true)
      expect(Object.keys(messages).sort()).toEqual(Object.keys(zh).sort())
      for (const key of required) expect(messages[key], `${locale}:${key}`).toEqual(expect.any(String))
    }
    expect(zh.title).toBe('自定义角色')
    expect(zh['errors.revisionConflict']).toBe('角色版本已变化，请刷新后重试')
    expect(zh['errors.stepUpRequired']).toBe('此操作需要有效且未使用的二次认证证明')
    expect(zh['errors.permissionNotDelegable']).toBe('所选权限不能委派给租户自定义角色')
    expect(flatten(customRolesPageMessages['qps-ploc']).title!.length).toBeGreaterThan(zh.title.length)
    expect(customRolesPageMessages['qps-Ploc']).toEqual(customRolesPageMessages['qps-ploc'])
  })

  it('never exposes raw server wording or credential labels', () => {
    for (const locale of Object.values(customRolesPageMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|database topology|bearer token|session token|private authorization detail/i)
      }
    }
  })
})
