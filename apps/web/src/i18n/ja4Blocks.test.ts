import i18n from './index'
import { ja4BlocksMessages } from './ja4Blocks'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))))
}

describe('ja4BlocksMessages', () => {
  it('registers complete zh-CN, en-US, and expanded pseudo-locale trees', () => {
    const zh = flatten(ja4BlocksMessages['zh-CN'])
    const required = [
      'title', 'description', 'actions.create', 'actions.confirm', 'actions.confirmBlock', 'actions.cancel',
      'actions.retryRead', 'actions.retrySame', 'actions.abandon',
      'states.empty', 'states.loading', 'states.loadError', 'states.forbidden', 'states.outcomeUnknown',
      'fields.tenantScopeId', 'fields.siteId', 'fields.ja4', 'fields.maskedJa4', 'fields.snapshotAt',
      'fields.durationSeconds', 'fields.reason', 'fields.stepUp', 'fields.workflowId',
      'fields.ja4Sha256', 'fields.phase', 'fields.revision', 'fields.policyId',
      'fields.policyRevision', 'fields.bindingId', 'fields.bindingRevision',
      'fields.edgePublicationId', 'fields.rolloutId', 'fields.edgeState', 'fields.attemptCount',
      'phases.queued', 'phases.policy_ready', 'phases.edge_pending', 'phases.active',
      'phases.failed', 'phases.expired', 'edgeStates.pending', 'edgeStates.active',
      'edgeStates.failed', 'edgeStates.rolled_back', 'receipt.disclaimer',
      'errors.invalidInput', 'errors.permissionDenied', 'errors.idempotencyConflict',
      'errors.authenticationRequired', 'errors.conflict', 'errors.snapshotStale', 'errors.dependencyInvalid',
      'errors.revisionConflict', 'errors.stepUpRequired', 'errors.unavailable', 'errors.requestFailed',
      'confirmation.title', 'confirmation.description',
    ]
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'ja4Blocks')).toBe(true)
      const flat = flatten(ja4BlocksMessages[locale])
      expect(Object.keys(flat).sort()).toEqual(Object.keys(zh).sort())
      for (const key of required) expect(flat[key], `${locale}:${key}`).toEqual(expect.any(String))
    }
    expect(zh['actions.create']).toBe('创建 JA4 封禁')
    expect(zh['states.empty']).toBe('本页尚未跟踪 JA4 封禁工作流')
    expect(zh['states.outcomeUnknown']).toBe('创建结果待确认')
    expect(zh['receipt.disclaimer']).toBe('回执仅陈述不可变策略、绑定、发布和灰度状态；只有工作流与边缘状态均为 active 时才表示已激活。')
    expect(flatten(ja4BlocksMessages['qps-ploc']).description!.length).toBeGreaterThan(zh.description!.length)
    expect(ja4BlocksMessages['qps-Ploc']).toEqual(ja4BlocksMessages['qps-ploc'])
  })

  it('contains no raw server wording, secrets, or storage instructions', () => {
    for (const locale of Object.values(ja4BlocksMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|private database|localStorage|sessionStorage|access[_ -]?token/i)
      }
    }
  })
})
