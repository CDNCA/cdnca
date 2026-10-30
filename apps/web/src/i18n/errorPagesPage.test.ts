import i18n from './index'
import { errorPagesMessages } from './errorPagesPage'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))))
}

describe('errorPagesMessages', () => {
  it('registers complete zh-CN, en-US, and pseudo-locale trees', () => {
    const zh = flatten(errorPagesMessages['zh-CN'])
    const required = [
      'actions.applyScope', 'actions.retryPublication', 'sections.publication',
      'actions.publishNodes', 'actions.confirmPublication', 'actions.retryReceipt',
      'actions.retryExactPublication', 'actions.abandonPublication', 'sections.publicationReceipt',
      'fields.scopeId', 'fields.contentType', 'fields.scanStatus', 'fields.priority',
      'fields.publicationTarget', 'fields.nodeIds', 'fields.snapshotId', 'fields.snapshotRevision',
      'fields.resolverSha256', 'fields.activationTimeoutMs', 'fields.observationWindowMs',
      'fields.requiredConsecutiveSuccesses', 'fields.maxAttempts', 'fields.deadline',
      'fields.publicationId', 'fields.configVersionId', 'fields.rolloutId', 'fields.artifactSha256',
      'publication.loading', 'publication.empty', 'publication.loadError', 'publication.sourceOnly',
      'publication.globalRules', 'publication.siteOverrides',
      'publication.receiptLoading', 'publication.receiptEmpty', 'publication.receiptLoadError',
      'publication.receiptOnly', 'publication.sourceRevision', 'publication.publicationRevision',
      'publication.nodeCount', 'publication.targetExplicit', 'publication.targetResolver',
      'publication.targets.nodes', 'publication.targets.lineGroupSnapshot',
      'scans.pending', 'scans.passed', 'scans.rejected', 'scans.error',
      'errors.unsafeContent', 'errors.scanRejected', 'errors.quotaExceeded',
      'errors.publicationReadForbidden', 'errors.publicationManageForbidden',
      'errors.publicationIdempotencyConflict', 'errors.publicationRevisionConflict',
      'errors.publicationTargetIneligible', 'errors.publicationUnavailable',
      'errors.publicationOutcomeUnknown', 'dialogs.publishPublication',
    ]
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'errorPagesPage')).toBe(true)
      const flat = flatten(errorPagesMessages[locale])
      expect(Object.keys(flat).sort()).toEqual(Object.keys(zh).sort())
      for (const key of required) expect(flat[key], `${locale}:${key}`).toEqual(expect.any(String))
    }
    expect(zh.title).toBe('自定义错误页')
    expect(zh['publication.sourceOnly']).toBe('此处仅显示确定性发布源，不代表边缘已激活或最近有效配置。')
    expect(zh['actions.publishNodes']).toBe('发布到节点')
    expect(zh['publication.receiptOnly']).toBe('发布回执仅确认生产发布请求及不可变产物，不代表节点已激活或健康。')
    expect(zh['errors.publicationOutcomeUnknown']).toBe('发布结果待确认')
    expect(zh['errors.unsafeContent']).toBe('内容包含不安全元素，请修改后重试')
    expect(zh['errors.scanRejected']).toBe('内容安全扫描未通过')
    expect(zh['errors.quotaExceeded']).toBe('错误页配额已用尽')
    expect(flatten(errorPagesMessages['qps-ploc']).title!.length).toBeGreaterThan(zh.title!.length)
    expect(errorPagesMessages['qps-Ploc']).toEqual(errorPagesMessages['qps-ploc'])
  })

  it('contains no raw server wording or secret labels', () => {
    for (const locale of Object.values(errorPagesMessages)) {
      for (const value of Object.values(flatten(locale))) expect(value).not.toMatch(/raw server|internal service|secret[_ -]?access[_ -]?key|session[_ -]?token/i)
    }
  })
})
