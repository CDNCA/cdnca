import i18n from './index'
import { cachePolicyMessages } from './cachePolicy'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

function placeholderTokens(value: string): string[] {
  return value.match(/{{[^}]+}}/g)?.sort() ?? []
}

function nonPlaceholderLength(value: string): number {
  return value.replace(/{{[^}]+}}/g, '').replace(/\s/g, '').length
}

describe('cachePolicy translations', () => {
// every leaf under dialog.* and table.* (the tp-b3c-be rule dialog and table)
function dialogKeys(messages: MessageTree): string[] {
  return Object.keys(flatten(messages)).filter((key) => key.startsWith('dialog.') || key.startsWith('table.'))
}

  it('registers a complete cachePolicy namespace for every supported locale spelling', () => {
    const zh = flatten(cachePolicyMessages['zh-CN'])
    const expectedKeys = [
      'actions.addRule', 'actions.compare', 'actions.hideAdvanced', 'actions.history',
      'actions.moveDown', 'actions.moveUp', 'actions.next', 'actions.previous', 'actions.refresh',
      'actions.reload', 'actions.removeRule', 'actions.retry', 'actions.retryAfterReload',
      'actions.save', 'actions.showAdvanced', 'advanced.description', 'advanced.title',
      'comparison.base', 'comparison.draft', 'comparison.latest', 'comparison.title',
      'confirm.overwriteLatest', 'confirm.refreshDiscard', 'errors.idempotency_conflict',
      'errors.invalid_request', 'errors.invalid_response', 'errors.network_error', 'errors.not_found',
      'errors.permission_denied', 'errors.request_failed', 'errors.revision_conflict',
      'errors.service_unavailable', 'errors.validation_error', 'fields.diskQuotaBytes',
      'fields.extensions', 'fields.match', 'fields.mode', 'fields.order', 'fields.pathPrefix',
      'fields.queryMode', 'fields.queryNames', 'fields.rules', 'fields.statusCodes',
      'fields.ttlSeconds', 'fields.varyHeaders', 'history.createdAt', 'history.createdBy',
      'history.detailError', 'history.empty', 'history.requestId', 'history.revision', 'history.title', 'history.view',
      'matchTypes.all', 'matchTypes.extensions', 'matchTypes.pathPrefix', 'matchTypes.statusCodes',
      'modeHelp.disabled', 'modeHelp.follow_origin', 'modeHelp.override', 'modes.disabled',
      'modes.follow_origin', 'modes.override', 'queryModes.exclude', 'queryModes.ignore',
      'queryModes.include', 'queryModes.preserve', 'states.conflictDescription',
      'states.conflictTitle', 'states.empty', 'states.forbiddenDescription', 'states.forbiddenTitle',
      'states.loadError', 'states.loading', 'states.readOnly', 'states.saved', 'states.saving',
      'states.unchanged',
      // cache-status-header（迁移 472）：站点级缓存状态响应头开关。
      'statusHeader.errors.permission_denied', 'statusHeader.errors.request_failed',
      'statusHeader.errors.site_locked', 'statusHeader.errors.version_conflict',
      'statusHeader.help', 'statusHeader.label', 'statusHeader.saveFailed', 'statusHeader.saved',
      'title', 'units.bytes', 'units.gib', 'units.mib',
      'units.seconds', 'units.tib', 'validation.duplicate', 'validation.invalidExtension',
      'validation.invalidHeader', 'validation.invalidPath', 'validation.invalidStatus', 'validation.overlap',
      'validation.queryNamesForbidden', 'validation.queryNamesRequired', 'validation.quotaRange',
      'validation.required', 'validation.ruleRequired', 'validation.ttlRange',
      // ge-cache 第 4 节（045154639）：缓存策略扩展字段与“清空全部缓存”。
      'actions.cancel', 'fields.backgroundUpdate', 'fields.maxObjectBytes', 'fields.minObjectBytes',
      'fields.sliceBytes', 'fields.staleIfError', 'flush.action', 'flush.confirm', 'flush.description',
      'flush.done', 'flush.title', 'help.backgroundUpdate', 'help.objectBytes', 'help.sliceBytes',
      'help.staleIfError', 'slice.off', 'slice.size', 'validation.invalidExtensions',
      // ge36：缓存规则路径正则与响应内容类型条件。
      'fields.contentTypes', 'fields.pathRegex', 'placeholders.contentTypes', 'placeholders.pathRegex',
      'validation.invalidContentTypes', 'validation.invalidPathRegex', 'validation.tooManyConditionalRules',
      // n6b：schema v2 规则动作与浏览器缓存有效期。
      'fields.action', 'fields.browserTtlSeconds', 'help.browserTtl', 'help.browserTtlOff', 'help.noCache',
      'ruleActions.cache', 'ruleActions.no_cache', 'validation.browserTtlRange',
      // tp-b3c：缓存规则区（N 条、快速设置缓存、空态、其他设置）。
      'actions.quick', 'count', 'empty.add', 'empty.description', 'empty.title', 'other.description', 'other.title',
      'quick.home', 'quick.site', 'quick.static', 'quick.video',
      // tp-b3c-be：新增缓存规则弹窗、规则表格、WordPress 快速设置、按规则设置的校验。
      'quick.wordpress', ...dialogKeys(cachePolicyMessages['zh-CN']),
      'validation.invalidExactPath', 'validation.invalidCondition', 'validation.tooManyConditions',
      // e2fe64cca：Vary 改「按请求头区分缓存」多选，磁盘配额/对象大小带单位。
      'help.varyHeaders', 'help.diskQuota', 'placeholders.varyHeaders',
      'varyHeaderOptions.accept-encoding', 'varyHeaderOptions.accept-language', 'varyHeaderOptions.user-agent',
      'varyHeaderOptions.accept', 'varyHeaderOptions.origin', 'varyHeaderOptions.sec-ch-ua-mobile',
      'units.kb', 'units.mb', 'units.gb', 'units.tb', 'units.unitOf',
    ].sort()
    expect(Object.keys(zh).sort()).toEqual(expectedKeys)

    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const leaves = flatten(cachePolicyMessages[locale])
      expect(Object.keys(leaves).sort()).toEqual(expectedKeys)
      for (const key of expectedKeys) {
        expect(i18n.getResource(locale, 'cachePolicy', key)).toBe(leaves[key])
        expect(placeholderTokens(leaves[key]!)).toEqual(placeholderTokens(zh[key]!))
      }
    }
  })

  it('provides English without Chinese fallback and recursively expands both pseudo locales', () => {
    const zh = flatten(cachePolicyMessages['zh-CN'])
    const en = flatten(cachePolicyMessages['en-US'])
    expect(Object.values(en).join('')).not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    expect(cachePolicyMessages['qps-Ploc']).toEqual(cachePolicyMessages['qps-ploc'])

    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(cachePolicyMessages[locale])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value.startsWith('［')).toBe(true)
        expect(value.endsWith('］')).toBe(true)
        expect(nonPlaceholderLength(value.slice(1, -1))).toBeGreaterThan(nonPlaceholderLength(zh[key]!))
      }
    }
  })

  it('names only the rule actions the server accepts (cachecontrol.RuleAction)', () => {
    for (const locale of ['zh-CN', 'en-US'] as const) {
      expect(Object.keys(cachePolicyMessages[locale].ruleActions as object).sort()).toEqual(['cache', 'no_cache'])
    }
    expect(JSON.stringify(cachePolicyMessages)).not.toMatch(/force_cache/i)
  })
})
