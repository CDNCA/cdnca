import i18n from './index'
import { originAuthPublicationsMessages } from './originAuthPublications'

type MessageTree = { [key: string]: string | MessageTree }

function flatten(tree: MessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(flatten(value, path))
  }))
}

function placeholders(value: string): string[] {
  return value.match(/{{[^}]+}}/g)?.sort() ?? []
}

describe('originAuthPublications translations', () => {
  it('registers identical keys and placeholders for every supported locale spelling', () => {
    const zh = flatten(originAuthPublicationsMessages['zh-CN'])
    const keys = Object.keys(zh).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      const messages = flatten(originAuthPublicationsMessages[locale])
      expect(Object.keys(messages).sort()).toEqual(keys)
      for (const key of keys) {
        expect(i18n.getResource(locale, 'originAuthPublications', key)).toBe(messages[key])
        expect(placeholders(messages[key]!)).toEqual(placeholders(zh[key]!))
      }
    }
  })

  it('covers stable API errors and expands pseudo text without server wording', () => {
    const zh = flatten(originAuthPublicationsMessages['zh-CN'])
    expect(Object.keys(zh)).toEqual(expect.arrayContaining([
      'errors.invalid_request', 'errors.permission_denied', 'errors.entitlement_denied',
      'errors.not_found', 'errors.resource_conflict', 'errors.idempotency_conflict',
      'errors.revision_conflict', 'errors.validation_error', 'errors.request_canceled',
      'errors.service_unavailable', 'errors.invalid_response', 'errors.network_error',
    ]))
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudo = flatten(originAuthPublicationsMessages[locale])
      for (const [key, value] of Object.entries(pseudo)) {
        expect(value).toMatch(/^［.*］$/)
        expect(value.length).toBeGreaterThan(zh[key]!.length)
        expect(value).not.toMatch(/database|stack trace|secret|access key|session token/i)
      }
    }
  })

  it('defines complete tenant targeting and secret-free node publication copy', () => {
    const zh = flatten(originAuthPublicationsMessages['zh-CN'])
    const en = flatten(originAuthPublicationsMessages['en-US'])

    expect(zh).toMatchObject({
      'targetScope.label': '目标租户作用域',
      'targetScope.placeholder': '租户作用域 UUID',
      'targetScope.apply': '应用目标',
      'targetScope.required': '请先选择要查看的租户作用域。',
      'targetScope.invalid': '请输入有效的小写租户作用域 UUID。',
      'edge.title': '节点发布结果',
      'edge.loading': '正在加载节点发布结果',
      'edge.empty': '尚未执行节点发布',
      'edge.nodeCount': '{{count}} 个节点',
      'edge.dialogTitle': '发布源站鉴权到节点',
      'edge.fields.nodeIDs': '目标节点 UUID',
      'edge.fields.activationTimeout': '激活超时（毫秒）',
      'edge.fields.observationWindow': '观察窗口（毫秒）',
      'edge.fields.requiredSuccesses': '连续成功次数',
      'edge.fields.deadline': '截止时间（UTC）',
      'edge.details.publicationID': '发布 ID',
      'edge.details.rolloutID': '灰度 ID',
      'edge.details.configVersionID': '配置版本 ID',
      'edge.details.configSnapshotHash': '配置快照哈希',
      'edge.details.artifactManifestHash': '制品清单哈希',
      'edge.details.recipientBindingHash': '接收方绑定哈希',
      'edge.actions.publish': '发布到节点',
      'edge.actions.confirmPublish': '确认发布到节点',
      'edge.actions.retryRead': '重试读取节点发布结果',
      'edge.actions.retrySameRequest': '使用同一节点发布请求重试',
      'edge.actions.abandonRefresh': '放弃节点发布并刷新',
      'edge.uncertainty.title': '节点发布结果待确认',
      'edge.forbidden.title': '无权查看节点发布结果',
      'errors.edge_outcome_unknown': '节点发布结果待确认。',
      'errors.edge_unavailable': '节点发布服务暂不可用，请稍后重试。',
    })
    expect(en).toMatchObject({
      'targetScope.label': 'Target tenant scope',
      'targetScope.apply': 'Apply target',
      'edge.title': 'Node publication result',
      'edge.loading': 'Loading node publication result',
      'edge.empty': 'No node publication has been run',
      'edge.nodeCount': '{{count}} nodes',
      'edge.actions.publish': 'Publish to nodes',
      'edge.actions.confirmPublish': 'Confirm node publication',
      'edge.uncertainty.title': 'Node publication outcome is unknown',
      'edge.forbidden.title': 'Node publication result unavailable',
      'errors.edge_unavailable': 'The node publication service is unavailable. Try again later.',
    })
    expect(JSON.stringify(originAuthPublicationsMessages))
      .not.toMatch(/ciphertext|private key|wrapped key|recipient key|raw rollout/i)
  })
})
