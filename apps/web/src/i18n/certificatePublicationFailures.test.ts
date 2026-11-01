import { describe, expect, it } from 'vitest'
import i18n from './index'
import { certificatePublicationFailureMessage } from './certificatePublicationFailures'

// node-logs3：证书同步失败码（码[.节点 UUID]）中英翻译；未知码兜底不回显原文。
describe('certificatePublicationFailureMessage', () => {
  const node = '0b5a3c1e-2f4d-4a6b-8c9d-0e1f2a3b4c5d'
  const codes = [
    'target_policy_not_automatic', 'target_policy_invalid', 'target_snapshot_unresolved', 'target_no_nodes',
    'target_node_missing', 'target_node_inactive', 'target_node_not_carried', 'target_node_offline',
    'target_node_identity_ineligible', 'target_node_capability_missing', 'target_invalid', 'publication_node_not_found',
    'publication_config_not_releasable', 'publication_input_invalid', 'publication_unavailable', 'publication_pending', 'publication_node_busy',
    'publication_conflict', 'publication_contract_invalid', 'publication_terminal_failed', 'actor_unauthenticated',
    'publisher_unavailable', 'publisher_timeout', 'publisher_cancelled', 'publisher_panic', 'publisher_contract_invalid',
    'legacy_reissue_required', 'node_certificate_precheck_failed', 'node_certificate_activation_failed',
    'node_certificate_health_failed',
  ]

  it.each(['zh-CN', 'en-US'])('translates every code in %s', (locale) => {
    const t = i18n.getFixedT(locale, 'certificatePublicationFailures')
    const generic = t('unknown')
    for (const code of codes) {
      const text = certificatePublicationFailureMessage(code, t)
      expect(text, code).not.toBe(generic)
      expect(text, code).not.toContain(code)
      expect(text, code).not.toContain('{{')
    }
  })

  it('names the node of a node-scoped code and falls back for unknown ones', () => {
    const t = i18n.getFixedT('zh-CN', 'certificatePublicationFailures')
    expect(certificatePublicationFailureMessage(`target_node_offline.${node}`, t)).toBe(`节点 ${node} 离线，将自动重试`)
    expect(certificatePublicationFailureMessage('target_node_identity_ineligible', t)).toBe('部分节点身份暂不可用于发布，将自动重试')
    expect(certificatePublicationFailureMessage('target_no_nodes.not-a-uuid', t)).toBe('同步失败')
    expect(certificatePublicationFailureMessage('future_code', t)).toBe('同步失败')
    const en = i18n.getFixedT('en-US', 'certificatePublicationFailures')
    expect(certificatePublicationFailureMessage(`node_certificate_health_failed.${node}`, t)).toBe(`节点 ${node} 启用证书后 TLS 握手检查失败，已回退`)
    expect(certificatePublicationFailureMessage(`target_node_not_carried.${node}`, en)).toBe(`Node ${node} does not serve this tenant's sites`)
  })
})
