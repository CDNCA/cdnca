import { screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError, responseApiError } from '../api/auth'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { localizedUnknownApiError } from '../i18n/apiError'
import { displayIP } from '../i18n/formatters'
import SecurityActivationPanel from '../pages/security/SecurityActivationPanel'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const node = '5150a084-2a7d-88c9-95c7-838cf6b11f9b'
const other = '0814c213-6150-802a-a5ab-1ec162137d2f'
const packs = ['782892a2'.padEnd(64, '0'), 'b98bfa59'.padEnd(64, '1')]

// live-retest3 S4a (N17): the 422 rule_pack_unavailable of an automatic WAF
// activation only said "请求失败，请稍后重试".
async function rulePackRefusal(): Promise<ApiError> {
  return responseApiError(new Response(JSON.stringify({ error: {
    code: 'rule_pack_unavailable', request_id: 'req-21e12d98',
    message: `node ${node} has not installed the rule packs ... (节点尚未安装网站引用的规则包)`,
    rule_packs: { node_id: node, sha256: packs, other_node_ids: [other] },
  } }), { status: 422 }))
}

describe('N17 publish refusal reasons', () => {
  afterEach(() => vi.restoreAllMocks())

  it('names the node, packs and other nodes from error.rule_packs, not the raw message', async () => {
    await i18n.changeLanguage('zh-CN')
    const error = await rulePackRefusal()
    const text = localizedUnknownApiError(error, '请求失败，请稍后重试')
    expect(text).toContain(`节点 ${node} 尚未安装网站引用的规则包（782892a20000、b98bfa591111）`)
    expect(text).toContain(`同样受影响的节点：${other}`)
    expect(text).toContain('请求 ID：req-21e12d98')
    expect(text).not.toContain('has not installed')
  })

  // sa-rulepack-wait: a security activation refused for missing rule packs is
  // recorded (rule_packs.auto_resume) and delivered once the node has them.
  it('says the activation is delivered automatically when rule_packs.auto_resume is set', async () => {
    await i18n.changeLanguage('zh-CN')
    const error = await responseApiError(new Response(JSON.stringify({ error: {
      code: 'rule_pack_unavailable', request_id: 'req-21e12d98', message: 'raw',
      rule_packs: { node_id: node, sha256: packs, other_node_ids: [other], auto_resume: true },
    } }), { status: 422 }))
    expect(error.rulePacks?.auto_resume).toBe(true)
    const text = localizedUnknownApiError(error, '请求失败，请稍后重试')
    expect(text).toContain(`节点 ${node} 尚未安装网站引用的规则包（782892a20000、b98bfa591111）`)
    expect(text).toContain('节点装好规则包后会自动下发')
    expect(text).not.toContain('后重新发布')
    expect((await rulePackRefusal()).rulePacks?.auto_resume).toBeUndefined()
  })

  it('keeps the generic text when the structured field is missing or invalid', async () => {
    await i18n.changeLanguage('zh-CN')
    const error = await responseApiError(new Response(JSON.stringify({ error: {
      code: 'rule_pack_unavailable', message: 'raw', rule_packs: { node_id: 'https://x', sha256: [], other_node_ids: [] },
    } }), { status: 422 }))
    expect(localizedUnknownApiError(error, '请求失败，请稍后重试')).toBe('请求失败，请稍后重试')
  })

  it('shows the reason in the WAF auto-publish feedback dialog', async () => {
    await i18n.changeLanguage('zh-CN')
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const policy = { id: '44444444-4444-4444-8444-444444444444', kind: 'waf', name: 'cdnca-t WAF', enabled: true, version: 1, rules: [] } as unknown as SecurityPolicy
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null, operation: null })
    const error = await rulePackRefusal()
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockRejectedValue(error)
    renderWithProviders(<SecurityActivationPanel kind="waf" policies={[policy]} policiesLoading={false} autoPublish={{ id: policy.id, version: 1 }} />,
      ['/site/waf-rule?site_id=33333333-3333-4333-8333-333333333333'])
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(await screen.findByRole('dialog', { name: '发布操作失败' })).toBeInTheDocument()
    expect(screen.getByText(/尚未安装网站引用的规则包/)).toBeInTheDocument()
    expect(screen.queryByText(/^请求失败，请稍后重试/)).not.toBeInTheDocument()
  })
})

describe('client IP display', () => {
  it('shows an IPv4-mapped address as IPv4 and leaves others alone', () => {
    expect(displayIP('::ffff:198.51.100.83')).toBe('198.51.100.83')
    expect(displayIP('::FFFF:10.0.0.1')).toBe('10.0.0.1')
    expect(displayIP('2001:db8::1')).toBe('2001:db8::1')
    expect(displayIP('198.51.100.83')).toBe('198.51.100.83')
  })
})
