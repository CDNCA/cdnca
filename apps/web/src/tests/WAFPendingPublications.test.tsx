import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { wafRuleSubscriptionsApi, type WAFPendingPublication } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { SiteWAFTab } from '../pages/site-edit/SiteProtectionTabs'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const siteID = '55555555-5555-4555-8555-555555555555'
const nodeA = '66666666-6666-4666-8666-666666666666'
const nodeB = '77777777-7777-4777-8777-777777777777'
const library = {
  id: '88888888-8888-4888-8888-888888888888', scope_id: '22222222-2222-4222-8222-222222222222', kind: 'waf',
  name: '已知漏洞防护', description: '', enabled: true, default_action: 'allow', version: 3, created_at: '', updated_at: '',
  rules: null, origin: 'system', protected: true,
} as unknown as SecurityPolicy
const pending: WAFPendingPublication = {
  site_id: siteID, domain: 'shop.example.com', policy_id: library.id, active_version: 2, latest_version: 3,
  updated_at: '2026-10-17T00:00:00Z', publishing: false, last_target_node_ids: [nodeA, nodeB],
}

describe('订阅已更新、待发布 (NF37)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('lists sites behind their subscribed library and opens a prefilled, unconfirmed release', async () => {
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [library], total: 1, page: 1, limit: 20 })
    vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([pending])
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      binding: { id: 'b1', policy_id: library.id, binding_revision: 4, active_policy_version: 2, last_claimed_policy_version: 2 },
      latest_candidate: null, operation: null,
    })
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation')
    const actor = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])

    const alert = await screen.findByText('订阅已更新、待发布（1 个网站）')
    const row = within(alert.closest('.waf-pending-publications') as HTMLElement).getByText('shop.example.com').closest('tr')!
    expect(within(row).getByText('已知漏洞防护')).toBeInTheDocument()
    expect(within(row).getByText('v2 → v3')).toBeInTheDocument()
    await actor.click(within(row).getByRole('button', { name: /去发布/ }))

    expect(await screen.findByRole('heading', { name: '安全规则发布' })).toBeInTheDocument()
    // waf-tenant-fix (10-22 自动下发): a tenant release no longer carries nodes; the
    // control plane targets the site's package line groups, so last_target_node_ids is not prefilled.
    expect(await screen.findByText('已知漏洞防护 (v3)')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /节点/ })).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(nodeA)
    expect(document.body).not.toHaveTextContent(nodeB)
    // Nothing is published until the operator confirms.
    expect(publish).not.toHaveBeenCalled()
  })

  it('shows nothing when every site runs the latest version', async () => {
    const user = principal({ permissions: ['security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [library], total: 1, page: 1, limit: 20 })
    const pendingCall = vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
    await waitFor(() => expect(pendingCall).toHaveBeenCalled())
    expect(screen.queryByText(/订阅已更新、待发布/)).not.toBeInTheDocument()
  })

  // SEC-ACCOUNT-03: a failed read is unknown state with a retry, not an empty list.
  it('SEC-ACCOUNT-03: reports a failed pending-publication read and recovers on retry', async () => {
    const user = principal({ permissions: ['security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [library], total: 1, page: 1, limit: 20 })
    const pendingCall = vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications')
      .mockRejectedValueOnce(new ApiError('boom', 500, 'internal_error'))
      .mockResolvedValue([pending])
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
    expect(await screen.findByText('待发布列表读取失败，无法确认订阅更新是否已发布')).toBeInTheDocument()
    await userEvent.setup().click(screen.getAllByRole('button', { name: '重试' })[0])
    expect(await screen.findByText('订阅已更新、待发布（1 个网站）')).toBeInTheDocument()
    expect(pendingCall).toHaveBeenCalledTimes(2)
  })

  it('SEC-ACCOUNT-03: a denied pending-publication read says so without retry', async () => {
    const user = principal({ permissions: ['security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [library], total: 1, page: 1, limit: 20 })
    vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockRejectedValue(new ApiError('no', 403, 'permission_denied'))
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
    expect(await screen.findByText('当前账号无权查看待发布列表')).toBeInTheDocument()
  })

  it('the site WAF tab says the subscribed library waits to be published and links to the prefilled release', async () => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [library], total: 1, page: 1, limit: 100 })
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      binding: { id: 'b1', policy_id: library.id, binding_revision: 4, active_policy_version: 2, last_claimed_policy_version: 2 },
      latest_candidate: null, operation: null,
    })
    // The site's publication binding is a tenant resource: the tenant view shows the pending hint.
    renderWithProviders(<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind="tenant" scopeId="s1" accessToken="token"
      permissions={['security_policies.read', 'security_policies.manage']} locked={false} />)
    expect(await screen.findByText('当前规则库已更新到 v3，本网站仍在执行 v2，需要重新发布才会生效。')).toBeInTheDocument()
    // fix-siteprot（c0dd43c02）起在网站 WAF 页就地下发新版本，不再跳规则页。
    expect(screen.getByRole('button', { name: '立即下发新版本' })).toBeEnabled()
  })

  it('site-parity3b: the platform view no longer shows the tenant-only activation note', async () => {
    // W7 曾让平台视角不读激活状态并显示"由租户发布"；site-parity3b（a6c6c143d）起管理员直接读写站点发布。
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [library], total: 1, page: 1, limit: 100 })
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    renderWithProviders(<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind="platform" scopeId="s1" accessToken="token"
      permissions={['security_policies.read', 'security_policies.manage']} locked={false} />)
    expect(await screen.findByRole('heading', { name: 'WAF防护' })).toBeInTheDocument()
    expect(screen.queryByText(/站点当前生效的规则由租户发布/)).not.toBeInTheDocument()
  })
})
