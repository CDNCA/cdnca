import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import { firewallActionApi } from '../api/firewallAction'
import { useSessionStore } from '../auth/session'
import FirewallActionPoliciesPage from '../pages/FirewallActionPoliciesPage'

vi.mock('../api/firewallAction', async () => {
  const actual = await vi.importActual<typeof import('../api/firewallAction')>('../api/firewallAction')
  return { ...actual, firewallActionApi: { ...actual.firewallActionApi, get: vi.fn(), put: vi.fn(), recover: vi.fn() } }
})

const policy = {
  id: '33333333-3333-4333-8333-333333333333', tenant_scope_id: '11111111-1111-4111-8111-111111111111',
  site_id: '22222222-2222-4222-8222-222222222222', normal_action: 'return_page' as const, escalated_action: 'nftables' as const,
  engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'], trusted_proxies: ['192.0.2.0/24'],
  trusted_crawlers: [{ name: 'search', networks: ['203.0.113.0/24'], user_agent_prefixes: ['SearchBot/'] }],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8' as const, body: 'Request limited' },
  revision: 4, active_revision: 3, lkg_revision: 3, deployment_state: 'failed' as const, host_escalation: 'owned' as const, document_sha256: 'a'.repeat(64),
  created_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z',
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<CdncaProvider><MemoryRouter initialEntries={[`/config/firewall-actions?site_id=${policy.site_id}`]}><QueryClientProvider client={client}><FirewallActionPoliciesPage /></QueryClientProvider></MemoryRouter></CdncaProvider>)
}

describe('FirewallActionPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useSessionStore.setState({ accessToken: 'token', sessionEpoch: 1, principal: {
      user_id: '44444444-4444-4444-8444-444444444444', scope_id: policy.tenant_scope_id, scope_kind: 'tenant',
      tenant_id: policy.tenant_scope_id, username: 'operator', display_name: 'Operator', roles: ['tenant_admin'],
      permissions: ['firewall.read', 'firewall.manage'],
    } })
    vi.mocked(firewallActionApi.get).mockResolvedValue(policy)
  })

  it('renders failed candidate separately from active LKG in Chinese', async () => {
    renderPage()
    expect(await screen.findByText('候选策略下发失败，当前稳定版本继续生效')).toBeInTheDocument()
    expect(screen.getByText('当前生效修订：3')).toBeInTheDocument()
    expect(screen.getByText('最近稳定修订：3')).toBeInTheDocument()
    expect(screen.getByDisplayValue('SearchBot/')).toBeInTheDocument()
  })

  it('saves one atomic policy with revision CAS and can recover the LKG', async () => {
    vi.mocked(firewallActionApi.put).mockResolvedValue({ ...policy, revision: 5, deployment_state: 'failed' })
    vi.mocked(firewallActionApi.recover).mockResolvedValue({ ...policy, revision: 5, deployment_state: 'pending' })
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('候选策略下发失败，当前稳定版本继续生效')
    await user.clear(screen.getByLabelText('触发阈值'))
    await user.type(screen.getByLabelText('触发阈值'), '120')
    await user.click(screen.getByRole('button', { name: '保存策略' }))
    expect(firewallActionApi.put).toHaveBeenCalledWith('token', expect.objectContaining({ expectedRevision: 4, policy: expect.objectContaining({ engage_threshold: 120 }) }))
    await user.click(screen.getByRole('button', { name: '恢复最近稳定版本' }))
    expect(firewallActionApi.recover).toHaveBeenCalledWith('token', expect.objectContaining({ expectedRevision: 5 }))
  })

  // A08: a tenant whose sites run only on shared platform nodes is not
  // offered the nftables escalation; the normal actions stay.
  it('hides the nftables escalation when the tenant has only shared nodes', async () => {
    vi.mocked(firewallActionApi.get).mockResolvedValue({ ...policy, host_escalation: 'shared_unsupported' })
    renderPage()
    await screen.findByText('候选策略下发失败，当前稳定版本继续生效')
    expect(screen.queryByText('高负载动作')).not.toBeInTheDocument()
    expect(screen.queryByText('nftables 自动拦截')).not.toBeInTheDocument()
    expect(screen.getByText('常态动作')).toBeInTheDocument()
    expect(screen.queryByText(/共享节点不支持租户宿主规则/)).not.toBeInTheDocument()
  })

  it('shows the nftables escalation on a node the tenant owns', async () => {
    renderPage()
    await screen.findByText('候选策略下发失败，当前稳定版本继续生效')
    expect(screen.getByText('高负载动作')).toBeInTheDocument()
    expect(screen.getByText('nftables 自动拦截')).toBeInTheDocument()
  })

  it('does not render a request failure as an empty policy', async () => {
    vi.mocked(firewallActionApi.get).mockRejectedValue(new Error('network'))
    renderPage()
    expect(await screen.findByText('防火墙动作策略加载失败')).toBeInTheDocument()
    expect(screen.queryByText('尚未配置动作策略')).not.toBeInTheDocument()
  })
})
