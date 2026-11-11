import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import { firewallActionApi } from '../api/firewallAction'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import FirewallActionPoliciesPage from '../pages/FirewallActionPoliciesPage'

vi.mock('../api/firewallAction', async () => {
  const actual = await vi.importActual<typeof import('../api/firewallAction')>('../api/firewallAction')
  return { ...actual, firewallActionApi: { ...actual.firewallActionApi, get: vi.fn(), put: vi.fn(), recover: vi.fn(), inherit: vi.fn(), getDefault: vi.fn(), putDefault: vi.fn() } }
})

vi.mock('../api/sites', () => ({ sitesApi: { list: vi.fn(), detail: vi.fn() } }))
vi.mock('../api/users', () => ({ usersApi: { list: vi.fn().mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 }) } }))

const policy = {
  id: '33333333-3333-4333-8333-333333333333', tenant_scope_id: '11111111-1111-4111-8111-111111111111',
  site_id: '22222222-2222-4222-8222-222222222222', normal_action: 'return_page' as const, escalated_action: 'nftables' as const,
  engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'], trusted_proxies: ['192.0.2.0/24'],
  trusted_crawlers: [{ name: 'search', networks: ['203.0.113.0/24'], user_agent_prefixes: ['SearchBot/'] }],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8' as const, body: 'Request limited' },
  revision: 4, active_revision: 3, lkg_revision: 3, deployment_state: 'failed' as const, enabled: true, host_escalation: 'owned' as const, document_sha256: 'a'.repeat(64),
  created_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z', inherited: false, source: 'site' as const, delivered: true,
}

const inheritedTenant = { ...policy, revision: 5, active_revision: 0, lkg_revision: 0, deployment_state: 'inherited' as const, inherited: true,
  source: 'tenant_default' as const, engage_threshold: 300 }

const systemDefault = { tenant_scope_id: policy.tenant_scope_id, source: 'system_default' as const, revision: 0, normal_action: 'return_page' as const,
  escalated_action: 'nftables' as const, engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'],
  trusted_proxies: [], trusted_crawlers: [], return_page: policy.return_page, inheriting_site_count: 12, updated_at: null }

function renderPage(entry = `/config/firewall-actions?site_id=${policy.site_id}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<CdncaProvider><MemoryRouter initialEntries={[entry]}><QueryClientProvider client={client}><FirewallActionPoliciesPage /></QueryClientProvider></MemoryRouter></CdncaProvider>)
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
    vi.mocked(firewallActionApi.getDefault).mockResolvedValue(systemDefault)
    vi.mocked(sitesApi.detail).mockResolvedValue({ id: policy.site_id, scope_id: policy.tenant_scope_id, basic: { domains: ['shop.example.test'] } } as never)
    vi.mocked(sitesApi.list).mockResolvedValue({ items: [{ id: policy.site_id, display_id: 'S100', domain: 'shop.example.test',
      owner: { id: '55555555-5555-4555-8555-555555555555', display_name: 'Alice' } }] as never, total: 1, page: 1, limit: 20 })
  })

  // the admin page asked for raw tenant-scope and site UUIDs;
  // it now lists sites and loads the picked site's policy under its owner scope.
  it('lets a platform admin pick a site instead of typing scope and site UUIDs', async () => {
    useSessionStore.setState({ principal: { ...useSessionStore.getState().principal!, scope_kind: 'platform',
      scope_id: '66666666-6666-4666-8666-666666666666', tenant_id: null, permissions: ['platform.admin'] } })
    const user = userEvent.setup()
    renderPage('/config/firewall-action')
    expect(screen.queryByLabelText('目标租户作用域')).not.toBeInTheDocument()
    expect(await screen.findByText('shop.example.test')).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '配置 shop.example.test 的动作策略' }))
    expect(await screen.findByText('候选策略下发失败，当前稳定版本继续生效')).toBeInTheDocument()
    expect(firewallActionApi.get).toHaveBeenCalledWith('token', policy.tenant_scope_id, policy.site_id)
    expect(screen.getByText('网站：shop.example.test')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '返回网站列表' }))
    expect(await screen.findByRole('button', { name: '配置 shop.example.test 的动作策略' })).toBeInTheDocument()
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

  // A3-03: invalid CIDRs and a recover threshold not below the engage threshold are refused before the PUT.
  it('refuses invalid block networks and a recover threshold not below the engage threshold', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('候选策略下发失败，当前稳定版本继续生效')
    const save = screen.getByRole('button', { name: '保存策略' })
    const block = screen.getByLabelText('内核拦截网段')
    fireEvent.change(block, { target: { value: '198.51.100.0/24\nnot-a-cidr\n10.0.0.0/33\n2001:db8::/129\n2001:db8::/32' } })
    expect(screen.getByText('以下网段不是合法 CIDR：not-a-cidr、10.0.0.0/33、2001:db8::/129')).toBeInTheDocument()
    expect(block).toHaveAttribute('aria-invalid', 'true')
    expect(save).toBeDisabled()
    fireEvent.change(block, { target: { value: '198.51.100.0/24\n2001:db8::/32' } })
    expect(screen.queryByText(/不是合法 CIDR/)).not.toBeInTheDocument()
    expect(save).toBeEnabled()

    await user.clear(screen.getByLabelText('恢复阈值'))
    await user.type(screen.getByLabelText('恢复阈值'), '200')
    expect(screen.getByText('恢复阈值须小于触发阈值（100）')).toBeInTheDocument()
    expect(save).toBeDisabled()
    await user.click(save)
    expect(firewallActionApi.put).not.toHaveBeenCalled()
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

  // firewall-action-review: fields use the site edit pages' horizontal row
  // (label column + control), not a label stacked above the control.
  it('lays out each field as a label column beside its control', async () => {
    renderPage()
    await screen.findByText('候选策略下发失败，当前稳定版本继续生效')
    for (const label of ['常态动作', '触发阈值', '内核拦截网段', '状态码']) {
      const row = screen.getByText(label, { selector: 'label' }).closest('.site-form-row')
      expect(row).not.toBeNull()
      expect(row!.querySelector('.site-form-row-control')).not.toBeNull()
    }
  })

  // 网站列表上方是本租户的默认设置。
  it('edits the tenant default above the site list and says how many sites inherit it', async () => {
    vi.mocked(firewallActionApi.putDefault).mockResolvedValue({ ...systemDefault, source: 'tenant_default', revision: 1, engage_threshold: 250,
      updated_at: '2026-10-31T00:00:00Z' })
    const user = userEvent.setup()
    renderPage('/config/firewall-action')
    const card = await screen.findByRole('region', { name: '默认设置' })
    expect(await within(card).findByText('继承系统默认')).toBeInTheDocument()
    expect(within(card).getByText('继承此默认的网站')).toBeInTheDocument()
    expect(within(card).getByText('12 个')).toBeInTheDocument()
    expect(within(card).getByText(/尚未保存默认设置，使用系统内置默认/)).toBeInTheDocument()
    await user.click(within(card).getByRole('button', { name: '编辑默认设置' }))
    await user.clear(within(card).getByLabelText('触发阈值'))
    await user.type(within(card).getByLabelText('触发阈值'), '250')
    await user.click(within(card).getByRole('button', { name: '保存默认设置' }))
    expect(firewallActionApi.putDefault).toHaveBeenCalledWith('token', expect.objectContaining({ scopeId: policy.tenant_scope_id, expectedRevision: 0,
      policy: expect.objectContaining({ engage_threshold: 250 }) }))
    expect(await within(card).findByText('继承默认设置')).toBeInTheDocument()
  })

  // 平台管理员不带 target_scope_id 打开时先选用户，带上后显示该用户的默认设置。
  it('lets a platform admin pick a tenant to see its default settings', async () => {
    useSessionStore.setState({ principal: { ...useSessionStore.getState().principal!, scope_kind: 'platform',
      scope_id: '66666666-6666-4666-8666-666666666666', tenant_id: null, permissions: ['platform.admin'] } })
    const first = renderPage('/config/firewall-action')
    expect(await screen.findByRole('combobox', { name: '所属用户' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '默认设置' })).not.toBeInTheDocument()
    expect(firewallActionApi.getDefault).not.toHaveBeenCalled()
    first.unmount()
    renderPage(`/config/firewall-action?target_scope_id=${policy.tenant_scope_id}`)
    const card = await screen.findByRole('region', { name: '默认设置' })
    expect(await within(card).findByText('继承系统默认')).toBeInTheDocument()
    expect(firewallActionApi.getDefault).toHaveBeenCalledWith('token', policy.tenant_scope_id)
  })

  const platform = () => useSessionStore.setState({ principal: { ...useSessionStore.getState().principal!, scope_kind: 'platform',
    scope_id: '66666666-6666-4666-8666-666666666666', tenant_id: null, permissions: ['platform.admin'] } })

  // 重新设计：所属用户与搜索在同一条工具栏，网站列不再显示内部编号 display_id，有别名时显示数量。
  it('puts the owner filter and the search in one toolbar and hides the internal display id', async () => {
    platform()
    vi.mocked(sitesApi.list).mockResolvedValue({ items: [{ id: policy.site_id, display_id: 'S100', domain: 'shop.example.test',
      domains: ['shop.example.test', 'www.example.test', 'm.example.test'],
      owner: { id: '55555555-5555-4555-8555-555555555555', display_name: 'Alice' } }] as never, total: 1, page: 1, limit: 20 })
    renderPage('/config/firewall-action')
    expect(await screen.findByText('shop.example.test')).toBeInTheDocument()
    expect(screen.queryByText('S100')).not.toBeInTheDocument()
    expect(screen.getByText('另有 2 个域名')).toBeInTheDocument()
    const owner = screen.getByRole('combobox', { name: '所属用户' })
    const search = screen.getByRole('searchbox', { name: '按域名搜索网站' })
    const toolbar = owner.closest('.cdnca-table-toolbar')
    expect(toolbar).not.toBeNull()
    expect(toolbar!.contains(search)).toBe(true)
    expect(toolbar!.querySelector('.cdnca-table-toolbar-actions')!.contains(owner)).toBe(true)
    expect(toolbar!.querySelector('.cdnca-table-toolbar-filters')!.contains(search)).toBe(true)
    expect(screen.getByText('在下方选择所属用户，查看并编辑该用户的默认设置')).toBeInTheDocument()
  })

  it('filters the site list by the owner kept in the URL and keeps it after going back from a site', async () => {
    platform()
    const user = userEvent.setup()
    const ownerId = '55555555-5555-4555-8555-555555555555'
    renderPage(`/config/firewall-action?target_scope_id=${policy.tenant_scope_id}&owner_id=${ownerId}`)
    expect(await screen.findByRole('region', { name: '默认设置' })).toBeInTheDocument()
    expect(sitesApi.list).toHaveBeenCalledWith('token', expect.objectContaining({ owner: ownerId }))
    await user.click(await screen.findByRole('button', { name: '配置 shop.example.test 的动作策略' }))
    await screen.findByText('候选策略下发失败，当前稳定版本继续生效')
    await user.click(screen.getByRole('button', { name: '返回网站列表' }))
    expect(await screen.findByRole('region', { name: '默认设置' })).toBeInTheDocument()
    expect(vi.mocked(sitesApi.list).mock.calls.at(-1)![1]).toEqual(expect.objectContaining({ owner: ownerId }))
  })

  it('says what to try when a domain search matches nothing', async () => {
    vi.mocked(sitesApi.list).mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const user = userEvent.setup()
    renderPage('/config/firewall-action')
    expect(await screen.findByText('没有网站')).toBeInTheDocument()
    await user.type(screen.getByRole('searchbox', { name: '按域名搜索网站' }), 'nope{Enter}')
    expect(await screen.findByText('没有匹配「nope」的网站，换个域名关键字试试')).toBeInTheDocument()
  })

  it('shows an inheriting site as such, saves its own policy at its revision, and restores inheritance', async () => {
    vi.mocked(firewallActionApi.get).mockResolvedValue(inheritedTenant)
    vi.mocked(firewallActionApi.put).mockResolvedValue({ ...policy, revision: 6, deployment_state: 'pending' })
    vi.mocked(firewallActionApi.inherit).mockResolvedValue({ ...inheritedTenant, revision: 7 })
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText('本站正在使用默认设置')).toBeInTheDocument()
    expect(screen.getByText('继承默认设置')).toBeInTheDocument()
    expect(screen.getByLabelText('触发阈值')).toHaveValue('300')
    expect(screen.queryByRole('button', { name: '恢复继承默认' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '恢复最近稳定版本' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '保存策略' }))
    expect(firewallActionApi.put).toHaveBeenCalledWith('token', expect.objectContaining({ expectedRevision: 5 }))
    expect(await screen.findByText('本站自定义')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '恢复继承默认' }))
    expect(firewallActionApi.inherit).toHaveBeenCalledWith('token', expect.objectContaining({ expectedRevision: 6 }))
    expect(await screen.findByText('本站正在使用默认设置')).toBeInTheDocument()
  })

  it('says a disabled own policy is not applied', async () => {
    vi.mocked(firewallActionApi.get).mockResolvedValue({ ...policy, enabled: false, delivered: false })
    renderPage()
    expect(await screen.findByText(/本站动作策略已停用，节点不执行/)).toBeInTheDocument()
  })

  it('does not render a request failure as an empty policy', async () => {
    vi.mocked(firewallActionApi.get).mockRejectedValue(new Error('network'))
    renderPage()
    expect(await screen.findByText('防火墙动作策略加载失败')).toBeInTheDocument()
    expect(screen.queryByText('尚未配置动作策略')).not.toBeInTheDocument()
  })
})
