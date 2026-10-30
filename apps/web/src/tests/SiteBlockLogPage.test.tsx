import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { analyticsLogsApi } from '../api/analyticsLogs'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import SiteBlockLogPage from '../pages/SiteBlockLogPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'
const siteId = '018f0000-0000-7000-8000-000000000020'

describe('SiteBlockLogPage', () => {
  it('keeps the tabs, toolbar, and table in one competitor-style card', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [], total_count: 0, snapshot_at: '2026-09-21T02:03:05.987654321Z',
    })

    const { container } = renderWithProviders(<SiteBlockLogPage />)

    expect(await screen.findByRole('tab', { name: '当前拉黑', selected: true })).toBeInTheDocument()
    expect(container.querySelectorAll('.site-block-log-page > .analytics-panel')).toHaveLength(1)
    expect(container.querySelectorAll('.site-block-log-page .analytics-panel')).toHaveLength(1)
    expect(within(container.querySelector('.site-block-log-page > .analytics-panel') as HTMLElement)
      .getByTestId('block-state-current')).toBeInTheDocument()
  })

  it('exposes the competitor current, count, and history tabs and applies the visible filters', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const blockId = '018f0000-0000-5000-8000-000000000041'
    const policyId = '018f0000-0000-7000-8000-000000000042'
    const candidateId = '018f0000-0000-7000-8000-000000000043'
    const currentSpy = vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [{
        id: blockId, site_id: siteId, policy_id: policyId, policy_version: 7,
        tenant_id: tenantId,
        cidr: '192.0.2.10/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: true, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
      }],
      total_count: 1,
      snapshot_at: '2026-08-07T08:01:00Z',
    })
    const historySpy = vi.spyOn(analyticsLogsApi, 'listBlockHistory').mockResolvedValue({
      data: [{
        id: '018f0000-0000-5000-8000-000000000044', block_id: blockId,
        tenant_id: tenantId, site_id: siteId, policy_id: policyId, cidr: '192.0.2.10/32',
        reason_code: 'false_positive_confirmed', result_code: 'recovery_claimed',
        requested_at: '2026-08-07T08:02:00Z', unlocked_at: '2026-08-07T08:03:00Z',
        site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing', auto_unlock: false,
        edge_progress: {
          candidate_id: candidateId, state: 'healthy' as const, total_nodes: 2, ready_nodes: 2, failed_nodes: 0, superseded_nodes: 0,
        },
      }],
      total_count: 1,
      snapshot_at: '2026-08-07T08:03:00Z',
    })
    const unlockSpy = vi.spyOn(analyticsLogsApi, 'unlockCurrentBlock').mockResolvedValue({
      block_id: blockId, candidate_id: candidateId, progress: 'claimed',
      reason_code: 'recovery_claimed', replayed: false,
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    expect(await screen.findByRole('tab', { name: '当前拉黑', selected: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '拉黑统计' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '历史拉黑' })).toBeInTheDocument()
    await waitFor(() => expect(currentSpy).toHaveBeenNthCalledWith(1, expect.any(String), 'tenant', {
      limit: 10, offset: 0,
    }))

    await user.type(screen.getByPlaceholderText('请输入网站ID'), siteId)
    expect(await screen.findByText('192.0.2.10/32')).toBeInTheDocument()
    await waitFor(() => expect(currentSpy).toHaveBeenCalledWith(expect.any(String), 'tenant', {
      limit: 10, offset: 0, siteId,
    }))

    await user.click(screen.getByRole('button', { name: '解锁' }))
    expect(await screen.findByRole('dialog')).toHaveTextContent('已确认误报')
    await user.click(screen.getByRole('button', { name: '确认解锁' }))
    expect(await screen.findByText(new RegExp(candidateId))).toBeInTheDocument()
    expect(unlockSpy).toHaveBeenCalledWith(expect.any(String), 'tenant', expect.objectContaining({
      blockId, idempotencyKey: expect.stringMatching(/^unlock-/),
    }))

    await user.click(screen.getByRole('tab', { name: '历史拉黑' }))
    await waitFor(() => expect(historySpy).toHaveBeenCalledWith(expect.any(String), 'tenant', {
      limit: 10, offset: 0, siteId,
    }))
    // The applied site filter survives the tab switch, so history loads without retyping it.
    expect(await screen.findByText('手动解锁?')).toBeInTheDocument()
    expect((await screen.findAllByText('192.0.2.10/32')).length).toBeGreaterThan(0)
    // The competitor's history toolbar carries only the export button and a time range filter.
    expect(screen.queryByRole('button', { name: '解锁IP' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解锁网站' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /导出黑名单/ })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: '时间范围' })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: '选择时间范围' })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('请输入过滤器ID')).not.toBeInTheDocument()
  })

  it('filters current blocks by picking an ACL policy instead of typing its UUID (NF15)', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const policyId = '018f0000-0000-7000-8000-000000000052'
    const policySpy = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [
        { id: '018f0000-0000-7000-8000-000000000051', name: '默认拉黑', kind: 'acl' },
        { id: policyId, name: '海外拉黑', kind: 'acl' },
      ] as SecurityPolicy[],
      total: 2, page: 1, limit: 100,
    })
    const currentSpy = vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [], total_count: 0, snapshot_at: '2026-08-07T08:01:00Z',
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    expect(screen.queryByPlaceholderText('请输入过滤器ID')).not.toBeInTheDocument()
    await waitFor(() => expect(policySpy).toHaveBeenCalledWith(expect.any(String), { page: 1, limit: 100, kind: 'acl' }))
    await user.click(screen.getByRole('combobox', { name: '过滤器' }))
    await user.click(await screen.findByTitle('海外拉黑'))
    await waitFor(() => expect(currentSpy).toHaveBeenLastCalledWith(expect.any(String), 'tenant', {
      limit: 10, offset: 0, policyId,
    }))
    expect(screen.getByText('过滤器：海外拉黑')).toBeInTheDocument()
  })

  it('keeps the filter ID input when the user cannot list security policies', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const policySpy = vi.spyOn(securityPoliciesApi, 'list')
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [], total_count: 0, snapshot_at: '2026-08-07T08:01:00Z',
    })
    renderWithProviders(<SiteBlockLogPage />)

    expect(await screen.findByPlaceholderText('请输入过滤器ID')).toBeInTheDocument()
    expect(policySpy).not.toHaveBeenCalled()
  })

  it('loads history without a site filter, as the competitor does on mount', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const historySpy = vi.spyOn(analyticsLogsApi, 'listBlockHistory').mockResolvedValue({
      data: [], total_count: 0, snapshot_at: '2026-08-07T08:03:00Z',
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    await user.click(await screen.findByRole('tab', { name: '历史拉黑' }))
    await waitFor(() => expect(historySpy).toHaveBeenCalledWith(expect.any(String), 'tenant', {
      limit: 10, offset: 0,
    }))
 
    // fix-rangepicker：快捷项按秒、两端都含（今天 00:00:00 ~ 23:59:59）；清空后不带窗口。
    vi.useFakeTimers({ toFake: ['Date'], now: new Date(2026, 9, 28, 10, 20, 30) })
    await user.click(screen.getByText('今天'))
    await waitFor(() => expect(historySpy).toHaveBeenLastCalledWith(expect.any(String), 'tenant', {
      limit: 10, offset: 0, start: new Date(2026, 9, 28).getTime() / 1000, end: new Date(2026, 9, 28, 23, 59, 59).getTime() / 1000,
    }))
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    await user.click(screen.getByRole('button', { name: '清空' }))
    await waitFor(() => expect(historySpy).toHaveBeenLastCalledWith(expect.any(String), 'tenant', { limit: 10, offset: 0 }))
    vi.useRealTimers()
  })

  it('lists CC auto-banned IPs in their own tab (NF34)', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({ data: [], total_count: 0, snapshot_at: '2026-08-07T08:03:00Z' })
    const banSpy = vi.spyOn(analyticsLogsApi, 'listCCBans').mockResolvedValue({
      data: [{
        site_id: siteId, host: 'a.example.test', client_ip: '192.0.2.9', rule_id: '018f1000-0000-7000-8000-000000000026',
        ban_count: 3, first_banned_at: '2026-08-07T07:00:00Z', last_banned_at: '2026-08-07T08:00:00Z',
      }],
      truncated: false,
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    await user.click(await screen.findByRole('tab', { name: 'CC 自动封禁' }))
    expect(await screen.findByText('192.0.2.9')).toBeInTheDocument()
    expect(screen.getByText('a.example.test')).toBeInTheDocument()
    expect(within(screen.getByTestId('block-state-cc-bans')).getByText('3')).toBeInTheDocument()
    expect(banSpy).toHaveBeenCalledWith(expect.any(String), 'tenant', expect.objectContaining({ from: expect.any(String), to: expect.any(String) }))

    await user.type(screen.getByPlaceholderText('请输入IP地址'), '192.0.2.9')
    await user.click(screen.getByRole('button', { name: '搜索' }))
    await waitFor(() => expect(banSpy).toHaveBeenLastCalledWith(expect.any(String), 'tenant',
      expect.objectContaining({ clientIp: '192.0.2.9' })))
  })

  // stats-platform-l7：CC 自动封禁进入即列全平台，租户只作可选筛选。
  it('lists every tenant\'s CC auto-bans on entry and narrows to a picked tenant (NF34)', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      permissions: ['sites.read', 'platform.admin', 'identity.users.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({ data: [], total_count: 0, snapshot_at: '2026-08-07T08:03:00Z' })
    const lookup = vi.spyOn(usersApi, 'list').mockResolvedValue({
      items: [{
        id: '018f0000-0000-7000-8000-000000000030', display_id: '27', scope_id: '018f0000-0000-7000-8000-000000000031',
        tenant_id: tenantId, username: 'tenant-a', display_name: 'Tenant A', email: null, phone: null,
        status: 'active', role: 'tenant_owner', group_id: null, group_name: null, revision: 1,
        created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z',
      }],
      total: 1, page: 1, limit: 20,
    })
    const banSpy = vi.spyOn(analyticsLogsApi, 'listCCBans').mockResolvedValue({
      data: [{
        site_id: siteId, host: 'a.example.test', client_ip: '192.0.2.9', rule_id: '018f1000-0000-7000-8000-000000000026',
        ban_count: 2, first_banned_at: '2026-08-07T07:00:00Z', last_banned_at: '2026-08-07T08:00:00Z',
      }],
      truncated: false,
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    await user.click(await screen.findByRole('tab', { name: 'CC 自动封禁' }))
    expect(await screen.findByText('192.0.2.9')).toBeInTheDocument()
    expect(banSpy).toHaveBeenCalledTimes(1)
    expect(banSpy.mock.calls[0][2]).not.toHaveProperty('tenantId')
    expect(screen.queryByText('请先选择租户再查询。')).not.toBeInTheDocument()
    await waitFor(() => expect(lookup).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ role: 'tenant_owner' })))

    await user.click(screen.getByRole('combobox', { name: '租户' }))
    await user.click(await screen.findByText('tenant-a（27）'))
    await waitFor(() => expect(banSpy).toHaveBeenCalledWith(expect.any(String), 'admin', expect.objectContaining({ tenantId })))
  })

  it('falls back to a tenant ID input for admins without user management (NF34)', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null, permissions: ['sites.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({ data: [], total_count: 0, snapshot_at: '2026-08-07T08:03:00Z' })
    const lookup = vi.spyOn(usersApi, 'list')
    const banSpy = vi.spyOn(analyticsLogsApi, 'listCCBans').mockResolvedValue({ data: [], truncated: false })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    await user.click(await screen.findByRole('tab', { name: 'CC 自动封禁' }))
    await waitFor(() => expect(banSpy).toHaveBeenCalledTimes(1))
    expect(banSpy.mock.calls[0][2]).not.toHaveProperty('tenantId')
    await user.type(screen.getByRole('textbox', { name: '租户 ID' }), 'not-a-uuid')
    await user.click(screen.getByRole('button', { name: '搜索' }))
    expect(await screen.findByText('请输入有效的非零小写 UUID。')).toBeInTheDocument()
    expect(banSpy).toHaveBeenCalledTimes(1)
    await user.clear(screen.getByRole('textbox', { name: '租户 ID' }))
    await user.type(screen.getByRole('textbox', { name: '租户 ID' }), tenantId)
    await user.click(screen.getByRole('button', { name: '搜索' }))
    await waitFor(() => expect(banSpy).toHaveBeenCalledWith(expect.any(String), 'admin', expect.objectContaining({ tenantId })))
    expect(lookup).not.toHaveBeenCalled()
  })

  it('matches the admin reference without a tenant filter and keeps row unlock tenant-scoped', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      permissions: ['sites.read', 'platform.admin', 'security_policies.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const blockId = '018f0000-0000-5000-8000-000000000041'
    const currentSpy = vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [{
        id: blockId, tenant_id: tenantId, site_id: siteId,
        policy_id: '018f0000-0000-7000-8000-000000000042', policy_version: 7,
        cidr: '192.0.2.10/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: true, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
      }],
      total_count: 1, snapshot_at: '2026-08-07T08:01:00Z',
    })
    const unlockSpy = vi.spyOn(analyticsLogsApi, 'unlockCurrentBlock').mockResolvedValue({
      block_id: blockId, candidate_id: '018f0000-0000-7000-8000-000000000043', progress: 'claimed',
      reason_code: 'recovery_claimed', replayed: false,
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    await waitFor(() => expect(currentSpy).toHaveBeenCalledWith(expect.any(String), 'admin', {
      limit: 10, offset: 0,
    }))
    expect(screen.queryByLabelText('租户 ID')).not.toBeInTheDocument()
    expect(await screen.findByText('192.0.2.10/32')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '解锁' }))
    await user.click(await screen.findByRole('button', { name: '确认解锁' }))
    expect(unlockSpy).toHaveBeenCalledWith(expect.any(String), 'admin', expect.objectContaining({
      blockId, tenantId,
    }))
  })

  it('fails closed when an admin site display ID belongs to more than one tenant', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      permissions: ['sites.read', 'platform.admin', 'security_policies.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const otherTenantId = '018f0000-0000-7000-8000-000000000011'
    const otherSiteId = '018f0000-0000-7000-8000-000000000021'
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [
        {
          id: '018f0000-0000-5000-8000-000000000041', tenant_id: tenantId, site_id: siteId,
          policy_id: '018f0000-0000-7000-8000-000000000042', policy_version: 7,
          cidr: '192.0.2.10/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
          unlockable: true, site_display_id: 42, domain: 'one.example.test', position: 'CN-Beijing',
        },
        {
          id: '018f0000-0000-5000-8000-000000000045', tenant_id: otherTenantId, site_id: otherSiteId,
          policy_id: '018f0000-0000-7000-8000-000000000046', policy_version: 3,
          cidr: '198.51.100.20/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:04:00Z',
          unlockable: true, site_display_id: 42, domain: 'two.example.test', position: 'CN-Shanghai',
        },
      ],
      total_count: 2, snapshot_at: '2026-08-07T08:05:00Z',
    })
    const unlockSpy = vi.spyOn(analyticsLogsApi, 'unlockCurrentBlock')
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    expect(await screen.findByText('192.0.2.10/32')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '解锁网站' }))
    await user.type(within(await screen.findByRole('dialog')).getByPlaceholderText('请输入网站ID'), '42')
    await user.click(screen.getByRole('button', { name: '确认解锁' }))

    expect(await screen.findByText('该网站 ID 在多个租户中重复，无法安全批量解锁。')).toBeInTheDocument()
    expect(unlockSpy).not.toHaveBeenCalled()
  })

  it('shows the unlock edge progress in place: failed and ignored-old-release nodes (fix-tails1028)', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const candidateId = '018f0000-0000-7000-8000-000000000063'
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [{
        id: '018f0000-0000-5000-8000-000000000061', site_id: siteId,
        policy_id: '018f0000-0000-7000-8000-000000000062', policy_version: 7, tenant_id: tenantId,
        cidr: '192.0.2.20/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: false, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
        edge_progress: {
          candidate_id: candidateId, state: 'expanding', total_nodes: 5, ready_nodes: 2, failed_nodes: 1,
          superseded_nodes: 1,
        },
      }, {
        id: '018f0000-0000-5000-8000-000000000064', site_id: siteId,
        policy_id: '018f0000-0000-7000-8000-000000000062', policy_version: 7, tenant_id: tenantId,
        cidr: '192.0.2.21/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: true, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
      }],
      total_count: 2, snapshot_at: '2026-08-07T08:01:00Z',
    })
    const historySpy = vi.spyOn(analyticsLogsApi, 'listBlockHistory').mockResolvedValue({
      data: [{
        id: '018f0000-0000-5000-8000-000000000065', block_id: '018f0000-0000-5000-8000-000000000061',
        tenant_id: tenantId, site_id: siteId, policy_id: '018f0000-0000-7000-8000-000000000062',
        cidr: '192.0.2.20/32', reason_code: 'false_positive_confirmed', result_code: 'recovery_claimed',
        requested_at: '2026-08-07T08:02:00Z', unlocked_at: null,
        site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing', auto_unlock: false,
        edge_progress: {
          candidate_id: candidateId, state: 'failed', total_nodes: 3, ready_nodes: 1, failed_nodes: 2,
          superseded_nodes: 0,
        },
      }],
      total_count: 1, snapshot_at: '2026-08-07T08:03:00Z',
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    const progress = await screen.findByTestId('block-edge-progress')
    expect(progress).toHaveTextContent('扩展中')
    expect(progress).toHaveTextContent('就绪 2/5')
    expect(progress).toHaveTextContent('失败 1')
    expect(progress).toHaveTextContent('已忽略旧发布 1')
    // A row without an unlock in flight keeps the competitor's empty cell.
    expect(screen.getAllByTestId('block-edge-progress')).toHaveLength(1)

    await user.click(screen.getByRole('tab', { name: '历史拉黑' }))
    await waitFor(() => expect(historySpy).toHaveBeenCalled())
    const history = await screen.findByTestId('block-edge-progress')
    expect(history).toHaveTextContent('失败')
    expect(history).toHaveTextContent('就绪 1/3')
    expect(history).toHaveTextContent('失败 2')
    // No ignored-old-release fragment when none ignored it.
    expect(history).not.toHaveTextContent('已忽略旧发布')
  })

  it('W4 tells the user to select records first when unlocking without a selection', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(analyticsLogsApi, 'listCurrentBlocks').mockResolvedValue({
      data: [{
        id: '018f0000-0000-5000-8000-000000000041', site_id: siteId,
        policy_id: '018f0000-0000-7000-8000-000000000042', policy_version: 7, tenant_id: tenantId,
        cidr: '192.0.2.10/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: true, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
      }],
      total_count: 1, snapshot_at: '2026-08-07T08:01:00Z',
    })
    const unlockSpy = vi.spyOn(analyticsLogsApi, 'unlockCurrentBlock')
    const user = userEvent.setup()
    renderWithProviders(<SiteBlockLogPage />)

    expect(await screen.findByText('192.0.2.10/32')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '解锁IP' }))
    expect(await screen.findByText('请先选择要解锁的记录')).toBeInTheDocument()
    expect(unlockSpy).not.toHaveBeenCalled()

    const checkboxes = screen.getAllByRole('checkbox')
    await user.click(checkboxes[checkboxes.length - 1]!)
    expect(screen.queryByText('请先选择要解锁的记录')).not.toBeInTheDocument()
  })
})
