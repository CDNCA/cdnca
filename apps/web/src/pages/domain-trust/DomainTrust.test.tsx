import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { domainBlocklistApi, domainOwnershipApi, type DomainOwnership } from '../../api/domainTrust'
import { sitesApi } from '../../api/sites'
import { systemOtherSettingsApi } from '../../api/systemOtherSettings'
import { useSessionStore } from '../../auth/session'
import SystemGlobalSettingsPage from '../SystemGlobalSettingsPage'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { DomainOwnershipPanel } from './DomainOwnershipPanel'
import AccountDomainsPage from './AccountDomainsPage'
import DomainSecurityPage from './DomainSecurityPage'

function signIn(kind: 'platform' | 'tenant', permissions: string[]) {
  const actor = principal({ scope_kind: kind, ...(kind === 'platform' ? { tenant_id: null, roles: ['platform_owner'] } : {}), permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

const pending: DomainOwnership = {
  id: 'o1', scope_id: 's1', apex: 'example.com', method: 'dns_txt', status: 'pending', token: 'a'.repeat(48),
  txt_name: '_cdnca-verify.example.com', http_url: 'http://example.com/.well-known/cdnca-verify/x',
  last_failure_code: '', created_at: '2026-10-17T00:00:00Z', updated_at: '2026-10-17T00:00:00Z', revision: 1,
}

afterEach(() => { vi.restoreAllMocks() })

describe('domain ownership policy setting', () => {
  it('shows the three levels with wildcard_only selected and saves the chosen one', async () => {
    signIn('platform', ['system_configuration.read', 'system_configuration.manage'])
    const value = { source_ip_header: 'X-Real-IP', api_key_enabled: true, dns_protection: '', record_repair_mode: 'repair' as const, sync_batch: 1000,
      sync_scope: 'line_group' as const, disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1,
      l4_drain_max_seconds: 86400, domain_ownership_policy: 'wildcard_only' as const, certificate_expiry_notice_days: [30, 14, 7, 3, 1], rule_intel_contribution: true }
    vi.spyOn(systemOtherSettingsApi, 'get').mockResolvedValue({ schema: 'cdnca.platform-system-other-settings/v1', revision: 3, value })
    const put = vi.spyOn(systemOtherSettingsApi, 'put').mockResolvedValue({ schema: 'cdnca.platform-system-other-settings/v1', revision: 4, value: { ...value, domain_ownership_policy: 'all' } })
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    expect(await screen.findByRole('radio', { name: '只验通配符' })).toBeChecked()
    expect(screen.getByRole('radio', { name: '不验证' })).not.toBeChecked()
    // Radio.Button: the visible button is the label; its input has pointer-events: none.
    await user.click(screen.getByRole('radio', { name: '全部验证' }).closest('label')!)
    expect(screen.getByRole('radio', { name: '全部验证' })).toBeChecked()
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), 3,
      expect.objectContaining({ domain_ownership_policy: 'all' }), expect.any(String), expect.any(String)))
  })
})

describe('other settings grouped layout (fix-sysother)', () => {
  it('shows the summary, moves long hints behind (?) and blocks saving invalid notice days', async () => {
    signIn('platform', ['system_configuration.read', 'system_configuration.manage'])
    const value = { source_ip_header: 'X-Real-IP', api_key_enabled: false, dns_protection: '', record_repair_mode: 'repair' as const, sync_batch: 1000,
      sync_scope: 'line_group' as const, disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1,
      l4_drain_max_seconds: 86400, domain_ownership_policy: 'wildcard_only' as const, certificate_expiry_notice_days: [30, 14, 7, 3, 1], rule_intel_contribution: true }
    vi.spyOn(systemOtherSettingsApi, 'get').mockResolvedValue({ schema: 'cdnca.platform-system-other-settings/v1', revision: 3, value })
    const put = vi.spyOn(systemOtherSettingsApi, 'put')
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    const summary = await screen.findByRole('navigation', { name: '当前生效' })
    expect(summary).toHaveTextContent('按线路组 · 每批 1000 个')
    expect(summary).toHaveTextContent('提前 30/14/7/3/1 天')
    expect(screen.getByRole('heading', { name: '域名与证书' })).toBeInTheDocument()
    expect(screen.queryByText(/仅用于 DNS API 请求/)).toBeNull()
    expect(screen.getByRole('button', { name: 'http代理说明' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '验证策略说明' })).toBeInTheDocument()
    const days = screen.getByRole('textbox', { name: '提前提醒天数' })
    await user.clear(days)
    await user.type(days, '0 99')
    expect(screen.getAllByText('提醒天数格式不正确，修正后才能保存').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    expect(put).not.toHaveBeenCalled()
  })
})

describe('DomainOwnershipPanel', () => {
  it('shows the TXT record, reports a failed check, then verifies and claims a conflict', async () => {
    signIn('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(domainOwnershipApi, 'start').mockResolvedValue(pending)
    const check = vi.spyOn(domainOwnershipApi, 'check')
      .mockResolvedValueOnce({ ...pending, last_failure_code: 'txt_not_found', revision: 2 })
      .mockResolvedValueOnce({ ...pending, status: 'verified', revision: 3 })
    vi.spyOn(domainOwnershipApi, 'conflicts').mockResolvedValue([{ domain: 'www.example.com', site_count: 1, claimable: true }])
    const claim = vi.spyOn(domainOwnershipApi, 'claim').mockResolvedValue({ apex: 'example.com', domains: ['www.example.com'], suspended_sites: 1, notifications_sent: 2, notifications_failed: 0 })
    const verified = vi.fn()
    const user = userEvent.setup()
    renderWithProviders(<DomainOwnershipPanel domain="*.example.com" onVerified={verified} />)
    await user.click(screen.getByRole('button', { name: '获取验证信息' }))
    expect(await screen.findByText('_cdnca-verify.example.com')).toBeInTheDocument()
    expect(screen.getByText('a'.repeat(48))).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /立即检查/ }))
    expect(await screen.findByText('还未检测到：没有找到匹配的 TXT 记录')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /立即检查/ }))
    await waitFor(() => expect(verified).toHaveBeenCalled())
    expect(check).toHaveBeenCalledTimes(2)
    expect(await screen.findByText('www.example.com')).toBeInTheDocument()
    await user.click(screen.getAllByRole('checkbox')[1])
    await user.click(screen.getByRole('button', { name: '认领所选域名' }))
    await waitFor(() => expect(claim).toHaveBeenCalledWith(expect.any(String), 'example.com', ['www.example.com'], expect.stringMatching(/^domain-claim-/)))
  })

  it('maps a domain held by another account to its message', async () => {
    signIn('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(domainOwnershipApi, 'start').mockRejectedValue(new ApiError('x', 409, 'domain_verified_by_other'))
    const user = userEvent.setup()
    renderWithProviders(<DomainOwnershipPanel domain="example.com" />)
    await user.click(screen.getByRole('button', { name: '获取验证信息' }))
    expect(await screen.findByText('该根域名的所有权已被其他账户验证')).toBeInTheDocument()
  })
})

describe('DomainSecurityPage', () => {
  it('refuses non-platform sessions', () => {
    signIn('tenant', ['sites.manage'])
    renderWithProviders(<DomainSecurityPage />)
    expect(screen.getByText('需要域名安全管理权限')).toBeInTheDocument()
  })

  it('lists blocklist entries and disables selected hit sites through the site batch action', async () => {
    signIn('platform', ['domains.security.manage', 'sites.manage'])
    vi.spyOn(domainBlocklistApi, 'list').mockResolvedValue([{ id: 'b1', pattern: 'evil.test', match_type: 'root', reason: 'phishing', created_at: '2026-10-17T00:00:00Z', updated_at: '2026-10-17T00:00:00Z', revision: 1 }])
    vi.spyOn(domainBlocklistApi, 'hits').mockResolvedValue([
      { site_id: 'site-1', scope_id: 's1', display_id: 7, domain: 'www.evil.test', pattern: 'evil.test', enabled: true, revision: 4, owner_user_id: 'u1' },
    ])
    const batch = vi.spyOn(sitesApi, 'batchAction').mockResolvedValue({ items: [{ id: 'site-1', status: 'updated', site: {} as never }] })
    const user = userEvent.setup()
    renderWithProviders(<DomainSecurityPage />)
    expect(await screen.findByText('evil.test')).toBeInTheDocument()
    expect(screen.getByText('根域名（含全部子域）')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '命中站点' }))
    expect(await screen.findByText('www.evil.test')).toBeInTheDocument()
    await user.click(screen.getAllByRole('checkbox')[1])
    await user.click(screen.getByRole('button', { name: '一键停用所选' }))
    await waitFor(() => expect(batch).toHaveBeenCalledWith(expect.any(String),
      { action: 'disable', items: [{ id: 'site-1', expected_version: 4 }] }, expect.stringMatching(/^blocklist-disable-/)))
  })
})

describe('AccountDomainsPage', () => {
  it('runs the check from the list row and shows the result in the row (W7)', async () => {
    signIn('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(domainOwnershipApi, 'list').mockResolvedValue([pending])
    vi.spyOn(domainOwnershipApi, 'suspensions').mockResolvedValue([])
    const start = vi.spyOn(domainOwnershipApi, 'start')
    const check = vi.spyOn(domainOwnershipApi, 'check').mockResolvedValue({ ...pending, last_failure_code: 'txt_not_found', revision: 2 })
    const user = userEvent.setup()
    renderWithProviders(<AccountDomainsPage />)
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '立即检查' }))
    await waitFor(() => expect(check).toHaveBeenCalledWith(expect.any(String), 'example.com'))
    expect(await screen.findAllByText('还未检测到：没有找到匹配的 TXT 记录')).not.toHaveLength(0)
    expect(screen.getByText('_cdnca-verify.example.com')).toBeInTheDocument()
    expect(start).not.toHaveBeenCalled()
  })
})
