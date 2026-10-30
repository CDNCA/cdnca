import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, vi } from 'vitest'

import { ApiError, type Principal } from '../../api/auth'
import { dnsApi, type DNSProvider } from '../../api/dns'
import { dnsHubApi, type DNSHubAccount, type DNSHubDomain, type DNSHubRecord } from '../../api/dnsHub'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { getNavigation, isImplementedPath } from '../../routes/navigation'
import { authResponse, principal } from '../../test/fixtures'
import DnsHubPage from './DnsHubPage'

const aliyunID = '11111111-1111-4111-8111-111111111111'
const cfID = '33333333-3333-4333-8333-333333333333'
const provider = (id: string, name: string, type: string, extra: Partial<DNSProvider> = {}): DNSProvider => ({
  id, scope_id: '22222222-2222-4222-8222-222222222222', name, provider_type: type, credentials_configured: true,
  status: 'verified', managed_by: 'tenant', version: 1, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', ...extra,
})
const domainA: DNSHubDomain = { provider_id: aliyunID, provider_name: '主账号', provider_type: 'aliyun', apex: 'shop.example', record_count: 2, last_listed_at: '2026-10-29T01:00:00Z' }
const domainB: DNSHubDomain = { provider_id: cfID, provider_name: '海外 CF', provider_type: 'cloudflare', apex: 'blog.example', record_count: 1, list_error: 'credentials_rejected' }
const siteRecord: DNSHubRecord = { record_ref: 'r-www', name: 'www', fqdn: 'www.shop.example', type: 'CNAME', value: 'abc.cdnca.com', ttl: 600, line: '默认', weight: 0, managed: { kind: 'site_cname', site_id: '55555555-5555-4555-8555-555555555555', site_domain: 'shop.example' } }
const plainRecord: DNSHubRecord = { record_ref: 'r-mail', name: 'mail', fqdn: 'mail.shop.example', type: 'A', value: '192.0.2.10', ttl: 600, line: '电信', weight: 0, managed: null }
const account = (id: string, name: string, type: string, lines: string[]): DNSHubAccount => ({
  provider_id: id, name, provider_type: type, status: 'verified', last_listed_at: null, list_error: '', domain_count: 1,
  supported_lines: lines, supports_weight: false, record_types: ['A', 'AAAA', 'CNAME', 'TXT'],
})
const accounts = [account(aliyunID, '主账号', 'aliyun', ['默认', '电信', '联通', '移动', '境外']), account(cfID, '海外 CF', 'cloudflare', ['默认'])]

function authenticate(actor: Principal) {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'hub-token' }, actor, 'new')
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp><QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/site/dns-hub']}><DnsHubPage /></MemoryRouter>
      </QueryClientProvider></AntApp>
    </ConfigProvider>,
  )
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [
    provider(aliyunID, '主账号', 'aliyun'),
    provider(cfID, '海外 CF', 'cloudflare'),
    provider('44444444-4444-4444-8444-444444444444', '平台副本', 'aliyun', { managed_by: 'platform' }),
  ] })
  vi.spyOn(dnsHubApi, 'domains').mockResolvedValue({ accounts, items: [domainA, domainB], next_cursor: '' })
  vi.spyOn(dnsHubApi, 'records').mockResolvedValue({ provider_id: aliyunID, apex: 'shop.example', skipped: 2, items: [siteRecord, plainRecord] })
})

afterEach(() => {
  vi.restoreAllMocks()
  useSessionStore.getState().clearSession()
})

describe('DnsHubPage (ADR 0020 §3.4)', () => {
  it('is a tenant-only menu entry gated by dns.read', () => {
    const userSite = getNavigation('user').find((item) => item.key === 'site')?.children?.map((item) => item.key)
    const adminSite = getNavigation('admin').find((item) => item.key === 'site')?.children?.map((item) => item.key)
    expect(userSite).toContain('/site/dns-hub')
    expect(adminSite).not.toContain('/site/dns-hub')
    expect(isImplementedPath('user', '/site/dns-hub', ['dns.read'])).toBe(true)
    expect(isImplementedPath('user', '/site/dns-hub', [])).toBe(false)
  })

  it('refuses platform sessions and tenants without dns.read', () => {
    authenticate(principal({ scope_kind: 'platform', tenant_id: null, permissions: ['platform.admin', 'dns.read'] }))
    const { unmount } = renderPage()
    expect(screen.getByText('无权查看域名解析')).toBeInTheDocument()
    unmount()
    authenticate(principal({ permissions: [] }))
    renderPage()
    expect(screen.getByText('无权查看域名解析')).toBeInTheDocument()
    expect(dnsHubApi.domains).not.toHaveBeenCalled()
  })

  it('points to the DNS API page when the tenant has no own account', async () => {
    vi.mocked(dnsApi.list).mockResolvedValue({ items: [provider(aliyunID, '平台副本', 'aliyun', { managed_by: 'platform' })] })
    authenticate(principal({ permissions: ['dns.read', 'dns.manage'] }))
    renderPage()
    expect(await screen.findByText('还没有 DNS 账号')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '去添加 DNS 账号' })).toBeInTheDocument()
    expect(dnsHubApi.domains).not.toHaveBeenCalled()
  })

  it('lists own accounts only, filters domains by account and shows live records with the managed mark', async () => {
    const user = userEvent.setup()
    authenticate(principal({ permissions: ['dns.read', 'dns.manage'] }))
    renderPage()
    const accounts = await screen.findByRole('navigation', { name: 'DNS 账号' })
    expect(within(accounts).queryByText('平台副本')).not.toBeInTheDocument()
    expect(await screen.findByText('blog.example')).toBeInTheDocument()
    expect(screen.getByText(/上次刷新失败：DNS 账号凭据无效/)).toBeInTheDocument()

    await user.click(within(accounts).getByRole('button', { name: /海外 CF/ }))
    await waitFor(() => expect(dnsHubApi.domains).toHaveBeenLastCalledWith('hub-token', expect.objectContaining({ provider_id: cfID })))

    await user.click(screen.getByRole('button', { name: /shop\.example/ }))
    expect(await screen.findByText('abc.cdnca.com')).toBeInTheDocument()
    expect(dnsHubApi.records).toHaveBeenCalledWith('hub-token', aliyunID, 'shop.example')
    expect(screen.getByText('本平台在用')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument()
    expect(screen.getByText(/另有 2 条记录/)).toBeInTheDocument()
  })

  it('requires acknowledging the impact before changing a platform-managed record', async () => {
    const user = userEvent.setup()
    const update = vi.spyOn(dnsHubApi, 'update').mockResolvedValue({ op_id: 'op', state: 'applied', record: null })
    authenticate(principal({ permissions: ['dns.read', 'dns.manage'] }))
    renderPage()
    await user.click(await screen.findByRole('button', { name: /shop\.example/ }))
    await user.click(await screen.findByRole('button', { name: '修改 www CNAME' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/网站 shop\.example 的 CNAME 接入/)).toBeInTheDocument()
    const save = within(dialog).getByRole('button', { name: '保存' })
    expect(save).toBeDisabled()
    await user.click(within(dialog).getByRole('checkbox', { name: '我已了解影响，仍要继续' }))
    expect(save).toBeEnabled()
    await user.click(save)
    await waitFor(() => expect(update).toHaveBeenCalledWith('hub-token', aliyunID, 'shop.example', siteRecord,
      { name: 'www', type: 'CNAME', value: 'abc.cdnca.com', ttl: 600, line: '默认', weight: 0 }, true, expect.stringMatching(/^dns-hub-update-/)))
  })

  it('reloads the records when the provider reports a concurrent change', async () => {
    const user = userEvent.setup()
    vi.spyOn(dnsHubApi, 'update').mockRejectedValue(new ApiError('changed', 409, 'dns_record_changed'))
    authenticate(principal({ permissions: ['dns.read', 'dns.manage'] }))
    renderPage()
    await user.click(await screen.findByRole('button', { name: /shop\.example/ }))
    await user.click(await screen.findByRole('button', { name: '修改 mail A' }))
    const dialog = await screen.findByRole('dialog')
    const value = within(dialog).getByDisplayValue('192.0.2.10')
    await user.clear(value)
    await user.type(value, '192.0.2.11')
    const callsBefore = vi.mocked(dnsHubApi.records).mock.calls.length
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await screen.findByText(/刚被其他人或其他程序修改过/)).toBeInTheDocument()
    await waitFor(() => expect(vi.mocked(dnsHubApi.records).mock.calls.length).toBeGreaterThan(callsBefore))
  })

  it('validates the record value by type before writing', async () => {
    const user = userEvent.setup()
    const create = vi.spyOn(dnsHubApi, 'create')
    authenticate(principal({ permissions: ['dns.read', 'dns.manage'] }))
    renderPage()
    await user.click(await screen.findByRole('button', { name: /shop\.example/ }))
    await screen.findByText('abc.cdnca.com')
    await user.click(screen.getByRole('button', { name: '添加记录' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('主机记录'), 'api')
    await user.type(within(dialog).getByLabelText('记录值'), '999.1.1.1')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('请输入有效的 IPv4 地址')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
  })

  it('is read-only without dns.manage', async () => {
    const user = userEvent.setup()
    authenticate(principal({ permissions: ['dns.read'] }))
    renderPage()
    expect(await screen.findByText(/只能查看/)).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: /shop\.example/ }))
    await screen.findByText('abc.cdnca.com')
    expect(screen.queryByRole('button', { name: '添加记录' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^修改/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: 'shop.example' })).not.toBeInTheDocument()
  })

  it('runs a batch TTL change on the selected domains and shows per-domain results', async () => {
    const user = userEvent.setup()
    const blogRecord: DNSHubRecord = { ...plainRecord, record_ref: 'r-blog', fqdn: 'mail.blog.example', line: '默认' }
    vi.mocked(dnsHubApi.records).mockImplementation(async (_token, providerID, apex) => providerID === cfID
      ? { provider_id: cfID, apex, skipped: 0, items: [blogRecord] }
      : { provider_id: aliyunID, apex, skipped: 0, items: [siteRecord, plainRecord] })
    const batch = vi.spyOn(dnsHubApi, 'batch').mockResolvedValue({ results: [
      { index: 0, status: 200, op_id: 'op-1', state: 'applied', record: null, error: null },
      { index: 1, status: 502, error: { code: 'dns_provider_error', provider_code: 'credentials_rejected' } },
    ] })
    authenticate(principal({ permissions: ['dns.read', 'dns.manage'] }))
    renderPage()
    await user.click(await screen.findByRole('checkbox', { name: 'shop.example' }))
    await user.click(screen.getByRole('checkbox', { name: 'blog.example' }))
    await user.click(screen.getByRole('button', { name: /批量操作/ }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByText('批量修改 TTL'))
    const ttl = within(dialog).getByLabelText('TTL（秒）')
    await user.clear(ttl)
    await user.type(ttl, '300')
    await user.click(within(dialog).getByRole('button', { name: '执行' }))
    // 本平台在用的 www CNAME 不进批量；每个域名的普通记录各一条 update，expected 为改前值
    const value = (record: DNSHubRecord) => ({ name: record.name, type: record.type, value: record.value, ttl: record.ttl, line: record.line, weight: record.weight })
    await waitFor(() => expect(batch).toHaveBeenCalledWith('hub-token', [
      { provider_id: aliyunID, apex: 'shop.example', action: 'update', record_ref: 'r-mail', ...value(plainRecord), ttl: 300, expected: value(plainRecord) },
      { provider_id: cfID, apex: 'blog.example', action: 'update', record_ref: 'r-blog', ...value(blogRecord), ttl: 300, expected: value(blogRecord) },
    ], expect.stringMatching(/^dns-hub-batch-.+\.c0$/)))
    expect(await within(dialog).findByText('成功 1，失败 1，待确认 0，跳过 0')).toBeInTheDocument()
    expect(within(dialog).getByText('改动 1 条')).toBeInTheDocument()
    expect(within(dialog).getByText(/DNS 账号凭据无效/)).toBeInTheDocument()
  })
})
