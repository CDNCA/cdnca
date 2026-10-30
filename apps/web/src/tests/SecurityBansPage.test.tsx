import { fireEvent, screen, waitFor, within } from '@testing-library/react'

import { AppRoutes } from '../App'
import { sitesApi, type SiteListResponse } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { getNavigation } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'
const banID = '44444444-4444-4444-8444-444444444444'
const otherSiteID = '55555555-5555-4555-8555-555555555555'

function mockSites(items: { id: string; domain: string }[]) {
  return vi.spyOn(sitesApi, 'list').mockResolvedValue({ items, total: items.length, page: 1, limit: 100 } as unknown as SiteListResponse)
}

function ban(overrides: Record<string, unknown> = {}) {
  return {
    id: banID, tenant_scope_id: tenantID, site_id: siteID, site_domain: 'shop.example.com', client_ip: '198.51.100.9',
    source: 'waf', rule_id: 'r-1', reason: '', banned_at: '2026-10-19T01:00:00Z', banned_until: '2026-10-19T02:00:00Z',
    created_by: null, released_at: null, released_by: null, state: 'active', ...overrides,
  }
}

function authenticate(scope: 'tenant' | 'platform', permissions: string[]) {
  const actor = principal({
    scope_kind: scope,
    scope_id: scope === 'platform' ? 'platform' : tenantID,
    tenant_id: scope === 'platform' ? null : tenantID,
    roles: scope === 'platform' ? ['platform_admin'] : ['tenant_owner'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('security ban list page', () => {
  it('lists bans and releases one on confirmation', async () => {
    authenticate('tenant', ['security_policies.read', 'security_policies.manage'])
    const calls: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      calls.push(`${init?.method ?? 'GET'} ${url.replace(/^https?:\/\/[^/]+/, '')}`)
      if (url.includes(`/v1/security-bans/${banID}/release`)) {
        return json(ban({ state: 'released', released_at: '2026-10-19T01:30:00Z', released_by: tenantID }))
      }
      return json({ items: [ban(), ban({ id: otherSiteID, client_ip: '2001:db8:5::/48', source: 'manual' })], total: 2, page: 1, limit: 20 })
    })
    renderWithProviders(<AppRoutes />, ['/site/security-bans'])

    expect(await screen.findByRole('heading', { name: '封禁名单' })).toBeInTheDocument()
    // A network ban is marked as such.
    const network = (await screen.findByText('2001:db8:5::/48')).closest('tr') as HTMLElement
    expect(within(network).getByText('网段')).toBeInTheDocument()
    const row = (await screen.findByText('198.51.100.9')).closest('tr') as HTMLElement
    expect(within(row).queryByText('网段')).not.toBeInTheDocument()
    expect(within(row).getByText('WAF 自动封禁')).toBeInTheDocument()
    expect(within(row).getByText('封禁中')).toBeInTheDocument()
    expect(calls).toContain('GET /v1/security-bans?page=1&limit=20&state=active')

    fireEvent.click(within(row).getByRole('button', { name: /解封/ }))
    expect(await screen.findByText(/网站 shop\.example\.com 的所有节点会立即放行/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认解封' }))
    expect(await screen.findByText('已解封 198.51.100.9，正在下发到节点')).toBeInTheDocument()
    expect(calls).toContain(`POST /v1/security-bans/${banID}/release`)
  })

  it('bans an IP through the platform route with an idempotency key; the only site is preselected', async () => {
    authenticate('platform', ['platform.admin', 'security_policies.read', 'security_policies.manage'])
    let created: { body: unknown; key: string | null } | null = null
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/v1/admin/security-bans')) {
        created = { body: JSON.parse(String(init.body)), key: new Headers(init.headers).get('Idempotency-Key') }
        return json(ban({ source: 'manual', client_ip: '2001:db8::7', reason: 'abuse' }), 201)
      }
      return json({ items: [], total: 0, page: 1, limit: 20 })
    })
    mockSites([{ id: siteID, domain: 'shop.example.com' }])
    renderWithProviders(<AppRoutes />, ['/site/security-bans'])

    expect(await screen.findByText('暂无封禁记录')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /手工封禁/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('shop.example.com')).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('客户端 IP'), { target: { value: '2001:db8::7' } })
    fireEvent.change(within(dialog).getByLabelText('原因（可选）'), { target: { value: 'abuse' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '封禁' }))
    expect(await screen.findByText('已封禁 1 条，正在下发到节点')).toBeInTheDocument()
    await waitFor(() => expect(created).not.toBeNull())
    expect(created!.body).toEqual({ site_id: siteID, client_ip: '2001:db8::7', duration_seconds: 3600, reason: 'abuse' })
    expect(created!.key).toMatch(/^security-ban-/)
  })

  it('bans several IPs on several sites and reports each failure', async () => {
    // A refused field validation stays in the form; it must not leave an unhandled rejection.
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => { unhandled.push(reason) }
    process.on('unhandledRejection', onUnhandled)
    onTestFinished(() => { process.off('unhandledRejection', onUnhandled) })
    authenticate('tenant', ['security_policies.read', 'security_policies.manage'])
    const posted: { site_id: string; client_ip: string; duration_seconds: number }[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/v1/security-bans')) {
        const body = JSON.parse(String(init.body)) as { site_id: string; client_ip: string; duration_seconds: number }
        posted.push(body)
        if (body.client_ip === '198.51.100.8' && body.site_id === otherSiteID) {
          return json({ error: { code: 'security_ban_exists', message: 'exists' } }, 409)
        }
        return json(ban({ source: 'manual', site_id: body.site_id, client_ip: body.client_ip }), 201)
      }
      return json({ items: [], total: 0, page: 1, limit: 20 })
    })
    mockSites([{ id: siteID, domain: 'shop.example.com' }, { id: otherSiteID, domain: 'blog.example.com' }])
    renderWithProviders(<AppRoutes />, ['/site/security-bans'])

    fireEvent.click(await screen.findByRole('button', { name: /手工封禁/ }))
    const dialog = await screen.findByRole('dialog')
    const select = within(dialog).getByRole('combobox', { name: '网站' })
    fireEvent.mouseDown(select)
    fireEvent.click(await screen.findByTitle('shop.example.com'))
    fireEvent.click(await screen.findByTitle('blog.example.com'))
    const ips = within(dialog).getByLabelText('客户端 IP')
    // A network wider than /8 (IPv4) or /32 (IPv6) is refused before sending.
    fireEvent.change(ips, { target: { value: '203.0.0.0/7' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '封禁' }))
    expect(await within(dialog).findByText(/网段范围过大/)).toBeInTheDocument()
    expect(posted).toHaveLength(0)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(unhandled).toEqual([])

    // A network such as /24 is one ban, not split into single addresses.
    fireEvent.change(ips, { target: { value: '198.51.100.9\n198.51.100.8, 198.51.100.9 203.0.113.0/24' } })
    expect(await within(dialog).findByText(/节点版本过低/)).toBeInTheDocument()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '封禁时长' }))
    fireEvent.click(await screen.findByTitle('1 天'))
    fireEvent.click(within(dialog).getByRole('button', { name: '封禁' }))
    expect(await screen.findByText('已封禁 5 条，失败 1 条：')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.8 · blog.example.com：该 IP 在这个网站已经处于封禁中。')).toBeInTheDocument()
    expect(posted).toHaveLength(6)
    expect(posted.filter((item) => item.client_ip === '203.0.113.0/24')).toHaveLength(2)
    expect(new Set(posted.map((item) => `${item.site_id} ${item.client_ip}`)).size).toBe(6)
    expect(posted.every((item) => item.duration_seconds === 86400)).toBe(true)
  })

  // 结果未知的封禁记下幂等键；同一请求再提交（含离开/刷新后）沿用原键，服务端按原键重放已建记录，不会误报“已处于封禁中”。
  it('resends a ban whose outcome is unknown with its original key', async () => {
    window.sessionStorage.clear()
    authenticate('tenant', ['security_policies.read', 'security_policies.manage'])
    const keys: (string | null)[] = []
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/v1/security-bans')) {
        keys.push(new Headers(init.headers).get('Idempotency-Key'))
        if (fail) throw new TypeError('network down')
        return json(ban({ source: 'manual', client_ip: '198.51.100.7' }), 201)
      }
      return json({ items: [], total: 0, page: 1, limit: 20 })
    })
    mockSites([{ id: siteID, domain: 'shop.example.com' }])
    const submit = async () => {
      fireEvent.click(await screen.findByRole('button', { name: /手工封禁/ }))
      const dialog = await screen.findByRole('dialog')
      expect(await within(dialog).findByText('shop.example.com')).toBeInTheDocument()
      fireEvent.change(within(dialog).getByLabelText('客户端 IP'), { target: { value: '198.51.100.7' } })
      fireEvent.click(within(dialog).getByRole('button', { name: '封禁' }))
    }
    const first = renderWithProviders(<AppRoutes />, ['/site/security-bans'])
    await submit()
    expect(await screen.findByText('已封禁 0 条，失败 1 条：')).toBeInTheDocument()
    first.unmount()

    fail = false
    renderWithProviders(<AppRoutes />, ['/site/security-bans'])
    await submit()
    expect(await screen.findByText('已封禁 1 条，正在下发到节点')).toBeInTheDocument()
    expect(keys).toHaveLength(2)
    expect(keys[0]).toMatch(/^security-ban-/)
    expect(keys[1]).toBe(keys[0])
    // Answered: a later ban of the same address is a new request.
    expect(window.sessionStorage.getItem('cdnca.cache-pending-writes.v1')).toBe('[]')
  })

  it('keeps the dialog and its input when every ban fails, listing each failed line', async () => {
    authenticate('tenant', ['security_policies.read', 'security_policies.manage'])
    let posts = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST' && String(input).endsWith('/v1/security-bans')) {
        posts++
        const body = JSON.parse(String(init.body)) as { client_ip: string }
        return body.client_ip === '198.51.100.7'
          ? json({ error: { code: 'security_ban_exists', message: 'exists' } }, 409)
          : json({ error: { code: 'security_ban_limit', message: 'limit' } }, 409)
      }
      return json({ items: [], total: 0, page: 1, limit: 20 })
    })
    mockSites([{ id: siteID, domain: 'shop.example.com' }])
    renderWithProviders(<AppRoutes />, ['/site/security-bans'])

    fireEvent.click(await screen.findByRole('button', { name: /手工封禁/ }))
    const dialog = await screen.findByRole('dialog')
    await waitFor(() => expect(within(dialog).getByTitle('shop.example.com')).toBeInTheDocument())
    const ips = within(dialog).getByLabelText('客户端 IP')
    fireEvent.change(ips, { target: { value: '198.51.100.7\n198.51.100.6' } })
    fireEvent.change(within(dialog).getByLabelText('原因（可选）'), { target: { value: '扫描器' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '封禁' }))

    expect(await within(dialog).findByText('已封禁 0 条，失败 2 条：')).toBeInTheDocument()
    expect(within(dialog).getByText('198.51.100.7 · shop.example.com：该 IP 在这个网站已经处于封禁中。')).toBeInTheDocument()
    expect(within(dialog).getByText(/^198\.51\.100\.6 · shop\.example\.com：/)).toBeInTheDocument()
    expect(posts).toBe(2)
    // Nothing was banned: the dialog stays open with the input and reason as typed, ready to fix and retry.
    expect(screen.getByRole('dialog')).toBe(dialog)
    expect(ips).toHaveValue('198.51.100.7\n198.51.100.6')
    expect(within(dialog).getByLabelText('原因（可选）')).toHaveValue('扫描器')
    expect(within(dialog).getByTitle('shop.example.com')).toBeInTheDocument()
  })

  it('hides writes from read-only users', async () => {
    authenticate('tenant', ['security_policies.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [ban()], total: 1, page: 1, limit: 20 }))
    renderWithProviders(<AppRoutes />, ['/site/security-bans'])

    expect(await screen.findByText('198.51.100.9')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /手工封禁/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^解封$/ })).not.toBeInTheDocument()
  })

  it('appears in the site menu for security policy readers', () => {
    for (const role of ['admin', 'user'] as const) {
      const site = getNavigation(role, undefined, ['security_policies.read']).find((item) => item.key === 'site')
      expect(site?.children?.some((item) => item.key === '/site/security-bans')).toBe(true)
      const hidden = getNavigation(role, undefined, []).find((item) => item.key === 'site')
      expect(hidden?.children?.some((item) => item.key === '/site/security-bans') ?? false).toBe(false)
    }
  })
})
