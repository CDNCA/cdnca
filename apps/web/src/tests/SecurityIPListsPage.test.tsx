import { fireEvent, screen, waitFor, within } from '@testing-library/react'

import { AppRoutes } from '../App'
import { parseIPListEntries } from '../api/securityIPLists'
import { useSessionStore } from '../auth/session'
import { getNavigation } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantID = '22222222-2222-4222-8222-222222222222'
const ownID = '55555555-5555-4555-8555-555555555555'
const platformID = '66666666-6666-4666-8666-666666666666'

function list(overrides: Record<string, unknown> = {}) {
  return {
    id: ownID, name: 'office', description: 'HQ', entries: ['192.0.2.0/24', '198.51.100.9/32'], revision: 2,
    platform: false, updated_at: '2026-10-21T01:00:00Z', ...overrides,
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

describe('ge36-waf W2 IP list page', () => {
  it('lists own and platform lists; edits an own list with its revision and an idempotency key', async () => {
    authenticate('tenant', ['security_policies.read', 'security_policies.manage'])
    let updated: { body: unknown; key: string | null } | null = null
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'PUT' && url.endsWith(`/v1/security-ip-lists/${ownID}`)) {
        updated = { body: JSON.parse(String(init.body)), key: new Headers(init.headers).get('Idempotency-Key') }
        return json(list({ entries: ['10.0.0.0/8'], revision: 3 }))
      }
      return json({ items: [list(), list({ id: platformID, name: 'scanners', platform: true, revision: 7 })] })
    })
    renderWithProviders(<AppRoutes />, ['/site/ip-lists'])

    expect(await screen.findByRole('heading', { name: 'IP 名单' })).toBeInTheDocument()
    const own = (await screen.findByText('office')).closest('tr') as HTMLElement
    const shared = screen.getByText('scanners').closest('tr') as HTMLElement
    expect(within(own).getByText('本账号')).toBeInTheDocument()
    expect(within(shared).getByText('平台')).toBeInTheDocument()
    expect(within(shared).queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument()

    fireEvent.click(within(own).getByRole('button', { name: /编辑/ }))
    const entries = await screen.findByLabelText('地址与网段')
    expect(entries).toHaveValue('192.0.2.0/24\n198.51.100.9/32')
    fireEvent.change(entries, { target: { value: '10.0.0.0/8 # lab' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText(/已保存名单“office”（版本 3）/)).toBeInTheDocument()
    await waitFor(() => expect(updated).not.toBeNull())
    expect(updated!.body).toEqual({ expected_revision: 2, name: 'office', description: 'HQ', entries: ['10.0.0.0/8'] })
    expect(updated!.key).toMatch(/^security-ip-list-/)
  })

  it('creates a platform list through the admin route and shows a refused delete', async () => {
    authenticate('platform', ['platform.admin', 'security_policies.read', 'security_policies.manage'])
    let created: unknown = null
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/v1/admin/security-ip-lists')) {
        created = JSON.parse(String(init.body))
        return json(list({ id: platformID, name: 'bad bots', platform: true, revision: 1 }), 201)
      }
      if (init?.method === 'DELETE') {
        return json({ error: { code: 'ip_list_in_use', message: 'in use' } }, 409)
      }
      return json({ items: [list({ id: platformID, name: 'scanners', platform: true })] })
    })
    renderWithProviders(<AppRoutes />, ['/site/ip-lists'])

    fireEvent.click(await screen.findByRole('button', { name: /新建名单/ }))
    fireEvent.change(await screen.findByLabelText('名称'), { target: { value: 'bad bots' } })
    fireEvent.change(screen.getByLabelText('地址与网段'), { target: { value: '203.0.113.7\n2001:db8::/32' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText(/已保存名单“bad bots”/)).toBeInTheDocument()
    expect(created).toEqual({ name: 'bad bots', description: '', entries: ['203.0.113.7', '2001:db8::/32'] })

    const row = (await screen.findByText('scanners')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /删除/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /删除/ }))
    expect(await screen.findByText('仍有安全策略引用这个名单，先从规则里移除再删除。')).toBeInTheDocument()
  })

  // fix-secflow SF-IPLIST-FEEDBACK-01：非法条目在当前弹窗的字段上逐条指出（不发请求）；服务端拒绝的错误放在弹窗内，
  // 草稿保留，改正后原位保存。
  it('shows invalid entries on the field and a refused save inside the open editor, keeping the draft', async () => {
    authenticate('tenant', ['security_policies.read', 'security_policies.manage'])
    let posts = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/v1/security-ip-lists')) {
        posts++
        if (posts === 1) return json({ error: { code: 'ip_list_name_conflict', message: 'name' } }, 409)
        return json(list({ name: 'lab', revision: 1 }), 201)
      }
      return json({ items: [] })
    })
    renderWithProviders(<AppRoutes />, ['/site/ip-lists'])
    fireEvent.click(await screen.findByRole('button', { name: /新建名单/ }))
    const dialog = within(await screen.findByRole('dialog'))
    fireEvent.change(dialog.getByLabelText('名称'), { target: { value: 'lab' } })
    fireEvent.change(dialog.getByLabelText('地址与网段'), { target: { value: '192.0.2.1\n192.0.2.999\n2001:db8::/129' } })
    fireEvent.click(dialog.getByRole('button', { name: '保存' }))
    expect(await dialog.findByText(/192\.0\.2\.999/)).toBeInTheDocument()
    expect(dialog.getByText(/2001:db8::\/129/)).toBeInTheDocument()
    expect(posts).toBe(0)
    fireEvent.change(dialog.getByLabelText('地址与网段'), { target: { value: '192.0.2.1' } })
    fireEvent.click(dialog.getByRole('button', { name: '保存' }))
    const alert = await dialog.findByRole('alert')
    expect(within(alert).getByText('已有同名的名单。')).toBeInTheDocument()
    expect(dialog.getByLabelText('名称')).toHaveValue('lab')
    expect(dialog.getByLabelText('地址与网段')).toHaveValue('192.0.2.1')
    fireEvent.click(dialog.getByRole('button', { name: '保存' }))
    expect(await screen.findByText(/已保存名单“lab”/)).toBeInTheDocument()
    expect(posts).toBe(2)
  })

  it('hides writes from read-only users and is in the site menu for readers', async () => {
    authenticate('tenant', ['security_policies.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [list()] }))
    renderWithProviders(<AppRoutes />, ['/site/ip-lists'])
    expect(await screen.findByText('office')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新建名单/ })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument()
    for (const role of ['admin', 'user'] as const) {
      const site = getNavigation(role, undefined, ['security_policies.read']).find((item) => item.key === 'site')
      expect(site?.children?.some((item) => item.key === '/site/ip-lists')).toBe(true)
    }
  })

  it('parses entries one per line or comma with comments', () => {
    expect(parseIPListEntries('192.0.2.1, 192.0.2.2\n# note\n\n10.0.0.0/8 # lab')).toEqual(['192.0.2.1', '192.0.2.2', '10.0.0.0/8'])
  })
})
