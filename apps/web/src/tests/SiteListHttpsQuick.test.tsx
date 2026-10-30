import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteDetail, SiteListItem, SiteListResponse } from '../api/sites'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import SiteListPage from '../pages/SiteListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// HTTPS 列「未开启」可点击快捷开启，走站点 HTTPS 现有流程：
// 已绑定证书 → PATCH basic https_enabled=true；未绑定 → 引导申请/选择证书，不发写请求。
const scopeID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const tenantScope = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const site: SiteListItem = {
  id: 'site-1', display_id: '27', version: 7,
  owner: { id: 'tenant-1', display_id: '2', display_name: 'jason' },
  domain: 'quick.example.com', listen_ports: ['80'], origins: ['192.0.2.10:443'],
  cname: 'x.cdn.example', cname_state: 'done', https_enabled: false,
  package: { id: 'package-1', name: '测试套餐' }, group_name: null, region: null, status: 'active',
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  created_at: '2026-10-24T03:41:03Z',
}
const detail: SiteDetail = {
  id: site.id, scope_id: tenantScope, version: 7, owner: site.owner, created_at: site.created_at, updated_at: site.created_at,
  lock: site.lock, listener_state: site.listener_state,
  origin_pool: { origins: [{ host: '192.0.2.10', port: 443, weight: 1, enabled: true }], balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000 },
  basic: {
    package_id: 'package-1', package_name: '测试套餐', group_id: null, group_name: null,
    domains: [site.domain], http_enabled: true, http_listen_ports: ['80'], https_listen_ports: ['443'],
    ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'], origins: site.origins,
    cname: site.cname, https_enabled: false, enabled: true, status: 'active', sync_status: 'synced', is_default: false,
  },
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockFetch(bound: boolean) {
  const patches: unknown[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    if (url.includes(`/v1/sites/${site.id}/certificate-binding`)) {
      return bound
        ? json({ binding: { site_id: site.id } }, 500)
        : json({ error: { code: 'certificate_site_binding_not_found', message: 'none' } }, 404)
    }
    if (url.endsWith(`/v1/sites/${site.id}`)) {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as { changes: SiteDetail['basic'] }
        patches.push(body)
        return json({ ...detail, version: 8, basic: body.changes })
      }
      return json({ ...detail, https_certificate_bound: bound })
    }
    if (url.startsWith('/v1/sites?')) return json({ items: [site], total: 1, page: 1, limit: 10 } satisfies SiteListResponse)
    return json({ items: [] })
  })
  return patches
}

function CertTarget() {
  const { search } = useLocation()
  return <output data-testid="cert-target">{search}</output>
}

async function openQuick() {
  const actor = principal({
    scope_kind: 'platform', scope_id: scopeID, tenant_id: null, username: 'admin', display_name: 'admin',
    roles: ['platform_admin'], permissions: ['sites.read', 'sites.manage', 'certificates.read'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  renderWithProviders(<Routes><Route path="/site/list" element={<SiteListPage />} /><Route path="/site/cert" element={<CertTarget />} /></Routes>, ['/site/list'])
  const user = userEvent.setup({ delay: null })
  const row = (await screen.findByText(site.domain)).closest('tr')!
  await user.click(within(row).getByRole('button', { name: `点击开启 HTTPS ${site.domain}` }))
  return { user, dialog: await screen.findByRole('dialog', { name: '开启 HTTPS' }) }
}

beforeEach(async () => {
  vi.restoreAllMocks()
  sessionStorage.clear()
  resetSessionStore()
  await i18n.changeLanguage('zh-CN')
})

describe('site list HTTPS quick enable', () => {
  it('guides to request or choose a certificate when none is bound, without writing', async () => {
    const patches = mockFetch(false)
    const { dialog } = await openQuick()
    expect(await within(dialog).findByText(/还没有绑定证书/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '申请证书' })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '选择证书' })).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: '开启' })).toBeNull()
    expect(patches).toHaveLength(0)
  })

  // 去申请证书带上网站 ID，证书页据此带入网站所属用户。
  it('opens the certificate request with the site so its owner is filled in', async () => {
    mockFetch(false)
    const { user, dialog } = await openQuick()
    await user.click(await within(dialog).findByRole('button', { name: '申请证书' }))
    const params = new URLSearchParams((await screen.findByTestId('cert-target')).textContent ?? '')
    expect(params.get('domains')).toBe(site.domain)
    expect(params.get('site')).toBe(site.id)
  })

  it('turns HTTPS on with one basic PATCH when a certificate is bound', async () => {
    const patches = mockFetch(true)
    const { user, dialog } = await openQuick()
    expect(await within(dialog).findByText(/已绑定证书/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '开启' }))
    await vi.waitFor(() => expect(patches).toHaveLength(1))
    expect(patches[0]).toMatchObject({ expected_version: 7, section: 'basic', changes: { https_enabled: true, domains: [site.domain] } })
  })
})
