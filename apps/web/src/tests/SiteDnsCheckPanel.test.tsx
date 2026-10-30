import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { sitesApi, type SiteListItem } from '../api/sites'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import SiteDnsCheckPanel, { type SiteDnsCheckContext } from '../pages/SiteDnsCheckPanel'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// DC-UX-DETAIL-01（审测卡 12）：详细检测带着被点的域名、CNAME、DNS 账号和最近任务进入；
// 返回解析检测时恢复筛选和页码。
const site: SiteListItem = {
  id: '9f9f9f9f-9f9f-4f9f-8f9f-9f9f9f9f9f9f', display_id: '12', version: 3,
  owner: { id: 'tenant-1', display_id: '2', display_name: 'tenant' },
  domain: 'a.example.com', domains: ['a.example.com', 'b.example.com'], listen_ports: ['80'], origins: ['192.0.2.10:443'],
  cname: 'abc.cdn.example.net', cname_state: 'done', https_enabled: false,
  package: null, group_name: null, region: null, status: 'active',
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  created_at: '2026-10-27T00:00:00Z',
  auto_dns: {
    provider_id: '55555555-5555-4555-8555-555555555555', provider_name: 'own-cloudflare', state: 'failed',
    failure_code: 'dns_provider_unavailable', attempts: 2, results: [{ domain: 'b.example.com', code: 'zone_not_hosted' }],
    updated_at: '2026-10-27T01:00:00Z',
  },
}

function Probe() {
  const state = useLocation().state as { dnsCheck?: SiteDnsCheckContext } | null
  return <pre data-testid="context">{JSON.stringify(state?.dnsCheck ?? null)}</pre>
}

describe('SiteDnsCheckPanel detailed check', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
    const actor = principal({ permissions: ['sites.read', 'dns.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
  })

  it('passes the clicked domain and its facts to the detailed check', async () => {
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [site], total: 1, page: 1, limit: 10 })
    const user = userEvent.setup()
    renderWithProviders(<Routes>
      <Route path="/site/list" element={<SiteDnsCheckPanel onConfigureDnsApi={() => undefined} />} />
      <Route path="/site/:id/dns-reconcile" element={<Probe />} />
    </Routes>, ['/site/list'])
    const row = (await screen.findAllByText('b.example.com'))[0]!.closest('tr')!
    await user.click(within(row).getByRole('button', { name: '详细检测' }))
    const context = JSON.parse((await screen.findByTestId('context')).textContent!) as SiteDnsCheckContext
    expect(context).toMatchObject({
      siteID: site.id, domain: 'b.example.com', cname: 'abc.cdn.example.net',
      provider: { name: 'own-cloudflare' }, task: { state: 'failed', code: 'zone_not_hosted', attempts: 2 },
      resolve: 'failed', back: { filter: 'all', page: 1, limit: 10 },
    })
  })

  it('restores the filter, page and search it was left with', async () => {
    const list = vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [site], total: 30, page: 2, limit: 10 })
    renderWithProviders(<SiteDnsCheckPanel onConfigureDnsApi={() => undefined}
      restore={{ filter: 'failed', page: 2, limit: 10, search: { domain: 'example', siteIds: '' } }} />, ['/site/list'])
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.any(String),
      expect.objectContaining({ page: 2, limit: 10, domain: 'example' })))
    expect(screen.getByRole('textbox', { name: '域名' })).toHaveValue('example')
  })
})
