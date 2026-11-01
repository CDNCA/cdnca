import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'

import { dnsApi } from '../api/dns'
import { dnsReconcileApi } from '../api/dnsReconcile'
import { dnsZonesApi } from '../api/dnsZones'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import DnsReconcilePage from '../pages/DnsReconcilePage'
import { authResponse, principal } from '../test/fixtures'

const tenantID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const zoneID = '33333333-3333-4333-8333-333333333333'

describe('DNS-02 line and weight contract', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh-CN')
    const actor = principal({
      scope_kind: 'tenant', scope_id: tenantID, tenant_id: tenantID,
      permissions: ['dns.read', 'dns.manage'],
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'dns-token' }, actor, 'new')
  })

  it('submits and displays current and previous line and weight', async () => {
    const providerID = '55555555-5555-4555-8555-555555555555'
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [{ id: providerID, scope_id: tenantID }] } as unknown as Awaited<ReturnType<typeof dnsApi.list>>)
    vi.spyOn(dnsZonesApi, 'listZones').mockResolvedValue({ items: [{
      id: zoneID, scope_id: tenantID, provider_id: providerID, name: 'example.test', status: 'draft', version: 7,
      created_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z',
    }] })
    const dnsCheck = {
      siteID, siteDisplayID: '1', domain: 'www.example.test', cname: '', provider: null, task: null, resolve: 'none',
      back: { filter: 'all', page: 1, limit: 10, search: { domain: '', siteIds: '' } },
    }
    const dryRun = vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({
      tenant_id: tenantID, site_id: siteID, zone_id: zoneID, payload_digest: 'a'.repeat(64),
      plan: {
        tenant_id: tenantID, site_id: siteID, zone_id: zoneID, precondition_revision: 7,
        digest: 'b'.repeat(64), operations: [{
          sequence: 1, action: 'update', record_id: 'record-1', name: 'www.example.test.', type: 'A',
          value: '192.0.2.10', ttl: 300, line: '境外', weight: 80,
          previous_value: '192.0.2.10', previous_ttl: 300, previous_line: '默认', previous_weight: 20,
          reason: 'routing_mismatch',
        }],
      },
      status: 'dry_run', replayed: false, started_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z',
      initial_revision: 7, provider_revision: 7, operations: [], deferred_deletes: [], compensation_plan: [],
      propagation: [], error_class: '', error_code: '',
    })
    render(
      <ConfigProvider button={{ autoInsertSpace: false }}><AntApp>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <MemoryRouter initialEntries={[{ pathname: `/site/${siteID}/dns-reconcile`, state: { dnsCheck } }]}>
            <Routes><Route path="/site/:id/dns-reconcile" element={<DnsReconcilePage />} /></Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp></ConfigProvider>,
    )
    const user = userEvent.setup()
    await screen.findByText('example.test')
    await user.click(screen.getByRole('button', { name: /高级设置/ }))
    await user.type(screen.getByLabelText('应指向的值'), '192.0.2.10')
    await user.type(screen.getByLabelText('解析线路'), '境外')
    await user.clear(screen.getByLabelText('权重'))
    await user.type(screen.getByLabelText('权重'), '80')
    await user.click(screen.getByRole('button', { name: '检查并生成修复方案' }))

    await waitFor(() => expect(dryRun).toHaveBeenCalledTimes(1))
    expect(dryRun.mock.calls[0][2]).toMatchObject({ line: '境外', weight: 80 })
    expect(dryRun.mock.calls[0][2]).toMatchObject({ expected: [{ type: 'A', values: ['192.0.2.10'] }], provider: { zone_id: zoneID, revision: 7 } })
    expect(await screen.findByText('线路：默认 → 境外')).toBeInTheDocument()
    expect(screen.getByText('权重：20 → 80')).toBeInTheDocument()
  })
})
