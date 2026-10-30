import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'

import { dnsReconcileApi } from '../api/dnsReconcile'
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
          <MemoryRouter initialEntries={[`/site/${siteID}/dns-reconcile`]}>
            <Routes><Route path="/site/:id/dns-reconcile" element={<DnsReconcilePage />} /></Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp></ConfigProvider>,
    )
    const user = userEvent.setup()
    await user.type(screen.getByRole('textbox', { name: '域名' }), 'www.example.test')
    await user.type(screen.getByRole('textbox', { name: '预期记录值' }), '192.0.2.10')
    await user.type(screen.getByRole('textbox', { name: '线路' }), '境外')
    await user.clear(screen.getByRole('textbox', { name: '权重' }))
    await user.type(screen.getByRole('textbox', { name: '权重' }), '80')
    await user.clear(screen.getByRole('textbox', { name: 'DNS 区域 ID' }))
    await user.type(screen.getByRole('textbox', { name: 'DNS 区域 ID' }), zoneID)
    await user.clear(screen.getByRole('textbox', { name: '提供商修订' }))
    await user.type(screen.getByRole('textbox', { name: '提供商修订' }), '7')
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))

    await waitFor(() => expect(dryRun).toHaveBeenCalledTimes(1))
    expect(dryRun.mock.calls[0][2]).toMatchObject({ line: '境外', weight: 80 })
    expect(await screen.findByRole('columnheader', { name: '线路' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '权重' })).toBeInTheDocument()
    expect(screen.getByText('境外 ← 默认')).toBeInTheDocument()
    expect(screen.getByText('80 ← 20')).toBeInTheDocument()
  })
})
