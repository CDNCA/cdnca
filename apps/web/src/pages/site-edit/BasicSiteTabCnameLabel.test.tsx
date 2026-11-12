import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteBasicConfig, SiteDetail, SiteOriginPool } from '../../api/sites'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import BasicSiteTab from './BasicSiteTab'

const basic: SiteBasicConfig = {
  package_id: null, package_name: null, group_id: null, group_name: null, domains: ['example.com'], http_enabled: true,
  http_listen_ports: ['80'], https_listen_ports: ['443'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.1'], cname: 'n0kkk8g1.cdn86.com', cname_state: 'done', cname_mode: 'site', cname_domain: 'cdn86.com',
  https_enabled: false, enabled: true, status: 'active', sync_status: 'synced', is_default: false,
}
const pool: SiteOriginPool = {
  origins: [{ host: '192.0.2.1', port: 80, weight: 1, enabled: true, level: 0 }],
  balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000, failback_mode: 'auto',
}
const detail: SiteDetail = {
  id: '66666666-6666-4666-8666-666666666666', version: 3, owner: null, created_at: '2026-10-27T00:00:00Z',
  updated_at: '2026-10-27T00:00:00Z', lock: { locked: false, reason: null, locked_at: null, operator: null },
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' }, basic, origin_pool: pool,
}

function renderTab(role: 'admin' | 'user', value: SiteBasicConfig) {
  return renderWithProviders(<App><BasicSiteTab role={role} canManageDNS errors={{}} originPool={pool} value={value} detail={detail}
    onChange={() => {}} onBlockedAction={() => {}} onOriginChange={() => {}} /></App>)
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated' } as never)
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ label: '' }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
})
afterEach(() => { vi.restoreAllMocks() })

// 只有平台管理员能改 CNAME 主机名；用户只读并可复制。
describe('BasicSiteTab CNAME hostname', () => {
  it('lets an administrator fill the hostname of a site-mode CNAME and previews it', async () => {
    const user = userEvent.setup({ delay: null })
    renderTab('admin', basic)
    await user.click(screen.getByRole('button', { name: '更改CNAME' }))
    const input = await screen.findByRole('textbox', { name: '主机名' })
    await waitFor(() => expect(input).toBeEnabled())
    await user.type(input, 'shop')
    expect(screen.getByTestId('cname-label-preview')).toHaveTextContent('shop.cdn86.com')
  })

  it('does not offer the name editor to a package-mode site', async () => {
    const user = userEvent.setup({ delay: null })
    renderTab('admin', { ...basic, cname_mode: 'package', package_id: 'p1', package_subscription_id: 's1', package_name: '商务版' })
    await user.click(screen.getByRole('button', { name: '更改CNAME' }))
    expect(screen.queryByRole('button', { name: '保存主机名' })).toBeNull()
  })

  it('shows a user the CNAME read-only with a copy button and no change entry', () => {
    renderTab('user', basic)
    expect(screen.getAllByText('n0kkk8g1.cdn86.com').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: '复制CNAME' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '更改CNAME' })).toBeNull()
  })
})
