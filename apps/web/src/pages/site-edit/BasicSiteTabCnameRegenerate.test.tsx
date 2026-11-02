import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteBasicConfig, SiteDetail, SiteOriginPool } from '../../api/sites'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import BasicSiteTab from './BasicSiteTab'

const basic: SiteBasicConfig = {
  package_id: null, package_name: null, group_id: null, group_name: null, domains: ['tenant.example.com'], http_enabled: true,
  http_listen_ports: ['80'], https_listen_ports: ['443'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.1'], cname: 'n0kkk8g1.cdn.example.net', cname_state: 'pending', https_enabled: false, enabled: true,
  status: 'active', sync_status: 'synced', is_default: false,
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

beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

// 站点详情点“重新生成 CNAME”先二次确认，提醒旧地址约 24 小时后失效。
describe('BasicSiteTab regenerate CNAME confirmation', () => {
  it('asks before regenerating and only regenerates on confirm', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<BasicSiteTab role="user" canManageDNS errors={{}} originPool={pool} value={basic} detail={detail}
      onChange={onChange} onBlockedAction={() => {}} onOriginChange={() => {}} />)

    await user.click(screen.getByTestId('site-basic-cname-regenerate'))
    // antd 的 confirm 标题在弹窗头和正文各渲染一次，按确认框找。
    const confirm = () => document.querySelector<HTMLElement>('.ant-modal-confirm')
    await waitFor(() => expect(confirm()?.querySelector('.ant-modal-confirm-title')).toHaveTextContent('重新生成 tenant.example.com 的 CNAME？'))
    expect(confirm()).toHaveTextContent('重新生成会换成新的 CNAME 地址，旧地址约 24 小时后失效，请在此之前把域名解析改为新地址。')
    await user.click(within(confirm()!).getByRole('button', { name: /取\s*消/ }))
    await waitFor(() => expect(confirm()).toBeNull())
    expect(onChange).not.toHaveBeenCalled()

    await user.click(screen.getByTestId('site-basic-cname-regenerate'))
    await waitFor(() => expect(confirm()).not.toBeNull())
    await user.click(within(confirm()!).getByRole('button', { name: '确认重新生成' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ cname_regenerate: true })))
  })
})
