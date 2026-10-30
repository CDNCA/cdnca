import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'

import type { SiteBasicConfig, SiteDetail, SiteOriginPool } from '../../api/sites'
import i18n from '../../i18n'
import BasicSiteTab from './BasicSiteTab'

const siteId = '66666666-6666-4666-8666-666666666666'
const basic: SiteBasicConfig = {
  package_id: null, package_name: null, group_id: null, group_name: null, domains: ['example.com'], http_enabled: true,
  http_listen_ports: ['80'], https_listen_ports: ['443'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.1'], cname: '', https_enabled: true, enabled: true, status: 'active', sync_status: 'synced', is_default: false,
}
// 用户例子 A50 B10 C5 D20（合计 85），另有一个停用源站和一个备用源
const basePool: SiteOriginPool = {
  origins: [
    { host: '192.0.2.1', port: 80, weight: 50, enabled: true, level: 0 },
    { host: '192.0.2.2', port: 80, weight: 10, enabled: true, level: 0 },
    { host: '192.0.2.3', port: 80, weight: 5, enabled: true, level: 0 },
    { host: '192.0.2.4', port: 80, weight: 20, enabled: true, level: 0 },
    { host: '192.0.2.5', port: 80, weight: 40, enabled: false, level: 0 },
    { host: '198.51.100.7', port: 80, weight: 1, enabled: true, level: 1 },
  ],
  balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000, failback_mode: 'auto',
}

function Harness({ pool: initial = basePool }: { pool?: SiteOriginPool }) {
  const [pool, setPool] = useState(initial)
  const [client] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }))
  return <QueryClientProvider client={client}><MemoryRouter>
    <BasicSiteTab role="user" errors={{}} originPool={pool} value={basic}
      detail={{ id: siteId, version: 3, owner: null, created_at: '2026-10-27T00:00:00Z', updated_at: '2026-10-27T00:00:00Z',
        lock: { locked: false, reason: null, locked_at: null, operator: null },
        listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' }, basic, origin_pool: pool } satisfies SiteDetail}
      onChange={() => {}} onBlockedAction={() => {}} onOriginChange={setPool} />
  </MemoryRouter></QueryClientProvider>
}

function rowOf(address: string): HTMLElement {
  const list = document.querySelector('.site-basic-origin-list') as HTMLElement
  return within(list).getByText(address).closest('.site-basic-origin-row') as HTMLElement
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

describe('BasicSiteTab origin weight share', () => {
  it('shows each primary share over the enabled primaries; a disabled origin gets none', () => {
    render(<Harness />)
    expect(rowOf('192.0.2.1:80')).toHaveTextContent('权重 50 · 约 59%')
    expect(rowOf('192.0.2.2:80')).toHaveTextContent('权重 10 · 约 12%')
    expect(rowOf('192.0.2.3:80')).toHaveTextContent('权重 5 · 约 6%')
    expect(rowOf('192.0.2.4:80')).toHaveTextContent('权重 20 · 约 23%')
    expect(rowOf('192.0.2.5:80')).toHaveTextContent('权重 40 · 已停用，不分流量')
    expect(screen.getByText(/权重合计不必等于 100，未分配部分按同样比例分摊。 当前负载方式“轮询”/)).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '权重与流量占比说明' })).toBeInTheDocument()
    expect(screen.getByText(/所有主源站都不可用时才启用第 1 个备用源/)).toBeInTheDocument()
  })

  it('describes the hash and least connection methods by what they do', () => {
    const { unmount } = render(<Harness pool={{ ...basePool, balance_method: 'url_hash' }} />)
    expect(screen.getByText(/当前负载方式“URL 哈希”：同一 URL 固定落到一个源站，整体比例近似权重占比/)).toBeInTheDocument()
    unmount()
    render(<Harness pool={{ ...basePool, balance_method: 'least_conn' }} />)
    expect(screen.getByText(/当前负载方式“最少连接”：选当前连接数与权重之比最小的源站/)).toBeInTheDocument()
    expect(rowOf('192.0.2.1:80')).toHaveTextContent('权重 50 · 权重占比 59%')
  })

  it('updates the share live while typing a weight in the add and edit dialogs', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByRole('button', { name: '新增源站信息' }))
    const dialog = await screen.findByRole('dialog')
    // weight 1 joins 85: 1/86
    expect(within(dialog).getByText('该源站约占 1%')).toBeInTheDocument()
    const weight = within(dialog).getByLabelText('源站权重')
    await user.clear(weight)
    await user.type(weight, '15')
    // 15/100
    expect(within(dialog).getByText('该源站约占 15%')).toBeInTheDocument()
    expect(within(dialog).getByText(/权重 1–100。各源站按权重占比分配流量/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('switch', { name: '源站状态' }))
    expect(within(dialog).getByText('已停用，不分流量')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: /取\s*消/ }))

    await user.click(within(rowOf('192.0.2.4:80')).getByRole('button', { name: '编辑' }))
    const edit = await screen.findByRole('dialog')
    expect(within(edit).getByText('该源站约占 23%')).toBeInTheDocument()
    const editWeight = within(edit).getByLabelText('源站权重')
    // select and overwrite (clearing writes 1 back at once: the field's existing `weight ?? 1`)
    await user.tripleClick(editWeight)
    await user.keyboard('35')
    // 35/100, the origin is counted once
    expect(within(edit).getByText('该源站约占 35%')).toBeInTheDocument()
  })
})
