import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteOriginPoolStatus } from '../../api/siteOriginStatus'
import { backupOriginLines, expandBackupOrigins, parseOriginLine, type SiteBasicConfig, type SiteDetail, type SiteOrigin, type SiteOriginPool } from '../../api/sites'
import i18n from '../../i18n'
import BasicSiteTab from './BasicSiteTab'
import { SiteOriginStatusCard } from './SiteOriginStatusCard'

vi.mock('../../api/siteOriginStatus', () => ({ siteOriginStatusApi: { get: vi.fn(), failback: vi.fn() } }))

const siteId = '55555555-5555-4555-8555-555555555555'

function poolStatus(patch: Partial<SiteOriginPoolStatus> = {}): SiteOriginPoolStatus {
  return {
    site_id: siteId, failback_mode: 'manual', active_level: 1, overall: 'healthy', failback_ready: true,
    levels: [{ level: 0, status: 'healthy' }, { level: 1, status: 'healthy' }, { level: 2, status: 'unknown' }],
    origins: [
      { position: 1, host: '192.0.2.10', port: 80, level: 0, enabled: true, status: 'healthy', reason: '', checked_at: '2026-10-20T04:00:00Z' },
      { position: 2, host: '198.51.100.7', port: 8080, level: 1, enabled: true, status: 'healthy', reason: '', checked_at: '2026-10-20T04:00:00Z' },
      { position: 3, host: 'backup.example.com', port: 80, level: 2, enabled: true, status: 'unknown', reason: 'timeout', checked_at: null },
    ],
    switched_at: '2026-10-20T03:58:00Z', checked_at: '2026-10-20T04:00:00Z', ...patch,
  }
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('backup origin lines', () => {
  it('expands lines in order: blanks ignored, repeats and primaries dropped', () => {
    const primary: SiteOrigin = { host: '192.0.2.10', port: 80, weight: 1, enabled: true }
    const pool = expandBackupOrigins({
      origins: [primary],
      backup_origins: [' 198.51.100.7:8080 ', '', 'Backup.Example.com', '198.51.100.7:8080', '192.0.2.10', '[2001:db8::5]:81'],
    })
    expect(pool.origins.map((origin) => `${origin.host}:${origin.port}@${origin.level ?? 0}`)).toEqual([
      '192.0.2.10:80@0', '198.51.100.7:8080@1', 'backup.example.com:80@2', '2001:db8::5:81@3',
    ])
    expect('backup_origins' in pool).toBe(false)
    expect(backupOriginLines(pool.origins)).toEqual(['198.51.100.7:8080', 'backup.example.com', '[2001:db8::5]:81'])
  })

  it('rejects malformed lines', () => {
    expect(parseOriginLine('http://x.test/')).toBeNull()
    expect(parseOriginLine('x.test:70000')).toBeNull()
    expect(parseOriginLine('a b')).toBeNull()
    expect(parseOriginLine('x.test:8443')).toEqual({ host: 'x.test', port: 8443 })
  })
})

const basic: SiteBasicConfig = {
  package_id: null, package_name: null, group_id: null, group_name: null, domains: ['example.com'], http_enabled: true,
  http_listen_ports: ['80'], https_listen_ports: ['443'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.10'], cname: '', https_enabled: true, enabled: true, status: 'active', sync_status: 'synced', is_default: false,
}
const basePool: SiteOriginPool = {
  origins: [
    { host: '192.0.2.10', port: 80, weight: 1, enabled: true, level: 0 },
    { host: '198.51.100.7', port: 8080, weight: 1, enabled: true, level: 1 },
  ],
  balance_method: 'ip_hash', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000, failback_mode: 'auto',
}

function Harness({ onPool }: { onPool: (pool: SiteOriginPool) => void }) {
  const [pool, setPool] = useState(basePool)
  // BasicSiteTab's edge options section reads the L2 configurations (useQuery).
  const [client] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }))
  return <QueryClientProvider client={client}><MemoryRouter>
    <BasicSiteTab role="user" errors={{}} originPool={pool} value={basic}
      detail={{ id: siteId, version: 7, owner: null, created_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z',
        lock: { locked: false, reason: null, locked_at: null, operator: null },
        listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' }, basic, origin_pool: basePool } satisfies SiteDetail}
      onChange={() => {}} onBlockedAction={() => {}}
      onOriginChange={(next) => { setPool(next); onPool(next) }} />
  </MemoryRouter></QueryClientProvider>
}

describe('BasicSiteTab origin failover', () => {
  it('lists only primaries and edits backups in the text box', async () => {
    const onPool = vi.fn()
    const user = userEvent.setup()
    render(<Harness onPool={onPool} />)
    const list = document.querySelector('.site-basic-origin-list') as HTMLElement
    expect(within(list).getByText('192.0.2.10:80')).toBeInTheDocument()
    expect(within(list).queryByText('198.51.100.7:8080')).toBeNull()
    const box = screen.getByLabelText('备用源')
    expect(box).toHaveValue('198.51.100.7:8080')
    expect(screen.getByText(/主源不可用时按从上到下顺序依次切换/)).toBeInTheDocument()
    await user.clear(box)
    await user.type(box, 'b1.example.com{enter}{enter}198.51.100.9:81')
    const last = onPool.mock.calls.at(-1)?.[0] as SiteOriginPool
    expect(last.origins.map((origin) => `${origin.host}:${origin.port}@${origin.level ?? 0}`)).toEqual([
      '192.0.2.10:80@0', 'b1.example.com:80@1', '198.51.100.9:81@2',
    ])
    expect(last.balance_method).toBe('ip_hash')
    // the blank line the user typed stays in the box
    expect(box).toHaveValue('b1.example.com\n\n198.51.100.9:81')
    await user.type(box, '{enter}bad/path')
    expect(screen.getByRole('alert')).toHaveTextContent('第 4 行不是有效的地址。')
  })

  it('chooses the failback mode', async () => {
    const onPool = vi.fn()
    const user = userEvent.setup()
    render(<Harness onPool={onPool} />)
    await user.click(screen.getByRole('radio', { name: '手动切回' }))
    expect((onPool.mock.calls.at(-1)?.[0] as SiteOriginPool).failback_mode).toBe('manual')
  })
})

describe('SiteOriginStatusCard', () => {
  it('shows each origin state and switches a manual pool back', async () => {
    const { siteOriginStatusApi } = await import('../../api/siteOriginStatus')
    vi.mocked(siteOriginStatusApi.get).mockResolvedValue(poolStatus())
    vi.mocked(siteOriginStatusApi.failback).mockResolvedValue(poolStatus({ active_level: 0, failback_ready: false }))
    const user = userEvent.setup()
    render(<QueryClientProvider client={new QueryClient()}><SiteOriginStatusCard siteId={siteId} accessToken="token" canManage /></QueryClientProvider>)
    expect(await screen.findByText('当前在用')).toBeInTheDocument()
    expect(screen.getByText('更高级别的源站已恢复，可以切回。')).toBeInTheDocument()
    const rows = screen.getAllByRole('row')
    expect(within(rows[2]!).getByText('备用源 1')).toBeInTheDocument()
    expect(rows[2]).toHaveAttribute('aria-current', 'true')
    expect(within(rows[3]!).getByText('超时')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '切回主源' }))
    await waitFor(() => expect(siteOriginStatusApi.failback).toHaveBeenCalledTimes(1))
    expect(vi.mocked(siteOriginStatusApi.failback).mock.calls[0]?.slice(0, 2)).toEqual(['token', siteId])
    expect(await screen.findByText('已切回，正在下发到节点。')).toBeInTheDocument()
  })

  it('has no switch back in auto mode and disables it without a recovered level', async () => {
    const { siteOriginStatusApi } = await import('../../api/siteOriginStatus')
    vi.mocked(siteOriginStatusApi.get).mockResolvedValueOnce(poolStatus({ failback_mode: 'auto' }))
    const { unmount } = render(<QueryClientProvider client={new QueryClient()}><SiteOriginStatusCard siteId={siteId} accessToken="token" canManage /></QueryClientProvider>)
    expect(await screen.findByText('当前在用')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /切回/ })).toBeNull()
    unmount()
    vi.mocked(siteOriginStatusApi.get).mockResolvedValueOnce(poolStatus({
      failback_ready: false, levels: [{ level: 0, status: 'unhealthy' }, { level: 1, status: 'healthy' }],
    }))
    render(<QueryClientProvider client={new QueryClient()}><SiteOriginStatusCard siteId={siteId} accessToken="token" canManage /></QueryClientProvider>)
    expect(await screen.findByRole('button', { name: '切回主源' })).toBeDisabled()
  })
})
