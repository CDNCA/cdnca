import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import ControlUpgradesPage from '../pages/ControlUpgradesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// B04/X09 (主控同类): an opened run log follows the run until it ends.
// X08 (主控同类): a malformed S3 endpoint is marked in place, nothing is probed.
const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
  permissions: ['control.upgrades.read', 'control.upgrades.manage'] })

let finished = false
let failedRun = false
let nextRunAt: string | null = null
let statusReads = 0
const status = () => ({ data: {
  keys_ready: true, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), recipient: 'age1test', agent_installed: true, migration_ready: true,
  freeze: null, bundles: [], next_run_at: nextRunAt,
  runs: [{ id: '20261017T030000Z-000000000001', kind: 'backup', reason: 'manual', state: failedRun ? 'failed' : finished ? 'succeeded' : 'running', ...(failedRun ? { error: 'pg_dump: disk full' } : {}),
    requested_at: '2026-10-17T03:00:00Z', log: finished ? ['dump started', 'backup finished'] : ['dump started'] }],
  settings: { schedule: { enabled: false, weekdays: [1], hour: 4, minute: 0 }, keep_local: 7, keep_remote: 14, revision: 'rev-1',
    targets: [{ name: 'offsite', kind: 's3', enabled: true, endpoint: 'https://s3.example.com', region: 'us-east-1', bucket: 'cdnca-backups',
      prefix: 'ctl/', path_style: false, access_key_fingerprint: 'abcd1234', has_secret_key: true }] },
} })

function json(body: unknown, code = 200): Response {
  return new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } })
}

const probes: string[] = []
beforeEach(async () => {
  await changeLocale('zh-CN')
  finished = false
  failedRun = false
  nextRunAt = null
  statusReads = 0
  probes.length = 0
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'token-1' }, admin)
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    if (url.endsWith('/v1/admin/control-backup')) { statusReads++; return Promise.resolve(json(status())) }
    if (url.endsWith('/v1/admin/control-backup/targets/probe')) { probes.push(String(init?.body)); return Promise.resolve(json({ data: { ok: true } })) }
    return Promise.resolve(json({ data: [], items: [], pagination: { page: 1, page_size: 10, total: 0 } }))
  })
})
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

async function openMaintenance() {
  const user = userEvent.setup(vi.isFakeTimers() ? { advanceTimers: (ms) => vi.advanceTimersByTime(ms) } : {})
  renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
  await user.click(await screen.findByRole('tab', { name: '维护操作' }))
  return user
}

describe('主控备份任务状态', () => {
  it('X09：运行中打开日志，弹窗随状态刷新显示新日志与最终状态；运行中按 5 秒轮询', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = await openMaintenance()
    await user.click(await screen.findByRole('button', { name: '日志' }))
    const dialog = (await screen.findByText('dump started')).closest('.ant-modal') as HTMLElement
    finished = true
    const reads = statusReads
    await act(async () => { await vi.advanceTimersByTimeAsync(6_000) })
    await waitFor(() => expect(statusReads).toBeGreaterThan(reads))
    expect(await within(dialog).findByText(/backup finished/)).toBeInTheDocument()
    expect(within(dialog).getByText('成功')).toBeInTheDocument()
  })

  it('X08：Endpoint 不是 https://主机[:端口] 时就地标错，不发测试请求', async () => {
    const user = await openMaintenance()
    const panel = (await screen.findByRole('heading', { name: '异地存储' })).closest('form') as HTMLElement
    for (const value of ['https://', 'ftp://s3.example.com', 'http://s3.example.com', 'https://s3.example.com/x']) {
      fireEvent.change(within(panel).getByDisplayValue(/s3\.example\.com|^https?:\/\/$|^ftp/), { target: { value } })
      await user.click(within(panel).getByRole('button', { name: '测试连接' }))
      await waitFor(() => expect(within(panel).getByText(/Endpoint 格式不对/)).toBeInTheDocument())
    }
    expect(probes).toHaveLength(0)
  })

  it('X04：立即备份失败的弹窗有动作标题、中文原因与请求号，不显示服务端原文', async () => {
    vi.mocked(globalThis.fetch).mockImplementation((input, init) => {
      const url = String(input)
      if (url.endsWith('/v1/admin/control-backup')) return Promise.resolve(json(status()))
      if (url.endsWith('/v1/admin/control-backup/backups') && init?.method === 'POST') {
        return Promise.resolve(json({ error: { code: 'control_backup_busy', message: 'raw backend detail', request_id: 'req-busy-0001' } }, 409))
      }
      return Promise.resolve(json({ data: [], items: [], pagination: { page: 1, page_size: 10, total: 0 } }))
    })
    finished = true
    const user = await openMaintenance()
    await user.click(await screen.findByRole('button', { name: '立即备份' }))
    const confirm = await screen.findByRole('dialog', { name: '立即备份？' })
    await user.click(within(confirm).getByRole('button', { name: /确\s*定|OK/ }))
    const dialog = (await screen.findByText('无法开始备份')).closest('.ant-modal') as HTMLElement
    expect(within(dialog).getByText('已有备份或迁移在执行')).toBeInTheDocument()
    expect(within(dialog).getByText('req-busy-0001')).toBeInTheDocument()
    expect(screen.queryByText('raw backend detail')).not.toBeInTheDocument()
  })

  // b04 遗留：失败备份不自动重试，界面说明下次计划时间或只能手动补做。
  it('失败备份说明不会自动重试，并显示下次计划备份时间', async () => {
    failedRun = true
    nextRunAt = '2026-10-18T04:00:00Z'
    const user = await openMaintenance()
    expect(await screen.findByText(/^下次计划备份：/)).toBeInTheDocument()
    expect(screen.getByText(/失败的备份不会自动重试，下次计划备份 .+；需要现在补做请点「立即备份」/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '日志' }))
    const dialog = (await screen.findByText('pg_dump: disk full')).closest('.ant-modal') as HTMLElement
    expect(within(dialog).getByText(/失败的备份不会自动重试/)).toBeInTheDocument()
  })

  it('计划备份未开启时，失败行提示只能手动重试且不显示下次计划', async () => {
    failedRun = true
    await openMaintenance()
    expect(await screen.findByText('失败的备份不会自动重试，未开启计划备份；请点「立即备份」重试。')).toBeInTheDocument()
    expect(screen.queryByText(/^下次计划备份：/)).not.toBeInTheDocument()
  })
})
