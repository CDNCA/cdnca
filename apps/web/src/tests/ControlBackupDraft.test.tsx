import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import ControlUpgradesPage from '../pages/ControlUpgradesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// A04: the backup settings form keeps what the operator typed while the
// status polls (15s), the access token is renewed, the tab is switched, and
// another session saves meanwhile (revision conflict).
const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
  permissions: ['control.upgrades.read', 'control.upgrades.manage'] })

let revision = 'rev-1'
let statusReads = 0
const status = () => ({ data: {
  keys_ready: true, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), recipient: 'age1test', agent_installed: true, migration_ready: true,
  freeze: null, bundles: [], runs: [{ id: `20261017T030000Z-${String(statusReads).padStart(12, '0')}`, kind: 'backup', reason: 'manual',
    state: 'running', requested_at: '2026-10-17T03:00:00Z', log: [] }],
  settings: { schedule: { enabled: false, weekdays: [1], hour: 4, minute: 0 }, keep_local: 7, keep_remote: 14, revision,
    targets: [{ name: 'offsite', kind: 's3', enabled: true, endpoint: 'https://s3.example.com', region: 'us-east-1', bucket: 'cdnca-backups',
      prefix: 'ctl/', path_style: false, access_key_fingerprint: 'abcd1234', has_secret_key: true }] },
} })

function json(body: unknown, code = 200): Response {
  return new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } })
}

const calls: Array<{ url: string; init?: RequestInit }> = []
beforeEach(async () => {
  await changeLocale('zh-CN')
  revision = 'rev-1'
  statusReads = 0
  calls.length = 0
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'token-1' }, admin)
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    calls.push({ url, init })
    if (url.endsWith('/v1/admin/control-backup')) { statusReads++; return Promise.resolve(json(status())) }
    if (url.endsWith('/v1/admin/control-backup/settings')) {
      const body = JSON.parse(String(init?.body)) as { expected_revision: string }
      return Promise.resolve(body.expected_revision === revision ? json(status())
        : json({ error: { code: 'control_backup_revision_conflict', request_id: 'req-conflict' } }, 409))
    }
    if (url.endsWith('/v1/admin/control-backup/targets/probe')) return Promise.resolve(json({ data: { ok: true } }))
    return Promise.resolve(json({ data: [], items: [], pagination: { page: 1, page_size: 10, total: 0 } }))
  })
})
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

async function openMaintenance() {
  const user = userEvent.setup(vi.isFakeTimers() ? { advanceTimers: (ms) => vi.advanceTimersByTime(ms) } : {})
  renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
  await user.click(await screen.findByRole('tab', { name: '维护操作' }))
  const panel = (await screen.findByRole('heading', { name: '异地存储' })).closest('form') as HTMLElement
  return { user, panel }
}

describe('主控备份设置草稿不被后台刷新覆盖（A04）', () => {
  it('?tab=maintenance 直达维护操作（系统设置数据备份链接的落点）', async () => {
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op?tab=maintenance'])
    expect(await screen.findByRole('tab', { name: '维护操作' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByRole('heading', { name: '主控备份与迁移' })).toBeInTheDocument()
  })

  it('轮询与续期都不覆盖正在编辑的表单，也不把凭据写入本地存储', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { panel } = await openMaintenance()
    fireEvent.change(within(panel).getByDisplayValue('cdnca-backups'), { target: { value: 'draft-bucket' } })
    fireEvent.change(within(panel).getAllByLabelText('Secret Key')[0], { target: { value: 'typed-secret' } })
    // 15s poll with a new status object.
    const reads = statusReads
    await act(async () => { await vi.advanceTimersByTimeAsync(16_000) })
    await waitFor(() => expect(statusReads).toBeGreaterThan(reads))
    expect(within(panel).getByDisplayValue('draft-bucket')).toBeInTheDocument()
    // Token renewal: same session epoch, new access token.
    act(() => { useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'token-2' }, admin, 'refresh') })
    await act(async () => { await vi.advanceTimersByTimeAsync(100) })
    const current = (await screen.findByRole('heading', { name: '异地存储' })).closest('form') as HTMLElement
    expect(within(current).getByDisplayValue('draft-bucket')).toBeInTheDocument()
    expect(within(current).getAllByLabelText('Secret Key')[0]).toHaveValue('typed-secret')
    // Later polls use the renewed token.
    await act(async () => { await vi.advanceTimersByTimeAsync(16_000) })
    const last = calls.filter((call) => call.url.endsWith('/v1/admin/control-backup')).at(-1)
    expect(new Headers(last?.init?.headers).get('Authorization')).toBe('Bearer token-2')
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })
    expect(stored).not.toContain('typed-secret')
    expect(stored).not.toContain('draft-bucket')
  })

  it('切换 Tab 后回来草稿仍在', async () => {
    const { user, panel } = await openMaintenance()
    fireEvent.change(within(panel).getByDisplayValue('cdnca-backups'), { target: { value: 'draft-bucket' } })
    await user.click(screen.getByRole('tab', { name: '系统升级' }))
    await user.click(screen.getByRole('tab', { name: '维护操作' }))
    const current = (await screen.findByRole('heading', { name: '异地存储' })).closest('form') as HTMLElement
    expect(within(current).getByDisplayValue('draft-bucket')).toBeInTheDocument()
  })

  it('其他会话已修改设置时保存被拒（版本冲突），草稿保留并提示', async () => {
    const { user, panel } = await openMaintenance()
    fireEvent.change(within(panel).getByDisplayValue('cdnca-backups'), { target: { value: 'draft-bucket' } })
    revision = 'rev-2'
    await user.click(within(panel).getByRole('button', { name: '保存设置' }))
    expect(await screen.findByText(/设置已被修改/)).toBeInTheDocument()
    expect(within(panel).getByDisplayValue('draft-bucket')).toBeInTheDocument()
    const save = calls.find((call) => call.url.endsWith('/settings'))
    expect(JSON.parse(String(save?.init?.body))).toMatchObject({ expected_revision: 'rev-1',
      targets: [{ stored_name: 'offsite', bucket: 'draft-bucket' }] })
  })

  it('测试连接发送当前草稿（含 stored_name 与 revision），不保存', async () => {
    const { user, panel } = await openMaintenance()
    fireEvent.change(within(panel).getByDisplayValue('cdnca-backups'), { target: { value: 'draft-bucket' } })
    await user.click(within(panel).getByRole('button', { name: '测试连接' }))
    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/targets/probe'))).toBe(true))
    const probe = calls.find((call) => call.url.endsWith('/targets/probe'))
    expect(JSON.parse(String(probe?.init?.body))).toMatchObject({ expected_revision: 'rev-1',
      target: { stored_name: 'offsite', name: 'offsite', bucket: 'draft-bucket' } })
    expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(false)
  })
})
