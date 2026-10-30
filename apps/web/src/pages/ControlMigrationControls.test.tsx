import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { migrationHoldEvent } from '../api/auth'
import type { ControlBackupRun, ControlBackupStatus, ControlNewMaster } from '../api/controlBackup'
import { MigrationHoldGate } from '../components/MigrationHoldGate'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'
import ControlBackupPanel from './ControlBackupPanel'
import FrozenConsolePage from './FrozenConsolePage'

// fix-migrollback: stop, rollback with the new-master guard, phase log, frozen console.

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const runID = '20261028T030000Z-0123456789ab'
function migrationRun(overrides: Partial<ControlBackupRun> = {}): ControlBackupRun {
  return { id: runID, kind: 'migrate', reason: 'migration', state: 'running', requested_at: '2026-10-28T03:00:00Z', target: '203.0.113.9',
    phase: 'transfer', backup_id: '20261028T030000Z-abcdef12', log: ['2026-10-28T03:00:01Z phase: connect', '2026-10-28T03:00:09Z phase: transfer'], ...overrides }
}

function status(run: ControlBackupRun, held: boolean): ControlBackupStatus {
  return { keys_ready: true, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), recipient: 'age1test', agent_installed: true, migration_ready: true,
    freeze: held ? { mode: 'hold', id: 'm1', acquired_at: '2026-10-28T03:00:05Z' } : null, bundles: [], runs: [run], next_run_at: null,
    settings: { schedule: { enabled: false, weekdays: [0], hour: 4, minute: 0 }, keep_local: 7, keep_remote: 14, targets: [], revision: 'r1' } }
}

const servingMaster: ControlNewMaster = { host: '203.0.113.9', run_id: runID, phase: 'done', state: 'succeeded', restored: true, reachable: true,
  dns_points_to_new: false, serving: true, control_domain: 'cdnca.com', gateway_endpoint: 'gateway.cdnca.com:443',
  clean_command: '/var/lib/cdnca-control-backup/migrate-in/control-api native-backup clean-target --bundle /var/lib/cdnca-control-backup/bundles/20261028T030000Z-abcdef12 --signer SHA256:AAA',
  held: true }

type Call = [string, RequestInit | undefined]
function mockFetch(handlers: (url: string, init: RequestInit | undefined) => Response | undefined) {
  const calls: Call[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    calls.push([url, init])
    return Promise.resolve(handlers(url, init) ?? json({ error: { code: 'not_found' } }, 404))
  })
  return calls
}

afterEach(() => { vi.restoreAllMocks() })

describe('ControlMigrationControls', () => {
  it('stops a migration before the restore with the safe-stop explanation', async () => {
    await i18n.changeLanguage('zh-CN')
    const calls = mockFetch((url, init) => {
      if (url.endsWith(`/runs/${runID}/stop`) && init?.method === 'POST') return json({ data: { run_id: runID, phase: 'transfer', abort: false } }, 202)
      if (url.endsWith('/v1/admin/control-backup')) return json({ data: status(migrationRun(), true) })
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    const progress = (await screen.findByRole('heading', { name: /最近一次迁移/ })).closest('div')!
    expect(within(progress).getByText('传输备份')).toBeInTheDocument()
    await user.click(within(progress).getByRole('button', { name: '停止迁移' }))
    expect(await screen.findByText(/本机自动解除冻结并恢复写入/)).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '停止迁移' }).at(-1)!)
    await waitFor(() => expect(calls.some(([url, init]) => url.endsWith(`/runs/${runID}/stop`) && init?.method === 'POST')).toBe(true))
  })

  it('warns that stopping during the restore aborts and keeps this host frozen', async () => {
    await i18n.changeLanguage('zh-CN')
    mockFetch((url) => url.endsWith('/v1/admin/control-backup') ? json({ data: status(migrationRun({ phase: 'restore' }), true) }) : undefined)
    const user = userEvent.setup()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    const progress = (await screen.findByRole('heading', { name: /最近一次迁移/ })).closest('div')!
    await user.click(within(progress).getByRole('button', { name: '停止迁移' }))
    expect(await screen.findByText(/停止即中止迁移，本机保持冻结/)).toBeInTheDocument()
  })

  it('requires the "new host stopped" tick, the confirmation and the password before a rollback', async () => {
    await i18n.changeLanguage('zh-CN')
    const finished = migrationRun({ state: 'succeeded', phase: 'done' })
    const calls = mockFetch((url, init) => {
      if (url.endsWith('/new-master')) return json({ data: servingMaster })
      if (url.endsWith('/rollback') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as { password: string; confirm_new_master_stopped: boolean }
        if (body.password !== 'admin-pass') return json({ error: { code: 'control_backup_password_invalid' } }, 403)
        return json({ data: { ...finished, id: '20261028T040000Z-0123456789ab', kind: 'rollback', state: 'queued' } }, 202)
      }
      if (url.endsWith('/v1/admin/control-backup')) return json({ data: status(finished, true) })
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    await user.click(await screen.findByRole('button', { name: '回退到本机' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText(/新主控可能正在对外服务/)).toBeInTheDocument()
    expect(within(dialog).getByText(/管理端 cdnca.com；Gateway gateway.cdnca.com:443/)).toBeInTheDocument()
    expect(within(dialog).getByText(/native-backup clean-target/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('当前管理员密码'), 'wrong')
    await user.click(within(dialog).getByRole('button', { name: /回\s*退/ }))
    expect(await within(dialog).findByText('请先确认新主控已停止')).toBeInTheDocument()
    expect(calls.some(([url]) => url.endsWith('/rollback'))).toBe(false)
    await user.click(within(dialog).getByRole('checkbox', { name: '我确认新主控已停止（或已清理）' }))
    await user.click(within(dialog).getByRole('checkbox', { name: /回退后以本机为准/ }))
    await user.click(within(dialog).getByRole('button', { name: /回\s*退/ }))
    expect(await within(dialog).findByText('密码不正确')).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('当前管理员密码'), 'admin-pass')
    await user.click(within(dialog).getByRole('button', { name: /回\s*退/ }))
    await waitFor(() => {
      const sent = calls.filter(([url]) => url.endsWith('/rollback')).map(([, init]) => JSON.parse(String(init!.body)))
      expect(sent.at(-1)).toEqual({ password: 'admin-pass', confirm_new_master_stopped: true, confirm: 'rollback' })
    })
  })

  it('shows the phases and a redacted note in the run log, and names a stopped run', async () => {
    await i18n.changeLanguage('zh-CN')
    const stopped = migrationRun({ state: 'stopped', phase: 'transfer', error: 'migration_stopped' })
    mockFetch((url) => url.endsWith('/v1/admin/control-backup') ? json({ data: status(stopped, false) }) : undefined)
    const user = userEvent.setup()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    await user.click((await screen.findAllByRole('button', { name: '日志' }))[0]!)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('迁移已停止，本机已恢复写入')).toBeInTheDocument()
    expect(within(dialog).getByText(/日志已脱敏/)).toBeInTheDocument()
    expect(within(dialog).getByText(/phase: transfer/)).toBeInTheDocument()
    expect(within(dialog).getByText('新主控恢复')).toBeInTheDocument()
  })

  it('has every new key in English too', async () => {
    await i18n.changeLanguage('en-US')
    mockFetch((url) => url.endsWith('/v1/admin/control-backup') ? json({ data: status(migrationRun({ state: 'succeeded', phase: 'done' }), true) }) : undefined)
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    expect(await screen.findByRole('button', { name: 'Roll back to this host' })).toBeInTheDocument()
    expect(screen.getByText(/frozen for a migration/)).toBeInTheDocument()
    await i18n.changeLanguage('zh-CN')
  })
})

describe('FrozenConsolePage', () => {
  it('switches to the frozen console on a migration hold and signs in with a frozen session', async () => {
    await i18n.changeLanguage('zh-CN')
    const calls = mockFetch((url, init) => {
      if (url.endsWith('/health/ready')) return json({ error: { code: 'control_migration_hold' } }, 503)
      if (url.endsWith('/frozen-session') && init?.method === 'POST') {
        return json({ data: { access_token: 'frozen.abc', expires_at: '2999-01-01T00:00:00Z', username: 'admin', can_manage: true } })
      }
      if (url.endsWith('/v1/admin/control-backup')) return json({ data: status(migrationRun({ state: 'failed', phase: 'verify' }), true) })
    })
    const user = userEvent.setup()
    renderWithProviders(<MigrationHoldGate><p>normal app</p></MigrationHoldGate>)
    expect(screen.getByText('normal app')).toBeInTheDocument()
    window.dispatchEvent(new Event(migrationHoldEvent))
    expect(await screen.findByRole('heading', { name: '主控迁移冻结中' })).toBeInTheDocument()
    await user.type(screen.getByLabelText('用户名'), 'admin')
    await user.type(screen.getByLabelText('密码'), 'admin-pass')
    await user.click(screen.getByRole('button', { name: /登\s*录/ }))
    expect(await screen.findByRole('button', { name: '回退到本机' })).toBeInTheDocument()
    const statusCall = calls.find(([url]) => url.endsWith('/v1/admin/control-backup'))!
    expect(new Headers(statusCall[1]!.headers).get('Authorization')).toBe('Bearer frozen.abc')
    // Only migration controls: no settings, recovery kit or new migration.
    expect(screen.queryByRole('heading', { name: '定时备份' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '迁移主控' })).not.toBeInTheDocument()
    const signIn = calls.find(([url]) => url.endsWith('/frozen-session'))!
    expect(signIn[1]!.credentials).toBe('omit')
  })

  it('shows a read-only account the controls disabled', async () => {
    await i18n.changeLanguage('zh-CN')
    mockFetch((url, init) => {
      if (url.endsWith('/health/ready')) return json({}, 503)
      if (url.endsWith('/frozen-session') && init?.method === 'POST') return json({ data: { access_token: 'frozen.abc', expires_at: '2999-01-01T00:00:00Z', username: 'viewer', can_manage: false } })
      if (url.endsWith('/v1/admin/control-backup')) return json({ data: status(migrationRun({ state: 'failed', phase: 'verify' }), true) })
    })
    const user = userEvent.setup()
    renderWithProviders(<FrozenConsolePage />)
    await user.type(screen.getByLabelText('用户名'), 'viewer')
    await user.type(screen.getByLabelText('密码'), 'viewer-pass')
    await user.click(screen.getByRole('button', { name: /登\s*录/ }))
    expect(await screen.findByText('当前账号只有查看权限')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '回退到本机' })).toBeDisabled()
  })

  it('returns to sign-in when the frozen session expires (injected clock)', async () => {
    await i18n.changeLanguage('zh-CN')
    const clock = Date.parse('2026-10-28T03:30:00Z')
    mockFetch((url, init) => {
      if (url.endsWith('/health/ready')) return json({}, 503)
      if (url.endsWith('/frozen-session') && init?.method === 'POST') return json({ data: { access_token: 'frozen.abc', expires_at: '2026-10-28T03:30:00Z', username: 'admin', can_manage: true } })
      if (url.endsWith('/v1/admin/control-backup')) return json({ data: status(migrationRun({ state: 'failed', phase: 'verify' }), true) })
    })
    const user = userEvent.setup()
    renderWithProviders(<FrozenConsolePage now={() => clock} />)
    await user.type(screen.getByLabelText('用户名'), 'admin')
    await user.type(screen.getByLabelText('密码'), 'admin-pass')
    await user.click(screen.getByRole('button', { name: /登\s*录/ }))
    await waitFor(() => expect(screen.getByRole('button', { name: /登\s*录/ })).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: '回退到本机' })).not.toBeInTheDocument()
  })
})
