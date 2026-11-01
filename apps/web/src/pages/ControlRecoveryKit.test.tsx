import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { ControlBackupStatus } from '../api/controlBackup'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'
import ControlBackupPanel from './ControlBackupPanel'

// the recovery kit is exported without a passphrase by default.

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const status: ControlBackupStatus = { keys_ready: true, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), recipient: 'age1test', agent_installed: true,
  migration_ready: true, freeze: null, bundles: [], runs: [], next_run_at: null,
  settings: { schedule: { enabled: false, weekdays: [0], hour: 4, minute: 0 }, keep_local: 7, keep_remote: 14, targets: [], revision: 'r1' } }

function mockKitFetch() {
  const bodies: unknown[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    if (url.endsWith('/recovery-kit') && init?.method === 'POST') {
      bodies.push(JSON.parse(String(init.body)))
      return Promise.resolve(json({ schema: 'cdnca.control-native-backup.recovery-kit/v1' }))
    }
    if (url.endsWith('/v1/admin/control-backup')) return Promise.resolve(json({ data: status }))
    return Promise.resolve(json({ error: { code: 'not_found' } }, 404))
  })
  return bodies
}

afterEach(() => { vi.restoreAllMocks() })

describe('ControlRecoveryKit', () => {
  it('exports without a passphrase by default and warns that the file is the credential', async () => {
    await i18n.changeLanguage('zh-CN')
    URL.createObjectURL = vi.fn(() => 'blob:kit')
    URL.revokeObjectURL = vi.fn()
    const bodies = mockKitFetch()
    const user = userEvent.setup()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    expect(await screen.findByText('这个文件就是恢复凭据，任何拿到它的人都能解开备份，请离线妥善保管。')).toBeInTheDocument()
    expect(screen.queryByLabelText('恢复口令（12–1024 个字符）')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '导出' }))
    await waitFor(() => expect(bodies).toEqual([{ passphrase: '' }]))
  })

  it('asks for a 12+ character passphrase only when the operator opts in', async () => {
    await i18n.changeLanguage('zh-CN')
    URL.createObjectURL = vi.fn(() => 'blob:kit')
    URL.revokeObjectURL = vi.fn()
    const bodies = mockKitFetch()
    const user = userEvent.setup()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    await user.click(await screen.findByRole('checkbox', { name: '再加一道口令' }))
    expect(screen.queryByText('这个文件就是恢复凭据，任何拿到它的人都能解开备份，请离线妥善保管。')).not.toBeInTheDocument()
    const input = screen.getByLabelText('恢复口令（12–1024 个字符）')
    const exportButton = screen.getByRole('button', { name: '导出' })
    await user.type(input, 'short')
    expect(exportButton).toBeDisabled()
    await user.type(input, ' but long enough')
    expect(exportButton).toBeEnabled()
    await user.click(exportButton)
    await waitFor(() => expect(bodies).toEqual([{ passphrase: 'short but long enough' }]))
  })

  it('shows the English warning', async () => {
    await i18n.changeLanguage('en-US')
    mockKitFetch()
    renderWithProviders(<ControlBackupPanel accessToken="token" canManage />)
    expect(await screen.findByText('This file is the recovery credential: anyone holding it can decrypt the backups. Keep it offline and safe.')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Also protect it with a passphrase' })).toBeInTheDocument()
    await i18n.changeLanguage('zh-CN')
  })
})
