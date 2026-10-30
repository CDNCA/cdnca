import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import ControlUpgradesPage from '../pages/ControlUpgradesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// fix-btenv：迁移主控表单可选择新主控的目标环境（自动/宝塔/普通），随请求提交。
const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
  permissions: ['control.upgrades.read', 'control.upgrades.manage'] })

const status = { data: {
  keys_ready: true, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), recipient: 'age1test', agent_installed: true, migration_ready: true,
  freeze: null, bundles: [], next_run_at: null, runs: [],
  settings: { schedule: { enabled: false, weekdays: [1], hour: 4, minute: 0 }, keep_local: 7, keep_remote: 14, revision: 'rev-1', targets: [] },
} }

function json(body: unknown, code = 200): Response {
  return new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } })
}

const migrations: Record<string, unknown>[] = []
beforeEach(async () => {
  await changeLocale('zh-CN')
  migrations.length = 0
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'token-1' }, admin)
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    if (url.endsWith('/v1/admin/control-backup')) return Promise.resolve(json(status))
    if (url.endsWith('/v1/admin/control-backup/migrations')) {
      migrations.push(JSON.parse(String(init?.body)))
      return Promise.resolve(json({ data: { id: 'run-1', kind: 'migrate', state: 'queued', requested_at: '2026-10-28T03:00:00Z', log: [] } }, 202))
    }
    return Promise.resolve(json({ data: [], items: [], pagination: { page: 1, page_size: 10, total: 0 } }))
  })
})
afterEach(() => { vi.restoreAllMocks() })

async function openMigration() {
  const user = userEvent.setup()
  renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
  await user.click(await screen.findByRole('tab', { name: '维护操作' }))
  const panel = (await screen.findByRole('heading', { name: '迁移主控' })).closest('.control-backup-migration') as HTMLElement
  return { user, panel: within(panel) }
}

async function fillAndSubmit(user: ReturnType<typeof userEvent.setup>, panel: ReturnType<typeof within>) {
  await user.type(panel.getByLabelText('新主控 IP 或域名'), 'cdnca.com')
  await user.type(panel.getByLabelText('密码', { selector: 'input[type="password"]' }), 'ssh-pass')
  await user.type(panel.getByLabelText('主机指纹'), 'SHA256:' + 'Q'.repeat(43))
  await user.type(panel.getByLabelText('输入新主控地址确认'), 'cdnca.com')
  await user.click(panel.getByRole('button', { name: '开始迁移' }))
}

describe('迁移主控：目标环境', () => {
  it('默认“自动检测”并提交 env=auto，三个选项都有说明', async () => {
    const { user, panel } = await openMigration()
    const group = panel.getByRole('radiogroup', { name: '目标环境' })
    expect(within(group).getByRole('radio', { name: '自动检测' })).toBeChecked()
    expect(within(group).getByRole('radio', { name: '宝塔环境' })).toBeInTheDocument()
    expect(within(group).getByRole('radio', { name: '普通环境' })).toBeInTheDocument()
    expect(panel.getByText(/检测到宝塔面板（\/www\/server\/panel）即按宝塔环境迁移/)).toBeInTheDocument()
    await fillAndSubmit(user, panel)
    await waitFor(() => expect(migrations).toHaveLength(1))
    expect(migrations[0]).toMatchObject({ host: 'cdnca.com', env: 'auto' })
  })

  it('选择宝塔环境时提示迁移后要在宝塔里配置反向代理，并提交 env=bt', async () => {
    const { user, panel } = await openMigration()
    await user.click(panel.getByText('宝塔环境'))
    expect(panel.getByText(/不改动宝塔的 nginx、MySQL 与面板/)).toBeInTheDocument()
    expect(panel.getByText(/在宝塔「网站」为管理端域名添加站点并反向代理/)).toBeInTheDocument()
    await fillAndSubmit(user, panel)
    await waitFor(() => expect(migrations).toHaveLength(1))
    expect(migrations[0]).toMatchObject({ env: 'bt' })
  })

  it('选择普通环境提交 env=plain', async () => {
    const { user, panel } = await openMigration()
    await user.click(panel.getByText('普通环境'))
    await fillAndSubmit(user, panel)
    await waitFor(() => expect(migrations).toHaveLength(1))
    expect(migrations[0]).toMatchObject({ env: 'plain' })
  })
})

// fix-btenv2：迁移到宝塔目标成功后，运行记录与日志弹窗提示去新主控的宝塔配置反向代理及配置路径。
describe('迁移主控：宝塔目标完成提示', () => {
  const finished = (env: string) => ({ id: 'run-2', kind: 'migrate', reason: 'migration', state: 'succeeded', target: '203.0.113.9', target_env: env,
    requested_at: '2026-10-28T03:00:00Z', backup_id: '20261028T030000Z-abcdefgh', log: ['done: switch DNS'] })

  async function openLog(env: string) {
    status.data.runs = [finished(env)] as never
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await user.click(await screen.findByRole('tab', { name: '维护操作' }))
    return user
  }
  afterEach(() => { status.data.runs = [] })

  it('宝塔目标：运行记录标出宝塔环境，日志弹窗给出反向代理步骤与 bt-proxy.conf 路径', async () => {
    const user = await openLog('bt')
    expect(await screen.findByText('需配置宝塔反向代理')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '日志' }))
    const dialog = await screen.findByRole('dialog', { name: '运行日志' })
    expect(within(dialog).getByText('去新主控的宝塔配置反向代理')).toBeInTheDocument()
    expect(within(dialog).getByText(/\/etc\/cdnca-control\/bt-proxy\.conf/)).toBeInTheDocument()
  })

  it('普通目标没有宝塔提示', async () => {
    const user = await openLog('plain')
    await user.click(await screen.findByRole('button', { name: '日志' }))
    await screen.findByRole('dialog', { name: '运行日志' })
    expect(screen.queryByText('去新主控的宝塔配置反向代理')).not.toBeInTheDocument()
    expect(screen.queryByText('需配置宝塔反向代理')).not.toBeInTheDocument()
  })
})
