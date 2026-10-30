import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import ControlUpgradesPage from '../pages/ControlUpgradesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 维护操作页按任务分区——备份 / 定时备份与保留 / 存储位置 / 迁移，
// 侧栏放当前状态与安全信息；空运行记录只占一行；定时备份用「每天/指定星期」+ 时间选择器，
// 保留份数在同一卡；危险操作（恢复/删除/回退/开始迁移）红色并经二次确认。
const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
  permissions: ['control.upgrades.read', 'control.upgrades.manage', 'nodes.read', 'nodes.manage'] })

const fingerprint = 'SHA256:' + 'A'.repeat(43)
let schedule = { enabled: true, weekdays: [0, 1, 2, 3, 4, 5, 6], hour: 4, minute: 0 }
let runs: unknown[] = []
const bundle = { backup_id: '20261017T030000Z-abcdefgh', reason: 'manual', created_at: '2026-10-17T03:00:00Z', version: '1.0.35', schema_version: 580,
  bytes: 3 * 1024 * 1024, signer_fingerprint: fingerprint, signature_ok: true, components: ['postgres'] }
const status = () => ({ data: {
  keys_ready: true, signer_fingerprint: fingerprint, recipient: 'age1test', agent_installed: true, migration_ready: true, freeze: null,
  bundles: [bundle], runs, next_run_at: schedule.enabled ? '2026-10-29T04:00:00Z' : null,
  settings: { schedule, keep_local: 7, keep_remote: 14, revision: 'rev-1', targets: [] },
} })

function json(body: unknown, code = 200): Response {
  return new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } })
}

const calls: Array<{ url: string; init?: RequestInit }> = []
beforeEach(async () => {
  await changeLocale('zh-CN')
  schedule = { enabled: true, weekdays: [0, 1, 2, 3, 4, 5, 6], hour: 4, minute: 0 }
  runs = []
  calls.length = 0
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'token-1' }, admin)
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    calls.push({ url, init })
    if (url.endsWith('/v1/admin/control-backup')) return Promise.resolve(json(status()))
    if (url.endsWith('/v1/admin/control-backup/settings')) return Promise.resolve(json(status()))
    if (url.endsWith('/node-gateway-address-changes')) return Promise.resolve(json({ items: [] }))
    if (url.includes('/v1/nodes')) return Promise.resolve(json({ items: [] }))
    return Promise.resolve(json({ data: [], items: [], pagination: { page: 1, page_size: 10, total: 0 } }))
  })
})
afterEach(() => { vi.restoreAllMocks() })

async function openMaintenance() {
  const user = userEvent.setup()
  renderWithProviders(<ControlUpgradesPage />, ['/sys/op?tab=maintenance'])
  await screen.findAllByText(bundle.backup_id, { selector: 'td' })
  return user
}

const region = (name: string) => screen.getByRole('region', { name })
const savedSchedule = () => JSON.parse(String(calls.find((call) => call.url.endsWith('/settings'))?.init?.body)).schedule

describe('维护操作页分区', () => {
  it('按任务分区：备份、定时备份与保留、存储位置、迁移主控在主列，当前状态与安全信息在侧栏，节点连接单独一区', async () => {
    await openMaintenance()
    const layout = document.querySelector('.control-backup-layout')!
    const main = layout.querySelector('.control-backup-main') as HTMLElement
    const side = layout.querySelector('.control-backup-side') as HTMLElement
    for (const name of ['备份列表', '定时备份与保留', '存储位置', '迁移主控']) expect(within(main).getByRole('region', { name })).toBeInTheDocument()
    for (const name of ['当前状态', '安全信息']) expect(within(side).getByRole('region', { name })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '节点设置' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '更换主控连接地址' })).toBeInTheDocument()
  })

  it('当前状态汇总代理、最近备份、下次计划与本机份数', async () => {
    await openMaintenance()
    const card = region('当前状态')
    expect(within(card).getByText('已安装')).toBeInTheDocument()
    expect(within(card).getByText('1 份，共 3.0 MiB')).toBeInTheDocument()
    expect(within(card).getByText('未配置')).toBeInTheDocument()
    expect(within(card).getByText('下次计划')).toBeInTheDocument()
    expect(within(card).queryByText('未开启定时备份')).not.toBeInTheDocument()
  })

  it('签名指纹收在安全信息里并可复制，恢复密钥导出也在这里', async () => {
    await openMaintenance()
    const card = region('安全信息')
    expect(within(card).getByText(fingerprint)).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: /复制|Copy/i })).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: '导出' })).toBeInTheDocument()
    expect(within(region('备份列表')).queryByText(fingerprint)).not.toBeInTheDocument()
  })

  it('没有运行记录时只显示一行摘要，不渲染空表', async () => {
    await openMaintenance()
    const card = region('备份列表')
    expect(within(card).getByText(/运行记录：暂无/)).toBeInTheDocument()
    expect(within(card).getAllByRole('table')).toHaveLength(1)
  })

  it('有运行记录时显示运行记录表', async () => {
    runs = [{ id: 'r1', kind: 'backup', reason: 'manual', state: 'succeeded', requested_at: '2026-10-17T03:00:00Z', backup_id: bundle.backup_id, log: [] }]
    await openMaintenance()
    const card = region('备份列表')
    expect(within(card).getByRole('heading', { name: '运行记录' })).toBeInTheDocument()
    expect(within(card).getAllByRole('table')).toHaveLength(2)
    expect(within(card).queryByText(/运行记录：暂无/)).not.toBeInTheDocument()
  })

  it('每天：不显示星期，保存时 weekdays 为全部七天；保留份数与计划同在一卡', async () => {
    const user = await openMaintenance()
    const card = region('定时备份与保留')
    expect(within(card).getByRole('radio', { name: '每天' })).toBeChecked()
    expect(within(card).queryByRole('checkbox', { name: '一' })).not.toBeInTheDocument()
    expect(within(card).getByLabelText('本机保留份数')).toHaveValue('7')
    expect(within(card).getByLabelText('异地保留份数')).toHaveValue('14')
    expect(within(card).getByDisplayValue('04:00')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(true))
    expect(savedSchedule()).toEqual({ enabled: true, weekdays: [0, 1, 2, 3, 4, 5, 6], hour: 4, minute: 0 })
  })

  it('指定星期：显示七个星期选项，保存所选的星期', async () => {
    schedule = { enabled: true, weekdays: [1, 3], hour: 2, minute: 30 }
    const user = await openMaintenance()
    const card = region('定时备份与保留')
    expect(within(card).getByRole('radio', { name: '指定星期' })).toBeChecked()
    expect(within(card).getByRole('checkbox', { name: '一' })).toBeChecked()
    expect(within(card).getByRole('checkbox', { name: '二' })).not.toBeChecked()
    expect(within(card).getByDisplayValue('02:30')).toBeInTheDocument()
    await user.click(within(card).getByRole('checkbox', { name: '五' }))
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(true))
    expect(savedSchedule()).toEqual({ enabled: true, weekdays: [1, 3, 5], hour: 2, minute: 30 })
  })

  it('从指定星期切回每天保存全部七天；启用但一天都没选时就地报错且不保存', async () => {
    schedule = { enabled: true, weekdays: [2], hour: 4, minute: 0 }
    const user = await openMaintenance()
    const card = region('定时备份与保留')
    await user.click(within(card).getByRole('checkbox', { name: '二' }))
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    expect(await within(card).findByText('请至少选择一天')).toBeInTheDocument()
    expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(false)
    await user.click(within(card).getByText('每天'))
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(true))
    expect(savedSchedule().weekdays).toEqual([0, 1, 2, 3, 4, 5, 6])
  })

  it('时间选择器改时间后保存对应的时与分', async () => {
    const user = await openMaintenance()
    const card = region('定时备份与保留')
    const input = within(card).getByDisplayValue('04:00')
    fireEvent.mouseDown(input)
    fireEvent.change(input, { target: { value: '05:45' } })
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
    await waitFor(() => expect(within(card).getByDisplayValue('05:45')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(true))
    expect(savedSchedule()).toMatchObject({ hour: 5, minute: 45 })
  })

  it('存储位置：本机说明 + 异地为空时的提示与添加入口', async () => {
    await openMaintenance()
    const card = region('存储位置')
    expect(within(card).getByText(/每次备份都先保存在本机/)).toBeInTheDocument()
    expect(within(card).getByRole('heading', { name: '异地存储' })).toBeInTheDocument()
    expect(within(card).getByText(/还没有异地存储/)).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: '添加 S3/RustFS' })).toBeInTheDocument()
  })

  it('危险操作一律红色：备份行的恢复与删除、开始迁移', async () => {
    const user = await openMaintenance()
    const row = screen.getByText(bundle.backup_id, { selector: 'td' }).closest('tr')!
    for (const name of ['恢复', '删除']) expect(within(row).getByRole('button', { name })).toHaveClass('ant-btn-dangerous')
    expect(screen.getByRole('button', { name: '开始迁移' })).toHaveClass('ant-btn-dangerous')
    // 删除仍要输入备份号二次确认。
    await user.click(within(row).getByRole('button', { name: '删除' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('输入备份号确认删除（同时删除异地副本）')).toBeInTheDocument()
  })
})
