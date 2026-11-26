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
    fireEvent.change(within(panel).getAllByLabelText('访问密钥')[0], { target: { value: 'typed-secret' } })
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
    expect(within(current).getAllByLabelText('访问密钥')[0]).toHaveValue('typed-secret')
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
    expect(await screen.findByText(/内容已被其他人修改，请刷新后再保存/)).toBeInTheDocument()
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

// 
describe('存储目标与迁移表单的字段校验和首错聚焦', () => {
  it('S3 存储桶留空：标在存储桶输入框并聚焦，不发保存请求；字段名为中文', async () => {
    const { user, panel } = await openMaintenance()
    for (const label of ['服务地址（HTTPS）', '区域', '存储桶', '访问密钥 ID', '访问密钥', '路径式访问（RustFS/MinIO 选开）']) {
      expect(within(panel).getAllByLabelText(label).length).toBeGreaterThan(0)
    }
    expect(panel).not.toHaveTextContent(/Endpoint|Region|Bucket|Access Key|Secret Key|Path style/)
    const bucket = within(panel).getByDisplayValue('cdnca-backups')
    fireEvent.change(bucket, { target: { value: '' } })
    await user.click(within(panel).getByRole('button', { name: '保存设置' }))
    expect(await within(panel).findByText('请填写存储桶名称：3–63 个小写字母、数字、点或短横线')).toBeInTheDocument()
    await waitFor(() => expect(bucket).toHaveFocus())
    expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(false)
  })

  it('S3 存储桶留空点测试连接：同样聚焦存储桶输入框，不发探测请求', async () => {
    const { user, panel } = await openMaintenance()
    const bucket = within(panel).getByDisplayValue('cdnca-backups')
    fireEvent.change(bucket, { target: { value: '' } })
    await user.click(within(panel).getByRole('button', { name: '测试连接' }))
    expect(await within(panel).findByText('请填写存储桶名称：3–63 个小写字母、数字、点或短横线')).toBeInTheDocument()
    await waitFor(() => expect(bucket).toHaveFocus())
    expect(calls.some((call) => call.url.endsWith('/targets/probe'))).toBe(false)
  })

  it('服务端按 field 拒绝时把中文原因标到对应输入框，不弹「设置无效」、不显示英文原文', async () => {
    const { user, panel } = await openMaintenance()
    vi.mocked(globalThis.fetch).mockImplementation((input, init) => {
      const url = String(input)
      calls.push({ url, init })
      if (url.endsWith('/v1/admin/control-backup/settings')) return Promise.resolve(json({ error: { code: 'control_backup_invalid_settings',
        request_id: 'req-field', details: { target: 'offsite', field: 'region' } } }, 400))
      return Promise.resolve(json(status()))
    })
    fireEvent.change(within(panel).getAllByLabelText('访问密钥 ID')[0], { target: { value: 'AKIA' } })
    await user.click(within(panel).getByRole('button', { name: '保存设置' }))
    expect(await within(panel).findByText('请填写区域，如 us-east-1（小写字母、数字、短横线）')).toBeInTheDocument()
    await waitFor(() => expect(within(panel).getByDisplayValue('us-east-1')).toHaveFocus())
    expect(screen.queryByText('设置无效')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/needs an https endpoint|S3 target/)
  })

  it('新建 SFTP 目标：主机指纹等字段带必填标记，留空保存提示「请先获取并核对主机指纹」', async () => {
    const { user, panel } = await openMaintenance()
    await user.click(within(panel).getByRole('button', { name: '添加 SFTP' }))
    const hostKey = within(panel).getByLabelText('主机指纹')
    expect(hostKey.closest('.ant-form-item')!.querySelector('.ant-form-item-required')).not.toBeNull()
    for (const label of ['主机', '端口', '用户名', '远端目录']) {
      expect(within(panel).getAllByLabelText(label).at(-1)!.closest('.ant-form-item')!.querySelector('.ant-form-item-required'), label).not.toBeNull()
    }
    fireEvent.change(within(panel).getAllByLabelText('远端目录').at(-1)!, { target: { value: 'backups' } })
    await user.click(within(panel).getByRole('button', { name: '保存设置' }))
    expect(await within(panel).findByText('请先获取并核对主机指纹')).toBeInTheDocument()
    expect(within(panel).getByText('请填写以 / 开头的绝对目录，如 /backups/cdnca')).toBeInTheDocument()
    expect(within(panel).getByText('请填写主机名或 IP')).toBeInTheDocument()
    expect(calls.some((call) => call.url.endsWith('/settings'))).toBe(false)
  })

  it('迁移表单空提交：地址未填时不报「确认内容不一致」，焦点落到新主控地址', async () => {
    const { user } = await openMaintenance()
    const migration = screen.getByRole('heading', { name: '迁移主控' }).closest('section') as HTMLElement
    await user.click(within(migration).getByRole('button', { name: '开始迁移' }))
    await waitFor(() => expect(within(migration).getByLabelText('新主控 IP 或域名')).toHaveFocus())
    expect(within(migration).queryByText('确认内容不一致')).not.toBeInTheDocument()
    fireEvent.change(within(migration).getByLabelText('新主控 IP 或域名'), { target: { value: '203.0.113.9' } })
    fireEvent.change(within(migration).getByLabelText('输入新主控地址确认'), { target: { value: 'wrong' } })
    await user.click(within(migration).getByRole('button', { name: '开始迁移' }))
    expect(await within(migration).findByText('确认内容不一致')).toBeInTheDocument()
    expect(calls.some((call) => call.url.includes('/migrations'))).toBe(false)
  })
})

