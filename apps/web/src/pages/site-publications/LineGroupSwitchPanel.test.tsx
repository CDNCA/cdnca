import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import type { ComponentProps } from 'react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { ApiError, type Principal } from '../../api/auth'
import * as lineSwitchAPI from '../../api/l4LineSwitches'
import { resetSessionStore, useSessionStore } from '../../auth/session'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import LineGroupSwitchPanel, { type LineGroupSwitchOption } from './LineGroupSwitchPanel'

// antd 测试环境所有 Modal 的 aria-labelledby 都是 test-id，可访问名取的是 DOM 里第一个 test-id（常是反馈弹窗标题）；
// 业务弹窗按自身标题匹配，并排除反馈弹窗（.cdnca-feedback）
const pageDialogs = (name?: string) => screen.queryAllByRole('dialog')
  .filter((element) => !element.classList.contains('cdnca-feedback'))
  .filter((element) => name === undefined || element.querySelector('.ant-modal-title, .ant-drawer-title')?.textContent?.trim() === name)
const pageDialog = (name: string) => { const [element] = pageDialogs(name); if (!element) throw new Error(`no dialog ${name}`); return element }

vi.mock('../../api/l4LineSwitches', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/l4LineSwitches')>()
  return {
    ...actual,
    createL4LineSwitch: vi.fn(),
    getCurrentL4LineSwitch: vi.fn(),
    newL4LineSwitchWriteMetadata: vi.fn(actual.newL4LineSwitchWriteMetadata),
    reconcileL4LineSwitch: vi.fn(),
  }
})

const scopeID = '11111111-1111-4111-8111-111111111111'
const from: LineGroupSwitchOption = {
  id: '22222222-2222-4222-8222-222222222222', label: '线路 A (v3)',
}
const to: LineGroupSwitchOption = {
  id: '33333333-3333-4333-8333-333333333333', label: '线路 B (v7)',
}

const fromSnapshot = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', revision: 3, sha256: '31'.repeat(32) }
const toSnapshot = { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', revision: 7, sha256: '72'.repeat(32) }
const frozenMetadata: lineSwitchAPI.L4LineSwitchWriteMetadata = {
  requestId: '55555555-5555-4555-8555-555555555555',
  correlationId: '66666666-6666-4666-8666-666666666666',
  idempotencyKey: 'l4-line-switch-frozen',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

function actor(overrides: Partial<Principal> = {}): Principal {
  return principal({
    user_id: '77777777-7777-4777-8777-777777777777',
    scope_id: '88888888-8888-4888-8888-888888888888',
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions: ['edge_publications.manage'],
    ...overrides,
  })
}

function setSession(accessToken = 'token', value = actor(), update: 'new' | 'refresh' = 'new') {
  useSessionStore.getState().setSession({ ...authResponse(value), access_token: accessToken }, value, update)
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

async function submitCreate() {
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: '切换线路组' }))
  const fromSelect = screen.getByRole('combobox', { name: '原线路组' })
  const toSelect = screen.getByRole('combobox', { name: '目标线路组' })
  fireEvent.mouseDown(fromSelect.closest('.ant-select')!.querySelector('.ant-select-selector')!)
  fireEvent.click(await screen.findByText(from.label, { selector: '.ant-select-item-option-content' }))
  fireEvent.mouseDown(toSelect.closest('.ant-select')!.querySelector('.ant-select-selector')!)
  const targetOptions = await screen.findAllByText(to.label, { selector: '.ant-select-item-option-content' })
  fireEvent.click(targetOptions.at(-1)!)
  await user.click(screen.getByRole('button', { name: '确认切换' }))
}

function renderPanel(overrides: Partial<ComponentProps<typeof LineGroupSwitchPanel>> = {}) {
  return renderWithProviders(
    <LineGroupSwitchPanel
      accessToken="token"
      scopeID={scopeID}
      currentSourceRevision={19}
      snapshots={[from, to]}
      canManage
      loadSnapshot={vi.fn(async (id) => id === from.id ? fromSnapshot : toSnapshot)}
      {...overrides}
    />,
  )
}

function switchResult(): lineSwitchAPI.L4LineSwitch {
  return {
    id: '44444444-4444-4444-8444-444444444444',
    configuration_scope_id: scopeID,
    expected_source_revision: 19,
    from: fromSnapshot,
    to: toSnapshot,
    prepare_node_count: 3,
    retiring_node_count: 1,
    state: 'health_gate',
    state_revision: 2,
    prepare_publication: {},
    compensation_publication: {},
    drain_command_count: 0,
    deadline: '2026-08-07T04:00:00Z',
    created_at: '2026-08-07T03:00:00Z',
    updated_at: '2026-08-07T03:01:00Z',
  }
}

describe('LineGroupSwitchPanel', () => {
  beforeEach(() => {
    resetSessionStore()
    setSession()
    vi.mocked(lineSwitchAPI.createL4LineSwitch).mockReset()
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch).mockReset().mockResolvedValue(null)
    vi.mocked(lineSwitchAPI.newL4LineSwitchWriteMetadata).mockReset().mockReturnValue(frozenMetadata)
    vi.mocked(lineSwitchAPI.reconcileL4LineSwitch).mockReset()
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('requires two immutable snapshots before enabling a switch', () => {
    renderWithProviders(
      <LineGroupSwitchPanel accessToken="token" scopeID={scopeID} currentSourceRevision={19} snapshots={[from]} canManage loadSnapshot={vi.fn()} />,
    )
    expect(screen.getByRole('button', { name: '切换线路组' })).toBeDisabled()
    expect(screen.getByText('暂无进行中的线路切换')).toBeInTheDocument()
  })

  it('creates from distinct exact snapshots and renders health-gate facts', async () => {
    const create = vi.mocked(lineSwitchAPI.createL4LineSwitch).mockResolvedValue(switchResult())
    const changed = vi.fn()
    renderPanel({ onChanged: changed })
    await submitCreate()
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]?.[2]).toMatchObject({
      expected_source_revision: 19,
      from: fromSnapshot,
      to: toSnapshot,
    })
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ state: 'health_gate' }))
    expect(await screen.findByText('新线路健康检查中')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('explains a reconcile that waits for DNS before draining old listeners', async () => {
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch).mockResolvedValue(switchResult())
    vi.mocked(lineSwitchAPI.reconcileL4LineSwitch).mockResolvedValue({
      ...switchResult(), dns_gate: { state: 'retarget_pending', owners: 2, pending_owners: 1 },
    })
    renderPanel()
    await userEvent.click(await screen.findByRole('button', { name: '推进并刷新' }))
    expect(await screen.findByText('等待解析切走旧节点（1/2 个域名未完成），旧节点端口保持监听')).toBeInTheDocument()
  })

  it('renders a readable reason for a DNS timeout rollback', async () => {
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch).mockResolvedValue({
      ...switchResult(), state: 'compensating_old', error_code: 'DNS_PROPAGATION_TIMEOUT',
    })
    renderPanel()
    expect(await screen.findByText(/在整体期限内 DNS 未切离旧节点/)).toBeInTheDocument()
  })

  it('freezes create metadata before snapshot loading and reuses the exact command after an unknown outcome', async () => {
    const firstSnapshot = deferred<lineSwitchAPI.L4LineSnapshotReference>()
    const secondSnapshot = deferred<lineSwitchAPI.L4LineSnapshotReference>()
    const loadSnapshot = vi.fn((id: string) => id === from.id ? firstSnapshot.promise : secondSnapshot.promise)
    const create = vi.mocked(lineSwitchAPI.createL4LineSwitch)
      .mockRejectedValueOnce(new ApiError('network', 0, 'network_error'))
      .mockResolvedValueOnce(switchResult())
    renderPanel({ loadSnapshot })

    await submitCreate()
    expect(lineSwitchAPI.newL4LineSwitchWriteMetadata).toHaveBeenCalledTimes(1)
    expect(create).not.toHaveBeenCalled()
    await act(async () => {
      firstSnapshot.resolve(fromSnapshot)
      secondSnapshot.resolve(toSnapshot)
      await Promise.all([firstSnapshot.promise, secondSnapshot.promise])
    })

    expect(await screen.findByRole('dialog', { name: '线路切换结果未知' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '取消' })).not.toBeInTheDocument()
    const firstCall = create.mock.calls[0]
    await userEvent.click(screen.getByRole('button', { name: '按原命令重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(firstCall)
    expect(lineSwitchAPI.newL4LineSwitchWriteMetadata).toHaveBeenCalledTimes(1)
  })

  it('blocks a create before the API when the token lineage changes during snapshot loading', async () => {
    const snapshotsReady = deferred<void>()
    const loadSnapshot = vi.fn(async (id: string) => {
      await snapshotsReady.promise
      return id === from.id ? fromSnapshot : toSnapshot
    })
    renderPanel({ loadSnapshot })
    await submitCreate()
    expect(lineSwitchAPI.newL4LineSwitchWriteMetadata).toHaveBeenCalledTimes(1)
    act(() => setSession('refreshed-token', actor(), 'refresh'))
    await act(async () => snapshotsReady.resolve())
    await waitFor(() => expect(lineSwitchAPI.createL4LineSwitch).not.toHaveBeenCalled())
    expect(screen.queryByRole('dialog', { name: '线路切换结果未知' })).not.toBeInTheDocument()
  })

  it('treats snapshot preflight failure as known before the create API is sent', async () => {
    renderPanel({ loadSnapshot: vi.fn().mockRejectedValue(new ApiError('unavailable', 503, 'request_failed')) })
    await submitCreate()
    expect(await screen.findByText('线路切换操作未完成')).toBeInTheDocument()
    expect(lineSwitchAPI.createL4LineSwitch).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog', { name: '线路切换结果未知' })).not.toBeInTheDocument()
  })

  it('reuses the complete reconcile command after a 5xx and drops it when the owner changes', async () => {
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch).mockResolvedValue(switchResult())
    const reconcile = vi.mocked(lineSwitchAPI.reconcileL4LineSwitch)
      .mockRejectedValueOnce(new ApiError('unavailable', 503, 'request_failed'))
      .mockRejectedValueOnce(new ApiError('unavailable', 503, 'request_failed'))
    renderPanel()
    await userEvent.click(await screen.findByRole('button', { name: '推进并刷新' }))
    expect(await screen.findByRole('dialog', { name: '线路切换结果未知' })).toBeInTheDocument()
    expect(reconcile.mock.calls[0]?.[3]).toEqual(frozenMetadata)
    const firstCall = reconcile.mock.calls[0]
    await userEvent.click(screen.getByRole('button', { name: '按原命令重试' }))
    await waitFor(() => expect(reconcile).toHaveBeenCalledTimes(2))
    expect(reconcile.mock.calls[1]).toEqual(firstCall)
    expect(lineSwitchAPI.newL4LineSwitchWriteMetadata).toHaveBeenCalledTimes(1)

    act(() => setSession('other-token', actor({ user_id: '99999999-9999-4999-8999-999999999999' })))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '线路切换结果未知' })).not.toBeInTheDocument())
    expect(reconcile).toHaveBeenCalledTimes(2)
  })

  it.each([
    [400, 'validation_error', '线路切换请求无效'],
    [403, 'permission_denied', '没有权限执行线路切换'],
  ])('treats deterministic %i create failures as terminal', async (status, code, expected) => {
    vi.mocked(lineSwitchAPI.createL4LineSwitch).mockRejectedValue(new ApiError('terminal', status, code))
    renderPanel()
    await submitCreate()
    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '线路切换结果未知' })).not.toBeInTheDocument()
  })

  it('keeps an unknown command until an authoritative refresh succeeds', async () => {
    vi.mocked(lineSwitchAPI.createL4LineSwitch).mockRejectedValue(new ApiError('network', 0, 'network_error'))
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch)
      .mockResolvedValueOnce(null)
      .mockRejectedValueOnce(new ApiError('network', 0, 'network_error'))
      .mockResolvedValueOnce(switchResult())
    renderPanel()
    await submitCreate()
    expect(await screen.findByRole('dialog', { name: '线路切换结果未知' })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: '放弃并刷新事实' }))
    await waitFor(() => expect(lineSwitchAPI.getCurrentL4LineSwitch).toHaveBeenCalledTimes(2))
    expect(pageDialog('线路切换结果未知')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '放弃并刷新事实' }))
    await waitFor(() => expect(pageDialogs('线路切换结果未知')).toHaveLength(0))
  })

  it('renders read denial with a natural retry and hides reconcile for terminal state', async () => {
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch)
      .mockRejectedValueOnce(new ApiError('forbidden', 403, 'permission_denied'))
      .mockResolvedValueOnce({ ...switchResult(), state: 'completed' })
    renderPanel()
    expect(await screen.findByText('没有权限读取线路切换状态')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '重新读取' }))
    expect(await screen.findByText('切换完成')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '推进并刷新' })).not.toBeInTheDocument()
  })

  it('restores the latest durable switch after a page reload', async () => {
    vi.mocked(lineSwitchAPI.getCurrentL4LineSwitch).mockResolvedValue(switchResult())
    renderWithProviders(
      <LineGroupSwitchPanel
        accessToken="token"
        scopeID={scopeID}
        currentSourceRevision={19}
        snapshots={[from, to]}
        canManage
        loadSnapshot={vi.fn()}
      />,
    )
    expect(await screen.findByText('新线路健康检查中')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '推进并刷新' })).toBeEnabled()
  })
})
