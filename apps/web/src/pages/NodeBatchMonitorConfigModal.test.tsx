import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError } from '../api/auth'
import { nodeMonitoringApi, type NodeMonitoringOverride, type NodeMonitoringOverrideFields } from '../api/nodeMonitoring'
import { renderWithProviders } from '../test/render'
import { NodeBatchMonitorConfigModal, batchMonitorOverride } from './NodeListMonitorModals'
import './NodeListPage.locale'

const a = '018f0000-0000-7000-8000-000000000001'
const b = '018f0000-0000-7000-8000-000000000002'
const blank: NodeMonitoringOverrideFields = { monitor_enabled: null, protocol: null, probe_timeout_ms: null, monitor_port: null, monitor_action: null }
const view = (nodeID: string, revision: number, override: Partial<NodeMonitoringOverrideFields> = {}): NodeMonitoringOverride => ({
  schema_version: 1, node_id: nodeID, revision, updated_at: null, override: { ...blank, ...override },
  platform_state: 'unconfigured', platform_revision: null, effective_revision: null, effective_policy: null,
  effective_action: '', delivery_state: 'inactive',
})

describe('批量修改监控', () => {
  it('只改填写的项，保留节点已有覆盖', () => {
    expect(batchMonitorOverride({ ...blank, monitor_port: 8080, protocol: 'http' },
      { enabled: 'off', protocol: 'keep', timeout: '', port: '', action: 'pause' }))
      .toEqual({ monitor_enabled: false, protocol: 'http', probe_timeout_ms: null, monitor_port: 8080, monitor_action: 'pause' })
    expect(batchMonitorOverride(blank, { enabled: 'keep', protocol: 'tcp', timeout: '2.5', port: '443', action: 'keep' }))
      .toEqual({ ...blank, protocol: 'tcp', probe_timeout_ms: 2500, monitor_port: 443 })
  })

  it('逐个节点按各自版本保存，列出部分成功；结果未知只原样重试', async () => {
    const user = userEvent.setup()
    vi.spyOn(nodeMonitoringApi, 'getOverride').mockImplementation(async (_token, nodeID) =>
      nodeID === a ? view(a, 2, { monitor_port: 8080 }) : view(b, 5))
    const puts: Array<{ id: string; revision: number; override: NodeMonitoringOverrideFields; key: string }> = []
    let failB: ApiError | null = new ApiError('timeout', 0, 'network_error')
    vi.spyOn(nodeMonitoringApi, 'putOverride').mockImplementation(async (_token, nodeID, revision, override, key) => {
      puts.push({ id: nodeID, revision, override, key })
      if (nodeID === b && failB) { const error = failB; failB = null; throw error }
      return view(nodeID, revision + 1, override)
    })
    const onDone = vi.fn()
    const onClose = vi.fn()
    renderWithProviders(<NodeBatchMonitorConfigModal open canManage nodes={[{ id: a, name: 'A' }, { id: b, name: 'B' }]}
      getAccessToken={() => 'token'} onDenied={vi.fn()} onDone={onDone} onClose={onClose} />)
    const dialog = await screen.findByRole('dialog')
    // 未改任何项不提交。
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('请至少修改一项')).toBeInTheDocument()
    expect(puts).toHaveLength(0)
    await user.click(within(dialog).getAllByRole('radio', { name: '暂停' })[0]!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(screen.getByText('修改监控结果')).toBeInTheDocument())
    expect(puts.map((item) => [item.id, item.revision, item.override.monitor_action, item.override.monitor_port]))
      .toEqual([[a, 2, 'pause', 8080], [b, 5, 'pause', null]])
    expect(screen.getByText('已保存')).toBeInTheDocument()
    expect(screen.getByText('结果待确认')).toBeInTheDocument()
    // 结果未知时不能关闭。
    expect(screen.getByRole('button', { name: '关闭' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: /重试未成功的 1 个节点/ }))
    await waitFor(() => expect(screen.getAllByText('已保存')).toHaveLength(2))
    // 重试复用同一修订号与幂等键，不重新读取 B。
    expect(puts).toHaveLength(3)
    expect(puts[2]).toEqual(puts[1])
    expect(vi.mocked(nodeMonitoringApi.getOverride).mock.calls.filter(([, id]) => id === b)).toHaveLength(1)
    expect(onDone).toHaveBeenCalledTimes(2)
    await user.click(screen.getByRole('button', { name: '关闭' }))
    expect(onClose).toHaveBeenCalled()
  })

  it('版本冲突列为失败，重试时重新读取最新版本；无权限立即交给页面处理', async () => {
    const user = userEvent.setup()
    let revision = 1
    vi.spyOn(nodeMonitoringApi, 'getOverride').mockImplementation(async (_token, nodeID) => view(nodeID, revision))
    let conflict = true
    const put = vi.spyOn(nodeMonitoringApi, 'putOverride').mockImplementation(async (_token, nodeID, expected, override) => {
      if (conflict) { conflict = false; revision = 2; throw new ApiError('stale', 409, 'version_conflict') }
      return view(nodeID, expected + 1, override)
    })
    renderWithProviders(<NodeBatchMonitorConfigModal open canManage nodes={[{ id: a, name: 'A' }]}
      getAccessToken={() => 'token'} onDenied={vi.fn()} onDone={vi.fn()} onClose={vi.fn()} />)
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getAllByRole('radio', { name: '关闭' })[0]!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText(/已被其他人修改/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '关闭' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: /重试未成功的 1 个节点/ }))
    await waitFor(() => expect(screen.getByText('已保存')).toBeInTheDocument())
    expect(put.mock.calls[1]?.[2]).toBe(2)

    const denied = vi.fn()
    put.mockRejectedValue(new ApiError('forbidden', 403, 'permission_denied'))
    renderWithProviders(<NodeBatchMonitorConfigModal open canManage nodes={[{ id: b, name: 'B' }]}
      getAccessToken={() => 'token'} onDenied={denied} onDone={vi.fn()} onClose={vi.fn()} />)
    const second = (await screen.findAllByRole('dialog')).at(-1)!
    await user.click(within(second).getAllByRole('radio', { name: '开启' })[0]!)
    await user.click(within(second).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(denied).toHaveBeenCalled())
  })

  it('没有管理权限时不能提交', async () => {
    renderWithProviders(<NodeBatchMonitorConfigModal open canManage={false} nodes={[{ id: a, name: 'A' }]}
      getAccessToken={() => null} onDenied={vi.fn()} onDone={vi.fn()} onClose={vi.fn()} />)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
  })
})
