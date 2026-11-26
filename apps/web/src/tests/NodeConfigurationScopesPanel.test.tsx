import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { nodesApi, type NodeConfigurationScopes } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { NodeConfigurationScopesPanel } from '../components/NodeConfigurationScopesPanel'
import i18n from '../i18n'
import { nodeConfigurationScopesMessages } from '../i18n/nodeConfigurationScopes'

const nodeID = '018f0000-0000-7000-8000-000000000001'
const alpha = '018f0000-0000-7000-8000-0000000000a1'
const beta = '018f0000-0000-7000-8000-0000000000b1'
const version = '018f0000-0000-7000-8000-0000000000c1'

const shared: NodeConfigurationScopes = {
  node_id: nodeID,
  scopes: [
    {
      scope_id: alpha, scope_kind: 'tenant', tenant_id: '018f0000-0000-7000-8000-0000000000a2', tenant_name: 'Alpha',
      current_config_version_id: null, previous_config_version_id: null, reconciliation_required: false,
      updated_at: '2026-10-16T08:00:00Z',
      latest_deployment: {
        deployment_id: '018f0000-0000-7000-8000-0000000000d1', attempt: 1, rollout_id: '018f0000-0000-7000-8000-0000000000e1',
        config_version_id: version, action: 'apply', state: 'agent_queued', updated_at: '2026-10-16T08:00:00Z',
      },
      last_apply: null,
      telemetry_excluded: '',
    },
    {
      scope_id: beta, scope_kind: 'tenant', tenant_id: '018f0000-0000-7000-8000-0000000000b2', tenant_name: 'Beta',
      current_config_version_id: version, previous_config_version_id: null, reconciliation_required: true,
      updated_at: '2026-10-16T08:01:00Z',
      latest_deployment: {
        deployment_id: '018f0000-0000-7000-8000-0000000000d2', attempt: 2, rollout_id: '018f0000-0000-7000-8000-0000000000e2',
        config_version_id: version, action: 'apply', state: 'started', updated_at: '2026-10-16T08:01:00Z',
      },
      last_apply: {
        deployment_id: '018f0000-0000-7000-8000-0000000000d2', attempt: 2, config_version_id: version, state: 'superseded',
        error_code: null, finished_at: null, reported_at: '2026-10-16T08:01:00Z',
      },
      telemetry_excluded: 'invalid_config_version',
    },
  ],
  rejections: [{
    scope_id: alpha, tenant_name: 'Alpha', reason: 'port 80 (ipv4) would mix plaintext and TLS with another tenant',
    request_id: 'publish-refused', occurred_at: '2026-10-16T07:59:00Z',
  }],
  capability_regressions: [],
}

function renderPanel(accessToken: () => string | null = () => 'token') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ConfigProvider>
      <AntApp>
        <QueryClientProvider client={client}>
          <MemoryRouter>
            <NodeConfigurationScopesPanel nodeID={nodeID} queryKey={['node', nodeID]} accessToken={accessToken} />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

describe('NodeConfigurationScopesPanel', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh-CN')
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows every tenant with its deployment and apply state and the refused publications', async () => {
    const get = vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(shared)
    renderPanel()
    expect(await screen.findByText('Beta')).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('token', nodeID)
    const tenants = screen.getAllByRole('table')[0]!
    expect(within(tenants).getAllByText('Alpha').length).toBeGreaterThan(0)
    expect(within(tenants).getByText('节点排队中')).toBeInTheDocument()
    expect(within(tenants).getByText('已开始')).toBeInTheDocument()
    expect(within(tenants).getByText('已被新版本替换')).toBeInTheDocument()
    expect(within(tenants).getByText('待对账')).toBeInTheDocument()
    // Only Beta's telemetry is isolated; the tag explains why on hover.
    const isolated = within(tenants).getAllByText('遥测已隔离')
    expect(isolated).toHaveLength(1)
    fireEvent.mouseEnter(isolated[0]!)
    expect(await screen.findByText(/这个租户在本节点上的某个配置版本无法读取/)).toBeInTheDocument()
    const refused = screen.getAllByRole('table')[1]!
    expect(within(refused).getByText('port 80 (ipv4) would mix plaintext and TLS with another tenant')).toBeInTheDocument()
    expect(within(refused).getByText('publish-refused')).toBeInTheDocument()
  })

  // 复制按钮按列与租户命名，名称里不含完整 UUID
  it('names each copy button by column and tenant without the full identifier', async () => {
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue({
      ...shared,
      scopes: [shared.scopes[0]!, { ...shared.scopes[1]!, previous_config_version_id: alpha }],
    })
    renderPanel()
    expect(await screen.findByText('Beta')).toBeInTheDocument()
    const tenants = screen.getAllByRole('table')[0]!
    expect(within(tenants).getByRole('button', { name: '复制 Alpha 的租户 ID' })).toBeInTheDocument()
    expect(within(tenants).getByRole('button', { name: '复制 Beta 的租户 ID' })).toBeInTheDocument()
    expect(within(tenants).getByRole('button', { name: '复制 Beta 的当前配置版本' })).toBeInTheDocument()
    expect(within(tenants).getByRole('button', { name: '复制 Beta 的上一配置版本' })).toBeInTheDocument()
    expect(within(tenants).queryByRole('button', { name: '复制' })).not.toBeInTheDocument()
    for (const button of within(tenants).getAllByRole('button', { name: /^复制/ })) {
      for (const id of [alpha, beta, version]) expect(button).not.toHaveAccessibleName(new RegExp(id))
    }
  })

  it('warns when the node agent no longer declares a feature its healthy deployment uses', async () => {
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue({
      ...shared,
      capability_regressions: [{
        scope_id: beta, deployment_id: '018f0000-0000-7000-8000-0000000000d2', config_version_id: version,
        feature: 'l4_tls_passthrough', capability: 'CAPABILITY_NAME_TCP_PROXY', required: 4, declared: 3, agent_version: '1.0.33',
      }],
    })
    renderPanel()
    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('节点版本低于正在使用的功能')).toBeInTheDocument()
    expect(within(alert).getByText(/Beta 最近一次健康部署（版本 018f0000）用到了四层 TLS 透传（按 SNI）或与网站共享端口，但节点当前的 agent（1\.0\.33）只声明 TCP_PROXY v3，需要 v4/)).toBeInTheDocument()
    expect(within(alert).getByText(/把节点 agent 重新升级到 1\.0\.35 或更高版本/)).toBeInTheDocument()
    expect(within(alert).queryByText(/prepare-l4-rollback/)).toBeNull()
  })

  it('shows no warning when every feature in use is declared', async () => {
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(shared)
    renderPanel()
    expect(await screen.findByText('Beta')).toBeInTheDocument()
    expect(screen.queryByText('节点版本低于正在使用的功能')).not.toBeInTheDocument()
  })

  // 首代回滚失败后作用域待对账，之后的自动发布一直 retry_wait；面板给出可执行的对账动作。
  const asPlatform = (permissions: string[]) => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions })
    useSessionStore.getState().setSession(authResponse(actor), actor)
  }
  const waitingScopes = (): NodeConfigurationScopes => ({
    ...shared,
    scopes: [{ ...shared.scopes[1]!, reconciliation: {
      reason: 'rollback_failed', source_deployment_id: '018f0000-0000-7000-8000-0000000000d2', source_deployment_attempt: 1,
      observation: 'confirmed', unconfirmed_reason: null, reported_config_version_id: null, reported_at: '2026-10-16T08:02:00Z',
    } }],
  })

  // 节点最近应用回滚失败、待对账时默认写「回滚失败，需对账」，
  // 原始错误与最近一次恢复记录收在可展开的详情里。
  it('says a failed rollback needs reconciliation and folds the raw error and the recovery record', async () => {
    asPlatform(['nodes.read'])
    const waiting = waitingScopes()
    waiting.scopes[0] = { ...waiting.scopes[0]!, last_apply: {
      deployment_id: '018f0000-0000-7000-8000-0000000000d2', attempt: 1, config_version_id: version, state: 'rollback_failed',
      error_code: 'UNAVAILABLE', finished_at: '2026-10-16T08:00:00Z', reported_at: '2026-10-16T08:01:00Z',
    } }
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(waiting)
    renderPanel()
    const tenants = (await screen.findAllByRole('table'))[0]!
    expect(await within(tenants).findByText('回滚失败，需对账')).toBeInTheDocument()
    const detail = within(tenants).getByTestId('node-scope-apply-detail')
    expect((detail as HTMLDetailsElement).open).toBe(false)
    expect(detail).toHaveTextContent('原始错误：UNAVAILABLE')
    expect(detail).toHaveTextContent(/最近一次恢复记录：节点上报运行 无（节点已明确退回空配置）（2026/)
  })

  // 只读（nodes.read、无 edge_publications.manage）看得到对账状态，没有写动作。
  it('shows the reconciliation state but no action to a read-only platform account', async () => {
    asPlatform(['nodes.read'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(waitingScopes())
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockResolvedValue()
    renderPanel()
    const row = await screen.findByTestId('node-scope-reconciliation')
    expect(within(row).getByText(/部署 018f0000（第 1 次）回滚失败/)).toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: '按节点上报状态对账' })).toBeNull()
    expect(reconcile).not.toHaveBeenCalled()
  })

  it('reconciles a scope waiting on a failed rollback with what the node reports', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const waiting: NodeConfigurationScopes = {
      ...shared,
      scopes: [{ ...shared.scopes[1]!, reconciliation: {
        reason: 'rollback_failed', source_deployment_id: '018f0000-0000-7000-8000-0000000000d2', source_deployment_attempt: 1,
        observation: 'confirmed', unconfirmed_reason: null, reported_config_version_id: null, reported_at: '2026-10-16T08:02:00Z',
      } }],
    }
    const get = vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValueOnce(waiting)
      .mockResolvedValueOnce({ ...waiting, scopes: [{ ...shared.scopes[1]!, reconciliation_required: false, reconciliation: null }] })
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockResolvedValue()
    renderPanel()
    const row = await screen.findByTestId('node-scope-reconciliation')
    expect(within(row).getByText(/部署 018f0000（第 1 次）回滚失败/)).toBeInTheDocument()
    fireEvent.click(within(row).getByRole('button', { name: '按节点上报状态对账' }))
    expect(await screen.findByRole('dialog', { name: '按节点上报的状态结束待对账？' })).toBeInTheDocument()
    expect(await screen.findByText(/节点心跳上报这个租户当前运行的配置是 无（节点已明确退回空配置）/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^对\s?账$/ }))
    await waitFor(() => expect(reconcile).toHaveBeenCalledWith('token', nodeID, waiting.scopes[0], undefined))
    expect(await screen.findByText('已对账，已解除这个节点的对账限制。已超时的发布不会自动重发，请到网站详情点“重新发布”。')).toBeInTheDocument()
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(screen.queryByTestId('node-scope-reconciliation')).not.toBeInTheDocument()
  })

  // 节点仍在服务但心跳上报为空且仍报回滚失败——显示「节点状态未确认」，不以空配置为依据，只给人工确认。
  it('says the node state is unconfirmed and only offers a manual confirmation', async () => {
    const waiting: NodeConfigurationScopes = {
      ...shared,
      scopes: [{ ...shared.scopes[1]!, reconciliation: {
        reason: 'rollback_failed', source_deployment_id: '018f0000-0000-7000-8000-0000000000d2', source_deployment_attempt: 1,
        observation: 'unconfirmed', unconfirmed_reason: 'contradicting_report', reported_config_version_id: null, reported_at: null,
      } }],
    }
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(waiting)
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockResolvedValue()
    renderPanel()
    const row = await screen.findByTestId('node-scope-reconciliation')
    expect(within(row).getByTestId('node-scope-unconfirmed')).toHaveTextContent('节点状态未确认：节点上报互相矛盾')
    expect(within(row).queryByRole('button', { name: '按节点上报状态对账' })).not.toBeInTheDocument()
    fireEvent.click(within(row).getByRole('button', { name: '人工确认后对账' }))
    expect(await screen.findByText(/节点状态未确认，主控无法以节点上报为准/)).toBeInTheDocument()
    expect(screen.queryByText(/无（节点已明确退回空配置）/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^对\s?账$/ }))
    await waitFor(() => expect(reconcile).toHaveBeenCalledWith('token', nodeID, waiting.scopes[0], undefined))
  })

  // 首代回滚失败、节点状态未确认，而节点最近应用就是这次失败部署：
  // 对账弹窗多一个默认不勾选的「节点仍在服务原发布」，勾选后按原部署自己的版本人工确认。
  const failedSource = '018f0000-0000-7000-8000-0000000000d2'
  const servingVersion = '018f0000-0000-7000-8000-0000000000c9'
  const unconfirmedSource = (overrides: Partial<NodeConfigurationScopes['scopes'][number]> = {}): NodeConfigurationScopes => ({
    ...shared,
    scopes: [{
      ...shared.scopes[1]!, current_config_version_id: null,
      last_apply: {
        deployment_id: failedSource, attempt: 1, config_version_id: servingVersion, state: 'rollback_failed',
        error_code: 'ROLLBACK_RESTORE_FAILED', finished_at: '2026-11-22T17:00:00Z', reported_at: '2026-11-22T17:01:00Z',
      },
      reconciliation: {
        reason: 'rollback_failed', source_deployment_id: failedSource, source_deployment_attempt: 1,
        observation: 'unconfirmed', unconfirmed_reason: 'contradicting_report', reported_config_version_id: null, reported_at: null,
      },
      ...overrides,
    }],
  })

  it('lets the operator confirm that the node still serves the original release', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const waiting = unconfirmedSource()
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(waiting)
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockResolvedValue()
    renderPanel()
    const row = await screen.findByTestId('node-scope-reconciliation')
    fireEvent.click(within(row).getByRole('button', { name: '人工确认后对账' }))
    // The manual branch's title is its own, and the dialog's accessible name.
    const dialog = await screen.findByRole('dialog', { name: '人工确认后对账' })
    const option = within(dialog).getByRole('checkbox', { name: '节点仍在服务原发布（版本 018f0000）' })
    expect(option).not.toBeChecked()
    expect(within(dialog).getByText(/确认后主控不再假定节点运行该租户的任何配置/)).toBeInTheDocument()
    expect(within(dialog).getAllByText('请先在节点上核实。')).toHaveLength(1)
    fireEvent.click(option)
    expect(option).toBeChecked()
    // the body says what the ticked choice does.
    expect(within(dialog).getByText(/确认后主控按节点仍在运行原发布（版本 018f0000）处理/)).toBeInTheDocument()
    expect(within(dialog).queryByText(/不再假定节点运行该租户的任何配置/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^对\s?账$/ }))
    await waitFor(() => expect(reconcile).toHaveBeenCalledWith('token', nodeID, waiting.scopes[0], servingVersion))
    expect(await screen.findByText('已对账。请让租户重新发布一次，积压的访问记录随后补报。')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  // 409 在弹窗里回显，弹窗不关；取消勾选后改用空版本重试。
  it('shows a refusal in the dialog and retries without the version', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const waiting = unconfirmedSource()
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(waiting)
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope')
      .mockRejectedValueOnce(new ApiError('refused', 409, 'reconciliation_source_unverifiable'))
      .mockResolvedValueOnce()
    renderPanel()
    fireEvent.click(within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: /^对\s?账$/ }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/原发布的配置已无法核实/)
    expect(reconcile).toHaveBeenLastCalledWith('token', nodeID, waiting.scopes[0], servingVersion)
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: /^对\s?账$/ }))
    await waitFor(() => expect(reconcile).toHaveBeenLastCalledWith('token', nodeID, waiting.scopes[0], undefined))
    expect(await screen.findByText(/^已对账，已解除这个节点的对账限制/)).toBeInTheDocument()
  })

  it('cancels with Escape or the cancel button and reopens unticked', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(unconfirmedSource())
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockResolvedValue()
    renderPanel()
    const action = within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' })
    action.focus()
    fireEvent.click(action)
    let dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.keyDown(dialog, { key: 'Escape', code: 'Escape', keyCode: 27 })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(action).toHaveFocus())
    fireEvent.click(action)
    dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    fireEvent.click(within(dialog).getByRole('button', { name: /^取\s?消$/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(reconcile).not.toHaveBeenCalled()
  })

  it('keeps the manual confirmation without a version when the option is left unticked', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const waiting = unconfirmedSource()
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(waiting)
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockResolvedValue()
    renderPanel()
    fireEvent.click(within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' }))
    expect(await screen.findByRole('checkbox', { name: '节点仍在服务原发布（版本 018f0000）' })).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: /^对\s?账$/ }))
    await waitFor(() => expect(reconcile).toHaveBeenCalledWith('token', nodeID, waiting.scopes[0], undefined))
    expect(await screen.findByText(/^已对账，已解除这个节点的对账限制/)).toBeInTheDocument()
  })

  it.each([
    ['the last apply is another deployment', { last_apply: { deployment_id: '018f0000-0000-7000-8000-0000000000d7', attempt: 1,
      config_version_id: servingVersion, state: 'rollback_failed' as const, error_code: null, finished_at: null, reported_at: '2026-11-22T17:01:00Z' } }],
    ['the last apply did not fail its rollback', { last_apply: { deployment_id: failedSource, attempt: 1,
      config_version_id: servingVersion, state: 'failed' as const, error_code: null, finished_at: null, reported_at: '2026-11-22T17:01:00Z' } }],
  ])('offers no original-release option when %s', async (_name, overrides) => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(unconfirmedSource(overrides))
    renderPanel()
    fireEvent.click(within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' }))
    expect(await screen.findByText(/节点状态未确认，主控无法以节点上报为准/)).toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  // 未勾选时在按钮旁说明后果；勾选后说明消失；没有原发布选项时不出现。
  it('says what leaving the original-release option unticked does', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(unconfirmedSource())
    renderPanel()
    fireEvent.click(within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' }))
    const dialog = await screen.findByRole('dialog', { name: '人工确认后对账' })
    expect(within(dialog).getByTestId('node-scope-reconcile-held-note')).toHaveTextContent(
      '不勾选时，节点保留的原版本访问记录会继续保留，在补充确认前也会挡住后续的访问统计上报。')
    fireEvent.click(within(dialog).getByRole('checkbox'))
    expect(within(dialog).queryByTestId('node-scope-reconcile-held-note')).not.toBeInTheDocument()
  })

  it('says nothing about held records when there is no original-release option', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(unconfirmedSource({ last_apply: null }))
    renderPanel()
    fireEvent.click(within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' }))
    expect(await screen.findByRole('dialog', { name: '人工确认后对账' })).toBeInTheDocument()
    expect(screen.queryByTestId('node-scope-reconcile-held-note')).not.toBeInTheDocument()
  })

  // 已按 null 对账且满足条件时给补充确认入口；默认不执行，勾选核实后才可确认。
  const sourceConfirmation = {
    source_deployment_id: failedSource, source_deployment_attempt: 1, config_version_id: servingVersion,
    reconciled_at: '2026-11-22T17:10:00Z',
  }
  const reconciledWithoutVersion = (confirmation: typeof sourceConfirmation | null = sourceConfirmation) =>
    unconfirmedSource({ reconciliation_required: false, reconciliation: null, source_confirmation: confirmation })

  // The scope's row: the state and the action only; the dialog explains.
  const openSupplementDialog = async () => {
    const entry = await screen.findByTestId('node-scope-source-confirmation')
    fireEvent.click(within(entry).getByRole('button', { name: '补充确认' }))
    return screen.findByRole('dialog', { name: '补充确认原部署曾在节点运行' })
  }
  const tickAndConfirm = (dialog: HTMLElement) => {
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: '补充确认' }))
  }

  it('offers a supplemental confirmation after a reconciliation without a version', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const reconciled = reconciledWithoutVersion()
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValueOnce(reconciled)
      .mockResolvedValueOnce(reconciledWithoutVersion(null))
    const confirm = vi.spyOn(nodesApi, 'confirmConfigurationScopeSource').mockResolvedValue()
    const reconcile = vi.spyOn(nodesApi, 'reconcileConfigurationScope')
    renderPanel()
    const entry = await screen.findByTestId('node-scope-source-confirmation')
    expect(entry).toHaveTextContent(/^已对账 · 未确认版本补\s?充\s?确\s?认$/)
    expect(confirm).not.toHaveBeenCalled()
    const dialog = await openSupplementDialog()
    expect(dialog).toHaveTextContent('原部署 018f0000 在回滚失败后曾在本节点运行')
    expect(dialog).toHaveTextContent('旧版本 018f0000 进入节点的访问统计授权，当前版本不变')
    expect(dialog).toHaveTextContent('租户下一次发布到本节点时，节点放行按旧版本保留的访问记录')
    // not "still serves".
    expect(dialog).not.toHaveTextContent('仍在服务')
    const option = within(dialog).getByRole('checkbox', { name: '原部署在回滚失败后曾在本节点运行（旧版本 018f0000）' })
    expect(option).not.toBeChecked()
    expect(within(dialog).getAllByText('请先在节点上核实。')).toHaveLength(1)
    const ok = within(dialog).getByRole('button', { name: '补充确认' })
    expect(ok).toBeDisabled()
    fireEvent.click(ok)
    expect(confirm).not.toHaveBeenCalled()
    fireEvent.click(option)
    expect(ok).toBeEnabled()
    fireEvent.click(ok)
    await waitFor(() => expect(confirm).toHaveBeenCalledWith('token', nodeID, reconciled.scopes[0]))
    expect(reconcile).not.toHaveBeenCalled()
    expect(await screen.findByText('已为 Beta 补充确认。请让租户重新发布一次：发布到本节点时，节点放行保留的访问记录并按原顺序补报。')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByTestId('node-scope-source-confirmation')).not.toBeInTheDocument())
    // the focus moves to the receipt, not the page.
    await waitFor(() => expect(screen.getByTestId('node-scope-supplement-receipt')).toHaveFocus())
  })

  // a later deployment of the scope (current
  // version set by it) keeps the entry while the server offers it.
  it('offers the supplemental confirmation after a later deployment of the scope', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(unconfirmedSource({
      reconciliation_required: false, reconciliation: null, source_confirmation: sourceConfirmation,
      current_config_version_id: version,
      latest_deployment: {
        deployment_id: '018f0000-0000-7000-8000-0000000000d7', attempt: 1, rollout_id: '018f0000-0000-7000-8000-0000000000e7',
        config_version_id: version, action: 'apply', state: 'healthy', updated_at: '2026-11-22T17:20:00Z',
      },
    }))
    renderPanel()
    const dialog = await openSupplementDialog()
    expect(dialog).toHaveTextContent('在回滚失败后曾在本节点运行')
    expect(dialog).toHaveTextContent('当前版本不变')
  })

  it('returns the focus to the entry on cancel', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(reconciledWithoutVersion())
    renderPanel()
    const entry = await screen.findByTestId('node-scope-source-confirmation')
    const button = within(entry).getByRole('button', { name: '补充确认' })
    button.focus()
    fireEvent.click(button)
    const dialog = await screen.findByRole('dialog', { name: '补充确认原部署曾在节点运行' })
    fireEvent.click(within(dialog).getByRole('button', { name: /取\s?消/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(button).toHaveFocus())
  })

  // after the 201 the entry of that source
  // attempt is gone at once; a slow or failed readback neither brings it back
  // nor hides the receipt, and two clicks send one write.
  it('sends one write and keeps the receipt while the readback is slow', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    let releaseReadback: (value: NodeConfigurationScopes) => void = () => {}
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValueOnce(reconciledWithoutVersion())
      .mockImplementationOnce(() => new Promise((resolve) => { releaseReadback = resolve }))
    const confirm = vi.spyOn(nodesApi, 'confirmConfigurationScopeSource').mockResolvedValue()
    renderPanel()
    tickAndConfirm(await openSupplementDialog())
    await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1))
    const receipt = await screen.findByTestId('node-scope-supplement-receipt')
    expect(receipt).toHaveTextContent('正在读取最新状态。')
    expect(screen.queryByTestId('node-scope-source-confirmation')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '补充确认' })).not.toBeInTheDocument()
    releaseReadback(reconciledWithoutVersion(null))
    await waitFor(() => expect(receipt).not.toHaveTextContent('正在读取最新状态。'))
    expect(confirm).toHaveBeenCalledTimes(1)
  })

  it('keeps the receipt and a retry when the readback fails', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const get = vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValueOnce(reconciledWithoutVersion())
      .mockRejectedValueOnce(new ApiError('unavailable', 503, 'service_unavailable'))
      .mockResolvedValueOnce(reconciledWithoutVersion())
    const confirm = vi.spyOn(nodesApi, 'confirmConfigurationScopeSource').mockResolvedValue()
    renderPanel()
    tickAndConfirm(await openSupplementDialog())
    const receipt = await screen.findByTestId('node-scope-supplement-receipt')
    await waitFor(() => expect(receipt).toHaveTextContent('补充确认已记录，最新状态暂时读取失败'))
    expect(receipt).toHaveTextContent('请让租户重新发布一次')
    fireEvent.click(screen.getByRole('button', { name: /重\s?试/ }))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(3))
    // A stale readback still offering the entry does not bring it back.
    expect(await screen.findByText('Beta')).toBeInTheDocument()
    expect(screen.queryByTestId('node-scope-source-confirmation')).not.toBeInTheDocument()
    expect(screen.getByTestId('node-scope-supplement-receipt')).toBeInTheDocument()
    expect(confirm).toHaveBeenCalledTimes(1)
  })

  // with two sources waiting, the control
  // plane offers the oldest; once supplemented the next one is offered.
  it('offers the next source once the oldest is supplemented', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const nextSource = {
      source_deployment_id: '018f0000-0000-7000-8000-0000000000d8', source_deployment_attempt: 1,
      config_version_id: '018f0000-0000-7000-8000-0000000000c8', reconciled_at: '2026-11-22T17:30:00Z',
    }
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValueOnce(reconciledWithoutVersion())
      .mockResolvedValueOnce(reconciledWithoutVersion(nextSource))
    const confirm = vi.spyOn(nodesApi, 'confirmConfigurationScopeSource').mockResolvedValue()
    renderPanel()
    tickAndConfirm(await openSupplementDialog())
    await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1))
    expect(await screen.findByTestId('node-scope-supplement-receipt')).toBeInTheDocument()
    const dialog = await openSupplementDialog()
    expect(dialog).toHaveTextContent('原部署 018f0000')
    expect(within(dialog).getByRole('checkbox', { name: '原部署在回滚失败后曾在本节点运行（旧版本 018f0000）' })).not.toBeChecked()
    tickAndConfirm(dialog)
    await waitFor(() => expect(confirm).toHaveBeenCalledTimes(2))
    expect(confirm.mock.calls[1]![2].source_confirmation).toEqual(nextSource)
  })

  it.each([
    ['reconciliation_supplement_not_eligible', /最近一次对账已不是「未填版本」的人工确认/],
    ['reconciliation_version_not_source', /补充确认被拒绝：只能确认原部署自己的版本/],
  ])('explains the supplemental confirmation refusal %s in the dialog', async (code, message) => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(reconciledWithoutVersion())
    vi.spyOn(nodesApi, 'confirmConfigurationScopeSource').mockRejectedValue(new ApiError('refused', 409, code))
    renderPanel()
    const dialog = await openSupplementDialog()
    tickAndConfirm(dialog)
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(message)
  })

  // no "untick and retry" here; the
  // refusal offers refreshing the scopes and the tenant's publications.
  it('offers a refresh and the current publications when the source can no longer be verified', async () => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    const get = vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValueOnce(reconciledWithoutVersion())
      .mockResolvedValueOnce(reconciledWithoutVersion(null))
    vi.spyOn(nodesApi, 'confirmConfigurationScopeSource').mockRejectedValue(
      new ApiError('refused', 409, 'reconciliation_source_unverifiable'))
    renderPanel()
    const dialog = await openSupplementDialog()
    tickAndConfirm(dialog)
    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('原发布的配置已无法核实，不能再确认这个版本')
    expect(alert).not.toHaveTextContent('不勾选')
    expect(within(alert).getByRole('link', { name: '查看当前发布' })).toHaveAttribute('href',
      `/site/publications?target_scope_id=${beta}`)
    fireEvent.click(within(alert).getByRole('button', { name: '刷新作用域' }))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.queryByTestId('node-scope-source-confirmation')).not.toBeInTheDocument())
  })

  it.each([
    ['the control plane offers no source confirmation', reconciledWithoutVersion(null)],
    ['the scope still waits for reconciliation', unconfirmedSource({ source_confirmation: sourceConfirmation })],
  ])('offers no supplemental confirmation when %s', async (_name, scopes) => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(scopes)
    renderPanel()
    expect(await screen.findByText('Beta')).toBeInTheDocument()
    expect(screen.queryByTestId('node-scope-source-confirmation')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '补充确认' })).not.toBeInTheDocument()
  })

  it('shows a read-only account the supplemental confirmation state but no action', async () => {
    asPlatform(['nodes.read'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(reconciledWithoutVersion())
    renderPanel()
    const entry = await screen.findByTestId('node-scope-source-confirmation')
    expect(entry).toHaveTextContent('已对账 · 未确认版本')
    expect(within(entry).queryByRole('button')).not.toBeInTheDocument()
  })

  it.each([
    ['reconciliation_source_unverifiable', /原发布的配置已无法核实/],
    ['reconciliation_version_not_source', /只能确认这次失败部署自己的版本/],
  ])('explains the refusal %s', async (code, message) => {
    asPlatform(['nodes.read', 'edge_publications.manage'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(unconfirmedSource())
    vi.spyOn(nodesApi, 'reconcileConfigurationScope').mockRejectedValue(new ApiError('refused', 409, code))
    renderPanel()
    fireEvent.click(within(await screen.findByTestId('node-scope-reconciliation')).getByRole('button', { name: '人工确认后对账' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: '节点仍在服务原发布（版本 018f0000）' }))
    fireEvent.click(screen.getByRole('button', { name: /^对\s?账$/ }))
    expect(await screen.findByText(message)).toBeInTheDocument()
  })

  it.each([
    ['while reconciliation waits on the node report', unconfirmedSource({ reconciliation: {
      reason: 'rollback_failed', source_deployment_id: failedSource, source_deployment_attempt: 1,
      observation: 'confirmed', unconfirmed_reason: null, reported_config_version_id: servingVersion, reported_at: '2026-11-22T17:02:00Z' } })],
    ['after the reconciliation', unconfirmedSource({ reconciliation_required: false, reconciliation: null, current_config_version_id: servingVersion })],
  ])('says the last apply still serves the original release %s', async (_name, scopes) => {
    asPlatform(['nodes.read'])
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(scopes)
    renderPanel()
    const tenants = (await screen.findAllByRole('table'))[0]!
    expect(await within(tenants).findByText('回滚失败，仍在服务原发布')).toBeInTheDocument()
    expect(within(tenants).queryByText('回滚失败，需对账')).not.toBeInTheDocument()
  })

  // 两张表都给 scroll.x，并包在宽度受限、可横滚的容器里。
  it('keeps both tables scrollable sideways inside a bounded container', async () => {
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue(shared)
    renderPanel()
    expect(await screen.findByText('Beta')).toBeInTheDocument()
    for (const [testID, width] of [['node-scope-table-scroll', '720px'], ['node-scope-rejections-scroll', '560px']] as const) {
      const container = screen.getByTestId(testID)
      expect(container).toHaveClass('identity-table-scroll')
      const content = container.querySelector<HTMLElement>('.ant-table-content')
      expect(content).not.toBeNull()
      expect(content).toHaveStyle({ overflowX: 'auto' })
      expect(container.querySelector('table')).toHaveStyle({ width })
    }
  })

  it('says so when the node carries no tenant and nothing was refused', async () => {
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue({ node_id: nodeID, scopes: [], rejections: [], capability_regressions: [] })
    renderPanel()
    expect(await screen.findByText('此节点尚未承载任何租户的配置。')).toBeInTheDocument()
    expect(screen.getByText('没有被拒绝的发布。')).toBeInTheDocument()
  })

  it('reports an invalid response and an unavailable endpoint differently', async () => {
    vi.spyOn(nodesApi, 'getConfigurationScopes')
      .mockRejectedValueOnce(new ApiError('bad', 200, 'invalid_response'))
    renderPanel()
    expect(await screen.findByText('承载租户响应无效，请重试')).toBeInTheDocument()
  })

  it('does not request once the session changed', async () => {
    const get = vi.spyOn(nodesApi, 'getConfigurationScopes')
    renderPanel(() => null)
    await waitFor(() => expect(screen.getByText('承载租户暂不可用，请稍后重试')).toBeInTheDocument())
    expect(get).not.toHaveBeenCalled()
  })
})

describe('node configuration scopes translations', () => {
  it('registers the same keys in every locale', () => {
    const flatten = (value: unknown, prefix = ''): string[] => typeof value === 'string'
      ? [prefix]
      : Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => flatten(child, prefix ? `${prefix}.${key}` : key))
    const keys = flatten(nodeConfigurationScopesMessages['zh-CN']).sort()
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'nodeConfigurationScopes')).toBe(true)
      expect(flatten(nodeConfigurationScopesMessages[locale]).sort()).toEqual(keys)
    }
    expect(nodeConfigurationScopesMessages['qps-ploc'].attempt).toContain('{{attempt}}')
  })
})
