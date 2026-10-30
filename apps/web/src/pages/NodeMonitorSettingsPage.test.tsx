import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  notificationsApi,
  type NotificationChannels,
  type NotificationDeliveryPolicy,
} from '../api/notifications'
import {
  systemConfigurationApi,
  type NodeMonitoringConfiguration,
  type SystemConfigurationDocument,
} from '../api/systemConfiguration'
import { nodeMonitoringApi, type NodeMonitoringLatestBatch } from '../api/nodeMonitoring'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { dnspupNodeMonitoringApi, type DNSPupNodeMonitoringStatus } from '../api/probeDNSPup'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import NodeMonitorSettingsPage from './NodeMonitorSettingsPage'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const value: NodeMonitoringConfiguration = {
  port_mode: 'default',
  probe_interval_ms: 10_000,
  probe_timeout_ms: 3_000,
  failure_threshold: 3,
  recovery_threshold: 3,
  failure_debounce_ms: 0,
  recovery_debounce_ms: 0,
  recovery_notification_enabled: true,
}

function notificationChannels(overrides: Partial<NotificationChannels> = {}): NotificationChannels {
  return {
    sms_enabled: false,
    email_enabled: true,
    sms_supported: true,
    email_supported: true,
    revision: 7,
    changed: false,
    ...overrides,
  }
}

function notificationPolicy(overrides: Partial<NotificationDeliveryPolicy> = {}): NotificationDeliveryPolicy {
  return {
    schema: 'cdnca.notification-delivery-policy/v1',
    window_mode: 'custom',
    window_start: '08:00',
    window_end: '22:00',
    timezone: 'Asia/Shanghai',
    revision: 11,
    changed: false,
    events: [],
    ...overrides,
  }
}

function mockNotificationReads(
  channels = notificationChannels(),
  policy = notificationPolicy(),
) {
  const channelsSpy = vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue(channels)
  const policySpy = vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
  return { channelsSpy, policySpy }
}

function configDocument(overrides: Partial<SystemConfigurationDocument<'node_monitoring'>> = {}) {
  return {
    schema: 'cdnca.system-configuration/v2',
    category: 'node_monitoring',
    head_revision: 4,
    active_revision: 4,
    revision: 4,
    status: 'active',
    snapshot_sha256: 'a'.repeat(64),
    pending_categories: [],
    value,
    ...overrides,
  } satisfies SystemConfigurationDocument<'node_monitoring'>
}

function configurationResponse(document: SystemConfigurationDocument<'node_monitoring'>) {
  return new Response(JSON.stringify(document), {
    status: 200,
    headers: { 'Content-Type': 'application/json', ETag: `"${document.head_revision}"` },
  })
}

const executionNodeID = '66666666-6666-4666-8666-666666666666'

// NODE-N02: 查看节点执行状态 reads the node list and the nodes' monitoring receipts.
function mockNodeExecution(activeRevision: number, applied = true) {
  const node = { id: executionNodeID, name: '节点-A', description: '', region: 'cn', ipv4: '198.51.100.9', admin_state: 'enabled',
    management_settings: {}, revision: 1, created_at: '2026-09-15T10:00:00Z', updated_at: '2026-09-15T10:00:00Z',
    presence: { status: 'online' } } as unknown as NodeInventoryItem
  const listSpy = vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
  const latestSpy = vi.spyOn(nodeMonitoringApi, 'getLatest').mockResolvedValue({
    schema_version: 1, observed_at: '2026-09-15T10:01:00Z',
    configuration: { state: 'active', head_revision: activeRevision, active_revision: activeRevision, activated_at: '2026-09-15T10:00:00Z', policy: null },
    items: [applied ? {
      node_id: executionNodeID, freshness: 'fresh', revision_state: 'current', stale_after_ms: 40000, delivery_state: 'serving',
      apply_receipt: { state: 'applied', config_revision: String(activeRevision), observed_at: '2026-09-15T10:00:30Z' },
      sample: { active_config_revision: activeRevision, observed_at: '2026-09-15T10:00:40Z', healthy: true },
    } : {
      node_id: executionNodeID, freshness: 'not_reported', revision_state: 'unknown', stale_after_ms: 40000, delivery_state: 'awaiting_configuration', sample: null,
    }],
  } as unknown as NodeMonitoringLatestBatch)
  return { listSpy, latestSpy }
}

function admin(overrides: Partial<Principal> = {}) {
  return principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions: ['system_configuration.read', 'system_configuration.manage'],
    ...overrides,
  })
}

function authenticate(actor = admin(), token = 'node-monitor-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(initialEntry = '/node/monitor-setting') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false, gcTime: Infinity } },
  })
  const result = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[initialEntry]}>
            <NodeMonitorSettingsPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...result, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

describe('NodeMonitorSettingsPage', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  it.each([
    ['tenant actor', admin({ scope_kind: 'tenant', tenant_id: '22222222-2222-4222-8222-222222222222' })],
    ['platform actor carrying tenant identity', admin({ tenant_id: '22222222-2222-4222-8222-222222222222' })],
    ['missing read permission', admin({ permissions: ['system_configuration.manage'] })],
    ['zero session epoch', admin()],
  ])('renders a local 403 with zero requests for %s', async (name, actor) => {
    authenticate(actor)
    if (name === 'zero session epoch') useSessionStore.setState({ sessionEpoch: 0 })
    const configSpy = vi.spyOn(systemConfigurationApi, 'get')

    renderPage()

    expect(await screen.findByText('无权查看节点监控设置')).toBeInTheDocument()
    expect(configSpy).not.toHaveBeenCalled()
  })

  it('renders loading, localized error, retry recovery, and the active configuration state', async () => {
    authenticate()
    const pending = deferred<SystemConfigurationDocument<'node_monitoring'>>()
    vi.spyOn(systemConfigurationApi, 'get')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('raw private detail', 503, 'system_configuration_unavailable'))
      .mockResolvedValueOnce(configDocument())
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByLabelText('正在加载节点监控设置')).toBeInTheDocument()
    await act(async () => pending.resolve(configDocument()))
    expect(await screen.findByRole('heading', { name: '节点监控设置' })).toBeInTheDocument()
    expect(screen.getByText('主控已激活，节点执行待确认')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('READY_INTEGRATION')
    expect(document.body.textContent).not.toContain('Agent 消费')

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('节点监控设置暂不可用，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('主控已激活，节点执行待确认')).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private detail')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByRole('heading', { name: '节点监控设置' })).toBeInTheDocument()
  })

  it.each([true, false])('keeps revision zero as an unsaved draft and blocks preflight when the switch is %s', async (enabled) => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 0, active_revision: 0, revision: 0, status: 'draft',
      value: { ...value, monitor_enabled: enabled },
    }))
    const preflightSpy = vi.spyOn(systemConfigurationApi, 'preflight')
    const activateSpy = vi.spyOn(systemConfigurationApi, 'activate')
    const user = userEvent.setup()

    renderPage()

    expect(await screen.findByText('尚未配置，当前为默认草稿')).toBeInTheDocument()
    expect(screen.getByText('请先保存设置，再预检和激活；默认草稿尚未下发。')).toBeInTheDocument()
    const preflight = screen.getByRole('button', { name: '预检配置' })
    expect(preflight).toBeDisabled()
    await user.click(preflight)
    expect(preflightSpy).not.toHaveBeenCalled()
    expect(activateSpy).not.toHaveBeenCalled()
    expect(screen.queryByText('监控已开启')).not.toBeInTheDocument()
    expect(screen.queryByText('监控未启用')).not.toBeInTheDocument()
  })

  it.each([
    ['saved enabled draft', { head_revision: 1, active_revision: 0, revision: 1, status: 'draft', value: { ...value, monitor_enabled: true } }, '配置已保存，尚未激活'],
    ['saved disabled draft', { head_revision: 1, active_revision: 0, revision: 1, status: 'draft', value: { ...value, monitor_enabled: false } }, '配置已保存，尚未激活'],
    ['validated draft', { head_revision: 1, active_revision: 0, revision: 1, status: 'validated' }, '预检已通过，尚未激活'],
    ['rejected draft', { head_revision: 1, active_revision: 0, revision: 1, status: 'rejected' }, '配置已保存，尚未激活'],
    ['newer draft with an active revision', { head_revision: 5, active_revision: 4, revision: 5, status: 'draft', value: { ...value, monitor_enabled: false } }, '主控已有激活版本，另有未激活修改'],
    ['active enable request without node receipt', { value: { ...value, monitor_enabled: true } }, '主控已激活，节点执行待确认'],
    ['active disable request without stop receipt', { value: { ...value, monitor_enabled: false } }, '主控已激活，节点执行待确认'],
  ] satisfies [string, Partial<SystemConfigurationDocument<'node_monitoring'>>, string][])('reports the server configuration state for %s', async (_name, overrides, expected) => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument(overrides))
    const publicationSpy = vi.spyOn(systemConfigurationApi, 'listPublications')

    renderPage()

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(screen.queryByText('监控已开启')).not.toBeInTheDocument()
    expect(screen.queryByText('监控未启用')).not.toBeInTheDocument()
    expect(publicationSpy).not.toHaveBeenCalled()
  })

  it('probe-node links to the dnspup node availability probing settings only for its managers', async () => {
    authenticate(admin({ permissions: ['system_configuration.read', 'system.probe_dnspup.manage'] }))
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const first = renderPage()
    const entry = await screen.findByTestId('node-monitor-dnspup-probe-entry')
    expect(within(entry).getByRole('link', { name: '前往 dnspup 插件页设置「节点可用性拨测」' })).toHaveAttribute('href', '/sys/probe-dnspup')
    first.unmount()

    authenticate()
    renderPage()
    expect(await screen.findByRole('heading', { name: '节点监控设置' })).toBeInTheDocument()
    expect(screen.queryByTestId('node-monitor-dnspup-probe-entry')).not.toBeInTheDocument()
  })

  it('NODE-POLICY-HELP-01 describes the external probe decision as implemented and shows the effective source', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const statusSpy = vi.spyOn(dnspupNodeMonitoringApi, 'status')
    const first = renderPage()
    const help = await screen.findByTestId('node-monitor-policy-help')
    // nodeprobe.Decide: controller failed AND peers' overall failure ratio; one side missing → the other decides; no vote → keep.
    expect(help).toHaveTextContent('主控失败且互拨节点整体失败比例达到“监控点失败比率”')
    expect(help).toHaveTextContent('没有互拨节点投票时只看主控')
    expect(help).toHaveTextContent('主控没有结果时只看互拨节点')
    expect(help).toHaveTextContent('都没有结果时本轮不判定、保持原状态')
    expect(help).toHaveTextContent('有新鲜的 dnspup 拨测结论时以 dnspup 为准')
    expect(help).not.toHaveTextContent('任一监控组的失败比率')
    // Without the dnspup permission the page cannot read its state: the rule, not a guess.
    expect(screen.getByTestId('node-monitor-effective-source')).toHaveTextContent('需 dnspup 管理权限查看')
    expect(statusSpy).not.toHaveBeenCalled()
    first.unmount()

    authenticate(admin({ permissions: ['system_configuration.read', 'system.probe_dnspup.manage'] }))
    statusSpy.mockResolvedValue({ plugin_active: true, effective_interval_seconds: 300 } as DNSPupNodeMonitoringStatus)
    const second = renderPage()
    expect(await screen.findByText(/当前生效来源：dnspup 运营商检测点/)).toBeInTheDocument()
    second.unmount()

    statusSpy.mockResolvedValue({ plugin_active: true, effective_interval_seconds: 0 } as DNSPupNodeMonitoringStatus)
    renderPage()
    expect(await screen.findByText(/当前生效来源：主控与互拨节点 \+ 节点本机自检（dnspup 节点拨测未生效）/)).toBeInTheDocument()
  })

  it('W9 shows a visible empty state after viewing node execution status with no nodes', async () => {
    authenticate(admin({ permissions: ['system_configuration.read', 'system_configuration.manage', 'nodes.read'] }))
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({ head_revision: 1, active_revision: 1, revision: 1 }))
    const listSpy = vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })
    const latestSpy = vi.spyOn(nodeMonitoringApi, 'getLatest')
    const publicationSpy = vi.spyOn(systemConfigurationApi, 'listPublications')
    const scrollSpy = vi.fn()
    Element.prototype.scrollIntoView = scrollSpy
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('button', { name: '查看节点执行状态' }))
    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    const empty = await screen.findByText('暂无节点')
    expect(empty.closest('.ant-alert')).toHaveClass('ant-alert-info')
    expect(screen.getByText(/对主控激活版本 1 的执行回执/)).toBeVisible()
    expect(scrollSpy).toHaveBeenCalled()
    expect(latestSpy).not.toHaveBeenCalled()
    expect(publicationSpy).not.toHaveBeenCalled()
  })

  it('NODE-N02 lists each node\'s receipt (target / actual revision, state, reason, time), not tenant publications', async () => {
    authenticate(admin({ permissions: ['system_configuration.read', 'system_configuration.manage', 'nodes.read'] }))
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({ head_revision: 3, active_revision: 3, revision: 3 }))
    const publicationSpy = vi.spyOn(systemConfigurationApi, 'listPublications')
    const { latestSpy } = mockNodeExecution(3, false)
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('button', { name: '查看节点执行状态' }))
    await waitFor(() => expect(latestSpy).toHaveBeenCalledWith('node-monitor-token', [executionNodeID], expect.anything()))
    const row = (await screen.findByText('节点-A')).closest('tr')!
    expect(within(row).getByText('待配置')).toBeInTheDocument()
    expect(within(row).getByText('节点尚未收到监控配置')).toBeInTheDocument()
    expect(within(row).getByText('3')).toBeInTheDocument()
    expect(publicationSpy).not.toHaveBeenCalled()
  })

  it('NODE-N02 keeps the nodes.read boundary: without it the button is off and nothing is read', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({ head_revision: 3, active_revision: 3, revision: 3 }))
    const listSpy = vi.spyOn(nodesApi, 'list')
    renderPage()
    expect(await screen.findByRole('button', { name: '查看节点执行状态' })).toBeDisabled()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('does not turn an unsaved switch change into execution evidence', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const putSpy = vi.spyOn(systemConfigurationApi, 'put')
    const activateSpy = vi.spyOn(systemConfigurationApi, 'activate')
    const user = userEvent.setup()

    renderPage()
    await screen.findByText('主控已激活，节点执行待确认')
    await user.click(screen.getByRole('switch', { name: '监控开关' }))

    expect(screen.getByRole('switch', { name: '监控开关' })).not.toBeChecked()
    expect(screen.getByText('主控已激活，节点执行待确认')).toBeInTheDocument()
    expect(screen.queryByText('监控未启用')).not.toBeInTheDocument()
    expect(putSpy).not.toHaveBeenCalled()
    expect(activateSpy).not.toHaveBeenCalled()
  })

  it('keeps lifecycle actions denied for a read-only principal without requiring node read permission', async () => {
    authenticate(admin({ permissions: ['system_configuration.read'] }))
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 1, active_revision: 0, revision: 1, status: 'draft',
    }))
    const preflightSpy = vi.spyOn(systemConfigurationApi, 'preflight')
    const putSpy = vi.spyOn(systemConfigurationApi, 'put')
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('配置已保存，尚未激活')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '预检配置' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存设置' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '预检配置' }))
    expect(preflightSpy).not.toHaveBeenCalled()
    expect(putSpy).not.toHaveBeenCalled()
  })

  it.each(['owner', 'epoch'] as const)('does not restore an old active state after a %s change', async (change) => {
    const actor = admin()
    authenticate(actor)
    const oldRead = deferred<SystemConfigurationDocument<'node_monitoring'>>()
    const getSpy = vi.spyOn(systemConfigurationApi, 'get')
      .mockReturnValueOnce(oldRead.promise)
      .mockResolvedValueOnce(configDocument({ head_revision: 0, active_revision: 0, revision: 0, status: 'draft' }))

    renderPage()
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(1))
    await act(async () => {
      authenticate(change === 'owner' ? admin({ user_id: '99999999-9999-4999-8999-999999999999' }) : actor, 'next-token', 'new')
    })
    expect(await screen.findByText('尚未配置，当前为默认草稿')).toBeInTheDocument()
    await act(async () => oldRead.resolve(configDocument()))

    expect(screen.getByText('尚未配置，当前为默认草稿')).toBeInTheDocument()
    expect(screen.queryByText('主控已激活，节点执行待确认')).not.toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledTimes(2)
  })

  it.each(['zh-CN', 'en-US', 'qps-ploc'])('localizes the initial state and preflight guard in %s', async (locale) => {
    await i18n.changeLanguage(locale)
    const t = i18n.getFixedT(locale, 'nodeMonitorSettings')
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 0, active_revision: 0, revision: 0, status: 'draft',
    }))

    renderPage()

    expect(await screen.findByText(t('monitoringState.initialDraft'))).toBeInTheDocument()
    expect(screen.getByText(t('lifecycle.saveFirst'))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: t('lifecycle.actions.preflight') })).toBeDisabled()
  })

  it('matches the monitoring tabs and field inventory', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())

    renderPage()

    expect(await screen.findByTestId('node-monitor-settings-page')).toHaveClass('node-monitor-settings-page')
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual(['监控配置', '通知配置', '切换日志'])
    expect(screen.getByRole('tab', { name: '监控配置' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('默认监控协议')).toBeInTheDocument()
    expect(screen.getByText('默认监控端口')).toBeInTheDocument()
    expect(screen.getByText('探测超时（毫秒）')).toBeInTheDocument()
    expect(screen.getByText('默认监控组')).toBeInTheDocument()
    expect(screen.getByText('默认动作')).toBeInTheDocument()
    expect(screen.getByText('间隔时间')).toBeInTheDocument()
    expect(screen.getByText('监控点失败比率')).toBeInTheDocument()
    expect(screen.getByText('连续带宽超限次数')).toBeInTheDocument()
    expect(screen.getByText('监控开关')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '监控开关' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'TCP' })).toBeChecked()
    expect(screen.getByRole('spinbutton', { name: '默认监控端口' })).toHaveValue('80')
    expect(screen.getByRole('checkbox', { name: '国内组' })).toBeChecked()
    expect(screen.getByText('国内组')).toBeInTheDocument()
    expect(screen.queryByText(/目标租户作用域/)).not.toBeInTheDocument()
    expect(screen.queryByText(/线路组覆盖/)).not.toBeInTheDocument()
  })

  it('persists the editable monitoring controls with localized feedback', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const putSpy = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(configDocument({
      head_revision: 5,
      revision: 5,
      status: 'draft',
      value: {
        ...value,
        monitor_enabled: false,
        protocol: 'http',
        monitor_port: 8080,
        monitor_groups: ['domestic', 'telecom'],
        monitor_action: 'none',
        failure_ratio: 70,
        bandwidth_over_limit: 5,
      },
    }))
    const user = userEvent.setup()

    renderPage()
    await screen.findByRole('heading', { name: '节点监控设置' })
    await user.click(screen.getByRole('switch', { name: '监控开关' }))
    await user.click(screen.getByText('HTTP', { selector: 'span' }))
    const port = screen.getByRole('spinbutton', { name: '默认监控端口' })
    await user.clear(port)
    await user.type(port, '8080')
    await user.click(screen.getByText('电信组', { selector: 'span' }))
    await user.click(screen.getByText('不处理', { selector: 'span' }))
    const ratio = screen.getByRole('spinbutton', { name: '监控点失败比率' })
    await user.clear(ratio)
    await user.type(ratio, '70')
    const bandwidth = screen.getByRole('spinbutton', { name: '连续带宽超限次数' })
    await user.clear(bandwidth)
    await user.type(bandwidth, '5')
    await user.click(screen.getByRole('button', { name: '保存设置' }))

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy.mock.calls[0][2]).toMatchObject({
      monitor_enabled: false,
      protocol: 'http',
      monitor_port: 8080,
      probe_timeout_ms: 3000,
      monitor_groups: ['domestic', 'telecom'],
      monitor_action: 'none',
      failure_ratio: 70,
      bandwidth_over_limit: 5,
    })
    expect(await screen.findByText('节点监控设置已保存')).toBeInTheDocument()
    expect(screen.getByText('主控已有激活版本，另有未激活修改')).toBeInTheDocument()
  })

  it('shows the initial 10-second interval without changing the default configuration', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 0, active_revision: 0, revision: 0, status: 'draft',
    }))
    const putSpy = vi.spyOn(systemConfigurationApi, 'put')
    const activateSpy = vi.spyOn(systemConfigurationApi, 'activate')

    renderPage()

    expect(await screen.findByRole('radio', { name: '10秒' })).toBeChecked()
    expect(screen.getByRole('radio', { name: '30秒' })).not.toBeChecked()
    expect(screen.getByRole('spinbutton', { name: '探测间隔（毫秒）' })).toHaveValue('10000')
    expect(putSpy).not.toHaveBeenCalled()
    expect(activateSpy).not.toHaveBeenCalled()
  })

  it.each([
    [10_000, '10秒'],
    [20_000, '自定义当前值： 20,000 毫秒'],
    [1_001, '自定义当前值： 1,001 毫秒'],
  ])('saves the displayed interval %s without normalizing its value', async (interval, label) => {
    authenticate()
    const configuration = { ...value, probe_interval_ms: interval, probe_timeout_ms: 1_000 }
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({ value: configuration }))
    const putSpy = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(configDocument({
      head_revision: 5, revision: 5, status: 'draft', value: configuration,
    }))
    const user = userEvent.setup()

    renderPage()

    expect(await screen.findByRole('radio', { name: label })).toBeChecked()
    await user.click(screen.getByRole('button', { name: '保存设置' }))

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy.mock.calls[0][2]).toMatchObject({
      probe_interval_ms: interval, probe_timeout_ms: 1_000, port_mode: 'default',
    })
    expect(await screen.findByText('节点监控设置已保存')).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: label })).toBeChecked()
  })

  it('keeps the interval presets and advanced input synchronized in both directions', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const putSpy = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(configDocument())
    const user = userEvent.setup()

    renderPage()

    await user.click(await screen.findByText('30秒', { selector: 'span' }))
    const interval = screen.getByRole('spinbutton', { name: '探测间隔（毫秒）' })
    expect(interval).toHaveValue('30000')

    await user.clear(interval)
    await user.type(interval, '20000')
    expect(await screen.findByRole('radio', { name: '自定义当前值： 20,000 毫秒' })).toBeChecked()
    expect(screen.getByRole('radio', { name: '30秒' })).not.toBeChecked()

    await user.click(screen.getByText('10秒', { selector: 'span' }))
    expect(interval).toHaveValue('10000')
    expect(screen.queryByRole('radio', { name: /自定义当前值/ })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy.mock.calls[0][2]).toMatchObject({ probe_interval_ms: 10_000 })
  })

  it('localizes preset and custom interval labels in the pseudo locale', async () => {
    authenticate()
    await i18n.changeLanguage('qps-ploc')
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      value: { ...value, probe_interval_ms: 20_000 },
    }))

    renderPage()

    const custom = await screen.findByRole('radio', { name: /20,000/ })
    expect(custom).toBeChecked()
    expect(custom.closest('label')).toHaveTextContent('［自~定~义~当~前~值~：~］ 20,000 ［毫~秒~］')
    expect(screen.getByRole('radio', { name: '［1~0~秒~］' })).not.toBeChecked()
    expect(document.body.textContent).not.toContain('values.customCurrentInterval')
  })

  it('matches the notification and switch-log inventories without inventing records', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    mockNotificationReads(undefined, notificationPolicy({ timezone: 'America/New_York' }))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))

    expect(await screen.findByText('通知渠道')).toBeInTheDocument()
    // C20 / NOTIFY-UX02：时段旁显示服务端策略时区，不用浏览器或硬编码时区。
    expect(screen.getByTestId('node-monitor-notification-timezone')).toHaveTextContent('按 America/New_York 时间')
    expect(screen.getByText('消息类型订阅')).toBeInTheDocument()
    expect(screen.getByText('通知模板')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'IP可用性监控' })).toBeChecked()
    // ADMIN-CURRENT-02：未接通事件的订阅、联系人与模板不再以禁用控件出现，改为说明与入口。
    for (const name of ['带宽超限', '备用IP切换', '备用默认解析切换', '备用线路组切换']) {
      expect(screen.queryByRole('checkbox', { name })).not.toBeInTheDocument()
    }
    expect(screen.getByText(/暂无通知事件，因此不提供订阅/)).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('输入邮箱地址')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('输入手机号码')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '前往用户管理' })).toHaveAttribute('href', '/sys/user')
    expect(screen.getByRole('link', { name: '编辑通知模板' })).toHaveAttribute('href', '/sys/setting?tab=notification')
    expect(document.querySelector('.node-monitor-template-section input[disabled], .node-monitor-template-section button[disabled]')).toBeNull()
    expect(screen.queryByRole('button', { name: '保存设置' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '切换日志' }))
    expect(screen.getByText('当前账号缺少节点查看权限，无法查看切换日志')).toBeInTheDocument()
    expect(screen.queryByText('最近 31 天没有切换记录')).not.toBeInTheDocument()
  })

  it('preflights a draft, activates the validated revision, and loads node execution status', async () => {
    authenticate(admin({ permissions: ['system_configuration.read', 'system_configuration.manage', 'nodes.read'] }))
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 4,
      active_revision: 3,
      revision: 4,
      status: 'draft',
    }))
    const preflightSpy = vi.spyOn(systemConfigurationApi, 'preflight').mockResolvedValue({
      revision: 4,
      status: 'validated',
      snapshot_sha256: 'a'.repeat(64),
      replayed: false,
    })
    const activateSpy = vi.spyOn(systemConfigurationApi, 'activate').mockResolvedValue({
      revision: 4,
      status: 'active',
      snapshot_sha256: 'a'.repeat(64),
      replayed: false,
    })
    const { latestSpy } = mockNodeExecution(4)
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('button', { name: '预检配置' }))

    await waitFor(() => expect(preflightSpy).toHaveBeenCalledTimes(1))
    expect(preflightSpy).toHaveBeenCalledWith(
      'node-monitor-token',
      4,
      'a'.repeat(64),
      expect.any(String),
      expect.any(String),
      [],
    )
    expect(await screen.findByText('已预检')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '激活并下发' }))

    await waitFor(() => expect(activateSpy).toHaveBeenCalledTimes(1))
    expect(activateSpy).toHaveBeenCalledWith(
      'node-monitor-token',
      4,
      3,
      expect.any(String),
      expect.any(String),
      [],
    )
    expect(await screen.findByText('主控已激活')).toBeInTheDocument()
    expect(screen.getByText('主控激活版本：4')).toBeInTheDocument()
    await waitFor(() => expect(latestSpy).toHaveBeenCalled())
    const row = (await screen.findByText('节点-A')).closest('tr')!
    expect(within(row).getByText('已应用')).toBeInTheDocument()
    expect(within(row).getByText('探测正常')).toBeInTheDocument()
    expect(screen.getByText('主控已激活，节点执行待确认')).toBeInTheDocument()
  })

  it('warns about other pending categories and confirms before activating them together', async () => {
    authenticate()
    const pending = ['node_monitoring', 'ddos_protection'] as const
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 5, active_revision: 3, revision: 5, status: 'validated', pending_categories: [...pending],
    }))
    const activateSpy = vi.spyOn(systemConfigurationApi, 'activate').mockResolvedValue({
      revision: 5, status: 'active', snapshot_sha256: 'a'.repeat(64), replayed: false,
    })
    mockNodeExecution(5)
    const user = userEvent.setup()
    renderPage()

    const notice = await screen.findByTestId('pending-categories-notice')
    expect(notice).toHaveTextContent('其他分类还有未生效的修改')
    expect(notice).toHaveTextContent('一并生效：连接防护')
    expect(within(notice).getByText('去查看：连接防护')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '激活并下发' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('本次还会一并生效：连接防护')
    expect(activateSpy).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(activateSpy).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: '激活并下发' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确认并继续' }))
    await waitFor(() => expect(activateSpy).toHaveBeenCalledWith(
      'node-monitor-token', 5, 3, expect.any(String), expect.any(String), [...pending],
    ))
  })

  it('creates a rollback draft, then preflights and activates that exact immutable revision', async () => {
    authenticate(admin({ permissions: ['system_configuration.read', 'system_configuration.manage', 'nodes.read'] }))
    const initial = configDocument({
      head_revision: 4, active_revision: 4, revision: 4, status: 'active', snapshot_sha256: 'a'.repeat(64),
    })
    const activated = configDocument({
      head_revision: 5, active_revision: 5, revision: 5, status: 'active', snapshot_sha256: 'c'.repeat(64),
    })
    const getSpy = vi.spyOn(systemConfigurationApi, 'get')
      .mockResolvedValueOnce(initial)
      .mockResolvedValue(activated)
    const rollbackSpy = vi.spyOn(systemConfigurationApi, 'rollback').mockResolvedValue({
      revision: 5, status: 'draft', snapshot_sha256: 'c'.repeat(64), source_revision: 2, replayed: false,
    })
    const preflightSpy = vi.spyOn(systemConfigurationApi, 'preflight').mockResolvedValue({
      revision: 5, status: 'validated', snapshot_sha256: 'c'.repeat(64), replayed: false,
    })
    const activateSpy = vi.spyOn(systemConfigurationApi, 'activate').mockResolvedValue({
      revision: 5, status: 'active', snapshot_sha256: 'c'.repeat(64), replayed: false,
    })
    const { latestSpy } = mockNodeExecution(5)
    const user = userEvent.setup()

    renderPage()
    const target = await screen.findByRole('spinbutton', { name: '目标回滚版本' })
    await user.type(target, '2')
    await user.click(screen.getByRole('button', { name: '创建回滚草稿' }))

    await waitFor(() => expect(rollbackSpy).toHaveBeenCalledTimes(1))
    expect(rollbackSpy).toHaveBeenCalledWith(
      'node-monitor-token', 2, 4, 4, expect.any(String), expect.any(String),
    )
    expect(await screen.findByText('已从版本 2 创建回滚草稿 5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存设置' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: '预检配置' }))
    await waitFor(() => expect(preflightSpy).toHaveBeenCalledWith(
      'node-monitor-token', 5, 'c'.repeat(64), expect.any(String), expect.any(String), [],
    ))

    await user.click(screen.getByRole('button', { name: '激活并下发' }))
    await waitFor(() => expect(activateSpy).toHaveBeenCalledWith(
      'node-monitor-token', 5, 4, expect.any(String), expect.any(String), [],
    ))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(latestSpy).toHaveBeenCalled())
    expect(await screen.findByText('主控激活版本：5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存设置' })).toBeEnabled()
  })

  it('localizes a rejected rollback transition without exposing the server detail', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 4, active_revision: 4, revision: 4, status: 'active',
    }))
    vi.spyOn(systemConfigurationApi, 'rollback').mockRejectedValue(
      new ApiError('raw rollback detail', 409, 'system_configuration_invalid_transition'),
    )
    const user = userEvent.setup()

    renderPage()
    await user.type(await screen.findByRole('spinbutton', { name: '目标回滚版本' }), '2')
    await user.click(screen.getByRole('button', { name: '创建回滚草稿' }))

    expect(await screen.findByText('目标版本不是可回滚的已生效历史版本')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw rollback detail')
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
  })

  it('freezes an unknown rollback result and retries the exact request', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 4, active_revision: 4, revision: 4, status: 'active',
    }))
    const rollbackSpy = vi.spyOn(systemConfigurationApi, 'rollback')
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'system_configuration_unavailable'))
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'system_configuration_unavailable'))
    const user = userEvent.setup()

    renderPage()
    await user.type(await screen.findByRole('spinbutton', { name: '目标回滚版本' }), '2')
    await user.click(screen.getByRole('button', { name: '创建回滚草稿' }))
    expect(await screen.findByText('发布操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const firstCall = rollbackSpy.mock.calls[0]

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(rollbackSpy).toHaveBeenCalledTimes(2))
    expect(rollbackSpy.mock.calls[1]).toEqual(firstCall)
  })

  it.each([
    [403, 'system_configuration_permission_denied', 'preflight', '无权预检、激活或回滚节点监控配置'],
    [409, 'system_configuration_revision_conflict', 'preflight', '配置版本已变化，请刷新后重新操作'],
    [422, 'system_configuration_publication_failed', 'activate', '制品生成或发布失败，原生效版本保持不变'],
  ] as const)('localizes terminal lifecycle error %s without exposing server details', async (status, code, action, expected) => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 4,
      active_revision: 3,
      revision: 4,
      status: action === 'activate' ? 'validated' : 'draft',
    }))
    vi.spyOn(systemConfigurationApi, action).mockRejectedValue(new ApiError('raw lifecycle detail', status, code))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('button', { name: action === 'activate' ? '激活并下发' : '预检配置' }))

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw lifecycle detail')
  })

  it('freezes an unknown lifecycle result and retries the exact preflight request', async () => {
    authenticate()
    const getSpy = vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument({
      head_revision: 4,
      active_revision: 3,
      revision: 4,
      status: 'draft',
    }))
    const preflightSpy = vi.spyOn(systemConfigurationApi, 'preflight')
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'system_configuration_unavailable'))
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'system_configuration_unavailable'))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('button', { name: '预检配置' }))
    expect(await screen.findByText('发布操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const firstCall = preflightSpy.mock.calls[0]

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(preflightSpy).toHaveBeenCalledTimes(2))
    expect(preflightSpy.mock.calls[1]).toEqual(firstCall)

    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('发布操作结果待确认')).not.toBeInTheDocument()
  })

  it('auto-saves notification channels with the current revision', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    mockNotificationReads()
    const putSpy = vi.spyOn(notificationsApi, 'putChannels').mockResolvedValue(notificationChannels({
      sms_enabled: true,
      revision: 8,
      changed: true,
    }))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))
    await user.click(await screen.findByText('手机短信'))

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy).toHaveBeenCalledWith(
      'node-monitor-token',
      { email_enabled: true, sms_enabled: true },
      7,
      expect.any(String),
    )
  })

  it('auto-saves a valid custom notification window', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    mockNotificationReads()
    const putSpy = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockResolvedValue(notificationPolicy({
      window_start: '09:30',
      window_end: '23:00',
      revision: 12,
      changed: true,
    }))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))
    const input = await screen.findByRole('textbox', { name: '格式8-22' })
    await user.clear(input)
    await user.type(input, '9:30-23{Enter}')

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy).toHaveBeenCalledWith(
      'node-monitor-token',
      {
        window_mode: 'custom',
        window_start: '09:30',
        window_end: '23:00',
        timezone: 'Asia/Shanghai',
        events: [],
      },
      11,
      expect.any(String),
    )
  })

  it('auto-saves the supported IP availability subscription through node monitoring configuration', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    mockNotificationReads()
    const putSpy = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(configDocument({
      head_revision: 5,
      revision: 5,
      status: 'draft',
      value: { ...value, recovery_notification_enabled: false },
    }))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))
    await user.click(await screen.findByText('IP可用性监控'))

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy).toHaveBeenCalledWith(
      'node-monitor-token',
      'node_monitoring',
      {
        ...value,
        monitor_enabled: true,
        protocol: 'tcp',
        monitor_port: 80,
        monitor_groups: ['domestic'],
        monitor_action: 'pause',
        failure_ratio: 50,
        bandwidth_over_limit: 3,
        recovery_notification_enabled: false,
      },
      4,
      expect.any(String),
      expect.any(String),
    )
  })

  it.each([true, false])('preserves recovery notification %s on a fresh monitoring-tab save through the API adapter', async (enabled) => {
    authenticate()
    const configuration = { ...value, recovery_notification_enabled: enabled }
    const initial = configDocument({
      head_revision: 0, active_revision: 0, revision: 0, status: 'draft', value: configuration,
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(configurationResponse(initial))
      .mockResolvedValueOnce(configurationResponse({ ...initial, head_revision: 1, revision: 1 }))
    const user = userEvent.setup()

    renderPage()
    await screen.findByRole('heading', { name: '节点监控设置' })
    expect(screen.queryByRole('checkbox', { name: 'IP可用性监控' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存设置' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const [url, request] = fetchSpy.mock.calls[1]
    expect(url).toEqual(expect.stringContaining('/v1/admin/system-configuration/categories/node_monitoring'))
    expect(request?.method).toBe('PUT')
    expect(new Headers(request?.headers).get('If-Match')).toBe('"0"')
    expect(JSON.parse(String(request?.body))).toMatchObject({ value: configuration })
    expect(await screen.findByText('节点监控设置已保存')).toBeInTheDocument()
  })

  it.each([true, false])('applies an explicit recovery notification change from %s through the API adapter', async (enabled) => {
    authenticate()
    mockNotificationReads()
    const initial = configDocument({ value: { ...value, recovery_notification_enabled: enabled } })
    const saved = configDocument({
      head_revision: 5, revision: 5, status: 'draft',
      value: { ...value, recovery_notification_enabled: !enabled },
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(configurationResponse(initial))
      .mockResolvedValueOnce(configurationResponse(saved))
      .mockResolvedValueOnce(configurationResponse({ ...saved, head_revision: 6, revision: 6 }))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))
    const checkbox = await screen.findByRole('checkbox', { name: 'IP可用性监控' })
    expect(checkbox).toHaveProperty('checked', enabled)
    await user.click(screen.getByText('IP可用性监控', { selector: 'span' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(JSON.parse(String(fetchSpy.mock.calls[1][1]?.body))).toMatchObject({
      value: { recovery_notification_enabled: !enabled },
    })
    expect(new Headers(fetchSpy.mock.calls[1][1]?.headers).get('If-Match')).toBe('"4"')
    expect(await screen.findByText('节点监控设置已保存')).toBeInTheDocument()
    expect(checkbox).toHaveProperty('checked', !enabled)

    await user.click(screen.getByRole('tab', { name: '监控配置' }))
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toMatchObject({
      value: { recovery_notification_enabled: !enabled },
    })
    expect(new Headers(fetchSpy.mock.calls[2][1]?.headers).get('If-Match')).toBe('"5"')
  })

  it.each([503, 409])('retains recovery notification and the expected revision after a %s save failure', async (status) => {
    authenticate()
    const initial = configDocument()
    const saved = configDocument({
      head_revision: 5, revision: 5, status: 'draft', value: { ...value, probe_interval_ms: 60_000 },
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(configurationResponse(initial))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: {
        code: status === 503 ? 'system_configuration_unavailable' : 'system_configuration_revision_conflict',
      } }), { status, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(configurationResponse(saved))
    const user = userEvent.setup()

    const { queryClient } = renderPage()
    await user.click(await screen.findByText('1分钟', { selector: 'span' }))
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    expect(await screen.findByText(status === 503 ? '保存结果待确认' : '设置已被其他操作修改，请刷新后重试', status === 503 ? { selector: OUTCOME_BAR } : undefined)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '1分钟' })).toBeChecked()
    expect(queryClient.getQueryCache().getAll()[0].state.data).toMatchObject(initial)
    const failedRequest = fetchSpy.mock.calls[1][1]
    expect(JSON.parse(String(failedRequest?.body))).toMatchObject({
      value: { ...value, probe_interval_ms: 60_000 },
    })
    expect(new Headers(failedRequest?.headers).get('If-Match')).toBe('"4"')

    await user.click(screen.getByRole('button', { name: status === 503 ? '使用同一请求重试' : '保存设置' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    const retriedRequest = fetchSpy.mock.calls[2][1]
    expect(retriedRequest?.body).toBe(failedRequest?.body)
    expect(new Headers(retriedRequest?.headers).get('If-Match')).toBe('"4"')
    if (status === 503) expect(retriedRequest?.headers).toEqual(failedRequest?.headers)
    expect(await screen.findByText('节点监控设置已保存')).toBeInTheDocument()
  })

  it.each([undefined, null, 'false'])('rejects an unknown recovery notification value %s instead of manufacturing a default', async (enabled) => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      ...configDocument(), value: { ...value, recovery_notification_enabled: enabled },
    }), { status: 200, headers: { 'Content-Type': 'application/json', ETag: '"4"' } }))

    renderPage()

    expect(await screen.findByText('节点监控设置暂不可用，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '保存设置' })).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it.each([
    [403, 'notification_permission_denied', '无权修改通知配置'],
    [409, 'version_conflict', '通知配置已被其他操作修改，请放弃后刷新再试'],
  ])('renders a terminal localized notification write error for %s', async (status, code, expected) => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    mockNotificationReads()
    vi.spyOn(notificationsApi, 'putChannels').mockRejectedValue(new ApiError('raw notification detail', status, code))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))
    await user.click(await screen.findByText('手机短信'))

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw notification detail')
  })

  it('freezes an unknown notification write and retries the exact request', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const { channelsSpy } = mockNotificationReads()
    const putSpy = vi.spyOn(notificationsApi, 'putChannels')
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'notification_unavailable'))
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'notification_unavailable'))
    const user = userEvent.setup()

    renderPage()
    await user.click(await screen.findByRole('tab', { name: '通知配置' }))
    await user.click(await screen.findByText('手机短信'))
    expect(await screen.findByText('通知配置保存结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const firstCall = putSpy.mock.calls[0]

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(2))
    expect(putSpy.mock.calls[1]).toEqual(firstCall)

    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(channelsSpy).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('通知配置保存结果待确认')).not.toBeInTheDocument()
  })

  it('renders a terminal localized 403 for a remote read denial without retrying or exposing the server message', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockRejectedValue(
      new ApiError('raw private denial', 403, 'system_configuration_permission_denied'),
    )

    renderPage()

    expect(await screen.findByText('无权查看节点监控设置')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重试' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private denial')
  })

  it('freezes an unknown write attempt, retries exact metadata and value, then supports abandon and refresh', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const putSpy = vi.spyOn(systemConfigurationApi, 'put')
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'system_configuration_unavailable'))
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'system_configuration_unavailable'))
    const user = userEvent.setup()

    renderPage()
    await screen.findByRole('heading', { name: '节点监控设置' })
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    expect(await screen.findByText('保存结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存设置' })).toBeDisabled()
    const firstCall = putSpy.mock.calls[0]

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(2))
    expect(putSpy.mock.calls[1]).toEqual(firstCall)

    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    expect(await screen.findByRole('button', { name: '保存设置' })).toBeEnabled()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
  })

  it('treats a terminal 403 as non-retryable and does not expose the server message', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    vi.spyOn(systemConfigurationApi, 'put').mockRejectedValue(new ApiError('raw denial', 403, 'system_configuration_permission_denied'))
    const user = userEvent.setup()

    renderPage()
    await screen.findByRole('heading', { name: '节点监控设置' })
    await user.click(screen.getByRole('button', { name: '保存设置' }))

    expect(await screen.findByText('无权修改节点监控设置')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw denial')
  })

  it('uses owner and session epoch without tokens in cache identity across token refresh', async () => {
    const actor = admin()
    const epoch = authenticate(actor, 'old-token')
    const getSpy = vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const { queryClient } = renderPage()

    await screen.findByRole('heading', { name: '节点监控设置' })
    await act(async () => {
      authenticate(actor, 'new-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(getSpy).toHaveBeenCalledTimes(1)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toContain('old-token')
      expect(JSON.stringify(query.queryKey)).not.toContain('new-token')
    }
  })
})

describe('A10/N01 monitoring fields are registered once', () => {
  it('has one control per probe field and saves a 500 ms timeout within the server contract', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const putSpy = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(configDocument())
    const user = userEvent.setup()
    const view = renderPage()

    const timeout = await screen.findByRole('spinbutton', { name: '探测超时（毫秒）' })
    for (const id of ['probe_timeout_ms', 'probe_interval_ms', 'failure_threshold', 'recovery_threshold']) {
      expect(view.container.querySelectorAll(`[id$="${id}"]`).length).toBeLessThanOrEqual(1)
    }
    expect(screen.getAllByRole('spinbutton', { name: '探测超时（毫秒）' })).toHaveLength(1)
    expect(screen.getAllByRole('spinbutton', { name: '探测间隔（毫秒）' })).toHaveLength(1)
    await user.clear(timeout)
    await user.type(timeout, '500')
    await user.click(screen.getByRole('button', { name: '保存设置' }))
    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1))
    expect(putSpy.mock.calls[0][2]).toMatchObject({ probe_timeout_ms: 500 })
  })
})

describe('A10/N06 switch log reads real serving events', () => {
  const event = {
    id: '018f0000-0000-7000-8000-0000000000e1', source: 'availability_monitor' as const, event: 'held' as const,
    reason_code: 'probe_unhealthy', hold_revision: 1, detail: {}, occurred_at: '2026-10-24T01:00:00Z',
    node_id: '018f0000-0000-7000-8000-0000000000a1', node_name: 'edge-sh-1', ipv4: '192.0.2.10', ipv6: '',
  }
  const reader = () => admin({ permissions: ['system_configuration.read', 'nodes.read'] })

  it('lists events, applies filters, clears them and pages with the real query', async () => {
    authenticate(reader())
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const list = vi.spyOn(nodeMonitoringApi, 'listScopeServingEvents').mockImplementation(async (_token, query) => ({
      schema_version: 1, from: query.from, to: query.to, page: query.page, limit: query.limit, total: 25, items: [event],
    }))
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: '切换日志' }))

    expect(await screen.findByText('edge-sh-1')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument()
    expect(screen.getByText('节点探测连续失败')).toBeInTheDocument()
    expect(screen.getByText('共 25 条')).toBeInTheDocument()

    const ip = screen.getByRole('textbox', { name: '节点IP' })
    await user.type(ip, '192.0.2.10')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ ip: '192.0.2.10', page: 1 }), expect.anything()))

    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ ip: '192.0.2.10', page: 2 }), expect.anything()))

    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(ip).toHaveValue('')
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.not.objectContaining({ ip: expect.anything() }), expect.anything()))
    expect(list.mock.lastCall?.[1].page).toBe(1)
  })

  it('separates a failed query from a real zero result', async () => {
    authenticate(reader())
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(configDocument())
    const list = vi.spyOn(nodeMonitoringApi, 'listScopeServingEvents').mockRejectedValueOnce(new ApiError('down', 503, 'node_monitoring_unavailable'))
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: '切换日志' }))
    expect((await screen.findAllByText('切换日志加载失败，请稍后重试')).length).toBeGreaterThan(0)
    expect(screen.queryByText('最近 31 天没有切换记录')).not.toBeInTheDocument()

    list.mockImplementation(async (_token, query) => ({ schema_version: 1, from: query.from, to: query.to, page: 1, limit: 10, total: 0, items: [] }))
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('最近 31 天没有切换记录')).toBeInTheDocument()
  })
})
