import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { nodesApi, type NodeConfigurationScopes } from '../api/nodes'
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
          <NodeConfigurationScopesPanel nodeID={nodeID} queryKey={['node', nodeID]} accessToken={accessToken} />
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
