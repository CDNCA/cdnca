import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import type { Principal } from '../api/auth'
import { nodeIsolationApi, type NodeIsolationState } from '../api/nodeIsolation'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import NodeIsolationPage from './NodeIsolationPage'

const scopeID = '11111111-1111-4111-8111-111111111111'
const nodeID = '22222222-2222-4222-8222-222222222222'
const state: NodeIsolationState = {
  scope_id: scopeID, node_id: nodeID, status: 'isolated',
  desired: { schema: 1, config_version_id: '33333333-3333-4333-8333-333333333333', artifact_sha256: 'a'.repeat(64) },
  consecutive_failures: 3, consecutive_healthy: 0, last_session_epoch: 4, last_health_sequence: 9,
  last_report_id: '44444444-4444-4444-8444-444444444444', last_outcome: 'failed',
  last_error_code: 'agent_apply_failed', reason_code: 'sync_failure_threshold', revision: 7,
  isolated_at: '2026-08-09T00:00:00Z', recovered_at: null, updated_at: '2026-08-09T00:00:01Z',
}

function platform(overrides: Partial<Principal> = {}) {
  return principal({ scope_id: scopeID, scope_kind: 'platform', tenant_id: null,
    permissions: ['nodes.read'], roles: ['platform_admin'], ...overrides })
}

function renderPage(actor = platform()) {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'node-isolation-token' }, actor)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<ConfigProvider button={{ autoInsertSpace: false }}><AntApp><QueryClientProvider client={client}>
    <MemoryRouter><NodeIsolationPage /></MemoryRouter>
  </QueryClientProvider></AntApp></ConfigProvider>)
}

describe('NodeIsolationPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })
  afterEach(() => vi.restoreAllMocks())

  it('shows isolated nodes while stating healthy nodes continue', async () => {
    vi.spyOn(nodeIsolationApi, 'list').mockResolvedValue([state])
    renderPage()
    expect(await screen.findByRole('heading', { name: '节点同步隔离' })).toBeInTheDocument()
    expect(screen.getByText('已隔离')).toBeInTheDocument()
    expect(await screen.findByText('1 个节点已隔离，其他健康节点继续接收配置。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /解除|恢复/ })).not.toBeInTheDocument()
  })

  it.each([
    ['tenant', platform({ scope_kind: 'tenant', tenant_id: scopeID })],
    ['missing permission', platform({ permissions: [] })],
  ])('rejects %s locally without a request', async (_name, actor) => {
    const list = vi.spyOn(nodeIsolationApi, 'list')
    renderPage(actor)
    expect(await screen.findByText('无权查看节点隔离状态')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })
})
