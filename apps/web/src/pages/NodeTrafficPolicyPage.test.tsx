import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import type { Principal } from '../api/auth'
import { nodeTrafficPoliciesApi, type NodeTrafficPolicyState } from '../api/nodeTrafficPolicies'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { nodeTrafficPolicyResources } from '../i18n/nodeTrafficPolicy'
import { authResponse, principal } from '../test/fixtures'
import NodeTrafficPolicyPage from './NodeTrafficPolicyPage'

const scopeId = '22222222-2222-4222-8222-222222222222'
const nodeId = '33333333-3333-4333-8333-333333333333'
const state: NodeTrafficPolicyState = {
  policy: {
    id: '11111111-1111-4111-8111-111111111111', scope_id: scopeId, node_id: nodeId,
    monthly_limit_bytes: 1_000, timezone: 'Asia/Shanghai', windows: [], revision: 4,
    manual_override: { mode: 'none', revision: 0, expires_at: null },
    created_at: '2026-08-09T00:00:00Z', updated_at: '2026-08-09T00:00:00Z',
  },
  admin_state: 'active', current_config_version_id: '44444444-4444-4444-8444-444444444444',
  last_evaluation: null,
}

function platform(overrides: Partial<Principal> = {}) {
  return principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
    permissions: ['nodes.read', 'nodes.manage'], ...overrides,
  })
}

function renderPage(actor = platform()) {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'node-policy-token' }, actor)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[`/node/traffic-policy?scope_id=${scopeId}&node_id=${nodeId}`]}>
            <NodeTrafficPolicyPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

describe('NodeTrafficPolicyPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    for (const [locale, resource] of Object.entries(nodeTrafficPolicyResources)) {
      i18n.addResourceBundle(locale, 'nodeTrafficPolicy', resource, true, true)
    }
    await i18n.changeLanguage('zh-CN')
  })

  it('renders the real policy state and keeps advanced scheduling secondary', async () => {
    vi.spyOn(nodeTrafficPoliciesApi, 'get').mockResolvedValue(state)
    renderPage()

    expect(await screen.findByRole('heading', { name: '节点流量与自动状态策略' })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '自然月流量上限（字节）' })).toHaveValue('1000')
    expect(screen.getByText('当前节点状态：运行中')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '高级定时设置' })).toBeInTheDocument()
  })

  it('fails closed for unknown state and evaluation reason codes', async () => {
    vi.spyOn(nodeTrafficPoliciesApi, 'get').mockResolvedValue({
      ...state,
      admin_state: 'future_state',
      last_evaluation: {
        period_key: '2026-08',
        suppressed: true,
        reason_code: 'future_reason',
        override_revision: 0,
      },
    })
    renderPage()

    expect(await screen.findByText('当前节点状态：未知状态')).toBeInTheDocument()
    expect(screen.getByText('周期 2026-08，原因：原因暂无法识别，请联系管理员核对。')).toBeInTheDocument()
    expect(screen.queryByText(/future_state|future_reason/)).not.toBeInTheDocument()
  })

  it.each([
    ['tenant actor', platform({ scope_kind: 'tenant', tenant_id: scopeId })],
    ['missing read permission', platform({ permissions: ['nodes.manage'] })],
  ])('fails locally with zero requests for %s', async (_label, actor) => {
    const read = vi.spyOn(nodeTrafficPoliciesApi, 'get')
    renderPage(actor)
    expect(await screen.findByText('无权查看节点流量策略')).toBeInTheDocument()
    expect(read).not.toHaveBeenCalled()
  })
})
