import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { originRoutingApi, ORIGIN_ROUTING_SCHEMA, type OriginRoutingState } from '../../api/siteOriginRouting'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import '../../i18n/siteOriginRouting'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import ConditionalOriginSiteTab from './ConditionalOriginSiteTab'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const siteId = '11111111-1111-4111-8111-111111111111'
const token = 'memory-only-access-token'
const document = {
  schema: ORIGIN_ROUTING_SCHEMA,
  pools: [{ id: 'pool-a', balance_method: 'round_robin' as const, endpoints: [{ id: 'origin-a', host: '192.0.2.10', port: 443, weight: 100 }] }],
  ingress_source_enabled: false,
  default_pool_id: 'pool-a', routes: [],
  retry: { methods: ['GET', 'HEAD'] as Array<'GET' | 'HEAD'>, max_attempts: 2, connect_timeout_ms: 100, read_timeout_ms: 100, total_budget_ms: 300 },
}
function state(version = 7, maxAttempts = 2): OriginRoutingState {
  return {
    site_id: siteId,
    version,
    updated_at: '2026-08-06T09:00:00Z',
    document: { ...document, retry: { ...document.retry, max_attempts: maxAttempts } },
  }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}
function authenticate(permissions = ['sites.read', 'sites.manage']) {
  const actor = principal({ permissions, tenant_id: '22222222-2222-4222-8222-222222222222' })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return actor
}
function renderTab(permissions = ['sites.read', 'sites.manage'], options: { lockedForTenant?: boolean } = {}) {
  const actor = authenticate(permissions)
  return renderWithProviders(<ConditionalOriginSiteTab siteId={siteId} accessToken={token} scopeKind="tenant" scopeId={actor.scope_id} tenantId={actor.tenant_id} userId={actor.user_id} sessionEpoch={useSessionStore.getState().sessionEpoch} permissions={permissions} canManage={permissions.includes('sites.manage')} lockedForTenant={options.lockedForTenant ?? false} />)
}
const text = (key: string) => i18n.t(key, { ns: 'siteOriginRouting' })

beforeEach(async () => { await i18n.changeLanguage('zh-CN') })
afterEach(async () => { vi.restoreAllMocks(); await act(async () => { await i18n.changeLanguage('zh-CN') }); useSessionStore.getState().clearSession() })

describe('ConditionalOriginSiteTab read states', () => {
  it('shows a plain loading state without the internal candidate notice', async () => {
    vi.spyOn(originRoutingApi, 'get').mockReturnValue(new Promise<OriginRoutingState>(() => undefined))
    renderTab()
    expect(screen.queryByText('候选控制面配置', { exact: false })).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: text('title') })).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByText(text('states.loading'))).toBeInTheDocument()
  })

  it('fails closed without sites.read and sends zero request', () => {
    const get = vi.spyOn(originRoutingApi, 'get')
    renderTab(['sites.manage'])
    expect(screen.getByText(text('states.forbidden'))).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('maps 403 terminal, 404 empty, and recoverable 5xx with retry', async () => {
    const get = vi.spyOn(originRoutingApi, 'get').mockRejectedValueOnce(new ApiError('private', 403, 'permission_denied'))
    renderTab()
    expect(await screen.findByText(text('states.forbidden'))).toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(1)

    get.mockRejectedValueOnce(new ApiError('private', 404, 'not_found'))
    renderTab()
    expect(await screen.findByText(text('states.empty'))).toBeInTheDocument()

    get.mockRejectedValueOnce(new ApiError('private', 503, 'service_unavailable')).mockResolvedValueOnce(state())
    renderTab()
    expect(await screen.findByText(text('states.loadError'))).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: text('actions.retry') }))
    expect(await screen.findByRole('switch', { name: text('fields.ingressSource') })).toBeInTheDocument()
  })
})

describe('ConditionalOriginSiteTab writes and lineage', () => {
  it('saves the Chinese ingress-source origin switch as an explicit boolean', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace').mockResolvedValue(state(8))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    // fix-siteinstant: the switch saves at once (no save button)
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    expect(replace.mock.calls[0]![3].ingress_source_enabled).toBe(true)
  })

  it('shows units, explains locked pool deletion, and deletes an unused pool after confirmation', async () => {
    const pooled = state()
    pooled.document = { ...pooled.document, pools: [...pooled.document.pools, { id: 'pool-b', balance_method: 'random', endpoints: [{ id: 'origin-b', host: '198.51.100.20', port: 80, weight: 10 }] }] }
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(pooled)
    const replace = vi.spyOn(originRoutingApi, 'replace').mockResolvedValue(state(8))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    expect(screen.getAllByText(text('units.ms'))).toHaveLength(3)
    expect(screen.getByText(text('units.times'))).toBeInTheDocument()
    expect(screen.getByText(text('states.noRoutes'))).toBeInTheDocument()

    const used = within(screen.getByTestId('origin-pool-pool-a')).getByRole('button', { name: text('actions.deletePool') })
    expect(used).toBeDisabled()
    await user.hover(used.parentElement!)
    expect(await screen.findByText(text('hints.poolInUse'))).toBeInTheDocument()

    await user.click(within(screen.getByTestId('origin-pool-pool-b')).getByRole('button', { name: text('actions.deletePool') }))
    const popover = (await screen.findByText(i18n.t('actions.confirmDeletePool', { ns: 'siteOriginRouting', id: 'pool-b' }))).closest('.ant-popover') as HTMLElement
    await user.click(within(popover).getByRole('button', { name: text('actions.delete') }))
    await waitFor(() => expect(screen.queryByTestId('origin-pool-pool-b')).not.toBeInTheDocument())
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    expect(replace.mock.calls[0]![3].pools.map((pool) => pool.id)).toEqual(['pool-a'])
  })

  it('creates and edits a conditional route before saving the canonical document', async () => {
    const routed = state()
    routed.document = {
      ...routed.document,
      pools: [
        ...routed.document.pools,
        {
          id: 'pool-b',
          balance_method: 'least_conn',
          endpoints: [{ id: 'origin-b', host: '198.51.100.20', port: 443, weight: 100 }],
        },
      ],
    }
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(routed)
    const replace = vi.spyOn(originRoutingApi, 'replace').mockImplementation(async (_token, _site, version, document) => ({ ...routed, version: version + 1, document }))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })

    await user.click(screen.getByRole('button', { name: '添加条件规则' }))
    let dialog = await screen.findByRole('dialog', { name: '添加条件规则' })
    await user.type(within(dialog).getByLabelText('规则 ID'), 'api-route')
    await user.clear(within(dialog).getByLabelText('优先级'))
    await user.type(within(dialog).getByLabelText('优先级'), '100')
    await user.type(within(dialog).getByLabelText('路径前缀'), '/api')
    await user.type(within(dialog).getByLabelText('节点区域'), 'cn-east, cn-west')
    await user.type(within(dialog).getByLabelText('客户端网段'), '192.0.2.0/24')
    await user.click(within(dialog).getByRole('combobox', { name: '备用回源池' }))
    const poolBOptions = await screen.findAllByText('pool-b', { selector: '.ant-select-item-option-content' })
    await user.click(poolBOptions.at(-1)!)
    expect(within(dialog).getByText('pool-b', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '应用规则' }))

    expect(await screen.findByTestId('origin-route-api-route')).toHaveTextContent('api-route')
    await user.click(screen.getByRole('button', { name: '编辑规则 api-route' }))
    dialog = await screen.findByRole('dialog', { name: '编辑条件规则' })
    await user.clear(within(dialog).getByLabelText('优先级'))
    await user.type(within(dialog).getByLabelText('优先级'), '200')
    await user.clear(within(dialog).getByLabelText('路径前缀'))
    await user.type(within(dialog).getByLabelText('路径前缀'), '/v2')
    await user.click(within(dialog).getByRole('button', { name: '应用规则' }))

    // fix-siteinstant: each 应用规则 saves; the second save uses the version the first returned
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(2))
    expect(replace.mock.calls.map((call) => call[2])).toEqual([7, 8])
    expect(replace.mock.calls[1]![3].routes).toEqual([{
      id: 'api-route',
      priority: 200,
      path_prefix: '/v2',
      node_regions: ['cn-east', 'cn-west'],
      client_cidrs: ['192.0.2.0/24'],
      pool_id: 'pool-a',
      fallback_pool_id: 'pool-b',
    }])
  })

  it('sends complete document with strong CAS and idempotency, then saves', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace').mockResolvedValue(state(8))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    expect(replace.mock.calls[0]![0]).toBe(token)
    expect(replace.mock.calls[0]![2]).toBe(7)
    expect(replace.mock.calls[0]![4]).toBeTruthy()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('keeps 403 terminal and maps 412 without raw server details', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace').mockRejectedValue(new ApiError('private details', 412, 'precondition_failed'))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    expect(await screen.findByText(text('states.conflict'))).toBeInTheDocument()
    expect(screen.queryByText('private details')).not.toBeInTheDocument()
    expect(replace).toHaveBeenCalledTimes(1)
  })

  it.each([
    [new ApiError('raw network detail', 0, 'network_error')],
    [new ApiError('raw timeout detail', 408, 'request_timeout')],
    [new ApiError('raw throttle detail', 429, 'rate_limited')],
    [new ApiError('raw service detail', 503, 'service_unavailable')],
    [new ApiError('raw parser detail', 0, 'invalid_response')],
  ])('locks editing after an unknown replace result %#', async (writeError) => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace').mockRejectedValue(writeError)
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })

    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))

    expect(await screen.findByText(text('states.unknownResult'), OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toBeDisabled()
    expect(screen.getByRole('button', { name: text('actions.retryExact') })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: text('actions.abandonAndReload') })).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: text('fields.ingressSource') })).toBeDisabled()
    expect(screen.queryByText(writeError.message)).not.toBeInTheDocument()
    expect(replace).toHaveBeenCalledTimes(1)
  })

  it('retries the frozen site, version, document, and key with the refreshed token', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValueOnce(new ApiError('raw service detail', 503, 'service_unavailable'))
      .mockResolvedValueOnce(state(8))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })

    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await screen.findByText(text('states.unknownResult'), OUTCOME_BAR)
    const first = replace.mock.calls[0]!
    const actor = useSessionStore.getState().principal!
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: 'refreshed-token' },
      actor,
      'refresh',
    ))

    await user.click(screen.getByRole('button', { name: text('actions.retryExact') }))
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const second = replace.mock.calls[1]!
    expect(second[0]).toBe('refreshed-token')
    expect(second.slice(1)).toEqual(first.slice(1))
    expect(first[1]).toBe(siteId)
    expect(first[2]).toBe(7)
    expect(first[3]).toEqual({ ...state().document, ingress_source_enabled: true })
    expect(first[4]).toBeTruthy()
  })

  it('abandons an unknown attempt and refetches the current fact source', async () => {
    const get = vi.spyOn(originRoutingApi, 'get')
      .mockResolvedValueOnce(state())
      .mockResolvedValueOnce(state(9, 4))
    vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValue(new ApiError('raw service detail', 503, 'service_unavailable'))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })

    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await screen.findByText(text('states.unknownResult'), OUTCOME_BAR)
    await user.click(screen.getByRole('button', { name: text('actions.abandonAndReload') }))

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('4'))
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toBeEnabled()
    expect(screen.queryByRole('button', { name: text('actions.retryExact') })).not.toBeInTheDocument()
  })

  // B14：重新加载拿到与之前相同的 JSON 时 query.data 引用不变，曾经显示"尚未配置"，要切页签才恢复。
  it('restores the server snapshot when the reload returns the same JSON', async () => {
    const get = vi.spyOn(originRoutingApi, 'get')
      .mockResolvedValueOnce(state())
      .mockResolvedValueOnce(state())
    vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValue(new ApiError('raw service detail', 500, 'internal_error'))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await screen.findByText(text('states.unknownResult'), OUTCOME_BAR)

    await user.click(screen.getByRole('button', { name: text('actions.abandonAndReload') }))

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('switch', { name: text('fields.ingressSource') })).not.toBeChecked()
    expect(screen.queryByText(text('states.empty'))).not.toBeInTheDocument()
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('2')
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toBeEnabled()
    expect(screen.queryByText(text('states.unknownResult'), OUTCOME_BAR)).not.toBeInTheDocument()
  })

  it('keeps the previous snapshot and the unknown-result lock when the reload fails', async () => {
    const get = vi.spyOn(originRoutingApi, 'get')
      .mockResolvedValueOnce(state())
      .mockRejectedValueOnce(new ApiError('raw read detail', 503, 'service_unavailable'))
    vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValue(new ApiError('raw service detail', 503, 'service_unavailable'))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await screen.findByText(text('states.unknownResult'), OUTCOME_BAR)

    await user.click(screen.getByRole('button', { name: text('actions.abandonAndReload') }))

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(await screen.findByText(text('states.loadError'))).toBeInTheDocument()
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('2')
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toBeDisabled()
    expect(screen.getByText(text('states.unknownResult'), OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: text('actions.retryExact') })).toBeInTheDocument()
    expect(screen.queryByText('raw read detail')).not.toBeInTheDocument()
  })

  // p0c 遗留：读取失败后恢复条曾被卸载重挂，已关闭的"没有收到保存结果"说明弹窗会再弹一次。
  it('does not reopen the closed unknown-result dialog when the reload fails', async () => {
    const reload = deferred<OriginRoutingState>()
    vi.spyOn(originRoutingApi, 'get')
      .mockResolvedValueOnce(state())
      .mockReturnValueOnce(reload.promise.then(() => { throw new ApiError('raw read detail', 503, 'service_unavailable') }))
    vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValue(new ApiError('raw service detail', 503, 'service_unavailable'))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: '知道了' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: text('actions.abandonAndReload') }))
    // 重载期间表单保留在原位（已锁定），不切成加载态。
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toBeDisabled()
    expect(screen.queryByText(text('states.loading'))).not.toBeInTheDocument()
    await act(async () => { reload.resolve(state()) })

    expect(await screen.findByText(text('states.loadError'))).toBeInTheDocument()
    expect(screen.getByText(text('states.unknownResult'), OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('does not restore a reload that finishes after the owner session changes', async () => {
    const reload = deferred<OriginRoutingState>()
    const get = vi.spyOn(originRoutingApi, 'get')
      .mockResolvedValueOnce(state())
      .mockReturnValueOnce(reload.promise)
    vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValue(new ApiError('raw service detail', 503, 'service_unavailable'))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await screen.findByText(text('states.unknownResult'), OUTCOME_BAR)
    await user.click(screen.getByRole('button', { name: text('actions.abandonAndReload') }))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))

    act(() => useSessionStore.getState().clearSession())
    await act(async () => { reload.resolve(state(9, 4)) })

    expect(screen.queryByLabelText(text('fields.maxAttempts'))).not.toBeInTheDocument()
  })

  it.each([
    [403, 'permission_denied', 'errors.permission'],
    [404, 'not_found', 'errors.notFound'],
    [409, 'conflict', 'states.conflict'],
    [412, 'precondition_failed', 'states.conflict'],
    [422, 'validation_error', 'errors.validation'],
  ])('ends deterministic replace %i without exact retry', async (status, code, messageKey) => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace')
      .mockRejectedValue(new ApiError('raw deterministic detail', status, code))
    const user = userEvent.setup()
    renderTab()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })

    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))

    expect(await screen.findByText(text(messageKey))).toBeInTheDocument()
    expect(screen.queryByText('raw deterministic detail')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: text('actions.retryExact') })).not.toBeInTheDocument()
    // a refused change goes back to the saved value and the form stays editable
    expect(screen.getByRole('switch', { name: text('fields.ingressSource') })).toBeEnabled()
    await waitFor(() => expect(screen.getByRole('switch', { name: text('fields.ingressSource') })).not.toBeChecked())
    expect(replace).toHaveBeenCalledTimes(1)
  })

  it('ignores a late replace success after the owner session changes', async () => {
    const late = deferred<OriginRoutingState>()
    const get = vi.spyOn(originRoutingApi, 'get').mockImplementation((activeToken) => (
      Promise.resolve(activeToken === 'token-a' ? state(7, 2) : state(9, 4))
    ))
    vi.spyOn(originRoutingApi, 'replace').mockReturnValue(late.promise)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
    const actorA = authenticate()
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorA), access_token: 'token-a' }, actorA, 'refresh',
    ))
    const epochA = useSessionStore.getState().sessionEpoch
    const view = render(
      <QueryClientProvider client={queryClient}>
        <ConditionalOriginSiteTab siteId={siteId} accessToken="token-a" scopeKind="tenant" scopeId={actorA.scope_id} tenantId={actorA.tenant_id} userId={actorA.user_id} sessionEpoch={epochA} permissions={actorA.permissions} canManage lockedForTenant={false} />
      </QueryClientProvider>,
    )
    const user = userEvent.setup()
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))

    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: actorA.scope_id,
      tenant_id: actorA.tenant_id,
      permissions: ['sites.read', 'sites.manage'],
    })
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorB), access_token: 'token-b' }, actorB,
    ))
    const epochB = useSessionStore.getState().sessionEpoch
    view.rerender(
      <QueryClientProvider client={queryClient}>
        <ConditionalOriginSiteTab siteId={siteId} accessToken="token-b" scopeKind="tenant" scopeId={actorB.scope_id} tenantId={actorB.tenant_id} userId={actorB.user_id} sessionEpoch={epochB} permissions={actorB.permissions} canManage lockedForTenant={false} />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(get).toHaveBeenCalledWith('token-b', siteId))
    await waitFor(() => expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('4'))

    await act(async () => late.resolve(state(8, 6)))
    expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('4')
    expect(screen.queryByText('操作成功')).not.toBeInTheDocument()
    expect(queryClient.getQueryData([
      'site-origin-routing', 'tenant', actorA.scope_id, actorA.tenant_id,
      actorA.user_id, epochA, siteId,
    ])).toBeUndefined()
  })

  it('removes sensitive query cache after a new owner session and ignores late response', async () => {
    let resolveA!: (value: OriginRoutingState) => void
    const get = vi.spyOn(originRoutingApi, 'get').mockImplementation((activeToken) => activeToken === 'token-a'
      ? new Promise<OriginRoutingState>((resolve) => { resolveA = resolve })
      : Promise.resolve(state(9)))
    const actorA = authenticate()
    act(() => useSessionStore.getState().setSession({ ...authResponse(actorA), access_token: 'token-a' }, actorA))
    const first = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}><ConditionalOriginSiteTab siteId={siteId} accessToken="token-a" scopeKind="tenant" scopeId={actorA.scope_id} tenantId={actorA.tenant_id} userId={actorA.user_id} sessionEpoch={useSessionStore.getState().sessionEpoch} permissions={['sites.read', 'sites.manage']} canManage lockedForTenant={false} /></QueryClientProvider>)
    await waitFor(() => expect(get).toHaveBeenCalledWith('token-a', siteId))
    const actorB = principal({ user_id: '33333333-3333-4333-8333-333333333333', scope_id: actorA.scope_id, tenant_id: actorA.tenant_id, permissions: ['sites.read', 'sites.manage'] })
    act(() => useSessionStore.getState().setSession({ ...authResponse(actorB), access_token: 'token-b' }, actorB))
    first.rerender(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}><ConditionalOriginSiteTab siteId={siteId} accessToken="token-b" scopeKind="tenant" scopeId={actorB.scope_id} tenantId={actorB.tenant_id} userId={actorB.user_id} sessionEpoch={useSessionStore.getState().sessionEpoch} permissions={['sites.read', 'sites.manage']} canManage lockedForTenant={false} /></QueryClientProvider>)
    await waitFor(() => expect(get).toHaveBeenCalledWith('token-b', siteId))
    await act(async () => resolveA(state(1)))
    expect(screen.queryByText('1')).not.toBeInTheDocument()
  })
})

describe('ConditionalOriginSiteTab workflow state (SITE-CURRENT-02)', () => {
  it('reports the unsaved draft and the unknown attempt to the edit page', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    vi.spyOn(originRoutingApi, 'replace').mockRejectedValue(new ApiError('lost', 0, 'network_error'))
    const onState = vi.fn()
    const actor = authenticate()
    const user = userEvent.setup()
    renderWithProviders(<ConditionalOriginSiteTab siteId={siteId} accessToken={token} scopeKind="tenant" scopeId={actor.scope_id} tenantId={actor.tenant_id} userId={actor.user_id} sessionEpoch={useSessionStore.getState().sessionEpoch} permissions={['sites.read', 'sites.manage']} canManage lockedForTenant={false} onWorkflowStateChange={onState} />)
    await screen.findByRole('switch', { name: text('fields.ingressSource') })
    expect(onState).toHaveBeenLastCalledWith({ dirty: false, uncertain: false, pending: false })
    // fix-siteinstant: the switch saves at once; an unknown result keeps the draft and reports it
    await user.click(screen.getByRole('switch', { name: text('fields.ingressSource') }))
    await waitFor(() => expect(onState).toHaveBeenLastCalledWith({ dirty: true, uncertain: true, pending: false }))
  })
})

// CU-SITE-01：草稿绑定自己的基线（版本+文档），远端快照只在草稿未改动时接管。
describe('ConditionalOriginSiteTab draft baseline (CU-SITE-01)', () => {
  function mountWithClient() {
    const actor = authenticate()
    const epoch = useSessionStore.getState().sessionEpoch
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
    const key = ['site-origin-routing', 'tenant', actor.scope_id, actor.tenant_id, actor.user_id, epoch, siteId]
    renderWithProviders(<QueryClientProvider client={queryClient}><ConditionalOriginSiteTab siteId={siteId} accessToken={token} scopeKind="tenant" scopeId={actor.scope_id} tenantId={actor.tenant_id} userId={actor.user_id} sessionEpoch={epoch} permissions={['sites.read', 'sites.manage']} canManage lockedForTenant={false} /></QueryClientProvider>)
    return { queryClient, key }
  }
  const settle = () => act(async () => { await new Promise((resolve) => setTimeout(resolve, 50)) })

  it('keeps a number typed while the previous save is in flight, then saves it on blur with the new version', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const first = deferred<OriginRoutingState>()
    const replace = vi.spyOn(originRoutingApi, 'replace')
      .mockReturnValueOnce(first.promise)
      .mockImplementation(async (_token, _site, version, sent) => ({ ...state(version + 1), document: sent }))
    const user = userEvent.setup()
    mountWithClient()
    await user.click(await screen.findByRole('switch', { name: text('fields.ingressSource') }))
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    const field = screen.getByLabelText(text('fields.maxAttempts'))
    await user.clear(field)
    await user.type(field, '4')
    await act(async () => { first.resolve({ ...state(8), document: replace.mock.calls[0]![3] }) })
    await settle()
    expect(field).toHaveValue('4')
    expect(replace).toHaveBeenCalledTimes(1)
    await user.tab()
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(2))
    expect(replace.mock.calls[1]![2]).toBe(8)
    expect(replace.mock.calls[1]![3]).toMatchObject({ ingress_source_enabled: true, retry: { max_attempts: 4 } })
  })

  it('keeps a typed number when a background read returns the same content at a newer version', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace').mockImplementation(async (_token, _site, version, sent) => ({ ...state(version + 1), document: sent }))
    const user = userEvent.setup()
    const { queryClient, key } = mountWithClient()
    const field = await screen.findByLabelText(text('fields.maxAttempts'))
    await user.clear(field)
    await user.type(field, '4')
    await act(async () => { queryClient.setQueryData(key, state(8)) })
    await settle()
    expect(field).toHaveValue('4')
    expect(screen.queryByText(text('states.remoteChanged'))).not.toBeInTheDocument()
    await user.tab()
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    expect(replace.mock.calls[0]![2]).toBe(8)
  })

  it('keeps the draft, pauses auto-save, and overwrites only on explicit choice when someone else changed the configuration', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace')
    const user = userEvent.setup()
    const { queryClient, key } = mountWithClient()
    const field = await screen.findByLabelText(text('fields.maxAttempts'))
    await user.clear(field)
    await user.type(field, '4')
    const remote = state(8)
    remote.document = { ...remote.document, ingress_source_enabled: true }
    await act(async () => { queryClient.setQueryData(key, remote) })
    await settle()
    expect(field).toHaveValue('4')
    expect(screen.getByText(text('states.remoteChanged'))).toBeInTheDocument()
    // the old draft is never silently saved or bound to the newer version
    await user.tab()
    await settle()
    expect(replace).not.toHaveBeenCalled()
    replace.mockImplementation(async (_token, _site, version, sent) => ({ ...state(version + 1), document: sent }))
    await user.click(screen.getByRole('button', { name: text('actions.overwriteLatest') }))
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    expect(replace.mock.calls[0]![2]).toBe(8)
    expect(replace.mock.calls[0]![3]).toMatchObject({ ingress_source_enabled: false, retry: { max_attempts: 4 } })
    await waitFor(() => expect(screen.queryByText(text('states.remoteChanged'))).not.toBeInTheDocument())
  })

  it('loads the newer configuration when the user discards the draft from the conflict notice', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const replace = vi.spyOn(originRoutingApi, 'replace')
    const user = userEvent.setup()
    const { queryClient, key } = mountWithClient()
    const field = await screen.findByLabelText(text('fields.maxAttempts'))
    await user.clear(field)
    await user.type(field, '4')
    const remote = state(8, 3)
    remote.document = { ...remote.document, ingress_source_enabled: true }
    await act(async () => { queryClient.setQueryData(key, remote) })
    await user.click(await screen.findByRole('button', { name: text('actions.loadLatest') }))
    await waitFor(() => expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('3'))
    expect(screen.getByRole('switch', { name: text('fields.ingressSource') })).toBeChecked()
    expect(screen.queryByText(text('states.remoteChanged'))).not.toBeInTheDocument()
    expect(replace).not.toHaveBeenCalled()
  })

  it('adopts a background update while the draft is unchanged', async () => {
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue(state())
    const { queryClient, key } = mountWithClient()
    await screen.findByLabelText(text('fields.maxAttempts'))
    await act(async () => { queryClient.setQueryData(key, state(8, 5)) })
    await waitFor(() => expect(screen.getByLabelText(text('fields.maxAttempts'))).toHaveValue('5'))
  })
})
