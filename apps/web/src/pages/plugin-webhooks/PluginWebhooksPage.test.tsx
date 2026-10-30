import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type Mutation, type MutationStatus, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import PluginWebhooksPage from './PluginWebhooksPage'
import { pluginWebhooksApi, type PluginWebhookSubscription } from '../../api/pluginWebhooks'
import { authResponse, principal } from '../../test/fixtures'
import { useSessionStore, type SessionUpdate } from '../../auth/session'
import i18n, { changeLocale } from '../../i18n'
import { renderWithProviders } from '../../test/render'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const scopeID = '018cc251-f400-7def-8000-000000000020'
const tenantID = '018cc251-f400-7def-8000-000000000030'
const alternateTenantID = '018cc251-f400-7def-8000-000000000031'
const alternateUserID = '018cc251-f400-7def-8000-000000000032'
const alternateAccessToken = 'scope-b-memory-only-access-token'
const platformScopeID = '018cc251-f400-7def-8000-000000000040'
const targetScopeID = '018cc251-f400-7def-8000-000000000050'
const alternateScopeID = '018cc251-f400-7def-8000-000000000060'
const installationAuthorizationID = '018cc251-f400-7def-8000-000000000070'
const alternateInstallationID = '018cc251-f400-7def-8000-000000000071'
const subscriptionID = '018cc251-f400-7def-8000-000000000010'
const alternateSubscriptionID = '018cc251-f400-7def-8000-000000000013'
const secretID = '018cc251-f400-7def-8000-000000000011'
const rotationID = '018cc251-f400-7def-8000-000000000012'
const deliveryID = '018cc251-f400-7def-8000-000000000001'
const createSecret = 'A'.repeat(43)
const rotationSecret = `${'B'.repeat(42)}Q`

const copy = {
  title: 'Plugin webhooks', subtitle: 'Manage signed delivery targets.',
  actions: { refresh: 'Refresh', create: 'Create subscription', retry: 'Retry', view: 'View', test: 'Test', sendTest: 'Send test', rotate: 'Rotate secret', revoke: 'Revoke', replay: 'Replay', replayRange: 'Replay by time', activate: 'Activate', cancel: 'Cancel', close: 'Close', retrySameRequest: 'Retry same request', closeAndRefresh: 'Close and refresh' },
  columns: { name: 'Name', target: 'Target', status: 'Status', revision: 'Revision', updatedAt: 'Updated', actions: 'Actions' },
  states: { active: 'Active', revoked: 'Revoked' },
  summary: { label: 'Summary', total: 'Total', active: 'Active', revoked: 'Revoked', eventType: 'Event type' },
  empty: { title: 'No subscriptions', description: 'Create your first target.' },
  forbidden: { title: 'Forbidden', description: 'Permission required.' },
  errors: { requestFailed: 'Request failed', permissionDenied: 'Permission denied', notFound: 'Not found', targetForbidden: 'Target forbidden', stateConflict: 'State conflict', rotationPending: 'Rotation pending', validationError: 'Validation failed', idempotencyKeyRequired: 'Idempotency key required', preconditionRequired: 'Precondition required', revisionConflict: 'Revision conflict', idempotencyConflict: 'Idempotency conflict', idempotencyExpired: 'Idempotency receipt expired', deliveryNotReplayable: 'Delivery cannot be replayed', entitlementDenied: 'Entitlement denied', quotaExceeded: 'Quota exceeded', rateLimited: 'Rate limited', secretUnavailable: 'Secret unavailable', storeUnavailable: 'Store unavailable', resultUnknown: 'Result unknown', loadFailed: 'Load failed', actionFailed: 'Action failed', unknownOutcome: 'Unknown outcome', detailLoadFailed: 'Detail load failed', deliveryLoadFailed: 'Delivery load failed' },
  notices: { created: 'Created', test: 'Test queued', replay: 'Replay queued', activate: 'Activated', revoke: 'Revoked' },
  create: { title: 'Create subscription', notice: 'The secret is shown once.', name: 'Name', nameRequired: 'Name required', nameTooLong: 'Name too long', namePlaceholder: 'Billing events', target: 'Target URL', targetPlaceholder: 'https://hooks.example.com/cdnca', targetInvalid: 'Valid URL required', events: 'Events', eventsRequired: 'Choose at least one event type', eventsDescription: 'Test events need no installation authorization; deployment status events must bind an enabled installation.', eventTypes: { test: 'Test event', deployment: 'Deployment status changed', site: 'Site updated', certificate: 'Certificate status changed', certificateExpiry: 'Certificate expiring or expired', node: 'Node status changed', usage: 'Usage threshold reached', security: 'Security incident detected' }, installationAuthorization: 'Installation authorization ID', installationAuthorizationDescription: 'Copy the UUID of an enabled installation authorization from the plugin marketplace.', installationAuthorizationPlaceholder: 'Enter the installation authorization UUID', installationAuthorizationRequired: 'Business events require an installation authorization ID', installationAuthorizationInvalid: 'Enter a valid installation authorization UUID', siteFilter: 'Sites (optional)', siteFilterDescription: 'Site filter.', siteFilterPlaceholder: 'Site UUIDs', siteFilterInvalid: 'Enter valid site UUIDs' },
  secret: { createTitle: 'Secret', rotateTitle: 'Rotated secret', warning: 'Store the secret securely.', description: 'It will not be shown again.', copy: 'Copy' },
  detail: { title: 'Details', status: 'Status', revision: 'Revision', target: 'Target', events: 'Events', siteFilter: 'Sites', allSites: 'All sites', createdAt: 'Created', updatedAt: 'Updated' },
  replayRange: { title: 'Replay by time', notice: 'Replays finished deliveries.', failedOnly: 'Only failed', result: '{{replayed}} replayed, {{denied}} denied', remaining: 'More remain' },
  deliveries: { title: 'Deliveries', empty: 'No deliveries' },
  deliveryColumns: { id: 'ID', status: 'Status', attempts: 'Attempts', createdAt: 'Created', actions: 'Actions' },
  deliveryStates: { pending: 'Pending', queued: 'Queued', claimed: 'Claimed', retry_scheduled: 'Retry scheduled', delivered: 'Delivered', dead_letter_pending: 'Dead-letter pending', dead_lettered: 'Dead-lettered', revoked: 'Revoked' },
  revoke: { confirm: 'Revoke this subscription?' },
  targetScope: { label: 'Target tenant scope', placeholder: 'Tenant scope UUID', apply: 'Apply target', required: 'Select a target tenant scope before reading.', invalid: 'Enter a valid tenant scope UUID.' },
  pagination: { subscriptions: 'Subscriptions pagination', deliveries: 'Deliveries pagination', previous: 'Previous', next: 'Next', page: 'Page {{page}}' },
  accessibility: { loading: 'Loading' },
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function setSession(options: { kind?: 'platform' | 'tenant'; permissions?: string[]; tenantScopeID?: string; tenantID?: string; userID?: string; accessToken?: string; update?: SessionUpdate } = {}) {
  const kind = options.kind ?? 'tenant'
  const current = principal({
    ...(options.userID ? { user_id: options.userID } : {}),
    scope_kind: kind,
    scope_id: kind === 'platform' ? platformScopeID : (options.tenantScopeID ?? scopeID),
    tenant_id: kind === 'platform' ? null : (options.tenantID ?? tenantID),
    permissions: options.permissions ?? ['plugin_webhooks.read', 'plugin_webhooks.manage'],
  })
  const response = authResponse(current)
  useSessionStore.getState().setSession(
    { ...response, access_token: options.accessToken ?? response.access_token },
    current,
    options.update,
  )
  const sessionEpoch = useSessionStore.getState().sessionEpoch
  return {
    principal: current,
    sessionEpoch,
    ownerKey: JSON.stringify([current.scope_kind, current.scope_id, current.tenant_id, current.user_id, sessionEpoch]),
  }
}

function allPluginWebhookApiSpies() {
  return [
    vi.spyOn(pluginWebhooksApi, 'listSubscriptions'),
    vi.spyOn(pluginWebhooksApi, 'createSubscription'),
    vi.spyOn(pluginWebhooksApi, 'getSubscription'),
    vi.spyOn(pluginWebhooksApi, 'createTestDelivery'),
    vi.spyOn(pluginWebhooksApi, 'listDeliveries'),
    vi.spyOn(pluginWebhooksApi, 'getDelivery'),
    vi.spyOn(pluginWebhooksApi, 'replayDelivery'),
    vi.spyOn(pluginWebhooksApi, 'rotateSecret'),
    vi.spyOn(pluginWebhooksApi, 'activateSecret'),
    vi.spyOn(pluginWebhooksApi, 'revokeSubscription'),
  ]
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function addTranslations() {
  i18n.addResourceBundle('en-US', 'pluginWebhooks', copy, true, true)
}

function QueryClientCapture({ capture }: { capture: (queryClient: QueryClient) => void }) {
  capture(useQueryClient())
  return null
}

function renderPageWithQueryClient(initialEntries = ['/']) {
  let queryClient: QueryClient | undefined
  const result = renderWithProviders(<><QueryClientCapture capture={(client) => { queryClient = client }} /><PluginWebhooksPage /></>, initialEntries)
  if (!queryClient) throw new Error('query client was not captured')
  return { ...result, queryClient }
}

function serializedMutationCache(queryClient: QueryClient): string {
  return JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state))
}

function activationMutations(queryClient: QueryClient) {
  return mutationsForKind(queryClient, 'activate')
}

function mutationsForKind(queryClient: QueryClient, kind: string) {
  return queryClient.getMutationCache().getAll().filter((mutation) => {
    const variables = mutation.state.variables
    return typeof variables === 'object' && variables !== null && 'kind' in variables && variables.kind === kind
  })
}

function expectPendingMutation(queryClient: QueryClient, variables: Record<string, unknown>) {
  const mutations = mutationsForKind(queryClient, String(variables.kind))
  expect(mutations).toHaveLength(1)
  expect(mutations[0]!.state.variables).toEqual(variables)
  expect(mutations[0]!.state).toMatchObject({ status: 'pending', data: undefined, error: null })
}

function observeMutationTerminal(queryClient: QueryClient, mutation: Mutation) {
  let unsubscribe: () => void = () => undefined
  const terminal = new Promise<Extract<MutationStatus, 'success' | 'error'>>((resolve) => {
    unsubscribe = queryClient.getMutationCache().subscribe((event) => {
      if (event.type !== 'updated' || event.mutation !== mutation) return
      const status = event.mutation.state.status
      if (status === 'success' || status === 'error') resolve(status)
    })
  })
  return { terminal, unsubscribe: () => unsubscribe() }
}

function serializedQueryCache(queryClient: QueryClient): string {
  return JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state))
}

function serializedStorage(storage: Storage): string {
  return JSON.stringify(Array.from({ length: storage.length }, (_, index) => {
    const key = storage.key(index)
    return [key, key ? storage.getItem(key) : null]
  }))
}

const item = {
  id: subscriptionID, tenant_scope_id: scopeID, name: 'Billing events', target_url: 'https://hooks.example.com/cdnca',
  event_types: ['io.cdnca.webhook.v1.test'], status: 'active', revision: 1, active_secret_version_id: secretID,
  created_at: '2026-07-29T08:00:00Z', updated_at: '2026-07-29T08:00:00Z',
}

describe('PluginWebhooksPage', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    localStorage.clear()
    sessionStorage.clear()
    await changeLocale('en-US')
    addTranslations()
    setSession()
  })

  it('rejects every locally invalid identity or platform target before all webhook APIs', async () => {
    await changeLocale('zh-CN')
    const apiSpies = allPluginWebhookApiSpies()
    const cases: Array<{
      session: () => void
      path?: string
      expected: string
    }> = [
      { session: () => useSessionStore.getState().clearSession(), expected: '无权访问' },
      { session: () => { setSession({ permissions: ['plugin_webhooks.manage'] }) }, expected: '无权访问' },
      {
        session: () => { setSession({ kind: 'platform', permissions: ['plugin_webhooks.manage'] }) },
        path: `/sys/plugin-webhooks?target_scope_id=${targetScopeID}`,
        expected: '无权访问',
      },
      {
        session: () => { setSession({ kind: 'platform', permissions: ['plugin_webhooks.read'] }) },
        path: '/sys/plugin-webhooks',
        expected: '请先选择要管理的租户作用域。',
      },
      {
        session: () => { setSession({ kind: 'platform', permissions: ['plugin_webhooks.read'] }) },
        path: '/sys/plugin-webhooks?target_scope_id=not-a-uuid',
        expected: '请输入有效的租户作用域 UUID。',
      },
    ]

    for (const localCase of cases) {
      localCase.session()
      const view = renderWithProviders(<PluginWebhooksPage />, [localCase.path ?? '/sys/plugin-webhooks'])
      expect(await screen.findByText(localCase.expected)).toBeInTheDocument()
      for (const apiSpy of apiSpies) expect(apiSpy).not.toHaveBeenCalled()
      view.unmount()
    }
  })

  it('renders complete qps-ploc loading, empty, retry recovery, and local/API 403 states', async () => {
    await changeLocale('qps-ploc')
    const t = i18n.getFixedT('qps-ploc', 'pluginWebhooks')
    let resolvePending!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      new Promise<Response>((resolve) => { resolvePending = resolve }))

    const pending = renderWithProviders(<PluginWebhooksPage />)
    const loading = pending.container.querySelector<HTMLElement>('.plugin-webhook-loading')!
    expect(within(loading).getByLabelText(t('accessibility.loading'))).toBeInTheDocument()
    act(() => resolvePending(json({ items: [] })))
    expect(await screen.findByText(t('empty.title'))).toBeInTheDocument()
    pending.unmount()

    fetchSpy.mockReset()
      .mockResolvedValueOnce(json({
        error: { code: 'plugin_webhook_store_unavailable', message: 'private qps database host' },
      }, 503))
      .mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()
    const failed = renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText(t('errors.loadFailed'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.storeUnavailable'))).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private qps database host')
    await user.click(screen.getByRole('button', { name: t('actions.retry') }))
    expect(await screen.findByText(t('empty.title'))).toBeInTheDocument()
    failed.unmount()

    setSession({ permissions: [] })
    fetchSpy.mockClear()
    const apiSpies = allPluginWebhookApiSpies()
    const localForbidden = renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText(t('forbidden.title'))).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('Unauthorized')
    expect(fetchSpy).not.toHaveBeenCalled()
    for (const apiSpy of apiSpies) expect(apiSpy).not.toHaveBeenCalled()
    localForbidden.unmount()
    for (const apiSpy of apiSpies) apiSpy.mockRestore()

    setSession()
    fetchSpy.mockReset().mockResolvedValue(json({
      error: { code: 'permission_denied', message: 'private qps policy path' },
    }, 403))
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText(t('forbidden.title'))).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/private qps policy path|Unauthorized/)
  })

  it.each(['success', 'error'] as const)(
    'keeps B list, detail, and deliveries isolated when delayed owner-A reads settle with %s',
    async (outcome) => {
      const tokenA = 'plugin-webhook-delayed-owner-a'
      const tokenB = 'plugin-webhook-current-owner-b'
      const sessionA = setSession({ accessToken: tokenA })
      const itemA: PluginWebhookSubscription = {
        ...item, event_types: ['io.cdnca.webhook.v1.test'], status: 'active',
        name: 'Old owner A subscription',
      }
      const itemB: PluginWebhookSubscription = {
        ...itemA, id: alternateSubscriptionID, tenant_scope_id: alternateScopeID,
        name: 'Current owner B subscription',
      }
      const deliveryA = {
        id: deliveryID, subscription_id: itemA.id, event_id: secretID,
        status: 'dead_lettered' as const, attempt_count: 5, created_at: '2026-07-29T08:00:00Z',
      }
      const deliveryB = {
        ...deliveryA, id: rotationID, subscription_id: itemB.id, status: 'delivered' as const,
      }
      const lateList = deferred<Awaited<ReturnType<typeof pluginWebhooksApi.listSubscriptions>>>()
      const lateDetail = deferred<Awaited<ReturnType<typeof pluginWebhooksApi.getSubscription>>>()
      const lateDeliveries = deferred<Awaited<ReturnType<typeof pluginWebhooksApi.listDeliveries>>>()
      let aListReads = 0
      let aDetailReads = 0
      let aDeliveryReads = 0
      vi.spyOn(pluginWebhooksApi, 'listSubscriptions').mockImplementation(async (token) => {
        if (token === tokenB) return { items: [itemB] }
        aListReads += 1
        return aListReads === 1 ? { items: [itemA] } : lateList.promise
      })
      vi.spyOn(pluginWebhooksApi, 'getSubscription').mockImplementation(async (token) => {
        if (token === tokenB) return itemB
        aDetailReads += 1
        return aDetailReads === 1 ? itemA : lateDetail.promise
      })
      vi.spyOn(pluginWebhooksApi, 'listDeliveries').mockImplementation(async (token) => {
        if (token === tokenB) return { items: [deliveryB] }
        aDeliveryReads += 1
        return aDeliveryReads === 1 ? { items: [deliveryA] } : lateDeliveries.promise
      })
      const user = userEvent.setup()
      const { container, queryClient } = renderPageWithQueryClient()

      await user.click(await screen.findByRole('button', { name: 'View' }))
      const drawerA = await screen.findByRole('dialog', { name: 'Old owner A subscription' })
      expect(await within(drawerA).findByText(deliveryID)).toBeInTheDocument()
      act(() => {
        void queryClient.invalidateQueries({
          queryKey: ['plugin-webhook-subscriptions', sessionA.ownerKey, scopeID],
        })
        void queryClient.invalidateQueries({
          queryKey: ['plugin-webhook-subscription', sessionA.ownerKey, scopeID, itemA.id],
        })
        void queryClient.invalidateQueries({
          queryKey: ['plugin-webhook-deliveries', sessionA.ownerKey, scopeID, itemA.id],
        })
      })
      await waitFor(() => {
        expect(aListReads).toBe(2)
        expect(aDetailReads).toBe(2)
        expect(aDeliveryReads).toBe(2)
      })

      let sessionB!: ReturnType<typeof setSession>
      act(() => {
        sessionB = setSession({
          accessToken: tokenB, userID: alternateUserID,
          tenantScopeID: alternateScopeID, tenantID: alternateTenantID,
        })
      })
      expect(await screen.findByText('Current owner B subscription')).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'View' }))
      const drawerB = await screen.findByRole('dialog', { name: 'Current owner B subscription' })
      expect(await within(drawerB).findByText(rotationID)).toBeInTheDocument()

      await act(async () => {
        const settlements = Promise.allSettled([
          lateList.promise, lateDetail.promise, lateDeliveries.promise,
        ])
        if (outcome === 'success') {
          lateList.resolve({ items: [itemA] })
          lateDetail.resolve(itemA)
          lateDeliveries.resolve({ items: [deliveryA] })
        } else {
          lateList.reject(new Error('private owner A list database'))
          lateDetail.reject(new Error('private owner A detail record'))
          lateDeliveries.reject(new Error('private owner A delivery queue'))
        }
        await settlements
      })

      expect(within(drawerB).getByText('Current owner B subscription')).toBeInTheDocument()
      expect(within(drawerB).getByText(rotationID)).toBeInTheDocument()
      expect(screen.queryByText('Old owner A subscription')).not.toBeInTheDocument()
      expect(screen.queryByText(deliveryID)).not.toBeInTheDocument()
      expect(container.querySelector('.plugin-webhook-loading')).not.toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(
        /private owner A (?:list database|detail record|delivery queue)/,
      )
      for (const message of [copy.errors.loadFailed, copy.errors.detailLoadFailed, copy.errors.deliveryLoadFailed]) {
        expect(screen.queryByText(message)).not.toBeInTheDocument()
      }
      const bKeys = [
        ['plugin-webhook-subscriptions', sessionB.ownerKey, alternateScopeID, undefined],
        ['plugin-webhook-subscription', sessionB.ownerKey, alternateScopeID, itemB.id],
        ['plugin-webhook-deliveries', sessionB.ownerKey, alternateScopeID, itemB.id, undefined],
      ]
      for (const key of bKeys) {
        const state = queryClient.getQueryState(key)
        expect(state).toMatchObject({ status: 'success', fetchStatus: 'idle', error: null })
        const serialized = JSON.stringify(state?.data ?? null)
        expect(serialized).not.toContain(itemA.name)
        expect(serialized).not.toContain(deliveryA.id)
      }
    },
  )

  it('keeps the en-US loading state accessible while the tenant list is pending', () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => undefined))
    const { container } = renderWithProviders(<PluginWebhooksPage />)
    const loadingState = container.querySelector<HTMLElement>('.plugin-webhook-loading')!
    expect(loadingState.querySelector('.ant-spin')).toBeInTheDocument()
    expect(within(loadingState).getByLabelText('Loading')).toBeInTheDocument()
    expect(within(loadingState).queryByLabelText('loading')).not.toBeInTheDocument()
  })

  it('removes the default Unauthorized title from both zh-CN forbidden states', async () => {
    await changeLocale('zh-CN')
    setSession({ permissions: [] })
    const localForbidden = renderWithProviders(<PluginWebhooksPage />)
    expect(screen.getByText('无权访问')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('Unauthorized')
    localForbidden.unmount()

    setSession()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: { code: 'permission_denied', params: {}, message: 'internal policy path' } }, 403))
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('Unauthorized')
  })

  it('uses zh-CN accessible names for both modal close buttons', async () => {
    await changeLocale('zh-CN')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') return json({ subscription: item, secret: createSecret }, 201)
      return json({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText('暂无 Webhook 订阅')).toBeInTheDocument()

    await user.click(screen.getAllByRole('button', { name: '新建订阅' })[0]!)
    let dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('button', { name: '关闭' })).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('名称'), '业务事件')
    await user.type(screen.getByLabelText('目标 URL'), 'https://hooks.example.com/cdnca')
    await user.click(screen.getAllByRole('button', { name: '新建订阅' }).at(-1)!)

    expect(await screen.findByText('请立即保存密钥')).toBeInTheDocument()
    dialog = screen.getByRole('dialog')
    expect(within(dialog).getAllByRole('button', { name: '关闭' })).toHaveLength(2)
    expect(within(dialog).queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
  })

  it('uses zh-CN accessible names for the drawer close button and detail loading state', async () => {
    await changeLocale('zh-CN')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith(`/${subscriptionID}`)) return new Promise(() => undefined)
      if (url.includes('/deliveries')) return json({ items: [] })
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click(await screen.findByRole('button', { name: '查看' }))

    const drawer = await screen.findByRole('dialog')
    const loadingState = drawer.querySelector<HTMLElement>('.plugin-webhook-loading')!
    expect(within(drawer).getByRole('button', { name: '关闭' })).toBeInTheDocument()
    expect(within(loadingState).getByLabelText('加载中')).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
    expect(within(loadingState).queryByLabelText('loading')).not.toBeInTheDocument()
  })

  it('renders empty state and opens the strict create form', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText('No subscriptions')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'Create subscription' })[0]!)
    expect(await screen.findByRole('dialog')).toHaveTextContent('The secret is shown once.')
    expect(screen.getByLabelText('Name')).toBeInTheDocument()
  })

  it('requires an installation binding for deployment status subscriptions', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') return json({
        subscription: {
          ...item, event_types: ['io.cdnca.deployment.v1.status_changed'],
          installation_authorization_id: installationAuthorizationID,
          installation_id: alternateInstallationID, plugin_id: 'acme.events',
        }, secret: createSecret,
      }, 201)
      return json({ items: [] })
    })
    const user = userEvent.setup()
    renderPageWithQueryClient()
    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    const eventSelector = screen.getByRole('combobox')
    await user.click(eventSelector)
    await user.click(screen.getAllByText('Test event').at(-1)!)
    await user.click(await screen.findByText('Deployment status changed'))
    expect(screen.getByLabelText('Installation authorization ID')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Name'), 'Deployment events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.click((screen.getAllByRole('button', { name: 'Create subscription' })).at(-1)!)
    expect(await screen.findByText('Business events require an installation authorization ID')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Installation authorization ID'), installationAuthorizationID)
    await user.click((screen.getAllByRole('button', { name: 'Create subscription' })).at(-1)!)
    await screen.findByText('Store the secret securely.')
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    const body = JSON.parse(String(post?.[1]?.body)) as Record<string, unknown>
    expect(body.event_types).toEqual(['io.cdnca.deployment.v1.status_changed'])
    expect(body.installation_authorization_id).toBe(installationAuthorizationID)
  })

  it('offers all six public domain events and subscribes to site updates with an installation binding', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') return json({
        subscription: {
          ...item, event_types: ['io.cdnca.deployment.v1.status_changed', 'io.cdnca.site.v1.updated'],
          installation_authorization_id: installationAuthorizationID,
          installation_id: alternateInstallationID, plugin_id: 'acme.events',
        }, secret: createSecret,
      }, 201)
      return json({ items: [] })
    })
    const user = userEvent.setup()
    renderPageWithQueryClient()
    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.click(screen.getByRole('combobox'))
    await user.click(screen.getAllByText('Test event').at(-1)!)
    for (const label of ['Certificate status changed', 'Node status changed', 'Usage threshold reached', 'Security incident detected']) {
      expect(await screen.findByText(label)).toBeInTheDocument()
    }
    await user.click(await screen.findByText('Site updated'))
    await user.click(await screen.findByText('Deployment status changed'))
    await user.type(screen.getByLabelText('Name'), 'Site events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.type(screen.getByLabelText('Installation authorization ID'), installationAuthorizationID)
    await user.type(screen.getByLabelText('Sites (optional)'), `${alternateScopeID}, ${alternateScopeID.toUpperCase()}`)
    await user.click((screen.getAllByRole('button', { name: 'Create subscription' })).at(-1)!)
    await screen.findByText('Store the secret securely.')
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    const body = JSON.parse(String(post?.[1]?.body)) as Record<string, unknown>
    expect(body.site_ids).toEqual([alternateScopeID])
    expect(body.event_types).toEqual(['io.cdnca.site.v1.updated', 'io.cdnca.deployment.v1.status_changed'])
    expect(body.installation_authorization_id).toBe(installationAuthorizationID)
  })

  it('creates a subscription and shows its one-time secret', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') return json({ subscription: item, secret: createSecret }, 201)
      return json({ items: [] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.type(screen.getByLabelText('Name'), 'Billing events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.click((screen.getAllByRole('button', { name: 'Create subscription' })).at(-1)!)
    expect(await screen.findByText('Store the secret securely.')).toBeInTheDocument()
    expect(screen.getByDisplayValue(createSecret)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Secret' })).toHaveValue(createSecret)
    expect(serializedMutationCache(queryClient)).not.toContain(createSecret)
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)
    await waitFor(() => expect(screen.queryByDisplayValue(createSecret)).not.toBeInTheDocument())
    expect(serializedMutationCache(queryClient)).not.toContain(createSecret)
    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(screen.queryByDisplayValue(createSecret)).not.toBeInTheDocument()
  })

  it('pages subscriptions forward and backward without rendering opaque cursors', async () => {
    const requests: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      requests.push(url)
      if (url.includes('cursor=subscription-page-2')) return json({ items: [{ ...item, name: 'Page two' }] })
      return json({ items: [item], next_cursor: 'subscription-page-2' })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    const pagination = await screen.findByLabelText('Subscriptions pagination')
    expect(within(pagination).getByText('Page 1')).toBeInTheDocument()
    expect(within(pagination).getByRole('button', { name: 'Previous' })).toBeDisabled()
    expect(within(pagination).getByRole('button', { name: 'Next' })).toBeEnabled()
    expect(screen.queryByText('subscription-page-2')).not.toBeInTheDocument()

    await user.click(within(pagination).getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('Page two')).toBeInTheDocument()
    expect(requests.some((url) => new URL(url, 'https://cdnca.test').searchParams.get('cursor') === 'subscription-page-2')).toBe(true)
    const nextPagination = await screen.findByLabelText('Subscriptions pagination')
    expect(within(nextPagination).getByText('Page 2')).toBeInTheDocument()
    expect(within(nextPagination).getByRole('button', { name: 'Next' })).toBeDisabled()
    expect(within(nextPagination).getByRole('button', { name: 'Previous' })).toBeEnabled()

    await user.click(within(nextPagination).getByRole('button', { name: 'Previous' }))
    await waitFor(async () => expect(within(await screen.findByLabelText('Subscriptions pagination')).getByText('Page 1')).toBeInTheDocument())
    expect(screen.getByText('Billing events')).toBeInTheDocument()
  })

  it('resets the subscription cursor before reading a different platform target', async () => {
    setSession({ kind: 'platform', permissions: ['platform.admin'] })
    const requests: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      requests.push(url)
      return json(url.includes('cursor=subscription-page-2') ? { items: [item] } : { items: [item], next_cursor: 'subscription-page-2' })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />, [`/sys/plugin-webhooks?target_scope_id=${targetScopeID}`])
    const pagination = await screen.findByLabelText('Subscriptions pagination')
    await user.click(within(pagination).getByRole('button', { name: 'Next' }))
    await waitFor(async () => expect(within(await screen.findByLabelText('Subscriptions pagination')).getByText('Page 2')).toBeInTheDocument())

    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), alternateScopeID)
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await waitFor(() => expect(requests.some((url) => url.includes(`/tenant-scopes/${alternateScopeID}/`) && !new URL(url, 'https://cdnca.test').searchParams.has('cursor'))).toBe(true))
    expect(within(await screen.findByLabelText('Subscriptions pagination')).getByText('Page 1')).toBeInTheDocument()
  })

  it('renders a localized forbidden state without server detail', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: { code: 'permission_denied', params: {}, message: 'internal policy path' } }, 403))
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText('Forbidden')).toBeInTheDocument()
    expect(screen.queryByText('internal policy path')).not.toBeInTheDocument()
  })

  it('renders a localized load error without the server message', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: { code: 'plugin_webhook_store_unavailable', params: {}, message: 'database address' } }, 503))
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText('Load failed')).toBeInTheDocument()
    expect(screen.getByText('Store unavailable')).toBeInTheDocument()
    expect(screen.queryByText('database address')).not.toBeInTheDocument()
  })

  it('shows subscription details and queues a test delivery', async () => {
    let queued = false
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        queued = true
        return json({ delivery: { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } }, 202)
      }
      if (String(_input).includes('/deliveries')) return json({ items: queued ? [{ id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' }] : [] })
      if (String(_input).endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(await screen.findByText('Deliveries')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Send test' }))
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining('/test-deliveries'), expect.anything()))
    expect(await screen.findByText('Pending')).toBeInTheDocument()
  })

  it('pages deliveries and resets the cursor when a different subscription is selected', async () => {
    const second = { ...item, id: alternateSubscriptionID, name: 'Audit events' }
    const deliveryRequests: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/deliveries')) {
        deliveryRequests.push(url)
        if (url.includes(`/${alternateSubscriptionID}/`)) return json({ items: [] })
        if (url.includes('cursor=delivery-page-2')) return json({ items: [] })
        return json({ items: [], next_cursor: 'delivery-page-2' })
      }
      if (url.endsWith(`/${alternateSubscriptionID}`)) return json(second)
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item, second] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click((await screen.findAllByRole('button', { name: 'View' }))[0]!)
    const pagination = await screen.findByLabelText('Deliveries pagination')
    expect(within(pagination).getByRole('button', { name: 'Previous' })).toBeDisabled()
    await user.click(within(pagination).getByRole('button', { name: 'Next' }))
    await waitFor(async () => expect(within(await screen.findByLabelText('Deliveries pagination')).getByText('Page 2')).toBeInTheDocument())
    expect(deliveryRequests.some((url) => new URL(url, 'https://cdnca.test').searchParams.get('cursor') === 'delivery-page-2')).toBe(true)

    await user.click(screen.getByRole('button', { name: 'Close' }))
    await user.click(screen.getAllByRole('button', { name: 'View' })[1]!)
    await waitFor(() => expect(deliveryRequests.some((url) => url.includes(`/${alternateSubscriptionID}/deliveries`) && !new URL(url, 'https://cdnca.test').searchParams.has('cursor'))).toBe(true))
    expect(within(await screen.findByLabelText('Deliveries pagination')).getByText('Page 1')).toBeInTheDocument()
  })

  it('keeps token-free owner state and exact retry across a same-epoch token refresh', async () => {
    const oldToken = 'plugin-webhook-old-access-token'
    const newToken = 'plugin-webhook-new-access-token'
    const newestToken = 'plugin-webhook-newest-access-token'
    const session = setSession({ accessToken: oldToken })
    const stableItem = { ...item, id: alternateSubscriptionID, name: 'Stable page two' }
    const deadLetter = {
      id: deliveryID, subscription_id: stableItem.id, event_id: secretID, status: 'dead_lettered',
      attempt_count: 5, created_at: '2026-07-29T08:00:00Z',
    }
    const reads: Array<{ url: string; authorization: string | null }> = []
    const testWrites: Array<{ key: string; authorization: string | null }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(String(input), 'https://cdnca.test')
      const authorization = new Headers(init?.headers).get('Authorization')
      if (init?.method === 'POST') {
        if (url.pathname.endsWith('/secret-rotations')) {
          return json({
            rotation_id: rotationID, key_id: rotationID, status: 'pending',
            expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2,
          }, 201)
        }
        if (url.pathname.endsWith('/test-deliveries')) {
          testWrites.push({
            key: new Headers(init.headers).get('Idempotency-Key') ?? '', authorization,
          })
          return testWrites.length === 1
            ? json({ error: { code: 'plugin_webhook_result_unknown', message: 'private write host' } }, 503)
            : json({ delivery: { ...deadLetter, status: 'pending', attempt_count: 0 } }, 202)
        }
      }
      reads.push({ url: url.toString(), authorization })
      if (url.pathname.endsWith('/deliveries')) {
        return json(url.searchParams.get('cursor') === 'delivery-page-2'
          ? { items: [] }
          : { items: [deadLetter], next_cursor: 'delivery-page-2' })
      }
      if (url.pathname.endsWith(`/${stableItem.id}`)) return json(stableItem)
      if (url.pathname.endsWith(`/${subscriptionID}`)) return json(item)
      return json(url.searchParams.get('cursor') === 'subscription-page-2'
        ? { items: [stableItem] }
        : { items: [item], next_cursor: 'subscription-page-2' })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()

    expect(await screen.findByText('Billing events')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'View' }))
    const initialDrawer = await screen.findByRole('dialog', { name: 'Billing events' })
    await user.click(within(initialDrawer).getByRole('button', { name: 'Rotate secret' }))
    const secretInput = await screen.findByRole('textbox', { name: 'Rotated secret' })
    expect(secretInput).toHaveValue(rotationSecret)

    const expectTokensAbsent = (tokens: string[]) => {
      const serializedCaches = JSON.stringify({
        queries: queryClient.getQueryCache().getAll().map((query) => ({ key: query.queryKey, state: query.state })),
        mutations: queryClient.getMutationCache().getAll().map((mutation) => mutation.state),
      })
      for (const token of tokens) {
        expect(serializedCaches).not.toContain(token)
        expect(document.body).not.toHaveTextContent(token)
        expect(serializedStorage(localStorage)).not.toContain(token)
        expect(serializedStorage(sessionStorage)).not.toContain(token)
      }
    }
    const readsBeforeRefresh = reads.length
    act(() => setSession({ accessToken: newToken, update: 'refresh' }))

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(reads).toHaveLength(readsBeforeRefresh)
    expect(within(initialDrawer).getByText('Billing events')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Subscriptions pagination')).getByText('Page 1')).toBeInTheDocument()
    expect(initialDrawer).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Rotated secret' })).toHaveValue(rotationSecret)
    expect(screen.getAllByRole('button', { name: 'Activate' }).length).toBeGreaterThan(0)
    expectTokensAbsent([oldToken, newToken])

    const secretModal = secretInput.closest('.ant-modal') as HTMLElement
    await user.click(within(secretModal).getAllByRole('button', { name: 'Close' }).at(-1)!)
    await user.click(within(initialDrawer).getByRole('button', { name: 'Close' }))
    await user.click(within(await screen.findByLabelText('Subscriptions pagination'))
      .getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('Stable page two')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'View' }))
    const stableDrawer = await screen.findByRole('dialog', { name: 'Stable page two' })
    await user.click(within(await screen.findByLabelText('Deliveries pagination'))
      .getByRole('button', { name: 'Next' }))
    expect(within(await screen.findByLabelText('Deliveries pagination')).getByText('Page 2')).toBeInTheDocument()
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toContainEqual([
      'plugin-webhook-subscriptions', session.ownerKey, scopeID, 'subscription-page-2',
    ])
    expect(queryKeys).toContainEqual([
      'plugin-webhook-subscription', session.ownerKey, scopeID, stableItem.id,
    ])
    expect(queryKeys).toContainEqual([
      'plugin-webhook-deliveries', session.ownerKey, scopeID, stableItem.id, 'delivery-page-2',
    ])
    const sendTest = within(stableDrawer).getByRole('button', { name: 'Send test' })
    await waitFor(() => expect(sendTest).toBeEnabled())
    await user.click(sendTest)
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByText('private write host')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry same request' })).toBeEnabled()
    expect(testWrites).toEqual([{
      key: expect.any(String), authorization: `Bearer ${newToken}`,
    }])

    const readsBeforeNewestRefresh = reads.length
    act(() => setSession({ accessToken: newestToken, update: 'refresh' }))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(reads).toHaveLength(readsBeforeNewestRefresh)
    expect(within(stableDrawer).getByText('Stable page two')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Subscriptions pagination')).getByText('Page 2')).toBeInTheDocument()
    expect(stableDrawer).toBeInTheDocument()
    expect(within(screen.getByLabelText('Deliveries pagination')).getByText('Page 2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry same request' })).toBeEnabled()
    expectTokensAbsent([oldToken, newToken, newestToken])

    await user.click(screen.getAllByRole('button', { name: 'Refresh' })[0]!)
    await waitFor(() => expect(reads.slice(readsBeforeNewestRefresh)
      .some(({ authorization }) => authorization === `Bearer ${newestToken}`)).toBe(true))
    await user.click(within(stableDrawer).getByRole('button', { name: 'Close' }))
    await user.click(await screen.findByRole('button', { name: 'View' }))
    await waitFor(() => expect(reads.slice(readsBeforeNewestRefresh).some(({ url, authorization }) =>
      url.endsWith(`/${stableItem.id}`) && authorization === `Bearer ${newestToken}`)).toBe(true))
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    await waitFor(() => expect(testWrites).toHaveLength(2))
    expect(testWrites[1]).toEqual({ key: testWrites[0]!.key, authorization: `Bearer ${newestToken}` })
  })

  it('requires an explicit valid target for platform reads and never uses the platform scope as tenant target', async () => {
    setSession({ kind: 'platform', permissions: ['plugin_webhooks.read'] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    expect(await screen.findByText('Select a target tenant scope before reading.')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('Target tenant scope'), 'not-a-uuid')
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    expect(await screen.findByText('Enter a valid tenant scope UUID.')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()

    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), targetScopeID)
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    expect(await screen.findByText('No subscriptions')).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain(`/tenant-scopes/${targetScopeID}/`)
    expect(String(fetchSpy.mock.calls[0]?.[0])).not.toContain(platformScopeID)
    expect(screen.queryByRole('button', { name: 'Create subscription' })).not.toBeInTheDocument()
  })

  it('retains a platform read-only target_scope_id and write-free controls across a URL reload', async () => {
    setSession({ kind: 'platform', permissions: ['plugin_webhooks.read'] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/deliveries')) return json({ items: [{ id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'dead_lettered', attempt_count: 5, created_at: '2026-07-29T08:00:00Z' }] })
      if (String(input).endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    const firstRender = renderWithProviders(<PluginWebhooksPage />, [`/sys/plugin-webhooks?target_scope_id=${targetScopeID}`])
    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(await screen.findByText('Deliveries')).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain(`/tenant-scopes/${targetScopeID}/`)
    for (const name of ['Create subscription', 'Test', 'Send test', 'Rotate secret', 'Replay', 'Revoke']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }

    firstRender.unmount()
    fetchSpy.mockClear()
    renderWithProviders(<PluginWebhooksPage />, [`/sys/plugin-webhooks?target_scope_id=${targetScopeID}`])
    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(await screen.findByText('Deliveries')).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain(`/tenant-scopes/${targetScopeID}/`)
    for (const name of ['Create subscription', 'Test', 'Send test', 'Rotate secret', 'Replay', 'Revoke']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
  })

  it('ignores an injected target_scope_id for tenant reads', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    renderWithProviders(<PluginWebhooksPage />, [`/sys/plugin-webhooks?target_scope_id=${alternateScopeID}`])

    expect(await screen.findByText('No subscriptions')).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain(`/tenant-scopes/${scopeID}/`)
    expect(String(fetchSpy.mock.calls[0]?.[0])).not.toContain(alternateScopeID)
    expect(screen.queryByLabelText('Target tenant scope')).not.toBeInTheDocument()
  })

  it('keeps tenant viewers read-only across list and detail controls', async () => {
    setSession({ permissions: ['plugin_webhooks.read'] })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/deliveries')) return json({ items: [{ id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'dead_lettered', attempt_count: 5, created_at: '2026-07-29T08:00:00Z' }] })
      if (String(input).endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(await screen.findByText('Deliveries')).toBeInTheDocument()
    for (const name of ['Create subscription', 'Test', 'Send test', 'Rotate secret', 'Replay', 'Revoke']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
  })

  it('shows no write success and hides controls after live manage permission revocation', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') return json({ error: { code: 'permission_denied', params: {}, message: 'policy detail' } }, 403)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    await user.click(await screen.findByRole('button', { name: 'Test' }))
    expect(await screen.findByText('Permission denied')).toBeInTheDocument()
    expect(screen.queryByText('Test queued')).not.toBeInTheDocument()
    expect(screen.queryByText('policy detail')).not.toBeInTheDocument()

    act(() => setSession({ permissions: ['plugin_webhooks.read'], update: 'refresh' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Create subscription' })).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Test' })).not.toBeInTheDocument()
  })

  it('renders forbidden immediately after live read permission revocation', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [item] }))
    renderWithProviders(<PluginWebhooksPage />)
    expect(await screen.findByText('Billing events')).toBeInTheDocument()

    act(() => setSession({ permissions: [], update: 'refresh' }))
    expect(await screen.findByText('Forbidden')).toBeInTheDocument()
    expect(screen.queryByText('Billing events')).not.toBeInTheDocument()
  })

  it('clears all A-owned UI and write state when the authenticated tenant scope changes to B', async () => {
    const aItem = { ...item, name: 'Scope A subscription' }
    const bItem = { ...item, tenant_scope_id: alternateScopeID, name: 'Scope B subscription' }
    let resolveBList: ((response: Response) => void) | undefined
    const posts: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        posts.push(url)
        if (url.endsWith('/secret-rotations')) return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
        if (url.includes(`/tenant-scopes/${scopeID}/`)) return json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'scope A unknown' } }, 503)
        return json({ delivery: { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } }, 202)
      }
      if (url.includes(`/tenant-scopes/${alternateScopeID}/`) && /plugin-webhook-subscriptions(?:\?|$)/.test(url)) {
        return new Promise<Response>((resolve) => { resolveBList = resolve })
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(url.includes(alternateScopeID) ? bItem : aItem)
      return json({ items: [url.includes(alternateScopeID) ? bItem : aItem] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    expect(await screen.findByRole('textbox', { name: 'Rotated secret' })).toHaveValue(rotationSecret)
    fireEvent.click(screen.getByRole('button', { name: 'Send test' }))
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()

    act(() => setSession({ tenantScopeID: alternateScopeID }))
    expect(screen.queryByText('Scope A subscription')).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Rotated secret' })).not.toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()

    act(() => resolveBList?.(json({ items: [bItem] })))
    expect(await screen.findByText('Scope B subscription')).toBeInTheDocument()
    const bTest = await screen.findByRole('button', { name: 'Test' })
    expect(bTest).toBeEnabled()
    await user.click(bTest)
    await waitFor(() => expect(posts.some((url) => url.includes(`/tenant-scopes/${alternateScopeID}/`) && url.endsWith('/test-deliveries'))).toBe(true))

    act(() => setSession())
    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
  })

  it('rechecks live manage permission for stale direct action and validated create dispatches', async () => {
    const posts: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') posts.push(String(input))
      return json(init?.method === 'POST' ? { delivery: { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } } : { items: [item] }, init?.method === 'POST' ? 202 : 200)
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    const staleTest = await screen.findByRole('button', { name: 'Test' })
    act(() => {
      setSession({ permissions: ['plugin_webhooks.read'], update: 'refresh' })
      staleTest.click()
    })
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Test' })).not.toBeInTheDocument())
    expect(posts).toHaveLength(0)

    act(() => setSession())
    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.type(screen.getByLabelText('Name'), 'Billing events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    const staleSubmit = screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!
    act(() => {
      setSession({ permissions: ['plugin_webhooks.read'], update: 'refresh' })
      staleSubmit.click()
    })
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Create subscription' })).not.toBeInTheDocument())
    await act(async () => { await Promise.resolve() })
    expect(posts).toHaveLength(0)
  })

  it.each(['action', 'create', 'retry', 'activate'] as const)('rejects a stale A %s callback during a synchronous manage-capable owner transition', async (entry) => {
    const bItem = { ...item, tenant_scope_id: alternateScopeID, name: 'Scope B subscription' }
    const posts: Array<{ url: string; authorization: string }> = []
    let postCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        postCount += 1
        posts.push({ url, authorization: (init.headers as Record<string, string>).Authorization })
        if (entry === 'retry' && postCount === 1) {
          return json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'scope A unknown' } }, 503)
        }
        if (entry === 'activate' && url.endsWith('/secret-rotations')) {
          return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
        }
        return json({ delivery: { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } }, 202)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [url.includes(alternateScopeID) ? bItem : item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    let staleControl: HTMLElement
    let activationSecret: HTMLElement | null = null

    if (entry === 'create') {
      await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
      await user.type(screen.getByLabelText('Name'), 'Scope A events')
      await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
      staleControl = screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!
    } else if (entry === 'activate') {
      await user.click(await screen.findByRole('button', { name: 'View' }))
      await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
      activationSecret = await screen.findByRole('textbox', { name: 'Rotated secret' })
      const secretModal = activationSecret.closest('.ant-modal')
      expect(secretModal).not.toBeNull()
      staleControl = within(secretModal as HTMLElement).getByRole('button', { name: 'Activate' })
      await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0))
      posts.length = 0
    } else {
      const testButton = await screen.findByRole('button', { name: 'Test' })
      if (entry === 'retry') {
        await user.click(testButton)
        staleControl = await screen.findByRole('button', { name: 'Retry same request' })
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0))
        posts.length = 0
      } else {
        staleControl = testButton
      }
    }
    const mutationEvents: string[] = []
    const unsubscribe = queryClient.getMutationCache().subscribe((event) => {
      if (event.type === 'added' || event.type === 'updated') mutationEvents.push(event.type)
    })

    act(() => {
      setSession({ accessToken: alternateAccessToken, userID: alternateUserID, tenantScopeID: alternateScopeID, tenantID: alternateTenantID })
      staleControl.click()
      if (entry !== 'create') setSession()
    })
    await act(async () => { await Promise.resolve() })
    if (entry === 'create') act(() => setSession())

    expect(posts).toHaveLength(0)
    expect(mutationEvents).toEqual([])
    if (activationSecret) expect(activationSecret).not.toBeInTheDocument()
    unsubscribe()
  })

  it.each(['create', 'rotate', 'activate', 'revoke', 'test', 'replay'] as const)('reconciles exact queries without POST when closing an unknown %s', async (operation) => {
    const deadLetter = { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'dead_lettered', attempt_count: 5, created_at: '2026-07-29T08:00:00Z' }
    const calls: Array<{ url: string; method: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      calls.push({ url, method })
      if (method === 'POST') {
        if (operation === 'activate' && url.endsWith('/secret-rotations')) {
          return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
        }
        return json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'unknown detail' } }, 503)
      }
      if (url.includes('/deliveries')) return json({ items: [deadLetter] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    if (operation === 'create') {
      await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
      await user.type(screen.getByLabelText('Name'), 'Billing events')
      await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
      await user.click(screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!)
    } else if (operation === 'rotate') {
      await user.click(await screen.findByRole('button', { name: 'View' }))
      await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    } else if (operation === 'activate') {
      await user.click(await screen.findByRole('button', { name: 'View' }))
      await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
      const secret = await screen.findByRole('textbox', { name: 'Rotated secret' })
      await user.click(within(secret.closest('.ant-modal') as HTMLElement).getAllByRole('button', { name: 'Close' }).at(-1)!)
      await user.click(await screen.findByRole('button', { name: 'Activate' }))
    } else if (operation === 'revoke') {
      await user.click(await screen.findByRole('button', { name: 'View' }))
      await user.click(screen.getByRole('button', { name: 'Revoke' }))
      await user.click((await screen.findAllByRole('button', { name: 'Revoke' })).at(-1)!)
    } else {
      await user.click(await screen.findByRole('button', { name: 'View' }))
      if (operation === 'test') await user.click(await screen.findByRole('button', { name: 'Send test' }))
      else await user.click(await screen.findByRole('button', { name: 'Replay' }))
    }
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()

    const before = {
      list: calls.filter(({ url, method }) => method === 'GET' && /plugin-webhook-subscriptions(?:\?|$)/.test(url)).length,
      detail: calls.filter(({ url, method }) => method === 'GET' && url.endsWith(`/${subscriptionID}`)).length,
      deliveries: calls.filter(({ url, method }) => method === 'GET' && url.includes(`/${subscriptionID}/deliveries`)).length,
      posts: calls.filter(({ method }) => method === 'POST').length,
    }
    act(() => setSession({ permissions: ['plugin_webhooks.read'], update: 'refresh' }))
    await user.click(screen.getByRole('button', { name: 'Close and refresh' }))

    await waitFor(() => expect(calls.filter(({ url, method }) => method === 'GET' && /plugin-webhook-subscriptions(?:\?|$)/.test(url)).length).toBe(before.list + 1))
    if (operation === 'rotate' || operation === 'activate' || operation === 'revoke') {
      await waitFor(() => expect(calls.filter(({ url, method }) => method === 'GET' && url.endsWith(`/${subscriptionID}`)).length).toBe(before.detail + 1))
      expect(calls.filter(({ url, method }) => method === 'GET' && url.includes(`/${subscriptionID}/deliveries`))).toHaveLength(before.deliveries)
    }
    if (operation === 'test' || operation === 'replay') {
      await waitFor(() => expect(calls.filter(({ url, method }) => method === 'GET' && url.includes(`/${subscriptionID}/deliveries`)).length).toBe(before.deliveries + 1))
      expect(calls.filter(({ url, method }) => method === 'GET' && url.endsWith(`/${subscriptionID}`))).toHaveLength(before.detail)
    }
    expect(calls.filter(({ method }) => method === 'POST')).toHaveLength(before.posts)
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /secret/i })).not.toBeInTheDocument()
    if (operation === 'activate') {
      act(() => setSession({ update: 'refresh' }))
      expect(await screen.findByRole('button', { name: 'Rotate secret' })).toBeEnabled()
      expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    }
  })

  it('retries a 408 rotation with the exact request identity and the current refreshed token', async () => {
    const oldToken = 'plugin-webhook-timeout-old-token'
    const newToken = 'plugin-webhook-timeout-new-token'
    const session = setSession({ accessToken: oldToken })
    const rotations: Array<{ authorization: string | null; idempotencyKey: string | null; revision: string | null; body: BodyInit | null | undefined }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/secret-rotations')) {
        const headers = new Headers(init.headers)
        rotations.push({
          authorization: headers.get('Authorization'),
          idempotencyKey: headers.get('Idempotency-Key'),
          revision: headers.get('If-Match'),
          body: init.body,
        })
        if (rotations.length === 1) return json({ error: { code: 'request_timeout', message: 'private upstream timeout' } }, 408)
        return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByText('private upstream timeout')).not.toBeInTheDocument()

    act(() => setSession({ accessToken: newToken, update: 'refresh' }))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    expect(await screen.findByRole('textbox', { name: 'Rotated secret' })).toHaveValue(rotationSecret)
    expect(rotations).toEqual([
      { authorization: `Bearer ${oldToken}`, idempotencyKey: expect.any(String), revision: '"1"', body: '{}' },
      { authorization: `Bearer ${newToken}`, idempotencyKey: rotations[0]!.idempotencyKey, revision: '"1"', body: '{}' },
    ])
  })

  it('treats an explicit rate-limit error as terminal even when transported with a 5xx status', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        return json({ error: { code: 'plugin_webhook_rate_limited', message: 'private limiter detail' } }, 503)
      }
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    await user.click(await screen.findByRole('button', { name: 'Test' }))
    expect(await screen.findByText('Rate limited')).toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(screen.queryByText('private limiter detail')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Test' })).toBeEnabled()
  })

  it('waits for an exact detail response before enabling lifecycle writes and uses its revision', async () => {
    let resolveDetail: ((response: Response) => void) | undefined
    const posts: Array<[string, RequestInit | undefined]> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        posts.push([url, init])
        return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 8 }, 201)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return new Promise<Response>((resolve) => { resolveDetail = resolve })
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await waitFor(() => expect(resolveDetail).toBeTypeOf('function'))
    for (const name of ['Rotate secret', 'Activate', 'Revoke']) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    expect(posts).toHaveLength(0)

    act(() => resolveDetail?.(json({ ...item, revision: 7 })))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect((posts[0]?.[1]?.headers as Record<string, string>)['If-Match']).toBe('"7"')
  })

  it('keeps lifecycle writes unavailable when exact detail loading fails', async () => {
    const posts: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        posts.push(url)
        return json({}, 500)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json({ error: { code: 'plugin_webhook_store_unavailable', params: {}, message: 'detail unavailable' } }, 503)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)

    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(await screen.findByText('Detail load failed')).toBeInTheDocument()
    for (const name of ['Rotate secret', 'Activate', 'Revoke']) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    expect(posts).toHaveLength(0)
    expect(screen.queryByText('detail unavailable')).not.toBeInTheDocument()
  })

  it('closes the one-time secret and later activates the retained rotation from the drawer', async () => {
    const calls: Array<[string, RequestInit | undefined]> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push([String(input), init])
      if (init?.method === 'POST' && String(input).endsWith('/secret-rotations')) return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
      if (init?.method === 'POST' && String(input).endsWith(`/${rotationID}/activate`)) return json({ subscription: { ...item, revision: 3 } })
      if (String(input).includes('/deliveries')) return json({ items: [] })
      if (String(input).endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    expect(await screen.findByDisplayValue(rotationSecret)).toBeInTheDocument()
    expect(serializedMutationCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedQueryCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedStorage(localStorage)).not.toContain(rotationSecret)
    expect(serializedStorage(sessionStorage)).not.toContain(rotationSecret)

    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)
    await waitFor(() => expect(screen.queryByDisplayValue(rotationSecret)).not.toBeInTheDocument())
    expect(serializedMutationCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedQueryCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedMutationCache(queryClient)).not.toContain(rotationID)
    expect(serializedQueryCache(queryClient)).not.toContain(rotationID)
    expect(serializedStorage(localStorage)).not.toContain(rotationID)
    expect(serializedStorage(sessionStorage)).not.toContain(rotationID)

    await user.click(screen.getByRole('button', { name: 'Activate' }))
    await waitFor(() => expect(calls.some(([url]) => url.endsWith(`/${rotationID}/activate`))).toBe(true))
    expect(screen.queryByText('Store the secret securely.')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    const lifecycleCalls = calls.filter(([, init]) => init?.method === 'POST')
    expect((lifecycleCalls[0]?.[1]?.headers as Record<string, string>)['If-Match']).toBe('"1"')
    expect((lifecycleCalls[1]?.[1]?.headers as Record<string, string>)['If-Match']).toBe('"2"')
  })

  it('keeps a pending rotation isolated by platform target and restores it after switching back', async () => {
    setSession({ kind: 'platform', permissions: ['platform.admin'] })
    const calls: Array<[string, RequestInit | undefined]> = []
    let resolveRotation: ((response: Response) => void) | undefined
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      calls.push([url, init])
      if (init?.method === 'POST' && url.includes(`/tenant-scopes/${targetScopeID}/`) && url.endsWith('/secret-rotations')) {
        return new Promise<Response>((resolve) => { resolveRotation = resolve })
      }
      if (init?.method === 'POST' && url.includes(`/tenant-scopes/${targetScopeID}/`) && url.endsWith(`/${rotationID}/activate`)) {
        return json({ subscription: { ...item, tenant_scope_id: targetScopeID, revision: 3 } })
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json({ ...item, tenant_scope_id: url.includes(targetScopeID) ? targetScopeID : alternateScopeID })
      return json({ items: [{ ...item, tenant_scope_id: url.includes(targetScopeID) ? targetScopeID : alternateScopeID }] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />, [`/sys/plugin-webhooks?target_scope_id=${targetScopeID}`])

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    await waitFor(() => expect(resolveRotation).toBeTypeOf('function'))
    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), alternateScopeID)
    expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await user.keyboard('{Enter}')
    expect(calls.some(([url]) => url.includes(`/tenant-scopes/${alternateScopeID}/`))).toBe(false)

    act(() => resolveRotation?.(json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)))
    expect(await screen.findByRole('textbox', { name: 'Rotated secret' })).toHaveValue(rotationSecret)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)

    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply target' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await user.click((await screen.findAllByRole('button', { name: 'View' }))[0]!)
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Rotated secret' })).not.toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(calls.some(([url]) => url.includes(`/tenant-scopes/${alternateScopeID}/`) && url.includes(rotationID))).toBe(false)

    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), 'not-a-uuid')
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    expect(await screen.findByText('Enter a valid tenant scope UUID.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()

    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), targetScopeID)
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await user.click((await screen.findAllByRole('button', { name: 'View' }))[0]!)
    await user.click(await screen.findByRole('button', { name: 'Activate' }))

    await waitFor(() => expect(calls.some(([url]) => url.includes(`/tenant-scopes/${targetScopeID}/`) && url.endsWith(`/${rotationID}/activate`))).toBe(true))
    const activation = calls.find(([url]) => url.endsWith(`/${rotationID}/activate`))
    expect((activation?.[1]?.headers as Record<string, string>)['If-Match']).toBe('"2"')
  })

  it('binds a deferred rotation receipt and activation to the exact selected subscription', async () => {
    const alternateItem = { ...item, id: alternateSubscriptionID, name: 'Audit events' }
    const posts: string[] = []
    let resolveRotation: ((response: Response) => void) | undefined
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        posts.push(url)
        if (url.endsWith(`/${subscriptionID}/secret-rotations`)) {
          return new Promise<Response>((resolve) => { resolveRotation = resolve })
        }
        if (url.endsWith(`/${subscriptionID}/secret-rotations/${rotationID}/activate`)) {
          return json({ subscription: { ...item, revision: 3, active_secret_version_id: rotationID } })
        }
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      if (url.endsWith(`/${alternateSubscriptionID}`)) return json(alternateItem)
      return json({ items: [item, alternateItem] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()

    await user.click((await screen.findAllByRole('button', { name: 'View' }))[0]!)
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    await waitFor(() => expect(resolveRotation).toBeTypeOf('function'))
    await user.click((await screen.findAllByRole('button', { name: 'View' }))[1]!)

    act(() => resolveRotation?.(json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)))
    await waitFor(() => expect(mutationsForKind(queryClient, 'rotate')).toHaveLength(0))
    expect(screen.queryByRole('textbox', { name: 'Rotated secret' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    expect(posts.some((url) => url.includes(`/${alternateSubscriptionID}/`) && url.includes(rotationID))).toBe(false)

    await user.click((await screen.findAllByRole('button', { name: 'View' }))[0]!)
    const secretInput = await screen.findByRole('textbox', { name: 'Rotated secret' })
    expect(secretInput).toHaveValue(rotationSecret)
    const secretModal = secretInput.closest('.ant-modal')
    expect(secretModal).not.toBeNull()
    await user.click(within(secretModal as HTMLElement).getByRole('button', { name: 'Activate' }))

    await waitFor(() => expect(posts.some((url) => url.endsWith(`/${subscriptionID}/secret-rotations/${rotationID}/activate`))).toBe(true))
    expect(posts.some((url) => url.includes(`/${alternateSubscriptionID}/`) && url.includes(rotationID))).toBe(false)
  })

  it('gates and retries all six unknown platform writes with their original scope and key across live RBAC changes', async () => {
    setSession({ kind: 'platform', permissions: ['platform.admin'] })
    const attempts = new Map<string, Array<{ url: string; key: string }>>()
    const deadLetter = { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'dead_lettered', attempt_count: 5, created_at: '2026-07-29T08:00:00Z' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        const operation = url.endsWith('/test-deliveries') ? 'test'
          : url.endsWith('/secret-rotations') ? 'rotate'
            : url.endsWith('/activate') ? 'activate'
            : url.endsWith('/replays') ? 'replay' : 'create'
        const resolvedOperation = url.endsWith('/revoke') ? 'revoke' : operation
        const calls = attempts.get(resolvedOperation) ?? []
        calls.push({ url, key: (init.headers as Record<string, string>)['Idempotency-Key'] })
        attempts.set(resolvedOperation, calls)
        if (calls.length === 1) return json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: `${resolvedOperation} detail` } }, 503)
        if (resolvedOperation === 'create') return json({ subscription: { ...item, tenant_scope_id: targetScopeID }, secret: createSecret }, 201)
        if (resolvedOperation === 'rotate') return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
        if (resolvedOperation === 'activate') return json({ subscription: { ...item, tenant_scope_id: targetScopeID, revision: 3 } })
        if (resolvedOperation === 'replay') return json({ delivery: { ...deadLetter, id: rotationID, replay_of: deliveryID, status: 'pending', attempt_count: 0 } }, 202)
        if (resolvedOperation === 'revoke') return json({ subscription: { ...item, tenant_scope_id: targetScopeID, status: 'revoked', revision: 2 } })
        return json({ delivery: { ...deadLetter, status: 'pending', attempt_count: 0 } }, 202)
      }
      if (url.includes('/deliveries')) return json({ items: [deadLetter] })
      if (url.endsWith(`/${subscriptionID}`)) return json({ ...item, tenant_scope_id: url.includes(alternateScopeID) ? alternateScopeID : targetScopeID })
      return json({ items: [{ ...item, tenant_scope_id: url.includes(alternateScopeID) ? alternateScopeID : targetScopeID }] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient([`/sys/plugin-webhooks?target_scope_id=${targetScopeID}`])
    const retryAfterPermissionRoundTrip = async (operation: string) => {
      expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
      const calls = attempts.get(operation)!
      expect(calls).toHaveLength(1)
      const staleRetry = screen.getByRole('button', { name: 'Retry same request' })
      act(() => {
        setSession({ kind: 'platform', permissions: ['plugin_webhooks.read'], update: 'refresh' })
        staleRetry.click()
      })
      await waitFor(() => expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument())
      expect(screen.getByRole('button', { name: 'Close and refresh' })).toBeInTheDocument()
      expect(calls).toHaveLength(1)
      if (operation === 'activate' || operation === 'revoke') expect(mutationsForKind(queryClient, operation)).toHaveLength(0)

      act(() => setSession({ kind: 'platform', permissions: ['platform.admin'], update: 'refresh' }))
      await user.click(await screen.findByRole('button', { name: 'Retry same request' }))
      await waitFor(() => expect(calls).toHaveLength(2))
      expect(calls[0]!.key).toBe(calls[1]!.key)
      expect(calls.every(({ url }) => url.includes(`/tenant-scopes/${targetScopeID}/`))).toBe(true)
      await waitFor(() => expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument())
    }

    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.type(screen.getByLabelText('Name'), 'Billing events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.click(screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!)
    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), alternateScopeID)
    expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
    await retryAfterPermissionRoundTrip('create')
    expect(await screen.findByRole('textbox', { name: 'Secret' })).toHaveValue(createSecret)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)

    await user.click(await screen.findByRole('button', { name: 'Test' }))
    expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
    await retryAfterPermissionRoundTrip('test')

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
    await retryAfterPermissionRoundTrip('rotate')
    expect(await screen.findByRole('textbox', { name: 'Rotated secret' })).toHaveValue(rotationSecret)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)

    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    await retryAfterPermissionRoundTrip('activate')

    await user.click(await screen.findByRole('button', { name: 'Replay' }))
    expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
    await retryAfterPermissionRoundTrip('replay')

    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    await user.click((await screen.findAllByRole('button', { name: 'Revoke' })).at(-1)!)
    await retryAfterPermissionRoundTrip('revoke')

    for (const operation of ['create', 'test', 'rotate', 'activate', 'replay', 'revoke']) {
      const calls = attempts.get(operation)!
      expect(calls).toHaveLength(2)
      expect(calls[0]!.key).toBe(calls[1]!.key)
      expect(calls.every(({ url }) => url.includes(`/tenant-scopes/${targetScopeID}/`))).toBe(true)
    }

    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply target' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await user.click((await screen.findAllByRole('button', { name: 'View' }))[0]!)
    expect(screen.queryByRole('textbox', { name: /secret/i })).not.toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
  })

  it.each([
    ['success', () => json({ subscription: item, secret: createSecret }, 201)],
    ['error', () => json({ error: { code: 'revision_conflict', params: {}, message: 'scope A error' } }, 412)],
    ['unknown', () => json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'scope A unknown' } }, 503)],
  ])('keeps B writable and isolated when a deferred A create resolves with %s', async (_outcome, response) => {
    const bSecret = rotationSecret
    const bItem = { ...item, tenant_scope_id: alternateScopeID, name: 'Scope B subscription' }
    let resolveACreate: ((value: Response) => void) | undefined
    const posts: Array<{ url: string; authorization: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        posts.push({ url, authorization: (init.headers as Record<string, string>).Authorization })
        if (url.includes(`/tenant-scopes/${scopeID}/`)) return new Promise<Response>((resolve) => { resolveACreate = resolve })
        return json({ subscription: bItem, secret: bSecret }, 201)
      }
      return json({ items: [url.includes(alternateScopeID) ? bItem : item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()

    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.type(screen.getByLabelText('Name'), 'Scope A events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.click(screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!)
    await waitFor(() => expect(resolveACreate).toBeTypeOf('function'))
    const aMutation = mutationsForKind(queryClient, 'create')[0]!
    expect(aMutation.state).toMatchObject({ status: 'pending', variables: { kind: 'create', scopeID } })
    const aTerminal = observeMutationTerminal(queryClient, aMutation)

    act(() => setSession({ accessToken: alternateAccessToken, userID: alternateUserID, tenantScopeID: alternateScopeID, tenantID: alternateTenantID }))
    expect(await screen.findByText('Scope B subscription')).toBeInTheDocument()
    const bCreate = (await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!
    expect(bCreate).toBeEnabled()
    await user.click(bCreate)
    await user.type(screen.getByLabelText('Name'), 'Scope B events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/scope-b')
    await user.click(screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!)
    expect(await screen.findByRole('textbox', { name: 'Secret' })).toHaveValue(bSecret)
    expect(posts.filter(({ url, authorization }) => url.includes(`/tenant-scopes/${alternateScopeID}/`) && authorization === `Bearer ${alternateAccessToken}`)).toHaveLength(1)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)

    let terminalStatus: Extract<MutationStatus, 'success' | 'error'> | undefined
    await act(async () => {
      resolveACreate?.(response())
      terminalStatus = await aTerminal.terminal
    })
    aTerminal.unsubscribe()
    expect(terminalStatus).toBe(_outcome === 'success' ? 'success' : 'error')

    expect(screen.getByText('Scope B subscription')).toBeInTheDocument()
    expect((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]).toBeEnabled()
    expect(screen.queryByRole('textbox', { name: 'Secret' })).not.toBeInTheDocument()
    expect(screen.queryByText('Revision conflict')).not.toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(screen.queryByText('scope A error')).not.toBeInTheDocument()
    expect(screen.queryByText('scope A unknown')).not.toBeInTheDocument()
  })

  it.each([
    ['success', () => json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)],
    ['error', () => json({ error: { code: 'revision_conflict', params: {}, message: 'scope A action error' } }, 412)],
    ['unknown', () => json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'scope A action unknown' } }, 503)],
  ])('keeps B writable and isolated when a deferred A action resolves with %s', async (_outcome, response) => {
    const bItem = { ...item, tenant_scope_id: alternateScopeID, name: 'Scope B subscription' }
    let resolveARotation: ((value: Response) => void) | undefined
    const posts: Array<{ url: string; authorization: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        posts.push({ url, authorization: (init.headers as Record<string, string>).Authorization })
        if (url.includes(`/tenant-scopes/${scopeID}/`) && url.endsWith('/secret-rotations')) {
          return new Promise<Response>((resolve) => { resolveARotation = resolve })
        }
        return json({ delivery: { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } }, 202)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(url.includes(alternateScopeID) ? bItem : item)
      return json({ items: [url.includes(alternateScopeID) ? bItem : item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    await waitFor(() => expect(resolveARotation).toBeTypeOf('function'))
    const aMutation = mutationsForKind(queryClient, 'rotate')[0]!
    expect(aMutation.state).toMatchObject({ status: 'pending', variables: { kind: 'rotate', scopeID, subscriptionID } })
    const aTerminal = observeMutationTerminal(queryClient, aMutation)

    act(() => setSession({ accessToken: alternateAccessToken, userID: alternateUserID, tenantScopeID: alternateScopeID, tenantID: alternateTenantID }))
    expect(await screen.findByText('Scope B subscription')).toBeInTheDocument()
    const bTest = await screen.findByRole('button', { name: 'Test' })
    expect(bTest).toBeEnabled()
    await user.click(bTest)
    await waitFor(() => expect(posts.some(({ url, authorization }) => url.includes(`/tenant-scopes/${alternateScopeID}/`) && url.endsWith('/test-deliveries') && authorization === `Bearer ${alternateAccessToken}`)).toBe(true))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Test' })).toBeEnabled())

    let terminalStatus: Extract<MutationStatus, 'success' | 'error'> | undefined
    await act(async () => {
      resolveARotation?.(response())
      terminalStatus = await aTerminal.terminal
    })
    aTerminal.unsubscribe()
    expect(terminalStatus).toBe(_outcome === 'success' ? 'success' : 'error')

    expect(screen.getByText('Scope B subscription')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Test' })).toBeEnabled()
    expect(screen.queryByRole('textbox', { name: 'Rotated secret' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    expect(screen.queryByText('Revision conflict')).not.toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(screen.queryByText('scope A action error')).not.toBeInTheDocument()
    expect(screen.queryByText('scope A action unknown')).not.toBeInTheDocument()
  })

  it.each([
    ['error', () => json({ error: { code: 'revision_conflict', params: {}, message: 'scope A error' } }, 412)],
    ['unknown', () => json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'scope A unknown' } }, 503)],
  ])('keeps B unapplied during a deferred A %s and hides the A state after B is applied', async (outcome, response) => {
    setSession({ kind: 'platform', permissions: ['platform.admin'] })
    let resolveTest: ((value: Response) => void) | undefined
    const calls: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      calls.push(url)
      if (init?.method === 'POST') return new Promise<Response>((resolve) => { resolveTest = resolve })
      return json({ items: [{ ...item, tenant_scope_id: url.includes(alternateScopeID) ? alternateScopeID : targetScopeID }] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />, [`/sys/plugin-webhooks?target_scope_id=${targetScopeID}`])

    await user.click(await screen.findByRole('button', { name: 'Test' }))
    await waitFor(() => expect(resolveTest).toBeTypeOf('function'))
    await user.clear(screen.getByLabelText('Target tenant scope'))
    await user.type(screen.getByLabelText('Target tenant scope'), alternateScopeID)
    expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await user.keyboard('{Enter}')
    expect(calls.some((url) => url.includes(`/tenant-scopes/${alternateScopeID}/`))).toBe(false)

    act(() => resolveTest?.(response()))
    if (outcome === 'unknown') {
      expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Apply target' })).toBeDisabled()
      await user.click(screen.getByRole('button', { name: 'Close and refresh' }))
    } else {
      expect(await screen.findByText('Revision conflict')).toBeInTheDocument()
    }
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply target' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: 'Apply target' }))
    await waitFor(() => expect(calls.some((url) => url.includes(`/tenant-scopes/${alternateScopeID}/`))).toBe(true))
    expect(screen.queryByText('Revision conflict')).not.toBeInTheDocument()
    expect(screen.queryByText('Unknown outcome')).not.toBeInTheDocument()
    expect(screen.queryByText('scope A error')).not.toBeInTheDocument()
    expect(screen.queryByText('scope A unknown')).not.toBeInTheDocument()
  })

  it('keeps variables and returned data sensitive-free for all six write mutations', async () => {
    let resolveWrite: ((response: Response) => void) | undefined
    const deadLetter = { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'dead_lettered', attempt_count: 5, created_at: '2026-07-29T08:00:00Z' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') return new Promise<Response>((resolve) => { resolveWrite = resolve })
      if (url.includes('/deliveries')) return json({ items: [deadLetter] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    const finishWrite = async (response: Response) => {
      act(() => resolveWrite?.(response))
      resolveWrite = undefined
      await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0))
    }

    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.type(screen.getByLabelText('Name'), 'Billing events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.click(screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!)
    await waitFor(() => expectPendingMutation(queryClient, { kind: 'create', scopeID, key: expect.any(String) }))
    await finishWrite(json({ subscription: item, secret: createSecret }, 201))
    expect(await screen.findByRole('textbox', { name: 'Secret' })).toHaveValue(createSecret)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)

    await user.click(await screen.findByRole('button', { name: 'Test' }))
    await waitFor(() => expectPendingMutation(queryClient, { kind: 'test', scopeID, subscriptionID, key: expect.any(String) }))
    await finishWrite(json({ delivery: { ...deadLetter, status: 'pending', attempt_count: 0 } }, 202))

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    await waitFor(() => expectPendingMutation(queryClient, { kind: 'rotate', scopeID, subscriptionID, key: expect.any(String) }))
    await finishWrite(json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201))
    expect(await screen.findByRole('textbox', { name: 'Rotated secret' })).toHaveValue(rotationSecret)
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)

    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    await waitFor(() => expectPendingMutation(queryClient, { kind: 'activate', scopeID, subscriptionID, key: expect.any(String) }))
    await finishWrite(json({ subscription: { ...item, revision: 3, active_secret_version_id: rotationID } }))

    await user.click(await screen.findByRole('button', { name: 'Replay' }))
    await waitFor(() => expectPendingMutation(queryClient, { kind: 'replay', scopeID, subscriptionID, key: expect.any(String) }))
    await finishWrite(json({ delivery: { ...deadLetter, id: rotationID, replay_of: deliveryID, status: 'pending', attempt_count: 0 } }, 202))

    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    await user.click((await screen.findAllByRole('button', { name: 'Revoke' })).at(-1)!)
    await waitFor(() => expectPendingMutation(queryClient, { kind: 'revoke', scopeID, subscriptionID, key: expect.any(String) }))
    await finishWrite(json({ subscription: { ...item, status: 'revoked', revision: 2 } }))
  })

  it('keeps activation handles out of mutation state while pending and after unknown, close, and terminal errors', async () => {
    let resolvePendingActivation: ((response: Response) => void) | undefined
    let activationCount = 0
    const activationKeys: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/secret-rotations')) {
        return json({ rotation_id: rotationID, key_id: rotationID, status: 'pending', expires_at: '2026-07-30T08:00:00Z', secret: rotationSecret, subscription_revision: 2 }, 201)
      }
      if (init?.method === 'POST' && url.endsWith(`/${rotationID}/activate`)) {
        activationCount += 1
        activationKeys.push((init.headers as Record<string, string>)['Idempotency-Key'])
        if (activationCount === 1) return new Promise<Response>((resolve) => { resolvePendingActivation = resolve })
        if (activationCount === 2) return json({ error: { code: 'plugin_webhook_result_unknown', params: { rotation_id: rotationID, secret: rotationSecret }, message: rotationSecret } }, 503)
        return json({ error: { code: 'idempotency_expired', params: { rotation_id: rotationID, secret: rotationSecret }, message: rotationSecret } }, 409)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    await user.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!)
    await user.click(await screen.findByRole('button', { name: 'Activate' }))

    await waitFor(() => expect(activationMutations(queryClient)).toHaveLength(1))
    const pendingVariables = activationMutations(queryClient)[0]!.state.variables
    expect(pendingVariables).toEqual({ kind: 'activate', scopeID, subscriptionID, key: expect.any(String) })
    expect(activationMutations(queryClient)[0]!.state).toMatchObject({ status: 'pending', data: undefined, error: null })

    resolvePendingActivation?.(json({ error: { code: 'plugin_webhook_result_unknown', params: { rotation_id: rotationID, secret: rotationSecret }, message: rotationSecret } }, 503))
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    await waitFor(() => expect(activationMutations(queryClient)).toHaveLength(0))
    await user.click(screen.getByRole('button', { name: 'Close and refresh' }))
    expect(activationMutations(queryClient)).toHaveLength(0)

    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))
    const replacementSecret = await screen.findByRole('textbox', { name: 'Rotated secret' })
    await user.click(within(replacementSecret.closest('.ant-modal') as HTMLElement).getAllByRole('button', { name: 'Close' }).at(-1)!)
    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    expect(activationMutations(queryClient)).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    expect(await screen.findByText('Idempotency receipt expired')).toBeInTheDocument()
    expect(activationKeys[1]).toBe(activationKeys[2])
    expect(activationMutations(queryClient)).toHaveLength(0)
    expect(document.body).not.toHaveTextContent(rotationSecret)
    expect(serializedQueryCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedStorage(localStorage)).not.toContain(rotationSecret)
    expect(serializedStorage(sessionStorage)).not.toContain(rotationSecret)
  })

  it('keeps revoke request data out of mutation state while pending and after unknown, close, and terminal errors', async () => {
    let resolvePendingRevoke: ((response: Response) => void) | undefined
    let revokeCount = 0
    const revokeKeys: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/revoke')) {
        revokeCount += 1
        revokeKeys.push((init.headers as Record<string, string>)['Idempotency-Key'])
        if (revokeCount === 1) return new Promise<Response>((resolve) => { resolvePendingRevoke = resolve })
        if (revokeCount === 2) return json({ error: { code: 'plugin_webhook_result_unknown', params: { secret_version_id: secretID, revision: 1 }, message: rotationSecret } }, 503)
        return json({ error: { code: 'idempotency_expired', params: { secret_version_id: secretID, revision: 1 }, message: rotationSecret } }, 409)
      }
      if (url.includes('/deliveries')) return json({ items: [] })
      if (url.endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    const revoke = async () => {
      await user.click(screen.getByRole('button', { name: 'Revoke' }))
      await user.click((await screen.findAllByRole('button', { name: 'Revoke' })).at(-1)!)
    }

    await user.click(await screen.findByRole('button', { name: 'View' }))
    await revoke()
    await waitFor(() => expect(mutationsForKind(queryClient, 'revoke')).toHaveLength(1))
    expect(mutationsForKind(queryClient, 'revoke')[0]!.state.variables).toEqual({ kind: 'revoke', scopeID, subscriptionID, key: expect.any(String) })
    expect(mutationsForKind(queryClient, 'revoke')[0]!.state).toMatchObject({ status: 'pending', data: undefined, error: null })

    resolvePendingRevoke?.(json({ error: { code: 'plugin_webhook_result_unknown', params: { secret_version_id: secretID, revision: 1 }, message: rotationSecret } }, 503))
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    await waitFor(() => expect(mutationsForKind(queryClient, 'revoke')).toHaveLength(0))
    await user.click(screen.getByRole('button', { name: 'Close and refresh' }))
    expect(mutationsForKind(queryClient, 'revoke')).toHaveLength(0)

    await revoke()
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    expect(mutationsForKind(queryClient, 'revoke')).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    expect(await screen.findByText('Idempotency receipt expired')).toBeInTheDocument()
    expect(revokeKeys[1]).toBe(revokeKeys[2])
    expect(mutationsForKind(queryClient, 'revoke')).toHaveLength(0)
    expect(document.body).not.toHaveTextContent(rotationSecret)
  })

  it('replays a dead-lettered delivery and revokes the subscription', async () => {
    const calls: Array<[string, RequestInit | undefined]> = []
    const deadLetter = { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'dead_lettered', attempt_count: 5, created_at: '2026-07-29T08:00:00Z' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push([String(input), init])
      if (init?.method === 'POST' && String(input).endsWith('/replays')) return json({ delivery: { ...deadLetter, id: rotationID, replay_of: deliveryID, status: 'pending', attempt_count: 0 } }, 202)
      if (init?.method === 'POST' && String(input).endsWith('/revoke')) return json({ subscription: { ...item, status: 'revoked', revision: 2 } })
      if (String(input).includes('/deliveries')) return json({ items: [deadLetter] })
      if (String(input).endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Replay' }))
    await waitFor(() => expect(calls.some(([url]) => url.endsWith('/replays'))).toBe(true))
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    const revokeButtons = await screen.findAllByRole('button', { name: 'Revoke' })
    await user.click(revokeButtons.at(-1)!)
    await waitFor(() => expect(calls.some(([url]) => url.endsWith('/revoke'))).toBe(true))
  })

  it('replays a time range with one idempotency key across repeated runs', async () => {
    const replayCalls: Array<{ key: string, body: Record<string, unknown> }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST' && String(input).endsWith('/delivery-replays')) {
        replayCalls.push({ key: (init.headers as Record<string, string>)['Idempotency-Key'], body: JSON.parse(String(init.body)) as Record<string, unknown> })
        return json({ items: [{ replay_of: deliveryID, outcome: replayCalls.length === 1 ? 'replayed' : 'already_replayed', delivery: { id: rotationID, subscription_id: subscriptionID, event_id: secretID, replay_of: deliveryID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } }], remaining: replayCalls.length === 1 }, 202)
      }
      if (String(input).includes('/deliveries')) return json({ items: [] })
      if (String(input).endsWith(`/${subscriptionID}`)) return json({ ...item, site_ids: [alternateScopeID] })
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'View' }))
    expect(await screen.findByText(alternateScopeID)).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: 'Replay by time' }))
    const dialog = (await screen.findByText('Replays finished deliveries.')).closest('[role="dialog"]') as HTMLElement
    // fix-rangepicker2：重放范围改用共享 TimeRangeFilter（不可清空，最长 31 天与后端一致）；fix-rangecompact：默认今天。
    // 组件文案跟随 antd locale（生产由 main.tsx 按 i18n 设置）；测试渲染器的 antd locale 是 zh-CN。
    const range = within(dialog).getByRole('group', { name: '时间范围' })
    expect(within(range).getByRole('radio', { name: '今天' })).toBeChecked()
    expect(within(range).queryByRole('radio', { name: '近30天' })).toBeInTheDocument()
    expect(dialog.querySelector('input[type="datetime-local"]')).toBeNull()
    await user.click(within(range).getByText('近7天'))
    await user.click(within(dialog).getByRole('button', { name: 'Replay by time' }))
    expect(await within(dialog).findByText('1 replayed, 0 denied')).toBeInTheDocument()
    expect(Date.parse(String(replayCalls[0]!.body.to)) - Date.parse(String(replayCalls[0]!.body.from))).toBe(7 * 86_400_000)
    expect(within(dialog).getByText('More remain')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Replay by time' }))
    await waitFor(() => expect(replayCalls).toHaveLength(2))
    expect(replayCalls[0]!.key).toBe(replayCalls[1]!.key)
    expect(replayCalls[0]!.body).toMatchObject({ statuses: ['dead_lettered'], limit: 100 })
    expect(Date.parse(String(replayCalls[0]!.body.from))).toBeLessThan(Date.parse(String(replayCalls[0]!.body.to)))
  })

  it('retries an unknown write outcome with the same idempotency key and never renders server text', async () => {
    const postKeys: string[] = []
    let postCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        postCount += 1
        postKeys.push((init.headers as Record<string, string>)['Idempotency-Key'])
        if (postCount === 1) return json({ error: { code: 'plugin_webhook_result_unknown', params: {}, message: 'database detail' } }, 503)
        return json({ delivery: { id: deliveryID, subscription_id: subscriptionID, event_id: secretID, status: 'pending', attempt_count: 0, created_at: '2026-07-29T08:00:00Z' } }, 202)
      }
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginWebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'Test' }))
    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByText('database detail')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    await waitFor(() => expect(postKeys).toHaveLength(2))
    expect(postKeys[0]).toBe(postKeys[1])
  })

  it('retries an unknown create outcome with one key until the idempotency receipt expires', async () => {
    const postKeys: string[] = []
    let postCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        postCount += 1
        postKeys.push((init.headers as Record<string, string>)['Idempotency-Key'])
        if (postCount < 3) return json({ error: { code: 'plugin_webhook_result_unknown', params: { secret: createSecret }, message: createSecret } }, 503)
        return json({ error: { code: 'idempotency_expired', params: { secret: createSecret }, message: `expired ${createSecret}` } }, 409)
      }
      return json({ items: [] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    await user.click((await screen.findAllByRole('button', { name: 'Create subscription' }))[0]!)
    await user.type(screen.getByLabelText('Name'), 'Billing events')
    await user.type(screen.getByLabelText('Target URL'), 'https://hooks.example.com/cdnca')
    await user.click(screen.getAllByRole('button', { name: 'Create subscription' }).at(-1)!)

    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    await waitFor(() => expect(postKeys).toHaveLength(2))
    expect(new Set(postKeys).size).toBe(1)
    expect(screen.getByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))

    expect(await screen.findByText('Idempotency receipt expired')).toBeInTheDocument()
    expect(postKeys).toHaveLength(3)
    expect(new Set(postKeys).size).toBe(1)
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(createSecret)
    expect(serializedQueryCache(queryClient)).not.toContain(createSecret)
    expect(serializedMutationCache(queryClient)).not.toContain(createSecret)
    expect(serializedStorage(localStorage)).not.toContain(createSecret)
    expect(serializedStorage(sessionStorage)).not.toContain(createSecret)
  })

  it('retries an unknown rotation outcome with one key until the idempotency receipt expires', async () => {
    const postKeys: string[] = []
    let postCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        postCount += 1
        postKeys.push((init.headers as Record<string, string>)['Idempotency-Key'])
        if (postCount < 3) return json({ error: { code: 'plugin_webhook_result_unknown', params: { secret: rotationSecret }, message: rotationSecret } }, 503)
        return json({ error: { code: 'idempotency_expired', params: { secret: rotationSecret }, message: `expired ${rotationSecret}` } }, 409)
      }
      if (String(input).includes('/deliveries')) return json({ items: [] })
      if (String(input).endsWith(`/${subscriptionID}`)) return json(item)
      return json({ items: [item] })
    })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    await user.click(await screen.findByRole('button', { name: 'View' }))
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }))

    expect(await screen.findByText('Unknown outcome', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    await waitFor(() => expect(postKeys).toHaveLength(2))
    expect(new Set(postKeys).size).toBe(1)
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))

    expect(await screen.findByText('Idempotency receipt expired')).toBeInTheDocument()
    expect(postKeys).toHaveLength(3)
    expect(new Set(postKeys).size).toBe(1)
    expect(screen.queryByRole('button', { name: 'Retry same request' })).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(rotationSecret)
    expect(serializedQueryCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedMutationCache(queryClient)).not.toContain(rotationSecret)
    expect(serializedStorage(localStorage)).not.toContain(rotationSecret)
    expect(serializedStorage(sessionStorage)).not.toContain(rotationSecret)
  })
})
