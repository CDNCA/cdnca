import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { notificationsApi, type NotificationSubscription } from '../api/notifications'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import AccountSubscriptionsPage from '../pages/AccountSubscriptionsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// tp-b7：页面同时读取套餐/证书/工单事件行（单独在 AccountSubscriptionEvents.test.tsx 测）；
// 这里只测公告行的读写与结果未知重试，事件行置空，不消耗公告的 mock、也不计入调用次数。
vi.mock('../pages/tickets/useEventSubscriptionRows', () => ({ useEventSubscriptionRows: () => ({ rows: [], error: null }) }))

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const subscription: NotificationSubscription = {
  event_type: 'announcement.published', revision: 3,
  sms_enabled: false, email_enabled: false,
  sms_supported: false, email_supported: true, changed: false,
}

function authenticate() {
  const user = principal()
  useSessionStore.getState().setSession(authResponse(user), user)
}

function setActor(
  actor: ReturnType<typeof principal>,
  accessToken: string,
  update: 'new' | 'refresh' = 'new',
) {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: accessToken }, actor, update)
}

function subscriptionKey(actor: ReturnType<typeof principal>, epoch: number) {
  // 页面把订阅行当作主体自身作用域的行来寻址，平台作用域没有独立租户，用 scope_id 补齐。
  return [
    'notification-subscription', 'tenant', actor.scope_id, actor.scope_id,
    actor.user_id, epoch, 'announcement.published',
  ] as const
}

function renderSubscriptionsWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/account/subscribe']}>
            <AccountSubscriptionsPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((next, fail) => {
    resolve = next
    reject = fail
  })
  return { promise, resolve, reject }
}

function flattenKeys(value: unknown, prefix = ''): string[] {
  if (typeof value === 'string') return [prefix]
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    flattenKeys(child, prefix ? `${prefix}.${key}` : key)
  ))
}

describe('AccountSubscriptionsPage', () => {
  it('renders nothing and performs no account notification request while unauthenticated', () => {
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')

    const { container } = render(<AccountSubscriptionsPage />)

    expect(container).toBeEmptyDOMElement()
    expect(screen.queryByTestId('notification-settings-page')).not.toBeInTheDocument()
    expect(screen.queryByText('无权访问消息订阅')).not.toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
    expect(putSubscription).not.toHaveBeenCalled()
  })

  it('rejects a platform principal that carries a tenant lineage', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: '33333333-3333-4333-8333-333333333333',
      roles: ['platform_admin'],
      permissions: ['system_configuration.read', 'system_configuration.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')
    const getChannels = vi.spyOn(notificationsApi, 'getChannels')
    const listTemplates = vi.spyOn(notificationsApi, 'listTemplates')
    const getRuntimeHealth = vi.spyOn(notificationsApi, 'getRuntimeHealth')

    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])

    expect(await screen.findByText('无权访问消息订阅')).toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
    expect(putSubscription).not.toHaveBeenCalled()
    expect(getChannels).not.toHaveBeenCalled()
    expect(listTemplates).not.toHaveBeenCalled()
    expect(getRuntimeHealth).not.toHaveBeenCalled()
    expect(screen.queryByTestId('notification-settings-page')).not.toBeInTheDocument()
  })

  it.each([
    ['empty scope id', principal({ scope_id: '' })],
    ['missing tenant id', principal({ tenant_id: null })],
    ['empty user id', principal({ user_id: '' })],
  ] as const)('rejects malformed tenant lineage (%s) locally before any account request', async (_name, actor) => {
    setActor(actor, 'malformed-account-subscription-token')
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')

    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])

    expect(await screen.findByText('无权访问消息订阅')).toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
    expect(putSubscription).not.toHaveBeenCalled()
  })

  it('rejects a zero session epoch locally before any account request', async () => {
    const actor = principal()
    setActor(actor, 'zero-epoch-account-subscription-token')
    useSessionStore.setState({ sessionEpoch: 0 })
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')

    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])

    expect(await screen.findByText('无权访问消息订阅')).toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
  })

  it('keeps account subscription resources key-complete in zh-CN, en-US, and qps-ploc', () => {
    const locales = ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const
    const keysByLocale = locales.map((locale) => {
      const tree = i18n.getResource(locale, 'accountSubscriptions', '')
      expect(tree).toBeTruthy()
      return flattenKeys(tree).sort()
    })
    expect(keysByLocale[1]).toEqual(keysByLocale[0])
    expect(keysByLocale[2]).toEqual(keysByLocale[0])
    expect(keysByLocale[3]).toEqual(keysByLocale[2])
    expect(i18n.getResource('qps-ploc', 'accountSubscriptions', 'title')).not.toBe(
      i18n.getResource('zh-CN', 'accountSubscriptions', 'title'),
    )
  })

  // 平台未开通的渠道整列隐藏，不再显示禁用的“暂不支持”。
  it('loads the real subscription and hides the unsupported SMS channel', async () => {
    authenticate()
    let resolve!: (value: NotificationSubscription) => void
    vi.spyOn(notificationsApi, 'getSubscription').mockImplementation(() => new Promise((done) => { resolve = done }))
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    expect(screen.getByLabelText('正在加载消息订阅')).toBeInTheDocument()
    resolve(subscription)
    expect(await screen.findByText('公告发布')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeDisabled()
    expect(screen.queryByRole('checkbox', { name: '公告发布 手机提醒' })).not.toBeInTheDocument()
    expect(screen.queryByText('暂不支持')).not.toBeInTheDocument()
  })

  it('keeps the account surface compact while exposing every channel control', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)

    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])

    // tp-b7：卡片标题（蓝条 + 副标题），不是页内大标题。
    expect(await screen.findByRole('heading', { name: '消息订阅' })).toBeInTheDocument()
    expect(screen.getByText('选择重要事件的通知方式，切换后自动保存。')).toBeInTheDocument()
    expect(document.querySelector('[data-parity-surface="account-subscriptions"]')).toBeInTheDocument()
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(screen.getAllByRole('row')).toHaveLength(2)
    // 提醒类型列 + 邮件列；短信未开通整列不渲染。
    expect(screen.getAllByRole('columnheader')).toHaveLength(2)
    expect(screen.getAllByRole('checkbox')).toHaveLength(1)
    expect(screen.queryByRole('checkbox', { name: /手机提醒/ })).not.toBeInTheDocument()
    expect(screen.getAllByRole('checkbox', { name: /邮件提醒/ })[0]).not.toBeDisabled()
  })

  it('renders stable 403 and generic errors without raw server English', async () => {
    authenticate()
    const get = vi.spyOn(notificationsApi, 'getSubscription')
      .mockRejectedValueOnce(new ApiError('private policy detail', 403, 'notification_permission_denied'))
    const first = renderWithProviders(<AccountSubscriptionsPage />)
    expect(await screen.findByText('无权访问消息订阅')).toBeInTheDocument()
    expect(screen.queryByText(/private policy/)).not.toBeInTheDocument()
    first.unmount()

    get.mockRejectedValueOnce(new ApiError('private database detail', 500, 'internal_error', 'safe-request'))
    renderWithProviders(<AccountSubscriptionsPage />)
    expect(await screen.findByText('消息订阅加载失败')).toBeInTheDocument()
    expect(screen.getByText(/safe-request/)).toBeInTheDocument()
    expect(screen.queryByText(/private database/)).not.toBeInTheDocument()
  })

  it('retries an unknown write with the exact body and revision', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const put = vi.spyOn(notificationsApi, 'putSubscription')
      .mockRejectedValueOnce(new ApiError('network detail', 0, 'network_error'))
      .mockResolvedValueOnce({ ...subscription, revision: 4, email_enabled: true, changed: true })
    const user = userEvent.setup()
    renderWithProviders(<AccountSubscriptionsPage />)
    await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', OUTCOME_BAR)).toBeInTheDocument()
	  await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
	  await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
	  expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
	  expect(put.mock.calls[0][4]).toEqual(expect.any(String))
	  expect(put.mock.calls[0][4]).not.toBe('')
  })

  it('keeps an unknown retry and token-free scoped cache identity across a same-epoch token refresh', async () => {
    const actor = principal()
    const oldToken = 'old-subscription-access-token'
    const newToken = 'new-subscription-access-token'
    const get = vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const put = vi.spyOn(notificationsApi, 'putSubscription')
      .mockRejectedValueOnce(new ApiError('private network detail', 0, 'network_error'))
      .mockResolvedValueOnce({ ...subscription, revision: 4, email_enabled: true, changed: true })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    setActor(actor, oldToken)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderSubscriptionsWithQueryClient(queryClient)
    await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(put).toHaveBeenCalledTimes(1)
    const readsBeforeRefresh = get.mock.calls.length

    await act(async () => {
      setActor(actor, newToken, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(get).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(screen.getByText('保存结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    const activeKey = subscriptionKey(actor, sessionEpoch)
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toContainEqual(activeKey)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toContain(oldToken)
      expect(JSON.stringify(query.queryKey)).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.refetchQueries({ queryKey: activeKey, type: 'active' })
    await waitFor(() => expect(get).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
    expect(get.mock.calls.at(-1)).toEqual([newToken, 'announcement.published'])

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(put.mock.calls[0]?.[0]).toBe(oldToken)
    expect(put.mock.calls[1]?.[0]).toBe(newToken)
    expect(put.mock.calls[1]?.slice(1)).toEqual(put.mock.calls[0]?.slice(1))
    expect(put.mock.calls[0]?.slice(1)).toEqual([
      'announcement.published',
      { sms_enabled: false, email_enabled: true },
      subscription.revision,
      expect.any(String),
    ])
  })

  it('resets unknown state and isolates a delayed old subscription when the tenant session changes', async () => {
    const tenantA = principal()
    const tenantB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
    })
    const tenantAInitial = { ...subscription, email_enabled: true }
    const tenantALate = { ...subscription, revision: 5, email_enabled: true }
    const tenantBValue = { ...subscription, revision: 1, email_enabled: false }
    const lateTenantA = deferred<NotificationSubscription>()
    const pendingTenantB = deferred<NotificationSubscription>()
    let delayTenantA = false
    const get = vi.spyOn(notificationsApi, 'getSubscription').mockImplementation((token) => {
      if (token === 'tenant-a-subscription-token') {
        return delayTenantA ? lateTenantA.promise : Promise.resolve(tenantAInitial)
      }
      if (token === 'tenant-b-subscription-token') return pendingTenantB.promise
      throw new Error(`unexpected subscription token ${token}`)
    })
    vi.spyOn(notificationsApi, 'putSubscription')
      .mockRejectedValue(new ApiError('private old-session write', 0, 'network_error'))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    setActor(tenantA, 'tenant-a-subscription-token')
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const tenantAKey = subscriptionKey(tenantA, tenantAEpoch)
    const user = userEvent.setup()

    renderSubscriptionsWithQueryClient(queryClient)
    expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).toBeChecked()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    delayTenantA = true
    void queryClient.invalidateQueries({ queryKey: tenantAKey })
    await waitFor(() => expect(get.mock.calls.filter(([token]) => token === 'tenant-a-subscription-token')).toHaveLength(2))

    act(() => setActor(tenantB, 'tenant-b-subscription-token'))
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    const tenantBKey = subscriptionKey(tenantB, tenantBEpoch)
    await waitFor(() => expect(get.mock.calls.some(([token]) => token === 'tenant-b-subscription-token')).toBe(true))

    expect(tenantBEpoch).not.toBe(tenantAEpoch)
    expect(screen.getByLabelText('正在加载消息订阅')).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeInTheDocument()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()

    await act(async () => lateTenantA.resolve(tenantALate))
    expect(queryClient.getQueryData(tenantAKey)).toEqual(tenantALate)
    expect(queryClient.getQueryData(tenantBKey)).toBeUndefined()
    expect(screen.getByLabelText('正在加载消息订阅')).toBeInTheDocument()

    await act(async () => pendingTenantB.resolve(tenantBValue))
    expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeChecked()
    expect(queryClient.getQueryData(tenantBKey)).toEqual(tenantBValue)
    expect(queryClient.getQueryData(tenantAKey)).toEqual(tenantALate)
  })

  it.each(['success', 'error'] as const)(
    'isolates a delayed old-tenant subscription mutation %s after the new tenant has loaded',
    async (outcome) => {
      const tenantA = principal()
      const tenantB = principal({
        user_id: '88888888-8888-4888-8888-888888888888',
        scope_id: '77777777-7777-4777-8777-777777777777',
        tenant_id: '77777777-7777-4777-8777-777777777777',
      })
      const tenantAValue = { ...subscription, revision: 3, email_enabled: false }
      const tenantASaved = { ...subscription, revision: 4, email_enabled: true, changed: true }
      const tenantBValue = { ...subscription, revision: 11, email_enabled: false }
      const pendingTenantAWrite = deferred<NotificationSubscription>()
      vi.spyOn(notificationsApi, 'getSubscription').mockImplementation((token) => {
        if (token === 'tenant-a-late-mutation-token') return Promise.resolve(tenantAValue)
        if (token === 'tenant-b-late-mutation-token') return Promise.resolve(tenantBValue)
        throw new Error(`unexpected late mutation token ${token}`)
      })
      const put = vi.spyOn(notificationsApi, 'putSubscription')
        .mockImplementation(() => pendingTenantAWrite.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const setQueryData = vi.spyOn(queryClient, 'setQueryData')
      setActor(tenantA, 'tenant-a-late-mutation-token')
      const tenantAEpoch = useSessionStore.getState().sessionEpoch
      const tenantAKey = subscriptionKey(tenantA, tenantAEpoch)
      const user = userEvent.setup()

      renderSubscriptionsWithQueryClient(queryClient)
      await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
      expect(put).toHaveBeenCalledTimes(1)
      expect(put.mock.calls[0]?.slice(0, 4)).toEqual([
        'tenant-a-late-mutation-token', 'announcement.published',
        { sms_enabled: false, email_enabled: true }, tenantAValue.revision,
      ])
      expect(put.mock.calls[0]?.[4]).toEqual(expect.any(String))
      expect(put.mock.calls[0]?.[4]).not.toBe('')

      act(() => setActor(tenantB, 'tenant-b-late-mutation-token'))
      const tenantBEpoch = useSessionStore.getState().sessionEpoch
      const tenantBKey = subscriptionKey(tenantB, tenantBEpoch)
      expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeChecked()
      expect(queryClient.getQueryData(tenantBKey)).toEqual(tenantBValue)

      await act(async () => {
        if (outcome === 'success') {
          pendingTenantAWrite.resolve(tenantASaved)
          await pendingTenantAWrite.promise
        } else {
          pendingTenantAWrite.reject(new ApiError('private late tenant A write', 503, 'request_failed'))
          await pendingTenantAWrite.promise.catch(() => undefined)
        }
        await Promise.resolve()
      })

      if (outcome === 'success') {
        await waitFor(() => expect(queryClient.getQueryData(tenantAKey)).toEqual(tenantASaved))
        const subscriptionWrites = setQueryData.mock.calls
          .filter(([queryKey]) => Array.isArray(queryKey) && queryKey[0] === 'notification-subscription')
        expect(subscriptionWrites).toEqual([[tenantAKey, tenantASaved]])
      } else {
        expect(queryClient.getQueryData(tenantAKey)).toEqual(tenantAValue)
        expect(setQueryData).not.toHaveBeenCalled()
      }
      expect(queryClient.getQueryData(tenantBKey)).toEqual(tenantBValue)
      expect(screen.getByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeChecked()
      expect(screen.getByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeDisabled()
      expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText(/private late tenant A write/)).not.toBeInTheDocument()
    },
  )

  it('writes a successful subscription only to the exact current scoped cache key', async () => {
    const actor = principal()
    setActor(actor, 'current-subscription-token')
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const currentKey = subscriptionKey(actor, sessionEpoch)
    const foreignKey = subscriptionKey(principal({
      scope_id: '99999999-9999-4999-8999-999999999999',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      user_id: '99999999-9999-4999-8999-999999999998',
    }), 999)
    const foreignValue = { ...subscription, revision: 9, email_enabled: true }
    const saved = { ...subscription, revision: 4, email_enabled: true, changed: true }
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    queryClient.setQueryData(foreignKey, foreignValue)
    const setQueryData = vi.spyOn(queryClient, 'setQueryData')
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    vi.spyOn(notificationsApi, 'putSubscription').mockResolvedValue(saved)
    const user = userEvent.setup()

    renderSubscriptionsWithQueryClient(queryClient)
    await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
    await waitFor(() => expect(queryClient.getQueryData(currentKey)).toEqual(saved))

    const subscriptionWrites = setQueryData.mock.calls
      .filter(([queryKey]) => Array.isArray(queryKey) && queryKey[0] === 'notification-subscription')
    expect(subscriptionWrites).toEqual([[currentKey, saved]])
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignValue)
  })

  it.each([
	['validation', new ApiError('private validation detail', 400, 'validation_error'), '消息订阅设置无效，请刷新后重试'],
	['permission', new ApiError('private permission detail', 403, 'notification_permission_denied'), '无权访问消息订阅'],
	['revision', new ApiError('private revision detail', 409, 'version_conflict'), '订阅版本已变化，请刷新后重试'],
  ])('clears an unknown retry after a deterministic %s result', async (_name, deterministic, expected) => {
	authenticate()
	vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
	const put = vi.spyOn(notificationsApi, 'putSubscription')
	  .mockRejectedValueOnce(new ApiError('network detail', 0, 'network_error'))
	  .mockRejectedValueOnce(deterministic)
	const user = userEvent.setup()
	renderWithProviders(<AccountSubscriptionsPage />)
	await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
	await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
	expect(await screen.findByText(expected)).toBeInTheDocument()
	expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
	expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
	expect(put).toHaveBeenCalledTimes(2)
	expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
  })

  it.each([408, 425, 429, 500, 502, 503, 504])('keeps an HTTP %s write available for exact retry until a deterministic result', async (status) => {
    authenticate()
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const put = vi.spyOn(notificationsApi, 'putSubscription')
      .mockRejectedValueOnce(new ApiError('private upstream detail', status, status === 500 ? 'internal_error' : 'request_failed'))
      .mockRejectedValueOnce(new ApiError('private revision detail', 409, 'version_conflict'))
    const user = userEvent.setup()
    renderWithProviders(<AccountSubscriptionsPage />)
    await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('订阅版本已变化，请刷新后重试')).toBeInTheDocument()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
    expect(put).toHaveBeenCalledTimes(2)
    expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
  })

  it('treats an incorrect 2xx subscription response as unknown and retries the exact request', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ ...subscription, revision: '4', email_enabled: true }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ ...subscription, revision: 4, email_enabled: true, changed: true }),
      } as Response)
    const user = userEvent.setup()
    renderWithProviders(<AccountSubscriptionsPage />)

    await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeChecked()

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    const firstInit = fetchMock.mock.calls[0][1]
    const secondInit = fetchMock.mock.calls[1][1]
	  expect(firstInit?.body).toBe(JSON.stringify({ sms_enabled: false, email_enabled: true }))
	  expect(secondInit?.body).toBe(firstInit?.body)
	  expect(new Headers(secondInit?.headers).get('If-Match')).toBe(new Headers(firstInit?.headers).get('If-Match'))
	  const requestKey = new Headers(firstInit?.headers).get('X-Request-ID')
	  expect(requestKey).toEqual(expect.any(String))
	  expect(requestKey).not.toBe('')
	  expect(new Headers(secondInit?.headers).get('X-Request-ID')).toBe(requestKey)
	  expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).toBeChecked()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
  })

  it.each([
    ['non-200 success', 201, { ...subscription, revision: 4, email_enabled: true, changed: true }],
    ['missing changed', 200, { ...subscription, revision: 4, email_enabled: true, changed: undefined }],
    ['extra field', 200, { ...subscription, revision: 4, email_enabled: true, changed: true, extra: true }],
    ['wrong event path binding', 200, { ...subscription, event_type: 'other.event', revision: 4, email_enabled: true, changed: true }],
    ['wrong payload binding', 200, { ...subscription, revision: 4, email_enabled: false, changed: true }],
    ['wrong revision transition', 200, { ...subscription, revision: 5, email_enabled: true, changed: true }],
  ])('rejects a %s subscription PUT response as unknown', async (_name, status, payload) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      json: async () => payload,
    } as Response)

    await expect(notificationsApi.putSubscription(
      'memory-only-access-token',
      'announcement.published',
	      { sms_enabled: false, email_enabled: true },
	      3,
	      'subscription-response-request',
	    )).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('keeps pseudo locale and mobile layout shrinkable', async () => {
    await changeLocale('qps-ploc')
    authenticate()
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const { container } = renderWithProviders(<AccountSubscriptionsPage />)
    const title = i18n.getResource('qps-ploc', 'accountSubscriptions', 'title') as string
    expect(await screen.findByRole('heading', { name: title })).toBeInTheDocument()
    expect(container.querySelector('[data-testid="notification-settings-page"]')).toHaveStyle({ minWidth: 0 })
  })

  it.each(['en-US', 'qps-ploc'] as const)(
    'localizes account read error, retry recovery, and API 403 in %s without raw server text',
    async (locale) => {
      await changeLocale(locale)
      const actor = principal()
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const get = vi.spyOn(notificationsApi, 'getSubscription')
        .mockRejectedValueOnce(new ApiError('private account database topology', 500, 'internal_error', 'account-request-7'))
        .mockResolvedValueOnce(subscription)
      const loadFailed = i18n.getResource(locale, 'accountSubscriptions', 'errors.loadFailed') as string
      const requestFailed = i18n.getResource(locale, 'accountSubscriptions', 'errors.requestFailed') as string
      const retry = i18n.getResource(locale, 'common', 'retry') as string
      const event = i18n.getResource(locale, 'accountSubscriptions', 'events.announcementPublished') as string
      const forbidden = i18n.getResource(locale, 'accountSubscriptions', 'errors.forbidden') as string
      const loading = i18n.getResource(locale, 'accountSubscriptions', 'loading') as string
      const user = userEvent.setup()

      const failed = renderWithProviders(<AccountSubscriptionsPage />)
      expect(screen.getByLabelText(loading)).toBeInTheDocument()
      expect(await screen.findByText(loadFailed)).toBeInTheDocument()
      expect(screen.getByText(requestFailed.replace('{{requestId}}', 'account-request-7'))).toBeInTheDocument()
      expect(screen.queryByText(/private account database topology/)).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: retry }))
      expect(await screen.findByText(event)).toBeInTheDocument()
      failed.unmount()

      get.mockRejectedValueOnce(new ApiError('private account policy', 403, 'notification_permission_denied'))
      renderWithProviders(<AccountSubscriptionsPage />)
      expect(await screen.findByText(forbidden)).toBeInTheDocument()
      expect(screen.queryByText(/private account policy/)).not.toBeInTheDocument()
    },
  )
})
