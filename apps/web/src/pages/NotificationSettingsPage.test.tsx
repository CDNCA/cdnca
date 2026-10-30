import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  notificationsApi,
  type NotificationChannels,
  type NotificationDeliveryLog,
  type NotificationRuntimeHealth,
  type NotificationSubscription,
  type NotificationTemplate,
  type NotificationTemplatePage,
} from '../api/notifications'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import NotificationSettingsPage from './NotificationSettingsPage'

const channels: NotificationChannels = {
  revision: 1, sms_enabled: false, email_enabled: false,
  sms_supported: true, email_supported: true, changed: false,
}

const runtimeHealth: NotificationRuntimeHealth = {
  enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
}

const template: NotificationTemplate = {
  template_id: 'announcement_published', version: 1, channel: 'email',
  subject: '[Notice] {{.title}}', body: '{{.body}}', variables: ['title', 'body'],
  created_at: '2026-08-03T10:00:00Z', changed: false,
}

const subscription: NotificationSubscription = {
  event_type: 'announcement.published', revision: 3,
  sms_enabled: false, email_enabled: false,
  sms_supported: true, email_supported: true, changed: false,
}

const deliveryLog: NotificationDeliveryLog = {
  scope_id: '11111111-1111-4111-8111-111111111111',
  outbox_id: '22222222-2222-4222-8222-222222222222',
  event_type: 'announcement.published', channel: 'email', template_id: 'announcement_published',
  template_version: 1, generation: 1, state: 'retry_wait', revision: 2, attempt_count: 1,
  failure_code: 'smtp_temporary_failure', retry_at: '2026-08-08T10:01:00Z',
  created_at: '2026-08-08T10:00:00Z', updated_at: '2026-08-08T10:00:05Z',
}

function authenticate(permissions: string[]) {
  const user = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function setActor(
  actor: ReturnType<typeof principal>,
  accessToken: string,
  update: 'new' | 'refresh' = 'new',
) {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: accessToken }, actor, update)
}

function renderAdminWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/sys/notification']}>
            <NotificationSettingsPage mode="admin" />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function renderAccountWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/account/subscribe']}>
            <NotificationSettingsPage mode="account" />
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

function mockAdminReads(templatePage: NotificationTemplatePage = { items: [] }) {
  vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue(channels)
  vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue(templatePage)
  vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtimeHealth)
}

describe('NotificationSettingsPage', () => {
  beforeEach(() => {
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue({
      schema: 'cdnca.notification-delivery-policy/v1', window_mode: 'all_day',
      window_start: '00:00', window_end: '23:59', timezone: 'Asia/Shanghai', revision: 1, changed: false, events: [],
    })
  })

  it('loads real event policy on the administrator page while preserving channels, template versions and delivery logs', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    mockAdminReads({ items: [template] })
    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    expect(await screen.findByRole('radio', { name: '全天' })).toBeChecked()
    expect(notificationsApi.getDeliveryPolicy).toHaveBeenCalledWith(expect.any(String))
    expect(screen.getByRole('checkbox', { name: '邮件通知' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新建模板版本' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '查看发送日志' })).toBeInTheDocument()
    expect(screen.getByText(template.template_id)).toBeInTheDocument()
  })

  it('names templates and variables in Chinese (W2)', async () => {
    await changeLocale('zh-CN')
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    mockAdminReads({ items: [template, { ...template, template_id: 'market.seller.defaulted.zh-cn', variables: ['currency', 'observed'] }] })
    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    expect(await screen.findByText('节点市场：供货方被判定失联')).toBeInTheDocument()
    expect(screen.getByText('market.seller.defaulted.zh-cn')).toBeInTheDocument()
    expect(screen.getByText('公告发布')).toBeInTheDocument()
    expect(screen.getByText('币种（currency）、当前值（observed）')).toBeInTheDocument()
    expect(screen.getByText('标题（title）、正文（body）')).toBeInTheDocument()
  })

  it('opens redacted delivery logs, paginates by cursor, and loads attempt facts on demand', async () => {
    await changeLocale('zh-CN')
    authenticate(['system_configuration.read'])
    mockAdminReads()
    const listDeliveries = vi.spyOn(notificationsApi, 'listDeliveries')
      .mockResolvedValueOnce({ items: [deliveryLog], next_cursor: 'next-delivery-cursor' })
      .mockResolvedValueOnce({ items: [{ ...deliveryLog, outbox_id: '33333333-3333-4333-8333-333333333333', state: 'delivered' }] })
    const listAttempts = vi.spyOn(notificationsApi, 'listDeliveryAttempts').mockResolvedValue({
      outbox_id: deliveryLog.outbox_id,
      items: [{
        attempt_number: 1, outcome: 'temporary_failure', failure_code: 'smtp_temporary_failure',
        next_attempt_at: '2026-08-08T10:01:00Z', claimed_at: '2026-08-08T10:00:01Z',
        lease_expires_at: '2026-08-08T10:00:31Z',
        completed_at: '2026-08-08T10:00:05Z',
      }],
    })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('button', { name: '查看发送日志' }))
    const drawer = await screen.findByRole('dialog', { name: '通知发送日志' })
    expect(await within(drawer).findByText('等待重试')).toBeInTheDocument()
    expect(within(drawer).getByText('smtp_temporary_failure')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private')
    expect(listDeliveries).toHaveBeenCalledWith(expect.any(String), { limit: 20 })

    await user.click(within(drawer).getByRole('button', { name: '查看投递尝试' }))
    expect(await within(drawer).findByText('第 1 次')).toBeInTheDocument()
    expect(listAttempts).toHaveBeenCalledWith(expect.any(String), deliveryLog.outbox_id)

    await user.click(within(drawer).getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(listDeliveries).toHaveBeenLastCalledWith(expect.any(String), {
      limit: 20, cursor: 'next-delivery-cursor',
    }))
    expect(await within(drawer).findByText('已送达')).toBeInTheDocument()
  })

  it('renders nothing and performs no admin notification request while unauthenticated', () => {
    const getChannels = vi.spyOn(notificationsApi, 'getChannels')
    const listTemplates = vi.spyOn(notificationsApi, 'listTemplates')
    const getRuntimeHealth = vi.spyOn(notificationsApi, 'getRuntimeHealth')
    const putChannels = vi.spyOn(notificationsApi, 'putChannels')
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate')

    const { container } = render(<NotificationSettingsPage mode="admin" />)

    expect(container).toBeEmptyDOMElement()
    expect(screen.queryByTestId('notification-settings-page')).not.toBeInTheDocument()
    expect(screen.queryByText('无权访问通知设置')).not.toBeInTheDocument()
    expect(getChannels).not.toHaveBeenCalled()
    expect(listTemplates).not.toHaveBeenCalled()
    expect(getRuntimeHealth).not.toHaveBeenCalled()
    expect(putChannels).not.toHaveBeenCalled()
    expect(putTemplate).not.toHaveBeenCalled()
  })

  it('shows empty templates and only reports email ready from live ready and worker facts', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({
      revision: 1, sms_enabled: false, email_enabled: true,
      sms_supported: true, email_supported: true, changed: false,
    })
    vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
    })
    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    expect(await screen.findByText('通知发送已就绪')).toBeInTheDocument()
    expect(screen.getByText('暂无通知模板')).toBeInTheDocument()
  })

  it('fails closed before network calls without read permission', () => {
    authenticate([])
    const channels = vi.spyOn(notificationsApi, 'getChannels')
    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    expect(screen.getByText('无权访问通知设置')).toBeInTheDocument()
    expect(channels).not.toHaveBeenCalled()
  })

  it.each([
    ['a platform admin fallback without explicit read', principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })],
    ['a tenant principal carrying admin permissions', principal({
      permissions: ['system_configuration.read', 'system_configuration.manage'],
    })],
  ])('rejects %s locally before every admin notification read', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
    const getChannels = vi.spyOn(notificationsApi, 'getChannels')
    const listTemplates = vi.spyOn(notificationsApi, 'listTemplates')
    const getRuntimeHealth = vi.spyOn(notificationsApi, 'getRuntimeHealth')
    const putChannels = vi.spyOn(notificationsApi, 'putChannels')
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate')

    renderWithProviders(<NotificationSettingsPage mode="admin" />, ['/sys/notification'])

    expect(await screen.findByText('无权访问通知设置')).toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
    expect(getChannels).not.toHaveBeenCalled()
    expect(listTemplates).not.toHaveBeenCalled()
    expect(getRuntimeHealth).not.toHaveBeenCalled()
    expect(putChannels).not.toHaveBeenCalled()
    expect(putTemplate).not.toHaveBeenCalled()
    expect(screen.queryByTestId('notification-settings-page')).not.toBeInTheDocument()
  })

  it('keeps the email draft, template form, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['system_configuration.read', 'system_configuration.manage'],
    })
    const oldToken = 'old-admin-notification-token'
    const newToken = 'new-admin-notification-token'
    const getChannels = vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue(channels)
    const listTemplates = vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    const getRuntimeHealth = vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtimeHealth)
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate').mockResolvedValue({
      ...template, version: 7, subject: 'Stable subject', body: 'Stable body', variables: ['title'], changed: true,
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    setActor(actor, oldToken)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderAdminWithQueryClient(queryClient)
    const email = await screen.findByRole('checkbox', { name: '邮件通知' })
    await user.click(email)
    await user.click(screen.getByRole('button', { name: '新建模板版本' }))
    const dialog = screen.getByRole('dialog', { name: '新建通知模板版本' })
    await user.type(within(dialog).getByLabelText('模板 ID'), 'announcement_published')
    await user.clear(within(dialog).getByLabelText('版本'))
    await user.type(within(dialog).getByLabelText('版本'), '7')
    await user.type(within(dialog).getByLabelText('邮件主题'), 'Stable subject')
    await user.type(within(dialog).getByLabelText('邮件正文'), 'Stable body')
    await user.type(within(dialog).getByLabelText('变量'), 'title')
    const readsBeforeRefresh = [getChannels.mock.calls.length, listTemplates.mock.calls.length, getRuntimeHealth.mock.calls.length]

    await act(async () => {
      setActor(actor, newToken, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect([getChannels.mock.calls.length, listTemplates.mock.calls.length, getRuntimeHealth.mock.calls.length]).toEqual(readsBeforeRefresh)
    expect(email).toBeChecked()
    expect(screen.getByRole('dialog', { name: '新建通知模板版本' })).toBe(dialog)
    expect(within(dialog).getByLabelText('模板 ID')).toHaveValue('announcement_published')
    expect(within(dialog).getByLabelText('版本')).toHaveValue('7')
    expect(within(dialog).getByLabelText('邮件主题')).toHaveValue('Stable subject')
    expect(within(dialog).getByLabelText('邮件正文')).toHaveValue('Stable body')
    expect(within(dialog).getByLabelText('变量')).toHaveValue('title')

    const activeKey = ['notification-settings', actor.scope_id, sessionEpoch] as const
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toContainEqual(activeKey)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toContain(oldToken)
      expect(JSON.stringify(query.queryKey)).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.refetchQueries({ queryKey: activeKey, type: 'active' })
    await waitFor(() => expect(getChannels).toHaveBeenCalledTimes(readsBeforeRefresh[0] + 1))
    expect(getChannels.mock.calls.at(-1)).toEqual([newToken])
    expect(listTemplates.mock.calls.at(-1)).toEqual([newToken])
    expect(getRuntimeHealth.mock.calls.at(-1)).toEqual([newToken])

    await user.click(within(dialog).getByRole('button', { name: '创建模板版本' }))
    await waitFor(() => expect(putTemplate).toHaveBeenCalledTimes(1))
    expect(putTemplate).toHaveBeenCalledWith(
      newToken, 'announcement_published', 7, 'email',
      { subject: 'Stable subject', body: 'Stable body', variables: ['title'] },
      expect.any(String),
    )
  }, 20_000)

  it('resets the admin draft, template modal, and unknown write while isolating a delayed old-session read', async () => {
    const adminA = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['system_configuration.read', 'system_configuration.manage'],
    })
    const adminB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['system_configuration.read', 'system_configuration.manage'],
    })
    const adminATemplate = { ...template, template_id: 'admin_a_template' }
    const adminALateTemplate = { ...template, template_id: 'admin_a_late_template', version: 2 }
    const adminBTemplate = { ...template, template_id: 'admin_b_template' }
    const lateAdminA = deferred<NotificationTemplatePage>()
    const pendingAdminB = deferred<NotificationTemplatePage>()
    let delayAdminA = false
    vi.spyOn(notificationsApi, 'getChannels').mockImplementation((token) => Promise.resolve({
      ...channels, email_enabled: token === 'admin-b-notification-token',
    }))
    const listTemplates = vi.spyOn(notificationsApi, 'listTemplates').mockImplementation((token) => {
      if (token === 'admin-a-notification-token') {
        return delayAdminA ? lateAdminA.promise : Promise.resolve({ items: [adminATemplate] })
      }
      if (token === 'admin-b-notification-token') return pendingAdminB.promise
      throw new Error(`unexpected admin notification token ${token}`)
    })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtimeHealth)
    vi.spyOn(notificationsApi, 'putTemplate')
      .mockRejectedValue(new ApiError('private old-session write', 503, 'request_failed'))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    setActor(adminA, 'admin-a-notification-token')
    const adminAEpoch = useSessionStore.getState().sessionEpoch
    const adminAKey = ['notification-settings', adminA.scope_id, adminAEpoch] as const
    const user = userEvent.setup()

    renderAdminWithQueryClient(queryClient)
    expect(await screen.findByText('admin_a_template')).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: '邮件通知' }))
    await user.click(screen.getByRole('button', { name: '新建模板版本' }))
    const dialog = screen.getByRole('dialog', { name: '新建通知模板版本' })
    await user.type(within(dialog).getByLabelText('模板 ID'), 'pending_template')
    await user.clear(within(dialog).getByLabelText('版本'))
    await user.type(within(dialog).getByLabelText('版本'), '3')
    await user.type(within(dialog).getByLabelText('邮件主题'), 'Pending subject')
    await user.type(within(dialog).getByLabelText('邮件正文'), 'Pending body')
    await user.click(within(dialog).getByRole('button', { name: '创建模板版本' }))
    expect(await within(dialog).findByText('保存结果待确认')).toBeInTheDocument()

    delayAdminA = true
    void queryClient.invalidateQueries({ queryKey: adminAKey })
    await waitFor(() => expect(listTemplates.mock.calls.filter(([token]) => token === 'admin-a-notification-token')).toHaveLength(2))

    act(() => setActor(adminB, 'admin-b-notification-token'))
    const adminBEpoch = useSessionStore.getState().sessionEpoch
    const adminBKey = ['notification-settings', adminB.scope_id, adminBEpoch] as const
    await waitFor(() => expect(listTemplates.mock.calls.some(([token]) => token === 'admin-b-notification-token')).toBe(true))

    expect(adminBEpoch).not.toBe(adminAEpoch)
    expect(screen.getByLabelText('正在加载通知设置')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '新建通知模板版本' })).not.toBeInTheDocument()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('admin_a_template')).not.toBeInTheDocument()

    await act(async () => lateAdminA.resolve({ items: [adminALateTemplate] }))
    expect(queryClient.getQueryData(adminAKey)).toEqual({
      channels, templates: { items: [adminALateTemplate] }, health: runtimeHealth,
    })
    expect(queryClient.getQueryData(adminBKey)).toBeUndefined()
    expect(screen.getByLabelText('正在加载通知设置')).toBeInTheDocument()
    expect(screen.queryByText('admin_a_late_template')).not.toBeInTheDocument()

    await act(async () => pendingAdminB.resolve({ items: [adminBTemplate] }))
    expect(await screen.findByText('admin_b_template')).toBeInTheDocument()
    expect(screen.queryByText('admin_a_late_template')).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '邮件通知' })).toBeChecked()
    expect(queryClient.getQueryData(adminBKey)).toEqual({
      channels: { ...channels, email_enabled: true }, templates: { items: [adminBTemplate] }, health: runtimeHealth,
    })
  }, 20_000)

  it.each(['success', 'error'] as const)(
    'isolates a delayed old-admin channel mutation %s after the new admin has loaded',
    async (outcome) => {
      const adminA = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
        permissions: ['system_configuration.read', 'system_configuration.manage'],
      })
      const adminB = principal({
        user_id: '88888888-8888-4888-8888-888888888888',
        scope_id: '77777777-7777-4777-8777-777777777777',
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
        permissions: ['system_configuration.read', 'system_configuration.manage'],
      })
      const adminATemplate = { ...template, template_id: 'admin_a_mutation_template' }
      const adminBTemplate = { ...template, template_id: 'admin_b_mutation_template' }
      const adminBData = { channels, templates: { items: [adminBTemplate] }, health: runtimeHealth }
      vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue(channels)
      vi.spyOn(notificationsApi, 'listTemplates').mockImplementation((token) => Promise.resolve({
        items: [token === 'admin-a-late-mutation-token' ? adminATemplate : adminBTemplate],
      }))
      vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtimeHealth)
      const pendingAdminAWrite = deferred<NotificationChannels>()
      const put = vi.spyOn(notificationsApi, 'putChannels')
        .mockImplementation(() => pendingAdminAWrite.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      setActor(adminA, 'admin-a-late-mutation-token')
      const adminAEpoch = useSessionStore.getState().sessionEpoch
      const adminAKey = ['notification-settings', adminA.scope_id, adminAEpoch] as const
      const user = userEvent.setup()

      renderAdminWithQueryClient(queryClient)
      expect(await screen.findByText(adminATemplate.template_id)).toBeInTheDocument()
      await user.click(screen.getByRole('checkbox', { name: '邮件通知' }))
      await user.click(screen.getByRole('button', { name: '保存' }))
      expect(put).toHaveBeenCalledTimes(1)
      expect(put.mock.calls[0]?.slice(0, 3)).toEqual([
        'admin-a-late-mutation-token',
        { sms_enabled: false, email_enabled: true },
        channels.revision,
      ])
      expect(put.mock.calls[0]?.[3]).toEqual(expect.any(String))
      expect(put.mock.calls[0]?.[3]).not.toBe('')

      act(() => setActor(adminB, 'admin-b-late-mutation-token'))
      const adminBEpoch = useSessionStore.getState().sessionEpoch
      const adminBKey = ['notification-settings', adminB.scope_id, adminBEpoch] as const
      expect(await screen.findByText(adminBTemplate.template_id)).toBeInTheDocument()
      expect(queryClient.getQueryData(adminBKey)).toEqual(adminBData)
      const adminBEmail = screen.getByRole('checkbox', { name: '邮件通知' })
      await user.click(adminBEmail)
      expect(adminBEmail).toBeChecked()

      await act(async () => {
        if (outcome === 'success') {
          pendingAdminAWrite.resolve({ ...channels, revision: 2, email_enabled: true, changed: true })
          await pendingAdminAWrite.promise
        } else {
          pendingAdminAWrite.reject(new ApiError('private late admin A write', 503, 'request_failed'))
          await pendingAdminAWrite.promise.catch(() => undefined)
        }
        await Promise.resolve()
      })

      if (outcome === 'success') {
        await waitFor(() => expect(invalidate.mock.calls.some(([filters]) => (
          JSON.stringify(filters?.queryKey) === JSON.stringify(adminAKey)
        ))).toBe(true))
        const notificationInvalidations = invalidate.mock.calls
          .map(([filters]) => filters?.queryKey)
          .filter((queryKey) => queryKey?.[0] === 'notification-settings')
        expect(notificationInvalidations).toEqual([adminAKey])
      } else {
        expect(invalidate).not.toHaveBeenCalled()
      }
      expect(queryClient.getQueryData(adminBKey)).toEqual(adminBData)
      expect(screen.getByText(adminBTemplate.template_id)).toBeInTheDocument()
      expect(screen.queryByText(adminATemplate.template_id)).not.toBeInTheDocument()
      expect(adminBEmail).toBeChecked()
      expect(adminBEmail).not.toBeDisabled()
      expect(screen.getByRole('button', { name: '保存' })).not.toBeDisabled()
      expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText(/private late admin A write/)).not.toBeInTheDocument()
    },
  )

  it.each(['channels', 'template'] as const)(
    'invalidates only the current admin identity after a successful %s write',
    async (kind) => {
      const actor = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
        permissions: ['system_configuration.read', 'system_configuration.manage'],
      })
      setActor(actor, 'scoped-admin-notification-token')
      const sessionEpoch = useSessionStore.getState().sessionEpoch
      const currentPrefix = ['notification-settings', actor.scope_id, sessionEpoch] as const
      const foreignKey = [
        'notification-settings', '99999999-9999-4999-8999-999999999999', 999,
      ] as const
      const foreignData = { channels, templates: { items: [template] }, health: runtimeHealth }
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      queryClient.setQueryData(foreignKey, foreignData)
      mockAdminReads()
      vi.spyOn(notificationsApi, 'putChannels').mockResolvedValue({
        ...channels, revision: 2, email_enabled: true, changed: true,
      })
      vi.spyOn(notificationsApi, 'putTemplate').mockResolvedValue({ ...template, changed: true })
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      const user = userEvent.setup()

      renderAdminWithQueryClient(queryClient)
      await screen.findByText('暂无通知模板')
      if (kind === 'channels') {
        await user.click(screen.getByRole('checkbox', { name: '邮件通知' }))
        await user.click(screen.getByRole('button', { name: '保存' }))
      } else {
        await user.click(screen.getByRole('button', { name: '新建模板版本' }))
        const dialog = screen.getByRole('dialog', { name: '新建通知模板版本' })
        await user.type(within(dialog).getByLabelText('模板 ID'), template.template_id)
        fireEvent.change(within(dialog).getByLabelText('邮件主题'), { target: { value: template.subject } })
        fireEvent.change(within(dialog).getByLabelText('邮件正文'), { target: { value: template.body } })
        await user.type(within(dialog).getByLabelText('变量'), 'title, body')
        await user.click(within(dialog).getByRole('button', { name: '创建模板版本' }))
      }

      await waitFor(() => expect(invalidate.mock.calls.some(([filters]) => (
        JSON.stringify(filters?.queryKey) === JSON.stringify(currentPrefix)
      ))).toBe(true))
      const notificationInvalidations = invalidate.mock.calls
        .map(([filters]) => filters?.queryKey)
        .filter((queryKey) => queryKey?.[0] === 'notification-settings')
      expect(notificationInvalidations).toEqual([currentPrefix])
      expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
      expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
    },
    20_000,
  )

  it('keeps manage-only controls disabled for a platform reader', async () => {
    authenticate(['system_configuration.read'])
    mockAdminReads()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)

    expect(await screen.findByRole('checkbox', { name: '邮件通知' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '新建模板版本' })).toBeDisabled()
    expect(screen.getByText('通知发送已就绪')).toBeInTheDocument()
  })

  it('creates an immutable email template version and refreshes the list', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({
      revision: 1, sms_enabled: false, email_enabled: false,
      sms_supported: true, email_supported: true, changed: false,
    })
    vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
    })
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate').mockResolvedValue({
      template_id: 'announcement_published', version: 1, channel: 'email',
      subject: '[公告] {{.title}}', body: '{{.body}}', variables: ['title', 'body'],
      created_at: '2026-08-03T10:00:00Z', changed: true,
    })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('button', { name: '新建模板版本' }))
    await user.type(screen.getByLabelText('模板 ID'), 'announcement_published')
    await user.clear(screen.getByLabelText('版本'))
    await user.type(screen.getByLabelText('版本'), '1')
    fireEvent.change(screen.getByLabelText('邮件主题'), { target: { value: '[公告] {{.title}}' } })
    fireEvent.change(screen.getByLabelText('邮件正文'), { target: { value: '{{.body}}' } })
    await user.type(screen.getByLabelText('变量'), 'title, body')
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))

	    expect(putTemplate).toHaveBeenCalledWith('memory-only-access-token', 'announcement_published', 1, 'email', {
	      subject: '[公告] {{.title}}', body: '{{.body}}', variables: ['title', 'body'],
	    }, expect.any(String))
  })

  // fix-fielderr-be5：服务端拒绝模板某个变量时标在变量输入框下并写出是哪一个，弹窗不关、无错误条
  it('marks a refused template variable under its box with the variable name', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    mockAdminReads()
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-template'), { field: 'variables[1]', reason: 'invalid' }))
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('button', { name: '新建模板版本' }))
    await user.type(screen.getByLabelText('模板 ID'), 'site_ready')
    fireEvent.change(screen.getByLabelText('邮件主题'), { target: { value: '{{.title}}' } })
    fireEvent.change(screen.getByLabelText('邮件正文'), { target: { value: '{{.body}}' } })
    const variables = screen.getByLabelText('变量')
    await user.type(variables, 'title, api_key')
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))
    await waitFor(() => expect(putTemplate).toHaveBeenCalledTimes(1))
    const help = await screen.findByText('api_key：填写的内容不符合要求')
    expect(help.closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(help.closest('.ant-form-item')).toContainElement(variables)
    expect(screen.getByRole('dialog', { name: '新建通知模板版本' })).toBeInTheDocument()
    expect(document.querySelector('.ant-modal .ant-alert-error')).toBeNull()
  })

  it('updates SMS channels and creates an immutable SMS template version', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    mockAdminReads()
    const putChannels = vi.spyOn(notificationsApi, 'putChannels').mockResolvedValue({
      ...channels, revision: 2, sms_enabled: true, changed: true,
    })
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate').mockResolvedValue({
      template_id: 'announcement_published', version: 2, channel: 'sms', subject: '',
      body: '{{.title}}\n{{.body}}', variables: ['title', 'body'], created_at: '2026-08-03T10:00:00Z', changed: true,
    })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('checkbox', { name: '短信通知' }))
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(putChannels).toHaveBeenCalledWith(
      'memory-only-access-token', { sms_enabled: true, email_enabled: false }, 1, expect.any(String),
    ))

    await user.click(screen.getByRole('button', { name: '新建模板版本' }))
    await user.type(screen.getByLabelText('模板 ID'), 'announcement_published')
    await user.clear(screen.getByLabelText('版本'))
    await user.type(screen.getByLabelText('版本'), '2')
    await user.click(screen.getByRole('radio', { name: '短信通知' }))
    expect(screen.queryByLabelText('邮件主题')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('短信正文'), { target: { value: '{{.title}}\n{{.body}}' } })
    await user.type(screen.getByLabelText('变量'), 'title, body')
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))
    await waitFor(() => expect(putTemplate).toHaveBeenCalledWith(
      'memory-only-access-token', 'announcement_published', 2, 'sms',
      { subject: '', body: '{{.title}}\n{{.body}}', variables: ['title', 'body'] }, expect.any(String),
    ))
  })

  it('locks channel controls and retries an unknown channel write exactly', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({
      revision: 1, sms_enabled: false, email_enabled: false,
      sms_supported: true, email_supported: true, changed: false,
    })
    vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
    })
    const put = vi.spyOn(notificationsApi, 'putChannels')
      .mockRejectedValueOnce(new ApiError('network detail', 0, 'network_error'))
      .mockResolvedValueOnce({
        revision: 2, sms_enabled: false, email_enabled: true,
        sms_supported: true, email_supported: true, changed: true,
      })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    const email = await screen.findByRole('checkbox', { name: '邮件通知' })
    await user.click(email)
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText('保存结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(email).toBeDisabled()
    expect(screen.getByRole('button', { name: '新建模板版本' })).toBeDisabled()
	  await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
	  await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
	  expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
	  expect(put.mock.calls[0][3]).toEqual(expect.any(String))
	  expect(put.mock.calls[0][3]).not.toBe('')
  })

  it.each([
    [400, 'validation_error'],
    [403, 'notification_permission_denied'],
    [409, 'version_conflict'],
  ])('clears an admin unknown retry after deterministic HTTP %s', async (status, code) => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({
      revision: 1, sms_enabled: false, email_enabled: false,
      sms_supported: true, email_supported: true, changed: false,
    })
    vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
    })
    const put = vi.spyOn(notificationsApi, 'putChannels')
      .mockRejectedValueOnce(new ApiError('network detail', 0, 'network_error'))
      .mockRejectedValueOnce(new ApiError('deterministic detail', status, code))
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    const email = await screen.findByRole('checkbox', { name: '邮件通知' })
    await user.click(email)
    await user.click(screen.getByRole('button', { name: '保存' }))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(email).not.toBeDisabled()
    expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
  })

  it('keeps an HTTP 429 channel write uncertain in qps-ploc', async () => {
    await changeLocale('qps-ploc')
    const t = i18n.getFixedT('qps-ploc', 'notificationSettings')
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    mockAdminReads()
    const put = vi.spyOn(notificationsApi, 'putChannels').mockRejectedValue(
      new ApiError('private channel limiter bucket', 429, 'request_failed'),
    )
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    const email = await screen.findByRole('checkbox', { name: t('channels.email') })
    await user.click(email)
    await user.click(screen.getByRole('button', { name: t('actions.save') }))

    expect(await screen.findByText(t('uncertainty.title'), { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: t('actions.retrySame') })).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private channel limiter bucket')
    expect(email).toBeDisabled()
    expect(screen.getByRole('button', { name: t('actions.save') })).toBeDisabled()
    expect(put).toHaveBeenCalledOnce()
  })

  it('keeps an explicit template rate limit uncertain and locks the draft', async () => {
    await changeLocale('en-US')
    const t = i18n.getFixedT('en-US', 'notificationSettings')
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    mockAdminReads()
    const put = vi.spyOn(notificationsApi, 'putTemplate').mockRejectedValue(
      new ApiError('private template limiter shard', 503, 'rate_limited'),
    )
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('button', { name: t('actions.newTemplate') }))
    await user.type(screen.getByLabelText(t('templates.id')), 'rate_limited_template')
    await user.type(screen.getByLabelText(t('form.subject')), 'Subject')
    await user.type(screen.getByLabelText(t('form.body')), 'Body')
    await user.click(screen.getByRole('button', { name: t('actions.createTemplate') }))

    expect(await screen.findByText(t('uncertainty.title'))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: t('actions.retrySame') })).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private template limiter shard')
    expect(screen.getByLabelText(t('templates.id'))).toBeDisabled()
    expect(screen.getByLabelText(t('form.body'))).toBeDisabled()
    expect(put).toHaveBeenCalledOnce()
  })

  it('locks the template form and retries an unknown template write exactly', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({
      revision: 1, sms_enabled: false, email_enabled: false,
      sms_supported: true, email_supported: true, changed: false,
    })
    vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
    })
    const put = vi.spyOn(notificationsApi, 'putTemplate')
      .mockRejectedValueOnce(new ApiError('upstream detail', 503, 'request_failed'))
      .mockResolvedValueOnce({
        template_id: 'announcement_published', version: 2, channel: 'email',
        subject: '[公告] {{.title}}', body: '{{.body}}', variables: ['title', 'body'],
        created_at: '2026-08-03T10:00:00Z', changed: true,
      })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('button', { name: '新建模板版本' }))
    await user.type(screen.getByLabelText('模板 ID'), 'announcement_published')
    await user.clear(screen.getByLabelText('版本'))
    await user.type(screen.getByLabelText('版本'), '2')
    fireEvent.change(screen.getByLabelText('邮件主题'), { target: { value: '[公告] {{.title}}' } })
    fireEvent.change(screen.getByLabelText('邮件正文'), { target: { value: '{{.body}}' } })
    await user.type(screen.getByLabelText('变量'), 'title, body')
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))
    expect(await screen.findByText('保存结果待确认')).toBeInTheDocument()
    expect(screen.getByLabelText('模板 ID')).toBeDisabled()
    expect(screen.getByLabelText('邮件正文')).toBeDisabled()
	  await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
	  await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
	  expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
	  expect(put.mock.calls[0][5]).toEqual(expect.any(String))
	  expect(put.mock.calls[0][5]).not.toBe('')
	})

  it('abandons uncertain admin channel and template writes, clears drafts, and refetches authority', async () => {
    await changeLocale('zh-CN')
    const t = i18n.getFixedT('zh-CN', 'notificationSettings')
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const getChannels = vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue(channels)
    const listTemplates = vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    const getHealth = vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtimeHealth)
    const putChannels = vi.spyOn(notificationsApi, 'putChannels').mockRejectedValue(
      new ApiError('private channel timeout', 408, 'request_timeout'),
    )
    const putTemplate = vi.spyOn(notificationsApi, 'putTemplate').mockRejectedValue(
      new ApiError('private invalid template response', 502, 'invalid_response'),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderAdminWithQueryClient(queryClient)
    const email = await screen.findByRole('checkbox', { name: t('channels.email') })
    await user.click(email)
    await user.click(screen.getByRole('button', { name: t('actions.save') }))
    expect(await screen.findByText(t('uncertainty.title'), { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: t('actions.closeAndRefresh') }))

    await waitFor(() => expect(getChannels).toHaveBeenCalledTimes(2))
    expect(listTemplates).toHaveBeenCalledTimes(2)
    expect(getHealth).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('checkbox', { name: t('channels.email') })).not.toBeChecked()
    expect(screen.getByRole('button', { name: t('actions.save') })).toBeDisabled()
    expect(screen.queryByText(t('uncertainty.title'))).not.toBeInTheDocument()
    expect(putChannels).toHaveBeenCalledOnce()

    await user.click(screen.getByRole('button', { name: t('actions.newTemplate') }))
    await user.type(screen.getByLabelText(t('templates.id')), 'uncertain_template')
    await user.type(screen.getByLabelText(t('form.subject')), 'Uncertain subject')
    await user.type(screen.getByLabelText(t('form.body')), 'Uncertain body')
    await user.click(screen.getByRole('button', { name: t('actions.createTemplate') }))
    const dialog = await screen.findByRole('dialog', { name: t('form.title') })
    expect(within(dialog).getByText(t('uncertainty.title'))).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: t('actions.closeAndRefresh') }))

    await waitFor(() => expect(listTemplates).toHaveBeenCalledTimes(3))
    expect(screen.queryByRole('dialog', { name: t('form.title') })).not.toBeInTheDocument()
    expect(putTemplate).toHaveBeenCalledOnce()
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0)

    await user.click(screen.getByRole('button', { name: t('actions.newTemplate') }))
    expect(screen.getByLabelText(t('templates.id'))).toHaveValue('')
    expect(screen.getByLabelText(t('templates.version'))).toHaveValue('1')
    expect(screen.getByLabelText(t('form.subject'))).toHaveValue('')
    expect(screen.getByLabelText(t('form.body'))).toHaveValue('')
  }, 20_000)

  it('validates template source limits as UTF-8 bytes', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({
      revision: 1, sms_enabled: false, email_enabled: false,
      sms_supported: true, email_supported: true, changed: false,
    })
    vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
    })
    const put = vi.spyOn(notificationsApi, 'putTemplate').mockResolvedValue({
      template_id: 'byte_boundary', version: 1, channel: 'email', subject: 'subject', body: 'body',
      variables: [], created_at: '2026-08-03T10:00:00Z', changed: true,
    })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="admin" />)
    await user.click(await screen.findByRole('button', { name: '新建模板版本' }))
    await user.type(screen.getByLabelText('模板 ID'), 'byte_boundary')
    fireEvent.change(screen.getByLabelText('邮件主题'), { target: { value: `${'界'.repeat(682)}abc` } })
    fireEvent.change(screen.getByLabelText('邮件正文'), { target: { value: 'body' } })
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))
    expect(await screen.findByText('邮件主题不能超过 2048 个 UTF-8 字节')).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('邮件主题'), { target: { value: `${'界'.repeat(682)}ab` } })
    fireEvent.change(screen.getByLabelText('邮件正文'), { target: { value: `${'界'.repeat(43690)}abc` } })
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))
    expect(await screen.findByText('邮件正文不能超过 131072 个 UTF-8 字节')).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('邮件正文'), { target: { value: `${'界'.repeat(43690)}ab` } })
    await user.click(screen.getByRole('button', { name: '创建模板版本' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
  })

  it.each(['en-US', 'qps-ploc'] as const)(
    'localizes admin read error, retry recovery, empty state, and API 403 in %s without raw server text',
    async (locale) => {
      await changeLocale(locale)
      const actor = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
        permissions: ['system_configuration.read'],
      })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const getChannels = vi.spyOn(notificationsApi, 'getChannels')
        .mockRejectedValueOnce(new ApiError('private admin database topology', 500, 'internal_error', 'admin-request-8'))
        .mockResolvedValueOnce(channels)
      vi.spyOn(notificationsApi, 'listTemplates').mockResolvedValue({ items: [] })
      vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtimeHealth)
      const loading = i18n.getResource(locale, 'notificationSettings', 'loading') as string
      const loadFailed = i18n.getResource(locale, 'notificationSettings', 'errors.loadFailed') as string
      const requestFailed = i18n.getResource(locale, 'notificationSettings', 'errors.requestFailed') as string
      const retry = i18n.getResource(locale, 'common', 'retry') as string
      const empty = i18n.getResource(locale, 'notificationSettings', 'values.emptyTemplates') as string
      const forbidden = i18n.getResource(locale, 'notificationSettings', 'errors.forbidden') as string
      const user = userEvent.setup()

      const failed = renderWithProviders(<NotificationSettingsPage mode="admin" />)
      expect(screen.getByLabelText(loading)).toBeInTheDocument()
      expect(await screen.findByText(loadFailed)).toBeInTheDocument()
      expect(screen.getByText(requestFailed.replace('{{requestId}}', 'admin-request-8'))).toBeInTheDocument()
      expect(screen.queryByText(/private admin database topology/)).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: retry }))
      expect(await screen.findByText(empty)).toBeInTheDocument()
      failed.unmount()

      getChannels.mockRejectedValueOnce(new ApiError('private admin policy', 403, 'notification_permission_denied'))
      renderWithProviders(<NotificationSettingsPage mode="admin" />)
      expect(await screen.findByText(forbidden)).toBeInTheDocument()
      expect(screen.queryByText(/private admin policy/)).not.toBeInTheDocument()
    },
  )

  it.each([
    ['unsupported scope kind', principal({ scope_kind: 'platform', tenant_id: '77777777-7777-4777-8777-777777777777' })],
    ['empty scope id', principal({ scope_id: '' })],
    ['missing tenant id', principal({ tenant_id: null })],
    ['empty user id', principal({ user_id: '' })],
  ] as const)('rejects a malformed tenant lineage (%s) locally before any account notification request', async (_name, actor) => {
    setActor(actor, 'malformed-account-notification-token')
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')

    renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])

    expect(await screen.findByText('无权访问消息订阅')).toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
    expect(putSubscription).not.toHaveBeenCalled()
    expect(screen.queryByTestId('notification-settings-page')).not.toBeInTheDocument()
  })

  it('rejects a zero session epoch locally before any account notification request', async () => {
    const actor = principal()
    setActor(actor, 'zero-epoch-account-notification-token')
    useSessionStore.setState({ sessionEpoch: 0 })
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')

    renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])

    expect(await screen.findByText('无权访问消息订阅')).toBeInTheDocument()
    expect(getSubscription).not.toHaveBeenCalled()
    expect(putSubscription).not.toHaveBeenCalled()
  })

  it('keeps an account unknown write draft across a same-epoch token refresh and retries with the new token', async () => {
    const actor = principal()
    const oldToken = 'old-account-notification-token'
    const newToken = 'new-account-notification-token'
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')
      .mockRejectedValueOnce(new ApiError('private account network detail', 0, 'network_error'))
      .mockResolvedValueOnce({ ...subscription, revision: 4, email_enabled: true, changed: true })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    setActor(actor, oldToken)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderAccountWithQueryClient(queryClient)
    await user.click(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const readsBeforeRefresh = getSubscription.mock.calls.length

    await act(async () => {
      setActor(actor, newToken, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(getSubscription).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(screen.getByText('保存结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const activeKey = [
      'notification-subscription', actor.scope_kind, actor.scope_id, actor.scope_id,
      actor.user_id, sessionEpoch, 'announcement.published',
    ] as const
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toContainEqual(activeKey)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toContain(oldToken)
      expect(JSON.stringify(query.queryKey)).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.refetchQueries({ queryKey: activeKey, type: 'active' })
    await waitFor(() => expect(getSubscription).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
    expect(getSubscription.mock.calls.at(-1)).toEqual([newToken, 'announcement.published'])

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(putSubscription).toHaveBeenCalledTimes(2))
    expect(putSubscription.mock.calls[0]?.[0]).toBe(oldToken)
    expect(putSubscription.mock.calls[1]?.[0]).toBe(newToken)
    expect(putSubscription.mock.calls[1]?.slice(1)).toEqual(putSubscription.mock.calls[0]?.slice(1))
  }, 20_000)

  // A channel the platform has not switched on and configured is not shown at all.
  it('hides account channels the server reports unsupported and shows supported ones', async () => {
    setActor(principal(), 'account-visibility-token')
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue({ ...subscription, sms_supported: false, email_supported: true })
    const view = renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])
    expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: '公告发布 手机提醒' })).not.toBeInTheDocument()
    expect(screen.queryByText('手机提醒')).not.toBeInTheDocument()
    expect(screen.queryByText('暂不支持')).not.toBeInTheDocument()
    view.unmount()
  })

  it('shows no subscription table when no channel is supported', async () => {
    setActor(principal(), 'account-none-token')
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue({ ...subscription, sms_supported: false, email_supported: false })
    renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])
    expect(await screen.findByText('平台暂未开通提醒方式')).toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('updates the account SMS subscription without changing email', async () => {
    const actor = principal()
    setActor(actor, 'account-sms-notification-token')
    vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const put = vi.spyOn(notificationsApi, 'putSubscription').mockResolvedValue({
      ...subscription, revision: 4, sms_enabled: true, changed: true,
    })
    const user = userEvent.setup()

    renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])
    await user.click(await screen.findByRole('checkbox', { name: '公告发布 手机提醒' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      'account-sms-notification-token', 'announcement.published',
      { sms_enabled: true, email_enabled: false }, 3, expect.any(String),
    ))
  })

  it('keeps account rate limits uncertain and abandons with an authoritative refetch', async () => {
    await changeLocale('zh-CN')
    const t = i18n.getFixedT('zh-CN', 'accountSubscriptions')
    const actor = principal()
    setActor(actor, 'account-terminal-notification-token')
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription').mockResolvedValue(subscription)
    const putSubscription = vi.spyOn(notificationsApi, 'putSubscription')
      .mockRejectedValueOnce(new ApiError('private account limiter', 429, 'rate_limited'))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderAccountWithQueryClient(queryClient)
    const email = await screen.findByRole('checkbox', { name: `${t('events.announcementPublished')} ${t('columns.email')}` })
    await user.click(email)
    expect(await screen.findByText(t('uncertainty.title'), { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: t('actions.retrySame') })).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private account limiter')
    expect(email).toBeDisabled()

    await user.click(screen.getByRole('button', { name: t('actions.closeAndRefresh') }))

    await waitFor(() => expect(getSubscription).toHaveBeenCalledTimes(2))
    expect(screen.queryByText(t('uncertainty.title'))).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: t('actions.retrySame') })).not.toBeInTheDocument()
    expect(email).toBeEnabled()
    expect(putSubscription).toHaveBeenCalledOnce()
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0)
  })

  it('clears account write UI on a new session and isolates a delayed old-owner read', async () => {
    const tenantA = principal()
    const tenantB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
    })
    const lateTenantA = deferred<NotificationSubscription>()
    const pendingTenantB = deferred<NotificationSubscription>()
    let delayTenantA = false
    const getSubscription = vi.spyOn(notificationsApi, 'getSubscription').mockImplementation((token) => {
      if (token === 'tenant-a-account-notification-token') {
        return delayTenantA ? lateTenantA.promise : Promise.resolve({ ...subscription, email_enabled: true })
      }
      if (token === 'tenant-b-account-notification-token') return pendingTenantB.promise
      throw new Error(`unexpected account notification token ${token}`)
    })
    vi.spyOn(notificationsApi, 'putSubscription').mockRejectedValue(
      new ApiError('private old-owner write', 0, 'network_error'),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    setActor(tenantA, 'tenant-a-account-notification-token')
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const tenantAKey = [
      'notification-subscription', tenantA.scope_kind, tenantA.scope_id, tenantA.scope_id,
      tenantA.user_id, tenantAEpoch, 'announcement.published',
    ] as const
    const user = userEvent.setup()

    renderAccountWithQueryClient(queryClient)
    expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).toBeChecked()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 邮件提醒' }))
    expect(await screen.findByText('保存结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    delayTenantA = true
    void queryClient.invalidateQueries({ queryKey: tenantAKey })
    await waitFor(() => expect(getSubscription.mock.calls.filter(([token]) => token === 'tenant-a-account-notification-token')).toHaveLength(2))

    act(() => setActor(tenantB, 'tenant-b-account-notification-token'))
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    const tenantBKey = [
      'notification-subscription', tenantB.scope_kind, tenantB.scope_id, tenantB.scope_id,
      tenantB.user_id, tenantBEpoch, 'announcement.published',
    ] as const
    await waitFor(() => expect(getSubscription.mock.calls.some(([token]) => token === 'tenant-b-account-notification-token')).toBe(true))

    expect(tenantBEpoch).not.toBe(tenantAEpoch)
    expect(screen.getByLabelText('正在加载消息订阅')).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeInTheDocument()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()

    await act(async () => lateTenantA.resolve({ ...subscription, revision: 5, email_enabled: true }))
    expect(queryClient.getQueryData(tenantAKey)).toEqual({ ...subscription, revision: 5, email_enabled: true })
    expect(queryClient.getQueryData(tenantBKey)).toBeUndefined()
    expect(screen.getByLabelText('正在加载消息订阅')).toBeInTheDocument()

    await act(async () => pendingTenantB.resolve({ ...subscription, revision: 1, email_enabled: false }))
    expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).not.toBeChecked()
    expect(queryClient.getQueryData(tenantBKey)).toEqual({ ...subscription, revision: 1, email_enabled: false })
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
  }, 20_000)

  it.each(['en-US', 'qps-ploc'] as const)(
    'localizes account loading, error, retry, empty row and forbidden states in %s without raw server text',
    async (locale) => {
      await changeLocale(locale)
      const actor = principal()
      setActor(actor, `account-${locale}-notification-token`)
      const getSubscription = vi.spyOn(notificationsApi, 'getSubscription')
        .mockRejectedValueOnce(new ApiError('private account database detail', 500, 'internal_error', 'account-request-8'))
        .mockResolvedValueOnce(subscription)
      const loading = i18n.getResource(locale, 'accountSubscriptions', 'loading') as string
      const loadFailed = i18n.getResource(locale, 'accountSubscriptions', 'errors.loadFailed') as string
      const requestFailed = i18n.getResource(locale, 'accountSubscriptions', 'errors.requestFailed') as string
      const retry = i18n.getResource(locale, 'common', 'retry') as string
      const event = i18n.getResource(locale, 'accountSubscriptions', 'events.announcementPublished') as string
      const user = userEvent.setup()

      renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])
      expect(screen.getByLabelText(loading)).toBeInTheDocument()
      expect(await screen.findByText(loadFailed)).toBeInTheDocument()
      expect(screen.getByText(requestFailed.replace('{{requestId}}', 'account-request-8'))).toBeInTheDocument()
      expect(screen.queryByText(/private account database detail/)).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: retry }))
      expect(await screen.findByText(event)).toBeInTheDocument()
      expect(getSubscription).toHaveBeenCalledTimes(2)

      getSubscription.mockRejectedValueOnce(new ApiError('private account policy detail', 403, 'notification_permission_denied'))
      renderWithProviders(<NotificationSettingsPage mode="account" />, ['/account/subscribe'])
      expect(await screen.findByText(i18n.getResource(locale, 'accountSubscriptions', 'errors.forbidden') as string)).toBeInTheDocument()
      expect(screen.queryByText(/private account policy detail/)).not.toBeInTheDocument()
    },
  )

  it.each([
	    ['unsupported capability mismatch', () => notificationsApi.putChannels(
	      'token', { sms_enabled: true, email_enabled: false }, 1, 'channel-capability-request',
	    ), { revision: 2, sms_enabled: true, email_enabled: false, sms_supported: false, email_supported: true, changed: true }],
	    ['channel payload mismatch', () => notificationsApi.putChannels(
	      'token', { sms_enabled: false, email_enabled: true }, 1, 'channel-payload-request',
    ), { revision: 2, sms_enabled: false, email_enabled: false, sms_supported: true, email_supported: true, changed: true }],
	    ['channel revision mismatch', () => notificationsApi.putChannels(
	      'token', { sms_enabled: false, email_enabled: true }, 1, 'channel-revision-request',
    ), { revision: 3, sms_enabled: false, email_enabled: true, sms_supported: true, email_supported: true, changed: true }],
    ['template identity mismatch', () => notificationsApi.putTemplate(
	      'token', 'announcement_published', 2, 'email',
	      { subject: 'subject', body: 'body', variables: [] }, 'template-identity-request',
    ), { template_id: 'other_template', version: 2, channel: 'email', subject: 'subject', body: 'body', variables: [], created_at: '2026-08-03T10:00:00Z', changed: true }],
    ['template body mismatch', () => notificationsApi.putTemplate(
	      'token', 'announcement_published', 2, 'email',
	      { subject: 'subject', body: 'body', variables: [] }, 'template-body-request',
    ), { template_id: 'announcement_published', version: 2, channel: 'email', subject: 'subject', body: 'different', variables: [], created_at: '2026-08-03T10:00:00Z', changed: true }],
    ['template extra field', () => notificationsApi.putTemplate(
	      'token', 'announcement_published', 2, 'email',
	      { subject: 'subject', body: 'body', variables: [] }, 'template-extra-request',
    ), { template_id: 'announcement_published', version: 2, channel: 'email', subject: 'subject', body: 'body', variables: [], created_at: '2026-08-03T10:00:00Z', changed: true, extra: true }],
  ])('rejects a %s response as unknown', async (_name, request, payload) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true, status: 200, json: async () => payload,
    } as Response)
    await expect(request()).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
