import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { jobsApi, type BackgroundJob } from '../api/jobs'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { enUS, zhCN } from '../i18n/resources'
import AdminTasksPage from '../pages/AdminTasksPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const job: BackgroundJob = {
  task_id: 'a0000000-0000-4000-8000-000000000001',
  tenant_id: '2a2a2a2a-2a2a-4a2a-8a2a-2a2a2a2a2a2a', // tenants.id（fixtures principal 默认）
  kind: 'cache.purge',
  related_resource: { reference: 'site:tenant.test' },
  request_id: 'tenant-request-1',
  status: 'running',
  attempt: 1,
  max_attempts: 3,
  progress: { total: 2, completed: 1, succeeded: 1, failed: 0, cancelled: 0, pending: 1 },
  created_at: '2026-07-22T08:00:00Z',
  started_at: '2026-07-22T08:01:00Z',
  updated_at: '2026-07-22T08:02:00Z',
	revision: '7',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function authenticateTenant(permissions: string[]) {
  const actor = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function tenantResponse(input: RequestInfo | URL, currentJob: BackgroundJob): Response {
  const url = new URL(String(input), 'https://web.test')
  if (url.pathname.endsWith('/attempts')) return json({ data: [], page: {} })
  if (url.pathname.endsWith('/results')) return json({ data: [], page: {} })
  if (url.pathname === `/v1/jobs/${currentJob.task_id}`) return json({ data: currentJob })
  return json({
    data: [currentJob],
    page: {},
    query: { from: url.searchParams.get('from'), to: url.searchParams.get('to') },
  })
}

function renderTenantTasksWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/task']}><AdminTasksPage /></MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

// 真实租户的 tenants.id 与 access_scopes.id 是两个独立 UUID（001_identity）：按 scope 派生一个不同的 tenant_id。
function tenantFor(scopeID: string): string {
  return scopeID === '22222222-2222-4222-8222-222222222222' ? '2a2a2a2a-2a2a-4a2a-8a2a-2a2a2a2a2a2a' : `${scopeID.slice(0, -4)}7a7a`
}

function tenantSession(
  token: string,
  scopeID: string,
  permissions = ['jobs.read', 'jobs.manage'],
  update: 'new' | 'refresh' = 'new',
  userID = `${scopeID.slice(0, -1)}1`,
) {
  const actor = principal({
    scope_id: scopeID,
    tenant_id: tenantFor(scopeID),
    user_id: userID,
    permissions,
  })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return { actor, epoch: useSessionStore.getState().sessionEpoch }
}

function ownerTuple(actor: ReturnType<typeof principal>, epoch: number) {
  return [actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, epoch] as const
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

function allTenantJobsApiSpies() {
  return [
    vi.spyOn(jobsApi, 'list'),
    vi.spyOn(jobsApi, 'detail'),
    vi.spyOn(jobsApi, 'attempts'),
    vi.spyOn(jobsApi, 'results'),
    vi.spyOn(jobsApi, 'cancel'),
    vi.spyOn(jobsApi, 'retry'),
  ]
}

describe('tenant tasks page', () => {
  beforeEach(() => {
    vi.spyOn(jobsApi, 'kinds').mockResolvedValue({ data: [] })
  })

  it.each([
    ['missing tenant_id', null],
  ])('denies a malformed tenant principal with %s before every jobs API call', (_case, tenantID) => {
    const actor = principal({
      scope_id: '22222222-2222-4222-8222-222222222222',
      tenant_id: tenantID,
      permissions: ['jobs.read', 'jobs.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const apiSpies = allTenantJobsApiSpies()

    renderWithProviders(<AdminTasksPage />, ['/task'])

    expect(screen.getByText('无权查看后台任务')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少后台任务读取权限')).toBeInTheDocument()
    for (const spy of apiSpies) expect(spy).not.toHaveBeenCalled()
  })

  it('denies a tenant without jobs.read before every jobs API call', () => {
    authenticateTenant(['jobs.manage', 'jobs.read_all', 'jobs.manage_all'])
    const apiSpies = allTenantJobsApiSpies()

    renderWithProviders(<AdminTasksPage />, ['/task'])

    expect(screen.getByText('无权查看后台任务')).toBeInTheDocument()
    for (const spy of apiSpies) expect(spy).not.toHaveBeenCalled()
  })

  it.each([
    ['zh-CN', zhCN.jobs, {
      actions: {
        cancel: '取消任务', retryFailed: '重试失败任务', retrySame: '使用同一请求重试',
        confirm: '确认', close: '关闭',
      },
      states: { canceling: '取消中', retrying: '重试中' },
      errors: {
        job_idempotency_conflict: '幂等键已绑定到不同请求',
        job_invalid_transition: '当前任务状态不允许此操作',
        job_retries_exhausted: '任务重试次数已用尽',
      },
    }],
    ['en', enUS.jobs, {
      actions: {
        cancel: 'Cancel task', retryFailed: 'Retry failed task', retrySame: 'Retry same request',
        confirm: 'Confirm', close: 'Close',
      },
      states: { canceling: 'Cancelling', retrying: 'Retrying' },
      errors: {
        job_idempotency_conflict: 'The idempotency key is bound to a different request',
        job_invalid_transition: 'The current task state does not allow this operation',
        job_retries_exhausted: 'The task has no retries remaining',
      },
    }],
  ])('ships complete %s cancel and retry resources', (_locale, resources, expected) => {
    expect(resources).toMatchObject({
      ...expected,
      confirm: {
        cancelTitle: expect.any(String), cancelDescription: expect.any(String),
        retryTitle: expect.any(String), retryDescription: expect.any(String),
      },
      notices: {
        cancelSucceeded: expect.any(String), retrySucceeded: expect.any(String),
        unknownTitle: expect.any(String), unknownDescription: expect.any(String),
      },
      errors: {
        ...expected.errors,
        commandFailed: expect.any(String), job_permission_denied: expect.any(String),
        job_scope_forbidden: expect.any(String), job_not_found: expect.any(String),
        job_store_unavailable: expect.any(String),
      },
    })
  })

  it('uses tenant reads and cancellation at 390px without page-level horizontal overflow', async () => {
    authenticateTenant(['jobs.read', 'jobs.manage'])
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    let currentJob = job
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/cancel')) {
        currentJob = {
          ...job,
          status: 'cancelled',
          failure_code: 'cancelled',
          completed_at: '2026-07-22T08:03:00Z',
          updated_at: '2026-07-22T08:03:00Z',
          progress: { ...job.progress, completed: 2, cancelled: 1, pending: 0 },
        }
        return Promise.resolve(json({ data: currentJob, replayed: false }))
      }
      return Promise.resolve(tenantResponse(input, currentJob))
    })
    const user = userEvent.setup()

    const { container } = renderWithProviders(<AdminTasksPage />, ['/task'])

    expect(await screen.findByText('执行中')).toBeInTheDocument()
    const page = container.querySelector('.jobs-page')
    expect(page).toHaveStyle({ width: 'auto', minWidth: 0, maxWidth: '100%', overflowX: 'hidden' })
    expect(page).not.toHaveStyle({ width: '100%' })
    await user.click(screen.getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '子任务详情' })
    await waitFor(() => expect(within(drawer).getByText('site:tenant.test')).toBeInTheDocument())
    await user.click(within(drawer).getByRole('button', { name: '取消任务' }))
    await user.click(within((await screen.findByText('确认取消任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))
    expect(await screen.findByText('任务取消请求已提交')).toBeInTheDocument()

    const paths = fetchSpy.mock.calls.map(([input]) => new URL(String(input), 'https://web.test').pathname)
    expect(paths).toContain('/v1/jobs')
    expect(paths).toContain(`/v1/jobs/${job.task_id}`)
    expect(paths).toContain(`/v1/jobs/${job.task_id}/attempts`)
    expect(paths).toContain(`/v1/jobs/${job.task_id}/results`)
    expect(paths).toContain(`/v1/jobs/${job.task_id}/cancel`)
    expect(paths.some((path) => path.startsWith('/v1/admin/jobs'))).toBe(false)
  })

  it('uses the tenant retry endpoint for a retryable failed task', async () => {
    authenticateTenant(['jobs.read', 'jobs.manage'])
    const failedJob: BackgroundJob = {
      ...job,
      status: 'failed',
      attempt: 2,
      completed_at: '2026-07-22T08:03:00Z',
      failure_code: 'node_unavailable',
      progress: { ...job.progress, completed: 2, failed: 1, pending: 0 },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
        return Promise.resolve(json({ data: { ...job, status: 'queued', attempt: 2 }, replayed: false }))
      }
      return Promise.resolve(tenantResponse(input, failedJob))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText('确认重试任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))

    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input, init]) =>
      init?.method === 'POST' && String(input) === `/v1/jobs/${job.task_id}/retry`)).toBe(true)
  })

  it('does not treat platform-wide management as tenant write permission', async () => {
    authenticateTenant(['jobs.read', 'jobs.manage_all'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) =>
      Promise.resolve(tenantResponse(input, job)))

    renderWithProviders(<AdminTasksPage />, ['/task'])
    expect(await screen.findByText('执行中')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /取消任务|重试失败任务/ })).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalled()
  })

  it('fails a mixed-tenant list closed without caching or rendering foreign facts', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    const { actor, epoch } = tenantSession('tenant-list-token', scopeID, ['jobs.read'])
    const ownJob = { ...job, related_resource: { reference: 'site:own-list.test' } }
    const foreignJob = {
      ...job,
      task_id: 'f0000000-0000-4000-8000-000000000001',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      related_resource: { reference: 'site:foreign-list.test' },
      request_id: 'private-foreign-request',
    }
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [ownJob, foreignJob],
      page: {},
      query: { from: params.from, to: params.to },
    }))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    })

    renderTenantTasksWithQueryClient(queryClient)

    expect(await screen.findByText('后台任务加载失败')).toBeInTheDocument()
    expect(screen.getByText('服务响应无效，请稍后重试')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/site:(?:own|foreign)-list\.test/)
    expect(document.body).not.toHaveTextContent(/f0000000|private-foreign-request/)
    const listQueries = queryClient.getQueryCache().getAll()
      .filter((query) => query.queryKey[0] === 'jobs')
    expect(listQueries).toHaveLength(1)
    expect(listQueries[0]?.state.status).toBe('error')
    expect(listQueries[0]?.state.data).toBeUndefined()
    expect(listQueries[0]?.queryKey.slice(1, 6)).toEqual(ownerTuple(actor, epoch))
  })

  it('rejects a foreign tenant detail without displaying its task, resource, or server facts', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    tenantSession('tenant-detail-token', scopeID, ['jobs.read'])
    const ownJob = { ...job, related_resource: { reference: 'site:own-detail.test' } }
    const foreignJob = {
      ...job,
      task_id: 'f0000000-0000-4000-8000-000000000002',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      related_resource: { reference: 'site:foreign-detail.test' },
      request_id: 'private-foreign-detail-request',
    }
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [ownJob], page: {}, query: { from: params.from, to: params.to },
    }))
    vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: foreignJob })
    vi.spyOn(jobsApi, 'attempts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'results').mockResolvedValue({ data: [], page: {} })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '子任务详情' })

    expect(await within(drawer).findByText('任务详情加载失败')).toBeInTheDocument()
    expect(within(drawer).getByText('服务响应无效，请稍后重试')).toBeInTheDocument()
    expect(drawer).not.toHaveTextContent(/site:foreign-detail\.test/)
    expect(drawer).not.toHaveTextContent(/f0000000|private-foreign-detail-request/)
    expect(document.body).not.toHaveTextContent('API response was invalid')
  })

  it('rejects a same-tenant detail for a different task without exposing or operating that task', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    tenantSession('tenant-wrong-task-token', scopeID)
    const selectedJob = {
      ...job,
      task_id: 'a0000000-0000-4000-8000-00000000000a',
      related_resource: { reference: 'site:selected-task.test' },
    }
    const returnedJob = {
      ...job,
      task_id: 'b0000000-0000-4000-8000-00000000000b',
      status: 'failed' as const,
      attempt: 2,
      failure_code: 'node_unavailable',
      completed_at: '2026-07-22T08:03:00Z',
      updated_at: '2026-07-22T08:03:00Z',
      progress: { ...job.progress, completed: 2, failed: 1, pending: 0 },
      related_resource: { reference: 'site:returned-task.test' },
      request_id: 'private-same-tenant-wrong-task',
    }
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [selectedJob], page: {}, query: { from: params.from, to: params.to },
    }))
    const detail = vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: returnedJob })
    vi.spyOn(jobsApi, 'attempts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'results').mockResolvedValue({ data: [], page: {} })
    const cancel = vi.spyOn(jobsApi, 'cancel')
    const retry = vi.spyOn(jobsApi, 'retry')
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '子任务详情' })

    expect(await within(drawer).findByText('任务详情加载失败')).toBeInTheDocument()
    expect(within(drawer).getByText('服务响应无效，请稍后重试')).toBeInTheDocument()
    expect(drawer).not.toHaveTextContent(/site:returned-task\.test/)
    expect(drawer).not.toHaveTextContent(/b0000000|private-same-tenant-wrong-task/)
    expect(within(drawer).queryByRole('button', {
      name: /取消任务|重试失败任务|使用同一请求重试/,
    })).not.toBeInTheDocument()
    expect(detail).toHaveBeenCalledWith('tenant-wrong-task-token', 'tenant', selectedJob.task_id)
    expect(cancel).not.toHaveBeenCalled()
    expect(retry).not.toHaveBeenCalled()
  })

  it('treats a foreign cancellation response as unknown and retries it with the newest token and exact request', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    const { epoch } = tenantSession('tenant-cancel-token-a', scopeID)
    const runningJob = { ...job, related_resource: { reference: 'site:cancel-owner.test' } }
    const cancelledJob = {
      ...runningJob,
      status: 'cancelled' as const,
      failure_code: 'cancelled',
      completed_at: '2026-07-22T08:03:00Z',
      updated_at: '2026-07-22T08:03:00Z',
      progress: { ...runningJob.progress, completed: 2, cancelled: 1, pending: 0 },
    }
    const cancel = vi.spyOn(jobsApi, 'cancel')
      .mockResolvedValueOnce({
        data: { ...cancelledJob, tenant_id: '99999999-9999-4999-8999-999999999999' },
        replayed: false,
      })
      .mockResolvedValueOnce({ data: cancelledJob, replayed: true })
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [runningJob], page: {}, query: { from: params.from, to: params.to },
    }))
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/task'])
    await user.click(await screen.findByRole('button', { name: '取消任务' }))
    await user.click(within((await screen.findByText('确认取消任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))

    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByText('任务取消请求已提交')).not.toBeInTheDocument()
    act(() => tenantSession('tenant-cancel-token-b', scopeID, undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('任务取消请求已提交')).toBeInTheDocument()

    expect(cancel.mock.calls.map(([token]) => token)).toEqual([
      'tenant-cancel-token-a', 'tenant-cancel-token-b',
    ])
    expect(cancel.mock.calls[1]?.slice(1)).toEqual(cancel.mock.calls[0]?.slice(1))
  })

  it('treats a foreign retry response as unknown and retries it with the newest token and exact request', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    const { epoch } = tenantSession('tenant-retry-token-a', scopeID)
    const failedJob = {
      ...job,
      status: 'failed' as const,
      attempt: 2,
      failure_code: 'node_unavailable',
      completed_at: '2026-07-22T08:03:00Z',
      updated_at: '2026-07-22T08:03:00Z',
      progress: { ...job.progress, completed: 2, failed: 1, pending: 0 },
    }
    const queuedJob = {
      ...failedJob,
      status: 'queued' as const,
      failure_code: undefined,
      completed_at: undefined,
      started_at: undefined,
      updated_at: '2026-07-22T08:04:00Z',
      progress: { total: 2, completed: 0, succeeded: 0, failed: 0, cancelled: 0, pending: 2 },
    }
    const retry = vi.spyOn(jobsApi, 'retry')
      .mockResolvedValueOnce({
        data: { ...queuedJob, tenant_id: '99999999-9999-4999-8999-999999999999' },
        replayed: false,
      })
      .mockResolvedValueOnce({ data: queuedJob, replayed: true })
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [failedJob], page: {}, query: { from: params.from, to: params.to },
    }))
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText('确认重试任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))

    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByText('任务已重新入队')).not.toBeInTheDocument()
    act(() => tenantSession('tenant-retry-token-b', scopeID, undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()

    expect(retry.mock.calls.map(([token]) => token)).toEqual([
      'tenant-retry-token-a', 'tenant-retry-token-b',
    ])
    expect(retry.mock.calls[1]?.slice(1)).toEqual(retry.mock.calls[0]?.slice(1))
  })

  it('keeps token-free owner cache and every open tenant task state stable across a token refresh', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    const { actor, epoch } = tenantSession('tenant-stable-token-a', scopeID)
    const failedJob = {
      ...job,
      status: 'failed' as const,
      attempt: 2,
      failure_code: 'node_unavailable',
      completed_at: '2026-07-22T08:03:00Z',
      updated_at: '2026-07-22T08:03:00Z',
      progress: { ...job.progress, completed: 2, failed: 1, pending: 0 },
      related_resource: { reference: 'site:stable-tenant.test' },
    }
    const list = vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [failedJob],
      page: params.cursor ? {} : { next_cursor: 'tenant-list-page-2' },
      query: { from: params.from, to: params.to },
    }))
    const detail = vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: failedJob })
    const attempts = vi.spyOn(jobsApi, 'attempts').mockImplementation(
      async (_token, _audience, _id, _limit, cursor) => ({
        data: [], page: cursor ? {} : { next_cursor: 'tenant-attempt-page-2' },
      }),
    )
    const results = vi.spyOn(jobsApi, 'results').mockImplementation(
      async (_token, _audience, _id, _limit, cursor) => ({
        data: [], page: cursor ? {} : { next_cursor: 'tenant-result-page-2' },
      }),
    )
    const retry = vi.spyOn(jobsApi, 'retry')
      .mockRejectedValueOnce(new ApiError('private old token endpoint', 0, 'network_error'))
      .mockResolvedValueOnce({
        data: {
          ...failedJob,
          status: 'queued',
          failure_code: undefined,
          completed_at: undefined,
          started_at: undefined,
          progress: { total: 2, completed: 0, succeeded: 0, failed: 0, cancelled: 0, pending: 2 },
        },
        replayed: true,
      })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    const owner = ownerTuple(actor, epoch)

    renderTenantTasksWithQueryClient(queryClient)
    await screen.findByText('site:stable-tenant.test')
    await user.type(screen.getByRole('combobox', { name: '任务类型' }), 'cache.refresh')
    await user.type(screen.getByLabelText('资源标识'), 'site:stable-tenant.test')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    await user.click(screen.getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '子任务详情' })
    await user.click(await within(drawer).findByRole('button', { name: '下一页尝试记录' }))
    await user.click(await within(drawer).findByRole('button', { name: '下一页逐项结果' }))
    await user.click(within(drawer).getByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText('确认重试任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()

    const readsBeforeRefresh = [list, detail, attempts, results].map((spy) => spy.mock.calls.length)
    const keysBeforeRefresh = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(keysBeforeRefresh).toContainEqual([
      'jobs', ...owner, 'tenant', expect.objectContaining({
        kind: 'cache.refresh', resource: 'site:stable-tenant.test',
      }), 10, 'tenant-list-page-2',
    ])
    expect(keysBeforeRefresh).toContainEqual(['job', ...owner, 'tenant', failedJob.task_id])
    expect(keysBeforeRefresh).toContainEqual([
      'job-attempts', ...owner, 'tenant', failedJob.task_id, 'tenant-attempt-page-2',
    ])
    expect(keysBeforeRefresh).toContainEqual([
      'job-results', ...owner, 'tenant', failedJob.task_id, 'tenant-result-page-2',
    ])
    expect(queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey))
      .toContainEqual(['job-command', ...owner, 'tenant'])

    act(() => tenantSession('tenant-stable-token-b', scopeID, undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect([list, detail, attempts, results].map((spy) => spy.mock.calls.length)).toEqual(readsBeforeRefresh)
    expect(screen.getByRole('combobox', { name: '任务类型' })).toHaveValue('cache.refresh')
    expect(screen.getByLabelText('资源标识')).toHaveValue('site:stable-tenant.test')
    expect(within(document.querySelector('.jobs-pagination') as HTMLElement)
      .getByText('第 2 页')).toBeInTheDocument()
    expect(within(drawer).getAllByText('第 2 页')).toHaveLength(2)
    expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toEqual(keysBeforeRefresh)

    await act(async () => {
      await Promise.all([
        queryClient.refetchQueries({ queryKey: ['jobs', ...owner, 'tenant'] }),
        queryClient.refetchQueries({ queryKey: ['job', ...owner, 'tenant'] }),
        queryClient.refetchQueries({ queryKey: ['job-attempts', ...owner, 'tenant'] }),
        queryClient.refetchQueries({ queryKey: ['job-results', ...owner, 'tenant'] }),
      ])
    })
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()

    for (const spy of [list, detail, attempts, results]) {
      expect(spy.mock.calls.at(-1)?.[0]).toBe('tenant-stable-token-b')
    }
    expect(list.mock.calls.every(([, , params]) => params.limit === 10)).toBe(true)
    expect(attempts.mock.calls.every(([, , , limit]) => limit === 20)).toBe(true)
    expect(results.mock.calls.every(([, , , limit]) => limit === 10)).toBe(true)
    expect(retry.mock.calls.map(([token]) => token)).toEqual([
      'tenant-stable-token-a', 'tenant-stable-token-b',
    ])
    expect(retry.mock.calls[1]?.slice(1)).toEqual(retry.mock.calls[0]?.slice(1))
    const allIdentities = JSON.stringify({
      queries: queryClient.getQueryCache().getAll().map((query) => query.queryKey),
      mutations: queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey),
    })
    expect(allIdentities).not.toContain('tenant-stable-token-')
    expect(document.body).not.toHaveTextContent(/tenant-stable-token-[ab]/)
  })

  it.each(['success', 'error'] as const)(
    'resets the 31-day root state and isolates late list/detail %s on a new tenant identity',
    async (outcome) => {
    const scopeA = '22222222-2222-4222-8222-222222222222'
    const scopeB = '99999999-9999-4999-8999-999999999999'
    const sessionA = tenantSession('tenant-read-token-a', scopeA)
    const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
    const jobA = {
      ...job,
      task_id: 'a0000000-0000-4000-8000-00000000000a',
      tenant_id: tenantFor(scopeA),
      related_resource: { reference: 'site:a.test' },
    }
    const jobB = {
      ...job,
      task_id: 'b0000000-0000-4000-8000-00000000000b',
      tenant_id: tenantFor(scopeB),
      related_resource: { reference: 'site:b.test' },
    }
    const lateList = deferred<Awaited<ReturnType<typeof jobsApi.list>>>()
    const lateDetail = deferred<Awaited<ReturnType<typeof jobsApi.detail>>>()
    let aListReads = 0
    let aDetailReads = 0
    vi.spyOn(jobsApi, 'list').mockImplementation(async (token, _audience, params) => {
      if (token === 'tenant-read-token-b') {
        return { data: [jobB], page: {}, query: { from: params.from, to: params.to } }
      }
      aListReads += 1
      if (aListReads >= 4) return lateList.promise
      return {
        data: [jobA], page: params.cursor ? {} : { next_cursor: 'tenant-a-page-2' },
        query: { from: params.from, to: params.to },
      }
    })
    vi.spyOn(jobsApi, 'detail').mockImplementation((token) => {
      if (token !== 'tenant-read-token-a') return Promise.resolve({ data: jobB })
      aDetailReads += 1
      return aDetailReads === 1 ? Promise.resolve({ data: jobA }) : lateDetail.promise
    })
    vi.spyOn(jobsApi, 'attempts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'results').mockResolvedValue({ data: [], page: {} })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderTenantTasksWithQueryClient(queryClient)
    await screen.findByText('site:a.test')
    await user.type(screen.getByRole('combobox', { name: '任务类型' }), 'cache.refresh')
    await user.type(screen.getByLabelText('资源标识'), 'site:a.test')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByRole('dialog', { name: '子任务详情' })).toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog', { name: '子任务详情' }))
      .getByRole('button', { name: '取消任务' }))
    expect(await screen.findByText('确认取消任务')).toBeInTheDocument()
    const ownerAFamilies = queryClient.getQueryCache().getAll()
      .filter((query) => query.queryKey.slice(1, 6)
        .every((value, index) => value === ownerA[index]))
      .map((query) => query.queryKey[0])
    expect(new Set(ownerAFamilies)).toEqual(new Set([
      'job-kinds', 'jobs', 'job', 'job-attempts', 'job-results', 'job-dead-letters', 'job-receipts',
    ]))
    act(() => {
      void queryClient.invalidateQueries({
        queryKey: ['job', ...ownerA, 'tenant'],
      })
    })
    await waitFor(() => expect(aDetailReads).toBe(2))
    act(() => {
      void queryClient.invalidateQueries({
        queryKey: ['jobs', ...ownerA, 'tenant'],
      })
    })
    await waitFor(() => expect(aListReads).toBeGreaterThanOrEqual(4))

    act(() => tenantSession('tenant-read-token-b', scopeB))
    expect(await screen.findByText('site:b.test')).toBeInTheDocument()
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '任务类型' })).toHaveValue('')
    expect(screen.getByLabelText('资源标识')).toHaveValue('')
    expect(screen.queryByRole('dialog', { name: '子任务详情' })).not.toBeInTheDocument()
    expect(screen.queryByText('确认取消任务')).not.toBeInTheDocument()
    const resetParams = vi.mocked(jobsApi.list).mock.calls.filter(([token]) => token === 'tenant-read-token-b').at(-1)![2]
    expect(resetParams.kind).toBeUndefined()
    expect(resetParams.resource).toBeUndefined()
    expect(Date.parse(resetParams.to) - Date.parse(resetParams.from)).toBe(31 * 24 * 60 * 60 * 1000)

    await act(async () => {
      const settlements = Promise.allSettled([lateList.promise, lateDetail.promise])
      if (outcome === 'success') {
        lateList.resolve({ data: [jobA], page: {}, query: { from: '', to: '' } })
        lateDetail.resolve({ data: jobA })
      } else {
        lateList.reject(new ApiError(
          'private tenant A list database detail', 500, 'job_store_unavailable', 'tenant-a-list',
        ))
        lateDetail.reject(new ApiError(
          'private tenant A detail record', 500, 'job_store_unavailable', 'tenant-a-detail',
        ))
      }
      await settlements
    })
    expect(screen.getByText('site:b.test')).toBeInTheDocument()
    expect(screen.queryByText('site:a.test')).not.toBeInTheDocument()
    expect(screen.getByTestId('jobs-table-scroll')).toHaveAttribute('aria-busy', 'false')
    expect(screen.queryByText('后台任务加载失败')).not.toBeInTheDocument()
    expect(screen.queryByText('任务详情加载失败')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/private tenant A (?:list database detail|detail record)/)
    const currentEpoch = useSessionStore.getState().sessionEpoch
    const currentActor = useSessionStore.getState().principal!
    const ownerB = ownerTuple(currentActor, currentEpoch)
    const tenantBQueries = queryClient.getQueryCache().findAll({
      predicate: (query) => query.queryKey.slice(1, 6).every((value, index) => value === ownerB[index]),
    })
    expect(tenantBQueries.length).toBeGreaterThan(0)
    for (const query of tenantBQueries) {
      expect(query.state.error).toBeNull()
      expect(query.state.fetchStatus).toBe('idle')
      expect(JSON.stringify(query.state.data ?? null)).not.toContain(jobA.task_id)
    }
    const keys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(keys.some((key) => key.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
    expect(keys.some((key) => key.slice(1, 6).every((value, index) => value === ownerB[index]))).toBe(true)
    expect(JSON.stringify(keys)).not.toContain('tenant-read-token-')
    expect(document.body).not.toHaveTextContent(/tenant-read-token-[ab]/)
    },
  )

  it('clears an old tenant unknown-retry state and its mutation cache on a new owner session', async () => {
    const scopeA = '22222222-2222-4222-8222-222222222222'
    const scopeB = '99999999-9999-4999-8999-999999999999'
    const sessionA = tenantSession('tenant-unknown-token-a', scopeA)
    const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
    const failedJobA = {
      ...job,
      tenant_id: tenantFor(scopeA),
      status: 'failed' as const,
      attempt: 2,
      failure_code: 'node_unavailable',
      completed_at: '2026-07-22T08:03:00Z',
      updated_at: '2026-07-22T08:03:00Z',
      progress: { ...job.progress, completed: 2, failed: 1, pending: 0 },
      related_resource: { reference: 'site:unknown-a.test' },
    }
    const failedJobB = {
      ...failedJobA,
      task_id: 'b0000000-0000-4000-8000-00000000000b',
      tenant_id: tenantFor(scopeB),
      related_resource: { reference: 'site:unknown-b.test' },
    }
    vi.spyOn(jobsApi, 'list').mockImplementation(async (token, _audience, params) => ({
      data: [token === 'tenant-unknown-token-a' ? failedJobA : failedJobB],
      page: {},
      query: { from: params.from, to: params.to },
    }))
    vi.spyOn(jobsApi, 'retry')
      .mockRejectedValue(new ApiError('private tenant A endpoint', 0, 'network_error'))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderTenantTasksWithQueryClient(queryClient)
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText('确认重试任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey))
      .toContainEqual(['job-command', ...ownerA, 'tenant'])

    act(() => tenantSession('tenant-unknown-token-b', scopeB))

    expect(await screen.findByText('site:unknown-b.test')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/site:unknown-a\.test|private tenant A endpoint/)
    expect(queryClient.getMutationCache().getAll().some((mutation) =>
      mutation.options.mutationKey?.slice(1, 6)
        .every((value, index) => value === ownerA[index]))).toBe(false)
  })

  it.each(['success', 'error'] as const)(
    'removes an old tenant command mutation and isolates its delayed %s settlement on a new session',
    async (outcome) => {
      const scopeA = '22222222-2222-4222-8222-222222222222'
      const scopeB = '99999999-9999-4999-8999-999999999999'
      const sessionA = tenantSession('tenant-command-token-a', scopeA)
      const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
      const failedJobA = {
        ...job,
        tenant_id: tenantFor(scopeA),
        status: 'failed' as const,
        attempt: 2,
        failure_code: 'node_unavailable',
        completed_at: '2026-07-22T08:03:00Z',
        updated_at: '2026-07-22T08:03:00Z',
        progress: { ...job.progress, completed: 2, failed: 1, pending: 0 },
        related_resource: { reference: 'site:command-a.test' },
      }
      const failedJobB = {
        ...failedJobA,
        task_id: 'b0000000-0000-4000-8000-00000000000b',
        tenant_id: tenantFor(scopeB),
        related_resource: { reference: 'site:command-b.test' },
      }
      vi.spyOn(jobsApi, 'list').mockImplementation(async (token, _audience, params) => ({
        data: [token === 'tenant-command-token-a' ? failedJobA : failedJobB],
        page: {},
        query: { from: params.from, to: params.to },
      }))
      const delayedCommand = deferred<Awaited<ReturnType<typeof jobsApi.retry>>>()
      vi.spyOn(jobsApi, 'retry').mockReturnValue(delayedCommand.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      const user = userEvent.setup()

      renderTenantTasksWithQueryClient(queryClient)
      await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
      await user.click(within((await screen.findByText('确认重试任务')).closest<HTMLElement>('[role="dialog"]')!)
        .getByRole('button', { name: '确认' }))
      expect(queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey))
        .toContainEqual(['job-command', ...ownerA, 'tenant'])

      act(() => tenantSession('tenant-command-token-b', scopeB))
      expect(await screen.findByText('site:command-b.test')).toBeInTheDocument()
      await waitFor(() => {
        expect(queryClient.getMutationCache().getAll().some((mutation) =>
          mutation.options.mutationKey?.slice(1, 6)
            .every((value, index) => value === ownerA[index]))).toBe(false)
      })
      invalidate.mockClear()

      await act(async () => {
        if (outcome === 'success') {
          delayedCommand.resolve({
            data: {
              ...failedJobA,
              status: 'queued',
              failure_code: undefined,
              completed_at: undefined,
              started_at: undefined,
              progress: { total: 2, completed: 0, succeeded: 0, failed: 0, cancelled: 0, pending: 2 },
            },
            replayed: false,
          })
        } else {
          delayedCommand.reject(new ApiError('private old tenant command', 0, 'network_error'))
        }
        await Promise.resolve()
      })

      expect(screen.getByText('site:command-b.test')).toBeInTheDocument()
      expect(screen.queryByText('任务已重新入队')).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      expect(document.body).not.toHaveTextContent('private old tenant command')
      expect(invalidate).not.toHaveBeenCalled()
      expect(queryClient.getQueryCache().getAll().some((query) =>
        query.queryKey.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
    },
  )

  it.each(['en-US', 'qps-ploc'] as const)(
    'localizes %s error, retry, empty, and 403 states without raw server messages',
    async (locale) => {
      await changeLocale(locale)
      authenticateTenant(['jobs.read'])
      const t = i18n.getFixedT(locale, 'jobs')
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(json({
          error: { code: 'job_store_unavailable', message: 'private tenant database' },
        }, 503))
        .mockResolvedValueOnce(json({
          data: [],
          page: {},
          query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
        }))
      const user = userEvent.setup()

      const first = renderWithProviders(<AdminTasksPage />, ['/task'])
      expect(await screen.findByText(t('errors.listLoadFailed'))).toBeInTheDocument()
      expect(screen.getByText(t('errors.job_store_unavailable'))).toBeInTheDocument()
      expect(screen.queryByText('private tenant database')).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: t('actions.retry') }))
      expect(await screen.findByText(t('values.empty'))).toBeInTheDocument()
      first.unmount()

      fetchSpy.mockReset().mockResolvedValue(json({
        error: { code: 'job_permission_denied', message: 'private tenant RBAC row' },
      }, 403))
      authenticateTenant(['jobs.read'])
      renderWithProviders(<AdminTasksPage />, ['/task'])
      expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
      expect(screen.getByText(t('errors.job_permission_denied'))).toBeInTheDocument()
      expect(screen.queryByText('private tenant RBAC row')).not.toBeInTheDocument()
    },
  )
})
