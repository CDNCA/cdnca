import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { jobsApi, type BackgroundJob } from '../api/jobs'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import AdminTasksPage from '../pages/AdminTasksPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import adminTasksStyles from '../pages/AdminTasksPage.css?raw'

// antd 测试环境所有 Modal 的 aria-labelledby 都是 test-id，可访问名取的是 DOM 里第一个 test-id（常是反馈弹窗标题）；
// 业务弹窗按自身标题匹配，并排除反馈弹窗（.cdnca-feedback）
const pageDialogs = (name?: string) => screen.queryAllByRole('dialog')
  .filter((element) => !element.classList.contains('cdnca-feedback'))
  .filter((element) => name === undefined || element.querySelector('.ant-modal-title, .ant-drawer-title')?.textContent?.trim() === name)
const pageDialog = (name: string) => { const [element] = pageDialogs(name); if (!element) throw new Error(`no dialog ${name}`); return element }

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const job: BackgroundJob = {
  task_id: 'a0000000-0000-4000-8000-000000000001',
  tenant_id: 'b0000000-0000-4000-8000-000000000002',
  kind: 'cache.purge',
  related_resource: { reference: 'site:example.test' },
  request_id: 'request-1',
  trace_id: 'trace-1',
  status: 'partial_failed',
  attempt: 2,
  max_attempts: 3,
  progress: { total: 3, completed: 3, succeeded: 2, failed: 1, cancelled: 0, pending: 0 },
  failure_code: 'node_unavailable',
  created_at: '2026-07-22T08:00:00Z',
  started_at: '2026-07-22T08:01:00Z',
  updated_at: '2026-07-22T08:02:00Z',
  completed_at: '2026-07-22T08:02:00Z',
	revision: '7',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function authenticateAdmin(permissions = ['jobs.read_all']) {
  const actor = principal({
    scope_kind: 'platform',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_admin'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function jobResponse(
  input: RequestInfo | URL,
  currentJob: BackgroundJob = job,
  failureCodes = { attempt: 'node_unavailable', result: 'node_unavailable' },
): Response {
  const url = new URL(String(input), 'https://web.test')
  if (url.pathname.endsWith('/attempts')) {
    return json({
      data: [{
        number: 2,
        status: 'lease_expired',
        started_at: '2026-07-22T08:01:00Z',
        last_heartbeat_at: '2026-07-22T08:01:30Z',
        lease_expires_at: '2026-07-22T08:02:30Z',
        completed_at: '2026-07-22T08:02:00Z',
        failure_code: failureCodes.attempt,
      }],
      page: {},
    })
  }
  if (url.pathname.endsWith('/results')) {
    return json({
      data: [{
        ordinal: 1,
        item_id: 'node-1',
        node_id: 'c0000000-0000-4000-8000-000000000003',
        status: 'failed',
        attempt: 2,
        sequence: 4,
        failure_code: failureCodes.result,
        completed_at: '2026-07-22T08:02:00Z',
      }],
      page: {},
    })
  }
  if (url.pathname.endsWith('/receipts')) {
    return json({
      data: [],
      page: {},
    })
  }
  if (url.pathname.endsWith('/dead-letters')) {
    return json({
      data: [],
      page: {},
    })
  }
  if (url.pathname === `/v1/admin/jobs/${currentJob.task_id}`) return json({ data: currentJob })
  return json({
    data: [currentJob],
    page: { next_cursor: 'cursor-page-2' },
    query: {
      from: url.searchParams.get('from'),
      to: url.searchParams.get('to'),
    },
  })
}

function withStatus(status: BackgroundJob['status'], attempt = job.attempt): BackgroundJob {
  const value = { ...job, status, attempt }
  if (status === 'queued' || status === 'running') {
    delete value.completed_at
  }
  if (status === 'queued' || status === 'running' || status === 'succeeded') {
    delete value.failure_code
  } else if (status === 'cancelled') {
    value.failure_code = 'cancelled'
  }
  return value
}

function queuedFrom(source: BackgroundJob): BackgroundJob {
  const queued: BackgroundJob = {
    ...source,
    status: 'queued',
    progress: {
      total: source.progress.total,
      completed: 0,
      succeeded: 0,
      failed: 0,
      cancelled: 0,
      pending: source.progress.total,
    },
  }
  delete queued.failure_code
  delete queued.started_at
  delete queued.completed_at
  return queued
}

function renderTasksWithQueryClient(queryClient: QueryClient, path = '/sys/task') {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[path]}><AdminTasksPage /></MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function adminSession(
  token: string,
  permissions = ['jobs.read_all', 'jobs.manage_all'],
  update: 'new' | 'refresh' = 'new',
  scopeID = '22222222-2222-4222-8222-222222222222',
) {
  const actor = principal({
    scope_id: scopeID,
    scope_kind: 'platform',
    tenant_id: null,
    username: `admin-${scopeID.slice(0, 4)}`,
    display_name: 'admin',
    roles: ['platform_admin'],
    permissions,
  })
  useSessionStore.getState().setSession(
    { ...authResponse(actor), access_token: token },
    actor,
    update,
  )
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

function allJobsApiSpies() {
  return [
    vi.spyOn(jobsApi, 'kinds'),
    vi.spyOn(jobsApi, 'list'),
    vi.spyOn(jobsApi, 'detail'),
    vi.spyOn(jobsApi, 'attempts'),
    vi.spyOn(jobsApi, 'results'),
    vi.spyOn(jobsApi, 'receipts'),
    vi.spyOn(jobsApi, 'deadLetters'),
    vi.spyOn(jobsApi, 'cancel'),
    vi.spyOn(jobsApi, 'retry'),
  ]
}

describe('AdminTasksPage', () => {
  beforeEach(() => {
    vi.spyOn(jobsApi, 'kinds').mockResolvedValue({ data: [] })
  })

  it('makes zero jobs calls while unauthenticated', () => {
    const apiSpies = allJobsApiSpies()

    const { container } = renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(container.querySelector('.jobs-page')).not.toBeInTheDocument()
    expect(screen.queryByTestId('jobs-table-scroll')).not.toBeInTheDocument()
    expect(screen.queryByText('无权查看后台任务')).not.toBeInTheDocument()
    for (const spy of apiSpies) expect(spy).not.toHaveBeenCalled()
  })

  it('keeps the table stable while loading and then renders the empty state', async () => {
    authenticateAdmin()
    let resolveResponse!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise((resolve) => {
      resolveResponse = resolve
    }))

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(screen.getByTestId('jobs-table-scroll')).toHaveAttribute('aria-busy', 'true')
    resolveResponse(json({
      data: [], page: {}, query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
    }))
    expect(await screen.findByText('暂无后台任务')).toBeInTheDocument()
    expect(screen.getByTestId('jobs-table-scroll')).toHaveAttribute('aria-busy', 'false')
    const user = userEvent.setup()
    await user.click(screen.getByRole('combobox', { name: '任务类型' }))
    expect(await screen.findByTitle('—')).toBeInTheDocument()
  })

  it('localizes a transient list error and retries without exposing server detail', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        error: { code: 'job_store_unavailable', message: 'private database hostname', request_id: 'jobs-list-1' },
      }, 503))
      .mockResolvedValueOnce(json({
        data: [], page: {}, query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
      }))
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('后台任务加载失败')).toBeInTheDocument()
    expect(screen.getByText(/任务存储暂不可用，请稍后重试/)).toBeInTheDocument()
    expect(screen.queryByText('private database hostname')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无后台任务')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('fails closed when bulk cancel selection contains no cancellable jobs', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    const completedJob = withStatus('succeeded', 2)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) =>
      Promise.resolve(jobResponse(input, completedJob)),
    )
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('成功')).toBeInTheDocument()
    const checkboxes = screen.getAllByRole('checkbox')
    expect(checkboxes.length).toBeGreaterThan(1)
    await user.click(checkboxes.at(-1)!)
    await user.click(screen.getByRole('button', { name: '批量操作' }))

    expect(await screen.findByText('请先选择要取消的任务。')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '确认批量取消任务' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('bulk cancels through a default danger button only after the confirmation dialog', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    const queuedJob = withStatus('queued', 1)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) =>
      Promise.resolve(init?.method === 'POST'
        ? json({ data: withStatus('cancelled', 1) })
        : jobResponse(input, queuedJob)),
    )
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('待执行')).toBeInTheDocument()
    const bulkCancel = screen.getByRole('button', { name: '批量操作' })
    expect(bulkCancel).toHaveClass('ant-btn-default', 'ant-btn-dangerous')
    expect(bulkCancel).not.toHaveClass('ant-btn-primary')
    await user.click(screen.getAllByRole('checkbox').at(-1)!)
    await user.click(bulkCancel)

    const dialog = await screen.findByRole('dialog', { name: '确认批量取消任务' })
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1))
  })

  it('reports a partly failed bulk cancel item by item and retries only the failed ones (COV-04)', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    const first = { ...withStatus('queued', 1), task_id: 'a0000000-0000-4000-8000-0000000000a1' }
    const second = { ...withStatus('queued', 1), task_id: 'a0000000-0000-4000-8000-0000000000a2' }
    const third = { ...withStatus('queued', 1), task_id: 'a0000000-0000-4000-8000-0000000000a3' }
    const cancelled = new Set<string>()
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [first, second, third].map((item) => cancelled.has(item.task_id) ? { ...withStatus('cancelled', 1), task_id: item.task_id } : item),
      page: {}, query: { from: params.from, to: params.to },
    }))
    let failSecond = true
    const cancel = vi.spyOn(jobsApi, 'cancel').mockImplementation(async (_token, _audience, taskID) => {
      if (taskID === second.task_id && failSecond) throw new ApiError('private', 409, 'job_revision_conflict')
      cancelled.add(taskID)
      return { data: { ...withStatus('cancelled', 1), task_id: taskID }, replayed: false }
    })
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await screen.findByText(third.task_id)
    // 表头全选框之外的三行。
    for (const box of screen.getAllByRole('checkbox').slice(1)) await user.click(box)
    await user.click(screen.getByRole('button', { name: '批量操作' }))
    await user.click(within(await screen.findByRole('dialog', { name: '确认批量取消任务' })).getByRole('button', { name: '确认' }))

    const outcome = await screen.findByTestId('jobs-bulk-cancel-outcome')
    // 第二项失败不打断第三项。
    expect(cancel.mock.calls.map(([, , taskID]) => taskID)).toEqual([first.task_id, second.task_id, third.task_id])
    expect(outcome).toHaveTextContent('已取消 2 个，失败 1 个')
    expect(outcome).toHaveTextContent(second.task_id)
    expect(outcome).not.toHaveTextContent('private')
    expect(screen.queryByText('任务已取消')).not.toBeInTheDocument()

    failSecond = false
    await user.click(within(outcome).getByRole('button', { name: '重试失败项' }))
    await waitFor(() => expect(cancel).toHaveBeenCalledTimes(4))
    expect(cancel.mock.calls[3]![2]).toBe(second.task_id)
    await waitFor(() => expect(screen.queryByTestId('jobs-bulk-cancel-outcome')).not.toBeInTheDocument())
  })

  it('queries, filters, cursor-pages, and opens fact-backed task details', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      (input) => Promise.resolve(jobResponse(input)),
    )
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('cache.purge')).toBeInTheDocument()
    expect(screen.getByText('部分失败')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '资源 ID' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '失败次数' })).toBeInTheDocument()
    expect(within(screen.getByRole('row', { name: /cache\.purge/ })).getByText('1')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '优先级' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '名称' })).not.toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '依赖' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '创建时间' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '进度' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '尝试次数' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '租户 ID' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /取消任务|重试任务/ })).not.toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '每页条数' }))
    await user.click(await screen.findByTitle('20 条/页'))
    await waitFor(() => {
      const listCalls = fetchSpy.mock.calls.filter(([input]) => String(input).startsWith('/v1/admin/jobs?'))
      const url = new URL(String(listCalls.at(-1)?.[0]), 'https://web.test')
      expect(url.searchParams.get('limit')).toBe('20')
    })

    await user.click(screen.getByRole('combobox', { name: '任务状态' }))
    expect(screen.getByTitle('成功')).toBeInTheDocument()
    expect(screen.getByTitle('待执行')).toBeInTheDocument()
    expect(screen.getByTitle('执行中')).toBeInTheDocument()
    expect(screen.queryByTitle('已取消')).not.toBeInTheDocument()
    await user.click(await screen.findByTitle('失败'))
    await user.type(screen.getByRole('combobox', { name: '任务类型' }), 'cache.refresh')
    await user.type(screen.getByLabelText('资源标识'), 'site:filtered.test')
    await user.click(screen.getByRole('button', { name: '查询' }))

    await waitFor(() => {
      const listCalls = fetchSpy.mock.calls.filter(([input]) => String(input).startsWith('/v1/admin/jobs?'))
      const url = new URL(String(listCalls.at(-1)?.[0]), 'https://web.test')
      expect(url.searchParams.get('status')).toBe('failed,partial_failed')
      expect(url.searchParams.get('kind')).toBe('cache.refresh')
      expect(url.searchParams.get('resource')).toBe('site:filtered.test')
    })

    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => {
      const listCalls = fetchSpy.mock.calls.filter(([input]) => String(input).startsWith('/v1/admin/jobs?'))
      const url = new URL(String(listCalls.at(-1)?.[0]), 'https://web.test')
      expect(url.searchParams.get('cursor')).toBe('cursor-page-2')
    })
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '上一页' }))
    expect(await screen.findByText('第 1 页')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    expect(await within(drawer).findByText('执行进度')).toBeInTheDocument()
    expect(within(drawer).getByText('租约已过期')).toBeInTheDocument()
    expect(within(drawer).getByText('node-1')).toBeInTheDocument()
    expect(within(drawer).getAllByText('节点暂不可用')).toHaveLength(3)
    expect(within(drawer).queryByText('node_unavailable')).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).endsWith(`/${job.task_id}`))).toBe(true)
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes(`/${job.task_id}/attempts?`))).toBe(true)
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes(`/${job.task_id}/results?`))).toBe(true)
  })

  it('localizes the task type in details, marks unknown types with their raw code, and drops the subtask title', async () => {
    authenticateAdmin()
    vi.spyOn(jobsApi, 'kinds').mockResolvedValue({ data: [{
      kind: 'edge.publication', name_key: 'jobs.kindNames.edgePublication', integration: 'integrated', runtime_status: 'unknown',
    }] })
    const publication: BackgroundJob = { ...job, kind: 'edge.publication' }
    let current = publication
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jobResponse(input, current)))
    const user = userEvent.setup()
    const view = renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('节点配置发布')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    expect(screen.queryByRole('dialog', { name: '子任务详情' })).not.toBeInTheDocument()
    const kindCell = await within(drawer).findByText('节点配置发布')
    expect(kindCell).toBeInTheDocument()
    expect(within(drawer).queryByText('edge.publication')).not.toBeInTheDocument()
    view.unmount()

    current = { ...job, kind: 'future.kind' }
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const unknownDrawer = await screen.findByRole('dialog', { name: '任务详情' })
    const unknown = await within(unknownDrawer).findByText('未知任务类型', { exact: false })
    expect(unknown.closest('.jobs-detail-kind-unknown')).toHaveTextContent('future.kind')
  })

  it('uses a neutral dash for empty facts, lists the task ID once, and keeps producer-managed scheduling out of the rows', async () => {
    authenticateAdmin()
    const sameResource: BackgroundJob = { ...withStatus('succeeded', 1), related_resource: { reference: job.task_id }, trace_id: undefined }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === '/v1/admin/jobs') {
        return Promise.resolve(json({
          data: [sameResource],
          // 任务元数据只随编号分页返回；游标页带元数据按契约整页拒收
          page: { number: 1, limit: Number(url.searchParams.get('limit')), total: 1, total_pages: 1, consistency: 'request_snapshot' },
          query: { from: url.searchParams.get('from'), to: url.searchParams.get('to') },
          task_metadata: [{
            task_id: sameResource.task_id,
            name: { name_key: 'jobs.kindNames.unknown', resource: sameResource.related_resource.reference, source: 'derived' },
            priority: { policy: 'producer_managed' },
            dependencies: { state: 'unknown', items: [] },
          }],
        }))
      }
      return Promise.resolve(jobResponse(input, sameResource))
    })
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    const row = (await screen.findByText('cache.purge')).closest('tr')!
    expect(within(row).getAllByText(job.task_id)).toHaveLength(1)
    expect(screen.queryByRole('columnheader', { name: '优先级' })).not.toBeInTheDocument()
    expect(screen.queryByText('由任务生产方调度')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无事实')).not.toBeInTheDocument()

    await user.click(within(row).getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    expect(await within(drawer).findByText('由任务生产方调度')).toBeInTheDocument()
    expect(within(drawer).queryByText('暂无事实')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('失败代码', { selector: '.ant-descriptions-item-label' })).not.toBeInTheDocument()
    expect(within(drawer).getAllByText('—').length).toBeGreaterThan(0)
  })

  it('shows stable server denial without leaking its English message', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: {
        code: 'job_permission_denied',
        message: 'private role graph detail',
        request_id: 'jobs-denied-1',
      },
    }, 403))

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('无权查看后台任务')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少后台任务读取权限')).toBeInTheDocument()
    expect(screen.queryByText('private role graph detail')).not.toBeInTheDocument()
  })

  it('uses task management guidance for a denied command without changing read denial guidance', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
        return Promise.resolve(json({
          error: { code: 'job_permission_denied', message: 'private role graph detail' },
        }, 403))
      }
      return Promise.resolve(jobResponse(input, withStatus('failed', 2)))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: /^确认重试/ }))

    expect(await screen.findByText('当前账号缺少后台任务管理权限')).toBeInTheDocument()
    expect(screen.queryByText('当前账号缺少后台任务读取权限')).not.toBeInTheDocument()
    expect(screen.queryByText('private role graph detail')).not.toBeInTheDocument()
  })

  it('uses a localized fallback for unknown detail, attempt, and result failure codes', async () => {
    authenticateAdmin()
    const unknownJob = { ...job, failure_code: 'private_detail_code' }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jobResponse(
      input,
      unknownJob,
      { attempt: 'private_attempt_code', result: 'private_result_code' },
    )))
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })

    expect(await within(drawer).findAllByText('未知失败原因')).toHaveLength(3)
    expect(within(drawer).queryByText('private_detail_code')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('private_attempt_code')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('private_result_code')).not.toBeInTheDocument()
  })

  // TASK-CAUSE-01: a CNAME allocation item keeps its own cause (not "unknown"),
  // the summary names it with the next step for the role, and the item reads
  // as an operation rather than "data/allocate".
  it.each([
    ['platform', '在节点管理中补齐线路组'],
    ['tenant', '需要管理员处理：请提交工单'],
  ] as const)('explains a CNAME allocation failure to %s', async (kind, next) => {
    if (kind === 'platform') authenticateAdmin()
    else {
      const actor = principal({ scope_kind: 'tenant', tenant_id: job.tenant_id, permissions: ['jobs.read'] })
      useSessionStore.getState().setSession(authResponse(actor), actor)
    }
    const cnameJob = { ...job, kind: 'cname.allocation', status: 'failed' as const, failure_code: 'all_items_failed' }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const response = jobResponse(input, cnameJob, { attempt: 'cname_no_default_line_group', result: 'cname_no_default_line_group' })
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === `/v1/jobs/${cnameJob.task_id}`) return Promise.resolve(json({ data: cnameJob }))
      if (!url.pathname.endsWith('/results')) return Promise.resolve(response)
      return response.json().then((body: { data: Record<string, unknown>[]; page: unknown }) =>
        json({ ...body, data: body.data.map((item) => ({ ...item, item_id: 'allocate' })) }))
    })
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />, [kind === 'platform' ? '/sys/task' : '/account/tasks'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    const summary = await within(drawer).findByTestId('jobs-cause-summary')
    expect(summary).toHaveTextContent('任务失败：网站未绑定套餐且没有平台默认线路组')
    expect(summary).toHaveTextContent(next)
    expect(within(drawer).queryByText('未知失败原因')).toBeNull()
    expect(within(drawer).getAllByText('生成网站 CNAME').length).toBeGreaterThan(0)
  })

  // 清除CDN无关解析 items that were kept read as
  // why they were kept, not as an unknown failure.
  it.each([
    ['dns_record_changed', '记录已变化或已被网站使用，已保留未删除'],
    ['dns_cleanup_plan_stale', '清除计划由旧版本生成，缺少完整记录值，已跳过'],
  ] as const)('explains a kept DNS cleanup record (%s)', async (code, text) => {
    authenticateAdmin()
    const cleanupJob = { ...job, kind: 'dns.cleanup.v1', status: 'failed' as const, failure_code: 'all_items_failed' }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname === `/v1/jobs/${cleanupJob.task_id}`) return Promise.resolve(json({ data: cleanupJob }))
      return Promise.resolve(jobResponse(input, cleanupJob, { attempt: code, result: code }))
    })
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    expect(await within(drawer).findByTestId('jobs-cause-summary')).toHaveTextContent(text)
    expect(within(drawer).queryByText('未知失败原因')).toBeNull()
    expect(within(drawer).queryByText(code)).toBeNull()
  })

  it('localizes retries_exhausted for detail and result without exposing the raw code', async () => {
    const exhaustedJob = { ...job, failure_code: 'retries_exhausted' }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jobResponse(
      input,
      exhaustedJob,
      { attempt: 'node_unavailable', result: 'retries_exhausted' },
    )))
    const user = userEvent.setup()

    authenticateAdmin()
    const chinese = renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const chineseDrawer = await screen.findByRole('dialog', { name: '任务详情' })
    expect(await within(chineseDrawer).findAllByText('任务重试次数已用尽')).toHaveLength(2)
    expect(within(chineseDrawer).queryByText('retries_exhausted')).not.toBeInTheDocument()
    chinese.unmount()

    await changeLocale('en-US')
    authenticateAdmin()
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: 'Details' }))
    const englishDrawer = await screen.findByRole('dialog', { name: 'Task details' })
    expect(await within(englishDrawer).findAllByText('Task retries are exhausted')).toHaveLength(2)
    expect(within(englishDrawer).queryByText('retries_exhausted')).not.toBeInTheDocument()
  })

  it('uses English request ID and progress punctuation from locale resources', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://web.test')
      if (url.pathname.endsWith('/attempts')) {
        return Promise.resolve(json({
          error: { code: 'job_store_unavailable', message: 'private database detail', request_id: 'jobs-detail-1' },
        }, 503))
      }
      return Promise.resolve(jobResponse(input))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: 'Details' }))
    const drawer = await screen.findByRole('dialog', { name: 'Task details' })

    expect(await within(drawer).findByText(
      'Task storage is unavailable. Try again later. (Request ID: jobs-detail-1)',
    )).toBeInTheDocument()
    expect(within(drawer).getByText('Total: 3')).toBeInTheDocument()
    expect(within(drawer).queryByText(/（|）|：/)).not.toBeInTheDocument()
    expect(within(drawer).queryByText('private database detail')).not.toBeInTheDocument()
  })

  it('denies a platform principal without read permission before any jobs API request', () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, permissions: ['jobs.manage_all'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const apiSpies = allJobsApiSpies()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(screen.getByText('无权查看后台任务')).toBeInTheDocument()
    for (const spy of apiSpies) expect(spy).not.toHaveBeenCalled()
  })

  it('keeps every task view state and exact retry stable across same-epoch token refreshes', async () => {
    const { actor, epoch } = adminSession('jobs-token-a')
    const owner = ownerTuple(actor, epoch)
    const failedJob = { ...withStatus('failed', 2), related_resource: { reference: 'site:stable.test' } }
    const list = vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [failedJob],
      page: params.cursor ? {} : { next_cursor: 'list-page-2' },
      query: { from: params.from, to: params.to },
    }))
    vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: failedJob })
    vi.spyOn(jobsApi, 'attempts').mockImplementation(async (_token, _audience, _id, _limit, cursor) => ({
      data: [], page: cursor ? {} : { next_cursor: 'attempt-page-2' },
    }))
    vi.spyOn(jobsApi, 'results').mockImplementation(async (_token, _audience, _id, _limit, cursor) => ({
      data: [], page: cursor ? {} : { next_cursor: 'result-page-2' },
    }))
    const retry = vi.spyOn(jobsApi, 'retry')
      .mockRejectedValueOnce(new ApiError('private old token detail', 0, 'network_error'))
      .mockResolvedValueOnce({ data: withStatus('queued', 2), replayed: true })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderTasksWithQueryClient(queryClient)
    await screen.findByText('site:stable.test')
    await user.type(screen.getByRole('combobox', { name: '任务类型' }), 'cache.refresh')
    await user.type(screen.getByLabelText('资源标识'), 'site:stable.test')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    expect(within(document.querySelector('.jobs-pagination') as HTMLElement)
      .getByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    await user.click(await within(drawer).findByRole('button', { name: '下一页尝试记录' }))
    await user.click(await within(drawer).findByRole('button', { name: '下一页逐项结果' }))
    expect(within(drawer).getAllByText('第 2 页')).toHaveLength(2)
    await user.click(within(drawer).getByRole('button', { name: '重试失败任务' }))
    expect(await screen.findByText(/^重试任务「/)).toBeInTheDocument()

    const readsBeforeRefresh = list.mock.calls.length
    act(() => adminSession('jobs-token-b', undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(screen.getByText(/^重试任务「/)).toBeInTheDocument()
    await user.click(within(screen.getByText(/^重试任务「/).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: /^确认重试/ }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()

    act(() => adminSession('jobs-token-c', undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(screen.getByRole('combobox', { name: '任务类型' })).toHaveValue('cache.refresh')
    expect(screen.getByLabelText('资源标识')).toHaveValue('site:stable.test')
    expect(within(document.querySelector('.jobs-pagination') as HTMLElement)
      .getByText('第 2 页')).toBeInTheDocument()
    expect(pageDialog('任务详情')).toBeInTheDocument()
    expect(within(pageDialog('任务详情')).getAllByText('第 2 页')).toHaveLength(2)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()

    expect(retry.mock.calls.map(([token]) => token)).toEqual(['jobs-token-b', 'jobs-token-c'])
    expect(retry.mock.calls[1].slice(1)).toEqual(retry.mock.calls[0].slice(1))
    const retryKeys = retry.mock.calls.map((call) => call[3])
    expect(retryKeys[0]).toBe(retryKeys[1])
    const keys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(keys).toContainEqual(['job', ...owner, 'platform', failedJob.task_id])
    expect(keys).toContainEqual([
      'job-attempts', ...owner, 'platform', failedJob.task_id, 'attempt-page-2',
    ])
    expect(keys).toContainEqual([
      'job-results', ...owner, 'platform', failedJob.task_id, 'result-page-2',
    ])
    expect(keys).toContainEqual([
      'jobs', ...owner, 'platform', expect.objectContaining({
        kind: 'cache.refresh', resource: 'site:stable.test',
      }), 10, 'list-page-2',
    ])
    expect(queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey))
      .toContainEqual(['job-command', ...owner, 'platform'])
    expect(owner[2]).toBeNull()
    expect(JSON.stringify(keys)).not.toContain('jobs-token-')
    expect(JSON.stringify(queryClient.getMutationCache().getAll()
      .map((mutation) => mutation.options.mutationKey))).not.toContain('jobs-token-')
    expect(document.body).not.toHaveTextContent(/jobs-token-[abc]/)
  })

  it.each(['confirmation', 'unknown retry'] as const)(
    'removes an open %s write path when a same-epoch refresh revokes manage permission',
    async (writeState) => {
      const { epoch } = adminSession('permission-token-a')
      const currentJob = writeState === 'confirmation'
        ? { ...withStatus('running', 1), related_resource: { reference: 'site:permission.test' } }
        : { ...withStatus('failed', 2), related_resource: { reference: 'site:permission.test' } }
      const list = vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
        data: [currentJob], page: {}, query: { from: params.from, to: params.to },
      }))
      const cancel = vi.spyOn(jobsApi, 'cancel')
      const retry = vi.spyOn(jobsApi, 'retry')
        .mockRejectedValue(new ApiError('private permission refresh command', 0, 'network_error'))
      const user = userEvent.setup()

      renderWithProviders(<AdminTasksPage />, ['/sys/task'])
      await screen.findByText('site:permission.test')
      await user.type(screen.getByRole('combobox', { name: '任务类型' }), 'cache.refresh')
      if (writeState === 'confirmation') {
        await user.click(screen.getByRole('button', { name: '取消任务' }))
        expect(await screen.findByText('确认取消任务')).toBeInTheDocument()
      } else {
        await user.click(screen.getByRole('button', { name: '重试失败任务' }))
        await user.click(within((await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!)
          .getByRole('button', { name: /^确认重试/ }))
        expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
      }
      const readsBeforeRefresh = list.mock.calls.length
      const writesBeforeRefresh = cancel.mock.calls.length + retry.mock.calls.length

      act(() => adminSession('permission-token-b', ['jobs.read_all'], 'refresh'))

      expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
      await waitFor(() => {
        expect(screen.queryByText('确认取消任务')).not.toBeInTheDocument()
        expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      })
      expect(screen.getByText('site:permission.test')).toBeInTheDocument()
      expect(screen.getByRole('combobox', { name: '任务类型' })).toHaveValue('cache.refresh')
      expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
      expect(screen.queryByRole('button', {
        name: /取消任务|重试失败任务|使用同一请求重试/,
      })).not.toBeInTheDocument()
      expect(cancel.mock.calls.length + retry.mock.calls.length).toBe(writesBeforeRefresh)
      expect(document.body).not.toHaveTextContent('private permission refresh command')
    },
  )

  it('settles an in-flight known success for the same owner while manage permission is revoked', async () => {
    const { actor, epoch } = adminSession('known-revoke-token-a')
    const owner = ownerTuple(actor, epoch)
    let currentJob = withStatus('running', 1)
    const cancelledJob = {
      ...withStatus('cancelled', 1),
      progress: { ...job.progress, failed: 0, cancelled: 1 },
    }
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [currentJob], page: {}, query: { from: params.from, to: params.to },
    }))
    const response = deferred<Awaited<ReturnType<typeof jobsApi.cancel>>>()
    const cancel = vi.spyOn(jobsApi, 'cancel').mockReturnValue(response.promise)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const user = userEvent.setup()

    renderTasksWithQueryClient(queryClient)
    await user.click(await screen.findByRole('button', { name: '取消任务' }))
    await user.click(within((await screen.findByText('确认取消任务')).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))
    expect(cancel).toHaveBeenCalledTimes(1)

    act(() => adminSession('known-revoke-token-b', ['jobs.read_all'], 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(screen.queryByRole('button', { name: '取消任务' })).not.toBeInTheDocument()

    currentJob = cancelledJob
    await act(async () => {
      response.resolve({ data: cancelledJob, replayed: false })
      await response.promise
    })

    await waitFor(() => expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey)).toEqual([
      ['jobs', ...owner, 'platform'],
      ['job', ...owner, 'platform'],
      ['job-attempts', ...owner, 'platform'],
      ['job-results', ...owner, 'platform'],
    ]))
    expect(await screen.findByText('已取消')).toBeInTheDocument()
    expect(screen.queryByText('任务取消请求已提交')).not.toBeInTheDocument()

    act(() => adminSession('known-revoke-token-c', undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    // The terminal row keeps the competitor's visible but disabled "取消" link.
    expect(screen.getByRole('button', { name: '取消任务' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(screen.queryByText('任务取消请求已提交')).not.toBeInTheDocument()
    expect(cancel.mock.calls.map(([token]) => token)).toEqual(['known-revoke-token-a'])
  })

  it('restores an in-flight unknown attempt after regrant and retries it with the latest token and same key', async () => {
    const { epoch } = adminSession('unknown-revoke-token-a')
    const failedJob = {
      ...withStatus('failed', 2),
      related_resource: { reference: 'site:unknown-revoke.test' },
    }
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [failedJob], page: {}, query: { from: params.from, to: params.to },
    }))
    const response = deferred<Awaited<ReturnType<typeof jobsApi.retry>>>()
    const retry = vi.spyOn(jobsApi, 'retry')
      .mockReturnValueOnce(response.promise)
      .mockResolvedValueOnce({ data: queuedFrom(failedJob), replayed: true })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: /^确认重试/ }))
    expect(retry).toHaveBeenCalledTimes(1)
    const firstAttempt = retry.mock.calls[0]!

    act(() => adminSession('unknown-revoke-token-b', ['jobs.read_all'], 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()

    await act(async () => {
      response.reject(new ApiError('private in-flight endpoint', 0, 'network_error'))
      await Promise.allSettled([response.promise])
    })
    expect(retry).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private in-flight endpoint')

    act(() => adminSession('unknown-revoke-token-c', undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()

    expect(retry.mock.calls.map(([token]) => token)).toEqual([
      'unknown-revoke-token-a', 'unknown-revoke-token-c',
    ])
    expect(retry.mock.calls[1]?.slice(1)).toEqual(firstAttempt.slice(1))
    expect(retry.mock.calls[1]?.[3]).toBe(firstAttempt[3])
  })

  it('invalidates exactly four current-owner prefixes after command success', async () => {
    const { actor, epoch } = adminSession('jobs-owner-token')
    const owner = ownerTuple(actor, epoch)
    const runningJob = withStatus('running', 1)
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => ({
      data: [runningJob], page: {}, query: { from: params.from, to: params.to },
    }))
    vi.spyOn(jobsApi, 'cancel').mockResolvedValue({ data: withStatus('cancelled', 1), replayed: false })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const foreignScope = '99999999-9999-4999-8999-999999999999'
    const foreignOwner = ['platform', foreignScope, null, '99999999-9999-4999-8999-999999999991', epoch + 10] as const
    const foreignKeys = [
      ['jobs', ...foreignOwner, 'platform'] as const,
      ['job', ...foreignOwner, 'platform'] as const,
      ['job-attempts', ...foreignOwner, 'platform'] as const,
      ['job-results', ...foreignOwner, 'platform'] as const,
    ]
    for (const key of foreignKeys) queryClient.setQueryData(key, { owner: 'foreign' })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const user = userEvent.setup()

    renderTasksWithQueryClient(queryClient)
    await screen.findByText('执行中')
    await user.click(screen.getByRole('button', { name: '取消任务' }))
    await user.click(within(screen.getByText('确认取消任务').closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: '确认' }))
    expect(await screen.findByText('任务取消请求已提交')).toBeInTheDocument()

    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(4))
    expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey)).toEqual([
      ['jobs', ...owner, 'platform'],
      ['job', ...owner, 'platform'],
      ['job-attempts', ...owner, 'platform'],
      ['job-results', ...owner, 'platform'],
    ])
    for (const key of foreignKeys) {
      expect(queryClient.getQueryData(key)).toEqual({ owner: 'foreign' })
      expect(queryClient.getQueryState(key)?.isInvalidated).toBe(false)
    }
  })

  it.each(['success', 'error'] as const)(
    'does not carry a delayed tenant-A command %s into tenant B',
    async (outcome) => {
      const scopeA = '22222222-2222-4222-8222-222222222222'
      const scopeB = '99999999-9999-4999-8999-999999999999'
      const sessionA = adminSession('command-token-a', undefined, 'new', scopeA)
      const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
      const jobA = { ...withStatus('failed', 2), task_id: 'a0000000-0000-4000-8000-00000000000a' }
      const jobB = { ...withStatus('failed', 2), task_id: 'b0000000-0000-4000-8000-00000000000b', related_resource: { reference: 'site:b.test' } }
      vi.spyOn(jobsApi, 'list').mockImplementation(async (token, _audience, params) => ({
        data: [token === 'command-token-a' ? jobA : jobB],
        page: {}, query: { from: params.from, to: params.to },
      }))
      const command = deferred<Awaited<ReturnType<typeof jobsApi.retry>>>()
      vi.spyOn(jobsApi, 'retry').mockReturnValue(command.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      const user = userEvent.setup()

      renderTasksWithQueryClient(queryClient)
      await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
      await user.click(within(screen.getByText(/^重试任务「/).closest<HTMLElement>('[role="dialog"]')!)
        .getByRole('button', { name: /^确认重试/ }))
      act(() => adminSession('command-token-b', undefined, 'new', scopeB))
      expect(await screen.findByText('site:b.test')).toBeInTheDocument()

      await act(async () => {
        if (outcome === 'success') command.resolve({ data: queuedFrom(jobA), replayed: false })
        else command.reject(new ApiError('private tenant A command', 0, 'network_error'))
        await Promise.resolve()
      })

      expect(screen.queryByText('任务已重新入队')).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText('private tenant A command')).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: '重试失败任务' })).toBeEnabled()
      const currentActor = useSessionStore.getState().principal!
      const currentEpoch = useSessionStore.getState().sessionEpoch
      const ownerB = ownerTuple(currentActor, currentEpoch)
      expect(queryClient.getQueryState([
        'jobs', ...ownerB, 'platform',
      ])?.isInvalidated).not.toBe(true)
      const invalidatedKeys = invalidate.mock.calls.map(([filters]) => filters?.queryKey)
      expect(invalidatedKeys.every((key) => key?.slice(1, 6)
        .every((value, index) => value === ownerA[index]))).toBe(true)
    },
  )

  it('confirms a running-task cancellation, renders canceling, and refreshes every open task fact', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    let currentJob = withStatus('running', 1)
    let resolveCommand!: (response: Response) => void
    const commandResponse = new Promise<Response>((resolve) => { resolveCommand = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/cancel')) return commandResponse
      return Promise.resolve(jobResponse(input, currentJob))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('执行中')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog', { name: '任务详情' })
    expect(await within(drawer).findByText('执行进度')).toBeInTheDocument()
    await user.click(within(drawer).getByRole('button', { name: '取消任务' }))
    const confirmation = (await screen.findByText('确认取消任务')).closest<HTMLElement>('[role="dialog"]')!
    await user.click(within(confirmation).getByRole('button', { name: '确认' }))
    expect(within(drawer).getByRole('button', { name: '取消中' })).toBeDisabled()

    const commandCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(commandCall?.[0]).toBe(`/v1/admin/jobs/${job.task_id}/cancel`)
    expect(new Headers(commandCall?.[1]?.headers).get('Idempotency-Key')).toMatch(/^job-cancel-/)
	expect(new Headers(commandCall?.[1]?.headers).get('If-Match')).toBe('"7"')
    currentJob = {
      ...withStatus('cancelled', 1),
      progress: { ...job.progress, failed: 0, cancelled: 1 },
    }
    resolveCommand(json({ data: currentJob, replayed: false }))

    expect(await screen.findByText('任务取消请求已提交')).toBeInTheDocument()
    await waitFor(() => {
      const paths = fetchSpy.mock.calls
        .filter(([, init]) => init?.method !== 'POST')
        .map(([input]) => new URL(String(input), 'https://web.test').pathname)
      expect(paths.filter((path) => path === '/v1/admin/jobs').length).toBeGreaterThanOrEqual(2)
      expect(paths.filter((path) => path === `/v1/admin/jobs/${job.task_id}`).length).toBeGreaterThanOrEqual(2)
      expect(paths.filter((path) => path.endsWith('/attempts')).length).toBeGreaterThanOrEqual(2)
      expect(paths.filter((path) => path.endsWith('/results')).length).toBeGreaterThanOrEqual(2)
    })
  })

  it('confirms a failed-task retry, renders retrying, and reloads the succeeded result', async () => {
    authenticateAdmin(['jobs.read_all', 'platform.admin'])
    let currentJob = withStatus('failed', 2)
    let resolveCommand!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
        return new Promise<Response>((resolve) => { resolveCommand = resolve })
      }
      return Promise.resolve(jobResponse(input, currentJob))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])

    expect(await screen.findByText('失败')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试失败任务' }))
    const confirmation = (await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!
    await user.click(within(confirmation).getByRole('button', { name: /^确认重试/ }))
    expect(screen.getByRole('button', { name: '重试中' })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([input, init]) =>
      init?.method === 'POST' && String(input) === `/v1/admin/jobs/${job.task_id}/retry`)).toBe(true)
	const retryCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
	expect(new Headers(retryCall?.[1]?.headers).get('If-Match')).toBe('"7"')

    currentJob = { ...withStatus('succeeded', 3), progress: { ...job.progress, succeeded: 3, failed: 0 } }
    resolveCommand(json({ data: withStatus('queued', 2), replayed: false }))
    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('成功')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: '重试失败任务' })).not.toBeInTheDocument()
  })

  it('retries an unknown command outcome with the exact same idempotency key', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    let commandCalls = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
        commandCalls += 1
        if (commandCalls === 1) return Promise.reject(new Error('private upstream address'))
        return Promise.resolve(json({ data: withStatus('queued', 2), replayed: true }))
      }
      return Promise.resolve(jobResponse(input, withStatus('failed', 2)))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: /^确认重试/ }))

    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.queryByText('private upstream address')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('任务已重新入队')).toBeInTheDocument()

    const keys = fetchSpy.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => new Headers(init?.headers).get('Idempotency-Key'))
    expect(keys).toHaveLength(2)
    expect(keys[0]).toBe(keys[1])
  })

  it('localizes a deterministic command rejection and does not offer an uncertain retry', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
        return Promise.resolve(json({
          error: { code: 'job_invalid_transition', message: 'private state machine detail' },
        }, 409))
      }
      return Promise.resolve(jobResponse(input, withStatus('failed', 2)))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    await user.click(within((await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!)
      .getByRole('button', { name: /^确认重试/ }))

    expect(await screen.findByText('任务操作失败')).toBeInTheDocument()
    expect(screen.getByText('当前任务状态不允许此操作')).toBeInTheDocument()
    expect(screen.queryByText('private state machine detail')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
  })

	it('refreshes task facts after a stale revision rejection', async () => {
		authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
		let readCalls = 0
		vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
			const url = new URL(String(input), 'https://web.test')
			if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
				return Promise.resolve(json({
					error: { code: 'job_revision_conflict', message: 'private current revision' },
				}, 412))
			}
			readCalls += 1
			return Promise.resolve(jobResponse(input, withStatus('failed', 2)))
		})
		const user = userEvent.setup()

		renderWithProviders(<AdminTasksPage />, ['/sys/task'])
		await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
		await user.click(within((await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!)
			.getByRole('button', { name: /^确认重试/ }))

		expect(await screen.findByText('内容已被其他人修改，请刷新后再保存')).toBeInTheDocument()
		expect(screen.queryByText('private current revision')).not.toBeInTheDocument()
		const readsBeforeRefresh = readCalls
		await user.click(screen.getByRole('button', { name: '刷新任务' }))
		await waitFor(() => expect(readCalls).toBeGreaterThan(readsBeforeRefresh))
	})

  it('keeps command controls absent for read-only principals and succeeded tasks', async () => {
    authenticateAdmin(['jobs.read_all'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) =>
      Promise.resolve(jobResponse(input, withStatus('succeeded', 3))))

    const { container } = renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    expect(await screen.findByText('成功')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /取消任务|重试失败任务/ })).not.toBeInTheDocument()
    const page = container.querySelector('.jobs-page')
    expect(page).toHaveStyle({ width: 'auto', minWidth: 0, maxWidth: '100%', overflowX: 'hidden' })
    expect(page).not.toHaveStyle({ width: '100%' })
  })

  it('retries a cache operation from the task center; the server runs it on the cache module (CACHE-ADD-05)', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    const cacheJob: BackgroundJob = { ...withStatus('failed', 1), kind: 'cache.operation' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://web.test')
      if (init?.method === 'POST' && url.pathname.endsWith('/retry')) {
        return Promise.resolve(json({ data: { ...cacheJob, status: 'queued' }, replayed: false }))
      }
      return Promise.resolve(jobResponse(input, cacheJob))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    const confirmation = (await screen.findByText(/^重试任务「/)).closest<HTMLElement>('[role="dialog"]')!
    await user.click(within(confirmation).getByRole('button', { name: /^确认重试/ }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input, init]) =>
      init?.method === 'POST' && String(input) === `/v1/admin/jobs/${cacheJob.task_id}/retry`)).toBe(true))
    expect(screen.queryByRole('link', { name: /刷新预热/ })).not.toBeInTheDocument()
  })

  it('renders complete Chinese and pseudo-locale control text without missing keys', async () => {
    authenticateAdmin(['platform.admin'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [], page: {}, query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
    }))

    const chinese = renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    expect(await screen.findByText('暂无后台任务')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '查询' })).toBeInTheDocument()
    expect(screen.queryByText(/Background tasks|All statuses|Task type|Resource reference/)).not.toBeInTheDocument()
    chinese.unmount()

    await changeLocale('qps-ploc')
    authenticateAdmin(['platform.admin'])
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    expect(await screen.findByRole('button', { name: /［.*查~询~.*］/ })).toBeInTheDocument()
    expect(document.documentElement.lang).toBe('qps-ploc')
  })

  it('renders settlement receipts and dead letters with loading, empty, and retry states', async () => {
    authenticateAdmin(['jobs.read_all'])
    const receiptsDeferred = deferred<Awaited<ReturnType<typeof jobsApi.receipts>>>()
    const receipts = vi.spyOn(jobsApi, 'receipts').mockReturnValue(receiptsDeferred.promise)
    vi.spyOn(jobsApi, 'deadLetters').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'list').mockResolvedValue({
      data: [job], page: {}, query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
    })
    vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: job })
    vi.spyOn(jobsApi, 'attempts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'results').mockResolvedValue({ data: [], page: {} })
    const user = userEvent.setup()

    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '详情' }))
    const receiptsSection = await screen.findByRole('region', { name: '结算回执' })
    expect(screen.getByTestId('job-receipts-table')).toHaveAttribute('aria-busy', 'true')
    receiptsDeferred.reject(new ApiError('API request failed', 503, 'job_store_unavailable'))
    expect(await within(receiptsSection).findByText('结算回执加载失败')).toBeInTheDocument()
    expect(within(receiptsSection).getByRole('button', { name: '重试' })).toBeInTheDocument()

    receipts.mockResolvedValue({ data: [], page: {} })
    await user.click(within(receiptsSection).getByRole('button', { name: '重试' }))
    expect(await within(receiptsSection).findByText('暂无结算回执')).toBeInTheDocument()
    const deadLettersSection = screen.getByRole('region', { name: '死信记录' })
    expect(within(deadLettersSection).getByText('暂无死信记录')).toBeInTheDocument()
  })

  it('uses strict platform settlement child endpoints and rejects malformed receipts', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        data: [{
          ordinal: 1, item_id: 'node-1', node_id: 'c0000000-0000-4000-8000-000000000003', status: 'succeeded',
          attempt: 2, sequence: 4, source: 'worker', reported_at: '2026-07-22T08:02:00Z',
        }], page: { next_cursor: 'receipt-next' },
      }))
      .mockResolvedValueOnce(json({
        data: [{
          attempt: 2, reason_code: 'retries_exhausted', failed_item_count: 1,
          source: 'lease_expiry', created_at: '2026-07-22T08:02:00Z',
        }], page: {},
      }))
      .mockResolvedValueOnce(json({ data: [{ ordinal: 1 }], page: {} }))

    await expect(jobsApi.receipts('token', 'platform', job.task_id, 20, 'opaque receipt cursor'))
      .resolves.toMatchObject({ data: [{ ordinal: 1, source: 'worker' }], page: { next_cursor: 'receipt-next' } })
    await expect(jobsApi.deadLetters('token', 'platform', job.task_id, 20))
      .resolves.toMatchObject({ data: [{ attempt: 2, source: 'lease_expiry' }] })
    await expect(jobsApi.receipts('token', 'platform', job.task_id, 20)).rejects.toMatchObject({
      status: 502, code: 'invalid_response',
    })

    expect(String(fetchSpy.mock.calls[0][0])).toContain(`/v1/admin/jobs/${job.task_id}/receipts?`)
    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test').searchParams.get('cursor'))
      .toBe('opaque receipt cursor')
    expect(String(fetchSpy.mock.calls[1][0])).toContain(`/v1/admin/jobs/${job.task_id}/dead-letters?`)
    for (const [, init] of fetchSpy.mock.calls) {
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
      expect(String(init?.headers)).not.toContain('opaque receipt cursor')
    }
  })
})

describe('AdminTasksPage toolbar, retry target and narrow layout', () => {
  const lastListURL = (fetchSpy: { mock: { calls: unknown[][] } }) => new URL(String(fetchSpy.mock.calls
    .filter(([input]) => String(input).startsWith('/v1/admin/jobs?')).at(-1)?.[0]), 'https://web.test')

  it('shows the query button in the filter toolbar; Enter and click both apply the resource filter', async () => {
    authenticateAdmin(['jobs.read_all'])
    // 类型目录读取失败会弹出居中反馈框并抢走焦点，这里给一个空目录
    vi.spyOn(jobsApi, 'kinds').mockResolvedValue({ data: [] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jobResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await screen.findByText('site:example.test')
    const query = screen.getByRole('button', { name: '查询' })
    expect(query).not.toHaveClass('visually-hidden')
    expect(query.closest('.jobs-filter-group')).not.toBeNull()
    query.focus()
    expect(query).toHaveFocus()

    await user.type(screen.getByLabelText('资源标识'), 'site:enter.test{Enter}')
    await waitFor(() => expect(lastListURL(fetchSpy).searchParams.get('resource')).toBe('site:enter.test'))
    await user.clear(screen.getByLabelText('资源标识'))
    await user.type(screen.getByLabelText('资源标识'), 'site:click.test')
    await user.click(query)
    await waitFor(() => expect(lastListURL(fetchSpy).searchParams.get('resource')).toBe('site:click.test'))
  })

  it('names the task, its resource, state and failure in the retry confirmation', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jobResponse(input, withStatus('failed', 2))))
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    await user.click(await screen.findByRole('button', { name: '重试失败任务' }))
    const title = await screen.findByText(/^重试任务「.+」？$/)
    const dialog = title.closest<HTMLElement>('[role="dialog"]')!
    expect(within(dialog).getByText('site:example.test')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: /^确认重试 .+/ })).toBeInTheDocument()
    expect(within(dialog).getByText('失败')).toBeInTheDocument()
  })

  it('pins the actions column right so row entries stay reachable on a phone', async () => {
    authenticateAdmin(['jobs.read_all', 'jobs.manage_all'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jobResponse(input)))
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    const details = await screen.findByRole('button', { name: '详情' })
    expect(details.closest('td')).toHaveClass('ant-table-cell-fix-right')
    expect(screen.getByRole('columnheader', { name: '操作' })).toHaveClass('ant-table-cell-fix-right')
  })

  it('wraps the pager on a phone and keeps only previous / current / next page buttons', async () => {
    const sheet = document.createElement('style')
    sheet.textContent = adminTasksStyles
    document.head.append(sheet)
    const narrow = [...sheet.sheet!.cssRules].find((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 575px)')!
    const rule = (selector: string) => [...narrow.cssRules].find((item): item is CSSStyleRule => item instanceof CSSStyleRule && item.selectorText.includes(selector))!
    expect(rule('.jobs-page .jobs-total').style.getPropertyValue('flex')).toContain('100%')
    expect(rule('.jobs-page-number:not(.is-current)').style.getPropertyValue('display')).toBe('none')
    expect(rule('.jobs-pagination .ant-select').style.getPropertyValue('flex')).toContain('100%')
    sheet.remove()

    authenticateAdmin(['jobs.read_all'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://web.test')
      // 编号分页须与请求的 limit 一致并逐条带任务元数据（api/jobs.ts parseList）
      if (url.pathname === '/v1/admin/jobs') return Promise.resolve(json({ data: [job], page: { number: 1, limit: 10, total: 180, total_pages: 18, consistency: 'request_snapshot' },
        query: { from: url.searchParams.get('from'), to: url.searchParams.get('to') },
        task_metadata: [{ task_id: job.task_id, name: { name_key: 'jobs.kindNames.unknown', resource: job.related_resource.reference, source: 'derived' },
          priority: { policy: 'ready_fifo' }, dependencies: { state: 'unknown', items: [] } }] }))
      return Promise.resolve(jobResponse(input))
    })
    renderWithProviders(<AdminTasksPage />, ['/sys/task'])
    const current = await screen.findByRole('button', { name: '第 1 页', current: 'page' })
    expect(current.closest('.jobs-page-number')).toHaveClass('is-current')
    expect(screen.getByRole('button', { name: '第 18 页' }).closest('.jobs-page-number')).not.toHaveClass('is-current')
  })
})

