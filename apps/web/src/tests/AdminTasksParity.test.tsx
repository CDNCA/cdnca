import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import userEvent from '@testing-library/user-event'

import { ApiError } from '../api/auth'
import { jobsApi, type AdminJobListParams, type BackgroundJob, type JobKindListResponse, type JobListResponse } from '../api/jobs'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import AdminTasksPage from '../pages/AdminTasksPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const kindCatalog: JobKindListResponse = {
  data: [
    ['analytics.log_export', 'analyticsLogExport'], ['cache.operation', 'cacheOperation'],
    ['dns.cleanup.v1', 'dnsCleanup'], ['dns.repair.v1', 'dnsRepair'], ['dns_reconcile', 'dnsReconcile'],
    ['dns.cname.allocation', 'cnameAllocation'], ['dns.cname.intent', 'cnameIntent'], ['dns.cname.stream_intent', 'cnameStreamIntent'],
    ['edge.publication', 'edgePublication'],
    ['site.status_recovery', 'siteStatusRecovery'],
  ].map(([kind, name]) => ({
    kind, name_key: `jobs.kindNames.${name}`, integration: 'integrated', runtime_status: 'unknown',
  })),
}

const job: BackgroundJob = {
  task_id: 'a0000000-0000-4000-8000-000000000001',
  tenant_id: 'b0000000-0000-4000-8000-000000000002',
  kind: 'cache.operation',
  related_resource: { reference: 'site:example.test' },
  request_id: 'request-1', status: 'queued', attempt: 0, max_attempts: 3,
  progress: { total: 1, completed: 0, succeeded: 0, failed: 0, cancelled: 0, pending: 1 },
  created_at: '2026-07-22T08:00:00Z', updated_at: '2026-07-22T08:00:00Z', revision: '7',
}

function numberedResponse(params: AdminJobListParams, total = 0, data: BackgroundJob[] = []): JobListResponse {
  return {
    data,
    page: { number: params.page ?? 1, limit: params.limit, total, total_pages: Math.ceil(total / params.limit), consistency: 'request_snapshot' },
    query: { from: params.from, to: params.to },
    task_metadata: data.map((entry) => ({
      task_id: entry.task_id,
      name: { name_key: kindCatalog.data.find((kind) => kind.kind === entry.kind)!.name_key, resource: entry.related_resource.reference, source: 'derived' },
      priority: { policy: entry.kind === 'cache.operation' ? 'producer_managed' : 'ready_fifo' }, dependencies: { state: 'unknown', items: [] },
    })),
  }
}

function authenticate(token = 'task-reader') {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['jobs.read_all'] })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor)
}

describe('AdminTasksPage parity facts', () => {
  beforeEach(() => {
    authenticate()
    vi.spyOn(jobsApi, 'kinds').mockResolvedValue(kindCatalog)
    vi.spyOn(jobsApi, 'list').mockImplementation(async (_token, _audience, params) => numberedResponse(params))
  })

  it('shows the full integrated type directory and an exact zero total on an empty page', async () => {
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />)

    expect(await screen.findByText('共 0 条')).toBeInTheDocument()
    for (const name of ['优先级', '名称', '依赖']) expect(screen.getByRole('columnheader', { name })).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '任务类型' }))
    expect(await screen.findByText('缓存刷新/预热')).toBeInTheDocument()
    expect(screen.getByText('DNS 记录修复')).toBeInTheDocument()
    expect(document.querySelectorAll('.ant-select-item-option')).toHaveLength(11)
    expect(screen.queryByText('总数暂无事实')).not.toBeInTheDocument()
    expect(jobsApi.kinds).toHaveBeenCalledWith('task-reader', 'platform')
    expect(jobsApi.list).toHaveBeenLastCalledWith('task-reader', 'platform', expect.objectContaining({ page: 1, limit: 10 }))
  })

  it('uses server totals to jump to the last page and resets pagination for type and size changes', async () => {
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => numberedResponse(params, 137))
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />)

    expect(await screen.findByText('共 137 条')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '第 3 页' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '第 14 页' }))
    await waitFor(() => expect(jobsApi.list).toHaveBeenLastCalledWith('task-reader', 'platform', expect.objectContaining({ page: 14, limit: 10 })))
    expect(vi.mocked(jobsApi.list).mock.calls.at(-1)?.[2].cursor).toBeUndefined()

    await user.click(screen.getByRole('combobox', { name: '任务类型' }))
    await user.click(await screen.findByText('DNS 记录修复'))
    await waitFor(() => expect(jobsApi.list).toHaveBeenLastCalledWith('task-reader', 'platform', expect.objectContaining({ page: 1, kind: 'dns.repair.v1' })))
    expect(jobsApi.kinds).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole('combobox', { name: '每页条数' }))
    await user.click(await screen.findByTitle('20 条/页'))
    await waitFor(() => expect(jobsApi.list).toHaveBeenLastCalledWith('task-reader', 'platform', expect.objectContaining({ page: 1, limit: 20 })))
  })

  it('distinguishes real FIFO policy, derived names, recorded dependencies, and unknown facts', async () => {
    const dependencyID = 'c0000000-0000-4000-8000-000000000003'
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => {
      const response = numberedResponse(params, 1, [{ ...job, kind: 'dns.cname.allocation' }])
      response.task_metadata![0].dependencies = {
        state: 'observed', items: [{ task_id: dependencyID, relation: 'completion', status: 'succeeded' }],
      }
      return response
    })
    renderWithProviders(<AdminTasksPage />)

    expect(await screen.findByText('按就绪顺序')).toBeInTheDocument()
    expect(screen.getByText('CNAME 分配 · site:example.test')).toBeInTheDocument()
    expect(screen.getByText(dependencyID)).toBeInTheDocument()
    expect(screen.queryByText('无依赖')).not.toBeInTheDocument()
    expect(screen.queryByText('20')).not.toBeInTheDocument()
  })

  it('shows the competitor list cells from recorded facts: no dependency, not started, badges and short cancel', async () => {
    authenticate('task-manager')
    useSessionStore.getState().principal!.permissions.push('jobs.manage_all')
    const succeeded: BackgroundJob = {
      ...job, task_id: 'a0000000-0000-4000-8000-000000000011', status: 'succeeded', attempt: 1,
      progress: { total: 1, completed: 1, succeeded: 1, failed: 0, cancelled: 0, pending: 0 },
      started_at: '2026-07-22T08:00:00Z', updated_at: '2026-07-22T08:00:00Z', completed_at: '2026-07-22T08:00:00Z',
    }
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => {
      const response = numberedResponse(params, 2, [job, succeeded])
      for (const entry of response.task_metadata!) entry.dependencies = { state: 'none', items: [] }
      return response
    })
    renderWithProviders(<AdminTasksPage />)

    const queuedRow = (await screen.findByText(job.task_id)).closest('tr')!
    expect(within(queuedRow).getByText('无依赖')).toHaveClass('jobs-muted')
    expect(within(queuedRow).getAllByText('未开始')).toHaveLength(2)
    expect(within(queuedRow).getByText('待执行')).toBeInTheDocument()
    expect(within(queuedRow).getByRole('button', { name: '取消任务' })).toHaveTextContent('取消')
    expect(within(queuedRow).getByRole('button', { name: '取消任务' })).toBeEnabled()
    expect(within(queuedRow).getByText('由任务生产方调度')).toHaveClass('jobs-badge--priority')
    const succeededRow = screen.getByText(succeeded.task_id).closest('tr')!
    expect(within(succeededRow).getByText('0秒')).toHaveClass('jobs-badge--duration')
    expect(within(succeededRow).getByText(/^结束 /)).toBeInTheDocument()
    expect(within(succeededRow).getByText('成功')).toHaveClass('jobs-state-dot')
    expect(within(succeededRow).getByRole('button', { name: '取消任务' })).toBeDisabled()
    expect(screen.queryByText('依赖关系未记录')).not.toBeInTheDocument()
  })

  it('queries the newest 31-day window and applies a resource_id deep link from the URL', async () => {
    renderWithProviders(<AdminTasksPage />, ['/sys/task?resource_id=%2001a13148-0000-4000-8000-000000000001%20'])

    await screen.findByText('共 0 条')
    const params = vi.mocked(jobsApi.list).mock.calls.at(-1)![2]
    expect(params.resource).toBe('01a13148-0000-4000-8000-000000000001')
    expect(Date.parse(params.to) - Date.parse(params.from)).toBe(31 * 24 * 60 * 60 * 1000)
    expect(Date.parse(params.to)).toBeGreaterThan(Date.now())
    expect(screen.getByLabelText('资源标识')).toHaveValue('01a13148-0000-4000-8000-000000000001')
    expect(document.querySelector('input[type="datetime-local"]')).toBeNull()
  })

  it('filters to and opens the task named by a task_id deep link', async () => {
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => numberedResponse(params, 1, [job]))
    const detail = vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: job })
    vi.spyOn(jobsApi, 'attempts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'results').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'receipts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'deadLetters').mockResolvedValue({ data: [], page: {} })
    renderWithProviders(<AdminTasksPage />, [`/sys/task?task_id=${job.task_id.toUpperCase()}`])

    const dialog = await screen.findByRole('dialog', { name: '子任务详情' })
    await waitFor(() => expect(detail).toHaveBeenCalledWith('task-reader', 'platform', job.task_id))
    expect(vi.mocked(jobsApi.list).mock.calls.at(-1)![2].taskID).toBe(job.task_id)
    expect(screen.getByLabelText('任务ID')).toHaveValue(job.task_id)
    expect(await within(dialog).findByText(job.task_id)).toBeInTheDocument()
  })

  it('ignores a task_id deep link that is not a task UUID', async () => {
    const detail = vi.spyOn(jobsApi, 'detail')
    renderWithProviders(<AdminTasksPage />, ['/sys/task?task_id=DNS%E8%AE%B0%E5%BD%95%E4%BF%AE%E5%A4%8D'])

    await screen.findByText('共 0 条')
    expect(vi.mocked(jobsApi.list).mock.calls.at(-1)![2].taskID).toBeUndefined()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(detail).not.toHaveBeenCalled()
  })

  it('shows the subtask detail modal with refresh, real item facts, total, and a result dialog', async () => {
    const started: BackgroundJob = {
      ...job, status: 'running', attempt: 1, started_at: '2026-07-22T08:00:00Z',
    }
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => numberedResponse(params, 1, [started]))
    vi.spyOn(jobsApi, 'detail').mockResolvedValue({ data: started })
    vi.spyOn(jobsApi, 'attempts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'receipts').mockResolvedValue({ data: [], page: {} })
    vi.spyOn(jobsApi, 'deadLetters').mockResolvedValue({ data: [], page: {} })
    const results = vi.spyOn(jobsApi, 'results').mockResolvedValue({
      data: [{
        ordinal: 1, item_id: 'site-config-1', node_id: 'c0000000-0000-4000-8000-000000000003', status: 'failed',
        attempt: 1, sequence: 2, failure_code: 'node_unavailable', started_at: '2026-07-22T08:00:00Z',
        completed_at: '2026-07-22T08:00:07Z', failure_count: 1,
      }, { ordinal: 2, item_id: 'site-config-2', status: 'pending', attempt: 0, sequence: 0 }],
      page: {},
    })
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />)

    await user.click(await screen.findByRole('button', { name: '详情' }))
    const dialog = await screen.findByRole('dialog', { name: '子任务详情' })
    for (const name of ['ID', '资源', '操作项目', '开始时间', '耗时', '状态', '失败次数', '操作']) {
      expect(within(dialog).getAllByRole('columnheader', { name }).length).toBeGreaterThan(0)
    }
    expect(await within(dialog).findByText('site-config-1')).toBeInTheDocument()
    expect(within(dialog).getByText('7秒')).toBeInTheDocument()
    expect(within(dialog).getAllByText('未记录')).toHaveLength(2)
    expect(within(dialog).getByText('共 1 条')).toBeInTheDocument()
    expect(results).toHaveBeenLastCalledWith('task-reader', 'platform', job.task_id, 10, undefined)
    await user.click(within(dialog).getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(results).toHaveBeenCalledTimes(2))
    await user.click(within(dialog).getAllByRole('button', { name: '结果' })[0])
    const resultDialog = (await screen.findByText('子任务结果')).closest<HTMLElement>('.ant-modal')!
    expect(within(resultDialog).getByText('节点暂不可用')).toBeInTheDocument()
    expect(within(resultDialog).getByText('c0000000-0000-4000-8000-000000000003')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '关闭' })).toBeInTheDocument()
  })

  it('shows unknown dependency facts without inventing an empty dependency graph', async () => {
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => numberedResponse(params, 1, [{ ...job, kind: 'dns_reconcile' }]))
    renderWithProviders(<AdminTasksPage />)

    expect(await screen.findByText('依赖关系未记录')).toBeInTheDocument()
    expect(screen.queryByText('无依赖')).not.toBeInTheDocument()
  })

  it('keeps catalog errors separate from list results and allows a read-only retry', async () => {
    vi.mocked(jobsApi.kinds).mockRejectedValueOnce(new ApiError('private catalog detail', 503, 'job_store_unavailable'))
    const user = userEvent.setup()
    renderWithProviders(<AdminTasksPage />)

    expect(await screen.findByText('任务类型目录加载失败')).toBeInTheDocument()
    expect(await screen.findByText('共 0 条')).toBeInTheDocument()
    expect(screen.queryByText('private catalog detail')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试类型目录' }))
    await waitFor(() => expect(screen.queryByText('任务类型目录加载失败')).not.toBeInTheDocument())
    expect(jobsApi.kinds).toHaveBeenCalledTimes(2)
  })

  it('isolates and removes directory caches when the principal changes', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    render(<ConfigProvider><AntApp><QueryClientProvider client={queryClient}><AdminTasksPage /></QueryClientProvider></AntApp></ConfigProvider>)
    await screen.findByText('共 0 条')
    const initialKindKey = queryClient.getQueryCache().getAll().find((query) => query.queryKey[0] === 'job-kinds')!.queryKey

    act(() => authenticate('next-task-reader'))
    await waitFor(() => expect(jobsApi.kinds).toHaveBeenCalledWith('next-task-reader', 'platform'))
    expect(queryClient.getQueryData(initialKindKey)).toBeUndefined()
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))).not.toContain('task-reader')
  })

  it('translates new columns, directory labels, totals, and metadata in the pseudo locale', async () => {
    await changeLocale('qps-ploc')
    vi.mocked(jobsApi.list).mockImplementation(async (_token, _audience, params) => numberedResponse(params, 1, [{ ...job, kind: 'dns_reconcile' }]))
    renderWithProviders(<AdminTasksPage />)

    expect(await screen.findByText(/［.*就~绪~顺~序~/)).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /优~先~级~/ })).toBeInTheDocument()
    expect(document.querySelector('.jobs-total')).toHaveTextContent('1')
    expect(document.body.textContent).not.toMatch(/jobs\.(kindNames|taskFacts|pagination)/)
  })
})
