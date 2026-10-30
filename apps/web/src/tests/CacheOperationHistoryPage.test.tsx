import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  cacheOperationsApi,
  type CacheOperation,
  type CacheOperationSummary,
} from '../api/cacheOperations'
import { useSessionStore } from '../auth/session'
import CacheOperationHistoryPage from '../pages/CacheOperationHistoryPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 加载/请求失败从页内 Alert 改为 FeedbackWhen 居中弹窗（.cdnca-feedback）
const findFeedback = () => waitFor(() => { const element = document.querySelector<HTMLElement>('.cdnca-feedback'); if (!element) throw new Error('no feedback dialog'); return element })

const siteID = '33333333-3333-4333-8333-333333333333'
const operationID = '55555555-5555-4555-8555-555555555555'
const nodeID = '44444444-4444-4444-8444-444444444444'

const operation: CacheOperation = {
  id: operationID,
  display_id: '12',
  site_id: siteID,
  site_display_id: '3',
  action: 'purge',
  target_type: 'exact_url',
  state: 'partial_failed',
  max_attempts: 4,
  auto_nodes: false,
  progress: { total: 2, completed: 2, succeeded: 1, failed: 1, cancelled: 0 },
  targets: [{
    ordinal: 1,
    display_url: 'https://www.example.com/a.js',
    canonical_path: '/a.js',
    target_sha256: 'a'.repeat(64),
    query_redacted: false,
  }],
  nodes: [{
    node_id: nodeID,
    node_display_id: '7',
    state: 'failed',
    attempt: 1,
    progress: { total: 1, completed: 1, succeeded: 0, failed: 1, cancelled: 0 },
    last_error_code: 'node_offline',
    targets: [{ target_ordinal: 1, state: 'failed', attempt: 1, sequence: 2, error_code: 'node_offline' }],
    updated_at: '2026-07-28T08:00:00Z',
    completed_at: '2026-07-28T08:00:00Z',
  }],
  created_at: '2026-07-28T07:59:00Z',
  updated_at: '2026-07-28T08:00:00Z',
  completed_at: '2026-07-28T08:00:00Z',
}

function summary(overrides: Partial<CacheOperationSummary> = {}): CacheOperationSummary {
  return { ...operation, target_count: 1, node_count: 1, first_target: operation.targets[0]!, ...overrides }
}

function authenticate(permissions: string[] = ['sites.read', 'sites.manage']) {
  const actor = principal({
    scope_kind: 'tenant',
    scope_id: '22222222-2222-4222-8222-222222222222',
    tenant_id: '22222222-2222-4222-8222-222222222222',
    user_id: '11111111-1111-4111-8111-111111111111',
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('CacheOperationHistoryPage', () => {
  beforeEach(() => window.sessionStorage.clear())

  it('denies readers without sites.read before making a request', () => {
    authenticate([])
    const list = vi.spyOn(cacheOperationsApi, 'list')

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    expect(screen.getByText('当前账号缺少网站读取权限')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })

  // 重新提交选中与筛选整体放在标签行右侧，同一行，不再单独占一行。
  it('puts the resubmit button and filters on the tab row', async () => {
    authenticate(['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary()] })

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    expect(await screen.findByText('https://www.example.com/a.js')).toBeInTheDocument()
    const tabs = screen.getByRole('tablist', { name: '缓存操作页签' }).closest('.site-cache-tabs-row')!
    expect(tabs).not.toBeNull()
    expect(within(tabs as HTMLElement).getByRole('button', { name: /重新提交选中/ })).toBeInTheDocument()
    expect(within(tabs as HTMLElement).getByRole('combobox', { name: '类型' })).toBeInTheDocument()
    expect(within(tabs as HTMLElement).getByRole('searchbox', { name: '搜索 URL 或域名' })).toBeInTheDocument()
    expect(within(tabs as HTMLElement).getByRole('button', { name: '刷新' })).toBeInTheDocument()
    // The tab links stay a tablist of their own: the toolbar is not inside it.
    expect(within(screen.getByRole('tablist', { name: '缓存操作页签' })).queryByRole('button')).toBeNull()
  })

  it('lists the competitor six columns and sends type and URL search as server filters', async () => {
    authenticate(['sites.read'])
    const list = vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary()] })
    // The row's URL comes from the summary: no detail read per row.
    const get = vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    expect(await screen.findByText('https://www.example.com/a.js')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
    const headers = screen.getAllByRole('columnheader').map((cell) => cell.textContent).filter(Boolean)
    expect(headers).toEqual(['任务编号', '类型', 'URL', '状态', '创建时间', '操作'])
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('刷新 URL')).toBeInTheDocument()
    expect(screen.queryByText('节点数')).not.toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '类型' }))
    await user.click(await screen.findByText('预热', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(
      'memory-only-access-token',
      { kind: 'tenant' },
      { action: 'prewarm', target_type: 'exact_url', limit: 20, cursor: undefined },
    ))
    await user.type(screen.getByRole('searchbox', { name: '搜索 URL 或域名' }), ' www.example.com {enter}')
    await waitFor(() => expect(list.mock.calls.at(-1)?.[2]).toMatchObject({ search: 'www.example.com', action: 'prewarm' }))
  })

  it('folds a system follow-up under its parent and marks an orphan follow-up (CACHE-ADD-09b)', async () => {
    authenticate(['sites.read'])
    const parentID = '66666666-6666-4666-8666-666666666666'
    const childID = '67777777-7777-4777-8777-777777777777'
    const orphanID = '68888888-8888-4888-8888-888888888888'
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [
      summary({ id: childID, display_id: '21', auto_nodes: true, parent_operation_id: parentID }),
      summary({ id: parentID, display_id: '20', auto_nodes: true }),
      summary({ id: orphanID, display_id: '19', auto_nodes: true, parent_operation_id: operationID }),
    ] })
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    const parentRow = (await screen.findByText('20')).closest('tr')!
    expect(within(parentRow).getByText('含 1 个跟进任务')).toBeInTheDocument()
    // The child is folded: not shown until its parent row is expanded.
    expect(screen.queryByText('21')).toBeNull()
    const orphanRow = screen.getByText('19').closest('tr')!
    expect(within(orphanRow).getByText('系统跟进')).toBeInTheDocument()
    await user.click(within(parentRow).getByRole('button', { name: /展开|expand/i }))
    const childRow = (await screen.findByText('21')).closest('tr')!
    expect(within(childRow).getByText('系统跟进')).toBeInTheDocument()
  })

  it('shows server-side state counts and filters the pills on the server', async () => {
    authenticate(['sites.read'])
    const counts = { queued: 2, running: 1, succeeded: 7, partial_failed: 1, failed: 3, cancelled: 4 }
    const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation(async (_token, _scope, params) => ({
      items: params.states?.includes('succeeded')
        ? [summary({ id: '66666666-6666-4666-8666-666666666666', display_id: '13', state: 'succeeded', target_type: 'whole_site' })]
        : [summary({ target_type: 'whole_site' })],
      state_counts: counts,
    }))
    const user = userEvent.setup()
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    expect(await screen.findByText('12')).toBeInTheDocument()
    // Counts cover every page (from the server), not the one loaded row.
    expect(screen.getByLabelText('任务状态统计')).toHaveTextContent('全部18完成7失败4处理中3')
    expect(screen.queryByText('统计当前页')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /完成\s*7/ }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[2]).toMatchObject({ states: ['succeeded'], cursor: undefined }))
    expect(await screen.findByText('13')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /失败\s*4/ }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[2]).toMatchObject({ states: ['failed', 'partial_failed'] }))
  })

  it('resubmits selected tasks through the resubmit command and retries with the same batch key', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [
      summary(),
      summary({ id: '77777777-7777-4777-8777-777777777777', display_id: '14', state: 'running' }),
    ] })
    const get = vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const create = vi.spyOn(cacheOperationsApi, 'create')
    const resubmit = vi.spyOn(cacheOperationsApi, 'resubmit')
      .mockRejectedValueOnce(new ApiError('temporary control-plane failure', 503, 'service_unavailable'))
      .mockResolvedValue({ ...operation, id: '88888888-8888-4888-8888-888888888888', state: 'queued' })
    const user = userEvent.setup()
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await screen.findByText('14')
    const resubmitSelected = screen.getByRole('button', { name: /重新提交选中/ })
    expect(resubmitSelected).toBeDisabled()
    // A task still running cannot be selected.
    expect(screen.getByRole('checkbox', { name: '14' })).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: '12' }))
    await user.click(resubmitSelected)

    expect(await screen.findByText('已重新提交 0 个任务，失败 1 个')).toBeInTheDocument()
    expect(resubmit.mock.calls[0]?.slice(1, 3)).toEqual([{ kind: 'tenant' }, operationID])
    const firstKey = resubmit.mock.calls[0]?.[3]
    expect(firstKey).toMatch(/^cache-resubmit-/)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('已重新提交 1 个任务，失败 0 个')).toBeInTheDocument()
    expect(resubmit.mock.calls[1]?.[3]).toBe(firstKey)
    // The server holds the original targets (query included) and nodes.
    expect(get).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
  })

  it('resubmits a task whose URL query is redacted in the read model', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({
      first_target: { ...operation.targets[0]!, display_url: 'https://www.example.com/a.js?query=redacted', query_redacted: true },
    })] })
    const resubmit = vi.spyOn(cacheOperationsApi, 'resubmit').mockResolvedValue({ ...operation, state: 'queued' })
    const user = userEvent.setup()
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await user.click(await screen.findByRole('button', { name: /^重新提交$/ }))
    expect(await screen.findByText('已重新提交 1 个任务，失败 0 个')).toBeInTheDocument()
    expect(resubmit).toHaveBeenCalledTimes(1)
  })

  it('opens the detail drawer with targets, nodes, and localized failures', async () => {
    authenticate(['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary()] })
    const get = vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('操作记录详情')).toBeInTheDocument()
    // The URL shows in the row, the drawer's target table and its per-item result.
    expect(screen.getAllByText('https://www.example.com/a.js')).toHaveLength(3)
    expect(screen.getAllByText('节点离线，任务将在重连后继续').length).toBeGreaterThan(0)
    expect(get).toHaveBeenCalledWith('memory-only-access-token', { kind: 'tenant' }, operationID)
    // CACHE-ADD-06a: site and node show their short display IDs; the UUID is only the hover title.
    const drawer = screen.getByRole('dialog')
    expect(within(drawer).queryByText(siteID)).toBeNull()
    expect(within(drawer).queryByText(nodeID)).toBeNull()
    expect(within(drawer).getByTitle(siteID)).toHaveTextContent('3')
    expect(within(drawer).getAllByTitle(nodeID).every((element) => element.textContent === '7')).toBe(true)
  })

  it('shows each node\'s cancel confirmation once the task was cancelled (CACHE-ADD-07)', async () => {
    authenticate(['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'cancelled' })] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({
      ...operation, state: 'cancelled',
      nodes: [
        { ...operation.nodes[0]!, state: 'cancelled', cancel_confirmation: 'cancelled' },
        { ...operation.nodes[0]!, node_id: '45555555-5555-4555-8555-555555555555', node_display_id: '8', state: 'cancelled', cancel_confirmation: 'unsupported' },
      ],
    })
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByRole('columnheader', { name: '节点取消确认' })).toBeInTheDocument()
    expect(screen.getByText('节点已停止')).toBeInTheDocument()
    expect(screen.getByText('节点版本不支持远程取消（仅停止后续调度）')).toBeInTheDocument()
  })

  it('retries failed items with the same idempotency key after an uncertain response', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const retry = vi.spyOn(cacheOperationsApi, 'retry')
      .mockRejectedValueOnce(new ApiError('temporary control-plane failure', 503, 'service_unavailable'))
      .mockResolvedValue(operation)
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await screen.findByText('12')
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    expect(await screen.findByText('缓存控制服务暂不可用，请稍后重试')).toBeInTheDocument()
    const firstKey = retry.mock.calls[0]?.[3]
    expect(firstKey).toMatch(/^cache-retry-/)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(retry).toHaveBeenCalledTimes(2))
    expect(retry.mock.calls[1]?.[3]).toBe(firstKey)
  })

  // fp-site CACHE-ADD-05：结果未知时行内重试被锁定，不能生成新请求覆盖原请求
  it('locks the row retry while a retry outcome is unknown', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    vi.spyOn(cacheOperationsApi, 'retry').mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    const user = userEvent.setup()
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await screen.findByText('12')
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await screen.findByRole('button', { name: '使用同一请求重试' })
    expect(screen.getByRole('button', { name: '重新提交失败项' })).toBeDisabled()
  })

  // fp-site CACHE-ADD-06：未收录的节点错误码显示中文说明而不是英文码
  it('shows a localized fallback for unknown failure codes', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    const node = operation.nodes[0]!
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({ ...operation, nodes: [{ ...node, last_error_code: 'brand_new_code' }] })
    const user = userEvent.setup()
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('节点返回未识别的稳定错误码（brand_new_code）')).toBeInTheDocument()
  })

  it('supports cursor pagination without duplicating a repeated cursor', async () => {
    authenticate(['sites.read'])
    const next = 'history-page-2'
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation(async (_token, _scope, params) => (
      params.cursor ? { items: [summary({ id: '66666666-6666-4666-8666-666666666666', display_id: '13' })], next_cursor: next } : { items: [summary()], next_cursor: next }
    ))
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await screen.findByText('12')
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('13')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(list).toHaveBeenCalledTimes(2)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
  })

  it('does not leak an unknown service error in the empty/error state', async () => {
    authenticate(['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockRejectedValue(new ApiError('private database details', 500, 'private_db_error', 'req-history-1'))

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    const alert = await findFeedback()
    expect(alert.querySelector('.cdnca-feedback-title')).toHaveTextContent('请求失败')
    expect(alert.querySelector('.cdnca-feedback-detail')).toHaveTextContent('请稍后重试')
    expect(alert.querySelector('.cdnca-feedback-request-id')).toHaveTextContent('请求 ID：req-history-1')
    expect(alert).not.toHaveTextContent('private database details')
  })

  // P2-09 CACHE-ADD-05：结果未知的请求身份不因换按钮、离页返回而换新幂等键。
  it('reuses the unknown resubmit key from the row button', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary()] })
    const resubmit = vi.spyOn(cacheOperationsApi, 'resubmit')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockResolvedValue({ ...operation, state: 'queued' })
    const user = userEvent.setup()
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await user.click(await screen.findByRole('button', { name: /^重新提交$/ }))
    expect(await screen.findByText('已重新提交 0 个任务，失败 1 个')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /^重新提交$/ }))
    expect(await screen.findByText('已重新提交 1 个任务，失败 0 个')).toBeInTheDocument()
    expect(resubmit.mock.calls[1]?.[3]).toBe(resubmit.mock.calls[0]?.[3])
    // Settled: the next resubmit is a new request.
    await user.click(screen.getByRole('button', { name: /^重新提交$/ }))
    await waitFor(() => expect(resubmit).toHaveBeenCalledTimes(3))
    expect(resubmit.mock.calls[2]?.[3]).not.toBe(resubmit.mock.calls[0]?.[3])
  })

  it('keeps an unknown retry key after leaving and returning to the page', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    const retry = vi.spyOn(cacheOperationsApi, 'retry')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockResolvedValue(operation)
    const user = userEvent.setup()
    const first = renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await screen.findByRole('button', { name: '使用同一请求重试' })
    first.unmount()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await waitFor(() => expect(retry).toHaveBeenCalledTimes(2))
    expect(retry.mock.calls[1]?.[3]).toBe(retry.mock.calls[0]?.[3])
  })

  // 另一个标签页或刷新后再点，先查服务端回执：已受理不再重发，已拒绝显示原因。
  it('reads the receipt of an unknown retry and resubmit before sending them again', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    const retry = vi.spyOn(cacheOperationsApi, 'retry').mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    const resubmit = vi.spyOn(cacheOperationsApi, 'resubmit').mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    const receipt = vi.spyOn(cacheOperationsApi, 'writeReceipt').mockResolvedValue(null)
    const user = userEvent.setup()
    const first = renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await screen.findByRole('button', { name: '使用同一请求重试' })
    await user.click(screen.getByRole('button', { name: /^重新提交$/ }))
    expect(await screen.findByText('已重新提交 0 个任务，失败 1 个')).toBeInTheDocument()
    first.unmount()

    receipt.mockReset()
    receipt
      .mockResolvedValueOnce({ status: 'accepted', decided_at: '2026-08-06T08:00:00Z', operation })
      .mockResolvedValueOnce({ status: 'rejected', decided_at: '2026-08-06T08:00:00Z', rejection: { code: 'entitlement_denied' } })
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await waitFor(() => expect(receipt).toHaveBeenCalledWith(expect.any(String), { kind: 'tenant' },
      { action: 'retry', operationID: operation.id, key: retry.mock.calls[0]![3] }))
    await user.click(screen.getByRole('button', { name: /^重新提交$/ }))
    expect(await screen.findByText('已重新提交 0 个任务，失败 1 个')).toBeInTheDocument()
    expect(receipt).toHaveBeenLastCalledWith(expect.any(String), { kind: 'tenant' },
      { action: 'resubmit', operationID: operation.id, key: resubmit.mock.calls[0]![3] })
    expect(retry).toHaveBeenCalledTimes(1)
    expect(resubmit).toHaveBeenCalledTimes(1)
    // Both answered: nothing is left to look up.
    expect(window.sessionStorage.getItem('cdnca.cache-pending-writes.v1')).toBe('[]')
  })

  it('does not reuse an unknown key for another account', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    const retry = vi.spyOn(cacheOperationsApi, 'retry')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockResolvedValue(operation)
    const user = userEvent.setup()
    const first = renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await screen.findByRole('button', { name: '使用同一请求重试' })
    first.unmount()

    const other = principal({
      scope_kind: 'tenant', scope_id: '23333333-3333-4333-8333-333333333333', tenant_id: '23333333-3333-4333-8333-333333333333',
      user_id: '12222222-2222-4222-8222-222222222222', permissions: ['sites.read', 'sites.manage'],
    })
    useSessionStore.getState().setSession(authResponse(other), other)
    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])
    await user.click(await screen.findByRole('button', { name: '重新提交失败项' }))
    await waitFor(() => expect(retry).toHaveBeenCalledTimes(2))
    expect(retry.mock.calls[1]?.[3]).not.toBe(retry.mock.calls[0]?.[3])
  })

  // P2-13 CACHEFLOW-U02：首次读取失败关掉反馈后不能显示“暂无记录”、零计数或第 1 页。
  it('keeps a first read failure visible after the feedback is closed', async () => {
    authenticate(['sites.read'])
    const list = vi.spyOn(cacheOperationsApi, 'list')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockResolvedValue({ items: [summary()], state_counts: { queued: 0, running: 0, succeeded: 0, partial_failed: 1, failed: 0, cancelled: 0 } })
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    const feedback = await findFeedback()
    await user.click(within(feedback).getByRole('button', { name: '知道了' }))
    expect(screen.queryByText('暂无缓存操作记录')).toBeNull()
    expect(screen.queryByText('第 1 页')).toBeNull()
    expect(screen.getByLabelText('任务状态统计')).not.toHaveTextContent('0')
    const table = screen.getByRole('region', { name: '操作记录' })
    expect(within(table).getByText('操作记录读取失败，当前不代表没有记录')).toBeInTheDocument()
    await user.click(within(table).getByRole('button', { name: '重试' }))
    expect(await screen.findByText('12')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
  })

  it('keeps the last good records and marks them when an update fails', async () => {
    authenticate(['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list')
      .mockResolvedValueOnce({ items: [summary()] })
      .mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    expect(await screen.findByText('12')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('更新失败，显示上次结果')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
  })

  // P2-12 CACHEFLOW-U01：列表 403 后关闭详情、停止读取，写入口全部失效，点刷新不解除。
  it('ends the open detail and every write once the history is denied', async () => {
    authenticate()
    const list = vi.spyOn(cacheOperationsApi, 'list')
      .mockResolvedValueOnce({ items: [summary({ state: 'failed' })] })
      .mockRejectedValue(new ApiError('denied', 403, 'permission_denied'))
    const get = vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({ ...operation, state: 'failed' })
    const retry = vi.spyOn(cacheOperationsApi, 'retry')
    const resubmit = vi.spyOn(cacheOperationsApi, 'resubmit')
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('操作记录详情')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('当前账号缺少网站读取权限')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('button', { name: '重新提交失败项' })).toBeNull())
    expect(screen.queryByRole('button', { name: '查看详情' })).toBeNull()
    const calls = { list: list.mock.calls.length, get: get.mock.calls.length }
    expect(screen.getByRole('button', { name: '刷新' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /重新提交选中/ })).toBeDisabled()
    window.dispatchEvent(new Event('focus'))
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(list.mock.calls.length).toBe(calls.list)
    expect(get.mock.calls.length).toBe(calls.get)
    expect(retry).not.toHaveBeenCalled()
    expect(resubmit).not.toHaveBeenCalled()
  })

  it('disables every write after a 403 write and keeps the read-only detail', async () => {
    authenticate()
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'failed' })] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({ ...operation, state: 'failed' })
    const retry = vi.spyOn(cacheOperationsApi, 'retry').mockRejectedValue(new ApiError('denied', 403, 'permission_denied'))
    const user = userEvent.setup()

    renderWithProviders(<CacheOperationHistoryPage />, ['/site/cache-clean/history'])

    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    const drawer = await screen.findByRole('dialog')
    await user.click(await within(drawer).findByRole('button', { name: '重新提交失败项' }))
    await waitFor(() => expect(within(drawer).getByRole('button', { name: '重新提交失败项' })).toBeDisabled())
    expect(screen.getByText('操作记录详情')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^重新提交$/ })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).toBeNull()
    expect(retry).toHaveBeenCalledTimes(1)
  })
})
