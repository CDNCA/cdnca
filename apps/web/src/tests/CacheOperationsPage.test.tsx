import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  cacheOperationsApi,
  type CacheOperation,
  type CacheOperationScope,
  type CacheOperationSummary,
} from '../api/cacheOperations'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { sitesApi, type SiteListItem } from '../api/sites'
import { useSessionStore, type SessionUpdate } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import CacheOperationsPage from '../pages/CacheOperationsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const operation: CacheOperation = {
  id: '55555555-5555-4555-8555-555555555555',
  display_id: '12',
  site_id: '33333333-3333-4333-8333-333333333333',
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
    node_id: '44444444-4444-4444-8444-444444444444',
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

const tenantAID = '22222222-2222-4222-8222-222222222222'
const tenantBID = '77777777-7777-4777-8777-777777777777'
const tenantBUserID = '88888888-8888-4888-8888-888888888888'
const siteAID = '33333333-3333-4333-8333-333333333333'
const tenantScopeID = '44444444-4444-4444-8444-444444444444'
const siteBID = '99999999-9999-4999-8999-999999999999'
const nodeID = '44444444-4444-4444-8444-444444444444'

function summary(overrides: Partial<CacheOperationSummary> = {}): CacheOperationSummary {
  return { ...operation, target_count: 1, node_count: 1, first_target: operation.targets[0]!, ...overrides }
}

function setCacheSession(options: {
  kind?: 'tenant' | 'platform'
  scopeID?: string
  tenantID?: string | null
  userID?: string
  permissions?: string[]
  accessToken?: string
  update?: SessionUpdate
} = {}) {
  const kind = options.kind ?? 'tenant'
  const actor = principal({
    scope_kind: kind,
    scope_id: options.scopeID ?? (kind === 'tenant' ? tenantAID : 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    tenant_id: options.tenantID === undefined ? (kind === 'tenant' ? tenantAID : null) : options.tenantID,
    user_id: options.userID ?? '11111111-1111-4111-8111-111111111111',
    permissions: options.permissions ?? ['sites.read', 'sites.manage'],
  })
  const response = authResponse(actor)
  useSessionStore.getState().setSession(
    { ...response, access_token: options.accessToken ?? response.access_token },
    actor,
    options.update,
  )
  const sessionEpoch = useSessionStore.getState().sessionEpoch
  return {
    actor,
    sessionEpoch,
    owner: [actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch] as const,
  }
}

function authenticate(kind: 'tenant' | 'platform', permissions: string[]) {
  return setCacheSession({ kind, permissions })
}

function QueryClientCapture({ capture }: { capture: (queryClient: QueryClient) => void }) {
  capture(useQueryClient())
  return null
}

function renderPageWithQueryClient(route = '/site/cache-clean') {
  let queryClient: QueryClient | undefined
  const result = renderWithProviders(
    <><QueryClientCapture capture={(client) => { queryClient = client }} /><CacheOperationsPage /></>,
    [route],
  )
  if (!queryClient) throw new Error('query client was not captured')
  return { ...result, queryClient }
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

async function selectOption(
  user: ReturnType<typeof userEvent.setup>,
  label: string,
  option: string,
) {
  await user.click(screen.getByRole('combobox', { name: label }))
  await user.click(await screen.findByText(option, { selector: '.ant-select-item-option-content' }))
}

// fix-cachereplica：没有创建弹窗；主区文本框直接输入，服务端按域名匹配网站（mockTargetSites）。
function mainTargets() {
  return screen.getByRole('textbox', { name: 'URL 列表' })
}

async function typeMainTargets(value: string) {
  fireEvent.change(await screen.findByRole('textbox', { name: 'URL 列表' }), { target: { value } })
}

// Waits until the debounced site match settled ("涉及 N 个网站" shows) with
// the given task count.
async function waitForTaskCount(count: number) {
  await waitFor(() => {
    expect(document.querySelector('.cache-replica-site-count')).not.toBeNull()
    expect(document.querySelector('.cache-replica-task-count')).toHaveTextContent(String(count))
  }, { timeout: 3000 })
}

function submitMain() {
  return screen.getByRole('button', { name: '提交任务' })
}

// Every line matches siteID (in the scope the request names, or tenantAID).
function mockTargetSites(siteID = siteAID) {
  if (vi.isMockFunction(cacheOperationsApi.targetSites)) return cacheOperationsApi.targetSites as unknown as ReturnType<typeof vi.spyOn>
  return vi.spyOn(cacheOperationsApi, 'targetSites').mockImplementation(async (_token, scope, input) => ({
    groups: [{
      site_id: siteID, scope_id: scope.kind === 'admin' ? scope.scopeId : tenantAID, site_display_id: '3',
      domain: 'www.example.com', target_ordinals: input.targets.map((_, index) => index + 1),
    }],
    unmatched: [],
  }))
}

// Fills the main area with one matched URL and submits it.
async function submitOneURL(user: ReturnType<typeof userEvent.setup>, target = 'https://www.example.com/cache-state.js') {
  mockTargetSites()
  await typeMainTargets(target)
  await waitForTaskCount(1)
  await user.click(submitMain())
}

// The node picker under 高级 lists carrying nodes (tenant) or the node inventory (admin).
async function pickNode(user: ReturnType<typeof userEvent.setup>, id: string) {
  if (!screen.queryByRole('group', { name: '高级' })) await user.click(screen.getByRole('button', { name: /^高级/ }))
  const advanced = screen.getByRole('group', { name: '高级' })
  await user.click(within(advanced).getByRole('combobox', { name: '节点（可选）' }))
  const option = await waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option')]
      .find((item) => item.textContent === `node-${id.slice(0, 4)}（192.0.2.7）`)
    if (!found) throw new Error(`node option not found: ${id}`)
    return found
  })
  await user.click(option)
  await user.keyboard('{Escape}')
}

function mockSites() {
  return vi.spyOn(sitesApi, 'list').mockResolvedValue({
    items: [{ id: siteAID, domain: 'www.example.com', domains: ['www.example.com', '*.example.com'] } as SiteListItem],
    total: 1, page: 1, limit: 50,
  })
}

async function pickSite(user: ReturnType<typeof userEvent.setup>, domain: string) {
  await user.click(await screen.findByRole('combobox', { name: '网站' }))
  const option = await waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.ant-select-item-option')].find((item) => item.textContent === domain)
    if (!found) throw new Error(`site option not found: ${domain}`)
    return found
  })
  await user.click(option)
}

function errorBar() {
  return document.querySelector<HTMLElement>('.cache-replica-error-bar')
}

function apiSpies() {
  return {
    list: vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] }),
    get: vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation),
    create: vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation),
    retry: vi.spyOn(cacheOperationsApi, 'retry').mockResolvedValue(operation),
    cancel: vi.spyOn(cacheOperationsApi, 'cancel').mockResolvedValue(operation),
  }
}

// W2: the administrator target tenant is a searchable picker; a pasted scope UUID is offered as an option.
async function pickScope(user: ReturnType<typeof userEvent.setup>, scope: string) {
  const toolbar = document.querySelector<HTMLElement>('.cache-operations-toolbar')!
  const combobox = within(toolbar).getByRole('combobox', { name: '目标租户' })
  await user.type(combobox, scope)
  const option = await waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.ant-select-item-option')]
      .find((item) => item.getAttribute('title') === scope || item.textContent === scope)
    if (!found) throw new Error(`scope option not found: ${scope}`)
    return found
  })
  await user.click(option)
}

function selectedScope(): string {
  return document.querySelector('.cache-operations-tenant .ant-select-selection-item')?.textContent ?? ''
}

const testNode = (id: string) => ({ id, display_id: '7', name: `node-${id.slice(0, 4)}`, ipv4: '192.0.2.7' })

describe('CacheOperationsPage', () => {
  // The create dialog's node picker reads its choices when it opens.
  beforeEach(() => {
    window.sessionStorage.clear()
    vi.spyOn(cacheOperationsApi, 'carryingNodes').mockResolvedValue([testNode(nodeID)])
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [testNode(nodeID) as unknown as NodeInventoryItem] })
    // fix-cachequota：租户端进入即读账号额度。
    vi.spyOn(cacheOperationsApi, 'dailyUsage').mockResolvedValue({
      scope_id: tenantScopeID, resets_at: '2026-10-25T16:00:00Z', revision: 0,
      url_purge: { limit: 2000, used: 0, remaining: 2000, default_limit: 2000, override: null },
      directory_purge: { limit: 500, used: 0, remaining: 500, default_limit: 500, override: null },
      prewarm: { limit: 2000, used: 0, remaining: 2000, default_limit: 2000, override: null },
    })
  })

  it('renders a permission denial without reading cache facts', () => {
    authenticate('tenant', [])
    const list = vi.spyOn(cacheOperationsApi, 'list')

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    expect(screen.getByText('无权查看缓存任务')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })

  it('renders the real empty state for a tenant reader', async () => {
    authenticate('tenant', ['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    expect(await screen.findByRole('heading', { name: '刷新预热' })).toBeInTheDocument()
    expect(await screen.findByText('暂无缓存任务')).toBeInTheDocument()
    expect(cacheOperationsApi.list).toHaveBeenCalledWith(
      'memory-only-access-token', { kind: 'tenant' }, expect.objectContaining({ limit: 20 }),
    )
  })

  // fix-cachereplica：两张卡 + 右栏额度/状态，没有创建弹窗、站点/租户/节点字段常显。
  it('renders the two-card layout with no create dialog and no site, tenant or node fields', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await screen.findByText('暂无缓存任务')
    expect(screen.getByRole('heading', { name: '操作类型' })).toBeInTheDocument()
    expect(screen.getByText(/刷新 URL、刷新目录（含整站）、预热次数按账号每天分别计算/)).toBeInTheDocument()
    expect(screen.getByText('当前：刷新 URL')).toBeInTheDocument()
    const modes = screen.getByRole('group', { name: '操作类型' })
    expect(within(modes).getAllByRole('button').map((button) => button.textContent)).toEqual(['刷新 URL', '刷新目录', '预热', '刷新整站'])
    expect(within(modes).getByRole('button', { name: '刷新 URL' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('heading', { name: 'URL 列表' })).toBeInTheDocument()
    expect(screen.getByText('每行一个完整 URL，适合清理已缓存资源。')).toBeInTheDocument()
    expect(screen.getByText('支持批量粘贴，空行会自动忽略')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '今日额度' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '提交状态' })).toBeInTheDocument()
    expect(screen.getByText('待输入')).toBeInTheDocument()
    expect(screen.getByText('提交成功后可在操作记录里查看进度。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建任务' })).toBeNull()
    expect(screen.queryByRole('combobox', { name: '网站' })).toBeNull()
    expect(screen.queryByRole('combobox', { name: '节点（可选）' })).toBeNull()
    expect(document.querySelector('.cache-operation-modal')).toBeNull()
    expect(submitMain()).toBeDisabled()
  })

  // 已输入 N 条，错误 N 条；错误条就地列出原因；有错误时提交禁用，状态「需修正」。
  it('counts and lists line errors in place and disables the submit', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const resolve = mockTargetSites()
    const create = vi.spyOn(cacheOperationsApi, 'create')

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await typeMainTargets('www.example.com/a.js\nhttps://www.example.com/b.js\n\nhttps://www.example.com/b.js')
    const count = document.querySelector('.cache-baseline-count')!
    expect(count).toHaveTextContent('已输入 3 条，错误 2 条')
    expect(count.querySelector('.cache-replica-error-count')).toHaveTextContent('2')
    const bar = errorBar()!
    expect(bar).toHaveAttribute('role', 'alert')
    expect(bar).toHaveTextContent('第 1 行 www.example.com/a.js：URL 需要以 http:// 或 https:// 开头')
    expect(bar).toHaveTextContent('第 3 行 https://www.example.com/b.js：与前面的 URL 重复')
    expect(mainTargets()).toHaveAttribute('aria-invalid', 'true')
    expect(screen.queryByText('支持批量粘贴，空行会自动忽略')).toBeNull()
    expect(screen.getByText('需修正')).toBeInTheDocument()
    expect(submitMain()).toBeDisabled()
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 500))
    expect(resolve).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()

    await typeMainTargets('https://www.example.com/a.js')
    expect(errorBar()).toBeNull()
    await waitForTaskCount(1)
    expect(document.querySelector('.cache-baseline-footer')).toHaveTextContent('本次将提交 1 个任务')
    expect(screen.getByText('待提交')).toBeInTheDocument()
    expect(submitMain()).toBeEnabled()
  })

  // 我方保留：按域名自动匹配网站，「未找到对应网站」逐条并入错误条与错误计数，不发创建请求。
  it('marks URLs with no matching site as errors and sends nothing', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    const resolve = vi.spyOn(cacheOperationsApi, 'targetSites').mockResolvedValue({
      groups: [{ site_id: siteAID, scope_id: tenantAID, site_display_id: '3', domain: 'www.example.com', target_ordinals: [1] }],
      unmatched: [{ target_ordinal: 2, reason: 'target_site_not_found' }],
    })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await typeMainTargets('https://www.example.com/a.js\nhttps://nowhere.test/b.js')
    await waitFor(() => expect(errorBar()).toHaveTextContent('第 2 行 https://nowhere.test/b.js：未找到对应网站'), { timeout: 3000 })
    expect(resolve).toHaveBeenCalledWith(expect.any(String), { kind: 'tenant' }, {
      action: 'purge', target_type: 'exact_url', targets: ['https://www.example.com/a.js', 'https://nowhere.test/b.js'],
    })
    expect(document.querySelector('.cache-baseline-count')).toHaveTextContent('已输入 2 条，错误 1 条')
    expect(submitMain()).toBeDisabled()
    expect(create).not.toHaveBeenCalled()
  })

  // fix-cachedlg：服务端按 URL 域名匹配网站，每站一个任务、独立幂等键；结果逐站列在卡内，未知的用原键重试。
  it('submits one task per matched site and retries an unknown one with the same key', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const siteB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    const sites = vi.spyOn(sitesApi, 'list')
    vi.spyOn(cacheOperationsApi, 'targetSites').mockResolvedValue({
      groups: [
        { site_id: siteAID, scope_id: tenantAID, site_display_id: '3', domain: 'www.example.com', target_ordinals: [1, 3] },
        { site_id: siteB, scope_id: tenantAID, site_display_id: '4', domain: 'api.example.com', target_ordinals: [2] },
      ],
      unmatched: [],
    })
    const create = vi.spyOn(cacheOperationsApi, 'create')
      .mockResolvedValueOnce(operation)
      .mockRejectedValueOnce(new ApiError('lost', 0, 'network_error'))
      .mockResolvedValueOnce({ ...operation, id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await typeMainTargets('https://www.example.com/a.js\nhttps://api.example.com/v1\nhttps://img.example.com/x.png')
    await waitForTaskCount(2)
    expect(document.querySelector('.cache-baseline-footer')).toHaveTextContent('本次将提交 2 个任务（涉及 2 个网站，每个网站一个任务）')
    // fix-cachequota：额度按账号共用，多网站不再分站提示。
    expect(screen.queryByText('涉及多个网站，额度按各网站分别计算')).not.toBeInTheDocument()
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(sites).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(create.mock.calls[0]![2]).toEqual({
      site_id: siteAID, action: 'purge', target_type: 'exact_url',
      targets: ['https://www.example.com/a.js', 'https://img.example.com/x.png'], node_ids: [], max_retries: 3,
    })
    expect(create.mock.calls[1]![2]).toMatchObject({ site_id: siteB, targets: ['https://api.example.com/v1'] })
    expect(create.mock.calls[0]![3]).not.toBe(create.mock.calls[1]![3])
    const results = document.querySelector<HTMLElement>('.cache-replica-results')!
    expect(await within(results).findByText(/^结果待确认/)).toBeInTheDocument()
    expect(screen.getByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    await user.click(within(results).getByRole('button', { name: '重试未成功的网站' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(3))
    expect(create.mock.calls[2]![3]).toBe(create.mock.calls[1]![3])
    expect(await within(results).findAllByRole('button', { name: '已受理，查看任务' })).toHaveLength(2)
    expect(screen.getByText('已提交')).toBeInTheDocument()
    expect(mainTargets()).toHaveValue('')
  })

  // CACHE-ADD-01：租户单个网站一次提交，受理后打开任务详情、清空输入。
  it('submits one site in one step and opens the task details', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/baseline.js\nhttps://www.example.com/app.css')

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]!.slice(1, 3)).toEqual([{ kind: 'tenant' }, {
      site_id: siteAID, action: 'purge', target_type: 'exact_url',
      targets: ['https://www.example.com/baseline.js', 'https://www.example.com/app.css'], node_ids: [], max_retries: 3,
    }])
    expect(create.mock.calls[0]![3]).toMatch(/^cache-create-/)
    expect(await screen.findByText('缓存任务详情')).toBeInTheDocument()
    expect(await screen.findByText('缓存任务已进入队列')).toBeInTheDocument()
    expect(mainTargets()).toHaveValue('')
  })

  it('switches the list copy and request for 刷新目录 and 预热', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const resolve = mockTargetSites()
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await user.click(await screen.findByRole('button', { name: '刷新目录' }))
    expect(screen.getByText('当前：刷新目录')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '目录 URL' })).toBeInTheDocument()
    await typeMainTargets('https://www.example.com/assets')
    expect(errorBar()).toHaveTextContent('目录 URL 需以 / 结尾且不带查询参数')
    await typeMainTargets('https://www.example.com/assets/')
    await waitForTaskCount(1)
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]![2]).toMatchObject({ action: 'purge', target_type: 'directory_prefix', targets: ['https://www.example.com/assets/'] })

    await user.click(screen.getByRole('button', { name: '关闭' }))
    await user.click(screen.getByRole('button', { name: '预热' }))
    expect(screen.getByRole('heading', { name: '预热 URL' })).toBeInTheDocument()
    expect(screen.getByText('每行一个完整 URL，提交后提前拉取资源。')).toBeInTheDocument()
    await typeMainTargets('https://www.example.com/home.html')
    await waitForTaskCount(1)
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]![2]).toMatchObject({ action: 'prewarm', target_type: 'exact_url', targets: ['https://www.example.com/home.html'] })
    expect(resolve).toHaveBeenCalledWith(expect.any(String), { kind: 'tenant' }, expect.objectContaining({ action: 'prewarm' }))
  })

  // ADD-10：服务端按行给出拒绝原因（如 HTTPS 未开启），显示在该网站的结果行，原输入保留。
  it('names the refused line and reason from the server', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const refused = new ApiError('refused', 400, 'invalid_request', 'cache-reject-1')
    refused.targetRejection = { ordinal: 2, reason: 'target_listener_not_enabled' }
    vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(refused)
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'http://www.example.com/a.js\nhttps://www.example.com/b.js')

    const results = await waitFor(() => { const node = document.querySelector<HTMLElement>('.cache-replica-results .is-failed'); if (!node) throw new Error('no failed row'); return node })
    expect(results).toHaveTextContent('未受理：第 2 个 URL 未受理：该网站未在此协议或端口上监听（如未开启 HTTPS）（请求 ID：cache-reject-1）')
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(screen.getByText('需修正')).toBeInTheDocument()
    expect(mainTargets()).toHaveValue('http://www.example.com/a.js\nhttps://www.example.com/b.js')
  })

  // P2-09 CACHE-ADD-05：结果未知后编辑输入（清掉结果），再提交同样内容仍用原幂等键；离页重进同理。
  it('keeps an unknown create key after the result is cleared and across a remount', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    vi.spyOn(cacheOperationsApi, 'targetSites').mockResolvedValue({
      groups: [{ site_id: siteAID, scope_id: tenantAID, site_display_id: '3', domain: 'www.example.com', target_ordinals: [1] }],
      unmatched: [],
    })
    const create = vi.spyOn(cacheOperationsApi, 'create')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockResolvedValue(operation)
    const user = userEvent.setup({ delay: null })

    const first = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/a.js')
    expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    await typeMainTargets('https://www.example.com/a.js ')
    expect(document.querySelector('.cache-replica-results')).toBeNull()
    await waitForTaskCount(1)
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]![3]).toBe(create.mock.calls[0]![3])
    first.unmount()

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/a.js')
    await waitFor(() => expect(create).toHaveBeenCalledTimes(3))
    expect(create.mock.calls[2]![3]).toBe(create.mock.calls[0]![3])
  })

  // CACHE-01 / fix-cachequota：额度按账号来自服务端接口，未选网站即显示，按当前类型切换；读失败给重试，不写假 0。
  it('shows the account\'s daily quota without a picked site and retries a failed read', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    mockTargetSites()
    const usage = vi.spyOn(cacheOperationsApi, 'dailyUsage')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockResolvedValue({
        scope_id: tenantScopeID, resets_at: '2026-10-25T16:00:00Z', revision: 0,
        url_purge: { limit: 2000, used: 3, remaining: 1997, default_limit: 2000, override: null },
        directory_purge: { limit: 100, used: 100, remaining: 0, default_limit: 500, override: 100 },
        prewarm: { limit: 500, used: 0, remaining: 500, default_limit: 500, override: null },
      })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    const panel = await screen.findByRole('complementary', { name: '任务额度与提交状态' })
    // fix-cachequota：额度按账号，未输入 URL、未选网站即读取。
    expect(await within(panel).findByText('额度读取失败', {}, { timeout: 3000 })).toBeInTheDocument()
    expect(within(panel).queryByText('0')).not.toBeInTheDocument()
    await user.click(within(panel).getByRole('button', { name: '重试' }))
    expect(await within(panel).findByText('1,997')).toBeInTheDocument()
    expect(within(panel).getByText('剩余 / 2,000')).toBeInTheDocument()
    expect(within(panel).getByText('已用 3 条')).toBeInTheDocument()
    expect(within(panel).getByText('总量 2,000')).toBeInTheDocument()
    expect(within(panel).getByText(/主账号和成员共用，本账号所有网站共用/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新目录' }))
    expect(await within(panel).findByText('总量 100', {}, { timeout: 3000 })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '预热' }))
    expect(await within(panel).findByText('总量 500', {}, { timeout: 3000 })).toBeInTheDocument()
    // 输入 URL 匹配到网站不改变额度（同一账号共用），不重读。
    const reads = usage.mock.calls.length
    await typeMainTargets('https://www.example.com/a.js')
    expect(within(panel).getByText('总量 500')).toBeInTheDocument()
    expect(usage).toHaveBeenCalledTimes(reads)
    expect(usage).toHaveBeenLastCalledWith('memory-only-access-token', { kind: 'tenant' })
  })

  // 我方保留：刷新整站作为第 4 个操作类型，URL 框换成按域名搜索的网站选择；额度读目录（含整站）一项。
  it('purges a whole site picked by domain from the fourth operation type', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    vi.spyOn(cacheOperationsApi, 'dailyUsage').mockResolvedValue({
      scope_id: tenantScopeID, resets_at: '2026-10-25T16:00:00Z', revision: 0,
      url_purge: { limit: 2000, used: 0, remaining: 2000, default_limit: 2000, override: null },
      directory_purge: { limit: 500, used: 4, remaining: 496, default_limit: 500, override: null },
      prewarm: { limit: 500, used: 0, remaining: 500, default_limit: 500, override: null },
    })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    mockSites()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await user.click(await screen.findByRole('button', { name: '刷新整站' }))
    expect(screen.getByText('当前：刷新整站')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'URL 列表' })).toBeNull()
    expect(submitMain()).toBeDisabled()
    await pickSite(user, 'www.example.com')
    const panel = screen.getByRole('complementary', { name: '任务额度与提交状态' })
    expect(await within(panel).findByText('496')).toBeInTheDocument()
    expect(document.querySelector('.cache-replica-task-count')).toHaveTextContent('1')
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]!.slice(1, 3)).toEqual([{ kind: 'tenant' }, {
      site_id: siteAID, action: 'purge', target_type: 'whole_site', targets: [], node_ids: [], max_retries: 3,
    }])
  })

  // 我方保留：节点范围放在「高级」里，默认全部承载节点；选中后随请求带上。
  it('keeps the node scope under 高级 and sends the picked nodes', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await screen.findByText('暂无缓存任务')
    expect(screen.queryByRole('group', { name: '高级' })).toBeNull()
    expect(cacheOperationsApi.carryingNodes).not.toHaveBeenCalled()
    await pickNode(user, nodeID)
    expect(screen.getByRole('button', { name: '高级（已设置）' })).toHaveAttribute('aria-expanded', 'true')
    await submitOneURL(user, 'https://www.example.com/a.js')
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]![2]).toMatchObject({ node_ids: [nodeID] })
  })

  it('keeps the submit disabled when sites.manage is missing', async () => {
    authenticate('tenant', ['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    mockTargetSites()
    const create = vi.spyOn(cacheOperationsApi, 'create')
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await typeMainTargets('https://www.example.com/a.js')
    await waitForTaskCount(1)
    expect(submitMain()).toBeDisabled()
    await user.click(submitMain())
    expect(create).not.toHaveBeenCalled()
  })

  it('keys identical tenant filters by the complete owner, effective scope, and token-free params', async () => {
    const tenantAOperation = summary({ site_id: siteAID })
    const tenantBOperation = summary({
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      site_id: siteBID,
      state: 'succeeded',
    })
    const pendingTenantB = deferred<{ items: CacheOperationSummary[] }>()
    const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation((token) => {
      if (token === 'tenant-a-cache-token') return Promise.resolve({ items: [tenantAOperation] })
      if (token === 'tenant-b-cache-token') return pendingTenantB.promise
      throw new Error(`unexpected cache list token ${token}`)
    })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const sessionA = setCacheSession({ accessToken: 'tenant-a-cache-token', permissions: ['sites.read'] })
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient()
    const tenantScope: CacheOperationScope = { kind: 'tenant' }
    const params = { limit: 20, cursor: undefined }
    const listKeyA = ['cache-operations', sessionA.owner, tenantScope, params] as const
    const detailKeyA = ['cache-operation', sessionA.owner, tenantScope, operation.id] as const

    const details = await screen.findByRole('button', { name: '查看详情' })
    expect(screen.getByTitle(siteAID)).toBeInTheDocument()
    expect(queryClient.getQueryState(listKeyA)).toMatchObject({ status: 'success', data: { items: [tenantAOperation] } })
    await user.click(details)
    expect((await screen.findAllByText('节点离线，任务将在重连后继续')).length).toBeGreaterThan(0)
    expect(queryClient.getQueryData(detailKeyA)).toEqual(operation)
    await user.click(screen.getByRole('button', { name: '关闭' }))

    let sessionB!: ReturnType<typeof setCacheSession>
    act(() => {
      sessionB = setCacheSession({
        scopeID: tenantBID,
        tenantID: tenantBID,
        userID: tenantBUserID,
        accessToken: 'tenant-b-cache-token',
        permissions: ['sites.read'],
      })
    })
    const listKeyB = ['cache-operations', sessionB.owner, tenantScope, params] as const
    await waitFor(() => expect(list).toHaveBeenCalledWith('tenant-b-cache-token', tenantScope, params))

    expect(document.querySelector('.cache-operations-table')).toHaveAttribute('aria-busy', 'true')
    expect(screen.queryByText(siteAID)).not.toBeInTheDocument()
    expect(queryClient.getQueryState(listKeyB)).toMatchObject({
      status: 'pending', fetchStatus: 'fetching', data: undefined,
    })

    await act(async () => pendingTenantB.resolve({ items: [tenantBOperation] }))
    expect(await screen.findByTitle(siteBID)).toBeInTheDocument()
    expect(queryClient.getQueryData(listKeyB)).toEqual({ items: [tenantBOperation] })
    const serializedKeys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(serializedKeys).not.toContain('tenant-a-cache-token')
    expect(serializedKeys).not.toContain('tenant-b-cache-token')
  })

  // adm-fix-a (10-25)：管理端「操作记录」不能链到仅租户可进的 /site/cache-clean/history（404）；
  // fix-cachereplica：管理员的记录在本页 ?tab=history。
  it('offers the operation history tab where each audience opens it', async () => {
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    authenticate('platform', ['sites.read', 'sites.manage'])
    const view = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    expect(screen.getByRole('tab', { name: '刷新预热' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '操作记录' })).toHaveAttribute('href', '/site/cache-clean?tab=history')
    view.unmount()
    authenticate('tenant', ['sites.read', 'sites.manage'])
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    expect(screen.getByRole('tab', { name: '操作记录' })).toHaveAttribute('href', '/site/cache-clean/history')
  })

  // CACHE-02：管理员在「操作记录」页签选租户看记录；「刷新预热」页签只有提交区。
  it('shows the administrator tenant picker and records on the history tab only', async () => {
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    authenticate('platform', ['sites.read', 'sites.manage'])
    const view = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    expect(view.container.querySelector('.cache-operations-management')).not.toHaveClass('cache-operations-management-admin')
    expect(screen.getByRole('heading', { name: '操作类型' })).toBeInTheDocument()
    view.unmount()

    const { container } = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean?tab=history'])
    expect(screen.getByRole('tab', { name: '操作记录' })).toHaveAttribute('aria-selected', 'true')
    expect(container.querySelector('.cache-operations-management')).toHaveClass('cache-operations-management-admin')
    expect(screen.queryByRole('heading', { name: '操作类型' })).toBeNull()
    expect(within(container.querySelector<HTMLElement>('.cache-operations-toolbar')!).getByRole('combobox', { name: '目标租户' })).toBeInTheDocument()
  })

  it('requires an explicit tenant scope before an administrator query', async () => {
    authenticate('platform', ['sites.read', 'sites.manage'])
    const list = vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean?tab=history'])

    expect(screen.getByText('请先选择目标租户')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
    await pickScope(user, '22222222-2222-4222-8222-222222222222')
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByText('暂无缓存任务')).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith(
      'memory-only-access-token',
      { kind: 'admin', scopeId: '22222222-2222-4222-8222-222222222222' },
      expect.objectContaining({ limit: 20 }),
    )
  })

  it('preserves scoped page, filters, drawer, draft, and unknown retry across token refreshes', async () => {
    const pageTwoOperation = summary({
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      site_id: siteAID,
      action: 'prewarm',
      state: 'failed',
    })
    const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation(async (_token, _scope, params) => (
      params.cursor === 'same-epoch-cursor-2'
        ? { items: [pageTwoOperation] }
        : { items: [summary({ site_id: siteAID })], next_cursor: 'same-epoch-cursor-2' }
    ))
    const get = vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({
      ...operation, id: pageTwoOperation.id, site_id: siteAID, state: 'failed',
    })
    const create = vi.spyOn(cacheOperationsApi, 'create')
      .mockRejectedValueOnce(new ApiError('private cache write host', 503, 'service_unavailable'))
      .mockResolvedValueOnce(operation)
    const session = setCacheSession({ accessToken: 'cache-refresh-token-a' })
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient()
    const toolbar = document.querySelector<HTMLElement>('.cache-operations-toolbar')!

    await screen.findByTitle(siteAID)
    const siteFilter = within(toolbar).getByLabelText('站点 ID')
    await user.type(siteFilter, siteAID)
    await selectOption(user, '任务类型', '预热')
    await selectOption(user, '任务状态', '失败')
    await user.click(within(toolbar).getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(
      'cache-refresh-token-a',
      { kind: 'tenant' },
      { site_id: siteAID, action: 'prewarm', states: ['failed'], limit: 20, cursor: undefined },
    ))
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('缓存任务详情')).toBeInTheDocument()
    mockTargetSites()
    await typeMainTargets('https://www.example.com/token-refresh.js')
    await waitForTaskCount(1)

    const listKey = [
      'cache-operations', session.owner, { kind: 'tenant' },
      { site_id: siteAID, action: 'prewarm', states: ['failed'], limit: 20, cursor: 'same-epoch-cursor-2' },
    ] as const
    const detailKey = [
      'cache-operation', session.owner, { kind: 'tenant' }, pageTwoOperation.id,
    ] as const
    const listReadsBeforeRefresh = list.mock.calls.length
    const detailReadsBeforeRefresh = get.mock.calls.length

    act(() => setCacheSession({ accessToken: 'cache-refresh-token-b', update: 'refresh' }))

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(list).toHaveBeenCalledTimes(listReadsBeforeRefresh)
    expect(get).toHaveBeenCalledTimes(detailReadsBeforeRefresh)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(siteFilter).toHaveValue(siteAID)
    expect(within(toolbar).getByText('预热')).toBeInTheDocument()
    expect(within(toolbar).getByText('失败')).toBeInTheDocument()
    expect(screen.getByText('缓存任务详情')).toBeInTheDocument()
    expect(mainTargets()).toHaveValue('https://www.example.com/token-refresh.js')

    await act(async () => {
      await Promise.all([
        queryClient.refetchQueries({ queryKey: listKey, type: 'active' }),
        queryClient.refetchQueries({ queryKey: detailKey, type: 'active' }),
      ])
    })
    expect(list.mock.calls.at(-1)?.[0]).toBe('cache-refresh-token-b')
    expect(get.mock.calls.at(-1)?.[0]).toBe('cache-refresh-token-b')

    await user.click(screen.getByRole('button', { name: '关闭' }))
    await user.click(submitMain())
    expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    expect(create.mock.calls[0]?.[0]).toBe('cache-refresh-token-b')
    const detailReadsBeforeUnknownRefresh = get.mock.calls.length

    act(() => setCacheSession({ accessToken: 'cache-refresh-token-c', update: 'refresh' }))

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(get).toHaveBeenCalledTimes(detailReadsBeforeUnknownRefresh)
    expect(screen.getByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(siteFilter).toHaveValue(siteAID)
    expect(mainTargets()).toHaveValue('https://www.example.com/token-refresh.js')

    await user.click(screen.getByRole('button', { name: '重试未成功的网站' }))
    expect(await screen.findByText('缓存任务已进入队列')).toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(2)
    expect(create.mock.calls[1]?.[0]).toBe('cache-refresh-token-c')
    expect(create.mock.calls[1]?.slice(1)).toEqual(create.mock.calls[0]?.slice(1))
    const serializedKeys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(serializedKeys).not.toContain('cache-refresh-token-a')
    expect(serializedKeys).not.toContain('cache-refresh-token-b')
    expect(serializedKeys).not.toContain('cache-refresh-token-c')
  })

  it.each([
    ['list', 'success'],
    ['list', 'error'],
    ['detail', 'success'],
    ['detail', 'error'],
  ] as const)(
    'resets tenant state and isolates a late tenant A %s %s after switching to B',
    async (lateKind, outcome) => {
      const operationA = summary({ site_id: siteAID })
      const operationAPageTwo = summary({
        ...operationA,
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        state: 'failed',
      })
      const operationB = summary({
        id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        site_id: siteBID,
        state: 'succeeded',
      })
      const lateListA = deferred<{ items: CacheOperationSummary[] }>()
      const lateDetailA = deferred<CacheOperation>()
      const pendingListB = deferred<{ items: CacheOperationSummary[] }>()
      let delayListA = false
      const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation((token, _scope, params) => {
        if (token === 'state-tenant-a-token') {
          if (delayListA) return lateListA.promise
          return Promise.resolve(params.cursor === 'tenant-a-state-cursor'
            ? { items: [operationAPageTwo] }
            : { items: [operationA], next_cursor: 'tenant-a-state-cursor' })
        }
        if (token === 'state-tenant-b-token') return pendingListB.promise
        throw new Error(`unexpected state list token ${token}`)
      })
      const get = vi.spyOn(cacheOperationsApi, 'get').mockImplementation((token) => {
        if (token === 'state-tenant-a-token') {
          return lateKind === 'detail'
            ? lateDetailA.promise
            : Promise.resolve({ ...operation, id: operationAPageTwo.id, site_id: siteAID })
        }
        throw new Error(`unexpected state detail token ${token}`)
      })
      vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(
        new ApiError('private tenant A create failure', 503, 'service_unavailable'),
      )
      const sessionA = setCacheSession({ accessToken: 'state-tenant-a-token' })
      const user = userEvent.setup({ delay: null })
      const { queryClient } = renderPageWithQueryClient()
      const toolbar = document.querySelector<HTMLElement>('.cache-operations-toolbar')!

      await screen.findByTitle(siteAID)
      await user.type(within(toolbar).getByLabelText('站点 ID'), siteAID)
      await user.click(within(toolbar).getByRole('button', { name: '查询' }))
      await user.click(screen.getByRole('button', { name: '下一页' }))
      expect(await screen.findByText('第 2 页')).toBeInTheDocument()
      await submitOneURL(user, 'https://tenant-a.example.com/draft.js')
      expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: '查看详情' }))
      await waitFor(() => expect(get).toHaveBeenCalledWith(
        'state-tenant-a-token', { kind: 'tenant' }, operationAPageTwo.id,
      ))
      if (lateKind === 'list') {
        delayListA = true
        await user.click(within(toolbar).getByRole('button', { name: '刷新' }))
        await waitFor(() => expect(list.mock.calls.filter(([token]) => token === 'state-tenant-a-token').length)
          .toBeGreaterThan(3))
      }

      const listKeyA = [
        'cache-operations', sessionA.owner, { kind: 'tenant' },
        { site_id: siteAID, limit: 20, cursor: 'tenant-a-state-cursor' },
      ] as const
      const detailKeyA = [
        'cache-operation', sessionA.owner, { kind: 'tenant' }, operationAPageTwo.id,
      ] as const
      let sessionB!: ReturnType<typeof setCacheSession>
      act(() => {
        sessionB = setCacheSession({
          scopeID: tenantBID,
          tenantID: tenantBID,
          userID: tenantBUserID,
          accessToken: 'state-tenant-b-token',
        })
      })
      const listKeyB = [
        'cache-operations', sessionB.owner, { kind: 'tenant' }, { limit: 20, cursor: undefined },
      ] as const
      await waitFor(() => expect(list).toHaveBeenCalledWith(
        'state-tenant-b-token', { kind: 'tenant' }, { limit: 20, cursor: undefined },
      ))

      expect(screen.getByText('第 1 页')).toBeInTheDocument()
      expect(within(toolbar).getByLabelText('站点 ID')).toHaveValue('')
      expect(screen.queryByText('缓存任务详情')).not.toBeInTheDocument()
      expect(document.querySelector('.cache-replica-results')).toBeNull()
      expect(screen.queryByText('结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText('private tenant A create failure')).not.toBeInTheDocument()
      expect(mainTargets()).toHaveValue('')
      expect(screen.queryByText(siteAID)).not.toBeInTheDocument()
      expect(queryClient.getQueryState(listKeyA)).toBeUndefined()
      expect(queryClient.getQueryState(detailKeyA)).toBeUndefined()
      expect(queryClient.getQueryData(listKeyA)).toBeUndefined()
      expect(queryClient.getQueryData(detailKeyA)).toBeUndefined()
      expect(queryClient.getQueryState(listKeyB)).toMatchObject({ status: 'pending', data: undefined })

      await act(async () => pendingListB.resolve({ items: [operationB] }))
      expect(await screen.findByTitle(siteBID)).toBeInTheDocument()
      expect(screen.queryByRole('group', { name: '高级' })).toBeNull()
      expect(screen.getByText('当前：刷新 URL')).toBeInTheDocument()

      await act(async () => {
        const late = lateKind === 'list' ? lateListA : lateDetailA
        if (outcome === 'success') {
          if (lateKind === 'list') {
            lateListA.resolve({ items: [summary({ site_id: siteAID, id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' })] })
          } else {
            lateDetailA.resolve({ ...operation, site_id: siteAID, targets: [{
              ...operation.targets[0]!, display_url: 'https://tenant-a.example.com/late-detail.js',
            }] })
          }
        } else {
          late.reject(new ApiError('private late tenant A read', 503, 'service_unavailable'))
        }
        await late.promise.catch(() => undefined)
        await Promise.resolve()
      })

      expect(screen.getByTitle(siteBID)).toBeInTheDocument()
      expect(screen.queryByText(siteAID)).not.toBeInTheDocument()
      expect(screen.queryByText('https://tenant-a.example.com/late-detail.js')).not.toBeInTheDocument()
      expect(screen.queryByText('private late tenant A read')).not.toBeInTheDocument()
      expect(screen.queryByText('缓存任务加载失败')).not.toBeInTheDocument()
      expect(queryClient.getQueryData(listKeyB)).toEqual({ items: [operationB] })
    },
  )

  it.each([
    ['tenant platform.admin is not a wildcard', ['platform.admin']],
    ['missing sites.read denies locally', ['sites.manage']],
  ] as const)('%s and performs no cache read, detail, or write', async (_name, permissions) => {
    await changeLocale('zh-CN')
    setCacheSession({ permissions: [...permissions] })
    const spies = apiSpies()

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    expect(await screen.findByText('无权查看缓存任务')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少网站读取权限')).toBeInTheDocument()
    expect(spies.list).not.toHaveBeenCalled()
    expect(spies.get).not.toHaveBeenCalled()
    expect(spies.create).not.toHaveBeenCalled()
    expect(spies.retry).not.toHaveBeenCalled()
    expect(spies.cancel).not.toHaveBeenCalled()
  })

  it('terminally blocks polling, reconnects, stale controls, and active refetches after a list refresh returns 403', async () => {
    await changeLocale('zh-CN')
    const t = i18n.getFixedT('zh-CN', 'cacheOperations')
    const activeOperation = summary({ site_id: siteAID, state: 'running' })
    const list = vi.spyOn(cacheOperationsApi, 'list')
      .mockResolvedValueOnce({ items: [activeOperation], next_cursor: 'terminal-forbidden-next' })
      .mockRejectedValueOnce(new ApiError('private cache role row', 403, 'permission_denied'))
      .mockResolvedValue({ items: [activeOperation], next_cursor: 'terminal-forbidden-next' })
    const session = setCacheSession({ accessToken: 'terminal-forbidden-token', permissions: ['sites.read'] })
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient()

    await screen.findByTitle(siteAID)
    const staleRefresh = screen.getByRole('button', { name: t('actions.refresh') })
    const staleNext = screen.getByRole('button', { name: t('actions.next') })
    await user.click(staleRefresh)

    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    expect(screen.queryByText('private cache role row')).not.toBeInTheDocument()
    const readsAfterForbidden = list.mock.calls.length

    vi.useFakeTimers()
    try {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3_100)
        window.dispatchEvent(new Event('focus'))
        window.dispatchEvent(new Event('online'))
        fireEvent.click(staleRefresh)
        fireEvent.click(staleNext)
        await queryClient.refetchQueries({
          queryKey: ['cache-operations', session.owner],
          type: 'active',
        })
        await Promise.resolve()
      })

      expect(screen.getByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
      expect(list).toHaveBeenCalledTimes(readsAfterForbidden)
    } finally {
      vi.useRealTimers()
    }
  })

  it('blocks detached create and retry submissions after live sites.manage revocation', async () => {
    const failed = summary({ site_id: siteAID, state: 'failed' })
    const list = vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [failed] })
    const get = vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    const retry = vi.spyOn(cacheOperationsApi, 'retry').mockResolvedValue(operation)
    const cancel = vi.spyOn(cacheOperationsApi, 'cancel').mockResolvedValue(operation)
    const session = setCacheSession({ accessToken: 'manage-before-revocation' })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    const staleRetry = await screen.findByRole('button', { name: '重试失败项' })
    mockTargetSites()
    await typeMainTargets('https://www.example.com/revoked.js')
    await waitForTaskCount(1)
    const staleSubmit = submitMain()
    expect(staleSubmit).toBeEnabled()
    const readsBeforeRevocation = list.mock.calls.length

    act(() => setCacheSession({
      accessToken: 'manage-after-revocation',
      permissions: ['sites.read'],
      update: 'refresh',
    }))

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRevocation)
    expect(submitMain()).toBeDisabled()
    expect(screen.getByRole('button', { name: '重试失败项' })).toBeDisabled()
    fireEvent.click(staleSubmit)
    fireEvent.click(staleRetry)
    await act(async () => { await Promise.resolve() })

    expect(list).toHaveBeenCalledTimes(readsBeforeRevocation)
    expect(get).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
    expect(retry).not.toHaveBeenCalled()
    expect(cancel).not.toHaveBeenCalled()
  })

  it('blocks stale list and detail controls after live sites.read revocation in the same session', async () => {
    await changeLocale('zh-CN')
    const t = i18n.getFixedT('zh-CN', 'cacheOperations')
    const activeOperation = summary({ site_id: siteAID, state: 'running' })
    const list = vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({
      items: [activeOperation], next_cursor: 'revoked-read-next',
    })
    const get = vi.spyOn(cacheOperationsApi, 'get').mockRejectedValue(
      new ApiError('private cache detail dependency', 503, 'service_unavailable'),
    )
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    const retry = vi.spyOn(cacheOperationsApi, 'retry').mockResolvedValue(operation)
    const cancel = vi.spyOn(cacheOperationsApi, 'cancel').mockResolvedValue(operation)
    const session = setCacheSession({ accessToken: 'read-before-revocation' })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    const staleDetails = await screen.findByRole('button', { name: t('actions.details') })
    const staleRefresh = screen.getByRole('button', { name: t('actions.refresh') })
    const staleNext = screen.getByRole('button', { name: t('actions.next') })
    await user.click(staleDetails)
    expect(await screen.findByText(t('errors.detailLoadFailed'))).toBeInTheDocument()
    expect(screen.queryByText('private cache detail dependency')).not.toBeInTheDocument()
    const staleDetailRetry = screen.getByRole('button', { name: t('actions.retry') })
    const listReadsBeforeRevocation = list.mock.calls.length
    const detailReadsBeforeRevocation = get.mock.calls.length

    act(() => {
      setCacheSession({
        accessToken: 'read-after-revocation',
        permissions: ['sites.manage'],
        update: 'refresh',
      })
      fireEvent.click(staleDetails)
      fireEvent.click(staleDetailRetry)
      fireEvent.click(staleRefresh)
      fireEvent.click(staleNext)
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    await act(async () => { await Promise.resolve() })
    expect(list).toHaveBeenCalledTimes(listReadsBeforeRevocation)
    expect(get).toHaveBeenCalledTimes(detailReadsBeforeRevocation)
    expect(create).not.toHaveBeenCalled()
    expect(retry).not.toHaveBeenCalled()
    expect(cancel).not.toHaveBeenCalled()
  })

  it('keeps a platform list 403 terminal to its target scope while another target remains queryable', async () => {
    await changeLocale('zh-CN')
    const t = i18n.getFixedT('zh-CN', 'cacheOperations')
    const targetA = tenantAID
    const targetB = tenantBID
    const targetBOperation = summary({
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', site_id: siteBID, state: 'succeeded',
    })
    const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation(async (_token, scope) => {
      if (scope.kind !== 'admin') throw new Error('expected platform cache scope')
      if (scope.scopeId === targetA) {
        throw new ApiError('private target A permission row', 403, 'permission_denied')
      }
      if (scope.scopeId === targetB) return { items: [targetBOperation] }
      throw new Error(`unexpected platform target ${scope.scopeId}`)
    })
    const session = setCacheSession({
      kind: 'platform', accessToken: 'platform-scope-terminal-token', permissions: ['sites.read'],
    })
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient('/site/cache-clean?tab=history')
    const toolbar = document.querySelector<HTMLElement>('.cache-operations-toolbar')!
    const scopeInput = within(toolbar).getByRole('combobox', { name: t('filters.scope') })
    const query = within(toolbar).getByRole('button', { name: t('actions.query') })
    const refresh = within(toolbar).getByRole('button', { name: t('actions.refresh') })
    const params = { limit: 20, cursor: undefined }
    const targetAScope: CacheOperationScope = { kind: 'admin', scopeId: targetA }
    const targetAKey = ['cache-operations', session.owner, targetAScope, params] as const

    await pickScope(user, targetA)
    await user.click(query)

    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    expect(screen.queryByText('private target A permission row')).not.toBeInTheDocument()
    expect(toolbar).toBeInTheDocument()
    expect(scopeInput).toBeEnabled()
    expect(selectedScope()).toBe(targetA)
    expect(query).toBeEnabled()
    expect(queryClient.getQueryState(targetAKey)).toMatchObject({ status: 'error' })
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((item) => item.queryKey)))
      .not.toContain('platform-scope-terminal-token')
    const targetAReads = list.mock.calls.filter(
      ([, scope]) => scope.kind === 'admin' && scope.scopeId === targetA,
    ).length

    fireEvent.click(refresh)
    await act(async () => {
      await queryClient.refetchQueries({
        queryKey: ['cache-operations', session.owner, targetAScope],
        type: 'active',
      })
      await Promise.resolve()
    })
    expect(list.mock.calls.filter(
      ([, scope]) => scope.kind === 'admin' && scope.scopeId === targetA,
    )).toHaveLength(targetAReads)

    await pickScope(user, targetB)
    await user.click(query)

    expect(await screen.findByTitle(siteBID)).toBeInTheDocument()
    expect(screen.queryByText(t('errors.forbiddenTitle'))).not.toBeInTheDocument()
    expect(list.mock.calls.some(([, scope]) => scope.kind === 'admin' && scope.scopeId === targetB)).toBe(true)
    const targetBScope: CacheOperationScope = { kind: 'admin', scopeId: targetB }
    const targetBKey = ['cache-operations', session.owner, targetBScope, params] as const
    expect(queryClient.getQueryData(targetBKey)).toEqual({ items: [targetBOperation] })
    expect(targetAKey[1]).toEqual(targetBKey[1])
    expect(targetAKey[2]).not.toEqual(targetBKey[2])
    expect(JSON.stringify([targetAKey, targetBKey])).not.toContain('platform-scope-terminal-token')
  })

  it('isolates platform target state and permits an unknown retry only after returning to its owner and scope', async () => {
    const targetA = tenantAID
    const targetB = tenantBID
    const targetAOperation = summary({ site_id: siteAID, state: 'failed' })
    const targetBOperation = summary({
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', site_id: siteBID, state: 'succeeded',
    })
    const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation(async (_token, scope, params) => {
      if (scope.kind !== 'admin') throw new Error('expected platform cache scope')
      if (scope.scopeId === targetA) {
        return params.cursor
          ? { items: [targetAOperation] }
          : { items: [targetAOperation], next_cursor: 'platform-target-a-next' }
      }
      if (scope.scopeId === targetB) return { items: [targetBOperation] }
      throw new Error(`unexpected platform target ${scope.scopeId}`)
    })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const retry = vi.spyOn(cacheOperationsApi, 'retry')
      .mockRejectedValueOnce(new ApiError('private target A retry', 503, 'service_unavailable'))
      .mockResolvedValueOnce(operation)
    setCacheSession({ kind: 'platform', accessToken: 'platform-target-token' })
    const user = userEvent.setup({ delay: null })
    renderPageWithQueryClient('/site/cache-clean?tab=history')
    const toolbar = document.querySelector<HTMLElement>('.cache-operations-toolbar')!
    const siteFilter = within(toolbar).getByLabelText('站点 ID')

    await pickScope(user, targetA)
    await user.type(siteFilter, siteAID)
    await user.click(within(toolbar).getByRole('button', { name: '查询' }))
    expect(await screen.findByTitle(siteAID)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试失败项' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const targetARetry = screen.getByRole('button', { name: '使用同一请求重试' })

    await pickScope(user, targetB)
    await user.click(within(toolbar).getByRole('button', { name: '查询' }))
    expect(await screen.findByTitle(siteBID)).toBeInTheDocument()

    expect(selectedScope()).toBe(targetB)
    expect(siteFilter).toHaveValue('')
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(retry).toHaveBeenCalledTimes(1)
    fireEvent.click(targetARetry)
    await act(async () => { await Promise.resolve() })
    expect(retry).toHaveBeenCalledTimes(1)

    await pickScope(user, targetA)
    await user.click(within(toolbar).getByRole('button', { name: '查询' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('失败项已重新排队')).toBeInTheDocument()
    expect(retry).toHaveBeenCalledTimes(2)
    expect(retry.mock.calls[1]).toEqual(retry.mock.calls[0])
    expect(list.mock.calls.some(([, scope]) => scope.kind === 'admin' && scope.scopeId === targetB)).toBe(true)
  })

  it.each([
    ['create', 'success'],
    ['create', 'error'],
    ['retry', 'success'],
    ['retry', 'error'],
    ['cancel', 'success'],
    ['cancel', 'error'],
  ] as const)(
    'ignores a late tenant A %s %s without changing tenant B messages, locks, cache, or invalidation',
    async (kind, outcome) => {
      const operationA = summary({ state: kind === 'cancel' ? 'running' : 'failed', site_id: siteAID })
      const operationB = summary({
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', site_id: siteBID, state: 'succeeded',
      })
      const pendingWriteA = deferred<CacheOperation>()
      const list = vi.spyOn(cacheOperationsApi, 'list').mockImplementation(async (token) => {
        if (token === 'late-write-a-token') return { items: kind === 'create' ? [] : [operationA] }
        if (token === 'late-write-b-token') return { items: [operationB] }
        throw new Error(`unexpected late write list token ${token}`)
      })
      const create = vi.spyOn(cacheOperationsApi, 'create').mockImplementation(() => pendingWriteA.promise)
      const retry = vi.spyOn(cacheOperationsApi, 'retry').mockImplementation(() => pendingWriteA.promise)
      const cancel = vi.spyOn(cacheOperationsApi, 'cancel').mockImplementation(() => pendingWriteA.promise)
      setCacheSession({ accessToken: 'late-write-a-token' })
      const user = userEvent.setup({ delay: null })
      const { queryClient } = renderPageWithQueryClient()
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')

      if (kind === 'create') {
        await screen.findByText('暂无缓存任务')
        await submitOneURL(user, 'https://tenant-a.example.com/late-create.js')
        await waitFor(() => expect(create).toHaveBeenCalledOnce())
      } else if (kind === 'retry') {
        await user.click(await screen.findByRole('button', { name: '重试失败项' }))
        await waitFor(() => expect(retry).toHaveBeenCalledOnce())
      } else {
        await user.click(await screen.findByRole('button', { name: '取消任务' }))
        await user.click(await screen.findByRole('button', { name: '确认' }))
        await waitFor(() => expect(cancel).toHaveBeenCalledOnce())
      }

      let sessionB!: ReturnType<typeof setCacheSession>
      act(() => {
        sessionB = setCacheSession({
          scopeID: tenantBID,
          tenantID: tenantBID,
          userID: tenantBUserID,
          accessToken: 'late-write-b-token',
        })
      })
      expect(await screen.findByTitle(siteBID)).toBeInTheDocument()
      const bKey = [
        'cache-operations', sessionB.owner, { kind: 'tenant' }, { limit: 20, cursor: undefined },
      ] as const
      expect(queryClient.getQueryData(bKey)).toEqual({ items: [operationB] })
      expect(screen.queryByText(siteAID)).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      expect(document.querySelector('.cache-replica-results')).toBeNull()
      expect(screen.queryByText('提交中', { selector: '.cache-baseline-submit-status' })).toBeNull()
      expect(invalidate).not.toHaveBeenCalled()
      const readsBeforeSettlement = list.mock.calls.length

      await act(async () => {
        if (outcome === 'success') {
          pendingWriteA.resolve(operation)
        } else {
          pendingWriteA.reject(new ApiError('private late tenant A write', 503, 'service_unavailable'))
        }
        await pendingWriteA.promise.catch(() => undefined)
        await Promise.resolve()
      })

      expect(screen.getByTitle(siteBID)).toBeInTheDocument()
      expect(screen.queryByText(siteAID)).not.toBeInTheDocument()
      expect(screen.queryByText('缓存任务已进入队列')).not.toBeInTheDocument()
      expect(screen.queryByText('失败项已重新排队')).not.toBeInTheDocument()
      expect(screen.queryByText('取消请求已提交')).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText('private late tenant A write')).not.toBeInTheDocument()
      expect(document.querySelector('.cache-replica-results')).toBeNull()
      expect(screen.queryByText('缓存任务详情')).not.toBeInTheDocument()
      expect(queryClient.getQueryData(bKey)).toEqual({ items: [operationB] })
      expect(list).toHaveBeenCalledTimes(readsBeforeSettlement)
      expect(invalidate).not.toHaveBeenCalled()
    },
  )

  it('shows localized node failure details and exposes safe retry and cancel boundaries', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [{
      ...operation,
      target_count: 1,
      node_count: 1,
      first_target: operation.targets[0]!,
    }] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const retry = vi.spyOn(cacheOperationsApi, 'retry').mockResolvedValue({ ...operation, state: 'queued' })
    const cancel = vi.spyOn(cacheOperationsApi, 'cancel').mockResolvedValue({ ...operation, state: 'cancelled' })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    // CACHE-ADD-06a: the list's site column is the short display ID, the UUID only its title.
    expect(await screen.findByTitle(siteAID)).toHaveTextContent('3')
    expect(screen.queryByText(siteAID)).toBeNull()
    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect((await screen.findAllByText('节点离线，任务将在重连后继续')).length).toBeGreaterThan(0)
    expect(screen.queryByText(nodeID)).toBeNull()
    expect(screen.getAllByTitle(nodeID).every((element) => element.textContent === '7')).toBe(true)
    await user.click(screen.getAllByRole('button', { name: '重试失败项' }).at(-1)!)
    expect(retry).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole('button', { name: '关闭' }))
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [{
      ...operation,
      state: 'running',
      target_count: 1,
      node_count: 1,
      first_target: operation.targets[0]!,
    }] })
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await user.click(await screen.findByRole('button', { name: '取消任务' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('shows node cancel confirmations only for a cancelled task and explains older nodes (CACHE-ADD-07)', async () => {
    authenticate('tenant', ['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary({ state: 'cancelled' })] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({
      ...operation, state: 'cancelled',
      nodes: [{ ...operation.nodes[0]!, state: 'cancelled', cancel_confirmation: 'unresponsive' }],
    })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByRole('columnheader', { name: '节点取消确认' })).toBeInTheDocument()
    expect(screen.getByText('节点未响应')).toBeInTheDocument()
  })

  it('shows the canonical target identity without revealing redacted query values', async () => {
    const rawQueryValue = 'private-token-value'
    const target = {
      ...operation.targets[0]!,
      display_url: 'https://www.example.com/a.js?token=redacted',
      canonical_path: '/a.js?token=redacted',
      target_sha256: 'b'.repeat(64),
      query_redacted: true,
    }
    authenticate('tenant', ['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [summary()] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue({ ...operation, targets: [target] })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await user.click(await screen.findByRole('button', { name: '查看详情' }))

    const section = screen.getByRole('heading', { name: '规范化目标' }).closest('section')!
    expect(within(section).getByRole('columnheader', { name: '序号' })).toBeInTheDocument()
    expect(within(section).getByRole('columnheader', { name: '脱敏目标 URL' })).toBeInTheDocument()
    expect(within(section).getByRole('columnheader', { name: '规范化路径' })).toBeInTheDocument()
    expect(within(section).getByRole('columnheader', { name: '目标 SHA-256' })).toBeInTheDocument()
    expect(within(section).getByRole('columnheader', { name: '查询参数已脱敏' })).toBeInTheDocument()
    expect(within(section).getByText(target.display_url)).toBeInTheDocument()
    expect(within(section).getByText(target.canonical_path)).toBeInTheDocument()
    expect(within(section).getByText(target.target_sha256)).toBeInTheDocument()
    expect(within(section).getByText('是')).toBeInTheDocument()
    expect(screen.queryByText(rawQueryValue)).not.toBeInTheDocument()
  })

  // 服务端拒绝只显示中文映射与请求 ID，不露原文。
  it.each([
    ['entitlement_denied', 403, '当前授权不允许执行缓存刷新或预热'],
    ['daily_limit_exceeded', 429, '已超过本账号今日的刷新或预热额度，请明天再试或联系管理员调整'],
    ['wildcard_purge_unsupported', 409, '承载该网站的节点中有版本过旧、不支持通配域名刷新的节点，请先升级节点，或改填具体域名的 URL'],
    ['wildcard_target_host', 400, '预热的 URL 必须是具体域名（如 www.a.com），不能是通配符（如 *.a.com）'],
  ] as const)('localizes a %s refusal in the site result without the server message', async (code, status, text) => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(new ApiError('private server decision', status, code, 'cache-refusal-safe'))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/a.js')

    const failed = await waitFor(() => { const node = document.querySelector<HTMLElement>('.cache-replica-results .is-failed'); if (!node) throw new Error('no failed row'); return node })
    expect(failed).toHaveTextContent(`未受理：${text}（请求 ID：cache-refusal-safe）`)
    expect(screen.queryByText(/private server decision/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试未成功的网站' })).toBeInTheDocument()
  })

  // fp-site2 Q4：刷新可填通配主机，预热与不合规的通配在输入时就标为错误、不发请求。
  it.each([
    ['刷新 URL', 'https://*.example.com/a.js'],
    ['刷新目录', 'https://*.example.com/static/'],
  ])('accepts a wildcard host for %s', async (mode, target) => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    mockTargetSites()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await user.click(await screen.findByRole('button', { name: mode }))
    await typeMainTargets(target)
    expect(errorBar()).toBeNull()
    await waitForTaskCount(1)
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]![2]).toMatchObject({ action: 'purge', targets: [target] })
  })

  it.each([
    ['预热', 'https://*.example.com/a.js', '预热不支持通配域名'],
    ['刷新 URL', 'https://a*.example.com/a.js', '通配域名只支持开头一个 *.'],
    ['刷新 URL', 'https://*.*.example.com/a.js', '通配域名只支持开头一个 *.'],
    ['刷新 URL', 'https://*.com/a.js', '通配域名只支持开头一个 *.'],
  ])('marks %s target %s as an error before any request', async (mode, target, reason) => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const resolve = mockTargetSites()
    const create = vi.spyOn(cacheOperationsApi, 'create')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await user.click(await screen.findByRole('button', { name: mode }))
    await typeMainTargets(target)
    expect(errorBar()).toHaveTextContent(reason)
    expect(submitMain()).toBeDisabled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(resolve).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
  })

  it('lists list-wide limits in the error bar', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await typeMainTargets(Array.from({ length: 501 }, (_, index) => `https://www.example.com/${index}.js`).join('\n'))
    expect(errorBar()).toHaveTextContent('一次最多提交 500 个 URL')
    expect(document.querySelector('.cache-baseline-count')).toHaveTextContent('已输入 501 条，错误 1 条')
    expect(submitMain()).toBeDisabled()
  })

  // 管理员不选目标租户也能提交：URL 匹配全部租户的网站，任务建在各网站所在租户下。
  it('lets an administrator submit URLs of several tenants without picking a tenant', async () => {
    authenticate('platform', ['platform.admin'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const resolve = vi.spyOn(cacheOperationsApi, 'targetSites').mockResolvedValue({
      groups: [
        { site_id: siteAID, scope_id: tenantAID, site_display_id: '3', domain: 'www.example.com', target_ordinals: [1] },
        { site_id: siteBID, scope_id: tenantBID, site_display_id: '9', domain: 'b.example.net', target_ordinals: [2] },
      ],
      unmatched: [],
    })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await pickNode(user, nodeID)
    await typeMainTargets('https://www.example.com/a.js\nhttps://b.example.net/b.js')
    await waitForTaskCount(2)
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(resolve).toHaveBeenCalledWith(expect.any(String), { kind: 'admin-all' }, expect.objectContaining({ action: 'purge' }))
    expect(create.mock.calls[0]!.slice(1, 3)).toEqual([{ kind: 'admin', scopeId: tenantAID }, {
      site_id: siteAID, action: 'purge', target_type: 'exact_url', targets: ['https://www.example.com/a.js'],
      node_ids: [nodeID], max_retries: 3,
    }])
    expect(create.mock.calls[1]!.slice(1, 3)).toEqual([{ kind: 'admin', scopeId: tenantBID }, expect.objectContaining({
      site_id: siteBID, targets: ['https://b.example.net/b.js'],
    })])
    const accepted = await screen.findAllByRole('button', { name: '已受理，查看任务' })
    expect(accepted).toHaveLength(2)
    // 管理员查看受理的任务：切到「操作记录」页签，目标租户为该网站所在租户。
    await user.click(accepted[1]!)
    expect(await screen.findByText('缓存任务详情')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '操作记录' })).toHaveAttribute('aria-selected', 'true')
    expect(selectedScope()).toBe(tenantBID)
  })

  // fix-smallbatch 4：管理员在「高级」选了目标租户时，URL 只匹配该租户的网站（target-sites 带 scope_id）。
  it('matches URLs only in the tenant an administrator picked under 高级', async () => {
    authenticate('platform', ['platform.admin'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const resolve = vi.spyOn(cacheOperationsApi, 'targetSites').mockResolvedValue({
      groups: [{ site_id: siteAID, scope_id: tenantAID, site_display_id: '3', domain: 'www.example.com', target_ordinals: [1] }],
      unmatched: [],
    })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await user.click(await screen.findByRole('button', { name: /^高级/ }))
    const advanced = screen.getByRole('group', { name: '高级' })
    await user.type(within(advanced).getByRole('combobox', { name: '目标租户' }), tenantAID)
    await user.click(await waitFor(() => {
      const found = [...document.querySelectorAll<HTMLElement>('.ant-select-item-option')].find((item) => item.getAttribute('title') === tenantAID || item.textContent === tenantAID)
      if (!found) throw new Error('tenant option not found')
      return found
    }))
    await typeMainTargets('https://www.example.com/a.js')
    await waitForTaskCount(1)
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(resolve).toHaveBeenCalled()
    for (const call of resolve.mock.calls) expect(call[1]).toEqual({ kind: 'admin', scopeId: tenantAID })
    expect(create.mock.calls[0]![1]).toEqual({ kind: 'admin', scopeId: tenantAID })
  })

  // 管理员整站刷新：任务建在所选网站所在的租户下（网站详情的 scope_id）。
  it('purges an administrator\'s whole site in the site\'s tenant', async () => {
    authenticate('platform', ['platform.admin'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'dailyUsage').mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    vi.spyOn(sitesApi, 'detail').mockResolvedValue({ id: siteAID, scope_id: tenantBID } as Awaited<ReturnType<typeof sitesApi.detail>>)
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue(operation)
    mockSites()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    await user.click(await screen.findByRole('button', { name: '刷新整站' }))
    await pickSite(user, 'www.example.com')
    await waitFor(() => expect(submitMain()).toBeEnabled())
    await user.click(submitMain())
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0]!.slice(1, 3)).toEqual([{ kind: 'admin', scopeId: tenantBID }, {
      site_id: siteAID, action: 'purge', target_type: 'whole_site', targets: [], node_ids: [], max_retries: 3,
    }])
  })

  // 结果未知只能用原键重试；放弃（编辑输入后换成别的内容）后同样内容仍按 journal 用原键，直到收到确定答复。
  it('treats an invalid write response as unknown and never shows its text', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(
      new ApiError('malformed successful response', 502, 'invalid_response'),
    )
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user)

    expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    expect(screen.getByText(/未确认是否已建任务，重试会使用同一请求/)).toBeInTheDocument()
    expect(screen.queryByText(/malformed successful response/)).not.toBeInTheDocument()
    expect(create).toHaveBeenCalledOnce()
  })

  // fix-cacheflow5（merge-p22 按复刻主区改写）：结果未知后离页再回来，先按原幂等键查服务端回执，已受理直接显示结果、不再重发。
  it('shows an accepted receipt instead of re-sending an unknown create', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(cacheOperationsApi, 'get').mockResolvedValue(operation)
    const create = vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    const receipt = vi.spyOn(cacheOperationsApi, 'writeReceipt')
      .mockResolvedValueOnce(null)
      .mockResolvedValue({ status: 'accepted', decided_at: '2026-08-06T08:00:00Z', operation })
    const user = userEvent.setup({ delay: null })

    const first = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/a.js')
    expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    // After the lost response the receipt was read once: not received yet.
    expect(receipt).toHaveBeenCalledTimes(1)
    const key = create.mock.calls[0]![3]
    first.unmount()

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/a.js')
    await waitFor(() => expect(receipt).toHaveBeenCalledTimes(2))
    expect(create).toHaveBeenCalledTimes(1)
    expect(receipt).toHaveBeenLastCalledWith(expect.any(String), { kind: 'tenant' }, { action: 'create', key })
    await waitFor(() => expect(window.sessionStorage.getItem('cdnca.cache-pending-writes.v1')).toBe('[]'))
  })

  it('re-sends an unknown create the server never received, and shows a recorded refusal', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(cacheOperationsApi, 'create')
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
      .mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
    const receipt = vi.spyOn(cacheOperationsApi, 'writeReceipt')
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null)
      .mockResolvedValue({
        status: 'rejected', decided_at: '2026-08-06T08:00:00Z',
        rejection: { code: 'daily_limit_exceeded' },
      })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    await submitOneURL(user, 'https://www.example.com/a.js')
    expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()
    const results = document.querySelector<HTMLElement>('.cache-replica-results')!

    // Not received: the same request is sent again with the same key.
    await user.click(within(results).getByRole('button', { name: '重试未成功的网站' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
    expect(await screen.findByText('结果待确认', { selector: '.cache-baseline-submit-status' })).toBeInTheDocument()

    // The receipt now says refused: the reason is shown, nothing is sent, the record is cleared.
    await user.click(within(document.querySelector<HTMLElement>('.cache-replica-results')!).getByRole('button', { name: '重试未成功的网站' }))
    expect(await screen.findByText(/已超过本账号今日的刷新或预热额度/)).toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(2)
    expect(receipt).toHaveBeenCalledTimes(4)
    expect(window.sessionStorage.getItem('cdnca.cache-pending-writes.v1')).toBe('[]')
  })

  it('localizes a list failure and recovers through the retry action', async () => {
    authenticate('tenant', ['sites.read'])
    const list = vi.spyOn(cacheOperationsApi, 'list')
      .mockRejectedValueOnce(new ApiError('private database detail', 503, 'service_unavailable', 'cache-list-safe'))
      .mockResolvedValue({ items: [] })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    expect(await screen.findByText('缓存任务加载失败')).toBeInTheDocument()
    expect(screen.getByText('缓存控制服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(screen.getByText('请求 ID：cache-list-safe')).toBeInTheDocument()
    expect(screen.queryByText('private database detail')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无缓存任务')).not.toBeInTheDocument()
    const readsBeforeRetry = list.mock.calls.length
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无缓存任务')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(readsBeforeRetry + 1)
  })

  it('uses the server cursor for the next page', async () => {
    authenticate('tenant', ['sites.read'])
    const list = vi.spyOn(cacheOperationsApi, 'list')
      .mockResolvedValueOnce({ items: [{ ...operation, target_count: 1, node_count: 1, first_target: operation.targets[0]! }], next_cursor: 'cursor-2' })
      .mockResolvedValueOnce({ items: [] })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    // 按钮在首屏数据到达前就渲染（禁用），等它随 next_cursor 启用后再点。
    const next = await screen.findByRole('button', { name: '下一页' })
    await waitFor(() => expect(next).toBeEnabled())
    await user.click(next)
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    expect(list).toHaveBeenLastCalledWith(
      'memory-only-access-token', { kind: 'tenant' }, expect.objectContaining({ cursor: 'cursor-2' }),
    )
  })

  it('keeps qps-ploc loading, empty, error recovery, and local/API permission states accessible and local', async () => {
    await changeLocale('qps-ploc')
    const t = i18n.getFixedT('qps-ploc', 'cacheOperations')
    setCacheSession({ permissions: ['sites.read'] })
    const pendingList = deferred<{ items: CacheOperationSummary[] }>()
    const list = vi.spyOn(cacheOperationsApi, 'list')
      .mockImplementationOnce(() => pendingList.promise)
      .mockResolvedValueOnce({ items: [] })
    const user = userEvent.setup({ delay: null })
    const recoveryView = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    expect(document.querySelector('.cache-operations-table')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByLabelText(t('pagination.label'))).toBeInTheDocument()
    await act(async () => {
      pendingList.reject(new ApiError('private cache shard topology', 503, 'service_unavailable'))
      await pendingList.promise.catch(() => undefined)
    })
    expect(await screen.findByText(t('errors.listLoadFailed'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.service_unavailable'))).toBeInTheDocument()
    expect(screen.queryByText('private cache shard topology')).not.toBeInTheDocument()
    expect(document.querySelector('.cache-operations-table')).toHaveAttribute('aria-busy', 'false')
    await user.click(screen.getByRole('button', { name: t('actions.retry') }))
    expect(await screen.findByText(t('values.empty'))).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)
    expect(screen.queryByText(t('errors.listLoadFailed'))).not.toBeInTheDocument()
    recoveryView.unmount()

    vi.restoreAllMocks()
    setCacheSession({ permissions: ['sites.read'] })
    const apiForbiddenList = vi.spyOn(cacheOperationsApi, 'list').mockRejectedValue(
      new ApiError('private cache permission rule', 403, 'permission_denied'),
    )
    const apiForbiddenView = renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    expect(screen.queryByText('private cache permission rule')).not.toBeInTheDocument()
    expect(apiForbiddenList).toHaveBeenCalledOnce()
    apiForbiddenView.unmount()

    vi.restoreAllMocks()
    setCacheSession({ permissions: ['sites.manage'] })
    const localSpies = apiSpies()
    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])
    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    expect(localSpies.list).not.toHaveBeenCalled()
    expect(localSpies.get).not.toHaveBeenCalled()
    expect(localSpies.create).not.toHaveBeenCalled()
    expect(localSpies.retry).not.toHaveBeenCalled()
    expect(localSpies.cancel).not.toHaveBeenCalled()
  })

  it('renders cache resources through the expanded pseudo locale', async () => {
    await i18n.changeLanguage('qps-ploc')
    authenticate('tenant', ['sites.read'])
    vi.spyOn(cacheOperationsApi, 'list').mockResolvedValue({ items: [] })

    renderWithProviders(<CacheOperationsPage />, ['/site/cache-clean'])

    expect(await screen.findByRole('heading', { level: 1, name: /^［.+］$/ })).toBeInTheDocument()
    expect(i18n.exists('cacheOperations:states.partial_failed')).toBe(true)
    expect(i18n.exists('cacheOperations:failures.node_offline')).toBe(true)
  })
})
