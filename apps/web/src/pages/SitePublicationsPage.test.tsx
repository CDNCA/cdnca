import { useLayoutEffect } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation, useNavigate } from 'react-router-dom'

import * as lineSwitchAPI from '../api/l4LineSwitches'
import { nodeSchedulingApi } from '../api/nodeScheduling'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import SitePublicationsPage from './SitePublicationsPage'

// 自动发布未下发的说明由页内 Alert 改为 FeedbackWhen 弹窗（ui-feedback-modal）。
async function findAutomaticFailure(): Promise<HTMLElement> {
  return (await screen.findByText(/^自动发布未下发/, { selector: '.cdnca-feedback-title span' })).closest('.cdnca-feedback') as HTMLElement
}

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const scopeID = '018cc251-f400-7def-8000-000000000050'
const otherScopeID = '018cc251-f400-7def-8000-000000000051'
const publicationID = '018cc251-f400-7def-8000-000000000060'
const rolloutID = '018cc251-f400-7def-8000-000000000061'
const configVersionID = '018cc251-f400-7def-8000-000000000062'
const snapshotID = '018cc251-f400-7def-8000-000000000063'
const deploymentID = '018cc251-f400-7def-8000-000000000064'
const nodeID = '018cc251-f400-7def-8000-000000000065'
const otherNodeID = '018cc251-f400-7def-8000-000000000067'
const lineGroupID = '018cc251-f400-7def-8000-000000000066'
const digest = '1'.repeat(64)

const tenantPublication = {
  id: publicationID,
  source_revision: 7,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  target: { kind: 'line_group_snapshot' },
  node_count: 2,
  created_at: '2026-08-01T08:00:00Z',
}

const adminPublication = {
  ...tenantPublication,
  configuration_scope_id: scopeID,
  canonical_source_sha256: '2'.repeat(64),
  artifact_sha256: '3'.repeat(64),
  target: {
    kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4,
    resolver_sha256: digest, resolved_sha256: '4'.repeat(64),
  },
}

const adminRollback = {
  publication_id: publicationID,
  configuration_scope_id: scopeID,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  action: 'rollback',
  target: adminPublication.target,
  node_count: 2,
  created_at: '2026-08-01T08:05:00Z',
}

const adminRollout = {
  id: rolloutID,
  configuration_scope_id: scopeID,
  config_version_id: configVersionID,
  action: 'apply',
  state: 'partial_failed',
  revision: 3,
  max_attempts: 5,
  progress: { total: 2, pending: 0, running: 0, succeeded: 1, failed: 1, cancelled: 0, superseded: 0, frozen: 0 },
  can_cancel: false,
  can_retry: true,
  created_at: '2026-08-01T08:00:00Z',
  updated_at: '2026-08-01T08:03:00Z',
}

function progressiveAdminRollout(
  state: 'queued' | 'running' | 'paused',
  control: 'start' | 'pause' | 'resume',
) {
  return {
    ...adminRollout,
    state,
    revision: 4,
    progress: { total: 5, pending: 4, running: 0, succeeded: 1, failed: 0, cancelled: 0, superseded: 0, frozen: 0 },
    can_cancel: true,
    can_retry: false,
    can_start: control === 'start',
    can_pause: control === 'pause',
    can_resume: control === 'resume',
    rollout: {
      strategy: 'canary', canary_size: 1, batch_size: 2, failure_threshold: 1,
      cohort_count: 3, released_cohort: state === 'queued' ? -1 : 0,
    },
    pause_reason: state === 'paused' ? 'operator' : '',
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function setTenant(
  permissions = ['sites.read'],
  update: 'new' | 'refresh' = 'new',
  token = 'memory-only-access-token',
) {
  const actor = principal({ permissions })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return actor
}

function setPlatform(
  permissions = ['edge_publications.read', 'edge_publications.manage'],
  update: 'new' | 'refresh' = 'new',
  token = 'memory-only-access-token',
) {
  const actor = principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions,
  })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return actor
}

function publicationPage(platform = false, options: { items?: unknown[]; next_cursor?: string; revision?: number } = {}) {
  return {
    items: options.items ?? [platform ? adminPublication : tenantPublication],
    current_source_revision: options.revision ?? 7,
    ...(options.next_cursor ? { next_cursor: options.next_cursor } : {}),
  }
}

function installPlatformTargetMocks() {
  vi.spyOn(nodeSchedulingApi, 'list').mockResolvedValue({ items: [{
    id: lineGroupID,
    display_id: '9',
    tenant_scope_id: scopeID,
    revision: 9,
    name: '华东主线路',
    region: '华东',
    resolved_value: 'east-primary',
    note: '',
    sort_order: 100,
    health_policy: {
      probe_interval_ms: 10_000, probe_timeout_ms: 3_000,
      failure_threshold: 3, recovery_threshold: 3,
      failure_debounce_ms: 0, recovery_debounce_ms: 0,
    },
    endpoints: [],
    configuration_digest: '5'.repeat(64),
    created_by_user_id: nodeID,
    created_at: '2026-08-01T07:00:00Z',
    sealed_at: '2026-08-01T07:00:00Z',
  }] })
  vi.spyOn(nodeSchedulingApi, 'getTargetSnapshot').mockResolvedValue({
    id: snapshotID,
    revision: 4,
    tenant_scope_id: scopeID,
    source_line_group_id: lineGroupID,
    source_revision: 9,
    source_configuration_digest: '5'.repeat(64),
    node_set_digest: digest,
    node_ids: [nodeID],
  })
}

function RouteTargetControl({
  target = otherScopeID,
  testId = 'route-target-control',
  onTargetCommit,
}: {
  target?: string
  testId?: string
  onTargetCommit?: () => void
}) {
  const location = useLocation()
  const navigate = useNavigate()
  useLayoutEffect(() => {
    if (location.search === `?target_scope_id=${target}`) onTargetCommit?.()
  }, [location.search, onTargetCommit, target])
  return <button type="button" data-testid={testId} onClick={() => navigate(`/site/publications?target_scope_id=${target}`)} />
}

async function chooseTarget(user: ReturnType<typeof userEvent.setup>, target: string) {
  await user.type(screen.getByRole('combobox', { name: '目标租户作用域' }), target)
  const option = await waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.ant-select-item-option')]
      .find((item) => item.textContent?.includes(target))
    if (!found) throw new Error(`target option not found: ${target}`)
    return found
  })
  await user.click(option)
}

function selectedTarget(): string {
  return document.querySelector('.site-publications-target .ant-select-selection-item')?.textContent ?? ''
}

// The page no longer publishes; writes go through rollback.
async function submitRollback(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: '回滚到此版本' }))
  await user.click(await screen.findByRole('button', { name: '确认回滚' }))
}

afterEach(async () => {
  vi.restoreAllMocks()
  await i18n.changeLanguage('zh-CN')
})

describe('SitePublicationsPage', () => {
  beforeEach(() => {
    vi.spyOn(nodeSchedulingApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(lineSwitchAPI, 'getCurrentL4LineSwitch').mockResolvedValue(null)
  })

  it('keeps page two and the exact unknown write across a same-epoch token refresh without token cache keys', async () => {
    const oldToken = 'old-site-publication-access-token'
    const newToken = 'new-site-publication-access-token'
    const actor = setPlatform(undefined, 'new', oldToken)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const secondPublication = {
      ...adminPublication,
      id: '018cc251-f400-7def-8000-000000000070',
    }
    installPlatformTargetMocks()
    const writes: RequestInit[] = []
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        writes.push(init)
        if (writes.length === 1) throw new TypeError('response lost after commit')
        return json(adminRollback, 201)
      }
      const url = String(input)
      return url.includes('cursor=stable_next')
        ? json(publicationPage(true, { items: [secondPublication], revision: 7 }))
        : json(publicationPage(true, { next_cursor: 'stable_next', revision: 7 }))
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderWithProviders(
      <QueryClientProvider client={queryClient}><SitePublicationsPage /></QueryClientProvider>,
      [`/site/publications?target_scope_id=${scopeID}`],
    )

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText(secondPublication.id)).toBeInTheDocument()
    await submitRollback(user)
    expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
    const readsBeforeRefresh = fetchSpy.mock.calls.filter(([, init]) => init?.method !== 'POST').length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken }, actor, 'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByText(secondPublication.id)).toBeInTheDocument()
    expect(screen.queryByText(publicationID)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '使用原请求重试' })).toBeEnabled()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method !== 'POST')).toHaveLength(readsBeforeRefresh)
    for (const query of queryClient.getQueryCache().getAll()) {
      const key = JSON.stringify(query.queryKey)
      expect(key).not.toContain(oldToken)
      expect(key).not.toContain(newToken)
    }

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method !== 'POST'))
      .toHaveLength(readsBeforeRefresh + 1))
    const latestRead = fetchSpy.mock.calls.filter(([, init]) => init?.method !== 'POST').at(-1)!
    expect(new Headers(latestRead[1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)

    await user.click(screen.getByRole('button', { name: '使用原请求重试' }))
    await waitFor(() => expect(writes).toHaveLength(2))
    expect(writes[1]?.body).toBe(writes[0]?.body)
    expect(new Headers(writes[1]?.headers).get('Idempotency-Key'))
      .toBe(new Headers(writes[0]?.headers).get('Idempotency-Key'))
    expect(new Headers(writes[0]?.headers).get('Authorization')).toBe(`Bearer ${oldToken}`)
    expect(new Headers(writes[1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)
  }, 20_000)

  it('removes prior-session publication cache and ignores its late response', async () => {
    const oldToken = 'old-tenant-publication-token'
    const newToken = 'new-tenant-publication-token'
    const actor = setTenant(undefined, 'new', oldToken)
    const oldEpoch = useSessionStore.getState().sessionEpoch
    const oldOwnerKey = JSON.stringify([
      actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, oldEpoch,
    ])
    let resolveLate!: (response: Response) => void
    const lateResponse = new Promise<Response>((resolve) => { resolveLate = resolve })
    let oldReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (authorization === `Bearer ${oldToken}`) {
        oldReads += 1
        return oldReads === 1 ? json(publicationPage()) : lateResponse
      }
      if (authorization === `Bearer ${newToken}`) {
        return json(publicationPage(false, { items: [], revision: 8 }))
      }
      throw new Error(`unexpected publication authorization ${authorization}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderWithProviders(
      <QueryClientProvider client={queryClient}><SitePublicationsPage /></QueryClientProvider>,
    )

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(oldReads).toBe(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken }, actor,
      )
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).not.toBe(oldEpoch)
    expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()

    await act(async () => {
      resolveLate(json(publicationPage(false, { items: [{
        ...tenantPublication,
        id: '018cc251-f400-7def-8000-000000000071',
      }] })))
      await lateResponse
    })

    expect(screen.queryByText(publicationID)).not.toBeInTheDocument()
    expect(screen.queryByText('018cc251-f400-7def-8000-000000000071')).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => (
      new Headers(init?.headers).get('Authorization') === `Bearer ${newToken}`
    ))).toBe(true)
    const cache = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => ({
      key: query.queryKey,
      data: query.state.data,
    })))
    expect(cache).not.toContain(oldToken)
    expect(queryClient.getQueryCache().getAll().some((query) => query.queryKey[1] === oldOwnerKey)).toBe(false)
    expect(cache).not.toContain(publicationID)
    expect(cache).not.toContain('018cc251-f400-7def-8000-000000000071')
  }, 20_000)

  it('reserves the publication action column and full fixed-column scroll width', async () => {
    setTenant()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage()))
    renderWithProviders(<SitePublicationsPage />)

    await screen.findByRole('button', { name: '查看发布详情' })
    const tableRegion = screen.getByLabelText('发布记录表格')
    const columnWidths = Array.from(tableRegion.querySelectorAll('colgroup:first-of-type col'), (column) => (
      Number.parseFloat((column as HTMLElement).style.width)
    ))
    const expectedWidths = [245, 105, 150, 90, 180, 260]

    expect(columnWidths).toEqual(expectedWidths)
    expect(Number.parseFloat(tableRegion.querySelector('table')?.style.width ?? '')).toBeGreaterThanOrEqual(
      expectedWidths.reduce((sum, width) => sum + width, 0),
    )
  })

  it('renders tenant publications read-only and ignores an injected platform target', async () => {
    setTenant()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage()))

    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${otherScopeID}`])

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '站点与四层发布' })).toBeInTheDocument()
    expect(screen.queryByLabelText('目标租户作用域')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '发布配置' })).not.toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe('/v1/site-publications?limit=20')
  })

  // A revoked module the published release uses makes
  // the scope pending republication; the page says so and names the module.
  it('shows the pending republication notice for revoked modules', async () => {
    setTenant()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...publicationPage(), pending_modules: [{ module: 'pack.crs', source_revision: 7 }],
    }))

    renderWithProviders(<SitePublicationsPage />, ['/site/publications'])

    const notice = await screen.findByTestId('site-publications-pending-modules')
    expect(notice).toHaveTextContent('待重新发布：授权已不含以下模块')
    expect(notice).toHaveTextContent('pack.crs')
  })

  it('omits the notice without pending modules and rejects malformed ones', async () => {
    setTenant()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage()))
    const { unmount } = renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    expect(screen.queryByTestId('site-publications-pending-modules')).not.toBeInTheDocument()
    unmount()

    fetchSpy.mockResolvedValue(json({ ...publicationPage(), pending_modules: [{ module: 'Bad Code', source_revision: 7 }] }))
    renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    await waitFor(() => expect(screen.queryByText(publicationID)).not.toBeInTheDocument())
    expect(screen.queryByTestId('site-publications-pending-modules')).not.toBeInTheDocument()
  })

  // An automatic publication that reached no node is shown
  // with its reason instead of failing silently.
  it('shows why the latest automatic publication reached no node', async () => {
    setTenant()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: { reason: 'node_capability_unavailable', source_revision: 9, failed_at: '2026-10-22T05:00:00Z' },
    }))
    const { unmount } = renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    const notice = await findAutomaticFailure()
    expect(notice).toHaveTextContent('自动发布未下发：节点能力不足')
    expect(notice).toHaveTextContent('源修订 9')
    unmount()

    fetchSpy.mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: { reason: 'no_target_nodes', source_revision: 3, failed_at: '2026-10-22T05:00:00Z' },
    }))
    const { unmount: unmountEmpty } = renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    expect(await findAutomaticFailure()).toHaveTextContent('自动发布未下发：没有可用节点')
    unmountEmpty()

    // An unknown reason is an invalid response, not a notice.
    fetchSpy.mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: { reason: 'publish_outcome_unknown', source_revision: 3, failed_at: '2026-10-22T05:00:00Z' },
    }))
    renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    await waitFor(() => expect(screen.queryByText(publicationID)).not.toBeInTheDocument())
    expect(screen.queryByText(/自动发布未下发/)).not.toBeInTheDocument()
  })

  // O2 (live-site2 10-22): rule packs / IP library still reaching a new node
  // are shown as a node artifact sync with its progress, not as missing
  // node capabilities.
  it('shows node artifact sync progress instead of missing capabilities', async () => {
    setTenant()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: {
        reason: 'node_artifacts_syncing', source_revision: 11, failed_at: '2026-10-22T04:47:48Z',
        artifact_sync: { received_segments: 7, total_segments: 21, remaining_minutes: 15 },
      },
    }))
    const { unmount } = renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    const notice = await findAutomaticFailure()
    expect(notice).toHaveTextContent('自动发布未下发：节点制品同步中（已收 7/21，预计还需 15 分钟）')
    expect(notice).toHaveTextContent('源修订 11')
    expect(notice).not.toHaveTextContent('节点能力不足')
    unmount()

    // Before any node has a set there is no progress to show.
    fetchSpy.mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: { reason: 'node_artifacts_syncing', source_revision: 11, failed_at: '2026-10-22T04:47:48Z' },
    }))
    const { unmount: unmountStarting } = renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    const starting = await findAutomaticFailure()
    expect(starting).toHaveTextContent('自动发布未下发：节点制品同步中')
    expect(starting).not.toHaveTextContent('已收')
    unmountStarting()

    // Progress beyond its total is an invalid response, not a notice.
    fetchSpy.mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: {
        reason: 'node_artifacts_syncing', source_revision: 11, failed_at: '2026-10-22T04:47:48Z',
        artifact_sync: { received_segments: 22, total_segments: 21, remaining_minutes: 1 },
      },
    }))
    renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    await waitFor(() => expect(screen.queryByText(publicationID)).not.toBeInTheDocument())
    expect(screen.queryByText(/自动发布未下发/)).not.toBeInTheDocument()
  })

  // B15 NODE-PUB-01: an automatic publication another tenant's configuration
  // on a shared node refused says the settings were saved but not published.
  it('explains a publication refused by another tenant on a shared node', async () => {
    setTenant()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...publicationPage(),
      automatic_failure: { reason: 'node_scope_conflict', source_revision: 11, failed_at: '2026-10-22T04:47:48Z' },
    }))
    renderWithProviders(<SitePublicationsPage />, ['/site/publications'])
    // 这一类标题不以「自动发布未下发」开头，按标题原文找反馈框。
    const notice = (await screen.findByText('设置已保存，本次未发布：节点被其他用户的配置占用', { selector: '.cdnca-feedback-title span' }))
      .closest('.cdnca-feedback') as HTMLElement
    expect(notice).toHaveTextContent('源修订 11')
  })

  it('requires a canonical explicit tenant target before platform reads', async () => {
    setPlatform(['edge_publications.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage(true)))
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)

    expect(await screen.findByText('请先选择要查看的租户作用域。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    // Arbitrary text is only a search term, never a target.
    await user.type(screen.getByRole('combobox', { name: '目标租户作用域' }), 'not-a-uuid')
    expect(await screen.findByText('没有匹配的用户')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()

    await user.clear(screen.getByRole('combobox', { name: '目标租户作用域' }))
    await chooseTarget(user, scopeID)
    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain(`/v1/admin/site-publications?scope_id=${scopeID}`)
    expect(screen.queryByRole('button', { name: '发布配置' })).not.toBeInTheDocument()
  })

  it('W3: refresh without a target tenant never calls the tenant publications endpoint', async () => {
    setPlatform(['edge_publications.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage(true)))
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)
    expect(await screen.findByText('请先选择要查看的租户作用域。')).toBeInTheDocument()
    const refresh = screen.getByRole('button', { name: '刷新' })
    expect(refresh).toBeDisabled()
    await user.click(refresh)
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('/v1/site-publications'))).toBe(false)
  })

  it('synchronizes an explicit platform target when search params change on the same route', async () => {
    setPlatform(['edge_publications.read'])
    let resolveSecond!: (value: Response) => void
    const secondResponse = new Promise<Response>((resolve) => { resolveSecond = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes(`scope_id=${otherScopeID}`)) return secondResponse
      return json(publicationPage(true))
    })
    const user = userEvent.setup()
    let firstTargetCommit = ''
    renderWithProviders(
      <>
        <RouteTargetControl onTargetCommit={() => {
          firstTargetCommit ||= document.body.textContent ?? ''
        }} />
        <SitePublicationsPage />
      </>,
      [`/site/publications?target_scope_id=${scopeID}`],
    )

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    expect(selectedTarget()).toBe(scopeID)
    await user.click(screen.getByTestId('route-target-control'))

    expect(firstTargetCommit).not.toContain(publicationID)
    expect(selectedTarget()).toBe(otherScopeID)
    expect(screen.queryByText(publicationID)).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes(`scope_id=${otherScopeID}`))).toBe(true)
    resolveSecond(json(publicationPage(true, { items: [], revision: 8 })))
    expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()
  })

  it('fails closed on the first commit for an invalid same-route target URL', async () => {
    setPlatform()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage(true)))
    const user = userEvent.setup()
    let firstTargetCommit = ''
    renderWithProviders(
      <>
        <RouteTargetControl target="not-a-uuid" onTargetCommit={() => {
          firstTargetCommit ||= document.body.textContent ?? ''
        }} />
        <SitePublicationsPage />
      </>,
      [`/site/publications?target_scope_id=${scopeID}`],
    )

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    const requestCount = fetchSpy.mock.calls.length
    await user.click(screen.getByTestId('route-target-control'))

    expect(firstTargetCommit).not.toContain(publicationID)
    expect(firstTargetCommit).not.toContain('发布配置')
    expect(fetchSpy).toHaveBeenCalledTimes(requestCount)
    expect(await screen.findByText('请输入有效的小写租户作用域 UUID。')).toBeInTheDocument()
  })

  it('clears stale rows, selections, and cursors when the platform target changes', async () => {
    setPlatform(['edge_publications.read'])
    let resolveSecond!: (value: Response) => void
    const secondResponse = new Promise<Response>((resolve) => { resolveSecond = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes(`scope_id=${otherScopeID}`)) return secondResponse
      if (url.includes('cursor=next_page')) return json(publicationPage(true, { items: [], revision: 7 }))
      return json(publicationPage(true, { next_cursor: 'next_page' }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('cursor=next_page'))).toBe(true))

    await chooseTarget(user, otherScopeID)
    expect(screen.queryByText(publicationID)).not.toBeInTheDocument()
    expect(screen.getByLabelText('发布记录表格')).toHaveAttribute('aria-busy', 'true')
    expect(fetchSpy.mock.calls.some(([url]) => {
      const parsed = new URL(String(url), 'https://cdnca.test')
      return parsed.searchParams.get('scope_id') === otherScopeID && !parsed.searchParams.has('cursor')
    })).toBe(true)
    resolveSecond(json(publicationPage(true, { items: [], revision: 8 })))
    expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()
  })

  it('shows localized loading, empty, retryable error, and forbidden states without raw server detail', async () => {
    setTenant()
    let resolveLoad!: (value: Response) => void
    let resolveRetry!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { resolveLoad = resolve })
    const retryPending = new Promise<Response>((resolve) => { resolveRetry = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(pending).mockResolvedValueOnce(
      json({ error: { code: 'publication_service_unavailable', message: 'postgres host secret' } }, 503),
    ).mockReturnValueOnce(retryPending)
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)

    expect(screen.getByLabelText('发布记录表格')).toHaveAttribute('aria-busy', 'true')
    resolveLoad(json(publicationPage(false, { items: [] })))
    expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('加载发布记录失败')).toBeInTheDocument()
    expect(screen.queryByText('postgres host secret')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(screen.getByLabelText('发布记录表格')).toHaveAttribute('aria-busy', 'true')
    expect(screen.queryByText('加载发布记录失败')).not.toBeInTheDocument()
    resolveRetry(json(publicationPage(false, { items: [] })))
    expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()

    act(() => setTenant([]))
    expect(await screen.findByText('当前账号无权查看发布记录。')).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: 'Unauthorized' })).not.toBeInTheDocument()
  })

  it('maps a service failure by HTTP status when the server omits a stable code', async () => {
    setTenant()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { message: 'private service detail' },
    }, 503))
    renderWithProviders(<SitePublicationsPage />)

    expect(await screen.findByText('发布服务暂不可用。')).toBeInTheDocument()
    expect(screen.queryByText('private service detail')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无发布记录')).not.toBeInTheDocument()
  })

  it.each(['en-US', 'qps-ploc'] as const)('keeps publication errors localized in %s', async (locale) => {
    await i18n.changeLanguage(locale)
    setTenant()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'publication_service_unavailable', message: 'private English detail' },
    }, 503))
    renderWithProviders(<SitePublicationsPage />)

    const t = i18n.getFixedT(locale, 'sitePublications')
    expect(await screen.findByText(t('errors.serviceUnavailable'))).toBeInTheDocument()
    expect(screen.queryByText('private English detail')).not.toBeInTheDocument()
    expect(screen.queryByText(t('empty.publications'))).not.toBeInTheDocument()
  })

  it('opens publication details and rollout deployments with audience redaction', async () => {
    setTenant()
    const deployment = {
      id: deploymentID,
      attempt: 2,
      max_attempts: 5,
      state: 'failed',
      error_code: 'ACTIVATION_FAILED',
      created_at: '2026-08-01T08:01:00Z',
      updated_at: '2026-08-01T08:02:00Z',
      can_retry: true,
      cohort: 0,
      released: true,
    }
	const tenantRollout = Object.fromEntries(Object.entries(
	  progressiveAdminRollout('paused', 'resume'),
	).filter(([key]) => key !== 'configuration_scope_id'))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url === `/v1/site-publications/${publicationID}`) return json(tenantPublication)
      if (url === '/v1/site-rollouts?limit=20') {
		return json({ items: [tenantRollout] })
      }
      if (url === `/v1/site-rollouts/${rolloutID}`) {
		return json(tenantRollout)
      }
      if (url === `/v1/site-rollouts/${rolloutID}/deployments?limit=20`) return json({ items: [deployment] })
      return json(publicationPage())
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)

    await user.click(await screen.findByRole('button', { name: '查看发布详情' }))
    const detail = await screen.findByRole('dialog', { name: '发布详情' })
    expect(within(detail).getByText(configVersionID)).toBeInTheDocument()
    expect(within(detail).queryByText('制品摘要')).not.toBeInTheDocument()
    await user.click(within(detail).getByRole('button', { name: '关闭' }))
    await waitFor(() => expect(detail).not.toBeVisible())

    await user.click(screen.getByRole('tab', { name: '部署进度' }))
	expect(screen.queryByRole('button', { name: '继续' })).not.toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '查看部署' }))
    const deployments = await screen.findByRole('dialog')
    expect(within(deployments).getByText('节点部署')).toBeInTheDocument()
    expect(within(deployments).getByText('ACTIVATION_FAILED')).toBeInTheDocument()
    expect(within(deployments).queryByText(nodeID)).not.toBeInTheDocument()
  })

  // A node that already runs a newer release ignored this
  // one; it reads as such, not as a failure.
  it('shows a node that ignored an old release as ignored, not failed', async () => {
    setTenant()
    const ignored = {
      id: deploymentID, attempt: 1, max_attempts: 5, state: 'failed', error_code: 'ERROR_CODE_STALE_ATTEMPT',
      superseded: true, created_at: '2026-08-01T08:01:00Z', updated_at: '2026-08-01T08:02:00Z', can_retry: false,
    }
    const rollout = Object.fromEntries(Object.entries({
      ...adminRollout, state: 'succeeded', can_retry: false,
      progress: { total: 2, pending: 0, running: 0, succeeded: 1, failed: 0, cancelled: 0, superseded: 1, frozen: 0 },
    }).filter(([key]) => key !== 'configuration_scope_id'))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url === '/v1/site-rollouts?limit=20') return json({ items: [rollout] })
      if (url === `/v1/site-rollouts/${rolloutID}`) return json(rollout)
      if (url === `/v1/site-rollouts/${rolloutID}/deployments?limit=20`) return json({ items: [ignored] })
      return json(publicationPage())
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)

    await user.click(await screen.findByRole('tab', { name: '部署进度' }))
    expect(await screen.findByText('成功 1 / 2，失败 0，已忽略旧发布 1')).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '查看部署' }))
    const deployments = await screen.findByRole('dialog')
    expect(within(deployments).getByText('已忽略旧发布')).toBeInTheDocument()
    expect(within(deployments).getByText('节点已在更新版本')).toBeInTheDocument()
    expect(within(deployments).queryByText('失败')).not.toBeInTheDocument()
    expect(within(deployments).queryByText('ERROR_CODE_STALE_ATTEMPT')).not.toBeInTheDocument()
  })

  // A frozen node (expired service ticket) refused the
  // release; it waits for redelivery after renewal and is no failure.
  it('shows a release a frozen node refused as awaiting redelivery, not failed', async () => {
    setTenant()
    const frozen = {
      id: deploymentID, attempt: 1, max_attempts: 5, state: 'failed', error_code: 'ERROR_CODE_FAILED_PRECONDITION',
      frozen: true, created_at: '2026-08-01T08:01:00Z', updated_at: '2026-08-01T08:02:00Z', can_retry: false,
    }
    const rollout = Object.fromEntries(Object.entries({
      ...adminRollout, state: 'succeeded', can_retry: false,
      progress: { total: 2, pending: 0, running: 0, succeeded: 1, failed: 0, cancelled: 0, superseded: 0, frozen: 1 },
    }).filter(([key]) => key !== 'configuration_scope_id'))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url === '/v1/site-rollouts?limit=20') return json({ items: [rollout] })
      if (url === `/v1/site-rollouts/${rolloutID}`) return json(rollout)
      if (url === `/v1/site-rollouts/${rolloutID}/deployments?limit=20`) return json({ items: [frozen] })
      return json(publicationPage())
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)

    await user.click(await screen.findByRole('tab', { name: '部署进度' }))
    expect(await screen.findByText('成功 1 / 2，失败 0，冻结中待补发 1')).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '查看部署' }))
    const deployments = await screen.findByRole('dialog')
    expect(within(deployments).getByText('冻结中待补发')).toBeInTheDocument()
    expect(within(deployments).queryByText('失败')).not.toBeInTheDocument()
  })

	it.each([
	  { action: 'start', label: '开始发布', state: 'queued' },
	  { action: 'pause', label: '暂停', state: 'running' },
	  { action: 'resume', label: '继续', state: 'paused' },
	] as const)('executes the $action progressive rollout command with revision CAS', async ({ action, label, state }) => {
	  setPlatform()
	  const rollout = progressiveAdminRollout(state, action)
	  const requests: Array<{ url: string; init?: RequestInit }> = []
	  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
		const url = String(input)
		requests.push({ url, init })
		if (init?.method === 'POST') return json(rollout)
		if (url.startsWith('/v1/admin/site-rollouts')) return json({ items: [rollout] })
		return json(publicationPage(true))
	  })
	  const user = userEvent.setup()
	  renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

	  await user.click(await screen.findByRole('tab', { name: '部署进度' }))
	  await user.click(await screen.findByRole('button', { name: label }))
	  await waitFor(() => expect(requests.some(({ init }) => init?.method === 'POST')).toBe(true))
	  const write = requests.find(({ init }) => init?.method === 'POST')!
	  expect(write.url).toBe(`/v1/admin/site-rollouts/${rolloutID}/${action}`)
	  expect(JSON.parse(String(write.init?.body))).toEqual({
		configuration_scope_id: scopeID,
		expected_revision: 4,
	  })
	})

  it('picks the target tenant by username search instead of a typed UUID', async () => {
    setPlatform(['edge_publications.read', 'identity.users.manage'])
    const list = vi.spyOn(usersApi, 'list').mockImplementation(async (_token, params) => ({
      items: params.search === 't02' || !params.search ? [{
        id: nodeID, display_id: '3', scope_id: scopeID, tenant_id: otherNodeID, username: 't02', display_name: 't02',
        email: 't02@example.test', phone: null, status: 'active', role: 'tenant_owner', group_id: null, group_name: null,
        revision: 1, created_at: '2026-10-22T00:00:00Z', updated_at: '2026-10-22T00:00:00Z',
      }] : [],
      page: 1, limit: 20, total: 1,
    }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(publicationPage(true)))
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />)

    await chooseTarget(user, 't02')
    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith('memory-only-access-token', expect.objectContaining({ search: 't02' }))
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain(`/v1/admin/site-publications?scope_id=${scopeID}`)
    expect(selectedTarget()).toContain('t02（3）')
  })

  it('names the node and site whose JS challenge policy is missing when a rollback is refused', async () => {
    setPlatform()
    installPlatformTargetMocks()
    const siteID = '01990000-0000-7000-8000-0000000000b1'
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        return json({ error: { code: 'challenge_policy_unavailable', message: 'detail', request_id: 'req-challenge',
          challenge: { node_id: nodeID, site_id: siteID, domain: 'shop.example.com', policy_version: 4, other_node_ids: [] } } }, 422)
      }
      return json(publicationPage(true, { revision: 7 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    await submitRollback(user)

    expect(await screen.findByText(new RegExp(`节点 ${nodeID} 尚未安装站点 shop\\.example\\.com 的 JS 挑战策略（版本 v4）`))).toBeInTheDocument()
  })

  // The refusal body the control API writes for node_capability_unavailable
  // (edgepublishhttp newErrorEnvelope); the page lists every node to upgrade.
  async function publishRefusedForCapability(capability: unknown, locale = 'zh-CN') {
    await i18n.changeLanguage(locale)
    setPlatform()
    installPlatformTargetMocks()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        return json({ error: { code: 'node_capability_unavailable', message: 'node secret-host (agent 1.0.34) does not support',
          request_id: '018cc251-f400-7def-8000-0000000000c1', ...(capability === undefined ? {} : { capability }) } }, 422)
      }
      return json(publicationPage(true, { revision: 7 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])
    await user.click(await screen.findByRole('button', { name: locale === 'zh-CN' ? '回滚到此版本' : 'Roll back to this version' }))
    await user.click(await screen.findByRole('button', { name: locale === 'zh-CN' ? '确认回滚' : 'Confirm rollback' }))
  }

  it('lists every node to upgrade when target nodes lack a gated capability', async () => {
    await publishRefusedForCapability({ node_id: nodeID, capability: 'CAPABILITY_NAME_TCP_PROXY', required_version: 9,
      other_node_ids: [otherNodeID, nodeID] })

    expect(await screen.findByText(/部分目标节点版本过低，不支持这次配置用到的功能（TCP_PROXY v9），已拒绝整次发布/)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`需要升级的节点：${nodeID}、${otherNodeID}$`))).toBeInTheDocument()
    expect(screen.queryByText(/secret-host/)).not.toBeInTheDocument()
  })

  it('names the nodes still loading the IP intelligence library', async () => {
    await publishRefusedForCapability({ node_id: nodeID, capability: 'CAPABILITY_NAME_IP_INTEL', required_version: 1,
      other_node_ids: [otherNodeID] })

    expect(await screen.findByText(/运营商、IDC、ASN 或地区规则需要节点 IP 情报库/)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`尚未就绪的节点：${nodeID}、${otherNodeID}$`))).toBeInTheDocument()
  })

  it('explains a capability refusal in English with a single node', async () => {
    await publishRefusedForCapability({ node_id: nodeID, capability: 'CAPABILITY_NAME_CC', required_version: 4,
      other_node_ids: [] }, 'en-US')
    expect(await screen.findByText(new RegExp(`Some target nodes run an agent too old for a feature this configuration uses \\(CC v4\\).*Nodes to upgrade: ${nodeID}$`)))
      .toBeInTheDocument()
  })

  it('keeps the capability refusal explanation when the server omits the node details', async () => {
    await publishRefusedForCapability(undefined)

    expect(await screen.findByText('部分目标节点版本过低，不支持这次配置用到的功能，已拒绝整次发布。请升级这些节点，或去掉相应功能后重新发布。'))
      .toBeInTheDocument()
  })

  // rule_pack_unavailable (edgepublishhttp: error.rule_packs): the release is
  // held, not lost; the page says so and names the waiting nodes.
  async function publishRefusedForRulePacks(rulePacks: unknown, locale = 'zh-CN') {
    await i18n.changeLanguage(locale)
    setPlatform()
    installPlatformTargetMocks()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        return json({ error: { code: 'rule_pack_unavailable', message: 'node secret-host lacks rule pack',
          request_id: '018cc251-f400-7def-8000-0000000000c2', ...(rulePacks === undefined ? {} : { rule_packs: rulePacks }) } }, 422)
      }
      return json(publicationPage(true, { revision: 7 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])
    await user.click(await screen.findByRole('button', { name: locale === 'zh-CN' ? '回滚到此版本' : 'Roll back to this version' }))
    await user.click(await screen.findByRole('button', { name: locale === 'zh-CN' ? '确认回滚' : 'Confirm rollback' }))
  }

  it('names the nodes still waiting for rule packs and says the release goes out by itself', async () => {
    await publishRefusedForRulePacks({ node_id: nodeID, sha256: ['a'.repeat(64)], other_node_ids: [otherNodeID, nodeID] })

    expect(await screen.findByText(/部分目标节点还没有收到这次配置用到的规则包.*规则包同步到这些节点后会自动发布/)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`尚未收到规则包的节点：${nodeID}、${otherNodeID}$`))).toBeInTheDocument()
    expect(screen.queryByText(/secret-host/)).not.toBeInTheDocument()
  })

  it('explains a rule pack refusal in English and without node details', async () => {
    await publishRefusedForRulePacks({ node_id: 'not-a-uuid', sha256: [], other_node_ids: [] }, 'en-US')

    expect(await screen.findByText(/^Some target nodes have not received a rule pack this configuration uses.*there is no need to publish again\.$/))
      .toBeInTheDocument()
    expect(screen.queryByText(/Nodes waiting for rule packs/)).not.toBeInTheDocument()
  })

  it('rolls a line-group publication back with an exact immutable target and refreshes facts', async () => {
    setPlatform()
    const requests: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      requests.push({ url, init })
      if (init?.method === 'POST') return json(adminRollback, 201)
      return json(publicationPage(true, { revision: 7 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    await user.click(await screen.findByRole('button', { name: '回滚到此版本' }))
    expect(await screen.findByText('确认将所选线路分组的节点回滚到这个直接前序版本吗？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认回滚' }))

    await waitFor(() => expect(requests.some(({ init }) => init?.method === 'POST')).toBe(true))
    const write = requests.find(({ init }) => init?.method === 'POST')!
    expect(write.url).toBe(`/v1/admin/site-publications/${publicationID}/rollback`)
    expect(JSON.parse(String(write.init?.body))).toEqual({
      configuration_scope_id: scopeID,
      target: {
        kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4,
        resolver_sha256: digest,
      },
      health_check: {
        activation_timeout_ms: 60_000,
        observation_window_ms: 30_000,
        required_consecutive_successes: 3,
      },
      max_attempts: 5,
      deadline: expect.any(String),
      rollout: {
        strategy: 'canary', canary_size: 1, batch_size: 10,
        failure_threshold: 1, auto_start: true,
      },
    })
    expect(await screen.findByText('回滚任务已创建')).toBeInTheDocument()
    await waitFor(() => expect(requests.filter(({ init }) => init?.method !== 'POST').length).toBeGreaterThan(1))
  })

  it('drops A-scope cursor, selection, and unknown-write controls on the first B commit', async () => {
    setPlatform()
    installPlatformTargetMocks()
    let resolveSecond!: (value: Response) => void
    const secondResponse = new Promise<Response>((resolve) => { resolveSecond = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') throw new TypeError('connection reset')
      if (url.includes(`scope_id=${otherScopeID}`)) return secondResponse
      if (url.includes(`/${publicationID}`)) return json(adminPublication)
      return json(publicationPage(true, { next_cursor: 'old_cursor', revision: 7 }))
    })
    const user = userEvent.setup()
    let firstTargetCommit: { text: string; publicationDialog: boolean } | undefined
    renderWithProviders(
      <>
        <RouteTargetControl onTargetCommit={() => {
          firstTargetCommit ??= {
            text: document.body.textContent ?? '',
            publicationDialog: Boolean(screen.queryByRole('dialog', { name: '发布详情' })),
          }
        }} />
        <SitePublicationsPage />
      </>,
      [`/site/publications?target_scope_id=${scopeID}`],
    )

    expect(await screen.findByText(publicationID)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('cursor=old_cursor'))).toBe(true))
    await submitRollback(user)
    expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看发布详情' }))
    expect((await screen.findByText('发布详情', { selector: '.ant-drawer-title, .ant-modal-title' })).closest('[role="dialog"]')).toBeVisible()

    await user.click(screen.getByTestId('route-target-control'))

    expect(firstTargetCommit?.text).not.toContain(publicationID)
    expect(firstTargetCommit?.text).not.toContain('使用原请求重试')
    expect(firstTargetCommit?.text).not.toContain('发布配置')
    expect(firstTargetCommit?.publicationDialog).toBe(false)
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => {
      const parsed = new URL(String(url), 'https://cdnca.test')
      return parsed.searchParams.get('scope_id') === otherScopeID && !parsed.searchParams.has('cursor')
    })).toBe(true))
    resolveSecond(json(publicationPage(true, { items: [], revision: 8 })))
  })

  it('reuses the identical write metadata and body after an unknown result, then refreshes facts', async () => {
    setPlatform()
    installPlatformTargetMocks()
    const writes: RequestInit[] = []
    let writeCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        writes.push(init)
        writeCount += 1
        if (writeCount === 1) throw new TypeError('connection reset')
        return json(adminRollback, 201)
      }
      return json(publicationPage(true, { revision: 7 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    await submitRollback(user)
    expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用原请求重试' }))
    await waitFor(() => expect(writes).toHaveLength(2))

    expect(writes[1]?.body).toBe(writes[0]?.body)
    expect(writes[1]?.headers).toEqual(writes[0]?.headers)
    expect(await screen.findByText('回滚任务已创建')).toBeInTheDocument()
  })

  describe('unknown outcome scope locks', () => {
    it('retains the A-scope lock across A to B to A navigation', async () => {
      setPlatform()
      installPlatformTargetMocks()
      const writes: RequestInit[] = []
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        if (init?.method === 'POST') {
          writes.push(init)
          throw new TypeError('connection reset')
        }
        if (String(input).includes(`scope_id=${otherScopeID}`)) {
          return json(publicationPage(true, { items: [], revision: 8 }))
        }
        return json(publicationPage(true, { revision: 7 }))
      })
      const user = userEvent.setup()
      renderWithProviders(
        <>
          <RouteTargetControl target={otherScopeID} testId="route-target-b" />
          <RouteTargetControl target={scopeID} testId="route-target-a" />
          <SitePublicationsPage />
        </>,
        [`/site/publications?target_scope_id=${scopeID}`],
      )

      await submitRollback(user)
      expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
      await user.click(screen.getByTestId('route-target-b'))
      expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用原请求重试' })).not.toBeInTheDocument()

      await user.click(screen.getByTestId('route-target-a'))
      expect(await screen.findByRole('button', { name: '使用原请求重试' })).toBeEnabled()
      expect(writes).toHaveLength(1)
    })

    it('retains the current-scope lock across manage permission revocation and restoration', async () => {
      setPlatform()
      installPlatformTargetMocks()
      const writes: RequestInit[] = []
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        if (init?.method === 'POST') {
          writes.push(init)
          throw new TypeError('connection reset')
        }
        return json(publicationPage(true, { revision: 7 }))
      })
      const user = userEvent.setup()
      renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

      await submitRollback(user)
      expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
      act(() => setPlatform(['edge_publications.read'], 'refresh'))
      expect(screen.queryByRole('button', { name: '发布配置' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用原请求重试' })).not.toBeInTheDocument()

      act(() => setPlatform(undefined, 'refresh'))
      expect(await screen.findByRole('button', { name: '使用原请求重试' })).toBeEnabled()
      expect(writes).toHaveLength(1)
    })

    it('records an A-scope unknown outcome that completes after navigation to B', async () => {
      setPlatform()
      installPlatformTargetMocks()
      let rejectWrite!: (error: unknown) => void
      const pendingWrite = new Promise<Response>((_resolve, reject) => { rejectWrite = reject })
      const writes: RequestInit[] = []
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        if (init?.method === 'POST') {
          writes.push(init)
          return pendingWrite
        }
        if (String(input).includes(`scope_id=${otherScopeID}`)) {
          return json(publicationPage(true, { items: [], revision: 8 }))
        }
        return json(publicationPage(true, { revision: 7 }))
      })
      const user = userEvent.setup()
      renderWithProviders(
        <>
          <RouteTargetControl target={otherScopeID} testId="route-target-b" />
          <RouteTargetControl target={scopeID} testId="route-target-a" />
          <SitePublicationsPage />
        </>,
        [`/site/publications?target_scope_id=${scopeID}`],
      )

      await submitRollback(user)
      await waitFor(() => expect(writes).toHaveLength(1))
      await user.click(screen.getByTestId('route-target-b'))
      expect(await screen.findByText('暂无发布记录')).toBeInTheDocument()
      await act(async () => {
        rejectWrite(new TypeError('connection reset'))
        await pendingWrite.catch(() => undefined)
      })
      expect(screen.queryByRole('button', { name: '使用原请求重试' })).not.toBeInTheDocument()

      await user.click(screen.getByTestId('route-target-a'))
      expect(await screen.findByRole('button', { name: '使用原请求重试' })).toBeEnabled()
      expect(writes).toHaveLength(1)
    })
  })

  it('retains the original write lock until current-scope facts refresh successfully', async () => {
    setPlatform()
    installPlatformTargetMocks()
    let resolveFailedRefresh!: (value: Response) => void
    let resolveSuccessfulRefresh!: (value: Response) => void
    const failedRefresh = new Promise<Response>((resolve) => { resolveFailedRefresh = resolve })
    const successfulRefresh = new Promise<Response>((resolve) => { resolveSuccessfulRefresh = resolve })
    const writes: RequestInit[] = []
    let refreshCount = 0
    let writeFailed = false
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        writes.push(init)
        writeFailed = true
        throw new TypeError('connection reset')
      }
      if (!writeFailed) return json(publicationPage(true, { revision: 7 }))
      refreshCount += 1
      return refreshCount === 1 ? failedRefresh : successfulRefresh
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    await submitRollback(user)
    expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新事实' }))
    await waitFor(() => expect(refreshCount).toBe(1))
    expect(screen.getByRole('button', { name: '使用原请求重试' })).toBeDisabled()
    expect(writes).toHaveLength(1)

    await act(async () => {
      resolveFailedRefresh(json({
        error: { code: 'publication_service_unavailable', message: 'private database host' },
      }, 503))
      await failedRefresh
    })
    expect(await screen.findByText('发布服务暂不可用。')).toBeInTheDocument()
    expect(screen.queryByText('private database host')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '使用原请求重试' })).toBeEnabled()
    expect(writes).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: '刷新事实' }))
    await waitFor(() => expect(refreshCount).toBe(2))
    expect(screen.getByRole('button', { name: '使用原请求重试' })).toBeDisabled()
    await act(async () => {
      resolveSuccessfulRefresh(json(publicationPage(true, { revision: 8 })))
      await successfulRefresh
    })

    await waitFor(() => expect(screen.queryByRole('button', { name: '使用原请求重试' })).not.toBeInTheDocument())
    expect(writes).toHaveLength(1)
  })

  it('retains the write lock when manage permission is revoked during a successful facts refresh', async () => {
    setPlatform()
    installPlatformTargetMocks()
    let resolveSuccessfulRefresh!: (value: Response) => void
    const successfulRefresh = new Promise<Response>((resolve) => { resolveSuccessfulRefresh = resolve })
    const writes: RequestInit[] = []
    let writeFailed = false
    let refreshCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        writes.push(init)
        writeFailed = true
        throw new TypeError('connection reset')
      }
      if (!writeFailed) return json(publicationPage(true, { revision: 7 }))
      refreshCount += 1
      return successfulRefresh
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    await submitRollback(user)
    expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新事实' }))
    await waitFor(() => expect(refreshCount).toBe(1))
    act(() => setPlatform(['edge_publications.read'], 'refresh'))
    expect(screen.queryByRole('button', { name: '发布配置' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用原请求重试' })).not.toBeInTheDocument()

    await act(async () => {
      resolveSuccessfulRefresh(json(publicationPage(true, { items: [], revision: 8 })))
      await successfulRefresh
    })
    await waitFor(() => expect(screen.queryByText(publicationID)).not.toBeInTheDocument())
    expect(screen.getByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()

    act(() => setPlatform(undefined, 'refresh'))
    expect(await screen.findByRole('button', { name: '使用原请求重试' })).toBeEnabled()
    expect(writes).toHaveLength(1)
  })

  it('refreshes conflicts and removes stale write controls and retries after live permission revocation', async () => {
    setPlatform()
    installPlatformTargetMocks()
    let writeCount = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') {
        writeCount += 1
        if (writeCount === 1) return json({ error: { code: 'revision_conflict', message: 'private revision' } }, 412)
        throw new TypeError('unknown result')
      }
      return json(publicationPage(true, { revision: writeCount ? 8 : 7 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SitePublicationsPage />, [`/site/publications?target_scope_id=${scopeID}`])

    await submitRollback(user)
    // sec-ui-polish 改了冲突文案（已刷新为最新值），且写失败改为反馈弹窗：读到后关闭再重发。
    expect(await screen.findByText('源修订已变化，已刷新为最新值，请重新发布。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '知道了' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method !== 'POST').length).toBeGreaterThan(1))

    await submitRollback(user)
    expect(await screen.findByText('发布结果尚不确定', OUTCOME_BAR)).toBeInTheDocument()
    act(() => setPlatform(['edge_publications.read'], 'refresh'))
    expect(await screen.findByRole('heading', { name: '站点与四层发布' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '发布配置' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用原请求重试' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2)
  })
})
