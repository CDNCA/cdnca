import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import dayjs from 'dayjs'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { ja4BlocksApi, type JA4BlockWorkflow } from '../api/ja4Blocks'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import SiteAnalysisPage from '../pages/SiteAnalysisPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'
const siteId = '018f0000-0000-7000-8000-000000000020'
const snapshot = '2026-07-22T10:15:00Z'
const workflowId = '018f0000-0000-7000-8000-000000000040'
const rolloutId = '018f0000-0000-7000-8000-000000000050'
const workflow: JA4BlockWorkflow = {
  id: workflowId,
  tenant_scope_id: tenantId,
  site_id: siteId,
  ja4_sha256: 'a'.repeat(64),
  snapshot_at: snapshot,
  duration_seconds: 3600,
  reason: 'manual_security_review',
  phase: 'edge_pending',
  revision: 2,
  rollout_id: rolloutId,
  edge_state: 'pending',
  attempt_count: 1,
}

function authenticate(scope: 'platform' | 'tenant', permissions = ['sites.read']) {
  const actor = principal({
    scope_kind: scope,
    scope_id: scope === 'platform' ? 'platform' : tenantId,
    tenant_id: scope === 'platform' ? null : tenantId,
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const zeroSummary = {
  metric_version: 1, request_count: 0, request_bytes: 0, response_bytes: 0, total_bytes: 0, average_bandwidth_bps: 0,
  status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, security_events: 0, security_event_rows: 0,
  cache_hit_requests: 0, cache_hit_bytes: 0, unique_client_ips: 0,
}

// The page also reads the range summary (/summary); these tests count the
// ranking reads only.
function isSummary(input: RequestInfo | URL): boolean {
  return new URL(String(input), 'http://cdnca.test').pathname.endsWith('/summary')
}

function rankCalls(spy: { mock: { calls: Parameters<typeof fetch>[] } }): Parameters<typeof fetch>[] {
  return spy.mock.calls.filter(([input]) => new URL(String(input), 'http://cdnca.test').pathname.includes('/top/'))
}

function rankResponse(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'http://cdnca.test')
  const dimension = url.pathname.split('/').at(-1)!
  if (dimension === 'summary') {
    return json({ data: zeroSummary, meta: { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 } })
  }
  const cursor = url.searchParams.get('cursor')
  const meta = {
    from: url.searchParams.get('from'),
    to: url.searchParams.get('to'),
    timezone: 'UTC',
    metric_version: 1,
  }
  return json({
    data: cursor
      ? [{ key: 'second.example', request_count: 10, response_bytes: 1024 }]
      : [
          { key: 'first.example', request_count: 20, response_bytes: 2048 },
          { key: '__unknown__', request_count: 15, response_bytes: 1536 },
        ],
    dimension,
    page: cursor ? { snapshot_at: snapshot, source: 'history' } : { snapshot_at: snapshot, source: 'history', next_cursor: 'cursor-page-2' },
    meta,
  })
}

function renderWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/site/analysis']}>
            <SiteAnalysisPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function deferredResponse() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>((done) => { resolve = done })
  return { promise, resolve }
}

describe('SiteAnalysisPage', () => {
  it.each([
    ['unauthenticated', null],
    ['tenant without sites.read', principal({ permissions: [] })],
    ['tenant without a scope identity', principal({ scope_id: '', permissions: ['sites.read'] })],
  ])('fails closed with local 403 and zero requests for %s', async (_case, actor) => {
    if (actor) useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByText('无权查看监控数据')).toBeInTheDocument()
    expect(screen.getByText('当前账户没有此范围的监控读取权限。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps filters, page, and token-free owner identity stable across same-epoch token refresh until explicit refresh', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    const oldToken = 'site-analysis-old-token'
    const newToken = 'site-analysis-new-token'
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: oldToken }, actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)

    expect(await screen.findByText('first.example')).toBeInTheDocument()
    await user.type(screen.getByLabelText('站点 ID'), siteId)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(2))
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('second.example')).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    const readsBeforeRefresh = rankCalls(fetchSpy).length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken }, actor, 'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByDisplayValue(siteId)).toBeInTheDocument()
    expect(screen.getByText('second.example')).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(rankCalls(fetchSpy)).toHaveLength(readsBeforeRefresh)
    const ownerTuple = ['analytics', 'rank', 'tenant', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch]
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys.some((key) => ownerTuple.every((part) => JSON.stringify(key).includes(String(part))))).toBe(true)
    for (const key of queryKeys) {
      expect(JSON.stringify(key)).not.toContain(oldToken)
      expect(JSON.stringify(key)).not.toContain(newToken)
    }

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(readsBeforeRefresh + 1))
    expect(new Headers(rankCalls(fetchSpy).at(-1)![1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)
  }, 20_000)

  it('clears prior owner state and ignores a late prior-session response', async () => {
    const tenantA = principal({ permissions: ['sites.read'] })
    const tenantB = principal({
      scope_id: '99999999-9999-4999-8999-999999999999',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['sites.read'],
    })
    const late = deferredResponse()
    let tenantAReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (isSummary(input)) return Promise.resolve(rankResponse(input))
      if (authorization === 'Bearer tenant-a-analysis-token') {
        tenantAReads += 1
        return tenantAReads === 1 ? Promise.resolve(rankResponse(input)) : late.promise
      }
      if (authorization === 'Bearer tenant-b-analysis-token') {
        return Promise.resolve(json({
          data: [], dimension: 'domain', page: { snapshot_at: snapshot, source: 'history' },
          meta: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z', timezone: 'UTC', metric_version: 1 },
        }))
      }
      throw new Error(`unexpected analytics request ${authorization}`)
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-analysis-token' }, tenantA,
    )
    const user = userEvent.setup()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    renderWithQueryClient(queryClient)

    expect(await screen.findByText('first.example')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(tenantAReads).toBe(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-analysis-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(await screen.findByText('当前筛选范围内暂无数据')).toBeInTheDocument()
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.queryByText('first.example')).not.toBeInTheDocument()

    await act(async () => {
      late.resolve(rankResponse('/v1/analytics/top/domain?cursor=late'))
      await late.promise
    })

    expect(screen.queryByText('second.example')).not.toBeInTheDocument()
    expect(screen.queryByText('first.example')).not.toBeInTheDocument()
    const cache = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state.data))
    expect(cache).not.toContain('first.example')
    expect(cache).not.toContain('second.example')
    expect(rankCalls(fetchSpy).filter(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-analysis-token'
    ))).toHaveLength(1)
  }, 20_000)

  it('uses the admin rank route and applies the site and node filters', async () => {
    authenticate('platform')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByText('first.example')).toBeInTheDocument()
    // analysis 页筛选行只有一个「刷新」按钮，
    // 没有租户输入框。平台管理员的 rank 路由随之不再带 tenant_id。
    expect(screen.queryByLabelText('租户 ID')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('域名'), siteId)
    await user.click(screen.getByRole('button', { name: '刷新' }))

    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(2))
    const url = new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/top/domain')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(url.searchParams.get('site_id')).toBe(siteId)
    expect(url.searchParams.get('limit')).toBe('20')
  })

  it('uses tenant routes without exposing or sending tenant_id', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByText('first.example')).toBeInTheDocument()
    expect(screen.queryByLabelText('租户 ID')).not.toBeInTheDocument()
    const url = new URL(String(rankCalls(fetchSpy)[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/top/domain')
    expect(url.searchParams.has('tenant_id')).toBe(false)
  })

  it('canonicalizes multiple domains and queries the real Referer ranking', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    await screen.findByText('first.example')
    const domainInput = screen.getByPlaceholderText('输入域名，多个空格分隔')
    await user.type(domainInput, 'Static.Example.Test. cdn.example.test static.example.test')
    await user.click(screen.getByRole('button', { name: '刷新' }))

    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(2))
    const domainURL = new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test')
    expect(domainURL.searchParams.get('domain')).toBe('static.example.test cdn.example.test')
    expect(screen.getByText('域名：static.example.test')).toBeInTheDocument()
    expect(screen.getByText('域名：cdn.example.test')).toBeInTheDocument()
    expect(screen.queryByText('当前版本暂不支持同时筛选多个域名。')).not.toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '热门Referer' }))
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(3))
    const refererURL = new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test')
    expect(refererURL.pathname).toBe('/v1/analytics/top/referer')
    expect(refererURL.searchParams.get('domain')).toBe('static.example.test cdn.example.test')
    expect(screen.queryByText('当前版本不支持此排行维度。')).not.toBeInTheDocument()
  })

  it('keeps the table shell mounted through localized loading and empty states', async () => {
    authenticate('tenant')
    let resolveRank!: (response: Response) => void
    let requestedInput!: RequestInfo | URL
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      if (isSummary(input)) return Promise.resolve(rankResponse(input))
      requestedInput = input
      return new Promise((resolve) => { resolveRank = resolve })
    })
    renderWithProviders(<SiteAnalysisPage />)

    const table = screen.getByTestId('analytics-rank-table-scroll')
    expect(table).toHaveAttribute('aria-busy', 'true')
    expect(table).toHaveAttribute('aria-label', '正在加载监控数据')
    await act(async () => {
      const response = rankResponse(requestedInput)
      const body = await response.json() as Record<string, unknown>
      resolveRank(json({ ...body, data: [], page: { snapshot_at: snapshot, source: 'history' } }))
    })
    expect(await screen.findAllByText('当前筛选范围内暂无数据')).not.toHaveLength(0)
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('keeps a fixed snapshot while paging with the server cursor and can return to page one', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByText('first.example')).toBeInTheDocument()
    expect(screen.getByText('未知')).toBeInTheDocument()
    expect(screen.getByText('采集进度暂不可用')).toBeInTheDocument()
    // #48②：有下一页时不是精确总数，写明总数未统计；末页是已加载的确切条数。
    expect(screen.getByText(/^已加载 \d+ 条，还有更多，总数未统计$/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('second.example')).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(screen.queryByText(/总数未统计/)).not.toBeInTheDocument()
    const secondPage = new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test')
    expect(secondPage.searchParams.get('cursor')).toBe('cursor-page-2')

    await user.click(screen.getByRole('button', { name: '上一页' }))
    expect(await screen.findByText('first.example')).toBeInTheDocument()
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.getByTestId('analytics-rank-table-scroll')).toBeInTheDocument()
    expect(rankCalls(fetchSpy).map(([input]) => (
      new URL(String(input), 'http://cdnca.test').searchParams.get('cursor')
    ))).toEqual([null, 'cursor-page-2'])
  })

  it('queries, pages, and refreshes the JA4 dimension through the standard table', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    await screen.findByText('first.example')
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(2))
    await user.click(screen.getByRole('tab', { name: 'TLS指纹' }))
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(3))
    expect(new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test').pathname).toBe('/v1/analytics/top/ja4')
    expect(screen.getByTestId('analytics-rank-table-scroll')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('second.example')).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test').searchParams.get('cursor')).toBe('cursor-page-2')

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(5))
    expect(await screen.findByText('first.example')).toBeInTheDocument()
    const refreshed = new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test')
    expect(refreshed.pathname).toBe('/v1/analytics/top/ja4')
    expect(refreshed.searchParams.has('cursor')).toBe(false)
  })

  it('confirms and submits the exact tenant JA4 ranking identity to the mounted workflow', async () => {
    authenticate('tenant', [
      'sites.read',
      'sites.manage',
      'security_policies.read',
      'security_policies.manage',
    ])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const createTenant = vi.spyOn(ja4BlocksApi, 'createTenant').mockResolvedValue(workflow)
    const createAdmin = vi.spyOn(ja4BlocksApi, 'createAdmin').mockResolvedValue(workflow)
    const getTenant = vi.spyOn(ja4BlocksApi, 'getTenant').mockResolvedValue(workflow)
    const getAdmin = vi.spyOn(ja4BlocksApi, 'getAdmin').mockResolvedValue(workflow)
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />, ['/monitor/site/analysis?view=security#ja4-ranking'])

    await screen.findByText('first.example')
    await user.type(screen.getByLabelText('域名'), siteId)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await user.click(screen.getByRole('tab', { name: 'TLS指纹' }))
    await waitFor(() => expect(new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test').pathname).toBe('/v1/analytics/top/ja4'))
    await user.click(screen.getByRole('button', { name: '创建 JA4 封禁' }))

    const dialog = await screen.findByRole('dialog', { name: '确认 JA4 封禁' })
    expect(within(dialog).getByText(siteId)).toBeInTheDocument()
    expect(within(dialog).getByText('firs••••mple')).toBeInTheDocument()
    expect(within(dialog).queryByText('first.example')).not.toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('二次认证证明'), 'one-time-step-up')
    await user.click(within(dialog).getByRole('button', { name: '确认封禁' }))

    await waitFor(() => expect(createTenant).toHaveBeenCalledOnce())
    expect(createTenant).toHaveBeenCalledWith(
      expect.any(String),
      {
        site_id: siteId,
        ja4: 'first.example',
        snapshot_at: snapshot,
        duration_seconds: 3600,
        reason: 'manual_security_review',
      },
      expect.objectContaining({
        requestId: expect.stringMatching(/^ja4-block-request-/),
        idempotencyKey: expect.stringMatching(/^ja4-block-create-/),
        stepUpToken: 'one-time-step-up',
      }),
    )
    expect(createAdmin).not.toHaveBeenCalled()
    expect(getAdmin).not.toHaveBeenCalled()
    expect(getTenant).toHaveBeenCalledWith(expect.any(String), workflowId, expect.stringMatching(/^ja4-block-read-/))
    expect(await within(dialog).findByText(rolloutId)).toBeInTheDocument()
    expect(within(dialog).getByText('边缘下发中')).toBeInTheDocument()
    expect(screen.getAllByText('边缘下发中')).toHaveLength(2)
  })

  // 数据分析页筛选行只有「统计维度下拉 + 域名输入 + 刷新」，
  // 没有租户输入框，因此平台管理员在该页拿不到 tenant_scope_id，JA4 封禁入口随之不可达。
  // 保留这条断言是为了让这个后果显式可见，而不是被误读成权限判定出错。
  it('keeps the JA4 block command unavailable to a platform administrator without a tenant scope', async () => {
    authenticate('platform', [
      'sites.read',
      'sites.manage',
      'security_policies.read',
      'security_policies.manage',
      'platform.admin',
    ])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const createAdmin = vi.spyOn(ja4BlocksApi, 'createAdmin')
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />, ['/monitor/site/analysis?view=security#ja4-ranking'])

    await screen.findByText('first.example')
    await user.type(screen.getByLabelText('域名'), siteId)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await user.click(screen.getByRole('tab', { name: 'TLS指纹' }))
    await waitFor(() => expect(new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test').pathname).toBe('/v1/admin/analytics/top/ja4'))

    expect(screen.queryByRole('button', { name: '创建 JA4 封禁' })).not.toBeInTheDocument()
    expect(createAdmin).not.toHaveBeenCalled()
  })

  it.each([
    ['missing sites.manage', ['sites.read', 'security_policies.read', 'security_policies.manage']],
    ['missing security manage', ['sites.read', 'sites.manage', 'security_policies.read']],
  ])('keeps the JA4 block command and write API absent when %s', async (_case, permissions) => {
    authenticate('tenant', permissions)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const createTenant = vi.spyOn(ja4BlocksApi, 'createTenant')
    const createAdmin = vi.spyOn(ja4BlocksApi, 'createAdmin')
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    await screen.findByText('first.example')
    await user.type(screen.getByLabelText('站点 ID'), siteId)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await user.click(screen.getByRole('tab', { name: 'TLS指纹' }))
    await waitFor(() => expect(new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test').pathname).toBe('/v1/analytics/top/ja4'))

    expect(screen.queryByRole('button', { name: '创建 JA4 封禁' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/security/ja4-blocks'))).toBe(false)
    expect(createTenant).not.toHaveBeenCalled()
    expect(createAdmin).not.toHaveBeenCalled()
  })

  it('retries an unknown JA4 write with the exact frozen request or abandons it', async () => {
    authenticate('tenant', ['sites.read', 'sites.manage', 'security_policies.read', 'security_policies.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const create = vi.spyOn(ja4BlocksApi, 'createTenant')
      .mockRejectedValue(new ApiError('private transport detail', 0, 'network_error'))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    await screen.findByText('first.example')
    await user.type(screen.getByLabelText('站点 ID'), siteId)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await user.click(screen.getByRole('tab', { name: 'TLS指纹' }))
    await user.click(await screen.findByRole('button', { name: '创建 JA4 封禁' }))
    const dialog = await screen.findByRole('dialog', { name: '确认 JA4 封禁' })
    await user.type(within(dialog).getByLabelText('二次认证证明'), 'retry-step-up')
    await user.click(within(dialog).getByRole('button', { name: '确认封禁' }))

    expect(await within(dialog).findByText('创建结果待确认')).toBeInTheDocument()
    const firstCall = create.mock.calls[0]
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(firstCall)
    await user.click(within(dialog).getByRole('button', { name: '放弃并清除' }))
    expect(within(dialog).queryByText('创建结果待确认')).not.toBeInTheDocument()
  })

  it.each([
    [400, 'analytics_invalid_request', '筛选条件无效，请检查时间范围和 UUID。'],
    [422, 'analytics_dimension_unsupported', '当前版本不支持此排行维度。'],
    [503, 'analytics_storage_unavailable', '分析存储暂不可用，请稍后重试。'],
    [504, 'analytics_query_timeout', '查询超时，请缩小时间范围后重试。'],
    [502, 'analytics_storage_rejected', '监控数据加载失败，请稍后重试。'],
    [500, 'analytics_internal_failure', '监控数据加载失败，请稍后重试。'],
  ])('maps status %s without leaking the server response', async (status, code, expected) => {
    authenticate('tenant')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code, message: 'private clickhouse response body', request_id: `req-${status}` },
    }, status))
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findAllByText(expected)).not.toHaveLength(0)
    expect(screen.queryByText('private clickhouse response body')).not.toBeInTheDocument()
    expect(screen.queryByText('当前筛选范围内暂无数据')).not.toBeInTheDocument()
  })

  it('localizes network failures and recovers through retry without exposing private details', async () => {
    authenticate('tenant')
    let retryInput!: RequestInfo | URL
    let resolveRetry!: (response: Response) => void
    let rankReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      if (isSummary(input)) return Promise.resolve(rankResponse(input))
      rankReads += 1
      // The page retries a network failure once by itself (fix-ipdisplay2).
      if (rankReads <= 2) return Promise.reject(new Error('private ClickHouse host'))
      retryInput = input
      return new Promise((resolve) => { resolveRetry = resolve })
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByText('监控数据加载失败，请稍后重试。', undefined, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.queryByText('private ClickHouse host')).not.toBeInTheDocument()
    expect(screen.queryByText('当前筛选范围内暂无数据')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))

    await waitFor(() => expect(screen.getByTestId('analytics-rank-table-scroll')).toHaveAttribute('aria-busy', 'true'))
    expect(screen.queryByText('监控数据加载失败，请稍后重试。')).not.toBeInTheDocument()
    await act(async () => resolveRetry(rankResponse(retryInput)))
    expect(await screen.findByText('first.example')).toBeInTheDocument()
    expect(rankCalls(fetchSpy)).toHaveLength(3)
    expect(screen.queryByText('监控数据加载失败，请稍后重试。')).not.toBeInTheDocument()
  })

  it.each(['en-US', 'qps-ploc'] as const)('keeps stable invalid-request mapping in %s', async (locale) => {
    await changeLocale(locale)
    authenticate('tenant')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'analytics_invalid_request', message: 'private validator detail' },
    }, 400))
    renderWithProviders(<SiteAnalysisPage />)

    const t = i18n.getFixedT(locale, 'analytics')
    expect(await screen.findByText(t('states.invalidRequest'))).toBeInTheDocument()
    expect(screen.queryByText('private validator detail')).not.toBeInTheDocument()
    expect(screen.queryByText(t('states.empty'))).not.toBeInTheDocument()
  })

  it('renders permission denial separately and validates a 31-day maximum locally', async () => {
    authenticate('tenant')
    const denied = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'analytics_permission_denied', message: 'private permission detail', request_id: 'req-denied' },
    }, 403))
    const first = renderWithProviders(<SiteAnalysisPage />)
    expect(await screen.findByText('无权查看监控数据')).toBeInTheDocument()
    expect(screen.queryByText('private permission detail')).not.toBeInTheDocument()
    first.unmount()
    denied.mockRestore()

    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    await screen.findByText('first.example')
    // The 31-day limit now lives in the picker: an end day beyond it cannot be picked.
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const start = dayjs().startOf('month')
    await user.click(screen.getAllByRole('button', { name: start.format('YYYY-MM-DD') })[0])
    await user.click(screen.getByRole('button', { name: '下个月' }))
    expect(screen.getAllByRole('button', { name: start.add(2, 'month').format('YYYY-MM-DD') }).at(-1)!).toBeDisabled()
    expect(screen.getByRole('button', { name: '确定' })).toBeDisabled()
    await user.keyboard('{Escape}')
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(rankCalls(fetchSpy)).toHaveLength(2)
  })

  it('renders the English ranking surface and localized snapshot metadata', async () => {
    await changeLocale('en-US')
    authenticate('tenant')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByRole('heading', { name: 'Site analytics' })).toBeInTheDocument()
    await screen.findByText('first.example')
    expect(screen.getByRole('tab', { name: 'Popular URLs' })).toBeInTheDocument()
    expect(screen.getAllByText('Outbound traffic')).not.toHaveLength(0)
    expect(screen.getByText(/Ranking snapshot/)).toBeInTheDocument()
    expect(screen.getByText('Ingest progress is unavailable')).toBeInTheDocument()
  })
  // fix-rangecompact：快捷项统一为今天/近7天/近30天/自定义，原 30 分钟用例改为近 7 天（仍按分钟对齐）。
  it('requests the summary for the 7-day preset as a minute-aligned window (ui-click F4)', async () => {
    authenticate('tenant')
    const summaryWindows: Array<{ from: string | null; to: string | null }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      const meta = { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 }
      if (url.pathname.endsWith('/summary')) {
        summaryWindows.push({ from: meta.from, to: meta.to })
        return Promise.resolve(json({ data: { ...zeroSummary, request_count: 4, status_2xx: 4, cache_hit_requests: 1, unique_client_ips: 2 }, meta }))
      }
      return Promise.resolve(json({ data: [], dimension: url.pathname.split('/').at(-1), page: { snapshot_at: snapshot, source: 'history' }, meta }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    await screen.findByText('独立 IP：2')

    await user.click(screen.getByText('近7天'))
    await user.click(screen.getByRole('button', { name: '刷新' }))

    await waitFor(() => expect(summaryWindows.some(({ from, to }) =>
      from !== null && to !== null && Date.parse(to) - Date.parse(from) === 7 * 86_400_000)).toBe(true))
    const window = summaryWindows.find(({ from, to }) => Date.parse(to!) - Date.parse(from!) === 7 * 86_400_000)!
    expect(Date.parse(window.from!) % 60_000).toBe(0)
    expect(screen.getByText('独立 IP：2')).toBeInTheDocument()
  })
  it('ends the quick ranges at the current minute, not the previous whole hour (fix-logfields)', async () => {
    // 73 实机 10-27：16:56 打开“近 30 分钟”，页面请求的是 15:30–16:00，近 56 分钟的请求全部落在窗口外。
    vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-10-26T16:56:42.123Z') })
    try {
      authenticate('tenant')
      const windows: Array<{ path: string; from: string | null; to: string | null }> = []
      vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        const url = new URL(String(input), 'http://cdnca.test')
        windows.push({ path: url.pathname, from: url.searchParams.get('from'), to: url.searchParams.get('to') })
        return Promise.resolve(rankResponse(input))
      })
      const user = userEvent.setup()
      renderWithProviders(<SiteAnalysisPage />)
      await waitFor(() => expect(windows.some(({ path }) => path.includes('/top/'))).toBe(true))
      // 初始“今天”（fix-rangecompact）：[当天 00:00, 16:57)，含刚刚这一分钟
      const midnight = new Date('2026-10-26T16:56:00.000Z')
      midnight.setHours(0, 0, 0, 0)
      expect(windows.find(({ path }) => path.includes('/top/'))).toMatchObject({ from: midnight.toISOString(), to: '2026-10-26T16:57:00.000Z' })

      windows.length = 0
      await user.click(screen.getByText('近7天'))
      await user.click(screen.getByRole('button', { name: '刷新' }))
      await waitFor(() => expect(windows.some(({ path, from }) => path.includes('/top/') && from === '2026-10-19T16:57:00.000Z')).toBe(true))
      expect(windows.filter(({ path }) => path.includes('/top/')).at(-1)).toMatchObject({ to: '2026-10-26T16:57:00.000Z' })
    } finally {
      vi.useRealTimers()
    }
  })

  // TEL-UX-DRILL：下钻带上同一时间、域名范围和该行的值；日志不支持的维度/端口筛选不给假下钻。
  it('drills into access logs with the same window, domain scope and row value (TEL-UX-DRILL)', async () => {
    authenticate('tenant')
    let topWindow: [string | null, string | null] = [null, null]
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      if (url.pathname.endsWith('/summary')) return Promise.resolve(rankResponse(input))
      topWindow = [url.searchParams.get('from'), url.searchParams.get('to')]
      const dimension = url.pathname.split('/').at(-1)!
      const keys: Record<string, string[]> = { ip: ['203.0.113.7'], province: ['440000'], domain: ['a.example'] }
      return Promise.resolve(json({
        data: (keys[dimension] ?? ['x']).map((key) => ({ key, request_count: 1, response_bytes: 1 })),
        dimension, page: { snapshot_at: snapshot, source: 'history' },
        meta: { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 },
      }))
    })
    const user = userEvent.setup()
    let landed: { search: string; state: unknown } | null = null
    function Landing() {
      const location = useLocation()
      landed = { search: location.search, state: location.state }
      return <p>access-log-landing</p>
    }
    render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
            <MemoryRouter initialEntries={['/site/analysis']}>
              <Routes>
                <Route path="/site/analysis" element={<SiteAnalysisPage />} />
                <Route path="/monitor/site/access-log" element={<Landing />} />
              </Routes>
            </MemoryRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    )
    await user.type(screen.getByPlaceholderText('输入域名，多个空格分隔'), 'a.example b.example')
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await user.click(screen.getByRole('tab', { name: '省份排行' }))
    expect(await screen.findByText('广东')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看日志' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: 'Top客户端IP' }))
    expect(await screen.findByText('203.0.113.7')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看日志' }))
    expect(await screen.findByText('access-log-landing')).toBeInTheDocument()
    const params = new URLSearchParams(landed!.search)
    expect(params.get('client_ip')).toBe('203.0.113.7')
    expect(params.get('host')).toBe('a.example b.example')
    // fix-rangecompact：默认"今天"，窗口随当前时间变；下钻与排行用同一窗口。
    expect([params.get('from'), params.get('to')]).toEqual(topWindow)
    expect(landed!.state).toEqual({ drillFrom: 'analysis' })
  })

  // TEL-UX-SUMMARY-SCOPE：汇总接口不支持域名/端口，排行按域名筛了，汇总要写明它统计的是全部站点。
  it('labels the range summary scope when the ranking is narrowed by domain (TEL-UX-SUMMARY-SCOPE)', async () => {
    authenticate('tenant')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    const strip = await screen.findByRole('group', { name: '范围汇总' })
    expect(within(strip).getByText('汇总范围：所选时间内全部站点')).toBeInTheDocument()
    await user.type(screen.getByPlaceholderText('输入域名，多个空格分隔'), 'a.example')
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(within(screen.getByRole('group', { name: '范围汇总' }))
      .getByText('汇总范围：所选时间内全部站点（汇总不按域名、端口筛选，下方排行已按所选条件筛选）')).toBeInTheDocument())
    const summaryURL = new URL(String(fetchSpy.mock.calls.filter(([input]) => isSummary(input)).at(-1)![0]), 'http://cdnca.test')
    expect(summaryURL.searchParams.has('domain')).toBe(false)
  })

  it('ranks provinces, browsers and OS by name, shows the range summary and warns about retention', async () => {
    authenticate('tenant')
    const retainedFrom = '2026-07-15T00:00:00Z'
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      const meta = { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 }
      if (url.pathname.endsWith('/summary')) {
        return Promise.resolve(json({ data: { ...zeroSummary, request_count: 8, request_bytes: 80, response_bytes: 720, total_bytes: 800,
          average_bandwidth_bps: 720 * 8 / 600, status_2xx: 8, cache_hit_requests: 6, cache_hit_bytes: 600, unique_client_ips: 3, security_events: 52, security_event_rows: 3 }, meta }))
      }
      const dimension = url.pathname.split('/').at(-1)!
      const keys: Record<string, string[]> = { province: ['440000', '__unknown__'], browser: ['chrome', 'bot'], os: ['harmonyos'], url: ['/a'] }
      return Promise.resolve(json({
        data: (keys[dimension] ?? ['x.example']).map((key, index) => ({ key, request_count: 5 - index, response_bytes: 500 - index })),
        dimension,
        page: dimension === 'url' ? { snapshot_at: snapshot, source: 'access_log', retained_from: retainedFrom } : { snapshot_at: snapshot, source: 'history' },
        meta,
      }))
    })
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)

    expect(await screen.findByText('缓存命中率：75%')).toBeInTheDocument()
    expect(screen.getByText('独立 IP：3')).toBeInTheDocument()
    // sec-log-agg: security events in requests, the record count in small text
    expect(screen.getByText('安全事件请求数：52')).toBeInTheDocument()
    expect(screen.getByText('（事件条数 3）')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '省份排行' }))
    expect(await screen.findByText('广东')).toBeInTheDocument()
    expect(screen.queryByText('当前版本不支持此排行维度。')).not.toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '浏览器分布' }))
    expect(await screen.findByText('Chrome')).toBeInTheDocument()
    expect(screen.getByText('爬虫/脚本')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '操作系统分布' }))
    expect(await screen.findByText('鸿蒙')).toBeInTheDocument()
    expect(screen.queryByText(/已超过/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '热门URL' }))
    expect(await screen.findByText(/访问日志已超过“网站访问日志”保留期/)).toBeInTheDocument()
  })
})
