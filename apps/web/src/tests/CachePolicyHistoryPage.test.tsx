import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import {
  cachePoliciesApi,
  type CachePolicyDocument,
  type CachePolicyView,
} from '../api/cachePolicies'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import CachePolicyHistoryPage from '../pages/CachePolicyHistoryPage'
import { authResponse, principal } from '../test/fixtures'

const tenantID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const otherTenantID = '33333333-3333-4333-8333-333333333333'

const policyDocument: CachePolicyDocument = {
  mode: 'override',
  rules: [{ order: 1, extensions: ['.css'], ttl_seconds: 3600 }],
  query_mode: 'ignore',
  query_names: [],
  vary_headers: ['accept-encoding'],
  disk_quota_bytes: 67_108_864,
}

function policy(revision: number, requestID = `request-${revision}`): CachePolicyView {
  return {
    site_id: siteID,
    revision,
    binding_mode: 'override',
    definition_id: siteID,
    definition_revision: revision,
    document: policyDocument,
    created_by_user_id: '44444444-4444-4444-8444-444444444444',
    request_id: requestID,
    created_at: `2026-08-0${revision}T08:00:00Z`,
  }
}

function tenant(overrides: Partial<Principal> = {}): Principal {
  return principal({
    scope_kind: 'tenant',
    scope_id: tenantID,
    tenant_id: tenantID,
    permissions: ['sites.read'],
    ...overrides,
  })
}

function authenticate(
  actor = tenant(),
  token = 'cache-history-token',
  update: 'new' | 'refresh' = 'new',
) {
  useSessionStore.getState().setSession(
    { ...authResponse(actor), access_token: token },
    actor,
    update,
  )
  return actor
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  return {
    queryClient,
    ...render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={queryClient}>
            <MemoryRouter><CachePolicyHistoryPage /></MemoryRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    ),
  }
}

async function applySite(user: ReturnType<typeof userEvent.setup>, value = siteID) {
  const input = screen.getByRole('textbox', { name: '站点 ID' })
  await user.clear(input)
  await user.type(input, value)
  await user.click(screen.getByRole('button', { name: '查询修订' }))
}

describe('CachePolicyHistoryPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('denies invalid tenant and RBAC identities locally without a request', async () => {
    const history = vi.spyOn(cachePoliciesApi, 'history')
    authenticate(tenant({ permissions: [] }))
    const view = renderPage()
    expect(await screen.findByText('无权查看缓存策略历史')).toBeInTheDocument()
    expect(history).not.toHaveBeenCalled()

    act(() => authenticate(tenant({ scope_id: tenantID, tenant_id: null })))
    view.rerender(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={new QueryClient()}>
            <MemoryRouter><CachePolicyHistoryPage /></MemoryRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    )
    expect(await screen.findByText('无权查看缓存策略历史')).toBeInTheDocument()
    expect(history).not.toHaveBeenCalled()
  })

  it('does not request before a valid site filter is applied', async () => {
    authenticate()
    const history = vi.spyOn(cachePoliciesApi, 'history').mockResolvedValue({ items: [] })
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText('输入站点 ID 后查询修订历史。')).toBeInTheDocument()
    expect(history).not.toHaveBeenCalled()

    await applySite(user, 'not-a-uuid')
    expect(await screen.findByText('请输入有效的站点 UUID。')).toBeInTheDocument()
    expect(history).not.toHaveBeenCalled()

    await applySite(user)
    await waitFor(() => expect(history).toHaveBeenCalledWith('cache-history-token', siteID, { limit: 20 }))
    expect(await screen.findByText('当前站点暂无缓存策略修订。')).toBeInTheDocument()
  })

  it('renders loading, localized error, and explicit retry recovery without raw messages', async () => {
    authenticate()
    let rejectFirst!: (error: unknown) => void
    const pending = new Promise<never>((_resolve, reject) => { rejectFirst = reject })
    const history = vi.spyOn(cachePoliciesApi, 'history')
      .mockReturnValueOnce(pending)
      .mockResolvedValueOnce({ items: [policy(3)] })
    const user = userEvent.setup()
    renderPage()
    await applySite(user)
    expect(await screen.findByLabelText('缓存策略修订加载中')).toHaveAttribute('aria-busy', 'true')

    await act(async () => rejectFirst(new ApiError('private upstream detail', 503, 'service_unavailable')))
    expect(await screen.findByText('缓存策略服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private upstream detail')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('request-3')).toBeInTheDocument()
    expect(history).toHaveBeenCalledTimes(2)
  })

  it.each([
    [403, 'permission_denied', '无权查看缓存策略历史'],
    [404, 'not_found', '未找到缓存策略历史'],
    [200, 'invalid_response', '缓存策略服务响应无效，请稍后重试。'],
  ])('maps status %s and %s without exposing the server message', async (status, code, expected) => {
    authenticate()
    vi.spyOn(cachePoliciesApi, 'history').mockRejectedValue(new ApiError('secret server text', status, code))
    const user = userEvent.setup()
    renderPage()
    await applySite(user)
    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('secret server text')
  })

  it('supports cursor pagination and localized revision details', async () => {
    authenticate()
    const history = vi.spyOn(cachePoliciesApi, 'history')
      .mockResolvedValueOnce({ items: [policy(3)], next_cursor: 'cursor-2' })
      .mockResolvedValueOnce({ items: [policy(2)] })
    const detail = vi.spyOn(cachePoliciesApi, 'getRevision').mockResolvedValue(policy(2))
    const user = userEvent.setup()
    renderPage()
    await applySite(user)
    expect(await screen.findByText('request-3')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(history).toHaveBeenLastCalledWith(
      'cache-history-token', siteID, { limit: 20, cursor: 'cursor-2' },
    ))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByRole('region', { name: '修订 2 详情' })).toBeInTheDocument()
    expect(detail).toHaveBeenCalledWith('cache-history-token', siteID, 2)
    expect(screen.getAllByText('64 MB').length).toBeGreaterThan(0)
  })

  it.each([
    {
      name: 'current cursor',
      pages: [
        { items: [policy(3)], next_cursor: 'cursor-2' },
        { items: [policy(2)], next_cursor: 'cursor-2' },
      ],
    },
    {
      name: 'previous cursor',
      pages: [
        { items: [policy(3)], next_cursor: 'cursor-2' },
        { items: [policy(2)], next_cursor: 'cursor-3' },
        { items: [policy(1)], next_cursor: 'cursor-2' },
      ],
    },
  ])('does not advance when the server repeats a $name', async ({ pages }) => {
    authenticate()
    const history = vi.spyOn(cachePoliciesApi, 'history')
    for (const page of pages) history.mockResolvedValueOnce(page)
    const user = userEvent.setup()
    renderPage()
    await applySite(user)

    for (let page = 2; page <= pages.length; page += 1) {
      await user.click(await screen.findByRole('button', { name: '下一页' }))
      expect(await screen.findByText(`第 ${page} 页`)).toBeInTheDocument()
    }

    const next = screen.getByRole('button', { name: '下一页' })
    expect(next).toBeDisabled()
    await user.click(next)
    expect(history).toHaveBeenCalledTimes(pages.length)
    expect(screen.getByText(`第 ${pages.length} 页`)).toBeInTheDocument()
  })

  it('localizes revision detail failures and retries the same read', async () => {
    authenticate()
    vi.spyOn(cachePoliciesApi, 'history').mockResolvedValue({ items: [policy(3)] })
    const detail = vi.spyOn(cachePoliciesApi, 'getRevision')
      .mockRejectedValueOnce(new ApiError('private detail', 404, 'not_found'))
      .mockResolvedValueOnce(policy(3))
    const user = userEvent.setup()
    renderPage()
    await applySite(user)
    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    const region = await screen.findByRole('region', { name: '修订 3 详情' })
    expect(within(region).getByText('该缓存策略修订不存在或不可见。')).toBeInTheDocument()
    expect(region.textContent).not.toContain('private detail')
    await user.click(within(region).getByRole('button', { name: '重试' }))
    expect(await within(region).findByText('request-3')).toBeInTheDocument()
    expect(detail).toHaveBeenCalledTimes(2)
  })

  it('removes cached history and revision details after a refresh is forbidden', async () => {
    authenticate()
    const history = vi.spyOn(cachePoliciesApi, 'history')
      .mockResolvedValueOnce({ items: [policy(3)] })
      .mockRejectedValueOnce(new ApiError('revoked server detail', 403, 'permission_denied'))
    vi.spyOn(cachePoliciesApi, 'getRevision').mockResolvedValue(policy(3))
    const user = userEvent.setup()
    renderPage()
    await applySite(user)
    await user.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByRole('region', { name: '修订 3 详情' })).toBeInTheDocument()
    expect(screen.getAllByText('request-3').length).toBeGreaterThan(0)

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('无权查看缓存策略历史')).toBeInTheDocument()
    expect(screen.queryByText('request-3')).not.toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '修订 3 详情' })).not.toBeInTheDocument()
    expect(history).toHaveBeenCalledTimes(2)
  })

  it('keeps filter, cursor, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = authenticate()
    const history = vi.spyOn(cachePoliciesApi, 'history')
      .mockResolvedValueOnce({ items: [policy(3)], next_cursor: 'cursor-2' })
      .mockResolvedValueOnce({ items: [policy(2)] })
      .mockResolvedValueOnce({ items: [policy(2, 'request-refreshed')] })
    const user = userEvent.setup()
    const { queryClient } = renderPage()
    await applySite(user)
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()

    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: 'refreshed-token' }, actor, 'refresh',
    ))
    expect(screen.getByDisplayValue(siteID)).toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toContain('cache-history-token')
    expect(keys).not.toContain('refreshed-token')

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(history).toHaveBeenLastCalledWith(
      'refreshed-token', siteID, { limit: 20, cursor: 'cursor-2' },
    ))
    expect(await screen.findByText('request-refreshed')).toBeInTheDocument()
  })

  it('resets owner state, clears old cache, and ignores a late response after a new session', async () => {
    authenticate()
    let resolveOld!: (value: { items: CachePolicyView[] }) => void
    const oldRead = new Promise<{ items: CachePolicyView[] }>((resolve) => { resolveOld = resolve })
    const history = vi.spyOn(cachePoliciesApi, 'history').mockReturnValue(oldRead)
    const user = userEvent.setup()
    const { queryClient } = renderPage()
    await applySite(user)
    await waitFor(() => expect(history).toHaveBeenCalledTimes(1))

    const next = tenant({
      user_id: '55555555-5555-4555-8555-555555555555',
      scope_id: otherTenantID,
      tenant_id: otherTenantID,
    })
    act(() => authenticate(next, 'new-session-token'))
    expect(await screen.findByText('输入站点 ID 后查询修订历史。')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: '站点 ID' })).toHaveValue('')
    await act(async () => resolveOld({ items: [policy(3, 'late-private-result')] }))
    expect(screen.queryByText('late-private-result')).not.toBeInTheDocument()
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toContain(tenantID)
    expect(keys).not.toContain(siteID)
    expect(keys).toContain(otherTenantID)
    expect(history).toHaveBeenCalledTimes(1)
  })
})
