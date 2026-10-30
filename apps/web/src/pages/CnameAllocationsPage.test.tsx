import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  cnameAllocationsApi,
  type CnameAllocation,
  type CnameAllocationDiagnosis,
} from '../api/cnameAllocations'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import CnameAllocationsPage from './CnameAllocationsPage'

const scopeID = '99999999-9999-4999-8999-999999999999'
const allocation: CnameAllocation = {
  id: '22222222-2222-4222-8222-222222222222',
  mode: 'site',
  owner_id: '33333333-3333-4333-8333-333333333333',
  provider_id: '44444444-4444-4444-8444-444444444444',
  zone_id: '55555555-5555-4555-8555-555555555555',
  domain: 'example.com',
  hostname: 'edge.example.com',
  explicit_hostname: true,
  state: 'done',
  job_id: '66666666-6666-4666-8666-666666666666',
  generation: 2,
  current_revision: 3,
  lkg_revision: 2,
  created_at: '2026-08-07T08:00:00Z',
  updated_at: '2026-08-07T08:05:00Z',
}
const diagnosis: CnameAllocationDiagnosis = {
  site_id: allocation.owner_id,
  mode: 'site',
  owner_id: allocation.owner_id,
  allocation_id: allocation.id,
  domain: allocation.domain,
  hostname: allocation.hostname,
  state: 'done',
  ready: true,
  reason_codes: ['ready'],
}

function tenantActor(overrides: Partial<Principal> = {}) {
  return principal({ permissions: ['dns.read'], ...overrides })
}

function platformActor(overrides: Partial<Principal> = {}) {
  return principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
    permissions: ['platform.admin'], ...overrides,
  })
}

function authenticate(actor = tenantActor(), token = 'cname-token', update: 'new' | 'refresh' = 'new') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return actor
}

function renderPage(path = '/site/cname-allocations', queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  return {
    queryClient,
    ...render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp><QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[path]}><CnameAllocationsPage /></MemoryRouter>
        </QueryClientProvider></AntApp>
      </ConfigProvider>,
    ),
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

describe('CnameAllocationsPage', () => {
  beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

  it.each([
    ['tenant permission', tenantActor({ permissions: [] })],
    ['platform permission', platformActor({ permissions: [] })],
    ['platform tenant identity', platformActor({ tenant_id: scopeID })],
  ])('renders local forbidden with zero requests for invalid %s', async (_name, actor) => {
    authenticate(actor)
    const listSpy = vi.spyOn(cnameAllocationsApi, 'list')
    renderPage()
    expect(await screen.findByText('无权查看 CNAME 分配权威')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('requires an explicit canonical tenant scope for platform reads', async () => {
    authenticate(platformActor())
    const listSpy = vi.spyOn(cnameAllocationsApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup()
    renderPage()

    expect(screen.getByText('请输入租户作用域后查询。')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
    await user.type(screen.getByRole('textbox', { name: '租户作用域 ID' }), 'INVALID')
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(screen.getByText('请输入规范的小写 UUID。')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
    await user.clear(screen.getByRole('textbox', { name: '租户作用域 ID' }))
    await user.type(screen.getByRole('textbox', { name: '租户作用域 ID' }), scopeID)
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(listSpy).toHaveBeenCalledWith('cname-token', {
      kind: 'platform', scopeID,
    }, { limit: 20, cursor: undefined }))
  })

  it('renders loading, empty, localized error/retry, and server forbidden states', async () => {
    authenticate()
    const pending = deferred<{ items: CnameAllocation[] }>()
    vi.spyOn(cnameAllocationsApi, 'list')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('raw backend detail', 503, 'cname_allocation_unavailable'))
      .mockResolvedValueOnce({ items: [allocation] })
      .mockRejectedValueOnce(new ApiError('raw IAM detail', 403, 'permission_denied'))
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByLabelText('正在加载 CNAME 分配记录')).toBeInTheDocument()
    await act(async () => pending.resolve({ items: [] }))
    expect(await screen.findByText('暂无 CNAME 分配记录')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('CNAME 分配服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw backend detail')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText(allocation.hostname)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('无权查看 CNAME 分配权威')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw IAM detail')
  })

  it('paginates, opens strict detail, and diagnoses with canonical filters', async () => {
    authenticate()
    const next = { ...allocation, id: '77777777-7777-4777-8777-777777777777', hostname: 'next.example.com' }
    const listSpy = vi.spyOn(cnameAllocationsApi, 'list').mockImplementation(async (_token, _audience, params) => (
      params?.cursor ? { items: [next] } : { items: [allocation], next_cursor: allocation.id }
    ))
    vi.spyOn(cnameAllocationsApi, 'get').mockResolvedValue(allocation)
    const diagnoseSpy = vi.spyOn(cnameAllocationsApi, 'diagnose').mockResolvedValue(diagnosis)
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText(allocation.hostname)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByText(allocation.job_id)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText(next.hostname)).toBeInTheDocument()
    expect(listSpy.mock.calls.at(-1)?.[2]).toEqual({ limit: 20, cursor: allocation.id })

    await user.type(screen.getByRole('textbox', { name: '站点 ID' }), allocation.owner_id)
    await user.type(screen.getByRole('textbox', { name: '域名' }), allocation.domain)
    await user.type(screen.getByRole('textbox', { name: '主机名' }), allocation.hostname)
    await user.click(screen.getByRole('button', { name: '诊断' }))
    await waitFor(() => expect(diagnoseSpy).toHaveBeenCalledWith('cname-token', { kind: 'tenant' }, {
      siteID: allocation.owner_id, domain: allocation.domain, hostname: allocation.hostname,
    }))
    expect(await screen.findByText('可用')).toBeInTheDocument()
    expect(screen.getByText('分配权威已就绪')).toBeInTheDocument()
  })

  it('keeps token-free cache and pagination on refresh, then isolates a new session and late response', async () => {
    const actorA = authenticate(tenantActor(), 'old-token')
    const pending = deferred<{ items: CnameAllocation[] }>()
    let calls = 0
    const listSpy = vi.spyOn(cnameAllocationsApi, 'list').mockImplementation(async () => {
      calls += 1
      if (calls === 1) return { items: [allocation], next_cursor: allocation.id }
      if (calls === 2) return { items: [{ ...allocation, hostname: 'page-two.example.com' }] }
      if (calls === 3) return pending.promise
      return { items: [] }
    })
    const user = userEvent.setup()
    const { queryClient } = renderPage()
    expect(await screen.findByText(allocation.hostname)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('page-two.example.com')).toBeInTheDocument()
    const epoch = useSessionStore.getState().sessionEpoch
    await act(async () => {
      authenticate(actorA, 'new-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(listSpy).toHaveBeenCalledTimes(2)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toMatch(/old-token|new-token/)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(3))
    expect(listSpy.mock.calls.at(-1)?.[0]).toBe('new-token')

    const actorB = tenantActor({ user_id: '88888888-8888-4888-8888-888888888888' })
    await act(async () => {
      authenticate(actorB, 'session-b-token')
      await Promise.resolve()
    })
    expect(await screen.findByText('暂无 CNAME 分配记录')).toBeInTheDocument()
    await act(async () => pending.resolve({ items: [{ ...allocation, hostname: 'late-secret.example.com' }] }))
    expect(screen.queryByText('late-secret.example.com')).not.toBeInTheDocument()
    const finalKeys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(finalKeys).not.toContain(actorA.user_id)
    expect(finalKeys).toContain(actorB.user_id)
  })
})
