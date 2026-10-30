import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import type { CertificateOrderStatusItem } from '../api/certificateOrderStatus'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import CertificateOrdersPage from '../pages/CertificateOrdersPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const scopeID = '22222222-2222-4222-8222-222222222222'
const activeOrder: CertificateOrderStatusItem = {
  id: '33333333-3333-4333-8333-333333333333',
  scope_id: scopeID,
  domains: ['example.com', 'www.example.com'],
  challenge_type: 'http-01',
  status: 'active',
  auto_renew: true,
  not_after: '2027-08-07T10:00:00Z',
  issued_asset_id: '66666666-6666-4666-8666-666666666666',
  issued_version_id: '77777777-7777-4777-8777-777777777777',
  issued_at: '2026-08-07T10:00:00Z',
  version: 3,
  created_at: '2026-08-07T09:00:00Z',
  updated_at: '2026-08-07T10:00:00Z',
}
const renewalOrder: CertificateOrderStatusItem = {
  ...activeOrder,
  id: '44444444-4444-4444-8444-444444444444',
  domains: ['renew.example.net'],
  challenge_type: 'dns-01',
  status: 'failed',
  auto_renew: false,
  renewal_of_order_id: activeOrder.id,
  not_after: undefined,
  issued_asset_id: undefined,
  issued_version_id: undefined,
  issued_at: undefined,
  failure_code: 'dns_propagation_timeout',
  version: 2,
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function authenticate({
  token = 'certificate-order-token',
  permissions = ['certificates.read'],
  update = 'new',
  actor = principal({ permissions: ['certificates.read'] }),
}: {
  token?: string
  permissions?: string[]
  update?: 'new' | 'refresh'
  actor?: ReturnType<typeof principal>
} = {}) {
  const nextActor = { ...actor, permissions }
  useSessionStore.getState().setSession(
    { ...authResponse(nextActor), access_token: token },
    nextActor,
    update,
  )
  return nextActor
}

function renderWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/site/cert/orders']}><CertificateOrdersPage /></MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function deferredResponse() {
  let resolve!: (value: Response) => void
  const promise = new Promise<Response>((done) => { resolve = done })
  return { promise, resolve }
}

describe('CertificateOrdersPage', () => {
  it.each([
    ['anonymous', null],
    ['platform principal', principal({ scope_kind: 'platform', scope_id: 'platform', tenant_id: null, permissions: ['certificates.read'] })],
    ['malformed tenant', principal({ tenant_id: null, permissions: ['certificates.read'] })],
    ['missing permission', principal({ permissions: [] })],
  ])('fails closed with local 403 and zero requests for %s', async (_label, actor) => {
    if (actor) authenticate({ actor, permissions: actor.permissions })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])

    expect(await screen.findByText('无权查看证书订单')).toBeInTheDocument()
    expect(screen.getByText('当前账户缺少证书读取权限。')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('renders strict order and renewal metadata and filters by domain and status without a fake renew action', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [activeOrder, renewalOrder] }))
    const user = userEvent.setup()
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])

    expect(await screen.findByRole('heading', { name: '证书订单与续期状态' })).toBeInTheDocument()
    expect(await screen.findByText('example.com, www.example.com')).toBeInTheDocument()
    expect(screen.getByText('renew.example.net')).toBeInTheDocument()
    expect(screen.getByText('续期订单')).toBeInTheDocument()
    expect(screen.getByText(activeOrder.id)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /续期|renew/i })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('域名'), 'renew.example')
    expect(screen.queryByText('example.com, www.example.com')).not.toBeInTheDocument()
    expect(screen.getByText('renew.example.net')).toBeInTheDocument()
    await user.selectOptions(screen.getByLabelText('状态'), 'active')
    expect(await screen.findByText('暂无符合条件的证书订单')).toBeInTheDocument()
  })

  // FX10: every backend failure code is readable, and an order still retrying
  // shows why instead of an empty failure column.
  it('shows backend failure codes and the retry reason of in-progress orders', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [
      { ...renewalOrder, failure_code: 'acme_authorization_invalid' },
      { ...activeOrder, id: '55555555-5555-4555-8555-555555555555', domains: ['retry.example.net'], status: 'validating',
        not_after: undefined, issued_asset_id: undefined, issued_version_id: undefined, issued_at: undefined,
        retry_error_code: 'acme_challenge_propagation_failed' },
    ] }))
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByText('证书签发机构验证域名失败')).toBeInTheDocument()
    expect(screen.getByText('重试中：验证 TXT 记录尚未在权威 DNS 全部生效')).toBeInTheDocument()
    expect(screen.queryByText(/acme_/)).not.toBeInTheDocument()
  })

  // 独立申请记录页同样显示 CA 原因。
  it('shows the CA reason after the failure category', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [
      { ...renewalOrder, failure_code: 'acme_order_rejected', failure_reason: 'DNS problem: NXDOMAIN looking up A for a.example.net' },
    ] }))
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByText('DNS problem: NXDOMAIN looking up A for a.example.net')).toBeInTheDocument()
  })

  it('rejects an oversized or control-character CA reason as an invalid response', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [
      { ...renewalOrder, failure_code: 'acme_order_rejected', failure_reason: 'x'.repeat(513) },
    ] }))
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByText('服务返回了无效的证书订单数据。')).toBeInTheDocument()
    expect(screen.queryByText('x'.repeat(513))).not.toBeInTheDocument()
  })

  it('shows localized loading and empty states', async () => {
    authenticate()
    const pending = deferredResponse()
    vi.spyOn(globalThis, 'fetch').mockReturnValue(pending.promise)
    const first = renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])

    expect(await screen.findByLabelText('正在加载证书订单')).toBeInTheDocument()
    first.unmount()

    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByText('暂无证书订单')).toBeInTheDocument()
  })

  it('maps stable errors without exposing raw server messages and recovers with retry', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        error: { code: 'certificate_order_unavailable', message: 'acme.internal secret account' },
      }, 503))
      .mockResolvedValueOnce(json({ items: [activeOrder] }))
    const user = userEvent.setup()
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])

    expect(await screen.findByText('证书签发服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByText(/acme\.internal/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('example.com, www.example.com')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('renders remote 403 as terminal forbidden and rejects a cross-tenant response', async () => {
    authenticate()
    const firstFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'permission_denied', message: 'internal role name' },
    }, 403))
    const first = renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByText('无权查看证书订单')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重试' })).not.toBeInTheDocument()
    first.unmount()
    firstFetch.mockRestore()

    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{
      ...activeOrder,
      scope_id: '88888888-8888-4888-8888-888888888888',
    }] }))
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByText('服务返回了无效的证书订单数据。')).toBeInTheDocument()
  })

  it('keeps filters and token-free cache identity stable across same-epoch token refresh', async () => {
    const actor = authenticate({ token: 'old-order-token' })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [activeOrder, renewalOrder] }))
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)
    await screen.findByText('renew.example.net')
    await user.type(screen.getByLabelText('域名'), 'renew')
    const epoch = useSessionStore.getState().sessionEpoch
    const calls = fetchSpy.mock.calls.length

    await act(async () => {
      authenticate({ token: 'new-order-token', actor, update: 'refresh' })
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(fetchSpy).toHaveBeenCalledTimes(calls)
    expect(screen.getByLabelText('域名')).toHaveValue('renew')
    const keys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(keys).toContainEqual([
      'certificate-order-status', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, epoch,
    ])
    for (const key of keys) {
      expect(JSON.stringify(key)).not.toMatch(/old-order-token|new-order-token/)
    }
  })

  it('clears old-owner cache/state and ignores delayed responses after a new session', async () => {
    const actorA = authenticate({ token: 'session-a-token' })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const first = deferredResponse()
    const second = deferredResponse()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise)
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)
    expect(await screen.findByLabelText('正在加载证书订单')).toBeInTheDocument()
    await user.type(screen.getByLabelText('域名'), 'old-filter')
    const epochA = useSessionStore.getState().sessionEpoch

    const actorB = principal({
      user_id: '99999999-9999-4999-8999-999999999999',
      scope_id: '88888888-8888-4888-8888-888888888888',
      tenant_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['certificates.read'],
    })
    await act(async () => { authenticate({ token: 'session-b-token', actor: actorB }) })
    expect(screen.getByLabelText('域名')).toHaveValue('')
    await act(async () => second.resolve(json({ items: [{
      ...activeOrder,
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      scope_id: actorB.scope_id,
      domains: ['new-owner.example'],
    }] })))
    expect(await screen.findByText('new-owner.example')).toBeInTheDocument()

    await act(async () => first.resolve(json({ items: [{ ...activeOrder, domains: ['stale-owner.example'] }] })))
    expect(screen.queryByText('stale-owner.example')).not.toBeInTheDocument()
    await waitFor(() => {
      const oldPrefix = ['certificate-order-status', actorA.scope_kind, actorA.scope_id, actorA.tenant_id, actorA.user_id, epochA]
      expect(queryClient.getQueryCache().find({ queryKey: oldPrefix, exact: true })).toBeUndefined()
    })
    expect(fetchSpy.mock.calls.map(([, init]) => new Headers(init?.headers).get('Authorization')))
      .toEqual(['Bearer session-a-token', 'Bearer session-b-token'])
  })

  it('renders complete English and pseudo-locale surfaces', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    await changeLocale('en-US')
    const english = renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByRole('heading', { name: 'Certificate orders and renewal status' })).toBeInTheDocument()
    expect(await screen.findByText('No certificate orders')).toBeInTheDocument()
    english.unmount()

    authenticate()
    await changeLocale('qps-ploc')
    renderWithProviders(<CertificateOrdersPage />, ['/site/cert/orders'])
    expect(await screen.findByRole('heading', { name: '［证~书~订~单~与~续~期~状~态~］' })).toBeInTheDocument()
  })
})
