import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { type QueryClient, useQueryClient } from '@tanstack/react-query'
import { Route, Routes, useNavigate } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import { cachePoliciesApi, type CachePolicyView } from '../api/cachePolicies'
import { originRoutingApi, ORIGIN_ROUTING_SCHEMA } from '../api/siteOriginRouting'
import type { SiteDetail } from '../api/sites'
import { useSessionStore, type SessionUpdate } from '../auth/session'
import i18n from '../i18n'
import '../i18n/cachePolicy'
import '../i18n/siteOriginRouting'
// 页签懒加载（site-tab-stuck）后 SiteProtectionTabs 不再被静态导入，断言用的文案资源要自己注册。
import '../i18n/siteProtection'
import '../i18n/sitePolicy'
import SiteEditPage from '../pages/SiteEditPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// The origin status card has its own request; keep it out of the fetch
// sequences these tests mock.
vi.mock('../api/siteOriginStatus', () => ({
  siteOriginStatusApi: { get: vi.fn(() => new Promise(() => {})), failback: vi.fn() },
}))
// So does the basic tab's group select (SitePackageGroupSelects).
vi.mock('../api/siteGroups', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/siteGroups')>()
  return { ...actual, siteGroupsApi: { ...actual.siteGroupsApi, list: vi.fn(() => new Promise(() => {})) } }
})

const detail: SiteDetail = {
  id: 'site-1',
  version: 1,
  owner: { id: 'tenant-1', display_name: 'jason' },
  created_at: '2026-07-21T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  origin_pool: {
    origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
    balance_method: 'round_robin',
    failover_tries: 1,
    connect_timeout_ms: 3000,
    read_timeout_ms: 30000,
  },
  basic: {
    package_id: 'package-1',
    package_name: '基础套餐',
    group_id: 'group-1',
    group_name: '默认分组',
    domains: ['www.example.com'],
    http_enabled: true,
    http_listen_ports: ['80'],
    https_listen_ports: ['443'],
    ipv6_enabled: false,
    tls_protocols: ['TLSv1.2', 'TLSv1.3'],
    origins: ['192.0.2.10:80'],
    cname: 'edge.example.net',
    https_enabled: true,
    enabled: true,
    status: 'active',
    sync_status: 'synced',
    is_default: false,
  },
}

const tenantAID = '22222222-2222-4222-8222-222222222222'
const tenantBID = '44444444-4444-4444-8444-444444444444'
const tenantAUserID = '11111111-1111-4111-8111-111111111111'
const tenantBUserID = '33333333-3333-4333-8333-333333333333'

function stableOriginRetryKey(
  scopeKind: 'tenant' | 'platform',
  scopeID: string,
  tenantID: string | null,
  userID: string,
  siteID: string,
): string {
  return `cdnca:site-origin-retry:v1:${[
    scopeKind,
    scopeID,
    tenantID ?? 'null',
    userID,
    siteID,
  ].map(encodeURIComponent).join(':')}`
}

const originRetryKey = stableOriginRetryKey(
  'tenant', tenantAID, tenantAID, tenantAUserID, 'site-1',
)

beforeEach(async () => {
  sessionStorage.clear()
  await i18n.changeLanguage('zh-CN')
})

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function authenticate(
  role: 'admin' | 'user' = 'user',
  permissions = ['sites.read', 'sites.manage'],
) {
  return setSiteSession({ kind: role === 'admin' ? 'platform' : 'tenant', permissions }).actor
}

function setSiteSession(options: {
  kind?: 'tenant' | 'platform'
  scopeID?: string
  tenantID?: string | null
  userID?: string
  permissions?: string[]
  accessToken?: string
  update?: SessionUpdate
} = {}) {
  const kind = options.kind ?? 'tenant'
  const scopeID = options.scopeID ?? tenantAID
  const actor = principal({
    scope_kind: kind,
    scope_id: scopeID,
    tenant_id: options.tenantID === undefined ? (kind === 'tenant' ? scopeID : null) : options.tenantID,
    user_id: options.userID ?? tenantAUserID,
    username: kind === 'platform' ? 'admin' : 'tenant-user',
    display_name: kind === 'platform' ? 'admin' : 'tenant-user',
    roles: kind === 'platform' ? ['platform_admin'] : ['tenant_user'],
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

function QueryClientCapture({ capture }: { capture: (queryClient: QueryClient) => void }) {
  capture(useQueryClient())
  return null
}

const SHARED = i18n.t('sites:edit.basic.aria.cacheShared')
// The saved site of a basic PATCH: the server echoes the saved basic configuration.
function savedBasic(body: { expected_version: number; changes: SiteDetail['basic'] }): SiteDetail {
  return { ...detail, version: body.expected_version + 1, basic: { ...detail.basic, ...body.changes } }
}

// 没有保存按钮。改动即保存；键入类字段在失焦时保存（这里让当前焦点失焦）。
async function commitEdits() {
  await act(async () => { (document.activeElement as HTMLElement | null)?.blur() })
}

function renderEdit(path = '/site/site-1/edit') {
  let queryClient: QueryClient | undefined
  const result = renderWithProviders(
    <>
      <QueryClientCapture capture={(client) => { queryClient = client }} />
      <Routes>
        <Route path="/site/:id/edit" element={<SiteEditPage />} />
        <Route path="/site/list" element={<div>网站列表占位</div>} />
      </Routes>
    </>,
    [path],
  )
  if (!queryClient) throw new Error('query client was not captured')
  return { ...result, queryClient }
}

function SwitchableSiteEdit() {
  const navigate = useNavigate()
  return (
    <>
      <button type="button" onClick={() => navigate('/site/site-2/edit')}>switch test site</button>
      <SiteEditPage />
    </>
  )
}

function renderSwitchableEdit() {
  return renderWithProviders(
    <Routes>
      <Route path="/site/:id/edit" element={<SwitchableSiteEdit />} />
      <Route path="/site/list" element={<div>网站列表占位</div>} />
    </Routes>,
    ['/site/site-1/edit'],
  )
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

function authorization(init?: RequestInit): string {
  return (init?.headers as Record<string, string> | undefined)?.Authorization ?? ''
}

function storedOriginAttempt(siteID = 'site-1') {
  return {
    version: 1,
    siteId: siteID,
    idempotencyKey: `site-origin-${siteID}-stable-key`,
    serializedBody: JSON.stringify({
      expected_version: detail.version,
      section: 'origin',
      changes: detail.origin_pool,
    }),
  }
}

async function loadBasic(role: 'admin' | 'user' = 'user') {
  authenticate(role)
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
  renderEdit()
  expect(await screen.findByRole('heading', { name: 'www.example.com' })).toBeInTheDocument()
  await screen.findByLabelText('域名')
}

describe('SiteEditPage states', () => {
  it('keeps a stable loading panel and handles an empty response', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise<Response>(() => undefined))
    const { unmount } = renderEdit()
    expect(screen.getByLabelText('网站详情加载中')).toBeInTheDocument()
    unmount()

    vi.restoreAllMocks()
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
    renderEdit()
    expect(await screen.findByText('暂无网站详情')).toBeInTheDocument()
  })

  it.each([
    [403, 'permission_denied', '无权查看网站详情'],
    [404, 'site_not_found', '网站不存在'],
    [503, 'unavailable', '网站详情加载失败'],
  ])('renders %i as a distinct persistent state', async (status, code, title) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ error: { code, message: `error-${status}`, request_id: 'request-1' } }, status),
    )
    renderEdit()

    expect(await screen.findByText(title)).toBeInTheDocument()
    expect(screen.queryByText(`error-${status}`)).not.toBeInTheDocument()
  })
})

describe('SiteEditPage basic configuration', () => {
  it('renders the observed basic sections, annotations, and real configuration controls', async () => {
    await loadBasic('admin')

    for (const heading of ['基础设置', '访问域名', '访问设置', '源站列表', '回源规则']) {
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument()
    }
    expect(screen.getByText('支持空格、换行或逗号批量粘贴，中文域名会自动转为 Punycode。')).toBeInTheDocument()
    expect(screen.getByText('HTTP 已开启 · 监听 80')).toBeInTheDocument()
    expect(screen.getByText('HTTPS 已开启 · 监听 443')).toBeInTheDocument()
    expect(screen.getByText('协议、回源域名和超时在回源设置中配置。')).toBeInTheDocument()
    // 条件源站/健康检查 sit side by side in 回源规则, their help behind (?)
    expect(screen.getByRole('img', { name: '在回源设置的“高级：条件回源”中配置。' })).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '检测异常并自动切换。' })).toBeInTheDocument()
    // tp-b3a: origin forwarding / keepalive moved to 回源设置.
    for (const moved of ['回源 Keepalive', '回源协议', 'WebSocket', '可信代理']) {
      expect(screen.queryByRole('switch', { name: moved })).not.toBeInTheDocument()
      expect(screen.queryByRole('combobox', { name: moved })).not.toBeInTheDocument()
    }
    expect(screen.queryByRole('heading', { name: '回源转发' })).not.toBeInTheDocument()
    // 负载方式 is cards with their use case, no select and no line below it.
    expect(screen.getByRole('radio', { name: '轮询' })).toBeChecked()
    expect(screen.getByText('按权重轮流，最通用')).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '源站负载方式' })).not.toBeInTheDocument()
    expect(screen.getByText('新增源站')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '批量编辑访问域名' })).toBeEnabled()
    expect(screen.queryByText('CNAME 模式')).not.toBeInTheDocument()
    expect(screen.queryByText('套餐所有者')).not.toBeInTheDocument()
  })

  it('adds an access domain through the compact domain editor', async () => {
    await loadBasic()
    const user = userEvent.setup()

    await user.type(screen.getByRole('textbox', { name: '新增访问域名' }), 'api.example.com')
    await user.click(screen.getByRole('button', { name: '添加访问域名' }))

    expect(screen.getByLabelText('域名')).toHaveValue('api.example.com www.example.com')
  })

  it('persists source health switching through the existing origin failover contract', async () => {
    authenticate()
    const twoOrigins: SiteDetail = {
      ...detail,
      origin_pool: {
        ...detail.origin_pool,
        origins: [
          detail.origin_pool.origins[0]!,
          { host: '192.0.2.11', port: 80, weight: 1, enabled: true },
        ],
      },
    }
    const saved: SiteDetail = {
      ...twoOrigins,
      version: 2,
      origin_pool: { ...twoOrigins.origin_pool, failover_tries: 2 },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(twoOrigins))
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    await user.click(screen.getByRole('switch', { name: '健康检查' }))
    await commitEdits()

    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patchCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    const body = JSON.parse(String(patchCall?.[1]?.body)) as {
      section: string
      changes: { failover_tries: number }
    }
    expect(body.section).toBe('origin')
    expect(body.changes.failover_tries).toBe(2)
  })
})

describe('SiteEditPage tp-b3a field moves keep the save contract', () => {
  type OriginPatch = { section: string; expected_version: number; changes: SiteDetail['origin_pool'] }
  type BasicPatch = { section: string; changes: SiteDetail['basic'] }

  // Each case edits one moved field on its new tab, saves once through the
  // unchanged PATCH (section=origin), and checks the saved response is what
  // the tab shows again.
  const originCases: Array<{
    name: string
    edit: (user: ReturnType<typeof userEvent.setup>) => Promise<void>
    expected: Partial<SiteDetail['origin_pool']>
    readBack: () => void
  }> = [
    {
      name: '回源协议 HTTPS',
      edit: async (user) => { await user.click(screen.getByRole('radio', { name: /^HTTPS 使用 HTTPS/u })) },
      expected: { scheme: 'https', https_port: 443 },
      readBack: () => expect(screen.getByRole('radio', { name: /^HTTPS 使用 HTTPS/u })).toBeChecked(),
    },
    {
      name: '固定 Host',
      edit: async (user) => {
        await user.click(screen.getByRole('radio', { name: /固定 Host/u }))
        await user.type(screen.getByLabelText('自定义 Host'), 'origin.example.com')
      },
      expected: { request_host: { mode: 'custom', value: 'origin.example.com' } },
      readBack: () => expect(screen.getByLabelText('自定义 Host')).toHaveValue('origin.example.com'),
    },
    {
      name: '回源超时 / 连接超时',
      edit: async () => {
        fireEvent.change(screen.getByRole('spinbutton', { name: '回源超时' }), { target: { value: '60' } })
        fireEvent.change(screen.getByRole('spinbutton', { name: '连接超时' }), { target: { value: '10' } })
      },
      expected: { read_timeout_ms: 60_000, connect_timeout_ms: 10_000 },
      readBack: () => {
        expect(screen.getByRole('spinbutton', { name: '回源超时' })).toHaveValue('60')
        expect(screen.getByRole('spinbutton', { name: '连接超时' })).toHaveValue('10')
      },
    },
    {
      name: 'Keepalive 空闲超时',
      edit: async () => { fireEvent.change(screen.getByRole('spinbutton', { name: '空闲超时' }), { target: { value: '50' } }) },
      expected: { keepalive_enabled: true, keepalive_idle_timeout_ms: 50_000 },
      readBack: () => expect(screen.getByRole('spinbutton', { name: '空闲超时' })).toHaveValue('50'),
    },
    {
      name: 'Keepalive 关闭',
      edit: async (user) => { await user.click(screen.getByRole('switch', { name: '回源 Keepalive' })) },
      expected: { keepalive_enabled: false },
      readBack: () => expect(screen.getByRole('switch', { name: '回源 Keepalive' })).not.toBeChecked(),
    },
    // tp-b3a-be：回源端口跟随并入第 4 项"跟随协议和端口"
    {
      name: '跟随协议和端口',
      edit: async (user) => { await user.click(screen.getByRole('radio', { name: /^跟随协议和端口/u })) },
      expected: { scheme: 'follow', follow_port: true, http_port: 80, https_port: 443 },
      readBack: () => expect(screen.getByRole('radio', { name: /^跟随协议和端口/u })).toBeChecked(),
    },
    {
      name: 'HTTP 回源端口',
      edit: async () => { fireEvent.change(screen.getByRole('spinbutton', { name: 'HTTP 回源端口' }), { target: { value: '8080' } }) },
      expected: { http_port: 8080 },
      readBack: () => expect(screen.getByRole('spinbutton', { name: 'HTTP 回源端口' })).toHaveValue('8080'),
    },
    {
      name: '访问域名+端口',
      edit: async (user) => { await user.click(screen.getByRole('radio', { name: /^访问域名\+端口/u })) },
      expected: { request_host: { mode: 'visitor_port', value: '' } },
      readBack: () => expect(screen.getByRole('radio', { name: /^访问域名\+端口/u })).toBeChecked(),
    },
    {
      name: '回源鉴权开关',
      edit: async (user) => { await user.click(screen.getByRole('switch', { name: '回源鉴权开关' })) },
      expected: { origin_auth_enabled: false },
      readBack: () => expect(screen.getByRole('switch', { name: '回源鉴权开关' })).not.toBeChecked(),
    },
    {
      name: '跟随源站跳转',
      edit: async (user) => { await user.click(screen.getByRole('switch', { name: '跟随源站跳转' })) },
      expected: { follow_redirect: { enabled: true, max_hops: 3, cross_origin: false } },
      readBack: () => expect(screen.getByRole('switch', { name: '跟随源站跳转' })).toBeChecked(),
    },
    {
      name: '可信代理',
      edit: async () => { fireEvent.change(screen.getByLabelText('可信代理'), { target: { value: '10.0.0.0/8' } }) },
      expected: { trusted_proxy_cidrs: ['10.0.0.0/8'] },
      readBack: () => expect(screen.getByLabelText('可信代理')).toHaveValue('10.0.0.0/8'),
    },
  ]

  it.each(originCases)('回源设置 saves $name through PATCH section=origin and reads it back', async ({ edit, expected, readBack }) => {
    authenticate()
    let saved: SiteDetail | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input instanceof Request ? input.url : input)
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as OriginPatch
        saved = { ...detail, version: body.expected_version + 1, origin_pool: body.changes }
        return Promise.resolve(jsonResponse(saved))
      }
      if (url.includes('/origin-routing')) return new Promise<Response>(() => undefined)
      return Promise.resolve(jsonResponse(saved ?? detail))
    })
    const user = userEvent.setup()
    renderEdit('/site/site-1/edit?tab=origin')
    await screen.findByRole('heading', { name: '回源协议与端口' })

    await edit(user)
    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()

    // A radio choice saves at once and the typed value after it (e.g. 固定 Host + its name): the last PATCH holds the field.
    await waitFor(() => expect(saved?.origin_pool).toMatchObject(expected))
    const patches = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(patches.length).toBeGreaterThanOrEqual(1)
    const body = JSON.parse(String(patches.at(-1)![1]!.body)) as OriginPatch
    expect(body.section).toBe('origin')
    // every save uses the version the previous one returned
    expect(patches.map(([, init]) => (JSON.parse(String(init!.body)) as OriginPatch).expected_version)).toEqual(patches.map((_, index) => 1 + index))
    expect(body.changes).toEqual({ ...detail.origin_pool, ...body.changes })
    expect(body.changes).toMatchObject(expected)
    // origins and balance stay as they were
    expect(body.changes.origins).toEqual(detail.origin_pool.origins)
    expect(body.changes.balance_method).toBe(detail.origin_pool.balance_method)
    readBack()
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
  })

  // WebSocket 只在高级设置 → 性能与协议，回源设置不再重复。
  it('WebSocket is only on 高级设置 and saves through PATCH section=origin', async () => {
    authenticate()
    let saved: SiteDetail | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input instanceof Request ? input.url : input)
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as OriginPatch
        saved = { ...detail, version: 2, origin_pool: body.changes }
        return Promise.resolve(jsonResponse(saved))
      }
      if (url.includes('/origin-routing')) return new Promise<Response>(() => undefined)
      return Promise.resolve(jsonResponse(saved ?? siteCardResponse(input)))
    })
    const user = userEvent.setup()
    const { unmount } = renderEdit('/site/site-1/edit?tab=origin')
    await screen.findByRole('heading', { name: '回源协议与端口' })
    expect(screen.queryByRole('switch', { name: 'WebSocket' })).not.toBeInTheDocument()
    unmount()

    renderEdit('/site/site-1/edit?tab=advanced')
    await user.click(await screen.findByRole('switch', { name: 'WebSocket' }))
    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patches = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(patches).toHaveLength(1)
    const body = JSON.parse(String(patches[0]![1]!.body)) as OriginPatch
    expect(body.section).toBe('origin')
    expect(body.changes).toMatchObject({ websocket: { enabled: false, allowed_origins: [] } })
    expect(screen.getByRole('switch', { name: 'WebSocket' })).not.toBeChecked()
  })

  it('基本配置 saves IPv6 from the HTTP entry card through PATCH section=basic and reads it back', async () => {
    authenticate()
    let saved: SiteDetail | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as BasicPatch
        saved = { ...detail, version: 2, basic: body.changes, listener_state: { ...detail.listener_state, ipv6_desired_enabled: body.changes.ipv6_enabled } }
        return Promise.resolve(jsonResponse(saved))
      }
      return Promise.resolve(jsonResponse(saved ?? detail))
    })
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    await user.click(screen.getByRole('switch', { name: 'IPv6开关' }))
    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    const body = JSON.parse(String(patch?.[1]?.body)) as BasicPatch
    expect(body.section).toBe('basic')
    // PJ-C02：sync_status 只读，写请求里去掉；社区版不绑定套餐，套餐字段也不发送。
    const { sync_status: _derived, package_id: _packageID, package_subscription_id: _subscriptionID, package_name: _packageName, ...writable } = detail.basic
    expect(body.changes).toMatchObject({ ...writable, ipv6_enabled: true })
    for (const key of ['sync_status', 'package_id', 'package_subscription_id', 'package_name']) expect(body.changes).not.toHaveProperty(key)
    expect(screen.getByRole('switch', { name: 'IPv6开关' })).toBeChecked()
  })

  // tp-b3a-be：新增源站默认用回源设置里的 HTTP 回源端口，保存时带 port_inherited
  it('基本配置 adds an origin on the pool origin port', async () => {
    authenticate()
    const pool = { ...detail.origin_pool, http_port: 8080 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as OriginPatch
        return Promise.resolve(jsonResponse({ ...detail, version: 2, origin_pool: body.changes }))
      }
      return Promise.resolve(jsonResponse({ ...detail, origin_pool: pool }))
    })
    const user = userEvent.setup()
    renderEdit()
    await user.click(await screen.findByRole('button', { name: '新增源站信息' }))
    const dialog = await screen.findByRole('dialog', { name: '新增源站' })
    expect(within(dialog).getByRole('switch', { name: '使用回源端口' })).toBeChecked()
    expect(within(dialog).getByRole('spinbutton', { name: '源站端口' })).toBeDisabled()
    expect(within(dialog).getByRole('spinbutton', { name: '源站端口' })).toHaveValue('8080')
    await user.type(within(dialog).getByLabelText('源地址'), '192.0.2.20')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/u }))
    await commitEdits()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')!
    const body = JSON.parse(String(patch[1]!.body)) as OriginPatch
    expect(body.changes.origins.at(-1)).toMatchObject({ host: '192.0.2.20', port: 8080, port_inherited: true })
  })

  // 保存即自动下发，标题旁显示下发状态；同步中时每 5 秒重读直到结束。
  // 10-27 用户：打开时已同步，改动保存后应立刻显示待同步倒计时，不用刷新页面。
  it('shows pending sync right after an instant save and reads the result after the countdown', async () => {
    authenticate()
    let saved: SiteDetail | undefined
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input instanceof Request ? input.url : input)
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as OriginPatch
        saved = { ...detail, version: 2, basic: { ...detail.basic, sync_status: 'synced' }, origin_pool: body.changes }
        return Promise.resolve(jsonResponse(saved))
      }
      if (url.includes('/origin-routing')) return new Promise<Response>(() => undefined)
      if (saved && new URL(url, 'https://cdnca.test').pathname === '/v1/sites/site-1') {
        reads += 1
        return Promise.resolve(jsonResponse({ ...saved, basic: { ...saved.basic, sync_status: 'synced' } }))
      }
      return Promise.resolve(jsonResponse(saved ?? siteCardResponse(input)))
    })
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
      renderEdit('/site/site-1/edit?tab=advanced')
      await user.click(await screen.findByRole('switch', { name: 'WebSocket' }))
      await commitEdits()
      await waitFor(() => expect(screen.getByTestId('site-edit-sync-status')).toHaveTextContent('待同步 · 5秒后刷新'))
      await act(async () => { await vi.advanceTimersByTimeAsync(5_100) })
      await waitFor(() => expect(screen.getByTestId('site-edit-sync-status')).toHaveTextContent('已同步'))
      expect(reads).toBeGreaterThanOrEqual(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('shows the delivery state of the saved configuration and polls it while syncing', async () => {
    authenticate()
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (new URL(String(input), 'https://cdnca.test').pathname !== '/v1/sites/site-1') return jsonResponse(detail)
      reads += 1
      return jsonResponse({ ...detail, basic: { ...detail.basic, sync_status: reads === 1 ? 'pending' : 'synced' } })
    })
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderEdit()
      // 10-27 用户：显示"待同步 · N秒后刷新"，默认 5 秒倒数，同步完成显示"已同步"。
      expect(await screen.findByTestId('site-edit-sync-status')).toHaveTextContent('待同步 · 5秒后刷新')
      await act(async () => { await vi.advanceTimersByTimeAsync(1_000) })
      expect(screen.getByTestId('site-edit-sync-status')).toHaveTextContent('待同步 · 4秒后刷新')
      await act(async () => { await vi.advanceTimersByTimeAsync(4_100) })
      await waitFor(() => expect(screen.getByTestId('site-edit-sync-status')).toHaveTextContent('已同步'))
      expect(reads).toBe(2)
      expect(screen.queryByRole('button', { name: /发布/ })).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  // 社区版：站点不绑定套餐，详情头不显示"暂不可用（无套餐）"。
  it('shows no package badge, whatever the package projection says', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => jsonResponse({ ...detail, package_unavailable_reason: 'no_package' }))
    renderEdit()
    expect(await screen.findByTestId('site-edit-sync-status')).toBeInTheDocument()
    expect(screen.queryByTestId('site-edit-package-unavailable')).not.toBeInTheDocument()
  })

  it('基本配置 shows the basic settings and links 条件源站 to the opened fold', async () => {
    await loadBasic()
    const user = userEvent.setup()
    const settings = screen.getByRole('heading', { name: '基础设置' }).closest('section')!
    const labels = [...settings.querySelectorAll('.site-basic-fact > span:first-child')].map((label) => label.textContent)
    expect(labels).toEqual(['状态', '创建时间', '更新时间', '网站分组', 'CNAME'])
    const rules = screen.getByRole('heading', { name: '回源规则' }).closest('section')!
    expect([...rules.querySelectorAll('.site-form-row-label > span:first-child')].map((label) => label.textContent))
      .toEqual(['负载方式', '条件源站', '健康检查'])
    await user.click(within(rules).getByRole('button', { name: '配置' }))
    await waitFor(() => expect(screen.getByRole('tab', { name: '回源设置' })).toHaveAttribute('aria-selected', 'true'))
    expect(await screen.findByRole('button', { name: /高级：条件回源/u })).toHaveAttribute('aria-expanded', 'true')
  })
})

describe('SiteEdit review closure authorization', () => {
  it.each([
    ['tenant missing read', { kind: 'tenant' as const, permissions: ['sites.manage'] }],
    ['tenant fake platform wildcard', { kind: 'tenant' as const, permissions: ['platform.admin'] }],
    ['platform missing read', { kind: 'platform' as const, permissions: [] }],
    ['malformed tenant lineage', {
      kind: 'tenant' as const, permissions: ['sites.read'], tenantID: null,
    }],
    ['platform principal carrying tenant lineage', {
      kind: 'platform' as const, permissions: ['platform.admin'], tenantID: tenantAID,
    }],
  ])('SiteEdit review closure rejects %s locally with zero fetch', async (_, actor) => {
    setSiteSession(actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))

    renderEdit()

    expect(await screen.findByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(i18n.t('sites:edit.errors.permission_denied'))).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each(['tenant', 'platform'] as const)(
    'SiteEdit review closure keeps a %s reader visible but all configuration writes disabled',
    async (kind) => {
      setSiteSession({ kind, permissions: ['sites.read'] })
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
      renderEdit()

      await screen.findByRole('heading', { name: 'www.example.com' })
      expect(screen.getByText('只读模式')).toBeInTheDocument()
      expect(screen.getByText('当前账号缺少网站管理权限，只能查看配置')).toBeInTheDocument()
      expect(await screen.findByLabelText('域名')).toBeDisabled()
      expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
      expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
      await commitEdits()
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
    },
  )

  it.each(['tenant', 'platform'] as const)(
    'SiteEdit review closure disables a recovered origin retry for a read-only %s principal',
    async (kind) => {
      const tenantID = kind === 'tenant' ? tenantAID : null
      sessionStorage.setItem(
        stableOriginRetryKey(kind, tenantAID, tenantID, tenantAUserID, 'site-1'),
        JSON.stringify(storedOriginAttempt()),
      )
      setSiteSession({ kind, tenantID, permissions: ['sites.read'] })
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
      renderEdit()

      await screen.findByRole('heading', { name: 'www.example.com' })
      expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeDisabled()
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
    },
  )

  it('SiteEdit review closure keeps the real platform.admin wildcard writable', async () => {
    setSiteSession({
      kind: 'platform', permissions: ['platform.admin'], accessToken: 'site-edit-platform-admin',
    })
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['platform-edit.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'platform-edit.example.com')
    await commitEdits()

    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(authorization(patch?.[1])).toBe('Bearer site-edit-platform-admin')
  })
})

describe('SiteEditPage owner lineage', () => {
  it('requests the same route for the new owner and clears parent drafts and lock state', async () => {
    authenticate()
    const detailA: SiteDetail = {
      ...detail,
      basic: { ...detail.basic, domains: ['a.example.com'] },
    }
    const detailB: SiteDetail = {
      ...detail,
      owner: { id: 'tenant-b', display_name: 'tenant-b' },
      basic: { ...detail.basic, domains: ['b.example.com'] },
      lock: {
        locked: true,
        reason: 'B tenant lock',
        locked_at: '2026-08-04T08:00:00Z',
        operator: { display_name: 'B operator' },
      },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization
      return Promise.resolve(jsonResponse(authorization === 'Bearer token-b' ? detailB : detailA))
    })
    const user = userEvent.setup()
    renderEdit()

    await screen.findByRole('heading', { name: 'a.example.com' })
    const domainA = await screen.findByLabelText('域名')
    await user.clear(domainA)
    await user.type(domainA, 'a-draft.example.com')
    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: '44444444-4444-4444-8444-444444444444',
      tenant_id: '44444444-4444-4444-8444-444444444444',
      permissions: ['sites.read', 'sites.manage'],
    })
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorB), access_token: 'token-b' },
      actorB,
    ))

    expect(await screen.findByRole('heading', { name: 'b.example.com' })).toBeInTheDocument()
    expect(screen.queryByText('a-draft.example.com')).not.toBeInTheDocument()
    expect(screen.getByText(/B tenant lock/)).toBeInTheDocument()
    expect(screen.getByText(/B operator/)).toBeInTheDocument()
    expect(await screen.findByLabelText('域名')).toHaveValue('b.example.com')
    expect(screen.getByLabelText('域名')).toBeDisabled()
    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/sites/site-1',
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer token-b' }),
      }),
    )
  })

  it('SiteEdit review closure ignores a late owner A detail after owner B has loaded on the same page instance', async () => {
    authenticate()
    const detailA: SiteDetail = {
      ...detail,
      basic: { ...detail.basic, domains: ['late-a.example.com'] },
      lock: {
        locked: true,
        reason: 'late A lock',
        locked_at: '2026-08-04T08:00:00Z',
        operator: { display_name: 'A operator' },
      },
    }
    const detailB: SiteDetail = {
      ...detail,
      owner: { id: 'tenant-b', display_name: 'tenant-b' },
      basic: { ...detail.basic, domains: ['b.example.com'] },
    }
    let resolveA!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization
      if (authorization === 'Bearer token-b') return Promise.resolve(jsonResponse(detailB))
      return new Promise<Response>((resolve) => { resolveA = resolve })
    })
    renderEdit()
    expect(screen.getByLabelText('网站详情加载中')).toBeInTheDocument()

    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: '44444444-4444-4444-8444-444444444444',
      tenant_id: '44444444-4444-4444-8444-444444444444',
      permissions: ['sites.read', 'sites.manage'],
    })
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorB), access_token: 'token-b' },
      actorB,
    ))

    expect(await screen.findByRole('heading', { name: 'b.example.com' })).toBeInTheDocument()
    await act(async () => resolveA(jsonResponse(detailA)))
    expect(screen.getByRole('heading', { name: 'b.example.com' })).toBeInTheDocument()
    expect(screen.queryByText('late-a.example.com')).not.toBeInTheDocument()
    expect(screen.queryByText('late A lock')).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('SiteEdit review closure ignores a late owner A detail error after owner B has loaded', async () => {
    setSiteSession({ accessToken: 'site-edit-detail-a' })
    const lateA = deferred<Response>()
    const detailB: SiteDetail = {
      ...detail,
      owner: { id: tenantBID, display_name: 'tenant-b' },
      basic: { ...detail.basic, domains: ['detail-b.example.com'] },
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      authorization(init) === 'Bearer site-edit-detail-b'
        ? Promise.resolve(jsonResponse(detailB))
        : lateA.promise,
    )
    renderEdit()

    act(() => {
      setSiteSession({
        scopeID: tenantBID,
        tenantID: tenantBID,
        userID: tenantBUserID,
        accessToken: 'site-edit-detail-b',
      })
    })
    expect(await screen.findByRole('heading', { name: 'detail-b.example.com' })).toBeInTheDocument()

    await act(async () => {
      lateA.resolve(jsonResponse({
        error: { code: 'unavailable', message: 'private late owner A detail error' },
      }, 503))
      await Promise.resolve()
    })
    expect(screen.getByRole('heading', { name: 'detail-b.example.com' })).toBeInTheDocument()
    expect(screen.queryByText('private late owner A detail error')).not.toBeInTheDocument()
    expect(screen.queryByText('网站详情加载失败')).not.toBeInTheDocument()
  })

  it.each(['success', 'error'] as const)(
    'SiteEdit review closure isolates a late owner A save %s from owner B',
    async (outcome) => {
      setSiteSession({ accessToken: 'site-edit-save-a' })
      const lateSave = deferred<Response>()
      const detailB: SiteDetail = {
        ...detail,
        owner: { id: tenantBID, display_name: 'tenant-b' },
        basic: { ...detail.basic, domains: ['save-b.example.com'] },
      }
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        const token = authorization(init)
        if (init?.method === 'PATCH' && token === 'Bearer site-edit-save-a') return lateSave.promise
        if (token === 'Bearer site-edit-save-b') return Promise.resolve(jsonResponse(detailB))
        if (!init?.method && token === 'Bearer site-edit-save-a') return Promise.resolve(jsonResponse(detail))
        return Promise.reject(new Error('unexpected late save request'))
      })
      const user = userEvent.setup()
      renderEdit()
      await screen.findByRole('heading', { name: 'www.example.com' })
      const domain = await screen.findByLabelText('域名')
      await user.clear(domain)
      await user.type(domain, 'late-save-a.example.com')
      await commitEdits()
      await waitFor(() =>
        expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1),
      )

      act(() => {
        setSiteSession({
          scopeID: tenantBID,
          tenantID: tenantBID,
          userID: tenantBUserID,
          accessToken: 'site-edit-save-b',
        })
      })
      expect(await screen.findByRole('heading', { name: 'save-b.example.com' })).toBeInTheDocument()
      await screen.findByLabelText('域名')

      await act(async () => {
        lateSave.resolve(outcome === 'success'
          ? jsonResponse({
              ...detail,
              version: 2,
              basic: { ...detail.basic, domains: ['late-save-a.example.com'] },
            })
          : jsonResponse({
              error: { code: 'unavailable', message: 'private late owner A save error' },
            }, 503))
        await Promise.resolve()
      })

      expect(screen.getByRole('heading', { name: 'save-b.example.com' })).toBeInTheDocument()
      expect(screen.getByLabelText('域名')).toHaveValue('save-b.example.com')
      expect(screen.queryByText('操作成功')).not.toBeInTheDocument()
      expect(screen.queryByText('private late owner A save error')).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(
        ([, init]) => init?.method === 'PATCH' && authorization(init) === 'Bearer site-edit-save-b',
      )).toHaveLength(0)
    },
  )

  it.each([
    ['404', () => jsonResponse({ error: { code: 'site_not_found', message: 'private B missing' } }, 404), '网站不存在'],
    ['null', () => new Response(null, { status: 204 }), '暂无网站详情'],
  ])('fails closed when owner B returns %s without retaining owner A detail', async (_, responseB, emptyTitle) => {
    authenticate()
    const detailA: SiteDetail = {
      ...detail,
      basic: { ...detail.basic, domains: ['a.example.com'] },
      lock: {
        locked: true,
        reason: 'A tenant lock',
        locked_at: '2026-08-04T08:00:00Z',
        operator: { display_name: 'A operator' },
      },
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization
      return Promise.resolve(authorization === 'Bearer token-b' ? responseB() : jsonResponse(detailA))
    })
    renderEdit()
    expect(await screen.findByRole('heading', { name: 'a.example.com' })).toBeInTheDocument()
    expect(screen.getByText(/A tenant lock/)).toBeInTheDocument()

    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: '44444444-4444-4444-8444-444444444444',
      tenant_id: '44444444-4444-4444-8444-444444444444',
      permissions: ['sites.read', 'sites.manage'],
    })
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorB), access_token: 'token-b' },
      actorB,
    ))

    expect(await screen.findByText(emptyTitle)).toBeInTheDocument()
    expect(screen.queryByText('a.example.com')).not.toBeInTheDocument()
    expect(screen.queryByText('A tenant lock')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('域名')).not.toBeInTheDocument()
    expect(screen.queryByText('private B missing')).not.toBeInTheDocument()
  })
})

describe('SiteEdit review closure session identity and live permissions', () => {
  it('uses full token-free owner keys and keeps them stable across a same-session token refresh', async () => {
    const session = setSiteSession({ accessToken: 'site-edit-key-token-a' })
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['keyed-save.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      init?.method === 'PATCH' ? Promise.resolve(jsonResponse(saved)) : Promise.resolve(jsonResponse(detail)),
    )
    const user = userEvent.setup()
    const { queryClient } = renderEdit()
    const detailKey = ['site-detail', session.owner, 'site-1'] as const
    const mutationKey = ['site-edit-save', session.owner, 'site-1'] as const

    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(queryClient.getQueryData(detailKey)).toEqual(detail)
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'keyed-save.example.com')

    act(() => {
      setSiteSession({ accessToken: 'site-edit-key-token-b', update: 'refresh' })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(queryClient.getQueryData(detailKey)).toEqual(detail)
    expect(screen.getByLabelText('域名')).toHaveValue('keyed-save.example.com')
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    expect(queryClient.getMutationCache().findAll({ mutationKey, exact: true })).toHaveLength(1)
    const serializedKeys = JSON.stringify([
      ...queryClient.getQueryCache().getAll().map((query) => query.queryKey),
      ...queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey),
    ])
    expect(serializedKeys).toContain(tenantAID)
    expect(serializedKeys).toContain(tenantAUserID)
    expect(serializedKeys).toContain(String(session.sessionEpoch))
    expect(serializedKeys).not.toContain('site-edit-key-token-a')
    expect(serializedKeys).not.toContain('site-edit-key-token-b')
    expect(authorization(fetchSpy.mock.calls[1][1])).toBe('Bearer site-edit-key-token-b')
  })

  it('removes old detail and save mutation caches when a late read crosses into a new session', async () => {
    const lateRead = deferred<Response>()
    const sessionA = setSiteSession({ accessToken: 'site-edit-cache-session-a' })
    const detailB = {
      ...detail,
      basic: { ...detail.basic, domains: ['cache-session-b.example.com'] },
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      authorization(init) === 'Bearer site-edit-cache-session-b'
        ? Promise.resolve(jsonResponse(detailB))
        : lateRead.promise,
    )
    const { queryClient } = renderEdit()
    const detailKeyA = ['site-detail', sessionA.owner, 'site-1'] as const
    const mutationKeyA = ['site-edit-save', sessionA.owner, 'site-1'] as const
    queryClient.getMutationCache().build(queryClient, {
      mutationKey: mutationKeyA,
      mutationFn: async () => undefined,
    })

    let sessionB!: ReturnType<typeof setSiteSession>
    act(() => {
      sessionB = setSiteSession({ accessToken: 'site-edit-cache-session-b' })
    })
    const detailKeyB = ['site-detail', sessionB.owner, 'site-1'] as const
    expect(await screen.findByRole('heading', { name: 'cache-session-b.example.com' })).toBeInTheDocument()
    expect(queryClient.getQueryState(detailKeyA)).toBeUndefined()
    expect(queryClient.getMutationCache().findAll({ mutationKey: mutationKeyA, exact: true })).toHaveLength(0)

    await act(async () => {
      lateRead.resolve(jsonResponse({
        ...detail,
        basic: { ...detail.basic, domains: ['late-cache-session-a.example.com'] },
      }))
      await Promise.resolve()
    })
    expect(queryClient.getQueryState(detailKeyA)).toBeUndefined()
    expect(queryClient.getMutationCache().findAll({ mutationKey: mutationKeyA, exact: true })).toHaveLength(0)
    expect(queryClient.getQueryData(detailKeyB)).toEqual(detailB)
    expect(screen.queryByText('late-cache-session-a.example.com')).not.toBeInTheDocument()
  })

  it.each(['success', 'error'] as const)(
    'removes and fences a late same-owner save %s after a new session starts',
    async (outcome) => {
      const lateSave = deferred<Response>()
      const sessionA = setSiteSession({ accessToken: 'site-edit-late-session-a' })
      const detailB = {
        ...detail,
        basic: { ...detail.basic, domains: ['late-session-b.example.com'] },
      }
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        if (init?.method === 'PATCH') return lateSave.promise
        return Promise.resolve(jsonResponse(
          authorization(init) === 'Bearer site-edit-late-session-b' ? detailB : detail,
        ))
      })
      const user = userEvent.setup()
      const { queryClient } = renderEdit()
      const detailKeyA = ['site-detail', sessionA.owner, 'site-1'] as const
      const mutationKeyA = ['site-edit-save', sessionA.owner, 'site-1'] as const
      await screen.findByRole('heading', { name: 'www.example.com' })
      const domain = await screen.findByLabelText('域名')
      await user.clear(domain)
      await user.type(domain, 'late-session-a.example.com')
      await commitEdits()
      await waitFor(() =>
        expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1),
      )

      let sessionB!: ReturnType<typeof setSiteSession>
      act(() => {
        sessionB = setSiteSession({ accessToken: 'site-edit-late-session-b' })
      })
      const detailKeyB = ['site-detail', sessionB.owner, 'site-1'] as const
      expect(await screen.findByRole('heading', { name: 'late-session-b.example.com' })).toBeInTheDocument()

      await act(async () => {
        lateSave.resolve(outcome === 'success'
          ? jsonResponse({
              ...detail,
              version: 2,
              basic: { ...detail.basic, domains: ['late-session-a.example.com'] },
            })
          : jsonResponse({
              error: { code: 'unavailable', message: 'private late session save error' },
            }, 503))
        await Promise.resolve()
      })

      expect(queryClient.getQueryState(detailKeyA)).toBeUndefined()
      expect(queryClient.getMutationCache().findAll({ mutationKey: mutationKeyA, exact: true })).toHaveLength(0)
      expect(queryClient.getQueryData(detailKeyB)).toEqual(detailB)
      expect(screen.getByRole('heading', { name: 'late-session-b.example.com' })).toBeInTheDocument()
      expect(screen.queryByText('late-session-a.example.com')).not.toBeInTheDocument()
      expect(screen.queryByText('private late session save error')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
    },
  )

  it.each([
    ['basic', 'permission_denied'],
    ['basic', 'forbidden'],
    ['origin', 'permission_denied'],
    ['origin', 'forbidden'],
  ] as const)(
    'makes a %s PATCH %s denial terminal for the current session lineage',
    async (section, code) => {
      const session = setSiteSession({ accessToken: `site-edit-terminal-${section}-${code}-a` })
      let detailReads = 0
      const rawMessage = `private ${section} ${code} policy detail`
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        if (init?.method === 'PATCH') {
          return Promise.resolve(jsonResponse({ error: { code, message: rawMessage } }, 403))
        }
        detailReads += 1
        return Promise.resolve(jsonResponse(detail))
      })
      const user = userEvent.setup()
      const { queryClient } = renderEdit()
      const detailKey = ['site-detail', session.owner, 'site-1'] as const
      const mutationKey = ['site-edit-save', session.owner, 'site-1'] as const
      await screen.findByRole('heading', { name: 'www.example.com' })

      if (section === 'basic') {
        const domain = await screen.findByLabelText('域名')
        await user.clear(domain)
        await user.type(domain, 'terminal-denial.example.com')
      } else {
        await user.click(await screen.findByRole('radio', { name: '随机' }))
      }
      await commitEdits()

      expect(await screen.findByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()
      expect(screen.getByText(i18n.t('sites:edit.errors.permission_denied'))).toBeInTheDocument()
      expect(screen.queryByText(rawMessage)).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
      expect(queryClient.getQueryState(detailKey)).toBeUndefined()
      await waitFor(() =>
        expect(queryClient.getMutationCache().findAll({ mutationKey, exact: true })).toHaveLength(0),
      )
      if (section === 'origin') expect(sessionStorage.getItem(originRetryKey)).toBeNull()
      const requestsBeforeRefresh = fetchSpy.mock.calls.length

      act(() => {
        setSiteSession({
          accessToken: `site-edit-terminal-${section}-${code}-b`,
          update: 'refresh',
        })
      })
      await act(async () => { await Promise.resolve() })
      expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
      expect(fetchSpy).toHaveBeenCalledTimes(requestsBeforeRefresh)
      expect(screen.getByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()

      act(() => {
        setSiteSession({ accessToken: `site-edit-terminal-${section}-${code}-fresh` })
      })
      expect(await screen.findByRole('heading', { name: 'www.example.com' })).toBeInTheDocument()
      expect(detailReads).toBe(2)
      expect(authorization(fetchSpy.mock.calls.at(-1)?.[1])).toBe(
        `Bearer site-edit-terminal-${section}-${code}-fresh`,
      )
    },
  )

  it('keeps an entitlement 403 recoverable and uses the latest token for a new save attempt', async () => {
    const session = setSiteSession({ accessToken: 'site-edit-entitlement-a' })
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['entitlement.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockResolvedValueOnce(jsonResponse({
        error: { code: 'entitlement_required', message: 'private entitlement detail' },
      }, 403))
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'entitlement.example.com')
    await commitEdits()

    expect(await screen.findByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText(i18n.t('sites:edit.errors.forbiddenTitle'))).not.toBeInTheDocument()
    expect(screen.queryByText('private entitlement detail')).not.toBeInTheDocument()
    act(() => {
      setSiteSession({ accessToken: 'site-edit-entitlement-b', update: 'refresh' })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    // The refused change went back to the saved value; the next change is a new attempt.
    expect(domain).toHaveValue('www.example.com')
    await user.clear(domain)
    await user.type(domain, 'entitlement.example.com')
    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    expect(authorization(fetchSpy.mock.calls[2][1])).toBe('Bearer site-edit-entitlement-b')
  })

  it('SiteEdit review closure preserves the active tab and basic draft on token refresh and saves with the latest token', async () => {
    const initial = setSiteSession({ accessToken: 'site-edit-basic-token-a' })
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['refresh-basic.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) =>
      init?.method === 'PATCH' ? Promise.resolve(jsonResponse(saved)) : Promise.resolve(jsonResponse(siteCardResponse(input))),
    )
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'refresh-basic.example.com')

    // The field is still being typed (saves on blur) when the token refreshes.
    act(() => {
      setSiteSession({ accessToken: 'site-edit-basic-token-b', update: 'refresh' })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(initial.sessionEpoch)
    expect(screen.getByRole('tab', { name: '基本配置' })).toHaveAttribute('aria-selected', 'true')
    // A token refresh must not refetch the site.
    expect(siteDetailFetches(fetchSpy)).toBe(1)
    expect(await screen.findByLabelText('域名')).toHaveValue('refresh-basic.example.com')

    // leaving the field (here: switching to 高级设置) saves it with the latest token
    await user.click(screen.getByRole('tab', { name: '高级设置' }))
    await waitFor(() =>
      expect(screen.getByRole('tab', { name: '高级设置' })).toHaveAttribute('aria-selected', 'true'),
    )
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(authorization(patch?.[1])).toBe('Bearer site-edit-basic-token-b')
  })

  it('SiteEdit review closure preserves the origin draft on token refresh and saves with the latest token', async () => {
    const initial = setSiteSession({ accessToken: 'site-edit-origin-token-a' })
    const saved: SiteDetail = {
      ...detail,
      version: 2,
      origin_pool: {
        ...detail.origin_pool,
        origins: [{ ...detail.origin_pool.origins[0], weight: 25 }],
      },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      init?.method === 'PATCH' ? Promise.resolve(jsonResponse(saved)) : Promise.resolve(jsonResponse(detail)),
    )
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑源站' })
    await user.clear(within(dialog).getByLabelText('源站权重'))
    await user.type(within(dialog).getByLabelText('源站权重'), '25')

    // The dialog keeps its own draft until 确定; a refresh meanwhile changes nothing.
    act(() => {
      setSiteSession({ accessToken: 'site-edit-origin-token-b', update: 'refresh' })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(initial.sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(within(dialog).getByLabelText('源站权重')).toHaveValue('25')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(authorization(patch?.[1])).toBe('Bearer site-edit-origin-token-b')
  })

  it('SiteEdit review closure does not auto-read on token refresh and explicit retry uses the latest token', async () => {
    const initial = setSiteSession({ accessToken: 'site-edit-refetch-token-a' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({
        error: { code: 'unavailable', message: 'private initial detail error' },
      }, 503))
      .mockResolvedValueOnce(jsonResponse(detail))
    const user = userEvent.setup()
    renderEdit('/site/site-1/edit?tab=advanced')
    expect(await screen.findByText('网站详情加载失败')).toBeInTheDocument()

    act(() => {
      setSiteSession({ accessToken: 'site-edit-refetch-token-b', update: 'refresh' })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(initial.sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('button', { name: '重试' }))

    expect(await screen.findByRole('heading', { name: 'www.example.com' })).toBeInTheDocument()
    expect(authorization(fetchSpy.mock.calls[1][1])).toBe('Bearer site-edit-refetch-token-b')
    expect(screen.getByRole('tab', { name: '高级设置' })).toHaveAttribute('aria-selected', 'true')
  })

  it('SiteEdit review closure preserves an uncertain basic attempt across token refresh and retries it with the latest token', async () => {
    const initial = setSiteSession({ accessToken: 'site-edit-retry-token-a' })
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['refresh-retry.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'refresh-retry.example.com')
    await commitEdits()
    expect(await screen.findByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    const firstPatch = fetchSpy.mock.calls[1]

    act(() => {
      setSiteSession({ accessToken: 'site-edit-retry-token-b', update: 'refresh' })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(initial.sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(screen.getByLabelText('域名')).toHaveValue('refresh-retry.example.com')
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))

    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const retryPatch = fetchSpy.mock.calls[2]
    expect(authorization(retryPatch[1])).toBe('Bearer site-edit-retry-token-b')
    expect(retryPatch[1]?.body).toBe(firstPatch[1]?.body)
    expect((retryPatch[1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(
      (firstPatch[1]?.headers as Record<string, string>)['Idempotency-Key'],
    )
  })

  it('SiteEdit review closure blocks a stale save handler after same-epoch sites.manage revocation', async () => {
    const initial = setSiteSession({ accessToken: 'site-edit-stale-save-a' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'stale-save.example.com')

    // The blur that would save lands in the same tick as the revocation.
    act(() => {
      setSiteSession({
        accessToken: 'site-edit-stale-save-b',
        permissions: ['sites.read'],
        update: 'refresh',
      })
      fireEvent.blur(domain)
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(initial.sessionEpoch)
    await act(async () => { await Promise.resolve() })
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
    expect(screen.getByLabelText('域名')).toBeDisabled()
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
  })

  it('SiteEdit review closure reconciles an in-flight known save success while manage is revoked', async () => {
    const pending = deferred<Response>()
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['revoked-success.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(pending.promise)
    setSiteSession({ accessToken: 'site-edit-known-a' })
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'revoked-success.example.com')
    await commitEdits()
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))

    act(() => {
      setSiteSession({
        accessToken: 'site-edit-known-revoked', permissions: ['sites.read'], update: 'refresh',
      })
    })
    await act(async () => {
      pending.resolve(jsonResponse(saved))
      await Promise.resolve()
    })

    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'revoked-success.example.com' })).toBeInTheDocument()
    expect(screen.getByLabelText('域名')).toBeDisabled()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('SiteEdit review closure retains an in-flight unknown attempt until manage is regranted', async () => {
    const pending = deferred<Response>()
    const saved = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['revoked-unknown.example.com'] },
    }
    let patchCount = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method !== 'PATCH') return Promise.resolve(jsonResponse(detail))
      patchCount += 1
      return patchCount === 1 ? pending.promise : Promise.resolve(jsonResponse(saved))
    })
    const initial = setSiteSession({ accessToken: 'site-edit-unknown-a' })
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'revoked-unknown.example.com')
    await commitEdits()
    await waitFor(() => expect(patchCount).toBe(1))
    const firstPatch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')!

    act(() => {
      setSiteSession({
        accessToken: 'site-edit-unknown-revoked', permissions: ['sites.read'], update: 'refresh',
      })
    })
    await act(async () => {
      pending.reject(new TypeError('connection reset during revocation'))
      await new Promise<void>((resolve) => setTimeout(resolve, 0))
    })
    const retry = await screen.findByRole('button', { name: '使用同一请求重试' })
    expect(retry).toBeDisabled()
    fireEvent.click(retry)
    expect(patchCount).toBe(1)

    act(() => {
      setSiteSession({
        accessToken: 'site-edit-unknown-restored',
        permissions: ['sites.read', 'sites.manage'],
        update: 'refresh',
      })
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(initial.sessionEpoch)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(patchCount).toBe(2))
    const patches = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(patches[1][1]?.body).toBe(firstPatch[1]?.body)
    expect(authorization(patches[1][1])).toBe('Bearer site-edit-unknown-restored')
    expect((patches[1][1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(
      (firstPatch[1]?.headers as Record<string, string>)['Idempotency-Key'],
    )
  })

  it('SiteEdit review closure resets tabs and drafts for a new session of the same principal', async () => {
    setSiteSession({ accessToken: 'site-edit-new-session-a' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) =>
      Promise.resolve(jsonResponse(siteCardResponse(input))),
    )
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'old-session-draft.example.com')
    await user.click(screen.getByRole('tab', { name: '高级设置' }))
    const oldEpoch = useSessionStore.getState().sessionEpoch

    act(() => {
      setSiteSession({ accessToken: 'site-edit-new-session-b' })
    })
    expect(useSessionStore.getState().sessionEpoch).not.toBe(oldEpoch)
    // A new session refetches the site (the basic tab's cards fetch their own
    // endpoints besides).
    await waitFor(() => expect(siteDetailFetches(fetchSpy)).toBe(2))
    const refreshedDomain = await screen.findByLabelText('域名')
    expect(screen.getByRole('tab', { name: '基本配置' })).toHaveAttribute('aria-selected', 'true')
    expect(refreshedDomain).toHaveValue('www.example.com')
    expect(screen.queryByText('old-session-draft.example.com')).not.toBeInTheDocument()
  })

  it('SiteEdit review closure resets the editor when the route site ID changes', async () => {
    setSiteSession({ accessToken: 'site-edit-switch-site' })
    const siteTwo: SiteDetail = {
      ...detail,
      id: 'site-2',
      basic: { ...detail.basic, domains: ['site-two.example.com'] },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) =>
      Promise.resolve(jsonResponse(String(input).endsWith('/site-2') ? siteTwo : detail)),
    )
    const user = userEvent.setup()
    renderSwitchableEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'site-one-draft.example.com')
    await user.click(screen.getByRole('button', { name: 'switch test site' }))

    expect(await screen.findByRole('heading', { name: 'site-two.example.com' })).toBeInTheDocument()
    expect(await screen.findByLabelText('域名')).toHaveValue('site-two.example.com')
    expect(screen.queryByText('site-one-draft.example.com')).not.toBeInTheDocument()
    // Leaving the field saved site 1's edit; site 2 is read once.
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method !== 'PATCH')).toHaveLength(2)
    expect(fetchSpy.mock.calls.filter(([input, init]) => init?.method === 'PATCH' && String(input).endsWith('/site-2'))).toHaveLength(0)
  })
})

describe('SiteEditPage tabs and roles', () => {
  const cachePolicy: CachePolicyView = {
    site_id: 'site-1',
    revision: 3,
    binding_mode: 'override',
    definition_id: 'site-1',
    definition_revision: 1,
    document: {
      mode: 'follow_origin',
      rules: [],
      query_mode: 'preserve',
      query_names: [],
      vary_headers: [],
      disk_quota_bytes: 64 * 1024 * 1024,
    },
    created_by_user_id: '11111111-1111-4111-8111-111111111111',
    request_id: 'cache-request-3',
    created_at: '2026-08-03T08:00:00Z',
  }

  it('renders all eight tabs, opens the tenant cache policy, and keeps other tabs locked', async () => {
    authenticate('user', ['sites.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jsonResponse(siteCardResponse(input))))
    vi.spyOn(originRoutingApi, 'get').mockResolvedValue({
      site_id: 'site-1',
      version: 1,
      updated_at: '2026-08-06T09:00:00Z',
      document: {
        schema: ORIGIN_ROUTING_SCHEMA,
        ingress_source_enabled: false,
        pools: [{
          id: 'pool-a',
          balance_method: 'round_robin',
          endpoints: [{ id: 'origin-a', host: '192.0.2.10', port: 443, weight: 100 }],
        }],
        default_pool_id: 'pool-a',
        routes: [],
        retry: {
          methods: ['GET', 'HEAD'],
          max_attempts: 2,
          connect_timeout_ms: 100,
          read_timeout_ms: 100,
          total_budget_ms: 300,
        },
      },
    })
    const getPolicy = vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(cachePolicy)
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const labels = ['基本配置', '回源设置', 'HTTPS设置', '缓存设置', 'CC防护', 'WAF防护', '自动防御', '高级设置']
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual(labels)

    for (const label of ['回源设置', 'HTTPS设置', 'CC防护', 'WAF防护', '自动防御', '高级设置']) {
      await user.click(screen.getByRole('tab', { name: label }))
      await waitFor(() =>
        expect(screen.getByRole('tab', { name: label })).toHaveAttribute('aria-selected', 'true'),
      )
      if (label === 'HTTPS设置') {
        expect(await screen.findByRole('switch', { name: 'HTTPS访问' })).toBeDisabled()
        expect(screen.queryByRole('button', { name: '保存更改' })).not.toBeInTheDocument()
        continue
      }
      if (label === '回源设置') {
        // tp-b3a: the origin fields (same origin pool draft) with
        // the page save button, read-only here; our conditional origin editor
        // is folded below and keeps its own read-only notice.
        expect(await screen.findByRole('switch', { name: '回源 Keepalive' })).toBeDisabled()
        expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
        await user.click(screen.getByRole('button', { name: /高级：条件回源/u }))
        expect(await screen.findByText(i18n.t('siteOriginRouting:states.readOnly'))).toBeInTheDocument()
        continue
      }
      if (label === '高级设置') {
        // sites.read alone reads the site's own 302 schedule and traffic limit
        // cards there (d808e4b8, 109e2ef1), so the tab is no longer a bare 403;
        // without sites.manage they stay read-only.
        expect(await screen.findByText(i18n.t('siteTrafficLimit:title'))).toBeInTheDocument()
        expect(screen.getByRole('switch', { name: i18n.t('siteTrafficLimit:enabled') })).toBeDisabled()
        expect(screen.queryByText(i18n.t('httpPolicies:title'))).not.toBeInTheDocument()
        // The tab shows the page save button for its edge options (53324798c);
        // read-only here.
        expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
        continue
      }
      // 已访问的标签隐藏挂载着，只在当前可见面板里找。
      const panel = document.querySelector<HTMLElement>(`[data-site-edit-tab="${label === 'CC防护' ? 'cc' : label === 'WAF防护' ? 'waf' : 'autodefense'}"]`)!
      expect(await within(panel).findByText(i18n.t('siteProtection:common.readOnly'))).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '保存更改' })).not.toBeInTheDocument()
    }

    await user.click(screen.getByRole('tab', { name: '缓存设置' }))
    expect(await screen.findByRole('heading', { name: i18n.t('cachePolicy:title') })).toBeInTheDocument()
    expect(screen.queryByText('当前设置暂不可编辑')).not.toBeInTheDocument()
    expect(screen.getByText(i18n.t('cachePolicy:states.readOnly'))).toBeInTheDocument()
    expect(getPolicy).toHaveBeenCalledWith('memory-only-access-token', 'site-1')
    // One site read; the advanced tab's cards read their own endpoints.
    expect(siteDetailFetches(fetchSpy)).toBe(1)
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false)
  })

  it('mounts cache only after first visit, keeps its draft across tabs, and guards navigation without enabling basic save', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    const getPolicy = vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue({
      ...cachePolicy,
      document: {
        ...cachePolicy.document,
        mode: 'override',
        rules: [{ order: 1, ttl_seconds: 3600 }],
      },
    })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(getPolicy).not.toHaveBeenCalled()

    // tp-b3c：规则改在弹窗里编辑，主表不再有 TTL 输入；改用删除这条规则制造草稿
    await user.click(screen.getByRole('tab', { name: '缓存设置' }))
    // 摘要条也显示规则数，限定在分区标题行内查找
    const cacheHeading = await screen.findByRole('heading', { name: i18n.t('cachePolicy:title'), level: 2 })
    const titleLine = cacheHeading.parentElement as HTMLElement
    expect(await within(titleLine).findByText(i18n.t('cachePolicy:count', { count: 1 }))).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: i18n.t('cachePolicy:actions.removeRule') }))
    expect(within(titleLine).getByText(i18n.t('cachePolicy:count', { count: 0 }))).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '基本配置' }))

    const cachePanel = screen.getByTestId('cache-policy-panel')
    expect(cachePanel).toHaveAttribute('hidden')
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
    const beforeUnload = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(beforeUnload)
    expect(beforeUnload.defaultPrevented).toBe(true)
    await user.click(screen.getByRole('button', { name: '返回网站列表' }))
    expect(confirm).toHaveBeenCalledWith('当前页面有未保存的修改，确定离开吗？')

    await user.click(screen.getByRole('tab', { name: '缓存设置' }))
    expect(within(titleLine).getByText(i18n.t('cachePolicy:count', { count: 0 }))).toBeInTheDocument()
    expect(getPolicy).toHaveBeenCalledTimes(1)
  })

  it('passes account lineage so the same page cannot reuse the previous tenant cache query', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(detail)))
    const getPolicy = vi.spyOn(cachePoliciesApi, 'get')
      .mockResolvedValueOnce(cachePolicy)
      .mockResolvedValueOnce({
        ...cachePolicy,
        revision: 4,
        document: {
          ...cachePolicy.document,
          mode: 'disabled',
          disk_quota_bytes: 0,
        },
      })
    const user = userEvent.setup()
    renderEdit('/site/site-1/edit?tab=cache')
    expect(await screen.findByRole('radio', { name: /遵循源站/ })).toBeChecked()

    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: '44444444-4444-4444-8444-444444444444',
      tenant_id: '44444444-4444-4444-8444-444444444444',
      permissions: ['sites.read', 'sites.manage'],
    })
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorB), access_token: 'token-b' },
      actorB,
    ))

    await waitFor(() =>
      expect(screen.getByRole('tab', { name: '基本配置' })).toHaveAttribute('aria-selected', 'true'),
    )
    await user.click(screen.getByRole('tab', { name: '缓存设置' }))
    expect(await screen.findByRole('radio', { name: /停用缓存/ })).toBeChecked()
    await waitFor(() => expect(getPolicy).toHaveBeenCalledTimes(2))
    expect(getPolicy).toHaveBeenNthCalledWith(1, 'memory-only-access-token', 'site-1')
    expect(getPolicy).toHaveBeenNthCalledWith(2, 'token-b', 'site-1')
  })

  it('reads the cache policy in the site tenant scope for a platform administrator', async () => {
    // Administrators edit the tenant's cache rules here, no switch to the tenant.
    authenticate('admin', ['platform.admin'])
    const siteScope = '44444444-4444-4444-8444-444444444444'
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ ...detail, scope_id: siteScope }))
    const getPolicy = vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue({
      site_id: 'site-1', revision: 1, binding_mode: 'override', definition_id: 'site-1', definition_revision: 1,
      document: { mode: 'disabled', rules: [], query_mode: 'preserve', query_names: [], vary_headers: [], disk_quota_bytes: 1024 * 1024 * 1024 },
      created_by_user_id: '11111111-1111-4111-8111-111111111111', request_id: 'request-1', created_at: '2026-08-01T08:00:00Z',
    })
    renderEdit('/site/site-1/edit?tab=cache')

    await waitFor(() => expect(getPolicy).toHaveBeenCalledWith('memory-only-access-token', 'site-1', siteScope))
    expect(screen.queryByText(i18n.t('cachePolicy:states.forbiddenDescription'))).not.toBeInTheDocument()
  })

  it('rejects a tenant without sites.read at the editor boundary before cache requests', async () => {
    authenticate('user', ['sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    const getPolicy = vi.spyOn(cachePoliciesApi, 'get')
    renderEdit('/site/site-1/edit?tab=cache')

    expect(await screen.findByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(i18n.t('sites:edit.errors.permission_denied'))).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(getPolicy).not.toHaveBeenCalled()
  })

  it('omits administrator-only settings for tenant users', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(jsonResponse(siteCardResponse(input))))
    renderEdit('/site/site-1/edit?tab=advanced')

    // The tenant reads its own site cards (302 schedule, traffic limit) on the
    // advanced tab; administrator settings are not rendered.
    expect(await screen.findByText(i18n.t('siteTrafficLimit:title'))).toBeInTheDocument()
    // 摘要条也显示“302 调度”，限定在卡片标题查找
    expect(screen.getByRole('heading', { name: i18n.t('siteSchedule302:title') })).toBeInTheDocument()
    expect(screen.queryByText('管理员设置')).not.toBeInTheDocument()
  })
})

describe('SiteEditPage editing', () => {
  it('shows lock metadata and prevents tenant configuration writes', async () => {
    authenticate('user')
    const locked: SiteDetail = {
      ...detail,
      lock: {
        locked: true,
        reason: '账户归属复核',
        locked_at: '2026-07-22T09:10:00Z',
        operator: { display_name: '平台管理员' },
      },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(locked))
    renderEdit()

    expect(await screen.findByText('网站已被管理员锁定')).toBeInTheDocument()
    expect(screen.getByText(/账户归属复核/)).toBeInTheDocument()
    expect(screen.getByText(/平台管理员/)).toBeInTheDocument()
    expect(await screen.findByLabelText('域名')).toBeDisabled()
    expect(screen.getByLabelText('HTTP监听端口')).toBeDisabled()
    expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
    await commitEdits()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('keeps locked-site maintenance writable for platform administrators', async () => {
    authenticate('admin')
    const locked: SiteDetail = {
      ...detail,
      lock: {
        locked: true,
        reason: '租户写入暂停',
        locked_at: '2026-07-22T09:10:00Z',
        operator: { display_name: '平台管理员' },
      },
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(jsonResponse(init?.method === 'PATCH'
      ? { ...locked, ...savedBasic(JSON.parse(String(init.body))), lock: locked.lock } : locked)))
    const user = userEvent.setup()
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.queryByText('网站已被管理员锁定')).not.toBeInTheDocument()
    const domain = await screen.findByLabelText('域名')
    expect(domain).not.toBeDisabled()
    await user.clear(domain)
    await user.type(domain, 'maintenance.example.com')
    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('refreshes lock state and blocks further tenant writes after a concurrent lock', async () => {
    authenticate('user')
    const locked: SiteDetail = {
      ...detail,
      version: 2,
      lock: {
        locked: true,
        reason: '并发安全复核',
        locked_at: '2026-07-22T09:30:00Z',
        operator: { display_name: '平台管理员' },
      },
    }
    let detailReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) !== '/v1/sites/site-1') {
        return Promise.reject(new Error(`unexpected request ${String(input)}`))
      }
      if (init?.method === 'PATCH') {
        return Promise.resolve(
          jsonResponse(
            { error: { code: 'site_locked', message: 'site is locked', request_id: 'r-lock' } },
            409,
          ),
        )
      }
      detailReads += 1
      return Promise.resolve(jsonResponse(detailReads === 1 ? detail : locked))
    })
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'blocked.example.com')
    await commitEdits()

    expect(await screen.findByText('网站已被管理员锁定，不能保存新配置')).toBeInTheDocument()
    expect(await screen.findByText('网站已被管理员锁定')).toBeInTheDocument()
    expect(screen.getByLabelText('域名')).toHaveValue('www.example.com')
    expect(screen.getByLabelText('域名')).toBeDisabled()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('validates the observed basic fields before issuing PATCH', async () => {
    await loadBasic()
    const fetchSpy = vi.mocked(globalThis.fetch)
    const user = userEvent.setup()

    await user.clear(screen.getByLabelText('域名'))
    await user.type(screen.getByLabelText('域名'), 'not a domain')
    await user.clear(screen.getByLabelText('HTTP监听端口'))
    await user.type(screen.getByLabelText('HTTP监听端口'), '70000')
    await commitEdits()

    expect(await screen.findByText(/1 到 100 个有效且不重复的域名/)).toBeInTheDocument()
    expect(screen.getByText(/1-65535/)).toBeInTheDocument()
    // UX-03: field errors stay at the fields (checked on blur, focus left alone), no dialog, nothing sent.
    expect(screen.queryByText('请检查标红字段')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  // 没有底部保存条与「放弃修改」，选择类改动即保存、输入失焦保存，成功轻提示“操作成功”。
  it('has no save bar; a switch saves at once and shows the 操作成功 toast', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? Promise.resolve(jsonResponse(savedBasic(JSON.parse(String(init.body)))))
      : Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.queryByRole('region', { name: '保存更改' })).toBeNull()
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
    expect(screen.queryByRole('button', { name: '放弃修改' })).toBeNull()
    expect(screen.queryByRole('button', { name: '保存基本配置' })).toBeNull()

    await user.click((await screen.findByRole('switch', { name: SHARED })))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1))
    const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')![1]!.body))
    expect(body).toMatchObject({ expected_version: 1, section: 'basic', changes: { cache_shared_across_domains: true } })
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('saves a typed field on blur (not per keystroke) and edits the origin list without locking it', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? Promise.resolve(jsonResponse(savedBasic(JSON.parse(String(init.body)))))
      : Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const ports = screen.getByLabelText('HTTP监听端口')
    await user.clear(ports)
    await user.type(ports, '8080')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
    // the other section is not locked by a pending edit any more
    expect(screen.getByRole('button', { name: '新增源站信息' })).toBeEnabled()
    expect(screen.queryByText('基本配置有未保存的修改，先保存或撤销基本配置后才能修改源站设置')).toBeNull()
    fireEvent.blur(ports)
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1))
    expect(JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')![1]!.body)))
      .toMatchObject({ section: 'basic', changes: { http_listen_ports: ['8080'] } })
  })

  it('marks a server-refused field under it instead of a dialog', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? Promise.resolve(jsonResponse({ error: { code: 'validation_error', message: 'raw', request_id: 'req-1',
        details: { field: 'http_listen_ports', reason: 'invalid' } } }, 400))
      : Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const ports = await screen.findByLabelText('HTTP监听端口', {}, { timeout: 5_000 })
    await user.clear(ports)
    await user.type(ports, '8080')
    fireEvent.blur(ports)
    const reason = await screen.findByText(/HTTP 端口不正确/, { selector: '.site-field-error' })
    expect(reason).not.toHaveTextContent('请求 ID')
    expect(screen.getByLabelText('HTTP监听端口')).toHaveValue('80')
    expect(screen.getByLabelText('HTTP监听端口')).toHaveClass('ant-input-status-error')
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
  })

  it('keeps the dialog with the server reason for a refused field the tab cannot mark', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? Promise.resolve(jsonResponse({ error: { code: 'validation_error', message: 'raw', details: { field: 'https_enabled', reason: 'certificate_required' } } }, 400))
      : Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const ports = await screen.findByLabelText('HTTP监听端口', {}, { timeout: 5_000 })
    await user.clear(ports)
    await user.type(ports, '8080')
    fireEvent.blur(ports)
    await waitFor(() => expect(document.querySelector('.cdnca-feedback')).toHaveTextContent('还没有绑定证书'))
    expect(document.querySelector('.site-field-error')).toBeNull()
  })

  it('rolls a refused change back to the saved value', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? Promise.resolve(jsonResponse({ error: { code: 'validation_failed', message: '配置无效' } }, 422))
      : Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const ipv6 = (await screen.findByRole('switch', { name: SHARED }))
    const before = ipv6.getAttribute('aria-checked')
    await user.click(ipv6)
    expect(await screen.findByText('请求失败，请稍后重试')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('switch', { name: SHARED })).toHaveAttribute('aria-checked', before!))
  })

  // CFG-DRAFT-01: a refusal takes back only what that attempt sent. Input
  // made while it ran (same section or the origin pool) stays as an unsaved draft.
  it('keeps input made while a refused basic save ran', async () => {
    authenticate()
    let refuse: ((response: Response) => void) | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? new Promise<Response>((resolve) => { refuse = resolve })
      : Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const shared = await screen.findByRole('switch', { name: SHARED })
    const before = shared.getAttribute('aria-checked')
    await user.click(shared)
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1))
    const ports = screen.getByLabelText('HTTP监听端口')
    await user.clear(ports)
    await user.type(ports, '8081')
    await act(async () => refuse!(jsonResponse({ error: { code: 'validation_failed', message: 'refused' } }, 422)))
    expect(await screen.findByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(ports).toHaveValue('8081')
    await waitFor(() => expect(screen.getByRole('switch', { name: SHARED })).toHaveAttribute('aria-checked', before!))
  })

  it('keeps the origin draft when a basic save is refused', async () => {
    authenticate()
    let refuse: ((response: Response) => void) | undefined
    let patches = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method !== 'PATCH') return Promise.resolve(jsonResponse(detail))
      patches += 1
      return patches === 1 ? new Promise<Response>((resolve) => { refuse = resolve }) : new Promise<Response>(() => {})
    })
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    await user.click(await screen.findByRole('switch', { name: SHARED }))
    await waitFor(() => expect(patches).toBe(1))
    const backups = screen.getByRole('textbox', { name: i18n.t('siteOriginForwarding:fields.backupOrigins') })
    await user.type(backups, '192.0.2.20:80')
    await act(async () => refuse!(jsonResponse({ error: { code: 'validation_failed', message: 'refused' } }, 422)))
    expect(await screen.findByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(backups).toHaveValue('192.0.2.20:80')
  })

  // WEB/FLOW-STATE-01: a failed sync status read says so and offers a retry
  // instead of counting down "pending" as if it were read.
  it('says when the sync status cannot be read and reads it again on request', async () => {
    authenticate()
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(++reads === 1
      ? jsonResponse({ ...detail, basic: { ...detail.basic, sync_status: 'pending' } })
      : reads === 2 ? jsonResponse({ error: { code: 'service_unavailable', message: 'unavailable' } }, 503)
        : jsonResponse({ ...detail, basic: { ...detail.basic, sync_status: 'synced' } })))
    const { queryClient } = renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    await act(async () => { await queryClient.invalidateQueries({ queryKey: ['site-sync-status'] }) })
    const status = await screen.findByTestId('site-edit-sync-status')
    await waitFor(() => expect(status).toHaveTextContent('同步状态暂时无法读取'))
    expect(status).not.toHaveTextContent('秒后刷新')
    await userEvent.setup().click(within(status).getByRole('button', { name: '重新读取' }))
    await waitFor(() => expect(screen.getByTestId('site-edit-sync-status')).toHaveTextContent('已同步'))
  })

  it('links the site to its publication records', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderWithProviders(<Routes>
      <Route path="/site/:id/edit" element={<SiteEditPage />} />
      <Route path="/site/publications" element={<div>发布记录占位</div>} />
    </Routes>, ['/site/site-1/edit'])
    await screen.findByRole('heading', { name: 'www.example.com' })
    await user.click(screen.getByTestId('site-edit-publications'))
    expect(await screen.findByText('发布记录占位')).toBeInTheDocument()
  })

  it('sends only the last of fast repeated changes after the running save', async () => {
    authenticate()
    let resolveFirst: ((response: Response) => void) | undefined
    const bodies: { expected_version: number; changes: SiteDetail['basic'] }[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method !== 'PATCH') return Promise.resolve(jsonResponse(detail))
      const body = JSON.parse(String(init.body))
      bodies.push(body)
      const saved = jsonResponse(savedBasic(body))
      return bodies.length === 1 ? new Promise<Response>((resolve) => { resolveFirst = () => resolve(saved) }) : Promise.resolve(saved)
    })
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const ipv6 = (await screen.findByRole('switch', { name: SHARED }))
    const start = ipv6.getAttribute('aria-checked') === 'true'
    await user.click(ipv6)
    await waitFor(() => expect(bodies).toHaveLength(1))
    // three more toggles while the first save runs
    await user.click(ipv6)
    await user.click(ipv6)
    await user.click(ipv6)
    expect(bodies).toHaveLength(1)
    await act(async () => resolveFirst?.(new Response()))
    await waitFor(() => expect(bodies).toHaveLength(2))
    expect(bodies[1]).toMatchObject({ expected_version: 2, changes: { cache_shared_across_domains: start } })
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)) })
    expect(bodies).toHaveLength(2)
  })

  it('sends a complete versioned basic PATCH with an idempotency key and shows success', async () => {
    authenticate()
    let resolvePatch: ((response: Response) => void) | undefined
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(new Promise<Response>((resolve) => { resolvePatch = resolve }))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'new.example.com')
    await commitEdits()

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const [, patchInit] = fetchSpy.mock.calls[1]
    expect(patchInit).toMatchObject({ method: 'PATCH' })
    expect(patchInit?.headers).toEqual(
      expect.objectContaining({ 'Idempotency-Key': expect.any(String) }),
    )
    expect(JSON.parse(String(patchInit?.body))).toMatchObject({
      expected_version: 1,
      section: 'basic',
      changes: { domains: ['new.example.com'], cname: 'edge.example.net', status: 'active' },
    })

    await act(async () => {
      resolvePatch?.(jsonResponse({
        ...detail,
        version: 2,
        basic: { ...detail.basic, domains: ['new.example.com'] },
      }))
    })
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    expect(screen.queryByText('未保存')).not.toBeInTheDocument()
  })

  it('reloads the latest values and says so on a version conflict', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockResolvedValueOnce(
        jsonResponse(
          { error: { code: 'version_conflict', message: 'internal version conflict', request_id: 'r2' } },
          409,
        ),
      )
      .mockResolvedValueOnce(jsonResponse({ ...detail, version: 3, basic: { ...detail.basic, domains: ['latest.example.com'] } }))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'draft.example.com')
    await commitEdits()

    expect(await screen.findByText('配置已被其他人修改，已刷新为最新值，请重新操作')).toBeInTheDocument()
    expect(screen.queryByText('internal version conflict')).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('域名')).toHaveValue('latest.example.com'))
    expect(screen.queryByText('未保存')).not.toBeInTheDocument()
  })

  it('reuses the idempotency key only when the network result is unknown', async () => {
    authenticate()
    const saved = { ...detail, version: 2, basic: { ...detail.basic, domains: ['retry.example.com'] } }
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'retry.example.com')
    await commitEdits()
    expect(await screen.findByText('无法连接服务，请稍后重试')).toBeInTheDocument()
    expect(screen.getByLabelText('域名')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()

    const firstKey = (fetchSpy.mock.calls[1][1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ]
    const secondKey = (fetchSpy.mock.calls[2][1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ]
    expect(firstKey).toBeTruthy()
    expect(secondKey).toBe(firstKey)
    expect(fetchSpy.mock.calls[2][1]?.body).toBe(fetchSpy.mock.calls[1][1]?.body)
  })

  it.each([
    ['408', () => jsonResponse({ error: { code: 'timeout', message: '请求超时' } }, 408)],
    ['429', () => jsonResponse({ error: { code: 'rate_limited', message: '请求过于频繁' } }, 429)],
    ['503', () => jsonResponse({ error: { code: 'unavailable', message: '服务暂不可用' } }, 503)],
    [
      'an invalid success response',
      () => new Response('{', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ],
  ])('reuses the idempotency key after %s leaves the write outcome uncertain', async (_, failure) => {
    authenticate()
    const saved = { ...detail, version: 2, basic: { ...detail.basic, domains: ['retry.example.com'] } }
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockResolvedValueOnce(failure())
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'retry.example.com')
    await commitEdits()
    expect(await screen.findByText(/^(请求失败，请稍后重试|保存失败，请稍后重试)$/)).toBeInTheDocument()
    expect(screen.getByLabelText('域名')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()

    const firstKey = (fetchSpy.mock.calls[1][1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ]
    const secondKey = (fetchSpy.mock.calls[2][1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ]
    expect(firstKey).toBeTruthy()
    expect(secondKey).toBe(firstKey)
    expect(fetchSpy.mock.calls[2][1]?.body).toBe(fetchSpy.mock.calls[1][1]?.body)
  })

  it('rotates the idempotency key after an explicit business rejection', async () => {
    authenticate()
    const saved = { ...detail, version: 2, basic: { ...detail.basic, domains: ['retry.example.com'] } }
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: 'validation_failed', message: '配置无效' } }, 422),
      )
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    const domain = await screen.findByLabelText('域名')
    await user.clear(domain)
    await user.type(domain, 'retry.example.com')
    await commitEdits()
    expect(await screen.findByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('配置无效')).not.toBeInTheDocument()
    // the refused value went back; editing again sends a new attempt
    await waitFor(() => expect(domain).toHaveValue('www.example.com'))
    await user.clear(domain)
    await user.type(domain, 'retry.example.com')
    await commitEdits()
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()

    const firstKey = (fetchSpy.mock.calls[1][1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ]
    const secondKey = (fetchSpy.mock.calls[2][1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ]
    expect(firstKey).toBeTruthy()
    expect(secondKey).not.toBe(firstKey)
  })

  it('confirms page exit and registers native unload protection while dirty', async () => {
    await loadBasic()
    const user = userEvent.setup()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)

    await user.clear(screen.getByLabelText('域名'))
    await user.type(screen.getByLabelText('域名'), 'dirty.example.com')
    const beforeUnload = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(beforeUnload)
    expect(beforeUnload.defaultPrevented).toBe(true)

    await user.click(screen.getByRole('button', { name: '返回网站列表' }))
    expect(confirm).toHaveBeenCalledWith('当前页面有未保存的修改，确定离开吗？')
    expect(screen.getByRole('heading', { name: 'dirty.example.com' })).toBeInTheDocument()
  })
})

describe('SiteEditPage origin pool editing', () => {
  it('SiteEdit review closure persists the exact origin section under the stable owner key before sending', async () => {
    authenticate()
    let resolvePatch: ((response: Response) => void) | undefined
    const saved: SiteDetail = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, origins: ['192.0.2.10'] },
      origin_pool: {
        ...detail.origin_pool,
        origins: [{ ...detail.origin_pool.origins[0], weight: 25 }],
        balance_method: 'least_conn',
      },
    }
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(new Promise<Response>((resolve) => { resolvePatch = resolve }))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑源站' })
    const weight = within(dialog).getByLabelText('源站权重')
    await user.clear(weight)
    await user.type(weight, '25')
    // The dialog's 确定 saves the origin list; the balance chosen meanwhile waits for that save.
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await user.click(await screen.findByRole('radio', { name: '最少连接' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const stored = JSON.parse(sessionStorage.getItem(originRetryKey) ?? 'null') as {
      idempotencyKey: string
      serializedBody: string
    }
    const [, patchInit] = fetchSpy.mock.calls[1]
    expect(patchInit?.headers).toEqual(
      expect.objectContaining({ 'Idempotency-Key': stored.idempotencyKey }),
    )
    expect(patchInit?.body).toBe(stored.serializedBody)
    expect(JSON.parse(stored.serializedBody)).toEqual({
      expected_version: 1,
      section: 'origin',
      changes: { ...detail.origin_pool, origins: saved.origin_pool.origins },
    })

    fetchSpy.mockResolvedValueOnce(jsonResponse({ ...saved, version: 3 }))
    await act(async () => resolvePatch?.(jsonResponse({ ...saved, origin_pool: { ...saved.origin_pool, balance_method: detail.origin_pool.balance_method } })))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({
      expected_version: 2,
      section: 'origin',
      changes: saved.origin_pool,
    })
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    await waitFor(() => expect(sessionStorage.getItem(originRetryKey)).toBeNull())
  })

  it('keeps the exact origin attempt locked when clearing it after a known success fails', async () => {
    authenticate()
    const pending = deferred<Response>()
    const saved: SiteDetail = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, domains: ['server-saved.example.com'] },
      origin_pool: { ...detail.origin_pool, balance_method: 'least_conn' },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(pending.promise)
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    await user.click(await screen.findByRole('radio', { name: '最少连接' }))
    await commitEdits()

    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    const persisted = sessionStorage.getItem(originRetryKey)
    expect(persisted).not.toBeNull()
    const attempt = JSON.parse(persisted ?? 'null') as {
      idempotencyKey: string
      serializedBody: string
    }
    const patch = fetchSpy.mock.calls[1][1]
    expect(attempt.idempotencyKey).toBe(
      (patch?.headers as Record<string, string>)['Idempotency-Key'],
    )
    expect(attempt.serializedBody).toBe(patch?.body)
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation((key) => {
      if (key === originRetryKey) throw new DOMException('storage unavailable')
    })

    await act(async () => pending.resolve(jsonResponse(saved)))

    expect(await screen.findByRole('heading', { name: 'server-saved.example.com' })).toBeInTheDocument()
    expect(await screen.findByText(i18n.t('sites:edit.feedback.originRetryClearFailed'))).toBeInTheDocument()
    expect(sessionStorage.getItem(originRetryKey)).toBe(persisted)
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
    expect(screen.getByRole('radio', { name: '最少连接' })).toBeDisabled()
    const domain = screen.getByLabelText('域名')
    expect(domain).toBeDisabled()
    fireEvent.change(domain, { target: { value: 'different-request.example.com' } })
    expect(domain).toHaveValue('server-saved.example.com')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('restores an unknown origin write after remount and retries the same key and body', async () => {
    authenticate()
    const saved: SiteDetail = {
      ...detail,
      version: 2,
      origin_pool: { ...detail.origin_pool, balance_method: 'random' },
    }
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockResolvedValueOnce(jsonResponse(saved))
    const user = userEvent.setup()
    const first = renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    await user.click(await screen.findByRole('radio', { name: '随机' }))
    await commitEdits()
    expect(await screen.findByText('无法连接服务，请稍后重试')).toBeInTheDocument()
    const firstWrite = fetchSpy.mock.calls[1][1]
    first.unmount()

    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.getByText('上次源站保存结果待确认，请使用同一请求重试')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()

    const retryWrite = fetchSpy.mock.calls[3][1]
    expect(retryWrite?.body).toBe(firstWrite?.body)
    expect((retryWrite?.headers as Record<string, string>)['Idempotency-Key']).toBe(
      (firstWrite?.headers as Record<string, string>)['Idempotency-Key'],
    )
    expect(sessionStorage.getItem(originRetryKey)).toBeNull()
  })

  it('does not send when the frozen origin retry cannot be persisted', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    const user = userEvent.setup()
    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const hash = await screen.findByRole('radio', { name: 'IP 哈希' })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('quota exceeded')
    })
    await user.click(hash)

    expect(await screen.findByText('浏览器无法保存重试凭据，未发送源站更改')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('fails closed when the persisted origin retry is corrupted and unlocks only after loading latest state', async () => {
    authenticate()
    sessionStorage.setItem(originRetryKey, JSON.stringify({ version: 1, siteId: 'site-1' }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.getByText('待确认源站请求无法恢复，网站设置保持只读')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '结果待确认' })).toBeDisabled()
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole('button', { name: '加载最新配置' }))
    expect(await screen.findByText('已清除损坏记录并加载最新配置')).toBeInTheDocument()
    expect(sessionStorage.getItem(originRetryKey)).toBeNull()
    expect(screen.getByRole('button', { name: '新增源站信息' })).toBeEnabled()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('keeps a corrupted origin retry locked when loading latest state fails', async () => {
    authenticate()
    sessionStorage.setItem(originRetryKey, JSON.stringify({ version: 1, siteId: 'site-1' }))
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(detail))
      .mockRejectedValueOnce(new TypeError('offline'))
    const user = userEvent.setup()
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    await user.click(screen.getByRole('button', { name: '加载最新配置' }))

    expect(await screen.findByText('最新配置加载失败，网站设置继续保持只读')).toBeInTheDocument()
    expect(sessionStorage.getItem(originRetryKey)).not.toBeNull()
    expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
  })

  it('keeps a corrupted origin retry locked when its storage record cannot be removed', async () => {
    authenticate()
    sessionStorage.setItem(originRetryKey, JSON.stringify({ version: 1, siteId: 'site-1' }))
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
      throw new DOMException('storage unavailable')
    })
    await user.click(screen.getByRole('button', { name: '加载最新配置' }))

    expect(await screen.findByText('无法清除损坏记录，网站设置继续保持只读')).toBeInTheDocument()
    expect(sessionStorage.getItem(originRetryKey)).not.toBeNull()
    expect(await screen.findByRole('button', { name: '新增源站信息' })).toBeDisabled()
  })
})

describe('SiteEdit review closure stable origin retry identity', () => {
  it.each(['permission_denied', 'forbidden'] as const)(
    'settles a restored cross-epoch origin retry when the old request returns terminal %s',
    async (code) => {
      const latePatch = deferred<Response>()
      const sessionA = setSiteSession({ accessToken: `site-origin-terminal-${code}-a` })
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
        init?.method === 'PATCH' ? latePatch.promise : Promise.resolve(jsonResponse(detail)),
      )
      const user = userEvent.setup()
      const { queryClient } = renderEdit()
      await screen.findByRole('heading', { name: 'www.example.com' })
      await user.click(await screen.findByRole('radio', { name: '随机' }))
      await commitEdits()
      await waitFor(() =>
        expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1),
      )
      const persisted = sessionStorage.getItem(originRetryKey)
      expect(persisted).not.toBeNull()

      let sessionB!: ReturnType<typeof setSiteSession>
      act(() => {
        sessionB = setSiteSession({ accessToken: `site-origin-terminal-${code}-b` })
      })
      const retry = await screen.findByRole('button', { name: '使用同一请求重试' })
      expect(sessionB.sessionEpoch).not.toBe(sessionA.sessionEpoch)
      expect(fetchSpy).toHaveBeenCalledTimes(3)

      vi.spyOn(Storage.prototype, 'removeItem').mockImplementation((key) => {
        if (key === originRetryKey) throw new DOMException('terminal remove unavailable')
      })
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation((key) => {
        if (key === originRetryKey) throw new DOMException('terminal tombstone unavailable')
      })
      const rawMessage = `private late ${code} origin policy detail`
      await act(async () => {
        latePatch.resolve(jsonResponse({ error: { code, message: rawMessage } }, 403))
        await new Promise<void>((resolve) => setTimeout(resolve, 0))
      })

      expect(await screen.findByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()
      expect(screen.getByText(i18n.t('sites:edit.errors.permission_denied'))).toBeInTheDocument()
      expect(screen.queryByText(rawMessage)).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
      expect(sessionStorage.getItem(originRetryKey)).toBe(persisted)
      expect(queryClient.getQueryState(['site-detail', sessionA.owner, 'site-1'])).toBeUndefined()
      expect(queryClient.getQueryState(['site-detail', sessionB.owner, 'site-1'])).toBeUndefined()
      for (const session of [sessionA, sessionB]) {
        expect(queryClient.getMutationCache().findAll({
          mutationKey: ['site-edit-save', session.owner, 'site-1'],
          exact: true,
        })).toHaveLength(0)
      }

      act(() => {
        setSiteSession({ accessToken: `site-origin-terminal-${code}-refresh`, update: 'refresh' })
      })
      fireEvent.click(retry)
      await act(async () => { await Promise.resolve() })
      expect(fetchSpy).toHaveBeenCalledTimes(3)
      expect(screen.getByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()

      act(() => {
        setSiteSession({ accessToken: `site-origin-terminal-${code}-next-epoch` })
      })
      await act(async () => { await Promise.resolve() })
      expect(fetchSpy).toHaveBeenCalledTimes(3)
      expect(screen.getByText(i18n.t('sites:edit.errors.forbiddenTitle'))).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    },
  )

  it('SiteEdit review closure restores the same stable owner across a new epoch and retries with the latest token', async () => {
    const attempt = storedOriginAttempt()
    sessionStorage.setItem(originRetryKey, JSON.stringify(attempt))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) =>
      init?.method === 'PATCH'
        ? Promise.resolve(jsonResponse({ ...detail, version: 2 }))
        : Promise.resolve(jsonResponse(detail)),
    )
    setSiteSession({ accessToken: 'site-edit-stable-owner-a' })
    const user = userEvent.setup()
    renderEdit()
    expect(await screen.findByText('上次源站保存结果待确认，请使用同一请求重试')).toBeInTheDocument()
    const firstEpoch = useSessionStore.getState().sessionEpoch

    act(() => {
      setSiteSession({ accessToken: 'site-edit-stable-owner-b' })
    })
    expect(useSessionStore.getState().sessionEpoch).not.toBe(firstEpoch)
    expect(await screen.findByText('上次源站保存结果待确认，请使用同一请求重试')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))

    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')!
    expect(authorization(patch[1])).toBe('Bearer site-edit-stable-owner-b')
    expect(patch[1]?.body).toBe(attempt.serializedBody)
    expect((patch[1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(attempt.idempotencyKey)
    expect(sessionStorage.getItem(originRetryKey)).toBeNull()
  })

  it('SiteEdit review closure does not replay equal scope user and site IDs across kind or tenant boundaries', async () => {
    const attempt = storedOriginAttempt()
    sessionStorage.setItem(originRetryKey, JSON.stringify(attempt))
    setSiteSession({
      kind: 'platform',
      scopeID: tenantAID,
      tenantID: null,
      userID: tenantAUserID,
      accessToken: 'site-edit-collision-platform',
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.queryByText('上次源站保存结果待确认，请使用同一请求重试')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(sessionStorage.getItem(originRetryKey)).toBe(JSON.stringify(attempt))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
  })

  it('SiteEdit review closure ignores and does not migrate the legacy short origin key', async () => {
    const legacyKey =
      `cdnca:site-origin-retry:v1:${tenantAID}:${tenantAUserID}:site-1`
    const attempt = storedOriginAttempt()
    sessionStorage.setItem(legacyKey, JSON.stringify(attempt))
    setSiteSession({ accessToken: 'site-edit-legacy-key' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.queryByText('上次源站保存结果待确认，请使用同一请求重试')).not.toBeInTheDocument()
    expect(sessionStorage.getItem(legacyKey)).toBe(JSON.stringify(attempt))
    expect(sessionStorage.getItem(originRetryKey)).toBeNull()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
  })
})

// siteDetailFetches counts the GETs of the site detail itself.
function siteDetailFetches(fetchSpy: { mock: { calls: Parameters<typeof fetch>[] } }): number {
  return fetchSpy.mock.calls.filter(([input, init]) =>
    (init?.method ?? 'GET') === 'GET' && new URL(String(input), 'http://localhost').pathname.endsWith('/v1/sites/site-1'),
  ).length
}

// siteCardResponse answers the advanced tab's per-site cards (access control,
// 302 schedule, traffic limit) with an unset setting, and the site detail otherwise.
function siteCardResponse(input: Parameters<typeof fetch>[0]): unknown {
  const path = new URL(String(input), 'http://localhost').pathname
  if (path.endsWith('/schedule302')) {
    return { site_id: 'site-1', version: 1, plain_http: true, updated_at: null, settings: {
      enabled: false, target: 'address', keep_path: true, keep_query: true, signature_ttl_seconds: 60,
      https_to_http: false, extensions: [], path_prefixes: [], min_size_bytes: 0 } }
  }
  if (path.endsWith('/access')) {
    return { site_id: 'site-1', version: 1, https_enabled: false, force_https: false,
      domains: ['www.example.com'], updated_at: null, settings: {
        host_redirects: [], hsts: null, compression: null, limits: null, basic_auth: null, maintenance: null,
        force_https: { status: 301, exclude_hosts: [] } } }
  }
  if (path.endsWith('/traffic-limit')) {
    return { site_id: 'site-1', version: 1, total_since: null, exceeded_period: '', exceeded_at: null,
      evaluated_at: null, updated_at: null, setting: { enabled: false, daily_bytes: null, monthly_bytes: null,
        total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '' } }
  }
  return detail
}
