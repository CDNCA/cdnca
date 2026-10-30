import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import type { SiteDetail, SiteListItem, SiteListResponse } from '../api/sites'
import { usersApi, type ManagedUser } from '../api/users'
import { siteGroupsApi } from '../api/siteGroups'
import { useSessionStore, type SessionUpdate } from '../auth/session'
import SiteListPage from '../pages/SiteListPage'
import { runtimeFeaturesQueryKey } from '../components/useRuntimeFeatures'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 在 jsdom 下所有弹窗共用 aria-labelledby="test-id"，常驻的反馈弹窗（useFeedback/OutcomeUnknown）
// 挂在前面时会抢走其他弹窗的可访问名；按可见标题找当前可见的弹窗/抽屉。
const dialogsNamed = (name: string | RegExp) => screen.queryAllByRole('dialog').filter((node) => {
  const title = node.querySelector('.ant-modal-title, .ant-modal-confirm-title, .ant-drawer-title')?.textContent?.trim() ?? ''
  return typeof name === 'string' ? title === name : name.test(title)
})
const queryDialog = (name: string | RegExp) => {
  const found = dialogsNamed(name)
  if (found.length > 1) throw new Error(`multiple dialogs named ${String(name)}`)
  return found[0] ?? null
}
const getDialog = (name: string | RegExp) => {
  const found = queryDialog(name)
  if (!found) throw new Error(`no dialog named ${String(name)}`)
  return found
}
const findDialog = (name: string | RegExp, options?: { timeout?: number }) => waitFor(() => getDialog(name), options)

const site: SiteListItem = {
  id: 'site-1',
  display_id: '27',
  version: 7,
  owner: { id: 'tenant-1', display_id: '2', display_name: 'jason' },
  domain: 'www.example.com',
  listen_ports: ['80', '443'],
  origins: ['192.0.2.10:80'],
  cname: 'edge.example.net',
  https_enabled: true,
  package: { id: 'package-1', name: '基础套餐' },
  group_name: '默认分组',
  region: { name: '中国大陆', node_group_name: '主线路' },
  status: 'active',
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  created_at: '2026-07-22T08:00:00Z',
}

const tenantAID = '22222222-2222-4222-8222-222222222222'
const tenantBID = '77777777-7777-4777-8777-777777777777'
const tenantAUserID = '11111111-1111-4111-8111-111111111111'
const tenantBUserID = '88888888-8888-4888-8888-888888888888'
const resourceUser: ManagedUser = {
  id: tenantAUserID, display_id: '27', scope_id: tenantAID, tenant_id: tenantBID,
  username: 'tenant-a', display_name: 'Tenant A User', email: null, phone: null,
  status: 'active', role: 'tenant_owner', group_id: null, group_name: null, revision: 1,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}
function response(items: SiteListItem[] = [site], total = items.length): Response {
  const body: SiteListResponse = { items, total, page: 1, limit: 10 }
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function detailFor(item: SiteListItem = site, version = 7): SiteDetail {
  return {
    id: item.id,
    version,
    owner: item.owner,
    created_at: item.created_at,
    updated_at: '2026-07-22T09:00:00Z',
    lock: item.lock,
    listener_state: item.listener_state,
    origin_pool: {
      origins: item.origins.map((origin) => {
        const [host, rawPort] = origin.split(':')
        return { host, port: Number(rawPort || 80), weight: 1, enabled: true }
      }),
      balance_method: 'round_robin',
      failover_tries: 1,
      connect_timeout_ms: 3000,
      read_timeout_ms: 30000,
    },
    basic: {
      package_id: item.package?.id ?? null,
      package_subscription_id: null,
      cname_mode: '',
      cname_domain: '',
      cname_hostname: '',
      package_name: item.package?.name ?? null,
      group_id: null,
      group_name: item.group_name,
      domains: [item.domain],
      http_enabled: true,
      http_listen_ports: ['80'],
      https_listen_ports: item.https_enabled ? ['443'] : [],
      ipv6_enabled: item.listener_state.ipv6_desired_enabled,
      tls_protocols: ['TLSv1.2', 'TLSv1.3'],
      origins: item.origins,
      cname: item.cname,
      cname_state: null,
      cname_task_id: null,
      cname_current_revision: null,
      cname_lkg_revision: null,
      https_enabled: item.https_enabled,
      enabled: item.status !== 'disabled',
      status: item.status,
      sync_status: 'synced',
      is_default: false,
    },
  }
}

function changedDetail(item: SiteListItem, version: number, enabled: boolean): SiteDetail {
  const detail = detailFor(item, version)
  return {
    ...detail,
    basic: {
      ...detail.basic,
      enabled,
      status: enabled ? 'active' : 'disabled',
    },
  }
}

function createdSite(domain = 'new.example.com', origin = 'origin.example.com:8080'): SiteListItem {
  return {
    ...site,
    id: '33333333-3333-7333-8333-333333333333',
    version: 1,
    owner: null,
    domain,
    listen_ports: ['80'],
    origins: [origin],
    cname: '',
    https_enabled: false,
    package: null,
    group_name: null,
    region: null,
    status: 'active',
  }
}

function createdDetail(domain = 'new.example.com', origin = 'origin.example.com:8080'): SiteDetail {
  const detail = detailFor(createdSite(domain, origin), 1)
  return {
    ...detail,
    basic: { ...detail.basic, sync_status: 'pending' },
  }
}

function authenticate(role: 'admin' | 'user', permissions?: string[]) {
  const user = principal(
    role === 'admin'
      ? {
          scope_kind: 'platform',
          tenant_id: null,
          username: 'admin',
          display_name: 'admin',
          roles: ['platform_admin'],
          permissions: permissions ?? ['sites.read', 'sites.manage'],
        }
      : { permissions: permissions ?? ['sites.read', 'sites.manage'] },
  )
  useSessionStore.getState().setSession(authResponse(user), user)
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
  const scopeID = options.scopeID ?? (kind === 'tenant' ? tenantAID : 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
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
  const auth = authResponse(actor)
  useSessionStore.getState().setSession(
    { ...auth, access_token: options.accessToken ?? auth.access_token },
    actor,
    options.update,
  )
  const sessionEpoch = useSessionStore.getState().sessionEpoch
  return {
    actor,
    sessionEpoch,
    owner: [actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch] as const,
    role: kind === 'platform' ? 'admin' as const : 'user' as const,
  }
}

function QueryClientCapture({ capture }: { capture: (queryClient: QueryClient) => void }) {
  capture(useQueryClient())
  return null
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}{location.search}</output>
}

function renderPageWithQueryClient() {
  let queryClient: QueryClient | undefined
  const result = renderWithProviders(
    <><QueryClientCapture capture={(client) => { queryClient = client }} /><SiteListPage /></>,
    ['/site/list'],
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

function authorization(init?: RequestInit): string {
  return (init?.headers as Record<string, string> | undefined)?.Authorization ?? ''
}

function columnNames(): string[] {
  return screen.getAllByRole('columnheader').map((header) => header.textContent?.trim() ?? '')
}

beforeEach(() => {
  sessionStorage.clear()
  localStorage.removeItem('cdnca.advancedFilters.site-list')
})

describe('SiteListPage', () => {
  // WEB-C01/C05: HTTPS on without a bound certificate is not shown green.
  it('WEB-C01: shows HTTPS without a certificate as needing one, not as a green "on"', async () => {
    setSiteSession()
    const bound: SiteListItem = { ...site, id: 'site-bound', domain: 'bound.example.com', https_enabled: true, https_certificate_bound: true }
    const missing: SiteListItem = { ...site, id: 'site-missing', domain: 'missing.example.com', https_enabled: true, https_certificate_bound: false }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([bound, missing]))
    renderWithProviders(<SiteListPage />, ['/site/list'])

    const needed = await screen.findByText('待配置证书')
    expect(needed.closest('.ant-tag')).toHaveClass('ant-tag-warning')
    const on = screen.getByText('已开启')
    expect(on.closest('.ant-tag')).toHaveClass('ant-tag-success')
  })

  // 社区版：网站不绑定套餐，无套餐不再标"暂不可用"；接入缺口按线路/CNAME/证书说明（FLOW001）。
  it('a site without a package is not marked unavailable', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
    const noPackage: SiteListItem = { ...site, id: 'site-nopkg', domain: 'nopkg.example.com', cname: 'abc123.cdn.example.net',
      cname_state: 'done', package: null, package_subscription_id: null }
    const generating: SiteListItem = { ...site, id: 'site-gen', domain: 'gen.example.com', cname: '', cname_state: 'pending' }
    const noCert: SiteListItem = { ...site, id: 'site-nocert', domain: 'nocert.example.com', https_enabled: true, https_certificate_bound: false }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([noPackage, site, generating, noCert]))
    renderWithProviders(<SiteListPage />, ['/site/list'])

    const row = await screen.findByText('nopkg.example.com').then((element) => element.closest('tr')!)
    expect(within(row).getByText('abc123.cdn.example.net')).toBeInTheDocument()
    expect(within(row).queryByTestId('site-no-package')).not.toBeInTheDocument()
    expect(within(row).queryByText('使用平台默认线路')).not.toBeInTheDocument()
    expect(within(row).queryByTestId('site-access-gap')).not.toBeInTheDocument()
    const packaged = screen.getByText('www.example.com').closest('tr')!
    expect(within(packaged).queryByTestId('site-no-package')).not.toBeInTheDocument()
    expect(within(packaged).queryByTestId('site-access-gap')).not.toBeInTheDocument()
    const pending = screen.getByText('gen.example.com').closest('tr')!
    expect(within(pending).getByTestId('site-access-gap')).toHaveTextContent('接入未就绪：CNAME 未生成')
    const cert = screen.getByText('nocert.example.com').closest('tr')!
    expect(within(cert).getByTestId('site-access-gap')).toHaveTextContent('接入未就绪：HTTPS 缺证书')
  })

  // 服务端 access_readiness 优先于前端推导（节点离线、解析未指向等前端看不到的事实）。
  it('the status column shows the server access readiness', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
    const checks = (failing: Record<string, string>) => (['package', 'line_group', 'cname_generated', 'dns_resolved', 'https_cert', 'published'] as const)
      .map((code) => ({ code, ok: !(code in failing), detail: failing[code] ?? '', checked_at: '2026-10-27T12:00:00Z' }))
    const offline: SiteListItem = { ...site, id: 'site-offline', domain: 'offline.example.com',
      access_readiness: { state: 'blocked', checks: checks({ line_group: 'no_online_nodes' }) } }
    const ready: SiteListItem = { ...site, id: 'site-ready', domain: 'ready.example.com',
      access_readiness: { state: 'ready', checks: checks({}) } }
    const dns: SiteListItem = { ...site, id: 'site-dns', domain: 'dns.example.com',
      access_readiness: { state: 'pending', checks: checks({ dns_resolved: 'dns_points_elsewhere' }) } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([offline, ready, dns]))
    renderWithProviders(<SiteListPage />, ['/site/list'])

    const row = await screen.findByText('offline.example.com').then((element) => element.closest('tr')!)
    expect(within(row).getByTestId('site-access-status')).toHaveTextContent('接入受阻：线路无在线节点')
    expect(within(row).queryByTestId('site-access-gap')).not.toBeInTheDocument()
    expect(within(screen.getByText('ready.example.com').closest('tr')!).getByTestId('site-access-status')).toHaveTextContent('接入已就绪')
    expect(within(screen.getByText('dns.example.com').closest('tr')!).getByTestId('site-access-status'))
      .toHaveTextContent('接入未就绪：域名未解析到 CNAME')
  })

  it('FLOW001: a tenant whose CNAME failed for want of a line is told to contact the administrator, not sent to 节点管理', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
    const failed: SiteListItem = { ...site, id: 'site-noline', domain: 'noline.example.com', cname: '', cname_state: 'failed',
      cname_failure_code: 'cname_no_default_line_group', package: null, package_subscription_id: null }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([failed]))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    const row = await screen.findByText('noline.example.com').then((element) => element.closest('tr')!)
    expect(within(row).queryByTestId('site-no-package')).not.toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: /生成失败/ }))
    const dialog = await screen.findByRole('dialog', { name: 'CNAME 生成失败' })
    expect(within(dialog).getByTestId('cname-failure-text')).toHaveTextContent('平台尚未配置可用线路，请联系管理员')
    expect(within(dialog).queryByText(/节点管理/)).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '联系管理员（提交工单）' })).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: '去线路组' })).not.toBeInTheDocument()
  })

  it('cname-retry: shows why CNAME generation failed, offers regenerate, and shows generating', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
    const failed: SiteListItem = { ...site, id: 'site-failed', domain: 'failed.example.com', cname: '',
      cname_state: 'failed', cname_failure_code: 'cname_zone_not_configured', cname_domain: 'cdn.cdnca.com' }
    const pending: SiteListItem = { ...site, id: 'site-pending', domain: 'pending.example.com', cname: '', cname_state: 'pending' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([failed, pending]))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])

    const cell = await screen.findByTestId('site-cname-failed')
    expect(screen.getByText('生成中')).toBeInTheDocument()
    // ui-feedback-modal: a 生成失败 mark in the CNAME cell; reason, code and actions open in a dialog.
    expect(cell).toHaveTextContent('生成失败')
    expect(cell).not.toHaveTextContent('cname_zone_not_configured')
    await user.click(within(cell).getByRole('button', { name: '生成失败：套餐 CNAME 域名 cdn.cdnca.com 未在 DNS 配置的 CNAME 域名里，点击查看原因' }))
    const reason = await findDialog('CNAME 生成失败')
    expect(reason).toHaveTextContent('套餐 CNAME 域名 cdn.cdnca.com 未在 DNS 配置的 CNAME 域名里')
    // 10-27 用户：失败弹窗里的「重新生成」就是确认，直接提交，不再弹确认框。
    const posts = vi.mocked(globalThis.fetch).mock.calls.length
    await user.click(within(reason).getByRole('button', { name: '重新生成' }))
    await waitFor(() => expect(vi.mocked(globalThis.fetch).mock.calls.slice(posts)
      .some(([url, init]) => String(url) === '/v1/sites/batch-action' && init?.method === 'POST')).toBe(true))
    expect(screen.queryByText('重新生成 failed.example.com 的 CNAME')).not.toBeInTheDocument()
  })

  describe('a row CNAME regeneration with a 500 answer', () => {
    const failed: SiteListItem = { ...site, id: 'site-failed', domain: 'ikvm.asia', cname: '',
      cname_state: 'failed', cname_failure_code: 'dns_reconcile_unavailable', cname_domain: '' }
    const other: SiteListItem = { ...site, id: 'site-other', domain: 'other.example.com' }
    const p1134 = () => jsonResponse({ error: { code: 'internal_error', message: 'internal error' } }, 500)

    async function regenerateFromRow(user: ReturnType<typeof userEvent.setup>) {
      const cell = await screen.findByTestId('site-cname-failed')
      await user.click(within(cell).getByRole('button', { name: /^生成失败：/ }))
      await user.click(within(await findDialog('CNAME 生成失败')).getByRole('button', { name: '重新生成' }))
    }

    // 点确认重新生成后、请求返回前不得闪出「结果待确认」提示条/弹窗或失败态，
    // 只显示确认按钮的 loading；结果返回后再显示结果弹窗。
    it('shows only loading while the regeneration request is in flight', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true })
      try {
        setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
        const queued = detailFor(failed, 8)
        queued.basic = { ...queued.basic, cname_state: 'pending', cname_task_id: '99999999-9999-4999-8999-999999999999' }
        vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
          const url = String(input)
          if (url.startsWith('/v1/sites?')) return Promise.resolve(response([failed, other]))
          if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
            return new Promise((resolve) => setTimeout(() =>
              resolve(jsonResponse({ items: [{ id: failed.id, status: 'queued', site: queued }] })), 3000))
          }
          return Promise.reject(new Error(`unexpected request ${url}`))
        })
        const user = userEvent.setup({ delay: null, advanceTimers: vi.advanceTimersByTime })
        renderWithProviders(<SiteListPage />, ['/site/list'])
        await regenerateFromRow(user)

        await vi.advanceTimersByTimeAsync(1000)
        // 只弹一次框：确认框不再出现，请求中也不闪结果待确认/失败态
        expect(screen.queryByText('重新生成 ikvm.asia 的 CNAME')).not.toBeInTheDocument()
        expect(document.querySelector('.cdnca-outcome-bar')).toBeNull()
        expect(screen.queryByText(/重新生成结果待确认/)).not.toBeInTheDocument()
        expect(dialogsNamed(/./).filter((node) => node.closest('.cdnca-feedback'))).toHaveLength(0)
        expect(document.querySelector('.ant-alert-error, .ant-tag-error')).toBeNull()
        // 刷新页面仍能找回这次请求：重试记录已落盘
        expect(sessionStorage).toHaveLength(1)

        await vi.advanceTimersByTimeAsync(3000)
        // 成功只给轻提示，不再弹结果框
        expect(await screen.findByText('已开始重新生成 ikvm.asia 的 CNAME')).toBeInTheDocument()
        expect(screen.queryByText('ikvm.asia 的 CNAME 重新生成结果')).not.toBeInTheDocument()
        expect(document.querySelector('.cdnca-outcome-bar')).toBeNull()
        expect(sessionStorage).toHaveLength(0)
      } finally {
        vi.useRealTimers()
      }
    })

    it('shows a definite failure, without the page lock, when the site is unchanged', async () => {
      setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([failed, other]))
        if (url === '/v1/sites/batch-action' && init?.method === 'POST') return Promise.resolve(p1134())
        return Promise.reject(new Error(`unexpected request ${url}`))
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await regenerateFromRow(user)

      await waitFor(() => expect(sessionStorage).toHaveLength(0))
      expect(screen.queryByText('批量操作结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText(/重新生成结果待确认/)).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: '添加网站' })).toBeEnabled()
      expect(screen.getByRole('button', { name: /更多操作/ })).toBeEnabled()
      const lookups = fetchSpy.mock.calls.filter(([url]) => String(url).includes('site_ids='))
      expect(lookups).toHaveLength(1)
      expect(String(lookups[0][0])).toContain('site_ids=site-failed')
      expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(1)
    })

    it('replays the same idempotency key when the site changed, and shows the stored result', async () => {
      setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
      const taskID = '99999999-9999-4999-8999-999999999999'
      const queued = detailFor(failed, 8)
      queued.basic = { ...queued.basic, cname_state: 'pending', cname_task_id: taskID }
      let writes = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.includes('site_ids=')) return Promise.resolve(response([{ ...failed, version: 8, cname_state: 'pending' }]))
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([failed, other]))
        if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
          writes += 1
          return Promise.resolve(writes === 1 ? p1134()
            : jsonResponse({ items: [{ id: failed.id, status: 'queued', site: queued }] }))
        }
        return Promise.reject(new Error(`unexpected request ${url}`))
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await regenerateFromRow(user)

      expect(await screen.findByText('已开始重新生成 ikvm.asia 的 CNAME')).toBeInTheDocument()
      const posts = fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')
      expect(posts).toHaveLength(2)
      const keys = posts.map(([, init]) => (init?.headers as Record<string, string>)['Idempotency-Key'])
      expect(keys[0]).toBe(keys[1])
      expect(posts[1][1]?.body).toBe(posts[0][1]?.body)
      expect(sessionStorage).toHaveLength(0)
    })

    it('keeps other writes available on an unknown outcome and discards it after confirmation', async () => {
      setSiteSession({ permissions: ['sites.read', 'sites.manage', 'dns.manage'] })
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.includes('site_ids=')) return Promise.resolve(jsonResponse({ error: { code: 'unavailable' } }, 503))
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([failed, other]))
        if (url === '/v1/sites/batch-action' && init?.method === 'POST') return Promise.resolve(p1134())
        return Promise.reject(new Error(`unexpected request ${url}`))
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await regenerateFromRow(user)

      expect(await screen.findByText('ikvm.asia 的 CNAME 重新生成结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
      expect(sessionStorage).toHaveLength(1)
      // only new batch writes wait; the rest of the page stays usable
      expect(screen.getByRole('button', { name: '添加网站' })).toBeEnabled()
      expect(screen.getByRole('checkbox', { name: other.domain })).toBeEnabled()
      expect(within(screen.getByRole('row', { name: /other\.example\.com/ })).getByRole('button', { name: '管理' })).toBeEnabled()
      expect(screen.getByRole('button', { name: '批量修改' })).toBeDisabled()

      const listsBefore = fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites?page')).length
      await user.click(screen.getByRole('button', { name: '放弃这次结果' }))
      const confirm = await screen.findByText('放弃后不再跟踪这次请求，列表会按服务端的实际状态刷新。确认放弃？')
      expect(sessionStorage).toHaveLength(1)
      const popover = confirm.closest('.ant-popover') as HTMLElement
      await user.click(within(popover).getByRole('button', { name: '放弃这次结果' }))

      await waitFor(() => expect(screen.queryByText(/重新生成结果待确认/)).not.toBeInTheDocument())
      expect(sessionStorage).toHaveLength(0)
      expect(screen.getByRole('button', { name: '批量修改' })).toBeEnabled()
      await waitFor(() => expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites?page')).length).toBeGreaterThan(listsBefore))
      expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(1)
    })
  })

  // N22: a pending CNAME is polled every 2 s (at most 60 s) so the address
  // shows without a manual refresh; polling stops once it is done.
  it('n22: polls the list while a CNAME is pending and stops when it is done', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      setSiteSession()
      const pending: SiteListItem = { ...site, id: 'site-pending', domain: 'pending.example.com', cname: '', cname_state: 'pending' }
      const done: SiteListItem = { ...pending, cname: 'k3x9.cdn.example.com', cname_state: 'done' }
      const lists = () => fetchSpy.mock.calls.filter(([input]) => String(input).startsWith('/v1/sites?')).length
      let calls = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
        if (!String(input).startsWith('/v1/sites?')) return response()
        calls += 1
        return response([calls < 3 ? pending : done])
      })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      expect(await screen.findByText('生成中')).toBeInTheDocument()
      await vi.advanceTimersByTimeAsync(2000)
      await vi.advanceTimersByTimeAsync(2000)
      expect(await screen.findByText('k3x9.cdn.example.com')).toBeInTheDocument()
      const afterDone = lists()
      await vi.advanceTimersByTimeAsync(10000)
      expect(lists()).toBe(afterDone)
    } finally {
      vi.useRealTimers()
    }
  })

  // O2 (live-site2 10-22): a tenant's site list says why its latest automatic
  // publication has not reached the nodes (node artifacts still syncing,
  // with progress), not that the nodes lack capabilities.
  it('shows the automatic publication waiting for node artifacts', async () => {
    setSiteSession()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).startsWith('/v1/site-publications')
      ? jsonResponse({
        items: [], current_source_revision: 11,
        automatic_failure: {
          reason: 'node_artifacts_syncing', source_revision: 11, failed_at: '2026-10-22T04:47:48Z',
          artifact_sync: { received_segments: 7, total_segments: 21, remaining_minutes: 15 },
        },
      })
      : response())
    renderWithProviders(<SiteListPage />, ['/site/list'])
    const notice = await screen.findByTestId('site-list-automatic-failure')
    expect(notice).toHaveTextContent('自动发布未下发：节点制品同步中（已收 7/21，预计还需 15 分钟）')
    expect(notice).not.toHaveTextContent('节点能力不足')
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/site-publications?limit=1')).toBe(true)
  })

  it('opens the real certificate workflow with selected site domains', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.manage', 'certificates.manage'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])

    await screen.findByText(site.domain)
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: '申请证书' }))

    expect(screen.getByTestId('location')).toHaveTextContent('/site/cert?domains=www.example.com&site=site-1')
  })

  // P3：同一用户多选带 site= 让证书页带入网站用户；跨用户提示按用户分别申请，不跳转。
  it('carries the shared owner into a multi-site certificate request and refuses mixed owners', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.manage', 'certificates.manage'] })
    const sameOwner = { ...site, id: 'site-2', display_id: '28', domain: 'api.example.com' }
    const otherOwner = { ...site, id: 'site-3', display_id: '29', domain: 'shop.example.org', owner: { id: 'tenant-9', display_id: '9', display_name: 'other' } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([site, sameOwner, otherOwner]))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])

    await screen.findByText(site.domain)
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('checkbox', { name: otherOwner.domain }))
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    expect(await screen.findByText(/^所选网站属于不同用户/)).toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent('/site/list')

    await user.click(screen.getByRole('checkbox', { name: otherOwner.domain }))
    await user.click(screen.getByRole('checkbox', { name: sameOwner.domain }))
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/site/cert?domains=www.example.com%0Aapi.example.com&site=site-1')
  })

  it('exports only the exact active tenant domain filter and downloads the returned snapshot', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.export'] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/export?domain=example.com') {
        return Promise.resolve(new Response('site_id,domain\nsite-1,www.example.com\n', {
          status: 200,
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': 'attachment; filename="site-domains.csv"',
            'X-Site-Domain-Export-Snapshot-ID': '01999999-9999-7999-8999-999999999999',
          },
        }))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const NativeURL = URL
    const createObjectURL = vi.fn().mockReturnValue('blob:site-domain-export')
    const revokeObjectURL = vi.fn()
    class TestURL extends NativeURL {
      static createObjectURL = createObjectURL
      static revokeObjectURL = revokeObjectURL
    }
    vi.stubGlobal('URL', TestURL)
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.type(screen.getByLabelText('快速搜索内容'), 'example.com')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('domain=example.com'))).toBe(true))
    await user.click(screen.getAllByRole('button', { name: '导出' })[0]!)

    expect(await screen.findByText('网站域名导出已开始')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites/export'))).toHaveLength(1)
    expect(createObjectURL).toHaveBeenCalledTimes(1)
    expect(click).toHaveBeenCalledTimes(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:site-domain-export')
    vi.unstubAllGlobals()
  })

  it('exports the exact advanced tenant filters supported by the snapshot contract', async () => {
    setSiteSession({ permissions: ['sites.read', 'sites.export'] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/export?http_port=8080') {
        return Promise.resolve(new Response('site_id,domain\n', {
          status: 200,
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': 'attachment; filename="site-domains.csv"',
            'X-Site-Domain-Export-Snapshot-ID': '01999999-9999-7999-8999-999999999999',
          },
        }))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const createObjectURL = vi.fn().mockReturnValue('blob:advanced-site-export')
    const NativeURL = URL
    class TestURL extends NativeURL {
      static createObjectURL = createObjectURL
      static revokeObjectURL = vi.fn()
    }
    vi.stubGlobal('URL', TestURL)
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    await user.type(within(advanced).getByLabelText('HTTP监听端口'), '8080')
    await user.click(within(advanced).getByRole('button', { name: '应用' }))
    await user.click(screen.getAllByRole('button', { name: '导出' })[0]!)

    expect(await screen.findByText('网站域名导出已开始')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites/export'))).toHaveLength(1)
    expect(createObjectURL).toHaveBeenCalledTimes(1)
    vi.unstubAllGlobals()
  })

  it('W1: platform export asks for the target tenant and sends target_scope_id', async () => {
    authenticate('admin', ['sites.read', 'sites.export', 'identity.users.manage'])
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [resourceUser], page: 1, limit: 20, total: 1 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).startsWith('/v1/sites/export')
      ? new Response('domain\n', { status: 200, headers: {
        'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="sites.csv"',
        'X-Site-Domain-Export-Snapshot-ID': '99999999-9999-4999-8999-999999999999' } })
      : response())
    const NativeURL = URL
    class TestURL extends NativeURL {
      static createObjectURL = vi.fn(() => 'blob:sites')
      static revokeObjectURL = vi.fn()
    }
    vi.stubGlobal('URL', TestURL)
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getAllByRole('button', { name: '导出' })[0]!)
    const dialog = await findDialog('选择导出的租户')
    expect(document.body).not.toHaveTextContent('合同字段')
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites/export'))).toHaveLength(0)
    await user.click(within(dialog).getByRole('combobox', { name: '目标租户' }))
    await user.click(await screen.findByText('tenant-a（27）'))
    await user.click(within(dialog).getByRole('button', { name: '导出' }))

    expect(await screen.findByText('网站域名导出已开始')).toBeInTheDocument()
    const exports = fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites/export'))
    expect(exports).toHaveLength(1)
    expect(String(exports[0]![0])).toContain(`target_scope_id=${tenantAID}`)
    vi.unstubAllGlobals()
  })

  it('W1: owner name links to the user list filtered by that user, without a package column', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><SiteListPage /><LocationProbe /></>, ['/site/list'])
    await screen.findByText(site.domain)
    expect(within(screen.getByTestId('site-table-scroll')).queryByText('基础套餐')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'jason (2)' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/sys/user?display_id=2')
    expect(document.body).not.toHaveTextContent('用户详情暂不可用')
  })

  it('renders administrator-only owner and region columns', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('www.example.com')).toBeInTheDocument()
    expect(screen.getByLabelText(site.display_id)).toHaveTextContent(site.display_id)
    expect(screen.getByLabelText(site.display_id)).not.toHaveTextContent(site.id)
    expect(columnNames()).toEqual(expect.arrayContaining([
      'ID', '域名', 'CNAME', 'HTTPS', '源站 / 监听', '分组', '区域', '状态', '添加时间', '操作',
    ]))
    expect(columnNames()).not.toEqual(expect.arrayContaining(['用户', '监听端口', '源站', '套餐', '套餐/分组']))
    expect(screen.getByText('jason (2)')).toBeInTheDocument()
    expect(screen.queryByText(/jason \(tenant-1\)/)).not.toBeInTheDocument()
    // 添加时间日期、时间分两行显示。
    expect(screen.getByText('2026-07-22')).toBeInTheDocument()
    expect(screen.getByText('16:00:00')).toBeInTheDocument()
    const rowMore = screen.getByRole('button', { name: '更多' })
    expect(rowMore).toHaveClass('site-row-more-button')
    expect(rowMore).toHaveTextContent('')
  })

  it('omits administrator columns for tenant users', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('www.example.com')).toBeInTheDocument()
    expect(columnNames()).not.toContain('用户')
    expect(columnNames()).not.toContain('区域')
    expect(columnNames()).toEqual(expect.arrayContaining(['源站 / 监听', '分组', '状态']))
  })

  it('shows locked_at state and reason to tenants without exposing lock controls', async () => {
    authenticate('user')
    const lockedSite: SiteListItem = {
      ...site,
      status: 'active',
      lock: {
        locked: true,
        reason: '账户归属复核',
        locked_at: '2026-07-22T09:10:00Z',
        operator: { display_name: '平台管理员' },
      },
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([lockedSite]))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('账户归属复核')).toBeInTheDocument()
    expect(screen.getByText('已锁定')).toBeInTheDocument()
    expect(screen.queryByText('正常')).not.toBeInTheDocument()
    const row = screen.getByText(lockedSite.domain).closest('tr')
    if (!row) throw new Error('locked site row is missing')
    expect(within(row).getByRole('checkbox', { name: lockedSite.domain })).toBeDisabled()
    expect(within(row).getByRole('button', { name: '管理' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '更多' }))
    expect(screen.queryByText(/^锁定网站/)).not.toBeInTheDocument()
    expect(screen.queryByText(/^解锁网站/)).not.toBeInTheDocument()
    expect(screen.getByText('停用网站（节点停止服务）').closest('li')).toHaveAttribute('aria-disabled', 'true')
    expect(screen.queryByText('启用网站（恢复节点服务）')).not.toBeInTheDocument()
    expect(screen.getByText('删除').closest('li')).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByText('已锁定').closest('.ant-tag')?.querySelector('.site-status-lock-icon')).not.toBeNull()
  })

  it('locks and unlocks from the administrator list with latest revisions and reasons', async () => {
    authenticate('admin')
    let latest = detailFor(site, 7)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) {
        return Promise.resolve(
          response([{ ...site, status: latest.basic.status, lock: latest.lock }]),
        )
      }
      if (url === '/v1/sites/site-1' && !init?.method) {
        return Promise.resolve(jsonResponse(latest))
      }
      if (url.endsWith('/lock') && init?.method === 'POST') {
        latest = {
          ...latest,
          version: 8,
          lock: {
            locked: true,
            reason: '账户归属复核',
            locked_at: '2026-07-22T09:10:00Z',
            operator: { display_name: '平台管理员' },
          },
        }
        return Promise.resolve(jsonResponse(latest))
      }
      if (url.endsWith('/unlock') && init?.method === 'POST') {
        latest = {
          ...latest,
          version: 9,
          lock: { locked: false, reason: null, locked_at: null, operator: null },
        }
        return Promise.resolve(jsonResponse(latest))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText('www.example.com')

    await user.click(screen.getByRole('button', { name: '更多' }))
    await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
    const lockDialog = await findDialog('锁定网站')
    expect(within(lockDialog).getByText(/^锁定后网站继续正常服务/)).toBeInTheDocument()
    await user.type(within(lockDialog).getByLabelText('锁定原因'), '账户归属复核')
    await user.click(within(lockDialog).getByRole('button', { name: '确认锁定' }))

    expect(await screen.findByText('网站 www.example.com 已锁定')).toBeInTheDocument()
    expect(screen.getByText('已锁定')).toBeInTheDocument()
    expect(screen.getByText('账户归属复核')).toBeInTheDocument()
    const lockCall = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/lock'))
    expect(lockCall?.[1]).toMatchObject({ method: 'POST' })
    expect(JSON.parse(String(lockCall?.[1]?.body))).toEqual({
      expected_version: 7,
      reason: '账户归属复核',
    })
    expect(lockCall?.[1]?.headers).toEqual(
      expect.objectContaining({ 'Idempotency-Key': expect.any(String) }),
    )

    await user.click(screen.getByRole('button', { name: '更多' }))
    await user.click(await screen.findByText('解锁网站（允许用户修改）'))
    const unlockDialog = await findDialog('解锁网站')
    expect(within(unlockDialog).getByText('账户归属复核')).toBeInTheDocument()
    expect(within(unlockDialog).getByText(/平台管理员/)).toBeInTheDocument()
    await user.click(within(unlockDialog).getByRole('button', { name: '确认解锁' }))

    expect(await screen.findByText('网站 www.example.com 已解锁')).toBeInTheDocument()
    expect(screen.getByText('正常')).toBeInTheDocument()
    const unlockCall = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/unlock'))
    expect(JSON.parse(String(unlockCall?.[1]?.body))).toEqual({ expected_version: 8 })
  })

  it('honors the platform administrator wildcard for lock controls', async () => {
    authenticate('admin', ['platform.admin'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])

    await screen.findByText('www.example.com')
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    expect(screen.getByRole('button', { name: /更多操作/ })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: '更多' }))
    expect(await screen.findByText('锁定网站（继续服务，禁止用户修改）')).toBeInTheDocument()
  })

  it('locks an unknown write to the exact version, reason, body, and idempotency key', async () => {
    authenticate('admin')
    const current = detailFor(site, 4)
    const saved: SiteDetail = {
      ...current,
      version: 5,
      lock: {
        locked: true,
        reason: '异常流量调查',
        locked_at: '2026-07-22T09:20:00Z',
        operator: { display_name: '平台管理员' },
      },
    }
    let writeCount = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) {
        return Promise.resolve(
          response([{ ...site, status: saved.basic.status, lock: writeCount >= 2 ? saved.lock : site.lock }]),
        )
      }
      if (url === '/v1/sites/site-1' && !init?.method) return Promise.resolve(jsonResponse(current))
      if (url.endsWith('/lock') && init?.method === 'POST') {
        writeCount += 1
        return writeCount === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(jsonResponse(saved))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText('www.example.com')

    await user.click(screen.getByRole('button', { name: '更多' }))
    await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
    const dialog = await findDialog('锁定网站')
    const reason = within(dialog).getByLabelText('锁定原因')
    await user.type(reason, '异常流量调查')
    await user.click(within(dialog).getByRole('button', { name: '确认锁定' }))

    expect(await within(dialog).findByText('操作结果待确认')).toBeInTheDocument()
    expect(reason).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('网站 www.example.com 已锁定')).toBeInTheDocument()

    const writes = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/lock'))
    expect(writes).toHaveLength(2)
    expect(writes[0][1]?.body).toBe(writes[1][1]?.body)
    expect(writes[0][1]?.headers).toEqual(writes[1][1]?.headers)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({
      expected_version: 4,
      reason: '异常流量调查',
    })
  })

  it('requires a fresh revision after conflict and rotates the idempotency key', async () => {
    authenticate('admin')
    let detailReads = 0
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) {
        return Promise.resolve(
          response([
            {
              ...site,
              lock:
                writes >= 2
                  ? {
                      locked: true,
                      reason: '并发状态复核',
                      locked_at: '2026-07-22T09:30:00Z',
                      operator: { display_name: '平台管理员' },
                    }
                  : site.lock,
            },
          ]),
        )
      }
      if (url === '/v1/sites/site-1' && !init?.method) {
        detailReads += 1
        return Promise.resolve(jsonResponse(detailFor(site, detailReads === 1 ? 3 : 4)))
      }
      if (url.endsWith('/lock') && init?.method === 'POST') {
        writes += 1
        if (writes === 1) {
          return Promise.resolve(
            jsonResponse(
              { error: { code: 'version_conflict', message: '网站版本已变化', request_id: 'r1' } },
              409,
            ),
          )
        }
        return Promise.resolve(
          jsonResponse({
            ...detailFor(site, 5),
            lock: {
              locked: true,
              reason: '并发状态复核',
              locked_at: '2026-07-22T09:30:00Z',
              operator: { display_name: '平台管理员' },
            },
          }),
        )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText('www.example.com')

    await user.click(screen.getByRole('button', { name: '更多' }))
    await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
    const dialog = await findDialog('锁定网站')
    await user.type(within(dialog).getByLabelText('锁定原因'), '并发状态复核')
    await user.click(within(dialog).getByRole('button', { name: '确认锁定' }))
    expect(await within(dialog).findByText('网站版本已变化')).toBeInTheDocument()

    await user.click(within(dialog).getByRole('button', { name: '重新加载状态' }))
    await waitFor(() =>
      expect(within(dialog).queryByText('网站版本已变化')).not.toBeInTheDocument(),
    )
    await user.click(within(dialog).getByRole('button', { name: '确认锁定' }))
    expect(await screen.findByText('网站 www.example.com 已锁定')).toBeInTheDocument()

    const lockCalls = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/lock'))
    expect(lockCalls.map(([, init]) => JSON.parse(String(init?.body)).expected_version)).toEqual([3, 4])
    expect((lockCalls[0][1]?.headers as Record<string, string>)['Idempotency-Key']).not.toBe(
      (lockCalls[1][1]?.headers as Record<string, string>)['Idempotency-Key'],
    )
  })

  it('keeps a loading table in place and renders the empty state', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise<Response>(() => undefined))
    const { unmount } = renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(screen.getByTestId('site-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('table')).toBeInTheDocument()
    unmount()

    vi.restoreAllMocks()
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([]))
    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(screen.getByText('共 0 条')).toBeInTheDocument()
  })

  it('shows a persistent error and retries the production request', async () => {
    authenticate('user')
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: { code: 'unavailable', message: '服务暂不可用', request_id: 'request-1' },
          }),
          { status: 503, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(response([]))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('网站列表加载失败')).toBeInTheDocument()
    expect(screen.getByText('操作失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('服务暂不可用')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    // The tenant's automatic publication notice reads /v1/site-publications
    // once the list loaded (O2); the list itself was requested twice.
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites?'))).toHaveLength(2)
  })

  it('renders forbidden separately from service failures', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: 'forbidden', message: '缺少 sites.read 权限', request_id: 'request-2' },
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('无权查看网站列表')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少网站读取权限')).toBeInTheDocument()
    expect(screen.queryByText('缺少 sites.read 权限')).not.toBeInTheDocument()
    expect(screen.queryByText('网站列表加载失败')).not.toBeInTheDocument()
  })

  it.each([
    ['permission_denied', 'private list permission detail'],
    ['forbidden', 'private list forbidden detail'],
  ] as const)('makes a current-owner %s list denial terminal across token refresh', async (code, rawMessage) => {
    const session = setSiteSession({ accessToken: 'site-terminal-list-a' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ error: { code, message: rawMessage } }, 403),
    )
    const { queryClient } = renderPageWithQueryClient()
    const listKey = ['sites', session.owner, session.role, 1, 10, {}] as const

    expect(await screen.findByText('无权查看网站列表')).toBeInTheDocument()
    expect(screen.queryByText(rawMessage)).not.toBeInTheDocument()
    await waitFor(() => expect(queryClient.getQueryState(listKey)).toBeUndefined())
    const requestsBeforeRefresh = fetchSpy.mock.calls.length

    act(() => setSiteSession({ accessToken: 'site-terminal-list-b', update: 'refresh' }))
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: ['sites', session.owner], type: 'all' })
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(requestsBeforeRefresh)
    expect(screen.getByText('无权查看网站列表')).toBeInTheDocument()
  })

  it('sends quick filters, advanced filters, and pagination to GET /v1/sites', async () => {
    authenticate('admin')
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(() => Promise.resolve(response([site], 25)))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText('www.example.com')

    await user.type(screen.getByLabelText('快速搜索内容'), 'example.com')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => {
      expect(String(fetchSpy.mock.calls.at(-1)?.[0])).toContain('domain=example.com')
    })

    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    await user.type(within(advanced).getByLabelText('HTTP监听端口'), '8080')
    await user.click(within(advanced).getByRole('combobox', { name: '网站状态' }))
    await user.click(await screen.findByText('已锁定'))
    await user.click(within(advanced).getByRole('button', { name: '应用' }))
    await waitFor(() => {
      expect(String(fetchSpy.mock.calls.at(-1)?.[0])).toContain('http_port=8080')
      expect(String(fetchSpy.mock.calls.at(-1)?.[0])).toContain('status=locked')
    })

    await user.click(screen.getByTitle('2'))
    await waitFor(() => {
      expect(String(fetchSpy.mock.calls.at(-1)?.[0])).toContain('page=2')
    })
    expect(fetchSpy.mock.calls.every(([url]) => String(url).startsWith('/v1/sites?'))).toBe(true)
  })

  it('快速搜索边输入边生效；用户可输入用户名，选中联想后按用户 ID 过滤', async () => {
    authenticate('admin')
    const owner = { ...resourceUser, display_id: '20001', username: 'bob', display_name: 'bob' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).includes('/v1/admin/users?')
      ? Promise.resolve(new Response(JSON.stringify({ items: [owner], page: 1, limit: 10, total: 1 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      : Promise.resolve(response([site], 25)))
    const siteQueries = () => fetchSpy.mock.calls.map(([input]) => new URL(String(input), 'https://control.example')).filter((url) => url.pathname.endsWith('/sites'))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    const before = siteQueries().length

    await user.type(screen.getByLabelText('快速搜索内容'), 'example.com')
    await waitFor(() => expect(siteQueries().at(-1)?.searchParams.get('domain')).toBe('example.com'), { timeout: 2000 })
    expect(siteQueries().length).toBe(before + 1)

    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    await user.type(within(advanced).getByRole('combobox', { name: '用户' }), 'bo')
    await user.click(await screen.findByText('bob（20001）'))
    await waitFor(() => expect(siteQueries().at(-1)?.searchParams.get('owner')).toBe(owner.id), { timeout: 2000 })
  })

  // 只认 ID 的网站ID 输入名称即按名称参数过滤。
  it('网站ID 未选联想项时按名称过滤', async () => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(response([site], 25)))
    const siteQueries = () => fetchSpy.mock.calls.map(([input]) => new URL(String(input), 'https://control.example')).filter((url) => url.pathname.endsWith('/sites'))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    expect(within(advanced).queryByRole('combobox', { name: '基础套餐' })).not.toBeInTheDocument()
    await user.type(within(advanced).getByRole('combobox', { name: '网站ID' }), 'example')
    await waitFor(() => expect(siteQueries().at(-1)!.searchParams.get('site')).toBe('example'), { timeout: 2000 })
  })

  it('quick search stays in the row, the rest fold into 高级筛选 with count, tags and clear', async () => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(response([site], 25)))
    const lastQuery = () => new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'https://control.example').searchParams
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    // 同一行：快速搜索 + 查询 + 重置 + 高级筛选；面板默认收起。
    const toggle = screen.getByRole('button', { name: '高级筛选' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByRole('button', { name: '重置' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '高级搜索' })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('快速搜索内容'), 'example.com')
    await user.click(toggle)
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    await user.type(within(advanced).getByLabelText('HTTP监听端口'), '8080')
    await user.click(within(advanced).getByRole('combobox', { name: '网站状态' }))
    await user.click(await screen.findByText('已锁定'))
    await user.click(within(advanced).getByRole('button', { name: '应用' }))

    // 快速搜索与高级条件一起生效。
    await waitFor(() => {
      expect(lastQuery().get('domain')).toBe('example.com')
      expect(lastQuery().get('http_port')).toBe('8080')
      expect(lastQuery().get('status')).toBe('locked')
    })
    expect(screen.getByRole('button', { name: '高级筛选 · 2' })).toBeInTheDocument()
    const tags = screen.getByRole('list', { name: '已启用的高级条件' })
    expect(within(tags).getByText('网站状态：已锁定')).toBeInTheDocument()

    await user.click(within(tags).getByRole('button', { name: '移除条件 HTTP监听端口' }))
    await waitFor(() => expect(lastQuery().get('http_port')).toBeNull())
    expect(lastQuery().get('status')).toBe('locked')
    expect(lastQuery().get('domain')).toBe('example.com')
    expect(within(advanced).getByLabelText('HTTP监听端口')).toHaveValue('')

    await user.click(within(advanced).getByRole('button', { name: '清空高级条件' }))
    await waitFor(() => expect(lastQuery().get('status')).toBeNull())
    expect(lastQuery().get('domain')).toBe('example.com')
    expect(screen.getByRole('button', { name: '高级筛选' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '重置' }))
    await waitFor(() => expect(lastQuery().get('domain')).toBeNull())
    expect(screen.getByLabelText('快速搜索内容')).toHaveValue('')
  })

  it('exposes the administrator quick-search fields in reference order', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('combobox', { name: '快速搜索字段' }))
    const popup = document.querySelector('.site-quick-field-popup')
    expect(popup).not.toBeNull()
    expect(Array.from(popup!.querySelectorAll('.ant-select-item-option-content'), (item) => item.textContent)).toEqual([
      '域名', '多域名', '源IP', '网站ID', '用户ID', '区域', '线路分组',
      'CNAME域名', 'CNAME主机名', 'HTTP监听端口', 'HTTPS监听端口', 'HTTPS启用',
      '网站启用', '默认站点', '同步状态', '网站状态',
    ])
  })

  it.each([
    ['domain', '域名', 'example.com'],
    ['domains', '多域名', 'www.example.com'],
    ['origin_ip', '源IP', '192.0.2.10'],
    ['site_ids', '网站ID', '11111111-1111-4111-8111-111111111111'],
    ['owner', '用户ID', 'tenant-owner'],
    ['region_id', '区域', '33333333-3333-4333-8333-333333333333'],
    ['node_group_id', '线路分组', '44444444-4444-4444-8444-444444444444'],
    ['cname_domain', 'CNAME域名', 'edge.example.net'],
    ['cname_hostname', 'CNAME主机名', 'edge'],
    ['http_port', 'HTTP监听端口', '80'],
    ['https_port', 'HTTPS监听端口', '443'],
    ['https_enabled', 'HTTPS启用', 'true'],
    ['enabled', '网站启用', 'false'],
    ['is_default', '默认站点', 'true'],
    ['sync_status', '同步状态', 'pending'],
    ['status', '网站状态', 'locked'],
  ] as const)('sends administrator quick-search field %s through the real query key', async (key, label, value) => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    if (key !== 'domain') {
      await user.click(screen.getByRole('combobox', { name: '快速搜索字段' }))
      const popup = document.querySelector('.site-quick-field-popup')
      expect(popup).not.toBeNull()
      await user.click(within(popup as HTMLElement).getByText(label))
    }
    await user.type(screen.getByLabelText('快速搜索内容'), value)
    await user.click(screen.getByRole('button', { name: '查询' }))

    await waitFor(() => {
      const requestURL = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'https://control.example')
      expect(requestURL.searchParams.get(key)).toBe(value)
    })
  })

  it('orders administrator advanced fields and desktop more-actions in reference order', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    expect(Array.from(advanced.querySelectorAll('.cdnca-adv-filters-label'), (label) => label.textContent)).toEqual([
      '域名', '源IP', '网站ID', '用户',
      '多域名', '区域', '线路分组',
      'CNAME域名', 'CNAME主机名', 'HTTP监听端口', 'HTTPS监听端口',
      'HTTPS启用', '网站启用', '默认站点', '同步状态', '网站状态',
    ])

    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    const menu = document.querySelector('.site-toolbar-more-popup')
    expect(menu).not.toBeNull()
    expect(Array.from(
      menu!.querySelectorAll('.ant-dropdown-menu-item:not(.site-more-mobile-only)'),
      (item) => item.textContent,
    )).toEqual([
      '启用', '禁用', '删除', '解锁黑名单', '清空缓存', '设置状态', 'CNAME域名', 'CNAME模式', '线路分组',
    ])
  })

  it('routes supported single-site more-actions to their real workflows', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><SiteListPage /><LocationProbe /></>, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('checkbox', { name: site.domain }))

    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('清空缓存'))
    expect(screen.getByTestId('location')).toHaveTextContent(`/site/cache-clean?site_id=${site.id}`)
  })

  it('drops the clear-cache action once the shell reports the cache-control runtime off', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient()
    act(() => { queryClient.setQueryData(runtimeFeaturesQueryKey, ['custom_rbac']) })
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    expect(await screen.findByText('解锁黑名单')).toBeInTheDocument()
    expect(screen.queryByText('清空缓存')).not.toBeInTheDocument()
  })

  it('routes set-status through the current site version and real basic update contract', async () => {
    authenticate('admin')
    const current = detailFor(site, 7)
    const saved: SiteDetail = {
      ...current,
      version: 8,
      basic: { ...current.basic, status: 'package_expired', enabled: true },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/site-1' && !init?.method) return Promise.resolve(jsonResponse(current))
      if (url === '/v1/sites/site-1' && init?.method === 'PATCH') return Promise.resolve(jsonResponse(saved))
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('设置状态'))
    const dialog = await findDialog('设置网站状态')
    await user.click(within(dialog).getByRole('combobox', { name: '网站状态' }))
    await user.click(await screen.findByText('套餐过期'))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('已为 1 个网站设置状态')).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/sites/site-1' && init?.method === 'PATCH')
    expect(JSON.parse(String(write?.[1]?.body))).toMatchObject({
      expected_version: 7,
      section: 'basic',
      changes: { enabled: true, status: 'package_expired' },
    })
    expect(write?.[1]?.headers).toEqual(expect.objectContaining({ 'Idempotency-Key': expect.any(String) }))
  })

  it.each([
    ['enable', '启用网站（恢复节点服务）', '批量启用', '确认启用', 'updated', true],
    ['disable', '停用网站（节点停止服务）', '批量禁用', '确认禁用', 'updated', false],
    ['delete', '删除', '批量删除', '确认删除', 'deleted', false],
  ] as const)(
    'routes the single-row %s action through the durable site mutation',
    async (action, menuLabel, dialogTitle, confirmLabel, status, enabled) => {
      authenticate('admin')
      const listed = action === 'enable' ? { ...site, status: 'disabled' as const } : site
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([listed]))
        if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
          return Promise.resolve(jsonResponse({
            items: [{
              id: site.id,
              status,
              ...(status === 'updated' ? { site: changedDetail(site, 8, enabled) } : {}),
            }],
          }))
        }
        return Promise.reject(new Error(`unexpected request ${url}`))
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)

      await user.click(screen.getByRole('button', { name: '更多' }))
      await user.click(await screen.findByText(menuLabel))
      const finalDialog = await findDialog(dialogTitle)
      // L2：启用/停用确认框写明对节点服务的影响。
      if (action === 'disable') expect(within(finalDialog).getByText(/^停用后节点停止服务这些网站/)).toBeInTheDocument()
      if (action === 'enable') expect(within(finalDialog).getByText('启用后节点恢复服务这些网站。')).toBeInTheDocument()
      if (action === 'delete') {
        // 单站删除只确认一次：写明域名与后果，确认按钮为 danger。
        expect(within(finalDialog).getByText(`确定删除网站 ${site.domain}？`)).toBeInTheDocument()
        expect(within(finalDialog).getByText(/^删除后无法恢复。系统会撤下这些网站自己的 CNAME 解析记录/)).toBeInTheDocument()
        expect(within(finalDialog).getByRole('button', { name: confirmLabel })).toHaveClass('ant-btn-dangerous')
      }
      await user.click(within(finalDialog).getByRole('button', { name: confirmLabel }))

      expect(await findDialog('批量操作结果')).toBeInTheDocument()
      const writes = fetchSpy.mock.calls.filter(
        ([url, init]) => String(url) === '/v1/sites/batch-action' && init?.method === 'POST',
      )
      expect(writes).toHaveLength(1)
      expect(JSON.parse(String(writes[0][1]?.body))).toEqual({
        action,
        items: [{ id: site.id, expected_version: site.version }],
      })
      expect(writes[0][1]?.headers).toEqual(
        expect.objectContaining({ 'Idempotency-Key': expect.any(String) }),
      )
      expect(screen.queryByText(`${menuLabel}网站 ${site.domain}暂不可用`)).not.toBeInTheDocument()
    },
  )

  it('submits selected sites in order with their list versions', async () => {
    authenticate('admin')
    const second: SiteListItem = {
      ...site,
      id: 'site-2',
      version: 11,
      domain: 'api.example.com',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site, second]))
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(
          jsonResponse({
            items: [
              { id: site.id, status: 'updated', site: changedDetail(site, 8, false) },
              { id: second.id, status: 'updated', site: changedDetail(second, 12, false) },
            ],
          }),
        )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('checkbox', { name: second.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('禁用'))
    const confirm = await findDialog('批量禁用')
    expect(within(confirm).getByText(`${site.domain}、${second.domain}`)).toBeInTheDocument()
    await user.click(within(confirm).getByRole('button', { name: '确认禁用' }))

    const result = await findDialog('批量操作结果')
    expect(within(result).getByText(site.domain)).toBeInTheDocument()
    expect(within(result).getByText(second.domain)).toBeInTheDocument()
    expect(within(result).getAllByText('已禁用')).toHaveLength(2)
    const write = fetchSpy.mock.calls.find(([url]) => String(url) === '/v1/sites/batch-action')
    expect(JSON.parse(String(write?.[1]?.body))).toEqual({
      action: 'disable',
      items: [
        { id: site.id, expected_version: 7 },
        { id: second.id, expected_version: 11 },
      ],
    })
    expect(write?.[1]?.headers).toEqual(
      expect.objectContaining({ 'Idempotency-Key': expect.any(String) }),
    )
    expect(screen.getByRole('checkbox', { name: site.domain })).not.toBeChecked()
  })

  it('renders ordered successes and stable item failure codes', async () => {
    authenticate('admin')
    const second: SiteListItem = {
      ...site,
      id: 'site-2',
      version: 4,
      domain: 'stale.example.com',
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site, second]))
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(
          jsonResponse({
            items: [
              { id: site.id, status: 'updated', site: changedDetail(site, 8, true) },
              { id: second.id, status: 'failed', error: { code: 'version_conflict' } },
            ],
          }),
        )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('checkbox', { name: second.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('启用'))
    await user.click(
      within(await findDialog('批量启用')).getByRole('button', {
        name: '确认启用',
      }),
    )

    const result = await findDialog('批量操作结果')
    expect(within(result).getByText('已启用')).toBeInTheDocument()
    expect(within(result).getByText('网站版本已变化')).toBeInTheDocument()
    expect(within(result).queryByText('version_conflict')).not.toBeInTheDocument()
    expect(within(result).getByText(site.domain)).toBeInTheDocument()
    expect(within(result).getByText(second.domain)).toBeInTheDocument()

    await user.click(within(result).getByRole('button', { name: '重试失败项' }))
    const retry = await findDialog('批量启用')
    expect(within(retry).getByText(second.domain)).toBeInTheDocument()
    expect(within(retry).queryByText(site.domain)).not.toBeInTheDocument()
  })

  it('restores the global lock and exact frozen retry after remounting an unknown result', async () => {
    authenticate('admin')
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        writes += 1
        return writes === 1
          ? new Promise<Response>(() => undefined)
          : Promise.resolve(
              jsonResponse({
                items: [{ id: site.id, status: 'updated', site: changedDetail(site, 8, false) }],
              }),
            )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    const { unmount } = renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('禁用'))
    await user.click(
      within(await findDialog('批量禁用')).getByRole('button', {
        name: '确认禁用',
      }),
    )

    // While the request is still in flight only the confirm
    // button loads; 结果待确认 appears once the outcome is actually unknown.
    await waitFor(() => expect(within(getDialog('批量禁用')).getByRole('button', { name: /确认禁用/ })).toHaveClass('ant-btn-loading'))
    expect(document.querySelector('.cdnca-outcome-bar')).toBeNull()
    expect(sessionStorage).toHaveLength(1)
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeDisabled()
    expect(screen.getByRole('button', { name: '添加网站' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /更多操作/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: '管理' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '更多' })).toBeDisabled()

    unmount()
    renderWithProviders(<SiteListPage />, ['/site/list'])
    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    // The restored record holds back new batch writes only
    expect(screen.getByRole('button', { name: '批量修改' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '添加网站' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await findDialog('批量操作结果')).toBeInTheDocument()
    expect(sessionStorage).toHaveLength(0)
    const calls = fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    expect(calls[0][1]?.headers).toEqual(calls[1][1]?.headers)
    expect(JSON.parse(String(calls[0][1]?.body))).toEqual({
      action: 'disable',
      items: [{ id: site.id, expected_version: 7 }],
    })
  })

  it('review closure persists the complete frozen attempt under the stable principal identity', async () => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        expect(sessionStorage).toHaveLength(1)
        const storageKey = sessionStorage.key(0)
        expect(storageKey).toBe(
          'cdnca:site-batch-retry:platform:22222222-2222-4222-8222-222222222222:null:11111111-1111-4111-8111-111111111111',
        )
        const stored = JSON.parse(String(sessionStorage.getItem(String(storageKey))))
        expect(stored.body).toBe(init.body)
        expect(stored.key).toBe(
          (init.headers as Record<string, string>)['Idempotency-Key'],
        )
        expect(stored).toMatchObject({
          action: 'enable',
          targets: [{ id: site.id, domain: site.domain, version: 7 }],
          input: {
            action: 'enable',
            items: [{ id: site.id, expected_version: 7 }],
          },
        })
        return Promise.resolve(
          jsonResponse({
            items: [{ id: site.id, status: 'updated', site: changedDetail(site, 8, true) }],
          }),
        )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('启用'))
    await user.click(
      within(await findDialog('批量启用')).getByRole('button', {
        name: '确认启用',
      }),
    )

    expect(await findDialog('批量操作结果')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(1)
    expect(sessionStorage).toHaveLength(0)
  })

  it('does not send the batch request when the retry lock cannot be persisted', async () => {
    authenticate('admin')
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('storage unavailable', 'QuotaExceededError')
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('禁用'))
    await user.click(
      within(await findDialog('批量禁用')).getByRole('button', {
        name: '确认禁用',
      }),
    )

    expect(await screen.findByText('待确认批量操作无法恢复', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(0)
    // Only new batch writes wait; the rest of the page stays usable
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeEnabled()
    expect(screen.getByRole('button', { name: '批量修改' })).toBeDisabled()
  })

  it.each([408, 503])('persists an HTTP %s unknown result for exact retry', async (status) => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(
          jsonResponse(
            { error: { code: 'temporarily_unavailable', message: '状态暂不可确认' } },
            status,
          ),
        )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('禁用'))
    await user.click(
      within(await findDialog('批量禁用')).getByRole('button', {
        name: '确认禁用',
      }),
    )

    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(sessionStorage).toHaveLength(1)
    expect(screen.getByRole('button', { name: '批量修改' })).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeEnabled()
  })

  it('clears the persisted lock after an explicit 409 response', async () => {
    authenticate('admin')
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(
              jsonResponse(
                { error: { code: 'version_conflict', message: '网站版本已变化' } },
                409,
              ),
            )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('启用'))
    await user.click(
      within(await findDialog('批量启用')).getByRole('button', {
        name: '确认启用',
      }),
    )
    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(sessionStorage).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('网站版本已变化')).toBeInTheDocument()
    expect(sessionStorage).toHaveLength(0)
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeEnabled()
    expect(screen.getByRole('button', { name: /更多操作/ })).toBeEnabled()
  })

  it('requires a second confirmation before deleting selected sites', async () => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ items: [{ id: site.id, status: 'deleted' }] }))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('删除'))
    const confirm = await findDialog('批量删除')
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(0)
    expect(within(confirm).getByText(`确定删除网站 ${site.domain}？`)).toBeInTheDocument()
    expect(within(confirm).queryByRole('button', { name: '继续删除' })).not.toBeInTheDocument()
    await user.click(within(confirm).getByRole('button', { name: '确认删除' }))
    expect(await screen.findByText('已删除')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(1)
  })

  it('treats a success status that does not match the requested action as unknown', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ items: [{ id: site.id, status: 'deleted' }] }))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByText('启用'))
    await user.click(
      within(await findDialog('批量启用')).getByRole('button', {
        name: '确认启用',
      }),
    )

    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(queryDialog('批量操作结果')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '批量修改' })).toBeDisabled()
  })

  it.each(['reordered', 'missing', 'duplicate'] as const)(
    'treats a %s batch response as unknown',
    async (variant) => {
      authenticate('admin')
      const second: SiteListItem = {
        ...site,
        id: 'site-2',
        version: 4,
        domain: 'second.example.com',
      }
      const firstResult = {
        id: site.id,
        status: 'updated',
        site: changedDetail(site, 8, true),
      }
      const secondResult = {
        id: second.id,
        status: 'updated',
        site: changedDetail(second, 5, true),
      }
      const items =
        variant === 'reordered'
          ? [secondResult, firstResult]
          : variant === 'missing'
            ? [firstResult]
            : [firstResult, firstResult]
      vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site, second]))
        if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
          return Promise.resolve(jsonResponse({ items }))
        }
        return Promise.reject(new Error(`unexpected request ${url}`))
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)

      await user.click(screen.getByRole('checkbox', { name: site.domain }))
      await user.click(screen.getByRole('checkbox', { name: second.domain }))
      await user.click(screen.getByRole('button', { name: /更多操作/ }))
      await user.click(await screen.findByText('启用'))
      await user.click(
        within(await findDialog('批量启用')).getByRole('button', {
          name: '确认启用',
        }),
      )

      expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
      expect(sessionStorage).toHaveLength(1)
      expect(queryDialog('批量操作结果')).not.toBeInTheDocument()
    },
  )

  it('review closure fails closed for corrupted retry data without leaking the lock to another principal', async () => {
    const currentUserID = '11111111-1111-4111-8111-111111111111'
    const currentScopeID = '22222222-2222-4222-8222-222222222222'
    sessionStorage.setItem(
      `cdnca:site-batch-retry:platform:${currentScopeID}:null:${currentUserID}`,
      JSON.stringify({ action: 'enable', key: 'damaged' }),
    )
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(response()))
    const { unmount } = renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('待确认批量操作无法恢复', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await screen.findByText(site.domain)
    // An unreadable (older-format) record locks only batch writes
    // and can be discarded after a refresh; it never locks the whole page.
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeEnabled()
    expect(screen.getByRole('button', { name: '添加网站' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '批量修改' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    const user = userEvent.setup({ delay: null })
    await user.click(screen.getByRole('button', { name: '放弃这次结果' }))
    const confirm = await screen.findByText('放弃后不再跟踪这次请求，列表会按服务端的实际状态刷新。确认放弃？')
    await user.click(within(confirm.closest('.ant-popover') as HTMLElement).getByRole('button', { name: '放弃这次结果' }))
    await waitFor(() => expect(screen.queryByText('待确认批量操作无法恢复')).not.toBeInTheDocument())
    expect(sessionStorage).toHaveLength(0)
    expect(screen.getByRole('button', { name: '批量修改' })).toBeEnabled()
    unmount()
    sessionStorage.setItem(
      `cdnca:site-batch-retry:platform:${currentScopeID}:null:${currentUserID}`,
      JSON.stringify({ action: 'enable', key: 'damaged' }),
    )

    const other = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: '44444444-4444-4444-8444-444444444444',
      scope_kind: 'platform',
      tenant_id: null,
      username: 'other-admin',
      display_name: 'other-admin',
      roles: ['platform_admin'],
      permissions: ['sites.read', 'sites.manage'],
    })
    useSessionStore.getState().setSession(authResponse(other), other)
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    expect(screen.queryByText('待确认批量操作无法恢复')).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeEnabled()
  })

  it('review closure isolates retry data for equal scope and user IDs across scope kinds and tenants', async () => {
    const retryInput = {
      action: 'disable' as const,
      items: [{ id: site.id, expected_version: site.version }],
    }
    const retryAttempt = {
      action: retryInput.action,
      targets: [{ id: site.id, domain: site.domain, version: site.version }],
      input: retryInput,
      body: JSON.stringify(retryInput),
      key: 'site-batch-tenant-owner-only',
    }
    const tenantRetryKey =
      `cdnca:site-batch-retry:tenant:${tenantAID}:${tenantAID}:${tenantAUserID}`
    sessionStorage.setItem(tenantRetryKey, JSON.stringify(retryAttempt))
    setSiteSession({
      kind: 'platform',
      scopeID: tenantAID,
      tenantID: null,
      userID: tenantAUserID,
      accessToken: 'site-retry-collision-platform',
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([site]))

    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    expect(screen.queryByText('批量操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(sessionStorage.getItem(tenantRetryKey)).toBe(JSON.stringify(retryAttempt))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  it('keeps the batch menu available without a selection and disables it without sites.manage permission', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const { unmount } = renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    expect(screen.getByRole('button', { name: /更多操作/ })).toBeEnabled()
    unmount()

    vi.restoreAllMocks()
    authenticate('admin', ['sites.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /更多操作/ })).toBeDisabled()
  })

  it('links tenant operators to DNS reconciliation from the site row', async () => {
    authenticate('user', ['sites.read', 'dns.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '更多' }))
    const link = await screen.findByRole('menuitem', { name: 'DNS 解析检查' })
    expect(link).toBeEnabled()
  })

  // B2（审计 4.2）：解析检测是全站列表，不再要求先勾选网站；同步解析按网站提交。
  it('shows the tenant DNS check as a whole-site list and syncs the selected domains', async () => {
    authenticate('user', ['sites.read', 'sites.manage', 'dns.read', 'dns.manage'])
    const failing = { ...site, domains: [site.domain], cname: 'abc.cdn.example.net',
      auto_dns: { provider_id: 'p-1', provider_name: '我的 Cloudflare', state: 'failed', failure_code: 'dns_record_conflict',
        attempts: 1, results: [{ domain: site.domain, code: 'dns_record_conflict' }], updated_at: '2026-10-25T00:00:00Z' } }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.includes('/v1/dns/providers')) return jsonResponse({ items: [] })
      if (url.endsWith('/auto-dns/sync') && init?.method === 'POST') {
        return jsonResponse({ ...failing.auto_dns, state: 'pending', failure_code: null }, 202)
      }
      return response([failing as SiteListItem])
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '解析检测' }))

    expect(screen.getByTestId('location')).toHaveTextContent('/site/list')
    expect(screen.getByRole('button', { name: '解析检测' })).toHaveAttribute('aria-pressed', 'true')
    expect(await screen.findByText('我的 Cloudflare')).toBeInTheDocument()
    expect(screen.getByText('解析失败', { selector: '.ant-tag' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '同步解析' })).toBeDisabled()
    await user.click(screen.getAllByRole('checkbox').at(-1)!)
    await user.click(screen.getByRole('button', { name: '同步解析' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([url, init]) =>
      String(url) === `/v1/sites/${site.id}/auto-dns/sync` && init?.method === 'POST')).toBe(true))
    expect(await screen.findByText('已提交 1 个网站的同步解析')).toBeInTheDocument()
  })

  it('opens the platform website defaults from the site subnavigation (ui-click F7)', async () => {
    authenticate('admin', ['sites.read', 'system_configuration.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '默认设置' }))

    expect(screen.getByTestId('location')).toHaveTextContent('/config/default')
    expect(screen.queryByText(/暂不可用/)).not.toBeInTheDocument()
  })

  // B2：租户的默认设置是本页标签（/v1/site-defaults），不再跳管理员页。
  it('opens the tenant site defaults in place and creates one with an idempotency key', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const created = {
      id: '019a1b00-0000-7000-8000-000000000001', display_id: '1', scope_id: tenantAID, owner_user_id: tenantAUserID,
      setting_name: 'http_listen_port', setting_value: '8080', scope_name: 'global', group_id: null, group_name: null,
      enabled: true, version: 1, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z',
    }
    let listed = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/site-defaults') && init?.method === 'POST') return jsonResponse(created, 201)
      if (url.startsWith('/v1/site-defaults')) {
        listed += 1
        return jsonResponse({ items: listed > 1 ? [created] : [], total: listed > 1 ? 1 : 0, page: 1, limit: 10 })
      }
      return response()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '默认设置' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/site/list')
    expect(await screen.findByRole('heading', { name: '站点默认设置' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /新增设置/ }))
    const dialog = getDialog('新增设置')
    await user.type(within(dialog).getByRole('textbox', { name: '设置值' }), '8080')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('HTTP 默认监听端口')).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/site-defaults' && init?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body))).toEqual({ setting_name: 'http_listen_port', setting_value: '8080', scope_name: 'global' })
    expect(write[1]?.headers).toMatchObject({ 'Idempotency-Key': expect.stringMatching(/^site-default-create-/) })
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('/v1/system-configuration'))).toBe(false)
  })

  it('hides the website defaults entry from platform users without configuration read', async () => {
    authenticate('admin', ['sites.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    expect(screen.queryByRole('button', { name: '默认设置' })).not.toBeInTheDocument()
  })

  it('moves the tenant verified domains entry into more actions', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])
    await screen.findByText(site.domain)

    expect(screen.queryByRole('button', { name: '已验证域名' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /更多操作/ }))
    await user.click(await screen.findByRole('menuitem', { name: '已验证域名' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/account/domains')
  })

  // 10-25 用户截图：用户端点 DNS API 曾跳到管理员 /node/dns，平台 DNS 配置读取失败。
  it('opens the tenant DNS API in place without entering the administrator DNS page', async () => {
    authenticate('user', ['sites.read', 'dns.read', 'dns.manage'])
    const provider = {
      id: '019a03a3-735c-7b8c-9cc2-8543d041c901', scope_id: tenantAID, name: '我的阿里云', provider_type: 'aliyun',
      credentials_configured: true, status: 'verified', version: 2, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).includes('/v1/dns/providers')
      ? new Response(JSON.stringify({ items: [provider] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      : response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: 'DNS API' }))

    expect(await screen.findByText('我的阿里云')).toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent('/site/list')
    expect(screen.getByRole('button', { name: 'DNS API' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: /新增 DNS API/ })).toBeEnabled()
    const urls = fetchSpy.mock.calls.map(([input]) => String(input))
    expect(urls.some((url) => url.includes('/v1/dns/providers'))).toBe(true)
    expect(urls.some((url) => url.includes('/v1/dns/platform-config'))).toBe(false)
  })

  // DNS-SEC-20261027-01：平台托管的 DNS 副本在用户端只读（标「平台托管」，无验证/编辑/删除，不能勾选）。
  it('shows the platform-managed DNS copy read-only in the tenant DNS API', async () => {
    authenticate('user', ['sites.read', 'dns.read', 'dns.manage'])
    const own = {
      id: '019a03a3-735c-7b8c-9cc2-8543d041c901', scope_id: tenantAID, name: '我的阿里云', provider_type: 'aliyun',
      credentials_configured: true, status: 'verified', managed_by: 'tenant', version: 2,
      created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    }
    const platformCopy = { ...own, id: '019a03a3-735c-7b8c-9cc2-8543d041c9ff', name: '平台DNS配置', provider_type: 'dnspod_cn', managed_by: 'platform' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).includes('/v1/dns/providers')
      ? new Response(JSON.stringify({ items: [own, platformCopy] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      : response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: 'DNS API' }))

    const copyRow = (await screen.findByText('平台DNS配置')).closest('tr')!
    expect(within(copyRow).getByText('平台托管')).toBeInTheDocument()
    expect(within(copyRow).queryByRole('button', { name: /平台DNS配置/ })).not.toBeInTheDocument()
    expect(within(copyRow).getByRole('checkbox')).toBeDisabled()
    const ownRow = screen.getByText('我的阿里云').closest('tr')!
    expect(within(ownRow).getAllByRole('button', { name: /我的阿里云/ })).toHaveLength(3)
  })

  // B2：DNS API 新增弹窗分区（基础信息 / 验证信息），带备注；列表显示备注列。
  it('creates a tenant DNS API with a remark from the sectioned dialog', async () => {
    authenticate('user', ['sites.read', 'dns.read', 'dns.manage'])
    const provider = {
      id: '019a03a3-735c-7b8c-9cc2-8543d041c901', scope_id: tenantAID, name: '我的阿里云', remark: '主业务域名', provider_type: 'aliyun',
      credentials_configured: true, status: 'verified', version: 2, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.includes('/v1/dns/providers') && init?.method === 'POST') return jsonResponse({ ...provider, id: 'new', name: 'CF', remark: '备用' }, 201)
      if (url.includes('/v1/dns/providers')) return jsonResponse({ items: [provider] })
      return response()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: 'DNS API' }))
    expect(await screen.findByText('主业务域名')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /新增 DNS API/ }))
    const dialog = getDialog('新增DNS API')
    expect(within(dialog).getByText('基础信息')).toBeInTheDocument()
    expect(within(dialog).getByText('验证信息')).toBeInTheDocument()
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), 'CF')
    await user.type(within(dialog).getByRole('textbox', { name: '备注' }), ' 备用 ')
    await user.type(within(dialog).getByLabelText('API Token'), 'cloudflare-token-value-0123456789')
    await user.click(within(dialog).getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([url, init]) => String(url).includes('/v1/dns/providers') && init?.method === 'POST')).toBe(true))
    const write = fetchSpy.mock.calls.find(([url, init]) => String(url).includes('/v1/dns/providers') && init?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body))).toMatchObject({ name: 'CF', remark: '备用', provider_type: 'cloudflare' })
  })

  it('hides the DNS API entry from tenants without dns.read', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    expect(screen.queryByRole('button', { name: 'DNS API' })).not.toBeInTheDocument()
  })

  it('keeps the platform DNS configuration link for administrators with dns.read', async () => {
    authenticate('admin', ['sites.read', 'dns.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><LocationProbe /><SiteListPage /></>, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: 'DNS API' }))

    expect(screen.getByTestId('location')).toHaveTextContent('/node/dns')
  })

  it('keeps the table scroll container inside the panel and denies tenant create without sites.manage', async () => {
    authenticate('user', ['sites.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const { container } = renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText('www.example.com')

    const panel = container.querySelector('.site-list-page')
    const scroll = screen.getByTestId('site-table-scroll')
    const subnav = screen.getByRole('navigation', { name: '网站管理栏目' })
    const subnavScroll = subnav.querySelector('.site-subnav-scroll')
    const scrollBy = vi.fn()
    expect(subnavScroll).not.toBeNull()
    Object.defineProperty(subnavScroll!, 'scrollBy', { value: scrollBy })
    expect(panel).toContainElement(scroll)
    expect(scroll.querySelector('.ant-table-content')).toBeInTheDocument()
    expect(container.querySelector('.site-batch-button')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '向后查看更多栏目' }))
    expect(scrollBy).toHaveBeenCalledWith({ left: 120, behavior: 'smooth' })

    expect(screen.getByRole('button', { name: '添加网站' })).toBeDisabled()

    expect(screen.getByRole('button', { name: /更多操作/ })).toBeDisabled()
  })

  it('creates a site for an explicit tenant owner as a platform administrator', async () => {
    authenticate('admin', ['sites.read', 'sites.manage', 'identity.users.manage'])
    const owner = { id: tenantAUserID, display_name: 'Tenant A User' }
    const savedItem = { ...createdSite('admin.example.com', '192.0.2.80'), owner }
    const saved = { ...createdDetail('admin.example.com', '192.0.2.80'), owner }
    let listReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) {
        listReads += 1
        return Promise.resolve(response(listReads === 1 ? [site] : [site, savedItem]))
      }
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse(saved, 201))
      }
      if (url.startsWith('/v1/admin/users?')) {
        return Promise.resolve(jsonResponse({ items: [{
          id: tenantAUserID, display_id: '27', scope_id: tenantAID,
          tenant_id: tenantBID, username: 'tenant-a', display_name: 'Tenant A User',
          email: null, phone: null, status: 'active', role: 'tenant_owner',
          group_id: null, group_name: null, revision: 1,
          created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
        }], total: 1, page: 1, limit: 20 }))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    expect(within(dialog).queryByRole('textbox', { name: '目标租户作用域' })).not.toBeInTheDocument()
    const ownerUser = within(dialog).getByRole('combobox', { name: '所属用户' })
    const domain = within(dialog).getByRole('textbox', { name: '网站域名' })
    const origin = within(dialog).getByRole('textbox', { name: '源站地址' })
    const submit = within(dialog).getByRole('button', { name: '创建网站' })

    await user.type(domain, 'admin.example.com')
    await user.type(origin, '192.0.2.80')
    await user.click(submit)
    expect(within(dialog).getByText('请选择有效的所属用户')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)

    await user.click(ownerUser)
    await user.click(await screen.findByText('tenant-a（27）'))
    await user.click(submit)

    expect(await screen.findByText(/^网站 admin\.example\.com 创建成功。/)).toBeInTheDocument()
    expect(await screen.findByText(savedItem.domain)).toBeInTheDocument()
    const writes = fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST',
    )
    expect(writes).toHaveLength(1)
	    expect(JSON.parse(String(writes[0][1]?.body))).toMatchObject({
      target_scope_id: tenantAID,
      owner_id: tenantAUserID,
      basic: {
        domains: ['admin.example.com'],
	        origins: ['192.0.2.80'],
	      },
	      origin_pool: {
	        origins: [{ host: '192.0.2.80', port: 80, weight: 1, enabled: true }],
	      },
	    })
    // SITE-CURRENT-01：没改的端口与负载方式交给目标用户的默认设置
    expect(JSON.parse(String(writes[0][1]?.body)).origin_pool).not.toHaveProperty('balance_method')
    expect(JSON.parse(String(writes[0][1]?.body)).basic).not.toHaveProperty('http_listen_ports')
    expect(writes[0][1]?.headers).toMatchObject({
      'Idempotency-Key': expect.stringMatching(/^site-create-/),
    })
  })

  // 社区版：建站不选套餐，提交时套餐字段固定为空（package_id / package_subscription_id / package_name 都不发送）。
  it('loads real paginated owner groups, offers no package, and sends no package fields', async () => {
    authenticate('admin', ['platform.admin'])
    const lookup = vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [resourceUser], total: 1, page: 1, limit: 20 })
    const group = { id: '55555555-5555-4555-8555-555555555555', scope_id: tenantAID, name: '生产站点', revision: 1,
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }
    const groups = vi.spyOn(siteGroupsApi, 'list').mockResolvedValue({ items: [group], total: 1, page: 1, limit: 20 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
      String(input) === '/v1/sites' && init?.method === 'POST'
        ? jsonResponse({ error: { code: 'validation_error' } }, 422) : response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('combobox', { name: '所属用户' }))
    await user.type(within(dialog).getByRole('combobox', { name: '所属用户' }), 'tenant-a')
    await user.click(await screen.findByText('tenant-a（27）'))
    expect(lookup).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ search: 'tenant-a', status: 'active' }))
    expect(within(dialog).queryByRole('combobox', { name: '用户套餐' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '高级设置' }))
    await user.click(within(dialog).getByRole('combobox', { name: '所属分组' }))
    await user.click(await screen.findByText('生产站点'))
    expect(groups).toHaveBeenCalledWith(expect.any(String), tenantAID, 1, 20)
    for (const label of ['目标租户作用域', '套餐 ID', '套餐名称', '套餐订阅 ID', '网站分组 ID', '网站分组名称']) {
      expect(within(dialog).queryByRole('textbox', { name: label })).not.toBeInTheDocument()
    }
    expect(within(dialog).queryByText(/^由所选套餐决定：/)).not.toBeInTheDocument()
    for (const label of ['CNAME 分配模式', 'CNAME 域名', 'CNAME 主机名']) {
      expect(within(dialog).queryByLabelText(label)).not.toBeInTheDocument()
    }
    expect(within(dialog).getByText(/^留空自动分配；填写则使用你自己的 CNAME 主机名/)).toBeInTheDocument()
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'selected.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), '192.0.2.80')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
    await screen.findByText('网站信息校验失败，请检查后重试')
    const write = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')
    const body = JSON.parse(String(write?.[1]?.body))
    expect(body).toMatchObject({ target_scope_id: tenantAID, owner_id: tenantAUserID,
      basic: { group_id: group.id, group_name: group.name, cname_mode: '', cname_domain: '', cname_hostname: '' } })
    for (const key of ['package_id', 'package_subscription_id', 'package_name']) expect(body.basic).not.toHaveProperty(key)
  })

  it('explains unavailable resource lookup permissions instead of exposing UUID fallback fields', async () => {
    authenticate('admin', ['sites.read', 'sites.manage'])
    const users = vi.spyOn(usersApi, 'list')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    expect(within(dialog).getByText('当前账号没有查询用户权限，请联系管理员授权。')).toBeInTheDocument()
    expect(within(dialog).getByRole('combobox', { name: '所属用户' })).toBeDisabled()
    expect(within(dialog).queryByRole('textbox', { name: '目标租户作用域' })).not.toBeInTheDocument()
    expect(users).not.toHaveBeenCalled()
  })

  it('rejects a group page whose page number does not match the request', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    vi.spyOn(siteGroupsApi, 'list').mockResolvedValue({ items: [], total: 21, page: 2, limit: 20 })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('button', { name: '高级设置' }))
    expect(await within(dialog).findByText('读取失败，请重试')).toHaveAttribute('role', 'alert')
    await user.click(within(dialog).getByRole('combobox', { name: '所属分组' }))
    expect(screen.queryByRole('button', { name: '加载更多' })).not.toBeInTheDocument()
  })

  it('rejects invalid domains and origins, then clears each field error while editing', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    const domainInput = within(dialog).getByRole('textbox', { name: '网站域名' })
    const originInput = within(dialog).getByRole('textbox', { name: '源站地址' })
    const submit = within(dialog).getByRole('button', { name: '创建网站' })

    await user.type(originInput, 'origin.example.com')
    for (const invalid of [
      'https://example.com',
      'example.com/path',
      'example.com:443',
      '-bad.example.com',
      'bad_.example.com',
    ]) {
      await user.clear(domainInput)
      await user.type(domainInput, invalid)
      await user.click(submit)
      expect(within(dialog).getByText('请输入有效的网站域名')).toBeInTheDocument()
      await user.type(domainInput, 'x')
      expect(within(dialog).queryByText('请输入有效的网站域名')).not.toBeInTheDocument()
    }

    await user.clear(domainInput)
    await user.type(domainInput, 'Example.COM.')
    for (const invalid of [
      'https://origin.example.com',
      'origin.example.com/path',
      '999.999.999.999',
      'bad_.example.com',
      'origin.example.com:0',
      'origin.example.com:65536',
      '[2001:db8::1]:70000',
    ]) {
      await user.clear(originInput)
      fireEvent.change(originInput, { target: { value: invalid } })
      await user.click(submit)
      expect(within(dialog).getByText('请输入有效且不重复的源站地址（最多 32 个）')).toBeInTheDocument()
      await user.type(originInput, 'x')
      expect(within(dialog).queryByText('请输入有效且不重复的源站地址（最多 32 个）')).not.toBeInTheDocument()
    }

    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  // C09: the advanced area reads origin → listening/HTTPS → CNAME → group, and a
  // created site offers a button straight to its details.
  it('orders the advanced fields and links the created site to its details', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const saved = createdDetail()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
      if (url === '/v1/sites' && init?.method === 'POST') return Promise.resolve(jsonResponse(saved, 201))
      if (url.startsWith('/v1/site-groups')) return Promise.resolve(jsonResponse({ items: [], total: 0, page: 1, page_size: 50 }))
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><SiteListPage /><LocationProbe /></>, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('button', { name: /高级设置/ }))
    const labels = Array.from(dialog.querySelectorAll('.site-create-advanced-fields [aria-label]'))
      .map((node) => node.getAttribute('aria-label'))
    const at = (label: string) => labels.indexOf(label)
    expect(at('回源协议')).toBe(0)
    expect(at('回源 Host')).toBeLessThan(at('HTTP 监听端口'))
    expect(at('HTTPS 监听端口')).toBeLessThan(at('CNAME'))
    const lastCname = labels.reduce((last, label, index) => (label?.startsWith('CNAME') ? index : last), -1)
    expect(lastCname).toBeLessThan(at('所属分组'))
    await user.click(within(dialog).getByRole('button', { name: /高级设置/ }))
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com:8080')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
    expect(await screen.findByText(/^网站 new\.example\.com 创建成功。/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看站点' }))
    expect(screen.getByTestId('location')).toHaveTextContent(`/site/${saved.id}/edit`)
  })

  it('creates a tenant site with the frozen request and refetches the real list', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const savedItem = createdSite()
    const saved = createdDetail()
    let listReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) {
        listReads += 1
        return Promise.resolve(response(listReads === 1 ? [site] : [site, savedItem]))
      }
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse(saved, 201))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), ' New.Example.COM. ')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), ' Origin.Example.COM:08080 ')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    expect(await screen.findByText(/^网站 new\.example\.com 创建成功。/)).toBeInTheDocument()
    expect(queryDialog('添加网站')).not.toBeInTheDocument()
    expect(await screen.findByText(savedItem.domain)).toBeInTheDocument()
    expect(listReads).toBe(2)

    const writes = fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST',
    )
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({
      // 社区版：写请求不带 package_id / package_subscription_id / package_name。
      basic: {
        cname_mode: '',
        cname_domain: '',
        cname_hostname: '',
        group_id: null,
        group_name: null,
        domains: ['new.example.com'],
        http_enabled: true,
        // SITE-CURRENT-01 / CU-SITE-02：没填的 HTTP 端口、负载方式、IPv6、TLS 不提交，由默认设置决定
        https_listen_ports: [],
        origins: ['origin.example.com:8080'],
        cname: '',
        https_enabled: false,
        enabled: true,
        status: 'active',
        is_default: false,
	      },
	      origin_pool: {
	        origins: [{ host: 'origin.example.com', port: 8080, weight: 1, enabled: true }],
	        failover_tries: 1,
	        connect_timeout_ms: 3000,
	        read_timeout_ms: 30000,
	      },
	    })
    // PJ-C02：同步状态只由服务端派生，建站请求不再带 sync_status。
    expect(JSON.parse(String(writes[0][1]?.body)).basic).not.toHaveProperty('sync_status')
    expect(JSON.parse(String(writes[0][1]?.body))).not.toHaveProperty('target_scope_id')
    expect(JSON.parse(String(writes[0][1]?.body))).not.toHaveProperty('owner_id')
	    expect(writes[0][1]?.headers).toMatchObject({
      'Idempotency-Key': expect.stringMatching(/^site-create-/),
	    })
	  })

  // B2：建站弹窗「DNS API（自动添加记录）」只列本人已验证账号，选了才带 dns_provider_id。
  it('sends the chosen DNS API account for automatic records when creating a tenant site', async () => {
    authenticate('user', ['sites.read', 'sites.manage', 'dns.read', 'dns.manage'])
    const verified = { id: '019a03a3-735c-7b8c-9cc2-8543d041c901', scope_id: tenantAID, name: '我的阿里云', provider_type: 'aliyun',
      credentials_configured: true, status: 'verified', version: 2, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' }
    const unverified = { ...verified, id: '019a03a3-735c-7b8c-9cc2-8543d041c902', name: '未验证账号', status: 'unverified' }
    const platformCopy = { ...verified, id: '019a03a3-735c-7b8c-9cc2-8543d041c9ff', name: '平台DNS配置', managed_by: 'platform' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return response([site])
      if (url.includes('/v1/dns/providers')) return jsonResponse({ items: [verified, unverified, platformCopy] })
      if (url.startsWith('/v1/site-groups')) return jsonResponse({ items: [], total: 0, page: 1, limit: 20 })
      if (url === '/v1/sites' && init?.method === 'POST') return jsonResponse(createdDetail(), 201)
      throw new Error(`unexpected request ${url}`)
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), '192.0.2.10')
    await user.click(within(dialog).getByRole('button', { name: '高级设置' }))
    await user.click(within(dialog).getByRole('combobox', { name: 'DNS API' }))
    expect(screen.queryByTitle('未验证账号')).not.toBeInTheDocument()
    expect(screen.queryByTitle('平台DNS配置')).not.toBeInTheDocument()
    await user.click(await screen.findByTitle('我的阿里云'))
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    await waitFor(() => expect(fetchSpy.mock.calls.filter(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')).toHaveLength(1))
    const write = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body)).dns_provider_id).toBe(verified.id)
  })

  // CU-SITE-02：未操作的 IPv6/TLS/超时/回源协议不提交，由服务端按默认设置解析；显式 HTTP 必须发送。
  describe('create omits untouched defaults (CU-SITE-02)', () => {
    function createSpy(saved: SiteDetail) {
      return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
        if (url === '/v1/sites' && init?.method === 'POST') return Promise.resolve(jsonResponse(saved, 201))
        return Promise.reject(new Error(`unexpected request ${url}`))
      })
    }
    const pickOption = async (title: string) => (await screen.findAllByTitle(title)).find((node) => node.classList.contains('ant-select-item-option'))!
    const postBody = (spy: ReturnType<typeof createSpy>) => JSON.parse(String(spy.mock.calls.find(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')![1]?.body))
    async function fillAndOpen() {
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)
      await user.click(screen.getByRole('button', { name: '添加网站' }))
      const dialog = getDialog('添加网站')
      await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
      await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com:8080')
      return { user, dialog }
    }

    it('leaves IPv6, TLS and the origin protocol out and accepts the values the defaults resolved', async () => {
      authenticate('user', ['sites.read', 'sites.manage'])
      const saved = createdDetail()
      saved.basic = { ...saved.basic, ipv6_enabled: true, tls_protocols: ['TLSv1.2'] }
      saved.listener_state = { ...saved.listener_state, ipv6_desired_enabled: true }
      saved.origin_pool = { ...saved.origin_pool, scheme: 'https', https_port: 8443, keepalive_enabled: false }
      const spy = createSpy(saved)
      const { user, dialog } = await fillAndOpen()
      await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
      expect(await screen.findByText(/^网站 new\.example\.com 创建成功。/)).toBeInTheDocument()
      const body = postBody(spy)
      expect(body.basic).not.toHaveProperty('ipv6_enabled')
      expect(body.basic).not.toHaveProperty('tls_protocols')
      // 回源超时暂仍发送系统默认（服务端无默认时不补，省略会 400；待服务端兜底）
      expect(body.origin_pool).toMatchObject({ connect_timeout_ms: 3000, read_timeout_ms: 30000 })
      expect(body.origin_pool).not.toHaveProperty('scheme')
    })

    it('sends an explicitly chosen HTTP origin protocol', async () => {
      authenticate('user', ['sites.read', 'sites.manage'])
      const spy = createSpy(createdDetail())
      const { user, dialog } = await fillAndOpen()
      await user.click(within(dialog).getByRole('button', { name: /高级设置/ }))
      await user.click(within(dialog).getByRole('combobox', { name: '回源协议' }))
      await user.click(await pickOption('HTTPS'))
      await user.click(within(dialog).getByRole('combobox', { name: '回源协议' }))
      await user.click(await pickOption('HTTP'))
      await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
      expect(await screen.findByText(/^网站 new\.example\.com 创建成功。/)).toBeInTheDocument()
      expect(postBody(spy).origin_pool).toMatchObject({ scheme: 'http' })
    })

    it('still refuses a response that changed an explicitly chosen origin protocol', async () => {
      authenticate('user', ['sites.read', 'sites.manage'])
      const saved = createdDetail()
      saved.origin_pool = { ...saved.origin_pool, scheme: 'https' }
      createSpy(saved)
      const { user, dialog } = await fillAndOpen()
      await user.click(within(dialog).getByRole('button', { name: /高级设置/ }))
      await user.click(within(dialog).getByRole('combobox', { name: '回源协议' }))
      await user.click(await pickOption('HTTP'))
      await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
      await waitFor(() => expect(screen.queryByText(/^网站 new\.example\.com 创建成功。/)).not.toBeInTheDocument())
      expect(await within(dialog).findByRole('button', { name: /重试|原请求/ })).toBeInTheDocument()
    })
  })

  it('sends the origin protocol and origin Host chosen in the create dialog', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
      if (url === '/v1/sites' && init?.method === 'POST') return Promise.resolve(jsonResponse(createdDetail(), 201))
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), '192.0.2.10')
    // C09: origin protocol and Host sit in the advanced section.
    expect(within(dialog).queryByRole('textbox', { name: '回源 Host' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: /高级设置/ }))
    await user.click(within(dialog).getByRole('combobox', { name: '回源协议' }))
    await user.click(await screen.findByTitle('跟随访问协议'))
    const host = within(dialog).getByRole('textbox', { name: '回源 Host' })
    await user.type(host, 'bad host')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
    expect(within(dialog).getByText('请输入有效的域名或 IP，可带端口')).toBeInTheDocument()
    await user.clear(host)
    await user.type(host, ' Origin.Example.COM ')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    await waitFor(() => expect(fetchSpy.mock.calls.filter(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')).toHaveLength(1))
    const write = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body)).origin_pool).toMatchObject({
      scheme: 'follow', request_host: { mode: 'custom', value: 'origin.example.com' },
    })
  })

	  it('creates a complete site and atomically sends the exact rich origin pool', async () => {
	    authenticate('user', ['sites.read', 'sites.manage'])
	    const pool = {
	      origins: [
	        { host: 'origin-a.example.com', port: 8080, weight: 1, enabled: true },
	        { host: '2001:db8::10', port: 8443, weight: 1, enabled: true },
	      ],
	      balance_method: 'least_conn' as const,
      failover_tries: 1,
	      connect_timeout_ms: 3000,
	      read_timeout_ms: 30000,
	    }
    const expectedBasic: Omit<SiteDetail['basic'], 'ipv6_enabled' | 'tls_protocols'> = {
      package_id: null,
      package_subscription_id: null,
      cname_mode: '',
      cname_domain: '',
      cname_hostname: '',
      package_name: null,
      group_id: '55555555-5555-4555-8555-555555555555',
      group_name: '生产站点',
      domains: ['api.example.com', 'www.example.net'],
      http_enabled: true,
      http_listen_ports: ['80', '8080'],
      https_listen_ports: ['443', '8443'],
      origins: ['origin-a.example.com:8080', '[2001:db8::10]:8443'],
      cname: 'edge.example.net',
      https_enabled: true,
      enabled: true,
      status: 'active',
      is_default: false,
    }
    const saved = createdDetail('api.example.com', 'origin-a.example.com:8080')
    saved.basic = { ...saved.basic, ...expectedBasic, ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'] }
	    saved.origin_pool = pool
	    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
	      const url = String(input)
	      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
	      if (url.startsWith('/v1/site-groups?')) return Promise.resolve(jsonResponse({
          items: [{ id: expectedBasic.group_id, scope_id: tenantAID, name: expectedBasic.group_name,
            revision: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }],
          page: 1, limit: 20, total: 1,
        }))
	      if (url === '/v1/sites' && init?.method === 'POST') return Promise.resolve(jsonResponse(saved, 201))
	      return Promise.reject(new Error(`unexpected request ${url}`))
	    })
	    const user = userEvent.setup({ delay: null })
	    renderWithProviders(<SiteListPage />, ['/site/list'])
	    await screen.findByText(site.domain)

	    await user.click(screen.getByRole('button', { name: '添加网站' }))
	    const dialog = getDialog('添加网站')
	    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'api.example.com\nwww.example.net')
	    fireEvent.change(within(dialog).getByRole('textbox', { name: '源站地址' }), {
	      target: { value: 'origin-a.example.com:8080\n[2001:db8::10]:8443' },
	    })
	    await user.click(within(dialog).getByRole('button', { name: '高级设置' }))
	    await user.click(within(dialog).getByRole('combobox', { name: '所属分组' }))
	    await user.click(await screen.findByText('生产站点'))
	    await user.clear(within(dialog).getByRole('textbox', { name: 'HTTP 监听端口' }))
    await user.type(within(dialog).getByRole('textbox', { name: 'HTTP 监听端口' }), '80 8080')
    await user.click(within(dialog).getByRole('switch', { name: '启用 HTTPS' }))
    await user.clear(within(dialog).getByRole('textbox', { name: 'HTTPS 监听端口' }))
    await user.type(within(dialog).getByRole('textbox', { name: 'HTTPS 监听端口' }), '443 8443')
	    await user.type(within(dialog).getByRole('textbox', { name: 'CNAME' }), 'edge.example.net')
	    await user.click(within(dialog).getByRole('combobox', { name: '负载均衡' }))
	    await user.click(await screen.findByText('最少连接'))
	    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

	    await screen.findByText(/^网站 api\.example\.com 创建成功。/)
	    const write = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST')
    // 社区版：写请求不带套餐字段（服务端按无套餐处理）。
    const { package_id: _packageID, package_subscription_id: _subscriptionID, package_name: _packageName, ...writtenBasic } = expectedBasic
    expect(JSON.parse(String(write?.[1]?.body))).toEqual({ basic: writtenBasic, origin_pool: pool })
	  })

	  it('strictly parses toolbar batch input in stable order before opening the existing confirmation flow', async () => {
	    authenticate('user', ['sites.read', 'sites.manage'])
	    const firstID = '33333333-3333-4333-8333-333333333333'
	    const secondID = '44444444-4444-4444-8444-444444444444'
	    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
	      const url = String(input)
	      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
	      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
	        return Promise.resolve(jsonResponse({ items: [
	          { id: firstID, status: 'deleted' },
	          { id: secondID, status: 'deleted' },
	        ] }))
	      }
	      return Promise.reject(new Error(`unexpected request ${url}`))
	    })
	    const user = userEvent.setup({ delay: null })
	    renderWithProviders(<SiteListPage />, ['/site/list'])
	    await screen.findByText(site.domain)

	    await user.click(screen.getByRole('button', { name: '批量修改' }))
	    const editor = getDialog('批量修改')
	    const input = within(editor).getByRole('textbox', { name: '网站 ID 与版本' })
	    await user.type(input, `${firstID},0\nnot-a-uuid,7\n${firstID},9`)
	    await user.click(within(editor).getByRole('button', { name: '预览' }))
	    expect(within(editor).getByText('每行必须是唯一的网站 UUID 和大于 0 的整数版本')).toBeInTheDocument()
	    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/sites/batch-action')).toHaveLength(0)

	    await user.clear(input)
	    await user.type(input, `${firstID},9\n${secondID},12`)
	    await user.click(within(editor).getByRole('combobox', { name: '批量操作' }))
	    await user.click(await screen.findByText('批量删除'))
	    await user.click(within(editor).getByRole('button', { name: '预览' }))
	    const firstConfirm = await findDialog('批量删除')
	    expect(within(firstConfirm).getByText(`确定删除这 2 个网站：${firstID}、${secondID}？`)).toBeInTheDocument()
	    await user.click(within(firstConfirm).getByRole('button', { name: '确认删除' }))
	    await findDialog('批量操作结果')

	    const write = fetchSpy.mock.calls.find(([url]) => String(url) === '/v1/sites/batch-action')
	    expect(JSON.parse(String(write?.[1]?.body))).toEqual({
	      action: 'delete',
	      items: [
	        { id: firstID, expected_version: 9 },
	        { id: secondID, expected_version: 12 },
	      ],
	    })
	  })

  it.each([200, 202, 204])('keeps an unexpected HTTP %s success status available for exact retry', async (status) => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.resolve(status === 204
          ? new Response(null, { status })
          : jsonResponse(createdDetail(), status))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com:8080')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    expect(await within(dialog).findByText('创建结果待确认')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST',
    )).toHaveLength(1)
  })

  it.each(['malformed', 'mismatched'] as const)('keeps a %s 201 response available for exact retry', async (kind) => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const saved = kind === 'malformed'
      ? {
          ...createdDetail(),
          id: '',
          created_at: undefined,
          basic: { ...createdDetail().basic, domains: [] },
        }
      : createdDetail('other.example.com')
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse(saved, 201))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com:8080')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    expect(await within(dialog).findByText('创建结果待确认')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
  })

  it('sends only one POST for synchronous duplicate create clicks', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const savedItem = createdSite()
    let resolveWrite!: (response: Response) => void
    const pendingWrite = new Promise<Response>((resolve) => {
      resolveWrite = resolve
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) {
        const writeStarted = fetchSpy.mock.calls.some(
          ([request, options]) => String(request) === '/v1/sites' && options?.method === 'POST',
        )
        return Promise.resolve(response(writeStarted ? [site, savedItem] : [site]))
      }
      if (url === '/v1/sites' && init?.method === 'POST') return pendingWrite
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com:8080')
    const submit = within(dialog).getByRole('button', { name: '创建网站' })
    act(() => {
      submit.click()
      submit.click()
    })

    await waitFor(() => expect(fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST',
    )).toHaveLength(1))
    act(() => resolveWrite(jsonResponse(createdDetail(), 201)))
    expect(await screen.findByText(/^网站 new\.example\.com 创建成功。/)).toBeInTheDocument()
  })

  it.each([
    ['site_domain_conflict', 409, '该网站域名已存在'],
    ['validation_error', 400, '网站信息校验失败，请检查后重试'],
    ['idempotency_conflict', 409, '幂等请求内容不一致，请修改后重新提交'],
    ['entitlement_denied', 403, '当前授权不允许创建网站'],
    ['entitlement_unavailable', 403, '授权状态暂不可用，请稍后重试'],
    ['entitlement_state_denied', 403, '当前授权状态不允许创建网站'],
    ['entitlement_feature_denied', 403, '当前授权未启用网站创建'],
    ['entitlement_quota_denied', 403, '网站授权额度不足'],
    ['entitlement_quota_exceeded', 403, '网站授权额度已用尽'],
  ])('maps create error %s without exposing the server message', async (code, status, message) => {
    authenticate('user', ['sites.read', 'sites.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ error: { code, message: 'private backend detail' } }, status))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    expect(await within(dialog).findByText(message)).toBeInTheDocument()
    expect(within(dialog).queryByText('private backend detail')).not.toBeInTheDocument()
  })

  // PJ-C05：服务端点名的字段就地标红并说明是哪一项，不只是"网站信息校验失败"。
  it('marks the origin field the server refused and says which field', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ error: { code: 'validation_error', message: 'site field origins is invalid: duplicate',
          details: { field: 'origins', reason: 'duplicate' } } }, 400))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    expect(await within(dialog).findByText(/源站地址不正确/)).toBeInTheDocument()
    expect(within(dialog).getByRole('textbox', { name: '源站地址' })).toHaveClass('ant-input-status-error')
    expect(within(dialog).getByRole('textbox', { name: '网站域名' })).not.toHaveClass('ant-input-status-error')
    expect(within(dialog).queryByText(/site field origins/)).not.toBeInTheDocument()
  })

  it.each(['network', '503'])('retries an unknown %s result only with the exact frozen request', async (failure) => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const savedItem = createdSite()
    const saved = createdDetail()
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response(writes >= 2 ? [site, savedItem] : [site]))
      if (url === '/v1/sites' && init?.method === 'POST') {
        writes += 1
        if (writes === 1) {
          return failure === 'network'
            ? Promise.reject(new TypeError('connection reset'))
            : Promise.resolve(jsonResponse({ error: { code: 'unavailable', message: 'private outage' } }, 503))
        }
        return Promise.resolve(jsonResponse(saved, 201))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com:8080')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))

    expect(await within(dialog).findByText('创建结果待确认')).toBeInTheDocument()
    expect(within(dialog).queryByText('private outage')).not.toBeInTheDocument()
    expect(writes).toBe(1)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(writes).toBe(1)

    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText(/^网站 new\.example\.com 创建成功。/)).toBeInTheDocument()
    const requests = fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST',
    )
    expect(requests).toHaveLength(2)
    expect(requests[0][1]?.body).toBe(requests[1][1]?.body)
    expect(requests[0][1]?.headers).toEqual(requests[1][1]?.headers)
  })

  it('abandons an unknown attempt when a field changes or the dialog closes', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites' && init?.method === 'POST') {
        return Promise.reject(new TypeError('connection reset'))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    const domain = within(dialog).getByRole('textbox', { name: '网站域名' })
    await user.type(domain, 'new.example.com')
    await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com')
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
    expect(await within(dialog).findByText('创建结果待确认')).toBeInTheDocument()

    await user.type(domain, '2')
    expect(within(dialog).queryByText('创建结果待确认')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
    expect(await within(dialog).findByText('创建结果待确认')).toBeInTheDocument()

    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const reopened = getDialog('添加网站')
    await user.type(within(reopened).getByRole('textbox', { name: '网站域名' }), 'third.example.com')
    await user.type(within(reopened).getByRole('textbox', { name: '源站地址' }), 'third-origin.example.com')
    await user.click(within(reopened).getByRole('button', { name: '创建网站' }))
    expect(await within(reopened).findByText('创建结果待确认')).toBeInTheDocument()

    const requests = fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites' && init?.method === 'POST',
    )
    expect(requests).toHaveLength(3)
    expect(requests[0][1]?.headers).not.toEqual(requests[1][1]?.headers)
    expect(requests[1][1]?.headers).not.toEqual(requests[2][1]?.headers)
  })

  it.each([
    ['tenant without sites.read', 'tenant', ['sites.manage']],
    ['tenant fake platform.admin', 'tenant', ['platform.admin']],
    ['platform without sites.read', 'platform', ['sites.manage']],
  ] as const)('%s is denied locally without a request', async (_name, kind, permissions) => {
    setSiteSession({ kind, permissions: [...permissions] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('无权查看网站列表')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少网站读取权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('accepts a tenant whose entity and access-scope IDs differ', async () => {
    setSiteSession({ kind: 'tenant', scopeID: tenantAID, tenantID: tenantBID })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())

    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText(site.domain)).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalled()
  })

  it('denies a platform principal carrying tenant identity without a request', async () => {
    const sessionOptions = { kind: 'platform' as const, tenantID: tenantAID }
    setSiteSession(sessionOptions)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(await screen.findByText('无权查看网站列表')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少网站读取权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keys tenant list data by the complete owner and session epoch without storing the token', async () => {
    const session = setSiteSession({ accessToken: 'site-owner-token' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const { queryClient } = renderPageWithQueryClient()
    const listKey = ['sites', session.owner, session.role, 1, 10, {}] as const

    expect(await screen.findByText(site.domain)).toBeInTheDocument()
    expect(queryClient.getQueryState(listKey)).toMatchObject({
      status: 'success',
      data: { items: [site], total: 1, page: 1, limit: 10 },
    })
    expect(session.owner.at(-1)).toBe(session.sessionEpoch)
    const serializedKeys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(serializedKeys).not.toContain('site-owner-token')
  })

  it('preserves page, draft, and selection across a same-epoch token refresh and refetches with the latest token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      () => Promise.resolve(response([site], 25)),
    )
    const session = setSiteSession({ accessToken: 'site-refresh-token-a' })
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient()

    await screen.findByText(site.domain)
    const quickDraft = screen.getByLabelText('快速搜索内容')
    await user.type(quickDraft, 'draft.example.com')
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(String(fetchSpy.mock.calls.at(-1)?.[0])).toContain('page=2'))
    const listKey = ['sites', session.owner, session.role, 2, 10, {}] as const
    const readsBeforeRefresh = fetchSpy.mock.calls.length

    act(() => setSiteSession({
      accessToken: 'site-refresh-token-b',
      update: 'refresh',
    }))

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(quickDraft).toHaveValue('draft.example.com')
    expect(screen.getByRole('checkbox', { name: site.domain })).toBeChecked()
    expect(screen.getByTitle('2')).toHaveClass('ant-pagination-item-active')

    await act(async () => {
      await queryClient.refetchQueries({ queryKey: listKey, type: 'active' })
    })
    expect(authorization(fetchSpy.mock.calls.at(-1)?.[1])).toBe('Bearer site-refresh-token-b')
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey)))
      .not.toMatch(/site-refresh-token-[ab]/)
  })

  it('resets local state and removes old owner queries when a new session starts', async () => {
    const siteB: SiteListItem = {
      ...site,
      id: 'site-b',
      domain: 'tenant-b.example.com',
      owner: { id: tenantBID, display_name: 'tenant-b' },
    }
    const pendingB = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      const token = authorization(init)
      if (token === 'Bearer site-new-session-a') return Promise.resolve(response([site]))
      if (token === 'Bearer site-new-session-b') return pendingB.promise
      return Promise.reject(new Error('unexpected site session token'))
    })
    const sessionA = setSiteSession({ accessToken: 'site-new-session-a' })
    const user = userEvent.setup({ delay: null })
    const { queryClient } = renderPageWithQueryClient()
    const listKeyA = ['sites', sessionA.owner, sessionA.role, 1, 10, {}] as const

    await screen.findByText(site.domain)
    await user.type(screen.getByLabelText('快速搜索内容'), 'tenant-a-draft')
    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    await user.type(screen.getByRole('textbox', { name: '网站域名' }), 'draft.example.com')
    queryClient.setQueryData(['site-detail', sessionA.owner, site.id], detailFor(site))
    const oldMutationKeys = [
      ['site-create', sessionA.owner],
      ['site-lock', sessionA.owner],
      ['site-batch', sessionA.owner],
    ] as const
    for (const mutationKey of oldMutationKeys) {
      queryClient.getMutationCache().build(queryClient, {
        mutationKey,
        mutationFn: async () => undefined,
      })
    }

    let sessionB!: ReturnType<typeof setSiteSession>
    act(() => {
      sessionB = setSiteSession({ accessToken: 'site-new-session-b' })
    })
    const listKeyB = ['sites', sessionB.owner, sessionB.role, 1, 10, {}] as const

    expect(sessionB.sessionEpoch).not.toBe(sessionA.sessionEpoch)
    expect(queryDialog('添加网站')).not.toBeInTheDocument()
    expect(screen.getByLabelText('快速搜索内容')).toHaveValue('')
    expect(screen.queryByText(site.domain)).not.toBeInTheDocument()
    expect(screen.getByTestId('site-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(queryClient.getQueryState(listKeyA)).toBeUndefined()
    expect(queryClient.getQueryState(['site-detail', sessionA.owner, site.id])).toBeUndefined()
    for (const mutationKey of oldMutationKeys) {
      expect(queryClient.getMutationCache().findAll({ mutationKey, exact: true })).toHaveLength(0)
    }
    expect(queryClient.getQueryState(listKeyB)).toMatchObject({ status: 'pending', data: undefined })

    await act(async () => pendingB.resolve(response([siteB])))
    expect(await screen.findByText(siteB.domain)).toBeInTheDocument()
    expect(queryClient.getQueryData(listKeyB)).toEqual({
      items: [siteB], total: 1, page: 1, limit: 10,
    })
    expect(authorization(fetchSpy.mock.calls.at(-1)?.[1])).toBe('Bearer site-new-session-b')
  })

  it.each([
    ['create', 'tenant', 'permission_denied'],
    ['lock', 'platform', 'forbidden'],
    ['batch', 'platform', 'permission_denied'],
  ] as const)(
    'makes a current-owner %s authorization denial terminal without retrying or reopening after token refresh',
    async (kind, role, code) => {
      const rawMessage = `private ${kind} denial detail`
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
        if (kind === 'lock' && url === '/v1/sites/site-1' && !init?.method) {
          return Promise.resolve(jsonResponse(detailFor(site)))
        }
        if (init?.method === 'POST') {
          return Promise.resolve(jsonResponse({ error: { code, message: rawMessage } }, 403))
        }
        return Promise.reject(new Error(`unexpected terminal ${kind} request ${url}`))
      })
      const session = setSiteSession({ kind: role, accessToken: `site-terminal-${kind}-a` })
      const user = userEvent.setup({ delay: null })
      const { queryClient } = renderPageWithQueryClient()
      await screen.findByText(site.domain)

      if (kind === 'create') {
        await user.click(screen.getByRole('button', { name: '添加网站' }))
        const dialog = getDialog('添加网站')
        await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'denied.example.com')
        await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com')
        await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
      } else if (kind === 'lock') {
        await user.click(screen.getByRole('button', { name: '更多' }))
        await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
        const dialog = await findDialog('锁定网站')
        await user.type(within(dialog).getByLabelText('锁定原因'), 'terminal permission review')
        await user.click(within(dialog).getByRole('button', { name: '确认锁定' }))
      } else {
        await user.click(screen.getByRole('checkbox', { name: site.domain }))
        await user.click(screen.getByRole('button', { name: /更多操作/ }))
        await user.click(await screen.findByText('删除'))
        const finalDialog = await findDialog('批量删除')
        await user.click(within(finalDialog).getByRole('button', { name: '确认删除' }))
      }

      expect(await screen.findByText('无权查看网站列表')).toBeInTheDocument()
      expect(screen.queryByText(rawMessage)).not.toBeInTheDocument()
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
      const requestsBeforeRefresh = fetchSpy.mock.calls.length
      const mutationKey = [`site-${kind}`, session.owner] as const
      await waitFor(() =>
        expect(queryClient.getMutationCache().findAll({ mutationKey, exact: true })).toHaveLength(0),
      )

      act(() => setSiteSession({
        kind: role,
        accessToken: `site-terminal-${kind}-b`,
        update: 'refresh',
      }))
      await act(async () => { await Promise.resolve() })

      expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
      expect(fetchSpy).toHaveBeenCalledTimes(requestsBeforeRefresh)
      expect(screen.getByText('无权查看网站列表')).toBeInTheDocument()
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    },
  )

  it.each([
    ['list', 'success'],
    ['list', 'error'],
    ['detail', 'success'],
    ['detail', 'error'],
  ] as const)(
    'isolates a late owner A %s %s after switching to owner B',
    async (lateKind, outcome) => {
      const siteB: SiteListItem = {
        ...site,
        id: 'site-b',
        domain: 'owner-b.example.com',
        owner: { id: tenantBID, display_name: 'owner-b' },
      }
      const late = deferred<Response>()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        const token = authorization(init)
        if (token === 'Bearer site-late-read-a') {
          if (url.startsWith('/v1/sites?')) {
            return lateKind === 'list' ? late.promise : Promise.resolve(response([site]))
          }
          if (url === '/v1/sites/site-1' && !init?.method) {
            return lateKind === 'detail' ? late.promise : Promise.resolve(jsonResponse(detailFor(site)))
          }
        }
        if (token === 'Bearer site-late-read-b' && url.startsWith('/v1/sites?')) {
          return Promise.resolve(response([siteB]))
        }
        return Promise.reject(new Error('unexpected stale read request'))
      })
      const sessionA = setSiteSession({
        kind: 'platform',
        accessToken: 'site-late-read-a',
      })
      const user = userEvent.setup({ delay: null })
      const { queryClient } = renderPageWithQueryClient()

      if (lateKind === 'detail') {
        await screen.findByText(site.domain)
        await user.click(screen.getByRole('button', { name: '更多' }))
        await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
        expect(await findDialog('锁定网站')).toBeInTheDocument()
      } else {
        await waitFor(() => expect(fetchSpy).toHaveBeenCalledOnce())
      }

      let sessionB!: ReturnType<typeof setSiteSession>
      act(() => {
        sessionB = setSiteSession({
          kind: 'platform',
          scopeID: tenantBID,
          userID: tenantBUserID,
          accessToken: 'site-late-read-b',
        })
      })
      const listKeyB = ['sites', sessionB.owner, sessionB.role, 1, 10, {}] as const
      expect(await screen.findByText(siteB.domain)).toBeInTheDocument()
      expect(screen.queryByText(site.domain)).not.toBeInTheDocument()
      expect(queryDialog('锁定网站')).not.toBeInTheDocument()

      await act(async () => {
        late.resolve(outcome === 'success'
          ? lateKind === 'list' ? response([site]) : jsonResponse(detailFor(site))
          : jsonResponse({ error: { code: 'unavailable', message: 'private late owner A read' } }, 503))
        await new Promise<void>((resolve) => setTimeout(resolve, 0))
      })

      const listKeyA = ['sites', sessionA.owner, sessionA.role, 1, 10, {}] as const
      const detailKeyA = ['site-detail', sessionA.owner, site.id] as const
      expect(screen.getByText(siteB.domain)).toBeInTheDocument()
      expect(screen.queryByText(site.domain)).not.toBeInTheDocument()
      expect(screen.queryByText('private late owner A read')).not.toBeInTheDocument()
      expect(screen.queryByText('网站列表加载失败')).not.toBeInTheDocument()
      expect(queryClient.getQueryState(listKeyA)).toBeUndefined()
      expect(queryClient.getQueryState(detailKeyA)).toBeUndefined()
      expect(queryClient.getQueryData(listKeyB)).toEqual({
        items: [siteB], total: 1, page: 1, limit: 10,
      })
    },
  )

  it.each([
    ['create', 'success'],
    ['create', 'error'],
    ['lock', 'success'],
    ['lock', 'error'],
    ['batch', 'success'],
    ['batch', 'error'],
  ] as const)(
    'isolates a late owner A %s %s without mutating owner B state or cache',
    async (kind, outcome) => {
      const role = kind === 'create' ? 'tenant' : 'platform'
      const siteB: SiteListItem = {
        ...site,
        id: 'site-b',
        domain: 'write-owner-b.example.com',
        owner: { id: tenantBID, display_name: 'write-owner-b' },
      }
      const lateWrite = deferred<Response>()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        const token = authorization(init)
        if (url.startsWith('/v1/sites?')) {
          if (token === 'Bearer site-late-write-a') return Promise.resolve(response([site]))
          if (token === 'Bearer site-late-write-b') return Promise.resolve(response([siteB]))
        }
        if (token === 'Bearer site-late-write-a' && url === '/v1/sites/site-1' && !init?.method) {
          return Promise.resolve(jsonResponse(detailFor(site)))
        }
        const expectedWrite = kind === 'create'
          ? url === '/v1/sites' && init?.method === 'POST'
          : kind === 'lock'
            ? url.endsWith('/lock') && init?.method === 'POST'
            : url === '/v1/sites/batch-action' && init?.method === 'POST'
        if (token === 'Bearer site-late-write-a' && expectedWrite) return lateWrite.promise
        return Promise.reject(new Error('unexpected stale write request'))
      })
      setSiteSession({ kind: role, accessToken: 'site-late-write-a' })
      const user = userEvent.setup({ delay: null })
      const { queryClient } = renderPageWithQueryClient()
      await screen.findByText(site.domain)

      if (kind === 'create') {
        await user.click(screen.getByRole('button', { name: '添加网站' }))
        const dialog = getDialog('添加网站')
        await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'late-a.example.com')
        await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com')
        await user.click(within(dialog).getByRole('button', { name: '创建网站' }))
      } else if (kind === 'lock') {
        await user.click(screen.getByRole('button', { name: '更多' }))
        await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
        const dialog = await findDialog('锁定网站')
        await user.type(within(dialog).getByLabelText('锁定原因'), 'owner A review')
        await user.click(within(dialog).getByRole('button', { name: '确认锁定' }))
      } else {
        await user.click(screen.getByRole('checkbox', { name: site.domain }))
        await user.click(screen.getByRole('button', { name: /更多操作/ }))
        await user.click(await screen.findByText('启用'))
        await user.click(
          within(await findDialog('批量启用'))
            .getByRole('button', { name: '确认启用' }),
        )
      }
      await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1))

      let sessionB!: ReturnType<typeof setSiteSession>
      act(() => {
        sessionB = setSiteSession({
          kind: role,
          scopeID: tenantBID,
          tenantID: role === 'tenant' ? tenantBID : null,
          userID: tenantBUserID,
          accessToken: 'site-late-write-b',
        })
      })
      const listKeyB = ['sites', sessionB.owner, sessionB.role, 1, 10, {}] as const
      expect(await screen.findByText(siteB.domain)).toBeInTheDocument()
      const ownerBReadsBeforeLate = fetchSpy.mock.calls.filter(
        ([url, init]) => String(url).startsWith('/v1/sites?') &&
          authorization(init) === 'Bearer site-late-write-b',
      ).length

      await act(async () => {
        const success = kind === 'create'
          ? jsonResponse(createdDetail('late-a.example.com'), 201)
          : kind === 'lock'
            ? jsonResponse({
                ...detailFor(site, 8),
                lock: {
                  locked: true,
                  reason: 'owner A review',
                  locked_at: '2026-07-22T10:00:00Z',
                  operator: { display_name: 'owner A' },
                },
              })
            : jsonResponse({
                items: [{ id: site.id, status: 'updated', site: changedDetail(site, 8, true) }],
              })
        lateWrite.resolve(outcome === 'success'
          ? success
          : jsonResponse({ error: { code: 'unavailable', message: 'private stale owner A write' } }, 503))
        await new Promise<void>((resolve) => setTimeout(resolve, 0))
      })

      expect(screen.getByText(siteB.domain)).toBeInTheDocument()
      expect(screen.queryByText(site.domain)).not.toBeInTheDocument()
      expect(screen.queryByText('private stale owner A write')).not.toBeInTheDocument()
      expect(screen.queryByText(/^网站 late-a\.example\.com 创建成功/)).not.toBeInTheDocument()
      expect(screen.queryByText('网站 www.example.com 已锁定')).not.toBeInTheDocument()
      expect(screen.queryByText('批量操作结果待确认')).not.toBeInTheDocument()
      expect(queryDialog('批量操作结果')).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(
        ([url, init]) => String(url).startsWith('/v1/sites?') &&
          authorization(init) === 'Bearer site-late-write-b',
      )).toHaveLength(ownerBReadsBeforeLate)
      expect(fetchSpy.mock.calls.filter(
        ([, init]) => init?.method === 'POST' &&
          authorization(init) === 'Bearer site-late-write-b',
      )).toHaveLength(0)
      expect(queryClient.getQueryData(listKeyB)).toEqual({
        items: [siteB], total: 1, page: 1, limit: 10,
      })
    },
  )

  it.each(['create', 'lock', 'batch'] as const)(
    'blocks a stale %s handler after same-epoch sites.manage revocation',
    async (kind) => {
      const role = kind === 'create' ? 'tenant' : 'platform'
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
        if (url === '/v1/sites/site-1' && !init?.method) {
          return Promise.resolve(jsonResponse(detailFor(site)))
        }
        if (init?.method === 'POST') {
          return Promise.resolve(jsonResponse({ error: { code: 'unexpected_write' } }, 500))
        }
        return Promise.reject(new Error('unexpected revocation request'))
      })
      const session = setSiteSession({ kind: role, accessToken: 'site-manage-before-revocation' })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)
      let staleSubmit: HTMLElement

      if (kind === 'create') {
        await user.click(screen.getByRole('button', { name: '添加网站' }))
        const dialog = getDialog('添加网站')
        await user.type(within(dialog).getByRole('textbox', { name: '网站域名' }), 'revoked.example.com')
        await user.type(within(dialog).getByRole('textbox', { name: '源站地址' }), 'origin.example.com')
        staleSubmit = within(dialog).getByRole('button', { name: '创建网站' })
      } else if (kind === 'lock') {
        await user.click(screen.getByRole('button', { name: '更多' }))
        await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
        const dialog = await findDialog('锁定网站')
        await user.type(within(dialog).getByLabelText('锁定原因'), 'revoked review')
        staleSubmit = within(dialog).getByRole('button', { name: '确认锁定' })
      } else {
        await user.click(screen.getByRole('checkbox', { name: site.domain }))
        await user.click(screen.getByRole('button', { name: /更多操作/ }))
        await user.click(await screen.findByText('禁用'))
        staleSubmit = within(await findDialog('批量禁用'))
          .getByRole('button', { name: '确认禁用' })
      }
      const readsBeforeRevocation = fetchSpy.mock.calls.length

      act(() => {
        setSiteSession({
          kind: role,
          accessToken: 'site-manage-after-revocation',
          permissions: ['sites.read'],
          update: 'refresh',
        })
        fireEvent.click(staleSubmit)
      })

      expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
      await act(async () => { await Promise.resolve() })
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
      expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRevocation)
      expect(screen.getAllByText(site.domain).length).toBeGreaterThan(0)
      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: /更多操作/ })).toBeDisabled()
      if (role === 'tenant') {
        expect(screen.getByRole('button', { name: '添加网站' })).toBeDisabled()
      }
    },
  )

  it.each(['success', 'unknown error'] as const)(
    'review closure preserves an in-flight lock %s across same-epoch manage revocation',
    async (outcome) => {
      const pendingLock = deferred<Response>()
      const saved: SiteDetail = {
        ...detailFor(site, 8),
        lock: {
          locked: true,
          reason: 'revocation review',
          locked_at: '2026-07-22T10:30:00Z',
          operator: { display_name: 'platform admin' },
        },
      }
      let lockWriteCount = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
        if (url === '/v1/sites/site-1' && !init?.method) {
          return Promise.resolve(jsonResponse(detailFor(site)))
        }
        if (url.endsWith('/lock') && init?.method === 'POST') {
          lockWriteCount += 1
          return lockWriteCount === 1 ? pendingLock.promise : Promise.resolve(jsonResponse(saved))
        }
        return Promise.reject(new Error(`unexpected revocation lock request ${url}`))
      })
      const session = setSiteSession({
        kind: 'platform',
        accessToken: 'site-lock-before-revocation',
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)

      await user.click(screen.getByRole('button', { name: '更多' }))
      await user.click(await screen.findByText('锁定网站（继续服务，禁止用户修改）'))
      const dialog = await findDialog('锁定网站')
      await user.type(within(dialog).getByLabelText('锁定原因'), 'revocation review')
      await user.click(within(dialog).getByRole('button', { name: '确认锁定' }))
      await waitFor(() =>
        expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/lock'))).toHaveLength(1),
      )
      const firstWrite = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/lock'))!
      const firstKey = (firstWrite[1]?.headers as Record<string, string>)['Idempotency-Key']

      act(() => {
        setSiteSession({
          kind: 'platform',
          accessToken: 'site-lock-revoked',
          permissions: ['sites.read'],
          update: 'refresh',
        })
      })
      expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)

      await act(async () => {
        if (outcome === 'success') pendingLock.resolve(jsonResponse(saved))
        else pendingLock.reject(new TypeError('connection reset during revocation'))
        await new Promise<void>((resolve) => setTimeout(resolve, 0))
      })

      act(() => {
        setSiteSession({
          kind: 'platform',
          accessToken: 'site-lock-restored',
          permissions: ['sites.read', 'sites.manage'],
          update: 'refresh',
        })
      })
      expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)

      if (outcome === 'success') {
        const staleConfirm = screen.queryByRole('button', { name: '确认锁定' })
        if (staleConfirm) await user.click(staleConfirm)
        const writes = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/lock'))
        expect(writes).toHaveLength(1)
        expect(
          screen.queryByText('网站 www.example.com 已锁定') ??
            screen.queryByRole('button', { name: '重新加载状态' }),
        ).toBeInTheDocument()
        return
      }

      const retry = screen.queryByRole('button', { name: '使用同一请求重试' }) ??
        screen.getByRole('button', { name: '确认锁定' })
      await user.click(retry)
      await waitFor(() =>
        expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/lock'))).toHaveLength(2),
      )
      const writes = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/lock'))
      expect(writes[1][1]?.body).toBe(firstWrite[1]?.body)
      expect(authorization(writes[1][1])).toBe('Bearer site-lock-restored')
      expect((writes[1][1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(firstKey)
      expect(retry).toHaveAccessibleName('使用同一请求重试')
    },
  )

  it('review closure restores a batch retry for the same stable owner across epochs without exposing it cross-owner', async () => {
    const retryInput = {
      action: 'disable' as const,
      items: [{ id: site.id, expected_version: site.version }],
    }
    const retryAttempt = {
      action: retryInput.action,
      targets: [{ id: site.id, domain: site.domain, version: site.version }],
      input: retryInput,
      body: JSON.stringify(retryInput),
      key: 'site-batch-disable-recovered',
    }
    const retryKey =
      `cdnca:site-batch-retry:tenant:${tenantAID}:${tenantAID}:${tenantAUserID}`
    sessionStorage.setItem(retryKey, JSON.stringify(retryAttempt))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response([site]))
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({
          items: [{ id: site.id, status: 'updated', site: changedDetail(site, 8, false) }],
        }))
      }
      return Promise.reject(new Error('unexpected retry recovery request'))
    })
    const sessionA = setSiteSession({ accessToken: 'site-retry-epoch-a' })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    let refreshedA!: ReturnType<typeof setSiteSession>
    act(() => {
      refreshedA = setSiteSession({ accessToken: 'site-retry-epoch-b' })
    })
    expect(refreshedA.sessionEpoch).not.toBe(sessionA.sessionEpoch)
    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    act(() => setSiteSession({
      scopeID: tenantBID,
      tenantID: tenantBID,
      userID: tenantBUserID,
      accessToken: 'site-retry-owner-b',
    }))
    await waitFor(() => expect(screen.queryByText('批量操作结果待确认')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(sessionStorage.getItem(retryKey)).toBe(JSON.stringify(retryAttempt))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)

    act(() => setSiteSession({ accessToken: 'site-retry-epoch-c' }))
    expect(await screen.findByText('批量操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await findDialog('批量操作结果')).toBeInTheDocument()

    const retryWrites = fetchSpy.mock.calls.filter(
      ([url, init]) => String(url) === '/v1/sites/batch-action' && init?.method === 'POST',
    )
    expect(retryWrites).toHaveLength(1)
    expect(authorization(retryWrites[0][1])).toBe('Bearer site-retry-epoch-c')
    expect(retryWrites[0][1]?.body).toBe(retryAttempt.body)
    expect((retryWrites[0][1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(retryAttempt.key)
    expect(sessionStorage.getItem(retryKey)).toBeNull()
  })

  it.each(['admin', 'user'] as const)(
    'queues durable CNAME regeneration for an authorized %s',
    async (role) => {
      const failedSite: SiteListItem = { ...site, cname_state: 'failed', cname_task_id: null }
      const taskID = '99999999-9999-4999-8999-999999999999'
      const queued = detailFor(failedSite, 8)
      queued.basic = {
        ...queued.basic,
        cname_state: 'pending',
        cname_task_id: taskID,
        sync_status: 'pending',
      }
      authenticate(role, ['sites.read', 'sites.manage', 'dns.manage'])
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/sites?')) return Promise.resolve(response([failedSite]))
        if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
          return Promise.resolve(jsonResponse({
            items: [{ id: failedSite.id, status: 'queued', site: queued }],
          }))
        }
        return Promise.reject(new Error(`unexpected CNAME regeneration request ${url}`))
      })
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(failedSite.domain)

      await user.click(screen.getByRole('checkbox', { name: failedSite.domain }))
      await user.click(screen.getByRole('button', { name: /更多操作/ }))
      await user.click(await screen.findByText('重新生成 CNAME'))
      const dialog = await findDialog('重新生成 CNAME')
      await user.click(within(dialog).getByRole('button', { name: '确认重新生成' }))

      const result = await findDialog('批量操作结果')
      expect(within(result).getByText('已排队')).toBeInTheDocument()
      expect(within(result).getByText(`任务 ID：${taskID}`)).toBeInTheDocument()
      const writes = fetchSpy.mock.calls.filter(
        ([url, init]) => String(url) === '/v1/sites/batch-action' && init?.method === 'POST',
      )
      expect(writes).toHaveLength(1)
      expect(JSON.parse(String(writes[0][1]?.body))).toEqual({
        action: 'regenerate_cname',
        items: [{ id: failedSite.id, expected_version: failedSite.version }],
      })
    },
  )

  it.each(['admin', 'user'] as const)(
    'does not mount CNAME regeneration or issue writes without dns.manage for %s',
    async (role) => {
      authenticate(role, ['sites.read', 'sites.manage'])
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response([
        { ...site, cname_state: 'failed', cname_task_id: null },
      ]))
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)

      await user.click(screen.getByRole('checkbox', { name: site.domain }))
      await user.click(screen.getByRole('button', { name: /更多操作/ }))

      expect(screen.queryByText('重新生成 CNAME')).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
    },
  )

  it('matches the batch-create surface and creates rows in input order', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const savedRows = [createdDetail('one.example.com', 'origin-one.example.com:8080'), createdDetail('two.example.com', 'origin-two.example.com:8081')]
    let createIndex = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(response())
      if (url === '/v1/sites' && init?.method === 'POST') return Promise.resolve(jsonResponse(savedRows[createIndex++]!, 201))
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    expect(within(dialog).getByRole('tab', { name: '单个' })).toHaveAttribute('aria-selected', 'true')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    await user.type(within(dialog).getByRole('textbox', { name: '网站数据' }), 'domain=one.example.com|ip=origin-one.example.com:8080\ndomain=two.example.com|ip=origin-two.example.com:8081')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2))
    expect(JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')?.[1]?.body))).toMatchObject({
      basic: { domains: ['one.example.com'], origins: ['origin-one.example.com:8080'] },
      origin_pool: { origins: [{ host: 'origin-one.example.com', port: 8080 }] },
    })
  })

  it('stops batch creation immediately after the session changes even when errors are ignored', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    let finishFirst!: (value: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) === '/v1/sites' && init?.method === 'POST') return new Promise((resolve) => { finishFirst = resolve })
      return Promise.resolve(response())
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80\ndomain=two.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('switch', { name: '忽略错误' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(finishFirst).toBeTypeOf('function'))
    await act(async () => {
      setSiteSession({ scopeID: tenantBID, tenantID: tenantBID, userID: tenantBUserID })
      finishFirst(jsonResponse(createdDetail('one.example.com', '192.0.2.80'), 201))
    })
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
  })

  it('locks a batch with an unknown result to the same bodies and keys', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) =>
      String(input) === '/v1/sites' && init?.method === 'POST'
        ? Promise.reject(new TypeError('network')) : Promise.resolve(response()))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('创建结果待确认')
    expect(within(dialog).getByRole('textbox', { name: '网站数据' })).toBeDisabled()
    expect(within(dialog).getByRole('tab', { name: '单个' })).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2))
    const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(writes[1][1]?.body).toBe(writes[0][1]?.body)
    expect(writes[1][1]?.headers).toEqual(writes[0][1]?.headers)
  })

  it.each([409, 422])('keeps an unknown batch locked after an HTTP %s retry rejection', async (status) => {
    authenticate('user', ['sites.read', 'sites.manage'])
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) !== '/v1/sites' || init?.method !== 'POST') return Promise.resolve(response())
      writes += 1
      return writes === 1 ? Promise.reject(new TypeError('network'))
        : Promise.resolve(jsonResponse({ code: 'validation_error' }, status))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('创建结果待确认')
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '使用同一请求重试' })).not.toHaveClass('ant-btn-loading'))
    expect(within(dialog).getByRole('textbox', { name: '网站数据' })).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    expect(sessionStorage).toHaveLength(1)
  })

  it.each(['pending', 'unknown'] as const)('restores a %s create batch after remount without sending automatically', async (failure) => {
    setSiteSession({ accessToken: 'before-remount' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) !== '/v1/sites' || init?.method !== 'POST') return Promise.resolve(response())
      if (authorization(init) === 'after-remount') throw new Error('Bearer prefix missing')
      if (authorization(init) === 'Bearer before-remount') return failure === 'pending'
        ? new Promise<Response>(() => undefined) : Promise.reject(new TypeError('network'))
      return Promise.resolve(jsonResponse(createdDetail('one.example.com', '192.0.2.80'), 201))
    })
    const user = userEvent.setup({ delay: null })
    const page = renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1))
    expect(sessionStorage).toHaveLength(1)
    page.unmount()
    act(() => setSiteSession({ accessToken: 'after-remount' }))
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const restored = await findDialog('添加网站')
    expect(within(restored).getByRole('textbox', { name: '网站数据' })).toBeDisabled()
    expect(within(restored).getByRole('textbox', { name: '网站数据' })).toHaveValue('domain=one.example.com|ip=192.0.2.80')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    await user.click(within(restored).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(sessionStorage).toHaveLength(0))
    const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(writes).toHaveLength(2)
    expect(writes[1][1]?.body).toBe(writes[0][1]?.body)
    expect((writes[1][1]?.headers as Record<string, string>)['Idempotency-Key']).toBe((writes[0][1]?.headers as Record<string, string>)['Idempotency-Key'])
    expect(authorization(writes[1][1])).toBe('Bearer after-remount')
  })

  it('does not send a create batch when its retry record cannot be saved', async () => {
    authenticate('user', ['sites.read', 'sites.manage'])
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('无法保存安全重试记录，尚未发送请求。请检查浏览器存储后重试。')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  it('never resumes an unmounted create batch after same-epoch permission restoration', async () => {
    const session = setSiteSession()
    const first = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) =>
      String(input) === '/v1/sites' && init?.method === 'POST' ? first.promise : Promise.resolve(response()))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80\ndomain=two.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1))
    act(() => useSessionStore.setState({ principal: { ...session.actor, permissions: ['sites.read'] } }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    act(() => useSessionStore.setState({ principal: session.actor }))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    const restored = await findDialog('添加网站')
    await act(async () => first.resolve(jsonResponse(createdDetail('one.example.com', '192.0.2.80'), 201)))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    expect(restored).toBeInTheDocument()
    expect(sessionStorage).toHaveLength(1)
  })

  it('keeps only unsuccessful rows editable after partial batch creation', async () => {
    setSiteSession()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) !== '/v1/sites' || init?.method !== 'POST') return Promise.resolve(response())
      const body = JSON.parse(String(init.body))
      return Promise.resolve(body.basic.domains[0] === 'one.example.com'
        ? jsonResponse(createdDetail('one.example.com', '192.0.2.80'), 201)
        : jsonResponse({ code: 'site_domain_conflict' }, 409))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: '添加网站' }))
    const dialog = getDialog('添加网站')
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: '网站数据' }), { target: { value: 'domain=one.example.com|ip=192.0.2.80\ndomain=two.example.com|ip=192.0.2.80' } })
    await user.click(within(dialog).getByRole('switch', { name: '忽略错误' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('批量创建完成：成功 1 条，失败 1 条')
    expect(within(dialog).getByRole('textbox', { name: '网站数据' })).toHaveValue('domain=two.example.com|ip=192.0.2.80')
    expect(sessionStorage).toHaveLength(0)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2)
  })
})
