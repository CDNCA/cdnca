import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { act, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteDetail, SiteListItem, SiteListResponse } from '../api/sites'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import SiteEditPage from '../pages/SiteEditPage'
import SiteListPage from '../pages/SiteListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 网站列表点「管理」后编辑页一直转圈，刷新才正常。
// 实测：GET /v1/sites/{id} 200 已返回，页面仍停在 site-edit-loading，无挂起请求。
// 根因：列表页卸载清理按前缀删 ['site-detail', owner]，把编辑页刚建好的详情 query 一起删掉
// （removeQueries → query.destroy → 静默取消），编辑页的观察者挂在已删的 query 上，永远 pending。

const scopeID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const site: SiteListItem = {
  id: 'site-1', display_id: '27', version: 7,
  owner: { id: 'tenant-1', display_id: '2', display_name: 'cdnca-t1' },
  domain: 'cdnca-t1.example.com', listen_ports: ['80'], origins: ['192.0.2.10:443'],
  cname: '', cname_state: 'pending', https_enabled: false,
  package: { id: 'package-1', name: '测试套餐' }, group_name: null, region: null, status: 'active',
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  created_at: '2026-10-24T03:41:03Z',
}
const detail: SiteDetail = {
  id: site.id, version: 7, owner: site.owner, created_at: site.created_at, updated_at: site.created_at,
  lock: site.lock, listener_state: site.listener_state,
  origin_pool: { origins: [{ host: '192.0.2.10', port: 443, weight: 1, enabled: true }], balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000 },
  basic: {
    package_id: 'package-1', package_name: '测试套餐', group_id: null, group_name: null,
    domains: [site.domain], http_enabled: true, http_listen_ports: ['80'], https_listen_ports: [],
    ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'], origins: site.origins,
    cname: '', cname_state: 'pending', https_enabled: false, enabled: true, status: 'active',
    sync_status: 'synced', is_default: false,
  },
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function authenticateAdmin() {
  const actor = principal({
    scope_kind: 'platform', scope_id: scopeID, tenant_id: null, username: 'admin', display_name: 'admin',
    roles: ['platform_admin'], permissions: ['sites.read', 'sites.manage'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function mockFetch(detailResponse: () => Response) {
  let detailCalls = 0
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    if (url.endsWith(`/v1/sites/${site.id}`)) {
      detailCalls += 1
      return detailResponse()
    }
    if (url.startsWith('/v1/sites?') || url === '/v1/sites') {
      const body: SiteListResponse = { items: [site], total: 1, page: 1, limit: 10 }
      return json(body)
    }
    return json({ items: [] })
  })
  return () => detailCalls
}

function renderListAndEdit() {
  renderWithProviders(
    <Routes>
      <Route path="/site/list" element={<SiteListPage />} />
      <Route path="/site/:id/edit" element={<SiteEditPage />} />
    </Routes>,
    ['/site/list'],
  )
}

async function clickManage() {
  const user = userEvent.setup({ delay: null })
  const row = (await screen.findByText(site.domain)).closest('tr')
  if (!row) throw new Error('site row not found')
  await user.click(within(row).getByRole('button', { name: '管理' }))
}

beforeEach(async () => {
  vi.restoreAllMocks()
  sessionStorage.clear()
  resetSessionStore()
  await i18n.changeLanguage('zh-CN')
})

describe('site list → 管理 → edit page', () => {
  it('shows the edit page content after a client-side navigation from the list', async () => {
    authenticateAdmin()
    const detailCalls = mockFetch(() => json(detail))
    renderListAndEdit()
    await clickManage()

    expect(await screen.findByRole('heading', { name: site.domain }, { timeout: 3000 })).toBeInTheDocument()
    expect(await screen.findByLabelText('域名', undefined, { timeout: 3000 })).toBeInTheDocument()
    expect(detailCalls()).toBe(1)
  })

  it('shows a retryable error state when the detail request fails after navigating from the list', async () => {
    authenticateAdmin()
    let fail = true
    mockFetch(() => fail
      ? json({ error: { code: 'internal_error', message: 'boom', request_id: 'req-1' } }, 500)
      : json(detail))
    renderListAndEdit()
    await clickManage()

    expect(await screen.findByText('网站详情加载失败', undefined, { timeout: 3000 })).toBeInTheDocument()
    expect(document.querySelector('.site-edit-loading')).toBeNull()
    fail = false
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByRole('heading', { name: site.domain })).toBeInTheDocument()
  })

  it('does not spin forever when the in-flight detail query is removed from the cache', async () => {
    authenticateAdmin()
    let release!: () => void
    let first = true
    mockFetch(() => json(detail))
    const fetchMock = vi.mocked(globalThis.fetch)
    const original = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (input, init) => {
      if (first && String(input).endsWith(`/v1/sites/${site.id}`)) {
        first = false
        await new Promise<void>((resolve) => { release = resolve })
      }
      return original(input, init)
    })
    let queryClient: QueryClient | undefined
    function Capture() { queryClient = useQueryClient(); return null }
    renderWithProviders(
      <><Capture /><Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes></>,
      [`/site/${site.id}/edit`],
    )
    expect(await screen.findByLabelText('网站详情加载中')).toBeInTheDocument()
    // 模拟任何外部清理（旧缺陷里是列表页卸载）在请求途中删掉详情 query。
    act(() => queryClient!.removeQueries({ queryKey: ['site-detail'] }))
    release()

    // 编辑页发现自己的 query 被删，按当前 key 重新拉取，内容正常出现。
    expect(await screen.findByRole('heading', { name: site.domain }, { timeout: 3000 })).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith(`/v1/sites/${site.id}`))).toHaveLength(2)
  })

  // be-gap-2 A11 / WEB-C08: a detail request that never answers no longer spins without an exit.
  it('bounds a detail request that never answers and re-reads it on request', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      authenticateAdmin()
      let first = true
      mockFetch(() => json(detail))
      const fetchMock = vi.mocked(globalThis.fetch)
      const original = fetchMock.getMockImplementation()!
      fetchMock.mockImplementation(async (input, init) => {
        if (first && String(input).endsWith(`/v1/sites/${site.id}`)) {
          first = false
          return new Promise<Response>(() => undefined) // hangs forever
        }
        return original(input, init)
      })
      renderWithProviders(<Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>, [`/site/${site.id}/edit`])
      expect(await screen.findByLabelText('网站详情加载中')).toBeInTheDocument()
      expect(screen.queryByText('网站详情加载时间较长')).not.toBeInTheDocument()

      act(() => { vi.advanceTimersByTime(15_000) })
      expect(await screen.findByText('网站详情加载时间较长')).toBeInTheDocument()
      expect(screen.getByText(/详情请求还没有返回/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '返回网站列表' })).toBeInTheDocument()

      await userEvent.setup({ delay: null, advanceTimers: vi.advanceTimersByTime }).click(screen.getByRole('button', { name: '重新读取' }))
      expect(await screen.findByRole('heading', { name: site.domain })).toBeInTheDocument()
      expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith(`/v1/sites/${site.id}`))).toHaveLength(2)
    } finally {
      vi.useRealTimers()
    }
  })
})
