import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import AccountQuotaPanel from '../pages/users/AccountQuotaPanel'
import { renderWithProviders } from '../test/render'

// 用户编辑「刷新预热额度」页签（fix-cachequota）：GET/PUT /v1/admin/cache-operations/daily-usage?scope_id=。
const tenantScope = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const quotaPath = `/v1/admin/cache-operations/daily-usage?scope_id=${tenantScope}`

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function usage(revision: number, url: { used: number; override: number | null }) {
  const limit = url.override ?? 2000
  return {
    scope_id: tenantScope, revision, resets_at: '2026-10-28T16:00:00Z',
    url_purge: { limit, used: url.used, remaining: Math.max(limit - url.used, 0), default_limit: 2000, override: url.override },
    directory_purge: { limit: 500, used: 2, remaining: 498, default_limit: 500, override: null },
    prewarm: { limit: 2000, used: 0, remaining: 2000, default_limit: 2000, override: null },
  }
}

describe('AccountQuotaPanel', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('shows today\'s use, refreshes it, and saves the account\'s own limits with empty = default', async () => {
    let used = 3
    const puts: unknown[] = []
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe(quotaPath)
      if (init?.method === 'PUT') {
        puts.push(JSON.parse(init.body as string))
        return json(usage(1, { used, override: 5000 }))
      }
      return json(usage(puts.length, { used, override: puts.length ? 5000 : null }))
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<AccountQuotaPanel scopeID={tenantScope} accessToken={() => 'token'} canManage />)

    const panel = await screen.findByTestId('account-quota-panel')
    // fix-cachequota2：主账号与成员共用；平台管理员代提交不计入。
    expect(within(panel).getByText(/主账号和成员共用.*平台管理员代提交不计入/)).toBeInTheDocument()
    const table = await within(panel).findByRole('table')
    const urlRow = (await within(table).findByText('刷新 URL')).closest('tr')!
    expect(within(urlRow).getByText('3')).toBeInTheDocument()
    expect(within(urlRow).getByText('1,997')).toBeInTheDocument()
    expect(within(urlRow).getByText('默认')).toBeInTheDocument()

    // 「刷新」重读最新已用。
    used = 7
    await user.click(within(panel).getByRole('button', { name: '刷新' }))
    expect(await within(urlRow).findByText('1,993')).toBeInTheDocument()

    const urlLimit = within(panel).getByRole('spinbutton', { name: '刷新 URL' })
    expect(urlLimit).toHaveAttribute('placeholder', '默认 2,000')
    await user.type(urlLimit, '5000')
    await user.click(within(panel).getByRole('button', { name: '保存额度' }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toEqual({ expected_revision: 0, url_purge_limit: 5000, directory_purge_limit: null, prewarm_limit: null })
    expect(await within(panel).findByText('单独设置', { selector: '.ant-tag' })).toBeInTheDocument()
  })

  it('reloads on a revision conflict and explains it', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => init?.method === 'PUT'
      ? json({ error: { code: 'revision_conflict', message: 'stale', request_id: 'r1' } }, 412)
      : json(usage(4, { used: 0, override: 100 }))))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<AccountQuotaPanel scopeID={tenantScope} accessToken={() => 'token'} canManage />)
    const panel = await screen.findByTestId('account-quota-panel')
    await within(panel).findByText('单独设置', { selector: '.ant-tag' })
    await user.click(within(panel).getByRole('button', { name: '保存额度' }))
    expect(await within(panel).findByText('额度已被其他管理员修改，已刷新为最新值，请确认后再保存')).toBeInTheDocument()
  })

  it('is read-only without the user management permission', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(usage(0, { used: 0, override: null }))))
    renderWithProviders(<AccountQuotaPanel scopeID={tenantScope} accessToken={() => 'token'} canManage={false} />)
    const panel = await screen.findByTestId('account-quota-panel')
    await within(panel).findByText('刷新 URL')
    expect(within(panel).getByRole('button', { name: '保存额度' })).toBeDisabled()
    expect(within(panel).getByRole('spinbutton', { name: '预热' })).toBeDisabled()
  })
})
