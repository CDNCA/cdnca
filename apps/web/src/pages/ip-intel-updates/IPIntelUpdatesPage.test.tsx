import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { ipIntelUpdatesMessages } from '../../i18n/ipIntelUpdates'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import IPIntelUpdatesPage from './IPIntelUpdatesPage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

// Obviously fake credentials.
const status = {
  licensed: true, enabled: true, url: 'https://api.dnspup.example/v1/tools/ip-intel-snapshot', api_key: 'dnp_key_fake_page_0000',
  secret_configured: true, secret_fingerprint: '0123456789abcdef', interval_minutes: 360, anchor_minute: 240,
  time_zone: 'Asia/Shanghai', revision: 3, settings_updated_at: '2026-10-18T02:00:00Z', running: false, check_requested: false,
  last_checked_at: '2026-10-18T02:00:00Z', last_success_at: '2026-10-18T02:00:00Z', last_outcome: 'published',
  last_release: 'ipx-98a5f2c77cd73826d2800b2f', last_http_status: 200, last_error_code: '', last_error: '',
  next_check_at: '2026-10-18T08:00:00Z',
  base: { artifact_id: 'ipintel/base', revision: 1, version: 'ipintel-20261017-000001', source_release: 'ipx-base',
    data_updated_at: '2026-10-17T00:00:00Z', usable: true },
  local: { artifact_id: 'ipintel/local', revision: 2, version: 'ipintel-local-20261018-000002', source_release: 'ipx-98a5f2c77cd73826d2800b2f',
    data_updated_at: '2026-10-17T13:19:58Z', usable: true },
  node_uses: 'ipintel/local', use_reason: 'local_newer',
}

type Fetch = (path: string, init?: RequestInit) => Promise<Response>

beforeEach(async () => {
  await changeLocale('zh-CN')
  const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['system.ip_intel_updates.manage'] })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'ipintel-token' }, admin)
})
afterEach(() => vi.unstubAllGlobals())

describe('IPIntelUpdatesPage', () => {
  it('keeps every locale structurally complete', () => {
    const keys = (tree: object, prefix = ''): string[] => Object.entries(tree).flatMap(([k, v]) =>
      typeof v === 'string' ? [`${prefix}${k}`] : keys(v as object, `${prefix}${k}.`))
    expect(keys(ipIntelUpdatesMessages['en-US'])).toEqual(keys(ipIntelUpdatesMessages['zh-CN']))
  })

  it('shows which library nodes use and saves without resending the stored secret', async () => {
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/ip-intel-updates' && !init?.method) return json(status)
      if (path === '/v1/admin/ip-intel-updates' && init?.method === 'PUT') return json({ ...status, revision: 4 })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<IPIntelUpdatesPage />)
    expect(await screen.findByDisplayValue('dnp_key_fake_page_0000')).toBeInTheDocument()
    expect(screen.getByText('本地库数据较新')).toBeInTheDocument()
    expect(screen.getByText(/已配置（指纹 0123456789abcdef）/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('拉取间隔（小时）'), { target: { value: '12' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([, call]) => call?.method === 'PUT')!
    const body = JSON.parse(String(init?.body))
    expect(body).toEqual({ enabled: true, url: status.url, api_key: status.api_key, interval_minutes: 720, anchor_minute: 240,
      time_zone: 'Asia/Shanghai' })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  // fix-fielderr-be5：保存 400 validation_error 带 details.field 时标在该输入框下，不弹窗
  it('marks a refused field under its box instead of the dialog', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/ip-intel-updates' && !init?.method) return json(status)
      return json({ error: { code: 'validation_error', message: 'x', request_id: 'r', details: { field: 'time_zone', reason: 'invalid' } } }, 400)
    }))
    renderWithProviders(<IPIntelUpdatesPage />)
    await screen.findByDisplayValue('dnp_key_fake_page_0000')
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    const help = await screen.findByText('填写的内容不符合要求')
    expect(help.closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(help.closest('.ant-form-item')).toContainElement(screen.getByLabelText('时区'))
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
  })

  it('is view-only without the licence module', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async () => json({ ...status, licensed: false, local: { ...status.local, usable: false },
      node_uses: 'ipintel/base', use_reason: 'only_base' })))
    renderWithProviders(<IPIntelUpdatesPage />)
    expect(await screen.findByText(/当前授权不含「IP 库实时更新」模块/)).toBeInTheDocument()
    expect(screen.getByText('授权不含本模块，节点不使用')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '测试连接' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '立即拉取' })).toBeDisabled()
  })

  it('shows a 403 page without the permission', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async () => json({ error: { code: 'permission_denied', message: 'x', request_id: 'r' } }, 403)))
    renderWithProviders(<IPIntelUpdatesPage />)
    expect(await screen.findByText('需要 IP 库更新管理权限')).toBeInTheDocument()
  })
})
