import { screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { brandAssetApi } from '../api/brandAsset'
import { publicBranding } from '../api/publicBranding'
import { systemSettingsApi, type PlatformSystemSettingsDocument } from '../api/systemSettings'
import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultThemeLayout, ThemeRuntimeContext } from '../theme/runtime'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const settingsDocument: PlatformSystemSettingsDocument = {
  schema: 'cdnca.platform-system-settings/v1',
  revision: 3,
  value: {
    system_name: '示例云', user_title: '示例云用户台', admin_title: '示例云管理台', footer_links: '', footer_text: '', global_js: '',
    bound_domains: '', expiry_close: false, traffic_close: false, allow_upgrade: true, allow_downgrade: true, maintenance: false,
    maintenance_message: '', auto_upgrade_node: false,
  },
}

function mockFetch() {
  const fetchMock = vi.fn(async (path: string) => path.endsWith('/v1/admin/system-settings')
    ? json(settingsDocument)
    : json({ code: 'not_found' }, 404))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function renderShell(brandName?: string) {
  const layout = brandName ? { ...defaultThemeLayout, brand_name: { 'zh-CN': brandName } } : defaultThemeLayout
  return renderWithProviders(
    <ThemeRuntimeContext.Provider value={{ document: null, layout }}>
      <Routes><Route element={<AppShell />}><Route path="*" element={<span />} /></Route></Routes>
    </ThemeRuntimeContext.Provider>,
    ['/admin-home'],
  )
}

afterEach(() => { vi.unstubAllGlobals(); vi.mocked(publicBranding).mockReset().mockResolvedValue(null); document.title = '' })

describe('AppShell system name and title (fix-ui1026 #4)', () => {
  it('uses the system settings name and admin title when the theme names nothing', async () => {
    mockFetch()
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const view = renderShell()
    await waitFor(() => expect(document.title).toBe('示例云管理台'))
    expect(view.container.querySelector('.shell-brand img')).toHaveAttribute('alt', '示例云')
  })

  it('lets the theme brand name win over the system settings', async () => {
    const fetchMock = mockFetch()
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const view = renderShell('主题云')
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/v1/admin/system-settings'))).toBe(true))
    await waitFor(() => expect(document.title).toBe('主题云'))
    expect(view.container.querySelector('.shell-brand img')).toHaveAttribute('alt', '主题云')
  })

  it('never reads the admin system settings from a tenant session', async () => {
    const fetchMock = mockFetch()
    const actor = principal({ permissions: ['sites.read'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const view = renderShell()
    await waitFor(() => expect(view.container.querySelector('.shell-brand img')).toHaveAttribute('alt', 'cdnca'))
    expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/v1/admin/system-settings'))).toBe(false)
  })

  // L6：租户会话读不到管理端系统配置，改用匿名公开品牌接口；规则仍是 主题 > 系统配置 > cdnca。
  function mockPublicFetch() {
    const fetchMock = mockFetch()
    vi.mocked(publicBranding).mockResolvedValue({ systemName: '示例云', userTitle: '示例云用户台', adminTitle: '示例云管理台' })
    return fetchMock
  }

  it('falls back to the public system name and user title for a tenant session', async () => {
    const fetchMock = mockPublicFetch()
    const actor = principal({ permissions: ['sites.read'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const view = renderShell()
    await waitFor(() => expect(document.title).toBe('示例云用户台'))
    expect(view.container.querySelector('.shell-brand img')).toHaveAttribute('alt', '示例云')
    expect(publicBranding).toHaveBeenCalled()
    expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/v1/admin/system-settings'))).toBe(false)
  })

  it('keeps the theme brand name over the public system name for a tenant session', async () => {
    mockPublicFetch()
    const actor = principal({ permissions: ['sites.read'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const view = renderShell('主题云')
    await waitFor(() => expect(publicBranding).toHaveBeenCalled())
    await waitFor(() => expect(document.title).toBe('主题云'))
    expect(view.container.querySelector('.shell-brand img')).toHaveAttribute('alt', '主题云')
  })
})

describe('system settings page theme override hint (fix-ui1026 #4)', () => {
  function renderPage(brandName?: string) {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(settingsDocument)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const layout = brandName ? { ...defaultThemeLayout, brand_name: { 'zh-CN': brandName } } : defaultThemeLayout
    const document = brandName ? { id: 'slate', name: { 'zh-CN': '石板' } } as never : null
    return renderWithProviders(
      <ThemeRuntimeContext.Provider value={{ document, layout }}><SystemGlobalSettingsPage /></ThemeRuntimeContext.Provider>,
    )
  }

  it('marks the name and title fields as overridden by the active theme (no theme page link in the community edition)', async () => {
    renderPage('主题云')
    const panel = await screen.findByTestId('system-settings-baseline-system')
    for (const key of ['system_name', 'user_title', 'admin_title']) {
      const hint = within(panel).getByTestId(`theme-override-${key}`)
      expect(hint).toHaveTextContent('当前由主题「石板」覆盖')
      expect(hint).toHaveTextContent('「主题云」')
      expect(within(hint).queryByRole('link', { name: '去主题设置' })).not.toBeInTheDocument()
    }
  })

  it('shows no hint when the theme names nothing', async () => {
    renderPage()
    const panel = await screen.findByTestId('system-settings-baseline-system')
    expect(within(panel).queryByTestId('theme-override-system_name')).not.toBeInTheDocument()
    // redesign-a：摘要条显示本页保存的系统名称，不带主题覆盖标签。
    const summary = within(within(panel).getByRole('navigation', { name: '当前生效' }))
    expect(summary.getByRole('button', { name: /登录后显示名称/ })).toHaveTextContent(settingsDocument.value.system_name)
    expect(summary.queryByText('主题覆盖')).not.toBeInTheDocument()
  })

  // redesign-a：摘要条"登录后显示名称"跟随主题覆盖，系统信息卡顶部概括覆盖并给出主题设置入口。
  it('puts the theme name in the summary with a theme-override tag', async () => {
    renderPage('主题云')
    const panel = await screen.findByTestId('system-settings-baseline-system')
    const summary = within(within(panel).getByRole('navigation', { name: '当前生效' }))
    const name = summary.getByRole('button', { name: /登录后显示名称/ })
    expect(name).toHaveTextContent('主题云')
    expect(within(name).getByText('主题覆盖')).toBeInTheDocument()
    expect(within(panel).getByText(/当前由主题「石板」覆盖，登录后显示为「主题云」/)).toBeInTheDocument()
  })
})
