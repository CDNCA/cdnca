import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { platformPluginInstallationsApi, type PluginInstallation } from '../../api/pluginInstallations'
import type { PluginUIPage } from '../../api/pluginUI'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { configPath } from '../market/marketModel'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { PlatformPluginsPanel } from './PluginMarketPage'

const platformScope = '018cc251-f400-7def-8000-000000000050'

function installed(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return {
    schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: platformScope,
    authorization_id: '018cc251-f400-7def-8000-000000000051', installation_id: '018cc251-f400-7def-8000-000000000052',
    verification_id: '018cc251-f400-7def-8000-000000000053', plugin_id: 'io.cdnca.cf-optimize', version: '1.0.2',
    resource_scope: 'platform', entrypoint_type: 'ui_page', manifest_sha256: 'a'.repeat(64),
    configuration_schema_sha256: 'b'.repeat(64), manifest_scopes: [], approved_scopes: [], sensitive_scopes: [], new_scopes: [],
    status: 'enabled', revision: 2, identity_generation: 1, lkg_verification_id: null, lkg_version: '1.0.2',
    stable_reason_code: null, updated_at: '2026-11-10T08:00:00Z', targets: { all_tenants: true, tenants: [], revision: 1 },
    ...overrides,
  } as PluginInstallation
}

const settingsPage: PluginUIPage = {
  plugin_id: 'io.cdnca.cf-optimize', plugin_version: '1.0.2', page_id: 'settings', origin: 'https://cf-optimize.cdnca.com',
  url: 'https://cf-optimize.cdnca.com/admin', mount: 'plugin_settings', role: 'admin',
  title: { 'zh-CN': 'CF 优选节点设置' }, required_module: 'module.cfopt', has_api: true,
}

function stubPages(items: PluginUIPage[]) {
  const body = JSON.stringify({ items })
  vi.stubGlobal('fetch', vi.fn(async (url: string) => String(url).endsWith('/v1/plugin-ui/pages')
    ? { ok: true, status: 200, json: async () => JSON.parse(body) as unknown, text: async (): Promise<string> => body }
    : { ok: false, status: 404, headers: new Headers(), json: async () => ({}), text: async (): Promise<string> => '{"error":"not_found"}' }))
}

// 插件自己的设置页放在「插件市场 → 已安装 → 插件详情 → 设置」，不占系统菜单。
describe('plugin settings page in the plugin market detail', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await changeLocale('zh-CN')
    const current = principal({ scope_kind: 'platform', scope_id: platformScope, tenant_id: null,
      permissions: ['plugin_installations.platform.read', 'plugin_installations.platform.manage'] })
    useSessionStore.getState().setSession(authResponse(current), current)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows the plugin_settings page in a sandboxed frame under 设置', async () => {
    stubPages([settingsPage])
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [installed()] })
    vi.spyOn(platformPluginInstallationsApi, 'get').mockResolvedValue(installed())
    renderWithProviders(<PlatformPluginsPanel />)
    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const drawer = (await screen.findByRole('dialog')) as HTMLElement
    await userEvent.click(await within(drawer).findByRole('tab', { name: '设置' }))
    const frame = await within(drawer).findByTitle('CF 优选节点设置')
    expect(frame.tagName).toBe('IFRAME')
    expect(frame.getAttribute('src')).toMatch(/^https:\/\/cf-optimize\.cdnca\.com\/admin#cdnca-nonce=/)
    expect(frame.getAttribute('sandbox')).toBe('allow-scripts allow-forms')
  })

  it('has no 设置 tab for a plugin without a settings page, or one that is not enabled', async () => {
    stubPages([{ ...settingsPage, plugin_id: 'acme.other' }])
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [installed()] })
    vi.spyOn(platformPluginInstallationsApi, 'get').mockResolvedValue(installed())
    const { unmount } = renderWithProviders(<PlatformPluginsPanel />)
    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const drawer = (await screen.findByRole('dialog')) as HTMLElement
    expect(await within(drawer).findByText('版本兼容')).toBeInTheDocument()
    expect(within(drawer).queryByRole('tab', { name: '设置' })).not.toBeInTheDocument()
    unmount()

    stubPages([settingsPage])
    const disabled = installed({ status: 'disabled' })
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [disabled] })
    vi.spyOn(platformPluginInstallationsApi, 'get').mockResolvedValue(disabled)
    renderWithProviders(<PlatformPluginsPanel />)
    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const second = (await screen.findByRole('dialog')) as HTMLElement
    expect(await within(second).findByText('版本兼容')).toBeInTheDocument()
    expect(within(second).queryByRole('tab', { name: '设置' })).not.toBeInTheDocument()
  })

  // 我的插件「去配置」：没有菜单页时打开设置页（同一个 /plugin-ui 路由）。
  it('uses the settings page as the configure path when the plugin has no admin menu page', () => {
    const plugin = { plugin_id: 'io.cdnca.cf-optimize', kind: 'ui_page', applies_to: 'tenant' } as never
    expect(configPath(plugin, [{ ...settingsPage }])).toBe('/plugin-ui/io.cdnca.cf-optimize/settings')
    expect(configPath(plugin, [{ ...settingsPage, page_id: 'report', mount: 'menu' }, { ...settingsPage }]))
      .toBe('/plugin-ui/io.cdnca.cf-optimize/report')
  })
})
