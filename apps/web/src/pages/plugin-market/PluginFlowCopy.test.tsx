import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { marketApi } from '../../api/market'
import { platformPluginInstallationsApi, type PluginInstallation } from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { PlatformPluginsPanel } from './PluginMarketPage'

// 空态按筛选区分、首次安装不叫“新增权限”、详情先状态后诊断。

const scopeID = '018cc251-f400-7def-8000-000000000040'
const authorizationID = '018cc251-f400-7def-8000-000000000041'
const verificationID = '018cc251-f400-7def-8000-000000000042'

function theme(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return { schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: scopeID, authorization_id: authorizationID,
    installation_id: '018cc251-f400-7def-8000-000000000043', verification_id: verificationID,
    plugin_id: 'review.example-theme', version: '1.0.0', resource_scope: 'platform', entrypoint_type: 'theme',
    manifest_sha256: 'a'.repeat(64), configuration_schema_sha256: 'b'.repeat(64), manifest_scopes: ['platform.themes.provide'],
    approved_scopes: [], sensitive_scopes: [], new_scopes: ['platform.themes.provide'], status: 'pending_confirmation', revision: 1,
    identity_generation: 0, lkg_verification_id: null, lkg_version: null, stable_reason_code: null,
    updated_at: '2026-10-28T08:00:00Z', authorization_status: 'pending_confirmation', ...overrides }
}

beforeEach(async () => {
  vi.restoreAllMocks()
  await changeLocale('zh-CN')
  const actor = principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null,
    permissions: ['plugin_installations.platform.read', 'plugin_installations.platform.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(marketApi, 'advisories').mockResolvedValue([])
})

describe('我的插件空态', () => {
  it('首次进入：暂无主题或规则包安装记录，引导去浏览', async () => {
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<PlatformPluginsPanel />)
    expect(await screen.findByText('暂无主题或规则包安装记录')).toBeInTheDocument()
  })

  it('失败分组为空：暂无失败插件，不引导去获取', async () => {
    const list = vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText('暂无主题或规则包安装记录')
    fireEvent.click(within(screen.getByRole('radiogroup', { name: '按处理阶段筛选' })).getByText('失败'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), scopeID, expect.objectContaining({ status: 'upgrade_failed_lkg_preserved' })))
    expect(await screen.findByText('暂无失败插件')).toBeInTheDocument()
    expect(screen.queryByText(/在“浏览”里获取/)).not.toBeInTheDocument()
  })

  it('搜索无匹配：说没有匹配项并能清除筛选回到全部', async () => {
    const list = vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText('暂无主题或规则包安装记录')
    fireEvent.change(screen.getByPlaceholderText('按插件名称（ID）搜索'), { target: { value: 'nothing.here' } })
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByText('没有匹配的插件')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '清除筛选' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), scopeID, expect.not.objectContaining({ plugin_id: expect.anything() })))
    expect(screen.getByPlaceholderText('按插件名称（ID）搜索')).toHaveValue('')
    expect(await screen.findByText('暂无主题或规则包安装记录')).toBeInTheDocument()
  })
})

describe('安装与升级的权限确认文案', () => {
  it('首次安装：确认本次安装所需权限，不叫“新版本新增”', async () => {
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [theme()] })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText('review.example-theme')
    fireEvent.click(screen.getByRole('button', { name: '安装' }))
    const dialog = (await screen.findByText('安装插件', { selector: '.ant-modal-title' })).closest('[role="dialog"]') as HTMLElement
    expect(within(dialog).getByRole('checkbox', { name: '我已确认本次安装所需的权限' })).toBeInTheDocument()
    expect(within(dialog).queryByText(/新版本/)).not.toBeInTheDocument()
    // 权限给中文用途，稳定 ID 仍在。
    expect(within(dialog).getByText('提供主题')).toBeInTheDocument()
    expect(within(dialog).getByText('platform.themes.provide')).toBeInTheDocument()
  })

  it('升级：仍叫新版本新增的权限', async () => {
    const installed = theme({ status: 'enabled', authorization_status: 'enabled', revision: 2, identity_generation: 1,
      lkg_verification_id: verificationID, lkg_version: '1.0.0', available_upgrade: { verification_id: '018cc251-f400-7def-8000-000000000045',
        version: '1.1.0', manifest_scopes: ['platform.themes.provide'], approved_scopes: ['platform.themes.provide'],
        sensitive_scopes: [], new_scopes: ['platform.themes.provide'] } })
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [installed] })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText('review.example-theme')
    fireEvent.click(screen.getByRole('button', { name: '升级' }))
    const dialog = (await screen.findByText('升级插件', { selector: '.ant-modal-title' })).closest('[role="dialog"]') as HTMLElement
    expect(within(dialog).getByRole('checkbox', { name: '我同意新版本新增的权限' })).toBeInTheDocument()
  })
})

describe('详情信息顺序', () => {
  it('名称/版本 → 状态 → 下一步在前，内部编号与指纹折在“诊断信息”里', async () => {
    const installed = theme({ status: 'enabled', authorization_status: 'enabled', revision: 2, identity_generation: 1,
      lkg_verification_id: verificationID, lkg_version: '1.0.0', new_scopes: [] })
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [installed] })
    vi.spyOn(platformPluginInstallationsApi, 'get').mockResolvedValue(installed)
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText('review.example-theme')
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    const drawer = await waitFor(() => {
      const found = screen.getAllByRole('dialog').find((item) => item.classList.contains('plugin-market-drawer'))
      expect(found).toBeDefined()
      return found!
    })
    const state = within(drawer).getByRole('region', { name: '当前状态' })
    const diagnostics = within(drawer).getByRole('button', { name: /诊断信息/ })
    expect(state.compareDocumentPosition(diagnostics) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // 折叠时不展示内部编号与指纹。
    expect(within(drawer).queryByText('a'.repeat(64))).not.toBeInTheDocument()
    fireEvent.click(diagnostics)
    expect(await within(drawer).findByText('a'.repeat(64))).toBeInTheDocument()
  })
})
