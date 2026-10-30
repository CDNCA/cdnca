import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { platformPluginInstallationsApi, pluginInstallationsApi, type PluginInstallation } from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { PlatformPluginsPanel } from './PluginMarketPage'

const platformScope = '018cc251-f400-7def-8000-000000000040'
const authorizationID = '018cc251-f400-7def-8000-000000000041'
const verificationID = '018cc251-f400-7def-8000-000000000042'

function theme(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return {
    schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: platformScope, authorization_id: authorizationID,
    installation_id: '018cc251-f400-7def-8000-000000000043', verification_id: verificationID,
    plugin_id: 'review-codex-20261027.dev.audit-theme', version: '1.0.0', resource_scope: 'platform', entrypoint_type: 'theme',
    manifest_sha256: 'a'.repeat(64), configuration_schema_sha256: 'b'.repeat(64), manifest_scopes: [],
    approved_scopes: [], sensitive_scopes: [], new_scopes: [], status: 'pending_confirmation', revision: 1,
    identity_generation: 0, lkg_verification_id: null, lkg_version: null, stable_reason_code: null,
    updated_at: '2026-10-27T08:00:00Z', authorization_status: 'pending_confirmation', ...overrides,
  }
}

function platformSession(permissions: string[]) {
  const current = principal({ scope_kind: 'platform', scope_id: platformScope, tenant_id: null, permissions })
  useSessionStore.getState().setSession(authResponse(current), current)
}

// 报告 A：主控管理员在“我的插件”看到待确认的用户控制台主题，在详情同处确认，装好后给“去主题管理”。
describe('PlatformPluginsPanel', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await changeLocale('zh-CN')
  })

  it('lists the pending platform theme and confirms it through the platform route', async () => {
    platformSession(['plugin_installations.platform.read', 'plugin_installations.platform.manage'])
    const tenantList = vi.spyOn(pluginInstallationsApi, 'list')
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [theme()] })
    const installed = theme({ status: 'enabled', revision: 2, identity_generation: 1, authorization_status: undefined,
      lkg_verification_id: verificationID, lkg_version: '1.0.0' })
    let confirmed = false
    vi.spyOn(platformPluginInstallationsApi, 'get').mockImplementation(async () => (confirmed ? installed : theme()))
    const confirm = vi.spyOn(platformPluginInstallationsApi, 'confirm').mockImplementation(async () => {
      confirmed = true
      return { installation: installed }
    })
    renderWithProviders(<PlatformPluginsPanel />)
    expect(await screen.findByText('review-codex-20261027.dev.audit-theme')).toBeInTheDocument()
    expect(tenantList).not.toHaveBeenCalled()

    await userEvent.click(screen.getAllByRole('button', { name: '安装' })[0]!)
    const dialog = (await screen.findByText('安装插件', { selector: '.ant-modal-title' })).closest('[role="dialog"]') as HTMLElement
    await userEvent.click(within(dialog).getByRole('button', { name: '确认安装' }))
    await waitFor(() => expect(confirm).toHaveBeenCalledWith(expect.any(String), platformScope, authorizationID, 1,
      expect.objectContaining({ verification_id: verificationID }), expect.any(String)))
    // 社区版没有主题管理页：装好的主题不给跳转入口。
    expect(await screen.findByText('已安装到本主控。到对应页面启用后才会生效。')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '去主题管理' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '去规则包' })).not.toBeInTheDocument()
  })

  // fix-plugconfirm3：已装好的规则包只给“去规则包”，按服务端签名的插件类型，不显示主题入口。
  it('links an installed rule pack only to rule packs', async () => {
    platformSession(['plugin_installations.platform.read'])
    const pack = theme({ plugin_id: 'acme.sqli-extra', entrypoint_type: 'rule_pack', status: 'enabled', revision: 2,
      identity_generation: 1, authorization_status: undefined, lkg_verification_id: verificationID, lkg_version: '1.0.0' })
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [pack] })
    vi.spyOn(platformPluginInstallationsApi, 'get').mockResolvedValue(pack)
    renderWithProviders(<PlatformPluginsPanel />)
    expect(await screen.findByText('acme.sqli-extra')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByRole('link', { name: '去规则包' })).toHaveAttribute('href', '/site/rule-packs')
    expect(screen.queryByRole('link', { name: '去主题管理' })).not.toBeInTheDocument()
  })

  // 我的插件按“待确认 / 已安装 / 失败”分组，各组只向服务端要对应状态。
  it('groups platform plugins into pending, installed and failed', async () => {
    platformSession(['plugin_installations.platform.read'])
    const list = vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [theme()] })
    renderWithProviders(<PlatformPluginsPanel />)
    expect(await screen.findByText('review-codex-20261027.dev.audit-theme')).toBeInTheDocument()
    expect(list).toHaveBeenLastCalledWith(expect.any(String), platformScope, expect.not.objectContaining({ status: expect.anything() }))
    const groups = screen.getByRole('radiogroup', { name: '按处理阶段筛选' })
    for (const [label, status] of [['待确认', 'pending_confirmation'], ['已安装', 'enabled'], ['失败', 'upgrade_failed_lkg_preserved']] as const) {
      await userEvent.click(within(groups).getByText(label))
      await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), platformScope, expect.objectContaining({ status })))
    }
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  })

  it('refuses sessions without the exact platform permission', () => {
    platformSession(['platform.admin', 'plugin_installations.read', 'plugin_installations.manage'])
    const list = vi.spyOn(platformPluginInstallationsApi, 'list')
    renderWithProviders(<PlatformPluginsPanel />)
    expect(screen.getByText('当前账号不能管理平台插件')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })

  it('reads only without the manage permission', async () => {
    platformSession(['plugin_installations.platform.read'])
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [theme()] })
    renderWithProviders(<PlatformPluginsPanel />)
    expect(await screen.findByText('review-codex-20261027.dev.audit-theme')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '安装' })).not.toBeInTheDocument()
  })
})
