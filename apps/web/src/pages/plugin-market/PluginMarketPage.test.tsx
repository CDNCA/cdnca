import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { marketApi, type MarketPluginDetail } from '../../api/market'
import { pluginInstallationsApi, type PluginInstallation } from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import i18n, { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import PluginMarketPage from './PluginMarketPage'

// antd 测试环境里所有弹窗的 aria-labelledby 都是 test-id，同时开着 feedback 弹窗时按 name 查会串到别的弹窗；按标题文字找所属弹窗。
const DIALOG_TITLE = { selector: '.ant-modal-title, .ant-drawer-title' }
function getDialogTitled(title: string | RegExp): HTMLElement {
  return screen.getByText(title, DIALOG_TITLE).closest('[role="dialog"]') as HTMLElement
}
async function findDialogTitled(title: string | RegExp): Promise<HTMLElement> {
  return (await screen.findByText(title, DIALOG_TITLE)).closest('[role="dialog"]') as HTMLElement
}

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const scopeID = '018cc251-f400-7def-8000-000000000020'
const tenantID = '018cc251-f400-7def-8000-000000000021'
const authorizationID = '018cc251-f400-7def-8000-000000000022'
const installationID = '018cc251-f400-7def-8000-000000000023'
const verificationID = '018cc251-f400-7def-8000-000000000024'

function installation(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return {
    schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: scopeID,
    authorization_id: authorizationID, installation_id: installationID, verification_id: verificationID,
    plugin_id: 'acme.cache', version: '1.2.3', resource_scope: 'tenant', entrypoint_type: 'external_https', manifest_sha256: 'a'.repeat(64),
    configuration_schema_sha256: 'b'.repeat(64), manifest_scopes: ['cache.purge', 'sites.read'],
    approved_scopes: ['cache.purge', 'sites.read'], sensitive_scopes: ['cache.purge'], new_scopes: [],
    status: 'enabled', revision: 4, identity_generation: 2, lkg_verification_id: verificationID,
    lkg_version: '1.2.3', stable_reason_code: null, updated_at: '2026-08-08T08:00:00Z',
    ...overrides,
  }
}

function setSession(permissions = ['plugin_installations.read', 'plugin_installations.manage']) {
  const current = principal({
    scope_kind: 'tenant', scope_id: scopeID, tenant_id: tenantID, permissions,
  })
  const response = authResponse(current)
  useSessionStore.getState().setSession(response, current)
}

function mockApi(item = installation()) {
  vi.spyOn(pluginInstallationsApi, 'list').mockResolvedValue({ items: [item] })
  vi.spyOn(pluginInstallationsApi, 'get').mockResolvedValue(item)
  vi.spyOn(pluginInstallationsApi, 'confirm').mockResolvedValue({ installation: { ...item, status: 'authorized', revision: item.revision + 1 } })
  vi.spyOn(pluginInstallationsApi, 'upgrade').mockResolvedValue({ installation: { ...item, revision: item.revision + 1 } })
  vi.spyOn(pluginInstallationsApi, 'disable').mockResolvedValue({ installation: { ...item, status: 'disabled', revision: item.revision + 1 } })
  vi.spyOn(pluginInstallationsApi, 'uninstall').mockResolvedValue({ installation: { ...item, status: 'uninstalled', revision: item.revision + 1 } })
  vi.spyOn(pluginInstallationsApi, 'resume').mockResolvedValue({ installation: { ...item, status: 'enabled', revision: item.revision + 1,
    authorization_status: 'enabled', paused_by: undefined, paused_reason: undefined } })
}

describe('PluginMarketPage', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await changeLocale('zh-CN')
    setSession()
  })

  it('defaults to Chinese and supports search, status filtering, detail and narrow table scrolling', async () => {
    mockApi()
    const { container } = renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('插件市场')).toBeInTheDocument()
    expect(await screen.findByText('acme.cache')).toBeInTheDocument()
    expect(container.querySelector('.ant-table-content')).toBeTruthy()
    await userEvent.type(screen.getByPlaceholderText('按插件名称（ID）搜索'), 'cache')
    await userEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(pluginInstallationsApi.list).toHaveBeenLastCalledWith(expect.any(String), scopeID, expect.objectContaining({ plugin_id: 'cache' })))
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('插件清单指纹（SHA-256）')).toBeInTheDocument()
    expect(screen.getAllByText('1.2.3').length).toBeGreaterThan(0)
  })

  it('shows empty, load error and forbidden states without leaking server messages', async () => {
    vi.spyOn(pluginInstallationsApi, 'list').mockResolvedValueOnce({ items: [] })
    const empty = renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('还没有可用的插件')).toBeInTheDocument()
    empty.unmount()

    vi.spyOn(pluginInstallationsApi, 'list').mockRejectedValueOnce(new ApiError('database detail', 503, 'plugin_installation_license_unavailable'))
    const failed = renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('暂时连不上授权服务，请稍后再试')).toBeInTheDocument()
    expect(screen.queryByText('database detail')).not.toBeInTheDocument()
    failed.unmount()

    setSession([])
    const listSpy = vi.spyOn(pluginInstallationsApi, 'list')
    renderWithProviders(<PluginMarketPage />)
    expect(screen.getByText('无权访问')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('renders an accessible loading status while the installation list is pending', () => {
    vi.spyOn(pluginInstallationsApi, 'list').mockImplementation(() => new Promise(() => undefined))
    renderWithProviders(<PluginMarketPage />)

    expect(screen.getByRole('status', { name: '正在加载插件列表' })).toHaveAttribute('aria-live', 'polite')
  })

  it('renders an explicit forbidden state for a server-side 403', async () => {
    vi.spyOn(pluginInstallationsApi, 'list')
      .mockRejectedValueOnce(new ApiError('private authorization detail', 403, 'forbidden'))
    renderWithProviders(<PluginMarketPage />)

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(screen.getByText('当前账号没有查看插件的权限。')).toBeInTheDocument()
    expect(screen.queryByText('加载插件列表失败')).not.toBeInTheDocument()
    expect(screen.queryByText('private authorization detail')).not.toBeInTheDocument()
  })

  it('bounds the drawer to the viewport and uses one detail column at 360px', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 360 })
    vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
      matches: query === '(max-width: 575px)', media: query, onchange: null,
      addListener: () => undefined, removeListener: () => undefined,
      addEventListener: () => undefined, removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }))
    mockApi()
    renderWithProviders(<PluginMarketPage />)

    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const drawer = await findDialogTitled('acme.cache')
    const wrapper = drawer.closest('.ant-drawer-content-wrapper')
    expect(wrapper).toHaveStyle({ width: 'min(760px, 100vw)' })
    const pluginLabel = within(drawer).getByText('插件')
    const versionLabel = within(drawer).getByText('版本')
    expect(pluginLabel.closest('tr')).not.toBe(versionLabel.closest('tr'))
  })

  it('requires separate sensitive and new-permission consent before installation confirmation', async () => {
    const pending = installation({
      status: 'pending_confirmation', approved_scopes: [], new_scopes: ['sites.read'], revision: 1,
      lkg_verification_id: null, lkg_version: null,
    })
    mockApi(pending)
    renderWithProviders(<PluginMarketPage />)
    await userEvent.click(await screen.findByRole('button', { name: '安装' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('cache.purge')).toBeInTheDocument()
    expect(within(dialog).getByText('sites.read')).toBeInTheDocument()
    const submit = within(dialog).getByRole('button', { name: '确认安装' })
    expect(submit).toBeDisabled()
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我已了解这些权限可以读取或修改重要数据' }))
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我同意新版本新增的权限' }))
    expect(submit).toBeEnabled()
    await userEvent.click(submit)
    await waitFor(() => expect(pluginInstallationsApi.confirm).toHaveBeenCalledWith(
      expect.any(String), scopeID, authorizationID, 1,
      { verification_id: verificationID, approved_scopes: ['cache.purge', 'sites.read'], sensitive_permissions_confirmed: true, new_permissions_confirmed: true },
      expect.stringMatching(/^plugin-installation-confirm-/),
    ))
  })

  it('reconfirms newly added upgrade permissions and displays LKG preservation after failure', async () => {
    const failedUpgrade = installation({
      status: 'upgrade_failed_lkg_preserved', version: '2.0.0',
      manifest_scopes: ['billing.read', 'cache.purge', 'sites.read'], new_scopes: ['billing.read'],
      lkg_version: '1.2.3', stable_reason_code: 'plugin_installation_version_incompatible',
    })
    mockApi(failedUpgrade)
    renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('升级没有成功，仍在使用版本 1.2.3')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('版本兼容')).toBeInTheDocument()
    expect(screen.getByText('当前主控版本不在插件支持的范围内')).toBeInTheDocument()
    expect(screen.getByText('插件版本不支持当前主控')).toBeInTheDocument()
    expect(screen.queryByText('plugin_installation_version_incompatible')).not.toBeInTheDocument()
    const details = getDialogTitled('acme.cache')
    await userEvent.click(within(details).getByRole('button', { name: '升级' }))
    const dialog = (await screen.findByText('升级插件')).closest('[role="dialog"]')
    expect(dialog).not.toBeNull()
    if (!(dialog instanceof HTMLElement)) throw new Error('upgrade dialog missing')
    expect(within(dialog).getByText('billing.read')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我已了解这些权限可以读取或修改重要数据' }))
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我同意新版本新增的权限' }))
    await userEvent.click(within(dialog).getByRole('button', { name: '确认升级' }))
    await waitFor(() => expect(pluginInstallationsApi.upgrade).toHaveBeenCalled())
  })

  it('offers a platform-approved upgrade and submits the new version, and shows a platform pause', async () => {
    const upgradeVerification = '018cc251-f400-7def-8000-000000000025'
    mockApi(installation({
      authorization_status: 'disabled',
      available_upgrade: { verification_id: upgradeVerification, version: '1.3.0',
        manifest_scopes: ['cache.purge', 'sites.read'], approved_scopes: ['cache.purge', 'sites.read'],
        sensitive_scopes: ['cache.purge'], new_scopes: [] },
    }))
    renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('平台已暂停')).toBeInTheDocument()
    expect(screen.getByText('可升级到 1.3.0')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '升级' }))
    const dialog = (await screen.findByText('升级插件')).closest('[role="dialog"]')
    if (!(dialog instanceof HTMLElement)) throw new Error('upgrade dialog missing')
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我已了解这些权限可以读取或修改重要数据' }))
    await userEvent.click(within(dialog).getByRole('button', { name: '确认升级' }))
    await waitFor(() => expect(pluginInstallationsApi.upgrade).toHaveBeenCalledWith(expect.any(String), scopeID,
      authorizationID, 4, expect.objectContaining({ verification_id: upgradeVerification,
        approved_scopes: ['cache.purge', 'sites.read'] }), expect.any(String)))
  })

  it('marks a purchased market plugin awaiting this controller and confirms it with the consent flags', async () => {
    mockApi(installation({
      status: 'pending_confirmation', authorization_status: 'pending_confirmation', revision: 1,
      identity_generation: 0, lkg_verification_id: null, lkg_version: null,
      manifest_scopes: ['edge.health_beacon'], approved_scopes: ['edge.health_beacon'],
      sensitive_scopes: ['edge.health_beacon'], new_scopes: ['edge.health_beacon'],
    }))
    renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('已购买，待你确认')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '安装' }))
    const dialog = (await screen.findByText('安装插件')).closest('[role="dialog"]')
    if (!(dialog instanceof HTMLElement)) throw new Error('install dialog missing')
    const ok = within(dialog).getByRole('button', { name: '确认安装' })
    expect(ok).toBeDisabled()
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我已了解这些权限可以读取或修改重要数据' }))
    await userEvent.click(within(dialog).getByRole('checkbox', { name: '我同意新版本新增的权限' }))
    await userEvent.click(ok)
    await waitFor(() => expect(pluginInstallationsApi.confirm).toHaveBeenCalledWith(expect.any(String), scopeID,
      authorizationID, 1, expect.objectContaining({ verification_id: verificationID, approved_scopes: ['edge.health_beacon'],
        sensitive_permissions_confirmed: true, new_permissions_confirmed: true }), expect.any(String)))
  })

  it('uses reasoned protective disable/uninstall and preserves an unknown write for exact retry', async () => {
    mockApi()
    vi.mocked(pluginInstallationsApi.disable).mockRejectedValueOnce(new ApiError('unknown', 503, 'plugin_installation_result_unknown'))
    renderWithProviders(<PluginMarketPage />)
    fireEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    await userEvent.click(await screen.findByRole('button', { name: '暂停' }))
    const dialog = (await screen.findByText('暂停插件')).closest('[role="dialog"]')
    expect(dialog).not.toBeNull()
    if (!(dialog instanceof HTMLElement)) throw new Error('disable dialog missing')
    await userEvent.type(within(dialog).getByLabelText('原因'), '安全响应')
    await userEvent.click(within(dialog).getByRole('button', { name: '确认暂停' }))
    expect(await screen.findByText('不确定操作是否成功', OUTCOME_BAR)).toBeInTheDocument()
    const firstKey = vi.mocked(pluginInstallationsApi.disable).mock.calls[0]?.[5]
    await userEvent.click(screen.getByRole('button', { name: '重新提交' }))
    await waitFor(() => expect(pluginInstallationsApi.disable).toHaveBeenCalledTimes(2))
    expect(vi.mocked(pluginInstallationsApi.disable).mock.calls[1]?.[5]).toBe(firstKey)
  })

  // 报告 B：主动暂停后在详情里"恢复使用"；顺序为 状态/原因 → 主动作 → 详情 → 卸载。
  it('resumes a plugin this tenant paused, with the current revision and its own idempotency key', async () => {
    mockApi(installation({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation',
      paused_reason: '临时排查' }))
    renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('已暂停')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '查看详情' }))
    const drawer = await findDialogTitled('acme.cache')
    const state = within(drawer).getByRole('region', { name: '当前状态' })
    expect(within(state).getByText('你已暂停这个插件，原因：临时排查')).toBeInTheDocument()
    const resume = within(state).getByRole('button', { name: '恢复使用' })
    expect(within(drawer).queryByRole('button', { name: '暂停' })).not.toBeInTheDocument()
    // 状态区在详情表之前，卸载在详情之后。
    const details = within(drawer).getByText('插件清单指纹（SHA-256）')
    const uninstall = within(drawer).getByRole('button', { name: '卸载' })
    expect(state.compareDocumentPosition(details) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(details.compareDocumentPosition(uninstall) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    await userEvent.click(resume)
    await waitFor(() => expect(pluginInstallationsApi.resume).toHaveBeenCalledWith(
      expect.any(String), scopeID, authorizationID, 4, expect.stringMatching(/^plugin-installation-resume-/)))
    expect(await screen.findByText('恢复使用已完成，当前状态：运行中')).toBeInTheDocument()
  })

  it('explains a platform pause with its handler and reason and offers no resume', async () => {
    mockApi(installation({ status: 'disabled', authorization_status: 'disabled', paused_by: 'service',
      paused_reason: '插件已从市场下架' }))
    renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('平台已暂停')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '查看详情' }))
    const drawer = await findDialogTitled('acme.cache')
    const state = within(drawer).getByRole('region', { name: '当前状态' })
    expect(within(state).getByText('插件市场已暂停这个插件（下架或安全公告），原因：插件已从市场下架。需要由平台处理，联系平台恢复后会自动生效。')).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: '恢复使用' })).not.toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '卸载' })).toBeInTheDocument()
  })

  it('keeps the plugin paused and says why when the platform refuses the resume', async () => {
    mockApi(installation({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation' }))
    vi.mocked(pluginInstallationsApi.resume).mockRejectedValueOnce(new ApiError('paused', 409, 'plugin_installation_platform_paused'))
    renderWithProviders(<PluginMarketPage />)
    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const drawer = await findDialogTitled('acme.cache')
    await userEvent.click(within(drawer).getByRole('button', { name: '恢复使用' }))
    expect(await screen.findByText('平台已暂停这个插件，不能在这里恢复，请联系平台')).toBeInTheDocument()
    expect(screen.queryByText('不确定操作是否成功', OUTCOME_BAR)).not.toBeInTheDocument()
  })

  // fix-plugverify B-补1：恢复结果不确定时，引导用原请求（同 key、同 revision）重新恢复，不引导重新购买或卸载。
  it('offers the exact resume retry when the resume outcome is unknown', async () => {
    mockApi(installation({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation' }))
    vi.mocked(pluginInstallationsApi.resume).mockRejectedValueOnce(new ApiError('unknown', 503, 'plugin_installation_result_unknown'))
    renderWithProviders(<PluginMarketPage />)
    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const drawer = await findDialogTitled('acme.cache')
    await userEvent.click(within(drawer).getByRole('button', { name: '恢复使用' }))
    expect(await screen.findByText('不确定恢复使用是否完成', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.getByText('插件可能已经恢复。点“重新恢复”会原样再提交这次恢复，不会重复恢复，也不需要重新购买或卸载。')).toBeInTheDocument()
    const first = vi.mocked(pluginInstallationsApi.resume).mock.calls[0]
    await userEvent.click(screen.getByRole('button', { name: '重新恢复' }))
    await waitFor(() => expect(pluginInstallationsApi.resume).toHaveBeenCalledTimes(2))
    const second = vi.mocked(pluginInstallationsApi.resume).mock.calls[1]
    expect(second?.[3]).toBe(first?.[3])
    expect(second?.[4]).toBe(first?.[4])
    expect(await screen.findByText('恢复使用已完成，当前状态：运行中')).toBeInTheDocument()
  })

  it('completes an uninstall with the exact tenant, revision, reason and idempotency key', async () => {
    mockApi()
    renderWithProviders(<PluginMarketPage />)

    await userEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    await userEvent.click(await screen.findByRole('button', { name: '卸载' }))
    const dialog = (await screen.findByText('卸载插件')).closest('[role="dialog"]')
    expect(dialog).not.toBeNull()
    if (!(dialog instanceof HTMLElement)) throw new Error('uninstall dialog missing')
    await userEvent.type(within(dialog).getByLabelText('原因'), '不再使用')
    await userEvent.click(within(dialog).getByRole('button', { name: '确认卸载' }))

    await waitFor(() => expect(pluginInstallationsApi.uninstall).toHaveBeenCalledWith(
      expect.any(String), scopeID, authorizationID, 4, { reason: '不再使用' },
      expect.stringMatching(/^plugin-installation-uninstall-/),
    ))
    expect((await screen.findAllByText('已卸载')).length).toBeGreaterThan(0)
    expect(screen.getByText('卸载已完成，当前状态：已卸载')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '卸载' })).not.toBeInTheDocument()
  })

  it('registers English and pseudo resources without changing the contract identifiers', async () => {
    mockApi()
    await changeLocale('en-US')
    const english = renderWithProviders(<PluginMarketPage />)
    expect(await screen.findByText('Plugin marketplace')).toBeInTheDocument()
    english.unmount()
    await changeLocale('qps-ploc')
    renderWithProviders(<PluginMarketPage />)
    expect((await screen.findByText(/插~件~市~场~/)).textContent).toContain('［')
    expect(i18n.language).toBe('qps-ploc')
  })

  it('shows open security advisories to the tenant and lets a manager acknowledge them for this scope', async () => {
    mockApi()
    const advisory = { id: '018cc251-f400-7def-8000-000000000030', plugin_id: 'acme.cache', affected_versions: '<1.3.0', fixed_version: '1.3.0',
      severity: 'critical', action: 'disable', title: '缓存投毒', body: '', published_at: '2026-10-16T00:00:00Z', acknowledgement: null }
    const fetchMock = vi.fn(async (path: string) => ({
      ok: true, status: 200,
      text: async () => JSON.stringify(path.endsWith('/acknowledge')
        ? { disposition: 'disabled', note: '', acknowledged_by: 'u', acknowledged_at: '2026-10-16T01:00:00Z' } : { items: [advisory] }),
    }) as unknown as Response)
    vi.stubGlobal('fetch', fetchMock)
    try {
      renderWithProviders(<PluginMarketPage />)
      expect(await screen.findByText('1 条安全公告待处理')).toBeInTheDocument()
      expect(await screen.findByText('缓存投毒')).toBeInTheDocument()
      expect(screen.getByText('严重')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: '我已处理' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: '我已处理' }))
      await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/advisories/${advisory.id}/acknowledge`,
        expect.objectContaining({ method: 'POST' })))
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('hides acknowledgement from read-only tenants and stays quiet without an advisory channel', async () => {
    setSession(['plugin_installations.read'])
    mockApi()
    const advisory = { id: '018cc251-f400-7def-8000-000000000031', plugin_id: 'acme.cache', affected_versions: '*', fixed_version: '',
      severity: 'low', action: 'notify', title: '提示', body: '', published_at: '2026-10-16T00:00:00Z', acknowledgement: null }
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ items: [advisory] }) }) as unknown as Response))
    try {
      const { unmount } = renderWithProviders(<PluginMarketPage />)
      expect(await screen.findByText('提示')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '我已处理' })).not.toBeInTheDocument()
      unmount()
      vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 404, text: async () => '{"error":"not_found"}' }) as unknown as Response))
      renderWithProviders(<PluginMarketPage />)
      expect(await screen.findByText('acme.cache')).toBeInTheDocument()
      expect(screen.queryByText(/安全公告/)).not.toBeInTheDocument()
      expect(screen.queryByText(/加载失败/)).not.toBeInTheDocument()
    } finally {
      vi.unstubAllGlobals()
    }
  })
  it('shows the signed ui_page menus and origin before confirming, only for the exact manifest', async () => {
    const pending = installation({ status: 'pending_confirmation', approved_scopes: [], revision: 1,
      lkg_verification_id: null, lkg_version: null })
    mockApi(pending)
    const marketRow = '018cc251-f400-7def-8000-000000000040'
    const uiPage = { origin: 'https://ui.acme.example', api_base_url: 'https://api.acme.example/v1', pages: [
      { id: 'report', path: '/report', mount: 'menu' as const, menu_parent: 'monitor', role: 'user' as const, title: { 'zh-CN': '缓存报表' } },
      { id: 'site-tools', path: '/site', mount: 'site_tab' as const, role: 'user' as const, title: { 'zh-CN': '站点工具' } },
    ] }
    const detail = (digest: string): MarketPluginDetail => ({
      plugin: { id: marketRow, plugin_id: 'acme.cache' } as MarketPluginDetail['plugin'], price_plans: [],
      versions: [{ id: 'v', plugin_id: marketRow, version: '1.2.3', status: 'published', manifest_sha256: digest,
        permissions: [], permissions_changed: false, channel: 'stable', ui_page: uiPage }],
    })
    vi.spyOn(marketApi, 'plugins').mockResolvedValue({ items: [{ id: marketRow, plugin_id: 'acme.cache' } as MarketPluginDetail['plugin']], next_cursor: null })
    const pluginSpy = vi.spyOn(marketApi, 'plugin').mockResolvedValue(detail('a'.repeat(64)))
    const { unmount } = renderWithProviders(<PluginMarketPage />)
    await userEvent.click(await screen.findByRole('button', { name: '安装' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('缓存报表（菜单）')).toBeInTheDocument()
    expect(within(dialog).getByText('站点工具（网站详情页签）')).toBeInTheDocument()
    expect(within(dialog).getByText('https://ui.acme.example')).toBeInTheDocument()
    expect(within(dialog).getByText('https://api.acme.example/v1')).toBeInTheDocument()
    expect(marketApi.plugins).toHaveBeenCalledWith(expect.any(String), { q: 'acme.cache' })
    expect(pluginSpy).toHaveBeenCalledWith(expect.any(String), marketRow)
    unmount()

    // The market version is not the authorized manifest: no declaration is shown.
    pluginSpy.mockResolvedValue(detail('c'.repeat(64)))
    renderWithProviders(<PluginMarketPage />)
    await userEvent.click(await screen.findByRole('button', { name: '安装' }))
    const second = await screen.findByRole('dialog')
    expect(await within(second).findByText(/对不上，无法展示页面声明/)).toBeInTheDocument()
    expect(within(second).queryByText('缓存报表（菜单）')).not.toBeInTheDocument()
  })

  it('shows the installation public key in the detail drawer and a clear notice when it is not configured', async () => {
    mockApi()
    vi.spyOn(marketApi, 'plugins').mockRejectedValue(new ApiError('x', 403, 'forbidden'))
    const key = { installation_id: installationID, key_id: '0123456789abcdef', algorithm: 'Ed25519',
      public_key: 'A'.repeat(43), signature_domain: 'cdnca-plugin-ui-proxy/v1' }
    const fetchSpy = vi.fn(async (url: string) => String(url).endsWith('/v1/plugin-ui/signing-key')
      ? { ok: true, status: 200, json: async () => key, text: async () => JSON.stringify(key) }
      : { ok: false, status: 404, json: async () => ({}), text: async () => '{"error":"not_found"}' })
    vi.stubGlobal('fetch', fetchSpy)
    try {
      const { unmount } = renderWithProviders(<PluginMarketPage />)
      fireEvent.click(await screen.findByRole('button', { name: '查看详情' }))
      expect(await screen.findByText('A'.repeat(43))).toBeInTheDocument()
      expect(screen.getByText('0123456789abcdef')).toBeInTheDocument()
      expect(screen.getByText('cdnca-plugin-ui-proxy/v1')).toBeInTheDocument()
      expect(await screen.findByText(/暂时无法从插件市场读取页面声明/)).toBeInTheDocument()
      unmount()
      vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 503, headers: new Headers(),
        json: async () => ({ error: { code: 'plugin_ui_proxy_unavailable', message: 'x' } }),
        text: async () => '{"error":{"code":"plugin_ui_proxy_unavailable","message":"x"}}' })))
      renderWithProviders(<PluginMarketPage />)
      fireEvent.click(await screen.findByRole('button', { name: '查看详情' }))
      expect(await screen.findByText('本主控还没有配置安装密钥，带页面插件的后端接口暂不可用。')).toBeInTheDocument()
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
