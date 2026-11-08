import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { platformPluginInstallationsApi, type PluginInstallation } from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import MarketStorePage from './MarketStorePage'
import { moduleSetup, ownedRows, storeState } from './marketModel'

// 已启用/已安装的卡片点了要去它的配置页；没有页面的不跳；可安装类能停用、重新启用。
// 官方功能模块也可在本机停用（MarketStoreSwitch.test.tsx），不再写“由授权自动启用、到哪里关”。

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body,
    text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

const freePlan = { id: 'p-free', plugin_id: 'x', revision: 1, kind: 'free', price_minor: 0, currency: 'CNY', trial_days: 0,
  status: 'active', active_revision: 1 }
const base = { namespace: 'io.cdnca', risk_class: 'privileged', status: 'listed', publisher_kind: 'official', latest_version: '1.0.0',
  price_plans: [freePlan] }
const dnspup = { ...base, id: '66666666-6666-4666-8666-666666666666', plugin_id: 'io.cdnca.probe-dnspup', kind: 'module',
  title: '拨测（dnspup）', feature_code: 'module.probe.dnspup' }
// The community edition has no 智能自动防御 or 计费桥接 page: the linked module cases use IP 情报库更新.
const ipintel = { ...base, id: '55555555-5555-4555-8555-555555555555', plugin_id: 'io.cdnca.ipintel-dnspup', kind: 'module',
  title: 'IP 情报库更新', feature_code: 'module.ipintel.dnspup' }
const nopage = { ...base, id: '88888888-8888-4888-8888-888888888888', plugin_id: 'io.cdnca.nopage', kind: 'module',
  title: '无页面模块', feature_code: 'module.nopage' }
const theme = { ...base, id: '33333333-3333-4333-8333-333333333333', plugin_id: 'bob.theme', namespace: 'bob', kind: 'theme',
  risk_class: 'sandboxed', title: 'Bob 主题', publisher_kind: 'third_party', feature_code: null }
const license = (pluginID: string) => ({ id: `l-${pluginID}`, plugin_id: pluginID, installation_id: 'i', kind: 'one_time', status: 'active' })

const platformScope = '018cc251-f400-7def-8000-000000000040'
const authorizationID = '018cc251-f400-7def-8000-000000000041'
const verificationID = '018cc251-f400-7def-8000-000000000042'
function installation(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return {
    schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: platformScope, authorization_id: authorizationID,
    installation_id: '018cc251-f400-7def-8000-000000000043', verification_id: verificationID,
    plugin_id: 'bob.theme', version: '1.0.0', resource_scope: 'platform', entrypoint_type: 'theme',
    manifest_sha256: 'a'.repeat(64), configuration_schema_sha256: 'b'.repeat(64), manifest_scopes: [],
    approved_scopes: [], sensitive_scopes: [], new_scopes: [], status: 'enabled', revision: 2,
    identity_generation: 1, lkg_verification_id: verificationID, lkg_version: '1.0.0', stable_reason_code: null,
    updated_at: '2026-11-06T08:00:00Z', authorization_status: 'enabled', ...overrides,
  }
}

type Fetch = (path: string, init?: RequestInit) => Promise<Response>
interface State { licenses: unknown[]; library: unknown[]; modules: string[]; dnspup?: Record<string, unknown> }

function routes(state: State, items: unknown[]) {
  return vi.fn<Fetch>(async (path) => {
    if (path.startsWith('/v1/admin/market/plugins?')) return json({ items, next_cursor: null })
    if (path.startsWith('/v1/admin/market/plugins/')) return json({ plugin: items[0], versions: [], price_plans: [freePlan] })
    if (path.startsWith('/v1/admin/market/licenses')) return json({ items: state.licenses, next_cursor: null })
    if (path === '/v1/admin/market/plugin-library') return json({ items: state.library })
    if (path === '/v1/modules') return json({ status: 'valid', lease_serial: 1, modules: state.modules })
    if (path.startsWith('/v1/admin/market/advisories')) return json({ items: [] })
    if (path.startsWith('/v1/plugin-ui/pages')) return json({ items: [] })
    if (path === '/v1/admin/probe-dnspup' && state.dnspup) return json(state.dnspup)
    return json({ error: { code: 'not_found' } }, 404)
  })
}

const card = async (pluginID: string) => screen.findByTestId(`market-card-${pluginID}`)
function session(permissions: string[]) {
  const admin = principal({ scope_kind: 'platform', scope_id: platformScope, tenant_id: null, roles: ['custom'], permissions })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'store-token' }, admin)
}
// 主题管理 /sys/themes 要 system_configuration.read（不走 platform.admin 兜底）。
const adminPermissions = ['marketplace.purchase', 'platform.admin', 'system_configuration.read', 'plugin_installations.platform.read',
  'plugin_installations.platform.manage']

beforeEach(async () => {
  await changeLocale('zh-CN')
  session(adminPermissions)
})
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('store card model', () => {
  it('reads a disabled installation as 已停用 and only flags dnspup setup from its own status', () => {
    const lib = [{ plugin_id: 'bob.theme', installed: true, enabled: false, withdrawn: false }]
    expect(storeState(theme as never, [license('bob.theme')] as never, lib, [], installation({ status: 'disabled' }))).toBe('disabled')
    // 本机只有停用的安装（installed && !enabled）就是已停用，读不到记录或另有待确认的记录也一样。
    expect(storeState(theme as never, [license('bob.theme')] as never, lib, [])).toBe('disabled')
    expect(storeState(theme as never, [license('bob.theme')] as never, lib, [], installation({ status: 'pending_confirmation' }))).toBe('disabled')
    // 授权已失效优先于停用：本机仍有安装就是“授权失效”。
    expect(storeState(theme as never, [], lib, [], installation({ status: 'disabled' }))).toBe('revoked')
    // 判断依据：dnspup 状态接口的 secret_configured（服务端 Active = 已授权 && enabled && secret_configured && 未暂停）。
    expect(moduleSetup('module.probe.dnspup', { enabled: true, secret_configured: false })).toBe('unconfigured')
    expect(moduleSetup('module.probe.dnspup', { enabled: false, secret_configured: true })).toBe('off')
    expect(moduleSetup('module.probe.dnspup', { enabled: true, secret_configured: true })).toBeNull()
    expect(moduleSetup('module.probe.dnspup', undefined)).toBeNull()
    expect(moduleSetup('module.autodefense', undefined)).toBeNull()
  })
})

describe('浏览页卡片跳转配置页', () => {
  it('links an enabled official module from its title and status to its page and keeps 详情 for the drawer', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [license('io.cdnca.ipintel-dnspup')], library: [], modules: ['module.ipintel.dnspup'] }, [ipintel]))
    renderWithProviders(<MarketStorePage />)
    const c = await card('io.cdnca.ipintel-dnspup')
    expect(await within(c).findByRole('link', { name: '已启用 · 去配置' })).toHaveAttribute('href', '/sys/ip-intel-updates')
    expect(within(c).getByRole('link', { name: 'IP 情报库更新' })).toHaveAttribute('href', '/sys/ip-intel-updates')
    // 官方模块也能在本机停用（原先“由授权自动启用，在配置页按网站关闭”的说明已删）。
    expect(within(c).queryByText(/由授权自动启用/)).toBeNull()
    expect(within(c).getByRole('button', { name: '停用' })).toBeInTheDocument()
    fireEvent.click(within(c).getByRole('button', { name: '详情' }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })

  it('does not link an enabled module without a page', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [license('io.cdnca.nopage'), license('io.cdnca.ipintel-dnspup')], library: [],
      modules: ['module.nopage', 'module.ipintel.dnspup'] }, [nopage, ipintel]))
    renderWithProviders(<MarketStorePage />)
    const c = await card('io.cdnca.nopage')
    expect(await within(c).findByText('已启用')).toBeInTheDocument()
    expect(within(c).queryByRole('link')).toBeNull()
    expect(within(c).getByRole('button', { name: '无页面模块' })).toBeInTheDocument()
    const b = await card('io.cdnca.ipintel-dnspup')
    expect(await within(b).findByRole('link', { name: '已启用 · 去配置' })).toHaveAttribute('href', '/sys/ip-intel-updates')
  })

  it('marks dnspup 未配置 without a key pair and 已关闭 when switched off, both to its settings page', async () => {
    const state: State = { licenses: [license('io.cdnca.probe-dnspup')], library: [], modules: ['module.probe.dnspup'],
      dnspup: { licensed: true, enabled: true, active: false, secret_configured: false, api_key: '' } }
    vi.stubGlobal('fetch', routes(state, [dnspup]))
    const first = renderWithProviders(<MarketStorePage />)
    let c = await card('io.cdnca.probe-dnspup')
    expect(await within(c).findByRole('link', { name: '未配置 · 去配置' })).toHaveAttribute('href', '/sys/probe-dnspup')
    first.unmount()
    state.dnspup = { licensed: true, enabled: false, active: false, secret_configured: true, api_key: 'k'.repeat(8) }
    renderWithProviders(<MarketStorePage />)
    c = await card('io.cdnca.probe-dnspup')
    expect(await within(c).findByRole('link', { name: '已关闭 · 去开启' })).toHaveAttribute('href', '/sys/probe-dnspup')
  })
})

describe('可安装类停用与重新启用', () => {
  const enabledLib = [{ plugin_id: 'bob.theme', installed: true, enabled: true, withdrawn: false }]

  it('disables an installed theme after a confirmation with a reason, then resumes it', async () => {
    const state: State = { licenses: [license('bob.theme')], library: enabledLib, modules: [] }
    vi.stubGlobal('fetch', routes(state, [theme]))
    let current = installation()
    vi.spyOn(platformPluginInstallationsApi, 'list').mockImplementation(async () => ({ items: [current] }))
    const disable = vi.spyOn(platformPluginInstallationsApi, 'disable').mockImplementation(async () => {
      current = installation({ status: 'disabled', revision: 3, authorization_status: 'disabled', paused_by: 'installation' })
      state.library = [{ ...enabledLib[0], enabled: false }]
      return { installation: current }
    })
    const resume = vi.spyOn(platformPluginInstallationsApi, 'resume').mockImplementation(async () => {
      current = installation({ revision: 4 })
      state.library = enabledLib
      return { installation: current }
    })
    renderWithProviders(<MarketStorePage />)
    let c = await card('bob.theme')
    fireEvent.click(await within(c).findByRole('button', { name: '停用' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/购买的使用权和安装记录保留/)).toBeInTheDocument()
    // 安装记录类插件停用不再填原因，确认即停用。
    expect(within(dialog).queryByLabelText('停用原因')).toBeNull()
    const ok = within(dialog).getByRole('button', { name: '确认停用' })
    expect(ok).toBeEnabled()
    fireEvent.click(ok)
    await waitFor(() => expect(disable).toHaveBeenCalledWith('store-token', platformScope, authorizationID, 2,
      expect.stringMatching(/^plugin-installation-disable-/)))
    c = await card('bob.theme')
    expect(await within(c).findByText('已停用')).toBeInTheDocument()
    expect(within(c).queryByText('已安装，可使用')).toBeNull()
    fireEvent.click(within(c).getByRole('button', { name: '重新启用' }))
    await waitFor(() => expect(resume).toHaveBeenCalledWith('store-token', platformScope, authorizationID, 3,
      expect.stringMatching(/^plugin-installation-resume-/)))
    expect(await within(await card('bob.theme')).findByText('已安装，可使用')).toBeInTheDocument()
  })

  it('does not offer 重新启用 for a platform pause and offers no 停用 without manage permission', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [license('bob.theme')], library: [{ ...enabledLib[0], enabled: false }], modules: [] }, [theme]))
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [installation({ status: 'disabled',
      authorization_status: 'disabled', paused_by: 'operator', paused_reason: '安全公告' })] })
    const first = renderWithProviders(<MarketStorePage />)
    const c = await card('bob.theme')
    expect(await within(c).findByText('已停用')).toBeInTheDocument()
    expect(within(c).getByText('平台已暂停，本机不能重新启用')).toBeInTheDocument()
    expect(within(c).queryByRole('button', { name: '重新启用' })).toBeNull()
    first.unmount()

    session(['marketplace.purchase', 'platform.admin', 'system_configuration.read', 'plugin_installations.platform.read'])
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [installation()] })
    vi.stubGlobal('fetch', routes({ licenses: [license('bob.theme')], library: enabledLib, modules: [] }, [theme]))
    renderWithProviders(<MarketStorePage />)
    expect(await within(await card('bob.theme')).findByText('已安装，可使用')).toBeInTheDocument()
    expect(within(await card('bob.theme')).queryByRole('button', { name: '停用' })).toBeNull()
  })

  it('offers 停用 in the 我的插件 row as well and shows 已停用 there afterwards', async () => {
    const state: State = { licenses: [license('bob.theme')], library: enabledLib, modules: [] }
    vi.stubGlobal('fetch', routes(state, [theme]))
    let current = installation()
    vi.spyOn(platformPluginInstallationsApi, 'list').mockImplementation(async () => ({ items: [current] }))
    vi.spyOn(platformPluginInstallationsApi, 'disable').mockImplementation(async () => {
      current = installation({ status: 'disabled', revision: 3, authorization_status: 'disabled', paused_by: 'installation' })
      state.library = [{ ...enabledLib[0], enabled: false }]
      return { installation: current }
    })
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?tab=mine'])
    const owned = (await screen.findByRole('heading', { name: '本主控已拥有的插件' })).closest('section')!
    const row = (await within(owned).findByText('Bob 主题')).closest('tr')!
    // The community edition has no theme management page: a theme row has no 去配置.
    expect(within(row).queryByRole('link', { name: '去配置' })).toBeNull()
    fireEvent.click(await within(row).findByRole('button', { name: '停用' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认停用' }))
    const after = (await within(owned).findByText('Bob 主题')).closest('tr')!
    expect(await within(after).findByText('已停用')).toBeInTheDocument()
    expect(within(after).getByRole('button', { name: '重新启用' })).toBeInTheDocument()
    expect(within(after).queryByRole('link', { name: '去配置' })).toBeNull()
  })
})

// 已获取的可安装插件还没有安装记录时，按前端已有数据区分“暂无可安装版本”与“等待发布或同步”，
// 不再一律写“在下方安装记录里确认”。判断依据：市场目录 latest_version（市场只取已发布版本，没有则为空）、
// 平台安装记录（/v1/platform/plugin-installations）里有没有这个 plugin_id。
describe('已获取但还没有安装记录', () => {
  const cfopt = { ...base, id: '99999999-9999-4999-8999-999999999999', plugin_id: 'io.cdnca.cf-optimize', kind: 'ui_page',
    risk_class: 'sandboxed', title: 'CF 优选', feature_code: 'module.cfopt', latest_version: null }
  const released = { ...cfopt, latest_version: '1.0.0' }

  it('derives 暂无可安装版本 / 等待发布或同步 / 待确认安装 from the catalog and the installation records', () => {
    const rows = (plugin: unknown, installations?: PluginInstallation[]) => ownedRows([license('io.cdnca.cf-optimize')] as never, [], [],
      new Map([['io.cdnca.cf-optimize', plugin as never]]), () => null, installations).map((r) => r.state)
    expect(rows(cfopt, [])).toEqual(['noVersion'])
    expect(rows(cfopt)).toEqual(['noVersion'])
    expect(rows(released, [])).toEqual(['awaitingSync'])
    expect(rows(released, [installation({ plugin_id: 'io.cdnca.cf-optimize', status: 'pending_confirmation' })])).toEqual(['pendingConfirm'])
    // 读不到安装记录（无平台读权限）：判断不了，不说“在下方确认”。
    expect(rows(released)).toEqual(['awaitingSync'])
  })

  it('shows 暂无可安装版本 in 我的插件 with the reason on hover and no 在下方安装记录里确认', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [license('io.cdnca.cf-optimize')], library: [], modules: ['module.cfopt'] }, [cfopt]))
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?tab=mine'])
    const owned = (await screen.findByRole('heading', { name: '本主控已拥有的插件' })).closest('section')!
    const row = (await within(owned).findByText('CF 优选')).closest('tr')!
    const tag = await within(row).findByText('暂无可安装版本')
    expect(within(row).queryByText('在下方安装记录里确认')).toBeNull()
    expect(within(row).queryByText('待确认安装')).toBeNull()
    fireEvent.mouseEnter(tag)
    expect(await screen.findByText('插件已获取，官方发布版本后会出现在下方等待确认')).toBeInTheDocument()
    // 浏览页卡片同样不引导去确认。
    fireEvent.click(screen.getByRole('tab', { name: '浏览' }))
    const c = await card('io.cdnca.cf-optimize')
    expect(await within(c).findByText('暂无可安装版本')).toBeInTheDocument()
    expect(within(c).queryByRole('button', { name: '去我的插件确认' })).toBeNull()
  })

  it('says 等待发布或同步 when a version exists but no installation record has arrived', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [license('io.cdnca.cf-optimize')], library: [], modules: ['module.cfopt'] }, [released]))
    vi.spyOn(platformPluginInstallationsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?tab=mine'])
    const owned = (await screen.findByRole('heading', { name: '本主控已拥有的插件' })).closest('section')!
    const row = (await within(owned).findByText('CF 优选')).closest('tr')!
    expect(await within(row).findByText('等待发布或同步（约 1 分钟）')).toBeInTheDocument()
    expect(within(row).queryByText('在下方安装记录里确认')).toBeNull()
  })
})
