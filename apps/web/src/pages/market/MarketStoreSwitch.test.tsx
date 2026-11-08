import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import MarketStorePage from './MarketStorePage'
import storeCSS from './MarketStorePage.css?raw'
import type { MarketPlugin } from '../../api/market'
import { dependentsOf, storeState } from './marketModel'

// 插件商店本机停用：
//   1 卡片底部操作条在同一行底边对齐，说明小字不把它挤到不同高度；
//   2 已启用的插件都能在本主控停用、再重新启用（官方模块走本机停用名单），停用被依赖的插件时列出会一起失效的；
//   3 详情抽屉里的状态标签常态可读，配色与卡片操作条一致。

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body,
    text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

const freePlan = { id: 'p-free', plugin_id: 'x', revision: 1, kind: 'free', price_minor: 0, currency: 'CNY', trial_days: 0,
  status: 'active', active_revision: 1 }
const base = { namespace: 'io.cdnca', risk_class: 'privileged', status: 'listed', publisher_kind: 'official', latest_version: '1.0.0',
  price_plans: [freePlan] }
const autodefense = { ...base, id: '44444444-4444-4444-8444-444444444444', plugin_id: 'io.cdnca.autodefense', kind: 'module',
  title: '智能自动防御', feature_code: 'module.autodefense' }
const auto = { ...base, id: '45555555-4444-4444-8444-444444444444', plugin_id: 'io.cdnca.autodefense-auto', kind: 'module',
  title: '智能自动防御：自动处置', feature_code: 'module.autodefense.auto' }
const escalate = { ...base, id: '46666666-4444-4444-8444-444444444444', plugin_id: 'io.cdnca.escalate', kind: 'module',
  title: '攻击自动升级', feature_code: 'module.escalate' }
const bridge = { ...base, id: '77777777-7777-4777-8777-777777777777', plugin_id: 'io.cdnca.billing-bridge', kind: 'module',
  title: '财务系统对接', feature_code: 'module.billing.bridge' }
// Modules with a page in the community edition.
const ipintel = { ...base, id: '55555555-5555-4555-8555-555555555555', plugin_id: 'io.cdnca.ipintel-dnspup', kind: 'module',
  title: 'IP 情报库更新', feature_code: 'module.ipintel.dnspup' }
const dnspup = { ...base, id: '66666666-6666-4666-8666-666666666666', plugin_id: 'io.cdnca.probe-dnspup', kind: 'module',
  title: '拨测（dnspup）', feature_code: 'module.probe.dnspup' }
const selfwaf = { ...base, id: '88888888-7777-4777-8777-777777777777', plugin_id: 'io.cdnca.selfwaf', kind: 'rule_pack',
  title: '自研检测规则集', feature_code: 'pack.selfwaf' }
const license = (pluginID: string) => ({ id: `l-${pluginID}`, plugin_id: pluginID, installation_id: 'i', kind: 'free', status: 'active' })

type Fetch = (path: string, init?: RequestInit) => Promise<Response>
interface State { modules: string[]; stopped: Map<string, string>; writes: { path: string; key: string | null; body: unknown }[] }

// The controller under test: the lease grants every code; stopping one takes it out of /v1/modules and lists it
// in the library with locally_disabled (as control-api does).
function routes(items: typeof autodefense[], state: State) {
  return vi.fn<Fetch>(async (path, init) => {
    const toggle = path.match(/^\/v1\/admin\/market\/plugin-library\/([^/]+)\/(disable|enable)$/)
    if (toggle && init?.method === 'POST') {
      const body = JSON.parse(String(init.body ?? '{}')) as { feature_code?: string }
      state.writes.push({ path, key: (init.headers as Record<string, string>)['Idempotency-Key'] ?? null, body })
      const plugin = decodeURIComponent(toggle[1])
      const code = items.find((p) => p.plugin_id === plugin)!.feature_code
      if (toggle[2] === 'disable') state.stopped.set(plugin, code)
      else state.stopped.delete(plugin)
      return json({ plugin_id: plugin, feature_code: code, locally_disabled: toggle[2] === 'disable' })
    }
    if (path.startsWith('/v1/admin/market/plugins?')) return json({ items, next_cursor: null })
    if (path.startsWith('/v1/admin/market/plugins/')) {
      const plugin = items.find((p) => path.endsWith(p.id)) ?? items[0]
      return json({ plugin, versions: [], price_plans: [freePlan] })
    }
    if (path.startsWith('/v1/admin/market/licenses')) return json({ items: items.map((p) => license(p.plugin_id)), next_cursor: null })
    if (path === '/v1/admin/market/plugin-library') {
      return json({ items: [...state.stopped.keys()].map((plugin_id) => ({ plugin_id, installed: false, enabled: false, withdrawn: false,
        locally_disabled: true })) })
    }
    if (path === '/v1/modules') {
      const stopped = new Set(state.stopped.values())
      return json({ status: 'valid', lease_serial: 1, modules: state.modules.filter((code) => !stopped.has(code)) })
    }
    if (path.startsWith('/v1/admin/market/advisories')) return json({ items: [] })
    if (path.startsWith('/v1/plugin-ui/pages')) return json({ items: [] })
    if (path.startsWith('/v1/platform/plugin-installations')) return json({ items: [] })
    return json({ error: { code: 'not_found' } }, 404)
  })
}

const card = async (pluginID: string) => screen.findByTestId(`market-card-${pluginID}`)
function session(permissions: string[]) {
  const admin = principal({ scope_kind: 'platform', scope_id: '018cc251-f400-7def-8000-000000000040', tenant_id: null, roles: ['custom'],
    permissions })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'store-token' }, admin)
}
const adminPermissions = ['marketplace.purchase', 'platform.admin', 'system_configuration.read', 'plugin_installations.platform.read',
  'plugin_installations.platform.manage']
const newState = (modules: string[]): State => ({ modules, stopped: new Map(), writes: [] })

beforeEach(async () => {
  await changeLocale('zh-CN')
  session(adminPermissions)
})
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('本机停用的状态与依赖', () => {
  it('reads a locally stopped plugin as 已停用 before the lease, and lists the enabled plugins that need it', () => {
    const lib = [{ plugin_id: 'io.cdnca.autodefense', installed: false, enabled: false, withdrawn: false, locally_disabled: true }]
    expect(storeState(autodefense as never, [license('io.cdnca.autodefense')] as never, lib, [])).toBe('disabled')
    expect(storeState(autodefense as never, [license('io.cdnca.autodefense')] as never, [], ['module.autodefense'])).toBe('enabled')
    // 授权失效仍优先：本机停用不掩盖授权已结束。
    expect(storeState(autodefense as never, [], [{ ...lib[0], installed: true }], [])).toBe('revoked')
    // 自动处置、攻击自动升级都靠智能自动防御的判定；只列本机仍生效的。
    expect(dependentsOf('module.autodefense', [autodefense, auto, escalate, bridge] as unknown as MarketPlugin[],
      ['module.autodefense', 'module.autodefense.auto', 'module.escalate', 'module.billing.bridge'])
      .map((p) => p.plugin_id)).toEqual(['io.cdnca.autodefense-auto', 'io.cdnca.escalate'])
    expect(dependentsOf('module.autodefense', [autodefense, auto, escalate] as unknown as MarketPlugin[], ['module.autodefense', 'module.escalate'])
      .map((p) => p.plugin_id)).toEqual(['io.cdnca.escalate'])
    expect(dependentsOf('module.billing.bridge', [autodefense, auto, bridge] as unknown as MarketPlugin[], ['module.billing.bridge'])).toEqual([])
  })
})

describe('官方模块与规则包在本主控停用、重新启用', () => {
  // The community edition never grants 智能自动防御 (no page, no dependents to list): the module case uses IP 情报库更新;
  // the dependents list is covered by dependentsOf above.
  it('stops an official module after a confirmation naming what it affects, then enables it again', async () => {
    const state = newState(['module.ipintel.dnspup'])
    vi.stubGlobal('fetch', routes([ipintel], state))
    renderWithProviders(<MarketStorePage />)
    let c = await card('io.cdnca.ipintel-dnspup')
    expect(await within(c).findByRole('link', { name: '已启用 · 去配置' })).toBeInTheDocument()
    // 原先“由授权自动启用，在配置页按网站关闭/本机没有单独的停用开关”这类话不再出现。
    expect(screen.queryByText(/由授权自动启用/)).toBeNull()
    fireEvent.click(within(c).getByRole('button', { name: '停用' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/本主控所有租户将无法使用该功能，已有配置保留/)).toBeInTheDocument()
    expect(within(dialog).getByText(/授权和计费不变/)).toBeInTheDocument()
    expect(within(dialog).queryByRole('list', { name: '会一起失效的插件' })).toBeNull()
    // 不再填停用原因，确认即停用，请求只带功能码。
    expect(within(dialog).queryByLabelText('停用原因')).toBeNull()
    expect(within(dialog).queryByRole('textbox')).toBeNull()
    const ok = within(dialog).getByRole('button', { name: '确认停用' })
    expect(ok).toBeEnabled()
    fireEvent.click(ok)
    await waitFor(() => expect(state.writes).toHaveLength(1))
    expect(state.writes[0]).toEqual({ path: '/v1/admin/market/plugin-library/io.cdnca.ipintel-dnspup/disable',
      key: expect.stringMatching(/^plugin-local-disable-/), body: { feature_code: 'module.ipintel.dnspup' } })
    c = await card('io.cdnca.ipintel-dnspup')
    expect(await within(c).findByText('已停用')).toBeInTheDocument()
    expect(within(c).queryByRole('link', { name: '已启用 · 去配置' })).toBeNull()
    fireEvent.click(within(c).getByRole('button', { name: '重新启用' }))
    await waitFor(() => expect(state.writes).toHaveLength(2))
    expect(state.writes[1]).toEqual({ path: '/v1/admin/market/plugin-library/io.cdnca.ipintel-dnspup/enable',
      key: expect.stringMatching(/^plugin-local-enable-/), body: {} })
    expect(await within(await card('io.cdnca.ipintel-dnspup')).findByRole('link', { name: '已启用 · 去配置' })).toBeInTheDocument()
  })

  it('stops a rule pack from the 我的插件 row and offers 重新启用 there', async () => {
    const state = newState(['pack.selfwaf', 'module.billing.bridge'])
    vi.stubGlobal('fetch', routes([selfwaf, bridge], state))
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?tab=mine'])
    const owned = (await screen.findByRole('heading', { name: '本主控已拥有的插件' })).closest('section')!
    const row = (await within(owned).findByText('自研检测规则集')).closest('tr')!
    fireEvent.click(await within(row).findByRole('button', { name: '停用' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('list', { name: '会一起失效的插件' })).toBeNull()
    expect(within(dialog).queryByLabelText('停用原因')).toBeNull()
    fireEvent.click(within(dialog).getByRole('button', { name: '确认停用' }))
    await waitFor(() => expect(state.writes.map((w) => w.path)).toEqual(['/v1/admin/market/plugin-library/io.cdnca.selfwaf/disable']))
    const after = (await within(owned).findByText('自研检测规则集')).closest('tr')!
    expect(await within(after).findByText('已停用')).toBeInTheDocument()
    expect(within(after).queryByRole('link', { name: '去配置' })).toBeNull()
    fireEvent.click(within(after).getByRole('button', { name: '重新启用' }))
    await waitFor(() => expect(state.writes).toHaveLength(2))
    expect(await within((await within(owned).findByText('自研检测规则集')).closest('tr')!).findByText('已启用')).toBeInTheDocument()
  })

  it('offers no 停用 to a session that cannot manage platform plugins', async () => {
    session(['marketplace.purchase', 'marketplace.browse'])
    vi.stubGlobal('fetch', routes([bridge], newState(['module.billing.bridge'])))
    renderWithProviders(<MarketStorePage />)
    const c = await card('io.cdnca.billing-bridge')
    expect(await within(c).findByText(/已启用/)).toBeInTheDocument()
    expect(within(c).queryByRole('button', { name: '停用' })).toBeNull()
  })
})

describe('卡片操作条对齐', () => {
  it('puts every card action in one footer at the end of a flex column body, below any hint', async () => {
    vi.stubGlobal('fetch', routes([ipintel, dnspup, selfwaf], newState(['module.ipintel.dnspup', 'module.probe.dnspup', 'pack.selfwaf'])))
    renderWithProviders(<MarketStorePage />)
    for (const id of ['io.cdnca.ipintel-dnspup', 'io.cdnca.probe-dnspup', 'io.cdnca.selfwaf']) {
      const c = await card(id)
      await within(c).findByRole('link', { name: '已启用 · 去配置' })
      // antd 的 actions 行会给链接套灰色并撑满整格：不用它。
      expect(c.querySelector('.ant-card-actions')).toBeNull()
      const body = c.querySelector('.ant-card-body')!
      const footer = body.lastElementChild!
      expect(footer).toHaveClass('market-store-footer')
      expect(within(footer as HTMLElement).getByRole('link', { name: '已启用 · 去配置' })).toBeInTheDocument()
    }
    const rule = (selector: string) => storeCSS.match(new RegExp(`(^|\\n)${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\{([^}]*)\\}`))?.[2] ?? ''
    expect(rule('.market-store-card')).toMatch(/display: flex/)
    expect(rule('.market-store-card')).toMatch(/flex-direction: column/)
    expect(rule('.market-store-card > .ant-card-body')).toMatch(/flex: 1/)
    expect(rule('.market-store-card > .ant-card-body')).toMatch(/flex-direction: column/)
    expect(rule('.market-store-footer')).toMatch(/margin-top: auto/)
  })
})

describe('详情抽屉状态标签', () => {
  it('shows the same readable status link in the drawer as on the card, without low opacity', async () => {
    vi.stubGlobal('fetch', routes([ipintel], newState(['module.ipintel.dnspup'])))
    renderWithProviders(<MarketStorePage />)
    const c = await card('io.cdnca.ipintel-dnspup')
    const onCard = await within(c).findByRole('link', { name: '已启用 · 去配置' })
    fireEvent.click(within(c).getByRole('button', { name: '详情' }))
    const dialog = await screen.findByRole('dialog')
    const inDrawer = await within(dialog).findByRole('link', { name: '已启用 · 去配置' })
    expect(inDrawer.className).toBe(onCard.className)
    // 根因：--ant-color-success 未定义时回退到 --cdnca-color-green6（主题里是 #edfbf3，和背景几乎同色）。
    const css = storeCSS.replace(/\/\*[\s\S]*?\*\//g, '')
    const ready = css.match(/\.market-store-goto\.market-store-goto--ready[^{]*\{([^}]*)\}/)?.[1] ?? ''
    expect(ready).toMatch(/color: color-mix\(in srgb, var\(--cdnca-color-success\) \d+%, var\(--cdnca-color-neutral80, #000000\)\)/)
    expect(ready).toMatch(/background: var\(--cdnca-color-success-bg\)/)
    expect(css).not.toMatch(/--ant-color-success|--cdnca-color-green6/)
    expect(css).not.toMatch(/market-store-goto[^{]*\{[^}]*opacity/)
    // 悬停不换颜色（原先悬停才变蓝看得见）：常态与悬停同一条规则。
    expect(css).toMatch(/\.market-store-goto\.market-store-goto--ready,\s*\.market-store-goto\.market-store-goto--ready:hover/)
  })
})
