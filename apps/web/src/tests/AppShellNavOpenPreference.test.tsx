import { fireEvent, screen } from '@testing-library/react'
import { Route, Routes, useNavigate } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'

const menuOpenKey = (role: string) => { const p = useSessionStore.getState().principal!; return `cdnca.ui.menu-open.${role}.${p.scope_id}.${p.user_id}.v3` }
import { renderWithProviders } from '../test/render'

// 手动展开偏好按角色存 cdnca.ui.menu-open.<role>.v2，只记用户手动开合的增量；
// 当前页的父组临时展开，离开即释放。旧键（混有自动展开）不再读取。
function installViewport(mobile: boolean) {
  vi.stubGlobal('innerWidth', mobile ? 390 : 1440)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: mobile && query === '(max-width: 767px)',
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }))
}

function Probe() {
  const navigate = useNavigate()
  return (
    <section aria-label="open-preference-probe">
      <button type="button" onClick={() => navigate('/admin-home')}>go-admin-home</button>
      <button type="button" onClick={() => navigate(-1)}>go-back</button>
      <button type="button" onClick={() => navigate('/home')}>go-home</button>
      <button type="button" onClick={() => navigate('/node/list')}>go-node-list</button>
      <button type="button" onClick={() => navigate('/monitor/stream/live-connections')}>go-live-connections</button>
    </section>
  )
}

const roles = {
  admin: {
    actor: () => principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] }),
    home: '/admin-home',
    deep: '/node/list',
    goHome: 'go-admin-home',
    goDeep: 'go-node-list',
    routeGroups: ['节点管理'],
    parentKey: 'node',
  },
  user: {
    actor: () => principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['identity.self.read', 'sites.read', 'streams.read', 'billing.account.read'] }),
    home: '/home',
    deep: '/monitor/stream/live-connections',
    goHome: 'go-home',
    goDeep: 'go-live-connections',
    routeGroups: ['统计分析', '诊断'],
    parentKey: 'monitor',
  },
} as const

function renderShell(role: keyof typeof roles, path: string, mobile: boolean) {
  const actor = roles[role].actor()
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const rendered = renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<Probe />} />
      </Route>
    </Routes>,
    [path],
  )
  if (mobile) fireEvent.click(screen.getByRole('button', { name: '打开导航' }))
  return rendered
}

const group = (name: string) => screen.getByRole('menuitem', { name })
const expandedGroups = (container: HTMLElement) => [...container.querySelectorAll('.app-sidebar [aria-expanded="true"]')]
  .map((node) => node.textContent)
const stored = (role: string) => JSON.parse(window.localStorage.getItem(menuOpenKey(role)) ?? 'null') as string[] | null

afterEach(() => {
  window.localStorage.clear()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe.each([
  ['管理员', 'admin', false],
  ['管理员', 'admin', true],
  ['租户', 'user', false],
  ['租户', 'user', true],
] as const)('%s（%s，手机抽屉 %s）展开偏好', (_name, role, mobile) => {
  const spec = roles[role]
  beforeEach(async () => {
    installViewport(mobile)
    await i18n.changeLanguage('zh-CN')
  })

  it('首次进入概览全部收拢；旧键里的污染数组不生效、不被删除', () => {
    const legacy = JSON.stringify(['monitor', 'monitor-diagnostics', 'node', 'site'])
    window.localStorage.setItem(`cdnca.ui.menu-open.${role}`, legacy)
    const { container } = renderShell(role, spec.home, mobile)

    expect(expandedGroups(container)).toEqual([])
    expect(window.localStorage.getItem(`cdnca.ui.menu-open.${role}`)).toBe(legacy)
    expect(stored(role)).toBeNull()
  })

  it('深链自动展开父链，回概览释放；手动开网站管理只存 site，刷新与换会话后只有它开着', () => {
    const first = renderShell(role, spec.deep, mobile)
    for (const name of spec.routeGroups) expect(group(name)).toHaveAttribute('aria-expanded', 'true')

    fireEvent.click(screen.getByRole('button', { name: spec.goHome }))
    expect(expandedGroups(first.container)).toEqual([])

    fireEvent.click(group('网站管理'))
    expect(group('网站管理')).toHaveAttribute('aria-expanded', 'true')
    expect(stored(role)).toEqual(['site'])
    first.unmount()

    const refreshed = renderShell(role, spec.home, mobile)
    expect(expandedGroups(refreshed.container)).toEqual(['网站管理'])
    refreshed.unmount()

    useSessionStore.getState().clearSession()
    const nextSession = renderShell(role, spec.home, mobile)
    expect(expandedGroups(nextSession.container)).toEqual(['网站管理'])
    expect(stored(role)).toEqual(['site'])
  })

  // 同一浏览器换账号不继承上一个账号的展开；换回原账号恢复它自己的选择。
  it('换账号首登全收拢，换回原账号恢复其偏好', () => {
    const shellAs = (userID: string) => {
      const actor = { ...roles[role].actor(), user_id: userID }
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const rendered = renderWithProviders(
        <Routes><Route element={<AppShell />}><Route path="*" element={<Probe />} /></Route></Routes>,
        [spec.home],
      )
      if (mobile) fireEvent.click(screen.getByRole('button', { name: '打开导航' }))
      return rendered
    }
    const a = shellAs('aaaaaaaa-0000-4000-8000-00000000000a')
    fireEvent.click(group('网站管理'))
    expect(group('网站管理')).toHaveAttribute('aria-expanded', 'true')
    a.unmount()
    useSessionStore.getState().clearSession()
    const b = shellAs('bbbbbbbb-0000-4000-8000-00000000000b')
    expect(expandedGroups(b.container)).toEqual([])
    b.unmount()
    useSessionStore.getState().clearSession()
    const again = shellAs('aaaaaaaa-0000-4000-8000-00000000000a')
    expect(expandedGroups(again.container)).toEqual(['网站管理'])
  })

  it('深链上收拢父组后本页保持关闭；再打开只存这次点的键；概览只按偏好展开', () => {
    const { container } = renderShell(role, spec.deep, mobile)
    const parent = spec.routeGroups[0]

    fireEvent.click(group(parent))
    expect(group(parent)).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(screen.getByRole('button', { name: spec.goDeep }))
    expect(group(parent)).toHaveAttribute('aria-expanded', 'false')
    expect(stored(role) ?? []).toEqual([])

    fireEvent.click(group(parent))
    expect(group(parent)).toHaveAttribute('aria-expanded', 'true')
    expect(stored(role)).toEqual([spec.parentKey])

    fireEvent.click(screen.getByRole('button', { name: spec.goHome }))
    expect(expandedGroups(container)).toEqual([parent])
  })

  it('收拢后换页，再进相关深链会重新自动展开，且不写偏好', () => {
    const { container } = renderShell(role, spec.deep, mobile)
    fireEvent.click(group(spec.routeGroups[0]))
    fireEvent.click(screen.getByRole('button', { name: spec.goHome }))
    expect(expandedGroups(container)).toEqual([])

    fireEvent.click(screen.getByRole('button', { name: spec.goDeep }))
    for (const name of spec.routeGroups) expect(group(name)).toHaveAttribute('aria-expanded', 'true')
    expect(stored(role) ?? []).toEqual([])
  })

  it('关闭当前父组 → 离开 → 浏览器后退回同一地址，父链重新完整打开', () => {
    const { container } = renderShell(role, spec.deep, mobile)
    fireEvent.click(group(spec.routeGroups[0]))
    expect(group(spec.routeGroups[0])).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(screen.getByRole('button', { name: spec.goHome }))
    expect(expandedGroups(container)).toEqual([])

    fireEvent.click(screen.getByRole('button', { name: 'go-back' }))
    for (const name of spec.routeGroups) expect(group(name)).toHaveAttribute('aria-expanded', 'true')
    expect(stored(role) ?? []).toEqual([])
  })

  // 只按角色存的旧键（v1 与 v2）都没有账号归属，不读：首次进入全收拢。
  it('只按角色存的旧键（含 v2）都不读，首次进入全收拢', () => {
    window.localStorage.setItem(`cdnca.ui.menu-open.${role}`, JSON.stringify(['site', 'monitor']))
    window.localStorage.setItem(`cdnca.ui.menu-open.${role}.v2`, JSON.stringify(['site', 'monitor']))
    const { container } = renderShell(role, spec.home, mobile)
    expect(expandedGroups(container)).toEqual([])
    expect(stored(role)).toBeNull()
  })
})

describe('折叠态', () => {
  it.each(['admin', 'user'] as const)('%s 深链回概览后折叠再展开，自动展开项不回来，偏好不变', async (role) => {
    installViewport(false)
    await i18n.changeLanguage('zh-CN')
    const spec = roles[role]
    const { container } = renderShell(role, spec.deep, false)
    fireEvent.click(screen.getByRole('button', { name: spec.goHome }))
    fireEvent.click(group('网站管理'))
    const toggle = () => screen.getByRole('button', { name: /^(折叠导航|展开导航)$/ })
    fireEvent.click(toggle())
    fireEvent.click(toggle())

    expect(expandedGroups(container)).toEqual(['网站管理'])
    expect(stored(role)).toEqual(['site'])
  })
})
