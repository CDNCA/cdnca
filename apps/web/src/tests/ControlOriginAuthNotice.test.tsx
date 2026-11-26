import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'

import { sourceIPHeaderReadable, type ControlOriginAuthStatus } from '../api/controlOriginAuth'
import { systemOtherSettingsApi, type PlatformSystemOtherSettings } from '../api/systemOtherSettings'
import { useSessionStore } from '../auth/session'
import ControlOriginAuthNotice, { VisitorIPSetting, controlOriginAuthSettingsPath } from '../components/ControlOriginAuthNotice'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// System settings → Other → Access and network
// holds 源IP请求头 (saved with the tab, applies at once) and one line saying
// where the visitor IP comes from; a host with origin authentication applied
// shows that line only. The platform home warns while a CDN request without
// the visitor IP is seen and links there. No root command anywhere.
// http代理 (DNS API requests) sits below it, saved with the tab.
function authenticate(permissions: string[]) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function status(overrides: Partial<ControlOriginAuthStatus>): ControlOriginAuthStatus {
  return { cdn_without_origin_auth: false, origin_auth_enabled: false, baota: false, client_headers_forwarded: true, real_ip_header: '',
    key_only: false, visitor_ip_confirmed: false, header: '', last_seen_at: null, last_confirmed_at: null, ...overrides }
}

const json = (body: unknown, code = 200) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } })
const isStatusCall = (input: unknown) => String(input instanceof Request ? input.url : input).includes('/v1/admin/control-origin-auth')

/** Answers the status endpoint with body; everything else is 404. */
function mockStatus(body: ControlOriginAuthStatus) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    isStatusCall(input) ? json(body) : json({ error: { code: 'not_found', request_id: 'r' } }, 404))
}

const behindCDN = status({ cdn_without_origin_auth: true, header: 'CF-Connecting-IP', last_seen_at: '2026-11-23T08:00:00Z' })
const originAuth = status({ origin_auth_enabled: true, real_ip_header: 'True-Client-IP', visitor_ip_confirmed: true, last_confirmed_at: '2026-11-23T08:00:00Z' })

// The fields no code reads: kept in the document and saved back unchanged, never shown.
const otherValue: PlatformSystemOtherSettings = {
  source_ip_header: '', api_key_enabled: true, dns_protection: 'www', record_repair_mode: 'repair_delete_extra', sync_batch: 500,
  sync_scope: 'region', disable_failed_sync_nodes: false, resource_rank: 50, http_proxy: 'http://proxy.example:3128', tcp_factor: 1.3,
  l4_drain_max_seconds: 86400, domain_ownership_policy: 'wildcard_only', certificate_expiry_notice_days: [30, 14, 7, 3, 1], rule_intel_contribution: true,
}
const removedLabels = ['DNS记录保护', '记录定时修复', '单次同步站点最大个数', '同步范围', '资源排行显示的数量', 'TCP系数',
  '直连（未设置代理）', '经代理', 'DNS 记录', '统计与流量', 'CDN 回源鉴权', 'X-Cdnca-Origin-Key']

function mockOtherSettings(value: PlatformSystemOtherSettings = otherValue) {
  vi.spyOn(systemOtherSettingsApi, 'get').mockResolvedValue({ schema: 'cdnca.platform-system-other-settings/v1', revision: 3, value })
  return vi.spyOn(systemOtherSettingsApi, 'put').mockImplementation(async (_token, revision, next) =>
    ({ schema: 'cdnca.platform-system-other-settings/v1', revision: revision + 1, value: next }))
}

async function openOptions() {
  fireEvent.mouseDown(await screen.findByRole('combobox', { name: '源IP请求头' }))
  const options = await screen.findAllByRole('option')
  return options.map((option) => ({ label: option.querySelector('.ant-select-item-option-content')?.textContent,
    disabled: option.classList.contains('ant-select-item-option-disabled') }))
}

function renderSetting(props: Partial<Parameters<typeof VisitorIPSetting>[0]> = {}) {
  const onChange = vi.fn()
  renderWithProviders(<VisitorIPSetting value="" saved="" disabled={false} onChange={onChange} {...props} />)
  return onChange
}

describe('ControlOriginAuthNotice (home)', () => {
  beforeEach(() => authenticate(['system_configuration.read']))
  afterEach(() => { vi.restoreAllMocks(); useSessionStore.getState().clearSession() })

  it('warns behind a CDN without the visitor IP and links to 源IP请求头', async () => {
    mockStatus(behindCDN)
    renderWithProviders(<ControlOriginAuthNotice />)
    const notice = await screen.findByTestId('control-origin-auth-home')
    expect(notice.textContent).toContain('检测到主控前面有 CDN，但未取得访客 IP')
    const link = within(notice).getByRole('link', { name: '设置源 IP 请求头' })
    expect(link.getAttribute('href')).toBe(controlOriginAuthSettingsPath)
    expect(controlOriginAuthSettingsPath).toBe('/sys/setting?tab=other&section=originauth')
    expect(notice.textContent).not.toMatch(/root|install-control|回源鉴权/)
  })

  it('on an origin-auth host whose CDN sent the key but not the visitor IP, names the header to add at the CDN', async () => {
    mockStatus(status({ cdn_without_origin_auth: true, origin_auth_enabled: true, real_ip_header: 'True-Client-IP', key_only: true }))
    renderWithProviders(<ControlOriginAuthNotice />)
    const notice = await screen.findByTestId('control-origin-auth-home')
    expect(notice.textContent).toContain('回源密钥通过，但未取得访客 IP')
    expect(notice.textContent).toContain('名称 True-Client-IP')
    expect(notice.textContent).not.toMatch(/执行|命令/)
  })

  it('shows nothing for direct access or once the visitor IP is confirmed', async () => {
    for (const body of [status({}), status({ visitor_ip_confirmed: true }), originAuth]) {
      const fetch = mockStatus(body)
      const { container, unmount } = renderWithProviders(<ControlOriginAuthNotice />)
      await waitFor(() => expect(fetch).toHaveBeenCalled())
      await new Promise((resolve) => setTimeout(resolve, 20))
      expect(container.querySelector('[data-testid="control-origin-auth-home"]')).toBeNull()
      unmount()
      vi.restoreAllMocks()
    }
  })

  it('does not ask without system_configuration.read', async () => {
    authenticate([])
    const fetch = mockStatus(behindCDN)
    renderWithProviders(<ControlOriginAuthNotice />)
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('VisitorIPSetting', () => {
  beforeEach(() => authenticate(['system_configuration.read']))
  afterEach(() => { vi.restoreAllMocks(); useSessionStore.getState().clearSession() })

  it('offers direct and the four headers, and reports a choice', async () => {
    mockStatus(status({}))
    const onChange = renderSetting()
    await waitFor(() => expect(screen.getByTestId('visitor-ip-status')).toBeInTheDocument())
    expect(await openOptions()).toEqual([
      { label: '不设置（直连）', disabled: false }, { label: 'CF-Connecting-IP', disabled: false }, { label: 'True-Client-IP', disabled: false },
      { label: 'X-Forwarded-For（取最左）', disabled: false }, { label: 'X-Real-IP', disabled: false }])
    fireEvent.click(screen.getByText('CF-Connecting-IP'))
    expect(onChange).toHaveBeenCalledWith('CF-Connecting-IP', expect.anything())
  })

  it.each([
    { name: 'the console nginx does not pass the client headers', body: status({ client_headers_forwarded: false }) },
    { name: 'a BaoTa host', body: status({ baota: true }) },
  ])('offers X-Forwarded-For / X-Real-IP only where they can be read: $name', async ({ body }) => {
    mockStatus(body)
    renderSetting()
    await waitFor(() => expect(screen.getByTestId('visitor-ip-status')).toBeInTheDocument())
    // the status has to be in before the options say which are readable
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect((await openOptions()).map((option) => option.disabled)).toEqual([false, false, false, true, true])
  })

  it.each([
    { name: 'direct', saved: '', body: status({}), text: '访客 IP 取自直连来源', state: 'direct' },
    { name: 'CF-Connecting-IP', saved: 'CF-Connecting-IP', body: status({}), text: '访客 IP 取自 CF-Connecting-IP', state: 'header' },
    { name: 'X-Forwarded-For', saved: 'X-Forwarded-For', body: status({}), text: '访客 IP 取自 X-Forwarded-For', state: 'header' },
    { name: 'X-Real-IP the console cannot read', saved: 'X-Real-IP', body: status({ client_headers_forwarded: false }), text: '访客 IP 取自直连来源', state: 'direct' },
    { name: 'a CDN request without the visitor IP', saved: '', body: behindCDN, text: '访客 IP 取自直连来源 · 最近经 CDN 的请求未取得访客 IP', state: 'direct' },
  ])('says where the visitor IP comes from by the saved value: $name', async ({ saved, body, text, state }) => {
    mockStatus(body)
    renderSetting({ saved, value: saved })
    await waitFor(() => expect(screen.getByTestId('visitor-ip-status').textContent).toBe(text))
    expect(screen.getByTestId('visitor-ip-status').getAttribute('data-state')).toBe(state)
  })

  // With the origin key on, a CDN request that did not match it
  // still takes 源IP请求头 (control-api withVisitorIP), so the choice stays next to the origin-auth line.
  it('on a host with origin authentication applied shows the origin-auth line and keeps the 源IP请求头 choice', async () => {
    mockStatus(originAuth)
    renderSetting({ saved: 'CF-Connecting-IP', value: 'CF-Connecting-IP' })
    const line = await screen.findByTestId('visitor-ip-origin-auth')
    expect(line.getAttribute('data-state')).toBe('origin_auth')
    expect(screen.getByTestId('visitor-ip-settings')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '源IP请求头' })).toBeInTheDocument()
    // The confirmed origin-auth line names the deployment's header; the selection line says it governs the rest.
    expect(screen.getByTestId('visitor-ip-origin-auth').textContent).toBe('已应用回源密钥校验，访客 IP 取自 True-Client-IP')
    expect(screen.getByTestId('visitor-ip-status').textContent).toBe('未通过回源密钥的请求：访客 IP 取自 CF-Connecting-IP')
    expect(screen.getByTestId('visitor-ip-settings').textContent).not.toMatch(/密钥值|secret|origin_auth_key/i)
  })

  // 密钥通过但所选头没有访客 IP（key_only）、或连厂商头都没有时，设置处不读作已确认。
  it.each([
    { name: 'key matched, header empty', body: status({ origin_auth_enabled: true, real_ip_header: 'True-Client-IP', cdn_without_origin_auth: true, key_only: true, last_seen_at: '2026-11-23T08:00:00Z' }),
      text: '已应用回源密钥校验 · 回源密钥已通过，但 True-Client-IP 里没有访客 IP，检查 CDN 回源请求头' },
    { name: 'a CDN header without the key', body: status({ origin_auth_enabled: true, real_ip_header: 'True-Client-IP', cdn_without_origin_auth: true, header: 'EO-Connecting-IP', last_seen_at: '2026-11-23T08:00:00Z' }),
      text: '已应用回源密钥校验 · 最近经 CDN 的请求未取得访客 IP' },
    { name: 'confirmed', body: originAuth, text: '已应用回源密钥校验，访客 IP 取自 True-Client-IP' },
  ])('on an origin-auth host says when the visitor IP is still missing: $name', async ({ body, text }) => {
    mockStatus(body)
    renderSetting({ saved: '', value: '' })
    await waitFor(() => expect(screen.getByTestId('visitor-ip-origin-auth').textContent).toBe(text))
    expect(screen.getByRole('combobox', { name: '源IP请求头' })).toBeInTheDocument()
  })

  it('stays usable when the status cannot be read', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ error: { code: 'internal', request_id: 'r' } }, 500))
    renderSetting({ saved: 'X-Real-IP', value: 'X-Real-IP' })
    expect(screen.getByTestId('visitor-ip-status').textContent).toBe('访客 IP 取自 X-Real-IP')
    expect((await openOptions()).every((option) => !option.disabled)).toBe(true)
  })

  it('treats only X-Forwarded-For and X-Real-IP as needing the client headers', () => {
    const blocked = status({ client_headers_forwarded: false })
    expect(['', 'CF-Connecting-IP', 'True-Client-IP'].every((header) => sourceIPHeaderReadable(header, blocked))).toBe(true)
    expect(sourceIPHeaderReadable('X-Forwarded-For', blocked) || sourceIPHeaderReadable('X-Real-IP', status({ baota: true }))).toBe(false)
    expect(sourceIPHeaderReadable('X-Real-IP')).toBe(true)
  })
})

describe('Other → Access and network', () => {
  beforeEach(() => authenticate(['system_configuration.read', 'system_configuration.manage']))
  afterEach(() => { vi.restoreAllMocks(); useSessionStore.getState().clearSession() })

  it('saves the chosen header with the tab; the status line follows the saved value', async () => {
    const put = mockOtherSettings()
    mockStatus(status({}))
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    const panel = await screen.findByTestId('system-settings-baseline-other')
    const group = within(panel).getByRole('heading', { name: '访问与网络' }).closest('section')!
    const line = within(group).getByTestId('visitor-ip-status')
    expect(line.textContent).toBe('访客 IP 取自直连来源')
    fireEvent.mouseDown(within(group).getByRole('combobox', { name: '源IP请求头' }))
    fireEvent.click(await screen.findByText('CF-Connecting-IP'))
    // not saved yet: the line keeps the value in force
    expect(line.textContent).toBe('访客 IP 取自直连来源')
    fireEvent.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), 3, { ...otherValue, source_ip_header: 'CF-Connecting-IP' },
      expect.any(String), expect.any(String)))
    await waitFor(() => expect(within(group).getByTestId('visitor-ip-status').textContent).toBe('访客 IP 取自 CF-Connecting-IP'))
  })

  it('keeps the choice, the line and http代理 in Access and network, without the old CDN access steps or fields nothing reads', async () => {
    const put = mockOtherSettings()
    mockStatus(status({ visitor_ip_confirmed: true }))
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    const panel = await screen.findByTestId('system-settings-baseline-other')
    await within(panel).findByTestId('visitor-ip-settings')
    const summary = within(panel).getByRole('navigation', { name: '当前生效' })
    for (const label of removedLabels) {
      expect(within(panel).queryByText(label, { exact: false })).toBeNull()
      expect(summary.textContent).not.toContain(label)
    }
    expect(within(panel).getByRole('textbox', { name: 'http代理' })).toHaveValue('http://proxy.example:3128')
    expect(panel.textContent).not.toMatch(/install-control|origin-auth\.secret|以 root 执行/)
    expect(panel.querySelector('section#other-network ol')).toBeNull()
    fireEvent.click(within(panel).getByRole('switch', { name: '禁用同步失败的节点' }))
    fireEvent.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), 3, { ...otherValue, disable_failed_sync_nodes: true }, expect.any(String), expect.any(String)))
  })

  it('saves http代理 with the tab and reads it back after a refresh with the password masked', async () => {
    const mask = (value: PlatformSystemOtherSettings) => ({ ...value, http_proxy: value.http_proxy.replace(/:[^:@/]+@/, ':********@') })
    let stored: PlatformSystemOtherSettings = { ...otherValue, http_proxy: '' }
    let revision = 3
    const get = vi.spyOn(systemOtherSettingsApi, 'get').mockImplementation(async () =>
      ({ schema: 'cdnca.platform-system-other-settings/v1', revision, value: mask(stored) }))
    const put = vi.spyOn(systemOtherSettingsApi, 'put').mockImplementation(async (_token, _revision, next) => {
      stored = next
      revision += 1
      return { schema: 'cdnca.platform-system-other-settings/v1', revision, value: mask(stored) }
    })
    mockStatus(status({}))
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    const panel = await screen.findByTestId('system-settings-baseline-other')
    const group = within(panel).getByRole('heading', { name: '访问与网络' }).closest('section')!
    const proxy = () => within(group).getByRole('textbox', { name: 'http代理' })
    expect(proxy()).toHaveValue('')
    fireEvent.change(proxy(), { target: { value: 'http://ops:s3cret@10.0.0.8:3128' } })
    fireEvent.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), 3, { ...otherValue, http_proxy: 'http://ops:s3cret@10.0.0.8:3128' },
      expect.any(String), expect.any(String)))
    await waitFor(() => expect(proxy()).toHaveValue('http://ops:********@10.0.0.8:3128'))
    fireEvent.click(within(panel).getByRole('button', { name: /刷\s*新/ }))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(proxy()).toHaveValue('http://ops:********@10.0.0.8:3128'))
    expect(panel.innerHTML).not.toContain('s3cret')
  })

  async function expectFocusedSetting() {
    await waitFor(() => expect(globalThis.document.activeElement?.id).toBe('system-settings-originauth-title'), { timeout: 4000 })
    expect(globalThis.document.activeElement?.textContent).toBe('源IP请求头')
    expect(screen.getByRole('tab', { name: '其它配置' }).getAttribute('aria-selected')).toBe('true')
    expect(globalThis.document.activeElement?.closest('section#other-network')?.querySelector('h2')?.textContent).toBe('访问与网络')
  }

  it('opens from the home link in Other → Access and network with 源IP请求头 focused', async () => {
    mockOtherSettings()
    mockStatus(behindCDN)
    renderWithProviders(<Routes>
      <Route path="/" element={<ControlOriginAuthNotice />} />
      <Route path="/sys/setting" element={<SystemGlobalSettingsPage />} />
    </Routes>)
    fireEvent.click(within(await screen.findByTestId('control-origin-auth-home')).getByRole('link'))
    await expectFocusedSetting()
  })

  it('takes the old ?tab=system&section=originauth link to the same place', async () => {
    mockOtherSettings()
    mockStatus(behindCDN)
    renderWithProviders(<SystemGlobalSettingsPage />, ['/sys/setting?tab=system&section=originauth'])
    await expectFocusedSetting()
  })

  // （两宽实测）：切换开关未保存时，「当前生效」与卡头仍是读回的值，保存成功后才变。
  it('keeps 当前生效 and the card heads on the saved value until the change is saved', async () => {
    mockOtherSettings()
    mockStatus(status({ visitor_ip_confirmed: true }))
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    const panel = await screen.findByTestId('system-settings-baseline-other')
    const summary = within(panel).getByRole('navigation', { name: '当前生效' })
    const apiHead = () => within(panel).getByRole('heading', { name: 'API 与规则情报' }).parentElement!
    expect(summary.textContent).toContain('API 密钥已开启')
    fireEvent.click(within(panel).getByRole('switch', { name: '密钥状态' }))
    expect(summary.textContent).toContain('API 密钥已开启')
    expect(summary.textContent).not.toContain('API 密钥已关闭')
    expect(apiHead().textContent).toContain('已开启')
    fireEvent.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(summary.textContent).toContain('API 密钥已关闭'))
    expect(apiHead().textContent).toContain('已关闭')
  })
})
