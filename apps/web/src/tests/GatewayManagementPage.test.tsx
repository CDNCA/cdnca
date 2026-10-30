import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter } from 'react-router-dom'

import { AppRoutes } from '../App'
import { buildGatewayInstallCommand, type Gateway } from '../api/gateways'
import { useSessionStore } from '../auth/session'
import GatewayManagementPage from '../pages/GatewayManagementPage'
import { getBreadcrumbLabels, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const token = `gwt1.018f47a2-5b9c-7d31-8a60-104c9c0b717f.${'a'.repeat(32)}.${'B'.repeat(43)}`

function gateway(overrides: Partial<Gateway>): Gateway {
  return {
    id: '018f47a2-5b9c-7d31-8a60-104c9c0b717f', name: 'gw-hk-1', host: 'gw1.example.com', enrollment_port: null, agent_port: null,
    status: 'pending', version: '', created_at: '2026-10-22T01:00:00Z', bound_at: null, ready_at: null,
    client_certificate_expires_at: null, server_certificate_expires_at: null, ...overrides,
  }
}

function authenticate(permissions: string[]) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

const loadedETag = `"sha256-${'a'.repeat(64)}"`
const savedETag = `"sha256-${'b'.repeat(64)}"`

type Call = { method: string; path: string; body: unknown; ifMatch: string | null }

// The page only reads node_health.total; the other sections are unavailable.
function dashboard(nodes: number) {
  const off = { available: false, reason: 'dependency_unavailable' }
  return {
    dashboard_version: 2,
    meta: { range: 'seven_days', timezone: 'Asia/Shanghai', from: '2026-10-18T16:00:00Z', to: '2026-10-25T16:00:00Z',
      generated_at: '2026-10-25T02:00:00Z', snapshot_at: '2026-10-25T02:00:00Z', window_complete: false },
    accounts: off, subscriptions: off, billing: off, resources: off, operations: off, entitlement: off,
    node_health: { available: true, value: { total: nodes, online_fresh: nodes, stale_or_offline: 0, presence_missing: 0, freshness_cutoff_seconds: 45 } },
    analytics_health: off, account_security: off, network: off, analytics: off,
  }
}

function mockApi(items: Gateway[], open = true, nodes?: number) {
  const calls: Call[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input).replace(/^.*?(\/v1\/)/, '$1')
    const method = init?.method ?? 'GET'
    calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : null, ifMatch: new Headers(init?.headers).get('If-Match') })
    if (path.startsWith('/v1/admin/dashboard?') && nodes !== undefined) return json(dashboard(nodes))
    if (path === '/v1/admin/gateways' && method === 'GET') return json({ items, installation_id: 'x', standalone_access_open: open })
    if (path === '/v1/admin/gateways' && method === 'POST') {
      return json({ gateway: gateway({ name: 'gw-sg-1', host: 'gw2.example.com' }), binding_token: token, token_expires_at: '2026-10-22T02:00:00Z' }, 201)
    }
    if (path === '/v1/admin/gateway-settings' && method === 'GET') {
      return json({ trusted_proxies: [{ cidr: '173.245.48.0/20', header: 'CF-Connecting-IP' }], entrypoints: [] }, 200, { ETag: loadedETag })
    }
    if (path === '/v1/admin/gateway-settings' && method === 'PUT') return json(JSON.parse(String(init?.body)), 200, { ETag: savedETag })
    if (path.endsWith('/allowed-ips')) return json(JSON.parse(String(init?.body)))
    if (path.endsWith('/binding-token')) return json({ gateway: items[0], binding_token: token, token_expires_at: '2026-10-22T02:00:00Z' })
    if (/\/(disable|enable)$/.test(path) || method === 'DELETE') return new Response(null, { status: 204 })
    return json({}, 404)
  })
  return calls
}

beforeEach(() => {
  ;(window as { __CDNCA_LICENSING_SERVER__?: string }).__CDNCA_LICENSING_SERVER__ = 'https://license.example.com'
  Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
})

describe('Gateway management', () => {
  it('builds the one-command install with the token on stdin', () => {
    const command = buildGatewayInstallCommand(token, 'https://console.example.com', 'https://license.example.com', 'gw1.example.com')
    expect(command).toBe(`(f=$(mktemp) || exit 1; trap 'rc=$?; rm -f "$f"; exit $rc' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; { curl --proto '=https' --proto-redir '=https' -fsSL -o "$f" 'https://license.example.com/downloads/install-control.sh'; } || { rc=$?; echo '[cdnca-control] error: 无法下载安装脚本' >&2; exit $rc; }; { [ "$(head -c 2 "$f")" = '#!' ] && [ "$(tail -n 1 "$f")" = 'main "$@"' ]; } || { echo '[cdnca-control] error: 下载的安装脚本为空或不完整' >&2; exit 1; }; printf '%s\\n' '${token}' | bash "$f" --mode gateway --control 'https://console.example.com' --gateway-host 'gw1.example.com' --gateway-token-file -)`)
    expect(() => buildGatewayInstallCommand('gwt1.bad', 'https://c.example.com', 'https://l.example.com', 'h')).toThrow()
    expect(() => buildGatewayInstallCommand(token, 'http://c.example.com', 'https://l.example.com', 'h')).toThrow()
  })

  it('is a system route gated by system.gateway.manage', () => {
    expect(isImplementedPath('admin', '/sys/gateways', ['system.gateway.manage'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/gateways', ['nodes.read'])).toBe(false)
    expect(getBreadcrumbLabels('admin', '/sys/gateways')).toEqual(['首页', '系统管理', '网关管理'])
  })

  it('adds a Gateway and shows the install command once; copy works', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([])
    renderWithProviders(<GatewayManagementPage />)
    expect(await screen.findByText('还没有独立网关。主控自带的本机网关不在此列表。')).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: '添加网关' }))
    const dialog = await screen.findByRole('dialog', { name: '添加网关' })
    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: ' gw-sg-1 ' } })
    fireEvent.change(within(dialog).getByLabelText('网关公网地址'), { target: { value: 'GW2.example.com' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '生成令牌' }))
    // jsdom serves http://localhost: no https control origin, so the page shows the
    // token alone with the manual hint (production consoles are https).
    expect(await screen.findByText(/本页面没有取到授权端地址/)).toBeInTheDocument()
    expect((screen.getByLabelText('绑定令牌') as HTMLTextAreaElement).value).toBe(token)
    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    vi.spyOn(window, 'location', 'get').mockReturnValue({ ...window.location, origin: 'https://console.example.com' } as Location)
    fireEvent.click(screen.getByRole('button', { name: '添加网关' }))
    const again = await screen.findByRole('dialog', { name: '添加网关' })
    fireEvent.change(within(again).getByLabelText('名称'), { target: { value: 'gw-sg-1' } })
    fireEvent.change(within(again).getByLabelText('网关公网地址'), { target: { value: 'gw2.example.com' } })
    fireEvent.click(within(again).getByRole('button', { name: '生成令牌' }))
    const command = await screen.findByLabelText('网关安装命令')
    expect((command as HTMLTextAreaElement).value).toContain("--mode gateway --control 'https://console.example.com' --gateway-host 'gw2.example.com'")
    expect((command as HTMLTextAreaElement).value).toContain(`printf '%s\\n' '${token}'`)
    expect(screen.getByText(/--server-cert <公网证书链> --server-key <私钥>/)).toBeInTheDocument()
    expect(calls.find((call) => call.method === 'POST')?.body).toEqual({ name: 'gw-sg-1', host: 'gw2.example.com' })
    fireEvent.click(screen.getByRole('button', { name: '复制命令' }))
    expect(await screen.findByRole('button', { name: '已复制' })).toBeInTheDocument()
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith((command as HTMLTextAreaElement).value)
    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '网关安装命令' })).toBeNull())
  })

  it('refuses an invalid form without calling the API', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([])
    renderWithProviders(<GatewayManagementPage />)
    fireEvent.click(await screen.findByRole('button', { name: '添加网关' }))
    const dialog = await screen.findByRole('dialog', { name: '添加网关' })
    fireEvent.change(within(dialog).getByLabelText('网关公网地址'), { target: { value: 'bad host/' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '生成令牌' }))
    expect(await within(dialog).findByText('请填写名称（1–64 个字符）')).toBeInTheDocument()
    expect(await within(dialog).findByText('请填写合法的域名或 IP')).toBeInTheDocument()
    expect(calls.filter((call) => call.method === 'POST')).toHaveLength(0)
  })

  it('reissues a token for a pending Gateway', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([gateway({})])
    renderWithProviders(<GatewayManagementPage />)
    expect(await screen.findByText('待绑定')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重发令牌' }))
    expect(await screen.findByLabelText('网关安装命令')).toBeInTheDocument()
    expect(calls.some((call) => call.method === 'POST' && call.path === '/v1/admin/gateways/018f47a2-5b9c-7d31-8a60-104c9c0b717f/binding-token')).toBe(true)
  })

  it('disables an online Gateway, enables a disabled one and deletes after confirmation', async () => {
    authenticate(['system.gateway.manage'])
    const online = gateway({ id: '11111111-1111-4111-8111-111111111111', name: 'gw-a', status: 'active', enrollment_port: 21443, agent_port: 21444,
      version: '1.0.35', bound_at: '2026-10-22T01:00:00Z', client_certificate_expires_at: '2026-11-21T01:00:00Z', server_certificate_expires_at: '2027-01-20T01:00:00Z' })
    const off = gateway({ id: '22222222-2222-4222-8222-222222222222', name: 'gw-b', status: 'disabled', enrollment_port: 22443, agent_port: 22444, bound_at: '2026-10-22T01:00:00Z' })
    const calls = mockApi([online, off])
    renderWithProviders(<GatewayManagementPage />)
    expect(await screen.findByText('在线')).toBeInTheDocument()
    expect(screen.getByText('21443 / 21444')).toBeInTheDocument()
    expect(screen.getByText('已停用')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '停用' }))
    fireEvent.click(await screen.findByRole('button', { name: '确定' }))
    await waitFor(() => expect(calls.some((call) => call.method === 'POST' && call.path.endsWith('/11111111-1111-4111-8111-111111111111/disable'))).toBe(true))

    fireEvent.click(screen.getByRole('button', { name: '启用' }))
    await waitFor(() => expect(calls.some((call) => call.method === 'POST' && call.path.endsWith('/22222222-2222-4222-8222-222222222222/enable'))).toBe(true))

    const row = screen.getByText('gw-b').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: '删除' }))
    const confirms = await screen.findAllByRole('button', { name: '确定' })
    fireEvent.click(confirms[confirms.length - 1])
    await waitFor(() => expect(calls.some((call) => call.method === 'DELETE' && call.path === '/v1/admin/gateways/22222222-2222-4222-8222-222222222222')).toBe(true))
  })

  it('closed access: no warning popup, a fixed local-Gateway note with the enable command, no "Add Gateway"', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([], false, 3)
    renderWithProviders(<GatewayManagementPage />)
    expect(await screen.findByText(/本主控当前使用主控自带的本机网关/)).toBeInTheDocument()
    expect(await screen.findByText(/现有 3 台节点都连在本机网关上/)).toBeInTheDocument()
    expect(screen.getByText(/独立网关是可选的/)).toBeInTheDocument()
    expect(screen.getByText(/还没有开启独立网关接入/)).toBeInTheDocument()
    const command = screen.getByLabelText('开启独立网关接入的命令') as HTMLTextAreaElement
    expect(command.value).toContain("'https://license.example.com/downloads/install-control.sh'")
    expect(command.value).toMatch(/bash "\$f" enable-gateway-access\)$/)
    expect(screen.queryByRole('button', { name: '添加网关' })).not.toBeInTheDocument()
    expect(screen.queryByText(/未开放独立网关接入/)).not.toBeInTheDocument()
    expect(screen.queryByRole('alert', { name: /警告|warning/i })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/ADR|9446|4223|6380|ControlInternal|--mode control/)
    fireEvent.click(screen.getByRole('button', { name: '复制命令' }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(command.value))
    fireEvent.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(calls.filter((call) => call.method === 'GET' && call.path === '/v1/admin/gateways')).toHaveLength(2))
  })

  it('open access: the note stays without the enable command and "Add Gateway" is shown', async () => {
    authenticate(['system.gateway.manage'])
    mockApi([], true, 7)
    renderWithProviders(<GatewayManagementPage />)
    expect(await screen.findByText(/现有 7 台节点都连在本机网关上/)).toBeInTheDocument()
    expect(screen.getByText(/独立网关是可选的/)).toBeInTheDocument()
    expect(screen.queryByLabelText('开启独立网关接入的命令')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加网关' })).toBeEnabled()
    expect(document.body.textContent).not.toMatch(/ADR/)
  })

  it('leaves the node count out when the dashboard is unavailable', async () => {
    authenticate(['system.gateway.manage'])
    mockApi([], false)
    renderWithProviders(<GatewayManagementPage />)
    expect(await screen.findByText(/本主控当前使用主控自带的本机网关/)).toBeInTheDocument()
    await waitFor(() => expect(vi.mocked(globalThis.fetch).mock.calls.some(([input]) => String(input).includes('/v1/admin/dashboard'))).toBe(true))
    expect(screen.queryByText(/台节点都连在本机网关上/)).not.toBeInTheDocument()
  })

  it('shows the error of a refused operation', async () => {
    authenticate(['system.gateway.manage'])
    mockApi([])
    vi.mocked(globalThis.fetch).mockImplementation(async (_input, init) => (init?.method === 'POST'
      ? json({ error: { code: 'gateway_name_taken', message: 'Conflict', request_id: 'r' } }, 409)
      : json({ items: [], installation_id: 'x', standalone_access_open: true })))
    renderWithProviders(<GatewayManagementPage />)
    fireEvent.click(await screen.findByRole('button', { name: '添加网关' }))
    const dialog = await screen.findByRole('dialog', { name: '添加网关' })
    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: 'dup' } })
    fireEvent.change(within(dialog).getByLabelText('网关公网地址'), { target: { value: 'gw.example.com' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '生成令牌' }))
    expect(await screen.findByText('名称已被其他网关使用')).toBeInTheDocument()
  })

  it('edits the allowed IPs of a bound Gateway and rejects ranges', async () => {
    authenticate(['system.gateway.manage'])
    const online = gateway({ id: '11111111-1111-4111-8111-111111111111', status: 'active', enrollment_port: 21443, agent_port: 21444,
      bound_at: '2026-10-22T01:00:00Z', source_ip: '198.51.100.1', allowed_ips: ['198.51.100.1'] })
    const calls = mockApi([online])
    renderWithProviders(<GatewayManagementPage />)
    const row = (await screen.findByText('gw-hk-1')).closest('tr') as HTMLElement
    expect(within(row).getByText('198.51.100.1')).toBeInTheDocument()
    fireEvent.click(within(row).getByRole('button', { name: '放行 IP' }))
    const dialog = await screen.findByRole('dialog', { name: '放行 IP' })
    expect(within(dialog).getByText(/默认是绑定时的来源地址 198.51.100.1/)).toBeInTheDocument()
    const input = within(dialog).getByLabelText('放行 IP（每行一个）')
    fireEvent.change(input, { target: { value: '10.0.0.0/8' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText(/请每行填写一个 IPv4 或 IPv6 地址/)).toBeInTheDocument()
    expect(calls.some((call) => call.path.endsWith('/allowed-ips'))).toBe(false)
    fireEvent.change(input, { target: { value: '198.51.100.1\n2001:db8::7\n' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(calls.find((call) => call.method === 'PUT' && call.path === '/v1/admin/gateways/11111111-1111-4111-8111-111111111111/allowed-ips')?.body)
      .toEqual({ allowed_ips: ['198.51.100.1', '2001:db8::7'] }))
  })

  it('saves trusted CDN ranges and extra entry points', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([])
    renderWithProviders(<GatewayManagementPage />)
    const proxies = await screen.findByLabelText('可信 CDN 回源 IP 段')
    await waitFor(() => expect((proxies as HTMLTextAreaElement).value).toBe('173.245.48.0/20=CF-Connecting-IP'))
    expect(screen.getByText(/只预置了 Cloudflare/)).toBeInTheDocument()
    const entrypoints = screen.getByLabelText('额外节点入口')
    fireEvent.change(entrypoints, { target: { value: 'cdn.example.com:443 gw.example.com grpc cdn.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    expect(await screen.findByText(/节点入口格式不对/)).toBeInTheDocument()
    expect(calls.some((call) => call.method === 'PUT')).toBe(false)
    fireEvent.change(proxies, { target: { value: '173.245.48.0/20=CF-Connecting-IP\n10.0.0.0/8' } })
    fireEvent.change(entrypoints, { target: { value: 'cdn.example.com:443 gw.example.com ws cdn.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    const dialog = await screen.findByRole('dialog', { name: '确认保存并下发？' })
    expect(calls.some((call) => call.method === 'PUT')).toBe(false)
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '确认保存并下发？' })).not.toBeInTheDocument())
    expect(calls.some((call) => call.method === 'PUT')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    fireEvent.click(within(await screen.findByRole('dialog', { name: '确认保存并下发？' })).getByRole('button', { name: '确认下发' }))
    await waitFor(() => expect(calls.find((call) => call.method === 'PUT' && call.path === '/v1/admin/gateway-settings')?.body).toEqual({
      trusted_proxies: [{ cidr: '173.245.48.0/20', header: 'CF-Connecting-IP' }, { cidr: '10.0.0.0/8', header: '' }],
      entrypoints: [{ address: 'cdn.example.com:443', server_name: 'gw.example.com', transport: 'ws', tunnel_host: 'cdn.example.com' }],
    }))
    expect(calls.find((call) => call.method === 'PUT')?.ifMatch).toBe(loadedETag)
    expect(await screen.findByText('已保存，网关 1 分钟内生效')).toBeInTheDocument()
  })

  it('G1: a save refused because someone else saved reloads their settings instead of overwriting them', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([])
    let current = { trusted_proxies: [{ cidr: '173.245.48.0/20', header: 'CF-Connecting-IP' }], entrypoints: [] as unknown[] }
    const base = vi.mocked(globalThis.fetch).getMockImplementation()!
    vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
      if (String(input).endsWith('/v1/admin/gateway-settings')) {
        calls.push({ method: init?.method ?? 'GET', path: '/v1/admin/gateway-settings', body: null, ifMatch: new Headers(init?.headers).get('If-Match') })
        if (init?.method === 'PUT') {
          // Another administrator saved in between.
          current = { trusted_proxies: [{ cidr: '10.0.0.0/8', header: 'X-Real-Ip' }], entrypoints: [] }
          return json({ error: { code: 'gateway_settings_changed', message: 'Conflict', request_id: 'r' } }, 409)
        }
        return json(current, 200, { ETag: current.trusted_proxies[0].cidr === '10.0.0.0/8' ? savedETag : loadedETag })
      }
      return base(input, init)
    })
    renderWithProviders(<GatewayManagementPage />)
    const proxies = await screen.findByLabelText('可信 CDN 回源 IP 段')
    await waitFor(() => expect((proxies as HTMLTextAreaElement).value).toBe('173.245.48.0/20=CF-Connecting-IP'))
    fireEvent.change(proxies, { target: { value: '192.0.2.0/24' } })
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    fireEvent.click(within(await screen.findByRole('dialog', { name: '确认保存并下发？' })).getByRole('button', { name: '确认下发' }))
    expect(await screen.findByText(/设置已被他人修改，未保存/)).toBeInTheDocument()
    await waitFor(() => expect((proxies as HTMLTextAreaElement).value).toBe('10.0.0.0/8=X-Real-Ip'))
    expect(calls.find((call) => call.method === 'PUT')?.ifMatch).toBe(loadedETag)
    expect(calls.filter((call) => call.method === 'GET' && call.path === '/v1/admin/gateway-settings').length).toBeGreaterThanOrEqual(2)
  })

  it('card 8: a draft keeps the ETag it was edited on even after a background refetch brings a newer one', async () => {
    authenticate(['system.gateway.manage'])
    const calls = mockApi([])
    let etag = loadedETag
    const base = vi.mocked(globalThis.fetch).getMockImplementation()!
    vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
      if (String(input).endsWith('/v1/admin/gateway-settings')) {
        calls.push({ method: init?.method ?? 'GET', path: '/v1/admin/gateway-settings', body: null, ifMatch: new Headers(init?.headers).get('If-Match') })
        if (init?.method === 'PUT') return json({ error: { code: 'gateway_settings_changed', message: 'Conflict', request_id: 'r' } }, 409)
        return json({ trusted_proxies: [{ cidr: '173.245.48.0/20', header: 'CF-Connecting-IP' }], entrypoints: [] }, 200, { ETag: etag })
      }
      return base(input, init)
    })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
    render(<CdncaProvider><QueryClientProvider client={client}><MemoryRouter><GatewayManagementPage /></MemoryRouter></QueryClientProvider></CdncaProvider>)
    const proxies = await screen.findByLabelText('可信 CDN 回源 IP 段')
    await waitFor(() => expect((proxies as HTMLTextAreaElement).value).toBe('173.245.48.0/20=CF-Connecting-IP'))
    fireEvent.change(proxies, { target: { value: '192.0.2.0/24' } })
    // Another administrator saved; the page refetches (focus, invalidation) while this draft is open.
    etag = savedETag
    await act(async () => { await client.refetchQueries({ queryKey: ['gateway-settings'] }) })
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    fireEvent.click(within(await screen.findByRole('dialog', { name: '确认保存并下发？' })).getByRole('button', { name: '确认下发' }))
    await waitFor(() => expect(calls.find((call) => call.method === 'PUT')?.ifMatch).toBe(loadedETag))
  })

  it('G2: a failed load shows only the error with a retry, not the empty state', async () => {
    authenticate(['system.gateway.manage'])
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input).replace(/^.*?(\/v1\/)/, '$1')
      if (path === '/v1/admin/gateways') return fail ? json({ error: { code: 'internal_error', message: 'x', request_id: 'r' } }, 500) : json({ items: [], installation_id: 'x', standalone_access_open: true })
      if (path === '/v1/admin/gateway-settings') return json({ error: { code: 'internal_error', message: 'x', request_id: 'r' } }, 500)
      return json({}, 404)
    })
    renderWithProviders(<GatewayManagementPage />)
    const listError = await screen.findByText('网关列表加载失败', { selector: '.data-state-error span' })
    expect(screen.queryByText('还没有独立网关。主控自带的本机网关不在此列表。')).not.toBeInTheDocument()
    expect(await screen.findByText('网关下发设置加载失败')).toBeInTheDocument()
    expect(screen.queryByLabelText('可信 CDN 回源 IP 段')).not.toBeInTheDocument()
    fail = false
    fireEvent.click(within(listError.closest('.data-state-error') as HTMLElement).getByRole('button', { name: '重试' }))
    expect(await screen.findByText('还没有独立网关。主控自带的本机网关不在此列表。')).toBeInTheDocument()
  })

  it('is forbidden without the permission', async () => {
    authenticate(['nodes.read'])
    renderWithProviders(<AppRoutes />, ['/sys/gateways'])
    expect(await screen.findByText('无权访问')).toBeInTheDocument()
  })
})
