import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { nodeSSHTerminalApi, parseBatchLines, type SSHInstallJob } from '../api/nodeSSHInstall'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import NodeSSHPanel from '../pages/NodeSSHPanel'
import { renderWithProviders } from '../test/render'

const fingerprint = `SHA256:${'B'.repeat(43)}`

function job(overrides: Partial<SSHInstallJob>): SSHInstallJob {
  return {
    id: '11111111-1111-4111-8111-111111111111', batch_id: '22222222-2222-4222-8222-222222222222',
    host: '203.0.113.7', port: 22, username: 'root', auth_kind: 'password', node_name: '',
    host_key_sha256: fingerprint, host_key_confirmed: false, state: 'awaiting_host_key', failure_code: '',
    progress: [], node_id: null, attempts: 0, created_at: '2026-10-31T00:00:00Z', started_at: null, finished_at: null,
    ...overrides,
  }
}

function reply(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

const errorText = (error: ApiError) => error.code

describe('parseBatchLines', () => {
  it('reads "IP port user password" and "IP user password"; marks bad lines', () => {
    const lines = parseBatchLines([
      '# comment', '203.0.113.7 2222 root pass word', '203.0.113.8 deploy secret', '', 'bad-host_ root x',
      '203.0.113.9 99999 root x', '203.0.113.10 root', '203.0.113.8 22 root again', '2001:db8::1 root v6',
      '203.0.113.11 Root x',
    ].join('\n'))
    expect(lines.map((line) => line.error ?? 'ok')).toEqual(['ok', 'ok', 'host', 'port', 'columns', 'duplicate', 'ok', 'username'])
    expect(lines[0]).toMatchObject({ line: 2, target: { host: '203.0.113.7', port: 2222, username: 'root', password: 'pass word' } })
    expect(lines[1].target).toEqual({ host: '203.0.113.8', port: 22, username: 'deploy', password: 'secret' })
    expect(lines[6].target?.host).toBe('2001:db8::1')
    const many = parseBatchLines(Array.from({ length: 101 }, (_, index) => `198.51.100.${index} root x`).join('\n'))
    expect(many.at(-1)?.error).toBe('too_many')
  })
})

describe('NodeSSHPanel', () => {
  it('hides the terminal from non administrators and shows install sections', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => reply({ items: [] }))
    renderWithProviders(<NodeSSHPanel canManage canTerminal={false} errorText={errorText} getAccessToken={() => 'token'} />)
    const sections = screen.getByLabelText('SSH 功能')
    expect(within(sections).queryByText('SSH 终端')).toBeNull()
    expect(within(sections).getByText('单台安装')).toBeInTheDocument()
    expect(within(sections).getByText('批量安装')).toBeInTheDocument()
    expect(await screen.findByLabelText('服务器 IP 或域名')).toBeInTheDocument()
  })

  it('refuses to send a batch with invalid lines and sends per-host logins', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      if (init?.method === 'POST') return reply({ items: [job({}), job({ id: '33333333-3333-4333-8333-333333333333', host: '203.0.113.8', username: 'deploy' })] }, 201)
      return reply({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal={false} errorText={errorText} getAccessToken={() => 'token'} />)
    await user.click(screen.getByText('批量安装'))
    const box = screen.getByLabelText('服务器列表')
    await user.type(box, '203.0.113.7 2222 root a{enter}203.0.113.8 deploy b{enter}nope')
    expect(screen.getByText('共 2 台可安装，1 行有错误')).toBeInTheDocument()
    expect(screen.getByText('列数不对')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '开始安装 2 台' })).toBeDisabled()
    // Passwords are masked in the preview.
    expect(screen.queryByText('a', { selector: 'td' })).toBeNull()
    await user.type(box, '{backspace}{backspace}{backspace}{backspace}{backspace}')
    await user.click(screen.getByLabelText('仅允许主控 SSH 连接（装好后其他来源连不上 SSH 端口）'))
    await user.click(screen.getByRole('button', { name: '开始安装 2 台' }))
    expect(await screen.findAllByText(fingerprint)).toHaveLength(2)
    const post = calls.find((call) => call.init?.method === 'POST')!
    expect(JSON.parse(String(post.init?.body))).toEqual({ restrict_ssh: true, language: 'zh-CN', targets: [
      { host: '203.0.113.7', port: 2222, username: 'root', password: 'a' },
      { host: '203.0.113.8', port: 22, username: 'deploy', password: 'b' },
    ] })
    expect(box).toHaveValue('')
    expect(screen.getByRole('button', { name: '确认全部指纹并安装（2 台）' })).toBeInTheDocument()
  })

  it('retries one failed host inside its batch', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      const body = init?.body ? JSON.parse(String(init.body)) : null
      if (init?.method === 'POST' && body?.batch_id) return reply({ items: [job({ id: '44444444-4444-4444-8444-444444444444' })] }, 201)
      if (init?.method === 'POST') return reply({ items: [job({ state: 'failed', failure_code: 'ssh_auth_failed' })] }, 201)
      return reply({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal={false} errorText={errorText} getAccessToken={() => 'token'} />)
    await user.click(screen.getByText('批量安装'))
    await user.type(screen.getByLabelText('服务器列表'), '203.0.113.7 root wrong')
    await user.click(screen.getByRole('button', { name: '开始安装 1 台' }))
    await user.click(await screen.findByRole('button', { name: '重试' }))
    await user.type(screen.getByLabelText('重试 203.0.113.7:22（用户 root）：请重新输入密码'), 'right')
    await user.click(screen.getAllByRole('button', { name: '重试' }).at(-1)!)
    await waitFor(() => expect(calls.filter((call) => call.init?.method === 'POST')).toHaveLength(2))
    const retry = JSON.parse(String(calls.filter((call) => call.init?.method === 'POST')[1].init?.body))
    expect(retry).toEqual({ batch_id: '22222222-2222-4222-8222-222222222222', restrict_ssh: false,
      language: 'zh-CN', targets: [{ host: '203.0.113.7', port: 22, username: 'root', password: 'right' }] })
  })

  it('builds the terminal socket on the page origin without credentials in the URL', () => {
    const url = nodeSSHTerminalApi.socketURL('55555555-5555-4555-8555-555555555555', 'https://cdnca.com')
    expect(url).toBe('wss://cdnca.com/v1/nodes/55555555-5555-4555-8555-555555555555/ssh-terminal')
  })

  const node = { id: '55555555-5555-4555-8555-555555555555', name: 'edge-1', ipv4: '203.0.113.7', admin_state: 'active' } as NodeInventoryItem
  const terminalFetch = (options: { saved?: unknown; egress?: string[]; setAccess?: (body: Record<string, unknown>) => Promise<Response>; calls?: Array<{ url: string; init?: RequestInit }> } = {}) =>
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      options.calls?.push({ url, init })
      if (url.endsWith('/ssh-endpoint')) return reply({ node_id: node.id, node_name: 'edge-1', host: '203.0.113.7', saved: options.saved ?? null })
      if (url.endsWith('/ssh-credential') && init?.method === 'DELETE') return Promise.resolve(new Response(null, { status: 204 }))
      if (url.includes('controller-egress')) return reply({ controller_cidrs: options.egress ?? [], configured: (options.egress ?? []).length > 0, rollback_seconds: 300 })
      if (url.endsWith('/ssh-access') && init?.method === 'PUT') {
        const body = JSON.parse(String(init.body))
        return options.setAccess ? options.setAccess(body) : reply({ node_id: node.id, enabled: body.enabled, ssh_port: 22,
          controller_cidrs: body.allow_cidrs, allow_cidrs: body.allow_cidrs, revision: 1, state: 'pending', failure_code: '', supported: true })
      }
      if (url.endsWith('/ssh-access')) return reply({ node_id: node.id, enabled: false, ssh_port: 22, controller_cidrs: [], allow_cidrs: [], revision: 0, state: '', failure_code: '', supported: true })
      return reply({ items: [] })
    })

  // A WebSocket stand-in: records what the page sends and lets the test answer.
  class FakeSocket {
    static last: FakeSocket | null = null
    sent: string[] = []
    readyState = 0
    binaryType = ''
    onopen: (() => void) | null = null
    onmessage: ((event: { data: unknown }) => void) | null = null
    onclose: (() => void) | null = null
    onerror: (() => void) | null = null
    constructor(readonly url: string) { FakeSocket.last = this }
    send(value: string) { this.sent.push(value) }
    close() { this.readyState = 3 }
    open() { this.readyState = 1; this.onopen?.() }
    message(value: unknown) { this.onmessage?.({ data: JSON.stringify(value) }) }
  }

  async function chooseNode(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole('combobox', { name: '节点' }))
    await user.click(await screen.findByText('edge-1（203.0.113.7）'))
  }

  it('connects without reading the host key and remembers the login for next time', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    terminalFetch()
    vi.stubGlobal('WebSocket', Object.assign(FakeSocket, { OPEN: 1 }))
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal errorText={errorText} getAccessToken={() => 'token'} />)
    await chooseNode(user)
    // No host key button, fingerprint or "I compared it" checkbox any more.
    expect(screen.queryByRole('button', { name: /读取主机指纹/ })).toBeNull()
    expect(screen.queryByLabelText(/核对一致/)).toBeNull()
    await user.type(screen.getByLabelText('SSH 密码'), 'pw')
    await user.click(screen.getByLabelText('记住此登录（加密保存在主控，下次免输入）'))
    const connect = screen.getByRole('button', { name: '连接' })
    expect(connect).toBeEnabled()
    await user.click(connect)
    const socket = await waitFor(() => { expect(FakeSocket.last).not.toBeNull(); return FakeSocket.last! })
    expect(socket.url).toBe(`ws://localhost:3000/v1/nodes/${node.id}/ssh-terminal`.replace('localhost:3000', window.location.host))
    socket.open()
    const open = JSON.parse(socket.sent[0])
    expect(open).toMatchObject({ type: 'open', access_token: 'token', port: 22, username: 'root', password: 'pw', use_saved: false, remember: true })
    expect(open).not.toHaveProperty('host_key_sha256')
    socket.message({ type: 'opened', session_id: 's', host_key_sha256: fingerprint, remembered: true })
    expect(await screen.findByText('已记住此登录，下次选择该节点可直接连接。')).toBeInTheDocument()
    // The remembered login is now the selected way in: no password field.
    expect(screen.getByRole('radio', { name: '使用已记住的登录' })).toBeChecked()
    expect(screen.queryByLabelText('SSH 密码')).toBeNull()
    vi.unstubAllGlobals()
  })

  it('uses and forgets a remembered login', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const calls: Array<{ url: string; init?: RequestInit }> = []
    terminalFetch({ calls, saved: { port: 2222, username: 'deploy', auth_kind: 'password', host_key_sha256: fingerprint, updated_at: '2026-11-01T00:00:00Z' } })
    vi.stubGlobal('WebSocket', Object.assign(FakeSocket, { OPEN: 1 }))
    FakeSocket.last = null
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal errorText={errorText} getAccessToken={() => 'token'} />)
    await chooseNode(user)
    expect(await screen.findByText(/将以 deploy 登录端口 2222/)).toBeInTheDocument()
    expect(screen.queryByLabelText('SSH 密码')).toBeNull()
    await user.click(screen.getByRole('button', { name: '连接' }))
    const socket = await waitFor(() => { expect(FakeSocket.last).not.toBeNull(); return FakeSocket.last! })
    socket.open()
    expect(JSON.parse(socket.sent[0])).toMatchObject({ type: 'open', port: 2222, use_saved: true })
    expect(JSON.parse(socket.sent[0])).not.toHaveProperty('password')
    await user.click(screen.getByRole('button', { name: '断开' }))
    await user.click(screen.getByRole('button', { name: '忘记此登录' }))
    expect(await screen.findByText('已忘记此登录。')).toBeInTheDocument()
    expect(calls.some((call) => call.url.endsWith('/ssh-credential') && call.init?.method === 'DELETE')).toBe(true)
    expect(screen.getByLabelText('SSH 密码')).toBeInTheDocument()
    vi.unstubAllGlobals()
  })

  it('says the WebSocket handshake failed when it never opens', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    terminalFetch()
    vi.stubGlobal('WebSocket', Object.assign(FakeSocket, { OPEN: 1 }))
    FakeSocket.last = null
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal errorText={errorText} getAccessToken={() => 'token'} />)
    await chooseNode(user)
    await user.type(screen.getByLabelText('SSH 密码'), 'pw')
    await user.click(screen.getByRole('button', { name: '连接' }))
    const socket = await waitFor(() => { expect(FakeSocket.last).not.toBeNull(); return FakeSocket.last! })
    socket.onerror?.()
    socket.onclose?.()
    expect(await screen.findByText(/无法建立终端连接（WebSocket 被代理拒绝或网络中断）/)).toBeInTheDocument()
    expect(screen.queryByText('SSH 终端暂不可用')).toBeNull()
    vi.unstubAllGlobals()
  })

  it('turns controller-only SSH on before connecting, with the allowlist when no egress is known', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const calls: Array<{ url: string; init?: RequestInit }> = []
    terminalFetch({ calls })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal errorText={errorText} getAccessToken={() => 'token'} />)
    await chooseNode(user)
    const toggle = await screen.findByRole('switch', { name: '仅允许主控 SSH 连接' })
    // Unknown egress and an empty allowlist: says what to fill in, stays off.
    await waitFor(() => expect(toggle).toBeDisabled())
    expect(screen.getByText(/请在「额外允许的地址」里填主控出口 IP/)).toBeInTheDocument()
    await user.type(screen.getByLabelText('额外允许的地址（可选）'), '203.0.113.9')
    await waitFor(() => expect(toggle).toBeEnabled())
    // No terminal connection was opened for it.
    expect(screen.getByRole('button', { name: '连接' })).toBeEnabled()
    await user.click(toggle)
    await waitFor(() => expect(toggle).toBeChecked())
    const put = calls.find((call) => call.init?.method === 'PUT')!
    expect(JSON.parse(String(put.init?.body))).toEqual({ enabled: true, ssh_port: 22, allow_cidrs: ['203.0.113.9'] })
  })

  it('shows the controller egress refusal of the single install instead of a generic failure', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      if (init?.method === 'POST') return reply({ error: { code: 'controller_egress_unknown' } }, 409)
      return reply({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal={false} errorText={() => '请求失败，请稍后重试'} getAccessToken={() => 'token'} />)
    await user.type(await screen.findByLabelText('服务器 IP 或域名'), '203.0.113.7')
    await user.type(screen.getByLabelText('SSH 密码'), 'pw')
    await user.click(screen.getByLabelText('仅允许主控 SSH 连接该节点'))
    await user.type(screen.getByLabelText('额外允许的地址（可选）'), '198.51.100.4')
    await user.click(screen.getByRole('button', { name: '开始' }))
    expect(await screen.findByText(/未能取得主控出口 IP，不能开启「仅允许主控 SSH」/)).toBeInTheDocument()
    expect(screen.queryByText('请求失败，请稍后重试')).toBeNull()
    const post = calls.find((call) => call.init?.method === 'POST')!
    expect(JSON.parse(String(post.init?.body))).toMatchObject({ restrict_ssh: true, allow_cidrs: ['198.51.100.4'] })
  })

  it('says the node version does not support controller-only SSH', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [{ id: '55555555-5555-4555-8555-555555555555', name: 'edge-1',
      ipv4: '203.0.113.7', admin_state: 'active' } as NodeInventoryItem] })
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/ssh-endpoint')) return reply({ node_id: '55555555-5555-4555-8555-555555555555', node_name: 'edge-1', host: '203.0.113.7', saved: null })
      if (url.includes('controller-egress')) return reply({ controller_cidrs: ['192.0.2.10/32'], configured: true, rollback_seconds: 300 })
      if (url.endsWith('/ssh-access')) return reply({ node_id: 'x', enabled: false, ssh_port: 22, controller_cidrs: [], allow_cidrs: [],
        revision: 0, state: '', failure_code: '', supported: false })
      return reply({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal errorText={errorText} getAccessToken={() => 'token'} />)
    await user.click(screen.getByRole('combobox', { name: '节点' }))
    await user.click(await screen.findByText('edge-1（203.0.113.7）'))
    expect(await screen.findByText('节点版本不支持')).toBeInTheDocument()
    expect(screen.getByText(/请先升级节点/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '仅允许主控 SSH 连接' })).toBeDisabled()
  })
})
