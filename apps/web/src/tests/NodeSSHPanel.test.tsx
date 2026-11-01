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

  it('requires reading and confirming the host key before connecting', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [{ id: '55555555-5555-4555-8555-555555555555', name: 'edge-1',
      ipv4: '203.0.113.7', admin_state: 'active' } as NodeInventoryItem] })
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/ssh-endpoint')) return reply({ node_id: '55555555-5555-4555-8555-555555555555', node_name: 'edge-1', host: '203.0.113.7', saved: null })
      if (url.endsWith('/ssh-host-key')) return reply({ node_id: 'x', host: '203.0.113.7', port: 22, host_key_sha256: fingerprint, saved_host_key_matches: false })
      if (url.includes('controller-egress')) return reply({ controller_cidrs: [], configured: false, rollback_seconds: 300 })
      if (url.endsWith('/ssh-access')) return reply({ node_id: 'x', enabled: false, ssh_port: 22, controller_cidrs: [], allow_cidrs: [], revision: 0, state: '', failure_code: '' })
      return reply({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHPanel canManage canTerminal errorText={errorText} getAccessToken={() => 'token'} />)
    await user.click(screen.getByRole('combobox', { name: '节点' }))
    await user.click(await screen.findByText('edge-1（203.0.113.7）'))
    await user.type(screen.getByLabelText('SSH 密码'), 'pw')
    const connect = screen.getByRole('button', { name: '连接' })
    expect(connect).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '读取主机指纹' }))
    expect(await screen.findByText(fingerprint)).toBeInTheDocument()
    expect(connect).toBeDisabled()
    await user.click(screen.getByLabelText(/我已在节点上核对一致/))
    expect(connect).toBeEnabled()
    // Without a configured controller egress the switch cannot be turned on.
    await waitFor(() => expect(screen.getByRole('switch', { name: '仅允许主控 SSH 连接' })).toBeDisabled())
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
