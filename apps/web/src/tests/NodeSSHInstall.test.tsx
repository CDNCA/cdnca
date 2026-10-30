import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { parseHosts, type SSHInstallJob } from '../api/nodeSSHInstall'
import NodeSSHInstall from '../pages/NodeSSHInstall'
import { renderWithProviders } from '../test/render'

const fingerprint = `SHA256:${'A'.repeat(43)}`

function job(overrides: Partial<SSHInstallJob>): SSHInstallJob {
  return {
    id: '11111111-1111-4111-8111-111111111111', batch_id: '22222222-2222-4222-8222-222222222222',
    host: '203.0.113.7', port: 22, username: 'root', auth_kind: 'password', node_name: '',
    host_key_sha256: fingerprint, host_key_confirmed: false, state: 'awaiting_host_key', failure_code: '',
    progress: [], node_id: null, attempts: 0, created_at: '2026-10-18T00:00:00Z', started_at: null, finished_at: null,
    ...overrides,
  }
}

function reply(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

describe('NodeSSHInstall', () => {
  it('parses pasted host lists', () => {
    expect(parseHosts(' 203.0.113.7\n203.0.113.8, 203.0.113.7  edge.example.net，198.51.100.1 ')).toEqual([
      '203.0.113.7', '203.0.113.8', 'edge.example.net', '198.51.100.1'])
    expect(parseHosts(Array.from({ length: 150 }, (_, index) => `198.51.100.${index}`).join('\n'))).toHaveLength(101)
  })

  it('creates a batch, shows the host key and confirms it; the password is not kept', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      if (String(input).endsWith('/confirm-host-key')) return reply(job({ state: 'pending', host_key_confirmed: true }))
      if (init?.method === 'POST') return reply({ items: [job({}), job({ id: '33333333-3333-4333-8333-333333333333', host: '203.0.113.8' })] }, 201)
      return reply({ items: [job({ state: 'running', progress: ['[cdnca-edge] preflight passed'] })] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
    await user.type(screen.getByLabelText('服务器 IP 或域名'), '203.0.113.7\n203.0.113.8')
    await user.type(screen.getByLabelText('SSH 密码'), 'root-secret')
    await user.click(screen.getByRole('button', { name: '开始' }))
    expect(await screen.findAllByText(fingerprint)).toHaveLength(2)
    const post = calls.find((call) => call.init?.method === 'POST')!
    const created = JSON.parse(String(post.init?.body))
    expect(post.url).toBe('/v1/admin/nodes/ssh-installs')
    expect(created).toEqual({ hosts: ['203.0.113.7', '203.0.113.8'], port: 22, username: 'root', password: 'root-secret' })
    expect(screen.getByLabelText('SSH 密码')).toHaveValue('')
    await user.click(screen.getAllByRole('button', { name: '确认指纹并安装' })[0])
    await waitFor(() => expect(screen.getByText('排队中')).toBeInTheDocument())
    const confirm = calls.find((call) => call.url.endsWith('/confirm-host-key'))
    expect(JSON.parse(String(confirm?.init?.body))).toEqual({ host_key_sha256: fingerprint })
  })

  it('shows a readable failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      reply({ items: [job({ state: 'failed', failure_code: 'ssh_auth_failed', host_key_sha256: fingerprint })] }, 201))
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
    await user.type(screen.getByLabelText('服务器 IP 或域名'), '203.0.113.7')
    await user.type(screen.getByLabelText('SSH 密码'), 'x')
    await user.click(screen.getByRole('button', { name: '开始' }))
    expect(await screen.findByText('SSH 登录失败（用户名、密码或私钥错误）')).toBeInTheDocument()
  })

  it('shows an installed node waiting for its first ticket as installed, not failed', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      reply({ items: [job({ state: 'succeeded', failure_code: 'installed_pending_ticket', host_key_confirmed: true })] }, 201))
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
    await user.type(screen.getByLabelText('服务器 IP 或域名'), '203.0.113.7')
    await user.type(screen.getByLabelText('SSH 密码'), 'x')
    await user.click(screen.getByRole('button', { name: '开始' }))
    expect(await screen.findByText('已安装、待首票')).toBeInTheDocument()
    // INSTALL-P2-02：已初始化但凭据未生效时先指向凭据列与授权连接，不再无条件要求去初始化。
    expect(screen.getByText(/已安装、等待授权凭据生效：请在节点上查看 journalctl -u cdnca-edge-agent/)).toBeInTheDocument()
    expect(screen.queryByText('失败')).not.toBeInTheDocument()
    expect(screen.queryByText('已完成')).not.toBeInTheDocument()
  })

  it.each([
    ['installed_pending_initialization', '已安装、待初始化', /请到「节点列表 → 待初始化」初始化该节点/],
    ['installed_banned', '已安装、已被封禁', /本主控安装已被授权方停用/],
    ['installed_ticket_expired', '已安装、凭据已过期', /授权签名凭据已过期/],
    ['installed_resume_failed', '已安装、恢复服务失败', /凭据已生效，但节点恢复对外服务失败/],
  ])('shows %s as its own installed state with the cause, not failed', async (code, label, cause) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      reply({ items: [job({ state: 'succeeded', failure_code: code, host_key_confirmed: true })] }, 201))
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
    await user.type(screen.getByLabelText('服务器 IP 或域名'), '203.0.113.7')
    await user.type(screen.getByLabelText('SSH 密码'), 'x')
    await user.click(screen.getByRole('button', { name: '开始' }))
    expect(await screen.findByText(label)).toBeInTheDocument()
    expect(screen.getByText(cause)).toBeInTheDocument()
    expect(screen.queryByText('失败')).not.toBeInTheDocument()
    expect(screen.queryByText('已完成')).not.toBeInTheDocument()
    expect(screen.queryByText(/安装脚本执行失败/)).not.toBeInTheDocument()
  })

  it('brings back jobs started before the dialog was closed (NET-08)', async () => {
    const calls: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push(`${init?.method ?? 'GET'} ${String(input)}`)
      return reply({ items: [job({ state: 'running', progress: ['[cdnca-edge] downloading'] })] })
    })
    renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
    expect(await screen.findByText('安装中')).toBeInTheDocument()
    expect(screen.getByText('downloading')).toBeInTheDocument()
    expect(screen.getByText(/下表为最近的安装任务（含关闭弹窗前提交的），状态更新于/)).toBeInTheDocument()
    expect(calls[0]).toBe('GET /v1/admin/nodes/ssh-installs')
  })

  it('says a status read failed and keeps the last rows; a 403 drops them', async () => {
    let status = 200
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => status === 200
      ? reply({ items: [job({ state: 'running' })] })
      : reply({ error: { code: status === 403 ? 'forbidden' : 'internal_error', message: 'x' } }, status))
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
      expect(await screen.findByText('安装中')).toBeInTheDocument()
      status = 500
      await vi.advanceTimersByTimeAsync(3100)
      expect(await screen.findByText(/安装任务状态更新失败：internal_error/)).toBeInTheDocument()
      expect(screen.getByText('安装中')).toBeInTheDocument()
      status = 403
      await vi.advanceTimersByTimeAsync(3100)
      expect(await screen.findByText(/安装任务状态更新失败：forbidden/)).toBeInTheDocument()
      await waitFor(() => expect(screen.queryByText('安装中')).not.toBeInTheDocument())
    } finally {
      vi.useRealTimers()
    }
  })

  it('sends one confirm per click while the request is pending', async () => {
    let confirms = 0
    let release: (() => void) | undefined
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      if (String(input).endsWith('/confirm-host-key')) {
        confirms += 1
        return new Promise<Response>((resolve) => { release = () => void reply(job({ state: 'pending', host_key_confirmed: true })).then(resolve) })
      }
      return reply({ items: [job({})] })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeSSHInstall getAccessToken={() => 'token'} errorText={(error: ApiError) => error.code} />)
    const confirm = await screen.findByRole('button', { name: '确认指纹并安装' })
    await user.click(confirm)
    await user.click(confirm)
    expect(confirms).toBe(1)
    release?.()
    expect(await screen.findByText('排队中')).toBeInTheDocument()
  })
})
