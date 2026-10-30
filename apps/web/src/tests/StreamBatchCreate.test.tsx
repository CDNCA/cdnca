import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { streamsApi } from '../api/streams'
import { useSessionStore } from '../auth/session'
import StreamListPage from '../pages/StreamListPage'
import { batchLines, originPoolFields } from '../pages/streamForm'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { stream } from './streamFixture'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const listResponse = () => json({ items: [stream], total: 1, page: 1, limit: 10 })

beforeEach(() => {
  const user = principal({ permissions: ['streams.read', 'streams.manage'] })
  useSessionStore.getState().setSession(authResponse(user), user)
})
afterEach(() => vi.restoreAllMocks())

describe('批量添加', () => {
  it('splits the forward data into trimmed non-empty lines', () => {
    expect(batchLines(' 88 99/udp|1.2.3.4|8080 \n\n77|8.8.8.8|80\r\n')).toEqual(['88 99/udp|1.2.3.4|8080', '77|8.8.8.8|80'])
  })

  it('posts the lines and 忽略错误 as one batch and lists the per-line result', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input).includes('/v1/streams/batch')) {
        return Promise.resolve(json({ committed: false, created: 0, failed: 1, items: [
          { line: 1, text: '88|1.2.3.4|8080', status: 'skipped' },
          { line: 2, text: '88|1.2.3.5|8080', status: 'failed', error: { code: 'stream_port_conflict' } },
        ] }, 422))
      }
      return Promise.resolve(init?.method ? json({}) : listResponse())
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    const data = within(dialog).getByLabelText('转发数据')
    expect(data.getAttribute('placeholder')).toContain('格式为：监听端口|IP|回源端口')
    expect(within(dialog).getByText('有转发添加出错时，不中断，继续添加下一条')).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('套餐订阅 ID')).toBeNull()
    await user.type(data, '88|1.2.3.4')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('第 1 行格式应为：监听端口|IP|回源端口')).toBeInTheDocument()
    await user.clear(data)
    await user.type(data, '88|1.2.3.4|8080{enter}88|1.2.3.5|8080')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/v1/streams/batch'))).toBe(true))
    const [, init] = fetchSpy.mock.calls.find(([input]) => String(input).includes('/v1/streams/batch'))!
    const body = JSON.parse(String(init?.body))
    expect(body).toEqual(expect.objectContaining({ lines: ['88|1.2.3.4|8080', '88|1.2.3.5|8080'], ignore_errors: false }))
    expect(body.template).not.toHaveProperty('package_subscription_id')
    expect(body.template).not.toHaveProperty('site_id')
    expect((init?.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^batch-create-streams/u)
    expect(await within(dialog).findByText('有转发添加出错，本批未添加任何转发')).toBeInTheDocument()
    expect(within(dialog).getByText('失败：监听端口已被占用')).toBeInTheDocument()
    expect(within(dialog).getByText('未添加')).toBeInTheDocument()
  })
})

describe('源站列表 / ACL / IPv6 回带', () => {
  it('keeps single-origin streams byte-identical and carries pools, ACLs and IPv6', () => {
    expect(originPoolFields(stream)).toEqual({})
    expect(originPoolFields({ ...stream, origins: [{ address: '192.0.2.1', weight: 2, down: false }, { address: '192.0.2.2', weight: 1, down: true }],
      listen_ipv6: true, acl: { default_action: 'deny', rules: [{ cidr: '10.0.0.0/8', action: 'allow' }] } })).toEqual({
      origins: [{ address: '192.0.2.1', weight: 2, down: false }, { address: '192.0.2.2', weight: 1, down: true }],
      listen_ipv6: true, acl: { default_action: 'deny', rules: [{ cidr: '10.0.0.0/8', action: 'allow' }] },
    })
  })

  it('sends 设置状态 with each item revision', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ id: stream.id, status: 'failed', error: { code: 'version_conflict' } }] }))
    const result = await streamsApi.batchAction('token', { action: 'set_status', admin_status: 'locked', items: [{ id: stream.id, expected_revision: 3 }] }, 'key-1')
    expect(result.items[0]!.error?.code).toBe('version_conflict')
    const [input, init] = fetchSpy.mock.calls[0]!
    expect(String(input)).toContain('/v1/streams/batch-action')
    expect(JSON.parse(String(init?.body))).toEqual({ action: 'set_status', admin_status: 'locked', items: [{ id: stream.id, expected_revision: 3 }] })
  })
})
