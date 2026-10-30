import { StrictMode } from 'react'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { RegionRecord } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import NodeListPage from '../pages/NodeListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const region: RegionRecord = {
  id: '1',
  name: '默认',
  code: 'default',
  country_code: '',
  province_code: '',
  description: '默认区域',
  l2_check_port: 80,
  sort: 100,
  revision: 1,
  created_at: '2026-09-15T08:01:42Z',
  updated_at: '2026-09-15T08:01:42Z',
}

function authenticate(permissions: string[]) {
  const admin = principal({
    scope_kind: 'platform',
    // 节点编辑恢复记录按 [platform, scope UUID, user UUID] 存储；非 UUID 的作用域会被视为存储不可用而锁定编辑。
    scope_id: '99999999-9999-4999-8999-999999999999',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_owner'],
    permissions,
  })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'region-access-token' }, admin)
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

async function openRegions(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText('暂无节点')
  await user.click(screen.getByRole('tab', { name: '区域管理' }))
}

describe('NodeRegionManagement', () => {
  it('settles the region query after the StrictMode setup-cleanup cycle', async () => {
    authenticate(['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(
      String(input).startsWith('/v1/regions') ? json({ count: 0, data: [] }) : json({ items: [] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<StrictMode><NodeListPage /></StrictMode>, ['/node/list'])
    await openRegions(user)

    expect(await screen.findByText('暂无区域')).toBeInTheDocument()
    expect(screen.getByText('暂无区域').closest('.node-table-scroll--regions')).toHaveAttribute('aria-busy', 'false')
  })

  it('renders the observed table and editor against the real region list contract', async () => {
    authenticate(['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(
      String(input).startsWith('/v1/regions') ? json({ count: 1, data: [region] }) : json({ items: [] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />, ['/node/list'])
    await openRegions(user)

    expect(await screen.findByText('默认区域')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith('/v1/regions?page=1&page_size=10', expect.objectContaining({
      credentials: 'include', headers: expect.objectContaining({ Authorization: 'Bearer region-access-token' }),
    }))
    for (const heading of ['ID', '名称', '备注', '排序', '添加时间', '操作']) {
      expect(screen.getByRole('columnheader', { name: heading })).toBeInTheDocument()
    }
    const row = screen.getByText('默认区域').closest('tr')!
    expect(within(row).getByText('1')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '编辑' })).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '删除' })).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '每页节点数' }).closest('.ant-select')).toHaveTextContent('10 条/页')

    await user.click(screen.getByRole('button', { name: '新增区域' }))
    const dialog = await screen.findByRole('dialog', { name: '新增区域' })
    expect(within(dialog).getByPlaceholderText('请输入区域名称')).toBeInTheDocument()
    expect(within(dialog).getByPlaceholderText('请输入备注')).toBeInTheDocument()
    expect(within(dialog).getByRole('spinbutton', { name: 'L2检查端口' })).toHaveValue('80')
    expect(within(dialog).getByRole('spinbutton', { name: '排序' })).toHaveValue('100')
    expect(within(dialog).getByText('该端口用于在L1边缘节点检查L2节点是否在线')).toBeInTheDocument()
    expect(dialog.querySelector('.node-region-warning')).toHaveTextContent(
      '注意：建议所有节点归属在同一个区域，因为不同区域的节点无法共享使用，除非某些节点是客户单独定制购买的。',
    )
    const footerButtons = [...dialog.querySelectorAll('.ant-modal-footer button')].map((button) => button.textContent)
    expect(footerButtons).toEqual(['取消', '确定'])
  })

  it('creates, edits and deletes a region with revision and idempotency headers', async () => {
    authenticate(['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'])
    let rows = [region]
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.startsWith('/v1/nodes')) return Promise.resolve(json({ items: [] }))
      if (url.startsWith('/v1/regions?')) return Promise.resolve(json({ count: rows.length, data: rows }))
      if (url === '/v1/regions' && method === 'POST') {
        const body = JSON.parse(String(init?.body))
        const created = { ...region, ...body, id: '2', name: body.name, revision: 1 }
        rows = [...rows, created]
        return Promise.resolve(json(created, 201))
      }
      if (url === '/v1/regions/2' && method === 'PATCH') {
        const body = JSON.parse(String(init?.body))
        const updated = { ...rows[1]!, ...body, revision: 2, updated_at: '2026-09-15T09:00:00Z' }
        rows = [rows[0]!, updated]
        return Promise.resolve(json(updated))
      }
      if (url === '/v1/regions/2' && method === 'DELETE') {
        rows = rows.filter((item) => item.id !== '2')
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      throw new Error(`unexpected request ${method} ${url}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />, ['/node/list'])
    await openRegions(user)
    await screen.findByText('默认区域')

    await user.click(screen.getByRole('button', { name: '新增区域' }))
    const createDialog = await screen.findByRole('dialog', { name: '新增区域' })
    await user.type(within(createDialog).getByPlaceholderText('请输入区域名称'), '华南')
    await user.type(within(createDialog).getByPlaceholderText('请输入备注'), '华南节点')
    // 省份只在选了中国后可选
    expect(within(createDialog).getByRole('combobox', { name: '省份' })).toBeDisabled()
    await user.click(within(createDialog).getByRole('combobox', { name: '国家/地区' }))
    await user.type(within(createDialog).getByRole('combobox', { name: '国家/地区' }), 'CN')
    await user.click(await screen.findByTitle('中国 (CN)'))
    await user.click(within(createDialog).getByRole('combobox', { name: '省份' }))
    await user.type(within(createDialog).getByRole('combobox', { name: '省份' }), '广东')
    await user.click(await screen.findByTitle('广东 (440000)'))
    await user.click(within(createDialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('华南节点')).toBeInTheDocument()
    expect(screen.getByText('中国 / 广东')).toBeInTheDocument()

    const createCall = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/regions' && init?.method === 'POST')!
    expect(createCall[1]).toMatchObject({
      body: JSON.stringify({ name: '华南', country_code: 'CN', province_code: '440000', description: '华南节点', l2_check_port: 80, sort: 100 }),
      headers: expect.objectContaining({ 'Idempotency-Key': expect.stringMatching(/^create-region-/) }),
    })

    let southRow = screen.getByText('华南节点').closest('tr')!
    await user.click(within(southRow).getByRole('button', { name: '编辑' }))
    const editDialog = await screen.findByRole('dialog', { name: '编辑区域' })
    const nameInput = within(editDialog).getByPlaceholderText('请输入区域名称')
    await user.clear(nameInput)
    await user.type(nameInput, '华南专线')
    await user.click(within(editDialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('华南专线')).toBeInTheDocument()

    const updateCall = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/regions/2' && init?.method === 'PATCH')!
    expect(updateCall[1]?.headers).toEqual(expect.objectContaining({
      'If-Match': '"1"', 'Idempotency-Key': expect.stringMatching(/^update-region-2-/),
    }))

    southRow = screen.getByText('华南专线').closest('tr')!
    await user.click(within(southRow).getByRole('button', { name: '删除' }))
    const confirm = await screen.findByRole('dialog', { name: '是否删除区域 id:2' })
    await user.click(within(confirm).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(screen.queryByText('华南专线')).not.toBeInTheDocument())
    const deleteCall = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/regions/2' && init?.method === 'DELETE')!
    expect(deleteCall[1]?.headers).toEqual(expect.objectContaining({
      'If-Match': '"2"', 'Idempotency-Key': expect.stringMatching(/^delete-region-2-/),
    }))
  })

  it('retries an unknown create with the exact same body and idempotency key', async () => {
    authenticate(['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'])
    let created: RegionRecord | null = null
    let createAttempts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/nodes')) return Promise.resolve(json({ items: [] }))
      if (url.startsWith('/v1/regions?')) return Promise.resolve(json({ count: created ? 1 : 0, data: created ? [created] : [] }))
      if (url === '/v1/regions' && init?.method === 'POST') {
        createAttempts++
        if (createAttempts === 1) return Promise.reject(new TypeError('connection reset'))
        const body = JSON.parse(String(init.body))
        created = { ...region, ...body, id: '3', revision: 1 }
        return Promise.resolve(json(created, 201))
      }
      throw new Error(`unexpected request ${url}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />, ['/node/list'])
    await openRegions(user)
    await screen.findByText('暂无区域')
    await user.click(screen.getByRole('button', { name: '新增区域' }))
    const dialog = await screen.findByRole('dialog', { name: '新增区域' })
    await user.type(within(dialog).getByPlaceholderText('请输入区域名称'), '华北')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('区域操作结果未知', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const firstCall = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/regions' && init?.method === 'POST')!
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('华北')).toBeInTheDocument()
    const createCalls = fetchSpy.mock.calls.filter(([url, init]) => String(url) === '/v1/regions' && init?.method === 'POST')
    expect(createCalls).toHaveLength(2)
    expect(createCalls[1]?.[1]?.body).toBe(firstCall[1]?.body)
    expect((createCalls[1]?.[1]?.headers as Record<string, string>)['Idempotency-Key'])
      .toBe((firstCall[1]?.headers as Record<string, string>)['Idempotency-Key'])
  })

  it('refreshes on a revision conflict and never displays the server message', async () => {
    authenticate(['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'])
    let listReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/nodes')) return Promise.resolve(json({ items: [] }))
      if (url.startsWith('/v1/regions?')) {
        listReads++
        return Promise.resolve(json({ count: 1, data: [{ ...region, revision: listReads > 1 ? 2 : 1 }] }))
      }
      if (url === '/v1/regions/1' && init?.method === 'PATCH') return Promise.resolve(json({
        error: { code: 'regions_revision_conflict', message: 'private database revision', request_id: 'request-1' },
      }, 412))
      throw new Error(`unexpected request ${url}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />, ['/node/list'])
    await openRegions(user)
    const row = (await screen.findByText('默认区域')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑区域' })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    const conflictAlert = await waitFor(() => { const node = document.querySelector<HTMLElement>('.cdnca-feedback-error'); expect(node).not.toBeNull(); return node! })
    // fix-feedbackui: a server sentence keeps its first clause as the title, the rest goes to the body.
    expect(conflictAlert.querySelector('.cdnca-feedback-title')).toHaveTextContent('区域已被其他操作修改')
    expect(conflictAlert.querySelector('.cdnca-feedback-detail')).toHaveTextContent('列表已刷新')
    expect(conflictAlert).toHaveTextContent('请求 ID：request-1')
    expect(conflictAlert).not.toHaveTextContent('private database revision')
    await waitFor(() => expect(listReads).toBeGreaterThan(1))
    expect(fetchSpy).toHaveBeenCalledWith('/v1/regions?page=1&page_size=10', expect.anything())
  })

  it('keeps region permissions independent from node permissions', async () => {
    authenticate(['nodes.read', 'nodes.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()
    const view = renderWithProviders(<NodeListPage />, ['/node/list'])

    await openRegions(user)
    expect(await screen.findByText('无权查看区域管理')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith('/v1/regions'))).toBe(false)

    view.unmount()
    authenticate(['nodes.read', 'regions.read'])
    vi.mocked(globalThis.fetch).mockImplementation((input) => Promise.resolve(
      String(input).startsWith('/v1/regions') ? json({ count: 1, data: [region] }) : json({ items: [] }),
    ))
    renderWithProviders(<NodeListPage />, ['/node/list'])
    await openRegions(user)
    expect(await screen.findByText('默认区域')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增区域' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
  })
})
