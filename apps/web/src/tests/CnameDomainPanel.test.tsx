import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import NodeDnsPage from '../pages/NodeDnsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 在 jsdom 下所有弹窗共用 aria-labelledby="test-id"，常驻的反馈弹窗（useFeedback/OutcomeUnknown）
// 挂在前面时会抢走其他弹窗的可访问名；按可见标题找当前可见的弹窗/抽屉。
const dialogsNamed = (name: string | RegExp) => screen.queryAllByRole('dialog').filter((node) => {
  const title = node.querySelector('.ant-modal-title, .ant-modal-confirm-title, .ant-drawer-title')?.textContent?.trim() ?? ''
  return typeof name === 'string' ? title === name : name.test(title)
})
const queryDialog = (name: string | RegExp) => {
  const found = dialogsNamed(name)
  if (found.length > 1) throw new Error(`multiple dialogs named ${String(name)}`)
  return found[0] ?? null
}
const getDialog = (name: string | RegExp) => {
  const found = queryDialog(name)
  if (!found) throw new Error(`no dialog named ${String(name)}`)
  return found
}
const findDialog = (name: string | RegExp, options?: { timeout?: number }) => waitFor(() => getDialog(name), options)

const at = '2026-10-14T00:00:00Z'
const zone = (displayID: number, name: string, remark = '', inUse = false, random = false) => ({
  id: `00000000-0000-4000-8000-00000000000${displayID}`, display_id: displayID, name, remark, in_use: inUse,
  random_allocation: random, version: 1, created_at: at, updated_at: at,
})
const json = (body: unknown, status = 200) => Promise.resolve(body === null ? new Response(null, { status })
  : new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

function authenticate(permissions = ['dns.read', 'dns.manage']) {
  const actor = principal({ scope_kind: 'platform', scope_id: '11111111-1111-4111-8111-111111111111', tenant_id: undefined, permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function mockAPI(state: { zones: ReturnType<typeof zone>[] }) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = new URL(String(input), 'https://test.invalid')
    const method = init?.method ?? 'GET'
    if (url.pathname === '/v1/dns/platform-config') {
      return json({ identifiers: {}, secret_saved: false, ttl: 600, ip_weight: false, weight_supported: false, version: 1,
        sync: { tenants: 0 }, last_error: null })
    }
    if (url.pathname === '/v1/dns/platform-zones' && method === 'POST') {
      const body = JSON.parse(String(init!.body))
      const created = zone(state.zones.length + 1, body.name, body.remark, false, body.random_allocation === true)
      state.zones.push(created)
      return json(created, 201)
    }
    if (url.pathname === '/v1/dns/platform-zones') {
      const search = url.searchParams.get('search') ?? ''
      const page = Number(url.searchParams.get('page')), limit = Number(url.searchParams.get('limit'))
      const matched = state.zones.filter((item) => item.name.includes(search))
      return json({ items: matched.slice((page - 1) * limit, page * limit), total: matched.length })
    }
    const id = url.pathname.split('/').pop()
    const target = state.zones.find((item) => item.id === id)
    if (target && method === 'PATCH') {
      Object.assign(target, JSON.parse(String(init!.body)), { version: target.version + 1 })
      return json(target)
    }
    if (target && method === 'DELETE') {
      if (target.in_use) return json({ error: { code: 'dns_zone_in_use', message: 'in use' } }, 409)
      state.zones = state.zones.filter((item) => item !== target)
      return json(null, 204)
    }
    return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
  })
}

afterEach(() => { vi.restoreAllMocks() })

async function openCnameTab() {
  const user = userEvent.setup()
  renderWithProviders(<NodeDnsPage />, ['/node/dns'])
  await user.click(await screen.findByRole('tab', { name: 'CNAME域名' }))
  return user
}

describe('节点管理 DNS配置 CNAME域名 tab', () => {
  it('lists domains with the reference columns and pagination text', async () => {
    authenticate()
    mockAPI({ zones: [zone(1, 'example.com')] })
    await openCnameTab()
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    const headers = screen.getAllByRole('columnheader').map((header) => header.textContent)
    expect(headers.slice(1)).toEqual(['ID', '域名', '备注', '参与随机分配', '操作'])
    // fix-cnamerand: the rule is explained above the list.
    expect(screen.getByText('新网站会在勾选的域名中随机分配一个；未勾选任何域名时使用默认 CNAME 域名。')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
    expect(screen.getByText('10 条/页')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新增域名/ })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('输入域名搜索')).toBeInTheDocument()
  })

  it('adds and edits a domain through the 新增域名 / 编辑域名 dialogs', async () => {
    authenticate()
    const state = { zones: [zone(1, 'example.com')] }
    const fetchMock = mockAPI(state)
    const user = await openCnameTab()
    await user.click(await screen.findByRole('button', { name: /新增域名/ }))
    let dialog = await findDialog('新增域名')
    expect(within(dialog).getByText('域名：')).toBeInTheDocument()
    expect(Array.from(dialog.querySelectorAll('.ant-modal-footer .ant-btn')).map((button) => button.textContent?.replace(/\s/g, '')))
      .toEqual(['取消', '确定'])
    await user.type(within(dialog).getByPlaceholderText('请输入域名'), 'bad domain')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    // C04：格式错误显示在字段下并聚焦该输入框，不叠第二层弹窗；改输入后错误消失。
    expect(await within(dialog).findByText('请输入正确的域名')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /知\s*道\s*了/ })).not.toBeInTheDocument()
    expect(within(dialog).getByPlaceholderText('请输入域名')).toHaveFocus()
    expect(within(dialog).getByPlaceholderText('请输入域名')).toHaveAttribute('aria-invalid', 'true')
    await user.clear(within(dialog).getByPlaceholderText('请输入域名'))
    await waitFor(() => expect(within(dialog).queryByText('请输入正确的域名')).not.toBeInTheDocument())
    await user.type(within(dialog).getByPlaceholderText('请输入域名'), 'CDN2.Example.com')
    await user.type(within(dialog).getByPlaceholderText('请输入备注'), '备用')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(await screen.findByText('cdn2.example.com', undefined, { timeout: 5000 })).toBeInTheDocument()
    const create = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(JSON.parse(String(create[1]!.body))).toEqual({ name: 'cdn2.example.com', remark: '备用', random_allocation: false })
    const row = screen.getByText('cdn2.example.com').closest('tr')!
    await user.click(within(row).getByText('编辑'))
    dialog = await findDialog('编辑域名')
    expect(within(dialog).getByPlaceholderText('请输入域名')).toHaveValue('cdn2.example.com')
    await user.clear(within(dialog).getByPlaceholderText('请输入备注'))
    await user.type(within(dialog).getByPlaceholderText('请输入备注'), '新备注')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(await screen.findByText('新备注', undefined, { timeout: 5000 })).toBeInTheDocument()
    const patch = fetchMock.mock.calls.find(([, init]) => init?.method === 'PATCH')!
    expect(new Headers(patch[1]!.headers).get('If-Match')).toBe('"1"')
  })

  it('a late reply of a save does not close the editor opened after it (NET-UX-3 #69)', async () => {
    authenticate()
    const state = { zones: [zone(1, 'example.com')] }
    const fetchMock = mockAPI(state)
    let release!: () => void
    const held = new Promise<void>((resolve) => { release = resolve })
    const passThrough = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (input, init) => {
      if (init?.method === 'POST') await held
      return passThrough(input, init)
    })
    const user = await openCnameTab()
    await user.click(await screen.findByRole('button', { name: /新增域名/ }))
    let dialog = await findDialog('新增域名')
    await user.type(within(dialog).getByPlaceholderText('请输入域名'), 'slow.example.com')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    // The save is pending: close it and open 编辑域名 on another row.
    await user.click(within(dialog).getByRole('button', { name: /取\s*消/ }))
    await user.click(within(screen.getByText('example.com').closest('tr')!).getByText('编辑'))
    dialog = await findDialog('编辑域名')
    release()
    expect(await screen.findByText('slow.example.com', undefined, { timeout: 5000 })).toBeInTheDocument()
    // The 编辑域名 editor opened afterwards stays open with its own values.
    await new Promise((resolve) => setTimeout(resolve, 50))
    const editor = getDialog('编辑域名')
    expect(editor.closest('.ant-modal-wrap')).not.toHaveStyle({ display: 'none' })
    expect(within(editor).getByPlaceholderText('请输入域名')).toHaveValue('example.com')
  })

  it('batch deletes selected domains and explains domains still used by sites', async () => {
    authenticate()
    const state = { zones: [zone(1, 'used.example.com', '', true), zone(2, 'spare.example.com')] }
    const fetchMock = mockAPI(state)
    const user = await openCnameTab()
    expect(await screen.findByText('spare.example.com')).toBeInTheDocument()
    const deleteButton = screen.getByRole('button', { name: /删\s*除/ })
    expect(deleteButton).toHaveClass('ant-btn-default', 'ant-btn-dangerous')
    expect(deleteButton).not.toHaveClass('ant-btn-primary')
    await user.click(deleteButton)
    // fix-feedbackui2: an in-place warning under the toolbar, not a dialog.
    expect(await screen.findByText('请先选择要删除的域名', { selector: '.cdnca-inline-notice-warning .cdnca-inline-notice-text' })).toBeInTheDocument()
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    for (const name of ['used.example.com', 'spare.example.com']) {
      await user.click(within(screen.getByText(name).closest('tr')!).getByRole('checkbox'))
    }
    await user.click(screen.getByRole('button', { name: /删\s*除/ }))
    // 未选择时的警告弹窗仍挂着（标题也含「删除」），按确认框精确标题找。
    const dialog = await findDialog('删除')
    expect(dialog).toHaveTextContent('确定删除选中的 2 个域名吗？')
    expect(dialog).toHaveTextContent('used.example.com')
    expect(dialog).toHaveTextContent('spare.example.com')
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(await screen.findByText(/used.example.com：该域名下还有网站在使用，不能删除或改名/)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('spare.example.com')).not.toBeInTheDocument())
    expect(state.zones.map((item) => item.name)).toEqual(['used.example.com'])
  })

  it('searches by domain', async () => {
    authenticate()
    mockAPI({ zones: [zone(1, 'alpha.example.com'), zone(2, 'beta.example.com')] })
    const user = await openCnameTab()
    expect(await screen.findByText('alpha.example.com')).toBeInTheDocument()
    await user.type(screen.getByPlaceholderText('输入域名搜索'), 'beta{Enter}')
    await waitFor(() => expect(screen.queryByText('alpha.example.com')).not.toBeInTheDocument())
    expect(screen.getByText('beta.example.com')).toBeInTheDocument()
  })

  it('marks a domain for random allocation from the list and keeps it when editing (fix-cnamerand)', async () => {
    authenticate()
    const state = { zones: [zone(1, 'a.example.com'), zone(2, 'b.example.com', '', false, true)] }
    const fetchMock = mockAPI(state)
    const user = await openCnameTab()
    const rowA = (await screen.findByText('a.example.com')).closest('tr')!
    const switchA = within(rowA).getByRole('switch', { name: 'a.example.com 参与随机分配' })
    expect(switchA).not.toBeChecked()
    expect(within(screen.getByText('b.example.com').closest('tr')!).getByRole('switch')).toBeChecked()
    await user.click(switchA)
    await waitFor(() => expect(state.zones[0].random_allocation).toBe(true))
    const patch = fetchMock.mock.calls.find(([, init]) => init?.method === 'PATCH')!
    expect(JSON.parse(String(patch[1]!.body))).toEqual({ name: 'a.example.com', remark: '', random_allocation: true })
    expect(new Headers(patch[1]!.headers).get('If-Match')).toBe('"1"')
    await waitFor(() => expect(within(screen.getByText('a.example.com').closest('tr')!).getByRole('switch')).toBeChecked())
    // The edit dialog shows the mark and sends it back unchanged.
    await user.click(within(screen.getByText('b.example.com').closest('tr')!).getByText('编辑'))
    const dialog = await findDialog('编辑域名')
    expect(within(dialog).getByRole('switch', { name: '参与随机分配' })).toBeChecked()
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(2))
    const second = fetchMock.mock.calls.filter(([, init]) => init?.method === 'PATCH')[1]
    expect(JSON.parse(String(second[1]!.body))).toEqual({ name: 'b.example.com', remark: '', random_allocation: true })
  })

  it('cannot toggle random allocation without dns.manage', async () => {
    authenticate(['dns.read'])
    mockAPI({ zones: [zone(1, 'a.example.com')] })
    await openCnameTab()
    const row = (await screen.findByText('a.example.com')).closest('tr')!
    expect(within(row).getByRole('switch')).toBeDisabled()
  })
})
