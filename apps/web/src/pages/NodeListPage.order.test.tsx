import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { authResponse, principal, nodeManagementSettingsFixture } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import NodeListPage from './NodeListPage'

describe('node list descending server pagination', function nodeOrderPageRegression() {
  const scope = '22222222-2222-4222-8222-222222222222'
  const order = 'management_sort_desc' as const
  const first: NodeInventoryItem = {
    id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'First edge', description: '', region: '',
    admin_state: 'active', management_settings: nodeManagementSettingsFixture(), revision: 1,
    created_at: '2026-10-10T10:00:00Z', updated_at: '2026-10-10T10:00:00Z',
    presence: { status: 'unknown', projection_freshness: 'never', lease_signal: 'unavailable' },
  }
  const second = { ...first, id: '018f0000-0000-7000-8000-000000000001', display_id: '1', name: 'Second edge' }
  const boundary = `nso1.${btoa(JSON.stringify({ version: 1, scope_id: scope, order, status: '', presence: '', search: '',
    last_sort: first.management_settings.sort, last_display_id: first.display_id, last_id: first.id,
  })).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}`

  beforeEach(() => {
    sessionStorage.clear()
    const admin = principal({ scope_kind: 'platform', scope_id: scope, tenant_id: null, roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage'] })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({ observed_at: '2026-10-10T10:00:00Z', items: [], not_reported_node_ids: [...ids] }))
  })

  it('requests explicit ordering, preserves the opaque next cursor, and resets it after saved sort readback', async () => {
    let writes = 0
    const saved = { ...second, revision: 2, management_settings: { ...second.management_settings, sort: 300 } }
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      let body: unknown
      if (init?.method === 'PATCH') { writes++; body = Object.fromEntries(Object.entries(saved).filter(([key]) => key !== 'presence')) }
      else if (url.pathname === `/v1/nodes/${second.id}`) body = saved
      else body = url.searchParams.has('cursor') ? { order, items: [writes ? saved : second] }
        : { order, items: [writes ? saved : first], ...(writes ? {} : { next_cursor: boundary }) }
      return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeListPage />)
    expect(await screen.findByRole('button', { name: first.name })).toBeInTheDocument()
    expect(new URL(String(fetch.mock.calls[0]![0]), 'https://test.invalid').searchParams.get('order')).toBe(order)
    await user.click(screen.getByRole('button', { name: '下一页' }))
    fireEvent.click(await screen.findByRole('button', { name: second.name }))
    const dialog = screen.getByRole('dialog')
    // rc-util's test-only IDs collide with the pagination tooltip title.
    expect(within(dialog).getByText('编辑节点')).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('排序'), { target: { value: '300' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toBe(1))
    await waitFor(() => {
      const listCalls = fetch.mock.calls.filter(([input]) => new URL(String(input), 'https://test.invalid').pathname === '/v1/nodes')
      expect(listCalls.some(([input]) => new URL(String(input), 'https://test.invalid').searchParams.get('cursor') === boundary)).toBe(true)
      expect(new URL(String(listCalls.at(-1)![0]), 'https://test.invalid').searchParams.has('cursor')).toBe(false)
    })
    expect(await screen.findByRole('button', { name: second.name })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
  })

  it('does not display an old Control response that ignored the requested order', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [first] })))
    renderWithProviders(<NodeListPage />)
    // 列表加载失败改为 FeedbackWhen 弹窗。
    expect(await screen.findByRole('dialog')).toHaveClass('cdnca-feedback-error')
    expect(screen.queryByRole('button', { name: first.name })).not.toBeInTheDocument()
  })
})
