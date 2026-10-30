import { nodesApi, type NodeInventoryItem } from './nodes'
import { nodeManagementSettingsFixture } from '../test/fixtures'

const scope = '22222222-2222-4222-8222-222222222222'
const order = 'management_sort_desc' as const

function nodeOrderFixture(id: number, displayID: string, sort: number): NodeInventoryItem {
  return {
    id: `018f0000-0000-7000-8000-${String(id).padStart(12, '0')}`, display_id: displayID,
    name: `Edge ${id}`, description: '', region: '', admin_state: 'active',
    management_settings: { ...nodeManagementSettingsFixture(), sort }, revision: 1,
    created_at: '2026-10-10T10:00:00Z', updated_at: '2026-10-10T10:00:00Z',
    presence: { status: 'unknown', projection_freshness: 'never', lease_signal: 'unavailable' },
  }
}

describe('node descending inventory contract', function nodeOrderContractRegression() {
  const items = [nodeOrderFixture(1, '3', 999999), nodeOrderFixture(2, '9007199254740993', 100), nodeOrderFixture(3, '9007199254740992', 100)]
  const boundary = {
    version: 1, scope_id: scope, order, status: '', presence: '', search: '',
    last_sort: 100, last_display_id: '9007199254740992', last_id: items[2]!.id,
  }
  const cursor = (value: unknown) => `nso1.${btoa(JSON.stringify(value)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}`
  const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } })

  it('requests the additive mode and preserves descending numeric IDs above JS safe integer', async () => {
    const page = { order, items, next_cursor: cursor(boundary) }
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page))
    await expect(nodesApi.list('token', { order, limit: 3 })).resolves.toEqual(page)
    expect(new URL(String(fetch.mock.calls[0]![0]), 'https://test.invalid').searchParams.get('order')).toBe(order)
  })

  it.each([
    ['missing order', { items }], ['wrong order', { order: 'uuid_asc', items }],
    ['unknown top field', { order, items, total: 3 }],
    ['sort ascending', { order, items: [...items].reverse() }],
    ['equal sort numeric IDs ascending', { order, items: [items[0], items[2], items[1]] }],
    ['duplicate node', { order, items: [items[0], items[0]] }],
    ['duplicate display ID', { order, items: [items[0], { ...items[1], display_id: '3' }] }],
    ['overflow display ID', { order, items: [{ ...items[0], display_id: '9223372036854775808' }] }],
    ['legacy cursor', { order, items, next_cursor: items[2]!.id }],
    ['empty cursor', { order, items, next_cursor: '' }],
    ['malformed cursor', { order, items, next_cursor: 'nso1.?' }],
    ['wrong boundary', { order, items, next_cursor: cursor({ ...boundary, last_sort: 0 }) }],
    ['wrong display boundary', { order, items, next_cursor: cursor({ ...boundary, last_display_id: '9' }) }],
    ['wrong filter', { order, items, next_cursor: cursor({ ...boundary, status: 'disabled' }) }],
    ['wrong cursor version', { order, items, next_cursor: cursor({ ...boundary, version: 2 }) }],
    ['extra cursor field', { order, items, next_cursor: cursor({ ...boundary, ignored: true }) }],
    ['nil scope', { order, items, next_cursor: cursor({ ...boundary, scope_id: '00000000-0000-0000-0000-000000000000' }) }],
    ['empty page cursor', { order, items: [], next_cursor: cursor(boundary) }],
  ])('rejects %s without silently reverting to UUID order', async (_name, page) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page))
    await expect(nodesApi.list('token', { order, limit: 3 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('preserves the legacy UUID mode and rejects the new echo when not requested', async () => {
    const legacy = { items, next_cursor: items[2]!.id }
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(legacy)).mockResolvedValueOnce(json({ order, items }))
    await expect(nodesApi.list('token', { limit: 3 })).resolves.toEqual(legacy)
    expect(String(fetch.mock.calls[0]![0])).not.toContain('order=')
    await expect(nodesApi.list('token', { limit: 3 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('binds a continuation to its original filter and rejects repeated/backwards rows', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ order, items: [items[0]] }))
    await expect(nodesApi.list('token', { order, limit: 3, cursor: cursor(boundary) })).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
