import { siteGroupsApi } from './siteGroups'

const scopeID = '018cc251-f400-7def-8000-000000000050'
const groupID = '018cc251-f400-7def-8000-000000000060'
const group = {
  id: groupID,
  scope_id: scopeID,
  name: '默认分组',
  revision: 3,
  created_at: '2026-09-26T08:00:00Z',
  updated_at: '2026-09-26T08:01:00Z',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('site groups API', () => {
  it('reads real global display IDs and resolves one owner without leaking a scope override', async () => {
    const admin = { ...group, display_id: '12', remark: '备注', user_state: 'resolved', user: { id: groupID, display_id: '2', username: 'jason' } }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ items: [admin], total: 1, page: 1, limit: 10 }))
      .mockResolvedValueOnce(json({ ...group, display_id: '12', remark: '备注' }))
    await expect(siteGroupsApi.listAdmin('token')).resolves.toMatchObject({ items: [admin], limit: 10 })
    await expect(siteGroupsApi.get('token', scopeID, groupID)).resolves.toMatchObject({ display_id: '12', remark: '备注' })
    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual(['/v1/admin/site-groups?page=1&limit=10', `/v1/site-groups/${groupID}?scope_id=${scopeID}`])
  })

  it.each([
    { display_id: '' }, { remark: null }, { user_state: 'resolved', user: null },
    { user_state: 'missing', user: { id: groupID, display_id: '2', username: 'jason' } },
    { user_state: 'ambiguous', user: { id: groupID, display_id: '2', username: 'jason' } },
    { user_state: 'other', user: null },
  ])('rejects unproved global identity metadata %j', async (bad) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ ...group, display_id: '12', remark: '', user_state: 'missing', user: null, ...bad }], total: 1, page: 1, limit: 10 }))
    await expect(siteGroupsApi.listAdmin('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('binds exact GET and scoped list to their requested resource and scope', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ ...group, id: scopeID, display_id: '12', remark: '' }))
      .mockResolvedValueOnce(json({ items: [{ ...group, scope_id: groupID }], total: 1, page: 1, limit: 20 }))
    await expect(siteGroupsApi.get('token', scopeID, groupID)).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(siteGroupsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('preserves omitted remark for legacy calls and sends explicit empty to clear', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(group, 201)).mockResolvedValueOnce(json(group))
    await siteGroupsApi.create('token', scopeID, group.name, 'legacy-key')
    await siteGroupsApi.rename('token', group, group.name, 'clear-key', '')
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).not.toHaveProperty('remark')
    expect(JSON.parse(String(fetchSpy.mock.calls[1][1]?.body))).toEqual({ expected_revision: 3, name: group.name, remark: '' })
  })

  it('rejects a successful-looking wrong DELETE acknowledgement', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ok: true }))
    await expect(siteGroupsApi.remove('token', group, 'delete-key')).rejects.toMatchObject({ code: 'invalid_response' })
  })
  it('uses explicit scope and revision/idempotency preconditions', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [group], total: 1, page: 1, limit: 20 }))
      .mockResolvedValueOnce(json(group, 201))
      .mockResolvedValueOnce(json({ ...group, name: '边缘分组', revision: 4 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))

    await expect(siteGroupsApi.list('token', scopeID)).resolves.toMatchObject({ items: [group] })
    await siteGroupsApi.create('token', scopeID, '默认分组', 'create-key')
    await siteGroupsApi.rename('token', group, '边缘分组', 'rename-key')
    await siteGroupsApi.remove('token', group, 'delete-key')

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      `/v1/site-groups?scope_id=${scopeID}&page=1&limit=20`,
      '/v1/site-groups',
      `/v1/site-groups/${groupID}?scope_id=${scopeID}`,
      `/v1/site-groups/${groupID}?scope_id=${scopeID}`,
    ])
    expect(fetchSpy.mock.calls[1][1]?.headers).toEqual(expect.objectContaining({
      Authorization: 'Bearer token', 'Idempotency-Key': 'create-key',
    }))
    expect(fetchSpy.mock.calls[2][1]?.headers).toEqual(expect.objectContaining({
      Authorization: 'Bearer token', 'Idempotency-Key': 'rename-key', 'If-Match': '"3"',
    }))
    expect(fetchSpy.mock.calls[3][1]?.headers).toEqual(expect.objectContaining({
      Authorization: 'Bearer token', 'Idempotency-Key': 'delete-key', 'If-Match': '"3"',
    }))
  })

  it.each([
    ['missing item fields', { items: [{ ...group, revision: 0 }], total: 1, page: 1, limit: 20 }],
    ['unknown response fields are tolerated by the API envelope', { items: [{ ...group, extra: true }], total: 1, page: 1, limit: 20 }],
  ])('validates group responses: %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))
    if (_name === 'missing item fields') {
      await expect(siteGroupsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
    } else {
      await expect(siteGroupsApi.list('token', scopeID)).resolves.toMatchObject({ total: 1 })
    }
  })
})
