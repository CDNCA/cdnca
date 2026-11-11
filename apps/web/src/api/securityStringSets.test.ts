import {
  createSecurityStringSet, deleteSecurityStringSet, getSecurityStringSet, listSecurityStringSetReferences,
  listSecurityStringSets, parseStringSetEntries, updateSecurityStringSet,
  type SecurityStringSet, type SecurityStringSetSummary,
} from './securityStringSets'

const setID = '0190a000-0000-7000-8000-0000000000c7'
const summary: SecurityStringSetSummary = {
  id: setID, name: '爬虫 UA 特征', description: '', match_mode: 'contains', case_sensitive: false,
  entry_count: 2, reference_count: 1, revision: 3, platform: false, updated_at: '2026-11-10T06:00:00Z',
}
const full: SecurityStringSet = { ...summary, entries: ['bot', 'spider'] }

function respond(status: number, value: unknown) {
  return vi.fn().mockImplementation(async () => status === 204 ? new Response(null, { status })
    : new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

afterEach(() => vi.unstubAllGlobals())

describe('securityStringSets API', () => {
  it('lists tenant and admin sets and validates the summaries', async () => {
    const fetchMock = respond(200, { items: [summary] })
    vi.stubGlobal('fetch', fetchMock)
    await expect(listSecurityStringSets('token', 'tenant')).resolves.toEqual([summary])
    expect(String(fetchMock.mock.calls[0][0])).toBe('/v1/security-string-sets')
    await listSecurityStringSets('token', 'admin')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/v1/admin/security-string-sets')
    vi.stubGlobal('fetch', respond(200, { items: [{ ...summary, match_mode: 'regex' }] }))
    await expect(listSecurityStringSets('token', 'tenant')).rejects.toMatchObject({ code: 'invalid_response' })
    vi.stubGlobal('fetch', respond(200, { items: [{ ...summary, reference_count: -1 }] }))
    await expect(listSecurityStringSets('token', 'tenant')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('reads one set with its entries', async () => {
    vi.stubGlobal('fetch', respond(200, full))
    await expect(getSecurityStringSet('token', 'tenant', setID)).resolves.toEqual(full)
    vi.stubGlobal('fetch', respond(200, summary))
    await expect(getSecurityStringSet('token', 'tenant', setID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('creates with an idempotency key and updates without the fixed fields', async () => {
    const fetchMock = respond(201, full)
    vi.stubGlobal('fetch', fetchMock)
    const input = { name: full.name, description: '', match_mode: 'contains' as const, case_sensitive: false, entries: full.entries }
    await createSecurityStringSet('token', 'tenant', input)
    const [, created] = fetchMock.mock.calls[0]
    expect(created.method).toBe('POST')
    expect(created.headers['Idempotency-Key']).toMatch(/^security-string-set-/)
    expect(JSON.parse(created.body)).toEqual(input)
    await updateSecurityStringSet('token', 'tenant', full, { name: 'x', description: 'd', entries: ['a'] })
    const [url, updated] = fetchMock.mock.calls[1]
    expect(String(url)).toBe(`/v1/security-string-sets/${setID}`)
    expect(JSON.parse(updated.body)).toEqual({ expected_revision: 3, name: 'x', description: 'd', entries: ['a'] })
  })

  it('deletes with the revision and maps a set in use', async () => {
    const fetchMock = respond(204, null)
    vi.stubGlobal('fetch', fetchMock)
    await deleteSecurityStringSet('token', 'admin', full)
    expect(String(fetchMock.mock.calls[0][0])).toBe(`/v1/admin/security-string-sets/${setID}?expected_revision=3`)
    vi.stubGlobal('fetch', respond(409, { error: { code: 'string_set_in_use', request_id: 'r1' } }))
    await expect(deleteSecurityStringSet('token', 'tenant', full)).rejects.toMatchObject({ status: 409, code: 'string_set_in_use', requestId: 'r1' })
  })

  it('lists references', async () => {
    const reference = { policy_id: '0190a000-0000-7000-8000-0000000000aa', policy_name: 'WAF', policy_kind: 'waf', rule_count: 2 }
    vi.stubGlobal('fetch', respond(200, { items: [reference] }))
    await expect(listSecurityStringSetReferences('token', 'tenant', setID)).resolves.toEqual([reference])
    vi.stubGlobal('fetch', respond(200, { items: [{ ...reference, rule_count: 0 }] }))
    await expect(listSecurityStringSetReferences('token', 'tenant', setID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('splits a textarea into entries by line only', () => {
    expect(parseStringSetEntries('bot\n  spider \n\n# not a comment, a, b\r\n')).toEqual(['bot', 'spider', '# not a comment, a, b'])
  })
})
