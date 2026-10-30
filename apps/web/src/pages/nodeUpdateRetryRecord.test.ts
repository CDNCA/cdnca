import { nodeManagementSettingsFixture } from '../test/fixtures'
import { clearNodeUpdateRetry, nodeUpdateRetryStorageKey, persistNodeUpdateRetry, restoreNodeUpdateRetry, type NodeUpdateRequestAttempt } from './nodeUpdateRetryRecord'

const owner = ['platform', '22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111'] as const
const storageKey = nodeUpdateRetryStorageKey(owner)
function nodeUpdateFixture(): NodeUpdateRequestAttempt {
  return { item: { id: '33333333-3333-4333-8333-333333333333', revision: 4 }, key: 'node-update-1',
    input: { name: '节点 A', description: '', ipv4: '', ipv6: '', management_settings: nodeManagementSettingsFixture() } }
}
beforeEach(() => sessionStorage.clear())

describe('node update retry record', () => {
  it('retains exact body, key and revision and only moves the matching attempt to readback', () => {
    const attempt = nodeUpdateFixture()
    expect(persistNodeUpdateRetry(owner, attempt)).toMatchObject({ phase: 'unknown', confirmedRevision: null })
    expect(restoreNodeUpdateRetry(owner).record).toMatchObject({ attempt, body: JSON.stringify(attempt) })
    expect(persistNodeUpdateRetry(owner, { ...attempt, key: 'different' })).toBeNull()
    expect(persistNodeUpdateRetry(owner, { ...attempt, input: { description: 'different' } })).toBeNull()
    expect(persistNodeUpdateRetry(owner, attempt, 5)).toMatchObject({ phase: 'readback', confirmedRevision: 5 })
    expect(persistNodeUpdateRetry(owner, attempt)).toBeNull()
    expect(persistNodeUpdateRetry(owner, attempt, 6)).toBeNull()
    expect(clearNodeUpdateRetry(owner, { ...attempt, key: 'different' })).toBe(false)
    expect(clearNodeUpdateRetry(owner, attempt)).toBe(true)
    expect(restoreNodeUpdateRetry(owner)).toEqual({ record: null, blocked: false })
  })

  it.each(['active', 'draining', 'disabled', 'retired'] as const)('supports the existing single-node %s operation without new payload fields', (admin_state) => {
    const attempt = { ...nodeUpdateFixture(), input: { admin_state } }
    expect(persistNodeUpdateRetry(owner, attempt)?.attempt).toEqual(attempt)
  })

  it('preserves zero settings and valid IPv4-mapped IPv6 addresses', () => {
    const attempt = nodeUpdateFixture()
    attempt.input.ipv6 = '::ffff:192.0.2.10'
    attempt.input.management_settings!.sort = 0
    attempt.input.management_settings!.secondary_ips = ['::ffff:192.0.2.11']
    expect(persistNodeUpdateRetry(owner, attempt)?.attempt).toEqual(attempt)
  })

  it('isolates owners and refuses copied owner records', () => {
    persistNodeUpdateRetry(owner, nodeUpdateFixture())
    for (const other of [
      ['platform', owner[1], '44444444-4444-4444-8444-444444444444'],
      ['platform', '55555555-5555-4555-8555-555555555555', owner[2]],
    ] as const) {
      expect(restoreNodeUpdateRetry(other)).toEqual({ record: null, blocked: false })
      sessionStorage.setItem(nodeUpdateRetryStorageKey(other), sessionStorage.getItem(storageKey)!)
      expect(restoreNodeUpdateRetry(other)).toEqual({ record: null, blocked: true })
    }
    expect(nodeUpdateRetryStorageKey(['platform', '', owner[2]])).toBe('')
  })

  it.each(['{', '{}', 'null', '[]', 'x'.repeat(65537)])('preserves invalid stored data and fails closed: %#', (raw) => {
    sessionStorage.setItem(storageKey, raw)
    expect(restoreNodeUpdateRetry(owner)).toEqual({ record: null, blocked: true })
    expect(persistNodeUpdateRetry(owner, nodeUpdateFixture())).toBeNull()
    expect(clearNodeUpdateRetry(owner, nodeUpdateFixture())).toBe(false)
    expect(sessionStorage.getItem(storageKey)).toBe(raw)
  })

  it.each(['record', 'attempt', 'input', 'item', 'settings', 'location', 'policy'])('rejects unknown or secret fields at %s', (location) => {
    persistNodeUpdateRetry(owner, nodeUpdateFixture())
    const record = JSON.parse(sessionStorage.getItem(storageKey)!)
    const targets = { record, attempt: record.attempt, input: record.attempt.input, item: record.attempt.item,
      settings: record.attempt.input.management_settings, location: record.attempt.input.management_settings.ip_location,
      policy: record.attempt.input.management_settings.auto_disable }
    targets[location as keyof typeof targets].accessToken = 'must-not-store'
    record.body = JSON.stringify(record.attempt)
    sessionStorage.setItem(storageKey, JSON.stringify(record))
    expect(restoreNodeUpdateRetry(owner)).toEqual({ record: null, blocked: true })
  })

  it('rejects non-contract shapes, negative/fractional sort, unsafe headers and invalid acknowledgments', () => {
    for (const attempt of [
      { ...nodeUpdateFixture(), key: 'bad\nkey' },
      { ...nodeUpdateFixture(), item: { ...nodeUpdateFixture().item, revision: 0 } },
      { ...nodeUpdateFixture(), input: {} },
      { ...nodeUpdateFixture(), input: { ipv4: '2001:db8::1' } },
      { ...nodeUpdateFixture(), input: { ipv6: '192.0.2.1' } },
      ...[-1, 0.5, 1000000].map((sort) => ({ ...nodeUpdateFixture(), input: { management_settings: { ...nodeManagementSettingsFixture(), sort } } })),
    ]) expect(persistNodeUpdateRetry(owner, attempt)).toBeNull()
    expect(persistNodeUpdateRetry(owner, nodeUpdateFixture(), 4)).toBeNull()
    expect(persistNodeUpdateRetry(owner, nodeUpdateFixture(), NaN)).toBeNull()
  })

  it('fails closed for thrown and silent storage failures and never clears a different attempt', () => {
    const attempt = nodeUpdateFixture()
    const read = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('denied') })
    expect(restoreNodeUpdateRetry(owner).blocked).toBe(true)
    read.mockRestore()
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    expect(persistNodeUpdateRetry(owner, attempt)).toBeNull()
    write.mockImplementation(() => undefined)
    expect(persistNodeUpdateRetry(owner, attempt)).toBeNull()
    write.mockRestore()
    persistNodeUpdateRetry(owner, attempt, 5)
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => undefined)
    expect(clearNodeUpdateRetry(owner, attempt)).toBe(false)
    expect(restoreNodeUpdateRetry(owner).record?.phase).toBe('readback')
  })
})

describe('A17 record version', () => {
  it('writes v2 records and still restores legacy v1 records so they can be confirmed by replay', () => {
    const attempt = { ...nodeUpdateFixture(), input: { admin_state: 'retired' as const } }
    expect(persistNodeUpdateRetry(owner, attempt, 5)).toMatchObject({ version: 2, phase: 'readback' })
    sessionStorage.clear()
    sessionStorage.setItem(storageKey, JSON.stringify({ version: 1, owner, phase: 'readback', confirmedRevision: 5, attempt, body: JSON.stringify(attempt) }))
    expect(restoreNodeUpdateRetry(owner)).toMatchObject({ blocked: false, record: { version: 1, phase: 'readback' } })
    sessionStorage.setItem(storageKey, JSON.stringify({ version: 3, owner, phase: 'readback', confirmedRevision: 5, attempt, body: JSON.stringify(attempt) }))
    expect(restoreNodeUpdateRetry(owner)).toEqual({ record: null, blocked: true })
  })
})
