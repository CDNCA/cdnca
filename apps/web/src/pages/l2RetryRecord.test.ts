import { clearL2Retry, l2RetryStorageKey, persistL2Retry, restoreL2Retry, type L2InventoryAttempt, type L2NodesAttempt } from './l2RetryRecord'

const owner = ['tenant', '22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111'] as const
const key = l2RetryStorageKey(owner, 'inventory')

function l2RetrySafetyFixture(): Extract<L2InventoryAttempt, { kind: 'config' }> {
  return { kind: 'config', id: null, input: { name: '配置', region: 'cn-east', remark: '', mode: 'cache', load_method: 'rr' },
    metadata: { requestId: 'l2-request-1', idempotencyKey: 'l2-key-1', expectedRevision: 0 } }
}

beforeEach(() => sessionStorage.clear())

describe('L2 retry record', () => {
  it('preserves an empty default region through exact unknown and readback records', function l2DefaultRetryRecord() {
    const request = l2RetrySafetyFixture()
    request.input.region = ''
    expect(persistL2Retry(owner, 'inventory', request, 'unknown')).toBe(true)
    expect(restoreL2Retry(owner, 'inventory').record).toMatchObject({ attempt: request, body: JSON.stringify(request), phase: 'unknown' })
    expect(persistL2Retry(owner, 'inventory', { ...request, input: { ...request.input, region: 'cn-east' } }, 'unknown')).toBe(false)
    expect(persistL2Retry(owner, 'inventory', request, 'readback')).toBe(true)
    expect(restoreL2Retry(owner, 'inventory').record?.attempt).toEqual(request)
    expect(clearL2Retry(owner, 'inventory', request)).toBe(true)
  })

  it.each([' ', '\u3000', '\t', '\n', 'x'.repeat(65), null, undefined, []])('rejects an invalid region without normalizing it: %j', (region) => {
    const request = l2RetrySafetyFixture()
    request.input.region = region as string
    expect(persistL2Retry(owner, 'inventory', request, 'unknown')).toBe(false)
    expect(sessionStorage.getItem(key)).toBeNull()
  })

  it('strictly round-trips each supported inventory and node write shape', () => {
    const node = '44444444-4444-4444-8444-444444444444'
    const metadata = { requestId: 'request-1', idempotencyKey: 'key-1', expectedRevision: 4 }
    const input = { condition_id: null, enabled: true, weight: 80, sort: 1 }
    const attempts: Array<[string, L2InventoryAttempt | L2NodesAttempt]> = [
      ['inventory', { kind: 'condition', id: null, input: { name: '条件', remark: '', rules: [{ field: 'host', operator: 'eq', value: 'example.test' }] }, metadata: { ...metadata, expectedRevision: 0 } }],
      ['inventory', { kind: 'delete', inventory: 'configuration', targets: [{ id: node, metadata }] }],
      ['inventory', { kind: 'delete', inventory: 'conditions', targets: [{ id: node, metadata }] }],
      [node, { kind: 'add', nodeIDs: [node], conditionID: null, metadata: { ...metadata, expectedRevision: 0 } }],
      [node, { kind: 'update', id: node, input, metadata }],
      [node, { kind: 'batchUpdate', targets: [{ id: node, input, metadata }] }],
      [node, { kind: 'delete', targets: [{ id: node, metadata }] }],
    ]
    for (const [resource, attempt] of attempts) {
      sessionStorage.clear()
      expect(persistL2Retry(owner, resource, attempt, 'unknown')).toBe(true)
      expect(restoreL2Retry(owner, resource).record?.attempt).toEqual(attempt)
    }
  })

  it('rejects malformed node fields, target duplicates and an oversized batch', () => {
    const resource = '44444444-4444-4444-8444-444444444444'
    const target = { id: resource, input: { condition_id: null, enabled: true, weight: 1, sort: 0 },
      metadata: { requestId: 'request-1', idempotencyKey: 'key-1', expectedRevision: 4 } }
    const attempts: L2NodesAttempt[] = [
      { kind: 'batchUpdate', targets: [target, target] },
      { kind: 'batchUpdate', targets: [{ ...target, input: { ...target.input, weight: 0 } }] },
      { kind: 'batchUpdate', targets: [{ ...target, input: { ...target.input, sort: 1000000 } }] },
      { kind: 'update', ...target, metadata: { ...target.metadata, expectedRevision: 0 } },
      { kind: 'add', nodeIDs: [resource, resource], conditionID: null, metadata: { ...target.metadata, expectedRevision: 0 } },
      { kind: 'add', nodeIDs: [resource], conditionID: 'not-a-uuid', metadata: { ...target.metadata, expectedRevision: 0 } },
    ]
    for (const attempt of attempts) expect(persistL2Retry(owner, resource, attempt, 'unknown')).toBe(false)
    const targets = Array.from({ length: 512 }, (_, index) => ({ ...target,
      id: `${String(index).padStart(8, '0')}-4444-4444-8444-444444444444`,
      metadata: { ...target.metadata, requestId: `request-${index}`, idempotencyKey: `key-${index}` } }))
    expect(persistL2Retry(owner, resource, { kind: 'batchUpdate', targets }, 'unknown')).toBe(true)
    sessionStorage.clear()
    expect(persistL2Retry(owner, resource, { kind: 'batchUpdate', targets: [...targets, target] }, 'unknown')).toBe(false)
    expect(sessionStorage.getItem(l2RetryStorageKey(owner, resource))).toBeNull()
  })

  it('preserves exact request bytes and only moves a matching record toward readback', () => {
    const request = l2RetrySafetyFixture()
    expect(restoreL2Retry(owner, 'inventory')).toEqual({ record: null, blocked: false })
    expect(persistL2Retry(owner, 'inventory', request, 'unknown')).toBe(true)
    expect(restoreL2Retry(owner, 'inventory').record).toMatchObject({ attempt: request, phase: 'unknown', body: JSON.stringify(request) })
    expect(persistL2Retry(owner, 'inventory', { ...request, metadata: { ...request.metadata, idempotencyKey: 'new' } }, 'unknown')).toBe(false)
    expect(persistL2Retry(owner, 'inventory', request, 'readback')).toBe(true)
    expect(persistL2Retry(owner, 'inventory', request, 'unknown')).toBe(false)
    expect(clearL2Retry(owner, 'inventory', request)).toBe(true)
  })

  it('isolates scope, user and resource and rejects copied owner records', () => {
    const request = l2RetrySafetyFixture()
    persistL2Retry(owner, 'inventory', request, 'unknown')
    const other = ['tenant', owner[1], '33333333-3333-4333-8333-333333333333'] as const
    expect(restoreL2Retry(other, 'inventory')).toEqual({ record: null, blocked: false })
    sessionStorage.setItem(l2RetryStorageKey(other, 'inventory'), sessionStorage.getItem(key)!)
    expect(restoreL2Retry(other, 'inventory')).toEqual({ record: null, blocked: true })
    expect(restoreL2Retry(owner, '44444444-4444-4444-8444-444444444444')).toEqual({ record: null, blocked: false })
  })

  it.each(['{', 'null', '{}', '[]', 'x'.repeat(512001)])('does not erase malformed or oversized records', (stored) => {
    sessionStorage.setItem(key, stored)
    expect(restoreL2Retry(owner, 'inventory')).toEqual({ record: null, blocked: true })
    expect(persistL2Retry(owner, 'inventory', l2RetrySafetyFixture(), 'unknown')).toBe(false)
    expect(sessionStorage.getItem(key)).toBe(stored)
  })

  it.each(['record', 'attempt', 'input', 'metadata'])('rejects secret or unknown fields at %s', (location) => {
    persistL2Retry(owner, 'inventory', l2RetrySafetyFixture(), 'unknown')
    const record = JSON.parse(sessionStorage.getItem(key)!)
    const target = location === 'record' ? record : location === 'attempt' ? record.attempt : record.attempt[location]
    target.accessToken = 'must-not-store'
    record.body = JSON.stringify(record.attempt)
    sessionStorage.setItem(key, JSON.stringify(record))
    expect(restoreL2Retry(owner, 'inventory')).toEqual({ record: null, blocked: true })
  })

  it('rejects altered bytes, unsafe keys, revisions and unsupported values', () => {
    for (const mutate of [
      (record: ReturnType<typeof JSON.parse>) => { record.body += ' ' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.metadata.idempotencyKey = 'bad\nheader' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.metadata.expectedRevision = -1 },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.input.mode = 'invented' },
    ]) {
      sessionStorage.clear()
      persistL2Retry(owner, 'inventory', l2RetrySafetyFixture(), 'unknown')
      const record = JSON.parse(sessionStorage.getItem(key)!)
      mutate(record)
      sessionStorage.setItem(key, JSON.stringify(record))
      expect(restoreL2Retry(owner, 'inventory')).toEqual({ record: null, blocked: true })
    }
  })

  it('fails closed when reads, writes, readback or removal are unavailable', () => {
    const request = l2RetrySafetyFixture()
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('read denied') })
    expect(restoreL2Retry(owner, 'inventory').blocked).toBe(true)
    get.mockRestore()
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    expect(persistL2Retry(owner, 'inventory', request, 'unknown')).toBe(false)
    set.mockImplementation(() => undefined)
    expect(persistL2Retry(owner, 'inventory', request, 'unknown')).toBe(false)
    set.mockRestore()
    expect(persistL2Retry(owner, 'inventory', request, 'readback')).toBe(true)
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => undefined)
    expect(clearL2Retry(owner, 'inventory', request)).toBe(false)
    expect(restoreL2Retry(owner, 'inventory').record?.phase).toBe('readback')
  })
})
