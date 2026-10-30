import {
  clearLineResolutionRetry, lineResolutionRetryStorageKey, persistLineResolutionRetry, restoreLineResolutionRetry,
  type LineResolutionAttempt,
} from './lineResolutionRetryRecord'

const scopeID = '22222222-2222-4222-8222-222222222222'
const userID = '11111111-1111-4111-8111-111111111111'
const resource = '33333333-3333-4333-8333-333333333333'
const owner = ['tenant', scopeID, userID] as const
const key = lineResolutionRetryStorageKey(owner, scopeID, resource)
const accepted = { revision: 8, configurationDigest: 'b'.repeat(64) }

function lineResolutionRetryFixture(): LineResolutionAttempt {
  return { input: { name: '线路', region: 'cn-east', resolved_value: 'line', ipv4_resolved_value: '',
    l2_config_id: null, failover_mode: 'primary_offline', note: '', sort_order: 100,
    health_policy: { probe_interval_ms: 10000, probe_timeout_ms: 3000, failure_threshold: 3,
      recovery_threshold: 3, failure_debounce_ms: 0, recovery_debounce_ms: 0 },
    endpoints: [{ id: resource, node_id: userID, address: '192.0.2.4', port: 8443,
      region: '', carrier: '', priority: 0, weight: 80, enabled: true }] },
    metadata: { requestId: 'line-request-1', idempotencyKey: 'line-key-1', expectedRevision: 7 } }
}

beforeEach(() => sessionStorage.clear())

describe('line resolution retry record', () => {
  it('preserves the exact snapshot, metadata and bytes and permits only forward readback transition', () => {
    const attempt = lineResolutionRetryFixture()
    expect(restoreLineResolutionRetry(owner, scopeID, resource)).toEqual({ record: null, blocked: false })
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(true)
    expect(restoreLineResolutionRetry(owner, scopeID, resource).record).toMatchObject({ attempt, body: JSON.stringify(attempt), phase: 'unknown' })
    expect(persistLineResolutionRetry(owner, scopeID, resource, { ...attempt, metadata: { ...attempt.metadata, idempotencyKey: 'new-key' } }, 'unknown')).toBe(false)
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', accepted)).toBe(true)
    expect(restoreLineResolutionRetry(owner, scopeID, resource).record).toMatchObject({ version: 2, accepted })
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(false)
    expect(clearLineResolutionRetry(owner, scopeID, resource, attempt)).toBe(false)
    expect(clearLineResolutionRetry(owner, scopeID, resource, attempt, accepted)).toBe(true)
    expect(restoreLineResolutionRetry(owner, scopeID, resource)).toEqual({ record: null, blocked: false })
  })

  it('never invents accepted evidence for legacy records and leaves legacy readback locked', () => {
    const attempt = lineResolutionRetryFixture()
    for (const phase of ['unknown', 'readback'] as const) {
      const raw = JSON.stringify({ version: 1, owner, scopeID, resource, phase, attempt, body: JSON.stringify(attempt) })
      sessionStorage.setItem(key, raw)
      expect(restoreLineResolutionRetry(owner, scopeID, resource)).toMatchObject({ blocked: false, record: { version: 1, phase } })
      if (phase === 'unknown') {
        expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(true)
        expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', accepted)).toBe(true)
      } else {
        expect(clearLineResolutionRetry(owner, scopeID, resource, attempt, accepted)).toBe(false)
        expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', accepted)).toBe(false)
        expect(sessionStorage.getItem(key)).toBe(raw)
      }
    }
  })

  it('binds readback to immutable accepted revision and digest and rejects malformed phase evidence', () => {
    const attempt = lineResolutionRetryFixture()
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback')).toBe(false)
    for (const invalid of [{ ...accepted, revision: 7 }, { ...accepted, revision: 9 },
      { ...accepted, configurationDigest: 'B'.repeat(64) }, { ...accepted, accessToken: 'never-persist' }])
      expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', invalid)).toBe(false)
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown', accepted)).toBe(false)
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', accepted)).toBe(true)
    const raw = sessionStorage.getItem(key)!
    const other = { ...accepted, configurationDigest: 'c'.repeat(64) }
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', other)).toBe(false)
    expect(clearLineResolutionRetry(owner, scopeID, resource, attempt, other)).toBe(false)
    for (const mutate of [
      (record: ReturnType<typeof JSON.parse>) => { record.accepted = null },
      (record: ReturnType<typeof JSON.parse>) => { record.accepted.revision = 9 },
      (record: ReturnType<typeof JSON.parse>) => { record.accepted.accessToken = 'never-persist' },
      (record: ReturnType<typeof JSON.parse>) => { record.phase = 'unknown' },
    ]) {
      const record = JSON.parse(raw)
      mutate(record)
      sessionStorage.setItem(key, JSON.stringify(record))
      expect(restoreLineResolutionRetry(owner, scopeID, resource).blocked).toBe(true)
    }
  })

  it('isolates user, actor kind, target scope and resource and rejects copied records', () => {
    const attempt = lineResolutionRetryFixture()
    persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')
    const otherUser = ['tenant', scopeID, resource] as const
    const platform = ['platform', scopeID, userID] as const
    expect(restoreLineResolutionRetry(otherUser, scopeID, resource)).toEqual({ record: null, blocked: false })
    expect(restoreLineResolutionRetry(platform, scopeID, resource)).toEqual({ record: null, blocked: false })
    expect(restoreLineResolutionRetry(owner, scopeID, userID)).toEqual({ record: null, blocked: false })
    expect(lineResolutionRetryStorageKey(owner, resource, resource)).toBe('')
    expect(lineResolutionRetryStorageKey(platform, resource, resource)).not.toBe(lineResolutionRetryStorageKey(platform, scopeID, resource))
    for (const foreignKey of [lineResolutionRetryStorageKey(otherUser, scopeID, resource), lineResolutionRetryStorageKey(platform, scopeID, resource), lineResolutionRetryStorageKey(owner, scopeID, userID)])
      sessionStorage.setItem(foreignKey, sessionStorage.getItem(key)!)
    expect(restoreLineResolutionRetry(otherUser, scopeID, resource).blocked).toBe(true)
    expect(restoreLineResolutionRetry(platform, scopeID, resource).blocked).toBe(true)
    expect(restoreLineResolutionRetry(owner, scopeID, userID).blocked).toBe(true)
  })

  it.each(['{', 'null', '{}', '[]', 'x'.repeat(512001)])('preserves malformed or oversized data fail-closed (%#)', (raw) => {
    sessionStorage.setItem(key, raw)
    expect(restoreLineResolutionRetry(owner, scopeID, resource)).toEqual({ record: null, blocked: true })
    expect(persistLineResolutionRetry(owner, scopeID, resource, lineResolutionRetryFixture(), 'unknown')).toBe(false)
    expect(clearLineResolutionRetry(owner, scopeID, resource, lineResolutionRetryFixture())).toBe(false)
    expect(sessionStorage.getItem(key)).toBe(raw)
  })

  it.each(['record', 'attempt', 'metadata', 'input', 'health_policy', 'endpoint'])('rejects token and unknown fields in %s even with a matching body', (location) => {
    persistLineResolutionRetry(owner, scopeID, resource, lineResolutionRetryFixture(), 'unknown')
    const record = JSON.parse(sessionStorage.getItem(key)!)
    const target = location === 'record' ? record : location === 'attempt' ? record.attempt :
      location === 'health_policy' ? record.attempt.input.health_policy : location === 'endpoint' ? record.attempt.input.endpoints[0] : record.attempt[location]
    target.accessToken = 'never-persist'
    record.body = JSON.stringify(record.attempt)
    sessionStorage.setItem(key, JSON.stringify(record))
    expect(restoreLineResolutionRetry(owner, scopeID, resource).blocked).toBe(true)
  })

  it('rejects body drift, invalid key/revision, invalid fields and duplicate endpoints', () => {
    for (const mutate of [
      (record: ReturnType<typeof JSON.parse>) => { record.body += ' ' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.metadata.idempotencyKey = 'bad\nheader' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.metadata.requestId = '' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.metadata.expectedRevision = 0 },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.metadata.expectedRevision = Number.MAX_SAFE_INTEGER + 1 },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.input.failover_mode = 'unknown' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.input.endpoints[0].port = 0 },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.input.endpoints[0].address = 'not-an-ip' },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.input.endpoints.push(record.attempt.input.endpoints[0]) },
      (record: ReturnType<typeof JSON.parse>) => { record.attempt.input.health_policy.probe_timeout_ms = 20000 },
    ]) {
      sessionStorage.clear()
      persistLineResolutionRetry(owner, scopeID, resource, lineResolutionRetryFixture(), 'unknown')
      const record = JSON.parse(sessionStorage.getItem(key)!)
      mutate(record)
      if (!record.body.endsWith(' ')) record.body = JSON.stringify(record.attempt)
      sessionStorage.setItem(key, JSON.stringify(record))
      expect(restoreLineResolutionRetry(owner, scopeID, resource).blocked).toBe(true)
    }
  })

  it('supports removal of all endpoints and rejects more than the 512 endpoint contract limit', () => {
    const attempt = lineResolutionRetryFixture()
    const endpoint = attempt.input.endpoints[0]!
    attempt.input.endpoints = []
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(true)
    sessionStorage.clear()
    attempt.input.endpoints = Array.from({ length: 512 }, (_, index) => ({ ...endpoint,
      id: `${String(index).padStart(8, '0')}-4444-4444-8444-444444444444` }))
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(true)
    sessionStorage.clear()
    attempt.input.endpoints.push(endpoint)
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(false)
  })

  it('does not clear a different or absent record and fails closed on storage exceptions or ignored operations', () => {
    const attempt = lineResolutionRetryFixture()
    expect(clearLineResolutionRetry(owner, scopeID, resource, attempt)).toBe(false)
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('read denied') })
    expect(restoreLineResolutionRetry(owner, scopeID, resource).blocked).toBe(true)
    get.mockRestore()
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(false)
    set.mockImplementation(() => undefined)
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'unknown')).toBe(false)
    set.mockRestore()
    expect(persistLineResolutionRetry(owner, scopeID, resource, attempt, 'readback', accepted)).toBe(true)
    expect(clearLineResolutionRetry(owner, scopeID, resource, { ...attempt, input: { ...attempt.input, name: 'changed' } })).toBe(false)
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => undefined)
    expect(clearLineResolutionRetry(owner, scopeID, resource, attempt, accepted)).toBe(false)
    expect(restoreLineResolutionRetry(owner, scopeID, resource).record?.phase).toBe('readback')
  })
})
