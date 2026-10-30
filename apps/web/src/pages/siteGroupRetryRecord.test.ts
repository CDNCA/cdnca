import { clearSiteGroupRetry, persistSiteGroupRetry, restoreSiteGroupRetry, siteGroupRetryStorageKey, type SiteGroupRetry } from './siteGroupRetryRecord'

const owner = ['platform', '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'] as const
const scope = '33333333-3333-4333-8333-333333333333'
const id = '44444444-4444-4444-8444-444444444444'
const attempt: SiteGroupRetry = { version: 1, owner, items: [{ action: 'create', scope, name: '名称', remark: '', key: 'create-key', phase: 'unknown' }] }

beforeEach(() => sessionStorage.clear())

describe('site group retry record', () => {
  it('survives a fresh reader without credentials and preserves the original request', () => {
    expect(persistSiteGroupRetry(attempt, null)).toBe(true)
    expect(restoreSiteGroupRetry(owner)).toEqual({ record: attempt, blocked: false })
    expect(persistSiteGroupRetry({ ...attempt, items: [{ ...attempt.items[0], key: 'new-key' }] }, attempt)).toBe(false)
    expect(sessionStorage.getItem(siteGroupRetryStorageKey(owner))).not.toMatch(/accessToken|Authorization|password/)
  })

  it('only advances an exact journal and never moves an accepted write back to unknown', () => {
    persistSiteGroupRetry(attempt, null)
    const accepted: SiteGroupRetry = { ...attempt, items: [{ ...attempt.items[0], phase: 'accepted', accepted: { id, revision: 1, name: '名称', remark: '' } }] }
    expect(persistSiteGroupRetry(accepted, attempt)).toBe(true)
    expect(persistSiteGroupRetry(attempt, accepted)).toBe(false)
    expect(clearSiteGroupRetry(attempt)).toBe(false)
    expect(clearSiteGroupRetry(accepted)).toBe(true)
  })

  it('isolates owners and rejects copied records', () => {
    persistSiteGroupRetry(attempt, null)
    const other = ['platform', owner[1], id] as const
    expect(restoreSiteGroupRetry(other)).toEqual({ record: null, blocked: false })
    sessionStorage.setItem(siteGroupRetryStorageKey(other), JSON.stringify(attempt))
    expect(restoreSiteGroupRetry(other).blocked).toBe(true)
  })

  it('preserves a verified later-version warning through done readback recovery', () => {
    const accepted: SiteGroupRetry = { ...attempt, items: [{ ...attempt.items[0], phase: 'accepted', accepted: { id, revision: 1, name: '名称', remark: '' } }] }
    expect(persistSiteGroupRetry(accepted, null)).toBe(true)
    const done = { ...accepted, items: [{ ...accepted.items[0], phase: 'done', superseded: true }] } as SiteGroupRetry
    expect(persistSiteGroupRetry(done, accepted)).toBe(true)
    expect(restoreSiteGroupRetry(owner)).toEqual({ record: done, blocked: false })
    expect(persistSiteGroupRetry({ ...accepted, items: [{ ...accepted.items[0], phase: 'done' }] }, done)).toBe(false)
    expect(persistSiteGroupRetry({ ...attempt, items: [{ ...attempt.items[0], superseded: true }] } as SiteGroupRetry, null)).toBe(false)
  })

  it.each(['{', 'null', '[]', '{}', 'x'.repeat(200001)])('retains invalid stored records and blocks new writes', (raw) => {
    const key = siteGroupRetryStorageKey(owner)
    sessionStorage.setItem(key, raw)
    expect(restoreSiteGroupRetry(owner).blocked).toBe(true)
    expect(persistSiteGroupRetry(attempt, null)).toBe(false)
    expect(sessionStorage.getItem(key)).toBe(raw)
  })

  it.each([
    { accessToken: 'forbidden' }, { revision: 0 }, { key: 'bad\nheader' }, { phase: 'invented' }, { remark: '\u0001' }, { name: '' },
  ])('rejects unsafe fields or shapes %j', (bad) => {
    expect(persistSiteGroupRetry({ ...attempt, items: [{ ...attempt.items[0], ...bad }] } as SiteGroupRetry, null)).toBe(false)
  })

  it('limits deletion to unique explicit targets and rejects a tenant scope override', () => {
    const item = { action: 'delete', scope, id, revision: 1, key: 'delete-key', phase: 'ready' } as const
    expect(persistSiteGroupRetry({ ...attempt, items: [item, item] }, null)).toBe(false)
    expect(persistSiteGroupRetry({ ...attempt, items: Array.from({ length: 101 }, () => item) }, null)).toBe(false)
    expect(persistSiteGroupRetry({ ...attempt, owner: ['tenant', owner[1], owner[2]] }, null)).toBe(false)
  })

  it('fails closed when storage cannot be read, written, confirmed or cleared', () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('denied') })
    expect(restoreSiteGroupRetry(owner).blocked).toBe(true)
    get.mockRestore()
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => undefined)
    expect(persistSiteGroupRetry(attempt, null)).toBe(false)
    set.mockRestore()
    persistSiteGroupRetry(attempt, null)
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => undefined)
    expect(clearSiteGroupRetry(attempt)).toBe(false)
  })
})
