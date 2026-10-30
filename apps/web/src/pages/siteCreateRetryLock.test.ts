import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { CreateSiteRequest } from '../api/sites'
import {
  clearSiteCreateRetry,
  persistSiteCreateRetry,
  restoreSiteCreateRetry,
  siteCreateRetryStorageKey,
  type SiteCreateRetryItem,
} from './siteCreateRetryLock'

function siteCreateRetryFixture(index = 1): SiteCreateRetryItem {
  const input: CreateSiteRequest = {
    basic: {
      package_id: null, package_name: null, group_id: null, group_name: null,
      domains: [`site-${index}.example.com`], http_enabled: true, http_listen_ports: ['80'],
      https_listen_ports: [], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'],
      origins: ['192.0.2.80:80'], cname: '', https_enabled: false, enabled: true,
      status: 'active', is_default: false,
    },
    origin_pool: {
      origins: [{ host: '192.0.2.80', port: 80, weight: 1, enabled: true }],
      balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000,
    },
  }
  return { input, key: `site-create-batch-${index}`, body: JSON.stringify(input) }
}

const storageKey = siteCreateRetryStorageKey('scope-a', 'user-a')

beforeEach(() => {
  vi.restoreAllMocks()
  sessionStorage.clear()
})

describe('siteCreateRetryLock', () => {
  it('returns an empty, uncorrupted state before any write', () => {
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: false })
  })

  it('round-trips exact request bodies and keys in order without sending requests', () => {
    const fetch = vi.spyOn(globalThis, 'fetch')
    const items = [siteCreateRetryFixture(2), siteCreateRetryFixture(1)]
    expect(persistSiteCreateRetry(storageKey, items)).toBe(true)
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items, corrupted: false })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('isolates stable owner keys and escapes delimiters without collisions', () => {
    const items = [siteCreateRetryFixture()]
    expect(siteCreateRetryStorageKey('scope:a', 'user')).not.toBe(siteCreateRetryStorageKey('scope', 'a:user'))
    expect(persistSiteCreateRetry(storageKey, items)).toBe(true)
    expect(restoreSiteCreateRetry(siteCreateRetryStorageKey('scope-b', 'user-a')).items).toBeNull()
    expect(restoreSiteCreateRetry(siteCreateRetryStorageKey('scope-a', 'user-b')).items).toBeNull()
    expect(restoreSiteCreateRetry(siteCreateRetryStorageKey('scope-a', 'user-a')).items).toEqual(items)
  })

  it('accepts 100 requests and paired platform target identity', () => {
    const items = Array.from({ length: 100 }, (_, index) => siteCreateRetryFixture(index))
    items[0].input.target_scope_id = '11111111-1111-4111-8111-111111111111'
    items[0].input.owner_id = '22222222-2222-4222-8222-222222222222'
    items[0].body = JSON.stringify(items[0].input)
    expect(persistSiteCreateRetry(storageKey, items)).toBe(true)
    expect(restoreSiteCreateRetry(storageKey).items).toEqual(items)
  })

  it('accepts optional named references and a request without an origin pool', () => {
    const item = siteCreateRetryFixture()
    delete item.input.origin_pool
    Object.assign(item.input.basic, {
      package_id: '11111111-1111-4111-8111-111111111111', package_name: 'package',
      package_subscription_id: '22222222-2222-4222-8222-222222222222',
      group_id: '33333333-3333-4333-8333-333333333333', group_name: 'group',
      cname_mode: 'site', cname_domain: 'cdn.example.com', cname_hostname: 'site-1',
    })
    item.body = JSON.stringify(item.input)
    expect(persistSiteCreateRetry(storageKey, [item])).toBe(true)
  })

  it.each(['{', 'null', '{}', '[]', '[null]'])('fails closed without deleting malformed stored data %s', (stored) => {
    sessionStorage.setItem(storageKey, stored)
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: true })
    expect(sessionStorage.getItem(storageKey)).toBe(stored)
  })

  it.each(['', ' ', 'with space', 'key\nheader', '/path', 'k'.repeat(129)])('rejects an invalid idempotency key %j', (key) => {
    const item = { ...siteCreateRetryFixture(), key }
    sessionStorage.setItem(storageKey, JSON.stringify([item]))
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: true })
    expect(persistSiteCreateRetry(storageKey, [item])).toBe(false)
  })

  it('rejects duplicate keys and batches above the limit', () => {
    const duplicates = [siteCreateRetryFixture(), siteCreateRetryFixture()]
    const tooMany = Array.from({ length: 101 }, (_, index) => siteCreateRetryFixture(index))
    for (const items of [duplicates, tooMany]) {
      sessionStorage.setItem(storageKey, JSON.stringify(items))
      expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: true })
      expect(persistSiteCreateRetry(storageKey, items)).toBe(false)
    }
  })

  it.each(['different body', 'equivalent JSON with whitespace'])('rejects %s rather than reserializing the frozen request', (kind) => {
    const item = siteCreateRetryFixture()
    item.body = kind === 'different body' ? '{}' : JSON.stringify(item.input, null, 2)
    sessionStorage.setItem(storageKey, JSON.stringify([item]))
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: true })
    expect(persistSiteCreateRetry(storageKey, [item])).toBe(false)
  })

  it.each([
    ['missing basic', (input: CreateSiteRequest) => { delete (input as Partial<CreateSiteRequest>).basic }],
    ['empty domains', (input: CreateSiteRequest) => { input.basic.domains = [] }],
    ['invalid origins', (input: CreateSiteRequest) => { input.basic.origins = [1 as unknown as string] }],
    ['invalid boolean', (input: CreateSiteRequest) => { input.basic.enabled = 'true' as unknown as boolean }],
    ['invalid port', (input: CreateSiteRequest) => { input.basic.http_listen_ports = ['70000'] }],
    ['invalid status', (input: CreateSiteRequest) => { input.basic.status = 'invalid' as never }],
    ['unpaired target', (input: CreateSiteRequest) => { input.target_scope_id = '11111111-1111-4111-8111-111111111111' }],
    ['unpaired reference', (input: CreateSiteRequest) => { input.basic.group_name = 'group' }],
    ['malformed origin pool', (input: CreateSiteRequest) => { input.origin_pool!.origins = [] }],
    ['invalid origin port', (input: CreateSiteRequest) => { input.origin_pool!.origins[0].port = 0 }],
  ] as const)('rejects the malformed request structure: %s', (_, mutate) => {
    const item = siteCreateRetryFixture()
    mutate(item.input)
    item.body = JSON.stringify(item.input)
    sessionStorage.setItem(storageKey, JSON.stringify([item]))
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: true })
    expect(persistSiteCreateRetry(storageKey, [item])).toBe(false)
  })

  it.each(['item', 'input', 'basic', 'origin pool', 'origin'])('does not persist auth or session fields on %s', (location) => {
    const item = siteCreateRetryFixture()
    const target = location === 'item' ? item : location === 'input' ? item.input : location === 'basic'
      ? item.input.basic : location === 'origin pool' ? item.input.origin_pool! : item.input.origin_pool!.origins[0]
    Object.assign(target, { accessToken: 'must-not-be-stored', sessionID: 'private-session' })
    item.body = JSON.stringify(item.input)
    expect(persistSiteCreateRetry(storageKey, [item])).toBe(false)
    expect(sessionStorage.getItem(storageKey)).toBeNull()
  })

  it('does not overwrite a saved batch with invalid input', () => {
    const items = [siteCreateRetryFixture()]
    expect(persistSiteCreateRetry(storageKey, items)).toBe(true)
    expect(persistSiteCreateRetry(storageKey, [])).toBe(false)
    expect(restoreSiteCreateRetry(storageKey).items).toEqual(items)
  })

  it('fails closed when storage reads throw', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('storage denied') })
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: true })
  })

  it('returns false when persistence throws or fails its readback', () => {
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    expect(persistSiteCreateRetry(storageKey, [siteCreateRetryFixture()])).toBe(false)
    set.mockImplementation(() => undefined)
    expect(persistSiteCreateRetry(storageKey, [siteCreateRetryFixture()])).toBe(false)
  })

  it('clears only its owner key and fails closed when removal fails', () => {
    const otherKey = siteCreateRetryStorageKey('scope-b', 'user-b')
    expect(persistSiteCreateRetry(storageKey, [siteCreateRetryFixture()])).toBe(true)
    sessionStorage.setItem(otherKey, 'keep')
    const remove = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('denied') })
    expect(clearSiteCreateRetry(storageKey)).toBe(false)
    remove.mockImplementation(() => undefined)
    expect(clearSiteCreateRetry(storageKey)).toBe(false)
    remove.mockRestore()
    expect(clearSiteCreateRetry(storageKey)).toBe(true)
    expect(restoreSiteCreateRetry(storageKey)).toEqual({ items: null, corrupted: false })
    expect(sessionStorage.getItem(otherKey)).toBe('keep')
  })

  it('rejects an empty storage key', () => {
    expect(restoreSiteCreateRetry('')).toEqual({ items: null, corrupted: true })
    expect(persistSiteCreateRetry('', [siteCreateRetryFixture()])).toBe(false)
    expect(clearSiteCreateRetry('')).toBe(false)
  })
})
