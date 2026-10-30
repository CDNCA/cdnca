import { vi } from 'vitest'

import { l4RealtimeApi, type L4RealtimeRow } from '../api/l4Realtime'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { parsePorts, readRows } from './l4RealtimeRead'

const tenantID = '018f0000-0000-7000-8000-000000000010'
const actor = principal({ scope_kind: 'tenant', scope_id: tenantID, tenant_id: tenantID, permissions: ['sites.read'] })
const ownerKey = `${actor.user_id}:${actor.scope_kind}:${actor.scope_id}`
const row = (bucket: string, protocol: 'tcp' | 'udp' = 'tcp'): L4RealtimeRow => ({
  bucket, node_id: '018f0000-0000-7000-8000-000000000020', site_id: '018f0000-0000-7000-8000-000000000030',
  stream_id: '018f0000-0000-7000-8000-000000000040', listener_id: '018f0000-0000-7000-8000-000000000050',
  protocol, listen_port: 80, sessions: 1, bytes_up: 50, bytes_down: 50, errors: 0,
})
const page = (rows: L4RealtimeRow[], next?: string) => ({ version: 'l4-realtime/v1' as const, meta: {} as never, totals: {} as never, rows, ...(next ? { next_cursor: next } : {}) })

beforeEach(() => useSessionStore.getState().setSession(authResponse(actor), actor))
afterEach(() => vi.restoreAllMocks())

describe('A06 parsePorts normalisation', () => {
  it.each([
    ['80 80/TCP', [{ listenPort: 80 }]],
    ['80/TCP 80', [{ listenPort: 80 }]],
    ['80/tcp 80/UDP', [{ listenPort: 80 }]],
    ['80/TCP 80/tcp', [{ listenPort: 80, protocol: 'tcp' }]],
    ['443/UDP, 80/TCP', [{ listenPort: 80, protocol: 'tcp' }, { listenPort: 443, protocol: 'udp' }]],
    ['80 443', [{ listenPort: 80 }, { listenPort: 443 }]],
  ])('%s', (input, expected) => expect(parsePorts(input)).toEqual(expected))

  it('rejects invalid tokens', () => {
    expect(parsePorts('0')).toBeNull()
    expect(parsePorts('80/SCTP')).toBeNull()
  })
})

describe('A06 readRows', () => {
  it('queries an overlapping 80 + 80/TCP filter once so traffic is not doubled', async () => {
    const read = vi.spyOn(l4RealtimeApi, 'read').mockResolvedValue(page([row('2026-10-24T00:00:00Z')]))
    const result = await readRows(ownerKey, 'tenant', { filters: { range: '1h', timezone: 'UTC', limit: 100 }, ports: parsePorts('80 80/TCP')! }, new AbortController().signal)
    expect(read).toHaveBeenCalledTimes(1)
    expect(result.rows).toHaveLength(1)
    expect(result.complete).toBe(true)
  })

  it.each([[19, true], [20, true], [21, false]])('marks completeness when %i pages are available', async (pages, complete) => {
    let calls = 0
    vi.spyOn(l4RealtimeApi, 'read').mockImplementation(async () => {
      calls += 1
      return page([row(`2026-10-24T00:${String(calls).padStart(2, '0')}:00Z`)], calls < pages ? `cursor-${calls}` : undefined)
    })
    const result = await readRows(ownerKey, 'tenant', { filters: { range: '1h', timezone: 'UTC', limit: 100 }, ports: [] }, new AbortController().signal)
    expect(calls).toBe(Math.min(pages, 20))
    expect(result.complete).toBe(complete)
  })
})
