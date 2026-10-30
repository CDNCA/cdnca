import dayjs from 'dayjs'

import { ApiError } from '../api/auth'
import { analyticsLogsApi, type AnalyticsLogFilters } from '../api/analyticsLogs'
import { blockWindow } from '../pages/blockWindow'

const tenantID = '018f0000-0000-7000-8000-000000000001'
const siteID = '018f0000-0000-7000-8000-000000000002'
const nodeID = '018f0000-0000-7000-8000-000000000003'
const blockID = '018f0000-0000-5000-8000-000000000004'
const policyID = '018f0000-0000-7000-8000-000000000005'
const candidateID = '018f0000-0000-7000-8000-000000000006'
const filters: AnalyticsLogFilters = {
  from: '2026-07-28T07:00:00Z',
  to: '2026-07-28T08:00:00Z',
  tenantId: tenantID,
  siteId: siteID,
  nodeId: nodeID,
  clientIp: '2001:db8::10',
  statusCode: 200,
  countryCode: 'CN',
  carrier: 'CMCC',
  method: 'GET',
  protocol: 'HTTP/2',
  cacheStatus: 'HIT',
  ja4: 't13d1516h2_8daaf6152771',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function validPage(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'https://cdnca.test')
  return json({
    data: [],
    meta: {
      from: url.searchParams.get('from'),
      to: url.searchParams.get('to'),
      timezone: 'UTC',
      consistency: 'snapshot',
      replacement_consistency: 'latest_event_id_at_snapshot',
      pagination: 'keyset',
    },
  })
}

function capturedBody(depth: number): Record<string, unknown> {
  let value: unknown = 'leaf'
  for (let index = 0; index < depth; index += 1) value = { child: value }
  return { root: value }
}

function accessEvent(replacement: Record<string, unknown> = {}) {
  return {
    event_id: 'capture-boundary', occurred_at: '2026-07-28T07:59:00Z', site_id: siteID, node_id: nodeID,
    request_id: 'capture-request', trace_id: 'capture-trace',
    config_version_id: '018f0000-0000-7000-8000-000000000004',
    host: 'cdn.example.test', uri_path: '/capture', client_ip: '192.0.2.10', country_code: 'CN', carrier: 'CMCC',
    method: 'GET', protocol: 'HTTP/2', cache_status: 'HIT', upstream_result: 'ok', upstream_addr: '', status_code: 200,
    request_bytes: 1, response_bytes: 2, duration_us: 3, task_id: null, installation_id: 'installation-1',
    request_headers: {}, response_headers: {}, request_body: null, response_body: null,
    ja4: null, origin_connect_us: null, origin_first_byte_us: null, origin_total_us: null,
    ...replacement,
  }
}

function capturedPage(replacement: Record<string, unknown>): Response {
  return json({
    data: [accessEvent(replacement)],
    meta: {
      from: filters.from, to: filters.to, timezone: 'UTC', consistency: 'snapshot',
      replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset',
    },
  })
}

describe('analytics logs API', () => {
  it('reads aggregated CC auto-bans with window, site and IP filters (NF34)', async () => {
    const response = {
      data: [{ site_id: '018f0000-0000-7000-8000-000000000020', host: 'a.example.test', client_ip: '192.0.2.9',
        rule_id: 'r-1', ban_count: 2, first_banned_at: '2026-08-07T07:00:00Z', last_banned_at: '2026-08-07T08:00:00Z' }],
      truncated: false,
      meta: { from: '2026-08-06T08:00:00Z', to: '2026-08-07T08:00:00Z', timezone: 'UTC',
        consistency: 'snapshot', snapshot_at: '2026-08-07T08:00:00Z', replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset' },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify(response),
      { status: 200, headers: { 'Content-Type': 'application/json' } })))
    const page = await analyticsLogsApi.listCCBans('tenant-token', 'tenant', {
      from: '2026-08-06T08:00:00Z', to: '2026-08-07T08:00:00Z', siteId: '018f0000-0000-7000-8000-000000000020', clientIp: '192.0.2.9',
    })
    expect(page.data[0].ban_count).toBe(2)
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/logs/cc-bans')
    expect(url.searchParams.get('client_ip')).toBe('192.0.2.9')
    expect(url.searchParams.get('site_id')).toBe('018f0000-0000-7000-8000-000000000020')
    fetchSpy.mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ ...response, data: [{ ...response.data[0], ban_count: 0 }] }),
      { status: 200, headers: { 'Content-Type': 'application/json' } })))
    await expect(analyticsLogsApi.listCCBans('tenant-token', 'tenant', { from: response.meta.from, to: response.meta.to }))
      .rejects.toBeInstanceOf(ApiError)
  })

  it('sends the URI prefix match mode only for a prefix filter (FX29/NF17)', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(validPage(input)))
    await analyticsLogsApi.listAccess('tenant-token', 'tenant', { ...filters, tenantId: undefined, uriPath: '/static/', uriPathMatch: 'prefix' }, 1)
    await analyticsLogsApi.listBlocks('tenant-token', 'tenant', { ...filters, tenantId: undefined, uriPath: '/static/' }, 1)
    const prefixURL = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(prefixURL.searchParams.get('uri_path')).toBe('/static/')
    expect(prefixURL.searchParams.get('uri_path_match')).toBe('prefix')
    const exactURL = new URL(String(fetchSpy.mock.calls[1][0]), 'https://cdnca.test')
    expect(exactURL.searchParams.has('uri_path_match')).toBe(false)
    await expect(analyticsLogsApi.listAccess('tenant-token', 'tenant', { ...filters, tenantId: undefined, uriPathMatch: 'prefix' }, 1))
      .rejects.toBeInstanceOf(ApiError)
  })

  // fix-waflogdetail: block events take every overview action, an event type and the overview domain list.
  it('sends observed and auto-block actions, the event type and a domain list for block events only', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(validPage(input)))
    const tenant = { ...filters, tenantId: undefined }
    await analyticsLogsApi.listBlocks('tenant-token', 'tenant', { ...tenant, action: 'log', eventType: 'waf', host: 'a.example.test b.example.test' }, 1)
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect([url.searchParams.get('action'), url.searchParams.get('event_type'), url.searchParams.get('host')])
      .toEqual(['log', 'waf', 'a.example.test b.example.test'])
    await analyticsLogsApi.listBlocks('tenant-token', 'tenant', { ...tenant, action: 'temporary_ban' }, 1)
    for (const invalid of [
      { host: 'a.example.test a.example.test' }, { host: 'a.example.test bad' }, { eventType: 'WAF type' },
      { action: 'allow' as never },
    ]) {
      await expect(analyticsLogsApi.listBlocks('tenant-token', 'tenant', { ...tenant, ...invalid }, 1)).rejects.toBeInstanceOf(ApiError)
    }
    for (const invalid of [{ eventType: 'waf' }, { action: 'log' as const }]) {
      await expect(analyticsLogsApi.listAccess('tenant-token', 'tenant', { ...tenant, ...invalid }, 1)).rejects.toBeInstanceOf(ApiError)
    }
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  // fix-waflogdetail2: the access log takes the same domain list as block events (one implementation).
  it('sends the same domain list for access logs as for block events', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(validPage(input)))
    const tenant = { ...filters, tenantId: undefined }
    await analyticsLogsApi.listAccess('tenant-token', 'tenant', { ...tenant, host: 'a.example.test b.example.test' }, 1)
    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test').searchParams.get('host'))
      .toBe('a.example.test b.example.test')
    for (const invalid of [{ host: 'a.example.test a.example.test' }, { host: 'a.example.test bad' }]) {
      await expect(analyticsLogsApi.listAccess('tenant-token', 'tenant', { ...tenant, ...invalid }, 1)).rejects.toBeInstanceOf(ApiError)
    }
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('keeps legal tenant and explicit-tenant admin requests compatible', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(validPage(input)))

    await analyticsLogsApi.listAccess('tenant-token', 'tenant', { ...filters, tenantId: undefined }, 1, 'cursor +/==')
    await analyticsLogsApi.listBlocks('admin-token', 'admin', { ...filters, tenantId: tenantID }, 100)

    const tenantURL = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(tenantURL.pathname).toBe('/v1/analytics/logs/access')
    expect(tenantURL.searchParams.has('tenant_id')).toBe(false)
    expect(tenantURL.searchParams.get('limit')).toBe('1')
    expect(tenantURL.searchParams.get('cursor')).toBe('cursor +/==')

    const adminURL = new URL(String(fetchSpy.mock.calls[1][0]), 'https://cdnca.test')
    expect(adminURL.pathname).toBe('/v1/admin/analytics/logs/block-events')
    expect(adminURL.searchParams.get('tenant_id')).toBe(tenantID)
    expect(adminURL.searchParams.get('limit')).toBe('100')
  })

  it.each([
    ['invalid from', { from: '2026-02-30T07:00:00Z' }],
    ['local time without UTC offset', { from: '2026-07-28T07:00:00' }],
    ['reversed window', { from: '2026-07-28T08:00:00Z' }],
    ['invalid site UUID', { siteId: 'site-1' }],
    ['invalid node UUID', { nodeId: 'node-1' }],
    ['invalid client IP', { clientIp: 'not-an-ip' }],
    ['invalid status code', { statusCode: 600 }],
    ['empty country', { countryCode: '' }],
    ['overlong carrier', { carrier: 'x'.repeat(129) }],
    ['empty method', { method: '' }],
    ['overlong protocol', { protocol: 'x'.repeat(33) }],
    ['empty cache status', { cacheStatus: '' }],
    ['overlong JA4', { ja4: 'x'.repeat(129) }],
  ])('rejects %s before making a request', async (_label, replacement) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const next = { ...filters, ...replacement }
    if (_label === 'reversed window') next.to = filters.from

    await expect(analyticsLogsApi.listAccess('token', 'tenant', next, 20)).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(ApiError)
      expect(error).toMatchObject({ status: 400, code: 'analytics_logs_invalid_request' })
      return true
    })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['zero limit', 0, undefined],
    ['overlarge limit', 101, undefined],
    ['empty cursor', 20, ''],
    ['overlong cursor', 20, 'x'.repeat(2049)],
  ])('rejects %s before making a request', async (_label, limit, cursor) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(analyticsLogsApi.listAccess('token', 'tenant', { ...filters, tenantId: undefined }, limit, cursor)).rejects.toMatchObject({
      status: 400,
      code: 'analytics_logs_invalid_request',
    })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed on malformed success responses, stable HTTP errors, and network failures', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: [], meta: { timezone: 'UTC' } }))
      .mockResolvedValueOnce(json({ error: { code: 'analytics_logs_storage_unavailable', message: 'private detail' } }, 503))
      .mockRejectedValueOnce(new Error('private host'))

    await expect(analyticsLogsApi.listAccess('token', 'tenant', { ...filters, tenantId: undefined }, 20)).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
    await expect(analyticsLogsApi.listAccess('token', 'tenant', { ...filters, tenantId: undefined }, 20)).rejects.toMatchObject({
      status: 503,
      code: 'analytics_logs_storage_unavailable',
      message: 'API request failed',
    })
    await expect(analyticsLogsApi.listAccess('token', 'tenant', { ...filters, tenantId: undefined }, 20)).rejects.toMatchObject({
      status: 0,
      code: 'network_error',
      message: 'Network request failed',
    })
    expect(fetchSpy).toHaveBeenCalledTimes(3)
  })

  it.each([
    ['header count', () => ({ request_headers: Object.fromEntries(Array.from({ length: 129 }, (_, index) => [`X-Capture-${index}`, 'ok'])) })],
    ['header key bytes', () => ({ request_headers: { [`X-${'K'.repeat(127)}`]: 'ok' } })],
    ['header value bytes', () => ({ request_headers: { 'X-Capture': 'v'.repeat((16 << 10) + 1) } })],
    ['body depth', () => ({ request_body: capturedBody(10) })],
    ['body nodes', () => ({ request_body: { items: Array.from({ length: 2049 }, () => null) } })],
    ['body key bytes', () => ({ request_body: { ['k'.repeat(129)]: true } })],
    ['body value bytes', () => ({ request_body: { value: 'v'.repeat((64 << 10) + 1) } })],
    ['body aggregate bytes', () => ({ request_body: Object.fromEntries(
      Array.from({ length: 17 }, (_, index) => [`value_${index}`, 'v'.repeat(64 << 10)]),
    ) })],
    ['raw sensitive header', () => ({ request_headers: { Authorization: 'Bearer raw-secret' } })],
    ['raw nested sensitive body', () => ({ request_body: { profile: { accessToken: 'raw-token' } } })],
    ['upstream_addr bytes', () => ({ upstream_addr: 'a'.repeat(65) })],
    ['missing upstream_addr', () => ({ upstream_addr: undefined })],
  ])('rejects captured %s overflow or secret before returning event data', async (_name, replacement) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(capturedPage(replacement()))

    await expect(analyticsLogsApi.listAccess('token', 'tenant', { ...filters, tenantId: undefined }, 20))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('counts nodes that ignored an unlock as an old release apart and bounds the sum', async () => {
    const block = (edge_progress: unknown) => json({
      data: [{
        id: blockID, site_id: siteID, policy_id: policyID, policy_version: 7, tenant_id: tenantID,
        cidr: '192.0.2.10/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: false, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing', edge_progress,
      }],
      total_count: 1, snapshot_at: '2026-08-07T08:01:00Z',
    })
    const progress = { candidate_id: candidateID, state: 'cancelled', total_nodes: 3, ready_nodes: 2, failed_nodes: 0 }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(block({ ...progress, superseded_nodes: 1 }))
      .mockResolvedValueOnce(block({ ...progress, superseded_nodes: 2 }))
      .mockResolvedValueOnce(block(progress))
    const current = await analyticsLogsApi.listCurrentBlocks('admin-token', 'admin', { limit: 20, offset: 0 })
    expect(current.data[0].edge_progress).toMatchObject({ failed_nodes: 0, superseded_nodes: 1 })
    await expect(analyticsLogsApi.listCurrentBlocks('admin-token', 'admin', { limit: 20, offset: 0 }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(analyticsLogsApi.listCurrentBlocks('admin-token', 'admin', { limit: 20, offset: 0 }))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('validates and scopes current blocks, history, and unlock requests', async () => {
    const progress = {
      candidate_id: candidateID, state: 'healthy', total_nodes: 2, ready_nodes: 2, failed_nodes: 0, superseded_nodes: 0,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        data: [{
          id: blockID, site_id: siteID, policy_id: policyID, policy_version: 7,
          tenant_id: tenantID,
          cidr: '192.0.2.10/32', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
          unlockable: false, site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
          edge_progress: progress,
        }],
        total_count: 21,
        snapshot_at: '2026-08-07T08:01:00Z',
      }))
      .mockResolvedValueOnce(json({
        data: [{
          id: '018f0000-0000-5000-8000-000000000007', block_id: blockID,
          tenant_id: tenantID, site_id: siteID, policy_id: policyID, cidr: '192.0.2.10/32',
          reason_code: 'false_positive_confirmed', result_code: 'recovery_claimed',
          requested_at: '2026-08-07T08:02:00Z', unlocked_at: '2026-08-07T08:02:30Z',
          site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing', auto_unlock: false,
          edge_progress: progress,
        }],
        total_count: 1,
        snapshot_at: '2026-08-07T08:03:00Z',
      }))
      .mockResolvedValueOnce(json({
        block_id: blockID, candidate_id: candidateID, progress: 'claimed',
        reason_code: 'recovery_claimed', replayed: false,
      }, 202))

    const current = await analyticsLogsApi.listCurrentBlocks('admin-token', 'admin', {
      siteId: siteID, policyId: policyID, cidr: '192.0.2.10/32', limit: 20, offset: 20,
    })
    const history = await analyticsLogsApi.listBlockHistory('tenant-token', 'tenant', {
      siteId: siteID, limit: 10, start: 1754553600, end: 1754640000,
    })
    const unlocked = await analyticsLogsApi.unlockCurrentBlock('admin-token', 'admin', {
      blockId: blockID, tenantId: tenantID, idempotencyKey: 'unlock-1',
    })

    expect(current.data[0]).toMatchObject({ id: blockID, cidr: '192.0.2.10/32', unlockable: false })
    expect(current.data[0].edge_progress).toMatchObject({ superseded_nodes: 0 })
    expect(history.data[0]).toMatchObject({ block_id: blockID, result_code: 'recovery_claimed' })
    expect(unlocked).toMatchObject({ block_id: blockID, candidate_id: candidateID, replayed: false })
    const currentURL = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(currentURL.pathname).toBe('/v1/admin/analytics/logs/blocks/current')
    expect(currentURL.searchParams.has('tenant_id')).toBe(false)
    expect(currentURL.searchParams.get('site_id')).toBe(siteID)
    expect(currentURL.searchParams.get('policy_id')).toBe(policyID)
    expect(currentURL.searchParams.get('cidr')).toBe('192.0.2.10/32')
    expect(currentURL.searchParams.get('limit')).toBe('20')
    expect(currentURL.searchParams.get('offset')).toBe('20')
    const historyURL = new URL(String(fetchSpy.mock.calls[1][0]), 'https://cdnca.test')
    expect(historyURL.pathname).toBe('/v1/analytics/logs/blocks/history')
    expect(historyURL.searchParams.has('tenant_id')).toBe(false)
    expect(historyURL.searchParams.get('offset')).toBe('0')
    // The competitor sends the history window as Unix seconds; the current-blocks endpoint must not receive it.
    expect(historyURL.searchParams.get('start')).toBe('1754553600')
    expect(historyURL.searchParams.get('end')).toBe('1754640000')
    expect(currentURL.searchParams.has('start')).toBe(false)
    expect(currentURL.searchParams.has('end')).toBe(false)
    const unlockURL = new URL(String(fetchSpy.mock.calls[2][0]), 'https://cdnca.test')
    expect(unlockURL.pathname).toBe(`/v1/admin/analytics/logs/blocks/current/${blockID}/unlock`)
    expect(unlockURL.searchParams.get('tenant_id')).toBe(tenantID)
    expect(fetchSpy.mock.calls[2][1]).toMatchObject({ method: 'POST' })
    const headers = new Headers(fetchSpy.mock.calls[2][1]?.headers)
    expect(headers.get('Idempotency-Key')).toBe('unlock-1')
    expect(await new Response(fetchSpy.mock.calls[2][1]?.body).json()).toEqual({ reason_code: 'false_positive_confirmed' })
  })

  it('accepts RFC3339Nano timestamps returned by the Go block-state API', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [{
        id: blockID, site_id: siteID, policy_id: policyID, policy_version: 7,
        tenant_id: tenantID,
        cidr: '192.0.2.10/32', reason_code: 'acl_policy_block',
        blocked_at: '2026-09-21T02:03:04.123456789Z', unlockable: true,
        site_display_id: 42, domain: 'cdn.example.test', position: 'CN-Beijing',
      }],
      total_count: 1,
      snapshot_at: '2026-09-21T02:03:05.987654321Z',
    }))

    await expect(analyticsLogsApi.listCurrentBlocks('admin-token', 'admin', { limit: 10, offset: 0 }))
      .resolves.toMatchObject({ total_count: 1, data: [{ id: blockID }] })
  })

  it('converts the block-history window to the Unix seconds the competitor submits', () => {
    expect(blockWindow(dayjs('2026-08-01T00:00:00'), dayjs('2026-08-02T00:00:00'))).toEqual({
      start: Math.floor(dayjs('2026-08-01T00:00:00').valueOf() / 1000),
      end: Math.floor(dayjs('2026-08-02T00:00:00').valueOf() / 1000),
    })
    // An empty side leaves that bound open rather than pinning it to the epoch.
    expect(blockWindow(null, dayjs('2026-08-02T00:00:00'))).not.toHaveProperty('start')
    expect(blockWindow(null, null)).toEqual({})
  })

  it('fails closed before request or rendering on malformed block-state authority', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(analyticsLogsApi.listCurrentBlocks('token', 'admin', { tenantId: 'invalid', limit: 20 }))
      .rejects.toMatchObject({ status: 400, code: 'analytics_logs_invalid_request' })
    await expect(analyticsLogsApi.unlockCurrentBlock('token', 'tenant', {
      blockId: blockID, tenantId: tenantID, idempotencyKey: 'unlock-tenant-rescope',
    })).rejects.toMatchObject({ status: 400, code: 'analytics_logs_invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()

    fetchSpy.mockResolvedValueOnce(json({
      data: [{
        id: blockID, site_id: siteID, policy_id: policyID, policy_version: 7,
        cidr: '192.0.2.11/24', reason_code: 'acl_policy_block', blocked_at: '2026-08-07T08:00:00Z',
        unlockable: true,
      }],
      snapshot_at: '2026-08-07T08:01:00Z',
    }))
    await expect(analyticsLogsApi.listCurrentBlocks('token', 'tenant', {}))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetchSpy.mockResolvedValueOnce(json({
      block_id: blockID, candidate_id: candidateID, progress: 'private_future_state',
      reason_code: 'recovery_claimed', replayed: false,
    }, 202))
    await expect(analyticsLogsApi.unlockCurrentBlock('token', 'tenant', {
      blockId: blockID, idempotencyKey: 'unlock-invalid-response',
    })).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('binds access export creation, status and one-time download to the exact filter and session', async () => {
    const exportID = '018f0000-0000-7000-8000-000000000077'
    const exportJob = {
      id: exportID, status: 'completed', reason: 'completed', snapshot_at: '2026-08-07T08:00:00Z',
      row_count: 2, byte_count: 512, sha256: 'a'.repeat(64), created_at: '2026-08-07T08:00:01Z',
      expires_at: '2026-08-07T09:00:01Z', downloadable: true,
      filter: { from: '2026-08-07T00:00:00Z', to: '2026-08-07T01:00:00Z', host: 'a.example', status_code: 404 },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(exportJob, 202))
      .mockResolvedValueOnce(json({ data: [exportJob] }))
      .mockResolvedValueOnce(json({ export_id: exportID, token: 't'.repeat(43), expires_at: '2026-08-07T08:05:00Z' }, 201))
      .mockResolvedValueOnce(new Response('event_id,occurred_at\r\nevent-a,2026-08-07T08:00:00Z\r\n', {
        status: 200,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="analytics-access-${exportID}.csv"`,
          'Digest': `sha-256=${'a'.repeat(64)}`,
        },
      }))
    const filters = {
      from: '2026-08-07T07:00:00Z', to: '2026-08-07T08:00:00Z', upstreamResult: 'success',
      contentType: 'application/json', userAgent: 'Mozilla/5.0', requestBytesMin: 10, requestBytesMax: 20,
      responseBytesMin: 30, responseBytesMax: 40, host: 'Shop.Example.test',
    }

    await expect(analyticsLogsApi.createAccessExport('token', 'tenant', filters, 'access-export-contract-1'))
      .resolves.toMatchObject({ id: exportID, downloadable: true })
    // LOG-02：申请记录带回服务端冻结的原查询条件
    await expect(analyticsLogsApi.listAccessExports('token', 'tenant')).resolves.toEqual([
      expect.objectContaining({ filter: { from: '2026-08-07T00:00:00Z', to: '2026-08-07T01:00:00Z', host: 'a.example', status_code: 404 } }),
    ])
    const grant = await analyticsLogsApi.grantAccessExportDownload('token', 'tenant', exportID)
    await expect(analyticsLogsApi.downloadAccessExport('token', 'tenant', exportID, grant.token)).resolves.toBeInstanceOf(Blob)
    // LOG-01：按当前条件找回（不带 limit/cursor），最多一条
    fetchSpy.mockResolvedValueOnce(json({ data: [exportJob] }))
    await expect(analyticsLogsApi.findAccessExportForScope('token', 'tenant', filters)).resolves.toMatchObject({ id: exportID })
    const lookup = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'https://cdnca.test')
    expect(lookup.pathname).toBe('/v1/analytics/logs/access/exports')
    expect(lookup.searchParams.get('host')).toBe('shop.example.test')
    expect(lookup.searchParams.has('limit')).toBe(false)
    fetchSpy.mockResolvedValueOnce(json({ data: [exportJob, exportJob] }))
    await expect(analyticsLogsApi.findAccessExportForScope('token', 'tenant', filters)).rejects.toMatchObject({ code: 'invalid_response' })

    const create = fetchSpy.mock.calls[0]
    expect(new URL(String(create[0]), 'https://cdnca.test').pathname).toBe('/v1/analytics/logs/access/exports')
    expect(new Headers(create[1]?.headers).get('Idempotency-Key')).toBe('access-export-contract-1')
    expect(await new Response(create[1]?.body).json()).toMatchObject({ filter: {
      upstream_result: 'success', content_type: 'application/json', user_agent: 'Mozilla/5.0',
      host: 'shop.example.test', request_bytes_min: 10, request_bytes_max: 20, response_bytes_min: 30, response_bytes_max: 40,
    } })
    expect(new Headers(fetchSpy.mock.calls[3][1]?.headers).get('X-Analytics-Download-Token')).toBe('t'.repeat(43))
  })
})
