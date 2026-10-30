import { observabilityLogsApi } from '../api/observabilityLogs'

function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }

describe('OBS-09 observability logs API', () => {
  it('binds filters to the bearer session and rejects malformed facts', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [{ event_id:'event-1', occurred_at:'2026-08-07T09:00:00Z', kind:'login', actor_user_display_id:'1', action:'auth.login', reason_code:'credentials_accepted', result_code:'success', source_ip:'192.0.2.1', geo_code:'unknown', user_agent:'Mozilla/5.0' }], snapshot_at:'2026-08-07T10:00:00Z', total_count:1 }))
      .mockResolvedValueOnce(json({ items: [{ event_id:'event-2', occurred_at:'bad', kind:'login', action:'auth.login', reason_code:'x', result_code:'raw secret', source_ip:'192.0.2.1', geo_code:'unknown' }], snapshot_at:'2026-08-07T10:00:00Z' }))
      .mockResolvedValueOnce(json({ items: [{ event_id:'event-3', occurred_at:'2026-08-07T09:00:00Z', kind:'login', action:'auth.login', reason_code:'credentials_accepted', result_code:'success', source_ip:'192.0.2.1', geo_code:'unknown', payload:{ password:'secret' } }], snapshot_at:'2026-08-07T10:00:00Z' }))
    const page = await observabilityLogsApi.list('token', { kinds:['login'], actorUserId:'11111111-1111-4111-8111-111111111111', action:'auth.login', from:'2026-08-07T08:00:00Z', to:'2026-08-07T10:00:00Z', limit:20 })
    expect(page.items[0].actor_user_display_id).toBe('1')
    const [input, init] = fetchSpy.mock.calls[0]
    const params = new URL(String(input), 'https://test').searchParams
    expect(params.get('kind')).toBe('login')
    expect(params.get('action')).toBe('auth.login')
    expect(params.get('actor_user_id')).toBe('11111111-1111-4111-8111-111111111111')
    expect(params.get('from')).toBe('2026-08-07T08:00:00Z')
    expect(params.get('to')).toBe('2026-08-07T10:00:00Z')
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
    await expect(observabilityLogsApi.list('token', { limit:20 })).rejects.toMatchObject({ code:'invalid_response' })
    await expect(observabilityLogsApi.list('token', { limit:20 })).rejects.toMatchObject({ code:'invalid_response' })
  })

  it('accepts a full 300-row page and rejects oversized requests and responses', async () => {
    const row = { event_id: 'event-1', occurred_at: '2026-08-07T09:00:00Z', kind: 'login', action: 'auth.login', reason_code: 'credentials_accepted', result_code: 'success', source_ip: '192.0.2.1', geo_code: 'unknown' }
    const items = Array.from({ length: 300 }, (_, index) => ({ ...row, event_id: `event-${index}` }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items, snapshot_at: '2026-08-07T10:00:00Z', total_count: 301, next_cursor: 'next' }))
      .mockResolvedValueOnce(json({ items: [...items, { ...row, event_id: 'event-300' }], snapshot_at: '2026-08-07T10:00:00Z' }))
    const page = await observabilityLogsApi.list('token', { kinds: ['login'], limit: 300 })
    expect(page.items).toHaveLength(300)
    expect(page.next_cursor).toBe('next')
    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://test').searchParams.get('limit')).toBe('300')
    await expect(observabilityLogsApi.list('token', { limit: 301 })).rejects.toMatchObject({ code: 'observability_logs_invalid_request' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    await expect(observabilityLogsApi.list('token', { limit: 300 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('uses the display ID query when the competitor-style numeric user ID is entered', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ items: [], snapshot_at: '2026-08-07T10:00:00Z', total_count: 0 }))
    await observabilityLogsApi.list('token', { kinds: ['login'], actorUserId: '1' })
    const params = new URL(String(fetchSpy.mock.calls[0][0]), 'https://test').searchParams
    expect(params.get('actor_user_display_id')).toBe('1')
    expect(params.get('actor_user_id')).toBeNull()
  })

  it('serializes the operation filters supported by the audit query contract', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ items: [], snapshot_at: '2026-08-07T10:00:00Z', total_count: 0 }))
    await observabilityLogsApi.list('token', {
      kinds: ['operation'], actorUserId: '1', actionVerb: 'update', resourceType: 'site', resourceId: 'site-1', change: 'revision',
    })
    const params = new URL(String(fetchSpy.mock.calls[0][0]), 'https://test').searchParams
    expect(params.get('kind')).toBe('operation')
    expect(params.get('actor_user_display_id')).toBe('1')
    expect(params.get('action_verb')).toBe('update')
    expect(params.get('resource_type')).toBe('site')
    expect(params.get('resource_id')).toBe('site-1')
    expect(params.get('change')).toBe('revision')
  })

  it('rejects invalid operation filters before issuing a request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(observabilityLogsApi.list('token', { resourceType: '站点' })).rejects.toMatchObject({ code: 'observability_logs_invalid_request' })
    await expect(observabilityLogsApi.list('token', { actionVerb: 'archive' as never })).rejects.toMatchObject({ code: 'observability_logs_invalid_request' })
    await expect(observabilityLogsApi.list('token', { change: `x`.repeat(257) })).rejects.toMatchObject({ code: 'observability_logs_invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('accepts structured change summaries and rejects the removed backup kind', async () => {
    const row = { event_id: 'op-1', occurred_at: '2026-08-07T09:00:00Z', kind: 'operation', action: 'site.update',
      reason_code: 'site.update', result_code: 'success', source_ip: '192.0.2.1', geo_code: 'unknown',
      change_summary: '{"status":"succeeded"}' }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [row], snapshot_at: '2026-08-07T10:00:00Z', total_count: 1 }))
      .mockResolvedValueOnce(json({ items: [{ ...row, kind: 'backup' }], snapshot_at: '2026-08-07T10:00:00Z', total_count: 1 }))
    const page = await observabilityLogsApi.list('token', { kinds: ['operation'] })
    expect(page.items[0].change_summary).toBe('{"status":"succeeded"}')
    // approval-center3：backup 不再是日志类型（旧高危操作中心已删），带 backup 的响应按非法拒绝。
    await expect(observabilityLogsApi.list('token', { kinds: ['operation'] })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts resolved login geography fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ items: [{
      event_id: 'login-geo-1', occurred_at: '2026-08-07T09:00:00Z', kind: 'login', action: 'auth.login',
      reason_code: 'credentials_accepted', result_code: 'success', source_ip: '192.0.2.1', geo_code: 'CN',
      geo_region: '湖南省', geo_city: '长沙市', geo_resolution: 'matched',
    }], snapshot_at: '2026-08-07T10:00:00Z' }))
    const page = await observabilityLogsApi.list('token', { kinds: ['login'] })
    expect(page.items[0]).toMatchObject({ geo_code: 'CN', geo_region: '湖南省', geo_city: '长沙市', geo_resolution: 'matched' })
  })

  it('accepts object names and the deleted marker, rejecting malformed ones (tp-b6b)', async () => {
    const row = { event_id: 'op-1', occurred_at: '2026-08-07T09:00:00Z', kind: 'operation', action: 'site.update',
      reason_code: 'site.update', result_code: 'success', source_ip: '192.0.2.1', geo_code: 'unknown', resource_type: 'site',
      resource_id: '7f3c2a1b-0000-4000-8000-000000000001' }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [{ ...row, resource_name: 'www.example.com' }, { ...row, event_id: 'op-2', resource_deleted: true }], snapshot_at: '2026-08-07T10:00:00Z', total_count: 2 }))
      .mockResolvedValueOnce(json({ items: [{ ...row, resource_name: 'evil\u0007name' }], snapshot_at: '2026-08-07T10:00:00Z' }))
      .mockResolvedValueOnce(json({ items: [{ ...row, resource_deleted: false }], snapshot_at: '2026-08-07T10:00:00Z' }))
    const page = await observabilityLogsApi.list('token', { kinds: ['operation'] })
    expect(page.items.map((item) => [item.resource_name, item.resource_deleted])).toEqual([['www.example.com', undefined], [undefined, true]])
    await expect(observabilityLogsApi.list('token', { kinds: ['operation'] })).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(observabilityLogsApi.list('token', { kinds: ['operation'] })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('posts only the stable frontend contract and downloads bounded CSV', async () => {
    const content = 'event_id\r\n'
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content)))].map((byte) => byte.toString(16).padStart(2, '0')).join('')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(null,{status:202})).mockResolvedValueOnce(new Response(content,{status:200,headers:{'Content-Type':'text/csv; charset=utf-8','X-Content-SHA256':digest}}))
    const targetScopeId = '22222222-2222-4222-8222-222222222222'
    await observabilityLogsApi.recordFrontend('token', { event_code:'render_error', route:'/home', reason_code:'component_failed', result_code:'failure', release:'2026.08.07' }, targetScopeId)
    const artifact = await observabilityLogsApi.exportCSV('token', { kinds:['frontend'] })
    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://test').searchParams.get('target_scope_id')).toBe(targetScopeId)
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).toEqual({ event_code:'render_error', route:'/home', reason_code:'component_failed', result_code:'failure', release:'2026.08.07' })
    expect(artifact.sha256).toBe(digest)
  })

  it('rejects a noncanonical frontend target before issuing a request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(observabilityLogsApi.recordFrontend('token', { event_code:'render_error', route:'/home', reason_code:'component_failed', result_code:'failure', release:'2026.08.07' }, 'PLATFORM')).rejects.toMatchObject({ code:'observability_logs_invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed when the CSV content does not match its digest', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('event_id\r\n',{status:200,headers:{'Content-Type':'text/csv; charset=utf-8','X-Content-SHA256':'a'.repeat(64)}}))
    await expect(observabilityLogsApi.exportCSV('token', {})).rejects.toMatchObject({ code:'invalid_response' })
  })
})
