import { openrestySecurityApi, type OpenRestySecurityDocument } from './openrestySecurity'

const document: OpenRestySecurityDocument = {
  id: '11111111-1111-4111-8111-111111111111', scope_type: 'global', scope_id: '0', revision: 4,
  config: {
    cc_enable: true, block_time: 3600, white_time: 21600, default_block_way: 'exit',
    waf_enable: true,
    waf_resource_limits: {
      candidate_per_param: 2048, candidate_per_request: 4096, ffi_per_request: 8192,
      json_max_leaves: 2048, json_max_nodes: 9216, json_max_depth: 64,
      json_max_string_bytes: 262144, json_body_bytes: 1048576, multipart_max_parts: 128,
      body_scan_bytes: 16777216,
    },
  },
  key_configured: true, updated_at: '2026-09-13T01:02:03Z',
}

describe('openrestySecurityApi', () => {
  afterEach(() => vi.restoreAllMocks())

  it('reads a strict redacted global document', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(document), { status: 200 }))
    await expect(openrestySecurityApi.getGlobal('token')).resolves.toEqual(document)
  })

  it('writes the smallest patch with CAS and stable identity headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...document, revision: 5 }), { status: 200 }))
    await openrestySecurityApi.patchGlobal('token', 4, { cc_enable: false }, { requestId: 'request-1', idempotencyKey: 'attempt-1' })
    const [, init] = fetchSpy.mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(init?.method).toBe('PATCH')
    expect(headers.get('If-Match')).toBe('"4"')
    expect(headers.get('Idempotency-Key')).toBe('attempt-1')
    expect(headers.get('X-Request-ID')).toBe('request-1')
    expect(JSON.parse(String(init?.body))).toEqual({ patch: { cc_enable: false } })
  })

  it('never accepts a secret returned in a document', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      ...document, config: { ...document.config, key: 'must-not-be-returned' },
    }), { status: 200 }))
    await expect(openrestySecurityApi.getGlobal('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('validates override pages and queues image download without parsing an empty response', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [], page: 1, page_size: 20, total: 0 }), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }))
    await expect(openrestySecurityApi.listOverrides('token')).resolves.toEqual({ items: [], page: 1, page_size: 20, total: 0 })
    await expect(openrestySecurityApi.queueCCImageDownload('token', { requestId: 'request-2', idempotencyKey: 'attempt-2' })).resolves.toBeUndefined()
    expect(new Headers(fetchSpy.mock.calls[1]?.[1]?.headers).get('Idempotency-Key')).toBe('attempt-2')
  })

  it('accepts only redacted CC rule-group metadata and rejects rule payload leakage', async () => {
    const groups = [{ id: '10002', name: '关闭', enabled: true, kind: 'system', system_rule: true, sort: 1 }]
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(groups), { status: 200 }))
    await expect(openrestySecurityApi.listRuleGroups('token')).resolves.toEqual(groups)

    vi.restoreAllMocks()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify([
      { ...groups[0], matcher: { field: 'path', values: ['/secret'] } },
    ]), { status: 200 }))
    await expect(openrestySecurityApi.listRuleGroups('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
