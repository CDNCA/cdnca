import { jobsApi, type BackgroundJob, type JobListResponse } from '../api/jobs'

const job: BackgroundJob = {
  task_id: 'a0000000-0000-4000-8000-000000000001',
  tenant_id: 'b0000000-0000-4000-8000-000000000002',
  kind: 'cache.purge',
  related_resource: { reference: 'site:example.test' },
  request_id: 'request-1',
  trace_id: 'trace-1',
  status: 'partial_failed',
  attempt: 2,
  max_attempts: 3,
  progress: { total: 3, completed: 3, succeeded: 2, failed: 1, cancelled: 0, pending: 0 },
  failure_code: 'node_unavailable',
  created_at: '2026-07-22T08:00:00Z',
  started_at: '2026-07-22T08:01:00Z',
  updated_at: '2026-07-22T08:02:00Z',
  completed_at: '2026-07-22T08:02:00Z',
  revision: '7',
}

function withJobState(status: BackgroundJob['status']): BackgroundJob {
  const value = { ...job, status }
  if (status === 'queued' || status === 'running') delete value.completed_at
  if (status === 'queued' || status === 'running' || status === 'succeeded') {
    delete value.failure_code
  } else if (status === 'cancelled') {
    value.failure_code = 'cancelled'
  }
  return value
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function listResponse(overrides: Partial<JobListResponse> = {}): JobListResponse {
  return {
    data: [job],
    page: { next_cursor: 'opaque cursor+/=' },
    query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
    ...overrides,
  }
}

describe('jobsApi', () => {
  it('requests numbered pages and preserves snapshot totals and task metadata', async () => {
    const response = {
      data: [{ ...job, kind: 'cache.operation' }],
      page: { number: 2, limit: 10, total: 11, total_pages: 2, consistency: 'request_snapshot' },
      query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
      task_metadata: [{
        task_id: job.task_id,
        name: { name_key: 'jobs.kindNames.cacheOperation', resource: job.related_resource.reference, source: 'derived' },
        priority: { policy: 'producer_managed' },
        dependencies: { state: 'unknown', items: [] },
      }],
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(jobsApi.list('access-token', 'platform', {
      from: response.query.from, to: response.query.to, limit: 10, page: 2,
    })).resolves.toEqual(response)

    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test')
    expect(url.searchParams.get('page')).toBe('2')
    expect(url.searchParams.has('cursor')).toBe(false)
  })

  it('loads a scope-specific task kind directory independently of list data', async () => {
    const response = { data: [{
      kind: 'cache.operation', name_key: 'jobs.kindNames.cacheOperation',
      integration: 'integrated', runtime_status: 'unknown',
    }] }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(response))

    await expect(jobsApi.kinds('token-a', 'platform')).resolves.toEqual(response)
    await expect(jobsApi.kinds('token-b', 'tenant')).resolves.toEqual(response)

    expect(fetchSpy.mock.calls.map(([input]) => String(input))).toEqual(['/v1/admin/jobs/kinds', '/v1/jobs/kinds'])
    expect(fetchSpy.mock.calls[1][1]).toMatchObject({ credentials: 'include', headers: { Authorization: 'Bearer token-b' } })
  })

  it('keeps empty and out-of-range numbered pages honest and rejects mixed pagination requests', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [], task_metadata: [],
      page: { number: 2, limit: 10, total: 0, total_pages: 0, consistency: 'request_snapshot' },
      query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
    }))
    const params = { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z', limit: 10, page: 2 }
    await expect(jobsApi.list('token', 'platform', params)).resolves.toMatchObject({ page: { number: 2, total: 0 } })
    await expect(jobsApi.list('token', 'platform', { ...params, cursor: 'cannot-mix' }))
      .rejects.toMatchObject({ status: 400, code: 'job_invalid_request' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('accepts a real CNAME completion dependency without changing the base job representation', async () => {
    const baseJob = { ...job, kind: 'dns.cname.allocation' }
    const response = {
      data: [baseJob],
      page: { number: 1, limit: 10, total: 1, total_pages: 1, consistency: 'request_snapshot' },
      query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
      task_metadata: [{
        task_id: job.task_id,
        name: { name_key: 'jobs.kindNames.cnameAllocation', resource: job.related_resource.reference, source: 'derived' },
        priority: { policy: 'ready_fifo' },
        dependencies: { state: 'observed', items: [{ task_id: 'c0000000-0000-4000-8000-000000000003', relation: 'completion', status: 'succeeded' }] },
      }],
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    await expect(jobsApi.list('token', 'tenant', { ...response.query, limit: 10, page: 1 }))
      .resolves.toMatchObject({ data: [baseJob], task_metadata: response.task_metadata })
  })

  it('accepts a recorded no-dependency fact only for integrated kinds without a dependency relation', async () => {
    const metadata = (kind: string, nameKey: string) => ({
      data: [{ ...job, kind }],
      page: { number: 1, limit: 10, total: 1, total_pages: 1, consistency: 'request_snapshot' },
      query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
      task_metadata: [{
        task_id: job.task_id,
        name: { name_key: nameKey, resource: job.related_resource.reference, source: 'derived' },
        priority: { policy: kind === 'cache.operation' ? 'producer_managed' : 'ready_fifo' },
        dependencies: { state: 'none', items: [] },
      }],
    })
    const params = { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z', limit: 10, page: 1 }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(metadata('cache.operation', 'jobs.kindNames.cacheOperation')))
      .mockResolvedValueOnce(json(metadata('dns.cname.allocation', 'jobs.kindNames.cnameAllocation')))
      .mockResolvedValueOnce(json(metadata('future.kind', 'jobs.kindNames.unknown')))
    await expect(jobsApi.list('token', 'platform', params)).resolves.toMatchObject({
      task_metadata: [{ dependencies: { state: 'none', items: [] } }],
    })
    await expect(jobsApi.list('token', 'platform', params)).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(jobsApi.list('token', 'platform', params)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts item start time and failure count facts and rejects inconsistent ones', async () => {
    const item = {
      ordinal: 1, item_id: 'node-1', status: 'failed', attempt: 2, sequence: 4, failure_code: 'node_unavailable',
      started_at: '2026-07-22T08:01:00Z', completed_at: '2026-07-22T08:02:00Z', failure_count: 2,
    }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: [item], page: {} }))
      .mockResolvedValueOnce(json({ data: [{ ...item, failure_count: -1 }], page: {} }))
      .mockResolvedValueOnce(json({ data: [{ ...item, started_at: '2026-07-22T08:03:00Z' }], page: {} }))
      .mockResolvedValueOnce(json({ data: [{ ordinal: 1, item_id: 'node-1', status: 'pending', attempt: 0, sequence: 0, started_at: '2026-07-22T08:01:00Z', failure_count: 0 }], page: {} }))
    await expect(jobsApi.results('token', 'platform', job.task_id, 10)).resolves.toMatchObject({ data: [item] })
    for (let index = 0; index < 3; index += 1) {
      await expect(jobsApi.results('token', 'platform', job.task_id, 10)).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it.each([
    { dependencies: { state: 'none', items: [{ task_id: 'c0000000-0000-4000-8000-000000000003', relation: 'completion', status: 'succeeded' }] } },
    { task_id: 'a0000000-0000-4000-8000-000000000009' },
    { name: { name_key: 'jobs.kindNames.unknown', resource: job.related_resource.reference, source: 'derived' } },
    { name: { name_key: 'jobs.kindNames.cacheOperation', resource: 'private-other-resource', source: 'derived' } },
    { name: { name_key: 'jobs.kindNames.cacheOperation', resource: job.related_resource.reference, source: 'stored' } },
    { priority: { policy: 'ready_fifo', priority: 20 } },
    { dependencies: { state: 'observed', items: [] } },
    { dependencies: { state: 'unknown', items: [{ task_id: 'c0000000-0000-4000-8000-000000000003', relation: 'completion', status: 'succeeded' }] } },
    { dependencies: { state: 'observed', items: [{ task_id: job.task_id, relation: 'completion', status: 'succeeded' }] } },
  ])('rejects task metadata that is unbound, fabricated, or inconsistent', async (override) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [{ ...job, kind: 'cache.operation' }],
      page: { number: 1, limit: 10, total: 1, total_pages: 1, consistency: 'request_snapshot' },
      query: { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z' },
      task_metadata: [{
        task_id: job.task_id,
        name: { name_key: 'jobs.kindNames.cacheOperation', resource: job.related_resource.reference, source: 'derived' },
        priority: { policy: 'producer_managed' }, dependencies: { state: 'unknown', items: [] },
        ...override,
      }],
    }))
    await expect(jobsApi.list('token', 'platform', {
      from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z', limit: 10, page: 1,
    })).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    { kind: 'cache.operation', name_key: 'private.sql', integration: 'integrated', runtime_status: 'unknown' },
    { kind: 'cache.operation', name_key: 'jobs.kindNames.cacheOperation', integration: 'integrated', runtime_status: 'ready' },
    { kind: 'cache.operation', name_key: 'jobs.kindNames.cacheOperation', integration: 'integrated', runtime_status: 'unknown', secret: 'unexpected' },
  ])('rejects unsupported or expanded task catalog facts', async (entry) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: [entry] }))
    await expect(jobsApi.kinds('token', 'platform')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    { number: 0, limit: 10, total: 1, total_pages: 1, consistency: 'request_snapshot' },
    { number: 1, limit: 10, total: -1, total_pages: 1, consistency: 'request_snapshot' },
    { number: 1, limit: 10, total: 1, total_pages: 2, consistency: 'request_snapshot' },
    { number: 1, limit: 10, total: 1, total_pages: 1, consistency: 'estimated' },
    { number: 1, limit: 10, total: 1, total_pages: 1, consistency: 'request_snapshot', next_cursor: 'not-both' },
  ])('rejects invalid numbered-page metadata', async (page) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...listResponse(), page, task_metadata: [] }))
    await expect(jobsApi.list('token', 'platform', {
      from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z', limit: 10, page: 1,
    })).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('encodes platform list filters and opaque cursors without leaking them into headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(listResponse()))

    await expect(jobsApi.list('access-token', 'platform', {
      from: '2026-07-22T00:00:00Z',
      to: '2026-07-23T00:00:00Z',
      statuses: ['running', 'partial_failed'],
      kind: 'cache.purge',
      resource: 'site:example.test/path?a=1&b=2',
      limit: 20,
      cursor: 'opaque cursor+/=',
    })).resolves.toEqual(listResponse())

    const [input, init] = fetchSpy.mock.calls[0]
    const url = new URL(String(input), 'https://web.test')
    expect(url.pathname).toBe('/v1/admin/jobs')
    expect(url.searchParams.get('from')).toBe('2026-07-22T00:00:00Z')
    expect(url.searchParams.get('to')).toBe('2026-07-23T00:00:00Z')
    expect(url.searchParams.get('status')).toBe('running,partial_failed')
    expect(url.searchParams.get('kind')).toBe('cache.purge')
    expect(url.searchParams.get('resource')).toBe('site:example.test/path?a=1&b=2')
    expect(url.searchParams.get('limit')).toBe('20')
    expect(url.searchParams.get('cursor')).toBe('opaque cursor+/=')
    expect(init).toEqual(expect.objectContaining({
      credentials: 'include',
      headers: { Authorization: 'Bearer access-token' },
    }))
  })

  it('uses the tenant list audience without changing the exact filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(listResponse()))

    await jobsApi.list('access-token', 'tenant', {
      from: '2026-07-22T00:00:00Z',
      to: '2026-07-23T00:00:00Z',
      limit: 20,
    })

    expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://web.test').pathname).toBe('/v1/jobs')
  })

  it('uses the platform read-only detail, attempt, and result endpoints', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: job }))
      .mockResolvedValueOnce(json({
        data: [{
          number: 2,
          status: 'partial_failed',
          started_at: '2026-07-22T08:01:00Z',
          last_heartbeat_at: '2026-07-22T08:01:30Z',
          lease_expires_at: '2026-07-22T08:02:30Z',
          completed_at: '2026-07-22T08:02:00Z',
          failure_code: 'node_unavailable',
        }],
        page: { next_cursor: 'attempt-next' },
      }))
      .mockResolvedValueOnce(json({
        data: [{
          ordinal: 1,
          item_id: 'node-1',
          node_id: '30000000-0000-4000-8000-000000000003',
          status: 'failed',
          attempt: 2,
          sequence: 4,
          failure_code: 'node_unavailable',
          completed_at: '2026-07-22T08:02:00Z',
        }],
        page: {},
      }))

    await jobsApi.detail('token', 'platform', job.task_id)
    await jobsApi.attempts('token', 'platform', job.task_id, 20, 'attempt cursor')
    await jobsApi.results('token', 'platform', job.task_id, 20)

    expect(String(fetchSpy.mock.calls[0][0])).toBe(`/v1/admin/jobs/${job.task_id}`)
    expect(String(fetchSpy.mock.calls[1][0])).toContain(`/v1/admin/jobs/${job.task_id}/attempts?`)
    expect(new URL(String(fetchSpy.mock.calls[1][0]), 'https://web.test').searchParams.get('cursor')).toBe('attempt cursor')
    expect(String(fetchSpy.mock.calls[2][0])).toContain(`/v1/admin/jobs/${job.task_id}/results?`)
    for (const [, init] of fetchSpy.mock.calls) expect(init?.method).toBeUndefined()
  })

  it('posts exact platform cancel and tenant retry commands and parses replay facts', async () => {
    const cancelled = withJobState('cancelled')
    const retried = withJobState('queued')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: cancelled, replayed: false }))
      .mockResolvedValueOnce(json({ data: retried, replayed: true }))

    await expect(jobsApi.cancel('token', 'platform', job.task_id, 'cancel-key', job.revision)).resolves.toEqual({
      data: cancelled, replayed: false,
    })
    await expect(jobsApi.retry('token', 'tenant', job.task_id, 'retry-key', job.attempt, job.revision)).resolves.toEqual({
      data: retried, replayed: true,
    })

    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(String(fetchSpy.mock.calls[0][0])).toBe(`/v1/admin/jobs/${job.task_id}/cancel`)
    expect(String(fetchSpy.mock.calls[1][0])).toBe(`/v1/jobs/${job.task_id}/retry`)
    expect(fetchSpy.mock.calls[0][1]).toEqual({
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer token',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'cancel-key',
        'If-Match': '"7"',
      },
      body: '{}',
    })
    expect(fetchSpy.mock.calls[1][1]).toEqual({
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer token',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'retry-key',
        'If-Match': '"7"',
      },
      body: '{}',
    })
  })

  it.each([
    { label: 'an already claimed retry', data: { ...withJobState('running'), attempt: 3 } },
    { label: 'a changed retry attempt', data: { ...withJobState('queued'), attempt: 1 } },
    {
      label: 'a changed task identity',
      data: { ...withJobState('queued'), task_id: 'a0000000-0000-4000-8000-000000000009' },
    },
  ])('rejects a retry receipt with $label', async ({ data }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data, replayed: false }))

	await expect(jobsApi.retry('token', 'tenant', job.task_id, 'retry-key', job.attempt, job.revision))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    { label: 'a queued job', data: withJobState('queued') },
    { label: 'a running job', data: withJobState('running') },
    { label: 'a succeeded job', data: withJobState('succeeded') },
    {
      label: 'a changed task identity',
      data: { ...withJobState('cancelled'), task_id: 'a0000000-0000-4000-8000-000000000009' },
    },
  ])('rejects a cancel receipt with $label', async ({ data }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data, replayed: false }))

	await expect(jobsApi.cancel('token', 'platform', job.task_id, 'cancel-key', job.revision))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    { label: 'missing replay fact', body: { data: job } },
    { label: 'non-boolean replay fact', body: { data: job, replayed: 'false' } },
    { label: 'extra command field', body: { data: job, replayed: false, request_id: 'private' } },
    { label: 'invalid command job', body: { data: { ...job, status: 'retrying' }, replayed: false } },
  ])('rejects a strict command response with $label', async ({ body }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))

	await expect(jobsApi.cancel('token', 'platform', job.task_id, 'cancel-key', job.revision))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it.each([
    ['job_idempotency_conflict', 409],
    ['job_invalid_transition', 409],
    ['job_retries_exhausted', 409],
		['job_revision_conflict', 412],
    ['job_permission_denied', 403],
    ['job_scope_forbidden', 403],
    ['job_not_found', 404],
    ['job_store_unavailable', 503],
  ])('preserves stable command error %s without private detail', async (code, status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code, message: 'private command detail', request_id: 'jobs-command-1' },
    }, status))

	await expect(jobsApi.retry('token', 'tenant', job.task_id, 'retry-key', job.attempt, job.revision)).rejects.toMatchObject({
      message: 'API request failed', status, code, requestId: 'jobs-command-1',
    })
  })

  it.each([
    { label: 'extra job field', body: listResponse({ data: [{ ...job, payload: 'secret' } as BackgroundJob] }) },
    { label: 'uppercase task UUID', body: listResponse({ data: [{ ...job, task_id: job.task_id.toUpperCase() }] }) },
    { label: 'collapsed partial failure', body: listResponse({ data: [{ ...job, status: 'partial' as never }] }) },
    { label: 'invalid progress', body: listResponse({ data: [{ ...job, progress: { ...job.progress, total: 0 } }] }) },
    { label: 'attempt beyond maximum', body: listResponse({ data: [{ ...job, attempt: 4 }] }) },
    { label: 'maximum attempt limit exceeded', body: listResponse({ data: [{ ...job, max_attempts: 1002 }] }) },
		{ label: 'missing revision', body: listResponse({ data: [{ ...job, revision: undefined } as unknown as BackgroundJob] }) },
		{ label: 'weak revision', body: listResponse({ data: [{ ...job, revision: 'W/"7"' }] }) },
    {
      label: 'completed progress mismatch',
      body: listResponse({ data: [{
        ...job,
        progress: { ...job.progress, completed: 2, pending: 1 },
      }] }),
    },
    {
      label: 'total progress mismatch',
      body: listResponse({ data: [{ ...job, progress: { ...job.progress, total: 4 } }] }),
    },
    { label: 'updated before creation', body: listResponse({ data: [{ ...job, updated_at: '2026-07-22T07:59:00Z' }] }) },
    { label: 'started before creation', body: listResponse({ data: [{ ...job, started_at: '2026-07-22T07:59:00Z' }] }) },
    { label: 'queued with completion', body: listResponse({ data: [{ ...withJobState('queued'), completed_at: job.completed_at }] }) },
    { label: 'running with completion', body: listResponse({ data: [{ ...withJobState('running'), completed_at: job.completed_at }] }) },
    { label: 'succeeded without completion', body: listResponse({ data: [{ ...withJobState('succeeded'), completed_at: undefined }] }) },
    { label: 'partial failure without completion', body: listResponse({ data: [{ ...job, completed_at: undefined }] }) },
    { label: 'failure without completion', body: listResponse({ data: [{ ...withJobState('failed'), completed_at: undefined }] }) },
    { label: 'cancellation without completion', body: listResponse({ data: [{ ...withJobState('cancelled'), completed_at: undefined }] }) },
    { label: 'completion before update', body: listResponse({ data: [{ ...job, completed_at: '2026-07-22T08:01:00Z' }] }) },
    { label: 'running with zero attempt', body: listResponse({ data: [{ ...withJobState('running'), attempt: 0 }] }) },
    { label: 'queued with failure code', body: listResponse({ data: [{ ...withJobState('queued'), failure_code: 'node_unavailable' }] }) },
    { label: 'running with failure code', body: listResponse({ data: [{ ...withJobState('running'), failure_code: 'node_unavailable' }] }) },
    { label: 'succeeded with failure code', body: listResponse({ data: [{ ...withJobState('succeeded'), failure_code: 'node_unavailable' }] }) },
    { label: 'partial failure without failure code', body: listResponse({ data: [{ ...job, failure_code: undefined }] }) },
    { label: 'failure without failure code', body: listResponse({ data: [{ ...withJobState('failed'), failure_code: undefined }] }) },
    { label: 'cancellation without failure code', body: listResponse({ data: [{ ...withJobState('cancelled'), failure_code: undefined }] }) },
    { label: 'cancellation with wrong failure code', body: listResponse({ data: [{ ...withJobState('cancelled'), failure_code: 'node_unavailable' }] }) },
    { label: 'extra page field', body: { ...listResponse(), page: { next_cursor: 'next', total: 9 } } },
  ])('rejects a strict response with $label', async ({ body }) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))

    await expect(jobsApi.list('token', 'platform', {
      from: '2026-07-22T00:00:00Z',
      to: '2026-07-23T00:00:00Z',
      limit: 20,
    })).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('keeps stable errors and discards private server or network detail', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        error: { code: 'job_store_unavailable', message: 'private primary host', request_id: 'jobs-request-1' },
      }, 503))
      .mockResolvedValueOnce(json({
        error: { code: 'NOT_STABLE', message: 'private SQL query' },
      }, 502))
      .mockRejectedValueOnce(new Error('private network address'))

    const params = { from: '2026-07-22T00:00:00Z', to: '2026-07-23T00:00:00Z', limit: 20 }
    await expect(jobsApi.list('token', 'platform', params)).rejects.toMatchObject({
      message: 'API request failed', status: 503, code: 'job_store_unavailable', requestId: 'jobs-request-1',
    })
    await expect(jobsApi.list('token', 'platform', params)).rejects.toMatchObject({
      message: 'API request failed', status: 502, code: 'request_failed',
    })
    await expect(jobsApi.list('token', 'platform', params)).rejects.toMatchObject({
      message: 'Network request failed', status: 0, code: 'network_error',
    })
  })
})
