import { vi } from 'vitest'

import {
  dnsReconcileApi,
  hasVerifiedDNSPropagation,
  type DNSReconcileCheckRequest,
  type DNSReconcileCommandIdentity,
  type DNSReconcileResult,
  type DNSReconcileTask,
} from '../api/dnsReconcile'

const tenantID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const zoneID = '33333333-3333-4333-8333-333333333333'
const taskID = '44444444-4444-4444-8444-444444444444'
const traceparent = '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01'

const check: DNSReconcileCheckRequest = {
  name: 'www.example.com',
  expected: [{ type: 'A', values: ['192.0.2.10'] }],
  authoritative_ns: ['ns1.example.net'],
  ttl: 300,
  propagation_started_at: '2026-08-04T00:00:00Z',
  propagation_window_seconds: 900,
  provider: {
    zone_id: zoneID,
    revision: 7,
    records: [{
      record_id: 'provider-record-1',
      name: 'www.example.com',
      type: 'A',
      value: '192.0.2.9',
      ttl: 300,
    }],
  },
}

const result: DNSReconcileResult = {
  tenant_id: tenantID,
  site_id: siteID,
  zone_id: zoneID,
  payload_digest: 'a'.repeat(64),
  plan: {
    tenant_id: tenantID,
    site_id: siteID,
    zone_id: zoneID,
    precondition_revision: 7,
    digest: 'b'.repeat(64),
    operations: [{
      sequence: 1,
      action: 'update',
      record_id: 'provider-record-1',
      name: 'www.example.com',
      type: 'A',
      value: '192.0.2.10',
      ttl: 300,
      previous_value: '192.0.2.9',
      previous_ttl: 300,
      reason: 'value_mismatch',
    }],
  },
  status: 'ready_to_commit',
  replayed: false,
  started_at: '2026-08-04T00:00:00Z',
  updated_at: '2026-08-04T00:02:00Z',
  ready_at: '2026-08-04T00:02:00Z',
  initial_revision: 7,
  provider_revision: 8,
  operations: [{
    source_sequence: 1,
    operation: {
      sequence: 1,
      action: 'update',
      record_id: 'provider-record-1',
      name: 'www.example.com',
      type: 'A',
      value: '192.0.2.10',
      ttl: 300,
      previous_value: '192.0.2.9',
      previous_ttl: 300,
      reason: 'value_mismatch',
    },
    client_request_id: 'provider-write-1',
    provider_request_id: 'provider-request-1',
    provider_record_id: 'provider-record-1',
    provider_revision: 8,
    status: 'succeeded',
    attempts: 1,
    error_class: '',
    error_code: '',
    report_sequence: 1,
  }],
  deferred_deletes: [],
  compensation_plan: [],
  propagation: [
    { number: 1, checked_at: '2026-08-04T00:01:00Z', status: 'healthy', consecutive_healthy: 1 },
    { number: 2, checked_at: '2026-08-04T00:02:00Z', status: 'healthy', consecutive_healthy: 2 },
  ],
  last_check: {
    name: 'www.example.com',
    status: 'healthy',
    compliant: true,
    checked_at: '2026-08-04T00:02:00Z',
    observations: [{
      role: 'authoritative',
      resolver: 'ns1.example.net',
      record_type: 'A',
      status: 'match',
      values: ['192.0.2.10'],
      cname_chain: [],
      attempts: 1,
      minimum_ttl: 300,
      error_code: '',
    }],
    repair_plan: {
      tenant_id: tenantID,
      site_id: siteID,
      zone_id: zoneID,
      precondition_revision: 8,
      digest: 'c'.repeat(64),
      operations: [],
    },
  },
  error_class: '',
  error_code: '',
}

const task: DNSReconcileTask = {
  id: taskID,
  tenant_id: tenantID,
  site_id: siteID,
  revision: 4,
  required_consecutive: 2,
  job: {
    id: taskID,
    kind: 'dns_reconcile',
    subject: 'www.example.com',
    state: 'running',
    attempt: 1,
    max_attempts: 5,
    progress: { total: 1, completed: 1, succeeded: 1, failed: 0, cancelled: 0, pending: 0 },
    created_at: '2026-08-04T00:00:00Z',
    started_at: '2026-08-04T00:00:01Z',
    updated_at: '2026-08-04T00:02:00Z',
  },
  request: check,
  result,
  created_at: '2026-08-04T00:00:00Z',
  updated_at: '2026-08-04T00:02:00Z',
  replayed: false,
}
const dryRunResult: DNSReconcileResult = { ...result, status: 'dry_run' }

function identity(action: string, revision: number): DNSReconcileCommandIdentity {
  return {
    idempotencyKey: `dns-reconcile-${action}-key`,
    requestID: `dns-reconcile-${action}-request`,
    traceparent,
    expectedRevision: revision,
  }
}

function response(value: unknown, status: number, requestID: string, etag?: string): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': requestID,
      ...(etag ? { ETag: etag } : {}),
    },
  }))
}

describe('dnsReconcileApi', () => {
  it('uses only the five mounted tenant routes with exact request identity and preconditions', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      calls.push({ url, init })
      const requestID = new Headers(init?.headers).get('X-Request-ID') ?? ''
      if (url.endsWith('/dry-run')) return response(dryRunResult, 200, requestID)
      if (url.endsWith('/apply')) return response(task, 202, requestID, '"4"')
      return response(task, 200, requestID, '"4"')
    })

    await dnsReconcileApi.dryRun('token', siteID, check, {
      requestID: 'dns-reconcile-dry-run-request', traceparent,
    })
    await dnsReconcileApi.apply('token', siteID, check, identity('apply', 7))
    await dnsReconcileApi.get('token', siteID, taskID, {
      requestID: 'dns-reconcile-get-request', traceparent,
    })
    await dnsReconcileApi.commit('token', siteID, taskID, identity('commit', 4))
    await dnsReconcileApi.cancel('token', siteID, taskID, identity('cancel', 4))

    expect(calls.map(({ url, init }) => `${init?.method ?? 'GET'} ${url}`)).toEqual([
      `POST /v1/sites/${siteID}/dns-reconcile/dry-run`,
      `POST /v1/sites/${siteID}/dns-reconcile/apply`,
      `GET /v1/sites/${siteID}/dns-reconcile/tasks/${taskID}`,
      `POST /v1/sites/${siteID}/dns-reconcile/tasks/${taskID}/commit`,
      `POST /v1/sites/${siteID}/dns-reconcile/tasks/${taskID}/cancel`,
    ])
    expect(calls.every(({ init }) => new Headers(init?.headers).get('Authorization') === 'Bearer token')).toBe(true)
    expect(calls.every(({ init }) => new Headers(init?.headers).get('traceparent') === traceparent)).toBe(true)
    expect(new Headers(calls[1].init?.headers).get('Idempotency-Key')).toBe('dns-reconcile-apply-key')
    expect(new Headers(calls[1].init?.headers).get('If-Match')).toBe('"7"')
    expect(new Headers(calls[3].init?.headers).get('If-Match')).toBe('"4"')
    expect(calls[0].init?.body).toBe(JSON.stringify(check))
    expect(calls[1].init?.body).toBe(JSON.stringify(check))
    expect(calls[3].init?.body).toBe('{}')
    expect(calls[4].init?.body).toBe('{}')
  })

  it.each(['apply', 'commit', 'cancel'] as const)(
    'lets callers retry an unknown %s outcome with byte-identical identity, headers, and body',
    async (operation) => {
      const calls: Array<{ url: string; headers: Headers; body: BodyInit | null | undefined }> = []
      vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        calls.push({ url: String(input), headers: new Headers(init?.headers), body: init?.body })
        const requestID = new Headers(init?.headers).get('X-Request-ID') ?? ''
        if (calls.length === 1) return response({
          error: { code: 'dns_reconcile_result_unknown', message: 'private provider detail', request_id: requestID },
        }, 503, requestID)
        return response(task, operation === 'apply' ? 202 : 200, requestID, '"4"')
      })
      const command = identity(operation, operation === 'apply' ? 7 : 4)
      const invoke = () => operation === 'apply'
        ? dnsReconcileApi.apply('token', siteID, check, command)
        : dnsReconcileApi[operation]('token', siteID, taskID, command)

      await expect(invoke()).rejects.toMatchObject({ status: 503, code: 'dns_reconcile_result_unknown' })
      await expect(invoke()).resolves.toEqual(task)
      expect(calls).toHaveLength(2)
      expect(calls[1].url).toBe(calls[0].url)
      expect(Object.fromEntries(calls[1].headers.entries())).toEqual(Object.fromEntries(calls[0].headers.entries()))
      expect(calls[1].body).toBe(calls[0].body)
      expect(JSON.stringify(calls)).not.toContain('private provider detail')
    },
  )

  it('rejects malformed or cross-scope success facts and never accepts provider success as propagation completion', async () => {
    const invalid: unknown[] = [
      { ...task, site_id: tenantID },
      { ...task, id: zoneID },
      { ...task, job: { ...task.job, id: zoneID } },
      { ...task, revision: 0 },
      { ...task, result: { ...result, tenant_id: siteID } },
      { ...task, result: { ...result, plan: { ...result.plan, site_id: tenantID } } },
      { ...task, result: { ...result, last_check: {
        ...result.last_check!, repair_plan: { ...result.last_check!.repair_plan, zone_id: taskID },
      } } },
      { ...task, result: { ...result, operations: [{ ...result.operations[0], status: 'accepted' }] } },
      { ...task, unexpected: true },
    ]
    for (const value of invalid) {
      vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => response(
        value, 200, new Headers(init?.headers).get('X-Request-ID') ?? '', '"4"',
      ))
      await expect(dnsReconcileApi.get('token', siteID, taskID, {
        requestID: 'dns-reconcile-invalid-response', traceparent,
      })).rejects.toMatchObject({ status: 0, code: 'response_invalid' })
    }

    expect(hasVerifiedDNSPropagation({
      ...task,
      result: { ...result, status: 'committed', propagation: [] },
    })).toBe(false)
    expect(hasVerifiedDNSPropagation({
      ...task,
      result: { ...result, status: 'committed' },
    })).toBe(true)
  })

  it('requires exact correlated headers, status, JSON shape, and duplicate-free bodies', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify(task), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'wrong', ETag: '"4"' },
    }))
    await expect(dnsReconcileApi.get('token', siteID, taskID, {
      requestID: 'dns-reconcile-header-request', traceparent,
    })).rejects.toMatchObject({ code: 'response_invalid' })

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify(task), {
      status: 200,
      headers: { 'Content-Type': 'text/plain', 'X-Request-ID': 'dns-reconcile-type-request', ETag: '"4"' },
    }))
    await expect(dnsReconcileApi.get('token', siteID, taskID, {
      requestID: 'dns-reconcile-type-request', traceparent,
    })).rejects.toMatchObject({ code: 'response_invalid' })

    const duplicate = JSON.stringify(task).replace(`"id":"${taskID}"`, `"id":"${taskID}","id":"${zoneID}"`)
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(duplicate, {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'dns-reconcile-duplicate-request', ETag: '"4"' },
    }))
    await expect(dnsReconcileApi.get('token', siteID, taskID, {
      requestID: 'dns-reconcile-duplicate-request', traceparent,
    })).rejects.toMatchObject({ code: 'response_invalid' })
  })

  it('maps exact error envelopes without exposing server messages', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => {
      const requestID = new Headers(init?.headers).get('X-Request-ID') ?? ''
      return response({
        error: { code: 'dns_reconcile_operation_in_flight', message: 'secret upstream provider row', request_id: requestID },
      }, 409, requestID)
    })

    const error = await dnsReconcileApi.cancel('token', siteID, taskID, identity('cancel-error', 4))
      .catch((value: unknown) => value)
    expect(error).toMatchObject({ status: 409, code: 'dns_reconcile_operation_in_flight' })
    expect(String(error)).not.toContain('secret upstream provider row')
    expect(JSON.stringify(error)).not.toContain('secret upstream provider row')
  })

  it.each([7, 9])('rejects UUIDv%s on the public tenant contract', async (version) => {
    const invalidSite = `22222222-2222-${version}222-8222-222222222222`
    await expect(dnsReconcileApi.get(
      'token', invalidSite, taskID, { requestID: `dns-reconcile-v${version}-request`, traceparent },
    )).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
  })

  it('rejects an idempotency key containing a colon before fetch', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')
    await expect(dnsReconcileApi.apply('token', siteID, check, {
      ...identity('apply-invalid-key', 7), idempotencyKey: 'dns-reconcile:invalid',
    })).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('rejects a non-dry-run status from the dry-run route', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => response(
      { ...result, status: 'committed' }, 200, new Headers(init?.headers).get('X-Request-ID') ?? '',
    ))
    await expect(dnsReconcileApi.dryRun('token', siteID, check, {
      requestID: 'dns-reconcile-wrong-dry-status', traceparent,
    })).rejects.toMatchObject({ status: 0, code: 'response_invalid' })
  })
})
