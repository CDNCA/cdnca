import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from './auth'
import {
  createOriginAuthEdgePublicationWriteMetadata,
  createOriginAuthPublicationWriteMetadata,
  originAuthPublicationsApi,
  type OriginAuthEdgePublication,
  type OriginAuthEdgePublicationWriteMetadata,
  type OriginAuthPublication,
  type OriginAuthPublicationWriteMetadata,
} from './originAuthPublications'

const scopeID = '22222222-2222-4222-8222-222222222222'
const publicationID = '11111111-1111-4111-8111-111111111111'
const ruleID = '33333333-3333-4333-8333-333333333333'
const siteID = '44444444-4444-4444-8444-444444444444'
const credentialRevisionID = '55555555-5555-4555-8555-555555555555'
const edgePublicationID = '66666666-6666-4666-8666-666666666666'
const configVersionID = '77777777-7777-4777-8777-777777777777'
const rolloutID = '88888888-8888-4888-8888-888888888888'
const nodeA = '99999999-9999-4999-8999-999999999999'
const nodeB = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const metadata: OriginAuthPublicationWriteMetadata = {
  idempotencyKey: 'origin-publication-1',
  requestID: 'request-1',
  traceID: 'trace-1',
}

const publication: OriginAuthPublication = {
  id: publicationID,
  tenant_scope_id: scopeID,
  revision: 1,
  snapshot_hash: 'a'.repeat(64),
  snapshot: {
    schema_version: 'cdnca.control.originauth-publication/v1',
    tenant_scope_id: scopeID,
    publication_revision: 1,
    rules: [{
      rule_id: ruleID,
      site_id: siteID,
      source_position: 1,
      provider: 's3',
      algorithm: 'aws4-hmac-sha256',
      endpoint: 'https://objects.example.test',
      bucket: 'tenant-assets',
      path_prefix: '/public',
      region: 'us-east-1',
      service: 's3',
      signature_ttl_seconds: 900,
      current_credential_revision_ref: credentialRevisionID,
      activate_current_at_unix: 1_786_060_800,
    }],
  },
  created_at: '2026-08-07T08:00:00Z',
}
const edgeRequest = {
  node_ids: [nodeA, nodeB],
  health_check: {
    activation_timeout_ms: 30_000,
    observation_window_ms: 10_000,
    required_consecutive_successes: 3,
  },
  deadline: '2026-08-08T12:00:00Z',
}
const edgeMetadata: OriginAuthEdgePublicationWriteMetadata = {
  idempotencyKey: 'origin-edge-publication-1',
  requestID: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  correlationID: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  traceparent: `00-${'d'.repeat(32)}-${'e'.repeat(16)}-01`,
  taskID: 'origin-edge-task-1',
}
const edgePublication: OriginAuthEdgePublication = {
  tenant_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  tenant_scope_id: scopeID,
  publication_id: edgePublicationID,
  source_publication_id: publicationID,
  source_revision: 1,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  config_snapshot_sha256: 'b'.repeat(64),
  artifact_manifest_sha256: 'c'.repeat(64),
  recipient_binding_sha256: 'd'.repeat(64),
  node_count: 2,
  created_at: '2026-08-08T10:00:00Z',
}
const retryBinding = {
  method: 'POST',
  path: `/v1/tenant-scopes/${scopeID}/origin-auth/edge-publications`,
  if_match: '"1"',
  idempotency_key: edgeMetadata.idempotencyKey,
  body_sha256: 'e'.repeat(64),
  request_id: edgeMetadata.requestID,
  correlation_id: edgeMetadata.correlationID,
  traceparent: edgeMetadata.traceparent,
  task_id: edgeMetadata.taskID,
}

function edgeJSON(value: unknown, status = 200, valueForHeaders: OriginAuthEdgePublication = edgePublication): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ETag: `"sha256-${valueForHeaders.artifact_manifest_sha256}"`,
      Location: `/v1/tenant-scopes/${scopeID}/origin-auth/edge-publications/${valueForHeaders.publication_id}`,
    },
  })
}

afterEach(() => vi.restoreAllMocks())

describe('originAuthPublicationsApi', () => {
  it('gets the latest exact secret-free snapshot and freezes every parsed level', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(publication), { status: 200 }),
    )

    const result = await originAuthPublicationsApi.getLatest('read-token', scopeID)

    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/tenant-scopes/${scopeID}/origin-auth/publications`,
      expect.objectContaining({
        credentials: 'include',
        headers: expect.objectContaining({ Authorization: 'Bearer read-token' }),
      }),
    )
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.snapshot)).toBe(true)
    expect(Object.isFrozen(result.snapshot.rules)).toBe(true)
    expect(Object.isFrozen(result.snapshot.rules[0])).toBe(true)
    expect(result).toEqual(publication)
    expect(JSON.stringify(result)).not.toMatch(/secret|access_key|session_token/i)
  })

  it('publishes an empty body with publication CAS and stable write metadata', async () => {
    const next = {
      ...publication,
      id: '66666666-6666-4666-8666-666666666666',
      revision: 2,
      previous_hash: publication.snapshot_hash,
      snapshot_hash: 'b'.repeat(64),
      snapshot: { ...publication.snapshot, publication_revision: 2 },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(next), { status: 201 }),
    )

    await expect(originAuthPublicationsApi.create(
      'manage-token', scopeID, 1, metadata,
    )).resolves.toEqual(next)

    const [path, init] = fetchSpy.mock.calls[0]!
    expect(path).toBe(`/v1/tenant-scopes/${scopeID}/origin-auth/publications`)
    expect(init).toEqual(expect.objectContaining({ method: 'POST', body: '{}' }))
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer manage-token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('If-Match')).toBe('"1"')
    expect(headers.get('Idempotency-Key')).toBe(metadata.idempotencyKey)
    expect(headers.get('X-Request-ID')).toBe(metadata.requestID)
    expect(headers.get('X-Trace-ID')).toBe(metadata.traceID)
  })

  it('uses quoted zero CAS for the first snapshot and creates bounded metadata', async () => {
    vi.spyOn(globalThis.crypto, 'randomUUID')
      .mockReturnValueOnce('77777777-7777-4777-8777-777777777777')
      .mockReturnValueOnce('88888888-8888-4888-8888-888888888888')
      .mockReturnValueOnce('99999999-9999-4999-8999-999999999999')
    const created = createOriginAuthPublicationWriteMetadata()
    expect(created).toEqual({
      idempotencyKey: '77777777-7777-4777-8777-777777777777',
      requestID: '88888888-8888-4888-8888-888888888888',
      traceID: '99999999-9999-4999-8999-999999999999',
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(publication), { status: 201 }),
    )

    await originAuthPublicationsApi.create('token', scopeID, 0, created)

    expect(new Headers(fetchSpy.mock.calls[0]?.[1]?.headers).get('If-Match')).toBe('"0"')
  })

  it('rejects extra, mismatched, malformed, unsafe, or secret-bearing snapshot fields', async () => {
    const rule = publication.snapshot.rules[0]!
    const invalidValues: unknown[] = [
      { ...publication, debug: true },
      { ...publication, id: 'not-a-uuid' },
      { ...publication, snapshot_hash: 'A'.repeat(64) },
      { ...publication, previous_hash: '' },
      { ...publication, created_at: '2026-02-30T00:00:00Z' },
      { ...publication, snapshot: { ...publication.snapshot, schema_version: 'v2' } },
      { ...publication, snapshot: { ...publication.snapshot, tenant_scope_id: siteID } },
      { ...publication, snapshot: { ...publication.snapshot, publication_revision: 2 } },
      { ...publication, snapshot: { ...publication.snapshot, secret: 'must-not-parse' } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, source_position: 0 }] } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, provider: 'aws' }] } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, algorithm: 'hmac' }] } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, endpoint: 'not a uri' }] } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, access_key: 'leak' }] } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, signature_ttl_seconds: 3601 }] } },
      { ...publication, snapshot: { ...publication.snapshot, rules: [{ ...rule, activate_current_at_unix: -1 }] } },
    ]
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const value of invalidValues) {
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(value), { status: 200 }))
      await expect(originAuthPublicationsApi.getLatest('token', scopeID)).rejects.toMatchObject({
        status: 0,
        code: 'invalid_response',
      })
    }
  })

  it('preserves stable server error codes without exposing the raw message', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: {
        code: 'revision_conflict',
        message: 'raw database conflict detail',
        request_id: 'request-safe-1',
        trace_id: 'trace-safe-1',
      },
    }), { status: 412 }))

    await expect(originAuthPublicationsApi.create('token', scopeID, 1, metadata)).rejects.toMatchObject({
      status: 412,
      code: 'revision_conflict',
      message: 'API request failed',
      requestId: 'request-safe-1',
    })
  })

  it('publishes to nodes separately from snapshot compilation with exact CAS and contract metadata', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(edgeJSON(edgePublication, 201))

    const result = await originAuthPublicationsApi.publishToNodes(
      'platform-token', scopeID, 1, edgeRequest, edgeMetadata,
    )

    expect(fetchSpy).toHaveBeenCalledOnce()
    const [path, init] = fetchSpy.mock.calls[0]!
    expect(path).toBe(`/v1/tenant-scopes/${scopeID}/origin-auth/edge-publications`)
    expect(init).toEqual(expect.objectContaining({
      method: 'POST', credentials: 'include', body: JSON.stringify(edgeRequest),
    }))
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer platform-token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('If-Match')).toBe('"1"')
    expect(headers.get('Idempotency-Key')).toBe(edgeMetadata.idempotencyKey)
    expect(headers.get('X-Request-ID')).toBe(edgeMetadata.requestID)
    expect(headers.get('X-Correlation-ID')).toBe(edgeMetadata.correlationID)
    expect(headers.get('Traceparent')).toBe(edgeMetadata.traceparent)
    expect(headers.get('X-Task-ID')).toBe(edgeMetadata.taskID)
    expect(headers.get('X-Step-Up-Proof')).toBeNull()
    expect(result).toEqual(edgePublication)
    expect(Object.isFrozen(result)).toBe(true)
    expect(JSON.stringify(result)).not.toMatch(/private|secret|ciphertext|recipient_key|wrapped_key/i)
  })

  it('reads an immutable node publication by exact tenant scope and publication identity', async () => {
    const readRequestID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(edgeJSON(edgePublication))

    await expect(originAuthPublicationsApi.getEdgePublication(
      'read-token', scopeID, edgePublicationID, readRequestID,
    )).resolves.toEqual(edgePublication)

    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/tenant-scopes/${scopeID}/origin-auth/edge-publications/${edgePublicationID}`,
      expect.objectContaining({
        credentials: 'include',
        headers: expect.objectContaining({ Authorization: 'Bearer read-token', 'X-Request-ID': readRequestID }),
      }),
    )
  })

  it('rejects malformed immutable rollout, artifact, target, and result identities', async () => {
    const invalidValues: unknown[] = [
      { ...edgePublication, targets: [nodeA, nodeB] },
      { ...edgePublication, artifacts: [{ ciphertext: 'secret' }] },
      { ...edgePublication, results: [{ node_id: nodeA, private_key: 'secret' }] },
      { ...edgePublication, tenant_scope_id: siteID },
      { ...edgePublication, publication_id: publicationID },
      { ...edgePublication, source_revision: 0 },
      { ...edgePublication, rollout_id: 'not-a-uuid' },
      { ...edgePublication, config_snapshot_sha256: 'B'.repeat(64) },
      { ...edgePublication, artifact_manifest_sha256: 'short' },
      { ...edgePublication, recipient_binding_sha256: 'short' },
      { ...edgePublication, node_count: 0 },
      { ...edgePublication, created_at: '2026-02-30T00:00:00Z' },
    ]
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const value of invalidValues) {
      fetchSpy.mockResolvedValueOnce(edgeJSON(value))
      await expect(originAuthPublicationsApi.getEdgePublication(
        'token', scopeID, edgePublicationID,
      )).rejects.toMatchObject({ status: 502, code: 'origin_auth_edge_publication_invalid_response' })
    }
  })

  it('rejects invalid node targets, health checks, deadlines, CAS, and metadata before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const invalidRequests = [
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 0, edgeRequest, edgeMetadata),
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 1, { ...edgeRequest, node_ids: [] }, edgeMetadata),
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 1, { ...edgeRequest, node_ids: [nodeA, nodeA] }, edgeMetadata),
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 1, {
        ...edgeRequest, health_check: { ...edgeRequest.health_check, activation_timeout_ms: 300_001 },
      }, edgeMetadata),
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 1, { ...edgeRequest, deadline: 'not-a-date' }, edgeMetadata),
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 1, edgeRequest, {
        ...edgeMetadata, correlationID: 'invalid',
      }),
      () => originAuthPublicationsApi.publishToNodes('token', scopeID, 1, edgeRequest, {
        ...edgeMetadata, traceparent: 'invalid',
      }),
    ]
    for (const request of invalidRequests) {
      await expect(request()).rejects.toMatchObject({
        status: 400,
        code: 'origin_auth_edge_publication_invalid_request',
      })
    }
    expect(fetchSpy).not.toHaveBeenCalled()

    const generated = createOriginAuthEdgePublicationWriteMetadata()
    expect(generated.idempotencyKey).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/)
    expect(generated.requestID).toMatch(/^[0-9a-f-]{36}$/)
    expect(generated.correlationID).toMatch(/^[0-9a-f-]{36}$/)
    expect(generated.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/)
    expect(generated.taskID).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
  })

  it('preserves a strict outcome-unknown retry binding without exposing raw server data', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(edgeJSON({ error: {
        code: 'origin_auth_edge_publication_outcome_unknown',
        message: 'raw transaction and encrypted artifact detail',
        request_id: edgeMetadata.requestID,
        retry: retryBinding,
      } }, 503))
      .mockResolvedValueOnce(edgeJSON({ error: {
        code: 'origin_auth_edge_publication_permission_denied',
        message: 'raw tenant and grant detail',
        request_id: edgeMetadata.requestID,
      } }, 403))

    const uncertain = await originAuthPublicationsApi.publishToNodes(
      'token', scopeID, 1, edgeRequest, edgeMetadata,
    ).catch((error: unknown) => error)
    expect(uncertain).toBeInstanceOf(ApiError)
    if (!(uncertain instanceof ApiError) || !('retry' in uncertain)) throw uncertain
    expect(uncertain).toMatchObject({
      status: 503,
      code: 'origin_auth_edge_publication_outcome_unknown',
      message: 'API request failed',
      requestId: edgeMetadata.requestID,
      retry: retryBinding,
    })
    expect(Object.isFrozen(uncertain.retry)).toBe(true)
    expect(String(uncertain)).not.toMatch(/transaction|encrypted artifact/i)

    const forbidden = await originAuthPublicationsApi.getEdgePublication(
      'token', scopeID, edgePublicationID,
    ).catch((error: unknown) => error)
    expect(forbidden).toMatchObject({
      status: 403,
      code: 'origin_auth_edge_publication_permission_denied',
      message: 'API request failed',
    })
    expect(String(forbidden)).not.toContain('raw tenant')
  })

  it('keeps the original node publication request caller-owned for exact retry or abandon', async () => {
    const attempt = Object.freeze({
      input: Object.freeze({ ...edgeRequest, node_ids: Object.freeze([...edgeRequest.node_ids]) }),
      metadata: Object.freeze({ ...edgeMetadata }),
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('response lost after commit'))
      .mockResolvedValueOnce(edgeJSON({ ...edgePublication, replayed: true }, 201, { ...edgePublication, replayed: true }))

    await expect(originAuthPublicationsApi.publishToNodes(
      'token', scopeID, 1, attempt.input, attempt.metadata,
    )).rejects.toMatchObject({ status: 0, code: 'origin_auth_edge_publication_outcome_unknown' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    await expect(originAuthPublicationsApi.publishToNodes(
      'token', scopeID, 1, attempt.input, attempt.metadata,
    )).resolves.toMatchObject({ publication_id: edgePublicationID, replayed: true })
    expect(fetchSpy.mock.calls[1]?.[0]).toBe(fetchSpy.mock.calls[0]?.[0])
    expect(fetchSpy.mock.calls[1]?.[1]?.body).toBe(fetchSpy.mock.calls[0]?.[1]?.body)
    expect(Object.fromEntries(new Headers(fetchSpy.mock.calls[1]?.[1]?.headers)))
      .toEqual(Object.fromEntries(new Headers(fetchSpy.mock.calls[0]?.[1]?.headers)))

    let pending: typeof attempt | undefined = attempt
    pending = undefined
    await Promise.resolve()
    expect(pending).toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })
})
