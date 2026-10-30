import { describe, expect, it, vi } from 'vitest'

import { errorPagesApi } from './errorPages'

const scopeID = '22222222-2222-4222-8222-222222222222'
const tenantID = '99999999-9999-4999-8999-999999999999'
const assetID = '11111111-1111-4111-8111-111111111111'
const ruleID = '33333333-3333-4333-8333-333333333333'
const publicationID = '66666666-6666-4666-8666-666666666666'
const configVersionID = '77777777-7777-4777-8777-777777777777'
const rolloutID = '88888888-8888-4888-8888-888888888888'
const snapshotID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const nodeID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const secondNodeID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const asset = {
  id: assetID, scope_id: scopeID, name: '维护页.html', mime_type: 'text/html', size_bytes: 4, sha256: 'a'.repeat(64),
  status: 'ready', scan_status: 'passed', revision: 2,
  created_by: '44444444-4444-4444-8444-444444444444', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}
const rule = {
  id: ruleID,
  target: { kind: 'site', scope_id: scopeID, site_id: '55555555-5555-4555-8555-555555555555' },
  fields: { category: 'origin_response', match: { kind: 'exact', from: 404, to: 404 }, asset_id: assetID, enabled: true },
  priority: 1, revision: 4, deleted: false,
  created_by: '44444444-4444-4444-8444-444444444444', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}
const resourceDigest = 'b'.repeat(64)
const edgeRule = {
  id: 'global-origin-404', category: 'origin_response', match: { codes: [404] },
  resource: { mime_type: 'text/html', size_bytes: 4, sha256: resourceDigest, file: `sha256/${resourceDigest}` },
}
const publicationSnapshot = {
  policy: {
    schema: 'cdnca.error-pages/v1', version: '2026.08.08', revision: 7,
    global: { rules: [edgeRule] },
    sites: [{
      site_key: 'site-55555555-5555-4555-8555-555555555555',
      rules: [{ ...edgeRule, id: 'site-connect-500-504', category: 'edge_connect', match: { ranges: [{ from: 500, to: 504 }] } }],
    }],
  },
  snapshot_sha256: 'c'.repeat(64),
  created_at: '2026-08-08T01:02:03Z',
}

type PublicationTargetRequest =
  | { kind: 'nodes'; node_ids: string[] }
  | { kind: 'line_group_snapshot'; snapshot_id: string; revision: number; resolver_sha256: string }
type PublicationRequest = {
  target: PublicationTargetRequest
  health_check: { activation_timeout_ms: number; observation_window_ms: number; required_consecutive_successes: number }
  max_attempts: number
  deadline: string
}
type PublicationWriteMetadata = {
  requestId: string
  correlationId?: string
  idempotencyKey: string
  traceparent: string
  taskId?: string
}
type PublicationReceipt = {
  tenant_id: string
  tenant_scope_id: string
  publication_id: string
  source_revision: number
  error_page_publication_revision: number
  config_version_id: string
  rollout_id: string
  artifact_sha256: string
  target: { kind: 'explicit' | 'resolver'; snapshot_id?: string; revision?: number; resolver_sha256?: string; resolved_sha256: string }
  node_count: number
  created_at: string
  replayed?: boolean
}
type PublicationRetryBinding = {
  method: 'POST'
  path: string
  if_match: string
  idempotency_key: string
  body_sha256: string
}
type PublicationApiError = Error & {
  status: number
  code: string
  requestId?: string
  retry?: PublicationRetryBinding
}
type PublicationApi = typeof errorPagesApi & {
  publishErrorPageConfiguration(token: string, scopeId: string, sourceRevision: number, input: PublicationRequest, metadata: PublicationWriteMetadata): Promise<PublicationReceipt>
  getErrorPagePublication(token: string, scopeId: string, publicationId: string, requestId?: string): Promise<PublicationReceipt>
}

const publicationApi = errorPagesApi as PublicationApi
const resolverDigest = 'd'.repeat(64)
const artifactDigest = 'e'.repeat(64)
const publicationInput: PublicationRequest = {
  target: { kind: 'nodes', node_ids: [nodeID, secondNodeID] },
  health_check: { activation_timeout_ms: 60_000, observation_window_ms: 30_000, required_consecutive_successes: 3 },
  max_attempts: 5,
  deadline: '2026-08-08T10:00:00Z',
}
const publicationMetadata: PublicationWriteMetadata = {
  requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  correlationId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  idempotencyKey: 'error-page-publication-8',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
  taskId: 'error-page-publication-task-8',
}
const publicationReceipt: PublicationReceipt = {
  tenant_id: tenantID,
  tenant_scope_id: scopeID,
  publication_id: publicationID,
  source_revision: 8,
  error_page_publication_revision: 3,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  artifact_sha256: artifactDigest,
  target: { kind: 'explicit', resolved_sha256: resolverDigest },
  node_count: 2,
  created_at: '2026-08-08T09:00:00Z',
  replayed: false,
}

function json(value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

async function textSha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

describe('errorPagesApi', () => {
  it('rejects unsupported MIME, size, digest, and status shapes', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    for (const invalid of [
      { ...asset, mime_type: 'image/svg+xml' },
      { ...asset, size_bytes: 0 },
      { ...asset, size_bytes: 1048577 },
      { ...asset, sha256: 'A'.repeat(64) },
      { ...asset, sha256: 'bad' },
      { ...asset, status: 'clean' },
      { ...asset, scan_status: 'clean' },
      { ...asset, name: undefined },
      { ...asset, name: 'x'.repeat(129) },
    ]) {
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ items: [invalid] }), { status: 200 }))
      await expect(errorPagesApi.listAssets('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchMock.mockRestore()
  })

  it('lists assets and rules with scope/site filters', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [asset] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [rule] }), { status: 200 }))
    await expect(errorPagesApi.listAssets('token', scopeID, 'ready')).resolves.toEqual({ items: [asset] })
    await expect(errorPagesApi.listRules('token', scopeID, rule.target.site_id)).resolves.toEqual({ items: [rule] })
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/v1/error-pages/assets?scope_id=${scopeID}&status=ready`)
    expect(fetchMock.mock.calls[1]?.[0]).toBe(`/v1/error-pages/rules?scope_id=${scopeID}&site_id=${rule.target.site_id}`)
    fetchMock.mockRestore()
  })

  it('passes stable cursor pagination to asset and rule list routes', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [asset], next_cursor: 'asset-next' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [rule], next_cursor: 'rule-next' }), { status: 200 }))

    await errorPagesApi.listAssets('token', scopeID, undefined, { limit: 20, cursor: 'asset-next' })
    await errorPagesApi.listRules('token', scopeID, undefined, { limit: 20, cursor: 'rule-next' })

    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/v1/error-pages/assets?scope_id=${scopeID}&limit=20&cursor=asset-next`)
    expect(fetchMock.mock.calls[1]?.[0]).toBe(`/v1/error-pages/rules?scope_id=${scopeID}&limit=20&cursor=rule-next`)
    fetchMock.mockRestore()
  })

  it('uploads raw content and applies CAS headers to delete and rule state', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: asset, replayed: false }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: asset, replayed: false }), { status: 202 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: rule, replayed: false }), { status: 200 }))
    await errorPagesApi.uploadAssetContent('token', assetID, new Blob(['test'], { type: 'text/html' }), 'text/html', 'idem-upload')
    await errorPagesApi.deleteAsset('token', assetID, asset.revision, 'idem-a')
    await errorPagesApi.setRuleEnabled('token', ruleID, rule.revision, false, 'idem-r')
    expect(fetchMock.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ method: 'PUT', body: expect.any(Blob), headers: expect.objectContaining({ 'Content-Type': 'text/html' }) }))
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).headers).not.toHaveProperty('Content-Length')
    expect(fetchMock.mock.calls[1]?.[1]).toEqual(expect.objectContaining({ headers: expect.objectContaining({ 'If-Match': '"2"', 'Idempotency-Key': 'idem-a' }) }))
    expect(fetchMock.mock.calls[2]?.[1]).toEqual(expect.objectContaining({ headers: expect.objectContaining({ 'If-Match': '"4"', 'Idempotency-Key': 'idem-r' }) }))
    fetchMock.mockRestore()
  })

  it('gets the canonical publication snapshot from the mounted read route', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(publicationSnapshot), { status: 200 }))

    await expect(errorPagesApi.getPublicationSnapshot('token')).resolves.toEqual(publicationSnapshot)

    expect(fetchMock).toHaveBeenCalledWith('/v1/error-pages/publication-snapshot', expect.objectContaining({
      credentials: 'include',
      headers: expect.objectContaining({ Authorization: 'Bearer token' }),
    }))
    expect(fetchMock.mock.calls[0]?.[1]).not.toHaveProperty('method')
    fetchMock.mockRestore()
  })

  it('rejects malformed publication policy fields, scope collections, and timestamps', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    for (const invalid of [
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, schema: 'cdnca.error-pages/v2' } },
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, version: ' invalid' } },
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, revision: 0 } },
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, revision: 1.5 } },
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, global: { rules: 'invalid' } } },
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, sites: [{ site_key: '', rules: [] }] } },
      { ...publicationSnapshot, policy: { ...publicationSnapshot.policy, sites: 'invalid' } },
      { ...publicationSnapshot, created_at: 'not-a-date' },
      { ...publicationSnapshot, receipt: { applied: true } },
    ]) {
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(invalid), { status: 200 }))
      await expect(errorPagesApi.getPublicationSnapshot('token')).rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchMock.mockRestore()
  })

  it('rejects unknown publication rule enums and invalid snapshot or resource digests', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    for (const invalid of [
      { ...publicationSnapshot, snapshot_sha256: 'C'.repeat(64) },
      { ...publicationSnapshot, snapshot_sha256: 'bad' },
      {
        ...publicationSnapshot,
        policy: { ...publicationSnapshot.policy, global: { rules: [{ ...edgeRule, category: 'upstream_timeout' }] } },
      },
      {
        ...publicationSnapshot,
        policy: { ...publicationSnapshot.policy, global: { rules: [{ ...edgeRule, resource: { ...edgeRule.resource, mime_type: 'image/svg+xml' } }] } },
      },
      {
        ...publicationSnapshot,
        policy: { ...publicationSnapshot.policy, global: { rules: [{ ...edgeRule, resource: { ...edgeRule.resource, sha256: 'bad' } }] } },
      },
      {
        ...publicationSnapshot,
        policy: { ...publicationSnapshot.policy, global: { rules: [{ ...edgeRule, resource: { ...edgeRule.resource, file: 'objects/private-key' } }] } },
      },
    ]) {
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(invalid), { status: 200 }))
      await expect(errorPagesApi.getPublicationSnapshot('token')).rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchMock.mockRestore()
  })

  it('publishes with exact CAS and request metadata, then reads the immutable item route', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(publicationReceipt, 201, {
        ETag: `"sha256-${artifactDigest}"`,
        Location: `/v1/tenant-scopes/${scopeID}/error-page-publications/${publicationID}`,
        'X-Request-ID': publicationMetadata.requestId,
      }))
      .mockResolvedValueOnce(json(publicationReceipt, 200, {
        ETag: `"sha256-${artifactDigest}"`,
        'X-Request-ID': publicationMetadata.requestId,
      }))

    await expect(publicationApi.publishErrorPageConfiguration(
      'publication-token', scopeID, 8, publicationInput, publicationMetadata,
    )).resolves.toEqual(publicationReceipt)
    await expect(publicationApi.getErrorPagePublication(
      'publication-token', scopeID, publicationID, publicationMetadata.requestId,
    )).resolves.toEqual(publicationReceipt)

    const [publishURL, publishInit] = fetchMock.mock.calls[0]!
    expect(publishURL).toBe(`/v1/tenant-scopes/${scopeID}/error-page-publications`)
    expect(publishInit).toEqual(expect.objectContaining({
      method: 'POST', credentials: 'include', body: JSON.stringify(publicationInput),
    }))
    const publishHeaders = new Headers(publishInit?.headers)
    expect(Object.fromEntries([
      'Authorization', 'Content-Type', 'If-Match', 'Idempotency-Key', 'X-Request-ID',
      'X-Correlation-ID', 'Traceparent', 'X-Task-ID',
    ].map((name) => [name, publishHeaders.get(name)]))).toEqual({
      Authorization: 'Bearer publication-token',
      'Content-Type': 'application/json',
      'If-Match': '"8"',
      'Idempotency-Key': publicationMetadata.idempotencyKey,
      'X-Request-ID': publicationMetadata.requestId,
      'X-Correlation-ID': publicationMetadata.correlationId,
      Traceparent: publicationMetadata.traceparent,
      'X-Task-ID': publicationMetadata.taskId,
    })
    expect(JSON.parse(String(publishInit?.body))).not.toHaveProperty('source_revision')

    const [readURL, readInit] = fetchMock.mock.calls[1]!
    expect(readURL).toBe(`/v1/tenant-scopes/${scopeID}/error-page-publications/${publicationID}`)
    expect(readInit).toEqual(expect.objectContaining({ method: 'GET', credentials: 'include' }))
    const readHeaders = new Headers(readInit?.headers)
    expect(readHeaders.get('Authorization')).toBe('Bearer publication-token')
    expect(readHeaders.get('X-Request-ID')).toBe(publicationMetadata.requestId)
    expect(readHeaders.has('Idempotency-Key')).toBe(false)
    expect(readHeaders.has('If-Match')).toBe(false)
    fetchMock.mockRestore()
  })

  it.each([
    ['explicit nodes', { kind: 'nodes', node_ids: [nodeID, secondNodeID] }, true],
    ['line-group snapshot', { kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4, resolver_sha256: resolverDigest }, true],
    ['empty nodes', { kind: 'nodes', node_ids: [] }, false],
    ['duplicate nodes', { kind: 'nodes', node_ids: [nodeID, nodeID] }, false],
    ['noncanonical node', { kind: 'nodes', node_ids: [nodeID.toUpperCase()] }, false],
    ['nodes with snapshot field', { kind: 'nodes', node_ids: [nodeID], snapshot_id: snapshotID }, false],
    ['nodes with secret field', { kind: 'nodes', node_ids: [nodeID], secret: 'private' }, false],
    ['snapshot missing ID', { kind: 'line_group_snapshot', revision: 4, resolver_sha256: resolverDigest }, false],
    ['snapshot missing revision', { kind: 'line_group_snapshot', snapshot_id: snapshotID, resolver_sha256: resolverDigest }, false],
    ['snapshot missing resolver digest', { kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4 }, false],
    ['snapshot mixed with nodes', { kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4, resolver_sha256: resolverDigest, node_ids: [nodeID] }, false],
    ['snapshot with response-only digest', { kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4, resolver_sha256: resolverDigest, resolved_sha256: resolverDigest }, false],
    ['unknown target', { kind: 'future_target', node_ids: [nodeID] }, false],
  ])('enforces the strict %s publication target', async (_name, target, accepted) => {
    const response = target.kind === 'line_group_snapshot'
      ? { ...publicationReceipt, target: { kind: 'resolver', snapshot_id: snapshotID, revision: 4, resolver_sha256: resolverDigest, resolved_sha256: artifactDigest } }
      : publicationReceipt
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response, 201))
    const input = { ...publicationInput, target } as PublicationRequest

    if (accepted) {
      await expect(publicationApi.publishErrorPageConfiguration('token', scopeID, 8, input, publicationMetadata))
        .resolves.toMatchObject({ tenant_scope_id: scopeID, source_revision: 8 })
      expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)).target).toEqual(target)
    } else {
      await expect(publicationApi.publishErrorPageConfiguration('token', scopeID, 8, input, publicationMetadata))
        .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
      expect(fetchMock).not.toHaveBeenCalled()
    }
    fetchMock.mockRestore()
  })

  it('rejects invalid health, deadline, CAS, and metadata before issuing a publication request', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    const attempts: Array<[number, PublicationRequest, PublicationWriteMetadata]> = [
      [0, publicationInput, publicationMetadata],
      [8, { ...publicationInput, health_check: { ...publicationInput.health_check, activation_timeout_ms: 0 } }, publicationMetadata],
      [8, { ...publicationInput, health_check: { ...publicationInput.health_check, observation_window_ms: 300_001 } }, publicationMetadata],
      [8, { ...publicationInput, health_check: { ...publicationInput.health_check, required_consecutive_successes: 101 } }, publicationMetadata],
      [8, { ...publicationInput, max_attempts: 11 }, publicationMetadata],
      [8, { ...publicationInput, deadline: 'not-a-time' }, publicationMetadata],
      [8, publicationInput, { ...publicationMetadata, idempotencyKey: 'contains spaces' }],
      [8, publicationInput, { ...publicationMetadata, requestId: 'not-a-uuid' }],
      [8, publicationInput, { ...publicationMetadata, traceparent: '00-invalid' }],
    ]
    for (const [revision, input, metadata] of attempts) {
      await expect(publicationApi.publishErrorPageConfiguration('token', scopeID, revision, input, metadata))
        .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    }
    expect(fetchMock).not.toHaveBeenCalled()
    fetchMock.mockRestore()
  })

  it('rejects malformed or identity-drifted immutable publication receipts', async () => {
    const invalidReceipts = [
      { ...publicationReceipt, unexpected: true },
      { ...publicationReceipt, tenant_scope_id: tenantID },
      { ...publicationReceipt, publication_id: nodeID },
      { ...publicationReceipt, source_revision: 0 },
      { ...publicationReceipt, error_page_publication_revision: 1.5 },
      { ...publicationReceipt, config_version_id: 'invalid' },
      { ...publicationReceipt, rollout_id: snapshotID.toUpperCase() },
      { ...publicationReceipt, artifact_sha256: artifactDigest.toUpperCase() },
      { ...publicationReceipt, target: { kind: 'nodes', resolved_sha256: resolverDigest } },
      { ...publicationReceipt, target: { kind: 'explicit', resolved_sha256: resolverDigest, snapshot_id: snapshotID } },
      { ...publicationReceipt, node_count: 0 },
      { ...publicationReceipt, created_at: 'not-a-time' },
    ]
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    for (const invalid of invalidReceipts) {
      fetchMock.mockResolvedValueOnce(json(invalid))
      await expect(publicationApi.getErrorPagePublication('token', scopeID, publicationID))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchMock.mockRestore()
  })

  it('keeps only a matching 503 outcome-unknown retry binding and never exposes the server message', async () => {
    const path = `/v1/tenant-scopes/${scopeID}/error-page-publications`
    const retry: PublicationRetryBinding = {
      method: 'POST', path, if_match: '"8"', idempotency_key: publicationMetadata.idempotencyKey,
      body_sha256: await textSha256(JSON.stringify(publicationInput)),
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        error: { code: 'error_page_publication_outcome_unknown', message: 'private publisher topology', request_id: publicationMetadata.requestId, retry },
      }, 503))
      .mockResolvedValueOnce(json({
        error: { code: 'error_page_publication_outcome_unknown', message: 'private publisher topology', request_id: publicationMetadata.requestId, retry: { ...retry, path: `${path}/drift` } },
      }, 503))

    const unknown = await publicationApi.publishErrorPageConfiguration(
      'token', scopeID, 8, publicationInput, publicationMetadata,
    ).catch((error: unknown) => error as PublicationApiError)
    expect(unknown).toBeInstanceOf(Error)
    if (!(unknown instanceof Error)) throw new Error('expected publication API error')
    const publicationError = unknown as PublicationApiError
    expect(publicationError).toMatchObject({
      status: 503, code: 'error_page_publication_outcome_unknown', requestId: publicationMetadata.requestId, retry,
    })
    expect(publicationError.message).not.toContain('private publisher topology')

    await expect(publicationApi.publishErrorPageConfiguration(
      'token', scopeID, 8, publicationInput, publicationMetadata,
    )).rejects.toMatchObject({ code: 'invalid_response' })
    fetchMock.mockRestore()
  })
})
