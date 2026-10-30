import { ApiError } from './auth'
import {
  lineGroupTargetFromSnapshot,
  newSitePublicationWriteMetadata,
  sitePublicationsApi,
  type PublishSiteConfigurationInput,
  type SitePublicationWriteMetadata,
} from './sitePublications'

const scopeID = '018cc251-f400-7def-8000-000000000050'
const otherScopeID = '018cc251-f400-7def-8000-000000000051'
const publicationID = '018cc251-f400-7def-8000-000000000060'
const rolloutID = '018cc251-f400-7def-8000-000000000061'
const configVersionID = '018cc251-f400-7def-8000-000000000062'
const snapshotID = '018cc251-f400-7def-8000-000000000063'
const deploymentID = '018cc251-f400-7def-8000-000000000064'
const nodeID = '018cc251-f400-7def-8000-000000000065'
const lineGroupID = '018cc251-f400-7def-8000-000000000066'
const digest = '1'.repeat(64)

const adminPublication = {
  id: publicationID,
  configuration_scope_id: scopeID,
  source_revision: 7,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  canonical_source_sha256: '2'.repeat(64),
  artifact_sha256: '3'.repeat(64),
  target: {
    kind: 'line_group_snapshot',
    snapshot_id: snapshotID,
    revision: 4,
    resolver_sha256: digest,
    resolved_sha256: '4'.repeat(64),
  },
  node_count: 2,
  created_at: '2026-08-01T08:00:00Z',
}

const tenantPublication = {
  id: publicationID,
  source_revision: 7,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  target: { kind: 'line_group_snapshot' },
  node_count: 2,
  created_at: '2026-08-01T08:00:00Z',
}

const adminRollout = {
  id: rolloutID,
  configuration_scope_id: scopeID,
  config_version_id: configVersionID,
  action: 'apply',
  state: 'partial_failed',
  revision: 3,
  max_attempts: 5,
  progress: { total: 2, pending: 0, running: 0, succeeded: 1, failed: 1, cancelled: 0, superseded: 0, frozen: 0 },
  can_cancel: false,
  can_retry: true,
  created_at: '2026-08-01T08:00:00Z',
  updated_at: '2026-08-01T08:03:00Z',
}

const tenantRollout = Object.fromEntries(
  Object.entries(adminRollout).filter(([key]) => key !== 'configuration_scope_id'),
)

const adminDeployment = {
  id: deploymentID,
  node_id: nodeID,
  attempt: 2,
  max_attempts: 5,
  state: 'failed',
  error_code: 'ACTIVATION_FAILED',
  created_at: '2026-08-01T08:01:00Z',
  updated_at: '2026-08-01T08:02:00Z',
  can_retry: true,
}

const metadata: SitePublicationWriteMetadata = {
  requestId: '018cc251-f400-7def-8000-000000000070',
  idempotencyKey: 'site-publication-publish-018cc251-f400-7def-8000-000000000070',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

const publishInput: PublishSiteConfigurationInput = {
  configuration_scope_id: scopeID,
  expected_source_revision: 7,
  target: {
    kind: 'line_group_snapshot',
    snapshot_id: snapshotID,
    revision: 4,
    resolver_sha256: digest,
  },
  health_check: {
    activation_timeout_ms: 60_000,
    observation_window_ms: 30_000,
    required_consecutive_successes: 3,
  },
  max_attempts: 5,
  deadline: '2026-08-01T09:00:00Z',
}

const adminRollback = {
  publication_id: publicationID,
  configuration_scope_id: scopeID,
  config_version_id: configVersionID,
  rollout_id: rolloutID,
  action: 'rollback',
  target: adminPublication.target,
  node_count: 2,
  created_at: '2026-08-01T08:05:00Z',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('site publications API', () => {
  it('uses the exact tenant and explicit platform list routes without scope substitution', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      json({ items: [tenantPublication], current_source_revision: 7, next_cursor: 'tenant_next' }),
    ).mockResolvedValueOnce(
      json({ items: [adminPublication], current_source_revision: 7 }),
    )

    const tenantPage = await sitePublicationsApi.listPublications(
      'access-token', { kind: 'tenant' }, { limit: 20 },
    )
    const platformPage = await sitePublicationsApi.listPublications(
      'access-token', { kind: 'platform', targetScopeId: scopeID }, { limit: 50 },
    )

    expect(tenantPage.current_source_revision).toBe(7)
    expect(platformPage.items[0]).toMatchObject({ configuration_scope_id: scopeID })
    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      '/v1/site-publications?limit=20',
      `/v1/admin/site-publications?scope_id=${scopeID}&limit=50`,
    ])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.headers).toEqual(expect.objectContaining({ Authorization: 'Bearer access-token' }))
    }
  })

  it.each([
    ['unknown page field', { items: [tenantPublication], current_source_revision: 7, internal: true }],
    ['missing current revision', { items: [tenantPublication] }],
    ['zero current revision', { items: [tenantPublication], current_source_revision: 0 }],
    ['tenant admin leakage', { items: [{ ...tenantPublication, artifact_sha256: digest }], current_source_revision: 7 }],
    ['noncanonical UUID', { items: [{ ...tenantPublication, id: publicationID.toUpperCase() }], current_source_revision: 7 }],
    ['invalid timestamp', { items: [{ ...tenantPublication, created_at: 'August 1' }], current_source_revision: 7 }],
  ])('rejects %s instead of trusting a tenant publication page', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))
    await expect(sitePublicationsApi.listPublications('token', { kind: 'tenant' }))
      .rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it.each([
    ['current', 'succeeded'],
    ['legacy', 'completed'],
  ])('accepts a %s successful rollout state as canonical succeeded', async (_name, state) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [{
        ...adminRollout,
        state,
        progress: { total: 2, pending: 0, running: 0, succeeded: 2, failed: 0, cancelled: 0, superseded: 0, frozen: 0 },
        can_retry: false,
      }],
    }))

    await expect(sitePublicationsApi.listRollouts(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).resolves.toMatchObject({ items: [{ state: 'succeeded' }] })
  })

  it('rejects an unknown rollout state', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [{ ...adminRollout, state: 'done' }],
    }))

    await expect(sitePublicationsApi.listRollouts(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('accepts legacy rollout control defaults without a progressive policy', async () => {
    const legacyRollout = {
      ...adminRollout,
      can_start: false,
      can_pause: false,
      can_resume: false,
      pause_reason: '',
    }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [legacyRollout] }))
      .mockResolvedValueOnce(json({ items: [{ ...legacyRollout, can_resume: true }] }))

    await expect(sitePublicationsApi.listRollouts(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).resolves.toMatchObject({ items: [{ can_resume: false, pause_reason: '' }] })
    await expect(sitePublicationsApi.listRollouts(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('strictly validates publication, rollout, and deployment response shapes', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...adminPublication, private_signature: 'secret' }))
      .mockResolvedValueOnce(json({ items: [{ ...tenantRollout, progress: { ...adminRollout.progress, total: 3 } }] }))
      .mockResolvedValueOnce(json({ items: [{ ...adminDeployment, state: 'future_state' }] }))

    await expect(sitePublicationsApi.getPublication('token', { kind: 'platform', targetScopeId: scopeID }, publicationID))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(sitePublicationsApi.listRollouts('token', { kind: 'tenant' }))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(sitePublicationsApi.listDeployments('token', { kind: 'platform', targetScopeId: scopeID }, rolloutID))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  // Frozen marks a failed, non-retryable deployment only.
  it('accepts a frozen refusal and refuses inconsistent frozen marks', async () => {
    const frozen = { ...adminDeployment, state: 'failed', can_retry: false, frozen: true }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [frozen] }))
      .mockResolvedValueOnce(json({ items: [{ ...frozen, can_retry: true }] }))
      .mockResolvedValueOnce(json({ items: [{ ...frozen, state: 'healthy' }] }))
      .mockResolvedValueOnce(json({ items: [{ ...frozen, superseded: true }] }))

    await expect(sitePublicationsApi.listDeployments('token', { kind: 'platform', targetScopeId: scopeID }, rolloutID))
      .resolves.toMatchObject({ items: [{ frozen: true }] })
    for (let index = 0; index < 3; index++) {
      await expect(sitePublicationsApi.listDeployments('token', { kind: 'platform', targetScopeId: scopeID }, rolloutID))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  // Node warnings ride a successful platform deployment only.
  it('accepts platform deployment warnings and refuses unknown, duplicate or tenant ones', async () => {
    const healthy = { ...adminDeployment, state: 'healthy', can_retry: false, error_code: undefined }
    const warnings = ['ddos_protection_fault', 'post_activation_maintenance_failed']
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [{ ...healthy, warnings }] }))
      .mockResolvedValueOnce(json({ items: [{ ...healthy, warnings: ['disk_on_fire'] }] }))
      .mockResolvedValueOnce(json({ items: [{ ...healthy, warnings: ['ddos_protection_fault', 'ddos_protection_fault'] }] }))
      .mockResolvedValueOnce(json({ items: [{ ...healthy, warnings: [] }] }))
      .mockResolvedValueOnce(json({ items: [{ ...Object.fromEntries(Object.entries(healthy).filter(([key]) => key !== 'node_id')), warnings }] }))

    await expect(sitePublicationsApi.listDeployments('token', { kind: 'platform', targetScopeId: scopeID }, rolloutID))
      .resolves.toMatchObject({ items: [{ warnings }] })
    for (let index = 0; index < 3; index++) {
      await expect(sitePublicationsApi.listDeployments('token', { kind: 'platform', targetScopeId: scopeID }, rolloutID))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
    await expect(sitePublicationsApi.listDeployments('token', { kind: 'tenant' }, rolloutID))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    ['nodes', { kind: 'nodes', resolved_sha256: '4'.repeat(64) }],
    ['line-group snapshot', adminPublication.target],
  ])('accepts an exact %s admin publication target', async (_name, target) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [{ ...adminPublication, target }],
      current_source_revision: 7,
    }))

    await expect(sitePublicationsApi.listPublications(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).resolves.toMatchObject({ items: [{ target }] })
  })

  it.each([
    ['nodes missing resolved digest', { kind: 'nodes' }],
    ['nodes with snapshot ID', { kind: 'nodes', resolved_sha256: digest, snapshot_id: snapshotID }],
    ['nodes with snapshot revision', { kind: 'nodes', resolved_sha256: digest, revision: 4 }],
    ['nodes with resolver digest', { kind: 'nodes', resolved_sha256: digest, resolver_sha256: digest }],
    ['nodes with invalid resolved digest', { kind: 'nodes', resolved_sha256: '0'.repeat(64) }],
    ['nodes with an extra field', { kind: 'nodes', resolved_sha256: digest, internal: true }],
    ['line-group snapshot missing snapshot ID', {
      kind: 'line_group_snapshot', revision: 4, resolver_sha256: digest, resolved_sha256: digest,
    }],
    ['line-group snapshot missing revision', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, resolver_sha256: digest, resolved_sha256: digest,
    }],
    ['line-group snapshot missing resolver digest', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4, resolved_sha256: digest,
    }],
    ['line-group snapshot missing resolved digest', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4, resolver_sha256: digest,
    }],
    ['line-group snapshot with noncanonical snapshot ID', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID.toUpperCase(), revision: 4,
      resolver_sha256: digest, resolved_sha256: digest,
    }],
    ['line-group snapshot with zero revision', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 0,
      resolver_sha256: digest, resolved_sha256: digest,
    }],
    ['line-group snapshot with fractional revision', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 1.5,
      resolver_sha256: digest, resolved_sha256: digest,
    }],
    ['line-group snapshot with invalid resolver digest', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4,
      resolver_sha256: '0'.repeat(64), resolved_sha256: digest,
    }],
    ['line-group snapshot with invalid resolved digest', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4,
      resolver_sha256: digest, resolved_sha256: '0'.repeat(64),
    }],
    ['line-group snapshot with an extra field', {
      ...adminPublication.target, internal: true,
    }],
    ['unknown kind', { kind: 'future_target', resolved_sha256: digest }],
  ])('rejects an admin publication target with %s', async (_name, target) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [{ ...adminPublication, target }],
      current_source_revision: 7,
    }))

    await expect(sitePublicationsApi.listPublications(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('rejects platform facts from another target scope and mismatched detail identities', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        items: [{ ...adminPublication, configuration_scope_id: otherScopeID }],
        current_source_revision: 7,
      }))
      .mockResolvedValueOnce(json({ ...adminPublication, id: '018cc251-f400-7def-8000-000000000099' }))
      .mockResolvedValueOnce(json({ ...adminRollout, configuration_scope_id: otherScopeID }))

    await expect(sitePublicationsApi.listPublications(
      'token', { kind: 'platform', targetScopeId: scopeID },
    )).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(sitePublicationsApi.getPublication(
      'token', { kind: 'platform', targetScopeId: scopeID }, publicationID,
    )).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(sitePublicationsApi.getRollout(
      'token', { kind: 'platform', targetScopeId: scopeID }, rolloutID,
    )).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects write responses that do not match their target scope or rollout identity', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...adminPublication, configuration_scope_id: otherScopeID }, 201))
      .mockResolvedValueOnce(json({ ...adminRollout, id: '018cc251-f400-7def-8000-000000000099' }))

    await expect(sitePublicationsApi.publish('token', publishInput, metadata))
      .rejects.toMatchObject({ code: 'invalid_response' })
    await expect(sitePublicationsApi.cancelRollout(
      'token', rolloutID, { configuration_scope_id: scopeID, expected_revision: 3 }, metadata,
    )).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('serializes opaque cursors and rejects unsafe list and identifier inputs before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [adminRollout], next_cursor: 'next_page',
    }))
    await sitePublicationsApi.listRollouts(
      'token', { kind: 'platform', targetScopeId: scopeID }, { limit: 10, cursor: 'next_page' },
    )
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe(
      `/v1/admin/site-rollouts?scope_id=${scopeID}&limit=10&cursor=next_page`,
    )

    await expect(sitePublicationsApi.listRollouts('token', { kind: 'tenant' }, { cursor: 'bad.cursor' }))
      .rejects.toMatchObject({ code: 'invalid_request' })
    await expect(sitePublicationsApi.getRollout('token', { kind: 'tenant' }, rolloutID.toUpperCase()))
      .rejects.toMatchObject({ code: 'invalid_request' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('sends an exact publication body with stable request, idempotency, and trace metadata', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () => json(adminPublication, 201),
    )

    await sitePublicationsApi.publish('access-token', publishInput, metadata)
    await sitePublicationsApi.publish('access-token', publishInput, metadata)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
    for (const [url, init] of fetchSpy.mock.calls) {
      expect(url).toBe('/v1/admin/site-publications')
      expect(init).toEqual(expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(publishInput),
        credentials: 'include',
        headers: expect.objectContaining({
          Authorization: 'Bearer access-token',
          'X-Request-ID': metadata.requestId,
          'Idempotency-Key': metadata.idempotencyKey,
          Traceparent: metadata.traceparent,
          'Content-Type': 'application/json',
        }),
      }))
    }
  })

  it.each([
    ['exact nodes', { kind: 'nodes', node_ids: [nodeID] }, true],
    ['exact line-group snapshot', publishInput.target, true],
    ['nodes missing node IDs', { kind: 'nodes' }, false],
    ['nodes mixed with snapshot ID', { kind: 'nodes', node_ids: [nodeID], snapshot_id: snapshotID }, false],
    ['nodes with duplicate IDs', { kind: 'nodes', node_ids: [nodeID, nodeID] }, false],
    ['nodes with a sensitive field', { kind: 'nodes', node_ids: [nodeID], private_key: 'secret' }, false],
    ['line-group snapshot missing snapshot ID', {
      kind: 'line_group_snapshot', revision: 4, resolver_sha256: digest,
    }, false],
    ['line-group snapshot missing revision', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, resolver_sha256: digest,
    }, false],
    ['line-group snapshot missing resolver digest', {
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4,
    }, false],
    ['line-group snapshot mixed with node IDs', {
      ...publishInput.target, node_ids: [nodeID],
    }, false],
    ['line-group snapshot with a sensitive field', {
      ...publishInput.target, private_key: 'secret',
    }, false],
    ['line-group snapshot with response-only resolved digest', {
      ...publishInput.target, resolved_sha256: digest,
    }, false],
    ['unknown target kind', { kind: 'future_target', node_ids: [nodeID] }, false],
  ])('%s publish target parity', async (_name, target, accepted) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(adminPublication, 201))
    const input = { ...publishInput, target } as unknown as PublishSiteConfigurationInput

    if (accepted) {
      await expect(sitePublicationsApi.publish('token', input, metadata)).resolves.toMatchObject({
        configuration_scope_id: scopeID,
      })
      expect(JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body)).target).toEqual(target)
    } else {
      await expect(sitePublicationsApi.publish('token', input, metadata))
        .rejects.toMatchObject({ code: 'invalid_request', status: 400 })
      expect(fetchSpy).not.toHaveBeenCalled()
    }
  })

  it('sends exact cancel and retry command bodies without tenant write aliases', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () => json(adminRollout),
    )
    const body = { configuration_scope_id: scopeID, expected_revision: 3 }

    await sitePublicationsApi.cancelRollout('token', rolloutID, body, metadata)
    await sitePublicationsApi.retryFailedRollout('token', rolloutID, body, metadata)

    expect(fetchSpy.mock.calls.map(([url, init]) => [url, init?.body])).toEqual([
      [`/v1/admin/site-rollouts/${rolloutID}/cancel`, JSON.stringify(body)],
      [`/v1/admin/site-rollouts/${rolloutID}/retry-failed`, JSON.stringify(body)],
    ])
  })

  it('sends an exact rollback request and rejects mismatched response identity', async () => {
    const body = {
      configuration_scope_id: scopeID,
      target: { kind: 'nodes' as const, node_ids: [nodeID] },
      health_check: publishInput.health_check,
      max_attempts: 5,
      deadline: '2026-08-01T09:00:00Z',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(adminRollback, 201))
      .mockResolvedValueOnce(json({ ...adminRollback, publication_id: snapshotID }, 201))

    await expect(sitePublicationsApi.rollback('token', publicationID, body, metadata))
      .resolves.toMatchObject({ publication_id: publicationID, action: 'rollback' })
    await expect(sitePublicationsApi.rollback('token', publicationID, body, metadata))
      .rejects.toMatchObject({ code: 'invalid_response' })

    expect(fetchSpy.mock.calls.map(([url, init]) => [url, init?.body])).toEqual([
      [`/v1/admin/site-publications/${publicationID}/rollback`, JSON.stringify(body)],
      [`/v1/admin/site-publications/${publicationID}/rollback`, JSON.stringify(body)],
    ])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.headers).toEqual(expect.objectContaining({
        Authorization: 'Bearer token',
        'X-Request-ID': metadata.requestId,
        'Idempotency-Key': metadata.idempotencyKey,
        Traceparent: metadata.traceparent,
      }))
    }
  })

  it('accepts only an exact existing line-group snapshot for the selected scope and revision', () => {
    const snapshot = {
      id: snapshotID,
      revision: 4,
      tenant_scope_id: scopeID,
      source_line_group_id: lineGroupID,
      source_revision: 9,
      source_configuration_digest: '5'.repeat(64),
      node_set_digest: digest,
      node_ids: [nodeID],
    }

    expect(lineGroupTargetFromSnapshot(snapshot, scopeID, lineGroupID, 9)).toEqual({
      kind: 'line_group_snapshot', snapshot_id: snapshotID, revision: 4,
      resolver_sha256: digest,
    })
    for (const drift of [
      { ...snapshot, tenant_scope_id: otherScopeID },
      { ...snapshot, source_line_group_id: nodeID },
      { ...snapshot, source_revision: 8 },
      { ...snapshot, node_set_digest: '0'.repeat(64) },
      { ...snapshot, node_ids: [] },
      { ...snapshot, unexpected: true },
    ]) {
      expect(() => lineGroupTargetFromSnapshot(drift, scopeID, lineGroupID, 9)).toThrow(ApiError)
    }
  })

  it('generates canonical nonzero write metadata and reports network failures without raw detail', async () => {
    const generated = newSitePublicationWriteMetadata('publish')
    expect(generated.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
    expect(generated.idempotencyKey).toMatch(/^site-publication-publish-[0-9a-f-]{36}$/)
    expect(generated.traceparent).toMatch(/^00-(?!0{32}-)[0-9a-f]{32}-(?!0{16}-)[0-9a-f]{16}-01$/)

    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('private socket address'))
    await expect(sitePublicationsApi.listPublications('token', { kind: 'tenant' }))
      .rejects.toMatchObject({ status: 0, code: 'network_error', message: 'Network request failed' })
  })
})
