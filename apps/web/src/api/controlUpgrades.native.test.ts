import { webcrypto } from 'node:crypto'

import { nativeControlUpgradesApi, previewNativeUpgradeBundle } from './controlUpgrades.native'
import { nativeBundleFixture, nativePublicationFixture, nativeStatusFixture } from './controlUpgrades.native.fixtures'

const metadata = { requestId: 'request-1', idempotencyKey: 'upgrade-1' }
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
const sha256 = async (value: string) => Array.from(new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(value))), (byte) => byte.toString(16).padStart(2, '0')).join('')

beforeEach(() => { vi.stubGlobal('crypto', webcrypto) })
afterEach(() => { vi.unstubAllGlobals() })

describe('native control upgrade contract', () => {
  it('reads the no-store native status with no guessed revision', async () => {
    const status = nativeStatusFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(status))
    expect(await nativeControlUpgradesApi.status('token')).toEqual(status)
    expect(fetch).toHaveBeenCalledWith('/v1/admin/control-upgrade-plan', expect.objectContaining({
      cache: 'no-store', headers: expect.objectContaining({ Authorization: 'Bearer token' }),
    }))
  })

  it.each([Number.MAX_SAFE_INTEGER + 1, -1, 0.5, '0'])('rejects unsafe publication revision %s', async (publication_revision) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...nativeStatusFixture(), publication_revision }))
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts the runner history journal and rejects malformed entries', async () => {
    const publication = nativePublicationFixture()
    const running = (history: unknown) => ({ ...nativeStatusFixture(), publication_revision: 1, publication,
      execution: { state: 'running', phase: 'drained', receipt: null, history } })
    const history = [{ phase: 'verified', at: 1780000001 }, { phase: 'drained', at: 1780000002 }]
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(running(history)))
      .mockResolvedValueOnce(json(running([{ phase: 'unknown_phase', at: 1780000001 }])))
      .mockResolvedValueOnce(json(running([{ phase: 'verified', at: 1780000001, pid: 1 }])))
      .mockResolvedValueOnce(json(running([{ phase: 'failed', at: 1780000001, error_code: 'Bad Code' }])))
    expect((await nativeControlUpgradesApi.status('token')).execution.history).toEqual(history)
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('accepts database migration checkpoints and evidence, rejecting malformed migration records', async () => {
    const publication = nativePublicationFixture()
    const migration = { applied: ['284_node_delete_cascade'], migrated: true, backup_path: '/var/lib/cdnca-upgrade/database-backups/p.dump',
      backup_bytes: 5944315, backup_sha256: 'a'.repeat(64), backup_ms: 900, migrate_ms: 120 }
    const running = (entry: unknown) => ({ ...nativeStatusFixture(), publication_revision: 1, publication,
      execution: { state: 'running', phase: 'database_migrated', receipt: null, history: [entry] } })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(running({ phase: 'database_migrated', at: 1780000001, migration })))
      .mockResolvedValueOnce(json(running({ phase: 'database_migrated', at: 1780000001, migration: { ...migration, applied: ['bad name'] } })))
      .mockResolvedValueOnce(json(running({ phase: 'database_migrated', at: 1780000001, migration: { ...migration, password: 'x' } })))
      .mockResolvedValueOnce(json(running({ phase: 'database_migrated', at: 1780000001, migration: { ...migration, backup_bytes: -1 } })))
    expect((await nativeControlUpgradesApi.status('token')).execution.history?.[0].migration).toEqual(migration)
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('rejects state/receipt mismatches rather than reporting execution success', async () => {
    const publication = nativePublicationFixture()
    const value = {
      ...nativeStatusFixture(), publication_revision: 1, publication,
      execution: { state: 'completed', phase: 'completed', receipt: {
        id: 'receipt-1', plan_id: publication.plan_id, bundle_sha256: 'c'.repeat(64), sequence: 5,
        target: 'native-standalone', current_version: '1.0.0', target_version: '1.1.0', result: 'applied', completed_at: 1780000001,
      } },
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects unexpected response fields and a ready runtime with an unknown reason', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ ...nativeStatusFixture(), pid: 123 }))
      .mockResolvedValueOnce(json({ ...nativeStatusFixture(), runtime: { ready: true, reason: 'new_state' } }))
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it.each(['applied', 'rolled_back', 'failed'] as const)('accepts only the matching terminal %s receipt', async (result) => {
    const publication = nativePublicationFixture()
    const status = { ...nativeStatusFixture(), publication_revision: 1, publication,
      execution: { state: 'completed', phase: result === 'applied' ? 'completed' : result, receipt: {
        id: `${publication.plan_id}:5`, plan_id: publication.plan_id, bundle_sha256: publication.bundle_sha256,
        sequence: publication.release_sequence, target: 'native-standalone', current_version: publication.current_version,
        target_version: publication.target_version, result, completed_at: 1780000001,
      } } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(status))
    expect(await nativeControlUpgradesApi.status('token')).toEqual(status)
  })

  it.each([
    { state: 'completed', phase: 'completed', receipt: null },
    { state: 'running', phase: 'completed', receipt: null },
    { state: 'not_started', phase: 'verified', receipt: null },
    { state: 'unavailable', phase: 'verified', receipt: null },
  ])('rejects contradictory execution facts %j', async (execution) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...nativeStatusFixture(), publication_revision: 1, publication: nativePublicationFixture(), execution }))
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects mismatched publication revisions and unrenderable receipt timestamps', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ ...nativeStatusFixture(), publication_revision: 1 }))
      .mockResolvedValueOnce(json({ ...nativeStatusFixture(), publication_revision: 1, publication: { ...nativePublicationFixture(), published_at: Number.MAX_SAFE_INTEGER } }))
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each(['2026-10-08T12:00:00', '2026-10-08', 'not-a-date'])('rejects non-RFC3339 observation time %s', async (observed_at) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...nativeStatusFixture(), observed_at }))
    await expect(nativeControlUpgradesApi.status('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('only previews allowlisted unsigned facts without exposing download URLs or signatures', () => {
    const preview = previewNativeUpgradeBundle(JSON.stringify(nativeBundleFixture()))
    expect(preview).toMatchObject({ currentVersion: '1.0.0', targetVersion: '1.1.0', releaseSequence: 5, channelRevision: 3 })
    expect(JSON.stringify(preview)).not.toMatch(/DO-NOT-DISPLAY|download_url|signature/)
  })

  it.each(['null', '{}', '{invalid', JSON.stringify({ ...nativeBundleFixture(), algorithm: 'none' })])('rejects malformed unsigned input %s', (input) => {
    expect(() => previewNativeUpgradeBundle(input)).toThrow()
  })

  it('rejects oversized and unsafe-number uploads before a request', async () => {
    const bundle = nativeBundleFixture()
    bundle.bundle.channel_revision = Number.MAX_SAFE_INTEGER + 1
    const fetch = vi.spyOn(globalThis, 'fetch')
    await expect(nativeControlUpgradesApi.publish('token', { rawJSON: JSON.stringify(bundle), expectedRevision: 0, metadata })).rejects.toMatchObject({ code: 'invalid_request' })
    expect(() => previewNativeUpgradeBundle(' '.repeat(262145))).toThrow()
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each([200, 201])('publishes the unchanged uploaded bytes and checks the actual receipt at HTTP %s', async (status) => {
    const rawJSON = `${JSON.stringify(nativeBundleFixture(), null, 2)}\n`
    const receipt = { ...nativePublicationFixture(), bundle_sha256: await sha256(rawJSON), idempotency_sha256: await sha256(metadata.idempotencyKey) }
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(receipt, status))
    expect(await nativeControlUpgradesApi.publish('token', { rawJSON, expectedRevision: 0, metadata })).toEqual(receipt)
    expect(fetch).toHaveBeenCalledWith('/v1/admin/control-upgrade-plan', expect.objectContaining({
      method: 'POST', body: rawJSON, headers: expect.objectContaining({
        'If-Match': '"0"', 'Idempotency-Key': 'upgrade-1', 'X-Request-ID': 'request-1',
      }),
    }))
  })

  it('rejects a successful HTTP receipt for a different request', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(nativePublicationFixture(), 201))
    await expect(nativeControlUpgradesApi.publish('token', { rawJSON: JSON.stringify(nativeBundleFixture()), expectedRevision: 0, metadata })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each(['expected_revision', 'request_id', 'plan_id', 'target_digest', 'release_sequence'] as const)('rejects a receipt with a changed %s', async (field) => {
    const rawJSON = JSON.stringify(nativeBundleFixture())
    const receipt = { ...nativePublicationFixture(), bundle_sha256: await sha256(rawJSON), idempotency_sha256: await sha256(metadata.idempotencyKey) }
    Object.assign(receipt, { [field]: typeof receipt[field] === 'number' ? 2 : 'other' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(receipt, 201))
    await expect(nativeControlUpgradesApi.publish('token', { rawJSON, expectedRevision: 0, metadata })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('parses the version list and sends the chosen artifact to /issue', async () => {
    const item = { artifact_id: '00000000-0000-4000-8000-0000000000a1', version: '1.0.36', release_notes: 'n', published_at: 1780000000,
      operation: 'upgrade', control_schema_head: 300, channel_target: true, pinned: false, selectable: true, reason: '' }
    const options = { schema: 'cdnca.native-control-upgrade-options/v1', observed_at: '2026-10-17T00:00:00Z',
      options: { current_version: '1.0.35', current_schema_head: 299, target_mode: 'follow_channel', items: [item] } }
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(options))
      .mockResolvedValueOnce(json({ ...options, options: { ...options.options, items: [{ ...item, selectable: true, reason: 'x' }] } }))
      // The removed "license service cannot list" shape is not a valid answer.
      .mockResolvedValueOnce(json({ ...options, supported: false, options: null }))
      .mockResolvedValueOnce(json({ error: { code: 'upgrade_options_unavailable' } }, 503))
      .mockResolvedValueOnce(json(nativePublicationFixture(), 201))
      .mockResolvedValueOnce(json(nativePublicationFixture(), 201))
    expect((await nativeControlUpgradesApi.options('token')).options.items).toEqual([item])
    await expect(nativeControlUpgradesApi.options('token')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(nativeControlUpgradesApi.options('token')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(nativeControlUpgradesApi.options('token')).rejects.toMatchObject({ status: 503 })
    expect(fetch).toHaveBeenNthCalledWith(1, '/v1/admin/control-upgrade-plan/options', expect.anything())
    await nativeControlUpgradesApi.issue('token', 'key-1', item.artifact_id)
    expect(fetch.mock.calls[4][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ requested_artifact_id: item.artifact_id }) })
    await nativeControlUpgradesApi.issue('token', 'key-2')
    expect(fetch.mock.calls[5][1]).toMatchObject({ body: '{}' })
    await expect(nativeControlUpgradesApi.issue('token', 'key-3', 'not-a-uuid')).rejects.toMatchObject({ code: 'invalid_request' })
    expect(fetch).toHaveBeenCalledTimes(6)
  })

  it('keeps the reason_code of a refused issue', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      error: { code: 'upgrade_target_blocked', reason_code: 'same_version', request_id: 'r' } }), { status: 409 }))
    await expect(nativeControlUpgradesApi.issue('token', 'issue-1')).rejects.toMatchObject({
      status: 409, code: 'upgrade_target_blocked', reasonCode: 'same_version' })
  })
})
