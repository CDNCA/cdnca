import { sitePublicationsApi, type SitePublicationWriteMetadata } from './sitePublications'

const scopeID = '018cc251-f400-7def-8000-000000000050'
const rolloutID = '018cc251-f400-7def-8000-000000000061'
const configVersionID = '018cc251-f400-7def-8000-000000000062'
const metadata: SitePublicationWriteMetadata = {
  requestId: '018cc251-f400-7def-8000-000000000070',
  idempotencyKey: 'site-publication-start-018cc251-f400-7def-8000-000000000070',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

const rollout = {
  id: rolloutID,
  configuration_scope_id: scopeID,
  config_version_id: configVersionID,
  action: 'apply',
  state: 'running',
  revision: 2,
  max_attempts: 3,
  rollout: {
    strategy: 'canary', canary_size: 1, batch_size: 2, failure_threshold: 1,
    cohort_count: 3, released_cohort: 0,
  },
  pause_reason: '',
  progress: { total: 5, pending: 5, running: 0, succeeded: 0, failed: 0, cancelled: 0, superseded: 0, frozen: 0 },
  can_start: false,
  can_pause: true,
  can_resume: false,
  can_cancel: true,
  can_retry: false,
  created_at: '2026-08-08T08:00:00Z',
  updated_at: '2026-08-08T08:01:00Z',
}

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('site publication rollout cohorts API', () => {
  it.each(['start', 'pause', 'resume'] as const)('sends %s with exact command identity', async (action) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(rollout))
    const command = {
      start: sitePublicationsApi.startRollout,
      pause: sitePublicationsApi.pauseRollout,
      resume: sitePublicationsApi.resumeRollout,
    }[action]
    await expect(command(
      'token', rolloutID, { configuration_scope_id: scopeID, expected_revision: 1 }, metadata,
    )).resolves.toMatchObject({ rollout: { strategy: 'canary', released_cohort: 0 } })
    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/admin/site-rollouts/${rolloutID}/${action}`,
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('rejects a rollout response that hides cohort control facts', async () => {
    const invalid = { ...rollout, rollout: undefined }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(invalid))
    await expect(sitePublicationsApi.getRollout(
      'token', { kind: 'platform', targetScopeId: scopeID }, rolloutID,
    )).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })
})
