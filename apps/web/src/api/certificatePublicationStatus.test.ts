import { certificateBindingPublicationState, parseCertificatePublication, parseCertificateRollout } from './certificatePublicationStatus'

const binding = {
  tenant_scope_id: '22222222-2222-4222-8222-222222222222', site_id: '33333333-3333-4333-8333-333333333333',
  asset_id: '44444444-4444-4444-8444-444444444444', version_id: '55555555-5555-4555-8555-555555555555',
  revision: 4, default: true, bound: true, changed_by: '66666666-6666-4666-8666-666666666666', changed_at: '2026-10-12T00:00:00Z',
}
const current = {
  tenant_scope_id: binding.tenant_scope_id, site_id: binding.site_id, asset_id: binding.asset_id, version_id: binding.version_id,
  binding_revision: binding.revision, operation: 'publish', default: true, state_sequence: 1, state: 'succeeded', attempt: 1,
  occurred_at: binding.changed_at, publication_id: '77777777-7777-4777-8777-777777777777', publication_revision: 2,
  config_version_id: '88888888-8888-4888-8888-888888888888', rollout_id: '99999999-9999-4999-8999-999999999999', rollout_revision: 2,
}
const publication = { current, history: [{ sequence: 1, state: 'succeeded', attempt: 1, occurred_at: current.occurred_at }] }
const rollout = {
  id: current.rollout_id, configuration_scope_id: binding.tenant_scope_id, config_version_id: current.config_version_id,
  revision: 2, state: 'succeeded', action: 'apply', progress: { total: 2, pending: 0, running: 0, succeeded: 2, failed: 0, cancelled: 0 },
}

describe('Certificate publication status', () => {
  it('accepts the complete append-only producer history with microsecond timestamps', () => {
    const history = [
      { sequence: 1, state: 'pending', attempt: 0, occurred_at: '2026-10-12T00:00:00.123456Z', next_attempt_at: '2026-10-12T00:00:00.123456Z' },
      { sequence: 2, state: 'leased', attempt: 1, occurred_at: '2026-10-12T00:00:00.223456Z' },
      { sequence: 3, state: 'retry_wait', attempt: 1, occurred_at: '2026-10-12T00:00:00.323456Z', next_attempt_at: '2026-10-12T00:00:01.323456Z', failure_code: 'publication_pending' },
      { sequence: 4, state: 'leased', attempt: 2, occurred_at: '2026-10-12T00:00:01.423456Z' },
      { sequence: 5, state: 'succeeded', attempt: 2, occurred_at: '2026-10-12T00:00:01.523456Z' },
    ]
    const receipt = { current: { ...current, state_sequence: 5, attempt: 2, occurred_at: history[4].occurred_at }, history }
    expect(parseCertificatePublication(receipt)).toBe(true)
    expect(certificateBindingPublicationState(binding, receipt, rollout)).toBe('complete')
  })

  it('accepts only a complete current binding receipt cross-checked with its rollout', () => {
    expect(parseCertificatePublication(publication)).toBe(true)
    expect(parseCertificateRollout(rollout)).toBe(true)
    expect(certificateBindingPublicationState(binding, publication, rollout)).toBe('complete')
    expect(certificateBindingPublicationState(binding, publication)).toBe('unknown')
  })

  it.each(['tenant_scope_id', 'site_id', 'asset_id', 'version_id', 'binding_revision', 'operation', 'default'] as const)(
    'rejects a publication with a mismatched %s', (field) => {
      const value = field === 'binding_revision' ? 3 : field === 'default' ? false : field === 'operation' ? 'unpublish' : current.publication_id
      expect(certificateBindingPublicationState(binding, { ...publication, current: { ...current, [field]: value } }, rollout)).toBe('unknown')
    },
  )

  it.each([
    { id: current.publication_id }, { configuration_scope_id: current.publication_id },
    { config_version_id: current.publication_id }, { revision: 3 }, { state: 'running' }, { action: 'rollback' },
    { progress: { ...rollout.progress, succeeded: 1, failed: 1 } },
  ])('rejects inconsistent rollout evidence %#', (patch) => {
    expect(certificateBindingPublicationState(binding, publication, { ...rollout, ...patch })).toBe('unknown')
  })

  it.each([
    { current: { ...current, rollout_id: undefined } }, { current: { ...current, config_version_id: 'not-a-uuid' } },
    { current: { ...current, rollout_revision: 0 } }, { current: { ...current, publication_revision: 3 } },
    { history: [] }, { history: [{ ...publication.history[0], state: 'pending' }] },
    { history: [{ ...publication.history[0], sequence: 2 }] }, { current: { ...current, occurred_at: 'invalid' } },
  ])('rejects missing or malformed publication evidence %#', (patch) => {
    expect(certificateBindingPublicationState(binding, { ...publication, ...patch }, rollout)).toBe('unknown')
  })

  it.each(['pending', 'leased', 'retry_wait', 'permanent_failed'])('keeps factual %s distinct from unknown', (state) => {
    const event = { ...publication.history[0], state, attempt: state === 'pending' ? 0 : 1,
      ...(state === 'pending' || state === 'retry_wait' ? { next_attempt_at: '2026-10-12T00:01:00Z' } : {}),
      ...(state === 'retry_wait' || state === 'permanent_failed' ? { failure_code: 'publication_unavailable' } : {}) }
    const receipt = { current: { ...current, ...event, publication_id: undefined, publication_revision: undefined,
      config_version_id: undefined, rollout_id: undefined, rollout_revision: undefined }, history: [event] }
    expect(certificateBindingPublicationState(binding, receipt)).toBe(state === 'permanent_failed' ? 'failed' : 'pending')
  })

  it('matches unpublish receipts only to the same unbound revision', () => {
    const receipt = { ...publication, current: { ...current, operation: 'unpublish' } }
    expect(certificateBindingPublicationState({ ...binding, bound: false }, receipt, rollout)).toBe('complete')
  })
})
