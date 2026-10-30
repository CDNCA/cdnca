import type { CertificateAssetBinding } from './certificates'

export type CertificatePublicationState = 'complete' | 'pending' | 'failed' | 'unknown'
type PublicationEvent = {
  sequence: number; state: string; attempt: number; occurred_at: string
  next_attempt_at?: string; failure_code?: string
}
export interface CertificatePublicationDetail {
  current: Omit<PublicationEvent, 'sequence'> & {
    tenant_scope_id: string; site_id: string; asset_id: string; version_id: string
    binding_revision: number; operation: 'publish' | 'unpublish'; default: boolean; state_sequence: number
    publication_id?: string; publication_revision?: number; config_version_id?: string
    rollout_id?: string; rollout_revision?: number
  }
  history: PublicationEvent[]
}
export interface CertificatePublicationRollout {
  id: string; configuration_scope_id?: string; config_version_id: string; revision: number; state: string; action: string
  progress: { total: number; pending: number; running: number; succeeded: number; failed: number; cancelled: number; superseded?: number; frozen?: number }
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const states = ['pending', 'leased', 'retry_wait', 'succeeded', 'permanent_failed']

export function parseCertificatePublication(value: unknown): value is CertificatePublicationDetail {
  if (!value || typeof value !== 'object') return false
  const { current, history } = value as CertificatePublicationDetail
  if (!current || typeof current !== 'object' || !Array.isArray(history) || history.length === 0 ||
    ![current.tenant_scope_id, current.site_id, current.asset_id, current.version_id].every((id) => typeof id === 'string' && uuid.test(id)) ||
    ![current.binding_revision, current.state_sequence].every((revision) => Number.isSafeInteger(revision) && revision > 0) ||
    !['publish', 'unpublish'].includes(current.operation) || typeof current.default !== 'boolean' || !states.includes(current.state) ||
    !Number.isSafeInteger(current.attempt) || current.attempt < 0 || typeof current.occurred_at !== 'string' || !Number.isFinite(Date.parse(current.occurred_at))) return false
  if (!history.every((event, index) => {
    if (!event || event.sequence !== index + 1 || !states.includes(event.state) || !Number.isSafeInteger(event.attempt) ||
      event.attempt < 0 || typeof event.occurred_at !== 'string' || !Number.isFinite(Date.parse(event.occurred_at))) return false
    const next = typeof event.next_attempt_at === 'string' ? Date.parse(event.next_attempt_at) : NaN
    const failure = typeof event.failure_code === 'string' && /^[a-z][a-z0-9._-]{0,127}$/.test(event.failure_code)
    if (event.state === 'pending') return event.sequence === 1 && event.attempt === 0 && next >= Date.parse(event.occurred_at) && event.failure_code === undefined
    if (event.state === 'retry_wait') return event.attempt > 0 && next > Date.parse(event.occurred_at) && failure
    if (event.state === 'permanent_failed') return event.attempt > 0 && event.next_attempt_at === undefined && failure
    return event.attempt > 0 && event.next_attempt_at === undefined && event.failure_code === undefined
  })) return false
  const last = history[history.length - 1]
  if (last.sequence !== current.state_sequence || last.state !== current.state || last.attempt !== current.attempt ||
    last.occurred_at !== current.occurred_at || last.failure_code !== current.failure_code || last.next_attempt_at !== current.next_attempt_at) return false
  if (current.state === 'succeeded' &&
    (![current.publication_id, current.config_version_id, current.rollout_id].every((id) => typeof id === 'string' && uuid.test(id)) ||
      !Number.isSafeInteger(current.rollout_revision) || current.rollout_revision! < 1 || current.publication_revision !== current.rollout_revision)) return false
  if (current.state !== 'succeeded' && [current.publication_id, current.publication_revision, current.config_version_id, current.rollout_id, current.rollout_revision].some((field) => field !== undefined)) return false
  return true
}

export function parseCertificateRollout(value: unknown): value is CertificatePublicationRollout {
  if (!value || typeof value !== 'object') return false
  const rollout = value as CertificatePublicationRollout
  if (![rollout.id, rollout.config_version_id].every((id) => typeof id === 'string' && uuid.test(id)) ||
    (rollout.configuration_scope_id !== undefined && !uuid.test(rollout.configuration_scope_id)) ||
    !Number.isSafeInteger(rollout.revision) || rollout.revision < 1 || !['apply', 'rollback'].includes(rollout.action) ||
    !['queued', 'running', 'paused', 'succeeded', 'failed', 'partial_failed', 'cancelled'].includes(rollout.state) || !rollout.progress) return false
  const { total, pending, running, succeeded, failed, cancelled, superseded = 0, frozen = 0 } = rollout.progress
  return [total, pending, running, succeeded, failed, cancelled, superseded, frozen].every((count) => Number.isSafeInteger(count) && count >= 0 && count <= 10000) &&
    total > 0 && pending + running + succeeded + failed + cancelled + superseded + frozen === total
}

export function certificateBindingPublicationState(
  binding: CertificateAssetBinding, publication: unknown, rollout?: unknown,
): CertificatePublicationState {
  if (!parseCertificatePublication(publication)) return 'unknown'
  const current = publication.current
  if (current.tenant_scope_id !== binding.tenant_scope_id || current.site_id !== binding.site_id ||
    current.asset_id !== binding.asset_id || current.version_id !== binding.version_id || current.binding_revision !== binding.revision ||
    current.default !== binding.default || current.operation !== (binding.bound ? 'publish' : 'unpublish')) return 'unknown'
  if (current.state === 'permanent_failed') return 'failed'
  if (current.state !== 'succeeded') return 'pending'
  if (!parseCertificateRollout(rollout) || rollout.id !== current.rollout_id || rollout.config_version_id !== current.config_version_id ||
    (rollout.configuration_scope_id !== undefined && rollout.configuration_scope_id !== binding.tenant_scope_id) ||
    rollout.revision !== current.rollout_revision || rollout.action !== 'apply' || rollout.state !== 'succeeded' || rollout.progress.succeeded !== rollout.progress.total) return 'unknown'
  return 'complete'
}
