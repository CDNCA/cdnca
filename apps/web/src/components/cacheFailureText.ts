import type { TFunction } from 'i18next'

const knownFailureCodes = new Set([
  'node_offline', 'lease_expired', 'delivery_timeout', 'cache_layout_unsafe', 'cache_metadata_invalid',
  'cache_entry_changed', 'cache_delete_failed', 'purge_entry_budget_exceeded', 'purge_scan_budget_exceeded',
  'site_context_stale', 'prewarm_timeout', 'prewarm_redirect_rejected', 'prewarm_response_too_large',
  'prewarm_task_bytes_exceeded', 'prewarm_upstream_failed', 'prewarm_status_rejected', 'prewarm_not_cacheable',
  'task_cancelled', 'task_deadline_exceeded', 'retry_exhausted', 'cancelled', 'cache_task_unavailable',
  'site_context_not_found', 'cache_task_capacity', 'cache_outcome_unknown',
])

/** A node's stable failure code in the user's language (unknown codes are named, never shown raw). */
export function cacheFailureText(code: string | undefined, t: TFunction<'cacheOperations'>): string {
  if (!code) return t('values.placeholder')
  const normalized = code.toLowerCase()
  return knownFailureCodes.has(normalized) ? t(`failures.${normalized}`) : t('failures.unknown', { code })
}
