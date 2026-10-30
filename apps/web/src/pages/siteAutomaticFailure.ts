import type { TFunction } from 'i18next'

import type { AutomaticPublicationFailure } from '../api/sitePublications'

/** The notice title of an automatic publication that reached no node (with node artifact sync progress when known). */
export function automaticFailureTitle(failure: AutomaticPublicationFailure, t: TFunction<'sitePublications'>): string {
  const sync = failure.artifact_sync
  if (failure.reason === 'node_artifacts_syncing' && sync) {
    return t('automaticFailure.node_artifacts_syncing.titleProgress', {
      received: sync.received_segments, total: sync.total_segments, minutes: sync.remaining_minutes,
    })
  }
  return t(`automaticFailure.${failure.reason}.title`)
}
