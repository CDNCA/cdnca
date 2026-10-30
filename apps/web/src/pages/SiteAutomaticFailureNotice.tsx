import { useQuery } from '@tanstack/react-query'
import { Alert } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { sitePublicationsApi } from '../api/sitePublications'
import '../i18n/sitePublications'
import { automaticFailureTitle } from './siteAutomaticFailure'
import { FeedbackWhen } from '@cdnca/ui'

/**
 * O2 (live-site2 10-22): the site list of a tenant shows why its latest
 * automatic publication has not reached the nodes, with the same wording as
 * the publication page (e.g. node artifacts still syncing, with progress).
 * The read is best effort: without an answer nothing is shown.
 */
export default function SiteAutomaticFailureNotice({ accessToken, ownerKey, enabled }: {
  accessToken: string
  ownerKey: string
  // read after the site list itself loaded (it is the page's primary read)
  enabled: boolean
}) {
  const { t } = useTranslation('sitePublications')
  const query = useQuery({
    queryKey: ['site-automatic-failure', ownerKey],
    queryFn: () => sitePublicationsApi.listPublications(accessToken, { kind: 'tenant' }, { limit: 1 }),
    enabled,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: (state) => state.state.data?.automatic_failure?.reason === 'node_artifacts_syncing' ? 60_000 : false,
  })
  const failure = query.data?.automatic_failure
  if (!failure) return null
  const description = (
    <>
      {t(`automaticFailure.${failure.reason}.description`, { revision: failure.source_revision })}{' '}
      <Link to="/site/publications">{t('title')}</Link>
    </>
  )
  // Syncing is a passing state shown in place; a failed automatic publish is a failure (dialog).
  if (failure.reason !== 'node_artifacts_syncing') return <FeedbackWhen title={automaticFailureTitle(failure, t)} detail={description} />
  return (
    <Alert
      className="site-modal-notice"
      type="info"
      showIcon
      data-testid="site-list-automatic-failure"
      message={automaticFailureTitle(failure, t)}
      description={description}
    />
  )
}
