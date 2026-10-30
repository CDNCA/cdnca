import { useQuery } from '@tanstack/react-query'
import { Button, Descriptions } from 'antd'
import { MapPin } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { analyticsGeoApi, type AnalyticsGeoAudience, type AnalyticsGeoKind } from '../api/analyticsGeo'
import { ApiError } from '../api/auth'
import '../i18n/analyticsGeo'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { FeedbackWhen } from '@cdnca/ui'

interface LogEventIdentity {
  event_id: string
  occurred_at: string
  site_id: string
  node_id: string
  client_ip: string
}

export default function LogGeoEvidence({ accessToken, audience, kind, event, tenantId }: {
  accessToken: string
  audience: AnalyticsGeoAudience
  kind: AnalyticsGeoKind
  event: LogEventIdentity
  tenantId?: string
}) {
  const { t, i18n } = useTranslation('analyticsGeo')
  const query = useQuery({
    queryKey: ['analytics-geo-evidence', audience, tenantId ?? '', kind, event.event_id],
    queryFn: ({ signal }) => analyticsGeoApi.lookup(accessToken, audience, kind, {
      eventId: event.event_id, occurredAt: event.occurred_at, siteId: event.site_id, nodeId: event.node_id,
      clientIp: event.client_ip, ...(tenantId ? { tenantId } : {}),
    }, signal),
    enabled: false,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const evidence = query.data?.data
  const errorKey = query.error instanceof ApiError && query.error.status === 504
    ? 'states.timeout'
    : query.error instanceof ApiError && query.error.code === 'invalid_response'
      ? 'states.invalid'
      : 'states.unavailable'
  return (
    <section aria-label={t('title')}>
      <Button icon={<MapPin size={15} />} loading={query.isFetching} onClick={() => void query.refetch()}>
        {query.data ? t('actions.retry') : t('actions.verify')}
      </Button>
      {query.error ? <FeedbackWhen title={t(errorKey)} /> : null}
      {evidence ? (
        <Descriptions size="small" bordered column={1} items={[
		  { key: 'resolution', label: t('fields.resolution'), children: t(`values.${evidence.resolution}`) },
		  { key: 'reason', label: t('fields.lookupReason'), children: t(`values.${evidence.lookup_reason}`) },
		  { key: 'family', label: t('fields.addressFamily'), children: t(`values.${evidence.address_family}`) },
		  { key: 'country', label: t('fields.countryRegion'), children: evidence.resolution === 'unknown' ? t('values.empty') : `${evidence.country_code} / ${evidence.region}` },
		  { key: 'city', label: t('fields.city'), children: evidence.resolution === 'unknown' ? t('values.empty') : evidence.city },
          { key: 'carrier', label: t('fields.carrier'), children: evidence.resolution === 'unknown' ? t('values.empty') : evidence.carrier },
          { key: 'asn', label: t('fields.asn'), children: evidence.asn ? formatNumber(evidence.asn, i18n.resolvedLanguage ?? 'zh-CN') : t('values.empty') },
          { key: 'reconciliation', label: t('fields.reconciliation'), children: t(`values.${evidence.reconciliation}`) },
          { key: 'source', label: t('fields.source'), children: `${evidence.source_country_code || t('values.empty')} / ${evidence.source_carrier || t('values.empty')}` },
		  { key: 'version', label: t('fields.version'), children: evidence.database_version },
		  { key: 'provider', label: t('fields.provider'), children: evidence.database_provider },
		  { key: 'published', label: t('fields.publishedAt'), children: formatDateTime(evidence.database_published_at, i18n.resolvedLanguage ?? 'zh-CN') },
		  { key: 'effective', label: t('fields.effectiveAt'), children: formatDateTime(evidence.database_effective_at, i18n.resolvedLanguage ?? 'zh-CN') },
          { key: 'digest', label: t('fields.digest'), children: evidence.database_sha256 },
        ]} />
      ) : null}
    </section>
  )
}
