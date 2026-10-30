import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { cnameAllocationsApi, type CnameAllocationAudience } from '../../api/cnameAllocations'
import '../../i18n/cnameAllocations'

// Codes that describe recovery facts rather than why allocation failed.
const informational = new Set(['ready', 'lkg_available', 'lkg_missing'])

// Explains a failed CNAME allocation with the diagnose reason codes instead of a bare "failed".
export default function CnameFailureReason({ accessToken, siteID, audience }: {
  accessToken: string
  siteID: string
  audience: CnameAllocationAudience
}) {
  const { t, i18n } = useTranslation('cnameAllocations')
  const query = useQuery({
    queryKey: ['cname-allocation-diagnose', audience, siteID],
    retry: false,
    queryFn: () => cnameAllocationsApi.diagnose(accessToken, audience, { siteID }),
  })
  if (query.isPending) return null
  const codes = (query.data?.reason_codes ?? []).filter((code) => !informational.has(code))
  if (codes.length === 0) return <span>{t('failure.unknown')}</span>
  const has = (key: string) => i18n.exists(`cnameAllocations:${key}`)
  const label = (code: string) => has(`reasons.${code}`) ? t(`reasons.${code}`) : t('reasons.unknown')
  const hints = codes.filter((code) => has(`failure.hints.${code}`)).map((code) => t(`failure.hints.${code}`))
  return <div data-testid="cname-failure-reason">
    <div>{t('failure.title', { reasons: codes.map(label).join('、') })}</div>
    {hints.map((hint) => <div key={hint}>{hint}</div>)}
  </div>
}
