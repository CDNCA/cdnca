import { useQuery } from '@tanstack/react-query'
import { Alert } from 'antd'
import { useTranslation } from 'react-i18next'

import { securityPoliciesApi } from '../../api/securityPolicies'
import '../../i18n/securityPoliciesRebind'

// waf-rebind: a library saved on the general rules page is republished by the
// control plane to every bound site that is behind (the site's package
// line groups). Sites whose package lacks the feature are not, and the page
// says how many; nothing is shown otherwise.
export default function RebindStatusNotice({ accessToken, kind, cacheKey }: {
  accessToken: string
  kind: 'waf' | 'cc'
  cacheKey: string
}) {
  const { t } = useTranslation('securityPolicies')
  const query = useQuery({
    queryKey: ['security-policy-rebind-status', cacheKey, kind],
    retry: false,
    refetchInterval: 30_000,
    queryFn: ({ signal }) => securityPoliciesApi.getRebindStatus(accessToken, kind, signal),
  })
  const count = query.data?.package_denied_sites ?? 0
  if (count === 0) return null
  return <Alert className="identity-alert" type="warning" showIcon role="status"
    message={t('rebind.packageDenied', { count })}
    description={t('rebind.packageDeniedDescription')} />
}
