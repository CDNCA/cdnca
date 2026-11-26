import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import '../../i18n/probeDNSPup'

// A 401 from the control plane is this console's sign-in, never the dnspup key pair: dnspup's own refusal arrives as a
// result's error_code (connection test, account check, a failed probe) and keeps the key wording there
// . showCode: an unknown code is shown as is instead of "request failed".
export function useProbeReason(showCode = false) {
  const { t, i18n } = useTranslation('probeDNSPup')
  return (error: unknown) => {
    if (!(error instanceof ApiError)) return t('errors.request_failed')
    if (error.status === 401) return t('errors.session_expired')
    if (i18n.exists(`probeDNSPup:errors.${error.code}`)) return t(`errors.${error.code}`)
    return showCode ? error.code : t('errors.request_failed')
  }
}
