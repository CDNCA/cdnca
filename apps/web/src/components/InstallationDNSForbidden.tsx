import { Button, Result } from 'antd'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import '../i18n/dnsConfig'

// The no-permission page of InstallationDNSRoute (RB-U01 子项，审测卡 11) for
// a tenant. Loaded only when shown, so the dnsConfig texts stay out of the
// first load.
export default function InstallationDNSForbidden({ canReadDNS }: { canReadDNS: boolean }) {
  const { t } = useTranslation('dnsConfig')
  const navigate = useNavigate()
  return <Result status="403" title="403" subTitle={t('installationOnly.description')} extra={
    canReadDNS
      ? <Button type="primary" onClick={() => navigate('/site/list', { state: { siteSubnav: 'dnsApi' } })}>{t('installationOnly.ownDnsApi')}</Button>
      : <Button type="primary" onClick={() => navigate('/')}>{t('installationOnly.home')}</Button>
  } />
}
