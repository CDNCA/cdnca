import { Alert, Button } from 'antd'
import { useTranslation } from 'react-i18next'

import './messages'

// MarketNotJoined: the market routes are not mounted on this controller. There is no switch in the console;
// the server administrator configures the deployment, then "re-check" probes again without a reload.
export function MarketNotJoined({ recheck, rechecking }: { recheck: () => void; rechecking: boolean }) {
  const { t } = useTranslation('marketStore')
  return <Alert type="info" showIcon message={t('errors.notJoined')}
    action={<Button size="small" loading={rechecking} onClick={recheck}>{t('errors.recheck')}</Button>} />
}
