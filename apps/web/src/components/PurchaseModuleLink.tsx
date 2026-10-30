import { Button } from 'antd'
import { ShoppingCart } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { marketAccess } from '../api/marketAccess'
import { useSessionStore } from '../auth/session'
import '../pages/market/messages'
import { useRuntimeFeatureOff } from './useRuntimeFeatures'

// eslint-disable-next-line react-refresh/only-export-components
export function purchasePath(featureCode: string): string {
  return `/sys/plugin-store?feature=${encodeURIComponent(featureCode)}`
}

/**
 * PurchaseModuleLink is the "去购买" entry shown where a module is not licensed: it opens the
 * plugin store on the official entry that unlocks featureCode (购买 → 下载 → 绑定本主控).
 * Hidden for principals without marketplace access (tenants ask their platform administrator).
 */
export function PurchaseModuleLink({ featureCode, size }: { featureCode: string; size?: 'small' | 'middle' }) {
  const { t } = useTranslation('marketStore')
  const access = marketAccess(useSessionStore((s) => s.principal))
  // No "去购买" while the market runtime is off.
  const marketOff = useRuntimeFeatureOff('market', useSessionStore((s) => s.accessToken))
  if (!access.browse || marketOff) return null
  return (
    <Link to={purchasePath(featureCode)}>
      <Button type="primary" size={size} icon={<ShoppingCart size={14} aria-hidden="true" />}>{t('guide.buy')}</Button>
    </Link>
  )
}
