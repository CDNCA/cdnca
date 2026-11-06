import { Tooltip, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import '../../i18n/marketNames'
import './MarketLabel.css'

// Short codes that match a subscription across the two sides: the buyer's
// purchased supply and the seller's subscriber list and hidden tenant name
// both carry the first 8 characters of the market subscription id.

/** The subscription short code (first 8 of the market id), with what it matches on the seller's side. */
export function SubscriptionCode({ id }: { id?: string | null }) {
  const { t } = useTranslation('marketNames')
  if (!id) return null
  const code = id.slice(0, 8)
  return (
    <Tooltip title={t('subscriptionCodeHelp', { code })}>
      <Typography.Text type="secondary" className="market-name-code" tabIndex={0}>{t('subscriptionCode', { code })}</Typography.Text>
    </Tooltip>
  )
}

/** Seller side: the code the hidden tenant's name ends with (marketsupply.SubscriberCode) for a subscriber row. */
export function SubscriberCode({ row }: { row: { relation: string; subscription_id: string; downstream_ref?: string } }) {
  const { t } = useTranslation('marketNames')
  // A resold row already shows its downstream ref as the subscriber; that ref is the code.
  if (row.relation !== 'direct') return <Typography.Text type="secondary">{t('subscriberCodeDownstream')}</Typography.Text>
  return <Tooltip title={t('subscriberCodeHelp')}><Typography.Text code tabIndex={0}>{row.subscription_id.slice(0, 8)}</Typography.Text></Tooltip>
}

/** Seller side: the column title with what the code is. */
export function SubscriberCodeTitle() {
  const { t } = useTranslation('marketNames')
  return <Tooltip title={t('subscriberCodeHelp')}><span className="market-name-code-title" tabIndex={0}>{t('subscriberCode')}</span></Tooltip>
}
