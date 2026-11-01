import { Tag } from 'antd'
import { PriceBadge, priceBadgeState } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import type { MarketPlugin } from '../../api/market'
import { headlinePlan, planPrice, publisherOf } from './marketModel'
import './messages'

const publisherColors = { official: 'blue', certified: 'green', third_party: 'default' } as const

export function PublisherBadge({ plugin }: { plugin: MarketPlugin }) {
  const { t } = useTranslation('marketStore')
  const kind = publisherOf(plugin)
  return <Tag color={publisherColors[kind]} data-publisher={kind}>{t(`publisher.${kind}`)}</Tag>
}

// PriceTag shows the free / 限免 badge (@cdnca/ui PriceBadge) or paid and the headline price of the
// cheapest plan on sale. A live promo also names what it costs afterwards ("限免 3 天 之后 ¥9.90/月",
// store-pricing 10-31); a promo past its deadline shows the price it turned into. The market already prices
// buyer reads for this controller's edition (market 068 ForEdition), so this is the community or the
// commercial price, never both.
export function PriceTag({ plugin }: { plugin: MarketPlugin }) {
  const { t } = useTranslation('marketStore')
  const plan = headlinePlan(plugin.price_plans)
  if (!plan) return <Tag>{t('price.none')}</Tag>
  const state = priceBadgeState(plan)
  if (state.kind !== 'paid') return <PriceBadge plan={plan} showThen />
  if (plan.kind === 'free') return <><Tag color="gold">{t('price.paid')}</Tag><PriceBadge plan={plan} /></>
  return <><Tag color="gold">{t('price.paid')}</Tag><strong>{planPrice(t, plan)}</strong></>
}
