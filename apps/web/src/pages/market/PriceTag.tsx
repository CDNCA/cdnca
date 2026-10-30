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
// cheapest plan on sale. A promo past its deadline shows the price it turned into.
export function PriceTag({ plugin }: { plugin: MarketPlugin }) {
  const { t } = useTranslation('marketStore')
  const plan = headlinePlan(plugin.price_plans)
  if (!plan) return <Tag>{t('price.none')}</Tag>
  const state = priceBadgeState(plan)
  if (state.kind !== 'paid') return <PriceBadge plan={plan} />
  if (plan.kind === 'free') return <><Tag color="gold">{t('price.paid')}</Tag><PriceBadge plan={plan} /></>
  return <><Tag color="gold">{t('price.paid')}</Tag><strong>{planPrice(t, plan)}</strong></>
}
