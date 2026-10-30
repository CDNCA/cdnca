import { Alert, Descriptions, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import type { MarketAgreement, MarketOfferListing } from '../../api/market'
import { PrivacyConsent } from '../market/MarketAgreements'
import { formatCap } from './limitsModel'
import { offerPriceText, offerQualityText } from './offerView'
import { formatYuan } from '@cdnca/ui/offer-terms'

const meteredModels = new Set(['traffic', 'bandwidth_95', 'bandwidth_daily_peak'])

// One purchase confirmation for every billing model (C17): what is charged
// now, what the price is in its own unit, the limits and what happens at
// them, the SLA, what happens when the prepaid balance runs out, and that the
// purchase is checked against the offer revision shown here. With a published
// privacy policy it also says "购买即表示同意《隐私政策》" (MARKET-03; no checkbox,
// no version recorded; nothing when unpublished).
export function PurchaseConfirm({ offer, days, changed, agreements = [] }: {
  offer: MarketOfferListing; days: number; changed?: boolean; agreements?: MarketAgreement[]
}) {
  const { t } = useTranslation('nodeMarket')
  const metered = meteredModels.has(offer.billing_model)
  const daily = offer.pricing?.daily_minor ?? 0
  const limits = (offer.limits ?? []).filter((l) => l.metric !== 'node_cpu_percent' && l.metric !== 'node_memory_percent')
  const charge = metered
    ? t('buy.review.chargeMetered', { deposit: formatYuan(offer.pricing?.deposit_minor ?? 0) })
    : t('buy.review.chargeDays', { days, price: formatYuan(daily), total: formatYuan(days * daily) })
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      {changed ? <Alert type="warning" showIcon message={t('buy.review.changed')} /> : null}
      <Descriptions size="small" column={1} bordered items={[
        { key: 'charge', label: t('buy.review.charge'), children: charge },
        { key: 'price', label: t('buy.review.price'), children: `${t(`models.${offer.billing_model}`, { defaultValue: offer.billing_model })} · ${offerPriceText(t, offer)}` },
        { key: 'settlement', label: t('filters.settlement'), children: t(`settlement.${offer.settlement_mode ?? 'direct'}`) },
        { key: 'limits', label: t('detail.limits'), children: limits.length === 0 ? t('detail.unlimited') : <Space direction="vertical" size={0}>
          {limits.map((l) => {
            const shown = formatCap(l.metric, l.cap)
            return <span key={l.metric}>{t(`limitMetrics.${l.metric}`)} {shown.value} {t(`limitUnits.${shown.unit}`)} → {t(`limitActions.${l.action}`)}</span>
          })}
        </Space> },
        { key: 'sla', label: t('sla.column'), children: offer.sla
          ? t('sla.summary', { target: (offer.sla.availability_target * 100).toFixed(2), window: t(`sla.windows.${offer.sla.measure_window}`) })
          : t('sla.none') },
        { key: 'prepaid', label: t('buy.review.prepaid'), children: t('detail.prepaid', { action: t(`limitActions.${offer.prepaid_exhausted_action || 'pause'}`) }) },
        { key: 'icp', label: t('offers.icp'), children: offer.compliance?.require_icp ? t('detail.yes') : t('detail.no') },
        { key: 'quality', label: t('quality.score'), children: offerQualityText(t, offer) },
      ]} />
      <Typography.Text type="secondary">{t('buy.review.revision', { revision: offer.revision ?? '—' })}</Typography.Text>
      <PrivacyConsent agreements={agreements} />
    </Space>
  )
}
