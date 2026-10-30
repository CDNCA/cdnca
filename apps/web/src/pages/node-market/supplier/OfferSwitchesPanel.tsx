import { useQuery } from '@tanstack/react-query'
import { Space, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketApi, newIdempotencyKey, type MarketOfferListing } from '../../../api/market'
import { marketSupplierApi } from '../../../api/marketSupplier'
import { useErrorText, useToken, useWrite } from './hooks'
import { LoadFailure } from './shared'

// The market lists these two switches on an offer (ML-19 resale_allowed, ML-24 site_auto_pause).
export type SupplierOffer = MarketOfferListing & { resale_allowed?: boolean; site_auto_pause?: boolean }

// ADR 0012 §17.2 / §19.4: per-offer "allow resale" and "same-site auto pause".
// Both go through PUT terms with the current pricing and bump the revision; the listed revision
// travels as expected_revision so a stale row cannot put back an older price (卡 11).
export function OfferSwitchesPanel() {
  const { t } = useTranslation('marketSupplier')
  const token = useToken()
  const errorText = useErrorText()
  const offers = useQuery({ queryKey: ['nodeMarket', 'myOffers'], queryFn: () => marketApi.myOffers(token), enabled: !!token })
  const save = useWrite((v: { offer: SupplierOffer; switches: { resale_allowed?: boolean; site_auto_pause?: boolean } }) =>
    marketSupplierApi.setOfferSwitches(token, v.offer.id, v.offer.pricing, v.switches, newIdempotencyKey('offer-switches'), v.offer.revision), 'switches.saved')
  const rows = ((offers.data ?? []) as SupplierOffer[]).filter((o) => o.status !== 'retired' && o.status !== 'delisted')
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Title level={5}>{t('switches.title')}</Typography.Title>
      {offers.error ? <LoadFailure scope="sell" error={offers.error} title={errorText(offers.error)} /> : null}
      <Table<SupplierOffer> size="small" rowKey="id" loading={offers.isLoading} dataSource={rows} pagination={false}
        locale={{ emptyText: t('common.empty') }}
        columns={[
          { title: t('subscribers.offer'), key: 'name', render: (_: unknown, o) => <Space size={4}>{o.name}
            {o.resale_allowed === false ? <Tag color="warning">{t('switches.resaleOff')}</Tag> : null}</Space> },
          { title: <Tooltip title={t('switches.resaleHelp')}>{t('switches.resale')}</Tooltip>, key: 'resale', render: (_: unknown, o) =>
            <Switch aria-label={`${t('switches.resale')} ${o.name}`} checked={o.resale_allowed !== false} loading={save.isPending}
              onChange={(checked) => save.mutate({ offer: o, switches: { resale_allowed: checked } })} /> },
          { title: <Tooltip title={t('switches.siteAutoPauseHelp')}>{t('switches.siteAutoPause')}</Tooltip>, key: 'pause', render: (_: unknown, o) =>
            <Switch aria-label={`${t('switches.siteAutoPause')} ${o.name}`} checked={o.site_auto_pause === true} loading={save.isPending}
              onChange={(checked) => save.mutate({ offer: o, switches: { site_auto_pause: checked } })} /> },
        ]} />
      <Typography.Text type="secondary">{t('switches.resaleHelp')}</Typography.Text>
      <Typography.Text type="secondary">{t('switches.siteAutoPauseHelp')}</Typography.Text>
    </Space>
  )
}
