import { useQuery } from '@tanstack/react-query'
import { Tabs } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketApi } from '../../../api/market'
import { DataState } from '../../../components/DataState'

import { ReceivedTopupsPanel } from '../DirectBalancesTab'
import { OfferListingForm } from '../OfferListingForm'
import { SellerSiteGuide } from '../SellerSiteGuide'
import { CommissionPanel } from './CommissionPanel'
import { ComplaintsPanel } from './ComplaintsPanel'
import { FeedbackList } from './FeedbackPanel'
import { HoldsList } from './HoldsList'
import { OfferSwitchesPanel } from './OfferSwitchesPanel'
import { SitePausesPanel } from './SitePausesPanel'
import { SubscribersPanel } from './SubscribersPanel'
import { useToken } from './hooks'
import { sellingFeatures } from './model'
import { NotOpen } from './shared'

// ADR 0012 ML-28: the supplier side (marketplace.sell).
// The lease decides selling (market.sell / market.resell): without it the market
// answers 403 to every supplier list, so the tab explains that instead of loading them.
export function SupplierTab() {
  const { t } = useTranslation('marketSupplier')
  const token = useToken()
  const member = useQuery({ queryKey: ['nodeMarket', 'member'], queryFn: () => marketApi.member(token), enabled: !!token })
  if (member.isLoading) return <DataState status="loading" />
  // Past received top-ups stay readable after selling lapses (they used to sit on the balances page).
  if (member.data && !member.data.features.some((f) => sellingFeatures.includes(f))) return <><NotOpen scope="sell" /><SellerSiteGuide scope="node" />
    <Tabs size="small" items={[{ key: 'received', label: t('nodeMarket:direct.received'), children: <ReceivedTopupsPanel /> }]} /></>
  return (
    <Tabs size="small" tabPosition="top" destroyOnHidden items={[
      { key: 'subscribers', label: t('subscribers.title'), children: <SubscribersPanel /> },
      { key: 'holds', label: t('tabs.sellerHolds'), children: <HoldsList role="seller" /> },
      { key: 'feedback', label: t('feedback.title'), children: <FeedbackList role="seller" canWrite /> },
      { key: 'complaints', label: t('complaints.title'), children: <ComplaintsPanel /> },
      { key: 'switches', label: t('switches.title'), children: <><OfferSwitchesPanel /><SitePausesPanel canResume /></> },
      { key: 'resale', label: t('resale.title'), children: <OfferListingForm initialSource="resale" /> },
      { key: 'received', label: t('nodeMarket:direct.received'), children: <ReceivedTopupsPanel /> },
      { key: 'commission', label: t('commission.title'), children: <CommissionPanel /> },
    ]} />
  )
}

// The subscriber side: paused nodes of what I bought and same-site pauses on my sites.
export function SubscriberHoldsTab() {
  return <><HoldsList role="buyer" /><SitePausesPanel canResume={false} /></>
}
