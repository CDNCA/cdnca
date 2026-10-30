import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Collapse, Descriptions, Drawer, Form, Input, InputNumber, Modal, Select, Space, Table, Tabs, Tag, Typography } from 'antd'
import type { CheckboxProps } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  checkoutURL, marketApi, marketForbidden, marketUnavailable, newIdempotencyKey, type DisputeFilters, type MarketDispute, type MarketDisputeState, type MarketLimitMetric,
  type MarketOfferListing, type MarketRollout,
  type MarketSelectionLimits, type MarketSupply, type MarketUpstreamPause, type MarketUsageStatement, type OfferFilters, type RenewalPricePolicy,
} from '../../api/market'
import { marketAccess } from '../../api/marketAccess'
import { useSessionStore } from '../../auth/session'
import { DataState } from '../../components/DataState'
import { MarketNotJoined } from '../market/MarketNotJoined'
import { useMarketConnection } from '../market/useMarketConnection'
import { MarketAgreementFooter, useMarketAgreements } from '../market/MarketAgreements'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/nodeMarket'
import './NodeMarketPage.css'
import '../site-edit/SiteEditV4.css'
import './NodeMarketV2.css'
import { DirectBalancesTab, SellerCreditTags, money } from './DirectBalancesTab'
import { formatCap, overriddenBy, type LoadFloor } from './limitsModel'
import { OfferDetailDrawer } from './OfferDetailDrawer'
import { offerPriceText, offerQualityText } from './offerView'
import { OfferBulkActions } from './OfferBulkActions'
import { OfferListingForm } from './OfferListingForm'
import { OfferSlaModal } from './OfferSlaModal'
import { SellerSiteGuide } from './SellerSiteGuide'
import { OfferSubscribersDrawer } from './OfferSubscribersDrawer'
import { PurchaseConfirm } from './PurchaseConfirm'
import { SubscriptionUsagePanel } from './SubscriptionUsagePanel'
import { BoundSupplies, ClampedReason, SitePicker, SiteRollout, type PickedSite } from './SiteRolloutPanel'
import { ReasonText } from './ReasonText'
import { FeedbackList } from './supplier/FeedbackPanel'
import { OutageCancel } from './supplier/OutageCancel'
import { SubscriberHoldsTab, SupplierTab } from './supplier/SupplierTab'
import { CursorPager, LoadFailure, NotOpen, useCursorPages } from './supplier/shared'
import { sellingFeatures } from './supplier/model'
import '../../i18n/marketSupplier'
import { AdvancedFilters, useFeedback, useLiveApply, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { closeReason, marketReason } from '@cdnca/ui/market-reasons'
import { outcomeUnknown, useIdempotencyKey } from '../market/idempotency'
import { clearPending, loadPending, pendingAccount, savePending } from './pendingPurchase'
import { formatYuan, minorToYuan, yuanToMinor } from '@cdnca/ui/offer-terms'

function useToken() {
  return useSessionStore((state) => state.accessToken) ?? ''
}

function useMarketWrite<A extends unknown[], R>(fn: (token: string, ...args: A) => Promise<R>, successKey: string) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const token = useToken()
  return useMutation({
    mutationFn: (args: A) => fn(token, ...args),
    onSuccess: () => { void message.success(t(successKey)); void client.invalidateQueries({ queryKey: ['nodeMarket'] }) },
    onError: (error) => {
      const code = error instanceof ApiError ? error.code : 'request_failed'
      // MC12 E3: known codes in words with the next step; unknown ones keep the code.
      const r = marketReason(code, i18n.language)
      void feedback.error(r.known ? t('supplies.failedWith', { reason: r.reason, next: r.next }) : t('errors.failed', { code }))
    },
  })
}

function State({ value }: { value: string }) {
  const { t } = useTranslation('nodeMarket')
  const color = ['active', 'listed', 'applied'].includes(value) ? 'success'
    : ['failed', 'blocked', 'inconsistent', 'frozen'].includes(value) ? 'error' : value === 'receipt_pending' ? 'warning' : 'default'
  return <Tag color={color}>{t(`states.${value}`, { defaultValue: value })}</Tag>
}

const meteredModels = new Set(['traffic', 'bandwidth_95', 'bandwidth_daily_peak'])

function errorCode(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

function Unavailable() {
  const { t } = useTranslation('nodeMarket')
  return <Alert type="info" showIcon message={t('unavailable')} />
}

// changed: the seller changed the offer since the last confirmation (C17 offer_changed).
interface BuyAttempt { offer: MarketOfferListing; days: number; trial: boolean; key: string; changed?: boolean }

function BrowseTab() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const access = marketAccess(useSessionStore((state) => state.principal))
  const [draft, setDraft] = useState<OfferFilters>({})
  const [filters, setFilters] = useState<OfferFilters>({})
  // Server keyset paging (C17): the cursors of the pages before the current one.
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  const applyFilters = (next: OfferFilters) => { setFilters(next); setCursors([]) }
  // 地区/线路/单价/质量分 边输入边生效（400ms 防抖），下拉选完即查。
  useLiveApply(draft, filters, applyFilters)
  const query = useQuery({ queryKey: ['nodeMarket', 'offers', filters, cursor], queryFn: () => marketApi.offers(token, filters, cursor), enabled: !!token })
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const idempotency = useIdempotencyKey('buy')
  // MARKET-03: a published privacy policy is noted in the purchase confirmation.
  const agreements = useMarketAgreements(token)
  // The purchase being confirmed: its key is fixed when the dialog opens and
  // reused by every retry of the same offer and days (market-buy-idem).
  // The confirmed offer revision travels with the purchase (C17): a seller change since is 409 offer_changed.
  const [attempt, setAttempt] = useState<BuyAttempt | null>(null)
  const [confirming, setConfirming] = useState(false)
  // MC01 (NM02): the purchase sent without a final answer yet. It is stored
  // per account (pendingPurchase.ts) from the moment it is sent, so a
  // cancelled wait, another section or a reload still checks exactly it; no
  // other purchase starts until it is answered or abandoned.
  const account = pendingAccount(useSessionStore((state) => state.principal))
  const [pending, setPendingState] = useState<BuyAttempt | null>(() => loadPending(account))
  const pendingKey = useRef(pending?.key ?? null)
  const setPending = (value: BuyAttempt | null) => { pendingKey.current = value?.key ?? null; setPendingState(value) }
  // Only the answer to the pending request ends it; any other is stale.
  const settle = (a: BuyAttempt) => {
    clearPending(account, a.key)
    idempotency.complete(a.key)
    if (pendingKey.current !== a.key) return false
    setPending(null)
    return true
  }
  // MC12 E1: after a purchase the page says where it went, not only a toast.
  const [bought, setBought] = useState<string | null>(null)
  const [, setParams] = useSearchParams()
  const buy = useMutation({
    mutationFn: (a: BuyAttempt) => marketApi.purchase(token, a.offer.id, a.days, a.key, a.trial, a.offer.revision),
    onSuccess: (_, a) => {
      void client.invalidateQueries({ queryKey: ['nodeMarket'] })
      if (!settle(a)) return
      setAttempt(null); setConfirming(false); setBought(a.offer.name)
      void message.success(t(a.trial ? 'buy.trialStarted' : 'offers.bought'))
    },
    onError: (error, a) => {
      if (outcomeUnknown(error)) return
      if (!settle(a)) return
      const code = errorCode(error)
      if (code === 'offer_changed') return void reconfirm(a)
      setAttempt(null); setConfirming(false)
      void feedback.error(code === 'trial_used' ? t('buy.trialUsed') : code === 'conflict' ? t('buy.keyConflict') : t('errors.failed', { code }))
    },
  })
  // Sending freezes the request first: a retry or a later visit replays it as is.
  const send = (a: BuyAttempt) => {
    if (!pending) { savePending(account, a); setPending(a) }
    buy.mutate(pending ?? a)
  }
  // Waiting for the first answer or holding an unknown one.
  const unknown = !!pending && !buy.isPending
  // A trial sends days 0: the market takes the offer's trial days (purchase.go).
  const openBuy = (offer: MarketOfferListing, n: number, trial = false, changed = false) => {
    if (pendingKey.current) return
    const days = trial ? 0 : n
    setAttempt({ offer, days, trial, changed, key: idempotency.keyFor({ offer: offer.id, days, trial, revision: offer.revision }) })
    setConfirming(true)
  }
  // The seller changed the offer: re-read the catalogue and confirm the new terms (nothing was charged).
  const reconfirm = async (a: BuyAttempt) => {
    setConfirming(false)
    const fresh = (await query.refetch()).data?.items.find((o) => o.id === a.offer.id)
    if (!fresh) { setAttempt(null); void feedback.error(t('errors.failed', { code: 'offer_changed' })); return }
    openBuy(fresh, a.days, a.trial, true)
  }
  // The user checked the orders and gives the unknown purchase up (it is not sent again).
  const abandon = () => {
    if (pending) settle(pending)
    setAttempt(null); setConfirming(false)
    void client.invalidateQueries({ queryKey: ['nodeMarket'] })
  }
  // The dialog shows the pending request when there is one, else the draft being confirmed.
  const shown = pending ?? attempt
  const [days, setDays] = useState<Record<string, number>>({})
  const [detail, setDetail] = useState<MarketOfferListing | null>(null)
  // The market applies every filter (OfferFilter); the page shows what it returned.
  const items = query.data?.items ?? []
  const next = query.data?.next_cursor
  const model = (value: string) => t(`models.${value}`, { defaultValue: value })
  const billingModels = ['daily_bundle', 'traffic', 'bandwidth_95', 'bandwidth_daily_peak']
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <OfferDetailDrawer offer={detail} onClose={() => setDetail(null)} />
      {/* Closing while waiting only hides the dialog: the pending request stays and is checked below. */}
      <Modal open={confirming && !!shown} title={t(shown?.trial ? 'buy.trialTitle' : 'buy.confirmTitle', { name: shown?.offer.name ?? '' })} destroyOnHidden
        onCancel={() => { setConfirming(false); setAttempt(null) }}
        okText={unknown ? t('buy.checkResult') : shown?.trial ? t('buy.trialConfirm') : t('buy.confirm')} confirmLoading={buy.isPending}
        onOk={() => shown && send(shown)}>
        {shown ? <Space direction="vertical" style={{ width: '100%' }}>
          {shown.trial ? <>
            {shown.changed ? <Alert type="warning" showIcon message={t('buy.review.changed')} /> : null}
            <Typography.Text>{t('buy.trialDetail', { days: shown.offer.trial_days ?? 0, price: formatYuan(shown.offer.pricing?.daily_minor ?? 0) })}</Typography.Text>
            <Typography.Text type="secondary">{t('buy.trialOnce')}</Typography.Text>
          </> : <PurchaseConfirm offer={shown.offer} days={shown.days} changed={shown.changed} agreements={agreements} />}
          {unknown ? <Alert type="warning" showIcon message={t('buy.unknownTitle')} description={t('buy.unknownDetail')} /> : null}
        </Space> : null}
      </Modal>
      {bought ? <Alert type="success" showIcon closable onClose={() => setBought(null)} message={t('buy.boughtTitle', { name: bought })}
        description={t('buy.boughtDetail')} action={<Button size="small" type="primary"
          onClick={() => setParams((cur) => { const next = new URLSearchParams(cur); next.set('tab', 'supplies'); return next }, { replace: true })}>
          {t('buy.toSupplies')}</Button>} /> : null}
      {pending && !confirming ? <OutcomeUnknown title={t('buy.unknownTitle')} detail={t('buy.pendingOf', { name: pending.offer.name, days: pending.trial ? pending.offer.trial_days ?? 0 : pending.days })
        + t('buy.unknownDetail')} action={<Space wrap>
        <Button size="small" loading={buy.isPending} onClick={() => send(pending)}>{t('buy.checkResult')}</Button>
        <Button size="small" onClick={abandon}>{t('buy.abandon')}</Button>
      </Space>} /> : null}
      {/* 常显 地区/线路/计费方式，单价上限、质量分下限、结算方式进高级筛选（共享 AdvancedFilters）。 */}
      <AdvancedFilters
        className="node-market-v2-advfilters"
        storageKey="node-market-offers"
        columns={3}
        primary={<>
          <Input style={{ width: 120 }} placeholder={t('filters.region')} aria-label={t('filters.region')} value={draft.region ?? ''}
            onChange={(e) => setDraft({ ...draft, region: e.target.value.trim() || undefined })} onPressEnter={() => applyFilters(draft)} />
          <Input style={{ width: 120 }} placeholder={t('filters.carrier')} aria-label={t('filters.carrier')} value={draft.carrier ?? ''}
            onChange={(e) => setDraft({ ...draft, carrier: e.target.value.trim() || undefined })} onPressEnter={() => applyFilters(draft)} />
          <Select style={{ width: 180 }} allowClear placeholder={t('filters.anyModel')} aria-label={t('filters.model')} value={draft.billing_model}
            // A price only compares within one billing model's unit: clearing the model drops it.
            onChange={(value?: string) => setDraft({ ...draft, billing_model: value, max_price: value ? draft.max_price : undefined })}
            options={billingModels.map((value) => ({ value, label: model(value) }))} />
        </>}
        items={[
          { key: 'max_price', label: t('filters.maxPrice'), applied: filters.max_price === undefined ? undefined : String(minorToYuan(filters.max_price)),
            field: <InputNumber min={0} precision={2} disabled={!draft.billing_model} aria-label={t('filters.maxPrice')}
              value={draft.max_price === undefined ? undefined : minorToYuan(draft.max_price)}
              placeholder={draft.billing_model ? t(`filters.maxPriceIn.${draft.billing_model}`, { defaultValue: t('filters.maxPrice') }) : t('filters.pickModelFirst')}
              onChange={(value) => setDraft({ ...draft, max_price: yuanToMinor(value) ?? undefined })} /> },
          { key: 'min_score', label: t('filters.minScore'), applied: filters.min_score === undefined ? undefined : String(filters.min_score),
            field: <InputNumber min={0} max={3} step={0.5} placeholder={t('filters.minScore')} aria-label={t('filters.minScore')}
              value={draft.min_score} onChange={(value) => setDraft({ ...draft, min_score: value === null ? undefined : Number(value) })} /> },
          { key: 'settlement_mode', label: t('filters.settlement'), applied: filters.settlement_mode ? t(`settlement.${filters.settlement_mode}`) : undefined,
            field: <Select allowClear placeholder={t('filters.anySettlement')} aria-label={t('filters.settlement')} value={draft.settlement_mode}
              onChange={(value?: 'direct' | 'escrow') => setDraft({ ...draft, settlement_mode: value })}
              options={[{ value: 'direct', label: t('settlement.direct') }, { value: 'escrow', label: t('settlement.escrow') }]} /> },
        ]}
        queryText={t('filters.apply')}
        onQuery={() => { if (JSON.stringify(draft) === JSON.stringify(filters)) void query.refetch(); else applyFilters(draft) }}
        onReset={() => { setDraft({}); applyFilters({}) }}
        onClearAdvanced={() => { const next = { ...draft, max_price: undefined, min_score: undefined, settlement_mode: undefined }; setDraft(next); applyFilters(next) }}
        onRemove={(key) => { const next = { ...draft, [key]: undefined }; setDraft(next); applyFilters(next) }}
      />
      <Typography.Text type="secondary" className="node-market-v2-help">{t('filters.help')} {t('settlement.directHelp')}</Typography.Text>
      {access.purchase && !access.sites ? <Alert type="warning" showIcon message={t('buy.noSiteAccess')} /> : null}
      {marketForbidden(query.error) ? <NotOpen scope="market" /> : null}
      {query.error && !marketUnavailable(query.error) && !marketForbidden(query.error)
        ? <DataState status="error" message={t('offers.loadFailed', { code: errorCode(query.error) })} onRetry={() => void query.refetch()} /> : null}
      <Table<MarketOfferListing> rowKey="id" loading={query.isLoading} dataSource={query.error ? [] : items} pagination={false} scroll={{ x: 1000 }}
        locale={{ emptyText: query.error ? (marketUnavailable(query.error) ? t('unavailable') : t('offers.loadFailedShort'))
          : Object.values(filters).some((v) => v !== undefined) ? t('offers.emptyFiltered') : t('offers.empty') }}
        columns={[
          // One column per decision: who sells it, what it costs, how good it is, what it requires.
          { title: t('offers.name'), key: 'name', render: (_: unknown, o) => <div className="node-market-v2-offer">
            <span className="node-market-v2-offer-name">{o.name}</span>
            <Space size={4} wrap>
              <Typography.Text type="secondary" className="node-market-v2-offer-seller">{t('offers.seller')} {o.seller_id.slice(0, 8)}</Typography.Text>
              <SellerCreditTags credit={o.seller_credit} />
            </Space>
          </div> },
          { title: t('offers.price'), key: 'price', render: (_: unknown, o) => <div className="node-market-v2-price">
            <span>{offerPriceText(t, o)}</span>
            <Typography.Text type="secondary">{model(o.billing_model)}</Typography.Text>
          </div> },
          { title: t('quality.score'), key: 'quality', width: 96, render: (_: unknown, o) => <span className="node-market-v2-num">{offerQualityText(t, o)}</span> },
          { title: t('offers.terms'), key: 'terms', render: (_: unknown, o) => <Space size={4} wrap>
            <Tag color={o.settlement_mode === 'escrow' ? 'blue' : 'default'}>{t(`settlement.${o.settlement_mode ?? 'direct'}`)}</Tag>
            <Tag>{t('offers.domainsCap', { value: limitCap(o, 'domains') ?? t('sell.unlimited') })}</Tag>
            {limitCap(o, 'monthly_traffic_bytes') ? <Tag>{t('buy.cap', { value: formatBytes(limitCap(o, 'monthly_traffic_bytes')!) })}</Tag> : null}
            {o.compliance?.require_icp ? <Tag color="warning">{t('offers.icp')}</Tag> : null}
          </Space> },
          { key: 'detail', render: (_: unknown, o) => <Button size="small" onClick={() => setDetail(o)}>{t('detail.open')}</Button> },
          {
            key: 'buy', render: (_: unknown, o) => {
              if (!access.purchase) return null
              // A13: node escrow is retired (direct only); the market hides and refuses such offers.
              if (o.settlement_mode === 'escrow') return <Typography.Text type="secondary">{t('buy.escrowRetired')}</Typography.Text>
              const metered = meteredModels.has(o.billing_model)
              return (
                <Space>
                  {metered ? <Typography.Text type="secondary">{t('buy.metered', { deposit: formatYuan(o.pricing?.deposit_minor ?? 0) })}</Typography.Text> :
                    <InputNumber size="small" min={o.pricing?.min_days ?? 1} max={o.pricing?.max_days ?? 365} aria-label={t('offers.days')}
                      value={days[o.id] ?? o.pricing?.min_days ?? 1} onChange={(value) => setDays({ ...days, [o.id]: Number(value) })} />}
                  {/* While a purchase's result is unknown no new one starts: it is checked by replaying its key. */}
                  <Button size="small" type="primary" disabled={!!pending}
                    onClick={() => openBuy(o, metered ? 1 : days[o.id] ?? o.pricing?.min_days ?? 1)}>{t('offers.buy')}</Button>
                  {!metered && (o.trial_days ?? 0) > 0 ? <Button size="small" disabled={!!pending}
                    onClick={() => openBuy(o, 0, true)}>{t('buy.trial', { days: o.trial_days })}</Button> : null}
                </Space>
              )
            },
          },
        ]} />
      {cursors.length || next ? <Space>
        <Button disabled={!cursors.length || query.isFetching} onClick={() => setCursors(cursors.slice(0, -1))}>{t('filters.previous')}</Button>
        <Typography.Text type="secondary">{t('filters.page', { page: cursors.length + 1 })}</Typography.Text>
        <Button disabled={!next || cursors.includes(next) || query.isFetching} onClick={() => next && setCursors([...cursors, next])}>
          {t('filters.next')}</Button>
      </Space> : null}
    </Space>
  )
}

function formatBytes(value: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${Number.isInteger(size) ? size : size.toFixed(1)} ${units[unit]}`
}

function limitCap(o: MarketOfferListing, metric: MarketLimitMetric): number | undefined {
  return o.limits?.find((l) => l.metric === metric)?.cap
}

// Limits of an own offer, with the node rows the platform floor now tightens
// and the tagged plugins the nodes no longer have.
function LimitsSummary({ offer, floor }: { offer: MarketOfferListing; floor: LoadFloor | null }) {
  const { t } = useTranslation('nodeMarket')
  const limits = offer.limits ?? []
  const overridden = overriddenBy(limits, floor)
  const missing = offer.plugins_unavailable ?? []
  return (
    <Space direction="vertical" size={2}>
      {limits.length === 0 ? <span>{t('sell.unlimited')}</span> : <Space size={4} wrap>
        {limits.map((l) => {
          const shown = formatCap(l.metric, l.cap)
          return <Tag key={l.metric}>{t(`limitMetrics.${l.metric}`)} {shown.value} {t(`limitUnits.${shown.unit}`)} · {t(`limitActions.${l.action}`)}</Tag>
        })}
      </Space>}
      {overridden.length ? <Typography.Text type="warning" style={{ fontSize: 12 }}>{t('sell.overridden', {
        items: overridden.map((o) => `${t(`limitMetrics.${o.metric}`)} ${o.effective}%`).join('、') })}</Typography.Text> : null}
      {missing.length ? <Typography.Text type="danger" style={{ fontSize: 12 }}>{t('sell.pluginsUnavailable', { plugins: missing.join('、') })}</Typography.Text> : null}
    </Space>
  )
}

// The probing notice is one short line; the long explanation
// (port 80, agent setting) opens on demand instead of filling the form's top.
function ProbeNotice() {
  const { t } = useTranslation('nodeMarket')
  const [open, setOpen] = useState(false)
  return <Alert type="info" showIcon style={{ marginBottom: 16 }} message={<Space size={4} wrap>
    <span>{t('sell.probeNotice')}</span>
    <Button type="link" size="small" style={{ padding: 0, height: 'auto' }} aria-expanded={open} onClick={() => setOpen((v) => !v)}>
      {t('sell.probeMore')}</Button>
  </Space>} description={open ? t('sell.probeDetail') : undefined} />
}

function SellTab() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const { message, modal } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  // PublishOffer lists a draft or a delisted offer again under the same ID; the
  // market re-checks every listing gate and answers listed or pending_review.
  const publish = useMutation({
    mutationFn: (offerID: string) => marketApi.publishOffer(token, offerID),
    onSuccess: (result) => {
      void message.success(result.status === 'pending_review' ? t('sell.publishedReview') : t('sell.published'))
      void client.invalidateQueries({ queryKey: ['nodeMarket'] })
    },
    onError: (error) => {
      const code = errorCode(error)
      void feedback.error(code === 'no_active_leaf' ? t('errors.noActiveLeaf') : t('errors.failed', { code }))
    },
  })
  const republish = (o: MarketOfferListing) => modal.confirm({
    title: t('sell.republishTitle', { name: o.name }), content: t('sell.republishConfirm'),
    okText: t('sell.republish'), onOk: () => publish.mutateAsync(o.id).catch(() => undefined),
  })
  const mine = useQuery({ queryKey: ['nodeMarket', 'myOffers'], queryFn: () => marketApi.myOffers(token), enabled: !!token })
  const [slaOffer, setSlaOffer] = useState<MarketOfferListing | null>(null)
  const [subscribersOf, setSubscribersOf] = useState<MarketOfferListing | null>(null)
  const [checked, setChecked] = useState<string[]>([])
  const policy = useQuery({ queryKey: ['nodeMarket', 'listing', 'floor'], queryFn: () => marketApi.supplyLimitsPolicy(token), enabled: !!token, retry: false })
  const floor = policy.data?.policy.load_floor ?? null
  const checkedOffers = (mine.data ?? []).filter((o) => checked.includes(o.id))
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <SellerSiteGuide scope="node" />
      <OfferSlaModal offer={slaOffer} onClose={() => setSlaOffer(null)} />
      <OfferSubscribersDrawer offer={subscribersOf} onClose={() => setSubscribersOf(null)} />
      <Typography.Title level={5}>{t('sell.mine')}</Typography.Title>
      <OfferBulkActions offers={checkedOffers} floor={floor} onDone={() => setChecked([])} />
      <Table<MarketOfferListing> rowKey="id" size="small" loading={mine.isLoading} dataSource={mine.data ?? []} pagination={{ pageSize: 20 }}
        locale={{ emptyText: t('sell.mineEmpty') }}
        rowSelection={{ selectedRowKeys: checked, onChange: (keys) => setChecked(keys.map(String)),
          // antd forwards aria-* to the checkbox input; its CheckboxProps type omits them.
          getCheckboxProps: (o) => ({ 'aria-label': o.name }) as CheckboxProps }}
        columns={[
          { title: t('offers.name'), dataIndex: 'name' },
          { title: t('sell.status'), dataIndex: 'status', render: (v: string) => <State value={v} /> },
          { title: t('offers.price'), key: 'price', render: (_: unknown, o) => offerPriceText(t, o) },
          { title: t('sell.limits'), key: 'limits', render: (_: unknown, o) => <LimitsSummary offer={o} floor={floor} /> },
          { title: t('sell.prepaid'), key: 'prepaid', render: (_: unknown, o) => t(`limitActions.${o.prepaid_exhausted_action ?? 'pause'}`) },
          { title: t('sla.column'), key: 'sla', render: (_: unknown, o) => o.sla
            ? t('sla.summary', { target: (o.sla.availability_target * 100).toFixed(2), window: t(`sla.windows.${o.sla.measure_window}`) })
            : t('sla.none') },
          {
            key: 'publish', render: (_: unknown, o) => <Space size={4}>
              {o.status === 'draft' ? <Button size="small" onClick={() => publish.mutate(o.id)} loading={publish.isPending && publish.variables === o.id}>{t('sell.publish')}</Button> : null}
              {o.status === 'delisted' ? <Button size="small" onClick={() => republish(o)} loading={publish.isPending && publish.variables === o.id}>{t('sell.republish')}</Button> : null}
              {o.status !== 'retired' ? <Button size="small" onClick={() => setSlaOffer(o)}>{t('sla.edit')}</Button> : null}
              {o.status !== 'draft' ? <Button size="small" onClick={() => setSubscribersOf(o)}>{t('sell.subscribers')}</Button> : null}
            </Space>,
          },
        ]} />
      <Typography.Title level={5}>{t('sell.create')}</Typography.Title>
      <ProbeNotice />
      <OfferListingForm />
    </Space>
  )
}

// The open or last upstream pause and how upstream-pause/v1 compensated it.
function UpstreamPauseText({ pause }: { pause: MarketUpstreamPause }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const at = (v: string) => formatDateTime(v, i18n.resolvedLanguage ?? 'zh-CN')
  if (!pause.ended_at || !pause.outcome) return <>{t('subscription.upstreamPauseOpen', { time: at(pause.started_at) })}</>
  const minutes = Math.round(pause.extended_seconds / 60)
  const duration = minutes >= 60 ? t('subscription.hoursMinutes', { h: Math.floor(minutes / 60), m: minutes % 60 }) : t('subscription.minutes', { m: minutes })
  return <>{t(`subscription.upstreamPauseOutcomes.${pause.outcome}`, { start: at(pause.started_at), end: at(pause.ended_at),
    duration, amount: money(pause.refund_minor) })}</>
}

function SubscriptionDrawer({ supply, onClose }: { supply: MarketSupply | null; onClose: () => void }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message, modal } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const canBuy = marketAccess(useSessionStore((state) => state.principal)).purchase
  const subscriptionID = supply?.market_subscription_id ?? ''
  const queryKey = ['nodeMarket', 'subscription', subscriptionID]
  const query = useQuery({ queryKey, enabled: !!token && !!subscriptionID, queryFn: () => marketApi.subscription(token, subscriptionID) })
  const fail = (error: unknown) => {
    if (marketUnavailable(error)) void message.info(t('unavailable'))
    else void feedback.error(t('errors.failed', { code: errorCode(error) }))
  }
  const refresh = () => void client.invalidateQueries({ queryKey })
  const renewal = useMutation({
    mutationFn: (value: RenewalPricePolicy) => marketApi.setRenewalPolicy(token, subscriptionID, value, newIdempotencyKey('renewal-policy')),
    onSuccess: () => { void message.success(t('subscription.saved')); refresh() }, onError: fail,
  })
  const limits = useMutation({
    mutationFn: (value: MarketSelectionLimits) => marketApi.setSelectionLimits(token, subscriptionID, value, newIdempotencyKey('selection-limits')),
    onSuccess: () => { void message.success(t('subscription.saved')); refresh() }, onError: fail,
  })
  const cancel = useMutation({
    mutationFn: () => marketApi.cancelSubscription(token, subscriptionID, newIdempotencyKey('subscription-cancel')),
    onSuccess: () => { void message.success(t('subscription.cancelled')); refresh(); void client.invalidateQueries({ queryKey: ['nodeMarket', 'supplies'] }) },
    onError: fail,
  })
  const terms = query.data
  const open = terms && terms.status === 'active' && !terms.cancel_at_period_end
  const policy = useQuery({ queryKey: ['nodeMarket', 'listing', 'floor'], queryFn: () => marketApi.supplyLimitsPolicy(token), enabled: !!terms?.outage, retry: false })
  return (
    <Drawer open={!!supply} onClose={onClose} width="min(880px, 100vw)" title={supply?.name} destroyOnHidden>
      {query.error ? (marketUnavailable(query.error) ? <Unavailable /> : <Alert type="error" showIcon
        message={t('errors.failed', { code: errorCode(query.error) })} />) : null}
      {terms ? <OutageCancel subscriptionID={subscriptionID} outage={terms.outage} canBuy={canBuy}
        cancelAfterMinutes={Number(policy.data?.policy.outage_cancel_after_minutes) || undefined} /> : null}
      {terms?.renewal_stop ? <Alert type="warning" showIcon message={t('subscription.renewalStopBanner', {
        reason: marketReason(terms.renewal_stop.reason, i18n.language).reason })}
        description={terms.renewal_stop.reason === 'upstream_paused' ? t('subscription.renewalStopPaused')
          : terms.renewal_stop.initiator === 'seller' ? t('subscription.renewalStopRefunded') : t('subscription.renewalStopNoRefund')} /> : null}
      {terms ? <Tabs items={[
        { key: 'usage', label: t('usage.title'), children: <SubscriptionUsagePanel terms={terms} /> },
        // C22 (u4d): report a fault straight to the seller.
        { key: 'feedback', label: t('marketSupplier:feedback.report'), children: <FeedbackList role="buyer" subscriptionID={subscriptionID} canWrite={canBuy} /> },
        { key: 'terms', label: t('subscription.manage'), children: <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label={t('supplies.status')}><State value={terms.status} />
            {terms.cancel_at_period_end ? <Tag>{t('subscription.endsAtPeriod')}</Tag> : null}</Descriptions.Item>
          <Descriptions.Item label={t('filters.settlement')}>{t(`settlement.${terms.settlement_mode}`)}</Descriptions.Item>
          {terms.paid_through ? <Descriptions.Item label={t('subscription.paidThrough')}>
            {formatDateTime(terms.paid_through, i18n.resolvedLanguage ?? 'zh-CN')}</Descriptions.Item> : null}
          {terms.renewal_stop ? <Descriptions.Item label={t('subscription.renewalStop')}>
            <ReasonText code={terms.renewal_stop.reason} /> · {t(`subscription.initiators.${terms.renewal_stop.initiator}`)}
            {' · '}{t('subscription.renewalStopSince', { time: formatDateTime(terms.renewal_stop.since, i18n.resolvedLanguage ?? 'zh-CN') })}
          </Descriptions.Item> : null}
          {terms.upstream_pause ? <Descriptions.Item label={t('subscription.upstreamPause')}>
            <UpstreamPauseText pause={terms.upstream_pause} /></Descriptions.Item> : null}
          {terms.compensation_policy ? <Descriptions.Item label={t('subscription.compensationPolicy')}>
            <Typography.Text>{t(`subscription.compensationPolicies.${terms.compensation_policy}`, { defaultValue: terms.compensation_policy })}</Typography.Text>
          </Descriptions.Item> : null}
          {/* MC12 E3: the close reason in words; the number stays copyable. */}
          {terms.close_code ? <Descriptions.Item label={t('subscription.closeCode')}>
            {closeReason(terms.close_code, i18n.language).reason} · {t(`subscription.initiators.${terms.close_initiator ?? 'system'}`)}
            <Typography.Text type="secondary" copyable={{ text: String(terms.close_code) }} style={{ marginInlineStart: 8, fontSize: 12 }}>{terms.close_code}</Typography.Text>
          </Descriptions.Item> : null}
        </Descriptions>
        <Typography.Text type="secondary">{t('settlement.' + (terms.settlement_mode === 'escrow' ? 'escrowHelp' : 'directHelp'))}</Typography.Text>
        <div>
          <Typography.Title level={5}>{t('subscription.renewal')}</Typography.Title>
          <Select<RenewalPricePolicy> style={{ width: 260 }} aria-label={t('subscription.renewal')} value={terms.renewal_price_policy}
            disabled={!canBuy} loading={renewal.isPending} onChange={(value) => renewal.mutate(value)}
            options={(['always', 'if_lesser', 'if_lesser_or_equal', 'if_equal', 'never'] as const).map((value) =>
              ({ value, label: t(`subscription.policies.${value}`) }))} />
        </div>
        <div>
          <Typography.Title level={5}>{t('subscription.selectionTitle')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('subscription.selectionHelp')}</Typography.Paragraph>
          <Form layout="vertical" key={`${terms.id}:${terms.max_unit_price_minor ?? ''}:${terms.min_quality_score ?? ''}`} disabled={!canBuy}
            initialValues={{ price: terms.max_unit_price_minor == null ? null : minorToYuan(terms.max_unit_price_minor), score: terms.min_quality_score ?? null }}
            onFinish={(v: { price: number | null; score: number | null }) => limits.mutate({
              max_unit_price_minor: v.price === null || v.price === undefined ? null : yuanToMinor(v.price),
              min_quality_score: v.score === null || v.score === undefined ? null : Number(v.score) })}>
            <Space wrap>
              <Form.Item name="price" label={t('subscription.priceCap')}><InputNumber min={0.01} precision={2} /></Form.Item>
              <Form.Item name="score" label={t('subscription.minScore')}><InputNumber min={0} max={3} step={0.1} /></Form.Item>
            </Space>
            {canBuy ? <Button type="primary" htmlType="submit" loading={limits.isPending}>{t('subscription.save')}</Button> : null}
          </Form>
        </div>
        {canBuy && open ? <Button danger loading={cancel.isPending}
          onClick={() => modal.confirm({ title: t('subscription.cancelConfirm'), onOk: () => cancel.mutateAsync() })}>{t('subscription.cancel')}</Button> : null}
      </Space> },
      ]} /> : null}
    </Drawer>
  )
}

function StatementsTab() {
  const { t } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const canAct = marketAccess(useSessionStore((state) => state.principal)).purchase
  const pages = useCursorPages()
  const query = useQuery({ queryKey: ['nodeMarket', 'statements', pages.cursor], queryFn: () => marketApi.usageStatements(token, undefined, pages.cursor), enabled: !!token })
  const [disputing, setDisputing] = useState<MarketUsageStatement | null>(null)
  const [note, setNote] = useState('')
  const done = (key: string) => () => { void message.success(t(key)); void client.invalidateQueries({ queryKey: ['nodeMarket', 'statements'] }) }
  const fail = (error: unknown) => void feedback.error(marketUnavailable(error) ? t('unavailable') : t('errors.failed', { code: errorCode(error) }))
  const accept = useMutation({ mutationFn: (s: MarketUsageStatement) => marketApi.acceptStatement(token, s.id, newIdempotencyKey('statement-accept')),
    onSuccess: done('statements.accepted'), onError: fail })
  const dispute = useMutation({
    mutationFn: (s: MarketUsageStatement) => marketApi.disputeStatement(token, s.id, note.trim(), newIdempotencyKey('statement-dispute')),
    onSuccess: (_, s) => { setDisputing(null); setNote(''); done(s.settlement_mode === 'escrow' ? 'statements.disputed' : 'statements.disputedDirect')() },
    onError: fail })
  if (marketUnavailable(query.error)) return <Unavailable />
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Text type="secondary">{t('statements.help')}</Typography.Text>
      {query.error ? <LoadFailure error={query.error} title={t('errors.failed', { code: errorCode(query.error) })} /> : null}
      <Table<MarketUsageStatement> rowKey="id" loading={query.isLoading} dataSource={query.data?.items ?? []} pagination={false}
        locale={{ emptyText: t('statements.empty') }} rowClassName={(s) => (s.flagged ? 'node-market-flagged' : '')}
        columns={[
          { title: t('statements.period'), key: 'period', render: (_: unknown, s) => `${s.period_start.slice(0, 10)} ~ ${s.period_end.slice(0, 10)}` },
          { title: t('statements.usage'), key: 'usage', render: (_: unknown, s) => [s.bytes_out !== undefined ? formatBytes(s.bytes_out) : null,
            s.p95_mbps !== undefined ? `P95 ${s.p95_mbps} Mbps` : null].filter(Boolean).join(' / ') || '—' },
          { title: t('statements.amount'), dataIndex: 'amount_minor', render: (v: number) => formatYuan(v) },
          { title: t('statements.status'), dataIndex: 'status', render: (v: string, s) => <Space size={4}><State value={v} />
            {s.flagged ? <Tag color="error">{t('statements.flagged')}</Tag> : null}</Space> },
          { title: t('statements.deadline'), dataIndex: 'accept_deadline', render: (v?: string | null) => v ? v.replace('T', ' ').slice(0, 16) : '—' },
          { key: 'actions', render: (_: unknown, s) => canAct && s.status === 'issued' ? <Space size={4}>
            <Button size="small" type="primary" loading={accept.isPending} onClick={() => accept.mutate(s)}>{t('statements.accept')}</Button>
            <Button size="small" danger onClick={() => setDisputing(s)}>{t('statements.dispute')}</Button>
          </Space> : null },
        ]} />
      <CursorPager pages={pages} pageSize={50} count={query.data?.items.length ?? 0} next={query.data?.next_cursor} busy={query.isFetching} />
      <Modal open={!!disputing} title={t('statements.dispute')} onCancel={() => setDisputing(null)} confirmLoading={dispute.isPending}
        okButtonProps={{ disabled: !note.trim() }} onOk={() => disputing && dispute.mutate(disputing)}>
        <Alert type="info" showIcon style={{ marginBottom: 12 }}
          message={t(disputing?.settlement_mode === 'escrow' ? 'statements.disputeEscrow' : 'statements.disputeDirect')} />
        <Input.TextArea aria-label={t('statements.disputeNote')} placeholder={t('statements.disputeNote')} maxLength={4000} rows={4}
          value={note} onChange={(e) => setNote(e.target.value)} />
      </Modal>
    </Space>
  )
}

function disputeSubject(d: MarketDispute): string {
  if (d.subject_kind === 'order') return d.market === 'plugin' ? 'plugin_order' : 'node_order'
  return d.subject_kind
}

function DisputesTab() {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message, modal } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const canAct = marketAccess(useSessionStore((state) => state.principal)).purchase
  const [filters, setFilters] = useState<DisputeFilters>({})
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  const query = useQuery({ queryKey: ['nodeMarket', 'disputes', filters, cursor], enabled: !!token,
    queryFn: () => marketApi.disputes(token, { ...filters, cursor }) })
  const withdraw = useMutation({
    mutationFn: (d: MarketDispute) => marketApi.withdrawDispute(token, d.id, newIdempotencyKey('dispute-withdraw')),
    onSuccess: () => { void message.success(t('disputes.withdrawn')); void client.invalidateQueries({ queryKey: ['nodeMarket', 'disputes'] }) },
    onError: (error) => void feedback.error(t('errors.failed', { code: errorCode(error) })),
  })
  const setFilter = (next: DisputeFilters) => { setFilters(next); setCursors([]) }
  const time = (v?: string | null) => (v ? formatDateTime(v, i18n.resolvedLanguage ?? 'zh-CN') || v : '—')
  const next = query.data?.next_cursor
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Space wrap>
        <Select<MarketDisputeState> allowClear style={{ width: 170 }} placeholder={t('disputes.anyState')} aria-label={t('disputes.state')}
          value={filters.status} onChange={(status) => setFilter({ ...filters, status })}
          options={(['awaiting_seller', 'under_review', 'resolved_buyer', 'resolved_seller', 'resolved_split', 'withdrawn', 'closed'] as const)
            .map((value) => ({ value, label: t(`disputes.stateNames.${value}`) }))} />
        <Select<NonNullable<DisputeFilters['subject_kind']>> allowClear style={{ width: 170 }} placeholder={t('disputes.anySubject')}
          aria-label={t('disputes.subject')} value={filters.subject_kind} onChange={(subject_kind) => setFilter({ ...filters, subject_kind })}
          options={(['plugin_order', 'order', 'usage_statement', 'sla_breach'] as const)
            .map((value) => ({ value, label: t(`disputes.filterSubjects.${value}`) }))} />
      </Space>
      {query.error ? <LoadFailure error={query.error} title={t('errors.failed', { code: errorCode(query.error) })} /> : null}
      <Table<MarketDispute> rowKey="id" loading={query.isLoading} dataSource={query.data?.items ?? []} pagination={false}
        locale={{ emptyText: t('disputes.empty') }} scroll={{ x: 980 }}
        columns={[
          { title: t('disputes.subject'), key: 'subject', render: (_: unknown, d) => <Space size={4}>
            <span>{t(`disputes.subjects.${disputeSubject(d)}`, { defaultValue: d.subject_kind })}</span>
            <Typography.Text code>{d.subject_id.slice(0, 8)}</Typography.Text></Space> },
          { title: t('disputes.state'), dataIndex: 'state', render: (v: string, d) => <Space size={4} wrap>
            <Tag>{t(`disputes.stateNames.${v}`, { defaultValue: v })}</Tag>
            {d.escalations ? <Tag>{t('disputes.escalations', { count: d.escalations })}</Tag> : null}
            {d.refund_id ? <Tag color="green">{t('disputes.refunded')}</Tag> : null}
          </Space> },
          { title: t('disputes.amount'), dataIndex: 'amount_minor', render: (v: number) => formatYuan(v) },
          { title: t('disputes.held'), dataIndex: 'held_minor', render: (v?: number) => v === undefined || v === null ? '—' : formatYuan(v) },
          { title: t('disputes.waiting'), dataIndex: 'waiting_on', render: (v?: string | null) => v ? t(`subscription.initiators.${v}`, { defaultValue: v }) : '—' },
          { title: t('disputes.opened'), dataIndex: 'opened_at', render: time },
          { title: t('disputes.deadline'), dataIndex: 'deadline', render: time },
          { key: 'actions', fixed: 'right', render: (_: unknown, d) => canAct && (d.state === 'awaiting_seller' || d.state === 'under_review') ? (
            <Button size="small" danger loading={withdraw.isPending}
              onClick={() => modal.confirm({ title: t('disputes.withdrawConfirm'), onOk: () => withdraw.mutateAsync(d) })}>{t('disputes.withdraw')}</Button>
          ) : null },
        ]} />
      <Space>
        <Button disabled={!cursors.length || query.isFetching} onClick={() => setCursors(cursors.slice(0, -1))}>{t('disputes.previous')}</Button>
        <Button disabled={!next || cursors.includes(next) || query.isFetching} onClick={() => next && setCursors([...cursors, next])}>
          {t('disputes.next')}</Button>
      </Space>
    </Space>
  )
}

// PrepaidTopup creates a platform top-up order (kind=prepaid_topup) and opens
// the portal checkout; the balance pays escrow subscriptions and plugins.
function PrepaidTopup() {
  const { t } = useTranslation('nodeMarket')
  const feedback = useFeedback()
  const token = useToken()
  const [created, setCreated] = useState<{ no: number; url: string | null } | null>(null)
  const idempotency = useIdempotencyKey('prepaid-topup')
  // A top-up whose answer was lost: replayed with its own key, never re-created.
  const [pending, setPending] = useState<{ amount_minor: number; currency: string; key: string } | null>(null)
  const topup = useMutation({
    mutationFn: (v: { amount_minor: number; currency: string; key: string }) => marketApi.createOrder(token,
      { kind: 'prepaid_topup', amount_minor: v.amount_minor, currency: v.currency }, v.key),
    onSuccess: (result) => {
      idempotency.complete()
      setPending(null)
      const url = checkoutURL(result.checkout_url)
      if (url) window.open(url, '_blank', 'noopener,noreferrer')
      else void feedback.error(t('buy.checkoutBlocked'))
      setCreated({ no: result.order.order_no, url })
    },
    onError: (error, v) => {
      if (outcomeUnknown(error)) return setPending(v)
      idempotency.complete()
      setPending(null)
      if (error instanceof ApiError && error.status === 503) void feedback.warning(t('topup.escrowOff'))
      else void feedback.error(t('errors.failed', { code: errorCode(error) }))
    },
  })
  return (
    <div>
      <Typography.Title level={5}>{t('topup.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('topup.help')}</Typography.Paragraph>
      <Form layout="inline" initialValues={{ currency: 'CNY' }} disabled={!!pending} onFinish={(v: { amount: number; currency: string }) => {
        const body = { amount_minor: yuanToMinor(v.amount) ?? 0, currency: v.currency.trim().toUpperCase() }
        topup.mutate({ ...body, key: idempotency.keyFor(body) })
      }}>
        <Form.Item name="amount" rules={[{ required: true }]}>
          <InputNumber min={0.01} max={1000000} precision={2} placeholder={t('topup.amount')} aria-label={t('topup.amount')} style={{ width: 180 }} />
        </Form.Item>
        <Form.Item name="currency" rules={[{ pattern: /^[A-Za-z]{3}$/ }]}><Input style={{ width: 80 }} aria-label={t('ledger.currency')} /></Form.Item>
        <Button type="primary" htmlType="submit" loading={topup.isPending}>{t('topup.submit')}</Button>
      </Form>
      {pending ? <OutcomeUnknown title={t('buy.unknownTitle')} detail={t('topup.unknownDetail')} action={<Space wrap>
        <Button size="small" loading={topup.isPending} onClick={() => topup.mutate(pending)}>{t('buy.checkResult')}</Button>
        <Button size="small" onClick={() => { idempotency.complete(); setPending(null) }}>{t('buy.abandon')}</Button>
      </Space>} /> : null}
      {created ? <Alert style={{ marginTop: 12 }} type="success" showIcon message={t('topup.created', { no: created.no })}
        action={created.url ? <Button size="small" href={created.url} target="_blank" rel="noopener noreferrer">{t('topup.reopen')}</Button> : null} /> : null}
    </div>
  )
}

// Shape of the cross-controller site config, shown as a placeholder only:
// no value is prefilled, so nothing can be applied without being typed (S6).
function configExample(domain: string, origin: string): string {
  return JSON.stringify({ schema: 'cdnca.market.site/v1', domains: [domain], http_ports: [80], https_ports: [],
    origins: [{ host: origin, port: 80, weight: 1 }] }, null, 2)
}

function SuppliesTab() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const access = marketAccess(useSessionStore((state) => state.principal))
  const [selecting, setSelecting] = useState<MarketSupply | null>(null)
  const query = useQuery({ queryKey: ['nodeMarket', 'supplies'], queryFn: () => marketApi.supplies(token), enabled: !!token && access.browse })
  const bind = useMarketWrite(marketApi.bind, 'supplies.bound')
  // MC12 E2: the administrator picks a saved site; the binding uses it once.
  const [site, setSite] = useState<PickedSite | null>(null)
  const [role, setRole] = useState<'primary' | 'backup'>('primary')
  const [priority, setPriority] = useState(10)
  const none = !query.isLoading && !query.error && (query.data ?? []).length === 0
  // Same query BoundSupplies shows: a supply already bound to the site may be
  // re-bound (role/priority) even with zero leaves; the server allows that (MC05).
  const bound = useQuery({ queryKey: ['nodeMarket', 'siteBindings', site?.id], queryFn: () => marketApi.siteBindings(token, site!.id),
    enabled: !!token && !!site && access.sites })
  const boundIDs = new Set((bound.data ?? []).map((b) => b.supply_id))
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <SubscriptionDrawer supply={selecting} onClose={() => setSelecting(null)} />
      {/* MC12 E1: with nothing bought there is nothing to bind or roll out: say so and point to buying. */}
      {none ? <DataState status="empty" message={t('supplies.none')} description={t('supplies.noneDetail')} /> : null}
      {!access.sites ? <Alert type="info" showIcon message={t('supplies.noSiteAccess')} /> : null}
      {access.sites && !none ? <Space wrap align="center">
        <SitePicker value={site} onChange={setSite} />
        <Select style={{ width: 120 }} aria-label={t('supplies.role')} value={role} onChange={setRole}
          options={[{ value: 'primary', label: t('supplies.usePrimary') }, { value: 'backup', label: t('supplies.useBackup') }]} />
        <Collapse ghost size="small" items={[{ key: 'priority', label: t('supplies.advanced'), children: (
          <Space><Typography.Text>{t('supplies.priority')}</Typography.Text>
            <InputNumber min={0} aria-label={t('supplies.priority')} value={priority} onChange={(value) => setPriority(Number(value ?? 0))} /></Space>
        ) }]} />
      </Space> : null}
      {/* MC04 (NM05): a failed read is not an empty list. */}
      {marketForbidden(query.error) ? <NotOpen scope="market" /> : marketUnavailable(query.error) ? <Unavailable /> : query.error
        ? <DataState status="error" message={t('supplies.loadFailed', { code: errorCode(query.error) })} onRetry={() => void query.refetch()} /> : null}
      {none ? null : <Table<MarketSupply> rowKey="id" loading={query.isLoading} dataSource={query.error ? [] : query.data ?? []} pagination={false}
        scroll={{ x: 'max-content' }} locale={query.error ? { emptyText: t('supplies.loadFailedShort') } : undefined}
        columns={[
          { title: t('supplies.name'), dataIndex: 'name' },
          { title: t('supplies.target'), dataIndex: 'target', render: (v: string) => v ? <Typography.Text copyable code>{v}</Typography.Text> : '—' },
          { title: t('supplies.leaves'), key: 'leaves', render: (_: unknown, s) => s.leaves.length },
          // MC05: an active contract without any leaf has no supply to serve with (the contract itself stays).
          { title: t('supplies.status'), dataIndex: 'status', render: (v: string, s) => v === 'active' && s.leaves.length === 0
            ? <Space direction="vertical" size={0}><Tag color="error">{t('supplies.noSupply')}</Tag>
              <Typography.Text type="secondary">{t('supplies.noSupplyDetail')}</Typography.Text></Space> : <State value={v} /> },
          {
            key: 'bind', render: (_: unknown, supply) => (
              <Space wrap>
                {access.sites ? (
                  <Button size="small" type="primary" disabled={!site || supply.status !== 'active' || supply.leaves.length === 0 && !boundIDs.has(supply.id)}
                    title={site ? undefined : t('supplies.pickSiteFirst')}
                    onClick={() => site && bind.mutate([site.id, supply.id, role, priority])}>
                    {site ? t('supplies.bindTo', { site: site.domain }) : t('supplies.bind')}</Button>
                ) : null}
                {supply.market_subscription_id ? <Button size="small" onClick={() => setSelecting(supply)}>{t('subscription.manage')}</Button> : null}
              </Space>
            ),
          },
        ]} />}
      {access.sites && !none && site ? <>
        <Typography.Title level={5}>{t('supplies.boundTitle', { site: site.domain })}</Typography.Title>
        <BoundSupplies site={site} />
        <Typography.Title level={5}>{t('supplies.rollout')}</Typography.Title>
        <SiteRollout site={site} />
      </> : null}
      {access.sites && !none ? <Collapse ghost size="small" items={[{ key: 'manual', label: t('supplies.manualTitle'), children: <ManualRollout /> }]} /> : null}
    </Space>
  )
}

// Advanced diagnostics: the hand-written revision + JSON rollout (S6: nothing
// prefilled). Ordinary use goes through SiteRollout above.
function ManualRollout() {
  const { t } = useTranslation('nodeMarket')
  const { modal } = App.useApp()
  const token = useToken()
  // MC06 (MK-BUYER-RESULT-01): a result keeps the request it answers (site,
  // revision, config, preview or apply); it only reads as current while the
  // form still holds that request, and a late answer to an older one never
  // replaces the latest.
  type RolloutRequest = { site: string; apply: boolean; revision: number; config: Record<string, unknown> }
  const [rollout, setRollout] = useState<{ request: RolloutRequest; result: MarketRollout } | null>(null)
  const latest = useRef<RolloutRequest | null>(null)
  const [form] = Form.useForm()
  const formValues = Form.useWatch([], form) as { site?: string; revision?: number; config?: string } | undefined
  const run = useMutation({
    mutationFn: (args: RolloutRequest) => marketApi.rollout(token, args.site, args.apply, args.revision, args.config),
    onSuccess: (result, request) => { if (latest.current === request) setRollout({ request, result }) },
  })
  const submit = async (apply: boolean) => {
    let values: { site: string; revision: number; config: string }
    try { values = await form.validateFields() } catch { return }
    let config: unknown
    try { config = JSON.parse(values.config) } catch { config = null }
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      form.setFields([{ name: 'config', errors: [t('supplies.configInvalid')] }])
      return
    }
    const request = { site: values.site.trim(), apply, revision: values.revision, config: config as Record<string, unknown> }
    latest.current = request
    run.mutate(request)
  }
  const rolloutStale = !!rollout && (formValues?.site?.trim() !== rollout.request.site || formValues?.revision !== rollout.request.revision
    || (() => { try { return JSON.stringify(JSON.parse(formValues?.config ?? '')) !== JSON.stringify(rollout.request.config) } catch { return true } })())
  return (
    <>
      <Typography.Paragraph type="secondary">{t('supplies.configHelp')}</Typography.Paragraph>
      <Form form={form} layout="vertical" style={{ maxWidth: 720 }} initialValues={{ revision: 1, config: '' }}>
        <Space wrap>
          <Form.Item name="site" label={t('supplies.siteID')} rules={[{ required: true, whitespace: true, message: t('supplies.siteRequired') }]}><Input style={{ width: 320 }} /></Form.Item>
          <Form.Item name="revision" label={t('supplies.revision')}><InputNumber min={1} /></Form.Item>
        </Space>
        <Form.Item name="config" label={t('supplies.config')} rules={[{ required: true, whitespace: true, message: t('supplies.configRequired') }]}>
          <Input.TextArea rows={8} spellCheck={false} placeholder={configExample(t('supplies.exampleDomain'), t('supplies.exampleOrigin'))} /></Form.Item>
        <Space>
          <Button onClick={() => void submit(false)} loading={run.isPending}>{t('supplies.preview')}</Button>
          <Button type="primary" loading={run.isPending} onClick={() => modal.confirm({ title: t('supplies.applyConfirm'), onOk: () => submit(true) })}>
            {t('supplies.apply')}</Button>
        </Space>
      </Form>
      {run.error && <FeedbackWhen title={run.error instanceof ApiError && run.error.code === 'revision_conflict'
        ? t('supplies.revisionConflict') : t('errors.failed', { code: run.error instanceof ApiError ? run.error.code : 'request_failed' })} />}
      {rollout && (
        <section aria-label={t('supplies.resultTitle')}>
          <Typography.Text type="secondary">{t(rollout.request.apply ? 'supplies.resultOfApply' : 'supplies.resultOfPreview',
            { site: rollout.request.site, revision: rollout.result.revision, digest: rollout.result.digest.slice(0, 12) })}</Typography.Text>
          {rolloutStale ? <Alert type="info" showIcon message={t('supplies.resultStale')} /> : null}
          <Alert type={rollout.result.applied ? 'success' : 'warning'} showIcon message={rollout.result.applied ? t('supplies.applied')
            : rollout.result.reason === 'receipt_pending' ? t('supplies.receiptPending') : t('supplies.notApplied')} />
          <Table rowKey={(l) => `${l.leaf.leaf_member_id}/${l.leaf.node_pool_ref}`} dataSource={rollout.result.leaves} pagination={false} size="small"
            columns={[
              { title: t('member.id'), key: 'leaf', render: (_: unknown, l) => <Typography.Text code>{l.leaf.leaf_member_id.slice(0, 8)}</Typography.Text> },
              { title: t('supplies.status'), dataIndex: 'state', render: (v: string) => <State value={v} /> },
              { key: 'detail', render: (_: unknown, l) => <ClampedReason lines={[
                ...(l.blockers ?? []).map((b, i) => <ReasonText key={`${b.code}-${i}`} code={b.code} detail={b.detail} />),
                ...(l.error ? [<Typography.Text key="error" type="secondary" copyable={{ text: l.error }}>{t('supplies.leafError')}</Typography.Text>] : []),
              ]} /> },
            ]} />
        </section>
      )}
    </>
  )
}

// A balance query frozen when it is sent (MC12 E4): account, both parties,
// currency and sequence. Its answer or error only shows while the inputs and
// the account still match and no later query went out; each carries its time.
type BalanceQuery = { account: string; buyer: string; seller: string; sellerName?: string; currency: string; seq: number }
type BalanceAnswer = { query: BalanceQuery; at: Date } & ({ balance: number } | { error: unknown })
const balanceKey = (q: Pick<BalanceQuery, 'account' | 'buyer' | 'seller' | 'currency'>) => `${q.account}/${q.buyer}/${q.seller}/${q.currency}`

function useBalanceQuery(inputs: Omit<BalanceQuery, 'seq'> | null) {
  const token = useToken()
  const latest = useRef(0)
  const [answer, setAnswer] = useState<BalanceAnswer | null>(null)
  const key = inputs ? balanceKey(inputs) : ''
  const live = useRef(key)
  live.current = key
  // Any change of inputs drops the answer and the query in flight, so going
  // back (A→B→A, CNY→USD→CNY) asks again instead of showing an older answer.
  const [shownKey, setShownKey] = useState(key)
  if (shownKey !== key) { setShownKey(key); setAnswer(null) }
  useEffect(() => { latest.current += 1 }, [key])
  const owns = (q: BalanceQuery) => latest.current === q.seq && live.current === balanceKey(q)
  const run = useMutation({
    mutationFn: (q: BalanceQuery) => marketApi.balance(token, q.buyer, q.seller, q.currency),
    onSuccess: (result, q) => { if (owns(q)) setAnswer({ query: q, at: new Date(), balance: result.balance_minor }) },
    onError: (error, q) => { if (owns(q)) setAnswer({ query: q, at: new Date(), error }) },
  })
  const send = () => {
    if (!inputs) return
    latest.current += 1
    run.mutate({ ...inputs, seq: latest.current })
  }
  // Other inputs or another account: the shown answer is of another query.
  const current = answer && balanceKey(answer.query) === key ? answer : null
  const pending = run.isPending && !!run.variables && owns(run.variables)
  return { send, current, pending }
}

function BalanceAnswerView({ answer, party, onRetry, pending }: { answer: BalanceAnswer; party: string; onRetry: () => void; pending: boolean }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const at = formatDateTime(answer.at.toISOString(), i18n.resolvedLanguage ?? 'zh-CN')
  if ('error' in answer) {
    return <Alert type="error" showIcon message={t('ledger.failedFor', { party, currency: answer.query.currency })}
      description={t('ledger.failedDetail', { reason: marketReason(errorCode(answer.error), i18n.language).reason, time: at })}
      action={<Button size="small" loading={pending} onClick={onRetry}>{t('ledger.retry')}</Button>} />
  }
  return (
    <div role="status">
      <Typography.Text strong>{t('ledger.balanceOf', { party, value: money(answer.balance, answer.query.currency) })}</Typography.Text>
      <br /><Typography.Text type="secondary">{t('ledger.queriedAt', { time: at })}</Typography.Text>
    </div>
  )
}

// SupplierBalance: my balance with one of my suppliers (the sellers of
// 我的供货方余额); my own member ID comes from the market, not a text box.
function SupplierBalance() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const account = useSessionStore((state) => state.principal ? `${state.principal.user_id}/${state.principal.scope_id}` : '')
  const member = useQuery({ queryKey: ['nodeMarket', 'member'], queryFn: () => marketApi.member(token), enabled: !!token })
  const summary = useQuery({ queryKey: ['nodeMarket', 'prepaid', 'CNY'], queryFn: () => marketApi.prepaid(token, 'CNY'), enabled: !!token, retry: false })
  const sellers = useQuery({ queryKey: ['nodeMarket', 'directSellers'], queryFn: () => marketApi.directSellers(token), enabled: !!token, retry: false })
  const options = new Map<string, { name: string; currency: string }>()
  // The same suppliers as 我的供货方余额: ledger rows, then direct sellers without one; a direct seller's own currency wins.
  for (const r of summary.data?.sellers ?? []) options.set(r.seller_member_id, { name: r.display_name, currency: summary.data?.currency ?? 'CNY' })
  for (const s of sellers.data ?? []) options.set(s.seller_id, { name: options.get(s.seller_id)?.name ?? s.display_name, currency: s.currency || 'CNY' })
  const [seller, setSeller] = useState<string | undefined>()
  const [currency, setCurrency] = useState('CNY')
  // Switching account resets the pick: the suppliers are of another member.
  const [pickedFor, setPickedFor] = useState(account)
  if (pickedFor !== account) { setPickedFor(account); setSeller(undefined) }
  const picked = seller ? options.get(seller) : undefined
  const me = member.data?.id
  const inputs = me && seller ? { account, buyer: me, seller, sellerName: picked?.name, currency: currency.trim().toUpperCase() } : null
  const balance = useBalanceQuery(inputs)
  const loadFailure = member.error ?? summary.error ?? sellers.error
  const loading = member.isLoading || summary.isLoading || sellers.isLoading
  return (
    <section aria-label={t('ledger.mineTitle')}>
      <Typography.Title level={5}>{t('ledger.mineTitle')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('ledger.mineHelp')}</Typography.Paragraph>
      {loadFailure ? <DataState status="error" message={t('ledger.suppliersFailed', { code: errorCode(loadFailure) })}
        onRetry={() => { void member.refetch(); void summary.refetch(); void sellers.refetch() }} />
        : !loading && options.size === 0 ? <Typography.Text type="secondary">{t('ledger.noSupplier')}</Typography.Text> : (
          <Space direction="vertical" style={{ width: '100%' }}>
            <Space wrap>
              <Select style={{ width: 280 }} aria-label={t('ledger.supplier')} placeholder={t('ledger.supplierPlaceholder')} loading={loading}
                value={seller} onChange={(v: string) => { setSeller(v); setCurrency(options.get(v)?.currency ?? 'CNY') }}
                options={[...options].map(([id, o]) => ({ value: id, label: o.name }))} />
              <Input style={{ width: 80 }} aria-label={t('ledger.currency')} value={currency} maxLength={3} onChange={(e) => setCurrency(e.target.value)} />
              <Button disabled={!inputs || !/^[A-Za-z]{3}$/.test(currency.trim())} loading={balance.pending} onClick={balance.send}>{t('ledger.balance')}</Button>
            </Space>
            {balance.current ? <BalanceAnswerView answer={balance.current} party={balance.current.query.sellerName ?? ''} pending={balance.pending} onRetry={balance.send} /> : null}
          </Space>
        )}
    </section>
  )
}

// AdvancedLedger: any trading edge by member IDs, for reconciliation; the
// market still decides which edges this controller may read.
function AdvancedLedger() {
  const { t } = useTranslation('nodeMarket')
  const account = useSessionStore((state) => state.principal ? `${state.principal.user_id}/${state.principal.scope_id}` : '')
  const [form] = Form.useForm<{ buyer: string; seller: string; currency: string }>()
  const values = Form.useWatch([], form) as { buyer?: string; seller?: string; currency?: string } | undefined
  const [submitted, setSubmitted] = useState(false)
  const inputs = values?.buyer?.trim() && values?.seller?.trim()
    ? { account, buyer: values.buyer.trim(), seller: values.seller.trim(), currency: (values.currency ?? 'CNY').trim().toUpperCase() } : null
  const balance = useBalanceQuery(inputs)
  const short = (id: string) => id.slice(0, 8)
  return (
    <section aria-label={t('ledger.advancedTitle')}>
      <Typography.Paragraph type="secondary">{t('ledger.advancedHelp')}</Typography.Paragraph>
      <Form form={form} layout="inline" initialValues={{ currency: 'CNY' }} onFinish={() => { setSubmitted(true); balance.send() }}>
        {/* MC12 E4: required messages in words, not the raw buyer/seller field names. */}
        <Form.Item name="buyer" rules={[{ required: true, whitespace: true, message: t('ledger.buyerRequired') }]}><Input placeholder={t('ledger.buyer')} aria-label={t('ledger.buyer')} /></Form.Item>
        <Form.Item name="seller" rules={[{ required: true, whitespace: true, message: t('ledger.sellerRequired') }]}><Input placeholder={t('ledger.seller')} aria-label={t('ledger.seller')} /></Form.Item>
        <Form.Item name="currency" rules={[{ pattern: /^[A-Za-z]{3}$/ }]}><Input style={{ width: 80 }} aria-label={t('ledger.currency')} /></Form.Item>
        <Button htmlType="submit" loading={balance.pending}>{t('ledger.balance')}</Button>
      </Form>
      {submitted && balance.current ? <div style={{ marginTop: 12 }}><BalanceAnswerView answer={balance.current} pending={balance.pending} onRetry={balance.send}
        party={t('ledger.edge', { buyer: short(balance.current.query.buyer), seller: short(balance.current.query.seller) })} /></div> : null}
    </section>
  )
}

function LedgerTab() {
  const { t } = useTranslation('nodeMarket')
  const access = marketAccess(useSessionStore((state) => state.principal))
  const canBuy = access.purchase
  return (
    <Space direction="vertical" style={{ width: '100%', maxWidth: 720 }}>
      <Alert type="info" showIcon message={t('ledgerHelp')} />
      {canBuy ? <PrepaidTopup /> : null}
      <SupplierBalance />
      <Collapse ghost size="small" items={[{ key: 'advanced', label: t('ledger.advanced'), children: <AdvancedLedger /> }]} />
    </Space>
  )
}

type SectionKey = 'browse' | 'supplies' | 'balances' | 'holds' | 'statements' | 'sell' | 'supplier' | 'disputes' | 'ledger'
interface Section { key: SectionKey; label: string; render: () => ReactNode }

// MemberSummary replaces the old 市场身份 tab: who this controller is in the market, in one strip.
function MemberSummary() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const query = useQuery({ queryKey: ['nodeMarket', 'member'], queryFn: () => marketApi.member(token), enabled: !!token })
  // MC04 (NM05): only the market's own "not registered" answer means this
  // controller is not a member; any other failure is a read failure to retry.
  if (query.error) {
    if (query.error instanceof ApiError && query.error.code === 'not_registered') return <Alert type="info" showIcon message={t('member.notRegistered')} />
    if (marketForbidden(query.error)) return <NotOpen scope="market" />
    return <DataState status="error" message={t('member.loadFailed', { code: errorCode(query.error) })} onRetry={() => void query.refetch()} />
  }
  const m = query.data
  const selling = m ? m.features.some((f) => sellingFeatures.includes(f)) : null
  const items: { key: string; label: string; value: ReactNode; tone?: string }[] = [
    { key: 'status', label: t('summary.status'), value: m ? t(`states.${m.status}`, { defaultValue: m.status }) : '—', tone: m?.status === 'active' ? 'is-on' : 'is-warn' },
    { key: 'selling', label: t('summary.selling'), value: selling === null ? '—' : t(selling ? 'summary.sellingOn' : 'summary.sellingOff'), tone: selling ? 'is-on' : 'is-off' },
    { key: 'quota', label: t('summary.quota'), value: m ? m.offers_quota : '—' },
    { key: 'id', label: t('summary.id'), value: m ? <Typography.Text copyable={{ text: m.id }} className="node-market-v2-id">{m.id.slice(0, 8)}</Typography.Text> : '—' },
  ]
  return (
    <section className="site-tab-summary node-market-v2-summary" aria-label={t('summary.label')}>
      <ul>{items.map((item) => <li key={item.key}><div>
        <span className="site-tab-summary-label">{item.label}</span>
        <strong className={`site-tab-summary-value ${item.tone ?? ''}`}>{item.value}</strong>
      </div></li>)}</ul>
    </section>
  )
}

export default function NodeMarketPage() {
  const { t } = useTranslation('nodeMarket')
  const principal = useSessionStore((state) => state.principal)
  const access = marketAccess(principal)
  const token = useToken()
  const { connected, recheck, rechecking } = useMarketConnection(token)
  const agreements = useMarketAgreements(connected ? token : '')
  const [params, setParams] = useSearchParams()
  if (!access.browse) return <Alert type="warning" showIcon message={t('errors.forbidden')} />
  // Nine sections in three groups: what I buy, what I sell, money owed either way.
  const groups: { key: string; items: Section[] }[] = ([
    { key: 'buy', items: [
      { key: 'browse', label: t('tabs.browse'), render: () => <BrowseTab /> },
      { key: 'supplies', label: t('tabs.supplies'), render: () => <SuppliesTab /> },
      { key: 'balances', label: t('tabs.balances'), render: () => <DirectBalancesTab /> },
      { key: 'holds', label: t('marketSupplier:tabs.holds'), render: () => <SubscriberHoldsTab /> },
      { key: 'statements', label: t('tabs.statements'), render: () => <StatementsTab /> },
    ] },
    { key: 'sell', items: access.sell ? [
      { key: 'sell', label: t('tabs.sell'), render: () => <SellTab /> },
      { key: 'supplier', label: t('marketSupplier:tabs.supplier'), render: () => <SupplierTab /> },
    ] : [] },
    { key: 'money', items: [
      { key: 'disputes', label: t('tabs.disputes'), render: () => <DisputesTab /> },
      ...(access.sell || access.purchase ? [{ key: 'ledger' as const, label: t('tabs.ledger'), render: () => <LedgerTab /> }] : []),
    ] },
  ] satisfies { key: string; items: Section[] }[]).filter((g) => g.items.length > 0)
  const all = groups.flatMap((g) => g.items)
  const active = all.find((item) => item.key === params.get('tab')) ?? all[0]
  const select = (key: SectionKey) => setParams((current) => {
    const next = new URLSearchParams(current)
    next.set('tab', key)
    return next
  }, { replace: true })
  return (
    <div className="page node-market-v2">
      <div className="node-market-v2-head">
        <Typography.Title level={4}>{t('title')}</Typography.Title>
        <Typography.Text type="secondary">{t('description')}</Typography.Text>
      </div>
      {connected === undefined ? <DataState status="loading" /> : !connected ? <MarketNotJoined recheck={recheck} rechecking={rechecking} /> : <>
        <MemberSummary />
        <div className="node-market-v2-body">
          <nav className="node-market-v2-nav" aria-label={t('groups.nav')}>
            {groups.map((group) => (
              <div key={group.key} className="node-market-v2-group">
                <span className="node-market-v2-group-title" id={`node-market-group-${group.key}`}>{t(`groups.${group.key}`)}</span>
                <div role="tablist" aria-orientation="vertical" aria-labelledby={`node-market-group-${group.key}`}>
                  {group.items.map((item) => (
                    <button key={item.key} type="button" role="tab" id={`node-market-tab-${item.key}`} aria-selected={item.key === active.key}
                      aria-controls="node-market-panel" tabIndex={item.key === active.key ? 0 : -1}
                      className={item.key === active.key ? 'node-market-v2-tab is-active' : 'node-market-v2-tab'}
                      onClick={() => select(item.key)}
                      onKeyDown={(event) => {
                        if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
                        event.preventDefault()
                        const at = all.findIndex((x) => x.key === item.key)
                        const next = all[(at + (event.key === 'ArrowDown' ? 1 : all.length - 1)) % all.length]
                        select(next.key)
                        document.getElementById(`node-market-tab-${next.key}`)?.focus()
                      }}>{item.label}</button>
                  ))}
                </div>
              </div>
            ))}
          </nav>
          <section className="node-market-v2-panel" role="tabpanel" id="node-market-panel" aria-labelledby={`node-market-tab-${active.key}`}>
            <Typography.Title level={5} className="node-market-v2-panel-title">{active.label}</Typography.Title>
            {active.render()}
          </section>
        </div>
      </>}
      <MarketAgreementFooter agreements={agreements} />
    </div>
  )
}
