import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Descriptions, InputNumber, Progress, Segmented, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import {
  marketApi, marketUnavailable, type MarketHold, type MarketLimitMetric, type MarketLimitUsage, type MarketSubscriptionTerms,
  type MarketSupplyState, type MarketUnscheduledNode,
} from '../../api/market'
import { marketAccess } from '../../api/marketAccess'
import { useSessionStore } from '../../auth/session'
import { MetricTrendChart } from '../../components/MetricTrendChart'
import { formatDateTime } from '../../i18n/formatters'
import { SellerCreditTags } from './DirectBalancesTab'
import { formatCap } from './limitsModel'
import { availabilityColor, hoursLeft, recoveryKey, seriesOf, stateColor, supplyAvailability, usagePercent, usageStatus } from './subscriberModel'
import { useFeedback } from '@cdnca/ui'
import { LoadFailure } from './supplier/shared'

const actionColor = { throttle: 'gold', pause: 'orange', stop: 'red' } as const

function errorCode(error: unknown): string {
  return (error as { code?: string } | null)?.code ?? 'request_failed'
}

function Failure({ error }: { error: unknown }) {
  const { t } = useTranslation('nodeMarket')
  if (marketUnavailable(error)) return <Alert type="info" showIcon message={t('unavailable')} />
  return <LoadFailure error={error} title={t('errors.failed', { code: errorCode(error) })} />
}

// Subscriber usage page of one subscription (ADR 0012 §9.3): each limit's
// usage bar (10–15 minutes behind), a 5-minute curve, holds with reason, start
// and recovery condition, each supply's service state, and the prepaid
// balance, overdraft and alert line.
export function SubscriptionUsagePanel({ terms }: { terms: MarketSubscriptionTerms }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const lang = i18n.resolvedLanguage ?? 'zh-CN'
  const time = (v?: string | null) => (v ? formatDateTime(v, lang) || v : '—')
  const query = useQuery({
    queryKey: ['nodeMarket', 'subscriptionLimits', terms.id], enabled: !!token, retry: false,
    queryFn: () => marketApi.subscriptionLimits(token, terms.id, 24),
  })
  const unscheduled = useQuery({
    queryKey: ['nodeMarket', 'unscheduled'], enabled: !!token, retry: false,
    queryFn: () => marketApi.unscheduled(token),
  })
  const data = query.data
  const [metric, setMetric] = useState<MarketLimitMetric | null>(null)
  const plotted = metric ?? data?.limits[0]?.metric ?? 'monthly_traffic_bytes'
  const points = useMemo(() => {
    const values = seriesOf(data?.series ?? [], plotted)
    return (data?.series ?? []).map((s, i) => ({ label: time(s.bucket_start).slice(-8, -3) || s.bucket_start, value: values[i] ?? 0 }))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, plotted])
  const amount = (m: MarketLimitMetric, value: number) => {
    const shown = formatCap(m, value)
    return `${Number(shown.value.toFixed(2))} ${t(`limitUnits.${shown.unit}`)}`.trim()
  }
  const mine = (unscheduled.data ?? []).filter((n) => n.subscription_id === terms.id)
  const availability = data ? supplyAvailability(data) : null
  return (
    <Space direction="vertical" style={{ width: '100%' }} size="middle">
      {query.error ? <Failure error={query.error} /> : null}
      <Card size="small" title={t('usage.state')} extra={availability ? <Tag color={availabilityColor[availability]}>
        {t(`usage.availability.${availability}`)}</Tag> : null}>
        {availability && availability !== 'serving' ? <Alert type={availability === 'degraded' ? 'warning' : 'error'} showIcon
          style={{ marginBottom: 8 }} message={t(`usage.availabilityHelp.${availability}`)} /> : null}
        <Table size="small" pagination={false} loading={query.isLoading} rowKey={(s) => `${s.leaf_member_id}|${s.node_pool_ref}`}
          dataSource={data?.supplies ?? []} locale={{ emptyText: t('usage.noSupplies') }}
          columns={[
            { title: t('usage.leaf'), dataIndex: 'leaf_member_id', render: (v: string) => <Typography.Text code>{v.slice(0, 8)}</Typography.Text> },
            { title: t('usage.pool'), dataIndex: 'node_pool_ref', render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
            { title: t('usage.serviceState'), dataIndex: 'state', render: (v: MarketSupplyState) => <Tag color={stateColor[v]}>{t(`usage.states.${v}`)}</Tag> },
          ]} />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('usage.stateHelp')}</Typography.Text>
      </Card>
      <Card size="small" title={t('usage.limits')} extra={<Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('usage.lag')}</Typography.Text>}>
        {data && data.limits.length === 0 ? <Typography.Text>{t('detail.unlimited')}</Typography.Text> : null}
        <Space direction="vertical" style={{ width: '100%' }}>
          {(data?.limits ?? []).map((l: MarketLimitUsage) => {
            const percent = usagePercent(l.value, l.cap)
            return <div key={l.metric}>
              <Space size={8} wrap>
                <Typography.Text strong>{t(`limitMetrics.${l.metric}`)}</Typography.Text>
                <span>{amount(l.metric, l.value)} / {amount(l.metric, l.cap)}</span>
                <Tag color={actionColor[l.action as keyof typeof actionColor] ?? 'default'}>{t('usage.atLimit', { action: t(`limitActions.${l.action}`) })}</Tag>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {l.metric === 'monthly_traffic_bytes' ? t('usage.monthToDate') : t('usage.lastPeak')}
                  {l.evaluated_through ? ` · ${t('usage.asOf', { time: time(l.evaluated_through) })}` : ` · ${t('usage.notEvaluated')}`}
                </Typography.Text>
              </Space>
              <Progress percent={percent} status={usageStatus(percent)} aria-label={`${t(`limitMetrics.${l.metric}`)} ${percent}%`} />
            </div>
          })}
        </Space>
      </Card>
      <Card size="small" className="node-market-curve" title={t('usage.curve')} extra={data && data.limits.length > 0 ? <Segmented size="small" value={plotted}
        onChange={(v) => setMetric(v as MarketLimitMetric)}
        options={data.limits.map((l) => ({ value: l.metric, label: t(`limitMetrics.${l.metric}`) }))} /> : null}>
        <MetricTrendChart points={points} status={query.isLoading ? 'loading' : query.error ? 'error' : 'success'} />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('usage.curveHelp', { metric: t(`limitMetrics.${plotted}`) })}</Typography.Text>
      </Card>
      <Card size="small" title={t('usage.holds')}>
        <Table<MarketHold> size="small" pagination={false} loading={query.isLoading} dataSource={data?.holds ?? []}
          rowKey={(h) => `${h.subscription_id}|${h.reason}|${h.metric ?? ''}|${h.since}`} locale={{ emptyText: t('usage.noHolds') }}
          columns={[
            { title: t('usage.reason'), key: 'reason', render: (_: unknown, h) => <Space size={4} wrap>
              <span>{t(`subscribers.reasons.${h.reason}`)}{h.metric ? ` · ${t(`limitMetrics.${h.metric}`)}` : ''}</span>
              {h.upstream ? <Tag>{t('usage.upstream')}</Tag> : null}
            </Space> },
            { title: t('usage.action'), dataIndex: 'action', render: (v: MarketHold['action']) => <Tag color={actionColor[v]}>{t(`limitActions.${v}`)}</Tag> },
            { title: t('subscribers.since'), dataIndex: 'since', render: (v: string) => time(v) },
            { title: t('usage.recovery'), key: 'recovery', render: (_: unknown, h) => t(`usage.recover.${recoveryKey(h)}`) },
          ]} />
      </Card>
      {mine.length || unscheduled.error ? <Card size="small" title={t('usage.unscheduled')}>
        {unscheduled.error ? <Failure error={unscheduled.error} /> : null}
        <Table<MarketUnscheduledNode> size="small" pagination={false} dataSource={mine} rowKey={(n) => `${n.leaf_member_id}|${n.node_pool_ref}|${n.node_id}`}
          locale={{ emptyText: t('usage.noHolds') }}
          columns={[
            { title: t('subscribers.node'), dataIndex: 'node_id', render: (v: string) => <Typography.Text code>{v.slice(0, 8)}</Typography.Text> },
            { title: t('listing.region'), key: 'loc', render: (_: unknown, n) => [n.region, n.carrier].filter(Boolean).join(' · ') || '—' },
            { title: t('usage.serviceState'), dataIndex: 'state', render: (v: MarketUnscheduledNode['state']) => <Tag color={stateColor[v]}>{t(`usage.states.${v}`)}</Tag> },
            { title: t('subscribers.since'), key: 'since', render: (_: unknown, n) => time(n.overloaded_since ?? n.holds[0]?.since) },
          ]} />
      </Card> : null}
      <PrepaidCard terms={terms} currency={data?.currency || 'CNY'} />
    </Space>
  )
}

// Prepaid balance, overdraft and the alert line (§5.4, §5.6). Escrow reads the
// market prepaid account (ML-04); direct reads the balance held by the seller.
function PrepaidCard({ terms, currency }: { terms: MarketSubscriptionTerms; currency: string }) {
  const { t } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const canBuy = marketAccess(useSessionStore((state) => state.principal)).purchase
  const client = useQueryClient()
  const escrow = terms.settlement_mode === 'escrow'
  const prepaid = useQuery({
    queryKey: ['nodeMarket', 'prepaid', currency], enabled: !!token && escrow, retry: false,
    queryFn: () => marketApi.prepaid(token, currency),
  })
  // Direct: the seller's row of the summary (ADR 0015 §12); one query serves every subscription card.
  const summary = useQuery({
    queryKey: ['nodeMarket', 'prepaid', currency], enabled: !!token && !escrow, retry: false,
    queryFn: () => marketApi.prepaid(token, currency),
  })
  const direct = { error: summary.error, data: summary.data?.sellers?.find((s) => s.seller_member_id === terms.seller_id) }
  const [alert, setAlert] = useState<number | null | undefined>(undefined)
  const save = useMutation({
    mutationFn: (value: number | null) => marketApi.setPrepaidAlert(token, currency, value),
    onSuccess: () => { void message.success(t('subscription.saved')); void client.invalidateQueries({ queryKey: ['nodeMarket', 'prepaid', currency] }) },
    onError: (error) => {
      if (marketUnavailable(error)) void message.info(t('unavailable'))
      else void feedback.error(t('errors.failed', { code: errorCode(error) }))
    },
  })
  const money = (minor: number) => t('usage.money', { value: (minor / 100).toFixed(2), currency })
  const p = prepaid.data
  const left = p ? hoursLeft(p) : null
  return (
    <Card size="small" title={t('usage.prepaid')} extra={<Tag>{t(`settlement.${terms.settlement_mode}`)}</Tag>}>
      {escrow ? <>
        {prepaid.error ? <Failure error={prepaid.error} /> : null}
        {p ? <Descriptions size="small" bordered column={{ xs: 1, sm: 2 }} items={[
          { key: 'balance', label: t('usage.balance'), children: <Typography.Text type={p.balance_minor < 0 ? 'danger' : undefined}>{money(p.balance_minor)}</Typography.Text> },
          { key: 'arrears', label: t('usage.arrears'), children: <Typography.Text type={p.arrears_minor > 0 ? 'warning' : undefined}>
            {money(p.arrears_minor)} / {t('usage.cap', { value: money(p.overdraft_cap_minor) })}</Typography.Text> },
          { key: 'spent', label: t('usage.spent24h'), children: money(p.spent_24h_minor) },
          { key: 'left', label: t('usage.lasts'), children: left === null ? t('usage.lastsUnknown') : left === 0 ? t('usage.lastsNone')
            : left >= 48 ? t('usage.lastsDays', { days: Math.floor(left / 24) }) : t('usage.lastsHours', { hours: left }) },
        ]} /> : null}
        <Space wrap style={{ marginTop: 12 }}>
          <Typography.Text>{t('usage.alert')}</Typography.Text>
          <InputNumber min={0} max={100000000} disabled={!canBuy} aria-label={t('usage.alert')} style={{ width: 160 }}
            addonAfter={currency} placeholder={t('usage.alertNone')}
            value={alert === undefined ? (p?.alert_minor === null || p?.alert_minor === undefined ? null : p.alert_minor / 100) : alert}
            onChange={(v) => setAlert(v === null ? null : Number(v))} />
          {canBuy ? <Button type="primary" loading={save.isPending}
            onClick={() => save.mutate(alert === undefined ? (p?.alert_minor ?? null) : alert === null ? null : Math.round(alert * 100))}>
            {t('subscription.save')}</Button> : null}
        </Space>
        <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>{t('usage.escrowHelp')}</Typography.Paragraph>
      </> : <>
        {direct.error ? <Failure error={direct.error} /> : null}
        {direct.data ? <Descriptions size="small" bordered column={{ xs: 1, sm: 2 }} items={[
          { key: 'balance', label: t('usage.balance'), children: <Typography.Text type={direct.data.balance_minor < 0 ? 'danger' : undefined}>{money(direct.data.balance_minor)}</Typography.Text> },
          { key: 'credit', label: t('usage.credit'), children: money(direct.data.credit_limit_minor) },
          { key: 'spent', label: t('usage.spent24h'), children: money(direct.data.spent_24h_minor) },
          { key: 'seller', label: t('direct.credit.title'), children: <SellerCreditTags credit={direct.data.seller_credit} /> },
        ]} /> : summary.data ? <Typography.Text type="secondary">{t('direct.noBalance')}</Typography.Text> : null}
        <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>{t('usage.directHelp')}</Typography.Paragraph>
      </>}
    </Card>
  )
}
