import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Drawer, Progress, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketApi, marketUnavailable, type MarketNodeOverload, type MarketOfferListing, type MarketOfferSubscriber } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import { formatCap } from './limitsModel'
import { CursorPager, SupplyStateTag, useCursorPages } from './supplier/shared'

const subscriberPageSize = 100

const actionColor = { throttle: 'gold', pause: 'orange', stop: 'red' } as const
const overloadColor = { normal: 'success', overloaded: 'error', unknown: 'default' } as const

// Seller view of an offer's subscribers (ADR 0012 §9.4): usage against each
// limit, active holds and the node overloads of the offer's supply.
export function OfferSubscribersDrawer({ offer, onClose }: { offer: MarketOfferListing | null; onClose: () => void }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const pages = useCursorPages()
  // A new offer starts on page 1 (reset during render, so no request goes out with the old offer's cursor).
  const [pagedOffer, setPagedOffer] = useState(offer?.id)
  if (pagedOffer !== offer?.id) { setPagedOffer(offer?.id); pages.reset() }
  const query = useQuery({
    queryKey: ['nodeMarket', 'offerSubscribers', offer?.id, pages.cursor], enabled: !!token && !!offer, retry: false,
    queryFn: () => marketApi.offerSubscribers(token, offer!.id, pages.cursor, subscriberPageSize),
  })
  // The market sends the overloads with the first page only; the first page stays cached
  // (same key), so later pages read the list from it instead of getting it again each time.
  const first = useQuery({
    queryKey: ['nodeMarket', 'offerSubscribers', offer?.id, undefined], enabled: !!token && !!offer && pages.cursor !== undefined, retry: false,
    queryFn: () => marketApi.offerSubscribers(token, offer!.id, undefined, subscriberPageSize),
  })
  const overloads = pages.cursor === undefined ? query : first
  const time = (v?: string | null) => (v ? formatDateTime(v, i18n.resolvedLanguage ?? 'zh-CN') || v : '—')
  const amount = (metric: MarketOfferSubscriber['usage'][number]['metric'], value: number) => {
    const shown = formatCap(metric, value)
    return `${Number(shown.value.toFixed(2))} ${t(`limitUnits.${shown.unit}`)}`.trim()
  }
  return (
    <Drawer open={!!offer} onClose={onClose} width={860} title={offer ? t('subscribers.title', { name: offer.name }) : ''} destroyOnHidden>
      {query.error ? (marketUnavailable(query.error) ? <Alert type="info" showIcon message={t('unavailable')} />
        : <Alert type="error" showIcon message={t('errors.failed', { code: (query.error as { code?: string }).code ?? 'request_failed' })} />) : null}
      <Space direction="vertical" style={{ width: '100%' }}>
        <Typography.Text type="secondary">{t('subscribers.help')}</Typography.Text>
        {/* C10: several downstream buyers share the hop's subscription id; downstream_ref keeps rows apart. */}
        <Table<MarketOfferSubscriber> rowKey={(s) => `${s.subscription_id}/${s.downstream_ref ?? ''}`} size="small" loading={query.isLoading} pagination={false}
          dataSource={query.data?.subscribers ?? []} locale={{ emptyText: t('subscribers.empty') }}
          columns={[
            { title: t('subscribers.buyer'), key: 'buyer', render: (_: unknown, s) => s.relation === 'downstream'
              ? <Space direction="vertical" size={0}>
                <Space size={4}><Tag>{t('subscribers.downstream')}</Tag><Typography.Text code>{s.downstream_ref}</Typography.Text></Space>
                {s.via_name ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('subscribers.via', { name: s.via_name })}</Typography.Text> : null}
              </Space>
              : <Space size={4}><Tag color="blue">{t('subscribers.direct')}</Tag>{s.buyer_name || <Typography.Text code>{s.buyer_id?.slice(0, 8)}</Typography.Text>}</Space> },
            // MC08: the contract and the supply behind it are two facts in adjacent columns, worded and coloured as in the
            // seller list (SupplyStateTag); an active contract does not imply the offer can serve it now.
            { title: t('subscribers.contract'), key: 'status', render: (_: unknown, s) => <Tag>{t(`states.${s.status}`, { defaultValue: s.status })}</Tag> },
            { title: t('subscribers.supply'), key: 'supply', render: (_: unknown, s) => s.state === 'no_supply'
              ? <Space direction="vertical" size={0}><SupplyStateTag value={s.state} />
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('subscribers.noSupplyDetail')}</Typography.Text></Space>
              : <SupplyStateTag value={s.state} /> },
            { title: t('subscribers.domains'), key: 'domains', render: (_: unknown, s) => s.domain_count === 0 ? '—' : <Space direction="vertical" size={0}>
              {s.domains.slice(0, 3).map((d) => <Typography.Text key={d} style={{ fontSize: 12 }}>{d}</Typography.Text>)}
              {s.domain_count > 3 ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('subscribers.moreDomains', { count: s.domain_count })}</Typography.Text> : null}
            </Space> },
            { title: t('subscribers.traffic'), key: 'traffic', render: (_: unknown, s) => <Space direction="vertical" size={0}>
              <Typography.Text style={{ fontSize: 12 }}>{t('subscribers.traffic24h', { value: amount('monthly_traffic_bytes', s.bytes_24h) })}</Typography.Text>
              <Typography.Text style={{ fontSize: 12 }}>{t('subscribers.trafficMonth', { value: amount('monthly_traffic_bytes', s.bytes_month) })}</Typography.Text>
            </Space> },
            { title: t('subscribers.paidThrough'), key: 'paid', render: (_: unknown, s) => time(s.paid_through) },
            { title: t('subscribers.usage'), key: 'usage', render: (_: unknown, s) => s.usage.length === 0 ? t('sell.unlimited') : (
              <Space direction="vertical" size={2} style={{ minWidth: 220 }}>
                {s.usage.map((u) => {
                  const percent = u.cap > 0 ? Math.min(100, Math.round((u.value / u.cap) * 100)) : 0
                  return <div key={u.metric}>
                    <Typography.Text style={{ fontSize: 12 }}>{t(`limitMetrics.${u.metric}`)}：{amount(u.metric, u.value)} / {amount(u.metric, u.cap)}</Typography.Text>
                    <Progress size="small" percent={percent} status={percent >= 95 ? 'exception' : 'normal'}
                      aria-label={`${t(`limitMetrics.${u.metric}`)} ${percent}%`} />
                  </div>
                })}
              </Space>) },
            { title: t('subscribers.holds'), key: 'holds', render: (_: unknown, s) => s.holds.length === 0 ? t('subscribers.none') : (
              <Space direction="vertical" size={2}>
                {s.holds.map((h) => <Space key={`${h.reason}-${h.metric ?? ''}-${h.since}`} size={4} wrap>
                  <Tag color={actionColor[h.action]}>{t(`limitActions.${h.action}`)}</Tag>
                  <span>{t(`subscribers.reasons.${h.reason}`)}{h.metric ? ` · ${t(`limitMetrics.${h.metric}`)}` : ''}</span>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>{time(h.since)}</Typography.Text>
                </Space>)}
              </Space>) },
          ]} />
        <CursorPager pages={pages} pageSize={subscriberPageSize} count={query.data?.subscribers.length ?? 0} next={query.data?.next_cursor} busy={query.isFetching} />
        <Typography.Title level={5}>{t('subscribers.overloads')}</Typography.Title>
        <Table<MarketNodeOverload> rowKey={(o) => `${o.node_id}-${o.cpu_threshold}-${o.memory_threshold}`} size="small" pagination={false}
          loading={overloads.isLoading} dataSource={overloads.data?.overloads ?? []} locale={{ emptyText: t('subscribers.overloadEmpty') }}
          columns={[
            { title: t('subscribers.node'), dataIndex: 'node_id', render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
            { title: t('subscribers.state'), dataIndex: 'state', render: (v: MarketNodeOverload['state']) => <Tag color={overloadColor[v]}>{t(`subscribers.states.${v}`)}</Tag> },
            { title: t('subscribers.since'), dataIndex: 'since', render: (v: string) => time(v) },
            { title: t('subscribers.thresholds'), key: 'th', render: (_: unknown, o) => `${o.cpu_threshold}% / ${o.memory_threshold}%` },
          ]} />
      </Space>
    </Drawer>
  )
}
