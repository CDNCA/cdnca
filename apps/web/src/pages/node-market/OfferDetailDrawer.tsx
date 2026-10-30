import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, Descriptions, Drawer, Row, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketApi, marketUnavailable, type MarketOfferListing, type MarketOfferNodes } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { formatCap } from './limitsModel'
import { offerQualityText } from './offerView'
import { formatDateTime } from '../../i18n/formatters'
import { declaredTagKeys } from './subscriberModel'

type Group = MarketOfferNodes['groups'][number]

// Subscriber-side supply detail (ADR 0012 §9.2): nodes by region, carrier and
// line grade, each limit with its action, the seller's self-declared tags apart
// from what the platform measured, and the platform floor against the seller's
// node thresholds.
export function OfferDetailDrawer({ offer, onClose }: { offer: MarketOfferListing | null; onClose: () => void }) {
  const { t } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const nodes = useQuery({
    queryKey: ['nodeMarket', 'offerNodes', offer?.id], enabled: !!token && !!offer, retry: false,
    queryFn: () => marketApi.offerNodes(token, offer!.id),
  })
  const limits = (offer?.limits ?? []).filter((l) => l.metric !== 'node_cpu_percent' && l.metric !== 'node_memory_percent')
  const nodeCap = (metric: 'node_cpu_percent' | 'node_memory_percent') => offer?.limits?.find((l) => l.metric === metric)?.cap
  const tags = offer?.tags
  const plugins = tags?.plugins ?? []
  const missing = new Set(offer?.plugins_unavailable ?? [])
  const yes = (v: boolean | undefined) => (v ? t('detail.yes') : t('detail.no'))
  const declared = (key: (typeof declaredTagKeys)[number]): string => {
    if (!tags) return '—'
    switch (key) {
      case 'cc_protection': return t(`tagValues.${tags.cc_protection}`)
      case 'tenancy': return t(`tagValues.${tags.tenancy}`)
      case 'ddos_protection_gbps': return tags.ddos_protection_gbps > 0 ? `${tags.ddos_protection_gbps} Gbps` : t('tagValues.none')
      case 'line_class': return tags.line_class || '—'
      default: return yes(tags[key])
    }
  }
  const grade = (g: string) => (g ? g.toUpperCase() : t('detail.gradeNone'))
  const data = nodes.data
  return (
    <Drawer open={!!offer} onClose={onClose} width="min(880px, 100vw)" title={offer ? t('detail.title', { name: offer.name }) : ''} destroyOnHidden>
      {offer ? <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Card size="small" title={t('detail.nodes')}>
          {nodes.error ? (marketUnavailable(nodes.error) ? <Alert type="info" showIcon message={t('unavailable')} />
            : <Alert type="error" showIcon message={t('errors.failed', { code: (nodes.error as { code?: string }).code ?? 'request_failed' })} />) : null}
          {data ? <Typography.Paragraph type="secondary">{t('detail.nodesSummary', { count: data.nodes })}</Typography.Paragraph> : null}
          <Table<Group> size="small" pagination={false} loading={nodes.isLoading} dataSource={data?.groups ?? []}
            rowKey={(g) => `${g.region}|${g.carrier}|${g.benchmark_grade}`} locale={{ emptyText: t('detail.nodesEmpty') }}
            columns={[
              { title: t('listing.region'), dataIndex: 'region', render: (v: string) => v || '—' },
              { title: t('listing.carrier'), dataIndex: 'carrier', render: (v: string) => v || '—' },
              { title: t('listing.grade'), dataIndex: 'benchmark_grade', render: (v: string) => <Tag color={v ? 'blue' : 'default'}>{grade(v)}</Tag> },
              { title: t('detail.nodeCount'), dataIndex: 'nodes' },
            ]} />
        </Card>
        <Card size="small" title={t('detail.limits')}>
          <Table size="small" pagination={false} rowKey="metric" dataSource={limits} locale={{ emptyText: t('detail.unlimited') }}
            columns={[
              { title: t('listing.metric'), dataIndex: 'metric', render: (v: string) => t(`limitMetrics.${v}`) },
              { title: t('listing.cap'), key: 'cap', render: (_: unknown, l) => {
                const shown = formatCap(l.metric, l.cap)
                return `${shown.value} ${t(`limitUnits.${shown.unit}`)}`
              } },
              { title: t('listing.action'), key: 'action', render: (_: unknown, l) => <Space size={4} wrap>
                <Tag color={l.action === 'stop' ? 'red' : l.action === 'pause' ? 'orange' : 'gold'}>{t(`limitActions.${l.action}`)}</Tag>
                {l.throttle_bps ? <span>{t('detail.throttleTo', { value: Math.round(l.throttle_bps / 1e6) })}</span> : null}
              </Space> },
            ]} />
          <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
            {t('detail.prepaid', { action: t(`limitActions.${offer.prepaid_exhausted_action ?? 'pause'}`) })}
          </Typography.Paragraph>
        </Card>
        <Row gutter={[16, 16]}>
          <Col xs={24} md={12}>
            <Card size="small" title={t('detail.declared')} extra={<Tag>{t('detail.declaredBadge')}</Tag>} style={{ height: '100%' }}>
              <Descriptions size="small" column={1} items={[...declaredTagKeys.map((key) => ({ key, label: t(`detail.tags.${key}`), children: declared(key) as ReactNode })),
                ...(tags?.custom?.length ? [{ key: 'custom', label: t('detail.tags.custom'),
                  children: <Space size={4} wrap data-testid="declared-custom">{tags.custom.map((c) => <Tag key={c}>{c}</Tag>)}</Space> as ReactNode }] : [])]} />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('detail.declaredHelp')}</Typography.Text>
            </Card>
          </Col>
          <Col xs={24} md={12}>
            <Card size="small" title={t('detail.measured')} extra={<Tag color="blue">{t('detail.measuredBadge')}</Tag>} style={{ height: '100%' }}>
              <Descriptions size="small" column={1} items={[
                { key: 'regions', label: t('listing.region'), children: [...new Set((data?.groups ?? []).map((g) => g.region).filter(Boolean))].join('、') || '—' },
                { key: 'carriers', label: t('listing.carrier'), children: [...new Set((data?.groups ?? []).map((g) => g.carrier).filter(Boolean))].join('、') || '—' },
                { key: 'grades', label: t('listing.grade'), children: [...new Set((data?.groups ?? []).map((g) => grade(g.benchmark_grade)))].join('、') || '—' },
                { key: 'score', label: t('quality.score'), children: offer.quality?.computed_at && offer.quality.tier !== 'insufficient'
                  ? t('quality.scoredAt', { score: offerQualityText(t, offer), at: formatDateTime(offer.quality.computed_at) }) : offerQualityText(t, offer) },
                { key: 'plugins', label: t('detail.plugins'), children: plugins.length === 0 ? t('tagValues.none') : <Space size={4} wrap>
                  {plugins.map((p) => <Tag key={p} color={missing.has(p) ? 'default' : 'green'}
                    style={missing.has(p) ? { textDecoration: 'line-through' } : undefined}>{p}</Tag>)}
                </Space> },
              ]} />
              {missing.size ? <Typography.Text type="warning" style={{ fontSize: 12 }}>{t('detail.pluginsMissing')}</Typography.Text> : null}
            </Card>
          </Col>
        </Row>
        <Card size="small" title={t('detail.thresholds')}>
          <Descriptions size="small" bordered column={{ xs: 1, sm: 3 }} items={[
            { key: 'floor', label: t('detail.floor'), children: data ? `CPU ${data.load_floor.cpu_percent}% · ${t('limitMetrics.node_memory_percent')} ${data.load_floor.memory_percent}%` : '—' },
            { key: 'seller', label: t('detail.sellerThreshold'), children: [nodeCap('node_cpu_percent'), nodeCap('node_memory_percent')].every((v) => v === undefined)
              ? t('detail.sellerNone')
              : `CPU ${nodeCap('node_cpu_percent') ?? '—'}% · ${t('limitMetrics.node_memory_percent')} ${nodeCap('node_memory_percent') ?? '—'}%` },
            { key: 'effective', label: t('detail.effective'), children: data ? `CPU ${data.load_thresholds.cpu_percent}% · ${t('limitMetrics.node_memory_percent')} ${data.load_thresholds.memory_percent}%` : '—' },
          ]} />
          <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>{t('detail.thresholdsHelp')}</Typography.Paragraph>
        </Card>
      </Space> : null}
    </Drawer>
  )
}
