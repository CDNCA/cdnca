import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Drawer, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketOfferListing, type MarketPoolReport, type MarketPoolReportNode,
  type MarketUnmappedNode } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import '../../i18n/poolReport'
import './SubscribedNodes.css'
import './OfferPoolReport.css'

// 我的上架 → 可上报节点. Per own node group of an
// offer, which nodes the controller reports to the market and, for every
// other node, why not and what to do (control-api marketprobe.PoolReport).

function ownPools(offer: MarketOfferListing | null): string[] {
  return (offer?.components ?? []).filter((c) => c.kind === 'own_pool' && c.node_pool_ref).map((c) => c.node_pool_ref!)
}

function usePoolReports(offer: MarketOfferListing | null, enabled = true) {
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const pools = ownPools(offer)
  const reports = useQueries({ queries: pools.map((id) => ({ queryKey: ['nodeMarket', 'poolReport', id], enabled: !!token && enabled,
    retry: false, staleTime: 60_000, queryFn: () => marketApi.supplyGroupReport(token, id) })) })
  return { pools, reports }
}

/** The 可上报节点 column: reportable / total over the offer's own groups. */
export function PoolReportCell({ offer, onOpen }: { offer: MarketOfferListing; onOpen: () => void }) {
  const { t } = useTranslation('poolReport')
  const { pools, reports } = usePoolReports(offer)
  if (pools.length === 0) return <span>{t('none')}</span>
  const loaded = reports.map((r) => r.data).filter((r): r is MarketPoolReport => !!r)
  const failed = reports.some((r) => r.isError)
  const reportable = loaded.reduce((sum, r) => sum + r.reportable, 0)
  const total = loaded.reduce((sum, r) => sum + r.total, 0)
  const off = loaded.find((r) => r.probe !== 'running')
  const color = failed || loaded.length < pools.length ? 'default' : reportable === 0 ? 'error' : reportable < total ? 'warning' : 'success'
  return (
    <Space size={4} wrap>
      <Tooltip title={t('columnHelp')}>
        <Tag color={color}>{loaded.length < pools.length && !failed ? '…' : t('cell', { reportable, total })}</Tag>
      </Tooltip>
      {off ? <Tag color="error">{t('probeOffTag')}</Tag> : null}
      <Button size="small" type="link" onClick={onOpen}>{t('open')}</Button>
    </Space>
  )
}

/** Next step for one node, from its reason, role and local setting. */
export function nextStep(node: MarketPoolReportNode, t: (key: string) => string): string {
  switch (node.reason) {
    case '':
      return '—'
    case 'node_not_join_market':
      if (node.role === 'disabled') return t('next.joinDisabled')
      if (node.role_source === 'local_leave') return t('next.joinLeave')
      if (!node.role_capable) return t('next.joinOld')
      return t('next.joinPending')
    case 'region_unmapped':
    case 'carrier_unmapped':
      return t('next.location')
    default:
      return t(`next.${node.reason}`)
  }
}

function unmappedOf(error: unknown): MarketUnmappedNode[] {
  const refusal = (error as { refusal?: { nodes?: unknown } } | null)?.refusal
  return error instanceof ApiError && error.code === 'node_location_unmapped' && Array.isArray(refusal?.nodes)
    ? refusal.nodes as MarketUnmappedNode[] : []
}

/** Names the nodes and fields a node_location_unmapped refusal is about (empty for other errors). */
export function UnmappedNodesAlert({ error }: { error: unknown }) {
  const { t } = useTranslation('poolReport')
  const nodes = unmappedOf(error)
  if (nodes.length === 0) return null
  const empty = (value: string) => value || t('emptyValue')
  return <Alert type="error" showIcon message={t('unmapped.title')} description={<>
    <ul className="subn-missing">{nodes.map((n) => <li key={n.node_id}>
      {t('unmapped.item', { name: n.name || n.node_id.slice(0, 8), fields: n.fields.map((f) => t(`unmapped.fields.${f}`)).join('、'),
        region: empty(n.region), carrier: empty(n.carrier) })}
    </li>)}</ul>
    <Typography.Text type="secondary">{t('unmapped.fix')}</Typography.Text>
  </>} />
}

function PoolSection({ id, report, error, loading }: { id: string; report?: MarketPoolReport; error: unknown; loading: boolean }) {
  const { t } = useTranslation('poolReport')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const { message } = App.useApp()
  const client = useQueryClient()
  // Same nodes again: the group's endpoints take each node's current IP 归属.
  const refresh = useMutation({
    mutationFn: async () => {
      const group = await marketApi.supplyGroup(token, id)
      return marketApi.updateSupplyGroup(token, id, group.revision, group.name, group.nodes.map((n) => n.node_id),
        newIdempotencyKey('pool-refresh'))
    },
    onSuccess: () => {
      void message.success(t('refreshed'))
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'poolReport', id] })
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'supplyGroup', id] })
    },
  })
  const nodes = report?.nodes ?? []
  const located = nodes.some((n) => n.reason === 'region_unmapped' || n.reason === 'carrier_unmapped')
  const empty = (value: string) => value || t('emptyValue')
  return <section className="subn-detail" aria-label={t('groupTitle', { name: id.slice(0, 8) })}>
    <h4>{t('groupTitle', { name: id.slice(0, 8) })}
      {report ? <Tag color={report.reportable === 0 ? 'error' : report.reportable < report.total ? 'warning' : 'success'}>
        {t('groupSummary', { reportable: report.reportable, total: report.total })}</Tag> : null}</h4>
    {error ? <Alert type="error" showIcon message={t('loadFailed', { code: error instanceof ApiError ? error.code : 'request_failed' })} /> : null}
    {refresh.error ? <UnmappedNodesAlert error={refresh.error} /> : null}
    {refresh.error && unmappedOf(refresh.error).length === 0 ? <Alert type="error" showIcon
      message={t('refreshFailed', { code: refresh.error instanceof ApiError ? refresh.error.code : 'request_failed' })} /> : null}
    <Table<MarketPoolReportNode> size="small" pagination={false} rowKey="node_id" loading={loading} dataSource={nodes}
      // A fixed width: the next-step text wraps in its column; a narrow screen scrolls the table, not the drawer.
      scroll={{ x: 960 }}
      columns={[
        { title: t('columns.node'), key: 'node', render: (_: unknown, n) => n.name || n.node_id.slice(0, 8) },
        { title: t('columns.address'), dataIndex: 'address' },
        { title: t('columns.location'), key: 'location', render: (_: unknown, n) => t('location', { region: empty(n.region), carrier: empty(n.carrier) }) },
        { title: t('columns.role'), key: 'role', render: (_: unknown, n) => <Space size={4} wrap>
          <span>{t(`roles.${n.role || 'unknown'}`)}</span>
          {n.role_source ? <Typography.Text type="secondary">{t(`roleSources.${n.role_source}`)}</Typography.Text> : null}
        </Space> },
        { title: t('columns.status'), key: 'status', render: (_: unknown, n) => n.reason === ''
          ? <Tag color="success">{t('ok')}</Tag>
          : <Tag color="warning">{t(`reasons.${n.reason}`, { value: n.value || t('emptyValue') })}</Tag> },
        { title: t('columns.next'), key: 'next', width: 320, render: (_: unknown, n) => <Space direction="vertical" size={2}>
          <Typography.Text>{nextStep(n, t)}</Typography.Text>
          {n.reason === 'region_unmapped' || n.reason === 'carrier_unmapped'
            ? <Link to={`/node/list?q=${encodeURIComponent(n.address)}`}>{t('editLocation')}</Link> : null}
        </Space> },
      ]} />
    {located ? <Space size={8} wrap>
      <Button size="small" onClick={() => refresh.mutate()} loading={refresh.isPending}>{t('refresh')}</Button>
      <Typography.Text type="secondary">{t('refreshHelp')}</Typography.Text>
    </Space> : null}
  </section>
}

export function OfferPoolReportDrawer({ offer, onClose }: { offer: MarketOfferListing | null; onClose: () => void }) {
  const { t } = useTranslation('poolReport')
  const { pools, reports } = usePoolReports(offer, !!offer)
  const resale = (offer?.components ?? []).some((c) => c.kind === 'upstream')
  const off = reports.map((r) => r.data).find((r) => r && r.probe !== 'running')
  return (
    <Drawer open={!!offer} onClose={onClose} width="min(1080px, 100vw)" destroyOnHidden title={offer ? t('title', { name: offer.name }) : ''}>
      {offer ? <div className="subn-coverage pool-report">
        <Typography.Paragraph type="secondary">{t('help')}</Typography.Paragraph>
        {off ? <Alert type="error" showIcon message={t(`probe.${off.probe}`, { defaultValue: t('probe.disabled') })} /> : null}
        {resale ? <Alert type="info" showIcon message={t('resale')} /> : null}
        {pools.map((id, i) => <PoolSection key={id} id={id} report={reports[i].data} error={reports[i].error} loading={reports[i].isLoading} />)}
      </div> : null}
    </Drawer>
  )
}
