import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, InputNumber, Modal, Radio, Select, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketOfferListing, type MarketPrepaidAction } from '../../api/market'
import { nodesApi } from '../../api/nodes'
import { useSessionStore } from '../../auth/session'
import { defaultRows, ruleOf, toLimits, type LimitRow, type LoadFloor } from './limitsModel'
import { allNodes, poolsOf, priceOf, repriced, runLimited, type PriceChange } from './listingModel'
import { formatYuan, yuanToMinor } from '@cdnca/ui/offer-terms'

type Kind = 'price' | 'limits' | 'delist' | 'removeNodes'
interface Outcome { key: string; label: string; ok: boolean; note?: string }

const codeOf = (error: unknown) => (error instanceof ApiError ? error.code : 'request_failed')

// Batch operations on own offers (ML-11b): price, limits, delist, and taking
// nodes out of their supplies. Each offer / supply reports its own outcome;
// one failure does not stop the others.
export function OfferBulkActions({ offers: selected, floor, onDone }: { offers: MarketOfferListing[]; floor: LoadFloor | null; onDone: () => void }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [kind, setKind] = useState<Kind | null>(null)
  const [price, setPrice] = useState<PriceChange>({ kind: 'percent', value: 0 })
  const [rows, setRows] = useState<LimitRow[]>(defaultRows)
  const [prepaid, setPrepaid] = useState<MarketPrepaidAction>('pause')
  const [removeNodes, setRemoveNodes] = useState<string[]>([])
  const [outcomes, setOutcomes] = useState<Outcome[]>([])
  // The offers the open dialog acts on, fixed when it opens (the selection is cleared after a run).
  const [offers, setOffers] = useState<MarketOfferListing[]>([])
  const nodes = useQuery({ queryKey: ['nodeMarket', 'listing', 'nodes'], enabled: !!token && kind === 'removeNodes',
    queryFn: async () => ({ items: await allNodes((cursor) => nodesApi.list(token, { limit: 200, cursor })) }) })
  const msg = (code: string) => i18n.exists(`nodeMarket:bulk.errors.${code}`) ? t(`bulk.errors.${code}`)
    : i18n.exists(`nodeMarket:listing.refused.${code}`) ? t(`listing.refused.${code}`) : t('errors.failed', { code })

  const run = useMutation({
    mutationFn: async (k: Kind): Promise<Outcome[]> => {
      if (k === 'removeNodes') {
        const groups = [...new Set(offers.flatMap(poolsOf))]
        const res = await marketApi.removeSupplyNodes(token, groups, removeNodes)
        return res.map((r) => ({ key: r.group_id, label: offers.filter((o) => poolsOf(o).includes(r.group_id)).map((o) => o.name).join('、') || r.group_id.slice(0, 8),
          ok: r.status !== 'failed', note: r.status === 'failed' ? msg(r.error ?? 'request_failed') : r.status === 'unchanged' ? t('bulk.unchanged') : undefined }))
      }
      const { limits, problems } = toLimits(rows, floor)
      if (k === 'limits' && problems.length) {
        return [{ key: 'form', label: '—', ok: false, note: problems.map((p) => t(`listing.problems.${p.code}`, { metric: t(`limitMetrics.${p.metric}`), floor: p.floor ?? '—' })).join('；') }]
      }
      return runLimited(offers, 4, async (o): Promise<Outcome> => {
        try {
          if (k === 'price') {
            const pricing = repriced(o, price.kind === 'set' ? { kind: 'set', value: yuanToMinor(price.value) ?? -1 } : price)
            if (!pricing) return { key: o.id, label: o.name, ok: false, note: msg('no_price') }
            await marketApi.updateOfferTerms(token, o.id, { pricing }, newIdempotencyKey('bulk-price'))
            return { key: o.id, label: o.name, ok: true, note: `${formatYuan(priceOf(o) ?? 0)} → ${formatYuan(priceOf({ ...o, pricing }) ?? 0)}` }
          }
          if (k === 'limits') await marketApi.updateOfferLimits(token, o.id, { limits, prepaid_exhausted_action: prepaid }, newIdempotencyKey('bulk-limits'))
          else await marketApi.delistOffer(token, o.id, newIdempotencyKey('bulk-delist'))
          return { key: o.id, label: o.name, ok: true }
        } catch (error) {
          return { key: o.id, label: o.name, ok: false, note: msg(codeOf(error)) }
        }
      })
    },
    onSuccess: (result) => {
      setOutcomes(result)
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'myOffers'] })
      onDone()
    },
    onError: (error) => setOutcomes([{ key: 'request', label: '—', ok: false, note: msg(codeOf(error)) }]),
  })
  const open = (k: Kind) => {
    setOffers(selected)
    setOutcomes([])
    setKind(k)
  }
  const setRow = (metric: LimitRow['metric'], patch: Partial<LimitRow>) =>
    setRows((current) => current.map((r) => (r.metric === metric ? { ...r, ...patch } : r)))

  return (
    <>
      <Space wrap aria-label={t('bulk.selected', { count: selected.length })}>
        <Typography.Text>{t('bulk.selected', { count: selected.length })}</Typography.Text>
        <Button size="small" disabled={!selected.length} onClick={() => open('price')}>{t('bulk.price')}</Button>
        <Button size="small" disabled={!selected.length} onClick={() => open('limits')}>{t('bulk.limits')}</Button>
        <Button size="small" disabled={!selected.length} onClick={() => open('removeNodes')}>{t('bulk.removeNodes')}</Button>
        <Button size="small" danger disabled={!selected.length} onClick={() => open('delist')}>{t('bulk.delist')}</Button>
      </Space>
      <Modal open={kind !== null} width={760} title={kind ? t(`bulk.${kind}`) : ''} onCancel={() => setKind(null)}
        okText={t('bulk.apply')} confirmLoading={run.isPending} onOk={() => kind && run.mutate(kind)}
        okButtonProps={{ disabled: kind === 'removeNodes' && removeNodes.length === 0, danger: kind === 'delist' }}>
        <Typography.Paragraph type="secondary">{t('bulk.selected', { count: offers.length })}：{offers.map((o) => o.name).join('、')}</Typography.Paragraph>
        {kind === 'price' ? <Space direction="vertical">
          <Typography.Text type="secondary">{t('bulk.priceHelp')}</Typography.Text>
          <Radio.Group value={price.kind} onChange={(e) => setPrice({ kind: e.target.value, value: price.value })}
            options={[{ value: 'percent', label: t('bulk.pricePercent') }, { value: 'set', label: t('bulk.priceSet') }]} />
          <InputNumber aria-label={price.kind === 'set' ? t('bulk.priceSet') : t('bulk.pricePercent')} value={price.value}
            min={price.kind === 'set' ? 0 : -99} max={price.kind === 'set' ? undefined : 1000} precision={price.kind === 'set' ? 2 : 0}
            onChange={(v) => setPrice({ ...price, value: Number(v ?? 0) })} />
        </Space> : null}
        {kind === 'limits' ? <Space direction="vertical" style={{ width: '100%' }}>
          <Typography.Text type="secondary">{t('bulk.limitsHelp')}</Typography.Text>
          <Table<LimitRow> rowKey="metric" size="small" pagination={false} dataSource={rows}
            columns={[
              { key: 'on', width: 40, render: (_: unknown, r) => <Checkbox aria-label={`${t('bulk.limits')} ${t(`limitMetrics.${r.metric}`)}`} checked={r.enabled}
                onChange={(e) => setRow(r.metric, { enabled: e.target.checked })} /> },
              { title: t('listing.metric'), key: 'metric', render: (_: unknown, r) => t(`limitMetrics.${r.metric}`) },
              { title: t('listing.cap'), key: 'cap', render: (_: unknown, r) => <Space size={4}>
                <InputNumber aria-label={`${t('bulk.limits')} ${t('listing.cap')} ${t(`limitMetrics.${r.metric}`)}`} disabled={!r.enabled} min={1} value={r.value}
                  onChange={(v) => setRow(r.metric, { value: v === null ? null : Number(v) })} />
                {ruleOf(r.metric).units.length > 1 ? <Select style={{ width: 90 }} disabled={!r.enabled} value={r.unit}
                  options={ruleOf(r.metric).units.map((u) => ({ value: u, label: t(`limitUnits.${u}`) }))} onChange={(unit) => setRow(r.metric, { unit })} />
                  : t(`limitUnits.${r.unit}`)}
              </Space> },
              { title: t('listing.action'), key: 'action', render: (_: unknown, r) => <Space size={4}>
                <Select style={{ width: 130 }} disabled={!r.enabled} value={r.action}
                  options={ruleOf(r.metric).actions.map((a) => ({ value: a, label: t(`limitActions.${a}`) }))} onChange={(action) => setRow(r.metric, { action })} />
                {r.metric === 'monthly_traffic_bytes' && r.action === 'throttle' && r.enabled ? <InputNumber placeholder={t('listing.throttleMbps')} min={1}
                  value={r.throttleMbps} onChange={(v) => setRow(r.metric, { throttleMbps: v === null ? null : Number(v) })} /> : null}
              </Space> },
            ]} />
          <Space><span>{t('listing.prepaid')}</span>
            <Select style={{ width: 160 }} value={prepaid} onChange={setPrepaid}
              options={(['pause', 'stop'] as const).map((value) => ({ value, label: t(`limitActions.${value}`) }))} /></Space>
        </Space> : null}
        {kind === 'delist' ? <Alert type="warning" showIcon message={t('bulk.delistConfirm')} /> : null}
        {kind === 'removeNodes' ? <Space direction="vertical" style={{ width: '100%' }}>
          <Alert type="info" showIcon message={t('bulk.removeNodesHelp')} />
          <Select mode="multiple" aria-label={t('bulk.removeNodes')} style={{ width: '100%' }} value={removeNodes} onChange={setRemoveNodes}
            loading={nodes.isLoading} options={(nodes.data?.items ?? []).map((n) => ({ value: n.id, label: n.name }))} />
        </Space> : null}
        {outcomes.length ? <Table<Outcome> style={{ marginTop: 16 }} rowKey="key" size="small" pagination={false} dataSource={outcomes}
          title={() => t('bulk.results')}
          columns={[
            { title: t('offers.name'), dataIndex: 'label' },
            { title: t('batch.status'), key: 'ok', render: (_: unknown, o) => <Tag color={o.ok ? 'success' : 'error'}>{o.ok ? t('bulk.ok') : t('batch.statuses.failed')}</Tag> },
            { title: t('batch.reason'), dataIndex: 'note', render: (v?: string) => v ?? '—' },
          ]} /> : null}
      </Modal>
    </>
  )
}
