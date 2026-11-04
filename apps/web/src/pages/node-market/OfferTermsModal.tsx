import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Form, InputNumber, Modal, Select, Space, Table, Tabs } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketLimit, type MarketOfferListing, type MarketPrepaidAction, type MarketPricing } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { ruleOf, toLimits, type LimitRow, type LoadFloor } from './limitsModel'
import { priceFormOf, pricingOf, rowsOf, withSustain, type PriceForm, type Yuan } from './offerLifecycleModel'

// one offer's 修改报价 from its row. Price through PUT …/terms (pricing only:
// community price, SLA and the switches are left as they are), limits through PUT …/limits; both send
// the revision the dialog opened on, so a change made meanwhile is refused (409 offer_changed).
// Buyers in period keep their snapshot; the new revision applies to new orders and renewals.

export function OfferTermsModal({ offer, floor, onClose }: { offer: MarketOfferListing | null; floor: LoadFloor | null; onClose: () => void }) {
  const { t } = useTranslation('nodeMarket')
  return (
    <Modal open={!!offer} title={t('life.editTitle', { name: offer?.name ?? '' })} onCancel={onClose} footer={null} destroyOnHidden width={760}>
      {offer ? <TermsEditor key={`${offer.id}:${offer.revision ?? ''}`} offer={offer} floor={floor} onClose={onClose} /> : null}
    </Modal>
  )
}

function TermsEditor({ offer, floor, onClose }: { offer: MarketOfferListing; floor: LoadFloor | null; onClose: () => void }) {
  const { t } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [form, setForm] = useState<PriceForm>(() => priceFormOf(offer))
  const [rows, setRows] = useState<LimitRow[]>(() => rowsOf(offer.limits))
  const [prepaid, setPrepaid] = useState<MarketPrepaidAction>(offer.prepaid_exhausted_action ?? 'pause')
  const [error, setError] = useState<string | null>(null)
  const expected = offer.revision ? { expected_revision: offer.revision } : {}
  const done = (next: MarketOfferListing) => {
    void message.success(next.revision === offer.revision ? t('life.unchanged') : t('life.saved'))
    void client.invalidateQueries({ queryKey: ['nodeMarket'] })
    onClose()
  }
  const fail = (e: unknown) => {
    const code = e instanceof ApiError ? e.code : 'request_failed'
    if (code === 'offer_changed') void client.invalidateQueries({ queryKey: ['nodeMarket'] })
    setError(code === 'offer_changed' ? t('life.changed') : t('errors.failed', { code }))
  }
  const savePrice = useMutation({
    mutationFn: (pricing: MarketPricing) => marketApi.updateOfferTerms(token, offer.id, { pricing, ...expected }, newIdempotencyKey('offer-terms')),
    onSuccess: done, onError: fail,
  })
  const saveLimits = useMutation({
    mutationFn: (limits: MarketLimit[]) => marketApi.updateOfferLimits(token, offer.id,
      { limits: withSustain(limits, offer.limits), prepaid_exhausted_action: prepaid, ...expected }, newIdempotencyKey('offer-limits')),
    onSuccess: done, onError: fail,
  })
  const setRow = (metric: LimitRow['metric'], patch: Partial<LimitRow>) =>
    setRows((current) => current.map((r) => (r.metric === metric ? { ...r, ...patch } : r)))
  const yuan = (label: string, value: Yuan, onChange: (v: Yuan) => void) => (
    <Form.Item label={label}>
      <InputNumber aria-label={label} min={0} precision={2} value={value} onChange={(v) => onChange(v === null ? null : Number(v))} /></Form.Item>
  )
  const model = offer.billing_model
  const price = (
    <Form layout="vertical" component="div">
      <Space wrap size={16} align="end">
        {model === 'traffic'
          ? (offer.pricing.tiers ?? []).map((tier, i) => <span key={i}>{yuan(t('life.tierPrice', { gb: tier.up_to_gb || t('life.tierLast') }), form.tiers[i] ?? null,
            (v) => setForm({ ...form, tiers: form.tiers.map((x, j) => (j === i ? v : x)) }))}</span>)
          : yuan(t('life.price'), form.main, (main) => setForm({ ...form, main }))}
        {model === 'daily_bundle' ? <>
          <Form.Item label={t('life.minDays')}><InputNumber aria-label={t('life.minDays')} min={1} max={3660} precision={0}
            value={form.minDays} onChange={(v) => setForm({ ...form, minDays: v === null ? null : Number(v) })} /></Form.Item>
          <Form.Item label={t('life.maxDays')}><InputNumber aria-label={t('life.maxDays')} min={1} max={3660} precision={0}
            value={form.maxDays} onChange={(v) => setForm({ ...form, maxDays: v === null ? null : Number(v) })} /></Form.Item>
        </> : offer.pricing.deposit_minor !== undefined ? yuan(t('life.deposit'), form.deposit, (deposit) => setForm({ ...form, deposit })) : null}
      </Space>
      <div><Button type="primary" loading={savePrice.isPending} onClick={() => {
        const pricing = pricingOf(offer, form)
        if (!pricing) { setError(t('life.errors.invalid')); return }
        savePrice.mutate(pricing)
      }}>{t('life.save')}</Button></div>
    </Form>
  )
  const limits = (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Table<LimitRow> rowKey="metric" size="small" pagination={false} dataSource={rows} columns={[
        { key: 'on', width: 40, render: (_: unknown, r) => <Checkbox aria-label={t(`limitMetrics.${r.metric}`)} checked={r.enabled}
          onChange={(e) => setRow(r.metric, { enabled: e.target.checked })} /> },
        { title: t('listing.metric'), key: 'metric', render: (_: unknown, r) => t(`limitMetrics.${r.metric}`) },
        { title: t('listing.cap'), key: 'cap', render: (_: unknown, r) => <Space size={4}>
          <InputNumber aria-label={`${t('listing.cap')} ${t(`limitMetrics.${r.metric}`)}`} disabled={!r.enabled} min={0} value={r.value}
            onChange={(v) => setRow(r.metric, { value: v === null ? null : Number(v) })} />
          {ruleOf(r.metric).units.length > 1 ? <Select style={{ width: 90 }} disabled={!r.enabled} value={r.unit} aria-label={t(`limitMetrics.${r.metric}`)}
            options={ruleOf(r.metric).units.map((u) => ({ value: u, label: t(`limitUnits.${u}`) }))}
            onChange={(unit) => setRow(r.metric, { unit, value: r.value })} /> : t(`limitUnits.${r.unit}`)}
        </Space> },
        { title: t('listing.action'), key: 'action', render: (_: unknown, r) => <Space size={4}>
          <Select style={{ width: 130 }} disabled={!r.enabled} value={r.action} aria-label={`${t('listing.action')} ${t(`limitMetrics.${r.metric}`)}`}
            options={ruleOf(r.metric).actions.map((a) => ({ value: a, label: t(`limitActions.${a}`) }))} onChange={(action) => setRow(r.metric, { action })} />
          {r.metric === 'monthly_traffic_bytes' && r.action === 'throttle' && r.enabled ? <InputNumber placeholder={t('listing.throttleMbps')} min={1}
            value={r.throttleMbps} onChange={(v) => setRow(r.metric, { throttleMbps: v === null ? null : Number(v) })} /> : null}
        </Space> },
      ]} />
      <Space><span>{t('listing.prepaid')}</span>
        <Select style={{ width: 160 }} value={prepaid} onChange={setPrepaid} aria-label={t('listing.prepaid')}
          options={(['pause', 'stop'] as const).map((value) => ({ value, label: t(`limitActions.${value}`) }))} /></Space>
      <Button type="primary" loading={saveLimits.isPending} onClick={() => {
        const { limits: next, problems } = toLimits(rows, floor)
        if (problems.length) {
          setError(problems.map((p) => t(`listing.problems.${p.code}`, { metric: t(`limitMetrics.${p.metric}`), floor: p.floor ?? '—' })).join('；'))
          return
        }
        saveLimits.mutate(next)
      }}>{t('life.save')}</Button>
    </Space>
  )
  return (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Alert type="info" showIcon message={t('life.editNotice')} />
      {error ? <Alert type="error" showIcon message={error} closable onClose={() => setError(null)} /> : null}
      <Tabs items={[{ key: 'price', label: t('life.tabPrice'), children: price }, { key: 'limits', label: t('life.tabLimits'), children: limits }]} />
    </Space>
  )
}
