import { useState } from 'react'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tabs, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketLimit, type MarketOfferListing, type MarketPrepaidAction, type MarketPricing,
  type MarketSupplyGroup, type MarketSupplyL2Option } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { offerablePlugin, ruleOf, toLimits, type LimitRow, type LoadFloor } from './limitsModel'
import { allocationOf, customProblem, declaredTagsOf, maxCustomTagLength, maxCustomTags, normalizeCustom, tagValuesOf, type ListingValues,
  type TagValues } from './listingModel'
import { CapabilityFields } from './OfferCapabilities'
import { priceFormOf, pricingOf, rowsOf, withSustain, type PriceForm, type Yuan } from './offerLifecycleModel'
import { PluginChecks } from './PluginChecks'
import { pluginLabel } from './resaleModel'

// one offer's 修改报价 from its row. Price through PUT …/terms (pricing only:
// community price, SLA and the switches are left as they are), limits through PUT …/limits; both send
// the revision the dialog opened on, so a change made meanwhile is refused (409 offer_changed).
// Buyers in period keep their snapshot; the new revision applies to new orders and renewals.
// 能力与防御 sends the capabilities and the included plugins through PUT …/limits too (the
// current limits unchanged). Capabilities reach new subscriptions only; plugins reach sold ones at once.
// 特性标签 edits the declared features shown on the offer card (共享/独立节点, CC, DDoS…)
// through PUT …/limits with tags (current limits unchanged); the plugins stay on 能力与防御.
// The tags form is named so its field ids do not collide with the listing form on the same page.
// The seller picks its own L2 configuration per own supply group (saved on the group, at
// once for every site on it) and declares 支持 L2 回源 among the capabilities; buyers never pick L2 nodes.

export function OfferTermsModal({ offer, floor, onClose }: { offer: MarketOfferListing | null; floor: LoadFloor | null; onClose: () => void }) {
  const { t } = useTranslation('nodeMarket')
  return (
    <Modal open={!!offer} title={t('life.editTitle', { name: offer?.name ?? '' })} onCancel={onClose} footer={null} destroyOnHidden width={760}>
      {offer ? <TermsEditor key={`${offer.id}:${offer.revision ?? ''}`} offer={offer} floor={floor} onClose={onClose} /> : null}
    </Modal>
  )
}

function TermsEditor({ offer, floor, onClose }: { offer: MarketOfferListing; floor: LoadFloor | null; onClose: () => void }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [form, setForm] = useState<PriceForm>(() => priceFormOf(offer))
  const [rows, setRows] = useState<LimitRow[]>(() => rowsOf(offer.limits))
  const [prepaid, setPrepaid] = useState<MarketPrepaidAction>(offer.prepaid_exhausted_action ?? 'pause')
  const [error, setError] = useState<string | null>(null)
  const expected = offer.revision ? { expected_revision: offer.revision } : {}
  const done = (next: MarketOfferListing, saved = t('life.saved')) => {
    void message.success(next.revision === offer.revision ? t('life.unchanged') : saved)
    void client.invalidateQueries({ queryKey: ['nodeMarket'] })
    onClose()
  }
  const fieldLabel = (field: string) => {
    const [group, key] = field.split('.')
    return group === 'tags' && i18n.exists(`nodeMarket:detail.tags.${key}`) ? t(`detail.tags.${key}`) : field
  }
  const fail = (e: unknown) => {
    const code = e instanceof ApiError ? e.code : 'request_failed'
    const refusal = (e as { refusal?: { plugins?: unknown; field?: unknown } }).refusal
    if (code === 'offer_changed') void client.invalidateQueries({ queryKey: ['nodeMarket'] })
    setError(code === 'offer_changed' ? t('life.changed')
      : code === 'plugin_unavailable' && Array.isArray(refusal?.plugins) ? t('caps.pluginUnavailable', { plugins: refusal.plugins.join('、') })
        : code === 'upstream_terms_exceeded' && typeof refusal?.field === 'string' ? t('caps.upstreamExceeded', { field: fieldLabel(refusal.field) })
          : code === 'l2_unavailable' ? t('caps.l2NotReported')
            : t('errors.failed', { code }))
  }
  const savePrice = useMutation({
    mutationFn: (pricing: MarketPricing) => marketApi.updateOfferTerms(token, offer.id, { pricing, ...expected }, newIdempotencyKey('offer-terms')),
    onSuccess: (next) => done(next), onError: fail,
  })
  const saveLimits = useMutation({
    mutationFn: (limits: MarketLimit[]) => marketApi.updateOfferLimits(token, offer.id,
      { limits: withSustain(limits, offer.limits), prepaid_exhausted_action: prepaid, ...expected }, newIdempotencyKey('offer-limits')),
    onSuccess: (next) => done(next), onError: fail,
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
      <Tabs items={[{ key: 'price', label: t('life.tabPrice'), children: price }, { key: 'limits', label: t('life.tabLimits'), children: limits },
        { key: 'caps', label: t('caps.tab'), children: <CapsEditor offer={offer} expected={expected} onDone={(next) => done(next, t('caps.saved'))} onFail={fail} /> },
        { key: 'tags', label: t('life.tabTags'), children: <TagsEditor offer={offer} expected={expected} onDone={(next) => done(next, t('caps.saved'))} onFail={fail} /> }]} />
    </Space>
  )
}

type CapsValues = Pick<ListingValues, 'httpPorts' | 'streamPorts' | 'http3'> & { l2: boolean; plugins: string[] }

// CapsEditor: capabilities (CapabilityFields, WebSocket always included) and the included node plugins.
// An offer of my own node groups offers the plugins every group has (as at listing, supply-groups/{id});
// one with a resold component can only keep or drop the plugins it has. The market checks again.
function CapsEditor({ offer, expected, onDone, onFail }: { offer: MarketOfferListing; expected: { expected_revision?: number };
  onDone: (o: MarketOfferListing) => void; onFail: (e: unknown) => void }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const [form] = Form.useForm<CapsValues>()
  const declared = offer.tags?.plugins ?? []
  const resold = (offer.components ?? []).some((c) => c.kind === 'upstream')
  const pools = (offer.components ?? []).filter((c) => c.kind === 'own_pool' && c.node_pool_ref).map((c) => c.node_pool_ref!)
  const groups = useQueries({ queries: (resold ? [] : pools).map((id) => ({ queryKey: ['nodeMarket', 'supplyGroup', id], enabled: !!token,
    retry: false, queryFn: () => marketApi.supplyGroup(token, id) })) })
  const lists = groups.map((g) => (g.data?.plugins ?? []).map((p) => p.code).filter(offerablePlugin))
  const available = resold || !lists.length || groups.some((g) => !g.data) ? [] : lists.reduce((a, b) => a.filter((code) => b.includes(code)))
  const codes = [...new Set([...declared, ...available])].sort()
  const names = useQuery({ queryKey: ['nodeMarket', 'pluginNames', codes.join(',')], enabled: !!token && codes.length > 0, retry: false,
    staleTime: 300_000, queryFn: () => marketApi.pluginNames(token, codes) })
  const nameMap = new Map([...groups.flatMap((g) => g.data?.plugins ?? []), ...(names.data ?? [])].map((p) => [p.code, p]))
  const english = (i18n.resolvedLanguage ?? 'zh-CN').startsWith('en')
  const save = useMutation({
    mutationFn: (v: CapsValues) => marketApi.updateOfferLimits(token, offer.id, { limits: offer.limits ?? [],
      prepaid_exhausted_action: offer.prepaid_exhausted_action ?? 'pause', allocation: allocationOf(v), plugins: [...v.plugins].sort(), ...expected },
    newIdempotencyKey('offer-caps')),
    onSuccess: onDone, onError: onFail,
  })
  const a = offer.allocation ?? {}
  return (
    <Form<CapsValues> form={form} layout="vertical" onFinish={(v) => save.mutate({ ...form.getFieldsValue(true), ...v })}
      initialValues={{ httpPorts: a.http_ports ?? 0, streamPorts: a.stream_ports ?? 0, http3: !!a.http3, l2: !!a.l2, plugins: declared }}>
      <Alert type="warning" showIcon message={t('caps.notice')} style={{ marginBottom: 12 }} />
      <Typography.Paragraph type="secondary">{t('caps.help')}</Typography.Paragraph>
      {offer.l2_unavailable ? <Alert type="warning" showIcon message={t('caps.l2Lost')} style={{ marginBottom: 12 }} /> : null}
      <CapabilityFields l2={{ help: resold ? t('caps.l2HelpResale') : t('caps.l2Help') }} />
      {!resold && pools.length > 0 ? <SupplyL2Pickers pools={pools} groups={groups.map((g) => g.data)} /> : null}
      <Form.Item name="plugins" label={t('caps.plugins')}
        extra={resold ? t('caps.pluginsResale') : codes.length === 0 && !groups.some((g) => g.isLoading) ? t('caps.pluginsNone') : t('caps.pluginsHelp')}>
        <PluginChecks options={codes.map((code) => ({ value: code, label: pluginLabel(code, nameMap, english) }))} />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={save.isPending}>{t('life.save')}</Button>
    </Form>
  )
}

// TagsEditor: the declared features as at listing (OfferListingForm 高级选项). A resale's upstream bound is checked by the market.
function TagsEditor({ offer, expected, onDone, onFail }: { offer: MarketOfferListing; expected: { expected_revision?: number };
  onDone: (o: MarketOfferListing) => void; onFail: (e: unknown) => void }) {
  const { t } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const resold = (offer.components ?? []).some((c) => c.kind === 'upstream')
  const save = useMutation({
    mutationFn: (v: TagValues) => marketApi.updateOfferLimits(token, offer.id, { limits: offer.limits ?? [],
      prepaid_exhausted_action: offer.prepaid_exhausted_action ?? 'pause', tags: declaredTagsOf(v), ...expected }, newIdempotencyKey('offer-tags')),
    onSuccess: onDone, onError: onFail,
  })
  const toggle = (name: 'complaint' | 'mobile' | 'regionBlock') => (
    <Form.Item name={name} label={t(`listing.${name}`)} extra={t(`listing.hints.${name}`)} style={{ width: 220 }} valuePropName="checked"><Switch /></Form.Item>
  )
  return (
    <Form<TagValues> name="offer-tags" layout="vertical" initialValues={tagValuesOf(offer.tags)} onFinish={(v) => save.mutate(v)}>
      <Typography.Paragraph type="secondary">{t('life.tagsNotice')}</Typography.Paragraph>
      <Space wrap align="start">
        <Form.Item name="tenancy" label={t('listing.tenancy')} extra={t('listing.hints.tenancy')} style={{ maxWidth: 220 }}>
          <Select style={{ width: 140 }} options={(['shared', 'dedicated'] as const).map((value) => ({ value, label: t(`tagValues.${value}`) }))} />
        </Form.Item>
        <Form.Item name="cc" label={t('listing.cc')}>
          <Select style={{ width: 140 }} options={(['none', 'basic', 'advanced'] as const).map((value) => ({ value, label: t(`tagValues.${value}`) }))} />
        </Form.Item>
        <Form.Item name="ddos" label={t('listing.ddos')}><InputNumber min={0} max={100000} precision={0} /></Form.Item>
        <Form.Item name="lineClass" label={t('listing.lineClass')}><Input maxLength={32} style={{ width: 200 }} disabled={resold} /></Form.Item>
      </Space>
      <Space wrap align="start">{toggle('complaint')}{toggle('mobile')}{toggle('regionBlock')}</Space>
      <Form.Item name="custom" label={t('listing.custom')} extra={t('listing.customHelp')} normalize={(value: string[]) => normalizeCustom(value)}
        rules={[{ validator: (_, value: string[]) => { const p = customProblem(value); return p ? Promise.reject(new Error(t(`listing.customInvalid.${p}`))) : Promise.resolve() } }]}>
        <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',', '，']} maxCount={maxCustomTags} style={{ maxWidth: 560 }}
          placeholder={t('listing.customPlaceholder')} maxTagTextLength={maxCustomTagLength} />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={save.isPending}>{t('life.save')}</Button>
    </Form>
  )
}

// SupplyL2Pickers: 供给组 L2 回源配置, one per own supply group of the offer. Saving writes the group
// (PUT supply-groups/{id} l2_config_id): the sites on it follow at once; the market sees the nodes'
// L2 at the controller's next pool report (about 5 minutes), then 支持 L2 回源 can be declared.
function SupplyL2Pickers({ pools, groups }: { pools: string[]; groups: Array<MarketSupplyGroup | undefined> }) {
  const { t } = useTranslation('nodeMarket')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const options = useQuery({ queryKey: ['nodeMarket', 'supplyL2Configs'], enabled: !!token, retry: false, staleTime: 60_000,
    queryFn: () => marketApi.supplyL2Configs(token) })
  return (
    <Form.Item label={t('caps.l2Config')} extra={t('caps.l2ConfigHelp')}>
      <Space direction="vertical" size={8} style={{ width: '100%' }}>
        {pools.map((pool, i) => <SupplyL2Picker key={pool} pool={pool} group={groups[i]} options={options.data ?? []}
          loading={options.isLoading} label={pools.length > 1 ? t('caps.l2ConfigGroup', { name: groups[i]?.name ?? pool.slice(0, 8) }) : t('caps.l2Config')} />)}
        {options.data && options.data.length === 0 ? <Typography.Text type="secondary">{t('caps.l2ConfigNone')}</Typography.Text> : null}
      </Space>
    </Form.Item>
  )
}

function SupplyL2Picker({ pool, group, options, loading, label }: { pool: string; group?: MarketSupplyGroup; options: MarketSupplyL2Option[];
  loading: boolean; label: string }) {
  const { t } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const current = group?.l2_config_id ?? ''
  const [value, setValue] = useState<string | null>(null)
  const chosen = value ?? current
  const save = useMutation({
    mutationFn: async (l2: string) => {
      const fresh = await marketApi.supplyGroup(token, pool)
      return marketApi.updateSupplyGroup(token, pool, fresh.revision, fresh.name, fresh.nodes.map((n) => n.node_id),
        newIdempotencyKey('supply-l2'), l2)
    },
    onSuccess: () => {
      void message.success(t('caps.l2ConfigSaved'))
      setValue(null)
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'supplyGroup', pool] })
    },
  })
  const code = save.error instanceof ApiError ? save.error.code : save.error ? 'request_failed' : ''
  return (
    <Space direction="vertical" size={4} style={{ width: '100%' }}>
      <Space wrap>
        <Select aria-label={label} style={{ width: 'min(320px, 100%)' }} loading={loading || !group} value={chosen}
          onChange={setValue} options={[{ value: '', label: t('caps.l2ConfigOff') },
            ...options.map((o) => ({ value: o.id, disabled: !o.usable && o.id !== current,
              label: o.usable ? o.name : t('caps.l2ConfigUnusableOption', { name: o.name }) }))]} />
        <Button disabled={!group || chosen === current} loading={save.isPending} onClick={() => save.mutate(chosen)}>
          {t('caps.l2ConfigApply')}</Button>
      </Space>
      {code ? <Alert type="error" showIcon message={code === 'l2_config_unusable' ? t('caps.l2ConfigUnusable') : t('errors.failed', { code })} /> : null}
    </Space>
  )
}
