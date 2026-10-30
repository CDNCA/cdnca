import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Descriptions, Form, Input, InputNumber, Modal, Radio, Select, Space, Steps, Switch, Table, Tag, Typography } from 'antd'
import type { CheckboxProps } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  marketApi, marketUnavailable, type MarketFrozenTerms, type MarketLimitAction, type MarketListingBatchItem, type MarketListingTemplate,
} from '../../api/market'
import { resaleForbiddenBy } from '../../api/marketSupplier'
import { nodesApi, type NodeInventoryItem, type NodeMetricsLatest } from '../../api/nodes'
import { useSessionStore } from '../../auth/session'
import { ListingBatchResults } from './ListingBatchResults'
import {
  defaultRows, floorOf, formatCap, offerablePlugin, ruleOf, shareOf, toLimits, type LimitRow, type LimitUnit, type LoadFloor,
} from './limitsModel'
import {
  allNodes as readAllNodes, billingModels, carrierOf, customProblem, defaultValues, exampleCharge, filterNodes, fromTemplate, maxCustomTagLength, maxCustomTags,
  mergeResults, moneyProblems, normalizeCustom, offerOf, regionOf, retryNodes, runLimited, templateBody,
  type BillingModel, type ListingValues, type NodeFilter,
} from './listingModel'
import {
  ccOptions, comboOfferOf, comboPlugins, comboTotals, maxIn, overUpstream, pluginLabel, resaleOfferOf, rowsFromUpstream, upstreamCap,
  valuesFromUpstream, type ResaleAllocation,
} from './resaleModel'
import { useErrorText } from './supplier/hooks'
import { useIdempotencyKey } from '../market/idempotency'
import { useFeedback } from '@cdnca/ui'
import { formatYuan } from '@cdnca/ui/offer-terms'

type Values = ListingValues & Partial<ResaleAllocation> & { subscription?: string; subscriptions?: string[] }
// C16: one listing flow, source → terms → publish. own: my nodes (listing
// batch, one own_pool each); resale: one of my bought subscriptions, whose
// frozen terms are inherited and may only be tightened; combo (u4g): my
// nodes plus subscriptions, or several subscriptions, in one offer (the
// market bounds each upstream leaf by its path, graph Min).
export type ListingSource = 'own' | 'resale' | 'combo'
type PluginNames = Map<string, { name_zh: string; name_en: string }>

const gradeRank: Record<string, number> = { s: 4, a: 3, b: 2, c: 1 }
// A combo's ports start at the components' sum (2 HTTP ports for my nodes, as a listing).
const defaultAllocation: ResaleAllocation = { httpPorts: 2, streamPorts: 0, websocket: false, http3: false }

const priceLabel = { daily_bundle: 'dailyMinor', traffic: 'perGBMinor', bandwidth_95: 'perMbpsMonthMinor', bandwidth_daily_peak: 'perMbpsDayMinor' } as const

// Current CPU / memory of the visible nodes, one metrics batch per table
// page instead of a history read per row (B23).
const PAGE_SIZE = 10

function NodeLoad({ load, loading }: { load?: NodeMetricsLatest; loading: boolean }) {
  const { t } = useTranslation('nodeMarket')
  if (!load || !load.known || load.cpu_percent === null || load.memory_used_bytes === null || !load.memory_total_bytes) {
    return <Typography.Text type="secondary">{loading ? '…' : t('listing.noLoad')}</Typography.Text>
  }
  return <span>{t('listing.loadValue', { cpu: Math.round(load.cpu_percent), memory: Math.round((load.memory_used_bytes / load.memory_total_bytes) * 100) })}</span>
}

const options = (values: string[]) => [...new Set(values.filter(Boolean))].sort().map((value) => ({ value, label: value }))

// C16: the terms frozen in the upstream subscription, read only. The fields
// below start at these values and can only be tightened (the market refuses
// anything looser).
function InheritedTerms({ up, plugin }: { up: MarketFrozenTerms; plugin: (code: string) => string }) {
  const { t } = useTranslation('nodeMarket')
  const a = up.allocation
  const g = up.tags
  const yes = (v?: boolean) => (v ? t('unified.yes') : t('unified.no'))
  return (
    <Descriptions size="small" bordered column={2} style={{ maxWidth: 720, marginBottom: 8 }} data-testid="inherited-terms"
      title={<Space size={8}>{t('unified.inherited')}<Tag color="orange">{t('unified.inheritedBadge')}</Tag></Space>}
      extra={<Typography.Text type="secondary">{t('unified.inheritedHelp')}</Typography.Text>}
      items={[
        { key: 'offer', label: t('unified.upstreamOffer'), children: `${up.name}（${t(`models.${up.billing_model}`, { defaultValue: up.billing_model })}）`, span: 2 },
        { key: 'ports', label: t('unified.ports'), children: t('unified.portsValue', { http: a.http_ports ?? 0, stream: a.stream_ports ?? 0 }) },
        { key: 'switches', label: t('unified.switches'), children: `WebSocket ${yes(a.websocket)} · HTTP/3 ${yes(a.http3)}` },
        { key: 'limits', label: t('listing.limits'), span: 2, children: up.limits.length ? up.limits.map((l) => {
          const c = formatCap(l.metric, l.cap)
          return <Tag key={l.metric}>{`${t(`limitMetrics.${l.metric}`)} ≤ ${c.value} ${t(`limitUnits.${c.unit}`)} · ${t(`limitActions.${l.action}`)}`}</Tag>
        }) : t('sell.unlimited') },
        { key: 'tags', label: t('listing.tags'), span: 2, children: [
          `${t('listing.cc')} ${t(`tagValues.${g.cc_protection ?? 'none'}`)}`, `DDoS ${g.ddos_protection_gbps ?? 0} Gbps`,
          t(`tagValues.${g.tenancy ?? 'shared'}`), ...(g.line_class ? [g.line_class] : []),
          ...(g.complaint_resistant ? [t('listing.complaint')] : []), ...(g.mobile_reachable ? [t('listing.mobile')] : []),
          ...(g.region_block ? [t('listing.regionBlock')] : []), ...(g.plugins ?? []).map(plugin), ...(g.custom ?? []),
        ].join(' · ') },
        { key: 'compliance', label: t('unified.compliance'), children: up.compliance.require_icp ? t('listing.icp') : t('unified.no') },
        { key: 'prepaid', label: t('listing.prepaid'), children: t(`limitActions.${up.prepaid_exhausted_action}`) },
      ]} />
  )
}

export function OfferListingForm({ initialSource = 'own' }: { initialSource?: ListingSource }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const errorText = useErrorText()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [form] = Form.useForm<Values>()
  const model = Form.useWatch('billing_model', form) ?? 'daily_bundle'
  const price = Form.useWatch('price', form)
  const [source, setSource] = useState<ListingSource>(initialSource)
  const resale = source === 'resale'
  const combo = source === 'combo'
  const subscription = Form.useWatch('subscription', form)
  const picked: string[] = Form.useWatch('subscriptions', form) ?? []
  const [refusal, setRefusal] = useState('')
  const member = useQuery({ queryKey: ['nodeMarket', 'member'], queryFn: () => marketApi.member(token), enabled: !!token, retry: false })
  const canResell = (member.data?.features ?? []).includes('market.resell')
  // MC09 (ML-26/26f): the offer quota is checked before the form is filled.
  // Remaining is known only when the market returns what is used; the market
  // still decides at creation (offer_quota_exceeded).
  const quota = member.data?.offers_quota
  const used = member.data?.offers_used
  const remaining = quota !== undefined && used !== undefined ? Math.max(quota - used, 0) : undefined
  const supplies = useQuery({ queryKey: ['nodeMarket', 'supplies'], queryFn: () => marketApi.supplies(token), enabled: !!token && (resale || combo) })
  const active = resale || combo ? (supplies.data ?? []).filter((s) => s.market_subscription_id && s.status === 'active') : []
  const terms = useQueries({ queries: active.map((s) => ({
    queryKey: ['nodeMarket', 'subscription', s.market_subscription_id], enabled: !!token,
    queryFn: () => marketApi.subscription(token, s.market_subscription_id),
  })) })
  // MC10 (B22): the market's answer for today (resale_now) when it gives one, else the right frozen at purchase.
  const termsOf = (id: string) => terms.find((q) => q.data?.id === id)?.data
  const forbidden = (id: string) => {
    const v = termsOf(id)
    return v?.resale_now ? !v.resale_now.allowed : v?.resale_allowed === false
  }
  const forbiddenText = (id: string) => {
    const now = termsOf(id)?.resale_now
    if (now?.reason === 'upstream_inactive') return t('marketSupplier:resale.upstreamInactive')
    return now?.ref ? t('marketSupplier:resale.forbiddenBy', { ref: now.ref }) : t('marketSupplier:resale.forbidden')
  }
  const up: MarketFrozenTerms | null = resale ? terms.find((q) => q.data?.id === subscription)?.data?.frozen_terms ?? null : null
  const frozenOf = (id: string) => terms.find((q) => q.data?.id === id)?.data?.frozen_terms
  const comboUps = combo ? picked.map(frozenOf).filter((f): f is MarketFrozenTerms => !!f) : []
  const [selected, setSelected] = useState<string[]>([])
  const [rows, setRows] = useState<LimitRow[]>(defaultRows)
  const [problems, setProblems] = useState<string[]>([])
  const [filter, setFilterState] = useState<NodeFilter>({})
  const [page, setPage] = useState(1)
  const setFilter = (update: (f: NodeFilter) => NodeFilter) => { setFilterState(update); setPage(1) }
  // single: one offer per node; multi: one offer over all selected nodes.
  const [listingMode, setMode] = useState<'single' | 'multi'>('single')
  // A combo puts all picked nodes in one pool: their common plugins.
  const mode = combo ? 'multi' : listingMode
  const [publish, setPublish] = useState(true)
  const [results, setResults] = useState<MarketListingBatchItem[]>([])
  const [template, setTemplate] = useState<MarketListingTemplate | null>(null)
  const [saveAs, setSaveAs] = useState<string | null>(null)

  const nodes = useQuery({ queryKey: ['nodeMarket', 'listing', 'nodes'], enabled: !!token,
    queryFn: async () => ({ items: await readAllNodes((cursor) => nodesApi.list(token, { limit: 200, cursor })) }) })
  const admissions = useQuery({ queryKey: ['nodeMarket', 'listing', 'admissions'], enabled: !!token, retry: false,
    queryFn: () => marketApi.nodeAdmissions(token) })
  const policy = useQuery({ queryKey: ['nodeMarket', 'listing', 'floor'], enabled: !!token, retry: false,
    queryFn: () => marketApi.supplyLimitsPolicy(token) })
  const templates = useQuery({ queryKey: ['nodeMarket', 'listing', 'templates'], enabled: !!token, retry: false,
    queryFn: () => marketApi.listingTemplates(token) })
  const floor: LoadFloor | null = policy.data?.policy.load_floor ?? null
  // Single-node mode: the plugin choice is the union over the nodes (each
  // item keeps what its node has, the rest is reported); multi: the intersection.
  const nodeKey = [...selected].sort().join(',')
  const plugins = useQuery({ queryKey: ['nodeMarket', 'listing', 'plugins', mode, nodeKey], enabled: !!token && selected.length > 0, retry: false,
    queryFn: async () => {
      if (mode === 'multi') return marketApi.supplyPlugins(token, [...selected].sort())
      const each = await runLimited([...selected].sort(), 8, (id) => marketApi.supplyPlugins(token, [id]))
      const seen = new Map<string, (typeof each)[number][number]>()
      for (const list of each) for (const p of list) seen.set(p.code, p)
      return [...seen.values()]
    } })
  const english = (i18n.resolvedLanguage ?? 'zh-CN').startsWith('en')
  // u4g: upstream snapshots keep plugin codes only; names come from this
  // controller's catalogue, an unknown code shows as is.
  const upstreamCodes = [...new Set([...(up?.tags.plugins ?? []), ...comboUps.flatMap((u) => u.tags.plugins ?? [])])].sort()
  const pluginNames = useQuery({ queryKey: ['nodeMarket', 'pluginNames', upstreamCodes.join(',')], enabled: !!token && upstreamCodes.length > 0,
    retry: false, staleTime: 300_000, queryFn: () => marketApi.pluginNames(token, upstreamCodes) })
  const nameMap: PluginNames = new Map([...(plugins.data ?? []), ...(pluginNames.data ?? [])].map((p) => [p.code, p]))
  const plugin = (code: string) => pluginLabel(code, nameMap, english)
  // A resale includes at most the upstream's plugins (graph: intersected along
  // the path); a combo only what every component has.
  const pluginCodes = resale ? (up?.tags.plugins ?? [])
    : combo ? comboPlugins(comboUps, selected.length ? (plugins.data ?? []).map((p) => p.code).filter(offerablePlugin) : null)
      : (plugins.data ?? []).filter((p) => offerablePlugin(p.code)).map((p) => p.code)
  const pluginOptions = pluginCodes.map((code) => ({ code, label: plugin(code) }))
  const totals = combo ? comboTotals(comboUps, selected.length > 0) : null

  // Picking a subscription starts the terms at what it inherits.
  const applied = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (!up || applied.current === subscription) return
    applied.current = subscription
    const model = billingModels.includes(up.billing_model as BillingModel) ? up.billing_model as BillingModel : 'daily_bundle'
    form.setFieldsValue({ ...valuesFromUpstream(up), billing_model: model })
    setRows(rowsFromUpstream(up))
  }, [up, subscription, form])
  // A combo's ports start at the sum of its components (adjustable).
  const comboPorts = totals ? `${totals.httpPorts + (selected.length ? 2 : 0)}:${totals.streamPorts}` : ''
  useEffect(() => {
    if (!comboPorts) return
    const [http, stream] = comboPorts.split(':').map(Number)
    form.setFieldsValue({ httpPorts: http, streamPorts: stream })
  }, [comboPorts, form])
  const switchSource = (next: ListingSource) => {
    setSource(next)
    setProblems([])
    setRefusal('')
    applied.current = undefined
    form.setFieldsValue({ ...defaultValues, subscription: undefined, subscriptions: [], name: form.getFieldValue('name') })
    setRows(defaultRows())
  }

  const grades = useMemo(() => {
    const out: Record<string, string> = {}
    for (const a of admissions.data ?? []) {
      const g = (a.benchmark_grade ?? '').toLowerCase()
      if (gradeRank[g] && (!out[a.node_id] || gradeRank[g] > gradeRank[out[a.node_id]])) out[a.node_id] = g
    }
    return out
  }, [admissions.data])
  const allNodes = useMemo(() => nodes.data?.items ?? [], [nodes.data])
  const shown = useMemo(() => filterNodes(allNodes, filter, grades), [allNodes, filter, grades])
  const visible = shown.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map((n) => n.id)
  const load = useQuery({ queryKey: ['nodeMarket', 'listing', 'load', visible.join(',')], enabled: !!token && visible.length > 0,
    staleTime: 60_000, retry: false, queryFn: async ({ signal }) => {
      const batch = await nodesApi.getLatestMetricsBatch(token, visible, signal)
      return Object.fromEntries(batch.items.map((m) => [m.node_id, m])) as Record<string, NodeMetricsLatest>
    } })
  const names = useMemo(() => Object.fromEntries(allNodes.map((n) => [n.id, n.name])), [allNodes])
  // Per-node share preview: each single-node item is one node.
  const shareNodes = mode === 'single' ? Math.min(selected.length, 1) : selected.length

  const setRow = (metric: LimitRow['metric'], patch: Partial<LimitRow>) =>
    setRows((current) => current.map((r) => (r.metric === metric ? { ...r, ...patch } : r)))

  const submit = useMutation({
    mutationFn: async ({ v, ids }: { v: Values; ids: string[] }) =>
      marketApi.listingBatch(token, { mode, node_ids: [...ids].sort(), offer: offerOf(v, rows, floor), publish }),
    onSuccess: (items, { ids }) => {
      const retry = ids.length < selected.length && results.length > 0
      setResults((current) => (retry ? mergeResults(current, items) : items))
      // Unpublished offers (publish failed) count too: not a success toast (B19).
      const failed = items.filter((i) => retryNodes([i]).length > 0).length
      if (failed) void feedback.warning(t('batch.someFailed', { count: failed }))
      else void message.success(t('batch.done', { count: items.length }))
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'myOffers'] })
    },
    onError: (error) => {
      const code = error instanceof ApiError ? error.code : 'request_failed'
      if (marketUnavailable(error)) void message.info(t('unavailable'))
      else void feedback.error(i18n.exists(`nodeMarket:listing.refused.${code}`) ? t(`listing.refused.${code}`) : t('errors.failed', { code }))
    },
  })

  // The market names the field by its JSON path (tags.cc_protection, limits.qps); show it in words.
  const upstreamFieldLabel = (field: string) => {
    const [group, key] = field.split('.')
    if (group === 'limits' && i18n.exists(`nodeMarket:limitMetrics.${key}`)) return t(`limitMetrics.${key}`)
    if (group === 'tags' && i18n.exists(`nodeMarket:detail.tags.${key}`)) return t(`detail.tags.${key}`)
    if (i18n.exists(`nodeMarket:unified.fields.${group}_${key}`)) return t(`unified.fields.${group}_${key}`)
    return field
  }
  const created = ({ status, publishError }: { status: string; publishError?: unknown }) => {
    setRefusal(publishError ? t('marketSupplier:resale.publishFailed', { reason: errorText(publishError) }) : '')
    if (!publishError) {
      void message.success(status === 'listed' ? t('marketSupplier:resale.listed') : status === 'pending_review' ? t('marketSupplier:resale.pendingReview') : t('marketSupplier:resale.created'))
    }
    void client.invalidateQueries({ queryKey: ['nodeMarket', 'myOffers'] })
  }
  const refused = (error: unknown) => {
    const ref = resaleForbiddenBy(error)
    const upstreamField = error instanceof ApiError && error.code === 'upstream_terms_exceeded'
      ? (error as ApiError & { refusal?: { field?: unknown } }).refusal?.field : undefined
    setRefusal(ref !== null ? (ref ? t('marketSupplier:resale.forbiddenBy', { ref }) : t('marketSupplier:resale.forbidden'))
      : typeof upstreamField === 'string' ? t('marketSupplier:resale.upstreamExceeded', { field: upstreamFieldLabel(upstreamField) })
        : error instanceof ApiError && error.status === 403 ? t('marketSupplier:resale.needResell') : errorText(error))
  }
  // Resale: one createOffer with the upstream component, then the same publish
  // endpoint as own-node listings; the result shows the real status.
  const createResale = useMutation({
    mutationFn: async (v: Values) => {
      const { id } = await marketApi.createOffer(token, resaleOfferOf(v as ListingValues & ResaleAllocation, rows, floor, v.subscription!, up!))
      if (!publish) return { status: 'draft' }
      try {
        return { status: (await marketApi.publishOffer(token, id)).status as string }
      } catch (error) {
        // The draft exists; say so instead of reporting the whole action as failed.
        return { status: 'draft', publishError: error as unknown }
      }
    },
    onSuccess: (r: { status: string; publishError?: unknown }) => created(r),
    onError: (error) => refused(error),
  })

  // Combo: the picked nodes become one supply group (own_pool), then one
  // createOffer with it and the subscriptions; publish as for a resale.
  const groupKey = useIdempotencyKey('combo-group')
  const createCombo = useMutation({
    mutationFn: async (v: Values) => {
      let poolRef: string | null = null
      if (selected.length) {
        const ids = [...selected].sort()
        poolRef = (await marketApi.createSupplyGroup(token, v.name.trim(), ids, groupKey.keyFor({ name: v.name.trim(), ids }))).node_pool_ref
      }
      const { id } = await marketApi.createOffer(token, comboOfferOf({ ...defaultAllocation, ...v } as ListingValues & ResaleAllocation, rows, floor,
        poolRef, v.subscriptions ?? [], pluginCodes))
      groupKey.complete()
      if (!publish) return { status: 'draft' }
      try {
        return { status: (await marketApi.publishOffer(token, id)).status as string }
      } catch (error) {
        return { status: 'draft', publishError: error as unknown }
      }
    },
    onSuccess: (r: { status: string; publishError?: unknown }) => created(r),
    // A refusal before the offer exists may retry with the same group key.
    onError: (error) => refused(error),
  })

  const check = (v: Values) => {
    const found = toLimits(rows, floor).problems.map((p) => t(`listing.problems.${p.code}`, { metric: t(`limitMetrics.${p.metric}`), floor: p.floor ?? '—' }))
    if (resale) {
      if (!v.subscription || !up) found.unshift(t('marketSupplier:resale.pickFirst'))
      else found.push(...overUpstream(rows, up).map((m) => t('marketSupplier:resale.overUpstream', { metric: t(`limitMetrics.${m}`) })))
    } else if (combo) {
      const subs = v.subscriptions ?? []
      if (subs.length === 0 || subs.length + (selected.length ? 1 : 0) < 2) found.unshift(t('unified.comboPick'))
    } else if (selected.length === 0) found.unshift(t('listing.noNodes'))
    const money = moneyProblems(v)
    if (money.includes('price')) found.push(`${t(`listing.${priceLabel[v.billing_model]}`)}：${t('listing.moneyInvalid')}`)
    if (money.includes('deposit')) found.push(`${t('listing.depositMinor')}：${t('listing.depositInvalid')}`)
    const custom = customProblem(v.custom)
    if (custom) found.push(t(`listing.customInvalid.${custom}`))
    if (!v.name?.trim()) found.unshift(t('batch.nameRequired'))
    setProblems(found)
    return found.length === 0
  }
  const onFinish = (v: Values) => {
    if (!check(v)) return
    if (resale) createResale.mutate({ ...(form.getFieldsValue(true) as Values), ...v })
    else if (combo) createCombo.mutate({ ...(form.getFieldsValue(true) as Values), ...v })
    else submit.mutate({ v, ids: selected })
  }
  const onRetry = () => {
    const v = form.getFieldsValue(true) as Values
    if (check(v)) submit.mutate({ v, ids: mode === 'multi' ? selected : retryNodes(results) })
  }

  const saveTemplate = useMutation({
    mutationFn: async (name: string) => marketApi.saveListingTemplate(token, {
      ...(template && template.name === name ? { id: template.id, revision: template.revision } : {}),
      name, body: templateBody(form.getFieldsValue(true) as Values, rows) }),
    onSuccess: (saved) => {
      setTemplate(saved)
      setSaveAs(null)
      void message.success(t('templates.saved'))
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'listing', 'templates'] })
    },
    onError: (error) => {
      const code = error instanceof ApiError ? error.code : 'request_failed'
      void feedback.error(i18n.exists(`nodeMarket:templates.errors.${code}`) ? t(`templates.errors.${code}`) : t('errors.failed', { code }))
    },
  })
  const removeTemplate = useMutation({
    mutationFn: (t: MarketListingTemplate) => marketApi.deleteListingTemplate(token, t.id, t.revision),
    onSuccess: () => {
      setTemplate(null)
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'listing', 'templates'] })
    },
  })
  // Applying overwrites the form (also when the current template is picked again).
  const apply = (id: string) => {
    const found = (templates.data ?? []).find((x) => x.id === id) ?? null
    setTemplate(found)
    if (!found) return
    const { values, rows: saved } = fromTemplate(found.body)
    form.setFieldsValue(values)
    setRows(saved)
  }

  const unitOptions = (units: LimitUnit[]) => units.map((u) => ({ value: u, label: t(`limitUnits.${u}`) || u }))
  const shareText = (row: LimitRow) => {
    const share = shareOf(row, shareNodes)
    if (!row.enabled || !share) return t('listing.shareNone')
    if (share.kind === 'perNode') return t('listing.sharePerNode')
    if (share.kind === 'total') return t('listing.shareTotal')
    const value = Number.isInteger(share.value) ? share.value : Number(share.value.toFixed(2))
    return t('listing.shareSplit', { value, unit: t(`limitUnits.${row.unit}`), nodes: shareNodes })
  }
  const upstreamText = (metric: LimitRow['metric']) => {
    const l = up ? upstreamCap(up, metric) : undefined
    if (!l) return t('unified.upstreamNone')
    const c = formatCap(metric, l.cap)
    return t('unified.upstreamCap', { value: c.value, unit: t(`limitUnits.${c.unit}`), action: t(`limitActions.${l.action}`) })
  }
  // Live example under the price (fix-offerform): what one subscriber pays.
  const charge = exampleCharge(model, Number(price))
  const example = charge ? t(`listing.example.${model}`, { quantity: charge.quantity, total: formatYuan(charge.total) }) : ''
  const shownIDs = shown.map((n) => n.id)
  const allShownSelected = shownIDs.length > 0 && shownIDs.every((id) => selected.includes(id))
  // Offers this submission creates: one per node in single mode, else one.
  const needed = !resale && !combo && mode === 'single' ? selected.length : 1
  const quotaBlock = quota === 0 ? t('quota.zero')
    : remaining !== undefined && remaining < needed ? t('quota.short', { total: quota, used, remaining, needed }) : ''

  return (
    <Form<Values> form={form} layout="vertical" onFinish={onFinish} initialValues={defaultValues}>
      {quota !== undefined ? <Alert type={quota === 0 || remaining === 0 ? 'warning' : 'info'} showIcon style={{ marginBottom: 16 }}
        message={remaining !== undefined ? t('quota.summary', { total: quota, used, remaining }) : t('quota.summaryTotal', { total: quota })}
        description={quota === 0 || remaining === 0 ? t('quota.who') : undefined} /> : null}
      <Steps size="small" style={{ marginBottom: 16, maxWidth: 640 }} current={resale ? (up ? 1 : 0) : combo ? (picked.length ? 1 : 0) : (selected.length ? 1 : 0)}
        items={[{ title: t('unified.steps.source') }, { title: t('unified.steps.terms') }, { title: t('unified.steps.publish') }]} />
      <Form.Item label={t('unified.source')} style={{ marginBottom: 12 }}>
        <Radio.Group value={source} optionType="button" aria-label={t('unified.source')} onChange={(e) => switchSource(e.target.value)}
          options={[{ value: 'own', label: t('unified.sources.own') },
            { value: 'resale', label: t('unified.sources.resale'), disabled: !!member.data && !canResell },
            { value: 'combo', label: t('unified.sources.combo'), disabled: !!member.data && !canResell }]} />
      </Form.Item>
      {member.data && !canResell ? <Typography.Paragraph type="secondary">{t('marketSupplier:resale.needResell')}</Typography.Paragraph> : null}
      {resale || combo ? null : <Space wrap align="end" style={{ marginBottom: 8 }}>
        <Form.Item label={t('templates.apply')} style={{ marginBottom: 0 }}>
          <Select aria-label={t('templates.apply')} allowClear style={{ width: 240 }} placeholder={t('templates.none')} value={template?.id}
            loading={templates.isLoading} onSelect={(id: string) => apply(id)} onClear={() => setTemplate(null)} options={(templates.data ?? []).map((x) => ({ value: x.id, label: x.name }))} />
        </Form.Item>
        <Button onClick={() => setSaveAs(template?.name ?? form.getFieldValue('name') ?? '')}>{t('templates.save')}</Button>
        {template ? <Button danger onClick={() => removeTemplate.mutate(template)} loading={removeTemplate.isPending}>{t('templates.delete')}</Button> : null}
      </Space>}
      <Modal open={saveAs !== null} title={t('templates.save')} onCancel={() => setSaveAs(null)} okText={t('templates.saveOk')}
        confirmLoading={saveTemplate.isPending} okButtonProps={{ disabled: !saveAs?.trim() }} onOk={() => saveTemplate.mutate(saveAs!.trim())}>
        <Typography.Paragraph type="secondary">{t('templates.help')}</Typography.Paragraph>
        <Input aria-label={t('templates.name')} placeholder={t('templates.name')} maxLength={64} value={saveAs ?? ''} onChange={(e) => setSaveAs(e.target.value)} />
      </Modal>

      <Form.Item name="name" label={t('listing.name')} extra={!resale && mode === 'single' ? t('batch.nameHelp') : undefined}
        rules={[{ required: true, whitespace: true }]}><Input maxLength={resale ? 128 : 64} style={{ maxWidth: 400 }} aria-label={t('listing.name')} /></Form.Item>

      {resale ? <>
        <Typography.Title level={5}>{t('marketSupplier:resale.component')}</Typography.Title>
        <Typography.Paragraph type="secondary">{t('marketSupplier:resale.help')}</Typography.Paragraph>
        <Form.Item name="subscription" label={t('marketSupplier:resale.component')} rules={[{ required: true }]}>
          <Select aria-label={t('marketSupplier:resale.component')} placeholder={t('marketSupplier:resale.pick')} notFoundContent={t('marketSupplier:resale.noSubscriptions')} style={{ maxWidth: 400 }}
            loading={supplies.isLoading} options={active.map((s) => ({ value: s.market_subscription_id, disabled: forbidden(s.market_subscription_id),
              label: forbidden(s.market_subscription_id) ? `${s.name}（${forbiddenText(s.market_subscription_id)}）` : s.name }))} />
        </Form.Item>
        {up ? <>
          <InheritedTerms up={up} plugin={plugin} />
          <Typography.Title level={5} style={{ marginTop: 16 }}>{t('unified.allocation')}</Typography.Title>
          <Space wrap align="start">
            <Form.Item name="httpPorts" label={t('unified.httpPorts')}>
              <InputNumber min={0} max={up.allocation.http_ports ?? 0} precision={0} aria-label={t('unified.httpPorts')} /></Form.Item>
            <Form.Item name="streamPorts" label={t('unified.streamPorts')}>
              <InputNumber min={0} max={up.allocation.stream_ports ?? 0} precision={0} aria-label={t('unified.streamPorts')} /></Form.Item>
            <Form.Item name="websocket" label={t('unified.websocket')} valuePropName="checked"><Switch disabled={!up.allocation.websocket} /></Form.Item>
            <Form.Item name="http3" label={t('unified.http3')} valuePropName="checked"><Switch disabled={!up.allocation.http3} /></Form.Item>
          </Space>
        </> : null}
      </> : <>
      {combo ? <>
        <Typography.Title level={5}>{t('unified.comboTitle')}</Typography.Title>
        <Typography.Paragraph type="secondary">{t('unified.comboHelp')}</Typography.Paragraph>
        <Form.Item name="subscriptions" label={t('unified.comboSubscriptions')}>
          <Select mode="multiple" aria-label={t('unified.comboSubscriptions')} placeholder={t('marketSupplier:resale.pick')} style={{ maxWidth: 560 }}
            notFoundContent={t('marketSupplier:resale.noSubscriptions')} loading={supplies.isLoading}
            options={active.map((s) => ({ value: s.market_subscription_id, disabled: forbidden(s.market_subscription_id),
              label: forbidden(s.market_subscription_id) ? `${s.name}（${forbiddenText(s.market_subscription_id)}）` : s.name }))} />
        </Form.Item>
      </> : null}
      <Typography.Title level={5}>{combo ? t('unified.comboNodes') : t('listing.nodes')}</Typography.Title>
      <Typography.Paragraph type="secondary">{combo ? t('unified.comboNodesHelp') : t('batch.nodesHelp')}</Typography.Paragraph>
      {combo ? null : <Radio.Group value={mode} onChange={(e) => setMode(e.target.value)} style={{ marginBottom: 12 }} aria-label={t('batch.mode')}
        options={[{ value: 'single', label: t('batch.modes.single') }, { value: 'multi', label: t('batch.modes.multi') }]} />}
      <Space wrap style={{ marginBottom: 8 }}>
        <Select aria-label={t('listing.region')} allowClear placeholder={t('listing.region')} style={{ width: 140 }} value={filter.region}
          options={options(allNodes.map(regionOf))} onChange={(region) => setFilter((f) => ({ ...f, region }))} />
        <Select aria-label={t('listing.carrier')} allowClear placeholder={t('listing.carrier')} style={{ width: 140 }} value={filter.carrier}
          options={options(allNodes.map(carrierOf))} onChange={(carrier) => setFilter((f) => ({ ...f, carrier }))} />
        <Select aria-label={t('listing.grade')} allowClear placeholder={t('listing.grade')} style={{ width: 120 }} value={filter.grade}
          options={['s', 'a', 'b', 'c'].map((g) => ({ value: g, label: g.toUpperCase() }))} onChange={(grade) => setFilter((f) => ({ ...f, grade }))} />
        <Input.Search aria-label={t('batch.keyword')} placeholder={t('batch.keyword')} allowClear style={{ width: 220 }}
          onSearch={(keyword) => setFilter((f) => ({ ...f, keyword }))} />
        <Checkbox checked={!!filter.onlineOnly} onChange={(e) => setFilter((f) => ({ ...f, onlineOnly: e.target.checked }))}>{t('batch.onlineOnly')}</Checkbox>
        <Button onClick={() => setSelected((current) => allShownSelected
          ? current.filter((id) => !shownIDs.includes(id)) : [...new Set([...current, ...shownIDs])])} disabled={shownIDs.length === 0}>
          {allShownSelected ? t('batch.unselectShown', { count: shownIDs.length }) : t('batch.selectShown', { count: shownIDs.length })}
        </Button>
      </Space>
      <Table<NodeInventoryItem> rowKey="id" size="small" loading={nodes.isLoading} dataSource={shown}
        pagination={{ pageSize: PAGE_SIZE, current: page, onChange: setPage, hideOnSinglePage: true, showSizeChanger: false }}
        rowSelection={{ selectedRowKeys: selected, preserveSelectedRowKeys: true, onChange: (keys) => setSelected(keys.map(String)),
          // antd forwards aria-* to the checkbox input; its CheckboxProps type omits them.
          getCheckboxProps: (n) => ({ 'aria-label': n.name }) as CheckboxProps }}
        columns={[
          { title: t('listing.node'), dataIndex: 'name' },
          { title: t('listing.region'), key: 'region', render: (_: unknown, n) => regionOf(n) || '—' },
          { title: t('listing.carrier'), key: 'carrier', render: (_: unknown, n) => carrierOf(n) || '—' },
          { title: t('listing.grade'), key: 'grade', render: (_: unknown, n) => grades[n.id] ? <Tag color="blue">{grades[n.id].toUpperCase()}</Tag> : '—' },
          { title: t('batch.presence'), key: 'presence', render: (_: unknown, n) => <Tag color={n.presence?.status === 'online' ? 'success' : 'default'}>
            {t(`batch.presenceValues.${n.presence?.status ?? 'unknown'}`)}</Tag> },
          { title: t('listing.load'), key: 'load', render: (_: unknown, n) => <NodeLoad load={load.data?.[n.id]} loading={load.isLoading} /> },
        ]} />
      <Typography.Text type="secondary">{combo ? t('unified.comboSelected', { count: selected.length }) : mode === 'single'
        ? t('batch.selectedSingle', { count: selected.length }) : t('batch.selectedMulti', { count: selected.length })}</Typography.Text>
      {totals ? <>
        <Descriptions size="small" bordered column={1} style={{ maxWidth: 720, marginTop: 16 }} data-testid="combo-totals"
          title={t('unified.comboTotals')} extra={<Typography.Text type="secondary">{t('unified.comboMin')}</Typography.Text>}
          items={[
            { key: 'ports', label: t('unified.ports'), children: t('unified.portsValue', { http: totals.httpPorts + (selected.length ? 2 : 0), stream: totals.streamPorts }) },
            ...defaultRows().filter((r) => r.metric in totals.limits).map((r) => {
              const cap = totals.limits[r.metric]
              const c = cap == null ? null : formatCap(r.metric, cap)
              return { key: r.metric, label: t(`limitMetrics.${r.metric}`), children: c ? `≤ ${c.value} ${t(`limitUnits.${c.unit}`)}` : t('sell.unlimited') }
            }),
          ]} />
        <Space wrap align="start" style={{ marginTop: 12 }}>
          <Form.Item name="httpPorts" label={t('unified.httpPorts')}><InputNumber min={0} precision={0} aria-label={t('unified.httpPorts')} /></Form.Item>
          <Form.Item name="streamPorts" label={t('unified.streamPorts')}><InputNumber min={0} precision={0} aria-label={t('unified.streamPorts')} /></Form.Item>
          <Form.Item name="websocket" label={t('unified.websocket')} valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="http3" label={t('unified.http3')} valuePropName="checked"><Switch /></Form.Item>
        </Space>
      </> : null}
      </>}

      <Typography.Title level={5} style={{ marginTop: 24 }}>{t('listing.pricing')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('listing.pricingHelp')}</Typography.Paragraph>
      <Space wrap align="start">
        <Form.Item name="billing_model" label={t('listing.model')} extra={t(`listing.modelHelp.${model}`)} style={{ maxWidth: 320 }}>
          <Select style={{ width: 280 }} optionLabelProp="title"
            options={billingModels.map((value) => ({ value, title: t(`models.${value}`), label: <Space direction="vertical" size={0}>
              <span>{t(`models.${value}`)}</span>
              <Typography.Text type="secondary" style={{ fontSize: 12, whiteSpace: 'normal' }}>{t(`listing.modelHelp.${value}`)}</Typography.Text>
            </Space> }))} />
        </Form.Item>
        <Form.Item name="price" label={t(`listing.${priceLabel[model]}`)} rules={[{ required: true }]}
          extra={example ? <span data-testid="price-example">{example}</span> : undefined}>
          <InputNumber min={0} step={0.01} style={{ width: 180 }} /></Form.Item>
        {model === 'daily_bundle' ? <>
          <Form.Item name="minDays" label={t('listing.minDays')}><InputNumber min={1} max={3660} precision={0} /></Form.Item>
          <Form.Item name="maxDays" label={t('listing.maxDays')}><InputNumber min={1} max={3660} precision={0} /></Form.Item>
          <Form.Item name="trialDays" label={t('listing.trialDays')} extra={t('listing.trialHelp')}>
            <InputNumber min={0} max={30} precision={0} aria-label={t('listing.trialDays')} /></Form.Item>
        </> : <Form.Item name="deposit" label={t('listing.depositMinor')} rules={[{ required: true }]} extra={t('listing.depositHelp')} style={{ maxWidth: 320 }}>
          <InputNumber min={0.01} step={0.01} style={{ width: 180 }} /></Form.Item>}
      </Space>
      {model !== 'daily_bundle' ? <Typography.Paragraph type="secondary">{t('listing.trialMetered')}</Typography.Paragraph> : null}

      <Typography.Title level={5}>{t('listing.limits')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('listing.limitsHelp')}</Typography.Paragraph>
      <Table<LimitRow> rowKey="metric" size="small" pagination={false} dataSource={rows} aria-label={t('listing.limits')}
        columns={[
          { key: 'on', width: 48, render: (_: unknown, row) => {
            const max = floorOf(row.metric, floor)
            const blocked = ruleOf(row.metric).perNode && max === undefined
            // An upstream cap is inherited: it can be lowered, not removed.
            const inherited = !!up && upstreamCap(up, row.metric) !== undefined
            return <Checkbox aria-label={t(`limitMetrics.${row.metric}`)} checked={row.enabled} disabled={blocked || inherited}
              onChange={(e) => setRow(row.metric, { enabled: e.target.checked, ...(e.target.checked && row.value === null && max !== undefined ? { value: max } : {}) })} />
          } },
          { title: t('listing.metric'), key: 'metric', render: (_: unknown, row) => {
            const max = floorOf(row.metric, floor)
            return <Space direction="vertical" size={0}>
              <span>{t(`limitMetrics.${row.metric}`)}</span>
              {ruleOf(row.metric).perNode ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {max === undefined ? t('listing.floorUnknown') : t('listing.floorHint', { floor: max })}</Typography.Text> : null}
              {up ? <Typography.Text type="secondary" style={{ fontSize: 12 }} data-testid={`upstream-${row.metric}`}>
                {upstreamText(row.metric)}</Typography.Text> : null}
            </Space>
          } },
          { title: t('listing.cap'), key: 'cap', render: (_: unknown, row) => {
            const max = up ? maxIn(row, up, floor) : ruleOf(row.metric).perNode ? floorOf(row.metric, floor) : undefined
            return <InputNumber aria-label={`${t('listing.cap')} ${t(`limitMetrics.${row.metric}`)}`} disabled={!row.enabled} min={1}
              max={max} value={row.value} placeholder={t('sell.unlimited')}
              onChange={(value) => setRow(row.metric, { value: value === null ? null : Number(value) })} />
          } },
          { title: t('listing.unit'), key: 'unit', render: (_: unknown, row) => {
            const units = ruleOf(row.metric).units
            return units.length > 1
              ? <Select aria-label={`${t('listing.unit')} ${t(`limitMetrics.${row.metric}`)}`} style={{ width: 96 }} disabled={!row.enabled} value={row.unit}
                options={unitOptions(units)} onChange={(unit: LimitUnit) => setRow(row.metric, { unit })} />
              : t(`limitUnits.${row.unit}`)
          } },
          { title: t('listing.action'), key: 'action', render: (_: unknown, row) => {
            const actions = ruleOf(row.metric).actions
            return <Space wrap>
              <Select aria-label={`${t('listing.action')} ${t(`limitMetrics.${row.metric}`)}`} style={{ width: 140 }} value={row.action}
                disabled={!row.enabled || actions.length === 1} options={actions.map((a) => ({ value: a, label: t(`limitActions.${a}`) }))}
                onChange={(action: MarketLimitAction) => setRow(row.metric, { action })} />
              {row.metric === 'monthly_traffic_bytes' && row.action === 'throttle' && row.enabled
                ? <InputNumber aria-label={t('listing.throttleMbps')} placeholder={t('listing.throttleMbps')} min={1} style={{ width: 150 }}
                  value={row.throttleMbps} onChange={(value) => setRow(row.metric, { throttleMbps: value === null ? null : Number(value) })} />
                : null}
            </Space>
          } },
          { title: t('listing.share'), key: 'share', render: (_: unknown, row) => <span data-testid={`share-${row.metric}`}>{shareText(row)}</span> },
        ]} />

      <Form.Item name="prepaid" label={t('listing.prepaid')} extra={t('listing.prepaidHelp')} style={{ marginTop: 24 }}>
        <Select style={{ width: 200 }} options={(['pause', 'stop'] as const).map((value) => ({ value, label: t(`limitActions.${value}`) }))} />
      </Form.Item>

      <Typography.Title level={5}>{t('listing.tags')}</Typography.Title>
      <Typography.Paragraph type="secondary">{resale ? t('unified.tagsInherited') : t('listing.tagsHelp')}</Typography.Paragraph>
      <Space wrap align="start">
        <Form.Item name="cc" label={t('listing.cc')}>
          <Select style={{ width: 140 }} aria-label={t('listing.cc')} options={(up ? ccOptions(up) : (['none', 'basic', 'advanced'] as const))
            .map((value) => ({ value, label: t(`tagValues.${value}`) }))} />
        </Form.Item>
        <Form.Item name="ddos" label={t('listing.ddos')}>
          <InputNumber min={0} max={up ? up.tags.ddos_protection_gbps ?? 0 : 100000} precision={0} aria-label={t('listing.ddos')} /></Form.Item>
        <Form.Item name="tenancy" label={t('listing.tenancy')} extra={t('listing.hints.tenancy')} style={{ maxWidth: 220 }}>
          <Select style={{ width: 140 }} options={(['shared', 'dedicated'] as const).map((value) => ({ value, label: t(`tagValues.${value}`),
            disabled: !!up && value === 'dedicated' && up.tags.tenancy !== 'dedicated' }))} />
        </Form.Item>
        <Form.Item name="lineClass" label={t('listing.lineClass')}><Input maxLength={32} style={{ width: 200 }} disabled={resale} /></Form.Item>
      </Space>
      <Space wrap>
        <Form.Item name="complaint" label={t('listing.complaint')} extra={t('listing.hints.complaint')} style={{ width: 260 }} valuePropName="checked"><Switch disabled={!!up && !up.tags.complaint_resistant} /></Form.Item>
        <Form.Item name="mobile" label={t('listing.mobile')} extra={t('listing.hints.mobile')} style={{ width: 260 }} valuePropName="checked"><Switch disabled={!!up && !up.tags.mobile_reachable} /></Form.Item>
        <Form.Item name="regionBlock" label={t('listing.regionBlock')} extra={t('listing.hints.regionBlock')} style={{ width: 260 }} valuePropName="checked"><Switch disabled={!!up && !up.tags.region_block} /></Form.Item>
      </Space>
      <Form.Item name="custom" label={t('listing.custom')} extra={t('listing.customHelp')} normalize={(value: string[]) => normalizeCustom(value)}
        rules={[{ validator: (_, value: string[]) => { const p = customProblem(value); return p ? Promise.reject(new Error(t(`listing.customInvalid.${p}`))) : Promise.resolve() } }]}>
        <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',', '，']} maxCount={maxCustomTags} style={{ maxWidth: 560 }}
          aria-label={t('listing.custom')} placeholder={t('listing.customPlaceholder')}
          maxTagTextLength={maxCustomTagLength} />
      </Form.Item>
      <Form.Item name="plugins" label={t('listing.plugins')} extra={combo ? t('unified.comboPlugins')
        : resale ? (pluginOptions.length ? t('unified.pluginsInherited') : t('unified.pluginsNone'))
        : selected.length === 0 ? t('listing.pluginsPickNodes')
          : pluginOptions.length === 0 && !plugins.isLoading ? t('listing.pluginsNone')
            : mode === 'single' ? `${t('listing.pluginsHelp')}${t('batch.pluginsHelp')}` : t('listing.pluginsHelp')}>
        <Checkbox.Group options={pluginOptions.map((p) => ({ value: p.code, label: p.label }))} />
      </Form.Item>
      <Form.Item name="icp" label={t('listing.icp')} valuePropName="checked"
        extra={up?.compliance.require_icp ? t('unified.icpInherited') : undefined}><Switch disabled={!!up?.compliance.require_icp} /></Form.Item>
      {refusal ? <Alert type="error" showIcon style={{ marginBottom: 16 }} message={refusal} /> : null}

      {problems.length ? <Alert type="error" showIcon style={{ marginBottom: 16 }} message={<ul style={{ margin: 0, paddingLeft: 16 }}>
        {problems.map((p) => <li key={p}>{p}</li>)}</ul>} /> : null}
      {quotaBlock ? <Alert type="warning" showIcon style={{ marginBottom: 16 }} message={quotaBlock} /> : null}
      <Space>
        <Checkbox checked={publish} onChange={(e) => setPublish(e.target.checked)}>{t('batch.publish')}</Checkbox>
        {combo
          ? <Button type="primary" htmlType="submit" loading={createCombo.isPending} disabled={!canResell || !!quotaBlock}>
            {publish ? t('unified.comboSubmitPublish') : t('unified.comboSubmit')}</Button>
          : resale ? <Button type="primary" htmlType="submit" loading={createResale.isPending} disabled={!canResell || !!quotaBlock}>
            {publish ? t('marketSupplier:resale.submitPublish') : t('marketSupplier:resale.submit')}</Button>
          : <Button type="primary" htmlType="submit" loading={submit.isPending} disabled={!!quotaBlock || selected.length === 0}>{mode === 'single'
            ? t('batch.submitSingle', { count: selected.length }) : t('batch.submitMulti')}</Button>}
        {!resale && !combo && selected.length === 0
          ? <Typography.Text type="secondary" data-testid="pick-nodes-first">{t('batch.pickNodesFirst')}</Typography.Text> : null}
      </Space>
      {!resale && !combo && results.length ? <ListingBatchResults items={results} names={names} onRetry={onRetry} retrying={submit.isPending} /> : null}
    </Form>
  )
}
