import { useState, type CSSProperties, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Result, Spin, Tabs } from 'antd'
import { ChevronDown, ChevronUp } from 'lucide-react'
import dayjs, { type Dayjs } from 'dayjs'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'

import {
  analyticsApi,
  type AnalyticsFilters,
  type AnalyticsWAFRankItem,
  type AnalyticsWAFTrendPoint,
} from '../api/analytics'
import { ApiError, type Principal } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { displayIP, formatDateTime, formatNumber, formatPercent } from '../i18n/formatters'
import '../i18n/wafLogs'
import { AnalyticsLogPage, type AnalyticsLogSeed } from './SiteAccessLogPage'
import { themeColor, useThemeRevision } from '../theme/themeColor'
import './WafLogsPage.css'
import './WafLogsV2.css'
import { FeedbackWhen, TimeRangeFilter, resolveTimeRangePreset } from '@cdnca/ui'

type WafOwner = readonly [Principal['scope_kind'], string, string | null, string, number]

interface WafDraft {
  /** TimeRangeFilter preset key or 'custom'. */
  preset: string
  from: string
  to: string
  domain: string
  siteId: string
  nodeId: string
}

const maximumWindow = 31 * 24 * 60 * 60 * 1000
const hostPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$/
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
// Read at render time from the theme (defaults: the chart palette).
// fix-waflogdetail3: one list for the trend lines, their legend and the
// summary card marks, so a count keeps one name (metrics.*) and one color.
type WafSeriesKey = 'attacks' | 'blocked' | 'challenged' | 'observed' | 'autoBlocked'
const wafSeries = () => [
  { key: 'attacks', field: 'attacks', color: themeColor('--cdnca-chart-color1', '#2d8cf0') },
  { key: 'blocked', field: 'blocked', color: themeColor('--cdnca-chart-color4', '#ed4014') },
  { key: 'challenged', field: 'intercepted', color: themeColor('--cdnca-chart-color5', '#9a66e4') },
  { key: 'observed', field: 'observed', color: themeColor('--cdnca-chart-color3', '#ff9900') },
  { key: 'autoBlocked', field: 'auto_blocked', color: themeColor('--cdnca-chart-color8', '#e46cbb') },
] as const satisfies readonly { key: WafSeriesKey, field: keyof AnalyticsWAFTrendPoint, color: string }[]

function localDateTime(value: Date): string {
  const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 19)
}

// The overview queries whole hours (validationMessage) over at most maximumWindow.
function presetWindow(preset: string): Pick<WafDraft, 'from' | 'to'> {
  const [from, to] = resolveTimeRangePreset(preset, 'hour')!
  return { from: hourStart(from), to: hourStart(to) }
}

function initialDraft(): WafDraft {
  return { preset: 'today', ...presetWindow('today'), domain: '', siteId: '', nodeId: '' }
}

function ownerFromPrincipal(principal: Principal, epoch: number): WafOwner | null {
  if (!principal.scope_id?.trim() || !principal.user_id?.trim() || epoch < 1) return null
  const canRead = principal.permissions.includes('sites.read') ||
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  if (!canRead) return null
  if (principal.scope_kind === 'tenant' && !principal.tenant_id) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, epoch]
}

function currentToken(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = ownerFromPrincipal(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function canonicalDomains(value: string): string | null {
  const tokens = value.trim().split(/\s+/u).filter(Boolean)
  if (tokens.length === 0) return ''
  if (tokens.length > 64) return null
  const domains: string[] = []
  const seen = new Set<string>()
  for (const token of tokens) {
    const domain = token.toLowerCase().replace(/\.$/u, '')
    if (!hostPattern.test(domain) || seen.has(domain)) return null
    seen.add(domain)
    domains.push(domain)
  }
  return domains.join(' ')
}

function filtersFromDraft(draft: WafDraft, domain: string): AnalyticsFilters {
  return {
    from: new Date(draft.from).toISOString(),
    to: new Date(draft.to).toISOString(),
    ...(domain ? { domain } : {}),
    ...(draft.siteId.trim() ? { siteId: draft.siteId.trim().toLowerCase() } : {}),
    ...(draft.nodeId.trim() ? { nodeId: draft.nodeId.trim().toLowerCase() } : {}),
  }
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.requestFailed'
  if (error.status === 403) return 'states.permissionTitle'
  if (error.status === 400) return 'states.invalidRequest'
  if (error.status === 502 || error.code === 'invalid_response') return 'states.invalidResponse'
  if (error.status === 503 || error.status === 0) return 'states.unavailable'
  return 'states.requestFailed'
}

function TrendChart({ points, language }: { points: AnalyticsWAFTrendPoint[]; language: string }) {
  const { t } = useTranslation('wafLogs')
  const width = 1000
  const height = 210
  const plot = { left: 44, right: 20, top: 24, bottom: 28 }
  const plotWidth = width - plot.left - plot.right
  const plotHeight = height - plot.top - plot.bottom
  const [hidden, setHidden] = useState<ReadonlySet<WafSeriesKey>>(() => new Set())
  useThemeRevision()
  const series = wafSeries()
  const shown = series.filter(({ key }) => !hidden.has(key))
  const toggle = (key: WafSeriesKey) => setHidden((current) => {
    const next = new Set(current)
    if (!next.delete(key)) next.add(key)
    return next
  })
  const maximum = Math.max(1, ...points.flatMap((point) => shown.map(({ field }) => point[field])))
  const x = (index: number) => points.length < 2 ? plot.left + plotWidth / 2 : plot.left + index / (points.length - 1) * plotWidth
  const y = (value: number) => plot.top + plotHeight - value / maximum * plotHeight
  const labels = points.length > 0 ? [points[0], points[Math.floor((points.length - 1) / 2)], points.at(-1)!] : []
  const timeFormatter = new Intl.DateTimeFormat(language === 'en-US' ? 'en-US' : 'zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  })

  return <section className="waf-overview-trend" aria-label={t('charts.trend')}>
    <div className="waf-overview-trend-legend" role="group" aria-label={t('charts.legend')}>
      {series.map(({ key, color }) => <button type="button" key={key} aria-pressed={!hidden.has(key)} onClick={() => toggle(key)}>
        <i aria-hidden="true" style={{ '--waf-series-color': color } as CSSProperties} />{t(`metrics.${key}`)}
      </button>)}
    </div>
    <div className="waf-overview-trend-canvas">
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={t('charts.trend')}>
        {[0, 0.5, 1].map((fraction) => {
          const gridY = plot.top + plotHeight - fraction * plotHeight
          return <g key={fraction}>
            <line className="waf-overview-grid-line" x1={plot.left} x2={width - plot.right} y1={gridY} y2={gridY} />
            <text className="waf-overview-axis-label" x={plot.left - 8} y={gridY + 4} textAnchor="end">{formatNumber(maximum * fraction, language)}</text>
          </g>
        })}
        {points.length > 0 ? shown.map(({ key, field, color }) => <polyline
          key={key}
          data-series={key}
          className="waf-overview-trend-line"
          points={points.map((point, index) => `${x(index)},${y(point[field])}`).join(' ')}
          style={{ '--waf-series-color': color } as CSSProperties}
        />) : null}
        {labels.map((point, index) => <text
          className="waf-overview-axis-label"
          key={`${point.hour}-${index}`}
          x={index === 0 ? plot.left : index === 1 ? plot.left + plotWidth / 2 : width - plot.right}
          y={height - 7}
          textAnchor={index === 0 ? 'start' : index === 1 ? 'middle' : 'end'}
        >{timeFormatter.format(new Date(point.hour))}</text>)}
      </svg>
      {points.length === 0 ? <span className="waf-overview-empty">{t('states.emptyTrend')}</span> : null}
    </div>
  </section>
}

// ui-errmsg-1024: an attack type is named like the block event list (the
// server's rule name, else "OWASP CRS #<id>" for a bare CRS ID); the key is the title.
function attackTypeLabel(item: AnalyticsWAFRankItem, t: TFunction<'wafLogs'>): string {
  if (item.name) return item.name
  if (item.key === '__unknown__') return t('states.unknownRule')
  if (/^[0-9]{6}$/.test(item.key)) return `OWASP CRS #${item.key}`
  // fix-wafname: a rule ID nothing names never shows as the whole UUID.
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.key)
    ? t('states.unnamedRule', { id: item.key.slice(0, 8).toLowerCase() })
    : item.key
}

// fix-waflog: one ranked list (name, share bar, share, count) instead of a donut plus the same table.
function AttackTypePanel({ items, language }: { items: AnalyticsWAFRankItem[]; language: string }) {
  const { t } = useTranslation('wafLogs')
  const total = items.reduce((sum, item) => sum + item.count, 0)

  return <section className="waf-v2-card waf-v2-attack-types" aria-labelledby="waf-attack-types-title">
    <h2 id="waf-attack-types-title">{t('charts.attackTypes')}</h2>
    <table className="waf-v2-rank-table">
      <thead><tr><th>{t('columns.attackType')}</th><th aria-hidden="true" /><th>{t('columns.ratio')}</th><th>{t('columns.count')}</th></tr></thead>
      <tbody>{items.length > 0 ? items.map((item) => <tr key={item.key}>
        <td title={item.key}>{attackTypeLabel(item, t)}</td>
        <td aria-hidden="true"><span className="waf-v2-bar" style={{ '--waf-share': `${item.count / total * 100}%` } as CSSProperties} /></td>
        <td>{formatPercent(item.count / total, language)}</td>
        <td>{formatNumber(item.count, language)}</td>
      </tr>) : <tr><td colSpan={4}>{t('states.emptyAttackTypes')}</td></tr>}</tbody>
    </table>
  </section>
}

// ui-errmsg-1024: the unknown sentinel reads as 未知; a mapped IPv4 client as IPv4.
function rankLabel(key: string, t: TFunction<'wafLogs'>): string {
  return key === '__unknown__' ? t('states.unknown') : displayIP(key)
}

/** Country rank keys are ISO codes (DE, SE); show the localized country name. */
function countryLabel(code: string, locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}

function RankTable({ title, valueLabel, items, language, onView, labelOf }: {
  title: string; valueLabel: string; items: AnalyticsWAFRankItem[]; language: string; onView?: (key: string) => void
  labelOf?: (key: string) => string
}) {
  const { t } = useTranslation('wafLogs')
  const top = Math.max(1, ...items.map((item) => item.count))
  return <section className="waf-v2-card waf-v2-ranking" aria-label={title}>
    <h2>{title}</h2>
    <table className="waf-v2-rank-table">
      <thead><tr><th>{valueLabel}</th><th>{t('columns.count')}</th></tr></thead>
      <tbody>{items.length > 0 ? items.map((item) => {
        const label = item.key !== '__unknown__' && labelOf ? labelOf(item.key) : rankLabel(item.key, t)
        return <tr key={item.key} style={{ '--waf-share': `${item.count / top * 100}%` } as CSSProperties}>
          <td title={item.key}>{onView && item.key !== '__unknown__'
            ? <button type="button" className="waf-v2-drill" aria-label={t('redesign.viewLogs', { value: label })} onClick={() => onView(item.key)}>{label}</button>
            : label}</td>
          <td>{formatNumber(item.count, language)}</td>
        </tr>
      }) : <tr><td colSpan={2}>{t('states.empty')}</td></tr>}</tbody>
    </table>
  </section>
}

function hourStart(value: Dayjs): string {
  return localDateTime(value.startOf('hour').toDate())
}

function validationMessage(nextDraft: WafDraft, t: TFunction<'wafLogs'>): string | null {
  const from = new Date(nextDraft.from)
  const to = new Date(nextDraft.to)
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to || to.getTime() - from.getTime() > maximumWindow ||
    from.getMinutes() !== 0 || from.getSeconds() !== 0 || to.getMinutes() !== 0 || to.getSeconds() !== 0) return t('states.invalidWindow')
  if (canonicalDomains(nextDraft.domain) === null) return t('states.invalidDomain')
  if (nextDraft.siteId.trim() && !uuidPattern.test(nextDraft.siteId.trim().toLowerCase())) return t('states.invalidSite')
  if (nextDraft.nodeId.trim() && !uuidPattern.test(nextDraft.nodeId.trim().toLowerCase())) return t('states.invalidNode')
  return null
}

interface WafOverviewState {
  draft: WafDraft
  applied: AnalyticsFilters
}

function WafOverview({ ownerKey, owner, state, onState, onViewLogs }: {
  ownerKey: string
  owner: WafOwner
  state: WafOverviewState
  onState: (next: WafOverviewState) => void
  onViewLogs: (seed: AnalyticsLogSeed) => void
}) {
  const { t, i18n } = useTranslation('wafLogs')
  const audience = owner[0] === 'platform' ? 'admin' : 'tenant'
  const { draft, applied } = state
  const [moreOpen, setMoreOpen] = useState(Boolean(draft.siteId || draft.nodeId))
  const [validationError, setValidationError] = useState<string | null>(null)
  useThemeRevision()
  const setDraft = (update: (current: WafDraft) => WafDraft) => onState({ draft: update(draft), applied })
  const query = useQuery({
    queryKey: ['waf-overview', ownerKey, applied],
    enabled: Boolean(currentToken(ownerKey)),
    queryFn: async () => {
      const token = currentToken(ownerKey)
      if (!token) throw new ApiError('Session changed', 403, 'analytics_scope_forbidden')
      const overview = await analyticsApi.wafOverview(token, audience, applied)
      if (!currentToken(ownerKey)) throw new ApiError('Session changed', 403, 'analytics_scope_forbidden')
      return overview
    },
    retry: false,
    refetchOnWindowFocus: false,
  })
  const apply = (draftToApply: WafDraft) => {
    // A quick range is relative: query it from the moment the user asks again.
    const nextDraft = draftToApply.preset === 'custom' ? draftToApply : { ...draftToApply, ...presetWindow(draftToApply.preset) }
    const message = validationMessage(nextDraft, t)
    setValidationError(message)
    if (message) {
      onState({ draft: nextDraft, applied })
      return
    }
    const next = filtersFromDraft(nextDraft, canonicalDomains(nextDraft.domain)!)
    if (JSON.stringify(next) === JSON.stringify(applied)) void query.refetch()
    onState({ draft: nextDraft, applied: next })
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    apply(draft)
  }
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const moreCount = [draft.siteId, draft.nodeId].filter((value) => value.trim()).length
  const data = query.data?.data
  const meta = query.data?.meta
  const share = (value: number) => data && data.attacks > 0 ? t('redesign.share', { value: formatPercent(value / data.attacks, language) }) : null
  // fix-waflogdetail: each hit count opens the details narrowed to its action
  // over the same window and filters ('' = every hit); unique clients do not.
  // fix-waflogdetail2: the four action cards add up to the attack total
  // (the server rejects counts that do not), each with its share.
  const metrics = data ? [
    ['attacks', t('metrics.attacks'), data.attacks, null, ''],
    ['blocked', t('metrics.blocked'), data.blocked, share(data.blocked), 'block'],
    ['challenged', t('metrics.challenged'), data.intercepted, share(data.intercepted), 'challenge'],
    ['observed', t('metrics.observed'), data.observed, share(data.observed), 'log'],
    ['autoBlocked', t('metrics.autoBlocked'), data.auto_blocked, share(data.auto_blocked), 'temporary_ban'],
    ['clients', t('metrics.clients'), data.clients, null, null],
  ] as const : []
  const seriesColors = new Map<string, string>(wafSeries().map(({ key, color }) => [key, color]))
  const view = (seed: AnalyticsLogSeed) => onViewLogs({
    from: applied.from, to: applied.to,
    ...(applied.domain ? { domain: applied.domain } : {}),
    ...(applied.siteId ? { siteId: applied.siteId } : {}),
    ...(applied.nodeId ? { nodeId: applied.nodeId } : {}),
    ...seed,
  })
  const rankings = data ? [
    [t('rankings.domains'), t('columns.domain'), data.top_domains, (key: string) => view({ domain: key }), undefined],
    [t('rankings.clients'), t('columns.client'), data.top_clients, (key: string) => view({ clientIp: key }), undefined],
    [t('rankings.uris'), t('columns.uri'), data.top_uris, undefined, undefined],
    [t('rankings.countries'), t('columns.country'), data.top_countries, undefined, (key: string) => countryLabel(key, language)],
    [t('rankings.provinces'), t('columns.province'), data.top_provinces, undefined, undefined],
    [t('rankings.carriers'), t('columns.carrier'), data.top_carriers, undefined, undefined],
  ] as const : []

  if (query.error instanceof ApiError && query.error.status === 403) {
    return <Result status="403" title={t('states.permissionTitle')} subTitle={t('states.permissionDescription')} />
  }

  return <div className="waf-v2-overview">
    <form className="waf-v2-filters" role="search" aria-label={t('redesign.filters')} onSubmit={submit}>
      <div className="waf-v2-filter-row">
        <div className="waf-v2-field waf-v2-range-field"><span>{t('filters.range')}</span>
          <TimeRangeFilter label={t('filters.range')} precision="hour" maxSpanMs={maximumWindow} allowClear={false}
            value={{ preset: draft.preset, range: [dayjs(draft.from), dayjs(draft.to)] }}
            onChange={({ preset, range }) => {
              if (!range) return
              setDraft((current) => ({ ...current, preset, from: hourStart(range[0]), to: hourStart(range[1]) }))
            }} />
        </div>
        <label className="waf-v2-field waf-v2-domain-field"><span>{t('filters.domain')}</span>
          <Input aria-label={t('filters.domain')} maxLength={4096} placeholder={t('filters.domainPlaceholder')} value={draft.domain}
            onChange={(event) => setDraft((current) => ({ ...current, domain: event.target.value }))} />
        </label>
        <div className="waf-v2-filter-actions">
          <Button type="primary" htmlType="submit" loading={query.isFetching}>{t('actions.query')}</Button>
          <Button onClick={() => { setMoreOpen(false); apply(initialDraft()) }}>{t('redesign.reset')}</Button>
          <Button type="link" aria-expanded={moreOpen} onClick={() => setMoreOpen((open) => !open)}
            icon={moreOpen ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}>
            {moreCount ? t('redesign.moreCount', { count: moreCount }) : t('redesign.more')}
          </Button>
        </div>
      </div>
      {moreOpen ? <div className="waf-v2-filter-row waf-v2-filter-more">
        <label className="waf-v2-field"><span>{t('filters.site')}</span><Input placeholder={t('filters.sitePlaceholder')} value={draft.siteId} onChange={(event) => setDraft((current) => ({ ...current, siteId: event.target.value }))} /></label>
        <label className="waf-v2-field"><span>{t('filters.node')}</span><Input placeholder={t('filters.nodePlaceholder')} value={draft.nodeId} onChange={(event) => setDraft((current) => ({ ...current, nodeId: event.target.value }))} /></label>
      </div> : null}
    </form>
    {validationError ? <Alert className="waf-overview-alert" type="error" showIcon message={validationError} /> : null}
    {query.error ? <FeedbackWhen title={t(errorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
    {query.isPending ? <div className="waf-overview-loading" aria-label={t('states.loading')}><Spin size="small" /></div> : null}
    {data ? <>
      <ul className="waf-v2-summary" aria-label={t('redesign.summary')}>
        {metrics.map(([key, label, value, note, action]) => {
          const color = seriesColors.get(key)
          const body = <>
            <span>{color ? <i aria-hidden="true" style={{ '--waf-series-color': color } as CSSProperties} /> : null}{label}</span>
            <strong>{formatNumber(value, language)}</strong>
            {note ? <small>{note}</small> : null}
          </>
          return <li className={`waf-v2-summary-item waf-v2-summary-item--${key}`} key={key}>
            {action === null ? body : <button type="button" className="waf-v2-summary-drill" aria-label={t('redesign.viewMetricLogs', { value: label })}
              onClick={() => view({ action })}>{body}</button>}
          </li>
        })}
      </ul>
      {meta ? <span className="visually-hidden">{t('evidence.snapshot', { from: formatDateTime(meta.from, language), to: formatDateTime(meta.to, language) })}</span> : null}
      <div className="waf-v2-insight">
        <div className="waf-v2-card waf-v2-trend"><TrendChart points={data.trend} language={language} /></div>
        <AttackTypePanel items={data.attack_types} language={language} />
      </div>
      <div className="waf-v2-rankings">
        {rankings.map(([title, valueLabel, items, onView, labelOf]) => <RankTable key={title} title={title} valueLabel={valueLabel} items={items} language={language} onView={onView} labelOf={labelOf} />)}
      </div>
    </> : null}
  </div>
}

export default function WafLogsPage() {
  const { t } = useTranslation('wafLogs')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? ownerFromPrincipal(principal, epoch) : null
  const [tab, setTab] = useState<'overview' | 'details'>('overview')
  const [seed, setSeed] = useState<AnalyticsLogSeed | undefined>()
  const [overview, setOverview] = useState<WafOverviewState>(() => {
    const draft = initialDraft()
    return { draft, applied: filtersFromDraft(draft, '') }
  })
  if (!accessToken || !principal || !owner) return <Result status="403" title={t('states.permissionTitle')} subTitle={t('states.permissionDescription')} />
  const ownerKey = JSON.stringify(owner)
  return <section className="analytics-page waf-logs-page waf-v2" aria-labelledby="waf-logs-title">
    <h1 className="visually-hidden" id="waf-logs-title">{t('title')}</h1>
    <div className="waf-logs-panel">
      <Tabs
        animated={false}
        className="waf-logs-tabs"
        activeKey={tab}
        onChange={(key) => setTab(key as 'overview' | 'details')}
        destroyOnHidden
        items={[
          {
            key: 'overview', label: t('tabs.overview'),
            children: <WafOverview ownerKey={ownerKey} owner={owner} state={overview} onState={setOverview}
              onViewLogs={(next) => { setSeed(next); setTab('details') }} />,
          },
          { key: 'details', label: t('tabs.details'), children: <AnalyticsLogPage kind="block" embedded layout="waf" seed={seed} eventType="waf" /> },
        ]}
      />
    </div>
  </section>
}
