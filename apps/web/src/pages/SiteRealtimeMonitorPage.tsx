import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Result, Spin, Table, Tabs } from 'antd'
import dayjs from 'dayjs'
import { Search } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  siteRealtimeApi,
  type SiteRealtimeAudience,
  type SiteRealtimeFilters,
  type SiteRealtimeMetrics,
  type SiteRealtimePoint,
  type SiteRealtimeTopItem,
} from '../api/siteRealtime'
import { useSessionStore } from '../auth/session'
import SiteQualityDiagnostics from '../components/SiteQualityDiagnostics'
import '../i18n/siteRealtime'
import { businessTimeZone, formatDateTime, formatNumber } from '../i18n/formatters'
import { formatAnalyticsBandwidth, formatAnalyticsBytes } from '../i18n/analyticsUnits'
import '../styles/analyticsControlParity.css'
import './SiteRealtimeMonitorPage.css'
import { FeedbackWhen, TimeRangeFilter, type TimeRangePreset } from '@cdnca/ui'

const hourMilliseconds = 60 * 60 * 1000
const maximumWindowMilliseconds = 31 * 24 * hourMilliseconds
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const hostPattern = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const nilUuid = '00000000-0000-0000-0000-000000000000'

// TimeRangeFilter preset key or 'custom'.
type RealtimeRange = string
// Quick ranges (today / last 7 days / last 30 days / custom); the backend accepts up to 31 days.
const presetKeys = ['today', 'last7d', 'last30d'] as const
type RealtimeOwner = readonly [SiteRealtimeAudience, Principal['scope_kind'], string, string | null, string, number]

interface DraftFilters {
  tenantId: string
  siteId: string
  host: string
  listenPort: string
  from: string
  to: string
}

// Quick ranges end at the next whole minute so the current minute is shown.
function currentMinute(): Date {
  return new Date(Math.ceil(Date.now() / 60_000) * 60_000)
}

function localDateTimeValue(value: Date): string {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: businessTimeZone, year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(value)
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((item) => item.type === type)!.value
  return `${part('year')}-${part('month')}-${part('day')}T${part('hour')}:${part('minute')}`
}

// A quick range in business-time wall clock: today starts at the business day's 00:00, the others count back whole days.
function preset(key: string): Pick<DraftFilters, 'from' | 'to'> | null {
  const to = currentMinute()
  const end = localDateTimeValue(to)
  if (key === 'today') return { from: `${end.slice(0, 10)}T00:00`, to: end }
  const days = key === 'last7d' ? 7 : key === 'last30d' ? 30 : null
  return days === null ? null : { from: localDateTimeValue(new Date(to.getTime() - days * 24 * hourMilliseconds)), to: end }
}

function parseLocalHour(value: string): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return null
  const parsed = new Date(`${value}:00+08:00`)
  return Number.isFinite(parsed.getTime()) && localDateTimeValue(parsed) === value ? parsed : null
}

function validUuid(value: string): boolean {
  return uuidPattern.test(value) && value.toLowerCase() !== nilUuid
}

function ownerFromPrincipal(principal: Principal, sessionEpoch: number): RealtimeOwner | null {
  const { scope_kind: scopeKind, scope_id: scopeId, tenant_id: tenantId, user_id: userId } = principal
  const canRead = principal.permissions.includes('sites.read') ||
    (scopeKind === 'platform' && principal.permissions.includes('platform.admin'))
  if (!scopeId?.trim() || !userId?.trim() || sessionEpoch < 1 || !canRead) return null
  if (scopeKind === 'tenant' && !tenantId) return null
  if (scopeKind === 'platform' && tenantId !== null) return null
  return [scopeKind === 'platform' ? 'admin' : 'tenant', scopeKind, scopeId, tenantId ?? null, userId, sessionEpoch]
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = ownerFromPrincipal(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function canonicalHosts(value: string): string | null {
  const hosts = value.trim().split(/\s+/).filter(Boolean)
  if (hosts.length === 0) return ''
  if (hosts.length > 64 || hosts.some((host) => !hostPattern.test(host) || host !== host.toLowerCase())) return null
  return [...new Set(hosts)].join(' ')
}

function validateDraft(draft: DraftFilters, audience: SiteRealtimeAudience, t: TFunction<'siteRealtime'>): string | null {
  const ids = audience === 'admin' ? [draft.tenantId, draft.siteId] : [draft.siteId]
  if (ids.some((value) => value.trim() !== '' && !validUuid(value.trim()))) return t('filters.invalidUuid')
  if (canonicalHosts(draft.host) === null) {
    return t('filters.invalidHost')
  }
  if (draft.listenPort.trim() !== '') {
    const port = Number(draft.listenPort)
    if (!Number.isInteger(port) || port < 1 || port > 65535) return t('filters.invalidPort')
  }
  const from = parseLocalHour(draft.from)
  const to = parseLocalHour(draft.to)
  if (!from || !to || from >= to) return t('filters.invalidWindow')
  if (to.getTime() - from.getTime() > maximumWindowMilliseconds) return t('filters.rangeTooLong')
  return null
}

function filtersFromDraft(draft: DraftFilters, audience: SiteRealtimeAudience): SiteRealtimeFilters {
  const filters: SiteRealtimeFilters = {
    from: parseLocalHour(draft.from)!.toISOString(),
    to: parseLocalHour(draft.to)!.toISOString(),
  }
  if (audience === 'admin' && draft.tenantId.trim()) filters.tenantId = draft.tenantId.trim().toLowerCase()
  if (draft.siteId.trim()) filters.siteId = draft.siteId.trim().toLowerCase()
  const hosts = canonicalHosts(draft.host)
  if (hosts) filters.host = hosts
  if (draft.listenPort.trim()) filters.listenPort = Number(draft.listenPort)
  return filters
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.requestFailed'
  if (error.code === 'analytics_realtime_evidence_unavailable' || error.status === 503) return 'states.unavailable'
  if (error.code === 'analytics_query_timeout' || error.status === 504) return 'states.timeout'
  if (error.code === 'invalid_response' || error.code === 'analytics_storage_invalid_response' || error.status === 502) return 'states.invalidResponse'
  if (error.status === 400) return 'states.invalidRequest'
  return 'states.requestFailed'
}

type RealtimeChartValue = number | null

type RealtimeChartProps = {
  title: string
  points: Array<{ bucket: string; value: RealtimeChartValue }>
  emptyBucket: string
  minimumMaximum: number
  language: string
  formatter: (value: number, language: string) => string
  minimumFormatter?: (value: number, language: string) => string
  emptyLabel: string
  unavailableLabel?: string
}

function fixedAxisUnit(value: number, language: string, divisor: number, unit: string): string {
  const locale = language === 'en-US' ? 'en-US' : 'zh-CN'
  const number = new Intl.NumberFormat(locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value / divisor)
  return `${number} ${unit}`
}

function RealtimeChart({ title, points, emptyBucket, minimumMaximum, language, formatter, minimumFormatter, emptyLabel, unavailableLabel }: RealtimeChartProps) {
  const { t } = useTranslation('siteRealtime')
  const canvasRef = useRef<HTMLDivElement>(null)
  const tooltipId = useId()
  const [activeIndex, setActiveIndex] = useState<number | null>(null)
  const [{ width, height }, setSize] = useState({ width: 640, height: 292 })
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const observer = new ResizeObserver(([entry]) => {
      if (entry.contentRect.width > 0 && entry.contentRect.height > 0) {
        setSize({ width: entry.contentRect.width, height: entry.contentRect.height })
      }
    })
    observer.observe(canvas)
    return () => observer.disconnect()
  }, [])
  const plot = { left: 78, right: 6, top: 12, bottom: 42 }
  const plotWidth = width - plot.left - plot.right
  const plotHeight = height - plot.top - plot.bottom
  // Preserve the observed competitor baseline while the API reports an
  // unavailable window. A real series containing only nulls remains visibly
  // unavailable and is never replaced with invented zeros.
  const displayPoints = points.length > 0 ? points : [{ bucket: emptyBucket, value: 0 }]
  const values = displayPoints.flatMap((point) => point.value === null ? [] : [point.value])
  const maximum = values.length > 0 ? Math.max(...values, 0) : 0
  const usesMinimumScale = maximum <= minimumMaximum
  const scaleMaximum = usesMinimumScale ? minimumMaximum : maximum
  const axisFormatter = usesMinimumScale ? minimumFormatter ?? formatter : formatter
  const firstTime = Date.parse(displayPoints[0]?.bucket ?? emptyBucket)
  const lastTime = Date.parse(displayPoints.at(-1)?.bucket ?? emptyBucket)
  const timeX = (time: number) => plot.left + ((time - firstTime) / (lastTime - firstTime)) * plotWidth
  const x = (index: number) => displayPoints.length <= 1
    ? plot.left + plotWidth / 2
    : timeX(Date.parse(displayPoints[index].bucket))
  const y = (value: number) => plot.top + plotHeight - (value / scaleMaximum) * plotHeight
  const linePoints = displayPoints.map((point, index) => point.value === null ? ''
    : `${index === 0 || displayPoints[index - 1].value === null ? 'M' : 'L'}${x(index)},${y(point.value)}`).join(' ')
  const tickIndices = displayPoints.length > 1 ? [0, displayPoints.length - 1] : [0]
  const timeLabel = new Intl.DateTimeFormat(language === 'en-US' ? 'en-US' : 'zh-CN', {
    timeZone: businessTimeZone, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  })
  const gridFractions = [0, 0.2, 0.4, 0.6, 0.8, 1]
  const active = activeIndex === null ? undefined : displayPoints[activeIndex]
  const noValueLabel = unavailableLabel ?? emptyLabel

  return (
    <section className="analytics-realtime-chart" aria-label={title}>
      <h2>{title}</h2>
      <div ref={canvasRef} className="analytics-realtime-chart-canvas">
        <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={title}
          tabIndex={points.length ? 0 : undefined} aria-describedby={active ? tooltipId : undefined}
          onFocus={() => setActiveIndex(points.length ? 0 : null)} onBlur={() => setActiveIndex(null)}
          onMouseLeave={() => setActiveIndex(null)}
          onMouseMove={(event) => {
            if (!points.length) return
            const bounds = event.currentTarget.getBoundingClientRect()
            if (!bounds.width) return
            const position = (event.clientX - bounds.left) * width / bounds.width
            const nearest = points.reduce((best, _, index) => Math.abs(x(index) - position) < Math.abs(x(best) - position) ? index : best, 0)
            setActiveIndex(nearest)
          }}
          onKeyDown={(event) => {
            if (event.key === 'Escape') setActiveIndex(null)
            else if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key) && points.length) {
              event.preventDefault()
              setActiveIndex(event.key === 'Home' ? 0 : event.key === 'End' ? points.length - 1
                : Math.max(0, Math.min(points.length - 1, (activeIndex ?? 0) + (event.key === 'ArrowRight' ? 1 : -1))))
            }
          }}>
          <desc>{t('charts.keyboardHint')}</desc>
          {gridFractions.map((fraction) => {
            const gridY = plot.top + plotHeight - fraction * plotHeight
            return (
              <g key={fraction}>
                <line x1={plot.left} x2={width - plot.right} y1={gridY} y2={gridY} className="analytics-realtime-grid-line" />
                <text x={plot.left - 10} y={gridY + 4} textAnchor="end" className="analytics-realtime-axis-label">
                  {axisFormatter(scaleMaximum * fraction, language)}
                </text>
              </g>
            )
          })}
          <line x1={plot.left} x2={width - plot.right} y1={plot.top + plotHeight} y2={plot.top + plotHeight} className="analytics-realtime-axis-line" />
          {displayPoints.length > 1 && values.length > 0 ? <path d={linePoints} className="analytics-realtime-series" /> : null}
          {displayPoints.map((point, index) => point.value === null ? null : <circle key={point.bucket} cx={x(index)} cy={y(point.value)} r="3" className="analytics-realtime-series-dot" />)}
          {active && activeIndex !== null ? <line x1={x(activeIndex)} x2={x(activeIndex)} y1={plot.top} y2={plot.top + plotHeight} className="analytics-realtime-hover-line" /> : null}
          {active && active.value !== null && activeIndex !== null ? <circle cx={x(activeIndex)} cy={y(active.value)} r="4" className="analytics-realtime-series-dot" /> : null}
          {tickIndices.map((index) => <text key={index} x={x(index)} y={height - 20}
            textAnchor={tickIndices.length === 1 ? 'middle' : index === 0 ? 'start' : 'end'} className="analytics-realtime-axis-label analytics-realtime-x-label">
            {timeLabel.format(new Date(displayPoints[index]?.bucket ?? emptyBucket))}
          </text>)}
        </svg>
        {points.length > 0 && values.length === 0 ? <span className="analytics-realtime-no-data">{noValueLabel}</span> : null}
        {active ? <div role="tooltip" id={tooltipId} className="analytics-realtime-tooltip">
          <span>{formatDateTime(active.bucket, language)}</span>
          <strong>{t('charts.tooltipValue', { metric: title, value: active.value === null ? noValueLabel : formatter(active.value, language) })}</strong>
        </div> : null}
      </div>
    </section>
  )
}

function metricPoints(series: SiteRealtimePoint[], key: keyof Pick<SiteRealtimePoint, 'bandwidth_bps' | 'traffic_bytes' | 'requests'>): Array<{ bucket: string; value: number }> {
  return series.map((point) => ({ bucket: point.bucket, value: point[key] }))
}

function qpsPoints(series: SiteRealtimePoint[], bucketSeconds: number, to: string): Array<{ bucket: string; value: number }> {
  return series.map((point) => ({ bucket: point.bucket,
    value: point.requests / Math.max(1, Math.min(bucketSeconds, (Date.parse(to) - Date.parse(point.bucket)) / 1000)),
  }))
}

function MetricStrip({ metrics, language }: { metrics: SiteRealtimeMetrics; language: string }) {
  const { t } = useTranslation('siteRealtime')
  const values = [
    [t('metrics.requests'), formatNumber(metrics.requests, language)],
    [t('metrics.traffic'), formatAnalyticsBytes(metrics.traffic_bytes, language)],
    [t('metrics.bandwidth'), formatAnalyticsBandwidth(metrics.bandwidth_bps, language)],
    [t('metrics.connections'), formatNumber(metrics.connections, language)],
  ]
  return <div className="analytics-summary">{values.map(([label, value]) => (
    <div className="analytics-summary-item" key={label}><span>{label}</span><strong className="analytics-summary-value">{value}</strong></div>
  ))}</div>
}

type RealtimeTab = 'basic' | 'quality' | 'origin'

const realtimeRefreshMs = 10_000

function SiteRealtimeContent({ owner, ownerKey }: { owner: RealtimeOwner; ownerKey: string }) {
  const { t, i18n } = useTranslation('siteRealtime')
  const audience = owner[0]
  const initial = useMemo(() => preset('today')!, [])
  const [range, setRange] = useState<RealtimeRange>('today')
  const [activeTab, setActiveTab] = useState<RealtimeTab>('basic')
  const [draft, setDraft] = useState<DraftFilters>({ tenantId: '', siteId: '', host: '', listenPort: '', ...initial })
  const [applied, setApplied] = useState<SiteRealtimeFilters>(() => filtersFromDraft({ tenantId: '', siteId: '', host: '', listenPort: '', ...initial }, audience))
  const [validationError, setValidationError] = useState<string | null>(null)
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)

  const query = useQuery({
    queryKey: ['site-realtime', owner, applied],
    queryFn: async ({ signal }) => {
      const token = currentAccess(ownerKey)
      if (!token) throw new ApiError('Session changed', 403, 'analytics_scope_forbidden')
      const response = await siteRealtimeApi.read(token, audience, applied, signal)
      if (!currentAccess(ownerKey)) throw new ApiError('Session changed', 403, 'analytics_scope_forbidden')
      return response
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    // 实时页每 10 秒自动刷新（页面隐藏时 TanStack Query 默认暂停，refetchIntervalInBackground 为 false）。
    // 快捷范围每次刷新都把窗口滚到当前分钟；自定义范围固定不动，只刷新数据。
    refetchInterval: realtimeRefreshMs,
    // 快捷范围滚到下一分钟会换 queryKey：只在同一主体、同一筛选、仅时间窗口变化时保留上一份数据，不闪成加载态。
    placeholderData: (previous, previousQuery) => {
      const [, previousOwner, previousFilters] = (previousQuery?.queryKey ?? []) as [string, RealtimeOwner, SiteRealtimeFilters]
      if (!previous || !previousFilters || JSON.stringify(previousOwner) !== JSON.stringify(owner)) return undefined
      const sameScope = JSON.stringify({ ...previousFilters, from: '', to: '' }) === JSON.stringify({ ...applied, from: '', to: '' })
      return sameScope ? previous : undefined
    },
  })
  const rollingPreset = preset(range) ? range : null
  useEffect(() => {
    if (rollingPreset === null) return
    const timer = window.setInterval(() => {
      if (document.visibilityState !== 'visible') return
      const window = preset(rollingPreset)!
      const from = parseLocalHour(window.from)!.toISOString()
      const to = parseLocalHour(window.to)!.toISOString()
      setApplied((current) => from === current.from && to === current.to ? current : { ...current, from, to })
    }, realtimeRefreshMs)
    return () => window.clearInterval(timer)
  }, [rollingPreset])

  // Quick ranges end at the current minute in the business time zone (preset()); the picker shows those wall-clock values.
  const rangePresets: TimeRangePreset[] = presetKeys.map((key) => ({
    key, range: () => { const window = preset(key)!; return [dayjs(window.from), dayjs(window.to)] },
  }))
  const applyRange = (value: RealtimeRange, from: string, to: string) => {
    setRange(value)
    setDraft((current) => ({ ...current, from, to }))
    setValidationError(null)
  }
  const apply = () => {
    const window = preset(range)
    const nextDraft = window === null ? draft : { ...draft, ...window }
    if (window !== null) setDraft(nextDraft)
    const error = validateDraft(nextDraft, audience, t)
    setValidationError(error)
    if (error) return
    const next = filtersFromDraft(nextDraft, audience)
    if (JSON.stringify(next) === JSON.stringify(applied)) void query.refetch()
    else setApplied(next)
  }

  if (query.error instanceof ApiError && query.error.status === 403) {
    return <Result className="analytics-page analytics-page-error" status="403" title={t('states.permissionTitle')} subTitle={t('states.permissionDescription')} />
  }

  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const data = query.data?.data
  const series = data?.series ?? []
  const filterBar = <div className="analytics-filter-bar analytics-realtime-filter-bar">
    <div className="analytics-realtime-primary-fields">
      <Input aria-label={t('filters.host')} placeholder={t('filters.hostPlaceholder')} value={draft.host} onChange={(event) => setDraft((current) => ({ ...current, host: event.target.value }))} />
      <Input aria-label={t('filters.port')} placeholder={t('filters.portPlaceholder')} inputMode="numeric" value={draft.listenPort} onChange={(event) => setDraft((current) => ({ ...current, listenPort: event.target.value }))} />
      <TimeRangeFilter label={t('filters.range')} presets={rangePresets} maxSpanMs={maximumWindowMilliseconds}
        value={{ preset: range, range: draft.from && draft.to ? [dayjs(draft.from), dayjs(draft.to)] : null }}
        onChange={({ preset: key, range: window }) => applyRange(key, window?.[0].format('YYYY-MM-DDTHH:mm') ?? '', window?.[1].format('YYYY-MM-DDTHH:mm') ?? '')} />
      <Button type="primary" icon={<Search size={15} />} loading={query.isFetching} onClick={apply}>{t('actions.query')}</Button>
    </div>
  </div>
  const tabs = [
    { key: 'basic', label: t('tabs.basic') },
    { key: 'quality', label: t('tabs.quality') },
    { key: 'origin', label: t('tabs.origin') },
  ]
  const errorContent = query.error && !(query.error instanceof ApiError && query.error.status === 403)
    ? <FeedbackWhen title={t(errorKey(query.error))} />
    : null
  const basicContent = (
    <>
      <div className="analytics-realtime-chart-grid">
        <RealtimeChart title={t('charts.bandwidth')} points={metricPoints(series, 'bandwidth_bps')} emptyBucket={applied.to} minimumMaximum={10} language={language} formatter={formatAnalyticsBandwidth} minimumFormatter={(value, locale) => fixedAxisUnit(value, locale, 1000, 'Kbps')} emptyLabel={t('states.empty')} />
        <RealtimeChart title={t('charts.traffic')} points={metricPoints(series, 'traffic_bytes')} emptyBucket={applied.to} minimumMaximum={1} language={language} formatter={formatAnalyticsBytes} minimumFormatter={(value, locale) => fixedAxisUnit(value, locale, 1024, 'KB')} emptyLabel={t('states.empty')} />
        <RealtimeChart title={t('charts.requests')} points={metricPoints(series, 'requests')} emptyBucket={applied.to} minimumMaximum={1} language={language} formatter={formatNumber} emptyLabel={t('states.empty')} />
        <RealtimeChart title={t('charts.qps')} points={qpsPoints(series, data?.series_bucket_seconds ?? 60, applied.to)} emptyBucket={applied.to} minimumMaximum={1} language={language} formatter={formatNumber} emptyLabel={t('states.empty')} />
      </div>
      {data ? <>
        <MetricStrip metrics={data.summary} language={language} />
        {/* Live data (query_version=4) carries no settlement claim; only the snapshot time is meaningful. */}
        <div className="analytics-meta" aria-label={t('evidence.title')}>
          <span className="analytics-meta-item">{t('evidence.snapshot', { time: formatDateTime(data.evidence.snapshot_at, language) })}</span>
          <span className="analytics-meta-item" data-testid="site-realtime-updated">{t('evidence.updated', { time: formatDateTime(new Date(query.dataUpdatedAt).toISOString(), language) })}</span>
        </div>
        <section className="analytics-realtime-ranking" aria-label={t('charts.ranking')}>
          <h2>{t('charts.ranking')}</h2>
          <Table<SiteRealtimeTopItem>
            size="small"
            rowKey={(item) => `${item.host}:${item.listen_port}`}
            columns={[
              { title: t('columns.hostPort'), key: 'host', render: (_: unknown, item: SiteRealtimeTopItem) => `${item.host}:${item.listen_port}` },
              { title: t('columns.requests'), dataIndex: 'requests', key: 'requests', align: 'right' as const, render: (value: number) => formatNumber(value, language) },
              { title: t('columns.traffic'), dataIndex: 'traffic_bytes', key: 'traffic', align: 'right' as const, render: (value: number) => formatAnalyticsBytes(value, language) },
            ]}
            dataSource={data.top}
            pagination={false}
            scroll={{ x: 560 }}
            locale={{ emptyText: t('states.empty') }}
          />
        </section>
      </> : null}
    </>
  )
  const chartProps = { emptyBucket: applied.to, minimumMaximum: 1, language, emptyLabel: t('states.empty') }
  const qualityContent = <div className="analytics-realtime-chart-grid">
    <RealtimeChart {...chartProps} title={t('charts.requestHitRatio')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.requests ? point.cache_hits / point.requests * 100 : null }))}
      formatter={(value, locale) => `${formatNumber(value, locale)} %`} />
    <RealtimeChart {...chartProps} title={t('charts.byteHitRatio')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.traffic_bytes ? point.cache_hit_bytes / point.traffic_bytes * 100 : null }))}
      formatter={(value, locale) => `${formatNumber(value, locale)} %`} />
    <RealtimeChart {...chartProps} title={t('charts.status4xx')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.status_4xx }))}
      formatter={(value, locale) => t('charts.countValue', { value: formatNumber(value, locale) })} />
    <RealtimeChart {...chartProps} title={t('charts.status5xx')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.status_5xx }))}
      formatter={(value, locale) => t('charts.countValue', { value: formatNumber(value, locale) })} />
  </div>
  const originContent = <div className="analytics-realtime-chart-grid">
    <RealtimeChart {...chartProps} title={t('charts.originBandwidth')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.origin_bandwidth_bps }))}
      minimumMaximum={10} formatter={formatAnalyticsBandwidth} minimumFormatter={(value, locale) => fixedAxisUnit(value, locale, 1000, 'Kbps')}
      unavailableLabel={t('states.originBytesUnavailable')} />
    <RealtimeChart {...chartProps} title={t('charts.originTraffic')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.origin_traffic_bytes }))}
      formatter={formatAnalyticsBytes} minimumFormatter={(value, locale) => fixedAxisUnit(value, locale, 1024, 'KB')}
      unavailableLabel={t('states.originBytesUnavailable')} />
    <RealtimeChart {...chartProps} title={t('charts.originDuration')}
      points={series.map((point) => ({ bucket: point.bucket, value: point.origin_total_us === null ? null : point.origin_total_us / 1_000_000 }))}
      formatter={(value, locale) => t('charts.secondsValue', { value: new Intl.NumberFormat(locale === 'en-US' ? 'en-US' : 'zh-CN', { maximumFractionDigits: 6 }).format(value) })}
      unavailableLabel={t('states.noOriginSamples')} />
  </div>

  return (
    <section className="analytics-page analytics-realtime-page" aria-labelledby="site-realtime-title">
      <h1 className="visually-hidden" id="site-realtime-title">{t('title')}</h1>
      <div className="analytics-panel">
        <Tabs
          className="analytics-tabs analytics-realtime-tabs"
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key as RealtimeTab)}
          items={tabs.map((tab) => ({ key: tab.key, label: tab.label }))}
        />
        {filterBar}
        {range === 'custom' ? <p className="analytics-realtime-range-hint">{t('filters.minuteHint')}</p> : null}
        {validationError ? <Alert className="analytics-filter-error" type="error" showIcon message={validationError} /> : null}
        {errorContent}
        {query.isPending ? <div className="analytics-chart-state" aria-label={t('states.loading')}><Spin size="small" /></div> : null}
        <div key={`${activeTab}:${JSON.stringify(applied)}`}>{activeTab === 'basic' ? basicContent : activeTab === 'quality' ? qualityContent : originContent}</div>
        {activeTab === 'quality' && data && (audience === 'tenant' || applied.tenantId) ? <details className="analytics-realtime-diagnostics" open={diagnosticsOpen}
          onToggle={(event) => setDiagnosticsOpen(event.currentTarget.open)}>
          <summary>{t('charts.advancedDiagnostics')}</summary>
          {diagnosticsOpen ? <SiteQualityDiagnostics key={JSON.stringify(applied)} accessToken={currentAccess(ownerKey) ?? ''} audience={audience} filters={{ from: applied.from, to: applied.to, tenantId: applied.tenantId, siteId: applied.siteId }} /> : null}
        </details> : null}
      </div>
    </section>
  )
}

export default function SiteRealtimeMonitorPage() {
  const { t } = useTranslation('siteRealtime')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(() => principal ? ownerFromPrincipal(principal, sessionEpoch) : null, [principal, sessionEpoch])
  if (!accessToken || !principal || !owner) {
    return <Result className="analytics-page analytics-page-error" status="403" title={t('states.permissionTitle')} subTitle={t('states.permissionDescription')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <SiteRealtimeContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}
