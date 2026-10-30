import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Input, Table, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, Filter, RotateCcw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  formatDashboardBytes,
  formatDashboardInteger,
  type DashboardAnalyticsOverview,
  type DashboardFilters,
  type DashboardRankItem,
  type NetworkStats,
} from '../api/dashboard'
import { rankAddressLabel } from '../pages/analyticsRankLabels'
import { businessTimeZone, formatNumber } from '../i18n/formatters'
import { formatAnalyticsBandwidth, formatAnalyticsBytes } from '../i18n/analyticsUnits'
import '../i18n/dashboardOverview'
import { useChartTheme } from './useChartTheme'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function DashboardDrilldown({ value, onApply }: {
  value: DashboardFilters
  onApply: (filters: DashboardFilters) => void
}) {
  const { t } = useTranslation('dashboardOverview')
  const [draft, setDraft] = useState(value)
  const [invalid, setInvalid] = useState(false)

  const apply = () => {
    const next = { siteId: draft.siteId?.trim() || undefined, nodeId: draft.nodeId?.trim() || undefined }
    if (next.siteId && !uuidPattern.test(next.siteId) || next.nodeId && !uuidPattern.test(next.nodeId)) {
      setInvalid(true)
      return
    }
    setInvalid(false)
    onApply(next)
  }

  const clear = () => {
    setDraft({})
    setInvalid(false)
    onApply({})
  }

  return (
    <div className="analytics-filter-bar dashboard-drilldown">
      <label className="analytics-filter-field">
        <span>{t('filters.site')}</span>
        <Input value={draft.siteId ?? ''} placeholder={t('filters.sitePlaceholder')}
          onChange={(event) => setDraft((current) => ({ ...current, siteId: event.target.value }))} />
      </label>
      <label className="analytics-filter-field">
        <span>{t('filters.node')}</span>
        <Input value={draft.nodeId ?? ''} placeholder={t('filters.nodePlaceholder')}
          onChange={(event) => setDraft((current) => ({ ...current, nodeId: event.target.value }))} />
      </label>
      <Button type="primary" icon={<Filter size={15} />} onClick={apply}>{t('actions.apply')}</Button>
      <Button icon={<RotateCcw size={15} />} onClick={clear}>{t('actions.clear')}</Button>
      {invalid ? <Alert className="analytics-filter-error" type="error" showIcon message={t('filters.invalid')} /> : null}
    </div>
  )
}

type TrendMetric = 'bandwidth' | 'requests' | 'traffic' | 'blocked'

function isAuthoritativeEmptyAnalytics(analytics: DashboardAnalyticsOverview): boolean {
  const summary = analytics.summary
  const summaryIsEmpty = [
    summary.request_count,
    summary.request_bytes,
    summary.response_bytes,
    summary.total_bytes,
    summary.status_2xx,
    summary.status_3xx,
    summary.status_4xx,
    summary.status_5xx,
    summary.security_events,
  ].every((value) => value === '0') && summary.average_bandwidth_bps === 0
  const ranksAreEmpty = analytics.top.every((snapshot) => snapshot.items.length === 0) &&
    (analytics.top_extended === undefined || analytics.top_extended.every((snapshot) => snapshot.items.length === 0))
  return summaryIsEmpty && analytics.trend.length === 0 && ranksAreEmpty
}

function BandwidthTrend({ analytics, locale, metric = 'bandwidth' }: { analytics: DashboardAnalyticsOverview; locale: string; metric?: TrendMetric }) {
  const { t } = useTranslation('dashboardOverview')
  const theme = useChartTheme()
  const containerRef = useRef<HTMLElement>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    setFailed(false)
    if ((import.meta.env.MODE === 'test' && analytics.trend.length === 0) || containerRef.current === null) return
    let disposed = false
    let chart: import('./echartsRuntime').ECharts | undefined
    let observer: ResizeObserver | undefined
    void import('./echartsRuntime').then((echarts) => {
      if (disposed || containerRef.current === null) return
      chart = echarts.init(containerRef.current)
      observer = new ResizeObserver(() => chart?.resize())
      observer.observe(containerRef.current)
      const value = (point: DashboardAnalyticsOverview['trend'][number]): number | null => {
        if (metric === 'requests') return Number(point.request_count)
        if (metric === 'traffic') return Number(point.total_bytes)
        if (metric === 'blocked') return point.blocked_ip_count === undefined ? null : Number(point.blocked_ip_count)
        return point.average_bandwidth_bps
      }
      const formatValue = (raw: unknown): string => {
        const numeric = Number(raw)
        if (raw === null || raw === undefined || !Number.isFinite(numeric)) return t('values.placeholder')
        return metric === 'bandwidth'
          ? formatAnalyticsBandwidth(numeric, locale)
          : metric === 'requests' ? formatDashboardInteger(String(Math.max(0, Math.trunc(numeric))), locale)
            : metric === 'traffic' ? numeric < 1024 ? formatAnalyticsBytes(numeric, locale) : formatDashboardBytes(String(Math.max(0, Math.trunc(numeric))), locale)
              : formatDashboardInteger(String(Math.max(0, Math.trunc(numeric))), locale)
      }
      const timeLabel = new Intl.DateTimeFormat(locale === 'en-US' ? 'en-US' : 'zh-CN', {
        timeZone: businessTimeZone, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
      })
      chart.setOption({
        grid: { top: '50px', left: '20px', bottom: '10px', containLabel: true },
        tooltip: {
          trigger: 'axis',
          backgroundColor: theme.surface,
          borderColor: theme.border,
          textStyle: { color: theme.text },
          axisPointer: { lineStyle: { color: theme.border } },
          valueFormatter: (raw: unknown) => formatValue(Number(raw)),
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: analytics.trend.map((point) => {
            const date = new Date(point.hour)
            return Number.isNaN(date.getTime()) ? t('values.placeholder') : timeLabel.format(date)
          }),
          axisLine: { lineStyle: { color: theme.border } },
          axisTick: { lineStyle: { color: theme.border } },
          axisLabel: { color: theme.muted },
        },
        yAxis: {
          type: 'value',
          splitLine: { lineStyle: { color: theme.border } },
          axisLine: { lineStyle: { color: theme.border } },
          axisLabel: { color: theme.muted, formatter: (raw: number) => formatValue(raw) },
        },
        series: [{
          type: 'line',
          data: analytics.trend.map(value),
          smooth: true,
          showSymbol: true,
          // Keep every sample node visible; ECharts' automatic symbol
          // culling otherwise hides dense series.
          showAllSymbol: true,
          symbolSize: 6,
          lineStyle: { color: theme.primary },
          // Use a white-centre, coloured-ring emptyCircle line symbol.
          symbol: 'emptyCircle',
          itemStyle: { color: theme.primary, borderColor: theme.primary, borderWidth: 2 },
          areaStyle: { color: theme.area },
        }],
        graphic: analytics.trend.length === 0 ? {
          type: 'text',
          left: 'center',
          top: 'center',
          style: { text: t('charts.empty'), fontSize: 14, fill: theme.muted },
        } : null,
      })
    }).catch(() => setFailed(true))
    const resize = () => chart?.resize()
    window.addEventListener('resize', resize)
    return () => {
      disposed = true
      window.removeEventListener('resize', resize)
      observer?.disconnect()
      chart?.dispose()
    }
  }, [analytics, locale, metric, t, theme])

  if (failed) return <div className="analytics-chart-state" role="alert">{t('charts.unavailable')}</div>
  return (
    <>
      <section ref={containerRef} className="analytics-trend-chart" aria-label={t(`charts.${metric}`)} />
      {analytics.trend.length === 0 ? <span className="visually-hidden">{t('charts.empty')}</span> : null}
    </>
  )
}

/** 结算水位落后时只提示，不拦截展示。 */
export function AnalyticsSettlingHint({ minutes }: { minutes?: number }) {
  const { t } = useTranslation('dashboardOverview')
  if (!minutes) return null
  return <div className="dashboard-analytics-settling" role="note">{t('settling', { count: minutes })}</div>
}

export function DashboardAnalyticsView({ analytics, locale, variant = 'default', mode = 'both' }: {
  analytics: DashboardAnalyticsOverview
  locale: string
  variant?: 'default' | 'admin'
  mode?: 'both' | 'trend' | 'rankings'
}) {
  const { t } = useTranslation('dashboardOverview')
  const displayMode = mode
  const [trendMetric, setTrendMetric] = useState<TrendMetric>('bandwidth')
  const rankTabViewportRef = useRef<HTMLDivElement>(null)
  const [rankTabsOverflow, setRankTabsOverflow] = useState(false)
  useEffect(() => {
    const viewport = rankTabViewportRef.current
    if (!viewport) return
    const update = () => setRankTabsOverflow(viewport.scrollWidth > (viewport.parentElement?.clientWidth ?? viewport.clientWidth) + 1)
    const observer = new ResizeObserver(update)
    observer.observe(viewport)
    if (viewport.parentElement) observer.observe(viewport.parentElement)
    update()
    return () => observer.disconnect()
  }, [variant, displayMode, locale])
  const rankSource = variant === 'admin' && analytics.top_extended ? analytics.top_extended : analytics.top
  const [selectedDimension, setSelectedDimension] = useState<NonNullable<DashboardAnalyticsOverview['top_extended']>[number]['dimension']>('domain')
  // Domain / URL rows show their address (host:port, scheme://host:port/path)
  // like the analytics page; other dimensions show the key.
  const columnsFor = (dimension: string): TableColumnsType<DashboardRankItem> => [
    // 首列按当前维度命名（域名/URL/IP/国家），与上方页签一致。
    { title: ({ domain: t('top.domain'), url: t('top.url'), ip: t('top.ip'), region: variant === 'admin' ? t('top.country') : t('top.region'), carrier: t('top.carrier') } as Record<string, string>)[dimension] ?? t('top.key'),
      dataIndex: 'key', key: 'key', ellipsis: true,
      render: (value: string, item) => rankAddressLabel(dimension, item) ?? value },
    { title: t('top.requests'), dataIndex: 'request_count', key: 'request_count', width: 80,
      render: (value: string) => formatDashboardInteger(value, locale) },
    { title: t('top.traffic'), dataIndex: 'response_bytes', key: 'response_bytes', width: 100,
      render: (value: string) => BigInt(value) < 1024n ? formatAnalyticsBytes(Number(value), locale) : formatDashboardBytes(value, locale) },
  ]
  const selected = rankSource.find((snapshot) => snapshot.dimension === selectedDimension) ?? rankSource[0]
  const extendedRanksAvailable = Boolean(variant === 'admin' && analytics.top_extended)
  const emptyAnalytics = isAuthoritativeEmptyAnalytics(analytics)
  const blockedTrendAvailable = variant === 'admin' &&
    (analytics.blocked_ip_count !== undefined || emptyAnalytics) &&
    (analytics.blocked_ip_trend_available === true ||
      (analytics.blocked_ip_trend_available === undefined &&
        (analytics.trend.some((point) => point.blocked_ip_count !== undefined) || emptyAnalytics)))
  const rankTabs = variant === 'admin'
      ? [
        { key: 'domain', label: t('top.domain'), enabled: true },
        { key: 'url', label: extendedRanksAvailable ? t('top.url') : t('top.urlUnavailable'), enabled: extendedRanksAvailable },
        { key: 'ip', label: extendedRanksAvailable ? t('top.ip') : t('top.ipUnavailable'), enabled: extendedRanksAvailable },
        { key: 'region', label: t('top.country'), enabled: true },
      ] as const
    : null
  const scrollRankTabs = (direction: -1 | 1) => {
    const viewport = rankTabViewportRef.current
    if (!viewport) return
    viewport.scrollLeft += direction * 112
  }
  const trend = (
    <section className="dashboard-trend-pane" aria-label={variant === 'admin' ? t('sections.trend') : undefined}>
      {variant === 'admin' ? <div className="dashboard-trend-tablist" role="tablist" aria-label={t('sections.trend')}>
        {([
          ['bandwidth', t('charts.bandwidth'), true],
          ['requests', t('charts.requests'), true],
          ['traffic', t('charts.traffic'), true],
          ['blocked', t('charts.blocked'), blockedTrendAvailable],
        ] as const).map(([key, label, enabled]) => (
          <button key={key} type="button" role="tab" aria-selected={enabled && trendMetric === key}
            aria-disabled={!enabled} className={!enabled ? 'is-disabled' : enabled && trendMetric === key ? 'is-active' : ''}
            onClick={() => { if (enabled) setTrendMetric(key as TrendMetric) }}>
            {label}
          </button>
        ))}
      </div> : null}
      <BandwidthTrend analytics={analytics} locale={locale} metric={variant === 'admin' ? trendMetric : 'bandwidth'} />
    </section>
  )
  const rankings = rankTabs ? (
      <section className="dashboard-rank-section dashboard-rank-tabs" aria-label={variant === 'admin' ? t('top.adminTitle') : t('top.title')}>
      {variant === 'admin' && displayMode === 'both' ? <h3 className="dashboard-trend-heading">{t('top.adminTitle')}</h3> : null}
      <div className="dashboard-rank-tabbar">
        {rankTabsOverflow ? <button className="dashboard-rank-tab-arrow" type="button" aria-label={t('top.previous')} onClick={() => scrollRankTabs(-1)}>
          <ChevronLeft size={16} aria-hidden="true" />
        </button> : null}
        <div ref={rankTabViewportRef} className="dashboard-rank-tablist" role="tablist">
          {rankTabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              role="tab"
              aria-selected={tab.enabled && selected?.dimension === tab.key}
              aria-disabled={!tab.enabled}
              className={!tab.enabled ? 'is-disabled' : tab.enabled && selected?.dimension === tab.key ? 'is-active' : ''}
              onClick={() => {
                if (tab.enabled) setSelectedDimension(tab.key as NonNullable<DashboardAnalyticsOverview['top_extended']>[number]['dimension'])
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
        {rankTabsOverflow ? <button className="dashboard-rank-tab-arrow" type="button" aria-label={t('top.next')} onClick={() => scrollRankTabs(1)}>
          <ChevronRight size={16} aria-hidden="true" />
        </button> : null}
      </div>
      {selected ? <div className="dashboard-table-wrap">
        <Table rowKey="key" size="small" pagination={false} columns={columnsFor(selected.dimension)} dataSource={selected.items}
          locale={{ emptyText: t('top.empty') }} scroll={displayMode === 'rankings' ? undefined : { x: 520 }} />
      </div> : <div className="dashboard-chart-state">{t('top.empty')}</div>}
    </section>
  ) : (
    <div className="dashboard-grid">
      {analytics.top.map((snapshot) => (
        <section className="dashboard-rank-section" key={snapshot.dimension}>
          <h3>{t(`top.${snapshot.dimension}`)}</h3>
          <div className="dashboard-table-wrap">
            <Table rowKey="key" size="small" pagination={false} columns={columnsFor(snapshot.dimension)} dataSource={snapshot.items}
              locale={{ emptyText: t('top.empty') }} scroll={{ x: 520 }} />
          </div>
        </section>
      ))}
    </div>
  )
  return (
    <div className={`dashboard-analytics-overview${variant === 'admin' ? ' dashboard-analytics-admin' : ''}${displayMode === 'trend' ? ' dashboard-analytics-trend-only' : displayMode === 'rankings' ? ' dashboard-analytics-rankings-only' : ''}`}>
      <AnalyticsSettlingHint minutes={analytics.settling_minutes} />
      {displayMode !== 'rankings' ? trend : null}
      {displayMode !== 'trend' ? rankings : null}
    </div>
  )
}

export function NetworkRegionTable({ network, locale }: { network: NetworkStats; locale: string }) {
  const { t } = useTranslation('dashboardOverview')
  const columns: TableColumnsType<NetworkStats['regions'][number]> = [
    { title: t('network.region'), dataIndex: 'region', key: 'region',
      render: (value: string) => value === 'unassigned' ? t('network.unassigned') : value },
    { title: t('network.nodes'), dataIndex: 'nodes_total', key: 'nodes_total', align: 'right', width: 100,
      render: (value: number) => formatNumber(value, locale) },
    { title: t('network.online'), dataIndex: 'nodes_online', key: 'nodes_online', align: 'right', width: 100,
      render: (value: number) => formatNumber(value, locale) },
  ]
  return <div className="dashboard-table-wrap"><Table rowKey="region" size="small" pagination={false}
    columns={columns} dataSource={network.regions} scroll={{ x: 420 }} /></div>
}
