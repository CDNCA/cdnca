import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Collapse, Segmented, Select, Space, Table, Tabs, type TableColumnsType } from 'antd'
import { RefreshCw } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { DataTable, PageHeader, PageSection, StatusTag } from '@cdnca/ui'

import { getRUMReport, rumMetrics, rumRanges, type RUMBreakdown, type RUMErrorTotal, type RUMMetric, type RUMRange, type RUMReport } from '../api/rum'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import '../i18n/rumReport'
import { themeColor, useThemeRevision } from '../theme/themeColor'
import './RumReportPage.css'

// 真实用户体验: one
// site's Web Vitals p75 against the official thresholds, its trend, the
// page / country / device breakdown and the top errors.

type Rating = 'good' | 'ni' | 'poor'
const ratingStatus: Record<Rating, 'success' | 'warning' | 'error'> = { good: 'success', ni: 'warning', poor: 'error' }
const fewSamples = 20

export function formatMetric(metric: RUMMetric, value: number | undefined): string {
  if (value === undefined) return '—'
  if (metric === 'cls') return value.toFixed(3)
  return value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(2)} s`
}

export function rateMetric(value: number, thresholds: [number, number]): Rating {
  return value <= thresholds[0] ? 'good' : value <= thresholds[1] ? 'ni' : 'poor'
}

function percent(value: number): string {
  return `${Math.round(value * 100)}%`
}

function MetricCard({ metric, report, selected, onSelect, index, t }: {
  metric: RUMMetric; report: RUMReport; selected: boolean; onSelect: () => void; index: number; t: TFunction<'rumReport'>
}) {
  const summary = report.summary[metric]
  const rating = summary ? rateMetric(summary.p75, report.thresholds[metric]) : undefined
  return (
    <button type="button" className="rum-card" aria-pressed={selected} onClick={onSelect}
      style={{ animationDelay: `${index * 30}ms` }} title={t(`metric.${metric}`)}>
      <span className="rum-card-name">{t(`metricShort.${metric}`)}</span>
      <span className="rum-card-value">{formatMetric(metric, summary?.p75)}</span>
      {rating ? <StatusTag status={ratingStatus[rating]}>{t(`rating.${rating}`)}</StatusTag>
        : <span className="rum-card-muted">{t('notMeasured')}</span>}
      {summary ? <>
        <span className="rum-card-bar" aria-hidden="true">
          <span className="rum-bar-good" style={{ width: percent(summary.good) }} />
          <span className="rum-bar-ni" style={{ width: percent(summary.needs_improvement) }} />
          <span className="rum-bar-poor" style={{ width: percent(summary.poor) }} />
        </span>
        <span className="rum-card-muted">{t('shares', { good: percent(summary.good), ni: percent(summary.needs_improvement), poor: percent(summary.poor) })}</span>
        <span className="rum-card-muted">{t('samples', { count: summary.samples, formatted: formatNumber(summary.samples) })}</span>
      </> : null}
    </button>
  )
}

function TrendChart({ metric, report, t }: { metric: RUMMetric; report: RUMReport; t: TFunction<'rumReport'> }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [failed, setFailed] = useState(false)
  const themeRevision = useThemeRevision()
  const [good, poor] = report.thresholds[metric]
  useEffect(() => {
    if (containerRef.current === null || report.series.length === 0) return
    let disposed = false
    let chart: import('../components/echartsRuntime').ECharts | undefined
    void import('../components/echartsRuntime').then((echarts) => {
      if (disposed || containerRef.current === null) return
      chart = echarts.init(containerRef.current)
      const line = themeColor('--cdnca-chart-color1', '#2d8cf0')
      const okColor = themeColor('--cdnca-color-success', '#19be6b')
      const badColor = themeColor('--cdnca-color-error', '#ed4014')
      const labels = report.series.map((point) => formatDateTime(point.at))
      const threshold = (name: string, value: number, color: string) => ({
        name, type: 'line', showSymbol: false, silent: true, data: labels.map(() => value),
        lineStyle: { color, width: 1, type: 'dashed' }, itemStyle: { color },
        endLabel: { show: true, formatter: name, color, fontSize: 11 },
      })
      chart.setOption({
        animationDuration: 180,
        grid: { left: 56, right: 96, top: 16, bottom: 30 },
        tooltip: {
          trigger: 'axis',
          formatter: (items: { dataIndex: number }[]) => {
            const point = report.series[items[0]?.dataIndex ?? 0]
            if (!point) return ''
            const few = point.views < fewSamples ? ` (${t('fewSamples')})` : ''
            return `${formatDateTime(point.at)}<br/>p75 ${formatMetric(metric, point.p75[metric])}<br/>${t('views')} ${formatNumber(point.views)}${few}`
          },
        },
        xAxis: { type: 'category', boundaryGap: false, data: labels },
        yAxis: { type: 'value', axisLabel: { formatter: (value: number) => formatMetric(metric, value) } },
        series: [
          {
            name: t(`metricShort.${metric}`), type: 'line', connectNulls: false, lineStyle: { color: line, width: 2 },
            data: report.series.map((point) => ({
              value: point.p75[metric] ?? null,
              symbol: point.views < fewSamples ? 'emptyCircle' : 'circle', symbolSize: point.views < fewSamples ? 6 : 4,
              itemStyle: { color: line },
            })),
          },
          threshold(t('goodLine', { value: formatMetric(metric, good) }), good, okColor),
          threshold(t('poorLine', { value: formatMetric(metric, poor) }), poor, badColor),
        ],
      })
    }).catch(() => setFailed(true))
    const resize = () => chart?.resize()
    window.addEventListener('resize', resize)
    return () => {
      disposed = true
      window.removeEventListener('resize', resize)
      chart?.dispose()
    }
  }, [metric, report, good, poor, t, themeRevision])
  const summary = report.summary[metric]
  const label = summary
    ? t('trendSummary', { metric: t(`metricShort.${metric}`), range: t(`ranges.${report.range}`), value: formatMetric(metric, summary.p75),
      rating: t(`rating.${rateMetric(summary.p75, report.thresholds[metric])}`) })
    : t('notMeasured')
  return <>
    {failed ? <Alert type="warning" showIcon message={t('failed')} /> : null}
    <div ref={containerRef} className="rum-chart" role="img" aria-label={label} />
    <Collapse ghost items={[{
      key: 'table', label: t('showTable'),
      children: <Table size="small" pagination={false} rowKey="at" dataSource={report.series} scroll={{ x: true }}
        columns={[
          { title: t('time'), dataIndex: 'at', render: (value: string) => formatDateTime(value) },
          { title: t('p75'), key: 'p75', render: (_: unknown, point) => formatMetric(metric, point.p75[metric]) },
          { title: t('views'), dataIndex: 'views', render: (value: number) => formatNumber(value) },
        ]} />,
    }]} />
  </>
}

function breakdownColumns(report: RUMReport, t: TFunction<'rumReport'>, valueTitle: string,
  label: (value: string) => string): TableColumnsType<RUMBreakdown> {
  return [
    { title: valueTitle, dataIndex: 'value', render: (value: string) => value === '(other)'
      ? <span title={t('other')}>{t('otherValue')}</span> : label(value) },
    { title: t('views'), dataIndex: 'views', sorter: (a, b) => a.views - b.views, defaultSortOrder: 'descend',
      render: (value: number) => formatNumber(value) },
    ...rumMetrics.map((metric) => ({
      title: t(`metricShort.${metric}`), key: metric,
      sorter: (a: RUMBreakdown, b: RUMBreakdown) => (a.p75[metric] ?? -1) - (b.p75[metric] ?? -1),
      render: (_: unknown, row: RUMBreakdown) => {
        const value = row.p75[metric]
        if (value === undefined) return '—'
        const rating = rateMetric(value, report.thresholds[metric])
        return <span className="rum-cell"><span className={`rum-dot rum-dot-${rating}`} role="img" aria-label={t(`rating.${rating}`)} />
          {formatMetric(metric, value)}</span>
      },
    })),
  ]
}

function errorColumns(report: RUMReport, t: TFunction<'rumReport'>): TableColumnsType<RUMErrorTotal> {
  return [
    { title: t('columns.kind'), dataIndex: 'kind', render: (value: RUMErrorTotal['kind']) => t(`errorKind.${value}`) },
    { title: t('columns.element'), dataIndex: 'element', render: (value: string) => value || '—' },
    { title: t('columns.target'), dataIndex: 'target', ellipsis: true },
    { title: t('columns.status'), dataIndex: 'status', render: (value: number) => value === 0 ? t('networkFailure') : value },
    { title: t('columns.count'), dataIndex: 'count', render: (value: number) => formatNumber(value) },
    { title: t('columns.share'), key: 'share', render: (_: unknown, row) => report.views > 0 ? percent(row.count / report.views) : '—' },
  ]
}

export default function RumReportPage() {
  const { t } = useTranslation('rumReport')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const admin = principal?.scope_kind === 'platform'
  const [siteSearch, setSiteSearch] = useState('')
  const [siteID, setSiteID] = useState<string>()
  const [range, setRange] = useState<RUMRange>('24h')
  const [metric, setMetric] = useState<RUMMetric>('lcp')
  const sites = useQuery({
    queryKey: ['rum-report-sites', siteSearch],
    queryFn: async () => (await sitesApi.list(accessToken!, { page: 1, limit: 100, ...(siteSearch ? { domain: siteSearch } : {}) })).items,
    enabled: Boolean(accessToken),
    staleTime: 30_000,
  })
  // the admin route needs the site's tenant scope (the detail carries it)
  const detail = useQuery({
    queryKey: ['rum-report-site', siteID],
    queryFn: () => sitesApi.detail(accessToken!, siteID!),
    enabled: Boolean(accessToken && siteID && admin),
  })
  const tenantScopeID = admin ? detail.data?.scope_id : undefined
  const report = useQuery({
    queryKey: ['rum-report', siteID, range, tenantScopeID],
    queryFn: () => getRUMReport(accessToken!, { siteID: siteID!, range, ...(tenantScopeID ? { tenantScopeID } : {}) }),
    enabled: Boolean(accessToken && siteID && (!admin || tenantScopeID)),
    retry: false,
  })
  const data = report.data
  const country = useMemo(() => {
    const names = new Intl.DisplayNames([document.documentElement.lang || 'zh-CN'], { type: 'region' })
    return (code: string) => code === '--' ? t('noCountry') : `${names.of(code) ?? code} (${code})`
  }, [t])
  return (
    <PageSection className="rum-report" aria-labelledby="rum-report-title">
      <PageHeader title={<span id="rum-report-title">{t('title')}</span>} description={t('description')}
        extra={data && data.views > 0 ? <span className="rum-asof">{t('asOf', { time: formatDateTime(data.to) })}</span> : undefined} />
      <Space wrap className="rum-toolbar">
        <Select showSearch allowClear aria-label={t('site')} placeholder={t('sitePlaceholder')} style={{ width: 240 }}
          filterOption={false} onSearch={setSiteSearch} value={siteID} onChange={setSiteID} loading={sites.isFetching}
          options={(sites.data ?? []).map((site) => ({ value: site.id, label: site.domain }))} />
        <Segmented aria-label={t('range')} value={range} onChange={(value) => setRange(value as RUMRange)}
          options={rumRanges.map((value) => ({ value, label: t(`ranges.${value}`) }))} />
        <Button icon={<RefreshCw size={14} aria-hidden="true" />} disabled={!siteID} loading={report.isFetching}
          onClick={() => void report.refetch()}>{t('refresh')}</Button>
      </Space>
      {!siteID ? <Alert type="info" showIcon message={t('pickSite')} /> : null}
      {report.isError ? <Alert type="error" showIcon message={t('failed')} /> : null}
      {data && data.rum_sample_percent === null ? <Alert type="info" showIcon message={t('off')}
        action={<Link to={`/site/${siteID}/edit?tab=advanced`}>{t('goEnable')}</Link>} /> : null}
      {data && data.rum_sample_percent !== null && data.views === 0 ? <Alert type="info" showIcon message={t('empty')} /> : null}
      {data && data.views > 0 ? <>
        <div className="rum-cards" role="group" aria-label={t('title')}>
          {rumMetrics.map((item, index) => <MetricCard key={item} metric={item} report={data} selected={item === metric}
            onSelect={() => setMetric(item)} index={index} t={t} />)}
        </div>
        <PageSection title={t('trend', { metric: t(`metricShort.${metric}`) })}>
          <TrendChart metric={metric} report={data} t={t} />
        </PageSection>
        <PageSection title={t('breakdown')}>
          <Tabs items={[
            { key: 'pages', label: t('tabs.pages'), children: <DataTable rowKey="value" dataSource={data.pages}
              columns={breakdownColumns(data, t, t('tabs.pages'), (value) => value)} /> },
            { key: 'countries', label: t('tabs.countries'), children: <DataTable rowKey="value" dataSource={data.countries}
              columns={breakdownColumns(data, t, t('tabs.countries'), country)} /> },
            { key: 'devices', label: t('tabs.devices'), children: <DataTable rowKey="value" dataSource={data.devices}
              columns={breakdownColumns(data, t, t('tabs.devices'), (value) => t(`devices.${value}`, { defaultValue: value }))} /> },
          ]} />
        </PageSection>
        <PageSection title={t('errors')}>
          <DataTable rowKey={(row: RUMErrorTotal) => `${row.kind}|${row.element}|${row.target}|${row.status}`}
            dataSource={data.errors} columns={errorColumns(data, t)} locale={{ emptyText: t('noErrors') }} />
        </PageSection>
        <p className="rum-footer">{t('footer', { dropped: formatNumber(data.dropped) })}</p>
      </> : null}
    </PageSection>
  )
}
