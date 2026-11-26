import { useId, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Radio, Spin, type TableColumnsType } from 'antd'
import { Tabs } from '../components/Tabs'
import { RefreshCw, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import dayjs from 'dayjs'

import { ApiError, type Principal } from '../api/auth'
import {
  type L4RealtimeAudience,
  type L4RealtimeFilters,
  type L4RealtimeRow,
} from '../api/l4Realtime'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatAnalyticsBandwidth as formatBandwidth, formatAnalyticsBytes as formatBytes } from '../i18n/analyticsUnits'
import '../i18n/l4Realtime'
import './L4RealtimeMonitorPage.css'
import '../styles/analyticsControlParity.css'
import { FeedbackWhen, TimeRangeFilter, Table } from '@cdnca/ui'
import { L4NodeSelect, L4TenantSelect } from './L4ScopeFilters'
import { parsePorts, readRows, type AppliedQuery } from './l4RealtimeRead'
import { FieldErrorText, filterFieldProps, useFieldFocus } from '../components/FilterFieldError'
import { filterParam, linkedTimeRange, timeRangeUrlValues, useFilterUrl } from './filterUrl'

type TrafficRange = 'today' | 'last7d' | 'last30d' | 'custom'
type RankingRange = '10m' | '30m' | '60m'
const rankingRanges: readonly RankingRange[] = ['10m', '30m', '60m']
const trafficPresets: readonly string[] = ['today', 'last7d', 'last30d']
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/


interface RankingRow {
  rank: number
  port: string
  sessions: number
  traffic: number
}

interface ChartPoint {
  bucket: string
  value: number
}

function canView(principal: Principal | null): boolean {
  if (!principal) return false
  if (principal.scope_kind === 'tenant') {
    return Boolean(principal.tenant_id) && principal.permissions.includes('sites.read')
  }
  return principal.scope_kind === 'platform'
    && principal.tenant_id === null
    && principal.permissions.includes('platform.admin')
}

function canonicalTime(value: Date): string {
  return value.toISOString().replace(/\.000Z$/, 'Z').replace(/(\.\d*?[1-9])0+Z$/, '$1Z')
}

function localDateTime(value: Date): string {
  const offset = value.getTimezoneOffset() * 60_000
  return new Date(value.getTime() - offset).toISOString().slice(0, 16)
}

// Quick ranges (today / last 7 days / last 30 days / custom) are sent as custom windows ending now;
// the backend's fixed windows stop at 24 hours, custom ones at 31 days.
function presetWindow(range: Exclude<TrafficRange, 'custom'>, now = dayjs()): [Date, Date] {
  const from = range === 'today' ? now.startOf('day') : now.subtract(range === 'last7d' ? 7 : 30, 'day')
  return [from.toDate(), now.toDate()]
}

function presetFilters(range: Exclude<TrafficRange, 'custom'>): L4RealtimeFilters {
  const [from, to] = presetWindow(range)
  return { range: 'custom', timezone: 'UTC', from: canonicalTime(from), to: canonicalTime(to), limit: 100 }
}

function customFilters(from: string, to: string): L4RealtimeFilters | null {
  const start = new Date(from)
  const end = new Date(to)
  if (!from || !to || !Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start >= end || end.getTime() - start.getTime() > 31 * 24 * 60 * 60 * 1000) return null
  return { range: 'custom', timezone: 'UTC', from: canonicalTime(start), to: canonicalTime(end), limit: 100 }
}

function rankingFilters(range: RankingRange): L4RealtimeFilters {
  if (range === '60m') return { range: '1h', timezone: 'UTC', limit: 100 }
  const minutes = range === '10m' ? 10 : 30
  const to = new Date()
  const from = new Date(to.getTime() - minutes * 60_000)
  return { range: 'custom', timezone: 'UTC', from: canonicalTime(from), to: canonicalTime(to), limit: 100 }
}

function formatNumber(value: number, language: string): string {
  return new Intl.NumberFormat(language, { maximumFractionDigits: 0 }).format(value)
}

function chartPoints(rows: L4RealtimeRow[], metric: 'traffic' | 'bandwidth'): ChartPoint[] {
  const buckets = new Map<string, number>()
  for (const row of rows) {
    const bytes = row.bytes_up + row.bytes_down
    buckets.set(row.bucket, (buckets.get(row.bucket) ?? 0) + (metric === 'traffic' ? bytes : bytes * 8 / 60))
  }
  return [...buckets.entries()].sort(([left], [right]) => Date.parse(left) - Date.parse(right)).map(([bucket, value]) => ({ bucket, value }))
}

function rankingRows(rows: L4RealtimeRow[]): RankingRow[] {
  const totals = new Map<string, Omit<RankingRow, 'rank'>>()
  for (const row of rows) {
    const port = `${row.listen_port}/${row.protocol.toUpperCase()}`
    const current = totals.get(port) ?? { port, sessions: 0, traffic: 0 }
    current.sessions += row.sessions
    current.traffic += row.bytes_up + row.bytes_down
    totals.set(port, current)
  }
  return [...totals.values()]
    .sort((left, right) => right.traffic - left.traffic || right.sessions - left.sessions || left.port.localeCompare(right.port))
    .slice(0, 10)
    .map((row, index) => ({ ...row, rank: index + 1 }))
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.requestFailed'
  if (error.status === 403) return 'states.permissionTitle'
  if (error.status === 504 || error.code.includes('timeout')) return 'states.timeout'
  if (error.status === 400) return 'states.invalidRequest'
  if (error.status === 502 || error.code === 'invalid_response') return 'states.invalidResponse'
  if (error.status === 503 || error.status === 0) return 'states.unavailable'
  return 'states.requestFailed'
}

function RealtimeChart({ title, points, language, formatter }: { title: string; points: ChartPoint[]; language: string; formatter: (value: number, language: string) => string }) {
  const width = 640
  const height = 270
  const plot = { left: 78, right: 14, top: 18, bottom: 28 }
  const plotWidth = width - plot.left - plot.right
  const plotHeight = height - plot.top - plot.bottom
  const maximum = Math.max(...points.map((point) => point.value), 0)
  const scale = maximum || 1
  const x = (index: number) => points.length <= 1 ? plot.left + plotWidth / 2 : plot.left + index / (points.length - 1) * plotWidth
  const y = (value: number) => plot.top + plotHeight - value / scale * plotHeight
  const polyline = points.map((point, index) => `${x(index)},${y(point.value)}`).join(' ')
  const total = points.reduce((sum, point) => sum + point.value, 0)

  return (
    <section className="l4-realtime-baseline-chart" aria-label={title}>
      <h2>{title}</h2>
      <span className="visually-hidden">{formatter(total, language)}</span>
      <div className="l4-realtime-baseline-chart-canvas">
        <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={title} preserveAspectRatio="none">
          {[0, 0.33, 0.66, 1].map((fraction) => {
            const gridY = plot.top + plotHeight - fraction * plotHeight
            return <g key={fraction}>
              <line className="l4-realtime-grid-line" x1={plot.left} x2={width - plot.right} y1={gridY} y2={gridY} />
              <text className="l4-realtime-axis-label" x={plot.left - 8} y={gridY + 4} textAnchor="end">{formatter(scale * fraction, language)}</text>
            </g>
          })}
          <line className="l4-realtime-axis-line" x1={plot.left} x2={width - plot.right} y1={plot.top + plotHeight} y2={plot.top + plotHeight} />
          {points.length > 0 ? <polyline className="l4-realtime-series" points={polyline} /> : null}
        </svg>
      </div>
    </section>
  )
}

// 已生效的时间范围、端口（平台还有租户、节点）写进 URL，刷新或打开链接时读回并按它首查；
// 链接里不认识的值用默认，端口不合法时放进输入框标错、不生效。
function linkedTraffic(searchParams: URLSearchParams, audience: L4RealtimeAudience) {
  const uuid = (key: string) => { const value = filterParam(searchParams, key).toLowerCase(); return uuidPattern.test(value) ? value : undefined }
  const linked = linkedTimeRange(searchParams, trafficPresets)
  const range = (linked?.preset ?? 'today') as TrafficRange
  const window = linked?.range ?? presetWindow(range === 'custom' ? 'today' : range)
  const port = filterParam(searchParams, 'port')
  const ports = parsePorts(port)
  const tenantId = audience === 'admin' ? uuid('tenant_id') : undefined
  const nodeId = audience === 'admin' ? uuid('node_id') : undefined
  const filters = range === 'custom' ? customFilters(localDateTime(window[0]), localDateTime(window[1])) : presetFilters(range)
  return {
    range, from: localDateTime(window[0]), to: localDateTime(window[1]), port, portValid: ports !== null, tenantId, nodeId,
    applied: { filters: { ...(filters ?? presetFilters('today')), ...(tenantId ? { tenantId } : {}), ...(nodeId ? { nodeId } : {}) }, ports: ports ?? [] } as AppliedQuery,
    appliedPort: ports ? port : '',
  }
}

function TrafficPanel({ audience, ownerKey }: { audience: L4RealtimeAudience; ownerKey: string }) {
  const { t, i18n } = useTranslation('l4Realtime')
  const [searchParams] = useSearchParams()
  const [linked] = useState(() => linkedTraffic(searchParams, audience))
  const [tenantId, setTenantId] = useState<string | undefined>(linked.tenantId)
  const [nodeId, setNodeId] = useState<string | undefined>(linked.nodeId)
  const [port, setPort] = useState(linked.port)
  const [range, setRange] = useState<TrafficRange>(linked.range)
  const [from, setFrom] = useState(linked.from)
  const [to, setTo] = useState(linked.to)
  const [validationError, setValidationError] = useState<string | null>(null)
  // 端口（443、443/TCP，逗号分隔多个）不合法时错误挂在端口输入框上并给它焦点，
  // 不发请求，已生效的范围与图表不变。
  const portFieldID = `${useId()}-port`
  const [portError, setPortError] = useState<string | null>(linked.portValid ? null : t('filters.invalidPort'))
  const focusField = useFieldFocus()
  const [applied, setApplied] = useState<AppliedQuery>(linked.applied)
  const [appliedView, setAppliedView] = useState({ range: linked.range, port: linked.appliedPort })
  useFilterUrl({
    port: appliedView.port, tenant_id: applied.filters.tenantId, node_id: applied.filters.nodeId,
    ...timeRangeUrlValues(appliedView.range, applied.filters.from ?? '', applied.filters.to ?? ''),
  })
  const query = useQuery({
    queryKey: ['l4-realtime-traffic', ownerKey, applied],
    queryFn: ({ signal }) => readRows(ownerKey, audience, applied, signal),
    retry: false,
    refetchOnWindowFocus: false,
  })

  const apply = () => {
    const ports = parsePorts(port)
    const filters = range === 'custom' ? customFilters(from, to) : presetFilters(range)
    setPortError(ports ? null : t('filters.invalidPort'))
    setValidationError(filters ? null : t('filters.invalidWindow'))
    if (!ports) {
      focusField(portFieldID)
      return
    }
    if (!filters) return
    const next = { filters: { ...filters, ...(tenantId ? { tenantId } : {}), ...(nodeId ? { nodeId } : {}) }, ports }
    setAppliedView({ range, port: port.trim() })
    if (JSON.stringify(next) === JSON.stringify(applied)) void query.refetch()
    else setApplied(next)
  }
  const rows = query.data?.rows ?? []
  const language = i18n.resolvedLanguage ?? 'zh-CN'

  return (
    <div className="l4-realtime-baseline-traffic">
      <div className="l4-realtime-baseline-filter">
        {audience === 'admin' ? <><L4TenantSelect ownerKey={ownerKey} value={tenantId} onChange={setTenantId} />
          <L4NodeSelect ownerKey={ownerKey} value={nodeId} onChange={setNodeId} /></> : null}
        <Input className="l4-realtime-baseline-port" aria-label={t('filters.port')} placeholder={t('filters.portPlaceholder')} value={port} onPressEnter={apply}
          {...filterFieldProps(portFieldID, portError)} onChange={(event) => { setPort(event.target.value); setPortError(null) }} />
        <TimeRangeFilter className="l4-realtime-baseline-range" label={t('filters.range')} maxSpanMs={31 * 24 * 60 * 60 * 1000}
          value={{ preset: range, range: from && to ? [dayjs(from), dayjs(to)] : null }}
          onChange={({ preset, range: window }) => {
            setRange(preset as TrafficRange)
            setFrom(window ? localDateTime(window[0].toDate()) : '')
            setTo(window ? localDateTime(window[1].toDate()) : '')
          }} />
        <Button className="l4-realtime-baseline-search" type="primary" icon={<Search size={15} />} loading={query.isFetching} onClick={apply}>{t('actions.query')}</Button>
      </div>
      <FieldErrorText id={portFieldID} error={portError} />
      {validationError ? <Alert className="l4-realtime-alert" type="error" showIcon message={validationError} /> : null}
      {query.error ? <FeedbackWhen title={t(errorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      {query.data && !query.data.complete ? <Alert className="l4-realtime-alert" type="warning" showIcon message={t('states.incomplete')} /> : null}
      {query.isPending ? <div className="l4-realtime-loading" aria-label={t('states.loading')}><Spin size="small" /></div> : null}
      {/* 只有读到了时间点才画图（全是 0 的时间点照常画坐标）；
          读取成功但这段时间没有任何点时给一条空态，不画四条 0 刻度加居中的 0。加载与失败各有自己的状态。 */}
      {rows.length > 0 ? (
        <div className="l4-realtime-baseline-chart-grid">
          <RealtimeChart title={t('charts.bandwidth')} points={chartPoints(rows, 'bandwidth')} language={language} formatter={formatBandwidth} />
          <RealtimeChart title={t('charts.traffic')} points={chartPoints(rows, 'traffic')} language={language} formatter={formatBytes} />
        </div>
      ) : query.isSuccess ? <DataState status="empty" message={t('states.empty')} /> : null}
    </div>
  )
}

function RankingPanel({ audience, ownerKey }: { audience: L4RealtimeAudience; ownerKey: string }) {
  const { t, i18n } = useTranslation('l4Realtime')
  // 已生效的排行时段写进 ?ranking_range=（默认 10 分钟不写）。
  const [searchParams] = useSearchParams()
  const [initialRange] = useState<RankingRange>(() => {
    const value = filterParam(searchParams, 'ranking_range')
    return rankingRanges.find((item) => item === value) ?? '10m'
  })
  const [range, setRange] = useState<RankingRange>(initialRange)
  const [appliedRange, setAppliedRange] = useState<RankingRange>(initialRange)
  const [applied, setApplied] = useState(() => rankingFilters(initialRange))
  useFilterUrl({ ranking_range: appliedRange === '10m' ? undefined : appliedRange })
  const query = useQuery({
    queryKey: ['l4-realtime-ranking', ownerKey, applied],
    queryFn: ({ signal }) => readRows(ownerKey, audience, { filters: applied, ports: [] }, signal),
    retry: false,
    refetchOnWindowFocus: false,
  })
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const rows = rankingRows(query.data?.rows ?? [])
  const columns: TableColumnsType<RankingRow> = [
    { title: t('columns.rank'), dataIndex: 'rank', key: 'rank', width: 70 },
    { title: t('columns.port'), dataIndex: 'port', key: 'port', width: 200 },
    { title: t('columns.sessions'), dataIndex: 'sessions', key: 'sessions', width: 150, render: (value: number) => formatNumber(value, language) },
    { title: t('columns.traffic'), dataIndex: 'traffic', key: 'traffic', width: 150, render: (value: number) => formatBytes(value, language) },
  ]
  const refresh = () => {
    const next = rankingFilters(range)
    setAppliedRange(range)
    if (JSON.stringify(next) === JSON.stringify(applied)) void query.refetch()
    else setApplied(next)
  }

  return (
    <div className="l4-realtime-baseline-ranking">
      <div className="l4-realtime-baseline-ranking-toolbar">
        <div role="radiogroup" aria-label={t('filters.rankingRange')}>
          <Radio.Group className="l4-realtime-baseline-ranking-range" optionType="button" buttonStyle="solid" value={range} onChange={(event) => setRange(event.target.value as RankingRange)} options={[
            { value: '10m', label: t('rankingRanges.tenMinutes') }, { value: '30m', label: t('rankingRanges.thirtyMinutes') }, { value: '60m', label: t('rankingRanges.oneHour') },
          ]} />
        </div>
        <Button className="l4-realtime-baseline-refresh" type="primary" icon={<RefreshCw size={15} />} loading={query.isFetching} onClick={refresh}>{t('actions.refresh')}</Button>
      </div>
      {query.error ? <FeedbackWhen title={t(errorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      {query.data && !query.data.complete ? <Alert className="l4-realtime-alert" type="warning" showIcon message={t('states.incomplete')} /> : null}
      <div className="l4-realtime-baseline-ranking-table-scroll">
        <Table<RankingRow> className="l4-realtime-baseline-ranking-table" columns={columns} dataSource={rows} loading={query.isPending} pagination={false} rowKey="port" locale={{ emptyText: t('states.emptyRanking') }} scroll={{ x: 570 }} />
      </div>
    </div>
  )
}

function L4RealtimeContent({ audience, ownerKey }: { audience: L4RealtimeAudience; ownerKey: string }) {
  const { t } = useTranslation('l4Realtime')
  // 当前页签写进 ?view=ranking（带宽流量为默认不写），刷新、复制地址和前进后退都回到原页签。
  const [searchParams, setSearchParams] = useSearchParams()
  const view = searchParams.get('view') === 'ranking' ? 'ranking' : 'traffic'
  const changeView = (next: string) => {
    const params = new URLSearchParams(searchParams)
    if (next === 'ranking') params.set('view', 'ranking')
    else params.delete('view')
    setSearchParams(params)
  }
  return (
    <section className="l4-realtime-baseline-page" aria-labelledby="l4-realtime-title">
      <h1 className="visually-hidden" id="l4-realtime-title">{t('heading')}</h1>
      <div className="l4-realtime-baseline-panel">
        <Tabs className="l4-realtime-baseline-tabs" animated={false} destroyOnHidden activeKey={view} onChange={changeView} items={[
          { key: 'traffic', label: t('tabs.traffic'), children: <TrafficPanel audience={audience} ownerKey={ownerKey} /> },
          { key: 'ranking', label: t('tabs.ranking'), children: <RankingPanel audience={audience} ownerKey={ownerKey} /> },
        ]} />
      </div>
    </section>
  )
}

export default function L4RealtimeMonitorPage() {
  const { t } = useTranslation('l4Realtime')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken || !principal || !canView(principal)) {
    return <DataState status="forbidden" className="identity-page" message={t('states.permissionTitle')} description={t('states.permissionDescription')} />
  }
  const audience: L4RealtimeAudience = principal.scope_kind === 'tenant' ? 'tenant' : 'admin'
  const ownerKey = `${principal.user_id}:${principal.scope_kind}:${principal.scope_id}`
  return <L4RealtimeContent audience={audience} ownerKey={ownerKey} />
}
