import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  Checkbox,
  Input,
  Popover,
  Result,
  Select,
  Radio,
  Table,
  Tabs,
  Tooltip,
  Typography,
  type TableColumnsType,
} from 'antd'
import dayjs from 'dayjs'
import { ChevronDown, CircleHelp, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  nodesApi,
  type NodeInventoryItem,
  type NodeMetricsHistoryPoint,
  type NodeMetricsLatest,
  type NodeMount,
  type NodeRealtimeMetric,
  type NodeRealtimeTopItem,
  type NodeTrafficItem,
} from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { businessTimeZone, formatBandwidth, formatBytes, formatDateTime } from '../i18n/formatters'
import '../i18n/nodeRealtime'
import { themeColor, themeColorAlpha, useThemeRevision } from '../theme/themeColor'
import './NodeRealtimePage.css'
import { TimeRangeFilter, type TimeRange, type TimeRangePreset } from '@cdnca/ui'

type Owner = readonly ['platform', string, string, number]

const staleRead = new Error('Node realtime owner changed during read')
/** GET /v1/nodes/metrics/latest takes at most 300 node_id per call. */
const latestBatchSize = 300

const durations: Record<string, number> = { '1h': 60 * 60 * 1000, '6h': 6 * 60 * 60 * 1000, '12h': 12 * 60 * 60 * 1000, last7d: 7 * 24 * 60 * 60 * 1000, last30d: 30 * 24 * 60 * 60 * 1000 }

function realtimeOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (
    principal.scope_kind !== 'platform' || principal.tenant_id !== null ||
    !principal.scope_id?.trim() || !principal.user_id?.trim() || sessionEpoch <= 0
  ) return null
  return ['platform', principal.scope_id, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.scope_kind === 'platform' && (
    principal.permissions.includes('nodes.read') || principal.permissions.includes('platform.admin')
  )
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal)) return null
  const owner = realtimeOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 429) return 'errors.tooManyRequests'
  if (error.code === 'node_inventory_unavailable' || error.code === 'validation_error') {
    return `errors.${error.code}`
  }
  return 'errors.requestFailed'
}

function metricsErrorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'metrics.errors.requestFailed'
  if (error.status === 404 || error.code === 'node_metrics_not_found') return 'metrics.errors.notFound'
  if (error.status === 403) return 'metrics.errors.forbidden'
  if (error.status === 429) return 'metrics.errors.tooManyRequests'
  if (error.code === 'node_metrics_unavailable') return 'metrics.errors.unavailable'
  return 'metrics.errors.requestFailed'
}

type NodeRealtimePoint = { timestamp: number; value: number }

type NodeRealtimeSeries = {
  name: string
  color: string
  points: readonly NodeRealtimePoint[]
}

type NodeRealtimeChartSection = {
  key: string
  title: string
  series: readonly NodeRealtimeSeries[]
  valueFormatter?: (value: number) => string
  showLegend?: boolean
}

type RankingMetric = NodeRealtimeMetric

type NodeRealtimeTableRow = {
  key: string
  item: NodeInventoryItem
  top?: NodeRealtimeTopItem
}

type TrafficCounterSample = {
  observedAt: string
  bytesReceived: number
  bytesSent: number
}

type TrafficIntervalSample = {
  observedAt: string
  bytesReceived: number
  bytesSent: number
}

function counterDelta(previous: number, current: number): number {
  return current < previous ? current : current - previous
}

function trafficCounterSamples(
  items: readonly NodeMetricsHistoryPoint[],
  excludedNIC: string,
): TrafficCounterSample[] {
  const excluded = new Set(excludedNIC.split(/\s+/).map((value) => value.trim()).filter(Boolean))
  return items.flatMap((item) => {
    if (!item.known) return []
    if (item.telemetry) {
      if (item.telemetry.network_interfaces.length > 0) {
        return [{
          observedAt: item.observed_at,
          bytesReceived: item.telemetry.network_interfaces
            .filter((network) => !excluded.has(network.name))
            .reduce((total, network) => total + network.rx_bytes, 0),
          bytesSent: item.telemetry.network_interfaces
            .filter((network) => !excluded.has(network.name))
            .reduce((total, network) => total + network.tx_bytes, 0),
        }]
      }
      if (excluded.size === 0) {
        return [{
          observedAt: item.observed_at,
          bytesReceived: item.telemetry.total_rx_bytes,
          bytesSent: item.telemetry.total_tx_bytes,
        }]
      }
      return []
    }
    if (excluded.size === 0 && item.total_rx_bytes !== null && item.total_tx_bytes !== null) {
      return [{
        observedAt: item.observed_at,
        bytesReceived: item.total_rx_bytes,
        bytesSent: item.total_tx_bytes,
      }]
    }
    return []
  })
}

function trafficIntervalsFromHistory(
  items: readonly NodeMetricsHistoryPoint[],
  excludedNIC: string,
): TrafficIntervalSample[] {
  const samples = trafficCounterSamples(items, excludedNIC)
  if (samples.length < 2) return []
  return samples.slice(1).map((current, index) => {
    const previous = samples[index]!
    return {
      observedAt: current.observedAt,
      bytesReceived: counterDelta(previous.bytesReceived, current.bytesReceived),
      bytesSent: counterDelta(previous.bytesSent, current.bytesSent),
    }
  })
}

function NodeRealtimeChart({
  title,
  ariaLabel,
  emptyMessage,
  renderErrorMessage,
  locale,
  series,
  valueFormatter,
  showLegend = true,
  className,
}: {
  title: string
  ariaLabel: string
  emptyMessage: string
  renderErrorMessage: string
  locale: string
  series: readonly NodeRealtimeSeries[]
  valueFormatter?: (value: number) => string
  showLegend?: boolean
  className?: string
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [failed, setFailed] = useState(false)
  const hasPoints = series.some((item) => item.points.length > 0)
  const themeRevision = useThemeRevision()

  useEffect(() => {
    setFailed(false)
    if (!hasPoints || containerRef.current === null) return

    let disposed = false
    let chart: import('../components/echartsRuntime').ECharts | undefined
    let observer: ResizeObserver | undefined

    void import('../components/echartsRuntime')
      .then((echarts) => {
        if (disposed || containerRef.current === null) return
        const timestamps = Array.from(new Set(series.flatMap((item) => item.points.map((point) => point.timestamp))))
          .sort((left, right) => left - right)
        const tickFormatter = new Intl.DateTimeFormat(locale === 'en-US' ? 'en-US' : 'zh-CN', {
          timeZone: businessTimeZone,
          month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
        })
        chart = echarts.init(containerRef.current)
        observer = new ResizeObserver(() => chart?.resize())
        observer.observe(containerRef.current)
        chart.setOption({
          animation: false,
          color: series.map((item) => item.color),
          backgroundColor: 'transparent',
          title: {
            text: title,
            left: 16,
            top: 12,
            textStyle: { color: themeColor('--cdnca-color-title', '#17233d'), fontSize: 14, fontWeight: 600 },
          },
          grid: { top: 64, right: 24, bottom: 42, left: 36, containLabel: true },
          legend: {
            show: showLegend,
            top: 12,
            left: 'center',
            itemWidth: 12,
            itemHeight: 8,
            textStyle: { color: themeColor('--cdnca-color-text-secondary', '#808695'), fontSize: 12 },
          },
          tooltip: {
            trigger: 'axis',
            confine: true,
            backgroundColor: themeColorAlpha('--cdnca-color-bg-container', '#ffffff', '0.96'),
            borderColor: themeColor('--cdnca-color-border-secondary', '#e8eaec'),
            textStyle: { color: themeColor('--cdnca-color-title', '#17233d') },
            valueFormatter: (value: unknown) => valueFormatter?.(Number(value)) ?? formatBandwidth(Number(value), locale),
          },
          xAxis: {
            type: 'category',
            boundaryGap: false,
            data: timestamps,
            axisPointer: { label: { formatter: ({ value }: { value: string | number }) => formatDateTime(new Date(Number(value)), locale) } },
            axisLine: { lineStyle: { color: themeColor('--cdnca-color-border-secondary', '#e8eaec') } },
            axisTick: { lineStyle: { color: themeColor('--cdnca-color-border-secondary', '#e8eaec') } },
            axisLabel: {
              color: themeColor('--cdnca-color-text-secondary', '#808695'), hideOverlap: true,
              alignMinLabel: 'left', alignMaxLabel: 'right', showMinLabel: true, showMaxLabel: true,
              formatter: (value: string) => tickFormatter.format(new Date(Number(value))),
            },
          },
          yAxis: {
            type: 'value',
            min: 0,
            axisLabel: { color: themeColor('--cdnca-color-text-secondary', '#808695'), formatter: (value: number) => valueFormatter?.(value) ?? formatBandwidth(value, locale) },
            splitLine: { lineStyle: { color: themeColor('--cdnca-color-border-panel', '#edf1f7') } },
          },
          series: series.map((item) => ({
            name: item.name,
            type: 'line',
            smooth: true,
            showSymbol: false,
            connectNulls: false,
            data: timestamps.map((timestamp) => item.points.find((point) => point.timestamp === timestamp)?.value ?? null),
            lineStyle: { color: item.color, width: 2 },
            itemStyle: { color: item.color },
          })),
        })
      })
      .catch(() => {
        if (!disposed) setFailed(true)
      })

    return () => {
      disposed = true
      observer?.disconnect()
      chart?.dispose()
    }
  }, [hasPoints, locale, series, showLegend, themeRevision, title, valueFormatter])

  return (
    <section className={`node-realtime-chart${className ? ` ${className}` : ''}`} aria-label={ariaLabel} role="region">
      {!hasPoints || failed ? <h2>{title}</h2> : null}
      {failed ? <DataState status="error" message={renderErrorMessage} />
        : hasPoints ? <div ref={containerRef} className="node-realtime-chart-canvas" role="img" aria-label={ariaLabel} />
          : <DataState status="empty" message={emptyMessage} />}
    </section>
  )
}

/** A row of the disk ranking's all-mounts detail: a node mount, or a node without mount data. */
interface NodeMountRow {
  key: string
  node: string
  mount?: NodeMount
  status?: 'notReported' | 'versionNotReported'
}

export default function NodeRealtimePage() {
  const { t } = useTranslation('nodeRealtime')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? realtimeOwner(principal, sessionEpoch) : null

  if (!accessToken || !principal) return null
  if (!owner || !canRead(principal)) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const ownerKey = JSON.stringify(owner)
  return <NodeRealtimeContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}

function NodeRealtimeContent({ owner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t, i18n } = useTranslation('nodeRealtime')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const lineageActiveRef = useRef(true)
  // The observed competitor view exposes refresh only; server filters remain
  // unset. Inventory is read 300 per page through the cursor until the last page.
  const status = undefined
  const presence = undefined
  const limit = 300
  const [activeView, setActiveView] = useState('ranking')
  const [rankingMetric, setRankingMetric] = useState<RankingMetric>('bandwidth')
  const [monitorMetric, setMonitorMetric] = useState<RankingMetric>('bandwidth')
  const [rankingRange, setRankingRange] = useState('1m')
  const [monitorRange, setMonitorRange] = useState('1h')
  const [trafficRange, setTrafficRange] = useState('today')
  const [monitorCustomRange, setMonitorCustomRange] = useState<TimeRange | null>(null)
  const [trafficCustomRange, setTrafficCustomRange] = useState<TimeRange | null>(null)
  const [analyticsNodeID, setAnalyticsNodeID] = useState('')
  const [trafficDirections, setTrafficDirections] = useState<string[]>(['outbound'])
  const [excludedNIC, setExcludedNIC] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const advancedButtonRef = useRef<HTMLButtonElement>(null)
  const [externalOnly, setExternalOnly] = useState(true)
  // fz-x11: the disk ranking's "显示全部挂载" detail (NodeTelemetry.mounts, NODE_TELEMETRY_DETAIL v1).
  const [allMounts, setAllMounts] = useState(false)
  const [windowAnchor, setWindowAnchor] = useState(() => Date.now())
  const prefix = useMemo(() => ['node-realtime', ...fixedOwner] as const, [fixedOwner])
  const queryKey = useMemo(
    () => [...prefix, status ?? '', presence ?? '', limit] as const,
    [limit, prefix, presence, status],
  )
  const identity = JSON.stringify(queryKey)
  const activeIdentityRef = useRef(identity)
  activeIdentityRef.current = identity

  const currentSessionAccess = useCallback(
    () => lineageActiveRef.current ? currentAccess(ownerKey) : null,
    [ownerKey],
  )

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token) throw staleRead
      try {
        // 节点超过一页（300）时按游标读全量，不截断（NodeRealtime 300 截断）。
        const all: NodeInventoryItem[] = []
        const seen = new Set<string>()
        let cursor: string | undefined
        do {
          const page = await nodesApi.list(token, { status, presence, limit, ...(cursor ? { cursor } : {}) })
          if (!currentSessionAccess() || activeIdentityRef.current !== identity) throw staleRead
          all.push(...page.items)
          if (cursor) seen.add(cursor)
          cursor = page.next_cursor && !seen.has(page.next_cursor) ? page.next_cursor : undefined
        } while (cursor)
        return { items: all }
      } catch (error) {
        if (!currentSessionAccess() || activeIdentityRef.current !== identity) throw staleRead
        throw error
      }
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const items = query.data?.items ?? []
  const rankingTopQuery = useQuery({
    queryKey: [...prefix, 'top', rankingMetric, rankingRange, externalOnly] as const,
    enabled: activeView === 'ranking',
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token) throw staleRead
      const result = await nodesApi.getNodeRealtimeTop(token, { recentTime: rankingRange, type: rankingMetric, externalOnly })
      if (!currentSessionAccess()) throw staleRead
      return result
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const analyticsNodeValue = items.some((item) => item.id === analyticsNodeID)
    ? analyticsNodeID
    : items[0]?.id
  // 每 300 个节点一次 GET /v1/nodes/metrics/latest?node_id=…（批量），不再每节点一个请求（N+1）。
  const metricChunks = useMemo(() => {
    const ids = [...new Set((query.data?.items ?? []).map((item) => item.id))]
    const chunks: string[][] = []
    for (let index = 0; index < ids.length; index += latestBatchSize) chunks.push(ids.slice(index, index + latestBatchSize))
    return chunks
  }, [query.data])
  const rankingMetricQueries = useQueries({
    queries: metricChunks.map((ids) => ({
      queryKey: [...prefix, 'metrics', ids.join(',')] as const,
      enabled: true,
      queryFn: async ({ signal }: { signal: AbortSignal }) => {
        const token = currentSessionAccess()
        if (!token) throw staleRead
        const result = await nodesApi.getLatestMetricsBatch(token, ids, signal)
        if (!currentSessionAccess()) throw staleRead
        return result
      },
      retry: false,
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
    })),
  })

  // Quick ranges count back from the moment the range was picked (windowAnchor).
  const rangePreset = (key: string, label?: string): TimeRangePreset => ({ key, label, range: (now) => [now.subtract(durations[key], 'millisecond'), now] })
  const monitorPresets = [rangePreset('1h', t('filters.monitorRanges.oneHour')), rangePreset('6h', t('filters.monitorRanges.sixHours')), rangePreset('12h', t('filters.monitorRanges.twelveHours'))]
  // Traffic uses the shared quick ranges (today / last 7 days / last 30 days / custom); the monitor
  // charts keep hour windows because they plot the latest 2000 raw samples (about 5.5 hours at 10s probes).
  const trafficPresets: TimeRangePreset[] = [{ key: 'today', range: (now) => [now.startOf('day'), now] }, rangePreset('last7d'), rangePreset('last30d')]
  const metricsWindow = useMemo(() => {
    const now = new Date(windowAnchor)
    const range = activeView === 'traffic' ? trafficRange : monitorRange
    const custom = activeView === 'traffic' ? trafficCustomRange : monitorCustomRange
    if (range === 'custom' && custom) return { from: custom[0].toDate(), to: custom[1].toDate() }
    if (range === 'today') return { from: dayjs(now).startOf('day').toDate(), to: now }
    return { from: new Date(now.getTime() - (durations[range] ?? durations['1h'])), to: now }
  }, [activeView, monitorCustomRange, monitorRange, trafficCustomRange, trafficRange, windowAnchor])
  const historyNodeID = analyticsNodeValue ?? ''
  const metricsHistoryIdentity = `${historyNodeID}:${metricsWindow.from.toISOString()}:${metricsWindow.to.toISOString()}`
  const metricsHistoryIdentityRef = useRef(metricsHistoryIdentity)
  metricsHistoryIdentityRef.current = metricsHistoryIdentity
  const monitorRealtimeQuery = useQuery({
    queryKey: [...prefix, 'realtime', historyNodeID, monitorMetric, metricsHistoryIdentity, externalOnly] as const,
    enabled: activeView === 'monitoring' && historyNodeID !== '',
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token || !historyNodeID) throw staleRead
      const result = await nodesApi.getNodeRealtimeSeries(token, {
        node: historyNodeID,
        type: monitorMetric,
        externalOnly,
        start: metricsWindow.from.toISOString(),
        end: metricsWindow.to.toISOString(),
        limit: 2000,
      })
      if (!currentSessionAccess()) throw staleRead
      return result
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const trafficQuery = useQuery({
    queryKey: [...prefix, 'traffic', historyNodeID, metricsHistoryIdentity, excludedNIC, externalOnly] as const,
    enabled: activeView === 'traffic' && historyNodeID !== '',
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token || !historyNodeID) throw staleRead
      const result = await nodesApi.getNodeTraffic(token, {
        node: historyNodeID,
        start: metricsWindow.from.toISOString(),
        end: metricsWindow.to.toISOString(),
        excludedNIC,
        externalOnly,
        limit: 2000,
      })
      if (!currentSessionAccess()) throw staleRead
      return result
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const chartQuery = activeView === 'traffic' ? trafficQuery : monitorRealtimeQuery
  const historyFallbackAllowed = (
    activeView === 'monitoring' && (monitorMetric !== 'bandwidth' || !externalOnly) ||
    activeView === 'traffic' && !externalOnly
  ) && !(chartQuery.error instanceof ApiError && [401, 403, 429].includes(chartQuery.error.status))
  const metricsHistoryQuery = useQuery({
    queryKey: [...prefix, 'history', metricsHistoryIdentity],
    enabled: chartQuery.isError && historyFallbackAllowed && historyNodeID !== '',
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token || !historyNodeID) throw staleRead
      try {
        const result = await nodesApi.getMetricsHistory(token, historyNodeID, {
          from: metricsWindow.from.toISOString(),
          to: metricsWindow.to.toISOString(),
          limit: 2000,
        })
        if (!currentSessionAccess() || metricsHistoryIdentityRef.current !== metricsHistoryIdentity) throw staleRead
        return result
      } catch (error) {
        if (!currentSessionAccess() || metricsHistoryIdentityRef.current !== metricsHistoryIdentity) throw staleRead
        throw error
      }
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const chartLoading = historyNodeID !== '' && (chartQuery.isPending || chartQuery.isFetching ||
    chartQuery.isError && historyFallbackAllowed && (metricsHistoryQuery.isPending || metricsHistoryQuery.isFetching))
  const chartError = chartQuery.isError && (!historyFallbackAllowed || metricsHistoryQuery.isError)
    ? historyFallbackAllowed ? metricsHistoryQuery.error : chartQuery.error
    : null
  const retryChart = () => {
    void Promise.all([
      chartQuery.refetch(),
      ...(historyFallbackAllowed ? [metricsHistoryQuery.refetch()] : []),
    ])
  }

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentAccess(ownerKey)) {
        queryClient.removeQueries({ queryKey: prefix })
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) queryClient.removeQueries({ queryKey: prefix })
      })
    }
  }, [ownerKey, prefix, queryClient])

  const refresh = () => {
    setWindowAnchor(Date.now())
    void Promise.all([
      query.refetch(),
      queryClient.refetchQueries({ queryKey: [...prefix, 'top'], type: 'active' }),
      queryClient.refetchQueries({ queryKey: [...prefix, 'metrics'], type: 'active' }),
      queryClient.refetchQueries({ queryKey: [...prefix, 'realtime'], type: 'active' }),
      queryClient.refetchQueries({ queryKey: [...prefix, 'traffic'], type: 'active' }),
      queryClient.refetchQueries({ queryKey: [...prefix, 'history'], type: 'active' }),
    ])
  }
  const metricsRefreshing = rankingMetricQueries.some((result) => result.isFetching) || rankingTopQuery.isFetching ||
    monitorRealtimeQuery.isFetching || trafficQuery.isFetching || metricsHistoryQuery.isFetching
  const language = i18n.resolvedLanguage ?? i18n.language
  const rankingMetrics = new Map<string, NodeMetricsLatest>()
  rankingMetricQueries.forEach((result) => {
    for (const value of result.data?.items ?? []) rankingMetrics.set(value.node_id, value)
  })
  const rankingTopItems = rankingTopQuery.data?.data ?? []
  const rankingTopByNode = new Map(rankingTopItems.map((item) => [item.node_id, item]))
  const rankingValue = (item: NodeInventoryItem): number | null => {
    const top = rankingTopByNode.get(item.id)
    if (top) {
      if (rankingMetric === 'bandwidth') return top.inbound + top.outbound
      return top.inbound
    }
    const value = rankingMetrics.get(item.id)
    if (!value?.known) return null
    if (rankingMetric === 'bandwidth') return externalOnly ? null : (value.tx_bandwidth_bps ?? 0) + (value.rx_bandwidth_bps ?? 0)
    if (rankingMetric === 'connections') return value.active_connections
    if (rankingMetric === 'load') return value.cpu_percent
    return null
  }
  const fallbackRankedItems = items.map((item, index) => ({ item, index, value: rankingValue(item) }))
    .sort((left, right) => {
      if (left.value === null && right.value === null) return left.index - right.index
      if (left.value === null) return 1
      if (right.value === null) return -1
      return right.value - left.value || left.index - right.index
    })
    .map(({ item }) => item)
  const rankedRowsFromTop = rankingTopItems.flatMap((top, index) => {
    const item = items.find((candidate) => candidate.id === top.node_id)
    return item ? [{ key: `${top.node_id}:${top.nic || 'aggregate'}:${index}`, item, top }] : []
  })
  const rankedRows: NodeRealtimeTableRow[] = rankingTopQuery.isSuccess && rankedRowsFromTop.length > 0
    ? [
      ...rankedRowsFromTop,
      ...fallbackRankedItems
        .filter((item) => !rankingTopByNode.has(item.id))
        .map((item) => ({ key: item.id, item })),
    ]
    : fallbackRankedItems.map((item) => ({ key: item.id, item }))
  const nodeOptions = items.map((item) => ({ value: item.id, label: item.name }))
  const metricValue = (
    row: NodeRealtimeTableRow,
    read: (metrics: NodeMetricsLatest) => number | null,
    topRead?: (top: NodeRealtimeTopItem) => number,
  ): number | null => {
    const top = row.top
    if (top && topRead) return topRead(top)
    const value = rankingMetrics.get(row.item.id)
    if (!value?.known) return null
    if (rankingMetric === 'bandwidth' && externalOnly) return null
    return read(value)
  }
  const telemetryFor = (row: NodeRealtimeTableRow) => rankingMetrics.get(row.item.id)?.telemetry
  const primaryNIC = (row: NodeRealtimeTableRow) => row.top?.nic || (externalOnly ? undefined : telemetryFor(row)?.network_interfaces[0]?.name)
  const rootDisk = (row: NodeRealtimeTableRow) => {
    if (rankingMetric === 'disk' && row.top) {
      const telemetryDisk = telemetryFor(row)?.disks.find((disk) => disk.path === row.top?.nic)
      return {
        path: row.top.nic,
        space_percent: row.top.inbound,
        inode_percent: telemetryDisk?.inode_percent,
      }
    }
    return telemetryFor(row)?.disks.find((disk) => disk.path === '/') ?? telemetryFor(row)?.disks[0]
  }
  const formatPercent = (value: number | null): string => value === null ? t('telemetry.notReported') : `${value.toFixed(1)}%`
  const formatMemoryPercent = (row: NodeRealtimeTableRow): string => {
    const value = rankingMetrics.get(row.item.id)
    if (!value?.known || value.memory_used_bytes === null || value.memory_total_bytes === null || value.memory_total_bytes <= 0) {
      return t('telemetry.notReported')
    }
    return `${((value.memory_used_bytes / value.memory_total_bytes) * 100).toFixed(1)}%`
  }
  const sortable = (
    title: string,
    key: string,
    read: (row: NodeRealtimeTableRow) => number | null,
    render: (row: NodeRealtimeTableRow) => ReactNode,
  ): TableColumnsType<NodeRealtimeTableRow>[number] => ({
    title,
    key,
    width: 120,
    sorter: (left, right) => (read(left) ?? -Infinity) - (read(right) ?? -Infinity),
    render: (_value, item) => render(item),
  })
  const baseColumns: TableColumnsType<NodeRealtimeTableRow> = [
    {
      title: t('columns.rank'), key: 'rank', width: 100,
      render: (_value, _item, index) => index + 1,
    },
    {
      title: t('columns.name'), key: 'name', width: 180, ellipsis: true,
      render: (_value, row) => t('columns.nodeDisplay', { name: row.item.name, id: row.item.display_id }),
    },
    {
      title: t('columns.nic'), key: 'nic', width: 100,
      render: (_value, row) => primaryNIC(row) ?? t(externalOnly ? 'networkSelection.unavailable' : 'telemetry.notReported'),
    },
  ]
  const columns: TableColumnsType<NodeRealtimeTableRow> = rankingMetric === 'bandwidth'
    ? [
      ...baseColumns,
      sortable(t('columns.egressBandwidth'), 'egress-bandwidth', (row) => metricValue(row, (value) => value.tx_bandwidth_bps, (top) => top.outbound), (row) => {
        const value = metricValue(row, (metrics) => metrics.tx_bandwidth_bps, (top) => top.outbound)
        return value === null ? t('telemetry.notReported') : formatBandwidth(value, language)
      }),
      sortable(t('columns.ingressBandwidth'), 'ingress-bandwidth', (row) => metricValue(row, (value) => value.rx_bandwidth_bps, (top) => top.inbound), (row) => {
        const value = metricValue(row, (metrics) => metrics.rx_bandwidth_bps, (top) => top.inbound)
        return value === null ? t('telemetry.notReported') : formatBandwidth(value, language)
      }),
    ]
    : rankingMetric === 'connections'
      ? [
        baseColumns[0]!, baseColumns[1]!,
        sortable(t('columns.connections'), 'connections', (row) => metricValue(row, (value) => value.active_connections, (top) => top.inbound), (row) => {
          const value = metricValue(row, (metrics) => metrics.active_connections, (top) => top.inbound)
          return value === null ? t('telemetry.notReported') : String(value)
        }),
        sortable(t('columns.ddosDrops'), 'ddos-drops', (row) => {
          const drops = telemetryFor(row)?.ddos_drops
          return drops === undefined ? null : drops.reduce((total, drop) => total + drop.packets, 0)
        }, (row) => {
          const telemetry = telemetryFor(row)
          if (!telemetry) return t('telemetry.notReported')
          const drops = telemetry.ddos_drops ?? []
          if (drops.length === 0) return t('ddosDrops.none')
          return (
            <span title={t('ddosDrops.hint')}>
              {drops.map((drop) => `${t(`ddosDrops.kinds.${drop.kind}`)} ${drop.packets}`).join(' / ')}
            </span>
          )
        }),
      ]
      : rankingMetric === 'load'
        ? [
          baseColumns[0]!, baseColumns[1]!,
          sortable(t('columns.cpuUsage'), 'cpu', (row) => metricValue(row, (value) => value.cpu_percent, (top) => top.inbound), (row) => formatPercent(metricValue(row, (value) => value.cpu_percent, (top) => top.inbound))),
          sortable(t('columns.memoryUsage'), 'memory', (row) => {
            const value = rankingMetrics.get(row.item.id)
            return value?.known && value.memory_total_bytes && value.memory_total_bytes > 0
              ? (value.memory_used_bytes ?? 0) / value.memory_total_bytes * 100
              : null
          }, formatMemoryPercent),
          sortable(t('columns.systemLoad'), 'load', (row) => telemetryFor(row)?.system_load?.one_minute ?? null, (row) => {
            const value = telemetryFor(row)?.system_load?.one_minute
            return value === undefined ? t('telemetry.notReported') : value.toFixed(2)
          }),
        ]
        : [
          baseColumns[0]!, baseColumns[1]!,
          {
            title: t('columns.partition'), key: 'partition', width: 120,
            render: (_value, row) => rootDisk(row)?.path ?? t('telemetry.notReported'),
          },
          sortable(t('columns.spaceUsage'), 'space', (row) => rootDisk(row)?.space_percent ?? null, (row) => {
            const value = rootDisk(row)?.space_percent
            return value === undefined ? t('telemetry.notReported') : `${value.toFixed(1)}%`
          }),
          sortable(t('columns.inodeUsage'), 'inode', (row) => rootDisk(row)?.inode_percent ?? null, (row) => {
            const value = rootDisk(row)?.inode_percent
            return value === undefined ? t('telemetry.notReported') : `${value.toFixed(1)}%`
          }),
        ]
  // One row per node mount; a node whose agent does not declare NODE_TELEMETRY_DETAIL gets one "version not reported" row.
  const mountRows: NodeMountRow[] = items.flatMap((item): NodeMountRow[] => {
    const value = rankingMetrics.get(item.id)
    if (!value?.known) return [{ key: item.id, node: item.name, status: 'notReported' }]
    if (!value.telemetry_detail) return [{ key: item.id, node: item.name, status: 'versionNotReported' }]
    return (value.telemetry?.mounts ?? []).map((mount) => ({ key: `${item.id}:${mount.path}`, node: item.name, mount }))
  })
  const yesNo = (value: boolean) => t(value ? 'mounts.yes' : 'mounts.no')
  const mountColumns: TableColumnsType<NodeMountRow> = [
    { title: t('columns.name'), key: 'node', width: 160, ellipsis: true, render: (_value, row) => row.node },
    { title: t('mounts.columns.path'), key: 'path', width: 220, ellipsis: true, render: (_value, row) => row.mount?.path ?? '—' },
    { title: t('mounts.columns.device'), key: 'device', width: 90, render: (_value, row) => row.mount?.device ?? '—' },
    { title: t('mounts.columns.fstype'), key: 'fstype', width: 100, render: (_value, row) => row.mount ? row.mount.fstype || '—' : '—' },
    { title: t('mounts.columns.readOnly'), key: 'readOnly', width: 70, render: (_value, row) => row.mount ? yesNo(row.mount.read_only) : '—' },
    { title: t('mounts.columns.bind'), key: 'bind', width: 70, render: (_value, row) => row.mount ? yesNo(row.mount.bind) : '—' },
    {
      title: t('mounts.columns.ranking'), key: 'ranking', width: 220,
      render: (_value, row) => {
        if (!row.mount) return t(row.status === 'versionNotReported' ? 'mounts.versionNotReported' : 'telemetry.notReported')
        return row.mount.filter_reason ? t('mounts.filtered', { reason: t(`mounts.reasons.${row.mount.filter_reason}`) }) : t('mounts.ranked')
      },
    },
  ]
  const historyItems = metricsHistoryQuery.data?.items ?? []
  const chartPoints = (read: (point: NodeMetricsHistoryPoint) => number | null): NodeRealtimePoint[] => (
    historyItems.flatMap((point) => {
      const value = point.known ? read(point) : null
      return value === null ? [] : [{ timestamp: Date.parse(point.observed_at), value }]
    })
  )
  const formatMetricNumber = (value: number): string => new Intl.NumberFormat(language === 'en-US' ? 'en-US' : 'zh-CN', { maximumFractionDigits: 2 }).format(value)
  const formatChartPercent = (value: number): string => `${value.toFixed(2)}%`
  const historyMonitoringSeries: NodeRealtimeSeries[] = monitorMetric === 'bandwidth'
    ? [
      { name: t('charts.inboundBandwidth'), color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: chartPoints((point) => point.rx_bandwidth_bps) },
      { name: t('charts.outboundBandwidth'), color: themeColor('--cdnca-chart-traffic-out', '#61d9a5'), points: chartPoints((point) => point.tx_bandwidth_bps) },
    ]
    : monitorMetric === 'connections'
      ? [{ name: t('filters.metrics.connections'), color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: chartPoints((point) => point.active_connections) }]
      : monitorMetric === 'load'
        ? [{ name: t('filters.metrics.load'), color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: chartPoints((point) => point.cpu_percent) }]
        : []
  const monitoringSeriesName = (name: string): string => ({
    inbound: t('charts.inboundBandwidth'),
    outbound: t('charts.outboundBandwidth'),
    connections: t('filters.metrics.connections'),
    cpu: t('charts.cpuUsage'),
    memory: t('charts.memoryUsage'),
    system_load: t('charts.systemLoad'),
    space: t('charts.spaceUsage'),
    inode: t('charts.inodeUsage'),
  }[name] ?? name)
  const monitoringSeriesColor = (name: string): string => monitorMetric === 'load' || name === 'inbound' || name === 'cpu' || name === 'space'
    ? themeColor('--cdnca-chart-traffic-in', '#5b8ff9')
    : themeColor('--cdnca-chart-traffic-out', '#61d9a5')
  const realtimeMonitoringSections: NodeRealtimeChartSection[] = monitorRealtimeQuery.data
    ? Object.entries(monitorRealtimeQuery.data.data).flatMap(([group, rawSeries]): NodeRealtimeChartSection[] => {
      const toSeries = (item: typeof rawSeries[number]): NodeRealtimeSeries => ({
        name: monitoringSeriesName(item.name),
        color: monitoringSeriesColor(item.name),
        points: item.data.map(([timestamp, value]) => ({ timestamp, value })),
      })
      if (monitorMetric === 'bandwidth') {
        return [{
          key: `bandwidth:${group}`,
          title: group === 'all' ? t('charts.monitoringTitle') : group,
          series: rawSeries.map(toSeries),
          valueFormatter: (value: number) => formatBandwidth(value, language),
          showLegend: true,
        }]
      }
      if (monitorMetric === 'connections') {
        return [{
          key: `connections:${group}`,
          title: t('charts.connectionsTitle'),
          series: rawSeries.map(toSeries),
          valueFormatter: formatMetricNumber,
          showLegend: false,
        }]
      }
      if (monitorMetric === 'load') {
        return rawSeries.map((item) => ({
          key: `load:${item.name}`,
          title: monitoringSeriesName(item.name),
          series: [toSeries(item)],
          valueFormatter: item.name === 'system_load' ? formatMetricNumber : formatChartPercent,
          showLegend: false,
        }))
      }
      return [{
        key: `disk:${group}`,
        title: t('charts.partitionTitle', { path: group }),
        series: rawSeries.map(toSeries),
        valueFormatter: formatChartPercent,
        showLegend: true,
      }]
    })
    : []
  const historyMonitoringSections: NodeRealtimeChartSection[] = (() => {
    if (monitorMetric === 'bandwidth') {
      return [{
        key: 'history:bandwidth', title: t('charts.monitoringTitle'), series: historyMonitoringSeries,
        valueFormatter: (value: number) => formatBandwidth(value, language), showLegend: true,
      }]
    }
    if (monitorMetric === 'connections') {
      return [{
        key: 'history:connections', title: t('charts.connectionsTitle'), series: historyMonitoringSeries,
        valueFormatter: formatMetricNumber, showLegend: false,
      }]
    }
    if (monitorMetric === 'load') {
      const sections = [
        { key: 'cpu', title: t('charts.cpuUsage'), points: chartPoints((point) => point.cpu_percent), valueFormatter: formatChartPercent },
        { key: 'system_load', title: t('charts.systemLoad'), points: chartPoints((point) => point.telemetry?.system_load?.one_minute ?? null), valueFormatter: formatMetricNumber },
        { key: 'memory', title: t('charts.memoryUsage'), points: chartPoints((point) => point.memory_total_bytes && point.memory_total_bytes > 0 ? point.memory_used_bytes === null ? null : 100 * point.memory_used_bytes / point.memory_total_bytes : null), valueFormatter: formatChartPercent },
      ]
      return sections.filter((section) => section.points.length > 0).map((section) => ({
        key: `history:load:${section.key}`, title: section.title,
        series: [{ name: section.title, color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: section.points }],
        valueFormatter: section.valueFormatter, showLegend: false,
      }))
    }
    const paths = Array.from(new Set(historyItems.flatMap((point) => point.telemetry?.disks.map((disk) => disk.path) ?? []))).sort()
    return paths.map((path) => ({
      key: `history:disk:${path}`, title: t('charts.partitionTitle', { path }),
      series: [
        { name: t('charts.spaceUsage'), color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: chartPoints((point) => point.telemetry?.disks.find((disk) => disk.path === path)?.space_percent ?? null) },
        { name: t('charts.inodeUsage'), color: themeColor('--cdnca-chart-traffic-out', '#61d9a5'), points: chartPoints((point) => point.telemetry?.disks.find((disk) => disk.path === path)?.inode_percent ?? null) },
      ],
      valueFormatter: formatChartPercent, showLegend: true,
    }))
  })()
  const monitoringSections = monitorRealtimeQuery.isSuccess ? realtimeMonitoringSections : externalOnly && monitorMetric === 'bandwidth' ? [] : historyMonitoringSections
  const trafficItems: NodeTrafficItem[] = trafficQuery.data?.data ?? []
  const trafficHistoryItems = metricsHistoryQuery.isSuccess && !externalOnly
    ? trafficIntervalsFromHistory(metricsHistoryQuery.data.items, excludedNIC)
    : []
  const trafficPoint = (item: NodeTrafficItem | TrafficIntervalSample): NodeRealtimePoint => ({
    timestamp: Date.parse(
      'observedAt' in item
        ? item.observedAt
        : `${item.create_at.replace(' ', 'T')}Z`,
    ),
    value: 0,
  })
  const trafficSeries: NodeRealtimeSeries[] = trafficQuery.isSuccess
    ? trafficDirections.length === 0 ? [] : [
      ...(trafficDirections.includes('inbound') ? [{ name: t('filters.trafficTypes.inbound'), color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: trafficItems.map((item) => ({ ...trafficPoint(item), value: item.bytes_received })) }] : []),
      ...(trafficDirections.includes('outbound') ? [{ name: t('filters.trafficTypes.outbound'), color: themeColor('--cdnca-chart-traffic-out', '#61d9a5'), points: trafficItems.map((item) => ({ ...trafficPoint(item), value: item.bytes_sent })) }] : []),
    ]
    : trafficDirections.length === 0 ? [] : [
      ...(trafficDirections.includes('inbound') ? [{ name: t('filters.trafficTypes.inbound'), color: themeColor('--cdnca-chart-traffic-in', '#5b8ff9'), points: trafficHistoryItems.map((item) => ({ ...trafficPoint(item), value: item.bytesReceived })) }] : []),
      ...(trafficDirections.includes('outbound') ? [{ name: t('filters.trafficTypes.outbound'), color: themeColor('--cdnca-chart-traffic-out', '#61d9a5'), points: trafficHistoryItems.map((item) => ({ ...trafficPoint(item), value: item.bytesSent })) }] : []),
    ]
  const trafficTotal = trafficQuery.isSuccess && trafficItems.length > 0
    ? trafficItems.reduce((total, item) => total +
      (trafficDirections.includes('inbound') ? item.bytes_received : 0) +
      (trafficDirections.includes('outbound') ? item.bytes_sent : 0), 0)
    : trafficQuery.isSuccess ? null
    : trafficHistoryItems.length > 0
      ? trafficHistoryItems.reduce((total, item) => total +
        (trafficDirections.includes('inbound') ? item.bytesReceived : 0) +
        (trafficDirections.includes('outbound') ? item.bytesSent : 0), 0)
      : null
  const error = query.error instanceof ApiError ? query.error : null
  if (error?.status === 403) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }
  if (error?.status === 404) {
    return (
      <Result
        className="identity-page"
        status="404"
        title={t('errors.notFoundTitle')}
        subTitle={t('errors.notFoundDescription')}
      />
    )
  }

  // 出口网卡开关紧跟在筛选条的「刷新」后同一行，说明收进问号提示。
  const showEgress = activeView === 'ranking' && rankingMetric === 'bandwidth' || activeView === 'monitoring' && monitorMetric === 'bandwidth' || activeView === 'traffic'
  const egressHint = t(externalOnly ? 'networkSelection.hint' : 'networkSelection.all')
  const egressControl = showEgress ? (
    <div className="node-realtime-control-group node-realtime-egress-item">
      <Checkbox id="node-realtime-external-only" name="node-realtime-external-only" checked={externalOnly} onChange={(event) => setExternalOnly(event.target.checked)}>{t('networkSelection.auto')}</Checkbox>
      <Tooltip title={egressHint} trigger={['hover', 'focus', 'click']} styles={{ root: { maxWidth: 360 } }}>
        <button type="button" className="node-realtime-egress-help" aria-label={egressHint}><CircleHelp size={14} aria-hidden /></button>
      </Tooltip>
    </div>
  ) : null
  // 节点流量的次要条件（排除网卡）收进行尾「高级筛选」下拉，筛选条在桌面保持一行。
  const advancedCount = excludedNIC.trim() ? 1 : 0
  const closeAdvanced = () => { setAdvancedOpen(false); advancedButtonRef.current?.focus() }
  const advancedFilters = (
    <div className="node-realtime-control-group node-realtime-advanced-item">
      <Popover
        trigger="click"
        placement="bottomRight"
        arrow={false}
        open={advancedOpen}
        onOpenChange={setAdvancedOpen}
        forceRender
        classNames={{ root: 'node-realtime-advanced-popover' }}
        content={(
          <div id="node-realtime-advanced-panel" className="node-realtime-advanced-panel" role="group" aria-label={t('filters.advanced')}
            onKeyDown={(event) => { if (event.key === 'Escape' || event.key === 'Enter') closeAdvanced() }}>
            <label className="node-realtime-advanced-field" htmlFor="node-realtime-excluded-nic">
              <span className="node-realtime-advanced-label">{t('filters.excludeNICLabel')}</span>
              <Input
                id="node-realtime-excluded-nic"
                name="node-realtime-excluded-nic"
                aria-label={t('filters.excludeNICLabel')}
                placeholder={t('filters.excludeNICPlaceholder')}
                allowClear
                value={excludedNIC}
                onChange={(event) => setExcludedNIC(event.target.value)}
              />
            </label>
          </div>
        )}
      >
        <Button
          ref={advancedButtonRef}
          className={`node-realtime-advanced-toggle${advancedCount ? ' node-realtime-advanced-toggle--active' : ''}`}
          aria-expanded={advancedOpen}
          aria-controls="node-realtime-advanced-panel"
          aria-label={advancedCount ? t('filters.advancedActive', { count: advancedCount }) : t('filters.advanced')}
        >
          <span>{advancedCount ? `${t('filters.advanced')} · ${advancedCount}` : t('filters.advanced')}</span>
          <ChevronDown size={14} aria-hidden className="node-realtime-advanced-chevron" />
        </Button>
      </Popover>
    </div>
  )
  const egressUnavailable = showEgress && externalOnly && items.some((item) => {
    if (activeView !== 'ranking' && item.id !== historyNodeID) return false
    const result = rankingMetrics.get(item.id)
    return result && result.telemetry?.network_selection?.source !== 'default_route'
  })

  return (
    <section className="identity-page node-realtime-page">
      <header className="identity-page-header">
        <div>
          <Typography.Title level={3}>{t('title')}</Typography.Title>
        </div>
      </header>

      <Tabs
        className="node-realtime-tabs"
        activeKey={activeView}
        onChange={(value) => { setWindowAnchor(Date.now()); setActiveView(value) }}
        items={[
          { key: 'ranking', label: t('views.ranking') },
          { key: 'monitoring', label: t('views.monitoring') },
          { key: 'traffic', label: t('views.traffic') },
        ]}
      />

      {activeView === 'ranking' ? (
        <div className="node-realtime-controls node-realtime-controls--ranking" aria-label={t('filters.controls')}>
          <div className="node-realtime-control-group node-realtime-control-group--metric">
            <span className="node-realtime-control-label">{t('filters.metricLabel')}</span>
            <Radio.Group
              aria-label={t('filters.metricLabel')}
              name="node-realtime-ranking-metric"
              optionType="button"
              value={rankingMetric}
              onChange={(event) => setRankingMetric(event.target.value)}
              options={[
                { value: 'bandwidth', label: t('filters.metrics.bandwidth') },
                { value: 'connections', label: t('filters.metrics.connections') },
                { value: 'load', label: t('filters.metrics.load') },
                { value: 'disk', label: t('filters.metrics.disk') },
              ]}
            />
          </div>
          <div className="node-realtime-control-group node-realtime-control-group--ranking-range">
            <span className="node-realtime-control-label">{t('filters.rangeLabel')}</span>
            <Radio.Group
              aria-label={t('filters.rangeLabel')}
              name="node-realtime-ranking-range"
              optionType="button"
              value={rankingRange}
              onChange={(event) => setRankingRange(event.target.value)}
              options={[
                { value: '1m', label: t('filters.ranges.oneMinute') },
                { value: '5m', label: t('filters.ranges.fiveMinutes') },
                { value: '30m', label: t('filters.ranges.thirtyMinutes') },
                { value: '1h', label: t('filters.ranges.oneHour') },
              ]}
            />
          </div>
          <div className="node-realtime-control-group node-realtime-refresh-item">
            <span className="node-realtime-control-label" aria-hidden="true" />
            <Button type="primary" className="node-realtime-refresh" icon={<RefreshCw size={14} />} loading={query.isFetching || metricsRefreshing} onClick={refresh}>
              {t('actions.refresh')}
            </Button>
          </div>
          {egressControl}
        </div>
      ) : activeView === 'monitoring' ? (
        <div className="node-realtime-controls node-realtime-controls--monitoring node-realtime-controls--inline" aria-label={t('filters.controls')}>
          <div className="node-realtime-control-group node-realtime-control-group--metric">
            <span className="node-realtime-control-label">{t('filters.metricLabel')}</span>
            <Radio.Group
              aria-label={t('filters.metricLabel')}
              name="node-realtime-monitor-metric"
              optionType="button"
              value={monitorMetric}
              onChange={(event) => setMonitorMetric(event.target.value)}
              options={[
                { value: 'bandwidth', label: t('filters.metrics.bandwidth') },
                { value: 'connections', label: t('filters.metrics.connections') },
                { value: 'load', label: t('filters.metrics.load') },
                { value: 'disk', label: t('filters.metrics.disk') },
              ]}
            />
          </div>
          <div className={`node-realtime-control-group node-realtime-control-group--monitor-range${monitorRange === 'custom' ? ' node-realtime-control-group--custom-range' : ''}`}>
            <span className="node-realtime-control-label">{t('filters.rangeLabel')}</span>
            <div className="node-realtime-range-control">
              <TimeRangeFilter id="node-realtime-monitor-range" label={t('filters.rangeLabel')} presets={monitorPresets} compact
                value={{ preset: monitorRange, range: monitorCustomRange }}
                onChange={({ preset, range }) => { setWindowAnchor(Date.now()); setMonitorRange(preset); setMonitorCustomRange(range) }} />
            </div>
          </div>
          <div className="node-realtime-control-group node-realtime-control-group--node">
            <span className="node-realtime-control-label">{t('filters.nodeLabel')}</span>
            <Select
              id="node-realtime-monitor-node"
              aria-label={t('filters.nodeLabel')}
              loading={query.isPending}
              options={nodeOptions}
              placeholder={t('filters.nodePlaceholder')}
              showSearch
              optionFilterProp="label"
              value={analyticsNodeValue}
              onChange={setAnalyticsNodeID}
            />
          </div>
          <div className="node-realtime-control-group node-realtime-refresh-item">
            <span className="node-realtime-control-label" aria-hidden="true" />
            <Button type="primary" className="node-realtime-refresh" icon={<RefreshCw size={14} />} loading={query.isFetching || metricsRefreshing} onClick={refresh}>
              {t('actions.refresh')}
            </Button>
          </div>
          {egressControl}
        </div>
      ) : (
        <div className="node-realtime-controls node-realtime-controls--traffic node-realtime-controls--inline" aria-label={t('filters.controls')}>
          <div className="node-realtime-control-group node-realtime-control-group--traffic-types">
            <span className="node-realtime-control-label">{t('filters.typeLabel')}</span>
            <Checkbox.Group
              name="node-realtime-traffic-direction"
              aria-label={t('filters.typeLabel')}
              className="node-realtime-traffic-types"
              value={trafficDirections}
              options={[
                { value: 'outbound', label: t('filters.trafficTypes.outbound') },
                { value: 'inbound', label: t('filters.trafficTypes.inbound') },
              ]}
              onChange={(values) => setTrafficDirections(values.map(String))}
            />
          </div>
          <div className={`node-realtime-control-group node-realtime-control-group--traffic-range${trafficRange === 'custom' ? ' node-realtime-control-group--custom-range' : ''}`}>
            <span className="node-realtime-control-label">{t('filters.rangeLabel')}</span>
            <div className="node-realtime-range-control">
              <TimeRangeFilter id="node-realtime-traffic-range" label={t('filters.rangeLabel')} presets={trafficPresets} compact
                value={{ preset: trafficRange, range: trafficCustomRange }}
                onChange={({ preset, range }) => { setWindowAnchor(Date.now()); setTrafficRange(preset); setTrafficCustomRange(range) }} />
            </div>
          </div>
          <div className="node-realtime-control-group node-realtime-control-group--node">
            <span className="node-realtime-control-label">{t('filters.nodeLabel')}</span>
            <Select
              id="node-realtime-traffic-node"
              aria-label={t('filters.nodeLabel')}
              loading={query.isPending}
              options={nodeOptions}
              placeholder={t('filters.nodePlaceholder')}
              showSearch
              optionFilterProp="label"
              value={analyticsNodeValue}
              onChange={setAnalyticsNodeID}
            />
          </div>
          <div className="node-realtime-control-group node-realtime-refresh-item">
            <span className="node-realtime-control-label" aria-hidden="true" />
            <Button type="primary" className="node-realtime-refresh" icon={<RefreshCw size={14} />} loading={query.isFetching || metricsRefreshing} onClick={refresh}>
              {t('actions.refresh')}
            </Button>
          </div>
          {egressControl}
          {advancedFilters}
        </div>
      )}

      {egressUnavailable ? (
        <div className="node-realtime-network-selection">
          <Typography.Text type="warning" role="status">{t('networkSelection.unavailableHint')}</Typography.Text>
        </div>
      ) : null}

      {query.isPending ? (
        <DataState status="loading" message={t('data.loading')} />
      ) : query.isError ? (
        <DataState
          status="error"
          message={t(errorKey(query.error))}
          onRetry={() => void query.refetch()}
        />
      ) : activeView === 'ranking' ? (
        <div className="node-realtime-table-scroll" aria-busy={query.isFetching}>
          <Table<NodeRealtimeTableRow>
            columns={columns}
            dataSource={rankedRows}
            pagination={false}
            rowKey="key"
            size="small"
            locale={{ emptyText: t('data.empty') }}
          />
          {rankingMetric === 'disk' ? (
            <div className="node-realtime-network-selection">
              <Checkbox id="node-realtime-all-mounts" name="node-realtime-all-mounts" checked={allMounts} onChange={(event) => setAllMounts(event.target.checked)}>{t('mounts.showAll')}</Checkbox>
              <Typography.Text type="secondary">{t('mounts.hint')}</Typography.Text>
            </div>
          ) : null}
          {rankingMetric === 'disk' && allMounts ? (
            <Table<NodeMountRow>
              data-testid="node-realtime-all-mounts"
              columns={mountColumns}
              dataSource={mountRows}
              pagination={mountRows.length > 50 ? { pageSize: 50, showSizeChanger: false } : false}
              rowKey="key"
              size="small"
              locale={{ emptyText: t('data.empty') }}
            />
          ) : null}
        </div>
      ) : chartLoading ? (
        <DataState status="loading" message={t('data.historyLoading')} />
      ) : chartError ? (
        <DataState status="error" message={t(metricsErrorKey(chartError))} onRetry={retryChart} />
      ) : activeView === 'monitoring' ? (
        <div className="node-realtime-monitoring-charts">
          {monitoringSections.length > 0 ? monitoringSections.map((section) => (
            <NodeRealtimeChart
              key={section.key}
              ariaLabel={t('charts.monitoringTitle')}
              emptyMessage={t('data.historyUnavailable')}
              locale={language}
              renderErrorMessage={t('charts.renderFailed')}
              series={section.series}
              showLegend={section.showLegend}
              title={section.title}
              valueFormatter={section.valueFormatter}
            />
          )) : (
            <NodeRealtimeChart
              ariaLabel={t('charts.monitoringTitle')}
              emptyMessage={t('data.historyUnavailable')}
              locale={language}
              renderErrorMessage={t('charts.renderFailed')}
              series={[]}
              title={t('charts.monitoringTitle')}
            />
          )}
        </div>
      ) : activeView === 'traffic' ? (
        <div className="node-realtime-traffic-result">
          <div className="node-realtime-traffic-total">{trafficTotal === null ? t('traffic.totalUnknown') : formatBytes(trafficTotal, language)}</div>
          <NodeRealtimeChart
            ariaLabel={t('traffic.chartTitle')}
            className="node-realtime-traffic-chart"
            emptyMessage={t('data.historyUnavailable')}
            locale={language}
            renderErrorMessage={t('charts.renderFailed')}
            series={trafficSeries}
            title={t('traffic.chartTitle')}
            valueFormatter={(value) => formatBytes(value, language)}
          />
        </div>
      ) : null}

    </section>
  )
}
