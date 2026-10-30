import type { ReactNode } from 'react'
import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Result } from 'antd'
import type { TFunction } from 'i18next'
import { Activity, CheckCircle2, ChevronDown, CircleAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import { analyticsApi, type AnalyticsBlockedIPCountResponse, type AnalyticsBlockedIPTrendResponse, type AnalyticsFilter, type AnalyticsPeakBandwidthResponse, type AnalyticsRankResponse, type AnalyticsSummaryResponse, type AnalyticsTrendResponse } from '../api/analytics'
import { DataState } from '../components/DataState'
import { installationLockQueryKey, useInstallationLockCheck } from '../components/useInstallationLockCheck'
import { DashboardAnalyticsView } from '../components/DashboardOverview'
import { useChartTheme } from '../components/useChartTheme'
import { ResourceID } from '../components/ResourceID'
import {
  dashboardApi,
  formatDashboardBytes,
  formatDashboardInteger,
  formatDashboardLoginSource,
  type AdminDashboard,
  type AdminDashboardRange,
  type AdminProfileStats,
  type DashboardAnalyticsOverview,
  type DashboardSection,
  type DashboardUnavailableReason,
  type OperationAmountPoint,
  type OperationCountPoint,
} from '../api/dashboard'
import type { InstallationLock } from '../api/installationLock'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/adminHomeParity'
import { businessTimeZone, formatNumber, formatQuota } from '../i18n/formatters'
import { formatAnalyticsBandwidth, formatAnalyticsBytes } from '../i18n/analyticsUnits'
import '../styles/adminHomeReference.css'
import { peakHourlyBandwidth } from './adminHomeMetrics'
import { themeColor, themeColorAlpha } from '../theme/themeColor'

interface Metric {
  label: string
  value: string
  tone?: 'danger' | 'success'
}

type AdminDashboardOwner = readonly ['platform', string, null, string, number]
type AdminAnalyticsRange = 'today' | 'yesterday' | 'seven_days' | 'thirty_days'
type AdminAnalyticsRankDimension = 'domain' | 'url' | 'ip' | 'region' | 'carrier'
const staleAdminDashboardRead = new Error('stale admin dashboard read')

function adminDashboardOwner(principal: Principal, sessionEpoch: number): AdminDashboardOwner | null {
  if (
    principal.scope_kind !== 'platform' ||
    !principal.scope_id ||
    principal.tenant_id !== null ||
    !principal.user_id ||
    !sessionEpoch
  ) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function currentAdminDashboardAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !principal.permissions.includes('platform.admin')) return null
  const owner = adminDashboardOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

type EntitlementRefreshOutcome = 'in_progress' | 'not_done' | 'unknown' | 'applied' | 'locked' | 'failed'
type DashboardEntitlement = AdminDashboard['entitlement'] extends DashboardSection<infer T> ? T : never
type EntitlementReread =
  | { kind: 'pending' }
  | { kind: 'failed' }
  | { kind: 'confirmed'; serial?: number; status: DashboardEntitlement['status']; verifiedAt?: string; effective: boolean }

// B18 / LIC-REC-03: control-api entitlement refresh outcomes. Only an error
// the server marks not_applied may say "unchanged"; a lost COMMIT answer,
// 503/504 and network errors may have installed the new lease ("unknown"),
// and an audit failure after install is "applied". Both re-read the lease.
// A locked controller refuses the refresh (423) and runs the lock check.
function entitlementRefreshOutcome(error: unknown): EntitlementRefreshOutcome {
  if (!(error instanceof ApiError)) return 'failed'
  if (error.code === 'entitlement_refresh_in_progress') return 'in_progress'
  if (error.code === 'installation_locked') return 'locked'
  if (error.code === 'entitlement_refresh_failed') return error.outcome === 'not_applied' ? 'not_done' : 'unknown'
  if (error.code === 'entitlement_refresh_audit_failed') return error.outcome === 'applied' ? 'applied' : 'unknown'
  if (error.code === 'entitlement_refresh_unknown' || error.code === 'entitlement_refresh_timeout' ||
    error.code === 'network_error') return 'unknown'
  return 'failed'
}

const refreshOutcomeKey: Record<EntitlementRefreshOutcome, string> = {
  in_progress: 'refreshInProgress', not_done: 'refreshNotDone', unknown: 'refreshUnknown', applied: 'refreshApplied',
  locked: 'refreshLocked', failed: 'refreshFailed',
}

/* The re-read shows the check took effect only when the persisted serial or
 * check time moved past what the card showed when the check started. */
function entitlementCheckEffective(before: DashboardEntitlement | undefined, after: DashboardEntitlement): boolean {
  if ((after.current_serial ?? 0) > (before?.current_serial ?? 0)) return true
  if (!after.last_verified_at) return false
  return !before?.last_verified_at || Date.parse(after.last_verified_at) > Date.parse(before.last_verified_at)
}

function errorMessage(error: unknown, t: TFunction<'adminHome'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  switch (error.code) {
    case 'network_error':
    case 'request_failed':
    case 'invalid_response':
    case 'dashboard_storage_unavailable':
    case 'dashboard_query_timeout':
    case 'dashboard_request_cancelled':
      return t(`errors.${error.code}`)
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

function analyticsFilter(endAt: string, range: AdminAnalyticsRange): AnalyticsFilter {
  const to = new Date(endAt)
  const days = range === 'today' ? 1 : range === 'yesterday' ? 1 : range === 'seven_days' ? 7 : 30
  const end = range === 'yesterday' ? new Date(to.getTime() - 24 * 60 * 60 * 1000) : to
  return { from: new Date(end.getTime() - days * 24 * 60 * 60 * 1000).toISOString(), to: end.toISOString() }
}

// Next business-day midnight (UTC instant) after the server's snapshot time.
// Network and monitor windows end here regardless of the operations range.
function businessDayEnd(generatedAt: string): string {
  const date = new Date(generatedAt)
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
    timeZone: businessTimeZone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).formatToParts(date).map((part) => [part.type, Number(part.value)]))
  const offset = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) -
    Math.floor(date.getTime() / 1000) * 1000
  return new Date(Date.UTC(parts.year, parts.month - 1, parts.day + 1) - offset).toISOString()
}

function formatAdminHomeDateTime(value: Date | string, locale: string): string {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  if (locale === 'en-US') {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: businessTimeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    }).format(date)
  }
  const formatter = new Intl.DateTimeFormat('zh-CN', {
    timeZone: businessTimeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  })
  const parts = formatter.formatToParts(date)
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((item) => item.type === type)?.value ?? ''
  return `${part('year')}-${part('month')}-${part('day')} ${part('hour')}:${part('minute')}:${part('second')}`
}

function analyticsSummary(value: AnalyticsSummaryResponse['data']) {
  return {
    metric_version: 1 as const,
    request_count: String(value.request_count),
    request_bytes: String(value.request_bytes),
    response_bytes: String(value.response_bytes),
    total_bytes: String(value.total_bytes),
    average_bandwidth_bps: value.average_bandwidth_bps,
    status_2xx: String(value.status_2xx),
    status_3xx: String(value.status_3xx),
    status_4xx: String(value.status_4xx),
    status_5xx: String(value.status_5xx),
    security_events: String(value.security_events),
    security_event_rows: String(value.security_event_rows),
  }
}

function analyticsRank<D extends AdminAnalyticsRankDimension>(dimension: D, response: AnalyticsRankResponse) {
  return {
    dimension,
    snapshot_at: response.page.snapshot_at,
    // host/port/path/scheme: the home page shows domains as host:port and URLs in full.
    items: response.data.map((item) => ({ key: item.key, request_count: String(item.request_count), response_bytes: String(item.response_bytes),
      host: item.host, port: item.port, path: item.path, scheme: item.scheme })),
  }
}

function analyticsOverview(
  summary: AnalyticsSummaryResponse,
  trend: AnalyticsTrendResponse,
  optional: {
    blockedIPCount?: AnalyticsBlockedIPCountResponse
    blockedIPTrend?: AnalyticsBlockedIPTrendResponse
    peakBandwidth?: AnalyticsPeakBandwidthResponse
  },
): DashboardAnalyticsOverview {
  const blockedByHour = optional.blockedIPTrend === undefined
    ? undefined
    : new Map(optional.blockedIPTrend.data.map((point) => [point.hour, point.blocked_ip_count]))
  return {
    ...(optional.blockedIPCount === undefined ? {} : { blocked_ip_count: String(optional.blockedIPCount.blocked_ip_count) }),
    blocked_ip_trend_available: optional.blockedIPCount !== undefined && optional.blockedIPTrend !== undefined,
    ...(optional.peakBandwidth === undefined ? {} : { peak_bandwidth_bps: String(optional.peakBandwidth.data.peak_bandwidth_bps) }),
    summary: analyticsSummary(summary.data),
    trend: trend.data.map((point) => {
      const blockedIPCount = blockedByHour?.get(point.hour)
      return {
        ...analyticsSummary(point),
        hour: point.hour,
        ...(blockedIPCount === undefined ? {} : { blocked_ip_count: String(blockedIPCount) }),
      }
    }),
    // Rankings come from the fixed TOP10 window (readAdminTopAnalytics), not this range.
    top: [],
  }
}

function settledValue<T>(result: PromiseSettledResult<T>): T | undefined {
  return result.status === 'fulfilled' ? result.value : undefined
}

async function readAdminAnalyticsRange(accessToken: string, endAt: string, range: AdminAnalyticsRange) {
  const filters = analyticsFilter(endAt, range)
  const core = Promise.all([
    analyticsApi.summary(accessToken, 'admin', filters),
    analyticsApi.trend(accessToken, 'admin', filters),
  ])
  const optional = Promise.allSettled([
    analyticsApi.blockedIPCount(accessToken, 'admin', filters),
    analyticsApi.blockedIPTrend(accessToken, 'admin', filters),
    analyticsApi.peakBandwidth(accessToken, 'admin', filters),
  ])
  const [[summary, trend], optionalResults] = await Promise.all([core, optional])
  return analyticsOverview(summary, trend, {
    blockedIPCount: settledValue(optionalResults[0]),
    blockedIPTrend: settledValue(optionalResults[1]),
    peakBandwidth: settledValue(optionalResults[2]),
  })
}

const topAnalyticsWindowMinutes = 30
// The rankings view never renders a summary; this placeholder only satisfies
// the shared overview shape.
const emptyAnalyticsSummary: DashboardAnalyticsOverview['summary'] = {
  metric_version: 1, request_count: '0', request_bytes: '0', response_bytes: '0', total_bytes: '0',
  average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0',
}

// TOP10 is a fixed, minute-aligned "last 30 minutes" window anchored to the
// server time of the dashboard snapshot, independent of the monitor range.
function topAnalyticsFilter(generatedAt: string): AnalyticsFilter {
  const to = Math.floor(new Date(generatedAt).getTime() / 60_000) * 60_000
  return { from: new Date(to - topAnalyticsWindowMinutes * 60_000).toISOString(), to: new Date(to).toISOString() }
}

async function readAdminTopAnalytics(accessToken: string, generatedAt: string): Promise<DashboardAnalyticsOverview> {
  const filters = topAnalyticsFilter(generatedAt)
  const core = Promise.all([
    analyticsApi.rank(accessToken, 'admin', 'domain', filters, 10),
    analyticsApi.rank(accessToken, 'admin', 'region', filters, 10),
  ])
  const optional = Promise.allSettled([
    analyticsApi.rank(accessToken, 'admin', 'url', filters, 10),
    analyticsApi.rank(accessToken, 'admin', 'ip', filters, 10),
  ])
  const [[domain, region], [url, ip]] = await Promise.all([core, optional])
  const urlRank = settledValue(url)
  const ipRank = settledValue(ip)
  return {
    summary: emptyAnalyticsSummary,
    trend: [],
    top: [analyticsRank('domain', domain), analyticsRank('region', region)],
    ...(urlRank === undefined || ipRank === undefined ? {} : {
      top_extended: [
        analyticsRank('domain', domain), analyticsRank('url', urlRank), analyticsRank('ip', ipRank), analyticsRank('region', region),
      ],
    }),
  }
}

function analyticsUnavailableReason(error: unknown): DashboardUnavailableReason {
  return error instanceof ApiError && error.status === 504 ? 'dependency_timeout' : 'dependency_unavailable'
}

/* The administrator overview uses compact legacy units in the network
 * metric band (for example, `0Kbps` and `0次`). Keep the API values untouched
 * and only adapt their presentation on this compatibility surface. */
function compactDashboardUnit(value: string): string {
  return value.replace(/\s+/g, '')
}

function formatAdminBandwidth(value: number, locale: string): string {
  return compactDashboardUnit(formatAnalyticsBandwidth(value, locale))
}

function formatAdminBytes(value: string, locale: string): string {
  if (BigInt(value) < 1024n) return compactDashboardUnit(formatAnalyticsBytes(Number(value), locale))
  return compactDashboardUnit(formatDashboardBytes(value, locale))
}

function formatAdminCount(value: string, kind: 'requests' | 'blockedIPs', locale: string): string {
  const suffix = locale === 'en-US'
    ? kind === 'requests' ? ' requests' : ' IPs'
    : kind === 'requests' ? '次' : '个'
  return `${formatDashboardInteger(value, locale)}${suffix}`
}

function MetricBand({ metrics }: { metrics: Metric[] }) {
  return (
    <dl className="dashboard-metric-band">
      {metrics.map((metric) => (
        <div className={`dashboard-metric${metric.tone ? ` is-${metric.tone}` : ''}`} key={metric.label}>
          <dt>{metric.label}</dt>
          <dd>{metric.value}</dd>
        </div>
      ))}
    </dl>
  )
}

function DashboardInfoRows({ rows }: { rows: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="dashboard-info-rows">
      {rows.map((row) => (
        <div key={row.label}>
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  )
}

function DashboardOperationPanel({ title, points, kind, tooltipFormatter, summary, unavailableReason }: {
  title: string
  points?: OperationCountPoint[] | OperationAmountPoint[]
  kind: 'count' | 'amount'
  tooltipFormatter: string
  summary?: string
  unavailableReason?: DashboardUnavailableReason
}) {
  const { t } = useTranslation('adminHome')
  const theme = useChartTheme()
  const containerRef = useRef<HTMLDivElement>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    setFailed(false)
    if (unavailableReason || import.meta.env.MODE === 'test' || containerRef.current === null) return
    let disposed = false
    let chart: import('../components/echartsRuntime').ECharts | undefined
    let observer: ResizeObserver | undefined
    void import('../components/echartsRuntime').then((echarts) => {
      if (disposed || containerRef.current === null) return
      chart = echarts.init(containerRef.current)
      observer = new ResizeObserver(() => chart?.resize())
      observer.observe(containerRef.current)
      const chartPoints = points ?? []
      const values = chartPoints.map((point) => kind === 'count'
        ? (point as OperationCountPoint).count
        : Number((point as OperationAmountPoint).sum_minor) / 100)
      chart.setOption({
        backgroundColor: 'transparent',
        // Each operation label is anchored to the card's upper-left inset;
        // ECharts' default title placement is centered in the canvas.
        title: { text: title, left: 16, top: 12, padding: 0, textStyle: { color: theme.text, fontSize: 12, fontWeight: 'normal', lineHeight: 10 } },
        grid: { top: '50px', left: '20px', bottom: '10px', containLabel: true },
        xAxis: { type: 'category', data: chartPoints.map((point) => point.time.slice(5, 10)), axisLine: { lineStyle: { color: theme.border } }, axisTick: { lineStyle: { color: theme.border } }, axisLabel: { color: theme.muted } },
        yAxis: { type: 'value', splitLine: { lineStyle: { color: theme.border } }, axisLine: { lineStyle: { color: theme.border } }, axisLabel: { color: theme.muted } },
        series: [{ type: 'bar', data: values, itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: themeColor('--cdnca-chart-bar1', '#69cdff') },
            { offset: 0.5, color: themeColor('--cdnca-chart-bar2', '#3eb3f7') },
            { offset: 1, color: themeColor('--cdnca-chart-bar3', '#1495eb') },
          ]),
          borderRadius: [3, 3, 0, 0],
        } }],
        tooltip: {
          trigger: 'axis',
          backgroundColor: theme.surface,
          borderColor: theme.border,
          textStyle: { color: theme.text },
          axisPointer: { type: 'shadow', shadowStyle: { color: themeColorAlpha('--cdnca-chart-color1', '#2d8cf0', '.10') } },
          formatter: tooltipFormatter,
        },
        graphic: chartPoints.length === 0 ? {
          type: 'text',
          left: 'center',
          top: 'center',
          style: { text: t('values.noData'), fontSize: 14, fill: theme.muted },
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
  }, [kind, points, t, theme, title, tooltipFormatter, unavailableReason])
  return (
    <section className="dashboard-operation-panel">
      <div className="dashboard-operation-chart__canvas" aria-label={title}>
        <div ref={containerRef} className="dashboard-operation-chart__plot" aria-hidden="true" />
        <h3 className="visually-hidden">{title}</h3>
        {unavailableReason ? <SectionUnavailable reason={unavailableReason} />
          : failed ? <div className="dashboard-operation-empty">{t('values.noData')}</div>
            : !points?.length ? <span className="visually-hidden">{t('values.noData')}</span> : null}
        {summary ? <span className="visually-hidden">{summary}</span> : null}
      </div>
    </section>
  )
}

function DashboardBlock({ title, icon, children, className, toolbar }: { title: string; icon?: ReactNode; children: ReactNode; className?: string; toolbar?: ReactNode }) {
  return (
    <section className={`dashboard-block${className ? ` ${className}` : ''}`}>
      <div className="dashboard-block-heading">
        <h2>{icon}<span className="dashboard-card-title">{title}</span></h2>
        {toolbar ? <div className="dashboard-block-extra">{toolbar}</div> : null}
      </div>
      {children}
    </section>
  )
}

function DashboardRangeControl({ value, options, ariaLabel, onChange }: {
  value: string
  options: Array<{ label: string; value: string }>
  ariaLabel: string
  onChange: (value: string) => void
}) {
  return (
    <div className="dashboard-range-control" role="radiogroup" aria-label={ariaLabel}>
      {options.map((option) => (
        <button key={option.value} type="button" role="radio" aria-checked={option.value === value}
          className={option.value === value ? 'is-selected' : ''} onClick={() => onChange(option.value)}>
          {option.label}
        </button>
      ))}
    </div>
  )
}

function DashboardPodiumIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" focusable="false">
      <rect x="1.5" y="7" width="3" height="7.5" rx="0.5" />
      <rect x="6.5" y="2.5" width="3" height="12" rx="0.5" />
      <rect x="11.5" y="5" width="3" height="9.5" rx="0.5" />
    </svg>
  )
}

function DashboardAppsIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" focusable="false">
      {[1, 6, 11].flatMap((x) => [2, 7, 12].map((y) => <rect key={`${x}-${y}`} x={x} y={y} width="3" height="3" rx="0.4" />))}
    </svg>
  )
}

function DashboardVolumeIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false">
      <path d="M3 9v6h4l5 5V4L7 9H3Zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02ZM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77Z" />
    </svg>
  )
}

function adminAccountID(principal: Principal) {
  const internalID = principal.user_id?.trim() ?? ''
  const displayID = (principal as Principal & { display_id?: string }).display_id?.trim()
  if (displayID) return <ResourceID internalId={internalID} displayId={displayID} />
  return (
    <span className="dashboard-profile-compact-id" title={internalID} aria-label={internalID} tabIndex={0}>
      <span aria-hidden="true">—</span>
      <span className="visually-hidden">{internalID}</span>
    </span>
  )
}

function AdminProfileCard({ principal, profile, locale }: { principal: Principal; profile?: DashboardSection<AdminProfileStats>; locale: string }) {
  const { t } = useTranslation('adminHome')
  const navigate = useNavigate()
  const hour = new Date().getHours()
  const greeting = hour < 6 ? t('profile.greeting.lateNight')
    : hour < 12 ? t('profile.greeting.morning')
      : hour < 18 ? t('profile.greeting.afternoon') : t('profile.greeting.evening')
  const facts = profile?.available ? profile.value : undefined
  const title = principal.username || principal.display_name || t('profile.platformAdmin')
  const avatar = title.slice(0, 1).toUpperCase()
  const loginSource = (facts && formatDashboardLoginSource(facts, locale)) ?? t('profile.notProvided')
  return (
    <section className="dashboard-card dashboard-profile-card" aria-labelledby="dashboard-profile-title">
      <div className="dashboard-profile-avatar" aria-hidden="true">{avatar}</div>
      <div className="dashboard-profile-content">
        <div className="dashboard-profile-title-row">
          <h2 id="dashboard-profile-title">{title}</h2>
          {principal.permissions.includes('identity.self.read') ? <button
            type="button"
            className="dashboard-profile-edit"
            aria-label={t('profile.edit')}
            onClick={() => navigate('/account/user')}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false">
              <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25Zm2.92 2.33H5v-.92l9.06-9.06.92.92L5.92 19.58ZM20.71 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83Z" />
            </svg>
          </button> : null}
          <p>{greeting}</p>
        </div>
        <dl className="dashboard-profile-meta">
          <div><dt>{t('profile.accountId')}:</dt><dd>{adminAccountID(principal)}</dd></div>
          <div><dt>{t('profile.lastLogin')}:</dt><dd>{facts?.last_login_at ? formatAdminHomeDateTime(facts.last_login_at, locale) : t('profile.notProvided')}</dd></div>
          <div><dt>{t('profile.loginIp')}:</dt><dd>{loginSource}</dd></div>
        </dl>
      </div>
    </section>
  )
}

function StatusCard({ data, locale, onCheck, checking }: {
  data: AdminDashboard
  locale: string
  onCheck: () => void
  checking: boolean
}) {
  const { t } = useTranslation('adminHome')
  const agentHealthy = data.node_health.available && data.node_health.value.stale_or_offline === 0
  const agentReason = !data.node_health.available ? t('status.agentUnreadable') : agentHealthy ? null
    : t('status.agentStale', { count: data.node_health.value.stale_or_offline, seconds: data.node_health.value.freshness_cutoff_seconds })
  const analyticsHealthy = data.analytics_health.available && data.analytics_health.value.unprepared_stream_gap === '0' &&
    (data.analytics.available || (data.analytics.reason !== 'dependency_unavailable' && data.analytics.reason !== 'dependency_timeout'))
  const indicator = (available: boolean) => {
    const Icon = available ? CheckCircle2 : CircleAlert
    const statusText = available ? t('status.available') : t('status.unavailable')
    return <span className={`dashboard-status-value ${available ? 'is-success' : 'is-danger'}`} aria-label={statusText}><Icon size={14} aria-hidden="true" />{available ? null : statusText}</span>
  }
  return (
    <section className="dashboard-card dashboard-status-card" aria-labelledby="dashboard-status-title">
      <h2 id="dashboard-status-title"><DashboardVolumeIcon /><span className="dashboard-card-title">{t('sections.systemStatus')}</span></h2>
      <dl className="dashboard-status-list">
        <div><dt>{t('status.controlPlane')}</dt><dd>{indicator(true)}</dd></div>
        {/* The analytics service is ClickHouse, not Elasticsearch (fix-e1 #5). */}
        <div><dt>{t('status.analytics')}</dt><dd>{indicator(analyticsHealthy)}</dd></div>
        <div><dt>{t('status.agent')}</dt><dd className={agentHealthy ? 'is-success' : 'is-danger'}>
          {indicator(agentHealthy)}
          <Button type="primary" size="small" loading={checking} onClick={onCheck}>{t('status.checkNow')}</Button>
        </dd></div>
      </dl>
      {agentReason ? <p className="dashboard-card-note is-danger">{agentReason}</p> : null}
      <p className="dashboard-card-note">{t('status.lastChecked', { date: formatAdminHomeDateTime(data.meta.snapshot_at, locale) })}</p>
    </section>
  )
}

function unavailableText(reason: DashboardUnavailableReason, t: TFunction<'adminHome'>): string {
  return t(`unavailable.${reason}`)
}

function SectionUnavailable({ reason }: { reason: DashboardUnavailableReason }) {
  const { t } = useTranslation('adminHome')
  return (
    <div className="dashboard-section-state" role="status">
      <CircleAlert size={15} aria-hidden="true" />
      <span>{unavailableText(reason, t)}</span>
    </div>
  )
}

/* LIC-REC-03: the authorization card's own details (serial, state, last
 * check) so an unknown refresh result can be checked in place. */
function EntitlementDetails({ entitlement, locale, open, onToggle }: {
  entitlement: DashboardEntitlement
  locale: string
  open: boolean
  onToggle: () => void
}) {
  const { t } = useTranslation('adminHome')
  const id = useId()
  return (
    <div className="dashboard-entitlement-details">
      <Button type="link" size="small" className="dashboard-entitlement-toggle" aria-expanded={open} aria-controls={id}
        icon={<ChevronDown size={14} aria-hidden="true" className={open ? 'is-open' : undefined} />} iconPosition="end"
        onClick={onToggle}>{t(open ? 'entitlement.hideDetails' : 'entitlement.showDetails')}</Button>
      {open ? <div id={id} role="region" aria-label={t('entitlement.details')} className="dashboard-entitlement-details-body">
        <DashboardInfoRows rows={[
          { label: t('entitlement.serial'), value: entitlement.current_serial === undefined ? t('values.placeholder') : String(entitlement.current_serial) },
          { label: t('entitlement.state'), value: t(`entitlement.status.${entitlement.status}`) },
          { label: t('entitlement.lastVerified'), value: entitlement.last_verified_at ? formatAdminHomeDateTime(entitlement.last_verified_at, locale) : t('values.placeholder') },
        ]} />
      </div> : null}
    </div>
  )
}

function SectionValue<T>({ section, children }: {
  section: DashboardSection<T>
  children: (value: T) => ReactNode
}) {
  return section.available ? children(section.value) : <SectionUnavailable reason={section.reason} />
}

function DashboardAnalyticsPlaceholder({ reason, mode = 'both' }: { reason: DashboardUnavailableReason; mode?: 'both' | 'trend' | 'rankings' }) {
  const { t } = useTranslation('dashboardOverview')
  const displayMode = mode
  return (
    <div className="dashboard-analytics-overview dashboard-analytics-admin dashboard-analytics-unavailable">
      {/* 数据不可用时不渲染无动作的标签按钮（ui-click F3），只保留不可用提示。 */}
      {displayMode !== 'rankings' ? <section className="dashboard-trend-pane" aria-label={t('sections.trend')}>
        <SectionUnavailable reason={reason} />
      </section> : null}
      {displayMode !== 'trend' ? <section className="dashboard-rank-tabs" aria-label={t('top.adminTitle')}>
        {displayMode === 'both' ? <h3 className="dashboard-trend-heading">{t('top.adminTitle')}</h3> : null}
        <SectionUnavailable reason={reason} />
      </section> : null}
    </div>
  )
}

export function AdminHomePage() {
  const { t } = useTranslation('adminHome')
  const sessionStatus = useSessionStore((state) => state.status)
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (sessionStatus === 'bootstrapping' || !principal || !accessToken) {
    return (
      <section className="overview-card admin-overview dashboard-page" aria-label={t('states.loading')} aria-busy="true" data-dashboard-state="loading">
        <DataState status="loading" className="dashboard-page-state" message={t('states.loading')} />
      </section>
    )
  }

  const owner = adminDashboardOwner(principal, sessionEpoch)
  if (!owner || !principal.permissions.includes('platform.admin')) {
    return (
      <Result
        className="identity-page identity-forbidden"
        data-dashboard-state="forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  const ownerKey = JSON.stringify(owner)
  return <AdminHomePageContent key={ownerKey} owner={owner} ownerKey={ownerKey} principal={principal} />
}

function AdminHomePageContent({ owner, ownerKey, principal }: { owner: AdminDashboardOwner; ownerKey: string; principal: Principal }) {
  const { t, i18n } = useTranslation('adminHome')
  const { t: overviewT } = useTranslation('dashboardOverview')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const [range, setRange] = useState<AdminDashboardRange>('seven_days')
  const [networkRange, setNetworkRange] = useState<AdminAnalyticsRange>('today')
  const [monitorRange, setMonitorRange] = useState<AdminAnalyticsRange>('today')
  const queryClient = useQueryClient()
  const queryOwner = useRef(owner).current
  const queryPrefix = useMemo(() => ['dashboard', 'admin', ...queryOwner] as const, [queryOwner])
  const lineageActiveRef = useRef(true)
  const currentSessionCanRead = useCallback(() => (
    lineageActiveRef.current && Boolean(currentAdminDashboardAccess(ownerKey))
  ), [ownerKey])

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentAdminDashboardAccess(ownerKey)) {
        queryClient.removeQueries({ queryKey: queryPrefix })
      }
    }
  }, [ownerKey, queryClient, queryPrefix])

  const dashboardQuery = useQuery({
    queryKey: [...queryPrefix, range, businessTimeZone],
    queryFn: async ({ signal }) => {
      const token = currentAdminDashboardAccess(ownerKey)
      if (!token) throw staleAdminDashboardRead
      try {
        const result = await dashboardApi.admin(token, range, businessTimeZone, signal)
        if (!currentSessionCanRead()) throw staleAdminDashboardRead
        return result
      } catch (error) {
        if (!currentSessionCanRead()) throw staleAdminDashboardRead
        throw error
      }
    },
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })
  const generatedAt = dashboardQuery.data?.meta.generated_at
  const analyticsEndAt = generatedAt ? businessDayEnd(generatedAt) : undefined
  // The dashboard's own analytics section covers the seven days ending at the
  // same business-day midnight only when the operations range is seven days.
  const baselineCoversSevenDays = dashboardQuery.data?.meta.range === 'seven_days'
  const usesBaseline = (selectedRange: AdminAnalyticsRange) => selectedRange === 'seven_days' && baselineCoversSevenDays
  const readIndependentAnalytics = useCallback(async (selectedRange: AdminAnalyticsRange) => {
    const token = currentAdminDashboardAccess(ownerKey)
    if (!token || !analyticsEndAt) throw staleAdminDashboardRead
    const result = await readAdminAnalyticsRange(token, analyticsEndAt, selectedRange)
    if (!currentSessionCanRead()) throw staleAdminDashboardRead
    return result
  }, [analyticsEndAt, currentSessionCanRead, ownerKey])
  // Network and monitor share one cache entry per range so equal ranges are read once.
  const rangeAnalyticsQuery = (selectedRange: AdminAnalyticsRange) => ({
    queryKey: [...queryPrefix, 'analytics', 'range', selectedRange, analyticsEndAt ?? 'pending'],
    queryFn: () => readIndependentAnalytics(selectedRange),
    enabled: !usesBaseline(selectedRange) && Boolean(analyticsEndAt),
    staleTime: 30_000,
    retry: false,
  })
  const networkAnalyticsQuery = useQuery(rangeAnalyticsQuery(networkRange))
  const monitorAnalyticsQuery = useQuery(rangeAnalyticsQuery(monitorRange))
  const topAnalyticsQuery = useQuery({
    queryKey: [...queryPrefix, 'analytics', 'top30m', generatedAt ?? 'pending'],
    queryFn: async () => {
      const token = currentAdminDashboardAccess(ownerKey)
      if (!token || !generatedAt) throw staleAdminDashboardRead
      const result = await readAdminTopAnalytics(token, generatedAt)
      if (!currentSessionCanRead()) throw staleAdminDashboardRead
      return result
    },
    enabled: Boolean(generatedAt),
    staleTime: 30_000,
    retry: false,
  })
  const [entitlementReread, setEntitlementReread] = useState<EntitlementReread>()
  const [entitlementDetailsOpen, setEntitlementDetailsOpen] = useState(false)
  const checkStartedWith = useRef<DashboardEntitlement | undefined>(undefined)
  const lockCheck = useInstallationLockCheck()
  // LIC-REC-03: the result may be unknown, so read the persisted lease again
  // without replacing the page with an error when that read fails too.
  const rereadEntitlement = async () => {
    setEntitlementReread({ kind: 'pending' })
    try {
      const token = currentAdminDashboardAccess(ownerKey)
      if (!token) throw staleAdminDashboardRead
      const result = await dashboardApi.admin(token, range, businessTimeZone)
      if (!currentSessionCanRead()) return
      queryClient.setQueryData([...queryPrefix, range, businessTimeZone], result)
      if (!result.entitlement.available) {
        setEntitlementReread({ kind: 'failed' })
        return
      }
      const after = result.entitlement.value
      setEntitlementReread({ kind: 'confirmed', serial: after.current_serial, status: after.status,
        verifiedAt: after.last_verified_at, effective: entitlementCheckEffective(checkStartedWith.current, after) })
      setEntitlementDetailsOpen(true)
    } catch {
      if (currentSessionCanRead()) setEntitlementReread({ kind: 'failed' })
    }
  }
  const refreshEntitlementMutation = useMutation({
    mutationFn: async () => {
      const token = currentAdminDashboardAccess(ownerKey)
      if (!token) throw staleAdminDashboardRead
      return dashboardApi.refreshEntitlement(token)
    },
    onMutate: () => setEntitlementReread(undefined),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryPrefix })
    },
    // B18: an unknown result (audit failed, timeout, network, lost COMMIT
    // answer) may already have installed the new lease; re-read it instead of
    // inviting a blind retry.
    onError: async (failure) => {
      const outcome = entitlementRefreshOutcome(failure)
      if (outcome === 'locked') lockCheck.mutate()
      if (outcome === 'unknown' || outcome === 'applied') await rereadEntitlement()
    },
  })
  // Home card and lock banner share one recovery action (the lock check).
  const checkEntitlement = (current: DashboardEntitlement) => {
    checkStartedWith.current = current
    if (queryClient.getQueryData<InstallationLock>(installationLockQueryKey)?.locked) lockCheck.mutate()
    else refreshEntitlementMutation.mutate()
  }
  const refreshFailure = refreshEntitlementMutation.error
  const refreshOutcome = refreshEntitlementMutation.isError ? entitlementRefreshOutcome(refreshFailure) : undefined

  const error = dashboardQuery.error
  if (error instanceof ApiError && error.status === 403) {
    return (
      <Result
        className="identity-page identity-forbidden"
        data-dashboard-state="forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  const rangeOptions = [
    { label: t('ranges.sevenDays'), value: 'seven_days' },
    { label: t('ranges.thirtyDays'), value: 'thirty_days' },
    { label: t('ranges.previousMonth'), value: 'previous_month' },
  ]
  const analyticsRangeOptions = [
    { label: overviewT('ranges.today'), value: 'today' },
    { label: overviewT('ranges.yesterday'), value: 'yesterday' },
    { label: overviewT('ranges.sevenDays'), value: 'seven_days' },
    { label: overviewT('ranges.thirtyDays'), value: 'thirty_days' },
  ]
  const data = dashboardQuery.data!
  const operationCharts = dashboardQuery.data?.operation_charts
  const operationChartsUnavailableReason = operationCharts && !operationCharts.available
    ? operationCharts.reason
    : undefined
  const baselineAnalytics: DashboardSection<DashboardAnalyticsOverview> = dashboardQuery.data?.analytics ?? {
    available: false,
    reason: 'dependency_unavailable',
  }
  const networkAnalytics: DashboardSection<DashboardAnalyticsOverview> = usesBaseline(networkRange)
    ? baselineAnalytics
    : networkAnalyticsQuery.isSuccess
      ? { available: true, value: networkAnalyticsQuery.data }
      : { available: false, reason: analyticsUnavailableReason(networkAnalyticsQuery.error) }
  const monitorAnalytics: DashboardSection<DashboardAnalyticsOverview> = usesBaseline(monitorRange)
    ? baselineAnalytics
    : monitorAnalyticsQuery.isSuccess
      ? { available: true, value: monitorAnalyticsQuery.data }
      : { available: false, reason: analyticsUnavailableReason(monitorAnalyticsQuery.error) }
  const topAnalytics: DashboardSection<DashboardAnalyticsOverview> = topAnalyticsQuery.isSuccess
    ? { available: true, value: topAnalyticsQuery.data }
    : { available: false, reason: analyticsUnavailableReason(topAnalyticsQuery.error) }
  const analyticsPending = (query: { isPending: boolean; fetchStatus: string }) => query.isPending && query.fetchStatus !== 'idle'

  return (
    <section
      className="overview-card admin-overview dashboard-page"
      aria-label={t('title')}
      aria-busy={dashboardQuery.isFetching}
      data-dashboard-state={dashboardQuery.isPending && !dashboardQuery.data ? 'loading' : error ? 'error' : 'ready'}
    >
      {!dashboardQuery.isSuccess ? <h1 className="visually-hidden">{t('title')}</h1> : null}
      {dashboardQuery.isPending && !dashboardQuery.data ? (
        <DataState status="loading" className="dashboard-page-state" message={t('states.loading')} />
      ) : error ? (
        <DataState
          status="error"
          className="dashboard-page-state"
          message={errorMessage(error, t)}
          onRetry={() => void dashboardQuery.refetch()}
        />
      ) : dashboardQuery.isSuccess ? (
        <div className="dashboard-content">
          <div className="dashboard-reference-layout">
            <div className="dashboard-reference-main">
              <DashboardBlock title={t('title')} icon={<DashboardPodiumIcon />} className="dashboard-reference-operations" toolbar={
                <DashboardRangeControl value={range} options={rangeOptions} ariaLabel={t('ranges.label')}
                  onChange={(value) => setRange(value as AdminDashboardRange)} />
              }>
                <div className="dashboard-operation-panels">
                  <DashboardOperationPanel
                    title={t('sections.registration')}
                    kind="count"
                    tooltipFormatter={t('charts.registrationTooltip')}
                    points={operationCharts?.available ? operationCharts.value.new_users : undefined}
                    summary={data.accounts.available ? formatNumber(data.accounts.value.tenant_users_total, locale) : undefined}
                    unavailableReason={operationChartsUnavailableReason}
                  />
                </div>
              </DashboardBlock>

              <DashboardBlock title={overviewT('sections.network')} icon={<DashboardPodiumIcon />} className="dashboard-reference-network" toolbar={
                <DashboardRangeControl value={networkRange} options={analyticsRangeOptions} ariaLabel={overviewT('ranges.networkLabel')}
                  onChange={(value) => setNetworkRange(value as AdminAnalyticsRange)} />
              }>
                {!usesBaseline(networkRange) && analyticsPending(networkAnalyticsQuery) ? <div className="dashboard-section-state" role="status">{t('states.analyticsLoading')}</div>
                  : networkAnalytics.available ? <MetricBand metrics={[
                  { label: t('metrics.peakBandwidth'), value: formatAdminBandwidth(peakHourlyBandwidth(networkAnalytics.value) ?? 0, locale) },
                  { label: t('metrics.requests'), value: formatAdminCount(networkAnalytics.value.summary.request_count, 'requests', locale) },
                  { label: t('metrics.totalTraffic'), value: formatAdminBytes(networkAnalytics.value.summary.total_bytes, locale) },
                  { label: t('metrics.blockedIPCount'), value: networkAnalytics.value.blocked_ip_count === undefined ? t('values.placeholder') : formatAdminCount(networkAnalytics.value.blocked_ip_count, 'blockedIPs', locale) },
                ]} /> : <MetricBand metrics={[
                  { label: t('metrics.peakBandwidth'), value: t('values.placeholder') },
                  { label: t('metrics.requests'), value: t('values.placeholder') },
                  { label: t('metrics.totalTraffic'), value: t('values.placeholder') },
                  { label: t('metrics.blockedIPCount'), value: t('values.placeholder') },
                ]} />}
              </DashboardBlock>

              <div className="dashboard-monitoring-grid">
                <DashboardBlock title={t('sections.monitoring')} icon={<Activity size={14} aria-hidden="true" />} className="dashboard-reference-monitoring" toolbar={
                  <DashboardRangeControl value={monitorRange} options={analyticsRangeOptions} ariaLabel={overviewT('ranges.monitorLabel')}
                    onChange={(value) => setMonitorRange(value as AdminAnalyticsRange)} />
                }>
                  {!usesBaseline(monitorRange) && analyticsPending(monitorAnalyticsQuery) ? <div className="dashboard-section-state" role="status">{t('states.analyticsLoading')}</div>
                    : monitorAnalytics.available
                      ? <DashboardAnalyticsView analytics={monitorAnalytics.value} locale={locale} variant="admin" mode="trend" />
                      : <DashboardAnalyticsPlaceholder reason={monitorAnalytics.reason} mode="trend" />}
                </DashboardBlock>
                <DashboardBlock title={overviewT('top.adminTitle')} icon={<Activity size={14} aria-hidden="true" />} className="dashboard-reference-top">
                  {analyticsPending(topAnalyticsQuery) ? <div className="dashboard-section-state" role="status">{t('states.analyticsLoading')}</div>
                    : topAnalytics.available
                      ? <DashboardAnalyticsView analytics={topAnalytics.value} locale={locale} variant="admin" mode="rankings" />
                      : <DashboardAnalyticsPlaceholder reason={topAnalytics.reason} mode="rankings" />}
                </DashboardBlock>
              </div>
            </div>

            <aside className="dashboard-reference-side">
              <AdminProfileCard principal={principal} profile={data.profile} locale={locale} />
              <StatusCard data={data} locale={locale} onCheck={() => void dashboardQuery.refetch()} checking={dashboardQuery.isFetching} />
              <DashboardBlock title={t('sections.entitlement')} icon={<DashboardVolumeIcon />} className="dashboard-card dashboard-entitlement-card">
                <SectionValue section={data.entitlement}>{(entitlement) => <>
                  <DashboardInfoRows rows={[
                    { label: t('authorization.licensedNodes'), value: entitlement.node_limit === undefined ? t('values.placeholder') : formatQuota(entitlement.node_limit, locale) },
                    { label: t('authorization.currentNode'), value: data.resources.available ? formatNumber(data.resources.value.nodes_total, locale) : t('values.placeholder') },
                    { label: t('authorization.expiresAt'), value: entitlement.expires_at ? formatAdminHomeDateTime(entitlement.expires_at, locale) : t('values.placeholder') },
                    { label: t('authorization.operation'), value: <Button type="primary" size="small" className="dashboard-action-button"
                      loading={refreshEntitlementMutation.isPending || lockCheck.isPending}
                      onClick={() => checkEntitlement(entitlement)}>{t('entitlement.refresh')}</Button> },
                  ]} />
                  <EntitlementDetails entitlement={entitlement} locale={locale} open={entitlementDetailsOpen}
                    onToggle={() => setEntitlementDetailsOpen((open) => !open)} />
                  {leaseInGrace(entitlement)
                    ? <p className="dashboard-card-note" role="alert">{t('entitlement.graceWarning', { count: graceDaysLeft(entitlement.grace_until ?? '') })}</p>
                    : null}
                  {refreshOutcome ? <p className="dashboard-card-note" role="alert">
                    <span>{t(`entitlement.${refreshOutcomeKey[refreshOutcome]}`)}</span>
                    {refreshFailure instanceof ApiError && refreshFailure.requestId
                      ? <span title={refreshFailure.requestId}>{' '}{t('entitlement.refreshRequestId', { id: refreshFailure.requestId })}</span> : null}
                  </p> : null}
                  {entitlementReread?.kind === 'confirmed' ? <p className="dashboard-card-note" role="status">
                    <span>{t('entitlement.rereadConfirmed', {
                      serial: entitlementReread.serial ?? t('values.placeholder'),
                      status: t(`entitlement.status.${entitlementReread.status}`),
                      time: entitlementReread.verifiedAt ? formatAdminHomeDateTime(entitlementReread.verifiedAt, locale) : t('values.placeholder'),
                    })}{t(entitlementReread.effective ? 'entitlement.rereadEffective' : 'entitlement.rereadNotSeen')}</span>
                  </p> : null}
                  {entitlementReread?.kind === 'failed' ? <p className="dashboard-card-note dashboard-entitlement-reread" role="alert">
                    <span>{t('entitlement.rereadFailed')}</span>
                    <Button type="link" size="small" onClick={() => void rereadEntitlement()}>{t('entitlement.reread')}</Button>
                  </p> : null}
                  {refreshEntitlementMutation.isSuccess ? <p className="dashboard-card-note" role="status">{t('entitlement.refreshSuccess')}</p> : null}
                </>}</SectionValue>
              </DashboardBlock>
              <DashboardBlock title={t('sections.usage')} icon={<DashboardAppsIcon />} className="dashboard-card dashboard-usage-card">
                <DashboardInfoRows rows={[
                  { label: t('usage.domainsTotal'), value: data.resources.available && data.resources.value.domains_total !== undefined ? formatNumber(data.resources.value.domains_total, locale) : t('values.placeholder') },
                  { label: t('usage.forwardsTotal'), value: data.resources.available && data.resources.value.forwards_total !== undefined ? formatNumber(data.resources.value.forwards_total, locale) : t('values.placeholder') },
                  { label: t('usage.certificatesShort'), value: data.resources.available ? formatNumber(data.resources.value.certificates_total, locale) : t('values.placeholder') },
                ]} />
              </DashboardBlock>
            </aside>
          </div>
        </div>
      ) : null}
    </section>
  )
}

/* The lease is past expires_at but before grace_until: it has not been
 * renewed. Only a time fact: the cause (network, customer/license state,
 * refusal) is not known from these fields. Judged from the lease times because
 * last_status only changes when a guard runs. */
function leaseInGrace(entitlement: { status: string, expires_at?: string, grace_until?: string }): boolean {
  if (entitlement.status === 'revoked' || !entitlement.expires_at || !entitlement.grace_until) return false
  const now = Date.now()
  return Date.parse(entitlement.expires_at) <= now && now < Date.parse(entitlement.grace_until)
}

/* Whole days left until the lease grace ends, rounded up: the control plane
 * keeps working in grace and stops creating/publishing when it ends. */
function graceDaysLeft(graceUntil: string): number {
  return Math.max(0, Math.ceil((Date.parse(graceUntil) - Date.now()) / 86_400_000))
}
