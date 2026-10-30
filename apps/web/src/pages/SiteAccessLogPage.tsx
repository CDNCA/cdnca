import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Input,
  Result,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  type DescriptionsProps,
  type TableColumnsType,
} from 'antd'
import { ChevronLeft, ChevronRight, Download, Eye } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'

import type { AnalyticsAudience } from '../api/analytics'
import {
  analyticsLogsApi,
  isSensitiveAnalyticsCaptureName,
  type AccessLogEvent,
  type AnalyticsLogExport,
  type AnalyticsLogExportFilter,
  type AnalyticsLogFilters,
  type AnalyticsLogPage,
  type BlockLogEvent,
} from '../api/analyticsLogs'
import { ApiError, type Principal } from '../api/auth'
import { useSessionStore } from '../auth/session'
import '../i18n/analyticsLogSecurity'
import '../i18n/analyticsLogParity'
import { analyticsLogExportMessage } from '../i18n/analyticsLogExport'
import { formatBytes, formatDateTime, formatNumber, displayIP } from '../i18n/formatters'
import LogGeoEvidence from '../components/LogGeoEvidence'
import '../i18n/ipIntel'
import '../i18n/wafLogs'
import { logASN, logCarrier, logIDC, logRegion } from './logIPIntel'
import './SiteAccessLogPage.css'
import dayjs from 'dayjs'
import { AdvancedFilters, FeedbackWhen, TimeRangeFilter, resolveTimeRangePreset, useLiveApply, type AdvancedFilterItem } from '@cdnca/ui'
import { filterParam, useFilterUrl } from './filterUrl'

const pageSize = 10
const maximumWindowMilliseconds = 31 * 24 * 60 * 60 * 1000
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const securityValueKeys = {
  eventType: { waf: 'values.eventType.waf', cc: 'values.eventType.cc', acl: 'values.eventType.acl' },
  action: { block: 'values.action.block', deny: 'values.action.deny', log: 'values.action.log', challenge: 'values.action.challenge', temporary_ban: 'values.action.temporary_ban' },
  severity: { low: 'values.severity.low', medium: 'values.severity.medium', high: 'values.severity.high', critical: 'values.severity.critical' },
} as const

export type AnalyticsLogKind = 'access' | 'block'
/** The WAF page's grouped filters, merged columns and grouped details. */
export type AnalyticsLogLayout = 'default' | 'waf'
/** Filters a WAF overview ranking opens the log details with (window as ISO instants). */
/** Drill-down initial filters; action '' lists every hit the overview counts. */
export interface AnalyticsLogSeed {
  from?: string; to?: string; domain?: string; clientIp?: string; siteId?: string; nodeId?: string; action?: SecurityLogAction
}

/** The hits the WAF overview counts (log = observed, temporary_ban = auto block). */
export type SecurityLogAction = '' | 'block' | 'challenge' | 'log' | 'temporary_ban'
type LogEvent = AccessLogEvent | BlockLogEvent
type DetailItem = NonNullable<DescriptionsProps['items']>[number]
type AnalyticsLogOwner = readonly [Principal['scope_kind'], string, string | null, string, number]
type AccessQuickFilter = 'domain' | 'clientIp' | 'uriPath' | 'method' | 'statusCode' | 'cacheStatus' | 'ja4' | 'nodeId' | 'countryCode' | 'carrier'

const staleAnalyticsLogRead = new Error('Analytics log owner changed during read')

// 申请下载的结果未知：网络中断、超时、5xx 或回包不合法（LOG-01）。
function exportOutcomeUnknown(error: unknown): boolean {
  if (error === staleAnalyticsLogRead) return false
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500 ||
    error.code === 'invalid_response'
}

type ExportText = (key: Parameters<typeof analyticsLogExportMessage>[1]) => string

// 确定失败按类型给出下一步（LOG-01）。
function exportCreateError(error: unknown, text: ExportText): string {
  if (!(error instanceof ApiError)) return text('createFailed')
  if (error.status === 403) return text('createForbidden')
  if (error.status === 429) return text('createThrottled')
  if (error.status === 400 || error.status === 422) return text('createInvalid')
  return text('createFailed')
}

// 失败原因码（analytics_log_export_events_v1.reason）转成可行动的说明（LOG-02）。
function exportFailureReason(reason: string, text: ExportText): string {
  if (reason === 'invalid_filter') return text('reasonInvalidFilter')
  if (reason === 'export_rejected') return text('reasonRejected')
  return text('reasonOther')
}

function exportExpired(item: AnalyticsLogExport): boolean {
  return item.status === 'completed' && item.expires_at !== null && Date.parse(item.expires_at) <= Date.now()
}

function analyticsLogOwner(principal: Principal, sessionEpoch: number): AnalyticsLogOwner | null {
  if (!principal.scope_id?.trim() || !principal.user_id?.trim() || sessionEpoch < 1) return null
  if (principal.scope_kind === 'tenant' && (
    !principal.tenant_id
  )) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canReadAnalyticsLogs(principal: Principal): boolean {
  return principal.permissions.includes('sites.read') || (
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  )
}

function currentAnalyticsLogAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canReadAnalyticsLogs(principal)) return null
  const owner = analyticsLogOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

interface DraftFilters {
  tenantId: string
  siteId: string
  domain: string
  nodeId: string
  clientIp: string
  uriPath: string
  uriPathMatch: 'exact' | 'prefix'
  statusCode: string
  countryCode: string
  carrier: string
  /** Block events: '' (all) or one SecurityLogAction. */
  action: SecurityLogAction
  method: string
  protocol: string
  cacheStatus: string
  upstreamResult: string
  contentType: string
  userAgent: string
  requestBytesMin: string
  requestBytesMax: string
  responseBytesMin: string
  responseBytesMax: string
  ja4: string
  from: string
  to: string
  /** Block events only (TimeRangeFilter): preset key or 'custom'. The access log keeps its own from/to inputs. */
  timePreset: string
}

function localDateTimeValue(value: Date): string {
  const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

function initialWindow(): Pick<DraftFilters, 'from' | 'to'> {
  const now = new Date(Date.now())
  const from = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const to = new Date(from)
  to.setDate(to.getDate() + 1)
  return {
    from: localDateTimeValue(from),
    to: localDateTimeValue(to),
  }
}

// Block events query a relative quick range from the moment the user asks again.
function resolvedDraft(draft: DraftFilters, kind: AnalyticsLogKind): DraftFilters {
  if (kind !== 'block' || draft.timePreset === 'custom') return draft
  const range = resolveTimeRangePreset(draft.timePreset, 'minute')
  return range ? { ...draft, from: localDateTimeValue(range[0].toDate()), to: localDateTimeValue(range[1].toDate()) } : draft
}

function optional(value: string): string | undefined {
  return value.trim() || undefined
}

function normalizedHost(value: string): string | undefined {
  const host = value.trim().toLowerCase().replace(/\.$/, '')
  return host && /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+$/.test(host)
    ? host
    : undefined
}

/** One host or the WAF overview's space-separated list (≤ 64, distinct). */
function normalizedHosts(value: string): string | undefined {
  const tokens = value.trim().split(/\s+/u).filter(Boolean)
  if (tokens.length === 0 || tokens.length > 64) return undefined
  const hosts = tokens.map(normalizedHost)
  if (hosts.some((host) => !host) || new Set(hosts).size !== hosts.length) return undefined
  return hosts.join(' ')
}

function validURIPathFilter(value: string): boolean {
  if (value.length > 4096 || !value.startsWith('/') || value.trim() !== value ||
    value.includes('?') || value.includes('#')) return false
  return !Array.from(value).some((character) => {
    const codePoint = character.charCodeAt(0)
    return codePoint < 0x20 || codePoint === 0x7f
  })
}

function validateDraft(
  draft: DraftFilters,
  audience: AnalyticsAudience,
  kind: AnalyticsLogKind,
  t: TFunction<'analyticsLogs'>,
): string | null {
  const ids = audience === 'admin' ? [draft.tenantId, draft.siteId, draft.nodeId] : [draft.siteId, draft.nodeId]
  if (ids.some((value) => value.trim() !== '' && !uuidPattern.test(value.trim()))) return t('states.invalidUuid')
  if (draft.domain.trim() !== '' && !normalizedHosts(draft.domain)) return t('states.invalidDomain')
  if (draft.uriPath && !validURIPathFilter(draft.uriPath)) return t('states.invalidRequest')
  const from = new Date(draft.from)
  const to = new Date(draft.to)
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) return t('states.invalidWindow')
  if (to.getTime() - from.getTime() > maximumWindowMilliseconds) return t('states.rangeTooLong')
  if (draft.statusCode.trim()) {
    const status = Number(draft.statusCode)
    const isWebStatus = status >= 100
      && status <= 599
    const valid = Number.isInteger(status) && ((kind === 'block' && status === 0) || isWebStatus)
    if (!valid) return t(kind === 'access' ? 'states.invalidAccessStatus' : 'states.invalidStatus')
  }
  if (kind === 'access') {
    const byteRanges = [
      [draft.requestBytesMin, draft.requestBytesMax],
      [draft.responseBytesMin, draft.responseBytesMax],
    ]
    if (byteRanges.some(([minimum, maximum]) => {
      const values = [minimum, maximum].filter(Boolean).map(Number)
      return values.some((value) => !Number.isSafeInteger(value) || value < 0) ||
        minimum !== '' && maximum !== '' && Number(minimum) > Number(maximum)
    }) || draft.userAgent.length > 512 || draft.contentType !== '' &&
      !/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(draft.contentType)) return t('states.invalidRequest')
  }
  return null
}

function buildFilters(draft: DraftFilters, audience: AnalyticsAudience, kind: AnalyticsLogKind, eventType?: string): AnalyticsLogFilters {
  return {
    from: new Date(draft.from).toISOString(),
    to: new Date(draft.to).toISOString(),
    ...(audience === 'admin' && optional(draft.tenantId) ? { tenantId: optional(draft.tenantId) } : {}),
    ...(optional(draft.siteId) ? { siteId: optional(draft.siteId) } : {}),
    ...(normalizedHosts(draft.domain) ? { host: normalizedHosts(draft.domain) } : {}),
    ...(optional(draft.nodeId) ? { nodeId: optional(draft.nodeId) } : {}),
    ...(optional(draft.clientIp) ? { clientIp: optional(draft.clientIp) } : {}),
    ...(draft.uriPath ? { uriPath: draft.uriPath, ...(draft.uriPathMatch === 'prefix' ? { uriPathMatch: 'prefix' as const } : {}) } : {}),
    ...(draft.statusCode.trim() ? { statusCode: Number(draft.statusCode) } : {}),
    ...(optional(draft.countryCode) ? { countryCode: draft.countryCode.trim().toUpperCase() } : {}),
    ...(optional(draft.carrier) ? { carrier: optional(draft.carrier) } : {}),
    ...(kind === 'block' && draft.action ? { action: draft.action } : {}),
    ...(kind === 'block' && eventType ? { eventType } : {}),
    ...(kind === 'access' && optional(draft.method) ? { method: draft.method.trim().toUpperCase() } : {}),
    ...(kind === 'access' && optional(draft.protocol) ? { protocol: optional(draft.protocol) } : {}),
    ...(kind === 'access' && optional(draft.cacheStatus) ? { cacheStatus: optional(draft.cacheStatus) } : {}),
    ...(kind === 'access' && optional(draft.upstreamResult) ? { upstreamResult: optional(draft.upstreamResult) } : {}),
    ...(kind === 'access' && optional(draft.contentType) ? { contentType: draft.contentType.trim().toLowerCase() } : {}),
    ...(kind === 'access' && optional(draft.userAgent) ? { userAgent: optional(draft.userAgent) } : {}),
    ...(kind === 'access' && draft.requestBytesMin.trim() ? { requestBytesMin: Number(draft.requestBytesMin) } : {}),
    ...(kind === 'access' && draft.requestBytesMax.trim() ? { requestBytesMax: Number(draft.requestBytesMax) } : {}),
    ...(kind === 'access' && draft.responseBytesMin.trim() ? { responseBytesMin: Number(draft.responseBytesMin) } : {}),
    ...(kind === 'access' && draft.responseBytesMax.trim() ? { responseBytesMax: Number(draft.responseBytesMax) } : {}),
    ...(optional(draft.ja4) ? { ja4: optional(draft.ja4) } : {}),
  }
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.requestFailed'
  if (error.status === 400 || error.code === 'analytics_logs_invalid_request') return 'states.invalidRequest'
  if (error.status === 404 || error.code === 'analytics_logs_route_not_found') return 'states.notFound'
  if (error.status === 422 || error.code === 'analytics_logs_capability_unsupported') return 'states.unsupported'
  if (error.status === 503 || error.code === 'analytics_logs_storage_unavailable') return 'states.storageUnavailable'
  if (error.status === 504 || error.code === 'analytics_logs_query_timeout') return 'states.queryTimeout'
  return 'states.requestFailed'
}

function code(value: string): React.ReactNode {
  return <span className="analytics-log-code" title={value}>{value || '-'}</span>
}

/**
 * Technical log references have no stable display_id contract yet. Keep the
 * full value available to assistive technology/tooltips while reserving the
 * table cell for the compact placeholder used by the reference UI.
 */
function opaqueID(value: string | null | undefined): React.ReactNode {
  const id = value?.trim() ?? ''
  if (!id || !uuidPattern.test(id)) return code(id)
  return (
    <span
      className="analytics-log-opaque-id"
      title={id || undefined}
      aria-label={id || undefined}
    >
      —
    </span>
  )
}

// 节点列：有节点名就显示节点名（完整 UUID 在提示里），否则保持 UUID 占位。
function nodeReference(name: string | undefined, id: string): React.ReactNode {
  const label = name?.trim()
  if (!label) return opaqueID(id)
  return <span className="analytics-log-code" title={id}>{label}</span>
}

// 未回源：没有任何回源计时（缓存命中、拦截页、套餐过期页等本节点直接应答）。
function notToOrigin(event: LogEvent): boolean {
  return event.origin_connect_us === null && event.origin_first_byte_us === null && event.origin_total_us === null
}

/**
 * A site or rule reference (P14): its name when the control plane resolved
 * one, otherwise the first 8 characters of the ID; the full ID is always in
 * the tooltip and the copy button.
 */
function namedReference(name: string | undefined, id: string, copyLabel: string): React.ReactNode {
  const value = id.trim()
  if (!value) return code('')
  const label = name?.trim() || (value.length > 12 ? `${value.slice(0, 8)}…` : value)
  return (
    <Typography.Text
      className="analytics-log-reference"
      title={value}
      copyable={{ text: value, tooltips: [copyLabel, '✓'] }}
    >
      {label}
    </Typography.Text>
  )
}

/** The request path with the query the node logged (sensitive values already ***). */
function requestPath(event: LogEvent): string {
  const query = 'uri_query' in event ? event.uri_query : ''
  return query ? `${event.uri_path}?${query}` : event.uri_path
}

function headerValue(headers: Record<string, string>, name: string): string {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name)
  return entry?.[1] ?? ''
}

function securityValue(kind: keyof typeof securityValueKeys, value: string, t: TFunction<'analyticsLogs'>): string {
  const key = (securityValueKeys[kind] as Record<string, string>)[value]
  return key ? t(key) : value || t('values.unknown')
}

function redactCapturedValue(value: unknown, redacted: string, name = ''): unknown {
  if (name && isSensitiveAnalyticsCaptureName(name)) return redacted
  if (Array.isArray(value)) return value.map((item) => redactCapturedValue(item, redacted))
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key,
      redactCapturedValue(item, redacted, key),
    ]))
  }
  return value
}

function capturedDetails(value: unknown, redacted: string): React.ReactNode {
  return code(value === null ? '' : JSON.stringify(redactCapturedValue(value, redacted)))
}

function carrierCell(event: LogEvent, ipT: TFunction<'ipIntel'>): React.ReactNode {
  const idc = logIDC(event, ipT)
  return <>{logCarrier(event, ipT)}{idc ? <span className="analytics-log-idc-tag">{idc}</span> : null}</>
}

function commonDetails(event: LogEvent, t: TFunction<'analyticsLogs'>, locale: string, ipT: TFunction<'ipIntel'>): DetailItem[] {
  return [
    { key: 'event', label: t('detail.eventId'), children: code(event.event_id), span: 'filled' },
    { key: 'occurred', label: t('detail.occurredAt'), children: formatDateTime(event.occurred_at, locale) },
    { key: 'status', label: t('table.status'), children: formatNumber(event.status_code, locale) },
    ...('site_domain' in event && event.site_domain
      ? [{ key: 'siteDomain', label: t('detail.siteDomain'), children: event.site_domain, span: 'filled' as const }] : []),
    { key: 'site', label: t('table.site'), children: code(event.site_id), span: 'filled' },
    { key: 'node', label: t('detail.nodeId'), children: code(event.node_id), span: 'filled' },
    { key: 'requestId', label: t('detail.requestId'), children: code(event.request_id), span: 'filled' },
    { key: 'traceId', label: t('detail.traceId'), children: code(event.trace_id), span: 'filled' },
    { key: 'configVersion', label: t('detail.configVersion'), children: code(event.config_version_id), span: 'filled' },
    { key: 'host', label: t('table.host'), children: code(event.host) },
    { key: 'path', label: t('table.path'), children: code(requestPath(event)) },
    { key: 'ip', label: t('table.clientIp'), children: code(displayIP(event.client_ip)) },
    { key: 'region', label: t('detail.regionCarrier'), children: <>{logRegion(event, locale)} / {carrierCell(event, ipT)}</> },
    { key: 'asn', label: ipT('columns.asn'), children: logASN(event, ipT) },
    { key: 'request', label: t('detail.requestBytes'), children: formatBytes(event.request_bytes, locale) },
    { key: 'response', label: t('table.responseBytes'), children: formatBytes(event.response_bytes, locale) },
  ]
}

function AnalyticsLogPageContent({ kind, owner, ownerKey, embedded, layout, seed, eventType }: {
  kind: AnalyticsLogKind
  owner: AnalyticsLogOwner
  ownerKey: string
  embedded: boolean
  layout: AnalyticsLogLayout
  seed?: AnalyticsLogSeed
  eventType?: string
}) {
  const { t, i18n } = useTranslation('analyticsLogs')
  const actionOptions: Array<{ value: SecurityLogAction; label: string }> = [
    { value: '', label: t('filters.actionAll') }, { value: 'block', label: t('filters.actionBlock') },
    { value: 'challenge', label: t('filters.actionChallenge') }, { value: 'log', label: t('filters.actionLog') },
    { value: 'temporary_ban', label: t('filters.actionTemporaryBan') },
  ]
  const { t: ipT } = useTranslation('ipIntel')
  const queryClient = useQueryClient()
  const queryOwner = useRef(owner).current
  const audience: AnalyticsAudience = queryOwner[0] === 'platform' ? 'admin' : 'tenant'
  const lineageActiveRef = useRef(true)
  const activeQueryIdentityRef = useRef('')
  const window = useMemo(initialWindow, [])
  const searchParams = useSearchParams()[0]
  const navigate = useNavigate()
  const location = useLocation()
  const drilledFromAnalysis = (location.state as { drillFrom?: string } | null)?.drillFrom === 'analysis'
  // TEL-UX-DRILL：数据分析"查看日志"带来的条件（白名单）；旧链接的 addr/host/uri_path 照旧。
  // 条件原样放进草稿：无效的不丢弃（丢了就悄悄放宽成全部日志），而是拒绝查询并提示。
  // 其余下钻键只认访问日志自己的路由：日志中心内嵌本页时，它的 ?node_id= 是审计对象过滤。
  const drillRoute = kind === 'access' && location.pathname.endsWith('/monitor/site/access-log')
  // URL 里的条件也是本页回写的已生效条件（filterParam：本标签页上一会话写的不读回）；WAF 概览带 seed 跳来时以 seed 为准。
  const linkParam = (key: string) => (seed ? '' : filterParam(searchParams, key))
  const drillParam = (key: string) => (drillRoute ? linkParam(key) : '')
  const linkedWindow = (): Partial<DraftFilters> => {
    if (!drillRoute || (!searchParams.has('from') && !searchParams.has('to'))) return {}
    const linkedFrom = Date.parse(linkParam('from'))
    const linkedTo = Date.parse(linkParam('to'))
    return {
      from: Number.isFinite(linkedFrom) ? localDateTimeValue(new Date(linkedFrom)) : '',
      to: Number.isFinite(linkedTo) ? localDateTimeValue(new Date(linkedTo)) : '',
      timePreset: 'custom',
    }
  }
  const emptyDraft = (): DraftFilters => ({
    tenantId: '', siteId: '', domain: '', nodeId: '', clientIp: '', uriPath: '', uriPathMatch: 'exact', statusCode: '', countryCode: '', carrier: '', action: '',
    method: '', protocol: '', cacheStatus: '', upstreamResult: '', contentType: '', userAgent: '',
    requestBytesMin: '', requestBytesMax: '', responseBytesMin: '', responseBytesMax: '', ja4: '', timePreset: 'today', ...window,
  })
  const linkedDraft = (): DraftFilters => ({
    ...emptyDraft(),
    ...linkedWindow(),
    ...(audience === 'admin' ? { tenantId: drillParam('tenant_id') } : {}),
    siteId: drillParam('site_id'),
    nodeId: drillParam('node_id'),
    domain: linkParam('host'),
    clientIp: drillParam('client_ip') || linkParam('addr'),
    uriPath: searchParams.get('uri_path') ?? '',
    ja4: drillParam('ja4'),
    countryCode: drillParam('country_code'),
    carrier: drillParam('carrier'),
  })
  const seededDraft = (): DraftFilters => ({
    ...linkedDraft(),
    ...(seed?.from && seed.to ? { from: localDateTimeValue(new Date(seed.from)), to: localDateTimeValue(new Date(seed.to)), timePreset: 'custom' } : {}),
    ...(seed?.domain ? { domain: seed.domain } : {}),
    ...(seed?.clientIp ? { clientIp: seed.clientIp } : {}),
    ...(seed?.siteId ? { siteId: seed.siteId } : {}),
    ...(seed?.nodeId ? { nodeId: seed.nodeId } : {}),
    ...(seed?.action ? { action: seed.action } : {}),
  })
  const [draft, setDraft] = useState<DraftFilters>(seededDraft)
  const currentDraft = draft
  const [initialError] = useState(() => validateDraft(seededDraft(), audience, kind, t))
  // 链接条件无效时不发首查，直到用户改正后点查询或重置。
  const [linkBlocked, setLinkBlocked] = useState(initialError !== null)
  const [appliedFilters, setAppliedFilters] = useState<AnalyticsLogFilters>(() =>
    buildFilters(initialError === null ? seededDraft() : emptyDraft(), audience, kind, eventType))
  const [validationError, setValidationError] = useState<string | null>(initialError)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageCursors, setPageCursors] = useState<Array<string | undefined>>([undefined])
  const [queryGeneration, setQueryGeneration] = useState(0)
  const [selected, setSelected] = useState<LogEvent | null>(null)
  const [quickFilter, setQuickFilter] = useState<AccessQuickFilter>('domain')
  const cursor = pageCursors[pageIndex]
  // Logs load on entry (platform-wide for operators); tenant only narrows.
  // Exports stay tenant-owned, so the platform must pick a tenant to export.
  const exportReady = !linkBlocked && (audience === 'tenant' || Boolean(appliedFilters.tenantId))

  const queryPrefix = useMemo(() => ['analytics-logs', kind, queryOwner] as const, [kind, queryOwner])
  const queryKey = useMemo(
    () => [...queryPrefix, appliedFilters, queryGeneration, cursor] as const,
    [appliedFilters, cursor, queryGeneration, queryPrefix],
  )
  const queryIdentity = JSON.stringify(queryKey)
  activeQueryIdentityRef.current = queryIdentity

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      queryClient.removeQueries({ queryKey: queryPrefix })
    }
  }, [queryClient, queryPrefix, lineageActiveRef])

  const query = useQuery<AnalyticsLogPage<LogEvent>>({
    queryKey,
    queryFn: async () => {
      const accessToken = lineageActiveRef.current ? currentAnalyticsLogAccess(ownerKey) : null
      if (!accessToken) throw staleAnalyticsLogRead
      if (audience === 'admin') {
        const filters = appliedFilters
        try {
          const result = kind === 'access'
            ? await analyticsLogsApi.listAccess(accessToken, 'admin', filters, pageSize, cursor)
            : await analyticsLogsApi.listBlocks(accessToken, 'admin', filters, pageSize, cursor)
          if (!lineageActiveRef.current || !currentAnalyticsLogAccess(ownerKey) || activeQueryIdentityRef.current !== queryIdentity) throw staleAnalyticsLogRead
          return result
        } catch (error) {
          if (!lineageActiveRef.current || !currentAnalyticsLogAccess(ownerKey) || activeQueryIdentityRef.current !== queryIdentity) throw staleAnalyticsLogRead
          throw error
        }
      }
      try {
        const result = kind === 'access'
          ? await analyticsLogsApi.listAccess(accessToken, 'tenant', appliedFilters, pageSize, cursor)
          : await analyticsLogsApi.listBlocks(accessToken, 'tenant', appliedFilters, pageSize, cursor)
        if (!lineageActiveRef.current || !currentAnalyticsLogAccess(ownerKey) || activeQueryIdentityRef.current !== queryIdentity) throw staleAnalyticsLogRead
        return result
      } catch (error) {
        if (!lineageActiveRef.current || !currentAnalyticsLogAccess(ownerKey) || activeQueryIdentityRef.current !== queryIdentity) throw staleAnalyticsLogRead
        throw error
      }
    },
    enabled: Boolean(!linkBlocked && lineageActiveRef.current && currentAnalyticsLogAccess(ownerKey)),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
    gcTime: Infinity,
    staleTime: Infinity,
  })

  // 最近一次 apply 的草稿（含校验不过的那次，避免同一非法草稿反复校验）。
  const [appliedDraftKey, setAppliedDraftKey] = useState(() => JSON.stringify(seededDraft()))
  const resetPages = () => {
    setPageIndex(0)
    setPageCursors([undefined])
    setQueryGeneration((current) => current + 1)
  }
  const apply = (base: DraftFilters = currentDraft, live = false) => {
    const draft = resolvedDraft(base, kind)
    if (draft !== currentDraft) setDraft(draft)
    setAppliedDraftKey(JSON.stringify(draft))
    const error = validateDraft(draft, audience, kind, t)
    setValidationError(error)
    if (error) return
    setSelected(null)
    setLinkBlocked(false)
    const next = buildFilters(draft, audience, kind, eventType)
    if (JSON.stringify(next) === JSON.stringify(appliedFilters) && pageIndex === 0) {
      if (!live) void query.refetch()
      return
    }
    setAppliedFilters(next)
    resetPages()
  }
  // 边输入边生效——草稿停下 400ms 后自动 apply（下拉/时间范围同样经此生效）；
  // apply 校验不过就地报错、不发请求。比较只看草稿本身（相对时间范围不因时钟走动反复查询）。
  const draftKey = JSON.stringify(currentDraft)
  useLiveApply(draftKey, appliedDraftKey, () => apply(currentDraft, true))
  // 已生效的域名/客户端 IP/路径写回 URL（与排行「查看日志」深链同名：host/addr/uri_path）。
  useFilterUrl({ host: appliedFilters.host, addr: appliedFilters.clientIp, uri_path: appliedFilters.uriPath })
  const reset = () => {
    const next = emptyDraft()
    setAppliedDraftKey(JSON.stringify(next))
    setDraft(next)
    setLinkBlocked(false)
    setValidationError(null)
    setSelected(null)
    setAppliedFilters(buildFilters(next, audience, kind, eventType))
    resetPages()
  }
  const nextPage = () => {
    const nextCursor = query.data?.meta.next_cursor
    if (!nextCursor) return
    setPageCursors((current) => [...current.slice(0, pageIndex + 1), nextCursor])
    setPageIndex((current) => current + 1)
  }
  // LOG-02：导出申请的原条件按"标签：值"列出；字段名与查询表单同名，只列有值的项。
  const exportFilterText = (filter: AnalyticsLogExportFilter): string => ([
    ['site_id', t('filters.site')], ['host', t('filters.domain')], ['node_id', t('filters.node')],
    ['client_ip', t('filters.clientIp')], ['uri_path', t('table.path')], ['status_code', t('filters.status')],
    ['country_code', t('filters.country')], ['carrier', t('filters.carrier')], ['method', t('filters.method')],
    ['protocol', t('filters.protocol')], ['cache_status', t('filters.cache')], ['upstream_result', exportText('upstreamResult')],
    ['content_type', exportText('contentType')], ['user_agent', exportText('userAgent')],
    ['request_bytes_min', exportText('requestBytesMin')], ['request_bytes_max', exportText('requestBytesMax')],
    ['response_bytes_min', exportText('responseBytesMin')], ['response_bytes_max', exportText('responseBytesMax')],
    ['ja4', t('table.tls')],
  ] as const).filter(([key]) => filter[key] !== undefined)
    .map(([key, label]) => `${label}：${filter[key]}${key === 'uri_path' && filter.uri_path_match === 'prefix' ? ` (${t('parity.uriPathPrefix')})` : ''}`)
    .join('；')
  const appliedTags = ([
    [t('filters.tenant'), audience === 'admin' ? appliedFilters.tenantId : undefined],
    [t('filters.site'), appliedFilters.siteId],
    [t('filters.domain'), appliedFilters.host],
    [t('filters.node'), appliedFilters.nodeId],
    [t('filters.clientIp'), appliedFilters.clientIp],
    [t('table.path'), appliedFilters.uriPath],
    [t('table.tls'), appliedFilters.ja4],
    [t('filters.country'), appliedFilters.countryCode],
    [t('filters.carrier'), appliedFilters.carrier],
  ] as const).filter((entry): entry is readonly [string, string] => Boolean(entry[1]))
  const tableLoading = query.isFetching && !query.data
  const exportText = (key: Parameters<typeof analyticsLogExportMessage>[1]) =>
    analyticsLogExportMessage(i18n.resolvedLanguage ?? 'zh-CN', key)
  const [downloadError, setDownloadError] = useState(false)
  const [exportHint, setExportHint] = useState(false)
  const [exportsVisible, setExportsVisible] = useState(false)
  const [accessView, setAccessView] = useState<'logs' | 'exports'>('logs')
  const exportsQueryKey = [...queryPrefix, 'exports', appliedFilters.tenantId] as const
  const exportsQuery = useQuery({
    queryKey: exportsQueryKey,
    queryFn: async () => {
      const accessToken = currentAnalyticsLogAccess(ownerKey)
      if (!accessToken) throw staleAnalyticsLogRead
      const result = await analyticsLogsApi.listAccessExports(accessToken, audience, appliedFilters.tenantId)
      if (!lineageActiveRef.current || currentAnalyticsLogAccess(ownerKey) !== accessToken) {
        throw staleAnalyticsLogRead
      }
      return result
    },
    enabled: kind === 'access' && exportReady && exportsVisible,
    retry: false,
    refetchInterval: (state) => state.state.data?.some((item) => item.status === 'pending' || item.status === 'running') ? 2000 : false,
  })
  // LOG-01：申请时冻结筛选条件与幂等键；结果未知（断网/超时/5xx）时只能用原请求
  // 重试或去申请记录核对，不会生成第二份申请；确定失败可修改条件后重新申请。
  // LOG-01：申请归属账号+查询范围，重新登录后按当前条件找回本账号的申请，
  // 在日志视图就地显示状态与失败原因。
  const exportScopeQueryKey = [...queryPrefix, 'export-scope', appliedFilters] as const
  const exportScopeQuery = useQuery({
    queryKey: exportScopeQueryKey,
    queryFn: async () => {
      const accessToken = currentAnalyticsLogAccess(ownerKey)
      if (!accessToken) throw staleAnalyticsLogRead
      const result = await analyticsLogsApi.findAccessExportForScope(accessToken, audience, appliedFilters)
      if (!lineageActiveRef.current || currentAnalyticsLogAccess(ownerKey) !== accessToken) {
        throw staleAnalyticsLogRead
      }
      return result
    },
    // 日志读到之后再找回，避免日志读不出时多打一次接口。
    enabled: kind === 'access' && exportReady && accessView === 'logs' && query.isSuccess,
    retry: false,
    refetchInterval: (state) => state.state.data?.status === 'pending' || state.state.data?.status === 'running' ? 2000 : false,
  })
  const scopeExport = exportScopeQuery.data ?? null
  const exportAttemptRef = useRef<{ filters: typeof appliedFilters; key: string } | null>(null)
  const exportMutation = useMutation({
    mutationFn: async () => {
      const accessToken = currentAnalyticsLogAccess(ownerKey)
      const frozen = exportAttemptRef.current
      if (!accessToken || !frozen) throw staleAnalyticsLogRead
      return analyticsLogsApi.createAccessExport(accessToken, audience, frozen.filters, frozen.key)
    },
    onSuccess: () => {
      exportAttemptRef.current = null
      setExportsVisible(true)
      setAccessView('exports')
      void queryClient.invalidateQueries({ queryKey: exportsQueryKey })
      void queryClient.invalidateQueries({ queryKey: [...queryPrefix, 'export-scope'] })
    },
    onError: (error) => {
      if (!exportOutcomeUnknown(error)) exportAttemptRef.current = null
    },
  })
  const exportUnknown = exportMutation.isError && exportAttemptRef.current !== null && exportOutcomeUnknown(exportMutation.error)
  const requestExport = () => {
    if (exportMutation.isPending) return
    // 当前条件已有申请时幂等键由原申请编号决定：重试、重新登录后再点都用同一键。
    if (!exportUnknown) {
      exportAttemptRef.current = {
        filters: appliedFilters,
        key: `access-export-${scopeExport?.id ?? crypto.randomUUID()}`,
      }
    }
    exportMutation.mutate()
  }
  const downloadExport = async (exportID: string) => {
    const accessToken = currentAnalyticsLogAccess(ownerKey)
    if (!accessToken) return
    setDownloadError(false)
    try {
      const grant = await analyticsLogsApi.grantAccessExportDownload(
        accessToken, audience, exportID, appliedFilters.tenantId,
      )
      if (!lineageActiveRef.current || currentAnalyticsLogAccess(ownerKey) !== accessToken) return
      const blob = await analyticsLogsApi.downloadAccessExport(
        accessToken, audience, exportID, grant.token, appliedFilters.tenantId,
      )
      if (!lineageActiveRef.current || currentAnalyticsLogAccess(ownerKey) !== accessToken) return
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analytics-access-${exportID}.csv`
      link.click()
      URL.revokeObjectURL(url)
      void exportsQuery.refetch()
    } catch {
      setDownloadError(true)
    }
  }

  if (query.error instanceof ApiError && query.error.status === 403) {
    return (
      <Result
        className="analytics-page analytics-page-error"
        status="403"
        title={t('states.permissionTitle')}
        subTitle={t('states.permissionDescription')}
      />
    )
  }

  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const accessQuickFilters: Array<{ value: AccessQuickFilter; label: string; placeholder: string; inputMode?: React.HTMLAttributes<HTMLInputElement>['inputMode'] }> = [
    { value: 'domain', label: t('filters.domain'), placeholder: t('filters.domainPlaceholder') },
    { value: 'clientIp', label: t('parity.clientIp'), placeholder: t('parity.clientIpPlaceholder') },
    { value: 'uriPath', label: t('parity.requestAddress'), placeholder: t('parity.requestAddressPlaceholder') },
    { value: 'method', label: t('filters.method'), placeholder: t('parity.methodPlaceholder') },
    { value: 'statusCode', label: t('filters.status'), placeholder: t('parity.statusPlaceholder'), inputMode: 'numeric' },
    { value: 'cacheStatus', label: t('filters.cache'), placeholder: '' },
    { value: 'ja4', label: t('parity.tlsFingerprint'), placeholder: t('parity.tlsFingerprintPlaceholder') },
    { value: 'nodeId', label: t('parity.nodeId'), placeholder: t('parity.nodeIdPlaceholder') },
    { value: 'countryCode', label: t('parity.country'), placeholder: t('parity.countryPlaceholder') },
    { value: 'carrier', label: t('parity.carrier'), placeholder: t('parity.carrierPlaceholder') },
  ]
  const activeQuickFilter = accessQuickFilters.find((filter) => filter.value === quickFilter)!
  const accessDateTime = (value: string) => {
    const formatted = formatDateTime(value, locale)
    return locale.toLowerCase().startsWith('zh') ? formatted.replaceAll('/', '-') : formatted
  }
  const jobsT = i18n.getFixedT(locale, 'jobs')
  const securityPoliciesT = i18n.getFixedT(locale, 'securityPolicies')
  const sitesT = i18n.getFixedT(locale, 'sites')
  const captureT = i18n.getFixedT(locale, 'analyticsLogSecurity')
  const redacted = captureT('redacted')
  const commonColumns: TableColumnsType<LogEvent> = [
    {
      title: t('table.occurredAt'), dataIndex: 'occurred_at', key: 'occurred_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('table.site'), dataIndex: 'site_id', key: 'site_id', width: 190,
      render: (value: string, event) => namedReference('site_domain' in event ? event.site_domain : '', value, t('actions.copyId')),
    },
    { title: t('table.host'), dataIndex: 'host', key: 'host', width: 190, render: code },
    { title: t('table.path'), dataIndex: 'uri_path', key: 'uri_path', width: 240, render: (_value: string, event) => code(requestPath(event)) },
    { title: t('table.clientIp'), dataIndex: 'client_ip', key: 'client_ip', width: 145, render: (value: string) => code(displayIP(value)) },
  ]
  const accessColumns: TableColumnsType<LogEvent> = [
    { title: t('table.accessTime'), dataIndex: 'occurred_at', key: 'occurred_at', width: 150, render: (value: string) => accessDateTime(value) },
    { title: t('table.host'), dataIndex: 'host', key: 'host', width: 200, render: code },
    { title: t('table.port'), dataIndex: 'listen_port', key: 'port', width: 70, align: 'right', render: (value: number) => value || '-' },
    { title: t('table.protocol'), dataIndex: 'protocol', key: 'protocol', width: 100 },
    { title: t('table.method'), dataIndex: 'method', key: 'method', width: 100 },
    { title: t('table.uri'), dataIndex: 'uri_path', key: 'path', width: 200, render: code },
    { title: t('table.status'), dataIndex: 'status_code', key: 'status_code', width: 80, align: 'right' },
    { title: t('table.accessClientIp'), dataIndex: 'client_ip', key: 'client_ip', width: 150, render: (value: string) => code(displayIP(value)) },
    { title: t('table.tls'), dataIndex: 'ja4', key: 'ja4', width: 180, render: (value: string | null) => code(value ?? '') },
    { title: t('table.region'), dataIndex: 'country_code', key: 'region', width: 150, render: (_value: string, event) => logRegion(event, locale) },
    { title: t('table.carrier'), dataIndex: 'carrier', key: 'carrier', width: 120, render: (_value: string, event) => carrierCell(event, ipT) },
    {
      title: t('table.origin'), dataIndex: 'upstream_addr', key: 'origin', width: 150,
      render: (value: string, event) => value || (notToOrigin(event) ? t('values.notToOrigin') : '-'),
    },
    {
      title: t('table.contentType'), key: 'content_type', width: 200,
      render: (_value, event) => code(headerValue(event.response_headers, 'content-type')),
    },
    {
      title: t('table.referer'), key: 'referer', width: 100,
      render: (_value, event) => code(headerValue(event.request_headers, 'referer')),
    },
    {
      title: t('table.userAgent'), key: 'user_agent', width: 200,
      render: (_value, event) => code(headerValue(event.request_headers, 'user-agent')),
    },
    {
      title: t('table.originDuration'), dataIndex: 'origin_total_us', key: 'origin_total_us', width: 100, align: 'right',
      render: (value: number | null, event) => value === null || value === undefined
        ? (notToOrigin(event) ? t('values.notToOrigin') : '-')
        : t('values.microseconds', { value: formatNumber(value, locale) }),
    },
    {
      title: t('table.returnBytes'), dataIndex: 'response_bytes', key: 'response_bytes', width: 100, align: 'right',
      render: (value: number) => formatBytes(value, locale),
    },
    { title: t('table.cacheHit'), dataIndex: 'cache_status', key: 'cache_status', width: 100 },
    // L1/L2 缓存命中、L2 IP：节点日志与 agent 都不产出分层缓存信息，列一直是 “-”，已去掉。
    ...(audience === 'admin' ? [{
      title: t('table.nodeId'), dataIndex: 'node_id', key: 'node', width: 140,
      render: (value: string, event: LogEvent) => nodeReference('node_name' in event ? event.node_name : undefined, value),
    }] : []),
  ]
  const blockColumns: TableColumnsType<LogEvent> = [
    ...commonColumns,
    { title: t('table.region'), key: 'region', width: 150, render: (_value, event) => logRegion(event, locale) },
    { title: t('table.carrier'), key: 'carrier', width: 120, render: (_value, event) => carrierCell(event, ipT) },
    { title: t('table.eventType'), dataIndex: 'event_type', key: 'event_type', width: 130, render: (value: string) => securityValue('eventType', value, t) },
    { title: t('table.action'), dataIndex: 'action', key: 'action', width: 100, render: (value: string) => securityValue('action', value, t) },
    { title: t('table.severity'), dataIndex: 'severity', key: 'severity', width: 100, render: (value: string) => securityValue('severity', value, t) },
    {
      title: t('table.rule'), dataIndex: 'rule_id', key: 'rule_id', width: 180,
      render: (value: string, event) => namedReference((event as BlockLogEvent).rule_name, value, t('actions.copyId')),
    },
    // CC challenge pages / 429s are one line per minute with their count
    { title: t('table.count'), dataIndex: 'count', key: 'count', width: 85, align: 'right', render: (value: number) => formatNumber(value, locale) },
    { title: t('table.status'), dataIndex: 'status_code', key: 'status_code', width: 85, align: 'right' },
  ]
  // Six merged columns (time, site + path, source + region, rule + type, action + status), no horizontal scroll.
  const wafT = i18n.getFixedT(locale, 'wafLogs')
  const actionTag = (action: string) => (
    <Tag className="waf-v2-action" color={action === 'block' || action === 'deny' ? 'error' : action === 'challenge' ? 'warning' : 'default'}>
      {securityValue('action', action, t)}
    </Tag>
  )
  const stacked = (main: React.ReactNode, sub: React.ReactNode) => (
    <span className="waf-v2-cell"><span className="waf-v2-cell-main">{main}</span><span className="waf-v2-cell-sub">{sub}</span></span>
  )
  const wafColumns: TableColumnsType<LogEvent> = [
    { title: wafT('redesign.columns.time'), dataIndex: 'occurred_at', key: 'occurred_at', width: 168, render: (value: string) => formatDateTime(value, locale) },
    {
      title: wafT('redesign.columns.site'), dataIndex: 'host', key: 'site',
      render: (_value: string, event) => stacked(<span title={event.host}>{event.host || '-'}</span>, <span className="analytics-log-code" title={requestPath(event)}>{requestPath(event)}</span>),
    },
    {
      title: wafT('redesign.columns.source'), dataIndex: 'client_ip', key: 'source', width: 220,
      render: (value: string, event) => stacked(<span className="analytics-log-code" title={value}>{displayIP(value)}</span>,
        <>{logRegion(event, locale)} · {carrierCell(event, ipT)}</>),
    },
    {
      title: wafT('redesign.columns.rule'), dataIndex: 'rule_id', key: 'rule',
      render: (value: string, event) => {
        const block = event as BlockLogEvent
        return stacked(namedReference(block.rule_name, value, t('actions.copyId')),
          `${securityValue('eventType', block.event_type, t)} · ${securityValue('severity', block.severity, t)}`)
      },
    },
    {
      title: wafT('redesign.columns.disposition'), dataIndex: 'action', key: 'disposition', width: 150,
      render: (value: string, event) => {
        const block = event as BlockLogEvent
        return stacked(actionTag(value), <>
          {block.status_code ? wafT('redesign.statusCode', { value: block.status_code }) : null}
          {block.count > 1 ? <span className="waf-v2-count">{wafT('redesign.count', { value: formatNumber(block.count, locale) })}</span> : null}
        </>)
      },
    },
  ]
  const columns: TableColumnsType<LogEvent> = [
    ...(layout === 'waf' ? wafColumns : kind === 'access' ? accessColumns : blockColumns),
    {
      title: t('table.actions'), key: 'actions', width: layout === 'waf' ? 96 : 130,
      render: (_value, event) => (
        <Button type="link" icon={<Eye size={15} />} onClick={(clickEvent) => { clickEvent.stopPropagation(); setSelected(event) }}>{t('actions.details')}</Button>
      ),
    },
  ]
  const detailItems: DetailItem[] = selected ? commonDetails(selected, t, locale, ipT) : []
  if (selected) {
    detailItems.push(
      { key: 'taskId', label: jobsT('columns.id'), children: code(selected.task_id ?? ''), span: 'filled' },
      {
        key: 'requestHeaders', label: sitesT('edit.locked.advanced.requestHeaders'),
        children: capturedDetails(selected.request_headers, redacted), span: 'filled',
      },
      {
        key: 'responseHeaders', label: sitesT('edit.locked.advanced.responseHeadersLog'),
        children: capturedDetails(selected.response_headers, redacted), span: 'filled',
      },
      {
        key: 'requestBody', label: sitesT('edit.locked.advanced.requestBody'),
        children: capturedDetails(selected.request_body, redacted), span: 'filled',
      },
      {
        key: 'responseBody', label: captureT('responseBody'),
        children: capturedDetails(selected.response_body, redacted), span: 'filled',
      },
      { key: 'ja4', label: securityPoliciesT('fields.ja4'), children: code(selected.ja4 ?? ''), span: 'filled' },
    )
  }
  if (selected && kind === 'access') {
    const access = selected as AccessLogEvent
    detailItems.push(
      { key: 'method', label: t('table.method'), children: access.method },
      { key: 'port', label: t('table.port'), children: access.listen_port ? String(access.listen_port) : '-' },
      { key: 'protocol', label: t('detail.protocol'), children: access.protocol },
      { key: 'cache', label: t('table.cache'), children: access.cache_status },
      { key: 'upstream', label: t('detail.upstream'), children: access.upstream_result },
      { key: 'origin', label: t('table.origin'), children: access.upstream_addr || (notToOrigin(access) ? t('values.notToOrigin') : '-') },
      { key: 'duration', label: t('table.duration'), children: t('values.microseconds', { value: formatNumber(access.duration_us, locale) }) },
    )
  } else if (selected) {
    const block = selected as BlockLogEvent
    detailItems.push(
      { key: 'eventType', label: t('table.eventType'), children: securityValue('eventType', block.event_type, t) },
      { key: 'action', label: t('table.action'), children: securityValue('action', block.action, t) },
      { key: 'severity', label: t('table.severity'), children: securityValue('severity', block.severity, t) },
      ...(block.rule_name ? [{ key: 'ruleName', label: t('detail.ruleName'), children: block.rule_name, span: 'filled' as const }] : []),
      { key: 'rule', label: t('table.rule'), children: code(block.rule_id), span: 'filled' },
      { key: 'count', label: t('table.count'), children: formatNumber(block.count, locale) },
    )
    // Attack evidence (WAF / ACL): shown only when the node recorded it.
    if (block.policy_id) detailItems.push({ key: 'policy', label: t('detail.policy'), children: code(block.policy_id), span: 'filled' })
    if (block.detector) detailItems.push({ key: 'detector', label: t('detail.detector'), children: block.detector })
    if (block.matched) detailItems.push({ key: 'matched', label: t('detail.matched'), children: code(block.matched), span: 'filled' })
    if (block.user_agent) detailItems.push({ key: 'userAgent', label: t('detail.userAgent'), children: block.user_agent, span: 'filled' })
    if (block.request_body_excerpt) {
      detailItems.push({ key: 'bodyExcerpt', label: t('detail.bodyExcerpt'), children: code(block.request_body_excerpt), span: 'filled' })
    }
  }

  return (
    <section
      className={`analytics-page analytics-log-page${kind === 'access' ? ' site-access-log-page' : ' analytics-block-log-page'}`}
      aria-label={embedded || kind === 'access' ? t(kind === 'access' ? 'title.access' : 'title.block') : undefined}
      aria-labelledby={!embedded && kind === 'block' ? 'analytics-log-title' : undefined}
    >
      <div className={`analytics-panel${kind === 'access' ? ` access-view-${accessView}` : ''}`}>
        {!embedded && kind === 'block' ? <h1 id="analytics-log-title" className="visually-hidden">{t('title.block')}</h1> : null}
        {kind === 'access' ? (
          <Tabs
            className="analytics-log-tabs"
            activeKey={accessView}
            items={[
              { key: 'logs', label: t('tabs.logs') },
              { key: 'exports', label: t('tabs.exports') },
            ]}
            onChange={(value) => {
              const next = value as 'logs' | 'exports'
              setAccessView(next)
              setExportsVisible(next === 'exports')
            }}
          />
        ) : null}
        {kind !== 'access' || accessView === 'logs' ? <>
        {(() => {
          // 常显 1–3 个条件 + 时间范围 + 查询/重置 + 高级筛选；其余条件进面板，
          // 已生效的高级条件以标签列出（徽标与标签读 appliedFilters，不读草稿）。
          type TextKey = Exclude<keyof DraftFilters, 'uriPathMatch' | 'action'>
          const textField = (key: TextKey, label: string, extra: { placeholder?: string; inputMode?: 'numeric' } = {}) => (
            <Input aria-label={label} {...extra} value={draft[key]} onPressEnter={() => apply()}
              onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))} />
          )
          const pathField = (
            <Space.Compact block><Select aria-label={t('parity.uriPathMatch')} virtual={false} style={{ width: 104 }} value={draft.uriPathMatch} options={[{ value: 'exact', label: t('parity.uriPathExact') }, { value: 'prefix', label: t('parity.uriPathPrefix') }]} onChange={(value: 'exact' | 'prefix') => setDraft((current) => ({ ...current, uriPathMatch: value }))} /><Input aria-label={t('table.path')} value={draft.uriPath} onChange={(event) => setDraft((current) => ({ ...current, uriPath: event.target.value }))} /></Space.Compact>
          )
          const actionField = (
            <Select aria-label={t('filters.action')} virtual={false} value={draft.action} options={actionOptions}
              onChange={(value: DraftFilters['action']) => setDraft((current) => ({ ...current, action: value }))} />
          )
          const number = (value: number | undefined) => value === undefined ? '' : String(value)
          const applied = appliedFilters
          const advanced: Array<AdvancedFilterItem & { key: keyof DraftFilters }> = [
            ...(audience === 'admin' ? [{ key: 'tenantId' as const, label: t('filters.tenant'), field: textField('tenantId', t('filters.tenant')), applied: applied.tenantId }] : []),
            { key: 'siteId', label: t('filters.site'), field: textField('siteId', t('filters.site'), { placeholder: t('filters.sitePlaceholder') }), applied: applied.siteId },
            { key: 'nodeId', label: t('filters.node'), field: textField('nodeId', t('filters.node')), applied: applied.nodeId },
            ...(layout === 'waf' ? [] : [{ key: 'clientIp' as const, label: t('filters.clientIp'), field: textField('clientIp', t('filters.clientIp')), applied: applied.clientIp }]),
            {
              key: 'uriPath', label: t('table.path'), field: pathField, wide: true,
              applied: applied.uriPath ? `${applied.uriPathMatch === 'prefix' ? t('parity.uriPathPrefix') : t('parity.uriPathExact')} ${applied.uriPath}` : '',
            },
            { key: 'statusCode', label: t('filters.status'), field: textField('statusCode', t('filters.status'), { inputMode: 'numeric' }), applied: number(applied.statusCode) },
            { key: 'countryCode', label: t('filters.country'), field: textField('countryCode', t('filters.country')), applied: applied.countryCode },
            { key: 'carrier', label: t('filters.carrier'), field: textField('carrier', t('filters.carrier')), applied: applied.carrier },
            ...(kind === 'block' && layout !== 'waf' ? [{
              key: 'action' as const, label: t('filters.action'), field: actionField,
              applied: applied.action ? actionOptions.find((option) => option.value === applied.action)?.label : '',
            }] : []),
            { key: 'ja4', label: securityPoliciesT('fields.ja4'), field: textField('ja4', securityPoliciesT('fields.ja4')), applied: applied.ja4 },
            ...(kind === 'access' ? [
              { key: 'method' as const, label: t('filters.method'), field: textField('method', t('filters.method')), applied: applied.method },
              { key: 'protocol' as const, label: t('filters.protocol'), field: textField('protocol', t('filters.protocol')), applied: applied.protocol },
              { key: 'cacheStatus' as const, label: t('filters.cache'), field: textField('cacheStatus', t('filters.cache')), applied: applied.cacheStatus },
              { key: 'upstreamResult' as const, label: exportText('upstreamResult'), field: textField('upstreamResult', exportText('upstreamResult')), applied: applied.upstreamResult },
              { key: 'contentType' as const, label: exportText('contentType'), field: textField('contentType', exportText('contentType')), applied: applied.contentType },
              { key: 'userAgent' as const, label: exportText('userAgent'), field: textField('userAgent', exportText('userAgent')), applied: applied.userAgent },
              { key: 'requestBytesMin' as const, label: exportText('requestBytesMin'), field: textField('requestBytesMin', exportText('requestBytesMin'), { inputMode: 'numeric' }), applied: number(applied.requestBytesMin) },
              { key: 'requestBytesMax' as const, label: exportText('requestBytesMax'), field: textField('requestBytesMax', exportText('requestBytesMax'), { inputMode: 'numeric' }), applied: number(applied.requestBytesMax) },
              { key: 'responseBytesMin' as const, label: exportText('responseBytesMin'), field: textField('responseBytesMin', exportText('responseBytesMin'), { inputMode: 'numeric' }), applied: number(applied.responseBytesMin) },
              { key: 'responseBytesMax' as const, label: exportText('responseBytesMax'), field: textField('responseBytesMax', exportText('responseBytesMax'), { inputMode: 'numeric' }), applied: number(applied.responseBytesMax) },
            ] : []),
          ]
          const items: AdvancedFilterItem[] = advanced
          // 网站访问日志的时间范围控件保持原样，放在面板里，不计入高级条件。
          if (kind === 'access') {
            items.push({
              key: 'timeRange', label: t('filters.timeRange'), wide: true, field: (
                <div className="analytics-log-time-range">
                  <span className="analytics-log-time-range-label">{t('filters.timeRange')}</span>
                  <label className="analytics-filter-field analytics-log-time-field analytics-log-time-field-start"><span>{t('filters.from')}</span><Input id="site-access-log-from" type="datetime-local" aria-label={t('filters.from')} value={draft.from} onChange={(event) => setDraft((current) => ({ ...current, from: event.target.value }))} /></label>
                  <span className="analytics-log-time-separator" aria-hidden="true">–</span>
                  <label className="analytics-filter-field analytics-log-time-field analytics-log-time-field-end"><span>{t('filters.to')}</span><Input type="datetime-local" aria-label={t('filters.to')} value={draft.to} onChange={(event) => setDraft((current) => ({ ...current, to: event.target.value }))} /></label>
                </div>
              ),
            })
          }
          const cleared = (keys: string[]): DraftFilters => {
            const next = { ...draft }
            for (const key of keys) {
              if (key === 'timeRange') continue
              if (key === 'uriPath') next.uriPathMatch = 'exact'
              ;(next as unknown as Record<string, string>)[key] = ''
            }
            return next
          }
          const timeRange = kind === 'block' ? (
            <div className={layout === 'waf' ? 'waf-v2-field waf-v2-range-field' : 'analytics-filter-field analytics-log-range-field'}><span>{t('filters.timeRange')}</span><TimeRangeFilter label={t('filters.timeRange')} maxSpanMs={maximumWindowMilliseconds} allowClear={false}
              value={{ preset: draft.timePreset, range: [dayjs(draft.from), dayjs(draft.to)] }}
              onChange={({ preset, range }) => { if (range) setDraft((current) => ({ ...current, timePreset: preset, from: localDateTimeValue(range[0].toDate()), to: localDateTimeValue(range[1].toDate()) })) }} /></div>
          ) : null
          const domainField = (
            <label className={layout === 'waf' ? 'waf-v2-field waf-v2-domain-field' : 'analytics-filter-field analytics-log-domain-filter'}><span>{t('filters.domain')}</span>
              <Input aria-label={t('filters.domain')} placeholder={t('filters.domainPlaceholder')} value={draft.domain} onPressEnter={() => apply()}
                onChange={(event) => setDraft((current) => ({ ...current, domain: event.target.value }))} /></label>
          )
          const primary = layout === 'waf' ? <>
            {domainField}
            <label className="waf-v2-field"><span>{t('filters.clientIp')}</span>{textField('clientIp', t('filters.clientIp'))}</label>
            <div className="waf-v2-field waf-v2-action-field"><span>{t('filters.action')}</span>{actionField}</div>
            {timeRange}
          </> : kind === 'block' ? <>{domainField}{timeRange}</> : (
            <div className="analytics-log-domain-control">
              <Select
                className="analytics-log-quick-filter"
                aria-label={t('filters.domainMode')}
                virtual={false}
                value={quickFilter}
                options={accessQuickFilters.map(({ value, label }) => ({ value, label }))}
                onChange={(value: AccessQuickFilter) => setQuickFilter(value)}
              />
              <label className="analytics-filter-field analytics-log-site-filter">
                <span>{activeQuickFilter.label}</span>
                {quickFilter === 'cacheStatus' ? <Select
                  aria-label={activeQuickFilter.label}
                  allowClear
                  virtual={false}
                  placeholder={activeQuickFilter.label}
                  value={draft.cacheStatus || undefined}
                  options={[
                    { value: 'HIT', label: t('parity.hit') },
                    { value: 'MISS', label: t('parity.miss') },
                  ]}
                  onChange={(value) => setDraft((current) => ({ ...current, cacheStatus: value ?? '' }))}
                /> : (
                <Input
                  aria-label={activeQuickFilter.label}
                  inputMode={activeQuickFilter.inputMode}
                  placeholder={activeQuickFilter.placeholder}
                  value={draft[quickFilter]}
                  onPressEnter={() => apply()}
                  onChange={(event) => setDraft((current) => ({ ...current, [quickFilter]: event.target.value }))}
                />
                )}
              </label>
            </div>
          )
          return <div className={layout === 'waf' ? 'waf-v2-filters' : 'analytics-log-advfilters'} role="search" aria-label={layout === 'waf' ? wafT('redesign.logFilters') : t('filters.label')}>
            <AdvancedFilters
              storageKey={`analytics-logs.${kind}.${layout}`}
              columns={kind === 'access' ? 4 : 3}
              primary={primary}
              items={items}
              onQuery={() => apply()}
              onReset={reset}
              onClearAdvanced={() => apply(cleared(items.map((item) => item.key)))}
              onRemove={(key) => apply(cleared([key]))}
              extra={kind === 'access' ? <div className="analytics-log-toolbar-actions">
                {/* Exports are tenant scoped (the platform API requires tenant_id), so the
                    platform view needs an applied tenant before a request can be sent. */}
                {/* ui-errmsg-1024: the tenant hint shows only after a click, so it is not read as needed for viewing. */}
                <Button className="analytics-log-export-action" loading={exportMutation.isPending}
                  aria-describedby={exportHint && !exportReady ? 'analytics-log-export-tenant-hint' : undefined}
                  disabled={exportUnknown}
                  onClick={() => { if (exportReady) requestExport(); else setExportHint(true) }}>{exportText('create')}</Button>
                {exportHint && !exportReady ? <span id="analytics-log-export-tenant-hint" className="analytics-log-export-hint" role="status">{exportText('tenantRequired')}</span> : null}
              </div> : undefined}
            />
            {kind === 'access' && accessView === 'logs' && exportMutation.isError && exportMutation.error !== staleAnalyticsLogRead ? (
              <FeedbackWhen
                title={exportUnknown ? exportText('createUnknown') : exportCreateError(exportMutation.error, exportText)}
                action={exportUnknown ? <Space size={4}>
                  <Button size="small" loading={exportMutation.isPending} onClick={requestExport}>{exportText('retrySame')}</Button>
                  <Button size="small" onClick={() => { setExportsVisible(true); setAccessView('exports'); void exportsQuery.refetch() }}>{exportText('viewRecords')}</Button>
                </Space> : undefined}
                onClose={exportUnknown ? undefined : () => exportMutation.reset()}
              />
            ) : null}
            {kind === 'access' && accessView === 'logs' && scopeExport && !exportUnknown ? (
              <div className="analytics-log-scope-export" role="status">
                <span>
                  {exportText('scopeExisting')}
                  <strong>{exportExpired(scopeExport) ? exportText('expired') : exportText(scopeExport.status)}</strong>
                  {scopeExport.status === 'failed' ? <small className="analytics-log-export-reason">{exportFailureReason(scopeExport.reason, exportText)}</small> : null}
                  {scopeExport.status === 'completed' && scopeExport.row_count === 0 ? <small className="analytics-log-export-reason">{exportText('noRows')}</small> : null}
                </span>
                <Space size={4}>
                  {scopeExport.downloadable && !exportExpired(scopeExport) ? (
                    <Button size="small" icon={<Download size={15} />} onClick={() => void downloadExport(scopeExport.id)}>{exportText('download')}</Button>
                  ) : null}
                  {scopeExport.status === 'failed' ? (
                    <Button size="small" loading={exportMutation.isPending} onClick={requestExport}>{exportText('retryThis')}</Button>
                  ) : null}
                  <Button size="small" type="link" onClick={() => { setExportsVisible(true); setAccessView('exports'); void exportsQuery.refetch() }}>{exportText('viewRecords')}</Button>
                </Space>
                {downloadError ? <span className="analytics-log-export-reason">{exportText('downloadFailed')}</span> : null}
              </div>
            ) : null}
          </div>
        })()}
        {kind === 'access' ? (
          <div className="analytics-log-tags" role="group" aria-label={t('filters.timeRange')}>
            <span className="analytics-log-tag">
              <span className="analytics-log-tag-label">{t('filters.timeRange')}</span>
              <span aria-hidden="true">：</span>
              <span className="analytics-log-tag-value">
                {accessDateTime(appliedFilters.from)} - {accessDateTime(appliedFilters.to)}
              </span>
            </span>
            {/* TEL-UX-DRILL：已生效的范围条件逐个列出，下钻进来的人能核对是不是原来那一行。 */}
            {appliedTags.map(([label, value]) => (
              <span key={label} className="analytics-log-tag">
                <span className="analytics-log-tag-label">{label}</span>
                <span aria-hidden="true">：</span>
                <span className="analytics-log-tag-value">{value}</span>
              </span>
            ))}
            <Button className="analytics-log-tags-clear" type="link" onClick={reset}>{t('actions.clear')}</Button>
            {drilledFromAnalysis ? <Button className="analytics-log-tags-clear" type="link" onClick={() => navigate(-1)}>{t('actions.backToAnalysis')}</Button> : null}
          </div>
        ) : null}
        {validationError ? <Alert className="analytics-page-error" type="error" showIcon message={validationError} /> : null}
        {query.error && !query.isFetching ? (
          <FeedbackWhen title={t(errorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
        ) : null}
        {query.data?.meta.snapshot_at ? (
          <div className="analytics-meta">
            <span>{t('meta.snapshot', { time: formatDateTime(query.data.meta.snapshot_at, locale) })}</span>
          </div>
        ) : null}
        <div className="analytics-log-table" data-testid="analytics-log-table" aria-busy={tableLoading} aria-label={tableLoading ? t('states.loading') : undefined}>
          <Table<LogEvent>
            rowKey="event_id"
            size="small"
            columns={columns}
            dataSource={query.data?.data ?? []}
            loading={tableLoading}
            pagination={false}
            {...(layout === 'waf' ? {
              tableLayout: 'fixed' as const,
              rowClassName: (event: LogEvent) => `waf-v2-row--${(event as BlockLogEvent).action}`,
              onRow: (event: LogEvent) => ({ onClick: () => setSelected(event) }),
            } : { scroll: { x: kind === 'access' ? (audience === 'admin' ? 3070 : 2580) : 1600 } })}
            locale={{ emptyText: tableLoading || query.error ? ' ' : kind === 'access' ? t('states.accessEmpty') : t('states.empty') }}
          />
        </div>
        <div className="analytics-pagination analytics-log-pagination">
          {/* ClickHouse 日志不做精确计数（tp-b7b）：已翻过的条数，还有下一页时显示 N+ */}
          <span>{t(query.data?.meta.next_cursor ? 'pagination.currentPageMore' : 'pagination.currentPage', { count: pageIndex * pageSize + (query.data?.data.length ?? 0) })}</span>
          <Button aria-label={t('actions.previous')} icon={<ChevronLeft size={15} />} disabled={pageIndex === 0 || query.isFetching} onClick={() => setPageIndex((current) => Math.max(0, current - 1))} />
          <span aria-hidden="true">{pageIndex + 1}</span>
          <span className="visually-hidden">{t('pagination.page', { page: pageIndex + 1 })}</span>
          <Button aria-label={t('actions.next')} icon={<ChevronRight size={15} />} disabled={!query.data?.meta.next_cursor || query.isFetching} onClick={nextPage} />
          <span>{t('pagination.pageSize', { size: pageSize })}</span>
        </div>
        </> : null}
        {kind === 'access' && accessView === 'exports' ? (
          <section className="analytics-log-exports is-active" aria-label={exportText('title')}>
            <div className="analytics-meta">
              <strong>{exportText('title')}</strong>
              <Button size="small" onClick={() => { setExportsVisible(true); void exportsQuery.refetch() }}>{exportText('refresh')}</Button>
            </div>
            {exportsQuery.isError ? <FeedbackWhen title={exportText('listFailed')} action={<Button size="small" onClick={() => void exportsQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
            {downloadError ? <FeedbackWhen title={exportText('downloadFailed')} /> : null}
            <Table
              rowKey="id"
              size="small"
              pagination={false}
              loading={exportsQuery.isLoading}
              dataSource={exportsQuery.data ?? []}
              locale={{ emptyText: exportText('empty') }}
              columns={[
                // LOG-02：申请记录用短编号辨认（完整编号在提示里，可复制给管理员）
                { title: exportText('exportId'), dataIndex: 'id', key: 'id', render: (value: string) => <span className="analytics-log-code" title={value} aria-label={value}>{value.slice(0, 8)}</span> },
                // LOG-02：原查询摘要取服务端冻结的条件（申请后改了页面筛选也不变）。
                {
                  title: exportText('filterSummary'), key: 'filter',
                  render: (_value: unknown, item: AnalyticsLogExport) => item.filter ? (
                    <span className="analytics-log-export-filter">
                      <span>{exportFilterText(item.filter) || exportText('filterAll')}</span>
                      <small>{formatDateTime(item.filter.from, locale)} - {formatDateTime(item.filter.to, locale)}</small>
                    </span>
                  ) : '—',
                },
                { title: exportText('createdAt'), dataIndex: 'created_at', key: 'created_at', render: (value: string) => formatDateTime(value, locale) },
                {
                  title: t('table.status'), dataIndex: 'status', key: 'status',
                  // LOG-02：失败显示原因；已过期明确提示重新申请
                  render: (status: AnalyticsLogExport['status'], item: AnalyticsLogExport) => (
                    <span>
                      {exportExpired(item) ? exportText('expired') : exportText(status)}
                      {status === 'failed' ? <small className="analytics-log-export-reason">{exportFailureReason(item.reason, exportText)}</small> : null}
                      {status === 'completed' && item.row_count === 0 ? <small className="analytics-log-export-reason">{exportText('noRows')}</small> : null}
                    </span>
                  ),
                },
                {
                  title: exportText('rows'), key: 'rows',
                  render: (_value, item: AnalyticsLogExport) => item.row_count === null ? '—'
                    : `${formatNumber(item.row_count, locale)}${item.byte_count === null ? '' : ` / ${formatBytes(item.byte_count, locale)}`}`,
                },
                { title: exportText('expiresAt'), dataIndex: 'expires_at', key: 'expires_at', render: (value: string | null) => value ? formatDateTime(value, locale) : '—' },
                {
                  title: t('table.actions'), key: 'actions',
                  render: (_value, item: AnalyticsLogExport) => item.downloadable && !exportExpired(item) ? (
                    <Button type="link" icon={<Download size={15} />} onClick={() => void downloadExport(item.id)}>{exportText('download')}</Button>
                  ) : item.status === 'failed' || exportExpired(item) ? (
                    <Button type="link" disabled={exportUnknown || exportMutation.isPending} onClick={requestExport}>{exportText('requestAgain')}</Button>
                  ) : null,
                },
              ]}
            />
          </section>
        ) : null}
      </div>
      <Drawer className={`analytics-log-detail${layout === 'waf' ? ' waf-v2-detail' : ''}`} title={t('detail.title')} open={selected !== null} width="min(620px, 100vw)" onClose={() => setSelected(null)}>
        {layout === 'waf' && selected ? (() => {
          const block = selected as BlockLogEvent
          // Every item of the flat list, in three groups; nothing is dropped.
          const hitKeys = new Set(['eventType', 'action', 'severity', 'ruleName', 'rule', 'count', 'policy', 'detector', 'matched', 'userAgent', 'bodyExcerpt'])
          const traceKeys = new Set(['event', 'node', 'requestId', 'traceId', 'configVersion', 'taskId'])
          const groups = [
            ['hit', detailItems.filter((item) => hitKeys.has(String(item.key)))],
            ['request', detailItems.filter((item) => !hitKeys.has(String(item.key)) && !traceKeys.has(String(item.key)))],
            ['trace', detailItems.filter((item) => traceKeys.has(String(item.key)))],
          ] as const
          return <>
            <header className="waf-v2-detail-head">
              <div className="waf-v2-detail-meta">{actionTag(block.action)}<span>{securityValue('severity', block.severity, t)}</span><span>{formatDateTime(block.occurred_at, locale)}</span></div>
              <p className="waf-v2-detail-rule">{block.rule_name || block.rule_id || t('values.unknown')}</p>
              <p className="waf-v2-detail-target"><span>{block.host}</span><span className="analytics-log-code">{requestPath(block)}</span></p>
            </header>
            {groups.map(([key, items]) => <section className="waf-v2-detail-group" key={key} aria-labelledby={`waf-v2-detail-${key}`}>
              <h3 id={`waf-v2-detail-${key}`}>{wafT(`redesign.groups.${key}`)}</h3>
              <Descriptions bordered size="small" column={1} items={items} />
            </section>)}
          </>
        })() : <Descriptions bordered size="small" column={1} items={detailItems} />}
        {selected && currentAnalyticsLogAccess(ownerKey) ? (
          <LogGeoEvidence
            accessToken={currentAnalyticsLogAccess(ownerKey)!}
            audience={audience}
            kind={kind}
            event={selected}
            tenantId={audience === 'admin' ? appliedFilters.tenantId : undefined}
          />
        ) : null}
      </Drawer>
    </section>
  )
}

export function AnalyticsLogPage({ kind, embedded = false, layout = 'default', seed, eventType }: {
  kind: AnalyticsLogKind
  embedded?: boolean
  layout?: AnalyticsLogLayout
  seed?: AnalyticsLogSeed
  /** Block events: pin one event type (the WAF page pins waf, as its overview counts). */
  eventType?: string
}) {
  const { t } = useTranslation('analyticsLogs')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(
    () => principal ? analyticsLogOwner(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )

  if (!accessToken || !principal) return null
  if (!owner || !canReadAnalyticsLogs(principal)) {
    return (
      <Result
        className="analytics-page analytics-page-error"
        status="403"
        title={t('states.permissionTitle')}
        subTitle={t('states.permissionDescription')}
      />
    )
  }
  const ownerKey = JSON.stringify(owner)
  return <AnalyticsLogPageContent key={`${ownerKey}${JSON.stringify(seed ?? null)}`} kind={kind} owner={owner} ownerKey={ownerKey} embedded={embedded} layout={layout} seed={seed} eventType={eventType} />
}

export default function SiteAccessLogPage() {
  return <AnalyticsLogPage kind="access" />
}
