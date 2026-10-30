import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Result,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  type TableColumnsType,
} from 'antd'
import dayjs from 'dayjs'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import {
  analyticsApi,
  type AnalyticsAudience,
  type AnalyticsFilters,
  type AnalyticsRankDimension,
  type AnalyticsRankItem,
} from '../api/analytics'
import { ApiError, type Principal } from '../api/auth'
import {
  createJA4BlockWriteMetadata,
  ja4BlocksApi,
  type AdminJA4BlockCreateInput,
  type JA4BlockCreateInput,
  type JA4BlockWorkflow,
  type JA4BlockWriteMetadata,
} from '../api/ja4Blocks'
import { useSessionStore } from '../auth/session'
import { formatBytes, formatDateTime, formatNumber } from '../i18n/formatters'
import '../i18n/ipIntel'
import { rankItemLabel } from './analyticsRankLabels'
import '../i18n/ja4Blocks'
import './SiteAnalysisPage.css'
import { FeedbackWhen, TimeRangeFilter, type TimeRange, type TimeRangePreset } from '@cdnca/ui'

const hourMilliseconds = 60 * 60 * 1000
const maximumWindowMilliseconds = 31 * 24 * hourMilliseconds
const pageSize = 20
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const canonicalUuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const domainPattern = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+$/
const ja4Pattern = /^[A-Za-z0-9_+.-]{1,128}$/
const reasonPattern = /^[a-z][a-z0-9_]{0,63}$/
const nilUuid = '00000000-0000-0000-0000-000000000000'

type AnalysisRange = 'today' | 'last7d' | 'last30d' | 'custom'
type AnalysisDimension = AnalyticsRankDimension
type AnalysisSearchType = 'domain' | 'server_port' | 'cc'

type AnalysisFilterTag = Readonly<{
  type: AnalysisSearchType
  value: string
  label: string
}>

interface DraftFilters {
  tenantId: string
  siteId: string
  nodeId: string
  from: string
  to: string
}

type JA4Target = Readonly<{
  rowKey: string
  tenantScopeID: string
  siteID: string
  snapshotAt: string
}>

type JA4Attempt = Readonly<{
  ownerSignature: string
  audience: AnalyticsAudience
  target: JA4Target
  input: Readonly<JA4BlockCreateInput | AdminJA4BlockCreateInput>
  metadata: Readonly<JA4BlockWriteMetadata>
}>

type JA4WorkflowState = Readonly<{
  ownerSignature: string
  audience: AnalyticsAudience
  target: JA4Target
  workflow: JA4BlockWorkflow
}>

// 预设窗口的结束：下一个整分钟（含当前这一分钟的请求）。排行与汇总只要求分钟对齐；
// 截到整点会让“近 10/30 分钟”落在上一个整点之前，刚产生的请求全部看不到。
function presetWindowEnd(): Date {
  return new Date((Math.floor(Date.now() / 60_000) + 1) * 60_000)
}

// Quick ranges (today / last 7 days / last 30 days / custom) end at presetWindowEnd; the backend allows 31 days.
function presetWindowStart(range: Exclude<AnalysisRange, 'custom'>, to: Date): Date {
  if (range === 'today') { const start = new Date(to.getTime() - 60_000); start.setHours(0, 0, 0, 0); return start }
  return new Date(to.getTime() - (range === 'last7d' ? 7 : 30) * 24 * 60 * 60 * 1000)
}

function localDateTimeValue(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value)
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

function parseLocalMinute(value: string): Date | null {
  const date = new Date(value)
  return Number.isFinite(date.getTime()) && date.getTime() % (60 * 1000) === 0 ? date : null
}

function optionalUuid(value: string): string | undefined {
  return value.trim() || undefined
}

function normalizedDomain(value: string): string | undefined {
  const candidates = value.trim().split(/\s+/).filter(Boolean)
  if (candidates.length === 0 || candidates.length > 64) return undefined
  const domains = [...new Set(candidates.map((candidate) => candidate.toLowerCase().replace(/\.$/, '')))]
  return domains.every((domain) => domainPattern.test(domain)) ? domains.join(' ') : undefined
}

function validUuid(value: string): boolean {
  return uuidPattern.test(value) && value.toLowerCase() !== nilUuid
}

function maskJA4(value: string): string {
  if (value.length < 9) return `${value.slice(0, 2)}••••`
  return `${value.slice(0, 4)}••••${value.slice(-4)}`
}

function compactTechnicalID(value?: string | null) {
  const normalized = typeof value === 'string' ? value.trim() : ''
  return normalized
    ? (
        <span title={normalized} aria-label={normalized}>
          <span aria-hidden="true">—</span>
          <span className="visually-hidden">{normalized}</span>
        </span>
      )
    : <span>—</span>
}

function unknownWriteOutcome(error: unknown): boolean {
  return error instanceof ApiError && (
    error.status === 0 || error.status === 408 || error.status === 503 || error.status === 504 ||
    error.code === 'network_error'
  )
}

function ja4WriteErrorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 401 || error.code === 'ja4_block_authentication_required') return 'errors.authenticationRequired'
  if (error.status === 403 || error.code === 'ja4_block_permission_denied') return 'errors.permissionDenied'
  if (error.status === 409 || error.code === 'ja4_block_conflict') return 'errors.conflict'
  if (error.status === 412 || error.code === 'ja4_block_snapshot_stale') return 'errors.snapshotStale'
  if (error.status === 428 || error.code === 'ja4_block_step_up_required') return 'errors.stepUpRequired'
  if (error.status === 400 || error.code === 'ja4_block_invalid_request') return 'errors.invalidInput'
  if (error.status === 502 || error.code === 'ja4_block_dependency_response_invalid') return 'errors.dependencyInvalid'
  return 'errors.requestFailed'
}

function canReadAnalytics(
  accessToken: string | null,
  status: string,
  principal: Principal | null,
): boolean {
  const canRead = principal?.permissions.includes('sites.read') ||
    (principal?.scope_kind === 'platform' && principal.permissions.includes('platform.admin'))
  if (status !== 'authenticated' || !accessToken || !principal || !canRead) {
    return false
  }
  if (!validUuid(principal.user_id)) return false
  if (principal.scope_kind === 'platform') {
    return principal.scope_id.trim() !== '' && principal.tenant_id === null
  }
  return validUuid(principal.scope_id) && principal.tenant_id !== null && validUuid(principal.tenant_id)
}

function validateDraft(draft: DraftFilters, audience: AnalyticsAudience, t: TFunction<'analytics'>): string | null {
  const siteFilter = draft.siteId.trim()
  const ids = audience === 'admin' ? [draft.tenantId, draft.nodeId] : [draft.nodeId]
  if (ids.some((value) => value.trim() !== '' && !validUuid(value.trim())) ||
    (siteFilter !== '' && !validUuid(siteFilter) && !normalizedDomain(siteFilter))) {
    return t('filters.invalidUuid')
  }
  const from = parseLocalMinute(draft.from)
  const to = parseLocalMinute(draft.to)
  if (!from || !to || from >= to) return t('filters.invalidWindow')
  if (to.getTime() - from.getTime() > maximumWindowMilliseconds) return t('filters.rangeTooLong')
  return null
}

function buildFilters(draft: DraftFilters, audience: AnalyticsAudience): AnalyticsFilters {
  const from = parseLocalMinute(draft.from)!
  const to = parseLocalMinute(draft.to)!
  const siteFilter = draft.siteId.trim()
  const siteId = validUuid(siteFilter) ? siteFilter : undefined
  const domain = siteId ? undefined : normalizedDomain(siteFilter)
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    ...(siteId ? { siteId } : {}),
    ...(domain ? { domain } : {}),
    ...(optionalUuid(draft.nodeId) ? { nodeId: optionalUuid(draft.nodeId) } : {}),
    ...(audience === 'admin' && optionalUuid(draft.tenantId)
      ? { tenantId: optionalUuid(draft.tenantId) }
      : {}),
  }
}

function retryableRankError(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status >= 500
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.requestFailed'
  if (error.status === 403) return 'states.permissionDescription'
  if (error.status === 400 || error.code === 'analytics_invalid_request') return 'states.invalidRequest'
  if (error.status === 422 || error.code === 'analytics_dimension_unsupported') return 'states.unsupportedDimension'
  if (error.status === 503 || error.code === 'analytics_storage_unavailable') return 'states.storageUnavailable'
  if (error.status === 504 || error.code === 'analytics_query_timeout') return 'states.queryTimeout'
  return 'states.requestFailed'
}

export default function SiteAnalysisPage() {
  const { t, i18n } = useTranslation('analytics')
  const { t: tJA4 } = useTranslation('ja4Blocks')
  const { t: tIPIntel } = useTranslation('ipIntel')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionStatus = useSessionStore((state) => state.status)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const principal = useSessionStore((state) => state.principal)
  const audience: AnalyticsAudience = principal?.scope_kind === 'platform' ? 'admin' : 'tenant'
  const initialWindow = useMemo(() => {
    const to = presetWindowEnd()
    return {
      from: localDateTimeValue(presetWindowStart('today', to)),
      to: localDateTimeValue(to),
    }
  }, [])
  const initialDraft = useMemo<DraftFilters>(() => ({
    tenantId: '',
    siteId: '',
    nodeId: '',
    ...initialWindow,
  }), [initialWindow])
  const [dimension, setDimension] = useState<AnalysisDimension>('domain')
  const [range, setRange] = useState<AnalysisRange>('today')
  const [searchType, setSearchType] = useState<AnalysisSearchType>('domain')
  const [searchValue, setSearchValue] = useState('')
  const [filterTags, setFilterTags] = useState<AnalysisFilterTag[]>([])
  const [draft, setDraft] = useState<DraftFilters>(initialDraft)
  const [appliedFilters, setAppliedFilters] = useState<AnalyticsFilters>(() => buildFilters(initialDraft, audience))
  const [validationError, setValidationError] = useState<string | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageCursors, setPageCursors] = useState<Array<string | undefined>>([undefined])
  const [queryGeneration, setQueryGeneration] = useState(0)
  const [ja4Target, setJA4Target] = useState<JA4Target | null>(null)
  const [ja4Duration, setJA4Duration] = useState<number | null>(3600)
  const [ja4Reason, setJA4Reason] = useState('manual_security_review')
  const [ja4StepUp, setJA4StepUp] = useState('')
  const [ja4FormError, setJA4FormError] = useState<string | null>(null)
  const [ja4Attempt, setJA4Attempt] = useState<JA4Attempt | null>(null)
  const [ja4WriteError, setJA4WriteError] = useState<unknown>(null)
  const [ja4WritePending, setJA4WritePending] = useState(false)
  const [ja4ReadError, setJA4ReadError] = useState<unknown>(null)
  const [ja4ReadPending, setJA4ReadPending] = useState(false)
  const [ja4Workflow, setJA4Workflow] = useState<JA4WorkflowState | null>(null)
  const cursor = pageCursors[pageIndex]

  const ownerKey = useMemo(
    () => [
      audience,
      principal?.scope_kind ?? null,
      principal?.scope_id ?? null,
      principal?.tenant_id ?? null,
      principal?.user_id ?? null,
      sessionEpoch,
    ] as const,
    [audience, principal?.scope_kind, principal?.scope_id, principal?.tenant_id, principal?.user_id, sessionEpoch],
  )
  const ownerSignature = ownerKey.map((value) => String(value)).join('|')
  const previousOwnerRef = useRef(ownerKey)
  const readyOwnerRef = useRef(ownerSignature)
  const ownerReady = readyOwnerRef.current === ownerSignature
  const hasReadAccess = canReadAnalytics(accessToken, sessionStatus, principal)
  const queryDimension: AnalyticsRankDimension = dimension

  useEffect(() => {
    if (previousOwnerRef.current.every((value, index) => value === ownerKey[index])) return
    queryClient.removeQueries({ queryKey: ['analytics', 'rank', ...previousOwnerRef.current] })
    previousOwnerRef.current = ownerKey
    readyOwnerRef.current = ownerSignature
    setDimension('domain')
    setRange('today')
    setSearchType('domain')
    setSearchValue('')
    setFilterTags([])
    setDraft(initialDraft)
    setAppliedFilters(buildFilters(initialDraft, audience))
    setValidationError(null)
    setPageIndex(0)
    setPageCursors([undefined])
    setQueryGeneration(0)
    setJA4Target(null)
    setJA4Attempt(null)
    setJA4Workflow(null)
    setJA4WriteError(null)
    setJA4ReadError(null)
    setJA4StepUp('')
  }, [audience, initialDraft, ownerKey, ownerSignature, queryClient])

  useEffect(() => () => {
    queryClient.removeQueries({ queryKey: ['analytics', 'rank', audience] })
    queryClient.removeQueries({ queryKey: ['analytics', 'summary', audience] })
    queryClient.removeQueries({ queryKey: ['analytics', 'trend', audience] })
  }, [audience, queryClient])

  const rankQuery = useQuery({
    queryKey: ['analytics', 'rank', ...ownerKey, dimension, appliedFilters, queryGeneration, cursor],
    queryFn: () => analyticsApi.rank(accessToken!, audience, queryDimension, appliedFilters, pageSize, cursor),
    enabled: hasReadAccess && ownerReady,
    gcTime: Infinity,
    staleTime: Infinity,
    // One retry for a network error or 5xx (e.g. a 502 while the control
    // plane restarts); refusals such as 400/403 are final.
    retry: (failureCount, error) => failureCount < 1 && retryableRankError(error),
  })

  // Cache hit ratio and unique client IPs of the applied range (history facts,
  // so they cover what the trend covers).
  const summaryQuery = useQuery({
    queryKey: ['analytics', 'summary', ...ownerKey, appliedFilters, queryGeneration],
    queryFn: () => analyticsApi.summary(accessToken!, audience, appliedFilters),
    enabled: hasReadAccess && ownerReady,
    gcTime: Infinity,
    staleTime: Infinity,
  })

  const resetPages = () => {
    setPageIndex(0)
    setPageCursors([undefined])
    setQueryGeneration((current) => current + 1)
  }
  const changeDimension = (value: string) => {
    setDimension(value as AnalysisDimension)
    resetPages()
    setValidationError(null)
  }
  // Quick ranges end at the next whole minute (presetWindowEnd).
  const rangePresets: TimeRangePreset[] = (['today', 'last7d', 'last30d'] as const).map((key) => ({
    key, range: () => {
      const to = presetWindowEnd()
      return [dayjs(presetWindowStart(key, to)), dayjs(to)]
    },
  }))
  const applyPreset = (value: AnalysisRange, window: TimeRange | null) => {
    setRange(value)
    if (window) setDraft((current) => ({ ...current, from: localDateTimeValue(window[0].toDate()), to: localDateTimeValue(window[1].toDate()) }))
    setValidationError(null)
  }
  const resolveListenPort = (): { blocked: boolean; listenPort?: number } => {
    if (searchType === 'cc') {
      setFilterTags((current) => [
        ...current.filter((tag) => tag.type !== 'cc'),
        { type: 'cc', value: '1', label: t('filters.attackRequest') },
      ])
      setValidationError(t('states.filterUnsupported'))
      return { blocked: true }
    }
    if (searchType === 'server_port') {
      const port = Number(searchValue.trim())
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        setValidationError(t('states.invalidPort'))
        return { blocked: true }
      }
      return { blocked: false, listenPort: port }
    }
    return { blocked: false, listenPort: appliedFilters.listenPort }
  }
  const apply = () => {
    if (queryDimension === null) {
      setValidationError(t('states.unsupportedDimension'))
      return
    }
    const search = resolveListenPort()
    if (search.blocked) return
    const to = presetWindowEnd()
    const effectiveDraft = range === 'custom' ? draft : {
      ...draft,
      from: localDateTimeValue(presetWindowStart(range, to)),
      to: localDateTimeValue(to),
    }
    if (range !== 'custom') setDraft(effectiveDraft)
    const error = validateDraft(effectiveDraft, audience, t)
    setValidationError(error)
    if (error) return
    const nextFilters = {
      ...buildFilters(effectiveDraft, audience),
      ...(search.listenPort ? { listenPort: search.listenPort } : {}),
    }
    const normalizedSiteFilter = nextFilters.siteId ?? nextFilters.domain ?? ''
    setDraft((current) => ({ ...current, ...effectiveDraft, siteId: normalizedSiteFilter }))
    const nextTags: AnalysisFilterTag[] = []
    for (const value of (nextFilters.domain ?? nextFilters.siteId ?? '').split(' ').filter(Boolean)) {
      nextTags.push({ type: 'domain', value, label: `${t('filters.domain')}：${value}` })
    }
    if (nextFilters.listenPort) {
      nextTags.push({
        type: 'server_port',
        value: String(nextFilters.listenPort),
        label: `${t('filters.serverPort')}：${nextFilters.listenPort}`,
      })
    }
    setFilterTags(nextTags)
    if (JSON.stringify(nextFilters) === JSON.stringify(appliedFilters) && pageIndex === 0) {
      void rankQuery.refetch()
      return
    }
    setAppliedFilters(nextFilters)
    resetPages()
  }
  const changeSearchType = (value: AnalysisSearchType) => {
    setSearchType(value)
    setSearchValue('')
    setValidationError(null)
    if (value === 'cc') {
      setFilterTags((current) => [
        ...current.filter((tag) => tag.type !== 'cc'),
        { type: 'cc', value: '1', label: t('filters.attackRequest') },
      ])
      setValidationError(t('states.filterUnsupported'))
    } else {
      setFilterTags((current) => current.filter((tag) => tag.type !== 'cc'))
    }
  }
  const clearFilterTags = () => {
    const nextDraft = { ...draft, siteId: '' }
    setDraft(nextDraft)
    setSearchValue('')
    setFilterTags([])
    setValidationError(null)
    if (!appliedFilters.domain && !appliedFilters.siteId && !appliedFilters.listenPort) return
    setAppliedFilters(buildFilters(nextDraft, audience))
    resetPages()
  }
  const removeFilterTag = (tag: AnalysisFilterTag) => {
    const remaining = filterTags.filter((candidate) => candidate !== tag)
    setFilterTags(remaining)
    if (tag.type === 'cc') {
      setValidationError(null)
      return
    }
    if (tag.type === 'server_port') {
      const nextFilters = { ...appliedFilters }
      delete nextFilters.listenPort
      setSearchValue('')
      setValidationError(null)
      setAppliedFilters(nextFilters)
      resetPages()
      return
    }
    const nextSiteFilter = remaining
      .filter((candidate) => candidate.type === 'domain')
      .map((candidate) => candidate.value)
      .join(' ')
    const nextDraft = { ...draft, siteId: nextSiteFilter }
    setDraft(nextDraft)
    setValidationError(null)
    setAppliedFilters({
      ...buildFilters(nextDraft, audience),
      ...(appliedFilters.listenPort ? { listenPort: appliedFilters.listenPort } : {}),
    })
    resetPages()
  }
  const nextPage = () => {
    const nextCursor = rankQuery.data?.page.next_cursor
    if (!nextCursor) return
    setPageCursors((current) => {
      const next = current.slice(0, pageIndex + 1)
      next.push(nextCursor)
      return next
    })
    setPageIndex((current) => current + 1)
  }

  const queryError = rankQuery.error
  if (!hasReadAccess || (queryError instanceof ApiError && queryError.status === 403)) {
    return (
      <Result
        className="analytics-page analytics-page-error"
        status="403"
        title={t('states.permissionTitle')}
        subTitle={t('states.permissionDescription')}
      />
    )
  }

  const tableLoading = rankQuery.isFetching && !rankQuery.data
  const ja4TenantScopeID = audience === 'admin' ? appliedFilters.tenantId : principal?.scope_id ?? undefined
  const hasJA4ManageAccess = Boolean(
    principal?.permissions.includes('sites.manage') &&
    principal.permissions.includes('security_policies.read') &&
    principal.permissions.includes('security_policies.manage') &&
    (audience === 'tenant' || principal.permissions.includes('platform.admin')),
  )
  const canCreateJA4Block = dimension === 'ja4' && Boolean(
    hasJA4ManageAccess &&
    ja4TenantScopeID && canonicalUuidPattern.test(ja4TenantScopeID) &&
    appliedFilters.siteId && canonicalUuidPattern.test(appliedFilters.siteId) &&
    rankQuery.data?.page.snapshot_at,
  )

  const currentJA4Token = (expectedOwnerSignature: string): string | null => {
    const current = useSessionStore.getState()
    const currentPrincipal = current.principal
    if (current.status !== 'authenticated' || !current.accessToken || !currentPrincipal) return null
    const currentAudience: AnalyticsAudience = currentPrincipal.scope_kind === 'platform' ? 'admin' : 'tenant'
    const currentSignature = [
      currentAudience,
      currentPrincipal.scope_kind,
      currentPrincipal.scope_id,
      currentPrincipal.tenant_id,
      currentPrincipal.user_id,
      current.sessionEpoch,
    ].map((value) => String(value)).join('|')
    if (currentSignature !== expectedOwnerSignature ||
      !currentPrincipal.permissions.includes('sites.manage') ||
      !currentPrincipal.permissions.includes('security_policies.read') ||
      !currentPrincipal.permissions.includes('security_policies.manage') ||
      (currentAudience === 'admin' && !currentPrincipal.permissions.includes('platform.admin'))) return null
    return current.accessToken
  }

  const refreshJA4Workflow = async (state: JA4WorkflowState) => {
    const token = currentJA4Token(state.ownerSignature)
    if (!token) return
    setJA4ReadPending(true)
    setJA4ReadError(null)
    try {
      const requestID = `ja4-block-read-${crypto.randomUUID()}`
      const workflow = state.audience === 'admin'
        ? await ja4BlocksApi.getAdmin(token, state.target.tenantScopeID, state.workflow.id, requestID)
        : await ja4BlocksApi.getTenant(token, state.workflow.id, requestID)
      if (!currentJA4Token(state.ownerSignature)) return
      setJA4Workflow({ ...state, workflow })
    } catch (error) {
      if (currentJA4Token(state.ownerSignature)) setJA4ReadError(error)
    } finally {
      if (currentJA4Token(state.ownerSignature)) setJA4ReadPending(false)
    }
  }

  const executeJA4Block = async (attempt: JA4Attempt) => {
    if (ja4WritePending) return
    const token = currentJA4Token(attempt.ownerSignature)
    if (!token) {
      setJA4Attempt(null)
      setJA4WriteError(new ApiError('JA4 block permission denied', 403, 'ja4_block_permission_denied'))
      return
    }
    setJA4WritePending(true)
    setJA4WriteError(null)
    setJA4ReadError(null)
    try {
      const workflow = attempt.audience === 'admin'
        ? await ja4BlocksApi.createAdmin(token, attempt.input as AdminJA4BlockCreateInput, attempt.metadata)
        : await ja4BlocksApi.createTenant(token, attempt.input as JA4BlockCreateInput, attempt.metadata)
      if (!currentJA4Token(attempt.ownerSignature)) return
      const state = { ownerSignature: attempt.ownerSignature, audience: attempt.audience, target: attempt.target, workflow }
      setJA4Attempt(null)
      setJA4Workflow(state)
      await refreshJA4Workflow(state)
    } catch (error) {
      if (!currentJA4Token(attempt.ownerSignature)) return
      setJA4WriteError(error)
      if (!unknownWriteOutcome(error)) setJA4Attempt(null)
    } finally {
      if (currentJA4Token(attempt.ownerSignature)) setJA4WritePending(false)
    }
  }

  const openJA4Block = (item: AnalyticsRankItem) => {
    if (!canCreateJA4Block || !ja4TenantScopeID || !appliedFilters.siteId || !rankQuery.data ||
      !ja4Pattern.test(item.key)) return
    setJA4Target(Object.freeze({
      rowKey: item.key,
      tenantScopeID: ja4TenantScopeID,
      siteID: appliedFilters.siteId,
      snapshotAt: rankQuery.data.page.snapshot_at,
    }))
    setJA4Duration(3600)
    setJA4Reason('manual_security_review')
    setJA4StepUp('')
    setJA4FormError(null)
    setJA4Attempt(null)
    setJA4Workflow(null)
    setJA4WriteError(null)
    setJA4ReadError(null)
  }

  const submitJA4Block = () => {
    if (!ja4Target) return
    if (ja4Duration === null || !Number.isInteger(ja4Duration) || ja4Duration < 60 || ja4Duration > 2_592_000) {
      setJA4FormError('validation.duration')
      return
    }
    if (!reasonPattern.test(ja4Reason)) {
      setJA4FormError('validation.reason')
      return
    }
    if (!ja4StepUp) {
      setJA4FormError('validation.stepUp')
      return
    }
    const tenantInput = Object.freeze({
      site_id: ja4Target.siteID,
      ja4: ja4Target.rowKey,
      snapshot_at: ja4Target.snapshotAt,
      duration_seconds: ja4Duration,
      reason: ja4Reason,
    })
    const input = audience === 'admin'
      ? Object.freeze({ ...tenantInput, tenant_scope_id: ja4Target.tenantScopeID })
      : tenantInput
    const attempt = Object.freeze({
      ownerSignature,
      audience,
      target: ja4Target,
      input,
      metadata: Object.freeze(createJA4BlockWriteMetadata(ja4StepUp)),
    })
    setJA4FormError(null)
    setJA4StepUp('')
    setJA4Attempt(attempt)
    void executeJA4Block(attempt)
  }

  const closeJA4Dialog = () => {
    if (ja4WritePending || ja4ReadPending) return
    setJA4Target(null)
    setJA4Attempt(null)
    setJA4WriteError(null)
    setJA4ReadError(null)
    setJA4StepUp('')
  }

  const abandonJA4Attempt = () => {
    setJA4Attempt(null)
    setJA4WriteError(null)
  }

  const language = i18n.resolvedLanguage ?? 'zh-CN'
  // TEL-UX-DRILL：访问日志能按同一条件筛的才给"查看日志"，带上同一时间窗、域名/站点/节点/租户范围与该行的值。
  // 省份、来源、浏览器、系统和端口筛选不是日志筛选项，未知值也筛不出来——给了就会悄悄放宽成全部日志。
  const drillQuery = (item: AnalyticsRankItem): URLSearchParams | null => {
    if (appliedFilters.listenPort) return null
    const query = new URLSearchParams({ from: appliedFilters.from, to: appliedFilters.to })
    const parameterByDimension: Partial<Record<AnalysisDimension, string>> = {
      ja4: 'ja4', ip: 'client_ip', region: 'country_code', carrier: 'carrier',
    }
    if (dimension === 'domain' || dimension === 'url') {
      if (!item.host || (dimension === 'url' && !item.path)) return null
      query.set('host', item.host)
      if (dimension === 'url') query.set('uri_path', item.path!)
    } else {
      const parameter = parameterByDimension[dimension]
      if (!parameter || item.key === '__unknown__') return null
      query.set(parameter, item.key)
      if (appliedFilters.domain) query.set('host', appliedFilters.domain)
    }
    if (appliedFilters.siteId) query.set('site_id', appliedFilters.siteId)
    if (appliedFilters.nodeId) query.set('node_id', appliedFilters.nodeId)
    if (audience === 'admin' && appliedFilters.tenantId) query.set('tenant_id', appliedFilters.tenantId)
    return query
  }
  const openAccessLogs = (query: URLSearchParams) => {
    navigate(`/monitor/site/access-log?${query.toString()}`, { state: { drillFrom: 'analysis' } })
  }
  const columns: TableColumnsType<AnalyticsRankItem> = [
    {
      title: t('table.rank'),
      key: 'rank',
      width: '9%',
      render: (_value, _item, index) => formatNumber(pageIndex * pageSize + index + 1, language),
    },
    {
      title: t(`table.columns.${dimension}`),
      dataIndex: 'key',
      key: 'key',
      width: '24%',
      render: (_value: string, item: AnalyticsRankItem) => {
        const label = rankItemLabel(dimension, item, t, tIPIntel, language)
        // IPv6 can be long: monospace, ellipsized, full text on hover.
        return (
          <span className={dimension === 'ip' ? 'analytics-rank-key analytics-rank-key-ip' : 'analytics-rank-key'} title={label}>
            {label}
          </span>
        )
      },
    },
    {
      title: t('table.requestCount'),
      dataIndex: 'request_count',
      key: 'request_count',
      width: '15%',
      sorter: (left, right) => left.request_count - right.request_count,
      render: (value: number) => formatNumber(value, language),
    },
    {
      title: t('table.responseBytes'),
      dataIndex: 'response_bytes',
      key: 'response_bytes',
      width: '15%',
      sorter: (left, right) => left.response_bytes - right.response_bytes,
      render: (value: number) => formatBytes(value, language),
    },
    {
      title: t('table.originBytes'),
      key: 'origin-bytes',
      width: '15%',
      render: () => <span title={t('capability.originUnavailable')}>—</span>,
    },
    {
      title: t('table.actions'),
      key: 'actions',
      width: '12%',
      render: (_value, item) => {
        const query = drillQuery(item)
        return query ? <Button type="link" onClick={() => openAccessLogs(query)}>{t('actions.viewLogs')}</Button> : null
      },
    },
    ...(canCreateJA4Block ? [{
      title: tJA4('actions.create'),
      key: 'ja4-block',
      width: '10%',
      render: (_value: unknown, item: AnalyticsRankItem) => item.key === '__unknown__' || !ja4Pattern.test(item.key)
        ? null
        : (
            <Space size="small">
              {ja4Workflow?.target.rowKey === item.key ? (
                <Tag color={ja4Workflow.workflow.phase === 'active' && ja4Workflow.workflow.edge_state === 'active' ? 'success' : 'processing'}>
                  {ja4Workflow.workflow.phase === 'active' && ja4Workflow.workflow.edge_state === 'active'
                    ? tJA4('states.active')
                    : tJA4(`phases.${ja4Workflow.workflow.phase === 'active' ? 'edge_pending' : ja4Workflow.workflow.phase}`)}
                </Tag>
              ) : null}
              <Button type="link" onClick={() => openJA4Block(item)}>{tJA4('actions.create')}</Button>
            </Space>
          ),
    }] : []),
  ]

  const dimensionTabs = [
    { key: 'domain', label: t('dimensions.domain') },
    { key: 'url', label: t('dimensions.url') },
    { key: 'ja4', label: <span aria-label={t('dimensions.ja4Accessible')}>{t('dimensions.ja4')}</span> },
    { key: 'ip', label: t('dimensions.ip') },
    { key: 'region', label: t('dimensions.region') },
    { key: 'province', label: t('dimensions.province') },
    { key: 'carrier', label: t('dimensions.carrier') },
    { key: 'browser', label: t('dimensions.browser') },
    { key: 'os', label: t('dimensions.os') },
    { key: 'referer', label: t('dimensions.referer') },
  ]

  return (
    <section
      className="analytics-page analytics-analysis-page"
      aria-labelledby="analytics-analysis-title"
    >
      <div className="analytics-panel">
        <header className="analytics-page-header">
          <h1 id="analytics-analysis-title">{t('title.analysis')}</h1>
        </header>
        <Tabs
          className="analytics-rank-tabs"
          type="card"
          activeKey={dimension}
          items={dimensionTabs}
          onChange={changeDimension}
        />
        <div className="analytics-filter-bar">
          <div className="analytics-range-control">
            <TimeRangeFilter label={t('filters.timeRange')} presets={rangePresets} maxSpanMs={maximumWindowMilliseconds} allowClear={false}
              value={{ preset: range, range: [dayjs(draft.from), dayjs(draft.to)] }}
              onChange={({ preset, range: window }) => applyPreset(preset as AnalysisRange, window)} />
          </div>
          <div className="analytics-domain-control">
            <label className="visually-hidden" htmlFor="analytics-analysis-site-filter">
              {t('filters.site')}
            </label>
            <Input.Search
              className="analytics-analysis-search-input"
              id="analytics-analysis-site-filter"
              aria-label={searchType === 'domain'
                ? t('filters.domain')
                : searchType === 'server_port' ? t('filters.serverPort') : t('filters.attackRequest')}
              addonBefore={(
                <Select
                  size="small"
                  className="analytics-analysis-search-type"
                  aria-label={t('filters.searchType')}
                  value={searchType}
                  placement="bottomLeft"
                  popupMatchSelectWidth
                  virtual={false}
                  listHeight={256}
                  classNames={{ popup: { root: 'analytics-analysis-domain-popup' } }}
                  onChange={changeSearchType}
                  options={[
                    { value: 'domain', label: t('filters.domain') },
                    { value: 'server_port', label: t('filters.serverPort') },
                    { value: 'cc', label: t('filters.attackRequest') },
                  ]}
                />
              )}
              value={searchType === 'domain' ? draft.siteId : searchValue}
              placeholder={searchType === 'domain'
                ? t('filters.domainPlaceholder')
                : searchType === 'server_port' ? t('filters.serverPortPlaceholder') : undefined}
              onSearch={apply}
              onChange={(event) => searchType === 'domain'
                ? setDraft((current) => ({ ...current, siteId: event.target.value }))
                : setSearchValue(event.target.value)}
            />
          </div>
          <span className="analytics-analysis-refresh-break" aria-hidden="true" />
          <Button className="analytics-analysis-refresh-action" type="primary" onClick={apply}>{t('actions.refresh')}</Button>
        </div>
        {filterTags.length > 0 ? (
          <div className="analytics-analysis-filter-tags" aria-label={t('filters.searchType')}>
            {filterTags.map((tag) => (
              <Tag key={`${tag.type}:${tag.value}`} closable onClose={() => removeFilterTag(tag)}>{tag.label}</Tag>
            ))}
            <Button type="link" size="small" onClick={clearFilterTags}>{t('actions.clear')}</Button>
          </div>
        ) : null}
        {validationError ? <Alert className="analytics-filter-error" type="error" showIcon message={validationError} /> : null}
        {queryError && !rankQuery.isFetching && !(queryError instanceof ApiError && queryError.status === 403) ? (
          <FeedbackWhen title={t(errorKey(queryError))} action={<Button size="small" onClick={() => void rankQuery.refetch()}>{t('actions.retry')}</Button>} />
        ) : null}
        <div className="analytics-meta">
            {rankQuery.data ? (
              <span className="analytics-meta-item">
                {t('meta.localWindow', {
                  from: formatDateTime(rankQuery.data.meta.from, language),
                  to: formatDateTime(rankQuery.data.meta.to, language),
                })}
              </span>
            ) : null}
            {rankQuery.data ? (
              <span className="analytics-meta-item">
                {t('meta.snapshotAt', { time: formatDateTime(rankQuery.data.page.snapshot_at, language) })}
              </span>
            ) : null}
            <span className="analytics-meta-item">{t('meta.watermarkUnavailable')}</span>
        </div>
        {summaryQuery.data ? (
          <div className="analytics-summary-strip" role="group" aria-label={t('rangeSummary.label')}>
            {/* TEL-UX-SUMMARY-SCOPE：汇总只按时间、站点 UUID、节点、租户统计（history 安全事实无 host 列），
                排行按域名/端口筛了也不能让人以为汇总是同一范围。 */}
            <span className="analytics-meta-item analytics-summary-scope">
              {t(appliedFilters.siteId
                ? 'rangeSummary.scopeSite'
                : appliedFilters.domain || appliedFilters.listenPort ? 'rangeSummary.scopeAllNarrowed' : 'rangeSummary.scopeAll')}
            </span>
            <span className="analytics-meta-item">
              {t('rangeSummary.cacheHitRatio', {
                value: summaryQuery.data.data.request_count === 0
                  ? '—'
                  : `${formatNumber(Math.round(summaryQuery.data.data.cache_hit_requests * 1000 / summaryQuery.data.data.request_count) / 10, language)}%`,
              })}
            </span>
            <span className="analytics-meta-item">
              {t('rangeSummary.cacheHitBytes', { value: formatBytes(summaryQuery.data.data.cache_hit_bytes, language) })}
            </span>
            <span className="analytics-meta-item">
              {t('rangeSummary.uniqueClientIPs', { value: formatNumber(summaryQuery.data.data.unique_client_ips, language) })}
            </span>
            <span className="analytics-meta-item">
              {t('rangeSummary.securityRequests', { value: formatNumber(summaryQuery.data.data.security_events, language) })}
              <small className="analytics-meta-note">
                {t('rangeSummary.securityRows', { value: formatNumber(summaryQuery.data.data.security_event_rows, language) })}
              </small>
            </span>
          </div>
        ) : null}
        {rankQuery.data?.page.retained_from ? (
          <FeedbackWhen type="warning" title={t(rankQuery.data.page.source === 'history' ? 'retention.history' : 'retention.accessLog', {
              time: formatDateTime(rankQuery.data.page.retained_from, language),
            })} />
        ) : null}
        <div className="analytics-table-shell">
          <div
            className="analytics-table-scroll"
            data-testid="analytics-rank-table-scroll"
            aria-busy={tableLoading}
            aria-label={tableLoading ? t('states.loading') : undefined}
          >
            <Table<AnalyticsRankItem>
              rowKey="key"
              size="small"
              columns={columns}
              dataSource={rankQuery.data?.data ?? []}
              loading={tableLoading}
              pagination={false}
              scroll={{ x: canCreateJA4Block ? 1060 : 900 }}
              locale={{ emptyText: queryError ? ' ' : t('states.empty') }}
            />
          </div>
          <div className={`analytics-pagination${!rankQuery.data?.page.next_cursor && pageIndex === 0 ? ' analytics-pagination-empty' : ''}`}>
              {/* 排行是 ClickHouse 聚合，不做精确计数（tp-b7b）：已翻过的条数，还有下一页时显示 N+ */}
              <span>{t(rankQuery.data?.page.next_cursor ? 'table.totalMore' : 'table.total', { count: pageIndex * pageSize + (rankQuery.data?.data.length ?? 0) })}</span>
              <span>{t('table.page', { page: pageIndex + 1 })}</span>
              <Button
                icon={<ChevronLeft size={15} />}
                disabled={pageIndex === 0 || rankQuery.isFetching}
                onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
              >
                {t('actions.previous')}
              </Button>
              <Button
                icon={<ChevronRight size={15} />}
                disabled={!rankQuery.data?.page.next_cursor || rankQuery.isFetching}
                onClick={nextPage}
              >
                {t('actions.next')}
              </Button>
          </div>
        </div>
      </div>
      <Modal
        title={tJA4('confirmation.title')}
        open={Boolean(ja4Target)}
        okText={tJA4('actions.confirmBlock')}
        cancelText={tJA4('actions.cancel')}
        confirmLoading={ja4WritePending}
        okButtonProps={{ disabled: Boolean(ja4Attempt || ja4Workflow) || ja4ReadPending }}
        closable={!ja4WritePending && !ja4ReadPending}
        maskClosable={!ja4WritePending && !ja4ReadPending}
        onOk={submitJA4Block}
        onCancel={closeJA4Dialog}
      >
        {ja4Target ? (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Alert type="warning" showIcon message={tJA4('confirmation.description')} />
            <Descriptions size="small" bordered column={1}>
              <Descriptions.Item label={tJA4('fields.tenantScopeId')}>{compactTechnicalID(ja4Target.tenantScopeID)}</Descriptions.Item>
              <Descriptions.Item label={tJA4('fields.siteId')}>{compactTechnicalID(ja4Target.siteID)}</Descriptions.Item>
              <Descriptions.Item label={tJA4('fields.maskedJa4')}>{maskJA4(ja4Target.rowKey)}</Descriptions.Item>
              <Descriptions.Item label={tJA4('fields.snapshotAt')}>{ja4Target.snapshotAt}</Descriptions.Item>
            </Descriptions>
            {!ja4Workflow ? (
              <Form layout="vertical">
                <Form.Item label={tJA4('fields.durationSeconds')}>
                  <InputNumber
                    aria-label={tJA4('fields.durationSeconds')}
                    min={60}
                    max={2_592_000}
                    value={ja4Duration}
                    onChange={setJA4Duration}
                  />
                </Form.Item>
                <Form.Item label={tJA4('fields.reason')}>
                  <Input aria-label={tJA4('fields.reason')} value={ja4Reason} onChange={(event) => setJA4Reason(event.target.value)} />
                </Form.Item>
                <Form.Item label={tJA4('fields.stepUp')}>
                  <Input.Password aria-label={tJA4('fields.stepUp')} value={ja4StepUp} onChange={(event) => setJA4StepUp(event.target.value)} />
                </Form.Item>
                {ja4FormError ? <Alert type="error" showIcon message={tJA4(ja4FormError)} /> : null}
              </Form>
            ) : null}
            {ja4Attempt && ja4WriteError && unknownWriteOutcome(ja4WriteError) ? (
              <Alert
                type="warning"
                showIcon
                message={tJA4('states.outcomeUnknown')}
                action={(
                  <Space wrap>
                    <Button type="primary" loading={ja4WritePending} onClick={() => void executeJA4Block(ja4Attempt)}>
                      {tJA4('actions.retrySame')}
                    </Button>
                    <Button disabled={ja4WritePending} onClick={abandonJA4Attempt}>{tJA4('actions.abandon')}</Button>
                  </Space>
                )}
              />
            ) : ja4WriteError ? <Alert type="error" showIcon message={tJA4(ja4WriteErrorKey(ja4WriteError))} /> : null}
            {ja4Workflow ? (
              <>
                <Alert type="info" showIcon message={tJA4('receipt.disclaimer')} />
                <Descriptions size="small" bordered column={1}>
                  <Descriptions.Item label={tJA4('fields.workflowId')}>{compactTechnicalID(ja4Workflow.workflow.id)}</Descriptions.Item>
                  <Descriptions.Item label={tJA4('fields.rolloutId')}>{compactTechnicalID(ja4Workflow.workflow.rollout_id)}</Descriptions.Item>
                  <Descriptions.Item label={tJA4('fields.revision')}>{ja4Workflow.workflow.revision}</Descriptions.Item>
                  <Descriptions.Item label={tJA4('fields.phase')}>
                    <Tag color={ja4Workflow.workflow.phase === 'active' && ja4Workflow.workflow.edge_state === 'active' ? 'success' : 'processing'}>
                      {ja4Workflow.workflow.phase === 'active' && ja4Workflow.workflow.edge_state === 'active'
                        ? tJA4('states.active')
                        : tJA4(`phases.${ja4Workflow.workflow.phase === 'active' ? 'edge_pending' : ja4Workflow.workflow.phase}`)}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label={tJA4('fields.edgeState')}>{tJA4(`edgeStates.${ja4Workflow.workflow.edge_state || 'none'}`)}</Descriptions.Item>
                </Descriptions>
                {ja4ReadError ? (
                  <Alert
                    type="error"
                    showIcon
                    message={tJA4('states.loadError')}
                    action={<Button onClick={() => void refreshJA4Workflow(ja4Workflow)}>{tJA4('actions.retryRead')}</Button>}
                  />
                ) : null}
              </>
            ) : null}
          </Space>
        ) : null}
      </Modal>
    </section>
  )
}
