import { useCallback, useEffect, useMemo, useRef, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntApp,
  Alert,
  AutoComplete,
  Button,
  Descriptions,
  Input,
  Modal,
  Progress,
  Result,
  Select,
  Space,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { Ban, ChevronLeft, ChevronRight } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useInRouterContext, useSearchParams } from 'react-router-dom'

import {
  jobsApi,
  type AdminJobListParams,
  type BackgroundJob,
  type JobAudience,
  type JobAttempt,
  type JobAttemptState,
  type JobCommand,
  type JobCommandResponse,
  type JobDeadLetter,
  type JobItemResult,
  type JobResultState,
  type JobSettlementReceipt,
  type JobState,
} from '../api/jobs'
import { ApiError, type Principal } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { adminTasksParityText } from '../i18n/adminTasksParity'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import i18n from '../i18n'
import '../i18n/jobSettlement'
import '../i18n/siteCnameRegeneration'
import './AdminTasksPage.css'
import { useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

const pageSizes = [10, 20, 50, 100] as const
const childPageSize = 20
const subtaskPageSize = 10
const maximumWindowMilliseconds = 31 * 24 * 60 * 60 * 1000
const kindPattern = /^[a-z][a-z0-9._-]{0,127}$/
const taskIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const knownFailureCodes = new Set([
  'all_items_failed', 'cancelled', 'item_failed', 'lease_expired', 'node_unavailable', 'retries_exhausted',
])
// Item causes only the platform fixes (line groups, DNS / CNAME domains): a
// tenant contacts an administrator, an administrator fixes the setting.
// Same set as fix-cuaccui's cnameFailureNeedsLine/NeedsPlatform (siteCnameRegeneration codes).
const platformFailureCodes = new Set([
  'cname_no_default_line_group', 'node_group_unavailable', 'node_targets_unavailable',
  'dns_provider_not_configured', 'cname_zone_not_configured', 'cname_zone_provider_mismatch',
  'cname_no_default_zone', 'platform_dns_sync_failed', 'domain_blocked',
])
type JobStatusFilter = 'success' | 'failure' | 'pending' | 'running'
const jobStatusFilters: Record<JobStatusFilter, JobState[]> = {
  success: ['succeeded'],
  failure: ['failed', 'partial_failed'],
  pending: ['queued'],
  running: ['running'],
}

interface FilterDraft {
  from: string
  to: string
  taskID: string
  status: JobStatusFilter | ''
  kind: string
  resource: string
}

interface CommandAttempt {
  action: JobCommand
  job: BackgroundJob
  idempotencyKey: string
}

interface CommandConfirmation {
  action: JobCommand
  job: BackgroundJob
}

interface JobOwner {
  scopeKind: Principal['scope_kind']
  scopeID: string
  tenantID: string | null
  userID: string
  sessionEpoch: number
}

type JobOwnerTuple = readonly [
  JobOwner['scopeKind'], string, string | null, string, number,
]

function jobOwner(principal: Principal, sessionEpoch: number): JobOwner {
  return {
    scopeKind: principal.scope_kind,
    scopeID: principal.scope_id,
    tenantID: principal.tenant_id,
    userID: principal.user_id,
    sessionEpoch,
  }
}

function jobOwnerTuple(owner: JobOwner): JobOwnerTuple {
  return [owner.scopeKind, owner.scopeID, owner.tenantID, owner.userID, owner.sessionEpoch]
}

function jobOwnerKey(owner: JobOwner): string {
  return JSON.stringify(jobOwnerTuple(owner))
}

function validJobPrincipal(principal: Principal): boolean {
  return principal.scope_kind !== 'tenant' || Boolean(principal.tenant_id)
}

function jobPrincipalCan(principal: Principal, operation: 'read' | 'manage'): boolean {
  if (!validJobPrincipal(principal)) return false
  if (principal.scope_kind === 'platform') {
    return principal.permissions.includes('platform.admin') ||
      principal.permissions.includes(operation === 'read' ? 'jobs.read_all' : 'jobs.manage_all')
  }
  return principal.permissions.includes(operation === 'read' ? 'jobs.read' : 'jobs.manage')
}

function currentJobSessionMatches(expectedOwnerKey: string): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  return Boolean(
    accessToken && principal && sessionEpoch && validJobPrincipal(principal) &&
    jobOwnerKey(jobOwner(principal, sessionEpoch)) === expectedOwnerKey,
  )
}

function currentJobSessionAccess(expectedOwnerKey: string, operation: 'read' | 'manage'): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !sessionEpoch || !jobPrincipalCan(principal, operation)) return null
  return jobOwnerKey(jobOwner(principal, sessionEpoch)) === expectedOwnerKey ? accessToken : null
}

function invalidJobResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function jobPermissionDenied(): ApiError {
  return new ApiError('Job permission denied', 403, 'job_permission_denied')
}

function assertJobTenantOwner(audience: JobAudience, owner: JobOwner, job: BackgroundJob): void {
  if (audience === 'tenant' && job.tenant_id !== owner.tenantID) throw invalidJobResponse()
}

// The list has no visible time filter (competitor parity); every query covers
// the newest 31 days, the maximum window the job API accepts.
function rollingWindow(): Pick<FilterDraft, 'from' | 'to'> {
  const to = new Date()
  to.setSeconds(0, 0)
  to.setMinutes(to.getMinutes() + 1)
  return {
    from: new Date(to.getTime() - maximumWindowMilliseconds).toISOString(),
    to: to.toISOString(),
  }
}

function initialFilters(resource = '', taskID = ''): FilterDraft {
  return { ...rollingWindow(), taskID, status: '', kind: '', resource }
}

// A task_id deep link only counts when it is a task UUID; anything else is ignored.
function deepLinkTaskID(value: string): string {
  return taskIDPattern.test(value) ? value.toLowerCase() : ''
}

function validateFilters(draft: FilterDraft, t: TFunction<'jobs'>, invalidTaskIDText: string): string | null {
  const from = new Date(draft.from)
  const to = new Date(draft.to)
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) {
    return t('validation.invalidWindow')
  }
  if (to.getTime() - from.getTime() > maximumWindowMilliseconds) {
    return t('validation.rangeTooLong')
  }
  if (draft.taskID && !taskIDPattern.test(draft.taskID.trim())) return invalidTaskIDText
  if (draft.kind && !kindPattern.test(draft.kind.trim())) return t('validation.invalidKind')
  if (draft.resource.length > 512) return t('validation.resourceTooLong')
  return null
}

function requestFilters(draft: FilterDraft): Omit<AdminJobListParams, 'limit' | 'cursor'> {
  return {
    from: new Date(draft.from).toISOString(),
    to: new Date(draft.to).toISOString(),
    ...(draft.taskID.trim() ? { taskID: draft.taskID.trim() } : {}),
    ...(draft.status ? { statuses: jobStatusFilters[draft.status] } : {}),
    ...(draft.kind.trim() ? { kind: draft.kind.trim() } : {}),
    ...(draft.resource ? { resource: draft.resource } : {}),
  }
}

interface BulkCancelOutcome {
  cancelled: string[]
  failed: Array<{ taskID: string; error: unknown }>
}

function errorMessage(error: unknown, t: TFunction<'jobs'>, operation: 'read' | 'write' = 'read'): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const knownCodes = new Set([
    'job_invalid_request',
    'job_idempotency_conflict',
    'job_invalid_transition',
    'job_retries_exhausted',
    'job_producer_command_required',
		'job_revision_conflict',
    'job_permission_denied',
    'job_scope_forbidden',
    'job_not_found',
    'job_request_cancelled',
    'job_store_invalid_response',
    'job_response_too_large',
    'job_store_unavailable',
    'job_query_timeout',
    'invalid_response',
    'network_error',
  ])
  const key = error.code === 'job_permission_denied' && operation === 'write'
    ? 'errors.job_permission_denied_manage'
    : knownCodes.has(error.code) ? `errors.${error.code}` : 'errors.request_failed'
  const localized = t(key)
  return error.requestId
    ? t('errors.withRequestId', { message: localized, requestId: error.requestId })
    : localized
}

function settlementErrorMessage(error: unknown, t: TFunction<'jobSettlement'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const knownCodes = new Set([
    'job_permission_denied', 'job_scope_forbidden', 'job_not_found', 'job_store_unavailable',
    'job_query_timeout', 'invalid_response', 'network_error',
  ])
  return t(knownCodes.has(error.code) ? `errors.${error.code}` : 'errors.request_failed')
}

function settlementRetryAllowed(error: unknown): boolean {
  return !(error instanceof ApiError && (error.status === 403 || error.status === 404))
}

// TASK-CAUSE-01: a job item's own stable code (a CNAME allocation's failure
// code, persisted per item) reads as that feature's words instead of
// "unknown"; codes nobody translates still show the generic text.
function failureText(code: string | undefined, placeholder: string, t: TFunction<'jobs'>): string {
  if (!code) return placeholder
  if (knownFailureCodes.has(code)) return t(`failures.${code}`)
  const cname = `siteCnameRegeneration:failures.${code}`
  if (code !== 'unknown' && i18n.exists(cname)) return i18n.t(cname, { domain: '' })
  return t('failures.unknown')
}

// Item IDs a job kind names its single item with (cnameallocation JobItemID).
function itemText(itemID: string, t: TFunction<'jobs'>): string {
  return i18n.exists(`jobs:items.${itemID}`) ? t(`items.${itemID}` as 'items.allocate') : itemID
}

function newCommandKey(action: JobCommand): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `job-${action}-${suffix}`
}

function unknownCommandOutcome(error: unknown): boolean {
  return error instanceof ApiError && (
    error.code === 'network_error' || error.code === 'invalid_response' || error.code === 'request_failed'
  )
}

// CACHE-ADD-05: cancel/retry of a cache operation is the same command here;
// the server runs it on the cache module (its own transaction and audit).
function canCancel(job: BackgroundJob): boolean {
  return job.status === 'queued' || job.status === 'running'
}

function canRetry(job: BackgroundJob): boolean {
  return (job.status === 'failed' || job.status === 'partial_failed') && job.attempt < job.max_attempts
}

function stateColor(state: JobState | JobAttemptState | JobResultState): string | undefined {
  if (state === 'running') return 'processing'
  if (state === 'succeeded') return 'success'
  if (state === 'partial_failed' || state === 'lease_expired') return 'warning'
  if (state === 'failed') return 'error'
  return undefined
}

function StateTag({ state, dot = false }: { state: JobState | JobAttemptState | JobResultState; dot?: boolean }) {
  const { t } = useTranslation('jobs')
  return <Tag className={dot ? 'jobs-state-dot' : undefined} color={stateColor(state)}>{t(`states.${state}`)}</Tag>
}

function durationText(
  value: { started_at?: string; completed_at?: string }, locale: string, t: TFunction<'jobs'>,
): string {
  if (!value.started_at) return t('values.noFact')
  const started = Date.parse(value.started_at)
  const ended = value.completed_at ? Date.parse(value.completed_at) : Date.now()
  if (!Number.isFinite(started) || !Number.isFinite(ended) || ended < started) return t('values.noFact')
  const seconds = Math.floor((ended - started) / 1000)
  if (seconds < 60) return t('duration.seconds', { count: formatNumber(seconds, locale) })
  if (seconds < 3600) return t('duration.minutes', { count: formatNumber(seconds / 60, locale) })
  return t('duration.hours', { count: formatNumber(seconds / 3600, locale) })
}

export default function AdminTasksPage() {
  const { t } = useTranslation('jobs')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal || !sessionEpoch) return null

  const audience: JobAudience = principal.scope_kind === 'platform' ? 'platform' : 'tenant'
  const canRead = jobPrincipalCan(principal, 'read')
  const canManage = jobPrincipalCan(principal, 'manage')

  if (!canRead) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.job_permission_denied')}
      />
    )
  }

  const owner = jobOwner(principal, sessionEpoch)
  const ownerKey = jobOwnerKey(owner)
  const props = { audience, canManage, owner, ownerKey }

  return <AdminTasksPageWithLocation key={ownerKey} {...props} />
}

interface AdminTasksContentProps {
  audience: JobAudience
  canManage: boolean
  owner: JobOwner
  ownerKey: string
  resourceQuery?: string
  taskQuery?: string
}

function AdminTasksPageWithLocation(props: AdminTasksContentProps) {
  return useInRouterContext() ? <AdminTasksPageRouted {...props} /> : <AdminTasksPageContent {...props} />
}

// Other pages deep-link with /sys/task?resource_id=<id> (e.g. a node's tasks),
// or with task_id=<uuid> to filter to one task and open its details.
function AdminTasksPageRouted(props: AdminTasksContentProps) {
  const [searchParams] = useSearchParams()
  return <AdminTasksPageContent {...props} resourceQuery={searchParams.get('resource_id')?.trim() ?? ''}
    taskQuery={searchParams.get('task_id')?.trim() ?? ''} />
}

function AdminTasksPageContent({
  audience, canManage, owner, ownerKey, resourceQuery = '', taskQuery = '',
}: AdminTasksContentProps) {
  const linkedTaskID = deepLinkTaskID(taskQuery)
  const { t, i18n } = useTranslation('jobs')
  const parityText = useMemo(() => adminTasksParityText(i18n.resolvedLanguage), [i18n.resolvedLanguage])
  const { t: settlementT } = useTranslation('jobSettlement')
  const queryClient = useQueryClient()
  const { message } = AntApp.useApp()
  const feedback = useFeedback()
  const queryOwner = useRef(owner).current
  const ownerTuple = useRef(jobOwnerTuple(queryOwner)).current
  const jobsPrefix = useMemo(() => ['jobs', ...ownerTuple, audience] as const, [audience, ownerTuple])
  const kindsPrefix = useMemo(() => ['job-kinds', ...ownerTuple, audience] as const, [audience, ownerTuple])
  const jobPrefix = useMemo(() => ['job', ...ownerTuple, audience] as const, [audience, ownerTuple])
  const attemptsPrefix = useMemo(
    () => ['job-attempts', ...ownerTuple, audience] as const,
    [audience, ownerTuple],
  )
  const resultsPrefix = useMemo(
    () => ['job-results', ...ownerTuple, audience] as const,
    [audience, ownerTuple],
  )
  const receiptsPrefix = useMemo(
    () => ['job-receipts', ...ownerTuple, audience] as const,
    [audience, ownerTuple],
  )
  const deadLettersPrefix = useMemo(
    () => ['job-dead-letters', ...ownerTuple, audience] as const,
    [audience, ownerTuple],
  )
  const commandMutationKey = useMemo(
    () => ['job-command', ...ownerTuple, audience] as const,
    [audience, ownerTuple],
  )
  const lineageActiveRef = useRef(true)
  const cleanupGenerationRef = useRef(0)
  const currentSessionAccess = useCallback((operation: 'read' | 'manage') => (
    lineageActiveRef.current ? currentJobSessionAccess(ownerKey, operation) : null
  ), [ownerKey])
  const currentSessionMatches = useCallback(() => (
    lineageActiveRef.current && currentJobSessionMatches(ownerKey)
  ), [ownerKey])
  const [draft, setDraft] = useState<FilterDraft>(() => initialFilters(resourceQuery, linkedTaskID))
  const [applied, setApplied] = useState(() => requestFilters(draft))
  const appliedResourceQuery = useRef(resourceQuery)
  const appliedTaskQuery = useRef(linkedTaskID)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageCursors, setPageCursors] = useState<Array<string | undefined>>([undefined])
  const [listPageSize, setListPageSize] = useState<(typeof pageSizes)[number]>(pageSizes[0])
  const [selectedTaskIDs, setSelectedTaskIDs] = useState<string[]>([])
  const [selectedTaskID, setSelectedTaskID] = useState<string | null>(linkedTaskID || null)
  const [attemptPageIndex, setAttemptPageIndex] = useState(0)
  const [attemptCursors, setAttemptCursors] = useState<Array<string | undefined>>([undefined])
  const [resultPageIndex, setResultPageIndex] = useState(0)
  const [resultCursors, setResultCursors] = useState<Array<string | undefined>>([undefined])
  const [receiptPageIndex, setReceiptPageIndex] = useState(0)
  const [receiptCursors, setReceiptCursors] = useState<Array<string | undefined>>([undefined])
  const [deadLetterPageIndex, setDeadLetterPageIndex] = useState(0)
  const [deadLetterCursors, setDeadLetterCursors] = useState<Array<string | undefined>>([undefined])
  const [selectedItem, setSelectedItem] = useState<JobItemResult | null>(null)
  const [commandConfirmation, setCommandConfirmation] = useState<CommandConfirmation | null>(null)
  const [bulkCancelOpen, setBulkCancelOpen] = useState(false)
  // COV-04：批量取消逐项结果（已取消 N、失败 M 及每项原因），失败项可重试。
  const [bulkOutcome, setBulkOutcome] = useState<BulkCancelOutcome | null>(null)
  const [commandAttempt, setCommandAttempt] = useState<CommandAttempt | null>(null)
  const [commandError, setCommandError] = useState<unknown>(null)
  const cursor = pageCursors[pageIndex]

  useEffect(() => {
    if (canManage) return
    setSelectedTaskIDs([])
    setCommandConfirmation(null)
    setBulkCancelOpen(false)
  }, [canManage])

  useEffect(() => {
    const generation = ++cleanupGenerationRef.current
    lineageActiveRef.current = true
    const cleanupOwnerCache = () => {
      queryClient.removeQueries({ queryKey: jobsPrefix })
      queryClient.removeQueries({ queryKey: kindsPrefix })
      queryClient.removeQueries({ queryKey: jobPrefix })
      queryClient.removeQueries({ queryKey: attemptsPrefix })
      queryClient.removeQueries({ queryKey: resultsPrefix })
      queryClient.removeQueries({ queryKey: receiptsPrefix })
      queryClient.removeQueries({ queryKey: deadLettersPrefix })
      const mutationCache = queryClient.getMutationCache()
      for (const mutation of mutationCache.findAll({ mutationKey: commandMutationKey, exact: true })) {
        mutationCache.remove(mutation)
      }
    }
    return () => {
      lineageActiveRef.current = false
      const current = useSessionStore.getState()
      const currentOwner = current.principal && current.sessionEpoch
        ? jobOwner(current.principal, current.sessionEpoch)
        : null
      if (!currentOwner || jobOwnerKey(currentOwner) !== ownerKey) {
        cleanupOwnerCache()
        return
      }
      queueMicrotask(() => {
        if (cleanupGenerationRef.current === generation) cleanupOwnerCache()
      })
    }
  }, [attemptsPrefix, commandMutationKey, deadLettersPrefix, jobPrefix, jobsPrefix, kindsPrefix, ownerKey, queryClient, receiptsPrefix, resultsPrefix])

  const kindsQuery = useQuery({
    queryKey: kindsPrefix,
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.kinds(token, audience)
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
    staleTime: 60_000,
  })

  const listQuery = useQuery({
    queryKey: [...jobsPrefix, applied, listPageSize, cursor ?? pageIndex + 1],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.list(token, audience, {
          ...applied, limit: listPageSize,
          ...(cursor ? { cursor } : { page: pageIndex + 1 }),
        })
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        if (audience === 'tenant') {
          for (const job of result.data) assertJobTenantOwner(audience, queryOwner, job)
        }
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
  })
  const detailQuery = useQuery({
    queryKey: [...jobPrefix, selectedTaskID],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.detail(token, audience, selectedTaskID!)
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        assertJobTenantOwner(audience, queryOwner, result.data)
        if (result.data.task_id !== selectedTaskID) throw invalidJobResponse()
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
    enabled: Boolean(selectedTaskID),
  })
  const attemptsQuery = useQuery({
    queryKey: [...attemptsPrefix, selectedTaskID, attemptCursors[attemptPageIndex]],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.attempts(
          token,
          audience,
          selectedTaskID!,
          childPageSize,
          attemptCursors[attemptPageIndex],
        )
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
    enabled: Boolean(selectedTaskID),
  })
  const resultsQuery = useQuery({
    queryKey: [...resultsPrefix, selectedTaskID, resultCursors[resultPageIndex]],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.results(
          token,
          audience,
          selectedTaskID!,
          subtaskPageSize,
          resultCursors[resultPageIndex],
        )
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
    enabled: Boolean(selectedTaskID),
  })
  const receiptsQuery = useQuery({
    queryKey: [...receiptsPrefix, selectedTaskID, receiptCursors[receiptPageIndex]],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.receipts(
          token,
          audience,
          selectedTaskID!,
          childPageSize,
          receiptCursors[receiptPageIndex],
        )
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
    enabled: Boolean(selectedTaskID),
  })
  const deadLettersQuery = useQuery({
    queryKey: [...deadLettersPrefix, selectedTaskID, deadLetterCursors[deadLetterPageIndex]],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw jobPermissionDenied()
      try {
        const result = await jobsApi.deadLetters(
          token,
          audience,
          selectedTaskID!,
          childPageSize,
          deadLetterCursors[deadLetterPageIndex],
        )
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        return result
      } catch (error) {
        if (!currentSessionAccess('read')) throw invalidJobResponse()
        throw error
      }
    },
    enabled: Boolean(selectedTaskID),
  })
  const commandMutation = useMutation<JobCommandResponse, unknown, CommandAttempt>({
    mutationKey: commandMutationKey,
    mutationFn: async (attempt) => {
      const token = currentSessionAccess('manage')
      if (!token) throw jobPermissionDenied()
      try {
        const result = attempt.action === 'retry'
			? await jobsApi.retry(
				token, audience, attempt.job.task_id, attempt.idempotencyKey,
				attempt.job.attempt, attempt.job.revision,
			)
			: await jobsApi.cancel(
				token, audience, attempt.job.task_id, attempt.idempotencyKey, attempt.job.revision,
			)
        if (!currentSessionMatches()) throw invalidJobResponse()
        assertJobTenantOwner(audience, queryOwner, result.data)
        return result
      } catch (error) {
        if (!currentSessionMatches()) throw invalidJobResponse()
        throw error
      }
    },
    onSuccess: async (_, attempt) => {
      if (!currentSessionMatches()) return
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: jobsPrefix }),
        queryClient.invalidateQueries({ queryKey: jobPrefix }),
        queryClient.invalidateQueries({ queryKey: attemptsPrefix }),
        queryClient.invalidateQueries({ queryKey: resultsPrefix }),
      ])
      if (!currentSessionMatches()) return
      setCommandAttempt(null)
      setCommandError(null)
      if (currentSessionAccess('manage')) message.success(t(`notices.${attempt.action}Succeeded`))
    },
    onError: (error, attempt) => {
      if (!currentSessionMatches()) return
      setCommandError(error)
      setCommandAttempt(unknownCommandOutcome(error) ? attempt : null)
    },
  })
  const bulkCancelMutation = useMutation<BulkCancelOutcome, unknown, BackgroundJob[]>({
    mutationKey: [...commandMutationKey, 'bulk-cancel'],
    mutationFn: async (jobs) => {
      const token = currentSessionAccess('manage')
      if (!token) throw jobPermissionDenied()
      const outcome: BulkCancelOutcome = { cancelled: [], failed: [] }
      // 逐项提交、逐项记结果：中途某项失败不影响后面的项，也不丢掉前面已取消的。
      for (const job of jobs) {
        if (!currentSessionMatches()) throw invalidJobResponse()
        try {
          const response = await jobsApi.cancel(token, audience, job.task_id, newCommandKey('cancel'), job.revision)
          assertJobTenantOwner(audience, queryOwner, response.data)
          outcome.cancelled.push(job.task_id)
        } catch (error) {
          if (!currentSessionMatches()) throw invalidJobResponse()
          outcome.failed.push({ taskID: job.task_id, error })
        }
      }
      return outcome
    },
    onSuccess: async (outcome) => {
      if (!currentSessionMatches()) return
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: jobsPrefix }),
        queryClient.invalidateQueries({ queryKey: jobPrefix }),
        queryClient.invalidateQueries({ queryKey: attemptsPrefix }),
        queryClient.invalidateQueries({ queryKey: resultsPrefix }),
      ])
      if (!currentSessionMatches()) return
      setBulkCancelOpen(false)
      setCommandError(null)
      // 失败项保持选中，便于重试；全部成功才清空。
      setSelectedTaskIDs(outcome.failed.map((item) => item.taskID))
      if (outcome.failed.length === 0) {
        setBulkOutcome(null)
        message.success(t('notices.cancelSucceeded'))
      } else {
        setBulkOutcome(outcome)
      }
    },
    onError: (error) => {
      if (!currentSessionMatches()) return
      setCommandError(error)
      setBulkCancelOpen(false)
    },
  })

  useEffect(() => {
    if (appliedResourceQuery.current === resourceQuery && appliedTaskQuery.current === linkedTaskID) return
    const taskChanged = appliedTaskQuery.current !== linkedTaskID
    appliedResourceQuery.current = resourceQuery
    appliedTaskQuery.current = linkedTaskID
    const next = { ...draft, ...rollingWindow(), resource: resourceQuery, taskID: taskChanged ? linkedTaskID : draft.taskID }
    setDraft(next)
    setApplied(requestFilters(next))
    setPageIndex(0)
    setPageCursors([undefined])
    setSelectedTaskIDs([])
    if (taskChanged && linkedTaskID) openDetails(linkedTaskID)
  }, [draft, resourceQuery, linkedTaskID])

  if (listQuery.error instanceof ApiError && listQuery.error.status === 403) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.job_permission_denied')}
      />
    )
  }

  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const placeholder = t('values.noFact')
  const resetPages = () => {
    setPageIndex(0)
    setPageCursors([undefined])
    setSelectedTaskIDs([])
  }
  const apply = (nextDraft: FilterDraft = draft) => {
    const windowed = { ...nextDraft, ...rollingWindow() }
    const error = validateFilters(windowed, t, parityText.invalidTaskID)
    setValidationError(error)
    if (error) return
    const next = requestFilters(windowed)
    if (JSON.stringify(next) === JSON.stringify(applied) && pageIndex === 0) {
      void listQuery.refetch()
      return
    }
    setDraft(windowed)
    setApplied(next)
    resetPages()
  }
  const applySelection = (nextDraft: FilterDraft) => {
    setDraft(nextDraft)
    apply(nextDraft)
  }
  const kindNames = new Map((kindsQuery.data?.data ?? []).map((entry) => [entry.kind, t(entry.name_key.slice(5))]))
  const kindLabel = (kind: string) => kindNames.get(kind) ?? kind
  const kindOptions = Array.from(new Set([
    ...(kindsQuery.data?.data.map((entry) => entry.kind) ?? []),
    ...(listQuery.data?.data.map((job) => job.kind) ?? []),
    ...(draft.kind ? [draft.kind] : []),
  ])).map((value) => ({ value, label: kindLabel(value) }))
  const kindSelectOptions = kindOptions.length > 0
    ? [{ value: '', label: t('filters.allKinds') }, ...kindOptions]
    : [{ value: '__no_fact__', label: t('values.noFact'), disabled: true }]
  const numberedPage = listQuery.data?.page && 'number' in listQuery.data.page ? listQuery.data.page : null
  const metadata = new Map((listQuery.data?.task_metadata ?? []).map((entry) => [entry.task_id, entry]))
  const pageWindowStart = numberedPage ? Math.max(1, Math.min(pageIndex, numberedPage.total_pages - 2)) : 1
  const visiblePageNumbers = numberedPage ? Array.from(new Set([
    1, pageWindowStart, pageWindowStart + 1, pageWindowStart + 2, Math.max(1, numberedPage.total_pages),
  ])).filter((value) => value >= 1 && value <= Math.max(1, numberedPage.total_pages)).sort((a, b) => a - b) : []
  const nextPage = () => {
    if (numberedPage) {
      if (pageIndex + 1 >= numberedPage.total_pages) return
      setPageIndex((current) => current + 1)
      setSelectedTaskIDs([])
      return
    }
    const nextCursor = listQuery.data && 'next_cursor' in listQuery.data.page ? listQuery.data.page.next_cursor : undefined
    if (!nextCursor) return
    setPageCursors((current) => [...current.slice(0, pageIndex + 1), nextCursor])
    setPageIndex((current) => current + 1)
    setSelectedTaskIDs([])
  }
  const openDetails = (taskID: string) => {
    setSelectedTaskID(taskID)
    setAttemptPageIndex(0)
    setAttemptCursors([undefined])
    setResultPageIndex(0)
    setResultCursors([undefined])
    setReceiptPageIndex(0)
    setReceiptCursors([undefined])
    setDeadLetterPageIndex(0)
    setDeadLetterCursors([undefined])
  }
  const closeDetails = () => {
    setSelectedTaskID(null)
    setSelectedItem(null)
  }
  const refreshDetails = () => {
    void detailQuery.refetch()
    void resultsQuery.refetch()
    void attemptsQuery.refetch()
    void receiptsQuery.refetch()
    void deadLettersQuery.refetch()
  }
  const nextAttemptPage = () => {
    const nextCursor = attemptsQuery.data?.page.next_cursor
    if (!nextCursor) return
    setAttemptCursors((current) => [...current.slice(0, attemptPageIndex + 1), nextCursor])
    setAttemptPageIndex((current) => current + 1)
  }
  const nextResultPage = () => {
    const nextCursor = resultsQuery.data?.page.next_cursor
    if (!nextCursor) return
    setResultCursors((current) => [...current.slice(0, resultPageIndex + 1), nextCursor])
    setResultPageIndex((current) => current + 1)
  }
  const nextReceiptPage = () => {
    const nextCursor = receiptsQuery.data?.page.next_cursor
    if (!nextCursor) return
    setReceiptCursors((current) => [...current.slice(0, receiptPageIndex + 1), nextCursor])
    setReceiptPageIndex((current) => current + 1)
  }
  const nextDeadLetterPage = () => {
    const nextCursor = deadLettersQuery.data?.page.next_cursor
    if (!nextCursor) return
    setDeadLetterCursors((current) => [...current.slice(0, deadLetterPageIndex + 1), nextCursor])
    setDeadLetterPageIndex((current) => current + 1)
  }
  const uncertainCommand = Boolean(commandAttempt && commandError && unknownCommandOutcome(commandError))
	const revisionConflict = commandError instanceof ApiError && commandError.code === 'job_revision_conflict'
  const writesLocked = commandMutation.isPending || bulkCancelMutation.isPending || uncertainCommand
	const selectedJobs = (listQuery.data?.data ?? []).filter((job) => selectedTaskIDs.includes(job.task_id))
	const selectedCancellableJobs = selectedJobs.filter(canCancel)
	const openBulkCancel = () => {
		if (!canManage || writesLocked) return
		if (selectedCancellableJobs.length === 0) {
			feedback.warning(parityText.selectTaskFirst)
			return
		}
		setCommandError(null)
		setBulkCancelOpen(true)
	}
	const confirmBulkCancel = () => {
		if (!canManage || writesLocked || selectedCancellableJobs.length === 0) return
		setBulkOutcome(null)
		bulkCancelMutation.mutate(selectedCancellableJobs)
	}
	// 重试失败项：用刷新后的列表（新 revision）里仍可取消的那些。
	const bulkRetryJobs = (listQuery.data?.data ?? [])
		.filter((job) => bulkOutcome?.failed.some((item) => item.taskID === job.task_id) && canCancel(job))
	const retryBulkFailures = () => {
		if (!canManage || writesLocked || bulkRetryJobs.length === 0) return
		setBulkOutcome(null)
		bulkCancelMutation.mutate(bulkRetryJobs)
	}
	const refreshAfterRevisionConflict = () => {
		setCommandError(null)
		void Promise.all([
			queryClient.invalidateQueries({ queryKey: jobsPrefix }),
			queryClient.invalidateQueries({ queryKey: jobPrefix }),
			queryClient.invalidateQueries({ queryKey: attemptsPrefix }),
			queryClient.invalidateQueries({ queryKey: resultsPrefix }),
		])
	}
  const openCommand = (action: JobCommand, job: BackgroundJob) => {
    if (!canManage || writesLocked) return
    setCommandError(null)
    setCommandConfirmation({ action, job })
  }
  const confirmCommand = () => {
    if (!canManage || !commandConfirmation || commandMutation.isPending) {
      if (!canManage) setCommandConfirmation(null)
      return
    }
    const attempt: CommandAttempt = {
      ...commandConfirmation,
      idempotencyKey: newCommandKey(commandConfirmation.action),
    }
    setCommandAttempt(attempt)
    setCommandConfirmation(null)
    setCommandError(null)
    commandMutation.mutate(attempt)
  }
  const retrySameCommand = () => {
    if (!canManage || !commandAttempt || commandMutation.isPending) return
    setCommandError(null)
    commandMutation.mutate(commandAttempt)
  }
  const renderCommandActions = (job: BackgroundJob, includeDetails: boolean) => {
    const pendingAction = commandMutation.isPending && commandAttempt?.job.task_id === job.task_id
      ? commandAttempt.action
      : null
    const cancelLabel = pendingAction === 'cancel' ? t('states.canceling') : t('actions.cancel')
    const retryLabel = pendingAction === 'retry' ? t('states.retrying') : t('actions.retryFailed')
    const cancellable = canCancel(job)
    return (
      <Space size={4} wrap={false}>
        {includeDetails ? (
          <Button
            type="link"
            size="small"
            onClick={() => openDetails(job.task_id)}
          >
            {t('actions.details')}
          </Button>
        ) : null}
        {canManage && (cancellable || includeDetails) ? (
          <Button
            type="link"
            size="small"
            aria-label={cancelLabel}
            disabled={writesLocked || !cancellable}
            loading={pendingAction === 'cancel'}
            onClick={() => openCommand('cancel', job)}
          >
            {includeDetails && pendingAction !== 'cancel' ? t('actions.cancelShort') : cancelLabel}
          </Button>
        ) : null}
        {canManage && canRetry(job) ? (
          <Button
            type="link"
            size="small"
            aria-label={retryLabel}
            disabled={writesLocked}
            loading={pendingAction === 'retry'}
            onClick={() => openCommand('retry', job)}
          >
            {retryLabel}
          </Button>
        ) : null}
      </Space>
    )
  }

  const columns: TableColumnsType<BackgroundJob> = [
    { title: t('columns.id'), dataIndex: 'task_id', width: 150, ellipsis: true },
    {
      title: t('columns.priority'), key: 'priority', width: 145,
      render: (_, job) => <span className="jobs-badge jobs-badge--priority">
        {t(`taskFacts.priority.${metadata.get(job.task_id)?.priority.policy ?? 'unknown'}`)}
      </span>,
    },
    {
      title: t('columns.name'), key: 'name', width: 220, ellipsis: true,
      render: (_, job) => {
        const name = metadata.get(job.task_id)?.name
        return name ? <span className="jobs-task-name-cell">
          {t('taskFacts.name', { kind: t(name.name_key.slice(5)), resource: name.resource })}
        </span> : placeholder
      },
    },
    { title: t('columns.kind'), dataIndex: 'kind', width: 160, ellipsis: true, render: kindLabel },
    {
      title: t('columns.resource'),
      dataIndex: ['related_resource', 'reference'],
      width: 140,
      ellipsis: true,
    },
    {
      title: t('columns.dependency'), key: 'dependencies', width: 180,
      render: (_, job) => {
        const dependencies = metadata.get(job.task_id)?.dependencies
        if (dependencies?.state === 'observed') return dependencies.items.map((dependency) => (
          <div className="jobs-dependency-cell" key={dependency.task_id}>
            <Button type="link" size="small" onClick={() => openDetails(dependency.task_id)}>{dependency.task_id}</Button>
            <small>{t('taskFacts.completionDependency')} · {t(`states.${dependency.status}`)}</small>
          </div>
        ))
        return <span className="jobs-muted">
          {t(dependencies?.state === 'none' ? 'taskFacts.noDependency' : 'taskFacts.dependenciesUnknown')}
        </span>
      },
    },
    {
      title: t('columns.startedAt'),
      dataIndex: 'started_at',
      width: 210,
      render: (value: string | undefined, job) => (
        <div className="jobs-start-time-cell">
          {value ? <span>{formatDateTime(value, locale)}</span> : <span className="jobs-muted">{t('values.notStarted')}</span>}
          {job.completed_at ? <small>{t('values.endedAt', { value: formatDateTime(job.completed_at, locale) })}</small> : null}
        </div>
      ),
    },
    {
      title: t('columns.duration'),
      key: 'duration',
      width: 100,
      render: (_, job) => job.started_at
        ? <span className="jobs-badge jobs-badge--duration">{durationText(job, locale, t)}</span>
        : <span className="jobs-badge">{t('values.notStarted')}</span>,
    },
    {
      title: t('columns.status'),
      dataIndex: 'status',
      width: 105,
      render: (value: JobState) => <StateTag state={value} dot />,
    },
    {
      title: t('columns.failureCount'),
      key: 'failureCount',
      width: 96,
      render: (_, job) => formatNumber(job.progress.failed, locale),
    },
    {
      title: t('columns.actions'),
      key: 'actions',
      width: 170,
      render: (_, job) => renderCommandActions(job, true),
    },
  ]
  const rowSelection = canManage ? {
    selectedRowKeys: selectedTaskIDs,
    onChange: (keys: Key[]) => setSelectedTaskIDs(keys.map(String)),
  } : undefined
  const attemptColumns: TableColumnsType<JobAttempt> = [
    { title: t('attempts.number'), dataIndex: 'number', width: 80 },
    { title: t('columns.status'), dataIndex: 'status', width: 120, render: (value: JobAttemptState) => <StateTag state={value} /> },
    { title: t('attempts.startedAt'), dataIndex: 'started_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: t('attempts.heartbeatAt'), dataIndex: 'last_heartbeat_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: t('attempts.leaseExpiresAt'), dataIndex: 'lease_expires_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: t('attempts.completedAt'), dataIndex: 'completed_at', width: 180, render: (value?: string) => value ? formatDateTime(value, locale) : placeholder },
    { title: t('columns.failureCode'), dataIndex: 'failure_code', width: 180, render: (value?: string) => failureText(value, placeholder, t) },
  ]
  const notRecorded = t('values.notRecorded')
  const resultColumns: TableColumnsType<JobItemResult> = [
    { title: t('subtasks.id'), dataIndex: 'ordinal', width: 64 },
    { title: t('subtasks.resource'), dataIndex: 'node_id', width: 200, ellipsis: true, render: (value?: string) => value || <span className="jobs-muted">{notRecorded}</span> },
    { title: t('subtasks.data'), dataIndex: 'item_id', width: 180, ellipsis: true, render: (value: string) => itemText(value, t) },
    { title: t('columns.startedAt'), dataIndex: 'started_at', width: 170, render: (value?: string) => value ? formatDateTime(value, locale) : <span className="jobs-muted">{t('values.notStarted')}</span> },
    { title: t('columns.duration'), key: 'duration', width: 90, render: (_, item) => item.started_at ? durationText(item, locale, t) : <span className="jobs-muted">{t('values.notStarted')}</span> },
    {
      title: t('columns.status'), dataIndex: 'status', width: 150,
      render: (value: JobResultState, item) => <div className="jobs-start-time-cell">
        <StateTag state={value} />
        {item.failure_code ? <small>{failureText(item.failure_code, placeholder, t)}</small> : null}
      </div>,
    },
    { title: t('columns.failureCount'), dataIndex: 'failure_count', width: 90, render: (value?: number) => value === undefined ? <span className="jobs-muted">{notRecorded}</span> : formatNumber(value, locale) },
    {
      title: t('columns.actions'), key: 'actions', width: 80,
      render: (_, item) => <Button type="link" size="small" onClick={() => setSelectedItem(item)}>{t('subtasks.result')}</Button>,
    },
  ]
  const receiptColumns: TableColumnsType<JobSettlementReceipt> = [
    { title: settlementT('receipts.columns.ordinal'), dataIndex: 'ordinal', width: 80 },
    { title: settlementT('receipts.columns.item'), dataIndex: 'item_id', width: 200, ellipsis: true },
    { title: settlementT('receipts.columns.node'), dataIndex: 'node_id', width: 220, ellipsis: true, render: (value?: string) => value || placeholder },
    { title: settlementT('receipts.columns.status'), dataIndex: 'status', width: 110, render: (value: JobResultState) => <Tag color={stateColor(value)}>{settlementT(`states.${value}`)}</Tag> },
    { title: settlementT('receipts.columns.attempt'), dataIndex: 'attempt', width: 100 },
    { title: settlementT('receipts.columns.sequence'), dataIndex: 'sequence', width: 100 },
    { title: settlementT('receipts.columns.source'), dataIndex: 'source', width: 110, render: (value: string) => settlementT(`sources.${value}`) },
    { title: settlementT('receipts.columns.reportedAt'), dataIndex: 'reported_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: settlementT('receipts.columns.failureCode'), dataIndex: 'failure_code', width: 180, render: (value?: string) => failureText(value, placeholder, t) },
  ]
  const deadLetterColumns: TableColumnsType<JobDeadLetter> = [
    { title: settlementT('deadLetters.columns.attempt'), dataIndex: 'attempt', width: 100 },
    { title: settlementT('deadLetters.columns.reason'), dataIndex: 'reason_code', width: 180, render: (value: string) => settlementT(`reasons.${value}`, { defaultValue: settlementT('reasons.item_failed') }) },
    { title: settlementT('deadLetters.columns.failedItems'), dataIndex: 'failed_item_count', width: 120 },
    { title: settlementT('deadLetters.columns.source'), dataIndex: 'source', width: 130, render: (value: string) => settlementT(`sources.${value}`) },
    { title: settlementT('deadLetters.columns.createdAt'), dataIndex: 'created_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
  ]
  const detail = detailQuery.data?.data
  const detailError = detailQuery.error ?? attemptsQuery.error ?? resultsQuery.error
  // TASK-CAUSE-01: a failed task says first why (its items' own causes, not
  // only "all items failed") and who acts next.
  const causeSummary = (() => {
    if (!detail || (detail.status !== 'failed' && detail.status !== 'partial_failed')) return null
    const causes = new Map<string, number>()
    for (const item of resultsQuery.data?.data ?? []) {
      if (item.status === 'failed' && item.failure_code) causes.set(item.failure_code, (causes.get(item.failure_code) ?? 0) + 1)
    }
    const reasons = [...causes].map(([code, count]) => causes.size > 1 || count > 1
      ? t('cause.reasonCount', { reason: failureText(code, placeholder, t), count }) : failureText(code, placeholder, t))
    const message = reasons.length > 0 ? t('cause.message', { reasons: reasons.join('；') })
      : t('cause.message', { reasons: failureText(detail.failure_code, placeholder, t) })
    const codes = [...causes.keys()]
    const platform = codes.some((code) => platformFailureCodes.has(code))
    const next = platform ? t(audience === 'platform' ? 'cause.nextAdmin' : 'cause.nextTenant') : t('cause.nextRetry')
    return { message, next }
  })()
  const progressPercent = detail
    ? Math.round(detail.progress.completed / detail.progress.total * 100)
    : 0
  const detailStatus = detail ? <StateTag state={detail.status} /> : placeholder

  return (
    <section
      className="identity-page jobs-page"
      aria-labelledby="jobs-page-title"
      style={{ width: 'auto', minWidth: 0, maxWidth: '100%', overflowX: 'hidden' }}
    >
      <h1 id="jobs-page-title" className="visually-hidden">{t('title')}</h1>
      <div className="jobs-toolbar">
        {canManage ? (
          <div className="jobs-action-group">
            <Button
              danger
              aria-label={parityText.bulkCancelAria}
              icon={<Ban size={15} aria-hidden="true" />}
              onClick={openBulkCancel}
              disabled={writesLocked}
            >
              {t('actions.cancel')}
            </Button>
          </div>
        ) : null}
        <div className="jobs-filter-group">
          <AutoComplete
            className="jobs-kind-filter"
            aria-label={t('filters.kind')}
            allowClear
            placeholder={t('filters.allKinds')}
            value={draft.kind}
            options={kindSelectOptions}
            virtual={false}
            title={t('taskFacts.catalogHint')}
            onChange={(kind) => setDraft((current) => ({ ...current, kind }))}
            onSelect={(kind) => applySelection({ ...draft, kind })}
            onClear={() => applySelection({ ...draft, kind: '' })}
            onInputKeyDown={(event) => { if (event.key === 'Enter') apply() }}
          />
          <Select<JobStatusFilter | ''>
            className="jobs-status-filter"
            aria-label={t('filters.status')}
            allowClear
            placeholder={t('filters.allStatuses')}
            value={draft.status || undefined}
            options={[
              { value: '', label: t('filters.allStatuses') },
              { value: 'success', label: t('filters.statusOptions.success') },
              { value: 'failure', label: t('filters.statusOptions.failure') },
              { value: 'pending', label: t('filters.statusOptions.pending') },
              { value: 'running', label: t('filters.statusOptions.running') },
            ]}
            onChange={(status) => applySelection({ ...draft, status: status || '' })}
          />
          <Input
            aria-label={parityText.taskID}
            addonBefore={parityText.taskID}
            placeholder={parityText.taskIDPlaceholder}
            value={draft.taskID}
            onChange={(event) => setDraft((current) => ({ ...current, taskID: event.target.value }))}
            onPressEnter={() => apply()}
          />
          <Input
            aria-label={t('filters.resource')}
            addonBefore={parityText.resourcePrefix}
            placeholder={t('filters.resourcePlaceholder')}
            value={draft.resource}
            onChange={(event) => setDraft((current) => ({ ...current, resource: event.target.value }))}
            onPressEnter={() => apply()}
          />
        </div>
        <Button className="visually-hidden" onClick={() => apply()}>
          {t('actions.query')}
        </Button>
      </div>

      {validationError ? <Alert className="identity-alert" type="error" showIcon message={validationError} /> : null}
      {kindsQuery.isError ? (
        <FeedbackWhen type="warning" title={t('taskFacts.catalogLoadFailed')} detail={errorMessage(kindsQuery.error, t)} action={<Button size="small" onClick={() => void kindsQuery.refetch()}>{t('taskFacts.catalogRetry')}</Button>} />
      ) : null}
      {listQuery.isError ? (
        <FeedbackWhen title={t('errors.listLoadFailed')} detail={errorMessage(listQuery.error, t)} action={<Button size="small" onClick={() => void listQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      {canManage && bulkOutcome ? (
        <Alert
          className="identity-alert"
          type="warning"
          showIcon
          closable
          onClose={() => setBulkOutcome(null)}
          data-testid="jobs-bulk-cancel-outcome"
          message={parityText.bulkCancelPartial
            .replace('{{cancelled}}', String(bulkOutcome.cancelled.length))
            .replace('{{failed}}', String(bulkOutcome.failed.length))}
          description={<ul className="jobs-bulk-failures">
            {bulkOutcome.failed.map((item) => (
              <li key={item.taskID}><code>{item.taskID}</code>：{errorMessage(item.error, t, 'write')}</li>
            ))}
          </ul>}
          action={<Button size="small" disabled={writesLocked || bulkRetryJobs.length === 0} loading={bulkCancelMutation.isPending}
            onClick={retryBulkFailures}>{parityText.bulkCancelRetry}</Button>}
        />
      ) : null}
      {canManage && commandError ? (
        uncertainCommand ? (
          <OutcomeUnknown className="identity-alert" title={t('notices.unknownTitle')} detail={t('notices.unknownDescription')} action={
            <Button size="small" loading={commandMutation.isPending} onClick={retrySameCommand}>
              {t('actions.retrySame')}
            </Button>} />
        ) : (
          <FeedbackWhen title={t('errors.commandFailed')} detail={errorMessage(commandError, t, 'write')}
            action={revisionConflict ? <Button size="small" onClick={refreshAfterRevisionConflict}>{t('actions.refresh')}</Button> : undefined} />
        )
      ) : null}

      <div
        className="identity-table-scroll jobs-table-scroll"
        data-testid="jobs-table-scroll"
        aria-busy={listQuery.isPending || listQuery.isFetching}
      >
        <Table<BackgroundJob>
          rowKey="task_id"
          size="small"
          rowSelection={rowSelection}
          columns={columns}
          dataSource={listQuery.data?.data ?? []}
          loading={listQuery.isPending || listQuery.isFetching}
          pagination={false}
          locale={{ emptyText: listQuery.isPending ? ' ' : t('values.empty') }}
          scroll={{ x: 1720 }}
        />
      </div>
      <div className="jobs-pagination" aria-label={t('pagination.label')}>
        <span className="jobs-total">{numberedPage
          ? t('pagination.total', { total: formatNumber(numberedPage.total, locale) })
          : t('pagination.totalUnknown')}</span>
        <Button
          aria-label={t('actions.previous')}
          icon={<ChevronLeft size={15} aria-hidden="true" />}
          disabled={pageIndex === 0 || listQuery.isFetching}
          onClick={() => setPageIndex((current) => current - 1)}
        />
        {numberedPage ? visiblePageNumbers.map((number, index) => <span className="jobs-page-number" key={number}>
          {index > 0 && number - visiblePageNumbers[index - 1] > 1 ? <span aria-hidden="true">…</span> : null}
          <Button
            aria-label={t('pagination.page', { page: formatNumber(number, locale) })}
            aria-current={number === pageIndex + 1 ? 'page' : undefined}
            type={number === pageIndex + 1 ? 'primary' : 'default'}
            ghost={number === pageIndex + 1}
            disabled={listQuery.isFetching}
            onClick={() => {
              setPageIndex(number - 1)
              setPageCursors([undefined])
              setSelectedTaskIDs([])
            }}
          >{formatNumber(number, locale)}</Button>
        </span>) : <Button type="primary" ghost className="jobs-current-page">
          {formatNumber(pageIndex + 1, locale)}
        </Button>}
        <Button
          aria-label={t('actions.next')}
          icon={<ChevronRight size={15} aria-hidden="true" />}
          disabled={listQuery.isFetching || (numberedPage
            ? pageIndex + 1 >= numberedPage.total_pages
            : !(listQuery.data && 'next_cursor' in listQuery.data.page && listQuery.data.page.next_cursor))}
          onClick={nextPage}
        />
        <Select
          aria-label={t('pagination.pageSize')}
          value={listPageSize}
          options={pageSizes.map((value) => ({ value, label: t('pagination.perPage', { count: value }) }))}
          onChange={(value) => {
            setListPageSize(value)
            resetPages()
          }}
        />
        <span className="visually-hidden">{t('pagination.page', { page: formatNumber(pageIndex + 1, locale) })}</span>
      </div>
      {numberedPage && pageIndex > 0 && pageIndex + 1 > numberedPage.total_pages ? (
        <Alert type="info" showIcon message={t('pagination.outOfRange')} />
      ) : null}

      <Modal
        className="jobs-detail-modal"
        width={1000}
        title={t('details.title')}
        open={selectedTaskID !== null}
        onCancel={closeDetails}
        footer={<Button onClick={closeDetails}>{t('actions.close')}</Button>}
      >
        <div className="jobs-detail-toolbar">
          <Button type="primary" loading={detailQuery.isFetching || resultsQuery.isFetching} onClick={refreshDetails}>
            {t('details.refresh')}
          </Button>
          {detail ? renderCommandActions(detail, false) : null}
        </div>
        {detailError ? (
          <Alert
            className="identity-alert"
            type="error"
            showIcon
            message={t('errors.detailLoadFailed')}
            description={errorMessage(detailError, t)}
          />
        ) : null}
        {causeSummary ? (
          <Alert data-testid="jobs-cause-summary" className="identity-alert" type="error" showIcon
            message={causeSummary.message} description={causeSummary.next} />
        ) : null}
        <section className="jobs-detail-section" aria-labelledby="jobs-results-title">
          <h2 id="jobs-results-title" className="visually-hidden">{t('results.title')}</h2>
          <div className="identity-table-scroll">
            <Table<JobItemResult>
              rowKey="ordinal"
              size="small"
              columns={resultColumns}
              dataSource={resultsQuery.data?.data ?? []}
              loading={resultsQuery.isPending || resultsQuery.isFetching}
              pagination={false}
              locale={{ emptyText: resultsQuery.isPending ? ' ' : t('results.empty') }}
              scroll={{ x: 1020 }}
            />
          </div>
          <div className="jobs-child-pagination jobs-subtask-pagination">
            <span>{detail
              ? t('pagination.total', { total: formatNumber(detail.progress.total, locale) })
              : t('pagination.totalUnknown')}</span>
            <Button aria-label={t('results.previous')} icon={<ChevronLeft size={15} aria-hidden="true" />} disabled={resultPageIndex === 0 || resultsQuery.isFetching} onClick={() => setResultPageIndex((current) => current - 1)} />
            <Button type="primary" ghost className="jobs-current-page" aria-current="page">{formatNumber(resultPageIndex + 1, locale)}</Button>
            <Button aria-label={t('results.next')} icon={<ChevronRight size={15} aria-hidden="true" />} disabled={!resultsQuery.data?.page.next_cursor || resultsQuery.isFetching} onClick={nextResultPage} />
            <span className="jobs-page-size-label">{t('pagination.perPage', { count: subtaskPageSize })}</span>
            <span className="visually-hidden">{t('pagination.page', { page: formatNumber(resultPageIndex + 1, locale) })}</span>
          </div>
        </section>

        <h2 className="jobs-detail-records-title">{t('details.records')}</h2>
        <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
          <Descriptions.Item label={t('columns.id')} span="filled">{detail?.task_id ?? selectedTaskID ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.status')}>{detailStatus}</Descriptions.Item>
          <Descriptions.Item label={t('columns.kind')}>{detail?.kind ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.tenant')} span="filled">{detail?.tenant_id ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.resource')} span="filled">{detail?.related_resource.reference ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('details.requestID')}>{detail?.request_id ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('details.traceID')}>{detail?.trace_id ?? placeholder}</Descriptions.Item>
			<Descriptions.Item label={t('details.revision')} span="filled">{detail?.revision ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.createdAt')}>{detail ? formatDateTime(detail.created_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.startedAt')}>{detail?.started_at ? formatDateTime(detail.started_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('details.updatedAt')}>{detail ? formatDateTime(detail.updated_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('details.completedAt')}>{detail?.completed_at ? formatDateTime(detail.completed_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.attempt')}>{detail ? `${formatNumber(detail.attempt, locale)} / ${formatNumber(detail.max_attempts, locale)}` : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.failureCode')}>{failureText(detail?.failure_code, placeholder, t)}</Descriptions.Item>
        </Descriptions>

        <section className="jobs-detail-section" aria-labelledby="jobs-progress-title">
          <h2 id="jobs-progress-title">{t('details.progress')}</h2>
          <Progress
            percent={progressPercent}
            status={detail?.status === 'failed' || detail?.status === 'partial_failed' ? 'exception' : undefined}
          />
          <div className="jobs-progress-facts">
            {(['total', 'completed', 'succeeded', 'failed', 'cancelled', 'pending'] as const).map((key) => (
              <span key={key}>{t('progress.fact', {
                label: t(`progress.${key}`),
                value: detail ? formatNumber(detail.progress[key], locale) : placeholder,
              })}</span>
            ))}
          </div>
        </section>

        <section className="jobs-detail-section" aria-labelledby="jobs-attempts-title">
          <h2 id="jobs-attempts-title">{t('attempts.title')}</h2>
          <div className="identity-table-scroll">
            <Table<JobAttempt>
              rowKey="number"
              size="small"
              columns={attemptColumns}
              dataSource={attemptsQuery.data?.data ?? []}
              loading={attemptsQuery.isPending || attemptsQuery.isFetching}
              pagination={false}
              locale={{ emptyText: attemptsQuery.isPending ? ' ' : t('attempts.empty') }}
              scroll={{ x: 1100 }}
            />
          </div>
          <div className="jobs-child-pagination">
            <span>{t('pagination.page', { page: formatNumber(attemptPageIndex + 1, locale) })}</span>
            <Button aria-label={t('attempts.previous')} icon={<ChevronLeft size={15} aria-hidden="true" />} disabled={attemptPageIndex === 0 || attemptsQuery.isFetching} onClick={() => setAttemptPageIndex((current) => current - 1)} />
            <Button aria-label={t('attempts.next')} icon={<ChevronRight size={15} aria-hidden="true" />} disabled={!attemptsQuery.data?.page.next_cursor || attemptsQuery.isFetching} onClick={nextAttemptPage} />
          </div>
        </section>

        <section className="jobs-detail-section" aria-labelledby="jobs-receipts-title">
          <h2 id="jobs-receipts-title">{settlementT('receipts.title')}</h2>
          {receiptsQuery.isError ? (
            <Alert
              className="identity-alert"
              type="error"
              showIcon
              message={settlementT('receipts.loadFailed')}
              description={settlementErrorMessage(receiptsQuery.error, settlementT)}
              action={settlementRetryAllowed(receiptsQuery.error) ? (
                <Button size="small" onClick={() => void receiptsQuery.refetch()}>{t('actions.retry')}</Button>
              ) : undefined}
            />
          ) : null}
          <div
            className="identity-table-scroll"
            data-testid="job-receipts-table"
            aria-busy={receiptsQuery.isPending || receiptsQuery.isFetching}
          >
            <Table<JobSettlementReceipt>
              rowKey={(value) => `${value.attempt}-${value.ordinal}`}
              size="small"
              columns={receiptColumns}
              dataSource={receiptsQuery.data?.data ?? []}
              loading={receiptsQuery.isPending || receiptsQuery.isFetching}
              pagination={false}
              locale={{ emptyText: receiptsQuery.isPending ? ' ' : settlementT('receipts.empty') }}
              scroll={{ x: 1350 }}
            />
          </div>
          <div className="jobs-child-pagination">
            <span>{t('pagination.page', { page: formatNumber(receiptPageIndex + 1, locale) })}</span>
            <Button aria-label={settlementT('receipts.previous')} icon={<ChevronLeft size={15} aria-hidden="true" />} disabled={receiptPageIndex === 0 || receiptsQuery.isFetching} onClick={() => setReceiptPageIndex((current) => current - 1)} />
            <Button aria-label={settlementT('receipts.next')} icon={<ChevronRight size={15} aria-hidden="true" />} disabled={!receiptsQuery.data?.page.next_cursor || receiptsQuery.isFetching} onClick={nextReceiptPage} />
          </div>
        </section>

        <section className="jobs-detail-section" aria-labelledby="jobs-dead-letters-title">
          <h2 id="jobs-dead-letters-title">{settlementT('deadLetters.title')}</h2>
          {deadLettersQuery.isError ? (
            <Alert
              className="identity-alert"
              type="error"
              showIcon
              message={settlementT('deadLetters.loadFailed')}
              description={settlementErrorMessage(deadLettersQuery.error, settlementT)}
              action={settlementRetryAllowed(deadLettersQuery.error) ? (
                <Button size="small" onClick={() => void deadLettersQuery.refetch()}>{t('actions.retry')}</Button>
              ) : undefined}
            />
          ) : null}
          <div
            className="identity-table-scroll"
            data-testid="job-dead-letters-table"
            aria-busy={deadLettersQuery.isPending || deadLettersQuery.isFetching}
          >
            <Table<JobDeadLetter>
              rowKey={(value) => String(value.attempt)}
              size="small"
              columns={deadLetterColumns}
              dataSource={deadLettersQuery.data?.data ?? []}
              loading={deadLettersQuery.isPending || deadLettersQuery.isFetching}
              pagination={false}
              locale={{ emptyText: deadLettersQuery.isPending ? ' ' : settlementT('deadLetters.empty') }}
              scroll={{ x: 760 }}
            />
          </div>
          <div className="jobs-child-pagination">
            <span>{t('pagination.page', { page: formatNumber(deadLetterPageIndex + 1, locale) })}</span>
            <Button aria-label={settlementT('deadLetters.previous')} icon={<ChevronLeft size={15} aria-hidden="true" />} disabled={deadLetterPageIndex === 0 || deadLettersQuery.isFetching} onClick={() => setDeadLetterPageIndex((current) => current - 1)} />
            <Button aria-label={settlementT('deadLetters.next')} icon={<ChevronRight size={15} aria-hidden="true" />} disabled={!deadLettersQuery.data?.page.next_cursor || deadLettersQuery.isFetching} onClick={nextDeadLetterPage} />
          </div>
        </section>
      </Modal>
      <Modal
        className="jobs-subtask-result-modal"
        open={selectedItem !== null}
        title={t('subtasks.resultTitle')}
        onCancel={() => setSelectedItem(null)}
        footer={<Button onClick={() => setSelectedItem(null)}>{t('actions.close')}</Button>}
        destroyOnHidden
      >
        {selectedItem ? <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label={t('results.ordinal')}>{selectedItem.ordinal}</Descriptions.Item>
          <Descriptions.Item label={t('results.item')}>{itemText(selectedItem.item_id, t)}</Descriptions.Item>
          <Descriptions.Item label={t('results.node')}>{selectedItem.node_id ?? notRecorded}</Descriptions.Item>
          <Descriptions.Item label={t('columns.status')}><StateTag state={selectedItem.status} /></Descriptions.Item>
          <Descriptions.Item label={t('columns.attempt')}>{formatNumber(selectedItem.attempt, locale)}</Descriptions.Item>
          <Descriptions.Item label={t('results.sequence')}>{formatNumber(selectedItem.sequence, locale)}</Descriptions.Item>
          <Descriptions.Item label={t('columns.startedAt')}>{selectedItem.started_at ? formatDateTime(selectedItem.started_at, locale) : t('values.notStarted')}</Descriptions.Item>
          <Descriptions.Item label={t('results.completedAt')}>{selectedItem.completed_at ? formatDateTime(selectedItem.completed_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.failureCount')}>{selectedItem.failure_count === undefined ? notRecorded : formatNumber(selectedItem.failure_count, locale)}</Descriptions.Item>
          <Descriptions.Item label={t('columns.failureCode')}>{failureText(selectedItem.failure_code, placeholder, t)}</Descriptions.Item>
        </Descriptions> : null}
      </Modal>
      <Modal
        open={canManage && bulkCancelOpen}
        title={parityText.bulkCancelTitle}
        okText={t('actions.confirm')}
        cancelText={t('actions.close')}
        confirmLoading={bulkCancelMutation.isPending}
        okButtonProps={{ disabled: !canManage || selectedCancellableJobs.length === 0 }}
        onOk={confirmBulkCancel}
        onCancel={() => setBulkCancelOpen(false)}
        destroyOnHidden
      >
        <p>{parityText.bulkCancelDescription.replace('{{count}}', String(selectedCancellableJobs.length))}</p>
      </Modal>
      <Modal
        open={canManage && commandConfirmation !== null}
        title={commandConfirmation ? t(`confirm.${commandConfirmation.action}Title`) : undefined}
        okText={commandConfirmation ? t('actions.confirm') : undefined}
        cancelText={commandConfirmation ? t('actions.close') : undefined}
        okButtonProps={{ disabled: !canManage }}
        onOk={confirmCommand}
        onCancel={() => setCommandConfirmation(null)}
        destroyOnHidden
      >
        {commandConfirmation ? <p>{t(`confirm.${commandConfirmation.action}Description`)}</p> : null}
      </Modal>
    </section>
  )
}
