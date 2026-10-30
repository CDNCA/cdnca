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
  Spin,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { ChevronLeft, ChevronRight, Eye, RefreshCw, RotateCcw, X } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  cacheOperationsApi,
  type CacheCancelConfirmation,
  type CacheNodeProjection,
  type CacheOperationListParams,
  type CacheOperationPage,
  type CacheOperationScope,
  type CacheOperationState,
  type CacheOperationSummary,
  type CacheOperationTarget,
  type CacheTargetType,
} from '../api/cacheOperations'
import { useSessionStore } from '../auth/session'
import CacheOperationOutcome from '../components/CacheOperationOutcome'
import { cacheFailureText } from '../components/cacheFailureText'
import SiteCacheTabs from '../components/SiteCacheTabs'
import '../i18n/cacheOperations'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import './CacheOperationHistoryPage.css'
import { cacheWriteIdentity, cacheWriteOwner, pendingCacheWriteKey, rememberCacheWrite, sendCacheWrite, settleCacheWrite } from './cacheWriteJournal'
import { FeedbackWhen } from '@cdnca/ui'

const pageSize = 20
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
// 类型 as the competitor shows it: action and target scope in one choice,
// both sent as server filters.
const kinds = {
  purge_url: { action: 'purge', target_type: 'exact_url' },
  purge_directory: { action: 'purge', target_type: 'directory_prefix' },
  purge_site: { action: 'purge', target_type: 'whole_site' },
  prewarm: { action: 'prewarm', target_type: 'exact_url' },
} as const satisfies Record<string, Pick<CacheOperationListParams, 'action' | 'target_type'>>
type OperationKind = keyof typeof kinds
// Status pills: the list filters by any of a pill's states on the server and
// returns per-state counts over every page (first page).
type StatePill = 'all' | 'done' | 'failed' | 'processing'
const pillStates: Record<Exclude<StatePill, 'all'>, readonly CacheOperationState[]> = {
  done: ['succeeded'], failed: ['failed', 'partial_failed'], processing: ['queued', 'running'],
}

function operationKind(item: { action: CacheOperationSummary['action']; target_type: CacheTargetType }): OperationKind {
  if (item.action === 'prewarm') return 'prewarm'
  return item.target_type === 'whole_site' ? 'purge_site' : item.target_type === 'directory_prefix' ? 'purge_directory' : 'purge_url'
}

// Each task of a "re-submit" click has its own key; a task whose outcome is
// unknown keeps it (cacheWriteJournal), so the server replays instead of
// duplicating whichever button sends it again.
type Resubmission = { operationID: string; key: string }
type ResubmitOutcome = { done: number; failed: Array<Resubmission & { error: unknown }> }

type HistoryOwner = readonly ['tenant', string, string, string, number]

// CACHE-ADD-09b: a system follow-up (parent_operation_id) is folded under its
// parent's row when the parent is on the same page; otherwise it is its own
// row marked as a follow-up.
type HistoryRow = CacheOperationSummary & { children?: HistoryRow[] }

function foldFollowUps(items: readonly CacheOperationSummary[]): HistoryRow[] {
  const rows = new Map<string, HistoryRow>()
  for (const item of items) rows.set(item.id, { ...item })
  const result: HistoryRow[] = []
  for (const item of items) {
    const row = rows.get(item.id)!
    const parent = item.parent_operation_id ? rows.get(item.parent_operation_id) : undefined
    if (parent && !parent.parent_operation_id) {
      parent.children = [...(parent.children ?? []), row]
    } else {
      result.push(row)
    }
  }
  return result
}

const staleOwner = new ApiError('Cache operation history owner changed', 403, 'permission_denied')

function deniedError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403
}

function historyOwner(principal: Principal | null, sessionEpoch: number): HistoryOwner | null {
  if (!principal || principal.scope_kind !== 'tenant' || !sessionEpoch ||
    !principal.tenant_id || !uuidPattern.test(principal.scope_id) ||
    !uuidPattern.test(principal.user_id)) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function ownerCan(owner: HistoryOwner, permission: 'sites.read' | 'sites.manage'): boolean {
  const { accessToken, principal, sessionEpoch, status } = useSessionStore.getState()
  if (!accessToken || status !== 'authenticated' || !principal ||
    !principal.permissions.includes(permission)) return false
  const current = historyOwner(principal, sessionEpoch)
  return current !== null && current.every((value, index) => value === owner[index])
}

// 网络中断/超时/5xx：重试请求的结果未知，只能用同一请求重试（CACHE-ADD-05）。
function retryOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500 ||
    error.code === 'invalid_response'
}

function localizedError(error: unknown, t: TFunction<'cacheOperations'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const known = new Set([
    'authentication_required', 'invalid_request', 'validation_error', 'permission_denied',
    'not_found', 'idempotency_conflict', 'invalid_operation_transition', 'retries_exhausted',
    'request_cancelled', 'service_unavailable', 'network_error', 'invalid_response',
    'daily_limit_exceeded', 'no_carrying_node', 'entitlement_denied', 'target_node_unavailable',
  ])
  const message = known.has(error.code) ? t(`errors.${error.code}`) : t('errors.request_failed')
  return error.requestId ? t('errors.withRequestId', { message, requestId: error.requestId }) : message
}

function stateColor(state: CacheOperationState): string | undefined {
  if (state === 'running') return 'processing'
  if (state === 'succeeded') return 'success'
  if (state === 'partial_failed') return 'warning'
  if (state === 'failed') return 'error'
  return undefined
}

function StateTag({ state }: { state: CacheOperationState }) {
  const { t } = useTranslation('cacheOperations')
  return <Tag color={stateColor(state)}>{t(`states.${state}`)}</Tag>
}

function commandKey(prefix = 'cache-retry'): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `${prefix}-${suffix}`
}

function CacheOperationHistoryOwned({
  accessToken,
  owner,
}: {
  accessToken: string
  owner: HistoryOwner
}) {
  const { t, i18n } = useTranslation('cacheOperations')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const tokenRef = useRef(accessToken)
  tokenRef.current = accessToken
  const ownerRef = useRef(owner)
  ownerRef.current = owner
  const [searchDraft, setSearchDraft] = useState('')
  const [filters, setFilters] = useState<CacheOperationListParams>({})
  const [kind, setKind] = useState<OperationKind>()
  const [pill, setPill] = useState<StatePill>('all')
  const [selectedIDs, setSelectedIDs] = useState<string[]>([])
  const [resubmitting, setResubmitting] = useState(false)
  const [resubmitOutcome, setResubmitOutcome] = useState<ResubmitOutcome | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageCursors, setPageCursors] = useState<Array<string | undefined>>([undefined])
  const [selectedOperationID, setSelectedOperationID] = useState<string | null>(null)
  const [retryError, setRetryError] = useState<unknown>(null)
  const [retryAttempt, setRetryAttempt] = useState<{ operationID: string; key: string } | null>(null)
  // CACHEFLOW-U01: a 403 read ends the history for this session (detail,
  // selection, polling, writes); a 403 write ends every write. Only a new
  // session or principal (a remount through the owner key) lifts it, never a
  // refresh click.
  const [readDenied, setReadDenied] = useState(false)
  const [writeDenied, setWriteDenied] = useState(false)
  const deniedRef = useRef({ read: false, write: false })
  const denyRead = () => {
    deniedRef.current = { read: true, write: true }
    setReadDenied(true)
    setWriteDenied(true)
    setSelectedOperationID(null)
    setSelectedIDs([])
  }
  const denyWrites = () => {
    deniedRef.current = { ...deniedRef.current, write: true }
    setWriteDenied(true)
  }
  const canRead = () => !deniedRef.current.read && ownerCan(ownerRef.current, 'sites.read')
  const canWrite = () => !deniedRef.current.write && ownerCan(ownerRef.current, 'sites.manage')
  const cursor = pageCursors[pageIndex]
  const scope: CacheOperationScope = { kind: 'tenant' }
  const [ownerKind, ownerScopeID, ownerTenantID, ownerUserID, ownerEpoch] = owner
  // CACHE-ADD-05: unknown writes keep their key across rows, the detail,
  // leaving and reloading (shared with the purge page).
  const journalOwner = cacheWriteOwner(ownerScopeID, ownerUserID, JSON.stringify(scope))
  const journalKey = (action: 'retry' | 'resubmit', operationID: string, prefix: string) =>
    pendingCacheWriteKey(journalOwner, cacheWriteIdentity(action, operationID)) ?? commandKey(prefix)
  // fix-cacheflow5: a key with an unknown outcome is looked up on the server before it is sent again.
  const sendJournaled = (action: 'retry' | 'resubmit', operationID: string, key: string) => sendCacheWrite(
    () => tokenRef.current, scope, { action, operationID, key },
    pendingCacheWriteKey(journalOwner, cacheWriteIdentity(action, operationID)) === key,
    () => cacheOperationsApi[action](tokenRef.current, scope, operationID, key), retryOutcomeUnknown,
  )
  const journal = (action: 'retry' | 'resubmit', operationID: string, key: string, error?: unknown) => {
    const identity = cacheWriteIdentity(action, operationID)
    if (error !== undefined && retryOutcomeUnknown(error)) rememberCacheWrite(journalOwner, identity, key)
    else settleCacheWrite(journalOwner, identity, key)
  }
  const queryPrefix = useMemo(
    () => ['cache-operation-history', [ownerKind, ownerScopeID, ownerTenantID, ownerUserID, ownerEpoch]] as const,
    [ownerKind, ownerScopeID, ownerTenantID, ownerUserID, ownerEpoch],
  )

  const listParams = useMemo<CacheOperationListParams>(() => ({
    ...filters,
    states: pill === 'all' ? undefined : [...pillStates[pill]],
    limit: pageSize,
    cursor,
  }), [cursor, filters, pill])

  const listQuery = useQuery({
    queryKey: [...queryPrefix, 'list', listParams],
    queryFn: async () => {
      try {
        if (!canRead()) throw staleOwner
        const result = await cacheOperationsApi.list(tokenRef.current, scope, listParams)
        if (!canRead()) throw staleOwner
        return result
      } catch (error) {
        if (deniedError(error)) denyRead()
        throw error
      }
    },
    enabled: !readDenied,
    retry: false,
    refetchInterval: (query) => canRead() && query.state.data?.items.some(
      (item) => item.state === 'queued' || item.state === 'running',
    ) ? 3_000 : false,
    refetchOnWindowFocus: canRead,
    refetchOnReconnect: canRead,
  })

  const detailQuery = useQuery({
    queryKey: [...queryPrefix, 'detail', selectedOperationID],
    queryFn: async () => {
      try {
        if (!selectedOperationID || !canRead()) throw staleOwner
        const result = await cacheOperationsApi.get(tokenRef.current, scope, selectedOperationID)
        if (!canRead()) throw staleOwner
        return result
      } catch (error) {
        if (deniedError(error)) denyRead()
        throw error
      }
    },
    enabled: selectedOperationID !== null && !readDenied,
    retry: false,
    refetchInterval: (query) => {
      const state = query.state.data?.state
      return canRead() && (state === 'queued' || state === 'running') ? 3_000 : false
    },
    refetchOnWindowFocus: canRead,
    refetchOnReconnect: canRead,
  })

  const retryMutation = useMutation({
    mutationFn: async ({ operationID, key }: { operationID: string; key: string }) => {
      if (!canWrite()) throw staleOwner
      return sendJournaled('retry', operationID, key)
    },
    onSuccess: async (_result, attempt) => {
      journal('retry', attempt.operationID, attempt.key)
      setRetryError(null)
      setRetryAttempt(null)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [...queryPrefix, 'list'] }),
        queryClient.invalidateQueries({ queryKey: [...queryPrefix, 'detail'] }),
      ])
    },
    onError: (error, attempt) => {
      if (error === staleOwner) return
      journal('retry', attempt.operationID, attempt.key, error)
      if (deniedError(error)) denyWrites()
      setRetryError(error)
      setRetryAttempt(attempt)
    },
  })

  useEffect(() => () => {
    queryClient.removeQueries({ queryKey: queryPrefix })
  }, [queryClient, queryPrefix])

  const applyFilters = (patch: CacheOperationListParams) => {
    setFilters((current) => ({ ...current, ...patch, cursor: undefined }))
    setPageIndex(0)
    setPageCursors([undefined])
    setSelectedOperationID(null)
    setSelectedIDs([])
  }
  const changeKind = (value?: OperationKind) => {
    setKind(value)
    applyFilters(value ? kinds[value] : { action: undefined, target_type: undefined })
  }
  const applySearch = (value: string) => {
    // The server caps search at 128 bytes of trimmed text.
    applyFilters({ search: value.trim().slice(0, 128) || undefined })
  }

  const nextPage = () => {
    const next = listQuery.data?.next_cursor
    if (!next || pageCursors.includes(next)) return
    setPageCursors((current) => [...current.slice(0, pageIndex + 1), next])
    setPageIndex((current) => current + 1)
    setSelectedOperationID(null)
  }

  const previousPage = () => {
    if (pageIndex === 0) return
    setPageIndex((current) => current - 1)
    setSelectedOperationID(null)
  }

  // The server recreates each task with its site, type, targets, retry budget and
  // nodes; per-task outcomes are reported, and a retry reuses the batch key.
  const resubmit = async (attempts: Resubmission[]) => {
    if (!canWrite() || resubmitting || attempts.length === 0) return
    setResubmitting(true)
    setResubmitOutcome(null)
    const outcome: ResubmitOutcome = { done: 0, failed: [] }
    for (const attempt of attempts) {
      try {
        if (!canWrite()) throw staleOwner
        await sendJournaled('resubmit', attempt.operationID, attempt.key)
        journal('resubmit', attempt.operationID, attempt.key)
        outcome.done += 1
      } catch (error) {
        if (error === staleOwner) break
        journal('resubmit', attempt.operationID, attempt.key, error)
        outcome.failed.push({ ...attempt, error })
        if (deniedError(error)) { denyWrites(); break }
      }
    }
    setResubmitting(false)
    setResubmitOutcome(outcome)
    setSelectedIDs(outcome.failed.map((item) => item.operationID))
    await queryClient.invalidateQueries({ queryKey: [...queryPrefix, 'list'] })
  }

  const items = useMemo(() => listQuery.data?.items ?? [], [listQuery.data?.items])
  const rows = useMemo(() => foldFollowUps(items), [items])
  // Counts come with the first page; later pages keep the first page's.
  const stateCounts = queryClient.getQueryData<CacheOperationPage>([...queryPrefix, 'list', { ...listParams, cursor: undefined }])?.state_counts ??
    listQuery.data?.state_counts
  const pillCounts = useMemo(() => {
    const count = (states: readonly CacheOperationState[]) => states.reduce((sum, state) => sum + (stateCounts?.[state] ?? 0), 0)
    return {
      all: count(['queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled']),
      done: count(pillStates.done), failed: count(pillStates.failed), processing: count(pillStates.processing),
    }
  }, [stateCounts])

  // 上一次重试结果未知时，只允许用同一请求重试，不生成新请求覆盖它。
  const retryUnknown = Boolean(retryAttempt && retryError && retryOutcomeUnknown(retryError))
  const retry = (operationID: string, key = journalKey('retry', operationID, 'cache-retry')) => {
    if (!canWrite() || retryMutation.isPending) return
    if (retryUnknown && (operationID !== retryAttempt!.operationID || key !== retryAttempt!.key)) return
    setRetryError(null)
    setRetryAttempt({ operationID, key })
    retryMutation.mutate({ operationID, key })
  }

  const terminal = (state: CacheOperationState) => !pillStates.processing.includes(state)

  const operationColumns: TableColumnsType<HistoryRow> = [
    {
      title: t('history.table.id'), dataIndex: 'display_id', key: 'id', width: 150,
      render: (value: string, item) => (
        <Space size={4}>
          <span title={item.id}>{value}</span>
          {item.parent_operation_id ? <Tag className="cache-operation-history-follow-up" title={t('history.followUpHint')}>{t('history.followUp')}</Tag> : null}
          {item.children?.length ? <small>{t('history.followUpCount', { count: item.children.length })}</small> : null}
        </Space>
      ),
    },
    {
      title: t('history.table.type'), key: 'type', width: 100,
      render: (_value, item) => t(`history.kinds.${operationKind(item)}`),
    },
    {
      title: t('history.table.target'), key: 'target', width: 300, ellipsis: true,
      render: (_value, item) => {
        if (item.target_type === 'whole_site') return <span>{t('history.wholeSite', { site: item.site_display_id })}</span>
        const first = item.first_target.display_url
        return (
          <span className="cache-operation-history-url" title={first}>
            <code>{first}</code>
            {item.target_count > 1 ? <small>{t('history.moreTargets', { count: item.target_count - 1 })}</small> : null}
          </span>
        )
      },
    },
    {
      title: t('history.table.state'), dataIndex: 'state', key: 'state', width: 100,
      render: (value: CacheOperationState) => <StateTag state={value} />,
    },
    {
      title: t('history.table.createdAt'), dataIndex: 'created_at', key: 'created_at', width: 170,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('history.table.actions'), key: 'actions', width: 300, fixed: 'right',
      render: (_value, item) => (
        <Space size={4} wrap>
          <Button
            type="link"
            size="small"
            icon={<Eye size={14} aria-hidden="true" />}
            onClick={() => setSelectedOperationID(item.id)}
          >
            {t('actions.details')}
          </Button>
          <Button
            type="link"
            size="small"
            icon={<RefreshCw size={14} aria-hidden="true" />}
            disabled={!terminal(item.state) || writeDenied || !ownerCan(owner, 'sites.manage') || resubmitting}
            onClick={() => void resubmit([{ operationID: item.id, key: journalKey('resubmit', item.id, 'cache-resubmit') }])}
          >
            {t('history.resubmit')}
          </Button>
          {item.state === 'failed' || item.state === 'partial_failed' ? (
            <Button
              type="link"
              size="small"
              icon={<RotateCcw size={14} aria-hidden="true" />}
              disabled={writeDenied || !ownerCan(owner, 'sites.manage') || retryMutation.isPending || retryUnknown}
              onClick={() => retry(item.id)}
            >
              {t('history.retryFailed')}
            </Button>
          ) : null}
        </Space>
      ),
    },
  ]

  const nodeColumns: TableColumnsType<CacheNodeProjection> = [
    {
      title: t('detail.node'), dataIndex: 'node_display_id', width: 120, ellipsis: true,
      render: (value: string, node) => <span title={node.node_id}>{value}</span>,
    },
    { title: t('history.table.state'), dataIndex: 'state', width: 130, render: (value: CacheOperationState) => <StateTag state={value} /> },
    { title: t('detail.attempt'), dataIndex: 'attempt', width: 90 },
    {
      title: t('columns.progress'), dataIndex: 'progress', width: 120,
      render: (value: CacheNodeProjection['progress']) => `${formatNumber(value.completed, locale)} / ${formatNumber(value.total, locale)}`,
    },
    { title: t('detail.failure'), dataIndex: 'last_error_code', width: 250, render: (value?: string) => cacheFailureText(value, t) },
    // CACHE-ADD-07: shown once the task was cancelled while a node ran it.
    ...(detailQuery.data?.nodes.some((node) => node.cancel_confirmation) ? [{
      title: t('detail.cancelConfirmation'), dataIndex: 'cancel_confirmation', width: 220,
      render: (value?: CacheCancelConfirmation) => value ? t(`detail.cancelConfirmations.${value}`) : t('values.placeholder'),
    }] : []),
  ]

  const targetColumns: TableColumnsType<CacheOperationTarget> = [
    { title: t('detail.ordinal'), dataIndex: 'ordinal', width: 80 },
    { title: t('history.table.target'), dataIndex: 'display_url', width: 420, render: (value: string) => <code>{value}</code> },
    { title: t('detail.canonicalPath'), dataIndex: 'canonical_path', width: 280, render: (value: string) => <code>{value}</code> },
    { title: t('detail.queryRedacted'), dataIndex: 'query_redacted', width: 150, render: (value: boolean) => <Tag color={value ? 'warning' : undefined}>{value ? t('values.yes') : t('values.no')}</Tag> },
  ]

  const detail = detailQuery.data
  const listError = listQuery.error
  const forbidden = readDenied || deniedError(listError)
  // CACHEFLOW-U02: a failed read is not an empty history. Without a good
  // result there are no rows, counts or page; with one, it stays and is
  // marked as the last result.
  const listFailed = !forbidden && listQuery.isError && !listQuery.isFetching
  const hasList = listQuery.data !== undefined

  return (
    <div className="identity-page cache-operation-history-page" style={{ minWidth: 0, maxWidth: '100%' }}>
      <SiteCacheTabs
        active="history"
        extra={(
          <div className="cache-operation-history-toolbar">
            <Button
              icon={<RefreshCw size={15} aria-hidden="true" />}
              disabled={selectedIDs.length === 0 || writeDenied || !ownerCan(owner, 'sites.manage') || resubmitting}
              loading={resubmitting}
              onClick={() => void resubmit(selectedIDs.map((operationID) => ({ operationID, key: journalKey('resubmit', operationID, 'cache-resubmit') })))}
            >
              {t('history.resubmitSelected')}
            </Button>
            <div className="cache-operation-history-filters">
              <Select<OperationKind>
                aria-label={t('history.kindFilter')}
                allowClear
                placeholder={t('history.allKinds')}
                options={(Object.keys(kinds) as OperationKind[]).map((value) => ({ value, label: t(`history.kinds.${value}`) }))}
                value={kind}
                onChange={changeKind}
              />
              <Input.Search
                allowClear
                aria-label={t('history.filter')}
                value={searchDraft}
                maxLength={128}
                placeholder={t('history.filterPlaceholder')}
                onChange={(event) => { setSearchDraft(event.target.value); if (!event.target.value) applySearch('') }}
                onSearch={applySearch}
              />
              <Button
                aria-label={t('actions.refresh')}
                icon={<RefreshCw size={15} aria-hidden="true" />}
                disabled={readDenied || listQuery.isFetching}
                onClick={() => { if (canRead()) void listQuery.refetch() }}
              />
            </div>
          </div>
        )}
      />
      <h1 className="sr-only">{t('history.title')}</h1>

      {!forbidden ? <div className="cache-operation-history-pills" aria-label={t('history.pills.label')}>
        <div>
          {(['all', 'done', 'failed', 'processing'] as const).map((key) => (
            <button key={key} type="button" className={`is-${key}${pill === key ? ' is-active' : ''}`} aria-pressed={pill === key}
              onClick={() => {
                setPill(key)
                setPageIndex(0)
                setPageCursors([undefined])
                setSelectedOperationID(null)
                setSelectedIDs([])
              }}>
              <span>{t(`history.pills.${key}`)}</span>{stateCounts ? <strong>{formatNumber(pillCounts[key], locale)}</strong> : null}
            </button>
          ))}
        </div>
      </div> : null}

      {resubmitOutcome ? (
        <Alert
          type={resubmitOutcome.failed.length ? 'warning' : 'success'}
          showIcon
          closable
          onClose={() => setResubmitOutcome(null)}
          message={t('history.resubmitOutcome', { done: resubmitOutcome.done, failed: resubmitOutcome.failed.length })}
          description={resubmitOutcome.failed.length ? (
            <Space direction="vertical" size={2}>
              {resubmitOutcome.failed.map((item) => (
                <span key={item.operationID}>
                  {items.find((row) => row.id === item.operationID)?.display_id ?? item.operationID}：{localizedError(item.error, t)}
                </span>
              ))}
              {/* An uncertain re-submit is retried with its batch key, never a fresh one. */}
              <Button size="small" disabled={resubmitting || writeDenied} onClick={() => void resubmit(resubmitOutcome.failed.map(({ operationID, key }) => ({ operationID, key })))}>
                {t('actions.retrySameRequest')}
              </Button>
            </Space>
          ) : undefined}
        />
      ) : null}
      {retryError ? <FeedbackWhen title={localizedError(retryError, t)} action={retryAttempt && !writeDenied ? <Button size="small" onClick={() => retry(retryAttempt.operationID, retryAttempt.key)}>{t('actions.retrySameRequest')}</Button> : undefined} /> : null}

      {forbidden ? (
        <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
      ) : null}
      {listFailed ? (
        <FeedbackWhen title={localizedError(listError, t)} action={<Button onClick={() => { if (canRead()) void listQuery.refetch() }}>{t('actions.retry')}</Button>} />
      ) : null}
      {!forbidden ? (
        <section className="cache-operation-history-table" aria-busy={listQuery.isFetching} aria-label={t('history.title')}>
          {listFailed ? (
            <Alert
              type={hasList ? 'warning' : 'error'}
              showIcon
              message={hasList ? t('history.staleResult') : t('history.loadFailed')}
              action={<Button size="small" onClick={() => { if (canRead()) void listQuery.refetch() }}>{t('actions.retry')}</Button>}
            />
          ) : null}
          {hasList || !listFailed ? <Table
            rowKey="id"
            size="small"
            loading={listQuery.isPending || listQuery.isFetching}
            columns={operationColumns}
            dataSource={rows}
            expandable={{ childrenColumnName: 'children', indentSize: 16 }}
            pagination={false}
            locale={{ emptyText: hasList ? t('history.empty') : ' ' }}
            rowSelection={{
              selectedRowKeys: selectedIDs,
              onChange: (keys) => setSelectedIDs(keys.map(String)),
              getCheckboxProps: (item) => ({ disabled: !terminal(item.state), 'aria-label': item.display_id }),
            }}
            scroll={{ x: 1092 }}
          /> : null}
          {hasList ? <div className="cache-operation-history-pagination" aria-label={t('pagination.label')}>
            <Button icon={<ChevronLeft size={15} aria-hidden="true" />} disabled={pageIndex === 0 || listQuery.isFetching} onClick={previousPage}>{t('actions.previous')}</Button>
            <span>{t('pagination.page', { page: formatNumber(pageIndex + 1, locale) })}</span>
            <Button icon={<ChevronRight size={15} aria-hidden="true" />} disabled={!listQuery.data?.next_cursor || listQuery.isFetching} onClick={nextPage}>{t('actions.next')}</Button>
          </div> : null}
        </section>
      ) : null}

      <Drawer
        className="cache-operation-history-drawer"
        open={selectedOperationID !== null && !readDenied}
        width={Math.min(920, typeof window === 'undefined' ? 920 : window.innerWidth - 24)}
        title={t('history.detailTitle')}
        extra={<Button icon={<X size={15} aria-hidden="true" />} onClick={() => setSelectedOperationID(null)}>{t('actions.close')}</Button>}
        onClose={() => setSelectedOperationID(null)}
      >
        {detailQuery.isPending ? <div className="data-state" aria-label={t('history.loading')} aria-busy="true"><Spin size="small" /></div> : null}
        {detailQuery.isError ? <Alert type="error" showIcon message={localizedError(detailQuery.error, t)} action={<Button onClick={() => void detailQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
        {detail ? (
          <div className="cache-operation-history-detail">
            <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
              <Descriptions.Item label={t('columns.id')}><code title={detail.id}>{detail.display_id}</code></Descriptions.Item>
              <Descriptions.Item label={t('columns.site')}><code title={detail.site_id}>{detail.site_display_id}</code></Descriptions.Item>
              <Descriptions.Item label={t('columns.nodes')}>{formatNumber(detail.nodes.length, locale)}</Descriptions.Item>
              <Descriptions.Item label={t('history.table.type')}>{t(`actions.values.${detail.action}`)}</Descriptions.Item>
              <Descriptions.Item label={t('filters.targetType')}>{t(`targetTypes.${detail.target_type}`)}</Descriptions.Item>
              <Descriptions.Item label={t('history.table.state')}><StateTag state={detail.state} /></Descriptions.Item>
              <Descriptions.Item label={t('detail.maxAttempts')}>{formatNumber(detail.max_attempts, locale)}</Descriptions.Item>
              <Descriptions.Item label={t('history.table.createdAt')}>{formatDateTime(detail.created_at, locale)}</Descriptions.Item>
              <Descriptions.Item label={t('detail.updatedAt')}>{formatDateTime(detail.updated_at, locale)}</Descriptions.Item>
            </Descriptions>
            <section>
              <h2>{t('detail.progress')}</h2>
              <CacheOperationOutcome operation={detail} />
            </section>
            <section>
              <h2>{t('detail.targets')}</h2>
              <Table rowKey="ordinal" size="small" columns={targetColumns} dataSource={detail.targets} pagination={false} scroll={{ x: 850 }} />
            </section>
            <section>
              <h2>{t('detail.nodes')}</h2>
              <Table rowKey="node_id" size="small" columns={nodeColumns} dataSource={detail.nodes} pagination={false} scroll={{ x: 850 }} />
            </section>
            {detail.state === 'succeeded' ? <Alert type="info" showIcon message={t('history.retryCompleted')} /> : null}
            {detail.state === 'failed' || detail.state === 'partial_failed' ? (
              <Button
                type="primary"
                icon={<RotateCcw size={15} aria-hidden="true" />}
                disabled={writeDenied || !ownerCan(owner, 'sites.manage') || retryMutation.isPending || retryUnknown}
                onClick={() => retry(detail.id)}
              >
                {t('history.retryFailed')}
              </Button>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}

export default function CacheOperationHistoryPage() {
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const status = useSessionStore((state) => state.status)
  const { t } = useTranslation('cacheOperations')
  const owner = historyOwner(principal, sessionEpoch)
  if (status !== 'authenticated' || !accessToken || !owner || !principal?.permissions.includes('sites.read')) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }
  return <CacheOperationHistoryOwned key={JSON.stringify(owner)} accessToken={accessToken} owner={owner} />
}
