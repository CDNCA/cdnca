import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Input,
  Popconfirm,
  Progress,
  Result,
  Select,
  Space,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import {
  Ban,
  ChevronLeft,
  ChevronRight,
  Eye,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  cacheOperationsApi,
  type CacheCancelConfirmation,
  type CacheNodeProjection,
  type CacheOperation,
  type CacheOperationAction,
  type CacheOperationListParams,
  type CacheOperationScope,
  type CacheWriteRef,
  type CacheOperationState,
  type CacheOperationSummary,
  type CacheOperationTarget,
  type CacheTargetType,
  type CacheTargetSiteGroup,
  type CacheTargetSites,
  type CacheTargetSiteScope,
  type CacheUnmatchedReason,
  type CreateCacheOperationInput,
} from '../api/cacheOperations'
import { nodesApi } from '../api/nodes'
import { sitesApi, type SiteListItem } from '../api/sites'
import { useSessionStore } from '../auth/session'
import CacheOperationOutcome from '../components/CacheOperationOutcome'
import { cacheFailureText } from '../components/cacheFailureText'
import SiteCacheTabs from '../components/SiteCacheTabs'
import TenantScopeSelect, { canonicalScopeUUIDPattern } from '../components/TenantScopeSelect'
import '../i18n/cacheOperations'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import './CacheOperationsPage.css'
import { cacheWriteIdentity, cacheWriteOwner, pendingCacheWriteKey, rememberCacheWrite, sendCacheWrite, settleCacheWrite } from './cacheWriteJournal'

const pageSize = 20
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const operationStates: CacheOperationState[] = [
  'queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled',
]
const operationActions: CacheOperationAction[] = ['purge', 'prewarm']
const targetTypes: CacheTargetType[] = ['exact_url', 'directory_prefix', 'whole_site']
const textEncoder = new TextEncoder()

interface FilterValues {
  site_id?: string
  action?: CacheOperationAction
  target_type?: CacheTargetType
  state?: CacheOperationState
}

// 主区直接提交，没有创建弹窗。URL/目录按每条
// URL 的域名由服务端匹配网站（一批可跨多个网站，每站一个任务）；整站刷新按域名选网站。
type MainMode = 'url' | 'directory' | 'prewarm' | 'site'

const mainModes: MainMode[] = ['url', 'directory', 'prewarm', 'site']

function modeRequest(mode: MainMode): { action: CacheOperationAction; targetType: CacheTargetType } {
  if (mode === 'prewarm') return { action: 'prewarm', targetType: 'exact_url' }
  if (mode === 'directory') return { action: 'purge', targetType: 'directory_prefix' }
  if (mode === 'site') return { action: 'purge', targetType: 'whole_site' }
  return { action: 'purge', targetType: 'exact_url' }
}

type CacheSessionOwner = readonly [string, string, string | null, string, number]

// Creates go through the per-site submission (runGroups); this mutation
// carries the record list's retry and cancel.
type WriteRequest = { kind: 'retry' | 'cancel'; operationID: string; key: string }

type WriteAttempt = WriteRequest & {
  owner: CacheSessionOwner
  ownerKey: string
  scope: CacheOperationScope
  scopeKey: string
  /** An earlier attempt with this key has an unknown outcome: read its receipt first. */
  recorded?: boolean
}

interface UnknownWrite {
  attempt: WriteAttempt
  error: unknown
}

const staleWriteAttempt = new Error('Cache operation session changed')

// CACHE-ADD-05: a write is the same write (same key) wherever it is sent from
// while its outcome is unknown, also after leaving or reloading the page.
function journalOwner(owner: CacheSessionOwner, scope: CacheOperationScope): string {
  return cacheWriteOwner(owner[1], owner[3], JSON.stringify(scope))
}

function writeIdentity(request: WriteRequest): string {
  return cacheWriteIdentity(request.kind, request.operationID)
}

function writeRef(request: WriteRequest): CacheWriteRef {
  return { action: request.kind, operationID: request.operationID, key: request.key }
}

function journalWrite(attempt: WriteAttempt, error?: unknown) {
  const owner = journalOwner(attempt.owner, attempt.scope)
  if (error !== undefined && unknownOutcome(error)) rememberCacheWrite(owner, writeIdentity(attempt), attempt.key)
  else settleCacheWrite(owner, writeIdentity(attempt), attempt.key)
}

function cacheSessionOwner(
  scopeKind: string | undefined,
  scopeID: string | undefined,
  tenantID: string | null | undefined,
  userID: string | undefined,
  sessionEpoch: number,
): CacheSessionOwner | null {
  if (!scopeID || !userID || !sessionEpoch) return null
  if (scopeKind === 'tenant' && tenantID) return [scopeKind, scopeID, tenantID, userID, sessionEpoch]
  if (scopeKind === 'platform') return [scopeKind, scopeID, tenantID ?? null, userID, sessionEpoch]
  return null
}

function currentCacheSessionCan(ownerKey: string, permission: 'sites.read' | 'sites.manage'): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  const owner = cacheSessionOwner(
    principal?.scope_kind,
    principal?.scope_id,
    principal?.tenant_id,
    principal?.user_id,
    sessionEpoch,
  )
  if (!accessToken || !principal || !owner || JSON.stringify(owner) !== ownerKey) return false
  return principal.permissions.includes(permission) || (
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  )
}

// OwnSiteSelect picks a site by domain (searchable, first 50): the whole-site
// purge of the main area (a tenant's own sites, an administrator's all sites).
function OwnSiteSelect({
  ownerKey,
  queryOwner,
  accessToken,
  value,
  onChange,
  id,
  ariaLabel,
  className,
}: {
  ownerKey: string
  queryOwner: CacheSessionOwner
  accessToken: () => string
  value?: string | null
  onChange?: (value: string | undefined, site: SiteListItem | undefined) => void
  id?: string
  ariaLabel?: string
  className?: string
}) {
  const { t } = useTranslation('cacheOperations')
  const [siteSearch, setSiteSearch] = useState('')
  const [opened, setOpened] = useState(false)
  const sites = useQuery({
    queryKey: ['cache-operation-sites', queryOwner, siteSearch],
    queryFn: () => sitesApi.list(accessToken(), { page: 1, limit: 50, ...(siteSearch ? { domain: siteSearch } : {}) }),
    enabled: opened && currentCacheSessionCan(ownerKey, 'sites.read'),
    retry: false,
  })
  return (
    <Select
      id={id}
      aria-label={ariaLabel}
      className={className}
      showSearch
      allowClear
      filterOption={false}
      placeholder={t('baseline.sitePlaceholder')}
      value={value || undefined}
      loading={sites.isFetching}
      onDropdownVisibleChange={(open) => { if (open) setOpened(true) }}
      onSearch={(search) => setSiteSearch(search.trim().toLowerCase())}
      onChange={(next?: string) => onChange?.(next, sites.data?.items.find((site) => site.id === next))}
      notFoundContent={sites.isError ? t('baseline.sitesFailed') : t('baseline.sitesEmpty')}
      options={(sites.data?.items ?? []).map((item) => ({ value: item.id, label: item.domain }))}
    />
  )
}

function groupInput(
  group: { site: { id: string }; targets: string[] },
  action: CacheOperationAction,
  targetType: CacheTargetType,
  nodeIDs: string[],
  maxRetries: number,
): CreateCacheOperationInput {
  return { site_id: group.site.id, action, target_type: targetType, targets: group.targets, node_ids: nodeIDs, max_retries: maxRetries }
}

function groupIdentity(
  group: { site: { id: string }; targets: string[] },
  action: CacheOperationAction,
  targetType: CacheTargetType,
  nodeIDs: string[],
  maxRetries: number,
): string {
  return cacheWriteIdentity('create', groupInput(group, action, targetType, nodeIDs, maxRetries))
}

function scopeIdentity(scope: CacheOperationScope): string {
  return JSON.stringify(scope)
}

function commandKey(kind: WriteRequest['kind'] | 'create'): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `cache-${kind}-${suffix}`
}

// One task's targets: 500 URLs or directories, 256 KiB in total.
const maxTargets = 500
const maxTargetBytes = 256 << 10

function splitLines(value: string): string[] {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
}

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

// 刷新可填通配主机（http(s)://*.example.com/...），清除本站
// 该后缀下所有域名的缓存；预热只抓具体主机，第一步拒绝通配。只认开头一个 "*." 标签。
function wildcardTarget(raw: string): boolean {
  return /^https?:\/\/[^/]*\*/i.test(raw.trim())
}

// Why one line cannot be sent (错误条逐行标出), or null.
type LineIssue = 'scheme' | 'invalid' | 'directory' | 'wildcardPrewarm' | 'wildcard' | 'duplicate' | 'tooLong'

function lineIssue(raw: string, targetType: CacheTargetType, action: CacheOperationAction): LineIssue | null {
  if (!/^https?:\/\//i.test(raw)) return 'scheme'
  if (textEncoder.encode(raw).byteLength > 16_384) return 'tooLong'
  if (raw.includes('\\')) return 'invalid'
  const leadingWildcard = /^(https?:\/\/)\*\.(?=[^/*]+\.[^/*]+)/i
  if (wildcardTarget(raw)) {
    if (action === 'prewarm') return 'wildcardPrewarm'
    if (!leadingWildcard.test(raw) || wildcardTarget(raw.replace(leadingWildcard, '$1'))) return 'wildcard'
  }
  try {
    const parsed = new URL(raw.replace(leadingWildcard, '$1wildcard.'))
    if (parsed.username || parsed.password || parsed.hash) return 'invalid'
    if (targetType === 'directory_prefix' && (parsed.search || !parsed.pathname.endsWith('/'))) return 'directory'
    return null
  } catch {
    return 'invalid'
  }
}

function validTarget(raw: string, targetType: CacheTargetType, action: CacheOperationAction): boolean {
  return raw === raw.trim() && lineIssue(raw, targetType, action) === null
}

interface LineError { line: number; target: string; reason: string }

// Every line's local problem (1-based line numbers of the non-blank lines),
// plus the list-wide limits as one entry each.
function localLineErrors(
  lines: readonly string[],
  targetType: CacheTargetType,
  action: CacheOperationAction,
  t: TFunction<'cacheOperations'>,
): { errors: LineError[]; listErrors: string[] } {
  const seen = new Set<string>()
  const errors: LineError[] = []
  lines.forEach((target, index) => {
    const issue = seen.has(target) ? 'duplicate' : lineIssue(target, targetType, action)
    seen.add(target)
    if (issue) errors.push({ line: index + 1, target, reason: t(`lineIssues.${issue}`) })
  })
  const listErrors: string[] = []
  if (lines.length > maxTargets) listErrors.push(t('lineIssues.tooMany', { max: maxTargets }))
  if (lines.reduce((total, item) => total + textEncoder.encode(item).byteLength, 0) > maxTargetBytes) {
    listErrors.push(t('lineIssues.tooLarge'))
  }
  return { errors, listErrors }
}

// 服务端按 URL 主机名匹配网站（主域名、别名、通配；租户只匹配本人网站，
// 管理员匹配全部租户），每个网站一个任务。scope 是该网站所在作用域（管理员按网站拆到各租户）。
interface GroupSite { id: string; domain: string; scope: CacheOperationScope }
type GroupStatus = 'pending' | 'running' | 'accepted' | 'failed' | 'unknown'
interface GroupTask {
  site: GroupSite
  targets: string[]
  key: string
  status: GroupStatus
  operationID?: string
  error?: unknown
}
interface GroupPreview {
  action: CacheOperationAction
  targetType: CacheTargetType
  nodeIDs: string[]
  maxRetries: number
  fromMain: boolean
  groups: GroupTask[]
  unmatched: Array<{ target: string; reason: CacheUnmatchedReason }>
}

function groupScope(group: CacheTargetSiteGroup, isAdmin: boolean): CacheOperationScope {
  return isAdmin ? { kind: 'admin', scopeId: group.scope_id } : { kind: 'tenant' }
}

// Ordinals in the resolution are 1-based positions of the lines sent.
function groupPreviewFrom(
  lines: readonly string[],
  resolution: CacheTargetSites,
  base: Omit<GroupPreview, 'groups' | 'unmatched'>,
  isAdmin: boolean,
  owner: CacheSessionOwner,
): GroupPreview {
  return {
    ...base,
    groups: resolution.groups.map((group) => {
      const site = { id: group.site_id, domain: group.domain, scope: groupScope(group, isAdmin) }
      const targets = group.target_ordinals.map((ordinal) => lines[ordinal - 1]!)
      // 结果未知的同一请求（离页、刷新后再提交）沿用原幂等键（CACHE-ADD-05）
      const identity = groupIdentity({ site, targets }, base.action, base.targetType, base.nodeIDs, base.maxRetries)
      return {
        site,
        targets,
        key: pendingCacheWriteKey(journalOwner(owner, site.scope), identity) ?? commandKey('create'),
        status: 'pending' as const,
      }
    }),
    unmatched: resolution.unmatched.map((item) => ({ target: lines[item.target_ordinal - 1]!, reason: item.reason })),
  }
}

function useDebounced<T>(value: T, delay: number): T {
  const [current, setCurrent] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setCurrent(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return current
}

function nodeLabel(name: string, ip?: string): string {
  return ip ? `${name}（${ip}）` : name
}

interface PreviewContext {
  owner: CacheSessionOwner
  scope: CacheTargetSiteScope
  ownerKey: string
  accessToken: () => string
}

// Debounced pre-check of a URL list as it is typed: only a list that passes
// the local checks is sent.
function useTargetSitesPreview(
  context: PreviewContext,
  enabled: boolean,
  action: CacheOperationAction,
  targetType: CacheTargetType,
  text: string,
) {
  const joined = useDebounced(splitLines(text).join('\n'), 400)
  const lines = joined ? joined.split('\n') : []
  const effectiveType: Exclude<CacheTargetType, 'whole_site'> = targetType === 'directory_prefix' ? 'directory_prefix' : 'exact_url'
  const valid = enabled && targetType !== 'whole_site' && lines.length > 0 && validTargets(joined, effectiveType, action)
  return useQuery({
    queryKey: targetSitesQueryKey(context.owner, context.scope, action, effectiveType, lines),
    queryFn: () => cacheOperationsApi.targetSites(context.accessToken(), context.scope, {
      action, target_type: effectiveType, targets: lines,
    }),
    enabled: valid && currentCacheSessionCan(context.ownerKey, 'sites.read'),
    staleTime: 30_000,
    retry: false,
  })
}

// The live "涉及 M 个网站 / 本次将提交 K 个任务" of a URL list: the same
// resolution a submit uses (cached under the same key).
function targetSitesQueryKey(
  owner: CacheSessionOwner,
  scope: CacheTargetSiteScope,
  action: CacheOperationAction,
  targetType: CacheTargetType,
  lines: readonly string[],
) {
  return ['cache-target-sites', owner, scope, action, targetType, lines] as const
}

function validTargets(value: string, targetType: CacheTargetType, action: CacheOperationAction): boolean {
  const values = splitLines(value)
  if (values.length === 0 || values.length > maxTargets || !unique(values)) return false
  if (!values.every((item) => validTarget(item, targetType, action))) return false
  return values.reduce((total, item) => {
    return total + textEncoder.encode(item).byteLength
  }, 0) <= maxTargetBytes
}


function unknownOutcome(error: unknown): boolean {
  // daily_limit_exceeded is a 429 the server answers after refusing the
  // write: a definite outcome, not a throttled request of unknown fate.
  if (error instanceof ApiError && error.code === 'daily_limit_exceeded') return false
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

function apiErrorMessage(error: unknown, t: TFunction<'cacheOperations'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const known = new Set([
    'authentication_required', 'invalid_request', 'validation_error', 'permission_denied',
    'not_found', 'idempotency_conflict', 'entitlement_denied', 'invalid_operation_transition', 'retries_exhausted',
    'wildcard_target_host', 'request_cancelled', 'service_unavailable', 'network_error', 'invalid_response',
    'daily_limit_exceeded', 'no_carrying_node', 'wildcard_purge_unsupported', 'target_node_unavailable',
  ])
  const reasons = new Set([
    'target_url_invalid', 'target_host_not_served', 'target_listener_not_enabled', 'target_path_invalid',
    'canonical_target_duplicate', 'targets_too_large',
  ])
  // ADD-10：指出第几行目标、什么原因被拒。
  const localized = error.targetRejection && reasons.has(error.targetRejection.reason)
    ? t('errors.targetRejected', { line: error.targetRejection.ordinal, reason: t(`targetReasons.${error.targetRejection.reason}`) })
    : known.has(error.code) ? t(`errors.${error.code}`) : t('errors.request_failed')
  return error.requestId
    ? t('errors.withRequestId', { message: localized, requestId: error.requestId })
    : localized
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

function CacheOperationsPageSession({
  accessToken,
  owner,
  ownerKey,
  isAdmin,
  canManage,
  canListTenants = false,
}: {
  accessToken: string
  owner: CacheSessionOwner
  ownerKey: string
  isAdmin: boolean
  canManage: boolean
  canListTenants?: boolean
}) {
  const { t, i18n } = useTranslation('cacheOperations')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const ownerRef = useRef({ ownerKey, owner })
  if (ownerRef.current.ownerKey !== ownerKey) ownerRef.current = { ownerKey, owner }
  const queryOwner = ownerRef.current.owner
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  // CACHE-02：管理员没有租户「操作记录」页，记录区在本页 ?tab=history。
  const [searchParams, setSearchParams] = useSearchParams()
  const showRecords = isAdmin && searchParams.get('tab') === 'history'
  const [stateOwnerKey, setStateOwnerKey] = useState(ownerKey)
  const [scopeDraft, setScopeDraft] = useState('')
  const [adminScopeID, setAdminScopeID] = useState<string | null>(null)
  const [filters, setFilters] = useState<FilterValues>({})
  const [appliedFilters, setAppliedFilters] = useState<FilterValues>({})
  const [validationError, setValidationError] = useState<string | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageCursors, setPageCursors] = useState<Array<string | undefined>>([undefined])
  const [selectedOperationID, setSelectedOperationID] = useState<string | null>(null)
  const [unknownWrites, setUnknownWrites] = useState<Record<string, UnknownWrite>>({})
  const [writeError, setWriteError] = useState<unknown>(null)
  const [mainMode, setMainMode] = useState<MainMode>('url')
  const [mainTargets, setMainTargets] = useState('')
  const [mainError, setMainError] = useState<string | null>(null)
  // 刷新整站：按域名选的网站（及其所在租户作用域，管理员读网站详情得到）。
  const [mainSite, setMainSite] = useState<{ id: string; domain: string; scope: CacheOperationScope | null } | null>(null)
  // 高级：节点范围（空 = 全部承载节点）、管理员目标租户（空 = 全部租户）。
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [mainNodeIDs, setMainNodeIDs] = useState<string[]>([])
  const [mainTenant, setMainTenant] = useState('')
  const [submission, setSubmission] = useState<GroupPreview | null>(null)
  const [groupLoading, setGroupLoading] = useState(false)
  const groupRunningRef = useRef(false)
  // Each submission run; a new owner starts a new generation, so a late run of the old one changes nothing.
  const runGenerationRef = useRef(0)
  const [groupRunning, setGroupRunning] = useState(false)
  const submissionRef = useRef<GroupPreview | null>(null)
  const [, setListPermissionVersion] = useState(0)
  const cleanupGenerationRef = useRef(0)
  const messageOwnerKeyRef = useRef(ownerKey)
  const deniedListScopesRef = useRef({ ownerKey, scopes: new Set<string>() })

  if (deniedListScopesRef.current.ownerKey !== ownerKey) {
    deniedListScopesRef.current = { ownerKey, scopes: new Set<string>() }
  }

  if (stateOwnerKey !== ownerKey) {
    setStateOwnerKey(ownerKey)
    setScopeDraft('')
    setAdminScopeID(null)
    setFilters({})
    setAppliedFilters({})
    setValidationError(null)
    setPageIndex(0)
    setPageCursors([undefined])
    setSelectedOperationID(null)
    setUnknownWrites({})
    setWriteError(null)
    setMainMode('url')
    setMainTargets('')
    setMainError(null)
    setMainSite(null)
    setAdvancedOpen(false)
    setMainNodeIDs([])
    setMainTenant('')
    setSubmission(null)
    submissionRef.current = null
    runGenerationRef.current += 1
    groupRunningRef.current = false
    setGroupRunning(false)
    setGroupLoading(false)
  }
  const ownerStateCurrent = stateOwnerKey === ownerKey

  useEffect(() => {
    if (messageOwnerKeyRef.current === ownerKey) return
    messageOwnerKeyRef.current = ownerKey
    messageApi.destroy()
  }, [messageApi, ownerKey])

  const cursor = ownerStateCurrent ? pageCursors[pageIndex] : undefined
  const effectiveAdminScopeID = ownerStateCurrent ? adminScopeID : null
  const effectiveSelectedOperationID = ownerStateCurrent ? selectedOperationID : null
  const scope = useMemo<CacheOperationScope | null>(() => {
    if (!isAdmin) return { kind: 'tenant' }
    return effectiveAdminScopeID ? { kind: 'admin', scopeId: effectiveAdminScopeID } : null
  }, [effectiveAdminScopeID, isAdmin])
  const effectiveScopeKey = scope ? scopeIdentity(scope) : null
  // URL 匹配网站的范围（租户：本人网站；管理员：全部租户）。按网站拆出的
  // 任务各自建在网站所在的租户下（分组提交）。管理员已选目标租户时
  // 只匹配该租户的网站（target-sites 带 scope_id），未选仍匹配全部租户。
  // 目标租户在「高级」里选（与记录页签的查询租户分开）。
  const mainTenantID = ownerStateCurrent && canonicalScopeUUIDPattern.test(mainTenant) ? mainTenant : null
  const targetSiteScope = useMemo<CacheTargetSiteScope>(() => {
    if (!isAdmin) return { kind: 'tenant' }
    return mainTenantID ? { kind: 'admin', scopeId: mainTenantID } : { kind: 'admin-all' }
  }, [mainTenantID, isAdmin])
  const portalKey = `${ownerKey}|${effectiveScopeKey ?? 'no-scope'}`
  const activeScopeKeyRef = useRef(effectiveScopeKey)
  activeScopeKeyRef.current = effectiveScopeKey
  const previousScopeRef = useRef<CacheOperationScope | null>(scope)
  const listScopeDenied = Boolean(
    effectiveScopeKey && deniedListScopesRef.current.scopes.has(effectiveScopeKey),
  )
  const currentListScopeCanRead = () => Boolean(
    effectiveScopeKey &&
    deniedListScopesRef.current.ownerKey === ownerKey &&
    !deniedListScopesRef.current.scopes.has(effectiveScopeKey) &&
    activeScopeKeyRef.current === effectiveScopeKey &&
    currentCacheSessionCan(ownerKey, 'sites.read'),
  )

  const listParams = useMemo<CacheOperationListParams>(() => {
    const { state, ...rest } = ownerStateCurrent ? appliedFilters : {}
    return { ...rest, ...(state ? { states: [state] } : {}), limit: pageSize, cursor }
  }, [ownerStateCurrent, appliedFilters, cursor])
  const listQuery = useQuery({
    queryKey: ['cache-operations', queryOwner, scope, listParams],
    queryFn: async () => {
      if (!scope || !effectiveScopeKey || !currentListScopeCanRead()) {
        throw new ApiError('Permission denied', 403, 'permission_denied')
      }
      try {
        return await cacheOperationsApi.list(accessTokenRef.current, scope, listParams)
      } catch (error) {
        if (error instanceof ApiError && error.status === 403 &&
          deniedListScopesRef.current.ownerKey === ownerKey) {
          const session = useSessionStore.getState()
          const currentOwner = cacheSessionOwner(
            session.principal?.scope_kind,
            session.principal?.scope_id,
            session.principal?.tenant_id,
            session.principal?.user_id,
            session.sessionEpoch,
          )
          if (session.accessToken && JSON.stringify(currentOwner) === ownerKey &&
            !deniedListScopesRef.current.scopes.has(effectiveScopeKey)) {
            deniedListScopesRef.current.scopes.add(effectiveScopeKey)
            setListPermissionVersion((version) => version + 1)
          }
        }
        throw error
      }
    },
    enabled: Boolean(scope && !listScopeDenied),
    refetchInterval: (query) => {
      if (!currentListScopeCanRead()) return false
      return query.state.data?.items.some(
        (operation) => operation.state === 'queued' || operation.state === 'running',
      ) ? 3_000 : false
    },
    refetchOnWindowFocus: currentListScopeCanRead,
    refetchOnReconnect: currentListScopeCanRead,
  })
  const detailQuery = useQuery({
    queryKey: ['cache-operation', queryOwner, scope, effectiveSelectedOperationID],
    queryFn: () => {
      if (!scope || !effectiveScopeKey || !effectiveSelectedOperationID || !currentListScopeCanRead()) {
        throw new ApiError('Permission denied', 403, 'permission_denied')
      }
      return cacheOperationsApi.get(accessTokenRef.current, scope, effectiveSelectedOperationID)
    },
    enabled: Boolean(scope && effectiveSelectedOperationID && !listScopeDenied),
    refetchInterval: (query) => {
      if (!currentListScopeCanRead()) return false
      const state = query.state.data?.state
      return state === 'queued' || state === 'running' ? 3_000 : false
    },
    refetchOnWindowFocus: currentListScopeCanRead,
    refetchOnReconnect: currentListScopeCanRead,
  })
  // 输入即校验（逐行错误）+ 防抖按域名匹配网站（"本次将提交 K 个任务"、未找到对应网站）。
  const { action: mainAction, targetType: mainTargetType } = modeRequest(ownerStateCurrent ? mainMode : 'url')
  const mainLines = splitLines(mainTargets)
  const localCheck = localLineErrors(mainLines, mainTargetType, mainAction, t)
  const previewContext = {
    owner: queryOwner, scope: targetSiteScope, ownerKey, accessToken: () => accessTokenRef.current,
  }
  const mainPreview = useTargetSitesPreview(previewContext, mainMode !== 'site', mainAction, mainTargetType, mainTargets)
  const previewLines = mainPreview.data ? mainLines : []
  const unmatchedErrors: LineError[] = localCheck.errors.length === 0 && mainPreview.data && !mainPreview.isFetching
    ? mainPreview.data.unmatched.map((item) => ({
      line: item.target_ordinal, target: previewLines[item.target_ordinal - 1] ?? '', reason: t(`summary.reasons.${item.reason}`),
    }))
    : []
  const lineErrors = [...localCheck.errors, ...unmatchedErrors]
  const errorCount = lineErrors.length + localCheck.listErrors.length
  const resolvedGroups = localCheck.errors.length === 0 && mainPreview.data && !mainPreview.isFetching
    ? mainPreview.data.groups
    : undefined
  const carryingNodesQuery = useQuery({
    queryKey: ['cache-operation-carrying-nodes', queryOwner, scope],
    queryFn: () => cacheOperationsApi.carryingNodes(accessTokenRef.current, scope!),
    enabled: advancedOpen && !isAdmin && Boolean(scope) && currentCacheSessionCan(ownerKey, 'sites.read'),
    staleTime: 60_000,
    retry: false,
  })
  const [nodeSearch, setNodeSearch] = useState('')
  const adminNodesQuery = useQuery({
    queryKey: ['cache-operation-admin-nodes', queryOwner, nodeSearch],
    queryFn: () => nodesApi.list(accessTokenRef.current, { limit: 100, ...(nodeSearch ? { search: nodeSearch } : {}) }),
    enabled: advancedOpen && isAdmin && currentCacheSessionCan(ownerKey, 'sites.read'),
    staleTime: 60_000,
    retry: false,
  })
  const nodeOptions = isAdmin
    ? (adminNodesQuery.data?.items ?? []).map((node) => ({ value: node.id, label: nodeLabel(node.name, node.ipv4 ?? node.ipv6) }))
    : (carryingNodesQuery.data ?? []).map((node) => ({ value: node.id, label: nodeLabel(node.name, node.ipv4 ?? node.ipv6) }))
  // 额度按账号计算（账号下所有网站共用），租户端进入即读，不必先选网站。
  const quotaEnabled = ownerStateCurrent && !isAdmin
  const dailyUsageQuery = useQuery({
    queryKey: ['cache-operation-daily-usage', queryOwner, scope],
    queryFn: () => {
      if (!scope || !currentListScopeCanRead()) {
        throw new ApiError('Permission denied', 403, 'permission_denied')
      }
      return cacheOperationsApi.dailyUsage(accessTokenRef.current, scope)
    },
    enabled: Boolean(quotaEnabled && scope && !listScopeDenied),
    retry: false,
  })
  const clearUnknownWrite = (scopeKey: string) => {
    setUnknownWrites((current) => {
      if (!current[scopeKey]) return current
      const next = { ...current }
      delete next[scopeKey]
      return next
    })
  }
  const writeMutation = useMutation<CacheOperation, Error, WriteAttempt>({
    mutationKey: ['cache-operation-write', ownerKey],
    mutationFn: (attempt) => {
      if (activeScopeKeyRef.current !== attempt.scopeKey ||
        !currentCacheSessionCan(attempt.ownerKey, 'sites.manage')) {
        throw staleWriteAttempt
      }
      // A key whose outcome is unknown is looked up before it is sent again.
      return sendCacheWrite(() => accessTokenRef.current, attempt.scope, writeRef(attempt), Boolean(attempt.recorded), () => (
        cacheOperationsApi[attempt.kind](accessTokenRef.current, attempt.scope, attempt.operationID, attempt.key)
      ), unknownOutcome)
    },
    onSuccess: async (_result, attempt) => {
      journalWrite(attempt)
      if (activeScopeKeyRef.current !== attempt.scopeKey ||
        !currentCacheSessionCan(attempt.ownerKey, 'sites.manage')) return
      clearUnknownWrite(attempt.scopeKey)
      setWriteError(null)
      messageApi.success(t(`notices.${attempt.kind}`))
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['cache-operations', attempt.owner, attempt.scope] }),
        queryClient.invalidateQueries({ queryKey: ['cache-operation', attempt.owner, attempt.scope] }),
        queryClient.invalidateQueries({ queryKey: ['cache-operation-daily-usage', attempt.owner, attempt.scope] }),
      ])
    },
    onError: (error, attempt) => {
      if (error !== staleWriteAttempt) journalWrite(attempt, error)
      if (error === staleWriteAttempt || activeScopeKeyRef.current !== attempt.scopeKey ||
        !currentCacheSessionCan(attempt.ownerKey, 'sites.manage')) return
      if (unknownOutcome(error)) {
        setUnknownWrites((current) => ({ ...current, [attempt.scopeKey]: { attempt, error } }))
        setWriteError(null)
        return
      }
      clearUnknownWrite(attempt.scopeKey)
      setWriteError(error)
    },
  })

  useEffect(() => {
    const previousScope = previousScopeRef.current
    previousScopeRef.current = scope
    if (!previousScope || scopeIdentity(previousScope) === effectiveScopeKey) return
    queryClient.removeQueries({ queryKey: ['cache-operations', queryOwner, previousScope] })
    queryClient.removeQueries({ queryKey: ['cache-operation', queryOwner, previousScope] })
  }, [effectiveScopeKey, queryClient, queryOwner, scope])

  useEffect(() => {
    const generation = ++cleanupGenerationRef.current
    const cleanupOwner = JSON.parse(ownerKey) as CacheSessionOwner
    const cleanupQueries = () => {
      queryClient.removeQueries({ queryKey: ['cache-operations', cleanupOwner] })
      queryClient.removeQueries({ queryKey: ['cache-operation', cleanupOwner] })
    }
    return () => {
      const state = useSessionStore.getState()
      const currentOwner = cacheSessionOwner(
        state.principal?.scope_kind,
        state.principal?.scope_id,
        state.principal?.tenant_id,
        state.principal?.user_id,
        state.sessionEpoch,
      )
      if (JSON.stringify(currentOwner) !== ownerKey) {
        cleanupQueries()
        return
      }
      queueMicrotask(() => {
        // eslint-disable-next-line react-hooks/exhaustive-deps -- The current generation cancels StrictMode's stale cleanup.
        if (cleanupGenerationRef.current === generation) cleanupQueries()
      })
    }
  }, [ownerKey, queryClient])

  const listForbidden = listScopeDenied ||
    (listQuery.error instanceof ApiError && listQuery.error.status === 403)
  if (!isAdmin && listForbidden) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  const resetPages = () => {
    setPageIndex(0)
    setPageCursors([undefined])
  }
  const resetTargetState = () => {
    setFilters({})
    setAppliedFilters({})
    setValidationError(null)
    resetPages()
    setSelectedOperationID(null)
    setWriteError(null)
    messageApi.destroy()
  }
  const applyFilters = () => {
    const scopeID = scopeDraft.trim().toLowerCase()
    const siteID = filters.site_id?.trim().toLowerCase()
    if (isAdmin && !uuidPattern.test(scopeID)) {
      setValidationError(t('validation.scope'))
      return
    }
    if (siteID && !uuidPattern.test(siteID)) {
      setValidationError(t('validation.site'))
      return
    }
    setValidationError(null)
    if (isAdmin && adminScopeID && adminScopeID !== scopeID) {
      setAdminScopeID(scopeID)
      resetTargetState()
      return
    }
    setAdminScopeID(isAdmin ? scopeID : null)
    const next = { ...filters, site_id: siteID || undefined }
    if (JSON.stringify(next) === JSON.stringify(appliedFilters) && scope !== null && pageIndex === 0) {
      if (currentListScopeCanRead()) void listQuery.refetch()
      return
    }
    setAppliedFilters(next)
    resetPages()
  }
  const refresh = () => {
    if (currentListScopeCanRead()) void listQuery.refetch()
  }
  const nextPage = () => {
    if (!currentListScopeCanRead()) return
    const nextCursor = listQuery.data?.next_cursor
    if (!nextCursor) return
    setPageCursors((current) => [...current.slice(0, pageIndex + 1), nextCursor])
    setPageIndex((current) => current + 1)
  }
  const currentUnknown = effectiveScopeKey ? unknownWrites[effectiveScopeKey] : undefined
  const mutationPending = writeMutation.isPending && writeMutation.variables?.ownerKey === ownerKey &&
    writeMutation.variables?.scopeKey === effectiveScopeKey
  const submitWrite = (request: WriteRequest) => {
    if (!scope || !effectiveScopeKey || mutationPending || currentUnknown ||
      !currentListScopeCanRead() || !currentCacheSessionCan(ownerKey, 'sites.manage')) return
    const recordedKey = pendingCacheWriteKey(journalOwner(queryOwner, scope), writeIdentity(request))
    const attempt = {
      ...request,
      key: recordedKey ?? request.key,
      recorded: recordedKey !== undefined,
      owner: queryOwner,
      ownerKey,
      scope,
      scopeKey: effectiveScopeKey,
    } as WriteAttempt
    clearUnknownWrite(effectiveScopeKey)
    setWriteError(null)
    writeMutation.mutate(attempt)
  }
  const retryOperation = (operationID: string) => submitWrite({
    kind: 'retry', operationID, key: commandKey('retry'),
  })
  const cancelOperation = (operationID: string) => submitWrite({
    kind: 'cancel', operationID, key: commandKey('cancel'),
  })
  const retryUnknown = (attempt: WriteAttempt) => {
    if (!currentUnknown || currentUnknown.attempt.key !== attempt.key || mutationPending ||
      !currentListScopeCanRead() ||
      activeScopeKeyRef.current !== attempt.scopeKey ||
      !currentCacheSessionCan(attempt.ownerKey, 'sites.manage')) return
    writeMutation.mutate({ ...attempt, recorded: true })
  }
  const uncertain = Boolean(currentUnknown)
  const writesLocked = mutationPending || uncertain
  const openDetail = (operationID: string) => {
    if (!currentListScopeCanRead()) return
    setSelectedOperationID(operationID)
  }
  // An accepted task of the submission: a tenant opens its details here; an
  // administrator goes to the records of the tenant the site belongs to.
  const openAccepted = (group: GroupTask) => {
    if (!group.operationID) return
    if (group.site.scope.kind === 'tenant') {
      openDetail(group.operationID)
      return
    }
    setScopeDraft(group.site.scope.scopeId)
    if (adminScopeID !== group.site.scope.scopeId) {
      setAdminScopeID(group.site.scope.scopeId)
      resetTargetState()
    }
    setSelectedOperationID(group.operationID)
    setSearchParams({ tab: 'history' })
  }
  const setGroups = (update: (current: GroupPreview) => GroupPreview) => {
    if (!submissionRef.current) return
    submissionRef.current = update(submissionRef.current)
    setSubmission(submissionRef.current)
  }
  const clearSubmission = () => {
    if (groupRunningRef.current) return
    submissionRef.current = null
    setSubmission(null)
  }
  // 服务端按 URL 域名匹配网站（同一批可跨多个网站），有未匹配时不发任何创建请求。
  const resolveTargetSites = (
    action: CacheOperationAction,
    targetType: Exclude<CacheTargetType, 'whole_site'>,
    lines: string[],
  ) => queryClient.fetchQuery({
    queryKey: targetSitesQueryKey(queryOwner, targetSiteScope, action, targetType, lines),
    queryFn: () => cacheOperationsApi.targetSites(accessTokenRef.current, targetSiteScope, {
      action, target_type: targetType, targets: lines,
    }),
    staleTime: 30_000,
  })
  // Submits one task per site in the page; a result of unknown outcome keeps
  // its key (journal) and "重试未成功的网站" sends the same request again.
  const runGroups = async () => {
    const preview = submissionRef.current
    if (!preview || groupRunningRef.current) return
    const run = ++runGenerationRef.current
    const live = () => runGenerationRef.current === run
    groupRunningRef.current = true
    setGroupRunning(true)
    const touched: CacheOperationScope[] = []
    try {
      for (const group of preview.groups) {
        if (!live()) return
        const current = submissionRef.current?.groups.find((item) => item.site.id === group.site.id)
        if (!current || current.status === 'accepted') continue
        if (!currentCacheSessionCan(ownerKey, 'sites.manage')) return
        // 明确失败的站没有建任务，换新幂等键；结果未知的站只能用原键重试
        const key = current.status === 'failed' ? commandKey('create') : current.key
        const mark = (patch: Partial<GroupTask>) => {
          if (live()) setGroups((value) => ({
            ...value, groups: value.groups.map((item) => item.site.id === group.site.id ? { ...item, ...patch } : item),
          }))
        }
        mark({ key, status: 'running', error: undefined })
        touched.push(group.site.scope)
        const owner = journalOwner(queryOwner, group.site.scope)
        const identity = groupIdentity(group, preview.action, preview.targetType, preview.nodeIDs, preview.maxRetries)
        try {
          // An unknown earlier attempt (same key in the journal) is looked up first.
          const recorded = pendingCacheWriteKey(owner, identity) === key
          const result = await sendCacheWrite(() => accessTokenRef.current, group.site.scope, { action: 'create', key }, recorded,
            () => cacheOperationsApi.create(accessTokenRef.current, group.site.scope,
              groupInput(group, preview.action, preview.targetType, preview.nodeIDs, preview.maxRetries), key), unknownOutcome)
          settleCacheWrite(owner, identity, key)
          mark({ status: 'accepted', operationID: result?.id })
        } catch (error) {
          if (unknownOutcome(error)) rememberCacheWrite(owner, identity, key)
          else settleCacheWrite(owner, identity, key)
          mark({ status: unknownOutcome(error) ? 'unknown' : 'failed', error })
        }
      }
    } finally {
      // A late answer after the session changed touches nothing of the new owner.
      if (live()) {
        groupRunningRef.current = false
        setGroupRunning(false)
      }
      if (live() && currentCacheSessionCan(ownerKey, 'sites.read')) for (const target of touched) {
        void queryClient.invalidateQueries({ queryKey: ['cache-operations', queryOwner, target] })
        void queryClient.invalidateQueries({ queryKey: ['cache-operation-daily-usage', queryOwner, target] })
      }
    }
    const settled = submissionRef.current
    if (!live() || !settled || !currentCacheSessionCan(ownerKey, 'sites.manage')) return
    if (settled.groups.length > 0 && settled.groups.every((group) => group.status === 'accepted')) {
      // 全部受理：清空输入，避免重复提交；租户单个任务直接打开任务详情（CACHE-ADD-01）。
      setMainTargets('')
      messageApi.success(t('notices.create'))
      const only = settled.groups.length === 1 ? settled.groups[0]! : null
      if (only?.operationID && only.site.scope.kind === 'tenant') openDetail(only.operationID)
    }
  }
  const startSubmission = (next: GroupPreview) => {
    submissionRef.current = next
    setSubmission(next)
    void runGroups()
  }
  const submitMain = async () => {
    if (!canManage || groupRunningRef.current || !currentCacheSessionCan(ownerKey, 'sites.manage')) return
    setMainError(null)
    const base = { action: mainAction, targetType: mainTargetType, nodeIDs: mainNodeIDs, maxRetries: 3, fromMain: true }
    if (mainMode === 'site') {
      if (!mainSite?.scope) return
      const site = { id: mainSite.id, domain: mainSite.domain, scope: mainSite.scope }
      const identity = groupIdentity({ site, targets: [] }, base.action, base.targetType, base.nodeIDs, base.maxRetries)
      startSubmission({
        ...base,
        groups: [{
          site, targets: [], status: 'pending',
          key: pendingCacheWriteKey(journalOwner(queryOwner, site.scope), identity) ?? commandKey('create'),
        }],
        unmatched: [],
      })
      return
    }
    if (mainLines.length === 0 || errorCount > 0) return
    const targetType: Exclude<CacheTargetType, 'whole_site'> = mainTargetType === 'directory_prefix' ? 'directory_prefix' : 'exact_url'
    setGroupLoading(true)
    try {
      const resolution = await resolveTargetSites(mainAction, targetType, mainLines)
      if (!currentCacheSessionCan(ownerKey, 'sites.manage')) return
      if (resolution.unmatched.length > 0) {
        setMainError(t('create.unmatched', { count: resolution.unmatched.length }))
        return
      }
      startSubmission(groupPreviewFrom(mainLines, resolution, base, isAdmin, queryOwner))
    } catch (error) {
      setMainError(apiErrorMessage(error, t))
    } finally {
      setGroupLoading(false)
    }
  }
  const pickMode = (mode: MainMode) => {
    setMainMode(mode)
    setMainError(null)
    clearSubmission()
  }
  const submissionRetryable = Boolean(!groupRunning && submission?.groups.some((group) => group.status === 'failed' || group.status === 'unknown'))

  const retryDetail = () => {
    if (currentListScopeCanRead()) void detailQuery.refetch()
  }

  const columns: TableColumnsType<CacheOperationSummary> = [
    { title: t('columns.id'), dataIndex: 'id', width: 220, ellipsis: true },
    // CACHE-ADD-06a: the site's short display ID (the UUID stays on hover).
    {
      title: t('columns.site'), dataIndex: 'site_display_id', width: 120, ellipsis: true,
      render: (value: string, item) => <span title={item.site_id}>{value}</span>,
    },
    {
      title: t('columns.action'), dataIndex: 'action', width: 90,
      render: (action: CacheOperationAction) => t(`actions.values.${action}`),
    },
    {
      title: t('columns.targetType'), dataIndex: 'target_type', width: 120,
      render: (targetType: CacheTargetType) => t(`targetTypes.${targetType}`),
    },
    { title: t('columns.targets'), dataIndex: 'target_count', width: 90 },
    { title: t('columns.nodes'), dataIndex: 'node_count', width: 90 },
    {
      title: t('columns.progress'), dataIndex: 'progress', width: 120,
      render: (progress: CacheOperationSummary['progress']) =>
        `${formatNumber(progress.completed, locale)} / ${formatNumber(progress.total, locale)}`,
    },
    {
      title: t('columns.state'), dataIndex: 'state', width: 120,
      render: (state: CacheOperationState) => <StateTag state={state} />,
    },
    {
      title: t('columns.createdAt'), dataIndex: 'created_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('columns.actions'), key: 'actions', fixed: 'right', width: 325,
      render: (_, operation) => (
        <Space size={4} wrap={false}>
          <Button
            type="link"
            size="small"
            icon={<Eye size={14} aria-hidden="true" />}
            onClick={() => openDetail(operation.id)}
          >
            {t('actions.details')}
          </Button>
          {operation.state === 'failed' || operation.state === 'partial_failed' ? (
            <Button
              type="link"
              size="small"
              icon={<RotateCcw size={14} aria-hidden="true" />}
              disabled={!canManage || writesLocked}
              onClick={() => retryOperation(operation.id)}
            >
              {t('actions.retryFailed')}
            </Button>
          ) : null}
          {operation.state === 'queued' || operation.state === 'running' ? (
            <Popconfirm
              title={t('confirm.cancelTitle')}
              description={t('confirm.cancelDescription')}
              okText={t('actions.confirm')}
              cancelText={t('actions.close')}
              onConfirm={() => cancelOperation(operation.id)}
            >
              <Button
                type="link"
                danger
                size="small"
                icon={<Ban size={14} aria-hidden="true" />}
                disabled={!canManage || writesLocked}
              >
                {t('actions.cancelOperation')}
              </Button>
            </Popconfirm>
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
    {
      title: t('columns.state'), dataIndex: 'state', width: 120,
      render: (state: CacheOperationState) => <StateTag state={state} />,
    },
    { title: t('detail.attempt'), dataIndex: 'attempt', width: 90 },
    {
      title: t('columns.progress'), dataIndex: 'progress', width: 110,
      render: (progress: CacheNodeProjection['progress']) =>
        `${formatNumber(progress.completed, locale)} / ${formatNumber(progress.total, locale)}`,
    },
    {
      title: t('detail.failure'), dataIndex: 'last_error_code', width: 260,
      render: (code?: string) => cacheFailureText(code, t),
    },
    {
      title: t('detail.updatedAt'), dataIndex: 'updated_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
    // CACHE-ADD-07: shown once the task was cancelled while a node ran it.
    ...(detailQuery.data?.nodes.some((node) => node.cancel_confirmation) ? [{
      title: t('detail.cancelConfirmation'), dataIndex: 'cancel_confirmation', width: 220,
      render: (value?: CacheCancelConfirmation) => value ? t(`detail.cancelConfirmations.${value}`) : t('values.placeholder'),
    }] : []),
  ]
  const operationTargetColumns: TableColumnsType<CacheOperationTarget> = [
    { title: t('detail.ordinal'), dataIndex: 'ordinal', width: 80 },
    {
      title: t('detail.displayUrl'), dataIndex: 'display_url', width: 360,
      render: (value: string) => <code>{value}</code>,
    },
    {
      title: t('detail.canonicalPath'), dataIndex: 'canonical_path', width: 300,
      render: (value: string) => <code>{value}</code>,
    },
    {
      title: t('detail.targetHash'), dataIndex: 'target_sha256', width: 520,
      render: (value: string) => <code>{value}</code>,
    },
    {
      title: t('detail.queryRedacted'), dataIndex: 'query_redacted', width: 150,
      render: (value: boolean) => <Tag color={value ? 'warning' : undefined}>
        {value ? t('values.yes') : t('values.no')}
      </Tag>,
    },
  ]
  const detail = detailQuery.data
  const placeholder = t('values.placeholder')
  const detailState = detail ? <StateTag state={detail.state} /> : placeholder
  const usage = quotaEnabled ? dailyUsageQuery.data : undefined
  const currentQuota = usage
    ? mainAction === 'prewarm' ? usage.prewarm : mainTargetType === 'exact_url' ? usage.url_purge : usage.directory_purge
    : undefined
  const modeLabel = (mode: MainMode) => t(`baseline.modes.${mode}`)
  const groupsRunning = groupRunning || groupLoading
  const submissionDone = Boolean(submission && submission.groups.length > 0 && submission.groups.every((group) => group.status === 'accepted'))
  const mainStatus = groupsRunning
    ? 'submitting'
    : submission?.groups.some((group) => group.status === 'unknown')
      ? 'unknown'
      : submissionDone
        ? 'submitted'
        : (errorCount > 0 || mainError || submission?.groups.some((group) => group.status === 'failed'))
          ? 'fix'
          : (mainMode === 'site' ? Boolean(mainSite) : mainLines.length > 0)
            ? 'ready'
            : 'pending'
  // 本次将提交 K 个任务：按网站拆分的任务数（未完成匹配前显示 —）。
  const taskCount = mainMode === 'site' ? (mainSite ? 1 : 0) : resolvedGroups?.length
  const siteCount = taskCount
  const mainSubmitDisabled = !canManage || groupsRunning || errorCount > 0 ||
    (mainMode === 'site' ? !mainSite?.scope : mainLines.length === 0)
  const listCopy = t(`baseline.lists.${mainMode === 'site' ? 'url' : mainMode}`, { returnObjects: true }) as { title: string; description: string }
  const shownErrors = lineErrors.slice(0, 20)
  const errorLines = [...localCheck.listErrors, ...shownErrors.map((item) => t('lineIssues.line', {
    line: formatNumber(item.line, locale), target: item.target, reason: item.reason,
  }))]

  return (
    <section className="identity-page cache-operations-page cache-replica-page" aria-labelledby="cache-operations-title">
      {messageContext}
      {/* 管理员没有 /site/cache-clean/history（租户专属），「操作记录」页签是本页 ?tab=history。 */}
      <SiteCacheTabs active={showRecords ? 'history' : 'purge'} historyHref={isAdmin ? '/site/cache-clean?tab=history' : undefined} />
      <h1 id="cache-operations-title" className="cache-page-heading">{t('title')}</h1>

      {!showRecords ? (
      <section className="cache-baseline-layout" aria-label={t('baseline.title')}>
        <div className="cache-baseline-main">
          <section className="cache-baseline-section cache-baseline-section-mode">
            <div className="cache-baseline-section-head">
              <div className="cache-baseline-title-wrap">
                <h2>{t('baseline.operationType')}</h2>
                <p>{t('baseline.operationDescription')}</p>
              </div>
              <span className="cache-baseline-current">{t('baseline.current', { value: modeLabel(mainMode) })}</span>
            </div>
            <div className="cache-baseline-mode-actions" role="group" aria-label={t('baseline.operationType')}>
              {mainModes.map((mode) => (
                <Button
                  key={mode}
                  className={mainMode === mode ? 'cache-replica-mode is-selected' : 'cache-replica-mode'}
                  aria-pressed={mainMode === mode}
                  disabled={groupsRunning}
                  onClick={() => pickMode(mode)}
                >
                  {modeLabel(mode)}
                </Button>
              ))}
            </div>
          </section>

          <section className="cache-baseline-section cache-baseline-section-input">
            <div className="cache-baseline-input-head">
              <div className="cache-baseline-title-wrap">
                <h2>{mainMode === 'site' ? t('baseline.siteTitle') : listCopy.title}</h2>
                <p>{mainMode === 'site' ? t('baseline.siteDescription') : listCopy.description}</p>
              </div>
              {mainMode === 'site' ? null : (
                <span className={errorCount > 0 ? 'cache-baseline-count is-error' : 'cache-baseline-count'} aria-live="polite">
                  {t('baseline.enteredPrefix')}<strong>{formatNumber(mainLines.length, locale)}</strong>{t('baseline.enteredUnit')}
                  {errorCount > 0 ? <>
                    {t('baseline.errorPrefix')}<strong className="cache-replica-error-count">{formatNumber(errorCount, locale)}</strong>{t('baseline.enteredUnit')}
                  </> : null}
                </span>
              )}
            </div>
            {mainMode === 'site' ? (
              <OwnSiteSelect
                ownerKey={ownerKey}
                queryOwner={queryOwner}
                accessToken={() => accessTokenRef.current}
                ariaLabel={t('baseline.siteTitle')}
                className="cache-replica-site-select"
                value={mainSite?.id ?? null}
                onChange={(next, site) => {
                  clearSubmission()
                  setMainError(null)
                  if (!next) { setMainSite(null); return }
                  const domain = site?.domain ?? next
                  if (!isAdmin) { setMainSite({ id: next, domain, scope: { kind: 'tenant' } }); return }
                  // 管理员：网站所在租户由网站详情给出，任务建在该租户下。
                  setMainSite({ id: next, domain, scope: null })
                  void sitesApi.detail(accessTokenRef.current, next).then((detail) => {
                    const scopeID = detail?.scope_id
                    if (scopeID) {
                      setMainSite((current) => current?.id === next ? { id: next, domain, scope: { kind: 'admin', scopeId: scopeID } } : current)
                    }
                  }).catch((error: unknown) => setMainError(apiErrorMessage(error, t)))
                }}
              />
            ) : (
              <textarea
                id="cache-baseline-targets"
                aria-label={t('baseline.url')}
                aria-invalid={errorCount > 0}
                aria-describedby="cache-replica-feedback"
                value={mainTargets}
                placeholder={t(mainMode === 'directory' ? 'baseline.directoryPlaceholder' : 'baseline.urlPlaceholder')}
                disabled={groupsRunning}
                onChange={(event) => {
                  setMainTargets(event.target.value)
                  setMainError(null)
                  clearSubmission()
                }}
              />
            )}
            <div id="cache-replica-feedback">
              {errorLines.length > 0 || mainError ? (
                <div className="cache-baseline-error cache-replica-error-bar" role="alert">
                  {mainError ? <p>{mainError}</p> : null}
                  {errorLines.length > 0 ? (
                    <ul>
                      {errorLines.map((text) => <li key={text}>{text}</li>)}
                    </ul>
                  ) : null}
                  {lineErrors.length > shownErrors.length ? <p>{t('summary.more', { count: lineErrors.length - shownErrors.length })}</p> : null}
                </div>
              ) : mainMode === 'site' ? (
                <p className="cache-baseline-paste-hint">{t('baseline.siteHint')}</p>
              ) : (
                <p className="cache-baseline-paste-hint">{t('baseline.pasteHint')}</p>
              )}
            </div>
            {submission ? (
              <div className="cache-replica-results" aria-live="polite">
                <ul>
                  {submission.groups.map((group) => (
                    <li key={group.site.id}>
                      <span className="cache-replica-result-site">{group.site.domain}</span>
                      <span className="cache-replica-result-count">
                        {group.targets.length ? t('groups.targetsCount', { count: formatNumber(group.targets.length, locale) }) : t('targetTypes.whole_site')}
                      </span>
                      {group.status === 'accepted' && group.operationID ? (
                        <Button type="link" size="small" onClick={() => openAccepted(group)}>{t('groups.states.accepted')}</Button>
                      ) : (
                        <span className={`cache-replica-result-state is-${group.status}`}>
                          {t(`groups.states.${group.status}`)}
                          {group.status === 'failed' ? `：${apiErrorMessage(group.error, t)}` : group.status === 'unknown' ? `：${t('groups.unknownReason')}` : ''}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
                {submissionRetryable ? (
                  <Button size="small" onClick={() => void runGroups()}>{t('groups.retry')}</Button>
                ) : null}
              </div>
            ) : null}
            {advancedOpen ? (
              <div className="cache-replica-advanced" role="group" aria-label={t('baseline.advanced')}>
                {isAdmin ? (
                  <label className="cache-replica-field">
                    <span>{t('baseline.targetTenant')}</span>
                    <TenantScopeSelect
                      className="cache-replica-tenant"
                      accessToken={accessToken}
                      ownerKey={ownerKey}
                      canList={canListTenants}
                      queryKeyPrefix="cache-operation-main-tenants"
                      ariaLabel={t('baseline.targetTenant')}
                      placeholder={t('baseline.targetTenantPlaceholder')}
                      emptyText={t('filters.scopeEmpty')}
                      value={mainTenant}
                      onChange={(next) => { setMainTenant(next); clearSubmission() }}
                    />
                  </label>
                ) : null}
                <label className="cache-replica-field">
                  <span>{t('create.nodes')}</span>
                  <Select
                    mode="multiple"
                    allowClear
                    showSearch
                    aria-label={t('create.nodes')}
                    placeholder={t('create.nodesPlaceholder')}
                    value={mainNodeIDs}
                    onChange={(next: string[]) => { setMainNodeIDs(next.slice(0, 1000)); clearSubmission() }}
                    loading={isAdmin ? adminNodesQuery.isFetching : carryingNodesQuery.isFetching}
                    filterOption={isAdmin ? false : (input, option) => String(option?.label ?? '').toLowerCase().includes(input.toLowerCase())}
                    onSearch={isAdmin ? (value) => setNodeSearch(value.trim()) : undefined}
                    notFoundContent={(isAdmin ? adminNodesQuery.isError : carryingNodesQuery.isError) ? t('create.nodesFailed') : t('create.nodesEmpty')}
                    options={nodeOptions}
                  />
                  <small>{t('create.nodesExtra')}</small>
                </label>
              </div>
            ) : null}
            <div className="cache-baseline-footer">
              <span aria-live="polite">
                {t('baseline.taskPrefix')}
                <strong className={errorCount > 0 ? 'cache-replica-task-count is-error' : 'cache-replica-task-count'}>
                  {/* 匹配前（含有错误时）按输入条数显示；匹配后为按网站拆分的任务数。 */}
                  {formatNumber(taskCount ?? mainLines.length, locale)}
                </strong>
                {t('baseline.taskUnit')}
                {mainMode !== 'site' && siteCount !== undefined && siteCount > 0 ? (
                  <span className="cache-replica-site-count">{t('baseline.sitesInvolved', { count: formatNumber(siteCount, locale) })}</span>
                ) : null}
              </span>
              <div className="cache-baseline-footer-actions">
                <Button
                  type="link"
                  size="small"
                  className="cache-replica-advanced-toggle"
                  aria-expanded={advancedOpen}
                  onClick={() => setAdvancedOpen((open) => !open)}
                >
                  {t('baseline.advanced')}
                  {mainNodeIDs.length > 0 || (isAdmin && mainTenantID) ? t('baseline.advancedSet') : ''}
                </Button>
                <Button
                  disabled={groupsRunning || (mainMode === 'site' ? !mainSite : mainTargets === '')}
                  onClick={() => {
                    if (mainMode === 'site') setMainSite(null)
                    else setMainTargets('')
                    setMainError(null)
                    clearSubmission()
                  }}
                >
                  {t('baseline.clear')}
                </Button>
                <Button
                  type="primary"
                  disabled={mainSubmitDisabled}
                  loading={groupsRunning}
                  onClick={() => void submitMain()}
                >
                  {t('baseline.submitTask')}
                </Button>
              </div>
            </div>
          </section>
        </div>

        <aside className="cache-baseline-side" aria-label={t('baseline.statusPanel')}>
          <section className="cache-baseline-status-panel">
            <h2>{t('baseline.dailyQuota')}</h2>
            {currentQuota ? (
              <>
                <div className="cache-baseline-quota-value">
                  <strong>{formatNumber(currentQuota.remaining, locale)}</strong>
                  <span>{t('baseline.remainingOf', { total: formatNumber(currentQuota.limit, locale) })}</span>
                </div>
                <div className="cache-baseline-quota-facts">
                  <span>{t('baseline.used', { count: formatNumber(currentQuota.used, locale) })}</span>
                  <span>{t('baseline.total', { count: formatNumber(currentQuota.limit, locale) })}</span>
                </div>
                <Progress percent={currentQuota.limit > 0 ? Math.round(currentQuota.used / currentQuota.limit * 100) : 100}
                  showInfo={false} size="small" aria-label={t('baseline.dailyQuota')} />
                <p>{t('baseline.quotaScope', { time: formatDateTime(usage!.resets_at, locale) })}</p>
              </>
            ) : quotaEnabled && dailyUsageQuery.isError ? (
              <div className="cache-baseline-quota-value" role="alert">
                <span>{t('baseline.quotaFailed')}</span>
                <Button size="small" onClick={() => void dailyUsageQuery.refetch()}>{t('actions.retry')}</Button>
              </div>
            ) : (
              <div className="cache-baseline-quota-value">
                <strong>{t('baseline.unavailable')}</strong>
                <span>{isAdmin ? t('baseline.quotaAdmin') : t('baseline.quotaLoading')}</span>
              </div>
            )}
          </section>
          <section className="cache-baseline-status-panel">
            <h2>{t('baseline.submitStatus')}</h2>
            <strong className={`cache-baseline-submit-status cache-replica-status-${mainStatus}`}>{t(`baseline.status.${mainStatus}`)}</strong>
            <p>{t('baseline.statusDescription')}</p>
          </section>
        </aside>
      </section>
      ) : null}

      {/* CACHE-02：管理员的租户选择与记录在「操作记录」页签；租户的记录在 /site/cache-clean/history，
          这里只留隐藏的列表供详情抽屉与重试/取消使用。 */}
      <div className={showRecords ? 'cache-operations-management cache-operations-management-admin' : 'cache-operations-management'}>
      <div className="cache-operations-toolbar">
        {isAdmin ? (
          <TenantScopeSelect
            className="cache-operations-tenant"
            accessToken={accessToken}
            ownerKey={ownerKey}
            canList={canListTenants}
            queryKeyPrefix="cache-operation-tenants"
            ariaLabel={t('filters.scope')}
            placeholder={t('filters.scopePlaceholder')}
            emptyText={t('filters.scopeEmpty')}
            value={scopeDraft}
            onChange={setScopeDraft}
          />
        ) : null}
        <Input
          aria-label={t('filters.site')}
          placeholder={t('filters.sitePlaceholder')}
          value={filters.site_id}
          onChange={(event) => setFilters((current) => ({ ...current, site_id: event.target.value }))}
          onPressEnter={applyFilters}
        />
        <Select<CacheOperationAction>
          aria-label={t('filters.action')}
          allowClear
          placeholder={t('filters.allActions')}
          value={filters.action}
          options={operationActions.map((action) => ({ value: action, label: t(`actions.values.${action}`) }))}
          onChange={(action) => setFilters((current) => ({ ...current, action }))}
        />
        <Select<CacheTargetType>
          aria-label={t('filters.targetType')}
          allowClear
          placeholder={t('filters.allTargetTypes')}
          value={filters.target_type}
          options={targetTypes.map((targetType) => ({ value: targetType, label: t(`targetTypes.${targetType}`) }))}
          onChange={(targetType) => setFilters((current) => ({ ...current, target_type: targetType }))}
        />
        <Select<CacheOperationState>
          aria-label={t('filters.state')}
          allowClear
          placeholder={t('filters.allStates')}
          value={filters.state}
          options={operationStates.map((state) => ({ value: state, label: t(`states.${state}`) }))}
          onChange={(state) => setFilters((current) => ({ ...current, state }))}
        />
        <Button type="primary" icon={<Search size={15} aria-hidden="true" />} onClick={applyFilters}>
          {t('actions.query')}
        </Button>
        <Button icon={<RefreshCw size={15} aria-hidden="true" />} disabled={!scope} onClick={refresh}>
          {t('actions.refresh')}
        </Button>
      </div>

      {isAdmin && !scope ? (
        <Alert className="identity-alert" type="info" showIcon message={t('statesUi.scopeRequired')} />
      ) : null}
      {validationError ? <Alert className="identity-alert" type="error" showIcon message={validationError} /> : null}
      {uncertain ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={
            <Space wrap>
              <Button
                size="small"
                disabled={!canManage || mutationPending}
                onClick={() => { if (currentUnknown) retryUnknown(currentUnknown.attempt) }}
              >
                {t('actions.retrySameRequest')}
              </Button>
              <Button
                size="small"
                onClick={() => {
                  if (!effectiveScopeKey || !currentListScopeCanRead()) return
                  // The user gives the write up: a later identical submit is a new one.
                  if (currentUnknown) settleCacheWrite(journalOwner(currentUnknown.attempt.owner, currentUnknown.attempt.scope), writeIdentity(currentUnknown.attempt), currentUnknown.attempt.key)
                  clearUnknownWrite(effectiveScopeKey)
                  setWriteError(null)
                  refresh()
                }}
              >
                {t('actions.closeAndRefresh')}
              </Button>
            </Space>
          } className="identity-alert" />
      ) : writeError ? (
        <FeedbackWhen title={apiErrorMessage(writeError, t)} />
      ) : null}
      {listForbidden ? (
        <Alert
          className="identity-alert"
          type="error"
          showIcon
          message={t('errors.forbiddenTitle')}
          description={t('errors.permission_denied')}
        />
      ) : listQuery.isError ? (
        <FeedbackWhen title={t('errors.listLoadFailed')} detail={apiErrorMessage(listQuery.error, t)} action={<Button size="small" onClick={refresh}>{t('actions.retry')}</Button>} />
      ) : null}

      <div className="identity-table-scroll cache-operations-table" aria-busy={listQuery.isPending || listQuery.isFetching}>
        <Table<CacheOperationSummary>
          rowKey="id"
          size="small"
          columns={columns}
          dataSource={listQuery.data?.items ?? []}
          loading={Boolean(scope && (listQuery.isPending || listQuery.isFetching))}
          pagination={false}
          locale={{ emptyText: scope && !listForbidden && !listQuery.isPending && !listQuery.isError ? t('values.empty') : ' ' }}
          scroll={{ x: 1645 }}
        />
      </div>
      <div className="cache-operations-pagination" aria-label={t('pagination.label')}>
        <span>{t('pagination.page', { page: formatNumber(pageIndex + 1, locale) })}</span>
        <Button
          aria-label={t('actions.previous')}
          icon={<ChevronLeft size={15} aria-hidden="true" />}
          disabled={pageIndex === 0 || listQuery.isFetching}
          onClick={() => {
            if (effectiveScopeKey && activeScopeKeyRef.current === effectiveScopeKey &&
              currentCacheSessionCan(ownerKey, 'sites.read')) setPageIndex((current) => current - 1)
          }}
        />
        <Button
          aria-label={t('actions.next')}
          icon={<ChevronRight size={15} aria-hidden="true" />}
          disabled={!listQuery.data?.next_cursor || listQuery.isFetching}
          onClick={nextPage}
        />
      </div>
      </div>

      <Drawer
        key={`detail-${portalKey}`}
        className="cache-operation-drawer"
        width={920}
        title={t('detail.title')}
        open={selectedOperationID !== null}
        closable={false}
        onClose={() => setSelectedOperationID(null)}
        extra={
          <Button
            type="text"
            icon={<X size={16} aria-hidden="true" />}
            aria-label={t('actions.close')}
            onClick={() => setSelectedOperationID(null)}
          />
        }
      >
        {detailQuery.isError ? (
          <Alert
            className="identity-alert"
            type="error"
            showIcon
            message={t('errors.detailLoadFailed')}
            description={apiErrorMessage(detailQuery.error, t)}
            action={<Button size="small" onClick={retryDetail}>{t('actions.retry')}</Button>}
          />
        ) : null}
        <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
          <Descriptions.Item label={t('columns.id')} span="filled">{detail ? <span title={detail.id}>{detail.display_id}</span> : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.state')}>{detailState}</Descriptions.Item>
          <Descriptions.Item label={t('columns.site')}>{detail ? <span title={detail.site_id}>{detail.site_display_id}</span> : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.action')}>{detail ? t(`actions.values.${detail.action}`) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.targetType')}>{detail ? t(`targetTypes.${detail.target_type}`) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('detail.maxAttempts')}>{detail?.max_attempts ?? placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('columns.createdAt')}>{detail ? formatDateTime(detail.created_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('detail.updatedAt')}>{detail ? formatDateTime(detail.updated_at, locale) : placeholder}</Descriptions.Item>
          <Descriptions.Item label={t('detail.completedAt')}>{detail?.completed_at ? formatDateTime(detail.completed_at, locale) : placeholder}</Descriptions.Item>
        </Descriptions>
        <section className="cache-operation-detail-section" aria-labelledby="cache-operation-progress-title">
          <h2 id="cache-operation-progress-title">{t('detail.progress')}</h2>
          {detail ? <CacheOperationOutcome operation={detail} /> : <span>{placeholder}</span>}
        </section>
        <section className="cache-operation-detail-section" aria-labelledby="cache-operation-targets-title">
          <h2 id="cache-operation-targets-title">{t('detail.targets')}</h2>
          <div className="identity-table-scroll">
            <Table<CacheOperationTarget>
              rowKey="ordinal"
              size="small"
              columns={operationTargetColumns}
              dataSource={detail?.targets ?? []}
              loading={detailQuery.isPending || detailQuery.isFetching}
              pagination={false}
              locale={{ emptyText: detailQuery.isPending ? ' ' : t('targetTypes.whole_site') }}
              scroll={{ x: 1410 }}
            />
          </div>
        </section>
        <section className="cache-operation-detail-section" aria-labelledby="cache-operation-nodes-title">
          <h2 id="cache-operation-nodes-title">{t('detail.nodes')}</h2>
          <div className="identity-table-scroll">
            <Table<CacheNodeProjection>
              rowKey="node_id"
              size="small"
              columns={nodeColumns}
              dataSource={detail?.nodes ?? []}
              loading={detailQuery.isPending || detailQuery.isFetching}
              pagination={false}
              locale={{ emptyText: detailQuery.isPending ? ' ' : t('values.noNodes') }}
              scroll={{ x: 980 }}
            />
          </div>
        </section>
        {detail?.state === 'failed' || detail?.state === 'partial_failed' ? (
          <Button
            type="primary"
            icon={<RotateCcw size={15} aria-hidden="true" />}
            disabled={!canManage || writesLocked}
            onClick={() => retryOperation(detail.id)}
          >
            {t('actions.retryFailed')}
          </Button>
        ) : null}
      </Drawer>
    </section>
  )
}

export default function CacheOperationsPage() {
  const { t } = useTranslation('cacheOperations')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken) return null

  const owner = cacheSessionOwner(
    principal?.scope_kind,
    principal?.scope_id,
    principal?.tenant_id,
    principal?.user_id,
    sessionEpoch,
  )
  const wildcard = principal?.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  const canRead = Boolean(wildcard || principal?.permissions.includes('sites.read'))
  if (!principal || !owner || !canRead) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  return (
    <CacheOperationsPageSession
      accessToken={accessToken}
      owner={owner}
      ownerKey={JSON.stringify(owner)}
      isAdmin={principal.scope_kind === 'platform'}
      canListTenants={principal.permissions.includes('identity.users.manage') || principal.permissions.includes('platform.admin')}
      canManage={Boolean(wildcard || principal.permissions.includes('sites.manage'))}
    />
  )
}
