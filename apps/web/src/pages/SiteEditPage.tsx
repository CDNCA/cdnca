import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { hashKey, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Result, Space, Tag, Tooltip } from 'antd'
import { ArrowLeft, ChevronLeft, ChevronRight } from 'lucide-react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import { writeOutcomeUnknown as hasUncertainWriteOutcome } from './site-edit/writeOutcome'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import {
  sitesApi,
  operationalSiteStatus,
  originForwarding,
  type PatchSiteBasicRequest,
  type PatchSiteOriginRequest,
  type SiteBasicConfig,
  type SiteDetail,
  type SiteOriginPool,
} from '../api/sites'
import { roleForPrincipal, useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/siteTLS'
import '../i18n/pluginUI'
import '../i18n/siteEditV4'
import './site-edit/SiteEditV4.css'
import './site-edit/SiteEditSyncStatus.css'
import { usePluginUIPages } from '../pluginui/usePluginUIPages'
import {
  canLeaveCurrentPage,
  unsavedChangesMessage,
  useNavigationGuardStore,
} from '../routes/navigationGuard'
import type { BasicValidationErrors } from './site-edit/siteEditValidation'
import { validateBasicConfig } from './site-edit/siteEditValidation'
import { retryableLazy, SiteEditTabBoundary } from './site-edit/SiteEditTabBoundary'
import SiteEditState from './site-edit/SiteEditState'
import { DataState } from '../components/DataState'
import {
  restoreSiteBatchRetry,
  siteBatchRetryStorageKey,
} from './siteBatchRetryLock'
import { OutcomeUnknown, FeedbackWhen } from '@cdnca/ui'
import { rebaseDraft, useCommitRequest, useInstantFeedback } from './site-edit/instantSave'
import { siteAccessGap } from './site-edit/cnameFailureText'
import { accessStatusLabel } from './site-edit/accessReadinessText'
import { SiteAccessReadinessCard } from './site-edit/SiteAccessReadiness'

const BasicSiteTab = retryableLazy(() => import('./site-edit/BasicSiteTab'))
const SiteTransferModal = retryableLazy(() => import('./site-edit/SiteTransferModal'))
const ConditionalOriginSiteTab = retryableLazy(() => import('./site-edit/ConditionalOriginSiteTab'))
const OriginSettingsTab = retryableLazy(() => import('./site-edit/OriginSettingsTab'))
const HttpsSiteTab = retryableLazy(() => import('./site-edit/HttpsSiteTab'))
const SiteCCTab = retryableLazy(() =>
  import('./site-edit/SiteProtectionTabs').then((module) => ({ default: module.SiteCCTab })),
)
const SiteWAFTab = retryableLazy(() =>
  import('./site-edit/SiteProtectionTabs').then((module) => ({ default: module.SiteWAFTab })),
)
const SiteAutoDefenseTab = retryableLazy(() => import('./site-edit/SiteAutoDefenseTab'))
const CacheSiteTab = retryableLazy(() => import('./site-edit/CacheSiteTab'))
const CacheStatusHeaderSwitch = retryableLazy(() => import('./site-edit/CacheStatusHeaderSwitch'))
const SitePluginTab = retryableLazy(() =>
  import('../pluginui/SitePluginTab').then((module) => ({ default: module.SitePluginTab })))
const SiteEdgeOptionsSection = retryableLazy(() => import('./site-edit/SiteEdgeOptionsSection'))
const AdvancedSiteTab = retryableLazy(() =>
  import('./site-edit/AdvancedSiteTab'),
)

type VisibleTabKey = 'basic' | 'origin' | 'https' | 'cache' | 'cc' | 'waf' | 'autodefense' | 'advanced'

// 悬停/聚焦标签时、页面空闲时提前下载该标签的分块，点下去不再等下载。
const tabChunks: Record<VisibleTabKey, { preload: () => void }[]> = {
  basic: [BasicSiteTab],
  origin: [OriginSettingsTab, ConditionalOriginSiteTab],
  https: [HttpsSiteTab],
  cache: [CacheSiteTab, CacheStatusHeaderSwitch],
  cc: [SiteCCTab],
  waf: [SiteWAFTab],
  autodefense: [SiteAutoDefenseTab],
  advanced: [AdvancedSiteTab, SiteEdgeOptionsSection],
}

function preloadTab(tab: VisibleTabKey) {
  for (const chunk of tabChunks[tab]) chunk.preload()
}
// 'extensions' (PA-19) is shown only when an enabled ui_page plugin mounts a site tab.
type TabKey = VisibleTabKey | 'extensions'
type SaveFeedback = 'idle' | 'validation' | 'conflict' | 'error'
type SitePermission = 'sites.read' | 'sites.manage' | 'dns.manage'
type SiteSessionOwner = readonly [
  Principal['scope_kind'],
  string,
  string | null,
  string,
  number,
]
type SaveAttempt = {
  ownerKey: string
  siteId: string
} & (
  | {
      section: 'basic'
      version: number
      changes: SiteBasicConfig
      idempotencyKey: string
      serializedBody: string
    }
  | {
      section: 'origin'
      version: number
      changes: SiteOriginPool
      idempotencyKey: string
      serializedBody: string
    }
)

interface StoredOriginAttempt {
  version: 1
  siteId: string
  idempotencyKey: string
  serializedBody: string
}

interface OriginAttemptState {
  attempt: SaveAttempt | null
  corrupted: boolean
  terminal: boolean
}

// CC/WAF 页的自动类功能集中到「自动防御」标签（?tab=autodefense）。
const tabs: VisibleTabKey[] = ['basic', 'origin', 'https', 'cache', 'cc', 'waf', 'autodefense', 'advanced']

const validTabs = new Set<TabKey>([...tabs, 'extensions'])

function normalizedSiteTab(value: string | null): TabKey {
  if (value === 'security') return 'cc'
  // 防盗链 / 跨域 used to be a ?tab=access sub-page; they now sit in 高级设置.
  if (value === 'access') return 'advanced'
  return value && validTabs.has(value as TabKey) ? value as TabKey : 'basic'
}
const staleSiteEditAttempt = new Error('stale site edit attempt')
const terminalOriginAttempts = new Set<string>()
const terminalOriginListeners = new Set<(identity: string) => void>()
// 当前已挂载的编辑页实例数，按站点详情 queryKey 计（同会话同站点）。
const liveSiteEditLineages = new Map<string, number>()

function terminalOriginAttemptIdentity(storageKey: string, idempotencyKey: string): string {
  return JSON.stringify([storageKey, idempotencyKey])
}

function markTerminalOriginAttempt(storageKey: string, idempotencyKey: string) {
  const identity = terminalOriginAttemptIdentity(storageKey, idempotencyKey)
  terminalOriginAttempts.add(identity)
  for (const listener of terminalOriginListeners) listener(identity)
}

function siteSessionOwner(principal: Principal, sessionEpoch: number): SiteSessionOwner | null {
  if (!principal.scope_id || !principal.user_id || !sessionEpoch) return null
  if (principal.scope_kind === 'tenant' && !principal.tenant_id) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
  ]
}

function sitePrincipalCan(principal: Principal, permission: SitePermission): boolean {
  return principal.permissions.includes(permission) || (
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  )
}

function currentSiteSessionAccess(
  ownerKey: string,
  permissions: readonly SitePermission[],
): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || permissions.some((permission) => !sitePrincipalCan(principal, permission))) {
    return null
  }
  const owner = siteSessionOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function isDirtyConfig(original: SiteBasicConfig, draft: SiteBasicConfig): boolean {
  return JSON.stringify(original) !== JSON.stringify(draft)
}

function cloneOriginPool(pool: SiteOriginPool): SiteOriginPool {
  return { ...pool, origins: pool.origins.map((origin) => ({ ...origin })) }
}

function validateOriginPool(pool: SiteOriginPool): string | null {
  if (pool.origins.length < 1 || pool.origins.length > 32) return 'edit.validation.originCount'
  const endpoints = new Set<string>()
  let enabled = 0
  for (const origin of pool.origins) {
    const host = origin.host.trim().toLowerCase()
    if (!host || host.length > 253 || /[\s[\]\\/?#@]/.test(host)) return 'edit.validation.originHost'
    if (!Number.isInteger(origin.port) || origin.port < 1 || origin.port > 65535) return 'edit.validation.originPort'
    if (!Number.isInteger(origin.weight) || origin.weight < 1 || origin.weight > 100) return 'edit.validation.originWeight'
    const endpoint = `${host}:${origin.port}`
    if (endpoints.has(endpoint)) return 'edit.validation.originDuplicate'
    endpoints.add(endpoint)
    if (origin.enabled) enabled += 1
    if ((origin.level ?? 0) > 15) return 'edit.validation.originCount'
  }
  if (enabled === 0) return 'edit.validation.originEnabled'
  if (!pool.origins.some((origin) => origin.enabled && (origin.level ?? 0) === 0)) return 'edit.validation.originEnabled'
  if (!Number.isInteger(pool.failover_tries) || pool.failover_tries < 1 || pool.failover_tries > enabled) {
    return 'edit.validation.failoverTries'
  }
  if (pool.connect_timeout_ms < 50 || pool.connect_timeout_ms > 30000) return 'edit.validation.connectTimeout'
  if (pool.read_timeout_ms < 100 || pool.read_timeout_ms > 300000) return 'edit.validation.readTimeout'
  const idle = pool.keepalive_idle_timeout_ms
  if (idle !== undefined && (!Number.isInteger(idle) || idle < 1000 || idle > 300000)) {
    return 'edit.validation.keepaliveIdleTimeout'
  }
  return null
}

function originRetryStorageKey(owner: SiteSessionOwner, siteId: string): string {
  return `cdnca:site-origin-retry:v1:${[
    owner[0], owner[1], owner[2] ?? 'null', owner[3], siteId,
  ].map(encodeURIComponent).join(':')}`
}

function restoreOriginAttempt(key: string | null, siteId: string, ownerKey: string): OriginAttemptState {
  if (!key) return { attempt: null, corrupted: false, terminal: false }
  try {
    const raw = sessionStorage.getItem(key)
    if (raw === null) return { attempt: null, corrupted: false, terminal: false }
    const stored = JSON.parse(raw) as StoredOriginAttempt | null
    if (!stored || stored.version !== 1 || stored.siteId !== siteId || !stored.idempotencyKey || !stored.serializedBody) {
      return { attempt: null, corrupted: true, terminal: false }
    }
    const body = JSON.parse(stored.serializedBody) as PatchSiteOriginRequest
    if (body.section !== 'origin' || !Number.isInteger(body.expected_version) || validateOriginPool(body.changes) !== null) {
      return { attempt: null, corrupted: true, terminal: false }
    }
    return {
      corrupted: false,
      terminal: terminalOriginAttempts.has(
        terminalOriginAttemptIdentity(key, stored.idempotencyKey),
      ),
      attempt: {
        ownerKey,
        siteId,
        section: 'origin',
        version: body.expected_version,
        changes: cloneOriginPool(body.changes),
        idempotencyKey: stored.idempotencyKey,
        serializedBody: stored.serializedBody,
      },
    }
  } catch {
    return { attempt: null, corrupted: true, terminal: false }
  }
}

function terminalSiteAuthorizationError(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 403 && (
    error.code === 'permission_denied' || error.code === 'forbidden'
  )
}

// Server-refused fields the basic / HTTPS tabs can mark in place (site.FieldError, details.field).
const inPlaceSiteFields = ['domains', 'http_listen_ports', 'https_listen_ports', 'origins'] as const

function serverFieldError(error: unknown): { field: (typeof inPlaceSiteFields)[number] } | null {
  if (!(error instanceof ApiError) || error.code !== 'validation_error' || !error.field) return null
  const field = inPlaceSiteFields.find((known) => known === error.field)
  return field ? { field } : null
}

function errorCodeMessage(error: ApiError, t: TFunction<['sites', 'siteTLS']>): string {
  switch (error.code) {
    case 'site_locked':
    case 'version_conflict':
    case 'permission_denied':
    case 'site_not_found':
    case 'network_error':
    case 'request_failed':
      return t(`edit.errors.${error.code}`)
    case 'validation_error':
      // The server names the refused field (error.details.field).
      if (error.field) {
        return localizedUnknownApiError(error, t(`edit.errors.fields.${error.field}`, {
          defaultValue: t('edit.errors.fieldInvalid', { field: error.field }),
        }))
      }
      return localizedUnknownApiError(error, t('edit.errors.request_failed'))
    default:
      return localizedUnknownApiError(error, t('edit.errors.request_failed'))
  }
}

function EditLoading() {
  const { t } = useTranslation('sites')
  return (
    <DataState className="site-edit-loading" status="loading" message={t('edit.loading')} />
  )
}

// A11 / WEB-C08: how long the first detail load may stay busy before the page
// says so and offers a re-read (GET only) and the way back to the list.
const siteEditSlowLoadMs = 15_000

// The page-level loading state, bounded: after siteEditSlowLoadMs it names the
// stage (request in flight, or details read but the form not started) and
// offers recovery. Writes are never retried from here.
function EditPageLoading({ stage, onReload, onBack }: {
  stage: 'fetching' | 'initializing'
  onReload: () => void
  onBack: () => void
}) {
  const { t } = useTranslation('sites')
  const [slow, setSlow] = useState(false)
  useEffect(() => {
    const timer = window.setTimeout(() => setSlow(true), siteEditSlowLoadMs)
    return () => window.clearTimeout(timer)
  }, [])
  return (
    <section className="site-edit-page" aria-busy={!slow}>
      <EditLoading />
      {slow ? (
        <Alert
          showIcon
          type="warning"
          role="alert"
          message={t('edit.errors.slowLoad.title')}
          description={t(`edit.errors.slowLoad.${stage}`)}
          action={(
            <Space direction="vertical">
              <Button size="small" type="primary" onClick={onReload}>{t('edit.errors.slowLoad.reload')}</Button>
              <Button size="small" onClick={onBack}>{t('edit.actions.back')}</Button>
            </Space>
          )}
        />
      ) : null}
    </section>
  )
}

function SiteEditForbidden() {
  const { t } = useTranslation('sites')
  return (
    <section className="site-edit-page">
      <SiteEditState status="forbidden" title={t('edit.errors.forbiddenTitle')} detail={t('edit.errors.permission_denied')} />
    </section>
  )
}

type SiteSyncStatus = 'synced' | 'pending' | 'failed'

const syncStatusTags = {
  synced: { color: 'success', stateKey: 'synced' },
  pending: { color: 'processing', stateKey: 'syncing' },
  failed: { color: 'error', stateKey: 'sync_failed' },
} as const

interface SiteEditPageContentProps {
  id: string
  principal: Principal
  accessToken: string
  owner: SiteSessionOwner
  ownerKey: string
  resetTab: boolean
  sessionEpoch: number
}

export default function SiteEditPage() {
  const { id = '' } = useParams()
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const previousIdentityRef = useRef<string | undefined>(undefined)

  if (!principal || !accessToken) return null
  const owner = siteSessionOwner(principal, sessionEpoch)
  if (!owner || !sitePrincipalCan(principal, 'sites.read')) return <SiteEditForbidden />
  const ownerKey = JSON.stringify(owner)
  const lineageKey = JSON.stringify([owner, id])
  const resetTab = previousIdentityRef.current !== undefined &&
    previousIdentityRef.current !== lineageKey
  previousIdentityRef.current = lineageKey
  return (
    <SiteEditPageContent
      key={lineageKey}
      id={id}
      principal={principal}
      accessToken={accessToken}
      owner={owner}
      ownerKey={ownerKey}
      resetTab={resetTab}
      sessionEpoch={sessionEpoch}
    />
  )
}

function SiteEditPageContent({
  id,
  principal,
  accessToken,
  owner,
  ownerKey,
  resetTab,
  sessionEpoch,
}: SiteEditPageContentProps) {
  const { t, i18n } = useTranslation(['sites', 'siteTLS', 'pluginUI'])
  const instantFeedback = useInstantFeedback()
  const { t: tV4 } = useTranslation('siteEditV4')
  const { t: tAccess } = useTranslation('siteAccessReadiness')
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [transferOpen, setTransferOpen] = useState(false)
  const { message } = App.useApp()
  const setNavigationDirty = useNavigationGuardStore((state) => state.setDirty)
  const role = roleForPrincipal(principal)
  const queryOwner = useRef(owner).current
  const canManage = sitePrincipalCan(principal, 'sites.manage')
  const canManageDNS = sitePrincipalCan(principal, 'dns.manage')
  const retryStorageKey = `${siteBatchRetryStorageKey(queryOwner[0], queryOwner[1])}:${
    encodeURIComponent(queryOwner[2] ?? 'null')
  }:${encodeURIComponent(queryOwner[3])}`
  const originStorageKey = originRetryStorageKey(queryOwner, id)
  const recoveredOrigin = useMemo(
    () => restoreOriginAttempt(originStorageKey, id, ownerKey),
    [id, originStorageKey, ownerKey],
  )
  const recoveredAttempt = recoveredOrigin.attempt
  const batchRetryLock = useMemo(
    () => restoreSiteBatchRetry(retryStorageKey),
    [retryStorageKey],
  )
  const batchWriteLocked = batchRetryLock.attempt !== null || batchRetryLock.corrupted
  const activeTab = normalizedSiteTab(searchParams.get('tab'))
  const pluginPages = usePluginUIPages(accessToken, { cachedOnly: true })
  const sitePluginPages = useMemo(() => pluginPages.filter((page) => page.mount === 'site_tab'), [pluginPages])
  // SITE-CURRENT-02：标签首次访问后保持挂载（草稿、未知请求、已加载数据都留着），
  // 再切回来不重建、不重新请求。“已访问”按 URL 的 ?tab= 推导：标签内按钮直接改 ?tab=
  // （如基本配置里的「HTTPS设置」）时面板也必须挂载，不能只靠标签栏的 setTab 记录。
  const [visitedTabs, setVisitedTabs] = useState<ReadonlySet<TabKey>>(() => new Set([activeTab]))
  if (!visitedTabs.has(activeTab)) setVisitedTabs(new Set([...visitedTabs, activeTab]))
  const tabMounted = (tab: TabKey) => tab === activeTab || visitedTabs.has(tab)
  useEffect(() => {
    // 首屏渲染完后趁空闲逐个下载其余标签的分块（每次空闲只取一个，不抢首屏）。
    const pending = [...tabs]
    let handle = 0
    const idle = (run: () => void) => typeof window.requestIdleCallback === 'function'
      ? window.requestIdleCallback(run, { timeout: 3000 })
      : window.setTimeout(run, 300)
    const cancel = (value: number) => typeof window.cancelIdleCallback === 'function'
      ? window.cancelIdleCallback(value)
      : window.clearTimeout(value)
    const next = () => {
      const tab = pending.shift()
      if (!tab) return
      preloadTab(tab)
      handle = idle(next)
    }
    handle = idle(next)
    return () => cancel(handle)
  }, [])
  const [cacheWriteState, setCacheWriteState] = useState({
    dirty: false,
    uncertain: false,
    pending: false,
  })
  const [httpsWriteState, setHttpsWriteState] = useState({
    dirty: false,
    uncertain: false,
    pending: false,
  })
  const [conditionalWriteState, setConditionalWriteState] = useState({
    dirty: false,
    uncertain: false,
    pending: false,
  })
  const tabScrollRef = useRef<HTMLDivElement>(null)
  const restoringHistoryRef = useRef(false)
  const lineageActiveRef = useRef(true)
  const saveAttemptRef = useRef<SaveAttempt | null>(recoveredAttempt)
  const [detail, setDetail] = useState<SiteDetail | null>(null)
  const [draft, setDraft] = useState<SiteBasicConfig | null>(null)
  const [originDraft, setOriginDraft] = useState<SiteOriginPool | null>(null)
  const [errors, setErrors] = useState<BasicValidationErrors>({})
  const [originError, setOriginError] = useState<string>()
  const [feedback, setFeedback] = useState<SaveFeedback>('idle')
  const [feedbackMessage, setFeedbackMessage] = useState('')
  // UX-03: a failed field check bumps this; the effect below moves focus to
  // the first marked field instead of opening a dialog over the form.
  const [focusErrorRequest, setFocusErrorRequest] = useState(0)
  // The reason of a server-refused field marked in place.
  const serverFieldMessage = useRef<string | null>(null)
  const [originRecoveryPending, setOriginRecoveryPending] = useState(false)
  const [terminalForbidden, setTerminalForbidden] = useState(recoveredOrigin.terminal)
  const [uncertainWrite, setUncertainWrite] = useState(
    !recoveredOrigin.terminal && (Boolean(recoveredAttempt) || recoveredOrigin.corrupted),
  )
  const detailQueryKey = useMemo(
    () => ['site-detail', queryOwner, id] as const,
    [id, queryOwner],
  )
  const saveMutationKey = useMemo(
    () => ['site-edit-save', queryOwner, id] as const,
    [id, queryOwner],
  )
  const currentSessionMatchesLineage = useCallback(() => {
    return lineageActiveRef.current && Boolean(currentSiteSessionAccess(ownerKey, ['sites.read']))
  }, [ownerKey])

  const attemptMatchesLiveReader = useCallback((attempt: SaveAttempt) => {
    return attempt.ownerKey === ownerKey && attempt.siteId === id && currentSessionMatchesLineage()
  }, [currentSessionMatchesLineage, id, ownerKey])

  const removeLineageCache = useCallback(() => {
    queryClient.removeQueries({ queryKey: detailQueryKey, exact: true })
    const mutationCache = queryClient.getMutationCache()
    for (const mutation of mutationCache.findAll({ mutationKey: saveMutationKey, exact: true })) {
      mutationCache.remove(mutation)
    }
  }, [detailQueryKey, queryClient, saveMutationKey])

  useEffect(() => {
    if (resetTab) setSearchParams({}, { replace: true })
  }, [resetTab, setSearchParams])

  useEffect(() => {
    lineageActiveRef.current = true
    const lineage = JSON.stringify(detailQueryKey)
    liveSiteEditLineages.set(lineage, (liveSiteEditLineages.get(lineage) ?? 0) + 1)
    return () => {
      lineageActiveRef.current = false
      const remaining = (liveSiteEditLineages.get(lineage) ?? 1) - 1
      if (remaining > 0) liveSiteEditLineages.set(lineage, remaining)
      else liveSiteEditLineages.delete(lineage)
      if (!currentSiteSessionAccess(ownerKey, ['sites.read'])) {
        removeLineageCache()
        return
      }
      // 同一会话、同一站点的新实例若已挂载（父级重挂载），不能删它正在用的 query：
      // removeQueries 会静默取消请求，新实例会永远停在加载中。
      queueMicrotask(() => {
        if (!lineageActiveRef.current && !liveSiteEditLineages.has(lineage)) removeLineageCache()
      })
    }
  }, [detailQueryKey, ownerKey, removeLineageCache])

  const query = useQuery({
    queryKey: terminalForbidden
      ? ['site-detail-terminal', queryOwner, id]
      : detailQueryKey,
    queryFn: async () => {
      const token = currentSiteSessionAccess(ownerKey, ['sites.read'])
      if (!token) throw staleSiteEditAttempt
      try {
        const result = await sitesApi.detail(token, id)
        if (!currentSessionMatchesLineage()) throw staleSiteEditAttempt
        return result
      } catch (error) {
        if (!currentSessionMatchesLineage()) throw staleSiteEditAttempt
        throw error
      }
    },
    enabled: Boolean(id) && !terminalForbidden,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const refetchDetail = query.refetch

  // 页面还在用时，详情 query 被别处的缓存清理删掉（removeQueries 会静默取消进行中的请求，
  // 状态永远停在 fetching），就按当前 key 重新拉一次，不让页面无限加载。
  useEffect(() => {
    if (terminalForbidden || !id) return
    const detailHash = hashKey(detailQueryKey)
    return queryClient.getQueryCache().subscribe((event) => {
      if (event.type !== 'removed' || event.query.queryHash !== detailHash) return
      if (!lineageActiveRef.current || !currentSessionMatchesLineage()) return
      queueMicrotask(() => {
        if (lineageActiveRef.current && currentSessionMatchesLineage()) void refetchDetail()
      })
    })
  }, [currentSessionMatchesLineage, detailQueryKey, id, queryClient, refetchDetail, terminalForbidden])

  // A11: a "reload" from the slow-loading state re-runs the initialization
  // below even when the query data did not change.
  const [initRequest, setInitRequest] = useState(0)
  useEffect(() => {
    if (query.data && !detail && currentSessionMatchesLineage()) {
      setDetail(query.data)
      setDraft(query.data.basic)
      setOriginDraft(
        recoveredAttempt?.section === 'origin'
          ? cloneOriginPool(recoveredAttempt.changes)
          : cloneOriginPool(query.data.origin_pool),
      )
      if (recoveredAttempt || recoveredOrigin.corrupted) {
        setFeedback('error')
        setFeedbackMessage(
          recoveredOrigin.corrupted
            ? t('edit.feedback.originRecoveryFailed')
            : t('edit.feedback.originOutcomeUnknown'),
        )
      }
    }
  }, [
    currentSessionMatchesLineage,
    detail,
    initRequest,
    query.data,
    recoveredAttempt,
    recoveredOrigin.corrupted,
    t,
  ])

  // A save publishes by itself (automatic publication); the header
  // shows the site's delivery state (sync_status) and re-reads it every 5 s
  // while it is pending, so no manual publish step is needed.
  // 10-27 用户：保存后（版本号比打开时新）自动发布刚排队，保存回包里的 sync_status
  // 还是旧的"已同步"——此时先显示待同步并按 5 秒重读，直到服务端给出结果。
  const openedVersion = useRef<number | undefined>(undefined)
  if (detail && openedVersion.current === undefined) openedVersion.current = detail.version
  const savedSinceOpen = Boolean(detail) && openedVersion.current !== undefined && (detail?.version ?? 0) > openedVersion.current
  const savedSyncStatus = savedSinceOpen && detail?.basic.sync_status === 'synced' ? 'pending' : detail?.basic.sync_status
  const syncQuery = useQuery({
    queryKey: ['site-sync-status', queryOwner, id, detail?.version],
    queryFn: async () => {
      const token = currentSiteSessionAccess(ownerKey, ['sites.read'])
      if (!token) throw staleSiteEditAttempt
      return (await sitesApi.detail(token, id))?.basic.sync_status ?? null
    },
    enabled: savedSyncStatus === 'pending' && !terminalForbidden,
    // The detail just read is the first sample; the next read waits one interval.
    initialData: 'pending' as SiteSyncStatus | null,
    staleTime: 5_000,
    refetchInterval: (state) => (state.state.data ?? 'pending') === 'pending' ? 5_000 : false,
    refetchOnWindowFocus: false,
    retry: false,
  })
  const syncStatus = savedSyncStatus === 'pending' ? (syncQuery.data ?? 'pending') : savedSyncStatus
  // WEB/FLOW-STATE-01: a failed read is not a node failure and not "pending";
  // the last known state stays, the header says the read failed and offers a retry.
  const syncReadFailed = savedSyncStatus === 'pending' && syncQuery.isError
  const publicationsPath = principal.scope_kind === 'platform' && detail?.scope_id
    ? `/site/publications?target_scope_id=${encodeURIComponent(detail.scope_id)}` : '/site/publications'
  // 10-27 用户：待同步时显示"N秒后刷新"，从 5 倒数到下一次重读。
  const [syncNow, setSyncNow] = useState(() => Date.now())
  useEffect(() => {
    if (syncStatus !== 'pending' || syncReadFailed) return
    const timer = window.setInterval(() => setSyncNow(Date.now()), 1_000)
    return () => window.clearInterval(timer)
  }, [syncStatus, syncReadFailed])
  const syncReadAt = syncQuery.dataUpdatedAt || syncNow
  const syncSecondsLeft = Math.min(5, Math.max(1, Math.ceil((syncReadAt + 5_000 - syncNow) / 1_000)))

  const basicDirty = useMemo(
    () => Boolean(detail && draft && isDirtyConfig(detail.basic, draft)),
    [detail, draft],
  )
  const originDirty = useMemo(
    () => Boolean(detail && originDraft && JSON.stringify(detail.origin_pool) !== JSON.stringify(originDraft)),
    [detail, originDraft],
  )
  const configDirty = basicDirty || originDirty || uncertainWrite

  useEffect(() => {
    if (focusErrorRequest === 0) return
    const page = document.querySelector('.site-edit-page')
    // 已访问的标签隐藏挂载着：只认当前可见面板里的标记字段。
    const marked = [...(page?.querySelectorAll<HTMLElement>('.ant-input-status-error input, input.ant-input-status-error, textarea.ant-input-status-error, .site-field-error') ?? [])]
      .find((element) => !element.closest('[hidden]'))
    const serverMessage = serverFieldMessage.current
    serverFieldMessage.current = null
    if (!marked) {
      // The marked field is on another tab: keep the old summary dialog
      // (a server refusal keeps its own reason).
      setFeedback(serverMessage ? 'error' : 'validation')
      setFeedbackMessage(serverMessage ?? t(originError ? 'edit.feedback.checkOrigin' : 'edit.feedback.checkFields'))
      return
    }
    // A server refusal arrives after the user moved on: bring its field into view.
    if (serverMessage) marked.scrollIntoView?.({ block: 'center' })
    // The check runs on blur, so focus stays where the user moved it.
  }, [focusErrorRequest]) // eslint-disable-line react-hooks/exhaustive-deps
  const cacheDirty = cacheWriteState.dirty || cacheWriteState.uncertain || cacheWriteState.pending
  const httpsDirty = httpsWriteState.dirty || httpsWriteState.uncertain || httpsWriteState.pending
  const conditionalDirty = conditionalWriteState.dirty || conditionalWriteState.uncertain || conditionalWriteState.pending
  const dirty = configDirty || cacheDirty || httpsDirty || conditionalDirty

  useEffect(() => {
    setNavigationDirty(dirty)
    return () => setNavigationDirty(false)
  }, [dirty, setNavigationDirty])

  useEffect(() => {
    if (!dirty) return
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    const onPopState = () => {
      if (restoringHistoryRef.current) {
        restoringHistoryRef.current = false
        return
      }
      if (!window.confirm(unsavedChangesMessage())) {
        restoringHistoryRef.current = true
        window.history.forward()
      }
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    window.addEventListener('popstate', onPopState)
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload)
      window.removeEventListener('popstate', onPopState)
    }
  }, [dirty])

  const clearSaveAttempt = (attempt?: SaveAttempt): boolean => {
    const currentAttempt = saveAttemptRef.current
    if (attempt && currentAttempt?.idempotencyKey !== attempt.idempotencyKey) return false
    if (currentAttempt?.section === 'origin' && originStorageKey) {
      try {
        sessionStorage.removeItem(originStorageKey)
      } catch {
        setUncertainWrite(true)
        setFeedback('error')
        setFeedbackMessage(t('edit.feedback.originRetryClearFailed'))
        return false
      }
    }
    saveAttemptRef.current = null
    setUncertainWrite(false)
    return true
  }

  const denyCurrentLineage = useCallback((attempt: SaveAttempt) => {
    lineageActiveRef.current = false
    if (attempt.section === 'origin' && originStorageKey) {
      const terminalIdentity = terminalOriginAttemptIdentity(
        originStorageKey,
        attempt.idempotencyKey,
      )
      let invalidated = false
      try {
        sessionStorage.removeItem(originStorageKey)
        invalidated = true
      } catch {
        try {
          sessionStorage.setItem(originStorageKey, '{}')
          invalidated = true
        } catch {
          // The current lineage remains terminal even when browser storage is unavailable.
        }
      }
      if (invalidated) terminalOriginAttempts.delete(terminalIdentity)
    }
    saveAttemptRef.current = null
    setDetail(null)
    setDraft(null)
    setOriginDraft(null)
    setErrors({})
    setOriginError(undefined)
    setFeedback('idle')
    setFeedbackMessage('')
    setUncertainWrite(false)
    setCacheWriteState({ dirty: false, uncertain: false, pending: false })
    setHttpsWriteState({ dirty: false, uncertain: false, pending: false })
    setConditionalWriteState({ dirty: false, uncertain: false, pending: false })
    setNavigationDirty(false)
    setTerminalForbidden(true)
    queueMicrotask(removeLineageCache)
  }, [originStorageKey, removeLineageCache, setNavigationDirty])

  useEffect(() => {
    const settle = (identity: string) => {
      const attempt = saveAttemptRef.current
      if (
        attempt?.section === 'origin' &&
        identity === terminalOriginAttemptIdentity(originStorageKey, attempt.idempotencyKey)
      ) {
        denyCurrentLineage(attempt)
      }
    }
    terminalOriginListeners.add(settle)
    const attempt = saveAttemptRef.current
    if (attempt?.section === 'origin') {
      const identity = terminalOriginAttemptIdentity(originStorageKey, attempt.idempotencyKey)
      if (terminalOriginAttempts.has(identity)) settle(identity)
    }
    return () => {
      terminalOriginListeners.delete(settle)
    }
  }, [denyCurrentLineage, originStorageKey])

  const detailRef = useRef<SiteDetail | null>(null)
  detailRef.current = detail
  const revertDrafts = () => {
    const stored = detailRef.current
    if (!stored) return
    setDraft(stored.basic)
    setOriginDraft(cloneOriginPool(stored.origin_pool))
    setErrors({})
    setOriginError(undefined)
  }
  const revertAttempt = (attempt: SaveAttempt) => {
    const stored = detailRef.current
    if (!stored) return
    if (attempt.section === 'basic') {
      setDraft((current) => current ? rebaseDraft(stored.basic, current, attempt.changes) : stored.basic)
      setErrors({})
    } else {
      // the origin pool is one value: kept only when edited after sending
      setOriginDraft((current) => current && JSON.stringify(current) !== JSON.stringify(attempt.changes)
        ? current : cloneOriginPool(stored.origin_pool))
      setOriginError(undefined)
    }
  }
  const reloadServerValues = (attempt: SaveAttempt) => {
    revertDrafts()
    const token = currentSiteSessionAccess(attempt.ownerKey, ['sites.read'])
    if (!token) return
    void sitesApi
      .detail(token, attempt.siteId)
      .then((latest) => {
        if (!latest || !attemptMatchesLiveReader(attempt)) return
        setDetail(latest)
        setDraft(latest.basic)
        setOriginDraft(cloneOriginPool(latest.origin_pool))
        setErrors({})
        setOriginError(undefined)
        queryClient.setQueryData(detailQueryKey, latest)
      })
      .catch(() => undefined)
  }

  const saveMutation = useMutation({
    mutationKey: saveMutationKey,
    mutationFn: async (input: SaveAttempt) => {
      const token = input.ownerKey === ownerKey && input.siteId === id
        ? currentSiteSessionAccess(input.ownerKey, ['sites.read', 'sites.manage'])
        : null
      if (!token || !lineageActiveRef.current) throw staleSiteEditAttempt
      try {
        const saved = input.section === 'origin'
          ? await sitesApi.patchOrigin(
              token,
              input.siteId,
              { expected_version: input.version, section: 'origin', changes: input.changes },
              input.idempotencyKey,
              input.serializedBody,
            )
          : await sitesApi.patchBasic(
              token,
              input.siteId,
              { expected_version: input.version, section: 'basic', changes: input.changes },
              input.idempotencyKey,
              input.serializedBody,
            )
        if (!attemptMatchesLiveReader(input)) throw staleSiteEditAttempt
        return saved
      } catch (error) {
        if (input.section === 'origin' && terminalSiteAuthorizationError(error)) {
          markTerminalOriginAttempt(originStorageKey, input.idempotencyKey)
        }
        if (!attemptMatchesLiveReader(input)) throw staleSiteEditAttempt
        throw error
      }
    },
    onSuccess: (saved, attempt) => {
      if (!attemptMatchesLiveReader(attempt)) return
      // Edits made while the save ran stay in the drafts (and
      // are saved next); everything else takes the saved values.
      const previous = detailRef.current
      setDetail(saved)
      if (attempt.section === 'basic') {
        setDraft((current) => current ? rebaseDraft(saved.basic, current, attempt.changes as SiteBasicConfig) : saved.basic)
        setOriginDraft((current) => !current || !previous || JSON.stringify(current) === JSON.stringify(previous.origin_pool)
          ? cloneOriginPool(saved.origin_pool) : current)
      } else {
        setOriginDraft((current) => current && JSON.stringify(current) !== JSON.stringify(attempt.changes)
          ? current : cloneOriginPool(saved.origin_pool))
        setDraft((current) => !current || !previous || JSON.stringify(current) === JSON.stringify(previous.basic) ? saved.basic : current)
      }
      setErrors({})
      setOriginError(undefined)
      queryClient.setQueryData(detailQueryKey, saved)
      if (!clearSaveAttempt(attempt)) return
      // UX-04: a save success is the light 操作成功 toast.
      setFeedback('idle')
      instantFeedback.success()
      commits.request()
    },
    onError: (error: unknown, attempt) => {
      if (error === staleSiteEditAttempt || !attemptMatchesLiveReader(attempt)) return
      if (terminalSiteAuthorizationError(error)) {
        denyCurrentLineage(attempt)
        return
      }
      if (error instanceof ApiError && error.status === 409 && error.code === 'site_locked') {
        if (!clearSaveAttempt(attempt)) return
        setFeedback('error')
        setFeedbackMessage(t('edit.feedback.siteLocked'))
        reloadServerValues(attempt)
        return
      }
      if (error instanceof ApiError && error.status === 409 && error.code === 'version_conflict') {
        // A conflict loads the latest values and says so.
        if (!clearSaveAttempt(attempt)) return
        setFeedback('idle')
        instantFeedback.warning(tV4('instant.conflict'))
        reloadServerValues(attempt)
        return
      }
      const uncertain = hasUncertainWriteOutcome(error)
      if (!uncertain && !clearSaveAttempt(attempt)) return
      setUncertainWrite(uncertain)
      // A refused field this page shows is marked on it (the
      // controls go back to the saved values, the reason stays under the
      // field); the focus check falls back to the dialog when it is on a
      // hidden tab.
      const pinned = !uncertain ? serverFieldError(error) : null
      if (pinned) {
        // Under the field only the reason; the dialog fallback keeps the request ID.
        const text = t(`edit.errors.fields.${pinned.field}`)
        revertDrafts()
        if (pinned.field === 'origins') setOriginError(text)
        else setErrors({ [pinned.field]: text })
        serverFieldMessage.current = errorCodeMessage(error as ApiError, t)
        setFeedback('idle')
        setFocusErrorRequest((request) => request + 1)
        return
      }
      setFeedback('error')
      setFeedbackMessage(
        error instanceof ApiError
          ? errorCodeMessage(error, t)
          : t('edit.feedback.saveFailed'),
      )
      // A refusal puts back only what this attempt sent (CFG-DRAFT-01):
      // fields changed after it was sent and the other section's draft stay
      // (they are not saved yet); an unknown outcome keeps the draft for the
      // exact retry.
      if (!uncertain) revertAttempt(attempt)
    },
  })

  const apiError = query.error instanceof ApiError ? query.error : null
  const forbidden = terminalForbidden || apiError?.status === 403 || apiError?.code === 'permission_denied'
  const notFound = apiError?.status === 404 || apiError?.code === 'site_not_found'

  const setTab = (tab: TabKey) => {
    setFeedback('idle')
    if (tab === 'basic') setSearchParams({}, { replace: true })
    else setSearchParams({ tab }, { replace: true })
  }

  // A change is saved at once (typed fields on blur / Enter).
  const updateDraft = (value: SiteBasicConfig) => {
    if (!canManage || uncertainWrite || batchWriteLocked) return
    setDraft(value)
    setErrors({})
    setFeedback('idle')
    commits.requestUnlessTyping()
  }

  const updateOriginDraft = (value: SiteOriginPool) => {
    if (!canManage || uncertainWrite || batchWriteLocked) return
    setOriginDraft(cloneOriginPool(value))
    setOriginError(undefined)
    setFeedback('idle')
    commits.requestUnlessTyping()
  }

  const retrySameRequest = () => {
    if (!currentSiteSessionAccess(ownerKey, ['sites.read', 'sites.manage'])) return
    if (uncertainWrite && saveAttemptRef.current && !saveMutation.isPending) saveMutation.mutate(saveAttemptRef.current)
  }

  // One section per request (basic first); the other is saved after it.
  const saveChanges = () => {
    if (
      !currentSiteSessionAccess(ownerKey, ['sites.read', 'sites.manage']) ||
      !detail || !draft || !originDraft || !canManage || uncertainWrite || saveMutation.isPending ||
      batchWriteLocked || httpsWriteState.pending || httpsWriteState.uncertain ||
      (role === 'user' && detail.lock.locked) || (!basicDirty && !originDirty)
    ) return
    if (basicDirty) {
      const nextErrors = validateBasicConfig(draft, t)
      if (Object.keys(nextErrors).length > 0) {
        // Marked in place; nothing is sent until the value is fixed.
        setErrors(nextErrors)
        setFocusErrorRequest((request) => request + 1)
        return
      }
      const changes: SiteBasicConfig = {
        ...draft,
        domains: [...draft.domains],
        http_listen_ports: [...draft.http_listen_ports],
        https_listen_ports: [...draft.https_listen_ports],
        tls_protocols: [...(draft.tls_protocols ?? [])],
        origins: [...draft.origins],
      }
      const request: PatchSiteBasicRequest = {
        expected_version: detail.version,
        section: 'basic',
        changes,
      }
      const attempt: SaveAttempt = {
        ownerKey,
        siteId: id,
        section: 'basic',
        version: detail.version,
        changes,
        idempotencyKey: crypto.randomUUID(),
        serializedBody: JSON.stringify(request),
      }
      saveAttemptRef.current = attempt
      saveMutation.mutate(attempt)
      return
    }

    const changes = cloneOriginPool(originDraft)
    changes.origins = changes.origins.map((origin) => ({ ...origin, host: origin.host.trim() }))
    const nextOriginError = validateOriginPool(changes)
    if (nextOriginError) {
      setOriginError(t(nextOriginError))
      setFocusErrorRequest((request) => request + 1)
      return
    }
    const request: PatchSiteOriginRequest = {
      expected_version: detail.version,
      section: 'origin',
      changes,
    }
    const attempt: SaveAttempt = {
      ownerKey,
      siteId: id,
      section: 'origin',
      version: detail.version,
      changes,
      idempotencyKey: crypto.randomUUID(),
      serializedBody: JSON.stringify(request),
    }
    if (!originStorageKey) {
      setFeedback('error')
      setFeedbackMessage(t('edit.feedback.originRecoveryUnavailable'))
      return
    }
    const stored: StoredOriginAttempt = {
      version: 1,
      siteId: id,
      idempotencyKey: attempt.idempotencyKey,
      serializedBody: attempt.serializedBody,
    }
    try {
      sessionStorage.setItem(originStorageKey, JSON.stringify(stored))
    } catch {
      setFeedback('error')
      setFeedbackMessage(t('edit.feedback.originCredentialsNotSaved'))
      return
    }
    setOriginDraft(changes)
    saveAttemptRef.current = attempt
    saveMutation.mutate(attempt)
  }

  // Edits wait while a save runs or a batch/HTTPS write is unsettled; the
  // latest drafts are saved after it (fast repeated edits send the last value).
  const commits = useCommitRequest(saveChanges, saveMutation.isPending || httpsWriteState.pending)

  const reloadLatest = async () => {
    if (dirty && !window.confirm(t('edit.confirm.reloadDiscard'))) return
    const result = await query.refetch()
    if (result.data && currentSessionMatchesLineage()) {
      setDetail(result.data)
      setDraft(result.data.basic)
      setOriginDraft(cloneOriginPool(result.data.origin_pool))
      setErrors({})
      setOriginError(undefined)
      setFeedback('idle')
    }
  }

  const blockAction = (action: string) => {
    setFeedback('error')
    setFeedbackMessage(t('edit.unavailable', { action }))
  }

  const recoverCorruptedOriginAttempt = async () => {
    if (!originStorageKey || originRecoveryPending) return
    const token = currentSiteSessionAccess(ownerKey, ['sites.read'])
    if (!token) return
    setOriginRecoveryPending(true)
    let latest: SiteDetail | null
    try {
      latest = await sitesApi.detail(token, id)
    } catch {
      if (!currentSessionMatchesLineage()) return
      setFeedback('error')
      setFeedbackMessage(t('edit.feedback.latestLoadFailed'))
      setOriginRecoveryPending(false)
      return
    }
    if (!currentSessionMatchesLineage()) return
    if (!latest) {
      setFeedback('error')
      setFeedbackMessage(t('edit.feedback.latestMissing'))
      setOriginRecoveryPending(false)
      return
    }
    try {
      sessionStorage.removeItem(originStorageKey)
    } catch {
      setFeedback('error')
      setFeedbackMessage(t('edit.feedback.corruptedClearFailed'))
      setOriginRecoveryPending(false)
      return
    }
    setDetail(latest)
    setDraft(latest.basic)
    setOriginDraft(cloneOriginPool(latest.origin_pool))
    setErrors({})
    setOriginError(undefined)
    saveAttemptRef.current = null
    setUncertainWrite(false)
    setFeedback('idle')
    void message.success(t('edit.feedback.corruptedCleared'))
    queryClient.setQueryData(detailQueryKey, latest)
    setOriginRecoveryPending(false)
  }

  const renderFeedback = () => {
    if (feedback === 'idle') return null
    if (feedback === 'conflict') {
      return (
        <FeedbackWhen
          type="warning"
          title={t('edit.feedback.conflictTitle')}
          detail={feedbackMessage}
          action={<Button size="small" onClick={() => void reloadLatest()}>{t('edit.actions.loadLatest')}</Button>}
        />
      )
    }
    return (
      <FeedbackWhen
        type={feedback === 'validation' ? 'warning' : 'error'}
        title={feedbackMessage}
        action={
          recoveredOrigin.corrupted && uncertainWrite && !saveAttemptRef.current ? (
            <Button
              size="small"
              loading={originRecoveryPending}
              onClick={() => void recoverCorruptedOriginAttempt()}
            >
              {t('edit.actions.loadLatest')}
            </Button>
          ) : null
        }
      />
    )
  }

  if (forbidden) {
    return (
      <section className="site-edit-page">
        <SiteEditState status="forbidden" title={t('edit.errors.forbiddenTitle')} detail={t('edit.errors.permission_denied')} />
      </section>
    )
  }

  // 只有请求真的在进行中才显示加载；请求被取消或暂停（pending 但 fetchStatus 不是 fetching）
  // 不会再有结果，落到下面的错误态给出重试，不无限转圈。
  if (query.isPending && query.fetchStatus === 'fetching') {
    return (
      <EditPageLoading
        key="fetching"
        stage="fetching"
        // The hanging read is cancelled first: without data, a refetch would
        // only join it. Only this page's own detail query is touched.
        onReload={() => {
          void queryClient.cancelQueries({ queryKey: detailQueryKey, exact: true })
            .then(() => { if (currentSessionMatchesLineage()) void query.refetch() })
        }}
        onBack={() => navigate('/site/list')}
      />
    )
  }

  if (notFound) {
    return (
      <section className="site-edit-page">
        <Result
          status="404"
          title={t('edit.errors.site_not_found')}
          extra={<Button onClick={() => navigate('/site/list')}>{t('edit.actions.back')}</Button>}
        />
      </section>
    )
  }

  if (query.isError || query.isPending) {
    return (
      <section className="site-edit-page">
        <SiteEditState
          status="error"
          title={t('edit.errors.loadFailed')}
          detail={apiError ? errorCodeMessage(apiError, t) : t('edit.errors.request_failed')}
          onRetry={() => void query.refetch()}
        />
      </section>
    )
  }

  if (query.data === null) {
    return (
      <section className="site-edit-page site-edit-empty">
        <SiteEditState status="empty" title={t('edit.errors.empty')} />
      </section>
    )
  }

  if (!detail || !draft || !originDraft) {
    return (
      <EditPageLoading
        key="initializing"
        stage="initializing"
        onReload={() => {
          setInitRequest((value) => value + 1)
          void query.refetch()
        }}
        onBack={() => navigate('/site/list')}
      />
    )
  }

  const lockedForTenant = role === 'user' && detail.lock.locked
  const statusState = operationalSiteStatus({
    status: detail.basic.status,
    status_state: detail.status_state,
    lock: detail.lock,
  })
  const statusTranslationKey = statusState === 'normal' ? 'active' : statusState
  const accessGap = siteAccessGap({ ...detail.basic, https_certificate_bound: detail.https_certificate_bound })
  const lockDescription = [
    detail.lock.reason,
    detail.lock.operator?.display_name
      ? t('edit.lock.operator', { name: detail.lock.operator.display_name })
      : null,
    detail.lock.locked_at
      ? t('edit.lock.lockedAt', {
          date: formatDateTime(detail.lock.locked_at, i18n.resolvedLanguage),
        })
      : null,
  ]
    .filter(Boolean)
    .join(i18n.resolvedLanguage === 'en-US' ? '; ' : '；')

  return (
    <section className="site-edit-page site-edit-v4" aria-labelledby="site-edit-title" {...commits.typingProps}>
      <header className="site-edit-header site-edit-title-row">
        <Button
          className="site-edit-back"
          type="text"
          aria-label={t('edit.actions.back')}
          icon={<ArrowLeft size={19} aria-hidden="true" />}
          onClick={() => {
            if (canLeaveCurrentPage()) navigate('/site/list')
          }}
        />
        <h1 id="site-edit-title">{draft.domains[0] || detail.id}</h1>
        <Tag color={statusState === 'normal' ? 'success' : statusState === 'locked' ? 'error' : 'warning'}>
          {t(`states.${statusTranslationKey}`)}
        </Tag>
        {syncStatus ? (
          <span data-testid="site-edit-sync-status" role="status" aria-live="polite"
            className={`site-edit-sync-status is-${syncStatus}`}>
            <span className="site-edit-sync-dot" aria-hidden="true" />
            {syncReadFailed
              ? t('states.syncReadFailed', { time: formatDateTime(new Date(Math.max(syncQuery.dataUpdatedAt, query.dataUpdatedAt)).toISOString(), i18n.resolvedLanguage) })
              : syncStatus === 'pending'
                ? t('states.syncPendingCountdown', { seconds: syncSecondsLeft })
                : t(`states.${syncStatusTags[syncStatus].stateKey}`)}
            {syncReadFailed ? (
              <Button type="link" size="small" onClick={() => void syncQuery.refetch()} loading={syncQuery.isFetching}>
                {t('states.syncReadRetry')}
              </Button>
            ) : null}
          </span>
        ) : null}
        {/* FLOW001：“已同步”只说节点配置；入口（线路/CNAME/证书）是否就绪单独标出，与列表同一判定。 */}
        {detail.access_readiness ? (
          <Tag data-testid="site-edit-access" color={detail.access_readiness.state === 'ready' ? 'success'
            : detail.access_readiness.state === 'blocked' ? 'error' : 'warning'}>
            {accessStatusLabel(detail.access_readiness, tAccess, (key) => i18n.exists(key))}
          </Tag>
        ) : accessGap ? (
          <Tooltip title={t(`states.accessGapHint.${accessGap}`)}>
            <Tag data-testid="site-edit-access" color="warning">{t(`states.accessGap.${accessGap}`)}</Tag>
          </Tooltip>
        ) : (
          <Tag data-testid="site-edit-access" color="success">{t('states.accessReady')}</Tag>
        )}
        {/* WEB/FLOW-STATE-01: one stable way from the site to what was published
            (the owner's publication records; an administrator lands on the owner). */}
        <a className="site-edit-publications-link" data-testid="site-edit-publications"
          href={publicationsPath}
          onClick={(event) => {
            event.preventDefault()
            if (canLeaveCurrentPage()) navigate(publicationsPath)
          }}>
          {t('states.viewPublications')}
        </a>
        {/* Changes save themselves; the header keeps the unsaved mark of the
            tabs that still wait for an action (certificate binding, conditional origin) and the
            exact retry of an unknown outcome. */}
        {uncertainWrite ? (
          <div className="site-edit-save-actions">
            <Tag color="warning">{t('edit.unsaved')}</Tag>
            <Button size="small" type="primary" loading={saveMutation.isPending}
              disabled={!saveAttemptRef.current || !canManage || lockedForTenant || batchWriteLocked || httpsWriteState.pending}
              onClick={retrySameRequest}>
              {saveAttemptRef.current ? t('actions.retrySameRequest') : t('edit.actions.outcomeUnknown')}
            </Button>
          </div>
        ) : dirty && !configDirty ? (
          <div className="site-edit-save-actions"><Tag color="warning">{t('edit.unsaved')}</Tag></div>
        ) : null}
      </header>

      <nav className="site-edit-tabs" aria-label={t('edit.tabs.label')}>
        <Button
          className="site-edit-tab-arrow"
          type="text"
          aria-label={t('edit.tabs.previous')}
          icon={<ChevronLeft size={16} aria-hidden="true" />}
          onClick={() => tabScrollRef.current?.scrollBy({ left: -140, behavior: 'smooth' })}
        />
        <div ref={tabScrollRef} className="site-edit-tab-scroll">
          {tabs.map((tab) => (
            <button
              className={activeTab === tab ? 'is-active' : undefined}
              type="button"
              role="tab"
              aria-selected={activeTab === tab}
              key={tab}
              onClick={() => setTab(tab)}
              onPointerEnter={() => preloadTab(tab)}
              onFocus={() => preloadTab(tab)}
            >
              {t(`edit.tabs.${tab}`)}
            </button>
          ))}
          {sitePluginPages.length > 0 ? (
            <button
              className={activeTab === 'extensions' ? 'is-active' : undefined}
              type="button"
              role="tab"
              aria-selected={activeTab === 'extensions'}
              onClick={() => setTab('extensions')}
            >
              {t('pluginUI:tab')}
            </button>
          ) : null}
        </div>
        <Button
          className="site-edit-tab-arrow"
          type="text"
          aria-label={t('edit.tabs.next')}
          icon={<ChevronRight size={16} aria-hidden="true" />}
          onClick={() => tabScrollRef.current?.scrollBy({ left: 140, behavior: 'smooth' })}
        />
      </nav>

      {lockedForTenant ? (
        <Alert
          className="site-edit-lock-banner"
          showIcon
          type="warning"
          message={t('edit.lock.title')}
          description={lockDescription || t('edit.lock.description')}
        />
      ) : null}

      {!canManage ? (
        <Alert
          className="site-edit-lock-banner"
          showIcon
          type="info"
          message={t('edit.readOnly.title')}
          description={t('edit.readOnly.description')}
        />
      ) : null}

      {batchWriteLocked ? (
        <OutcomeUnknown
          className="site-edit-lock-banner"
          title={batchRetryLock.corrupted ? t('edit.batch.recoveryFailed') : t('edit.batch.outcomeUnknown')}
          detail={t('edit.batch.readOnly')}
        />
      ) : null}

      {renderFeedback()}

      {tabMounted('basic') ? (
        <div data-site-edit-tab="basic" hidden={activeTab !== 'basic'}>
        <SiteEditTabBoundary key="basic" fallback={<EditLoading />}>
          {/* 服务端接入状态逐项（线路/CNAME/解析/证书/发布）与“立即检查”。 */}
          {detail.access_readiness ? (
            <SiteAccessReadinessCard readiness={detail.access_readiness} siteID={detail.id} admin={role === 'admin'}
              cname={detail.basic.cname}
              onCheckNow={accessToken ? async () => {
                const readiness = await sitesApi.checkAccess(accessToken, detail.id)
                queryClient.setQueryData<SiteDetail | null>(detailQueryKey,
                  (current) => current ? { ...current, access_readiness: readiness } : current)
              } : undefined} />
          ) : null}
          <BasicSiteTab
            detail={detail}
            role={role}
            canManageDNS={canManageDNS}
            value={draft}
            originPool={originDraft}
            errors={errors}
            originError={originError}
            readOnly={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked}
            originReadOnly={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked}
            onChange={updateDraft}
            onOriginChange={updateOriginDraft}
            onBlockedAction={blockAction}
            accessToken={accessToken}
            canManageOrigins={canManage && !lockedForTenant}
            selectScopeID={principal.scope_kind === 'platform' ? detail.scope_id : principal.scope_id}
            onTransfer={role === 'admin' && principal.scope_kind === 'platform' && canManage ? () => setTransferOpen(true) : undefined}
          />
          {transferOpen && accessToken ? (
            <SiteTransferModal
              open
              accessToken={accessToken}
              site={{ id: detail.id, version: detail.version, domain: detail.basic.domains[0] ?? '', cname: detail.basic.cname,
                ownerID: detail.owner?.id ?? null, ownerName: detail.owner?.display_name ?? '' }}
              canReadUsers={principal.permissions.includes('identity.users.manage') || principal.permissions.includes('platform.admin')}
              onClose={() => setTransferOpen(false)}
              onTransferred={(result) => {
                void queryClient.invalidateQueries({ queryKey: ['sites'] })
                navigate(`/site/${result.site.id}/edit`, { replace: true })
              }}
            />
          ) : null}
        </SiteEditTabBoundary>
        </div>
      ) : null}
      {tabMounted('origin') ? (
        <div data-site-edit-tab="origin" hidden={activeTab !== 'origin'}>
        <SiteEditTabBoundary key="origin" fallback={<EditLoading />}>
          <OriginSettingsTab
            pool={originDraft}
            originError={originError}
            readOnly={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked}
            canReadOriginAuth={principal.scope_kind === 'tenant' && principal.permissions.includes('origin_auth.read')}
            certificateBound={Boolean(detail.https_certificate_bound)}
            onOpenHttps={() => setTab('https')}
            // The certificate page's request dialog with the site's domains and owner.
            onRequestCertificate={() => navigate(`/site/cert?domains=${encodeURIComponent(draft.domains.join('\n'))}&site=${encodeURIComponent(id)}`)}
            onChange={updateOriginDraft}
            conditionalOpen={searchParams.get('conditional') === '1'}
            conditional={
              <SiteEditTabBoundary key="origin-conditional" fallback={<EditLoading />}>
              <ConditionalOriginSiteTab
                siteId={id}
                accessToken={accessToken}
                scopeKind={principal.scope_kind}
                scopeId={principal.scope_id}
                tenantId={principal.tenant_id}
                userId={principal.user_id}
                sessionEpoch={sessionEpoch}
                permissions={principal.permissions}
                canManage={canManage}
                lockedForTenant={lockedForTenant}
                onWorkflowStateChange={setConditionalWriteState}
              />
              </SiteEditTabBoundary>
            }
          />
        </SiteEditTabBoundary>
        </div>
      ) : null}
      {tabMounted('https') ? (
        <div data-site-edit-tab="https" hidden={activeTab !== 'https'}>
          <SiteEditTabBoundary fallback={<EditLoading />}>
            <HttpsSiteTab
              siteId={id}
              siteScopeId={detail.scope_id}
              accessToken={accessToken}
              scopeKind={principal.scope_kind}
              principalScopeId={principal.scope_id}
              permissions={principal.permissions}
              sessionEpoch={sessionEpoch}
              value={draft}
              errors={errors}
              readOnly={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked}
              onChange={updateDraft}
              onWorkflowStateChange={setHttpsWriteState}
              certificateBound={detail.https_certificate_bound}
              savedHttpsEnabled={detail.basic.https_enabled}
            />
          </SiteEditTabBoundary>
        </div>
      ) : null}
      {tabMounted('cache') ? (
        <div
          data-testid="cache-policy-panel"
          data-site-edit-tab="cache"
          hidden={activeTab !== 'cache'}
        >
          <SiteEditTabBoundary fallback={<EditLoading />}>
            <CacheSiteTab
              siteId={id}
              accessToken={accessToken}
              scopeKind={principal.scope_kind}
              permissions={principal.permissions}
              lockedForTenant={lockedForTenant}
              sessionEpoch={sessionEpoch}
              userId={principal.user_id}
              scopeId={principal.scope_id}
              tenantId={principal.tenant_id}
              siteScopeId={detail.scope_id}
              onDirtyChange={setCacheWriteState}
              extra={(
                <CacheStatusHeaderSwitch
                  detail={detail}
                  accessToken={accessToken}
                  disabled={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked || saveMutation.isPending}
                  onSaved={(saved) => {
                    // only this field: unsaved basic edits stay in the draft
                    setDetail(saved)
                    setDraft((current) => current && { ...current, cache_status_header: saved.basic.cache_status_header })
                    queryClient.setQueryData(detailQueryKey, saved)
                  }}
                />
              )}
            />
          </SiteEditTabBoundary>
        </div>
      ) : null}
      {tabMounted('cc') ? (
        <div data-site-edit-tab="cc" hidden={activeTab !== 'cc'}>
        <SiteEditTabBoundary key="cc" fallback={<EditLoading />}>
          <SiteCCTab
            siteId={id}
            host={(draft.domains[0] ?? '').trim().toLowerCase().replace(/^\*\./, '').replace(/:\d+$/, '')}
            scopeKind={principal.scope_kind}
            scopeId={principal.scope_id}
            accessToken={accessToken}
            permissions={principal.permissions}
            locked={lockedForTenant}
            siteScopeId={detail?.scope_id}
            siteOwnerId={detail?.owner?.id}
            cname={detail?.basic.cname}
          />
        </SiteEditTabBoundary>
        </div>
      ) : null}
      {tabMounted('waf') ? (
        <div data-site-edit-tab="waf" hidden={activeTab !== 'waf'}>
        <SiteEditTabBoundary key="waf" fallback={<EditLoading />}>
          <SiteWAFTab
            siteId={id}
            host={(draft.domains[0] ?? '').trim().toLowerCase().replace(/^\*\./, '').replace(/:\d+$/, '')}
            scopeKind={principal.scope_kind}
            scopeId={principal.scope_id}
            accessToken={accessToken}
            permissions={principal.permissions}
            locked={lockedForTenant}
            siteScopeId={detail?.scope_id}
            siteOwnerId={detail?.owner?.id}
          />
        </SiteEditTabBoundary>
        </div>
      ) : null}
      {tabMounted('autodefense') ? (
        <div data-site-edit-tab="autodefense" hidden={activeTab !== 'autodefense'}>
        <SiteEditTabBoundary key="autodefense" fallback={<EditLoading />}>
          <SiteAutoDefenseTab
            siteId={id}
            host={(draft.domains[0] ?? '').trim().toLowerCase().replace(/^\*\./, '').replace(/:\d+$/, '')}
            scopeKind={principal.scope_kind}
            scopeId={principal.scope_id}
            accessToken={accessToken}
            permissions={principal.permissions}
            locked={lockedForTenant}
            siteScopeId={detail?.scope_id}
            siteOwnerId={detail?.owner?.id}
            cname={detail?.basic.cname}
          />
        </SiteEditTabBoundary>
        </div>
      ) : null}
      {activeTab === 'extensions' ? (
        <SiteEditTabBoundary key="extensions" fallback={<EditLoading />}><SitePluginTab siteId={id} pages={sitePluginPages} /></SiteEditTabBoundary>
      ) : null}
      {tabMounted('advanced') ? (
        <div data-site-edit-tab="advanced" hidden={activeTab !== 'advanced'}>
        <SiteEditTabBoundary key="advanced" fallback={<EditLoading />}>
          <AdvancedSiteTab
            siteId={id}
            accessToken={accessToken}
            scopeKind={principal.scope_kind}
            scopeId={principal.scope_id}
            tenantId={principal.tenant_id}
            userId={principal.user_id}
            sessionEpoch={sessionEpoch}
            permissions={principal.permissions}
            canManage={canManage}
            lockedForTenant={lockedForTenant}
            siteScopeId={principal.scope_kind === 'platform' ? detail?.scope_id : principal.scope_id}
            websocketEnabled={detail ? originForwarding(detail.origin_pool).websocket.enabled : undefined}
            edgeOptions={draft && originDraft ? (part) => (
              <SiteEdgeOptionsSection part={part} pool={originDraft} basic={draft} admin={role === 'admin'} accessToken={accessToken}
                readOnly={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked}
                basicReadOnly={!canManage || lockedForTenant || uncertainWrite || batchWriteLocked}
                onChange={updateOriginDraft} onBasicChange={updateDraft} />
            ) : undefined}
          />
        </SiteEditTabBoundary>
        </div>
      ) : null}

    </section>
  )
}
