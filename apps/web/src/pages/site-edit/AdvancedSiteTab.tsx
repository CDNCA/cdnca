import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient, type QueryKey } from '@tanstack/react-query'
import { Alert, Button, Input, InputNumber, Modal, Radio, Select, Space, Switch, Table, Upload, type TableColumnsType } from 'antd'
import { Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type ScopeKind } from '../../api/auth'
import { writeOutcomeUnknown as outcomeUnknown } from './writeOutcome'
import { errorPagesApi, type ErrorPageAsset, type ErrorPageRule } from '../../api/errorPages'
import { useSessionStore } from '../../auth/session'
import '../../i18n/sitePolicy'
import HTTPPolicyPanel, { type HTTPPolicyParts } from './HTTPPolicyPanel'
import SiteAccessPanel, { type SiteAccessPart } from './SiteAccessPanel'
import { SiteSchedule302Card } from './SiteSchedule302Card'
import { SiteTrafficLimitCard } from './SiteTrafficLimitCard'
import { FormRow, SettingGroup, SettingSection } from './SiteEditFields'
import SiteCapturePolicyPanel from './SiteCapturePolicyPanel'
import { FeedbackWhen, MODAL_WIDTH, ModalFooter, OutcomeUnknown } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { emptyHttpPolicyConfig, MAX_HTTP_POLICY_UPLOAD_BYTES, type HttpPolicyPage } from '../../api/httpPolicies'
import type { SiteAccessState } from '../../api/siteAccess'
import type { Schedule302State } from '../../api/siteSchedule302'
import '../../i18n/httpPolicies'
import '../../i18n/siteAccess'
import '../../i18n/siteSchedule302'
import '../../i18n/siteEdgeOptions'
import '../../i18n/siteEditV4'
import { SiteTabSummary, type SummaryItem } from './SiteTabSummary'

interface AdvancedSiteTabProps {
  siteId: string
  // The site's tenant scope (the capture policy is per tenant scope);
  // absent: the log capture section is not shown.
  siteScopeId?: string
  // SiteEdgeOptionsSection cards for 性能与协议 and 其它, bound to the page's
  // basic/origin drafts and saved with the page's save button.
  edgeOptions?: (part: 'performance' | 'other') => ReactNode
  // WebSocket as saved on the site (本页摘要); absent: not shown.
  websocketEnabled?: boolean
  accessToken: string
  scopeKind: ScopeKind
  scopeId: string
  tenantId: string | null
  userId: string
  sessionEpoch: number
  permissions: readonly string[]
  canManage: boolean
  lockedForTenant: boolean
}

type WriteSource = 'assets' | 'rules'
type WriteAttempt = {
  id: string
  owner: string
  source: WriteSource
} & (
  // thenRule: a page written as text is uploaded as an asset
  // and the rule saved with it in the same write (one retry covers both)
  | { operation: 'asset-upload'; file: Blob; name: string; mimeType: string; size: number; sha256: string; keys: { initiate: string; upload: string; finalize: string }; initiatedAssetId?: string; uploadedAssetId?: string;
      finalizedAssetId?: string; thenRule?: { ruleId?: string; revision?: number; fields: Omit<ErrorPageRule['fields'], 'asset_id'>; key: string } }
  | { operation: 'asset-delete'; assetId: string; revision: number; key: string }
  | { operation: 'rule-save'; ruleId?: string; revision?: number; target: ErrorPageRule['target']; fields: ErrorPageRule['fields']; key: string }
  | { operation: 'rule-toggle'; ruleId: string; revision: number; enabled: boolean; key: string }
  | { operation: 'rule-delete'; ruleId: string; revision: number; key: string }
)

interface WriteHandle { id: string; owner: string }

// The SiteAccessPanel cards outside the competitor's six groups (更多设置).
const moreAccessParts: SiteAccessPart[] = ['forceHttps', 'hostRedirects', 'hsts', 'webp', 'responseRules', 'limits', 'basicAuth', 'maintenance']
// Error page categories a site rule may use (errorpagecontrol validate.go:93-125).
const siteCategories = ['origin_response', 'edge_route', 'edge_connect'] as const
const commonStatuses: Record<string, number[]> = {
  origin_response: [403, 404, 500, 502, 503, 504], edge_route: [403, 404, 500, 502, 503, 504], edge_connect: [502, 503, 504],
}

// be-gap-2: an asset's display name (migration 509): the file name, or the
// page's category and status for a page written as text; at most 128
// characters, no control characters, no surrounding blanks.
function assetName(raw: string): string {
  // eslint-disable-next-line no-control-regex
  return Array.from(raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').trim()).slice(0, 128).join('').trim()
}

function sizeText(bytes: number): string {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KiB` : `${bytes} B`
}

function ownerKey(props: AdvancedSiteTabProps): readonly unknown[] {
  return [props.scopeKind, props.scopeId, props.tenantId, props.userId, props.sessionEpoch, props.siteId, props.siteScopeId]
}

function currentAccess(props: AdvancedSiteTabProps, permission: string): string | null {
  const state = useSessionStore.getState()
  const principal = state.principal
  if (!state.accessToken || !principal || !state.sessionEpoch ||
    !principal.permissions.includes(permission) && !principal.permissions.includes('platform.admin')) return null
  if (principal.scope_kind !== props.scopeKind || principal.scope_id !== props.scopeId ||
    principal.tenant_id !== props.tenantId || principal.user_id !== props.userId || state.sessionEpoch !== props.sessionEpoch) return null
  return state.accessToken
}

function writeErrorKey(error: unknown): 'forbiddenWrite' | 'notFound' | 'conflict' | 'stale' | 'validation' | 'saveFailed' {
  if (!(error instanceof ApiError)) return 'saveFailed'
  if (error.status === 403 || error.code === 'permission_denied') return 'forbiddenWrite'
  if (error.status === 404) return 'notFound'
  if (error.status === 409) return 'conflict'
  if (error.status === 412) return 'stale'
  if (error.status === 422) return 'validation'
  return 'saveFailed'
}

function WriteErrorAlert({ error, uncertain, pending, abandoning, onRetry, onAbandon }: {
  error: unknown
  uncertain: boolean
  pending: boolean
  abandoning: boolean
  onRetry: () => void
  onAbandon: () => void
}) {
  const { t } = useTranslation('sitePolicy')
  if (!error) return null
  if (!uncertain) return <FeedbackWhen title={t(writeErrorKey(error))} />
  return (
    <OutcomeUnknown title={t('unknownTitle')} detail={t('unknownDescription')} action={<Space><Button loading={abandoning} disabled={pending} onClick={onAbandon}>{t('abandonRefresh')}</Button><Button type="primary" loading={pending} disabled={abandoning} onClick={onRetry}>{t('retryExact')}</Button></Space>} />
  )
}

function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  return crypto.subtle.digest('SHA-256', buffer).then((digest) => [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join(''))
}

function writeId(operation: WriteAttempt['operation']): string {
  return `site-policy-${operation}-${crypto.randomUUID()}`
}

// useCachedData reads a query the cards below own, without becoming one of its
// observers (so it never fetches nor changes that query's options).
function useCachedData<T>(queryKey: QueryKey): T | undefined {
  const queryClient = useQueryClient()
  const subscribe = useCallback((notify: () => void) => queryClient.getQueryCache().subscribe(notify), [queryClient])
  // getQueryData returns the cached object itself, a stable snapshot
  return useSyncExternalStore(subscribe, () => queryClient.getQueryData<T>(queryKey))
}

// AdvancedSummary is the 本页摘要 of the advanced tab. It only reads what the
// cards below already loaded (same query keys, no request of its own), so it
// shows the saved values.
function AdvancedSummary({ props, ownerParts }: { props: AdvancedSiteTabProps; ownerParts: readonly unknown[] }) {
  const { t } = useTranslation('siteEditV4')
  const { t: tPolicy } = useTranslation('sitePolicy')
  const { t: tHttp } = useTranslation('httpPolicies')
  const { t: tAccess } = useTranslation('siteAccess')
  const { t: t302 } = useTranslation('siteSchedule302')
  const { t: tEdge } = useTranslation('siteEdgeOptions')
  // no policy yet: the panel shows (and saves from) the empty config
  const policyPage = useCachedData<HttpPolicyPage>(['site-http-policy', ...ownerParts])
  const policy = policyPage ? policyPage.items[0] ?? emptyHttpPolicyConfig() : undefined
  const access = useCachedData<SiteAccessState>(['site-access', props.siteId])
  const schedule = useCachedData<Schedule302State>(['site-schedule302', props.siteId])
  const onOff = (on: boolean): Pick<SummaryItem, 'value' | 'tone'> => ({ value: t(on ? 'summary.on' : 'summary.off'), tone: on ? 'on' : 'off' })
  const items: SummaryItem[] = []
  if (policy) {
    items.push(
      { key: 'upload', label: tPolicy('groupUpload'), target: 'site-advanced-upload',
        value: policy.max_upload_bytes === MAX_HTTP_POLICY_UPLOAD_BYTES ? tHttp('uploadMax')
          : t('summary.advanced.uploadValue', { mb: Math.round(policy.max_upload_bytes / 1048576 * 10) / 10 }) },
      { key: 'referer', label: tHttp('refererTitle'), target: 'site-advanced-access', ...onOff(policy.referer_check !== null) },
      { key: 'cors', label: tHttp('corsTitle'), target: 'site-advanced-access', ...onOff(policy.cors !== null) },
    )
  }
  if (access) {
    const compression = access.settings.compression
    items.push({ key: 'compression', label: tAccess('compression.title'), target: 'site-advanced-performance',
      value: tAccess(`compression.modes.${compression === null ? 'inherit' : compression.enabled ? 'on' : 'off'}`),
      tone: compression === null ? 'plain' : compression.enabled ? 'on' : 'off' })
  }
  if (props.websocketEnabled !== undefined) {
    items.push({ key: 'websocket', label: tEdge('fields.websocket'), target: 'site-advanced-performance', ...onOff(props.websocketEnabled) })
  }
  if (schedule) items.push({ key: 'schedule302', label: t302('title'), target: 'site-schedule302-title', ...onOff(schedule.settings.enabled) })
  return items.length ? <SiteTabSummary items={items} /> : null
}

export default function AdvancedSiteTab(props: AdvancedSiteTabProps) {
  const { t } = useTranslation('sitePolicy')
  const queryClient = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [category, setCategory] = useState('origin_response')
  const [matchKind, setMatchKind] = useState('exact')
  const [statusFrom, setStatusFrom] = useState('404')
  const [statusTo, setStatusTo] = useState('404')
  // CU-ADV-01：本弹窗的状态码选择意图（常用码 / 其他 / 范围）单独保存，不从数值反推。
  const [statusChoice, setStatusChoice] = useState<'common' | 'custom' | 'range'>('common')
  const [ruleAsset, setRuleAsset] = useState('')
  const [editingRule, setEditingRule] = useState<ErrorPageRule | null>(null)
  const [ruleOpen, setRuleOpen] = useState(false)
  // the page written as text; loadedContent is the selected asset's body as read
  const [pageText, setPageText] = useState('')
  const [pageMime, setPageMime] = useState<'text/html' | 'text/plain'>('text/html')
  const [loadedContent, setLoadedContent] = useState<{ assetId: string; text: string } | null>(null)
  const [contentState, setContentState] = useState<'idle' | 'loading' | 'failed'>('idle')
  const [notice, setNotice] = useState<string | null>(null)
  const attemptRef = useRef<WriteAttempt | null>(null)
  const [attemptID, setAttemptID] = useState<string | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [preparingAsset, setPreparingAsset] = useState(false)
  const [abandoning, setAbandoning] = useState(false)
  const key = useMemo(() => ownerKey(props), [props])
  const owner = JSON.stringify(key)
  const platformAdmin = props.permissions.includes('platform.admin')
  const policyRead = props.permissions.includes('http_policies.read') || platformAdmin
  const siteRead = props.permissions.includes('sites.read') || platformAdmin
  const siteWrite = props.canManage && !props.lockedForTenant && (props.permissions.includes('sites.manage') || platformAdmin)
  // be-gap-2 (s4 遗留 6, like C28): a site's error pages live in the site's tenant scope. A platform
  // administrator reads and writes them there (the service refuses a site rule in the platform scope
  // and a rule's asset must share its scope); without the site's scope nothing is requested.
  const errorScopeId = props.scopeKind === 'platform' ? props.siteScopeId ?? '' : props.scopeId
  const errorRead = Boolean(errorScopeId) && (props.permissions.includes('error_pages.read') || platformAdmin)
  const errorWrite = Boolean(errorScopeId) && props.canManage && !props.lockedForTenant &&
    (props.permissions.includes('error_pages.manage') || platformAdmin)
  const trafficLimitRead = props.permissions.includes('sites.read') || platformAdmin
  const assetsQuery = useQuery({
    queryKey: ['site-error-assets', ...key],
    enabled: errorRead,
    retry: false,
    queryFn: async () => {
      const token = currentAccess(props, 'error_pages.read')
      if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
      const result = await errorPagesApi.listAssets(token, errorScopeId, 'ready')
      if (!currentAccess(props, 'error_pages.read')) throw new ApiError('Session changed', 401, 'authentication_required')
      return result
    },
  })
  const rulesQuery = useQuery({
    queryKey: ['site-error-rules', ...key],
    enabled: errorRead,
    retry: false,
    queryFn: async () => {
      const token = currentAccess(props, 'error_pages.read')
      if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
      const result = await errorPagesApi.listRules(token, errorScopeId, props.siteId)
      if (!currentAccess(props, 'error_pages.read')) throw new ApiError('Session changed', 401, 'authentication_required')
      return result
    },
  })
  useEffect(() => () => {
    const state = useSessionStore.getState()
    const principal = state.principal
    if (principal && state.sessionEpoch === props.sessionEpoch && principal.scope_kind === props.scopeKind &&
      principal.scope_id === props.scopeId && principal.tenant_id === props.tenantId && principal.user_id === props.userId) return
    queryClient.removeQueries({ queryKey: ['site-error-assets', ...key], exact: true })
    queryClient.removeQueries({ queryKey: ['site-error-rules', ...key], exact: true })
  }, [key, props.scopeId, props.scopeKind, props.sessionEpoch, props.tenantId, props.userId, queryClient])
  const clearAttempt = () => {
    attemptRef.current = null
    setAttemptID(null)
  }
  const accessFor = (permission: string): string => {
    const token = currentAccess(props, permission)
    if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
    return token
  }
  const executeAttempt = async (initial: WriteAttempt): Promise<unknown> => {
    if (initial.owner !== owner) throw new ApiError('Session changed', 401, 'authentication_required')
    switch (initial.operation) {
      case 'asset-upload': {
        let attempt = initial
        if (!attempt.initiatedAssetId) {
          const initiated = await errorPagesApi.initiateAsset(accessFor('error_pages.manage'), errorScopeId, attempt.mimeType, attempt.size, attempt.sha256, attempt.keys.initiate, attempt.name)
          attempt = { ...attempt, initiatedAssetId: initiated.value.id }
          attemptRef.current = attempt
        }
        const initiatedAssetId = attempt.initiatedAssetId
        if (!initiatedAssetId) throw new ApiError('Invalid error page response', 0, 'invalid_response')
        if (!attempt.uploadedAssetId) {
          const uploaded = await errorPagesApi.uploadAssetContent(accessFor('error_pages.manage'), initiatedAssetId, attempt.file, attempt.mimeType, attempt.keys.upload)
          attempt = { ...attempt, uploadedAssetId: uploaded.value.id }
          attemptRef.current = attempt
        }
        const uploadedAssetId = attempt.uploadedAssetId
        if (!uploadedAssetId) throw new ApiError('Invalid error page response', 0, 'invalid_response')
        if (!attempt.finalizedAssetId) {
          const finalized = await errorPagesApi.finalizeAsset(accessFor('error_pages.manage'), uploadedAssetId, attempt.keys.finalize)
          if (!attempt.thenRule) return finalized
          attempt = { ...attempt, finalizedAssetId: finalized.value.id }
          attemptRef.current = attempt
        }
        const rule = attempt.thenRule
        if (!rule || !attempt.finalizedAssetId) throw new ApiError('Invalid error page response', 0, 'invalid_response')
        const fields = { ...rule.fields, asset_id: attempt.finalizedAssetId }
        const token = accessFor('error_pages.manage')
        return rule.ruleId && rule.revision !== undefined
          ? errorPagesApi.updateRule(token, rule.ruleId, fields, rule.revision, rule.key)
          : errorPagesApi.createRule(token, { target: { kind: 'site', scope_id: errorScopeId, site_id: props.siteId }, fields }, rule.key)
      }
      case 'asset-delete':
        return errorPagesApi.deleteAsset(accessFor('error_pages.manage'), initial.assetId, initial.revision, initial.key)
      case 'rule-save': {
        const token = accessFor('error_pages.manage')
        return initial.ruleId && initial.revision !== undefined
          ? errorPagesApi.updateRule(token, initial.ruleId, initial.fields, initial.revision, initial.key)
          : errorPagesApi.createRule(token, { target: initial.target, fields: initial.fields }, initial.key)
      }
      case 'rule-toggle':
        return errorPagesApi.setRuleEnabled(accessFor('error_pages.manage'), initial.ruleId, initial.revision, initial.enabled, initial.key)
      case 'rule-delete':
        return errorPagesApi.deleteRule(accessFor('error_pages.manage'), initial.ruleId, initial.revision, initial.key)
    }
  }
  const writeMutation = useMutation({
    retry: false,
    mutationFn: (handle: WriteHandle) => {
      const attempt = attemptRef.current
      if (!attempt || attempt.id !== handle.id || attempt.owner !== handle.owner) throw new ApiError('Session changed', 401, 'authentication_required')
      return executeAttempt(attempt)
    },
    onSuccess: (_result, handle) => {
      const completed = attemptRef.current
      if (!completed || completed.id !== handle.id || completed.owner !== owner) return
      clearAttempt()
      setWriteError(null)
      const ruleSaved = completed.operation === 'rule-save' || completed.operation === 'asset-upload' && Boolean(completed.thenRule)
      if (completed.operation === 'asset-upload') {
        setFile(null)
        const value = (_result as { value?: { id?: string } } | undefined)?.value
        if (value?.id && !completed.thenRule) setRuleAsset(value.id)
      }
      if (ruleSaved) { setEditingRule(null); setRuleOpen(false); setNotice(t('saved')) }
      void queryClient.invalidateQueries({ queryKey: [completed.source === 'assets' ? 'site-error-assets' : 'site-error-rules', ...key] })
      if (ruleSaved) void queryClient.invalidateQueries({ queryKey: ['site-error-assets', ...key] })
    },
    onError: (error, handle) => {
      const failed = attemptRef.current
      if (!failed || failed.id !== handle.id || failed.owner !== owner) return
      setWriteError(error)
      if (!outcomeUnknown(error)) clearAttempt()
    },
  })
  const activeAttempt = attemptRef.current?.owner === owner && attemptRef.current.id === attemptID ? attemptRef.current : null
  const uncertain = Boolean(activeAttempt && writeError && outcomeUnknown(writeError))
  const writesLocked = preparingAsset || writeMutation.isPending || uncertain

  useEffect(() => {
    attemptRef.current = null
    setAttemptID(null)
    setWriteError(null)
    setPreparingAsset(false)
    setAbandoning(false)
  }, [owner])

  const beginWrite = (attempt: WriteAttempt) => {
    if (writesLocked) return
    attemptRef.current = attempt
    setAttemptID(attempt.id)
    setWriteError(null)
    writeMutation.mutate({ id: attempt.id, owner: attempt.owner })
  }
  const retryWrite = () => {
    if (!activeAttempt || writeMutation.isPending) return
    writeMutation.mutate({ id: activeAttempt.id, owner: activeAttempt.owner })
  }
  const abandonWrite = async () => {
    if (!activeAttempt || writeMutation.isPending || abandoning) return
    setAbandoning(true)
    const result = activeAttempt.source === 'assets' ? await assetsQuery.refetch() : await rulesQuery.refetch()
    setAbandoning(false)
    if (result.isError) return
    if (activeAttempt.operation === 'asset-upload') setFile(null)
    clearAttempt()
    setWriteError(null)
  }
  const uploadAsset = async () => {
    if (!file || !errorWrite || writesLocked) return
    if (!new Set(['text/html', 'text/plain', 'application/json']).has(file.type) || file.size < 1 || file.size > 1048576) {
      setWriteError(new ApiError('Invalid form', 422, 'validation_error'))
      return
    }
    setPreparingAsset(true)
    const frozenFile = file
    try {
      const sha256 = await sha256Hex(await frozenFile.arrayBuffer())
      const id = writeId('asset-upload')
      beginWrite({
        id, owner, source: 'assets', operation: 'asset-upload', file: frozenFile, name: assetName(frozenFile.name), mimeType: frozenFile.type,
        size: frozenFile.size, sha256, keys: { initiate: crypto.randomUUID(), upload: crypto.randomUUID(), finalize: crypto.randomUUID() },
      })
    } catch {
      setWriteError(new ApiError('Invalid file', 422, 'validation_error'))
    } finally {
      setPreparingAsset(false)
    }
  }
  const deleteAsset = (asset: ErrorPageAsset) => {
    if (!errorWrite || writesLocked) return
    const id = writeId('asset-delete')
    beginWrite({ id, owner, source: 'assets', operation: 'asset-delete', assetId: asset.id, revision: asset.revision, key: crypto.randomUUID() })
  }
  const saveRule = async () => {
    if (!errorWrite || writesLocked) return
    const fields = { category, match: { kind: matchKind, from: Number(statusFrom), to: Number(statusTo) }, enabled: true }
    // text written or changed: a new asset, then the rule (one write)
    const textChanged = pageText !== '' && !(loadedContent && loadedContent.assetId === ruleAsset && loadedContent.text === pageText)
    if (textChanged) {
      const bytes = new TextEncoder().encode(pageText)
      if (bytes.length < 1 || bytes.length > 1048576) {
        setWriteError(new ApiError('Invalid form', 422, 'validation_error'))
        return
      }
      const blob = new Blob([bytes], { type: pageMime })
      setPreparingAsset(true)
      try {
        const sha256 = await sha256Hex(bytes.buffer as ArrayBuffer)
        beginWrite({
          id: writeId('asset-upload'), owner, source: 'rules', operation: 'asset-upload', file: blob,
          name: assetName(`${t(`category_${category}`)} ${statusFrom === statusTo ? statusFrom : `${statusFrom}-${statusTo}`}`),
          mimeType: pageMime,
          size: bytes.length, sha256, keys: { initiate: crypto.randomUUID(), upload: crypto.randomUUID(), finalize: crypto.randomUUID() },
          thenRule: { ruleId: editingRule?.id, revision: editingRule?.revision, fields, key: crypto.randomUUID() },
        })
      } finally {
        setPreparingAsset(false)
      }
      return
    }
    if (!ruleAsset) {
      setWriteError(new ApiError('Invalid form', 422, 'validation_error'))
      return
    }
    const id = writeId('rule-save')
    beginWrite({
      id, owner, source: 'rules', operation: 'rule-save', ruleId: editingRule?.id, revision: editingRule?.revision,
      target: { kind: 'site', scope_id: errorScopeId, site_id: props.siteId },
      fields: { category, match: { kind: matchKind, from: Number(statusFrom), to: Number(statusTo) }, asset_id: ruleAsset, enabled: true },
      key: crypto.randomUUID(),
    })
  }
  const toggleRule = (rule: ErrorPageRule, enabled: boolean) => {
    if (!errorWrite || writesLocked) return
    const id = writeId('rule-toggle')
    beginWrite({ id, owner, source: 'rules', operation: 'rule-toggle', ruleId: rule.id, revision: rule.revision, enabled, key: crypto.randomUUID() })
  }
  const deleteRule = (rule: ErrorPageRule) => {
    if (!errorWrite || writesLocked) return
    const id = writeId('rule-delete')
    beginWrite({ id, owner, source: 'rules', operation: 'rule-delete', ruleId: rule.id, revision: rule.revision, key: crypto.randomUUID() })
  }
  const closeRule = () => { if (!writeMutation.isPending) { setRuleOpen(false); setEditingRule(null) } }
  if (!policyRead && !errorRead && !trafficLimitRead) return <SiteEditState status="forbidden" title={t('forbidden')} />
  const queryError = assetsQuery.error ?? rulesQuery.error
  const loading = errorRead && (assetsQuery.isPending || rulesQuery.isPending)
  if (loading) return <SiteEditState status="loading" label={t('loading')} />
  const isForbidden = queryError instanceof ApiError && queryError.status === 403
  const assets = assetsQuery.data?.items ?? []
  const rules = rulesQuery.data?.items ?? []
  const assetLabel = (id: string) => {
    const asset = assets.find((item) => item.id === id)
    return asset ? `${asset.mime_type} · ${sizeText(asset.size_bytes)}` : t('assetMissing')
  }
  const statusText = (rule: ErrorPageRule) => rule.fields.match.kind === 'range' && rule.fields.match.to !== rule.fields.match.from
    ? `${rule.fields.match.from}-${rule.fields.match.to}` : String(rule.fields.match.from)
  const openRule = (rule: ErrorPageRule | null) => {
    setEditingRule(rule)
    setCategory(rule?.fields.category ?? 'origin_response')
    setMatchKind(rule?.fields.match.kind ?? 'exact')
    setStatusFrom(String(rule?.fields.match.from ?? 404))
    setStatusTo(String(rule?.fields.match.to ?? 404))
    const from = rule?.fields.match.from ?? 404
    setStatusChoice(rule?.fields.match.kind === 'range' ? 'range'
      : (commonStatuses[rule?.fields.category ?? 'origin_response'] ?? []).includes(from) ? 'common' : 'custom')
    setRuleAsset(rule?.fields.asset_id ?? '')
    setFile(null)
    setPageText('')
    setLoadedContent(null)
    setContentState('idle')
    setRuleOpen(true)
    if (rule) void loadPageContent(rule.fields.asset_id)
  }
  // loadPageContent reads the selected asset's text into the editor (an
  // error page edits in place, as the competitor's).
  const loadPageContent = async (assetId: string) => {
    const asset = assets.find((item) => item.id === assetId)
    if (!asset || asset.mime_type === 'application/json') return
    setContentState('loading')
    try {
      const result = await errorPagesApi.getAssetContent(accessFor('error_pages.read'), assetId)
      setPageText(result.content)
      setPageMime(asset.mime_type === 'text/plain' ? 'text/plain' : 'text/html')
      setLoadedContent({ assetId, text: result.content })
      setContentState('idle')
    } catch {
      setContentState('failed')
    }
  }
  const templates: Record<'default' | 'plain' | 'html', [string, 'text/html' | 'text/plain']> = {
    default: [`<!doctype html>\n<html lang="zh-CN"><head><meta charset="utf-8"><title>${statusFrom}</title></head>\n<body><h1>${statusFrom}</h1><p>请求无法完成，请稍后重试。</p></body></html>\n`, 'text/html'],
    plain: [`${statusFrom} 请求无法完成，请稍后重试。\n`, 'text/plain'],
    html: ['<!doctype html>\n<html><head><meta charset="utf-8"><title>Error</title></head>\n<body><h1>出错了</h1><p>我们正在处理，请稍后再试。</p></body></html>\n', 'text/html'],
  }
  const ruleColumns: TableColumnsType<ErrorPageRule> = [
    { title: t('pageColumn'), key: 'page', render: (_, rule) => <span><strong>{statusText(rule)}</strong> {(siteCategories as readonly string[]).includes(rule.fields.category) ? t(`category_${rule.fields.category}`) : rule.fields.category}</span> },
    { title: t('assetColumn'), key: 'asset', render: (_, rule) => assetLabel(rule.fields.asset_id) },
    { title: t('enabledColumn'), key: 'enabled', width: 90, render: (_, rule) => (
      <Switch size="small" aria-label={`${t('enabledColumn')} ${statusText(rule)}`} checked={rule.fields.enabled}
        disabled={!errorWrite || writesLocked} onChange={(enabled) => toggleRule(rule, enabled)} />
    ) },
    ...(errorWrite ? [{ title: t('actionsColumn'), key: 'actions', width: 140, render: (_: unknown, rule: ErrorPageRule) => (
      <Space size={4}>
        <Button type="link" size="small" disabled={writesLocked} onClick={() => openRule(rule)}>{t('editRule')}</Button>
        <Button type="link" size="small" danger disabled={writesLocked} onClick={() => { if (window.confirm(t('confirmDelete'))) deleteRule(rule) }}>{t('deleteRule')}</Button>
      </Space>
    ) }] : []),
  ]
  const statusChoices = commonStatuses[category] ?? []
  const exactStatus = statusChoice === 'range' ? 'range' : statusChoice === 'custom' ? 'other' : statusFrom
  const errorPages = errorRead ? (
    <SettingGroup title={t('errorPages')} status={t('count', { count: rules.length })}
      extra={errorWrite ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => openRule(null)}>{t('addPage')}</Button> : null}>
      {rules.length ? (
        <Table<ErrorPageRule> rowKey="id" size="small" pagination={false} columns={ruleColumns} dataSource={rules}
          scroll={{ x: 'max-content' }} />
      ) : <div className="site-setting-empty">{t('emptyPages')}</div>}
      <Modal open={ruleOpen} title={editingRule ? t('editPage') : t('addPage')} width={MODAL_WIDTH.S} onCancel={closeRule} destroyOnHidden
        footer={<ModalFooter okText={t('confirmOk')} cancelText={t('cancel')} onCancel={closeRule} onOk={() => { void saveRule() }}
          okDisabled={!errorWrite || writesLocked || !ruleAsset && !pageText} loading={writeMutation.isPending && activeAttempt?.source === 'rules'} />}>
        <FormRow label={t('category')}>
          <Select aria-label={t('category')} style={{ width: 'min(280px, 100%)' }} value={category} disabled={writesLocked}
            options={siteCategories.map((value) => ({ value, label: t(`category_${value}`) }))}
            onChange={(value: string) => {
              setCategory(value)
              const first = String(commonStatuses[value]?.[0] ?? 404)
              if (statusChoice === 'common' && !commonStatuses[value]?.includes(Number(statusFrom))) { setStatusFrom(first); setStatusTo(first) }
            }} />
        </FormRow>
        <FormRow label={t('statusCode')} help={t(`categoryHelp_${category}`)}>
          <Radio.Group aria-label={t('statusCode')} optionType="button" value={exactStatus} disabled={writesLocked}
            options={[...statusChoices.map((value) => ({ value: String(value), label: String(value) })),
              { value: 'other', label: t('statusOther') }, { value: 'range', label: t('statusRange') }]}
            onChange={(event) => {
              const value = String(event.target.value)
              if (value === 'range') { setStatusChoice('range'); setMatchKind('range'); return }
              setMatchKind('exact')
              // 单码：起止相同（从范围切回时结束码跟随起始码）
              if (value === 'other') { setStatusChoice('custom'); setStatusTo(statusFrom); return }
              setStatusChoice('common')
              setStatusFrom(value); setStatusTo(value)
            }} />
          {exactStatus === 'other' || exactStatus === 'range' ? (
            <Space wrap className="site-error-page-status">
              <InputNumber aria-label={matchKind === 'range' ? t('statusFrom') : t('statusCode')} min={400} max={599} value={Number(statusFrom)}
                disabled={writesLocked} onChange={(value) => { setStatusFrom(String(value ?? '')); if (matchKind === 'exact') setStatusTo(String(value ?? '')) }} />
              {matchKind === 'range' ? <InputNumber aria-label={t('statusTo')} min={400} max={599} value={Number(statusTo)}
                disabled={writesLocked} onChange={(value) => setStatusTo(String(value ?? ''))} /> : null}
            </Space>
          ) : null}
        </FormRow>
        <FormRow label={t('pageContent')} help={t('pageContentHelp')}>
          <Space size={6} wrap className="site-error-page-templates">
            {(['default', 'plain', 'html'] as const).map((name) => (
              <Button key={name} size="small" disabled={writesLocked}
                onClick={() => { setPageText(templates[name][0]); setPageMime(templates[name][1]) }}>
                {t(name === 'default' ? 'templateDefault' : name === 'plain' ? 'templatePlain' : 'templateHtml')}
              </Button>
            ))}
            <Radio.Group size="small" optionType="button" aria-label={t('pageContentType')} value={pageMime} disabled={writesLocked}
              options={[{ value: 'text/html', label: t('contentTypeHtml') }, { value: 'text/plain', label: t('contentTypePlain') }]}
              onChange={(event) => setPageMime(event.target.value as 'text/html' | 'text/plain')} />
          </Space>
          <Input.TextArea aria-label={t('pageContent')} rows={8} value={pageText} disabled={writesLocked || contentState === 'loading'}
            placeholder={contentState === 'loading' ? t('pageContentLoading') : t('pageContentPlaceholder')}
            onChange={(event) => setPageText(event.target.value)} />
          {contentState === 'failed' ? <Alert type="warning" showIcon message={t('pageContentLoadFailed')} /> : null}
        </FormRow>
        <div className="site-setting-section-help">{t('uploadInstead')}</div>
        <FormRow label={t('asset')} help={t('assetHint')}>
          <Space.Compact style={{ width: '100%' }}>
            <Select aria-label={t('asset')} style={{ width: '100%' }} value={ruleAsset || undefined} placeholder={t('chooseAsset')} disabled={writesLocked}
              options={assets.map((asset) => ({ value: asset.id, label: asset.name
                ? `${asset.name} · ${sizeText(asset.size_bytes)}`
                : `${asset.mime_type} · ${sizeText(asset.size_bytes)} · ${asset.id.slice(0, 8)}` }))}
              onChange={(value: string) => { setRuleAsset(value); setPageText(''); setLoadedContent(null); void loadPageContent(value) }} />
            {ruleAsset && assets.some((asset) => asset.id === ruleAsset) && !rules.some((rule) => rule.fields.asset_id === ruleAsset) ? (
              <Button danger disabled={writesLocked} onClick={() => {
                const asset = assets.find((item) => item.id === ruleAsset)
                if (asset && window.confirm(t('confirmDeleteAsset'))) { deleteAsset(asset); setRuleAsset('') }
              }}>{t('deleteAsset')}</Button>
            ) : null}
          </Space.Compact>
        </FormRow>
        <FormRow label={t('uploadAsset')}>
          <Space wrap>
            <Upload accept=".html,.htm,.txt,.json,text/html,text/plain,application/json" maxCount={1} showUploadList={false} disabled={writesLocked}
              beforeUpload={(picked) => { setFile(picked); return false }}>
              <Button aria-label={t('chooseFile')} disabled={writesLocked}>{file ? file.name : t('chooseFile')}</Button>
            </Upload>
            <Button disabled={!file || writesLocked} loading={preparingAsset || writeMutation.isPending && activeAttempt?.operation === 'asset-upload'}
              onClick={() => { void uploadAsset() }}>{t('uploadAsset')}</Button>
          </Space>
        </FormRow>
      </Modal>
    </SettingGroup>
  ) : null
  const accessCards = (cards: SiteAccessPart[]) => siteRead
    ? <SiteAccessPanel siteId={props.siteId} accessToken={props.accessToken} canManage={siteWrite} locked={props.lockedForTenant} parts={cards} />
    : null
  const layout = (parts: HTTPPolicyParts | null, fallback: ReactNode) => <>
    {parts ? <>
      <SettingSection id="site-advanced-upload" title={t('groupUpload')} help={t('groupUploadHelp')}>{parts.upload}</SettingSection>
      <SettingSection id="site-advanced-access" title={t('groupAccess')} help={t('groupAccessHelp')}>{parts.referer}{parts.cors}</SettingSection>
    </> : fallback}
    <SettingSection id="site-advanced-performance" title={t('groupPerformance')} help={t('groupPerformanceHelp')}>
      <div className="site-setting-group-grid">
        {accessCards(['compression'])}
        {props.edgeOptions?.('performance')}
      </div>
    </SettingSection>
    {errorPages || parts ? (
      <SettingSection title={t('groupPages')} help={t('groupPagesHelp')}>
        {errorPages}{parts?.redirects}{parts?.rewrites}
      </SettingSection>
    ) : null}
    {parts ? <>
      <SettingSection title={t('groupHeaders')} help={t('groupHeadersHelp')}>{parts.requestHeaders}{parts.responseHeaders}{parts.actions}</SettingSection>
    </> : null}
    {props.edgeOptions ? (
      <SettingSection title={t('groupOther')} help={t('groupOtherHelp')}>
        <div className="site-setting-group-grid">{props.edgeOptions('other')}</div>
      </SettingSection>
    ) : null}
    <div className="site-setting-section-more">
      <SettingSection title={t('groupMore')} help={t('groupMoreHelp')}>
        {accessCards(moreAccessParts)}
        {/* hidden without access (通用规则), instead of a full-size 403 */}
        {props.siteScopeId && (platformAdmin || props.permissions.includes('site_capture.read')) ? (
          <div id="site-capture-heading">
            <SiteCapturePolicyPanel siteId={props.siteId} scopeId={props.siteScopeId} accessToken={props.accessToken}
              ownerKey={`${props.scopeKind}:${props.scopeId}:${props.userId}`} sessionEpoch={props.sessionEpoch}
              permissions={props.permissions} canManage={props.canManage} lockedForTenant={props.lockedForTenant} />
          </div>
        ) : null}
        {props.permissions.includes('sites.read') || props.scopeKind === 'platform' ? (
          <SiteSchedule302Card siteId={props.siteId} accessToken={props.accessToken}
            canManage={props.canManage && !props.lockedForTenant} />
        ) : null}
        {trafficLimitRead ? (
          <SiteTrafficLimitCard siteId={props.siteId} accessToken={props.accessToken}
            canManage={props.canManage && !props.lockedForTenant && (props.permissions.includes('sites.manage') || platformAdmin)} />
        ) : null}
      </SettingSection>
    </div>
  </>
  return (
    <div className="site-edit-tab-panel site-advanced-tab" aria-label={t('title')}>
      <AdvancedSummary props={props} ownerParts={key} />
      {notice ? <Alert type="success" message={notice} closable onClose={() => setNotice(null)} /> : null}
      <WriteErrorAlert
        error={writeError}
        uncertain={uncertain}
        pending={writeMutation.isPending}
        abandoning={abandoning}
        onRetry={retryWrite}
        onAbandon={() => { void abandonWrite() }}
      />
      {queryError ? (
        isForbidden
          ? <SiteEditState status="forbidden" title={t('forbidden')} detail={t('forbiddenWrite')} />
          : <SiteEditState status="error" title={t('loadFailed')} detail={t('requestFailed')} onRetry={() => { if (errorRead) { void assetsQuery.refetch(); void rulesQuery.refetch() } }} />
      ) : null}
      {policyRead ? <HTTPPolicyPanel {...props}>{layout}</HTTPPolicyPanel> : layout(null, null)}
    </div>
  )
}
