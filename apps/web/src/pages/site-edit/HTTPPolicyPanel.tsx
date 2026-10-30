import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Input, InputNumber, Radio, Space, Spin, Switch, Table, type TableColumnsType } from 'antd'
import { Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type ScopeKind } from '../../api/auth'
import { writeOutcomeUnknown as unknownOutcome } from './writeOutcome'
import {
  configFromHttpPolicy,
  emptyHttpPolicyConfig,
  httpPoliciesApi,
  MAX_HTTP_POLICY_UPLOAD_BYTES,
  type HeaderAction,
  type HttpPolicyConfig,
  type HttpPolicyIdentity,
  type HttpPolicyWriteMetadata,
} from '../../api/httpPolicies'
import { useSessionStore } from '../../auth/session'
import '../../i18n/httpPolicies'
import { FormRow, SettingGroup, SettingSection } from './SiteEditFields'
import { emptyRefererDraft, refererCheckFrom, refererDraftFrom, type RefererDraft } from './refererDraft'
import HTTPHeaderDialog from './HTTPHeaderDialog'
import URLRedirectDialog from './URLRedirectDialog'
import { draftFromRedirect, draftFromRewrite, type URLRedirectDraft } from './urlRedirectDraft'
import { OutcomeUnknown, FeedbackWhen } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { useCommitRequest, useInstantFeedback } from './instantSave'

export interface HTTPPolicyPanelProps {
  siteId: string
  /** C28: the site's tenant scope, the target of every HTTP policy request.
   * The actor identity (scopeKind/scopeId/tenantId/userId) stays the session's. */
  siteScopeId?: string
  scopeKind: ScopeKind
  scopeId: string
  tenantId: string | null
  userId: string
  sessionEpoch: number
  permissions: readonly string[]
  canManage: boolean
  lockedForTenant: boolean
  // tp-b3c: the HTTP policy is spread over several groups of
  // 高级设置; the caller places the parts (one draft, one save). Before the
  // policy loads (or without access) parts is null and fallback is the state.
  children?: (parts: HTTPPolicyParts | null, fallback: ReactNode) => ReactNode
}

export interface HTTPPolicyParts {
  upload: ReactNode
  referer: ReactNode
  cors: ReactNode
  redirects: ReactNode
  rewrites: ReactNode
  requestHeaders: ReactNode
  responseHeaders: ReactNode
  actions: ReactNode
}

type Operation = 'create' | 'update' | 'enable' | 'disable' | 'delete'
interface WriteAttempt {
  id: string
  owner: string
  operation: Operation
  policyId?: string
  revision?: number
  config?: HttpPolicyConfig
  metadata: HttpPolicyWriteMetadata
  identity: HttpPolicyIdentity
}

function currentAccess(props: HTTPPolicyPanelProps, permission: string): string | null {
  const state = useSessionStore.getState()
  const principal = state.principal
  if (!state.accessToken || !principal || !state.sessionEpoch ||
    !principal.permissions.includes(permission) && !principal.permissions.includes('platform.admin')) return null
  if (principal.scope_kind !== props.scopeKind || principal.scope_id !== props.scopeId || principal.tenant_id !== props.tenantId ||
    principal.user_id !== props.userId || state.sessionEpoch !== props.sessionEpoch) return null
  return state.accessToken
}

function lines(value: string): string[] {
  return [...new Set(value.split('\n').map((item) => item.trim()).filter(Boolean))]
}

// redirectHost: the authority of a redirect target (redirect_allowed_hosts).
function redirectHost(target: string): string | null {
  return /^https?:\/\/([^/]+)\//.exec(target)?.[1]?.toLowerCase() ?? null
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'unknown'
  if (error.code === 'referer_check_invalid') return 'refererInvalid'
  const known = new Set([
    'validation_error', 'invalid_request', 'authentication_required', 'permission_denied', 'entitlement_denied',
    'entitlement_unavailable', 'not_found', 'resource_conflict', 'idempotency_conflict', 'precondition_required',
    'revision_conflict', 'request_canceled', 'service_unavailable', 'method_not_allowed', 'invalid_response',
    'network_error', 'request_failed',
  ])
  return known.has(error.code) ? error.code : 'unknown'
}

function requestMetadata(operation: Operation): HttpPolicyWriteMetadata {
  const id = crypto.randomUUID()
  return {
    idempotencyKey: `http-policy-${operation}-${id}`,
    requestID: `request-${id}`,
    traceID: `trace-${id}`,
  }
}

function configValid(config: HttpPolicyConfig): boolean {
  if (!Number.isSafeInteger(config.max_upload_bytes) || config.max_upload_bytes < 1 ||
    config.max_upload_bytes > MAX_HTTP_POLICY_UPLOAD_BYTES) return false
  if (config.rewrites.some((rule) => !rule.match_path || !rule.target_path) ||
    config.redirects.some((rule) => !rule.match_path || !rule.target_url) || config.redirect_allowed_hosts.some((host) => !host)) return false
  return config.cors === null || config.cors.allowed_origins.length > 0 && config.cors.allowed_methods.length > 0 &&
    !(config.cors.allow_credentials && config.cors.allowed_origins.includes('*')) && Number.isSafeInteger(config.cors.max_age_seconds) &&
    config.cors.max_age_seconds >= 0 && config.cors.max_age_seconds <= 86400
}

export default function HTTPPolicyPanel(props: HTTPPolicyPanelProps) {
  const { t } = useTranslation('httpPolicies')
  const queryClient = useQueryClient()
  const ownerParts = useMemo(() => [props.scopeKind, props.scopeId, props.tenantId, props.userId, props.sessionEpoch, props.siteId, props.siteScopeId],
    [props.scopeId, props.scopeKind, props.sessionEpoch, props.siteId, props.siteScopeId, props.tenantId, props.userId])
  const owner = JSON.stringify(ownerParts)
  const queryKey = useMemo(() => ['site-http-policy', ...ownerParts], [ownerParts])
  const previewKey = useMemo(() => ['site-http-policy-preview', ...ownerParts], [ownerParts])
  const platformAdmin = props.permissions.includes('platform.admin')
  // Administrators address the site's tenant scope and write there directly
  // (site-parity3b; the service checks the platform role in that scope).
  const targetScopeId = props.scopeKind === 'platform' ? props.siteScopeId ?? '' : props.scopeId
  const canRead = Boolean(targetScopeId) && (platformAdmin || props.permissions.includes('http_policies.read'))
  const canWrite = Boolean(targetScopeId) && props.canManage && !props.lockedForTenant &&
    (platformAdmin || props.permissions.includes('http_policies.manage'))
  const expectedOwner = props.scopeKind === 'tenant' ? props.userId : undefined
  const identity = useMemo<HttpPolicyIdentity>(() => ({ scopeId: targetScopeId, siteId: props.siteId, ownerUserId: expectedOwner }),
    [expectedOwner, targetScopeId, props.siteId])
  const [config, setConfig] = useState<HttpPolicyConfig>(emptyHttpPolicyConfig)
  // Header and redirect dialogs (index null = new)
  const [headerDialog, setHeaderDialog] = useState<{ side: 'request' | 'response'; index: number | null } | null>(null)
  const [redirectDialog, setRedirectDialog] = useState<{ list: 'redirects' | 'rewrites'; index: number | null } | null>(null)
  const [refererDraft, setRefererDraft] = useState<RefererDraft>(emptyRefererDraft)
  const [loadedRevision, setLoadedRevision] = useState(0)
  const attemptRef = useRef<WriteAttempt | null>(null)
  const [attemptID, setAttemptID] = useState<string | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [notice, setNotice] = useState('')
  const [abandoning, setAbandoning] = useState(false)
  const feedback = useInstantFeedback()
  // 发出时的草稿；保存返回时用户又改过就保留当前草稿，等下一次提交。
  const sentRef = useRef<string | null>(null)

  const policyQuery = useQuery({
    queryKey,
    enabled: canRead,
    retry: false,
    queryFn: async () => {
      const token = currentAccess(props, 'http_policies.read')
      if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
      const result = await httpPoliciesApi.list(token, targetScopeId, props.siteId, expectedOwner)
      if (!currentAccess(props, 'http_policies.read')) throw new ApiError('Session changed', 401, 'authentication_required')
      return result
    },
  })
  const previewQuery = useQuery({
    queryKey: previewKey,
    enabled: canRead,
    retry: false,
    queryFn: async () => {
      const token = currentAccess(props, 'http_policies.read')
      if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
      const result = await httpPoliciesApi.preview(token, targetScopeId)
      if (!currentAccess(props, 'http_policies.read')) throw new ApiError('Session changed', 401, 'authentication_required')
      return result
    },
  })
  const policy = policyQuery.data?.items[0]

  useEffect(() => {
    if (!policy || policy.revision === loadedRevision || attemptRef.current) return
    setConfig(configFromHttpPolicy(policy))
    setRefererDraft(policy.referer_check ? refererDraftFrom(policy.referer_check) : emptyRefererDraft())
    setLoadedRevision(policy.revision)
  }, [loadedRevision, policy])

  useEffect(() => {
    attemptRef.current = null
    setAttemptID(null)
    setWriteError(null)
    setNotice('')
    setAbandoning(false)
    setLoadedRevision(0)
    setConfig(emptyHttpPolicyConfig())
    setRefererDraft(emptyRefererDraft())
  }, [owner])

  useEffect(() => () => {
    const state = useSessionStore.getState()
    const principal = state.principal
    if (principal && state.sessionEpoch === props.sessionEpoch && principal.scope_kind === props.scopeKind && principal.scope_id === props.scopeId &&
      principal.tenant_id === props.tenantId && principal.user_id === props.userId) return
    queryClient.removeQueries({ queryKey, exact: true })
    queryClient.removeQueries({ queryKey: previewKey, exact: true })
  }, [previewKey, props.scopeId, props.scopeKind, props.sessionEpoch, props.tenantId, props.userId, queryClient, queryKey])

  const mutation = useMutation({
    retry: false,
    mutationFn: async (id: string) => {
      const attempt = attemptRef.current
      if (!attempt || attempt.id !== id || attempt.owner !== owner) throw new ApiError('Session changed', 401, 'authentication_required')
      const token = currentAccess(props, 'http_policies.manage')
      if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
      if (attempt.operation === 'create' && attempt.config) {
        return httpPoliciesApi.create(token, targetScopeId, props.siteId, attempt.config, attempt.metadata, expectedOwner)
      }
      if (!attempt.policyId || attempt.revision === undefined) throw new ApiError('Invalid attempt', 400, 'invalid_request')
      if (attempt.operation === 'update' && attempt.config) {
        return httpPoliciesApi.update(token, targetScopeId, attempt.policyId, attempt.revision, attempt.config, attempt.metadata, attempt.identity)
      }
      if (attempt.operation === 'delete') {
        return httpPoliciesApi.delete(token, targetScopeId, attempt.policyId, attempt.revision, attempt.metadata, attempt.identity)
      }
      return httpPoliciesApi.setEnabled(token, targetScopeId, attempt.policyId, attempt.revision, attempt.operation === 'enable', attempt.metadata, attempt.identity)
    },
    onSuccess: (result, id) => {
      const completed = attemptRef.current
      if (!completed || completed.id !== id || completed.owner !== owner) return
      queryClient.setQueryData(queryKey, { items: result.deleted ? [] : [result] })
      setLoadedRevision(result.deleted ? 0 : result.revision)
      const editedSince = sentRef.current !== null && sentRef.current !== draftKey.current
      sentRef.current = null
      if (result.deleted) {
        setConfig(emptyHttpPolicyConfig())
        setRefererDraft(emptyRefererDraft())
      } else if (!editedSince) {
        setConfig(configFromHttpPolicy(result))
        setRefererDraft(result.referer_check ? refererDraftFrom(result.referer_check) : emptyRefererDraft())
      }
      if (result.deleted) setNotice(t('deleted'))
      else feedback.success()
      attemptRef.current = null
      setAttemptID(null)
      setWriteError(null)
      void queryClient.invalidateQueries({ queryKey: previewKey, exact: true })
    },
    onError: (error, id) => {
      if (attemptRef.current?.id !== id || attemptRef.current.owner !== owner) return
      setWriteError(error)
      if (!unknownOutcome(error)) {
        attemptRef.current = null
        setAttemptID(null)
        // 明确拒绝：控件回滚到服务端值；版本冲突重读最新值。
        sentRef.current = null
        const stored = policyQuery.data?.items[0]
        setConfig(stored ? configFromHttpPolicy(stored) : emptyHttpPolicyConfig())
        setRefererDraft(stored?.referer_check ? refererDraftFrom(stored.referer_check) : emptyRefererDraft())
        if (error instanceof ApiError && (error.code === 'revision_conflict' || error.status === 412)) void policyQuery.refetch()
      }
    },
  })
  const activeAttempt = attemptRef.current?.owner === owner && attemptRef.current.id === attemptID ? attemptRef.current : null
  const uncertain = Boolean(activeAttempt && writeError && unknownOutcome(writeError))
  const writesLocked = mutation.isPending || uncertain
  // 草稿改动不在请求进行中锁住（键入下一个框时不被禁用）；未知结果期间锁住等重试/放弃。
  const editLocked = uncertain

  const begin = (attempt: WriteAttempt) => {
    if (!canWrite || writesLocked) return
    attemptRef.current = attempt
    setAttemptID(attempt.id)
    setWriteError(null)
    setNotice('')
    mutation.mutate(attempt.id)
  }
  const save = () => {
    if (!canWrite || writesLocked || !draftChanged()) return
    if (!configValid(config)) {
      setWriteError(new ApiError('Invalid HTTP policy form', 422, 'validation_error'))
      return
    }
    const refererCheck = config.referer_check ? refererCheckFrom(refererDraft) : null
    if (config.referer_check && !refererCheck) {
      setWriteError(new ApiError('Invalid referer check', 422, 'referer_check_invalid'))
      return
    }
    sentRef.current = draftKey.current
    const operation = policy ? 'update' : 'create'
    const id = `http-policy-${operation}-${crypto.randomUUID()}`
    begin({ id, owner, operation, policyId: policy?.id, revision: policy?.revision,
      // the allowed redirect hosts are exactly the redirect targets' (the
      // dialog has no host list; the server requires each target's host)
      config: { ...config, referer_check: refererCheck, redirect_allowed_hosts: [...new Set(config.redirects
        .map((rule) => redirectHost(rule.target_url)).filter((host): host is string => Boolean(host)))].sort() },
      metadata: requestMetadata(operation), identity })
  }
  // 草稿一改就请求提交（键入类等失焦/回车）；校验失败就地提示，不提交。
  const draftKey = useRef('')
  draftKey.current = JSON.stringify([config, refererDraft])
  const storedConfig = policy ? configFromHttpPolicy(policy) : emptyHttpPolicyConfig()
  const storedReferer = policy?.referer_check ? refererDraftFrom(policy.referer_check) : emptyRefererDraft()
  const draftChanged = () => {
    const effective = (value: HttpPolicyConfig, referer: RefererDraft) => JSON.stringify({ ...value,
      referer_check: value.referer_check ? refererCheckFrom(referer) ?? referer : null, redirect_allowed_hosts: [] })
    return effective(config, refererDraft) !== effective(storedConfig, storedReferer)
  }
  const commits = useCommitRequest(save, mutation.isPending || policyQuery.isFetching)
  const editConfig: typeof setConfig = (value) => { setWriteError(null); setConfig(value); commits.requestUnlessTyping() }
  const toggle = (enabled: boolean) => {
    if (!policy) return
    const operation = enabled ? 'enable' : 'disable'
    begin({ id: `http-policy-${operation}-${crypto.randomUUID()}`, owner, operation, policyId: policy.id,
      revision: policy.revision, metadata: requestMetadata(operation), identity })
  }
  const removePolicy = () => {
    if (!policy || !window.confirm(t('confirmDelete'))) return
    begin({ id: `http-policy-delete-${crypto.randomUUID()}`, owner, operation: 'delete', policyId: policy.id,
      revision: policy.revision, metadata: requestMetadata('delete'), identity })
  }
  const retryExact = () => {
    if (activeAttempt && !mutation.isPending) mutation.mutate(activeAttempt.id)
  }
  const abandon = async () => {
    if (!activeAttempt || mutation.isPending || abandoning) return
    setAbandoning(true)
    const result = await policyQuery.refetch()
    if (!result.isError) {
      attemptRef.current = null
      setAttemptID(null)
      setWriteError(null)
      void previewQuery.refetch()
    }
    setAbandoning(false)
  }
  const headerList = (side: 'request' | 'response') => side === 'request' ? config.request_headers : config.response_headers
  const submitHeader = (action: HeaderAction) => {
    const dialog = headerDialog
    setHeaderDialog(null)
    if (!dialog) return
    const key = dialog.side === 'request' ? 'request_headers' : 'response_headers'
    editConfig((current) => {
      const list = [...current[key]]
      if (dialog.index === null) list.push(action)
      else list[dialog.index] = action
      return { ...current, [key]: list }
    })
  }
  const removeHeader = (side: 'request' | 'response', index: number) => editConfig((current) => {
    const key = side === 'request' ? 'request_headers' : 'response_headers'
    return { ...current, [key]: current[key].filter((_, position) => position !== index) }
  })
  // 内部重写 lives in rewrites, the others in redirects; editing may move a
  // rule between them (its rule_id kept). A redirect's target host joins
  // redirect_allowed_hosts.
  const submitRedirect = (draft: URLRedirectDraft) => {
    const dialog = redirectDialog
    setRedirectDialog(null)
    if (!dialog) return
    editConfig((current) => {
      const rewrites = [...current.rewrites]
      const redirects = [...current.redirects]
      const previous = dialog.index === null ? undefined : (dialog.list === 'rewrites' ? rewrites : redirects)[dialog.index]
      if (dialog.index !== null) (dialog.list === 'rewrites' ? rewrites : redirects).splice(dialog.index, 1)
      const ruleID = previous?.rule_id ?? crypto.randomUUID()
      const conditions = draft.conditions.length ? { conditions: draft.conditions } : {}
      let allowed = current.redirect_allowed_hosts
      if (draft.type === 'rewrite') {
        rewrites.push({ rule_id: ruleID, priority: previous?.priority ?? rewrites.length + redirects.length, match_kind: draft.match_kind,
          match_path: draft.match_path, target_path: draft.target, preserve_query: draft.preserve_query, preserve_cookie: true, ...conditions })
      } else {
        redirects.push({ rule_id: ruleID, priority: previous?.priority ?? rewrites.length + redirects.length, match_kind: draft.match_kind,
          match_path: draft.match_path, status: draft.type, target_url: draft.target, preserve_query: draft.preserve_query,
          preserve_path: false, ...conditions })
        const host = redirectHost(draft.target)
        if (host && !allowed.includes(host)) allowed = [...allowed, host]
      }
      return { ...current, rewrites, redirects, redirect_allowed_hosts: allowed }
    })
  }
  const updateCors = (changes: Partial<NonNullable<HttpPolicyConfig['cors']>>) => editConfig((current) => ({ ...current,
    cors: current.cors ? { ...current.cors, ...changes } : null }))

  const locked = !canWrite || editLocked
  if (!canRead) {
    const denied = <SiteEditState status="forbidden" title={t('readForbidden')} />
    return props.children ? props.children(null, denied) : denied
  }
  if (policyQuery.isPending || policyQuery.isError) {
    const state = policyQuery.isPending
      ? <SiteEditState status="loading" label={t('loading')} />
      : <SiteEditState status={policyQuery.error instanceof ApiError && policyQuery.error.status === 403 ? 'forbidden' : 'error'}
        title={t('loadFailed')} onRetry={() => { void policyQuery.refetch() }} />
    return props.children ? props.children(null, state) : state
  }

  const preview = previewQuery.data
  const included = preview?.snapshot.sites.some((site) => site.site_id === props.siteId) ?? false
  const custom = config.max_upload_bytes !== MAX_HTTP_POLICY_UPLOAD_BYTES
  const updateReferer = (changes: Partial<RefererDraft>) => { setWriteError(null); setRefererDraft((current) => ({ ...current, ...changes })); commits.requestUnlessTyping() }
  const empty = (text: string) => <div className="site-setting-empty">{text}</div>
  const count = (value: number) => t('count', { count: value })

  const kindLabel = (kind: HeaderAction['kind']) => t(kind === 'add' ? 'actionAdd' : kind === 'set' ? 'actionSet' : 'actionDelete')
  const headerColumns = (side: 'request' | 'response'): TableColumnsType<HeaderAction> => [
    { title: t('headerColName'), dataIndex: 'name', key: 'name' },
    { title: t('headerColValue'), key: 'value', render: (_: unknown, action) => action.values.length ? <code>{action.values.join(' | ')}</code> : '—' },
    { title: t('headerColAction'), key: 'kind', width: 90, render: (_: unknown, action) => kindLabel(action.kind) },
    { title: t('headerColDuplicate'), key: 'duplicate', width: 90,
      render: (_: unknown, action) => action.kind === 'add' ? t(action.allow_duplicate ? 'yes' : 'no') : '—' },
    ...(canWrite ? [{
      title: t('headerColOps'), key: 'ops', width: 140,
      render: (_: unknown, __: HeaderAction, index: number) => <Space size={4}>
        <Button type="link" size="small" disabled={editLocked} onClick={() => setHeaderDialog({ side, index })}>{t('editHeader')}</Button>
        <Button type="link" danger size="small" disabled={editLocked} onClick={() => removeHeader(side, index)}>{t('remove')}</Button>
      </Space>,
    }] : []),
  ]
  type RedirectRow = { key: string; list: 'redirects' | 'rewrites'; index: number; match: string; target: string; type: string; conditions: number }
  const redirectRows: RedirectRow[] = [
    ...config.redirects.map((rule, index) => ({ key: rule.rule_id, list: 'redirects' as const, index, match: rule.match_path,
      target: rule.target_url, type: t(`redirect${rule.status}`), conditions: rule.conditions?.length ?? 0, priority: rule.priority })),
    ...config.rewrites.map((rule, index) => ({ key: rule.rule_id, list: 'rewrites' as const, index, match: rule.match_path,
      target: rule.target_path, type: t('redirectRewrite'), conditions: rule.conditions?.length ?? 0, priority: rule.priority })),
  ].sort((left, right) => left.priority - right.priority)
  const removeRedirect = (row: RedirectRow) => editConfig((current) => ({ ...current,
    [row.list]: current[row.list].filter((_: unknown, position: number) => position !== row.index) }))
  const redirectColumns: TableColumnsType<RedirectRow> = [
    { title: t('redirectColMatch'), key: 'match', render: (_: unknown, row) => <code>{row.match}</code> },
    { title: t('redirectColTarget'), key: 'target', render: (_: unknown, row) => <code>{row.target}</code> },
    { title: t('redirectColType'), dataIndex: 'type', key: 'type', width: 120 },
    { title: t('redirectColConditions'), key: 'conditions', width: 110,
      render: (_: unknown, row) => row.conditions ? t('conditionsSet', { count: row.conditions }) : t('conditionsUnset') },
    ...(canWrite ? [{
      title: t('redirectColOps'), key: 'ops', width: 140,
      render: (_: unknown, row: RedirectRow) => <Space size={4}>
        <Button type="link" size="small" disabled={editLocked} onClick={() => setRedirectDialog({ list: row.list, index: row.index })}>{t('editHeader')}</Button>
        <Button type="link" danger size="small" disabled={editLocked} onClick={() => removeRedirect(row)}>{t('remove')}</Button>
      </Space>,
    }] : []),
  ]

  const parts: HTTPPolicyParts = {
    upload: <div className="site-instant-contents" {...commits.typingProps}>
      <FormRow label={t('uploadLimit')}>
        <Radio.Group aria-label={t('uploadLimit')} optionType="button" disabled={locked} value={custom ? 'custom' : 'max'}
          options={[{ value: 'max', label: t('uploadMax') }, { value: 'custom', label: t('uploadCustom') }]}
          onChange={(event) => editConfig((current) => ({ ...current,
            max_upload_bytes: event.target.value === 'max' ? MAX_HTTP_POLICY_UPLOAD_BYTES : 100 * 1024 * 1024 }))} />
      </FormRow>
      {custom ? (
        <FormRow label={t('maxUploadBytes')} help={t('uploadHint')}>
          <InputNumber aria-label={t('maxUploadBytes')} min={1} max={MAX_HTTP_POLICY_UPLOAD_BYTES} value={config.max_upload_bytes}
            disabled={locked} onChange={(value) => value !== null && editConfig((current) => ({ ...current, max_upload_bytes: value }))} />
        </FormRow>
      ) : null}
    </div>,
    referer: (
      <div className="site-instant-contents" {...commits.typingProps}><SettingGroup title={t('refererTitle')} status={config.referer_check ? t('stateOn') : t('stateOff')} help={t('refererShort')} tip={t('refererHelp')}
        extra={<Switch aria-label={t('refererEnabled')} checked={config.referer_check !== null} disabled={locked}
          onChange={(enabled) => editConfig((current) => ({ ...current, referer_check: enabled
            ? refererCheckFrom(refererDraft) ?? refererCheckFrom(emptyRefererDraft()) : null }))} />}>
        {config.referer_check ? <>
          <FormRow label={t('refererAllow')}>
            <Space wrap>
              <Checkbox aria-label={t('refererAllowEmpty')} checked={refererDraft.allowEmpty} disabled={locked} onChange={(event) => updateReferer({ allowEmpty: event.target.checked })}>{t('refererAllowEmpty')}</Checkbox>
              <Checkbox aria-label={t('refererAllowSameDomain')} checked={refererDraft.allowSameDomain} disabled={locked} onChange={(event) => updateReferer({ allowSameDomain: event.target.checked })}>{t('refererAllowSameDomain')}</Checkbox>
              <Checkbox aria-label={t('refererCheckOrigin')} checked={refererDraft.checkOrigin} disabled={locked} onChange={(event) => updateReferer({ checkOrigin: event.target.checked })}>{t('refererCheckOrigin')}</Checkbox>
            </Space>
          </FormRow>
          <FormRow label={t('refererAllowedDomains')}>
            <Input.TextArea aria-label={t('refererAllowedDomains')} rows={3} placeholder="*.example.com" value={refererDraft.allowedDomains} disabled={locked} onChange={(event) => updateReferer({ allowedDomains: event.target.value })} />
          </FormRow>
          <FormRow label={t('refererDeniedDomains')}>
            <Input.TextArea aria-label={t('refererDeniedDomains')} rows={3} value={refererDraft.deniedDomains} disabled={locked} onChange={(event) => updateReferer({ deniedDomains: event.target.value })} />
          </FormRow>
          <FormRow label={t('refererExtensions')} help={t('refererExtensionsHint')}>
            <Input.TextArea aria-label={t('refererExtensions')} rows={2} placeholder="jpg" value={refererDraft.extensions} disabled={locked} onChange={(event) => updateReferer({ extensions: event.target.value })} />
          </FormRow>
        </> : empty(t('refererOff'))}
      </SettingGroup></div>
    ),
    cors: (
      <div className="site-instant-contents" {...commits.typingProps}><SettingGroup title={t('corsTitle')} status={config.cors ? t('stateOn') : t('stateOff')} help={t('corsShort')}
        extra={<Switch aria-label={t('corsEnabled')} checked={config.cors !== null} disabled={locked}
          onChange={(enabled) => editConfig((current) => ({ ...current, cors: enabled ? {
            allowed_origins: [], allowed_methods: [], allowed_headers: [], exposed_headers: [], allow_credentials: false, max_age_seconds: 600,
          } : null }))} />}>
        {config.cors ? <>
          <FormRow label={t('corsOrigins')}><Input.TextArea aria-label={t('corsOrigins')} value={config.cors.allowed_origins.join('\n')} disabled={locked} onChange={(event) => updateCors({ allowed_origins: lines(event.target.value) })} /></FormRow>
          <FormRow label={t('corsMethods')}><Input.TextArea aria-label={t('corsMethods')} value={config.cors.allowed_methods.join('\n')} disabled={locked} onChange={(event) => updateCors({ allowed_methods: lines(event.target.value).map((item) => item.toUpperCase()) })} /></FormRow>
          <FormRow label={t('corsAllowedHeaders')}><Input.TextArea aria-label={t('corsAllowedHeaders')} value={config.cors.allowed_headers.join('\n')} disabled={locked} onChange={(event) => updateCors({ allowed_headers: lines(event.target.value).map((item) => item.toLowerCase()) })} /></FormRow>
          <FormRow label={t('corsExposedHeaders')}><Input.TextArea aria-label={t('corsExposedHeaders')} value={config.cors.exposed_headers.join('\n')} disabled={locked} onChange={(event) => updateCors({ exposed_headers: lines(event.target.value).map((item) => item.toLowerCase()) })} /></FormRow>
          <FormRow label={t('corsAllowCredentials')}><Switch aria-label={t('corsAllowCredentials')} checked={config.cors.allow_credentials} disabled={locked} onChange={(value) => updateCors({ allow_credentials: value })} /></FormRow>
          <FormRow label={t('corsMaxAge')}><InputNumber aria-label={t('corsMaxAge')} min={0} max={86400} value={config.cors.max_age_seconds} disabled={locked} onChange={(value) => value !== null && updateCors({ max_age_seconds: value })} /></FormRow>
        </> : empty(t('corsOff'))}
      </SettingGroup></div>
    ),
    // URL 转向 (one list; 内部重写 is one of its types, our rewrites)
    redirects: (
      <SettingGroup title={t('redirects')} status={count(redirectRows.length)} help={t('redirectsShort')}
        extra={canWrite ? <Button type="primary" icon={<Plus size={15} />} disabled={editLocked}
          onClick={() => setRedirectDialog({ list: 'redirects', index: null })}>{t('addRedirect')}</Button> : null}>
        {redirectRows.length ? (
          <Table<RedirectRow> rowKey="key" size="small" pagination={false} columns={redirectColumns} dataSource={redirectRows} scroll={{ x: 640 }} />
        ) : empty(t('redirectsEmpty'))}
      </SettingGroup>
    ),
    rewrites: null,
    requestHeaders: (
      <SettingGroup title={t('requestHeadersTitle')} status={count(config.request_headers.length)} help={t('requestHeadersShort')}
        extra={canWrite ? <Button type="primary" icon={<Plus size={15} />} disabled={editLocked}
          onClick={() => setHeaderDialog({ side: 'request', index: null })}>{t('addRequestHeader')}</Button> : null}>
        {config.request_headers.length ? (
          <Table<HeaderAction> rowKey="name" size="small" pagination={false} columns={headerColumns('request')}
            dataSource={config.request_headers} scroll={{ x: 560 }} />
        ) : empty(t('requestHeadersEmpty'))}
      </SettingGroup>
    ),
    responseHeaders: (
      <SettingGroup title={t('responseHeadersTitle')} status={count(config.response_headers.length)} help={t('responseHeadersShort')} tip={t('responseHeaderHint')}
        extra={canWrite ? <Button type="primary" icon={<Plus size={15} />} disabled={editLocked}
          onClick={() => setHeaderDialog({ side: 'response', index: null })}>{t('addResponseHeader')}</Button> : null}>
        {config.response_headers.length ? (
          <Table<HeaderAction> rowKey="name" size="small" pagination={false} columns={headerColumns('response')}
            dataSource={config.response_headers} scroll={{ x: 560 }} />
        ) : empty(t('responseHeadersEmpty'))}
      </SettingGroup>
    ),
    actions: <>
      {!policy ? <p className="site-setting-section-help">{t('empty')}</p> : null}
      {!canWrite ? <Alert type="info" message={t('readOnly')} /> : null}
      {notice ? <Alert type="success" message={notice} closable onClose={() => setNotice('')} /> : null}
      {writeError ? uncertain ? <OutcomeUnknown title={t('unknownTitle')} detail={t('unknownDescription')} action={<Space><Button loading={abandoning} disabled={mutation.isPending} onClick={() => { void abandon() }}>{t('abandonRefresh')}</Button>
          <Button type="primary" loading={mutation.isPending} disabled={abandoning} onClick={retryExact}>{t('retryExact')}</Button></Space>} />
        : <FeedbackWhen title={t(errorKey(writeError))} /> : null}
      {canWrite ? <div className="site-setting-actions">
        {policy ? <Switch aria-label={policy.enabled ? t('disable') : t('enable')} checked={policy.enabled} disabled={writesLocked} onChange={toggle} /> : null}
        {policy ? <Button danger icon={<Trash2 size={15} />} disabled={writesLocked} onClick={removePolicy}>{t('delete')}</Button> : null}
        <span className="site-setting-section-help">{t('saveScope')}</span>
      </div> : null}
      {headerDialog ? (
        <HTTPHeaderDialog open side={headerDialog.side} disabled={locked}
          action={headerDialog.index === null ? null : headerList(headerDialog.side)[headerDialog.index] ?? null}
          takenNames={headerList(headerDialog.side).filter((_, position) => position !== headerDialog.index).map((item) => item.name.toLowerCase())}
          onCancel={() => setHeaderDialog(null)} onSubmit={submitHeader} />
      ) : null}
      {redirectDialog ? (
        <URLRedirectDialog open disabled={locked} onCancel={() => setRedirectDialog(null)} onSubmit={submitRedirect}
          draft={redirectDialog.index === null ? null : redirectDialog.list === 'rewrites'
            ? draftFromRewrite(config.rewrites[redirectDialog.index]!) : draftFromRedirect(config.redirects[redirectDialog.index]!)} />
      ) : null}
      <h3 className="site-setting-subtitle">{t('publicationPreview')}</h3>
      {preview ? <Alert type="info" message={t('previewSummary', { revision: preview.snapshot.policy_version, included: t(included ? 'previewIncluded' : 'previewExcluded') })}
        description={<code>{preview.sha256}</code>} /> : previewQuery.isPending ? <Spin size="small" /> : <Alert type="info" message={t('previewUnavailable')} />}
    </>,
  }
  if (props.children) return props.children(parts, null)
  return (
    <SettingSection title={t('title')} help={t('description')}>
      {parts.upload}{parts.referer}{parts.cors}{parts.redirects}{parts.rewrites}{parts.requestHeaders}{parts.responseHeaders}{parts.actions}
    </SettingSection>
  )
}
