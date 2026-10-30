import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Result,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { CloudUpload, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import {
  challengePoliciesApi,
  type ChallengeBypassRoute,
  type ChallengeMode,
  type ChallengePolicy,
  type ChallengePolicyConfig,
  type ChallengePublicationStatus,
  type CreateChallengePolicyInput,
  type IPBinding,
} from '../../api/challengePolicies'
import { useSessionStore } from '../../auth/session'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/challengePolicies'
import { formatDateTime } from '../../i18n/formatters'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const hostPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/
const keyPattern = /^(?:keyref|vault|kms):[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$/
const appPattern = /^appref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,120}$/

interface PolicyForm {
  site_id: string
  host: string
  enabled: boolean
  priority: number
  mode: ChallengeMode
  min_delay_seconds: number
  challenge_ttl_seconds: number
  pass_ttl_seconds: number
  clock_skew_seconds: number
  failure_window_seconds: number
  max_failures_per_window: number
  ip_binding: IPBinding
  bind_user_agent: boolean
  bypass_routes: string
  key_reference: string
  provider?: 'tencent' | 'geetest-v4'
  app_reference?: string
}

type WriteAttempt =
  | { kind: 'create'; ownerKey: string; scopeID: string; input: CreateChallengePolicyInput; key: string }
  | { kind: 'update'; ownerKey: string; scopeID: string; id: string; revision: number; config: ChallengePolicyConfig; enabled: boolean; key: string }
  | { kind: 'delete' | 'enable' | 'disable'; ownerKey: string; scopeID: string; id: string; revision: number; key: string }

function writeKey(kind: WriteAttempt['kind']): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `challenge-policy-${kind}-${suffix}`
}

function unknownOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

function localError(error: ApiError, t: TFunction<'challengePolicies'>): string {
  const known = new Set(['invalid_response', 'permission_denied', 'revision_conflict', 'idempotency_conflict', 'validation_error', 'request_failed'])
  return known.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.request_failed'))
}

function parseBypassRoutes(value: string): ChallengeBypassRoute[] {
  const lines = value.split('\n').filter((line) => line.length > 0)
  if (lines.length > 32) throw new Error('too many bypass routes')
  const seen = new Set<string>()
  return lines.map((line) => {
    const separator = line.indexOf(' ')
    const kind = line.slice(0, separator)
    const path = line.slice(separator + 1)
    if (separator < 0 || (kind !== 'exact' && kind !== 'prefix') ||
      path.length < 1 || path.length > 512 || !/^[\x20-\x7e]+$/.test(path) || !path.startsWith('/') ||
      path.startsWith('//') || path.includes('//') || /[?%#\\]/.test(path) ||
      path.split('/').some((part) => part === '.' || part === '..') ||
      kind === 'prefix' && (path === '/' || !path.endsWith('/')) || seen.has(path)) throw new Error('invalid bypass route')
    seen.add(path)
    return { kind, path }
  })
}

/** A11: the site a site-edit link opened this page for (site_id/host/mode/tenant_scope_id in the URL). */
interface SiteIntent { siteID: string; host: string; mode?: ChallengeMode; tenantScopeID: string }

const challengeModes: readonly ChallengeMode[] = ['delay', 'click', 'slider', 'captcha', 'external']

function siteIntentFrom(params: URLSearchParams): SiteIntent | null {
  const siteID = (params.get('site_id') ?? '').trim().toLowerCase()
  if (!uuidPattern.test(siteID)) return null
  const host = (params.get('host') ?? '').trim().toLowerCase()
  const mode = params.get('mode') as ChallengeMode | null
  const tenantScopeID = (params.get('tenant_scope_id') ?? '').trim().toLowerCase()
  return { siteID, host: hostPattern.test(host) ? host : '', mode: mode && challengeModes.includes(mode) ? mode : undefined,
    tenantScopeID: uuidPattern.test(tenantScopeID) ? tenantScopeID : '' }
}

function initialForm(item: ChallengePolicy | null, intent?: SiteIntent | null): PolicyForm {
  return {
    site_id: item?.site_id ?? intent?.siteID ?? '',
    host: item?.host ?? intent?.host ?? '',
    enabled: item?.enabled ?? true,
    priority: item?.priority ?? 100,
    mode: item?.mode ?? intent?.mode ?? 'click',
    min_delay_seconds: item?.min_delay_seconds ?? 0,
    challenge_ttl_seconds: item?.challenge_ttl_seconds ?? 60,
    pass_ttl_seconds: item?.pass_ttl_seconds ?? 900,
    clock_skew_seconds: item?.clock_skew_seconds ?? 5,
    failure_window_seconds: item?.failure_window_seconds ?? 60,
    max_failures_per_window: item?.max_failures_per_window ?? 5,
    ip_binding: item?.ip_binding ?? 'exact',
    bind_user_agent: item?.bind_user_agent ?? true,
    bypass_routes: item?.bypass_routes.map((route) => `${route.kind} ${route.path}`).join('\n') ?? '',
    key_reference: '',
    provider: undefined,
    app_reference: '',
  }
}

function configFromForm(values: PolicyForm): ChallengePolicyConfig {
  const minDelay = values.mode === 'delay' ? values.min_delay_seconds : 0
  if (values.challenge_ttl_seconds <= minDelay + values.clock_skew_seconds ||
    values.key_reference.length < 8 || values.key_reference.length > 128 || !keyPattern.test(values.key_reference)) {
    throw new Error('invalid challenge config')
  }
  if (values.mode === 'external' && (!values.provider || !values.app_reference ||
    values.app_reference.length < 8 || values.app_reference.length > 128 || !appPattern.test(values.app_reference))) {
    throw new Error('invalid external provider reference')
  }
  return {
    priority: values.priority,
    mode: values.mode,
    min_delay_seconds: minDelay,
    challenge_ttl_seconds: values.challenge_ttl_seconds,
    pass_ttl_seconds: values.pass_ttl_seconds,
    clock_skew_seconds: values.clock_skew_seconds,
    attempts_per_nonce: 1,
    failure_window_seconds: values.failure_window_seconds,
    max_failures_per_window: values.max_failures_per_window,
    ip_binding: values.ip_binding,
    bind_user_agent: values.bind_user_agent,
    bypass_routes: parseBypassRoutes(values.bypass_routes),
    key_reference: values.key_reference,
    ...(values.mode === 'external' ? {
      external_provider: { provider: values.provider!, app_reference: values.app_reference! },
    } : {}),
  }
}

function PolicyEditor({
  item, intent, pending, canSubmit, onCancel, onSubmit,
}: {
  item: ChallengePolicy | null
  intent?: SiteIntent | null
  pending: boolean
  canSubmit: boolean
  onCancel: () => void
  onSubmit: (values: PolicyForm) => void
}) {
  const { t } = useTranslation('challengePolicies')
  const [form] = Form.useForm<PolicyForm>()
  const mode = Form.useWatch('mode', form) ?? item?.mode ?? intent?.mode ?? 'click'
  return (
    <Modal
      className="identity-modal challenge-policy-modal"
      open
      title={t(item ? 'editor.editTitle' : 'editor.createTitle')}
      width={820}
      confirmLoading={pending}
      okButtonProps={{ disabled: !canSubmit }}
      okText={t('actions.save')}
      cancelText={t('actions.cancel')}
      onCancel={onCancel}
      onOk={() => void form.validateFields().then(onSubmit).catch(() => undefined)}
      destroyOnHidden
    >
      <Form form={form} initialValues={initialForm(item, intent)} layout="vertical" requiredMark={false}>
        <Space size={12} wrap align="start">
          <Form.Item name="site_id" label={t('editor.site')} rules={[{ required: true, message: t('validation.required') }, { pattern: uuidPattern, message: t('validation.uuid') }]}>
            <Input disabled={Boolean(item)} style={{ width: 300 }} />
          </Form.Item>
          <Form.Item name="host" label={t('editor.host')} rules={[{ required: true, message: t('validation.required') }, { max: 253, message: t('validation.host') }, { pattern: hostPattern, message: t('validation.host') }]}>
            <Input disabled={Boolean(item)} style={{ width: 300 }} />
          </Form.Item>
          {!item ? <Form.Item name="enabled" label={t('editor.enabled')} valuePropName="checked"><Switch /></Form.Item> : null}
        </Space>
        <Space size={12} wrap align="start">
          <Form.Item name="priority" label={t('editor.priority')} rules={[{ required: true, type: 'number', min: 1, max: 1_000_000 }]}>
            <InputNumber min={1} max={1_000_000} precision={0} />
          </Form.Item>
          <Form.Item name="mode" label={t('editor.mode')} rules={[{ required: true }]}>
            <Select style={{ width: 150 }} options={(['delay', 'click', 'slider', 'captcha', 'external'] as const).map((value) => ({ value, label: t(`modes.${value}`) }))} />
          </Form.Item>
          {mode === 'delay' ? <Form.Item name="min_delay_seconds" label={t('editor.minDelay')} rules={[{ required: true, type: 'number', min: 5, max: 10 }]}><InputNumber min={5} max={10} precision={0} /></Form.Item> : null}
          <Form.Item
            name="challenge_ttl_seconds"
            label={t('editor.challengeTTL')}
            dependencies={['mode', 'min_delay_seconds', 'clock_skew_seconds']}
            rules={[
              { required: true, type: 'number', min: 10, max: 300 },
              { validator: async (_, value: number) => {
                if (!Number.isFinite(value)) return
                const minDelay = form.getFieldValue('mode') === 'delay' ? Number(form.getFieldValue('min_delay_seconds') ?? 0) : 0
                const clockSkew = Number(form.getFieldValue('clock_skew_seconds') ?? 0)
                if (value <= minDelay + clockSkew) throw new Error(t('validation.ttl'))
              } },
            ]}
          ><InputNumber min={10} max={300} precision={0} /></Form.Item>
          <Form.Item name="pass_ttl_seconds" label={t('editor.passTTL')} rules={[{ required: true, type: 'number', min: 1, max: 3600 }]}><InputNumber min={1} max={3600} precision={0} /></Form.Item>
          <Form.Item name="clock_skew_seconds" label={t('editor.clockSkew')} rules={[{ required: true, type: 'number', min: 0, max: 30 }]}><InputNumber min={0} max={30} precision={0} /></Form.Item>
        </Space>
        <Space size={12} wrap align="start">
          <Form.Item name="failure_window_seconds" label={t('editor.failureWindow')} rules={[{ required: true, type: 'number', min: 1, max: 3600 }]}><InputNumber min={1} max={3600} precision={0} /></Form.Item>
          <Form.Item name="max_failures_per_window" label={t('editor.maxFailures')} rules={[{ required: true, type: 'number', min: 1, max: 20 }]}><InputNumber min={1} max={20} precision={0} /></Form.Item>
          <Form.Item name="ip_binding" label={t('editor.ipBinding')} rules={[{ required: true }]}><Select style={{ width: 130 }} options={[{ value: 'none', label: t('bindings.none') }, { value: 'exact', label: t('bindings.ip') }]} /></Form.Item>
          <Form.Item name="bind_user_agent" label={t('editor.bindUA')} valuePropName="checked"><Switch /></Form.Item>
        </Space>
        <Alert type="info" showIcon message={t('editor.attempts')} style={{ marginBottom: 16 }} />
        <Form.Item
          name="bypass_routes"
          label={t('editor.bypass')}
          rules={[{ validator: async (_, value: string) => { try { parseBypassRoutes(value ?? '') } catch { throw new Error(t('validation.bypass')) } } }]}
        >
          <Input.TextArea rows={3} placeholder={t('editor.bypassPlaceholder')} />
        </Form.Item>
        <Form.Item name="key_reference" label={t('editor.keyReference')} rules={[{ required: true, message: t('validation.required') }, { min: 8, max: 128, message: t('validation.key') }, { pattern: keyPattern, message: t('validation.key') }]}>
          <Input.Password autoComplete="off" placeholder={t('editor.keyPlaceholder')} />
        </Form.Item>
        {mode === 'external' ? <Space size={12} wrap align="start">
          <Form.Item name="provider" label={t('editor.provider')} rules={[{ required: true, message: t('validation.required') }]}>
            <Select style={{ width: 180 }} options={[{ value: 'tencent', label: t('providers.tencent') }, { value: 'geetest-v4', label: t('providers.geetest') }]} />
          </Form.Item>
          <Form.Item name="app_reference" label={t('editor.appReference')} rules={[{ required: true, message: t('validation.required') }, { min: 8, max: 128, message: t('validation.app') }, { pattern: appPattern, message: t('validation.app') }]}>
            <Input.Password autoComplete="off" style={{ width: 320 }} placeholder={t('editor.appPlaceholder')} />
          </Form.Item>
        </Space> : null}
      </Form>
    </Modal>
  )
}

function bindingLabel(item: ChallengePolicy, t: TFunction<'challengePolicies'>): string {
  if (item.ip_binding === 'exact' && item.bind_user_agent) return t('bindings.both')
  if (item.ip_binding === 'exact') return t('bindings.ip')
  if (item.bind_user_agent) return t('bindings.userAgent')
  return t('bindings.none')
}

export default function ChallengePoliciesPanel() {
  const { t, i18n } = useTranslation('challengePolicies')
  const [searchParams] = useSearchParams()
  const [intent] = useState(() => siteIntentFrom(searchParams))
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const permissions = principal?.permissions ?? []
  const canRead = permissions.includes('challenge_policies.read')
  const canManage = permissions.includes('challenge_policies.manage')
  const isPlatform = principal?.scope_kind === 'platform'
  const identityKey = principal && sessionEpoch > 0
    ? JSON.stringify([
        principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch,
      ])
    : ''
  const ownerKey = accessToken && canRead ? identityKey : ''
  const ownerKeyRef = useRef(ownerKey)
  ownerKeyRef.current = ownerKey
  const previousOwnerKeyRef = useRef(ownerKey)
  const ownerChanged = previousOwnerKeyRef.current !== ownerKey
  // A11: opened from a site, the target tenant (administrators) and the
  // site/host filters start on that site.
  const [targetDraft, setTargetDraft] = useState(() => isPlatform ? intent?.tenantScopeID ?? '' : '')
  const [targetScopeID, setTargetScopeID] = useState(() => isPlatform ? intent?.tenantScopeID ?? '' : '')
  const [targetError, setTargetError] = useState(false)
  const [limit, setLimit] = useState(20)
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [siteDraft, setSiteDraft] = useState(() => intent?.siteID ?? '')
  const [hostDraft, setHostDraft] = useState(() => intent?.host ?? '')
  const [enabledDraft, setEnabledDraft] = useState<boolean>()
  const [filters, setFilters] = useState<{ site_id?: string; host?: string; enabled?: boolean }>(() => intent
    ? { site_id: intent.siteID, ...(intent.host ? { host: intent.host } : {}) } : {})
  const [editor, setEditor] = useState<ChallengePolicy | 'create' | null>(null)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const attemptRef = useRef<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [publications, setPublications] = useState<Record<string, ChallengePublicationStatus>>({})
  const [publicationBusy, setPublicationBusy] = useState('')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const activeTargetDraft = ownerChanged ? '' : targetDraft
  const activeTargetScopeID = ownerChanged ? '' : targetScopeID
  const activeLimit = ownerChanged ? 20 : limit
  const activeCursorStack = ownerChanged ? [] : cursorStack
  const activeSiteDraft = ownerChanged ? '' : siteDraft
  const activeHostDraft = ownerChanged ? '' : hostDraft
  const activeEnabledDraft = ownerChanged ? undefined : enabledDraft
  const activeFilters = ownerChanged ? {} : filters
  const activeEditor = ownerChanged ? null : editor
  const scopeID = principal ? isPlatform ? activeTargetScopeID : principal.scope_id : ''
  const scopeIDRef = useRef(scopeID)
  scopeIDRef.current = scopeID
  const activeWriteError = ownerChanged || attempt?.scopeID !== scopeID ? null : writeError
  const activePublications = ownerChanged ? {} : publications
  const cursor = activeCursorStack.at(-1)
  const scopeReady = uuidPattern.test(scopeID)

  const query = useQuery({
    queryKey: ['challenge-policies', ownerKey, scopeID, activeLimit, cursor, activeFilters],
    queryFn: ({ signal }) => challengePoliciesApi.list(accessToken!, scopeID, { limit: activeLimit, cursor, ...activeFilters }, signal),
    enabled: Boolean(ownerKey && scopeReady),
  })

  function currentSessionTokenForManage(expectedOwnerKey: string, expectedScopeID: string): string | null {
    const state = useSessionStore.getState()
    if (expectedOwnerKey !== ownerKeyRef.current || !state.accessToken || !state.principal || state.sessionEpoch < 1 ||
      !state.principal.permissions.includes('challenge_policies.read') ||
      !state.principal.permissions.includes('challenge_policies.manage')) return null
    const currentIdentity = JSON.stringify([
      state.principal.scope_kind, state.principal.scope_id, state.principal.tenant_id, state.principal.user_id,
      state.sessionEpoch,
    ])
    return currentIdentity === expectedOwnerKey && expectedScopeID === scopeIDRef.current &&
      (state.principal.scope_kind === 'platform' || state.principal.scope_id === expectedScopeID)
      ? state.accessToken
      : null
  }

  const mutation = useMutation<ChallengePolicy, Error, string>({
    mutationKey: ['challenge-policies-write', ownerKey, scopeID],
    gcTime: 0,
    mutationFn: (attemptKey) => {
      const next = attemptRef.current
      if (!next || next.key !== attemptKey) throw new ApiError('Write request unavailable', 409, 'request_failed')
      const currentToken = currentSessionTokenForManage(next.ownerKey, next.scopeID)
      if (!currentToken) throw new ApiError('permission denied', 403, 'permission_denied')
      if (next.kind === 'create') return challengePoliciesApi.create(currentToken, next.scopeID, next.input, next.key)
      if (next.kind === 'update') return challengePoliciesApi.update(currentToken, next.scopeID, next.id, next.revision, next.config, next.enabled, next.key)
      if (next.kind === 'delete') return challengePoliciesApi.remove(currentToken, next.scopeID, next.id, next.revision, next.key)
      return challengePoliciesApi[next.kind](currentToken, next.scopeID, next.id, next.revision, next.key)
    },
    onSuccess: (_, completedKey) => {
      const completed = attemptRef.current
      if (!completed || completed.key !== completedKey) return
      attemptRef.current = null
      setAttempt((current) => current?.key === completedKey ? null : current)
      if (completed.ownerKey !== ownerKeyRef.current || completed.scopeID !== scopeIDRef.current) return
      setWriteError(null)
      setEditor(null)
      void queryClient.invalidateQueries({ queryKey: ['challenge-policies', completed.ownerKey, completed.scopeID] })
      messageApi.success(t(`notices.${completed.kind}`))
    },
    onError: (error, failedKey) => {
      const failed = attemptRef.current
      if (!failed || failed.key !== failedKey) return
      if (failed.ownerKey !== ownerKeyRef.current || failed.scopeID !== scopeIDRef.current) {
        attemptRef.current = null
        setAttempt((current) => current?.key === failedKey ? null : current)
        return
      }
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      if (unknownOutcome(error)) {
        setAttempt(failed)
        return
      }
      attemptRef.current = null
      setAttempt(null)
      if (apiError.status === 412 || apiError.code === 'revision_conflict') {
        setEditor(null)
        setWriteError(null)
        void query.refetch()
        feedback.error(t('notices.conflict'))
      }
    },
  })

  const resetMutation = mutation.reset
  useEffect(() => () => {
    attemptRef.current = null
  }, [])
  useEffect(() => {
    if (previousOwnerKeyRef.current === ownerKey) return
    const previousOwnerKey = previousOwnerKeyRef.current
    previousOwnerKeyRef.current = ownerKey
    if (previousOwnerKey) {
      queryClient.removeQueries({ queryKey: ['challenge-policies', previousOwnerKey] })
      for (const cachedMutation of queryClient.getMutationCache().findAll({
        mutationKey: ['challenge-policies-write', previousOwnerKey],
      })) queryClient.getMutationCache().remove(cachedMutation)
    }
    setTargetDraft('')
    setTargetScopeID('')
    setTargetError(false)
    setLimit(20)
    setCursorStack([])
    setSiteDraft('')
    setHostDraft('')
    setEnabledDraft(undefined)
    setFilters({})
    setEditor(null)
    attemptRef.current = null
    setAttempt(null)
    setWriteError(null)
    resetMutation()
  }, [ownerKey, queryClient, resetMutation])

  const activeAttempt = attempt?.ownerKey === ownerKey && attempt.scopeID === scopeID ? attempt : null
  const uncertain = Boolean(activeAttempt && activeWriteError && unknownOutcome(activeWriteError))
  const mutationPending = mutation.isPending && mutation.variables === activeAttempt?.key
  const writesLocked = mutationPending || uncertain

  function begin(next: WriteAttempt) {
    if (writesLocked || !currentSessionTokenForManage(next.ownerKey, next.scopeID)) return
    attemptRef.current = next
    setAttempt(next)
    setWriteError(null)
    mutation.mutate(next.key)
  }

  function submit(values: PolicyForm) {
    if (!currentSessionTokenForManage(ownerKey, scopeID) || writesLocked) return
    let config: ChallengePolicyConfig
    try {
      config = configFromForm(values)
    } catch {
      return
    }
    const next: WriteAttempt = activeEditor === 'create'
      ? { kind: 'create', ownerKey, scopeID, input: { site_id: values.site_id, host: values.host, enabled: values.enabled, config }, key: writeKey('create') }
      : { kind: 'update', ownerKey, scopeID, id: activeEditor!.id, revision: activeEditor!.revision, config, enabled: activeEditor!.enabled, key: writeKey('update') }
    begin(next)
  }

  function applyTarget() {
    const value = activeTargetDraft.trim().toLowerCase()
    if (!uuidPattern.test(value)) {
      setTargetError(true)
      setTargetScopeID('')
      return
    }
    setTargetError(false)
    setTargetDraft(value)
    setTargetScopeID(value)
    setLimit(20)
    setCursorStack([])
    setSiteDraft('')
    setHostDraft('')
    setEnabledDraft(undefined)
    setFilters({})
    setEditor(null)
    attemptRef.current = null
    setAttempt(null)
    setWriteError(null)
    resetMutation()
  }

  async function publicationAction(item: ChallengePolicy, action: 'publish' | 'refresh' | 'promote') {
    const currentToken = currentSessionTokenForManage(ownerKey, scopeID)
    if (!currentToken) return
    const known = activePublications[item.id]
    if (action !== 'publish' && !known) return
    setPublicationBusy(item.id)
    try {
      const result = action === 'publish'
        ? await challengePoliciesApi.publish(currentToken, scopeID, item.id, item.revision, writeKey('update'))
        : action === 'refresh'
          ? await challengePoliciesApi.publicationStatus(currentToken, scopeID, item.id, known!.rollout_id)
          : await challengePoliciesApi.promote(currentToken, scopeID, item.id, known!.rollout_id, item.revision, writeKey('update'))
      setPublications((values) => ({ ...values, [item.id]: result }))
    } catch (error) {
      feedback.error(error instanceof ApiError ? localError(error, t) : t('errors.request_failed'))
    } finally {
      setPublicationBusy((value) => value === item.id ? '' : value)
    }
  }

  const columns: TableColumnsType<ChallengePolicy> = [
    { title: t('columns.host'), dataIndex: 'host', width: 190, ellipsis: true },
    { title: t('columns.site'), dataIndex: 'site_id', width: 230, ellipsis: true },
    { title: t('columns.mode'), dataIndex: 'mode', width: 115, render: (value: ChallengeMode) => t(`modes.${value}`) },
    { title: t('columns.ttl'), key: 'ttl', width: 145, render: (_, item) => t('values.ttl', { challenge: item.challenge_ttl_seconds, pass: item.pass_ttl_seconds }) },
    { title: t('columns.binding'), key: 'binding', width: 145, render: (_, item) => bindingLabel(item, t) },
    { title: t('columns.failures'), key: 'failures', width: 140, render: (_, item) => t('values.failures', { count: item.max_failures_per_window, window: item.failure_window_seconds }) },
    { title: t('columns.status'), dataIndex: 'enabled', width: 100, render: (value: boolean) => <Tag color={value ? 'success' : 'default'}>{t(value ? 'states.enabled' : 'states.disabled')}</Tag> },
    { title: t('columns.publication'), key: 'publication', width: 190, render: (_, item) => {
      const status = activePublications[item.id]
      if (!status) return <span>{t('publication.notPublished')}</span>
      const color = status.state === 'active' ? 'success' : status.state === 'failed' ? 'error' : status.state === 'healthy' ? 'processing' : 'warning'
      return <Space size={4} wrap><Tag color={color}>{t(`publication.states.${status.state}`)}</Tag><span>{t('publication.progress', { healthy: status.healthy, total: status.total })}</span>{status.superseded > 0 ? <span>{t('publication.superseded', { n: status.superseded })}</span> : null}</Space>
    } },
    { title: t('columns.revision'), dataIndex: 'revision', width: 80 },
    { title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value },
    ...(canManage ? [{
      title: t('columns.actions'), key: 'actions', fixed: 'right' as const, width: 205,
      render: (_: unknown, item: ChallengePolicy) => <Space size={2}>
        {!activePublications[item.id] ? <Tooltip title={t('actions.publish')}><Button type="text" size="small" aria-label={t('actions.publishNamed', { name: item.host })} icon={<CloudUpload size={15} />} loading={publicationBusy === item.id} disabled={writesLocked || !item.enabled} onClick={() => void publicationAction(item, 'publish')} /></Tooltip> : null}
        {activePublications[item.id] && activePublications[item.id].state !== 'active' ? <Tooltip title={t('actions.refreshPublication')}><Button type="text" size="small" aria-label={t('actions.refreshPublicationNamed', { name: item.host })} icon={<RefreshCw size={15} />} loading={publicationBusy === item.id} disabled={writesLocked} onClick={() => void publicationAction(item, 'refresh')} /></Tooltip> : null}
        {activePublications[item.id]?.state === 'healthy' ? <Button type="link" size="small" loading={publicationBusy === item.id} disabled={writesLocked} onClick={() => void publicationAction(item, 'promote')}>{t('actions.activate')}</Button> : null}
        <Tooltip title={t('actions.edit')}><Button type="text" size="small" aria-label={t('actions.editNamed', { name: item.host })} icon={<Pencil size={15} />} disabled={writesLocked} onClick={() => setEditor(item)} /></Tooltip>
        <Popconfirm title={t(item.enabled ? 'confirm.disable' : 'confirm.enable')} onConfirm={() => begin({ kind: item.enabled ? 'disable' : 'enable', ownerKey, scopeID, id: item.id, revision: item.revision, key: writeKey(item.enabled ? 'disable' : 'enable') })}>
          <Button type="link" size="small" aria-label={t(item.enabled ? 'actions.disableNamed' : 'actions.enableNamed', { name: item.host })} disabled={writesLocked}>{t(item.enabled ? 'actions.disable' : 'actions.enable')}</Button>
        </Popconfirm>
        <Popconfirm title={t('confirm.delete')} okButtonProps={{ danger: true }} onConfirm={() => begin({ kind: 'delete', ownerKey, scopeID, id: item.id, revision: item.revision, key: writeKey('delete') })}>
          <Tooltip title={t('actions.delete')}><Button danger type="text" size="small" aria-label={t('actions.deleteNamed', { name: item.host })} icon={<Trash2 size={15} />} disabled={writesLocked} /></Tooltip>
        </Popconfirm>
      </Space>,
    }] : []),
  ]

  if (!accessToken || !principal || !canRead) return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />

  return <section className="challenge-policy-page" aria-labelledby="challenge-policies-title">
    {messageContext}
    <div className="identity-toolbar">
      <div><h1 id="challenge-policies-title">{t('title')}</h1><p>{t('subtitle')}</p></div>
      {canManage && scopeReady ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => setEditor('create')}>{t('actions.create')}</Button> : null}
    </div>

    {isPlatform ? <div className="identity-filter-bar">
      <Input value={activeTargetDraft} aria-label={t('target.label')} placeholder={t('target.placeholder')} status={!ownerChanged && targetError ? 'error' : undefined} style={{ width: 330 }} onChange={(event) => setTargetDraft(event.target.value)} />
      <Button onClick={applyTarget}>{t('actions.applyTarget')}</Button>
      {targetError ? <span role="alert">{t('target.invalid')}</span> : null}
    </div> : null}
    {isPlatform && !scopeReady ? <Alert type="info" showIcon message={t('target.required')} /> : null}

    {scopeReady ? <>
      <div className="identity-filter-bar">
        <Input value={activeSiteDraft} aria-label={t('filters.site')} placeholder={t('filters.site')} style={{ width: 270 }} onChange={(event) => setSiteDraft(event.target.value)} />
        <Input value={activeHostDraft} aria-label={t('filters.host')} placeholder={t('filters.host')} style={{ width: 220 }} onChange={(event) => setHostDraft(event.target.value)} />
        <Select allowClear value={activeEnabledDraft} aria-label={t('filters.enabled')} placeholder={t('filters.enabled')} style={{ width: 130 }} options={[{ value: true, label: t('states.enabled') }, { value: false, label: t('states.disabled') }]} onChange={setEnabledDraft} />
        <Button onClick={() => { setCursorStack([]); setFilters({ ...(activeSiteDraft.trim() ? { site_id: activeSiteDraft.trim().toLowerCase() } : {}), ...(activeHostDraft.trim() ? { host: activeHostDraft.trim().toLowerCase() } : {}), ...(activeEnabledDraft === undefined ? {} : { enabled: activeEnabledDraft }) }) }}>{t('actions.applyFilters')}</Button>
        <Button onClick={() => { setSiteDraft(''); setHostDraft(''); setEnabledDraft(undefined); setFilters({}); setCursorStack([]) }}>{t('actions.resetFilters')}</Button>
        <Button icon={<RefreshCw size={14} />} aria-label={t('actions.refresh')} onClick={() => void query.refetch()} />
      </div>

      {activeWriteError ? (uncertain ? <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space><Button size="small" disabled={!canManage || mutationPending} onClick={() => { if (activeAttempt && currentSessionTokenForManage(activeAttempt.ownerKey, activeAttempt.scopeID)) mutation.mutate(activeAttempt.key) }}>{t('actions.retrySameRequest')}</Button><Button size="small" onClick={() => { attemptRef.current = null; setAttempt(null); setWriteError(null); setEditor(null); void query.refetch() }}>{t('actions.closeAndRefresh')}</Button></Space>} className="identity-alert" /> : <FeedbackWhen title={localError(activeWriteError, t)} />) : null}
      {query.isError ? <FeedbackWhen title={query.error instanceof ApiError && query.error.status === 403 ? t('forbidden.description') : t('errors.load')} detail={query.error instanceof ApiError && query.error.status !== 403 ? localError(query.error, t) : undefined} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}

      <div className="identity-table-scroll" data-testid="challenge-policy-table-scroll" aria-busy={query.isPending || query.isFetching}>
        <Table rowKey="id" size="small" columns={columns} dataSource={query.data?.items ?? []} loading={query.isPending || query.isFetching} pagination={false} locale={{ emptyText: query.isPending ? ' ' : t('values.empty') }} scroll={{ x: 1700 }} />
      </div>
      <div className="identity-pagination">
        <Space>
          <Button disabled={activeCursorStack.length === 0 || query.isFetching} onClick={() => setCursorStack((current) => current.slice(0, -1))}>{t('actions.previous')}</Button>
          <span>{t('pagination.page', { page: activeCursorStack.length + 1 })}</span>
          <Button disabled={!query.data?.next_cursor || query.isFetching || activeCursorStack.includes(query.data.next_cursor)} onClick={() => { if (query.data?.next_cursor) setCursorStack((current) => [...current, query.data!.next_cursor!]) }}>{t('actions.next')}</Button>
          <Select value={activeLimit} style={{ width: 90 }} options={[10, 20, 50, 100].map((value) => ({ value, label: value }))} onChange={(value) => { setLimit(value); setCursorStack([]) }} />
        </Space>
      </div>
    </> : null}

    {activeEditor !== null ? <PolicyEditor item={activeEditor === 'create' ? null : activeEditor} intent={intent} pending={mutationPending} canSubmit={canManage && !writesLocked} onCancel={() => { if (!writesLocked) setEditor(null) }} onSubmit={submit} /> : null}
  </section>
}
