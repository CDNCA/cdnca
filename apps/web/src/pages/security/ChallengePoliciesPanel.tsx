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
  Radio,
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
  type ExternalCredentialInput,
  type ExternalCredentialStatus,
  type ExternalProvider,
  type ExternalUnavailable,
  type IPBinding,
  externalAppIDPattern,
  externalSecretPattern,
  globalProviders,
  powDifficultyRange,
} from '../../api/challengePolicies'
import { useSessionStore } from '../../auth/session'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/challengePolicies'
import { formatDateTime } from '../../i18n/formatters'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const hostPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/
const keyPattern = /^(?:keyref|vault|kms):[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$/

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
  provider?: ExternalProvider
  /** Provider app id / site key (public). */
  app_id: string
  /** Write-only; empty keeps the stored secret. */
  secret: string
  score_threshold: number
  unavailable: ExternalUnavailable
  /** 0 = edge default (field omitted). */
  pow_difficulty: number
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
    provider: item?.external_provider_summary?.provider,
    app_id: '',
    secret: '',
    score_threshold: item?.external_provider_summary?.score_threshold ?? 0.5,
    unavailable: item?.external_provider_summary?.unavailable ?? 'builtin',
    pow_difficulty: item?.pow_difficulty ?? 0,
  }
}

// Worst-case browser proof-of-work time: 2^bits hashes at about 600k hashes/s on a low-end phone.
function powWorstCase(bits: number, t: TFunction<'challengePolicies'>): string {
  const seconds = 2 ** bits / 600_000
  return seconds < 1
    ? t('editor.powMilliseconds', { n: Math.max(1, Math.round(seconds * 1000)) })
    : t('editor.powSeconds', { n: Number(seconds.toFixed(1)) })
}

const powDifficulties = Array.from(
  { length: powDifficultyRange.max - powDifficultyRange.min + 1 }, (_, index) => powDifficultyRange.min + index,
)

function configFromForm(values: PolicyForm): ChallengePolicyConfig {
  const minDelay = values.mode === 'delay' ? values.min_delay_seconds : 0
  if (values.challenge_ttl_seconds <= minDelay + values.clock_skew_seconds ||
    values.key_reference.length < 8 || values.key_reference.length > 128 || !keyPattern.test(values.key_reference)) {
    throw new Error('invalid challenge config')
  }
  if (values.mode === 'external' && !values.provider) {
    throw new Error('invalid external provider')
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
    // Defaults (score 0.5, unavailable builtin) stay unset so tencent /
    // geetest-v4 policies keep working on nodes without CHALLENGE_EXTERNAL.
    ...(values.mode === 'external' ? {
      external_provider: {
        provider: values.provider!,
        ...(values.provider === 'recaptcha-v3' && values.score_threshold !== 0.5 ? { score_threshold: values.score_threshold } : {}),
        ...(values.unavailable === 'closed' ? { unavailable: 'closed' as const } : {}),
      },
    } : {}),
    ...(values.mode !== 'external' && values.pow_difficulty ? { pow_difficulty: values.pow_difficulty } : {}),
  }
}

const providerLabelKeys: Record<ExternalProvider, string> = {
  tencent: 'providers.tencent', 'geetest-v4': 'providers.geetest', turnstile: 'providers.turnstile', 'recaptcha-v3': 'providers.recaptcha',
}
const scoreThresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

/** Whether this save must PUT the credential: a new provider, a new app id or a typed secret. */
function credentialChanged(values: PolicyForm, credential: ExternalCredentialStatus | undefined): boolean {
  return values.mode === 'external' && (values.secret !== '' || !credential?.secret_configured ||
    credential.provider !== values.provider || credential.app_id !== values.app_id)
}

function ExternalProviderSection({ form, credential, credentialError, onProviderChange }: {
  form: ReturnType<typeof Form.useForm<PolicyForm>>[0]
  credential: ExternalCredentialStatus | undefined
  credentialError: 'secret' | 'provider' | null
  onProviderChange: () => void
}) {
  const { t } = useTranslation('challengePolicies')
  const provider = Form.useWatch('provider', form) as ExternalProvider | undefined
  const host = Form.useWatch('host', form) as string | undefined
  const global = provider !== undefined && globalProviders.includes(provider)
  const providerName = provider ? t(providerLabelKeys[provider]) : ''
  const keepsSecret = Boolean(credential?.secret_configured && credential.provider === provider)
  const option = (value: ExternalProvider) => <Radio value={value}>{t(providerLabelKeys[value])}</Radio>
  return <section aria-label={t('external.section')}>
    <Form.Item name="provider" label={t('editor.provider')} rules={[{ required: true, message: t('validation.required') }]}
      validateStatus={credentialError === 'provider' ? 'error' : undefined}
      help={credentialError === 'provider' ? t('external.providerMismatch') : undefined}>
      <Radio.Group onChange={onProviderChange}>
        <Space direction="vertical" size={4}>{option('tencent')}{option('geetest-v4')}{option('turnstile')}{option('recaptcha-v3')}</Space>
      </Radio.Group>
    </Form.Item>
    {provider ? <Space size={12} wrap align="start">
      <Form.Item name="app_id" label={t(global ? 'external.siteKey' : 'external.appID')}
        rules={[{ required: true, message: t('validation.required') }, { pattern: externalAppIDPattern, message: t('external.appIDInvalid') }]}>
        <Input autoComplete="off" spellCheck={false} style={{ width: 320 }} />
      </Form.Item>
      <Form.Item name="secret" label={t('external.secret')}
        validateStatus={credentialError === 'secret' ? 'error' : undefined}
        rules={[
          { required: !keepsSecret, message: t('validation.required') },
          { validator: async (_, value: string) => { if (value && !externalSecretPattern.test(value)) throw new Error(t('external.secretInvalid')) } },
        ]}
        help={credentialError === 'secret' ? t('external.secretInvalid') : undefined}>
        <Input.Password autoComplete="new-password" style={{ width: 320 }} placeholder={keepsSecret ? t('external.secretConfigured') : undefined} />
      </Form.Item>
    </Space> : null}
    {provider === 'recaptcha-v3' ? <Form.Item name="score_threshold" label={t('external.scoreThreshold')} extra={t('external.scoreHint')}>
      <Select style={{ width: 120 }} options={scoreThresholds.map((value) => ({ value, label: value.toFixed(1) }))} />
    </Form.Item> : null}
    {provider ? <Form.Item name="unavailable" label={t('external.unavailable')}>
      <Radio.Group options={[
        { value: 'builtin', label: t('external.unavailableBuiltin') },
        { value: 'closed', label: t('external.unavailableClosed') },
      ]} />
    </Form.Item> : null}
    {global ? <Alert type="info" showIcon style={{ marginBottom: 16 }}
      message={t('external.domainHint', { provider: providerName, host: host || '-' })}
      description={t('external.privacy', { provider: providerName })} /> : null}
  </section>
}

function PolicyEditor({
  item, intent, pending, canSubmit, credential, credentialRetry, credentialError, onCancel, onSubmit,
}: {
  item: ChallengePolicy | null
  intent?: SiteIntent | null
  pending: boolean
  canSubmit: boolean
  credential?: ExternalCredentialStatus
  /** The policy is saved; only the credential PUT is left. */
  credentialRetry: boolean
  credentialError: 'secret' | 'provider' | null
  onCancel: () => void
  onSubmit: (values: PolicyForm) => void
}) {
  const { t } = useTranslation('challengePolicies')
  const [form] = Form.useForm<PolicyForm>()
  const mode = Form.useWatch('mode', form) ?? item?.mode ?? intent?.mode ?? 'click'
  // The app id comes from the credential status, loaded after the form.
  useEffect(() => {
    if (credential?.app_id && !form.getFieldValue('app_id') && form.getFieldValue('provider') === credential.provider) {
      form.setFieldValue('app_id', credential.app_id)
    }
  }, [credential, form])
  return (
    <Modal
      className="identity-modal challenge-policy-modal"
      open
      title={t(item ? 'editor.editTitle' : 'editor.createTitle')}
      width={820}
      confirmLoading={pending}
      okButtonProps={{ disabled: !canSubmit }}
      okText={credentialRetry ? t('external.retryCredential') : t('actions.save')}
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
          {mode !== 'external' ? <Form.Item name="pow_difficulty" label={t('editor.powDifficulty')} rules={[{ required: true }]}>
            <Select style={{ width: 300 }} options={[
              { value: 0, label: t('editor.powDefault') },
              ...powDifficulties.map((bits) => ({ value: bits, label: t('editor.powOption', { bits, time: powWorstCase(bits, t) }) })),
            ]} />
          </Form.Item> : null}
          <Form.Item name="pass_ttl_seconds" label={t('editor.passTTL')} rules={[{ required: true, type: 'number', min: 1, max: 3600 }]}><InputNumber min={1} max={3600} precision={0} /></Form.Item>
          <Form.Item name="clock_skew_seconds" label={t('editor.clockSkew')} rules={[{ required: true, type: 'number', min: 0, max: 30 }]}><InputNumber min={0} max={30} precision={0} /></Form.Item>
        </Space>
        <Space size={12} wrap align="start">
          <Form.Item name="failure_window_seconds" label={t('editor.failureWindow')} rules={[{ required: true, type: 'number', min: 1, max: 3600 }]}><InputNumber min={1} max={3600} precision={0} /></Form.Item>
          <Form.Item name="max_failures_per_window" label={t('editor.maxFailures')} rules={[{ required: true, type: 'number', min: 1, max: 20 }]}><InputNumber min={1} max={20} precision={0} /></Form.Item>
          <Form.Item name="ip_binding" label={t('editor.ipBinding')} rules={[{ required: true }]}><Select style={{ width: 130 }} options={[{ value: 'none', label: t('bindings.none') }, { value: 'exact', label: t('bindings.ip') }]} /></Form.Item>
          <Form.Item name="bind_user_agent" label={t('editor.bindUA')} valuePropName="checked"><Switch /></Form.Item>
        </Space>
        <Alert
          type={mode === 'external' ? 'info' : 'warning'}
          showIcon
          data-testid="challenge-mode-strength"
          message={mode === 'external' ? t('strength.external') : t('strength.builtin')}
          description={mode === 'external' ? undefined : <>
            <div>{t('strength.noscript')}</div>
            {mode === 'slider' || mode === 'captcha' ? <div>{t('strength.screenReader')}</div> : null}
            <div>{t('editor.powHint')}</div>
          </>}
          style={{ marginBottom: 16 }}
        />
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
        {mode === 'external' ? <ExternalProviderSection form={form} credential={credential} credentialError={credentialError}
          onProviderChange={() => form.setFieldsValue({ app_id: '', secret: '' })} /> : null}
        {credentialRetry ? <Alert type="error" showIcon role="alert" message={t('external.credentialFailed')} style={{ marginBottom: 16 }} /> : null}
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
  // §8 two-step save: the credential to PUT after the policy write
  // (in memory only, keyed by the write attempt), and the saved policy whose
  // credential PUT failed (the editor then only retries that step).
  const pendingCredentialRef = useRef<{ key: string; input: ExternalCredentialInput } | null>(null)
  const [credentialStep, setCredentialStep] = useState<{ policy: ChallengePolicy; input: ExternalCredentialInput; error: 'secret' | 'provider' | null } | null>(null)
  const [credentialBusy, setCredentialBusy] = useState(false)
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

  // A leftover second step only applies while its editor is open.
  const activeCredentialStep = activeEditor === null ? null : credentialStep
  const editedPolicy = activeCredentialStep?.policy ?? (activeEditor !== null && activeEditor !== 'create' ? activeEditor : null)
  const credentialQuery = useQuery({
    queryKey: ['challenge-policies', ownerKey, scopeID, 'external-credential', editedPolicy?.id, editedPolicy?.revision],
    queryFn: ({ signal }) => challengePoliciesApi.externalCredential(accessToken!, scopeID, editedPolicy!.id, signal),
    enabled: Boolean(ownerKey && scopeReady && editedPolicy?.mode === 'external'),
  })

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
    onSuccess: (policy, completedKey) => {
      const completed = attemptRef.current
      if (!completed || completed.key !== completedKey) return
      attemptRef.current = null
      setAttempt((current) => current?.key === completedKey ? null : current)
      const credential = pendingCredentialRef.current?.key === completedKey ? pendingCredentialRef.current.input : null
      pendingCredentialRef.current = null
      if (completed.ownerKey !== ownerKeyRef.current || completed.scopeID !== scopeIDRef.current) return
      setWriteError(null)
      if (credential && (completed.kind === 'create' || completed.kind === 'update')) {
        void queryClient.invalidateQueries({ queryKey: ['challenge-policies', completed.ownerKey, completed.scopeID] })
        void saveCredential(policy, credential)
        return
      }
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

  async function saveCredential(policy: ChallengePolicy, input: ExternalCredentialInput) {
    const token = currentSessionTokenForManage(ownerKey, scopeID)
    if (!token) return
    setCredentialBusy(true)
    try {
      await challengePoliciesApi.putExternalCredential(token, scopeID, policy.id, policy.revision, input, writeKey('update'))
      setCredentialStep(null)
      setEditor(null)
      void queryClient.invalidateQueries({ queryKey: ['challenge-policies', ownerKey, scopeID] })
      messageApi.success(t('external.saved'))
    } catch (error) {
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      if (apiError.status === 412 || apiError.code === 'revision_conflict') {
        setCredentialStep(null)
        setEditor(null)
        void query.refetch()
        feedback.error(t('notices.conflict'))
        return
      }
      const field = apiError.code === 'provider_mismatch' ? 'provider' : apiError.code === 'validation_error' ? 'secret' : null
      // The policy is saved: the editor stays open on it and only retries this step.
      setCredentialStep({ policy, input, error: field })
      if (!field) feedback.error(localError(apiError, t))
    } finally {
      setCredentialBusy(false)
    }
  }

  function submit(values: PolicyForm) {
    if (!currentSessionTokenForManage(ownerKey, scopeID) || writesLocked || credentialBusy) return
    const credentialInput: ExternalCredentialInput | null = values.mode === 'external' && values.provider &&
      credentialChanged(values, credentialQuery.data)
      ? { provider: values.provider, app_id: values.app_id, secret: values.secret }
      : null
    if (activeCredentialStep) {
      if (credentialInput) void saveCredential(activeCredentialStep.policy, credentialInput)
      return
    }
    let config: ChallengePolicyConfig
    try {
      config = configFromForm(values)
    } catch {
      return
    }
    const next: WriteAttempt = activeEditor === 'create'
      ? { kind: 'create', ownerKey, scopeID, input: { site_id: values.site_id, host: values.host, enabled: values.enabled, config }, key: writeKey('create') }
      : { kind: 'update', ownerKey, scopeID, id: activeEditor!.id, revision: activeEditor!.revision, config, enabled: activeEditor!.enabled, key: writeKey('update') }
    pendingCredentialRef.current = credentialInput ? { key: next.key, input: credentialInput } : null
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

    {activeEditor !== null ? <PolicyEditor item={activeCredentialStep?.policy ?? (activeEditor === 'create' ? null : activeEditor)} intent={intent} pending={mutationPending || credentialBusy} canSubmit={canManage && !writesLocked && !(editedPolicy?.mode === 'external' && credentialQuery.isPending)} credential={credentialQuery.data} credentialRetry={activeCredentialStep !== null} credentialError={activeCredentialStep?.error ?? null} onCancel={() => { if (!writesLocked && !credentialBusy) { setCredentialStep(null); setEditor(null) } }} onSubmit={submit} /> : null}
  </section>
}
