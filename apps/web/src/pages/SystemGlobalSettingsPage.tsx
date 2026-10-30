import { Fragment, lazy, Suspense, useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Alert, App, Button, Checkbox, Collapse, Divider, Form, Input, InputNumber, Radio, Result, Select, Space, Spin, Switch, Tabs, Tag, Tooltip, Typography, Upload } from 'antd'
import { CircleHelp, RefreshCw, Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'

import '../i18n/systemGlobalSettings'
import '../i18n/logCenter'
import '../i18n/adminAccess'
import './SystemGlobalSettingsPage.css'
import './SystemGlobalSettingsV2.css'
import './SystemOtherSettingsV2.css'
import { ApiError, type Principal } from '../api/auth'
import { maxGlobalJSReportHosts, systemSettingsApi, validGlobalJSReportHosts, type PlatformSystemSettings, type PlatformSystemSettingsDocument } from '../api/systemSettings'
import { brandAssetApi, type BrandAsset, type BrandAssetSlot } from '../api/brandAsset'
import { publicBrandAssetUpdatedEvent } from '../components/PublicBrandAssetImage'
import { auditLogCategories } from '../api/auditLogs'
import { systemCleanupSettingsApi, type PlatformSystemCleanupDocument, type PlatformSystemCleanupSettings } from '../api/systemCleanupSettings'
import { mailProviderKind, nativeSMSProviders, systemMailSettingsApi, type PlatformSystemMailSettings, type PlatformSystemMailSettingsDocument } from '../api/systemMailSettings'
import { systemOtherSettingsApi, validCertificateNoticeDays, type PlatformSystemOtherSettings, type PlatformSystemOtherSettingsDocument } from '../api/systemOtherSettings'
import { systemUserSettingsApi, type PlatformSystemUserSettings, type PlatformSystemUserSettingsDocument } from '../api/systemUserSettings'
import { useSessionStore } from '../auth/session'
import { systemSettingsChangedEvent } from '../components/useSystemBranding'
import { localizedText } from '../api/theme'
import { builtInBrandAsset, useThemeBrandName, useThemeRuntime } from '../theme/runtime'
import MailProviderSection from './system/MailProviderSection'
import { useFeedback, FeedbackWhen, InlineNotice, OutcomeUnknown, fieldReasonText, submitErrorFields } from '@cdnca/ui'
import { ApprovalCenterSettings } from './ApprovalCenterSettings'

const NotificationSettingsPage = lazy(() => import('./NotificationSettingsPage'))

const captchaTemplatePlaceholder = /\{\{\s*\.?captcha\s*\}\}|\$\{captcha\}/
const sensitiveTemplatePlaceholder = /\{\{\s*\.?password\s*\}\}|\$\{\s*password\s*\}/i

function validUserNotificationTemplates(value: PlatformSystemUserSettings) {
  const templates = [
    value.registration_success_subject, value.registration_success_body,
    value.password_reset_subject, value.password_reset_body,
    value.verification_subject, value.verification_body, value.verification_sms_body,
  ]
  return captchaTemplatePlaceholder.test(value.verification_subject + value.verification_body) &&
    captchaTemplatePlaceholder.test(value.verification_sms_body) &&
    !templates.some((template) => sensitiveTemplatePlaceholder.test(template))
}

type BaselineTab = 'system' | 'cleanup' | 'account' | 'payment' | 'mail' | 'notification' | 'other'

// A save refusal naming a field shown in the panel (value.<key>, or a
// write-only secret such as mail_secret) is marked under it instead of the
// dialog (fix-fielderr-be). status(...keys) is the Form.Item props of the item
// holding those keys; shown tells the panel to skip its dialog.
function refusedFieldStatus(error: unknown, shownKeys: readonly string[], language: string | undefined) {
  const refused = error ? submitErrorFields(error)[0] : undefined
  const key = refused?.field.replace(/^value\./, '').replace(/\[\d+\]$/, '')
  const shown = Boolean(refused && key && shownKeys.includes(key))
  const help = refused ? fieldReasonText(refused.reason, language === 'en-US' ? 'en' : language === 'zh-TW' ? 'zh-tw' : 'zh-cn') : undefined
  const status = (...keys: string[]) => shown && key && keys.includes(key) ? { validateStatus: 'error' as const, help } : {}
  return { status, shown, key }
}

function baselineOwnerKey(principal: Principal | null, sessionEpoch: number): string | null {
  if (!principal || sessionEpoch < 1) return null
  return JSON.stringify([principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch])
}

function currentBaselineAccess(ownerKey: string | null): string | null {
  if (!ownerKey) return null
  const { accessToken, principal, sessionEpoch, status } = useSessionStore.getState()
  if (status !== 'authenticated' || !accessToken || !principal) return null
  return baselineOwnerKey(principal, sessionEpoch) === ownerKey ? accessToken : null
}

type SectionNavigationItem = { id: string; label: string }

function SectionNavigation({ label, items }: { label: string; items: SectionNavigationItem[] }) {
  const [activeId, setActiveId] = useState(items[0]?.id ?? '')
  const itemIds = items.map((item) => item.id).join('|')

  useEffect(() => {
    const sections = itemIds.split('|').filter(Boolean).map((id) => document.getElementById(id)).filter((section): section is HTMLElement => section !== null)
    if (sections.length === 0 || typeof IntersectionObserver === 'undefined') return
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top)[0]
      if (visible?.target instanceof HTMLElement) setActiveId(visible.target.id)
    }, { rootMargin: '-78px 0px -55% 0px', threshold: [0, 1] })
    sections.forEach((section) => observer.observe(section))
    return () => observer.disconnect()
  }, [itemIds])

  return <nav className="system-settings-section-nav" aria-label={label}>
    <Space wrap={false} size={[24, 4]}>
      {items.map((item) => <Button key={item.id} type="text" size="small" className={activeId === item.id ? 'is-active' : undefined}
        aria-current={activeId === item.id ? 'page' : undefined}
        onClick={() => { setActiveId(item.id); const target = document.getElementById(item.id); target?.scrollIntoView?.({ behavior: 'smooth', block: 'start' }) }}>{item.label}</Button>)}
    </Space>
  </nav>
}

function SaveState({ visible, label }: { visible: boolean; label: string }) {
  if (!visible) return null
  return <div className="sys-setting-save-state sys-setting-save-state--saving" role="status" aria-live="polite">
    <span className="sys-setting-save-icon sys-setting-save-icon--spin" aria-hidden="true">↻</span>
    <span>{label}</span>
  </div>
}

type BaselineWriteAttempt<T> = {
  ownerKey: string
  revision: number
  value: T
  requestId: string
  idempotencyKey: string
  scope: string
  generation: number
}

type BrandAssetUploadAttempt = {
  ownerKey: string
  generation: number
  slot: BrandAssetSlot
  revision: number
  file: File
  requestId: string
  idempotencyKey: string
}

type BaselineWriteOptions<T, R> = {
  ownerKey: string | null
  canManage: boolean
  revision: number | undefined
  scope: string
  submit: (accessToken: string, attempt: BaselineWriteAttempt<T>) => Promise<R>
  onSuccess: (result: R, attempt: BaselineWriteAttempt<T>) => void
}

const staleBaselineWriteAttempt = new Error('stale baseline settings write attempt')

function baselineWriteIdentity(scope: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `system-settings-${scope}-${suffix}`
}

function baselineManageAccess(ownerKey: string | null): string | null {
  if (!ownerKey) return null
  const { accessToken, principal, sessionEpoch, status } = useSessionStore.getState()
  if (status !== 'authenticated' || !accessToken || !principal || principal.scope_kind !== 'platform' ||
    (!principal.permissions.includes('system_configuration.manage') && !principal.permissions.includes('platform.admin'))) return null
  return baselineOwnerKey(principal, sessionEpoch) === ownerKey ? accessToken : null
}

function isUnknownBaselineWriteOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

function useBaselineWrite<T, R>(options: BaselineWriteOptions<T, R>) {
  const [attempt, setAttempt] = useState<BaselineWriteAttempt<T> | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [saving, setSaving] = useState(false)
  const [savingScope, setSavingScope] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const generation = useRef(0)

  useEffect(() => {
    generation.current += 1
    setAttempt(null)
    setError(null)
    setSaving(false)
    setSavingScope(null)
    setSaved(false)
    return () => { generation.current += 1 }
  }, [options.ownerKey])

  const matches = useCallback((candidate: BaselineWriteAttempt<T>) =>
    candidate.ownerKey === options.ownerKey && candidate.generation === generation.current && Boolean(currentBaselineAccess(candidate.ownerKey)), [options.ownerKey])

  const execute = useCallback(async (candidate: BaselineWriteAttempt<T>) => {
    if (!matches(candidate)) return
    const token = baselineManageAccess(candidate.ownerKey)
    if (!token) return
    setSaving(true)
    setSavingScope(candidate.scope)
    try {
      const result = await options.submit(token, candidate)
      if (!matches(candidate)) throw staleBaselineWriteAttempt
      setAttempt(null)
      setError(null)
      setSaved(true)
      options.onSuccess(result, candidate)
    } catch (reason) {
      if (reason === staleBaselineWriteAttempt || !matches(candidate)) return
      setError(reason)
      setAttempt(isUnknownBaselineWriteOutcome(reason) ? candidate : null)
    } finally {
      if (matches(candidate)) {
        setSaving(false)
        setSavingScope(null)
      }
    }
  }, [matches, options])

  const save = useCallback((value: T, scope = options.scope) => {
    if (!options.ownerKey || !options.canManage || options.revision === undefined || !baselineManageAccess(options.ownerKey)) return
    const requestId = baselineWriteIdentity(scope)
    const attemptValue: BaselineWriteAttempt<T> = {
      ownerKey: options.ownerKey,
      revision: options.revision,
      value,
      requestId,
      idempotencyKey: requestId,
      scope,
      generation: generation.current,
    }
    setAttempt(null)
    setError(null)
    setSaved(false)
    void execute(attemptValue)
  }, [execute, options.canManage, options.ownerKey, options.revision, options.scope])

  const uncertain = Boolean(attempt && error && isUnknownBaselineWriteOutcome(error))
  const retryExact = useCallback(() => {
    if (attempt && uncertain && !saving) void execute(attempt)
  }, [attempt, execute, saving, uncertain])
  const reset = useCallback(() => {
    generation.current += 1
    setAttempt(null)
    setError(null)
    setSaving(false)
    setSavingScope(null)
    setSaved(false)
  }, [])

  return { attempt, error, saving, savingScope, saved, uncertain, save, retryExact, reset }
}

function validSystemSettingsAutoSaveDraft(value: PlatformSystemSettings | null): value is PlatformSystemSettings {
  const validReference = (reference: string | undefined) => !reference ||
    (reference.startsWith('vault://') && reference.length > 'vault://'.length) ||
    (reference.startsWith('kms-envelope://') && reference.length > 'kms-envelope://'.length)
  return Boolean(value?.system_name && value.user_title && value.admin_title &&
    validReference(value.certificate) && validReference(value.private_key) &&
    (value.global_js_report_hosts === undefined || validGlobalJSReportHosts(value.global_js_report_hosts)))
}

// One host per line (or separated by spaces/commas); blank input means none.
function parseReportHosts(text: string): string[] {
  return text.split(/[\s,，]+/).map((host) => host.trim()).filter(Boolean)
}

function GlobalJSReportHostsField({ value, disabled, label, placeholder, help, invalid, serverError, onChange }: {
  value: string[] | undefined
  disabled: boolean
  label: string
  placeholder: string
  help: string
  invalid: string
  /** The server's refusal of these hosts (fix-fielderr-be), shown under the field. */
  serverError?: string
  onChange: (hosts: string[]) => void
}) {
  const [text, setText] = useState(() => (value ?? []).join('\n'))
  const committed = (value ?? []).join('\n')
  const [lastCommitted, setLastCommitted] = useState(committed)
  if (committed !== lastCommitted) {
    setLastCommitted(committed)
    setText(committed)
  }
  const hosts = parseReportHosts(text)
  const valid = validGlobalJSReportHosts(hosts)
  return <Form.Item label={label} validateStatus={valid && !serverError ? undefined : 'error'}
    help={valid ? serverError : invalid} extra={<div className="system-settings-form-warning">{help}</div>}>
    <Input.TextArea value={text} disabled={disabled} aria-label={label} autoSize={{ minRows: 2, maxRows: 6 }}
      placeholder={placeholder}
      onChange={(event) => {
        setText(event.target.value)
        const next = parseReportHosts(event.target.value)
        if (validGlobalJSReportHosts(next)) onChange(next)
      }} />
  </Form.Item>
}

function useBaselineAutoSave<T>({ draft, persisted, enabled, blocked, save, delay = 700 }: {
  draft: T | null
  persisted: T | null
  enabled: boolean
  blocked: boolean
  save: (value: T) => void
  delay?: number
}) {
  const saveRef = useRef(save)
  saveRef.current = save
  const draftSnapshot = draft === null ? null : JSON.stringify(draft)
  const persistedSnapshot = persisted === null ? null : JSON.stringify(persisted)
  const draftRef = useRef(draft)
  const persistedSnapshotRef = useRef(persistedSnapshot)
  const enabledRef = useRef(enabled)
  const blockedRef = useRef(blocked)
  const pendingRef = useRef(false)
  draftRef.current = draft
  persistedSnapshotRef.current = persistedSnapshot
  enabledRef.current = enabled
  blockedRef.current = blocked

  useEffect(() => {
    if (!draft || !enabled || blocked || draftSnapshot === persistedSnapshot) {
      pendingRef.current = false
      return
    }
    pendingRef.current = true
    const pendingDraft = draft
    const timer = window.setTimeout(() => {
      pendingRef.current = false
      saveRef.current(pendingDraft)
    }, delay)
    return () => window.clearTimeout(timer)
  }, [blocked, delay, draft, draftSnapshot, enabled, persistedSnapshot])

  useEffect(() => () => {
    if (!enabledRef.current || blockedRef.current) return
    const latestDraft = draftRef.current
    if (!latestDraft || JSON.stringify(latestDraft) === persistedSnapshotRef.current) return
    pendingRef.current = false
    saveRef.current(latestDraft)
  }, [])
}

type UserSettingsPanelMode = 'account' | 'payment' | 'all'

function UserSettingsPanel({ mode, shared = null, onShared }: {
  mode: UserSettingsPanelMode
  /** Newest copy of the shared account/payment document saved by the sibling panel. */
  shared?: PlatformSystemUserSettingsDocument | null
  onShared?: (document: PlatformSystemUserSettingsDocument) => void
}) {
  const { t, i18n } = useTranslation('systemGlobalSettings')
  const { t: adminAccessT } = useTranslation('adminAccess')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = baselineOwnerKey(principal, sessionEpoch)
  const state = mode === 'account'
    ? { loading: t('states.loadingAccount'), error: t('states.errorAccount'), saved: t('states.savedAccount') }
    : mode === 'payment'
      ? { loading: t('states.loadingPayment'), error: t('states.errorPayment'), saved: t('states.savedPayment') }
      : { loading: t('states.loadingUser'), error: t('states.errorUser'), saved: t('states.savedUser') }
  const [document, setDocument] = useState<PlatformSystemUserSettingsDocument | null>(null)
  const [draft, setDraft] = useState<PlatformSystemUserSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)

  const load = useCallback(async () => {
    const token = currentBaselineAccess(ownerKey)
    if (!token || !canRead) { if (token) setLoading(false); return }
    setLoading(true); setError(null)
    setDocument(null); setDraft(null)
    try {
      const value = await systemUserSettingsApi.get(token)
      if (!currentBaselineAccess(ownerKey)) return
      setDocument(value); setDraft(value.value)
    } catch (reason) {
      if (currentBaselineAccess(ownerKey)) setError(reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error'))
    } finally {
      if (currentBaselineAccess(ownerKey)) setLoading(false)
    }
  }, [canRead, ownerKey])
  useEffect(() => { void load() }, [load, sessionEpoch])

  const write = useBaselineWrite<PlatformSystemUserSettings, PlatformSystemUserSettingsDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: `user-${mode}`,
    submit: (token, attempt) => systemUserSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey),
    onSuccess: (next) => { setDocument(next); setDraft(next.value); onShared?.(next); message.success(state.saved) },
  })
  // The sibling tab saved a newer revision: adopt it, keeping only the fields edited here.
  useEffect(() => {
    if (!shared || !document || shared.revision <= document.revision) return
    setDraft((current) => current ? {
      ...shared.value,
      ...Object.fromEntries(Object.entries(current).filter(([key, value]) => JSON.stringify(value) !== JSON.stringify(document.value[key as keyof PlatformSystemUserSettings]))),
    } : shared.value)
    setDocument(shared)
  }, [document, shared])
  const refresh = () => { write.reset(); void load() }

  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={state.loading} /><Form labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} style={{ maxWidth: 520, opacity: 0.55 }}>{(['session_ttl_seconds', 'user_login_domains', 'admin_login_domains'] as const).map((key) => <Form.Item key={key} label={t(`userFields.${key}`)}><Input disabled /></Form.Item>)}</Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : state.error} subTitle={t(`errors.${error.code}`, { defaultValue: state.error })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null

  const update = <K extends keyof PlatformSystemUserSettings>(key: K, value: PlatformSystemUserSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const save = () => {
    if (!draft) return
    if ((mode === 'account' || mode === 'all') && !validUserNotificationTemplates(draft)) { feedback.error(t('errors.notification_template_invalid')); return }
    write.save(draft)
  }
  const writeErrorCode = write.error instanceof ApiError ? write.error.code : 'network_error'
  // Keys shown in this mode; a refusal of a key shown here goes under it (fix-fielderr-be2).
  const accountKeys = ['session_ttl_seconds', 'user_login_domains', 'admin_login_domains', 'registration_success_subject', 'registration_success_body',
    'password_reset_subject', 'password_reset_body', 'verification_template_channel', 'verification_subject', 'verification_body', 'verification_sms_body',
    'verification_sms_template_id', 'terms_title', 'terms_body', 'email_verification_required', 'phone_verification_required', 'default_phone_country_code',
    'login_failure_limit_per_hour', 'login_captcha_threshold_per_hour', 'email_anti_abuse_mode', 'sms_anti_abuse_mode', 'captcha_provider',
    'captcha_secret_id_reference', 'captcha_secret_key_reference', 'captcha_app_id', 'captcha_app_secret_reference']
  const paymentKeys = ['identity_verification_method', 'enterprise_secret_id_reference', 'enterprise_secret_key_reference']
  const { status: fieldStatus, shown: refusedShown } = refusedFieldStatus(write.error,
    [...(mode === 'payment' ? [] : accountKeys), ...(mode === 'account' ? [] : paymentKeys)], i18n.resolvedLanguage)
  const writeErrorKey = writeErrorCode === 'system_user_settings_revision_conflict'
    ? mode === 'account' ? 'errors.system_account_settings_revision_conflict' : mode === 'payment' ? 'errors.system_payment_settings_revision_conflict' : `errors.${writeErrorCode}`
    : `errors.${writeErrorCode}`
  const formProps = { className: 'system-settings-baseline-form', labelCol: { flex: '170px' }, wrapperCol: { flex: '330px' }, labelAlign: 'right' as const, colon: false, style: { maxWidth: 840 } }
  const section = (key: string, children: ReactNode) => <section className="system-settings-config-card" id={`${mode}-${key}`} aria-labelledby={`${mode}-${key}-title`}><h2 id={`${mode}-${key}-title`}>{t(`userSections.${key}`)}</h2>{children}</section>
  const toggle = (key: keyof PlatformSystemUserSettings) => <Switch checked={Boolean(draft[key])} disabled={!canManage} onChange={(value) => update(key, value as never)} aria-label={t(`userFields.${key}`)} />
  const text = (key: keyof PlatformSystemUserSettings, placeholder?: string) => <Input value={String(draft[key])} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`userFields.${key}`)} />
  const subjectInput = (key: keyof PlatformSystemUserSettings) => <Space.Compact block><Input value={t('labels.subject')} readOnly tabIndex={-1} aria-hidden style={{ width: 52, textAlign: 'center', pointerEvents: 'none' }} /><Input value={String(draft[key])} disabled={!canManage} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`userFields.${key}`)} /></Space.Compact>
  const template = (subject: keyof PlatformSystemUserSettings, body: keyof PlatformSystemUserSettings) => <Space direction="vertical" size={8} style={{ width: '100%' }}>{subjectInput(subject)}<Input.TextArea value={String(draft[body])} disabled={!canManage} rows={4} onChange={(event) => update(body, event.target.value as never)} aria-label={t(`userFields.${body}`)} /></Space>
  const requirement = (key: keyof PlatformSystemUserSettings, verification?: keyof PlatformSystemUserSettings) => <Space wrap><Checkbox checked={Boolean(draft[key])} disabled={!canManage} onChange={(event) => { update(key, event.target.checked as never); if (!event.target.checked && verification) update(verification, false as never) }}>{t('options.required')}</Checkbox>{verification ? <Checkbox checked={Boolean(draft[verification])} disabled={!canManage || !draft[key]} onChange={(event) => update(verification, event.target.checked as never)}>{t('options.verified')}</Checkbox> : null}</Space>
  const navigation = mode === 'account'
    ? [{ id: 'account-login', label: t('userSections.login') }, { id: 'account-registration', label: t('userSections.registration') }, { id: 'account-security', label: t('userSections.security') }, { id: 'account-captcha', label: t('userSections.captcha') }]
    : mode === 'payment'
      ? [{ id: 'payment-identity', label: t('userSections.identity') }, { id: 'payment-enterprise', label: t('userSections.enterprise') }]
      : [{ id: 'all-login', label: t('userSections.login') }, { id: 'all-registration', label: t('userSections.registration') }, { id: 'all-security', label: t('userSections.security') }, { id: 'all-captcha', label: t('userSections.captcha') }, { id: 'all-identity', label: t('userSections.identity') }, { id: 'all-enterprise', label: t('userSections.enterprise') }]

  return <div data-testid={`system-settings-baseline-${mode}`} style={{ minWidth: 0 }}>
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={state.error} detail={t(writeErrorKey, { defaultValue: state.error })} onClose={() => write.reset()} /> : null}
    <SectionNavigation label={t(`innerNavigation.${mode}`)} items={navigation} />
    <Form {...formProps}>
      {mode === 'account' || mode === 'all' ? <>
      {section('login', <>
        <Form.Item label={t('userFields.session_ttl_seconds')} {...fieldStatus('session_ttl_seconds')} extra={t('hints.sessionTtl')}><Space.Compact block><InputNumber min={300} max={31536000} value={draft.session_ttl_seconds} disabled={!canManage} onChange={(value) => update('session_ttl_seconds', value ?? 300)} style={{ width: '100%' }} aria-label={t('userFields.session_ttl_seconds')} /><Input value={t('units.seconds')} readOnly tabIndex={-1} aria-hidden style={{ width: 48, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>
        <Form.Item label={t('userFields.user_login_domains')} {...fieldStatus('user_login_domains')}>{text('user_login_domains', t('placeholders.userLoginDomains'))}</Form.Item>
        <Form.Item label={t('userFields.admin_login_domains')} {...fieldStatus('admin_login_domains')}>{text('admin_login_domains', t('placeholders.adminLoginDomains'))}</Form.Item>
        <Form.Item label={t('userFields.email_code_login_enabled')}>{toggle('email_code_login_enabled')}</Form.Item>
        <Form.Item label={t('userFields.sms_code_login_enabled')}>{toggle('sms_code_login_enabled')}</Form.Item>
      </>)}
      {section('registration', <>
        <Form.Item label={t('userFields.registration_enabled')}>{toggle('registration_enabled')}</Form.Item>
        <Form.Item label={t('userFields.registration_success_template')} {...fieldStatus('registration_success_subject', 'registration_success_body')}>{template('registration_success_subject', 'registration_success_body')}</Form.Item>
        <Form.Item label={t('userFields.password_reset_template')} {...fieldStatus('password_reset_subject', 'password_reset_body')}>{template('password_reset_subject', 'password_reset_body')}</Form.Item>
        <Form.Item label={t('userFields.verification_template')} {...fieldStatus('verification_template_channel', 'verification_subject', 'verification_body', 'verification_sms_body', 'verification_sms_template_id')}><Space direction="vertical" size={8} style={{ width: '100%' }}><Radio.Group value={draft.verification_template_channel} disabled={!canManage} onChange={(event) => update('verification_template_channel', event.target.value)}><Radio value="email">{t('options.emailTemplate')}</Radio><Radio value="sms">{t('options.smsTemplate')}</Radio></Radio.Group>{draft.verification_template_channel === 'email' ? template('verification_subject', 'verification_body') : <Space direction="vertical" size={8} style={{ width: '100%' }}><Typography.Text type="secondary">{t('hints.smsTemplate')}</Typography.Text><Input.TextArea value={draft.verification_sms_body} disabled={!canManage} rows={3} onChange={(event) => update('verification_sms_body', event.target.value)} aria-label={t('userFields.verification_sms_body')} /><Space.Compact block><Input value={t('labels.templateID')} readOnly tabIndex={-1} aria-hidden style={{ width: 68, textAlign: 'center', pointerEvents: 'none' }} /><Input value={draft.verification_sms_template_id} disabled={!canManage} onChange={(event) => update('verification_sms_template_id', event.target.value)} aria-label={t('userFields.verification_sms_template_id')} /></Space.Compact></Space>}</Space></Form.Item>
        <Form.Item label={t('userFields.terms')} {...fieldStatus('terms_title', 'terms_body')}><Space direction="vertical" size={8} style={{ width: '100%' }}>{subjectInput('terms_title')}<Input.TextArea value={draft.terms_body} disabled={!canManage} rows={4} onChange={(event) => update('terms_body', event.target.value)} aria-label={t('userFields.terms_body')} /></Space></Form.Item>
        <Form.Item label={t('userFields.username_required')}>{requirement('username_required')}</Form.Item>
        <Form.Item label={t('userFields.email_required')} {...fieldStatus('email_verification_required')}>{requirement('email_required', 'email_verification_required')}</Form.Item>
        <Form.Item label={t('userFields.phone_required')} {...fieldStatus('phone_verification_required')}>{requirement('phone_required', 'phone_verification_required')}</Form.Item>
        <Form.Item label={t('userFields.default_phone_country_code')} {...fieldStatus('default_phone_country_code')} extra={t('hints.defaultPhoneCountryCode')}><Input addonBefore="+" maxLength={4} inputMode="numeric" value={draft.default_phone_country_code} disabled={!canManage} onChange={(event) => update('default_phone_country_code', event.target.value.replace(/\D/g, '').slice(0, 4))} aria-label={t('userFields.default_phone_country_code')} style={{ width: 160 }} /></Form.Item>
        <Form.Item label={t('userFields.qq_required')}>{requirement('qq_required')}</Form.Item>
      </>)}
      {section('security', <>
        <Form.Item label=" "><Link to="/sys/admin-access">{adminAccessT('title')}</Link></Form.Item>
        <Form.Item label={t('userFields.login_failure_limit_per_hour')} {...fieldStatus('login_failure_limit_per_hour')} extra={t('hints.loginFailure')}><Space.Compact block><InputNumber min={1} max={1000} value={draft.login_failure_limit_per_hour} disabled={!canManage} onChange={(value) => update('login_failure_limit_per_hour', value ?? 1)} style={{ width: '100%' }} aria-label={t('userFields.login_failure_limit_per_hour')} /><Input value={t('units.perHour')} readOnly tabIndex={-1} aria-hidden style={{ width: 80, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>
        <Form.Item label={t('userFields.login_captcha_threshold_per_hour')} {...fieldStatus('login_captcha_threshold_per_hour')} extra={t('hints.loginCaptcha')}><Space.Compact block><InputNumber min={1} max={draft.login_failure_limit_per_hour} value={draft.login_captcha_threshold_per_hour} disabled={!canManage} onChange={(value) => update('login_captcha_threshold_per_hour', value ?? 1)} style={{ width: '100%' }} aria-label={t('userFields.login_captcha_threshold_per_hour')} /><Input value={t('units.perHour')} readOnly tabIndex={-1} aria-hidden style={{ width: 80, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>
        <Form.Item label={t('userFields.session_region_check')} extra={t('hints.sessionRegion')}>{toggle('session_region_check')}</Form.Item>
        {(['email_anti_abuse_mode', 'sms_anti_abuse_mode'] as const).map((key) => <Form.Item key={key} label={t(`userFields.${key}`)} {...fieldStatus(key)}><Select value={draft[key]} disabled={!canManage} onChange={(value) => update(key, value)} options={(['none', 'native', 'tencent', 'geetest_v4'] as const).map((value) => ({ value, label: t(`antiAbuse.${value}`) }))} /></Form.Item>)}
      </>)}
      {section('captcha', <>
        <Form.Item label={t('userFields.captcha_provider')} {...fieldStatus('captcha_provider')}><Radio.Group value={draft.captcha_provider} disabled={!canManage} onChange={(event) => update('captcha_provider', event.target.value)}><Radio value="tencent">{t('options.tencent')}</Radio><Radio value="geetest_v4">{t('options.geetest')}</Radio></Radio.Group></Form.Item>
        {(['captcha_secret_id_reference', 'captcha_secret_key_reference', 'captcha_app_id', 'captcha_app_secret_reference'] as const).map((key) => <Form.Item key={key} label={t(`userFields.${key}`)} {...fieldStatus(key)}>{text(key, key === 'captcha_app_id' ? undefined : t('placeholders.secretReference'))}</Form.Item>)}
        <Form.Item label=" "><Typography.Text type="danger">{t('hints.captcha')}</Typography.Text></Form.Item>
      </>)}
      </> : null}
      {mode === 'payment' || mode === 'all' ? <>
      {section('identity', <Form.Item label={t('userFields.identity_verification_method')} {...fieldStatus('identity_verification_method')} extra={t('hints.identityMethod')}><Radio.Group data-testid="system-settings-identity-method" aria-label={t('hints.identityMethodLabel')} value={draft.identity_verification_method} disabled={!canManage} onChange={(event) => update('identity_verification_method', event.target.value)}><Space wrap><Radio value="none">{t('options.identityNone')}</Radio><Radio value="alipay">{t('options.alipayIdentity')}</Radio><Radio value="wechat_face">{t('options.wechatFace')}</Radio><Radio value="phone_three_factor">{t('options.phoneThreeFactor')}</Radio></Space></Radio.Group></Form.Item>)}
      {section('enterprise', <>
        <Form.Item label={t('userFields.enterprise_verification_enabled')} extra={t('hints.enterpriseEnabled')}>{toggle('enterprise_verification_enabled')}</Form.Item>
        <Form.Item label={t('userFields.enterprise_secret_id_reference')} {...fieldStatus('enterprise_secret_id_reference')} extra={t('hints.enterpriseSecrets')}>{text('enterprise_secret_id_reference', t('placeholders.secretReference'))}</Form.Item>
        <Form.Item label={t('userFields.enterprise_secret_key_reference')} {...fieldStatus('enterprise_secret_key_reference')}>{text('enterprise_secret_key_reference', t('placeholders.secretReference'))}</Form.Item>
        <Form.Item label=" "><Typography.Link href="https://market.cloud.tencent.com/products/30310" target="_blank" rel="noreferrer">{t('hints.identityProviderHelp')}</Typography.Link></Form.Item>
      </>)}
      </> : null}
      {mode === 'payment' || mode === 'all' ? <Form.Item label=" "><Space><Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" onClick={save}>{t('actions.saveRecharge')}</Button></Space></Form.Item> : null}
      {mode === 'all' ? <Form.Item label=" "><Space><Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" onClick={save}>{t('actions.save')}</Button></Space></Form.Item> : null}
    </Form>
    {mode === 'account' || mode === 'all' ? <><Divider /><Space><Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button>{mode === 'all' ? null : <Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" icon={<Save size={14} />} onClick={save}>{t('actions.save')}</Button>}<Typography.Text type="secondary">{t('metadata.revision')} {document.revision}</Typography.Text></Space></> : null}
    {write.saved ? <Alert type="success" showIcon message={state.saved} style={{ marginTop: 12 }} /> : null}
  </div>
}

function CleanupPanel() {
  const { t } = useTranslation('systemGlobalSettings')
  const { t: logCenterText } = useTranslation('logCenter')
  const { message } = App.useApp()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = baselineOwnerKey(principal, sessionEpoch)
  const [document, setDocument] = useState<PlatformSystemCleanupDocument | null>(null)
  const [draft, setDraft] = useState<PlatformSystemCleanupSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const load = useCallback(async () => {
    const token = currentBaselineAccess(ownerKey)
    if (!token || !canRead) { if (token) setLoading(false); return }
    setLoading(true); setError(null)
    setDocument(null); setDraft(null)
    try {
      const value = await systemCleanupSettingsApi.get(token)
      if (!currentBaselineAccess(ownerKey)) return
      setDocument(value); setDraft(value.value)
    } catch (reason) {
      if (currentBaselineAccess(ownerKey)) setError(reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error'))
    } finally {
      if (currentBaselineAccess(ownerKey)) setLoading(false)
    }
  }, [canRead, ownerKey])
  useEffect(() => { void load() }, [load, sessionEpoch])
  const write = useBaselineWrite<PlatformSystemCleanupSettings, PlatformSystemCleanupDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: 'cleanup',
    submit: (token, attempt) => systemCleanupSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey),
    onSuccess: (next) => { setDocument(next); setDraft(next.value); message.success(t('states.saved')) },
  })
  const refresh = () => { write.reset(); void load() }
  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={t('states.loading')} /><Form layout="vertical" style={{ maxWidth: 720, opacity: 0.55 }}>{(['cleanup_cache_days', 'access_logs_days', 'node_metrics_days'] as const).map((key) => <Form.Item key={key} label={t(`fields.${key}`)}><Input disabled /></Form.Item>)}<Typography.Title level={5}>{t('sections.backup')}</Typography.Title></Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : t('states.error')} subTitle={t(`errors.${error.code}`, { defaultValue: t('states.error') })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null
  const update = <K extends keyof PlatformSystemCleanupSettings>(key: K, value: PlatformSystemCleanupSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const save = () => { if (draft) write.save(draft) }
  const dayFields = ['cleanup_cache_days', 'access_logs_days', 'node_metrics_days', 'bandwidth_history_days', 'blacklist_history_days', 'node_traffic_history_days'] as const
  const numberInput = (key: typeof dayFields[number], max: number) => (
    <InputNumber min={0} max={max} value={draft[key]} disabled={!canManage} onChange={(value) => update(key, value ?? 0)} aria-label={t(`fields.${key}`)} style={{ width: '100%' }} />
  )
  return <div data-testid="system-settings-baseline-cleanup" className="system-settings-baseline-panel">
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error ? <FeedbackWhen title={t('states.error')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.error') })} onClose={write.reset} /> : null}
    <section className="system-settings-config-card" aria-labelledby="system-settings-cleanup-title">
      <h2 id="system-settings-cleanup-title">{t('sections.cleanup')}</h2>
      <Form className="system-settings-baseline-form system-settings-cleanup-grid" labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} labelAlign="right" colon={false}>
        {dayFields.map((key) => <Form.Item key={key} label={t(`fields.${key}`)}><Space.Compact block>{numberInput(key, 3650)}<Input value={t('units.days')} readOnly tabIndex={-1} aria-hidden style={{ width: 42, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>)}
      </Form>
    </section>
    <section className="system-settings-config-card" aria-labelledby="system-settings-audit-retention-title" data-testid="system-settings-audit-retention">
      <h2 id="system-settings-audit-retention-title">{logCenterText('retention.title')}</h2>
      <Typography.Paragraph type="secondary">{logCenterText('retention.hint')}</Typography.Paragraph>
      <Form className="system-settings-baseline-form system-settings-cleanup-grid" labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} labelAlign="right" colon={false}>
        {auditLogCategories.map((category) => <Form.Item key={category} label={logCenterText(`categories.${category}`)}><Space.Compact block>
          <InputNumber min={0} max={3650} value={draft.audit_retention_days[category]} disabled={!canManage} aria-label={logCenterText(`categories.${category}`)} style={{ width: '100%' }}
            onChange={(value) => update('audit_retention_days', { ...draft.audit_retention_days, [category]: value ?? 0 })} />
          <Input value={t('units.days')} readOnly tabIndex={-1} aria-hidden style={{ width: 42, textAlign: 'center', pointerEvents: 'none' }} />
        </Space.Compact></Form.Item>)}
      </Form>
    </section>
    <section className="system-settings-config-card" aria-labelledby="system-settings-backup-title">
      <h2 id="system-settings-backup-title">{t('sections.backup')}</h2>
      <Typography.Paragraph type="secondary" data-testid="system-settings-backup-moved">{t('sections.backupMoved')} <Link to="/sys/op?tab=maintenance">{t('sections.backupMovedLink')}</Link>{t('sections.backupMovedSuffix')}</Typography.Paragraph>
    </section>
    <Divider /><Space><Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button><Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" icon={<Save size={14} />} onClick={save}>{t('actions.save')}</Button><Typography.Text type="secondary">{t('metadata.revision')} {document.revision}</Typography.Text></Space>
    {write.saved ? <Alert type="success" showIcon message={t('states.saved')} style={{ marginTop: 12 }} /> : null}
  </div>
}

function MailPanel() {
  const { t, i18n } = useTranslation('systemGlobalSettings')
  const { message } = App.useApp()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = baselineOwnerKey(principal, sessionEpoch)
  const [document, setDocument] = useState<PlatformSystemMailSettingsDocument | null>(null)
  const [draft, setDraft] = useState<PlatformSystemMailSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)

  const load = useCallback(async () => {
    const token = currentBaselineAccess(ownerKey)
    if (!token || !canRead) { if (token) setLoading(false); return }
    setLoading(true); setError(null)
    setDocument(null); setDraft(null)
    try {
      const value = await systemMailSettingsApi.get(token)
      if (!currentBaselineAccess(ownerKey)) return
      setDocument(value); setDraft(value.value)
    } catch (reason) {
      if (currentBaselineAccess(ownerKey)) setError(reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error'))
    } finally {
      if (currentBaselineAccess(ownerKey)) setLoading(false)
    }
  }, [canRead, ownerKey])
  useEffect(() => { void load() }, [load, sessionEpoch])
  // Write-only native SMS credential: kept in memory for the pending write only.
  const [smsSecret, setSMSSecret] = useState('')
  const smsSecretRef = useRef('')
  // Write-only official mail credential, likewise.
  const [mailSecret, setMailSecret] = useState('')
  const mailSecretRef = useRef('')

  const write = useBaselineWrite<PlatformSystemMailSettings, PlatformSystemMailSettingsDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: 'mail',
    submit: (token, attempt) => systemMailSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey,
      { smsAccessKeySecret: smsSecretRef.current || undefined, mailSecret: mailSecretRef.current || undefined }),
    onSuccess: (next, attempt) => {
      setDocument(next)
      smsSecretRef.current = ''
      setSMSSecret('')
      mailSecretRef.current = ''
      setMailSecret('')
      setDraft((current) => current ? {
        ...next.value,
        ...Object.fromEntries(Object.entries(current).filter(([key, value]) => value !== attempt.value[key as keyof PlatformSystemMailSettings])),
      } : next.value)
      message.success(t('states.savedMail'))
    },
  })
  const refresh = () => { write.reset(); void load() }

  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={t('states.loadingMail')} /><Form labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} style={{ maxWidth: 520, opacity: 0.55 }}><Form.Item label={t('fields.smtpAddress')}><Input disabled /></Form.Item><Form.Item label={t('fields.smtpPort')}><Input disabled /></Form.Item></Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : t('states.errorMail')} subTitle={t(`errors.${error.code}`, { defaultValue: t('states.errorMail') })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null

  const supportedProvider = (provider: string) => provider === '' || provider === 'https_json' || (nativeSMSProviders as readonly string[]).includes(provider)
  const unsupportedProvider = !supportedProvider(draft.sms_provider)
  const persistedUnsupportedProvider = !supportedProvider(document.value.sms_provider)
  const nativeProvider = (nativeSMSProviders as readonly string[]).includes(draft.sms_provider)
  const update = <K extends keyof PlatformSystemMailSettings>(key: K, value: PlatformSystemMailSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const text = (key: keyof PlatformSystemMailSettings, placeholder?: string) => <Input value={String(draft[key])} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`fields.${key === 'smtp_password_reference' ? 'smtpPassword' : key === 'sms_access_key_reference' ? 'accessKeySecret' : key === 'sms_access_key_id' ? 'accessKeyID' : key === 'smtp_address' ? 'smtpAddress' : key === 'smtp_user' ? 'smtpUser' : 'signatureName'}`)} />
  const save = (section: 'smtp' | 'sms' | 'provider') => {
    if (write.saving || write.uncertain || (section === 'sms' ? unsupportedProvider : persistedUnsupportedProvider)) return
    const value = section === 'smtp'
      ? { ...document.value, smtp_address: draft.smtp_address, smtp_ssl: draft.smtp_ssl, smtp_port: draft.smtp_port, smtp_user: draft.smtp_user, smtp_password_reference: draft.smtp_password_reference }
      : section === 'provider'
        // Only the sender fields: the SMTP section keeps its own draft.
        ? { ...document.value, mail_provider: draft.mail_provider, mail_region: mailProviderKind(draft.mail_provider) === 'official' ? draft.mail_region : document.value.mail_region,
            mail_access_key_id: draft.mail_provider === 'aliyun' ? draft.mail_access_key_id : document.value.mail_access_key_id,
            mail_from: draft.mail_from, mail_from_name: draft.mail_from_name }
        : { ...document.value, sms_provider: draft.sms_provider, sms_access_key_id: draft.sms_access_key_id,
            sms_access_key_reference: nativeProvider ? '' : draft.sms_access_key_reference, sms_signature_name: draft.sms_signature_name,
            sms_template_map: nativeProvider ? draft.sms_template_map : '' }
    smsSecretRef.current = section === 'sms' && nativeProvider ? smsSecret : ''
    mailSecretRef.current = section === 'provider' && mailProviderKind(draft.mail_provider) === 'official' ? mailSecret : ''
    write.save(value, section)
  }
  // A refusal of a field on this tab goes under it (fix-fielderr-be2).
  const { status: fieldStatus, shown: refusedShown } = refusedFieldStatus(write.error, ['smtp_address', 'smtp_port', 'smtp_user', 'smtp_password_reference',
    'sms_provider', 'sms_access_key_id', 'sms_access_key_reference', 'sms_access_key_secret', 'sms_signature_name', 'sms_template_map',
    'mail_provider', 'mail_region', 'mail_access_key_id', 'mail_secret', 'mail_from', 'mail_from_name'], i18n.resolvedLanguage)
  return <div data-testid="system-settings-baseline-mail" className="system-settings-baseline-panel">
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={t('states.errorMail')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.errorMail') })} onClose={write.reset} /> : null}
    {persistedUnsupportedProvider ? <Alert type="warning" showIcon message={t('smsProviders.repair')} style={{ marginBottom: 16 }} /> : null}
    <Form className="system-settings-baseline-form system-settings-baseline-wide-form" labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} labelAlign="right" colon={false}>
      <MailProviderSection accessToken={accessToken} canManage={canManage} document={document} draft={draft} update={update} fieldStatus={fieldStatus}
        secret={mailSecret} onSecretChange={setMailSecret} saving={write.saving && write.savingScope === 'provider'}
        disabled={write.uncertain || write.saving || persistedUnsupportedProvider} onSave={() => save('provider')} />
      <section className="system-settings-config-card" aria-labelledby="system-settings-smtp-title">
        <h2 id="system-settings-smtp-title">{t('sections.smtp')}</h2>
        <Form.Item label={t('fields.smtpAddress')} {...fieldStatus('smtp_address')}>{text('smtp_address')}</Form.Item>
        <Form.Item label={t('fields.smtpSSL')}><Switch checked={draft.smtp_ssl} disabled={!canManage} onChange={(value) => update('smtp_ssl', value)} aria-label={t('fields.smtpSSL')} /></Form.Item>
        <Form.Item label={t('fields.smtpPort')} {...fieldStatus('smtp_port')}><InputNumber min={1} max={65535} value={draft.smtp_port} disabled={!canManage} onChange={(value) => update('smtp_port', value ?? 465)} style={{ width: '100%' }} aria-label={t('fields.smtpPort')} /></Form.Item>
        <Form.Item label={t('fields.smtpUser')} {...fieldStatus('smtp_user')}>{text('smtp_user')}</Form.Item>
        <Form.Item label={t('fields.smtpPassword')} {...fieldStatus('smtp_password_reference')}>{text('smtp_password_reference', t('placeholders.secretReference'))}</Form.Item>
        <Typography.Text type="secondary">{t('states.sensitive')}</Typography.Text>
        <div><Button aria-label={t('mailActions.smtp')} aria-busy={write.saving && write.savingScope === 'smtp'} disabled={!canManage || write.uncertain || write.saving || persistedUnsupportedProvider} type="primary" loading={write.saving && write.savingScope === 'smtp'} onClick={() => save('smtp')}>{t('mailActions.smtp')}</Button></div>
      </section>
      <section className="system-settings-config-card" aria-labelledby="system-settings-sms-title">
        <h2 id="system-settings-sms-title">{t('sections.sms')}</h2>
        <Form.Item label={t('fields.smsProvider')} {...fieldStatus('sms_provider')} extra={t('smsProviders.hint')}>
          <Select value={draft.sms_provider} disabled={!canManage} aria-label={t('fields.smsProvider')} onChange={(value) => update('sms_provider', value)} options={[
            { value: '', label: t('smsProviders.inherit') }, { value: 'https_json', label: t('smsProviders.httpsJSON') },
            { value: 'aliyun', label: t('smsProviders.aliyun') }, { value: 'submail', label: t('smsProviders.submail') },
            ...(unsupportedProvider ? [{ value: draft.sms_provider, label: t('smsProviders.unsupported', { provider: draft.sms_provider }), disabled: true }] : []),
          ]} />
        </Form.Item>
        <Form.Item label={t('fields.accessKeyID')} {...fieldStatus('sms_access_key_id')}>{text('sms_access_key_id')}</Form.Item>
        {nativeProvider
          ? <Form.Item label={t('fields.accessKeySecret')} {...fieldStatus('sms_access_key_secret', 'sms_access_key_reference')} extra={document.sms_secret_configured ? t('smsProviders.secretSet', { fingerprint: document.sms_secret_fingerprint }) : t('smsProviders.secretRequired')}>
            <Input.Password value={smsSecret} disabled={!canManage} autoComplete="new-password" placeholder={document.sms_secret_configured ? t('smsProviders.secretKeep') : ''} onChange={(event) => setSMSSecret(event.target.value)} aria-label={t('fields.accessKeySecret')} />
          </Form.Item>
          : <Form.Item label={t('fields.accessKeySecret')} {...fieldStatus('sms_access_key_reference', 'sms_access_key_secret')}>{text('sms_access_key_reference', t('placeholders.secretReference'))}</Form.Item>}
        <Form.Item label={t('fields.signatureName')} {...fieldStatus('sms_signature_name')}>{text('sms_signature_name')}</Form.Item>
        {nativeProvider ? <Form.Item label={t('fields.smsTemplateMap')} {...fieldStatus('sms_template_map')} extra={t('smsProviders.templateMapHint')}>
          <Input.TextArea value={draft.sms_template_map} disabled={!canManage} rows={5} onChange={(event) => update('sms_template_map', event.target.value)} aria-label={t('fields.smsTemplateMap')} />
        </Form.Item> : null}
        <div><Button aria-label={t('mailActions.sms')} aria-busy={write.saving && write.savingScope === 'sms'} disabled={!canManage || write.uncertain || write.saving || unsupportedProvider} type="primary" loading={write.saving && write.savingScope === 'sms'} onClick={() => save('sms')}>{t('mailActions.sms')}</Button></div>
      </section>
    </Form>
    <Space wrap><Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button><Typography.Text type="secondary">{t('metadata.revision')} {document.revision}</Typography.Text></Space>
    {write.saved ? <Alert type="success" showIcon message={t('states.savedMail')} style={{ marginTop: 12 }} /> : null}
  </div>
}

/** "30 14 7" (spaces or commas) as descending distinct days 1–60, or null. */
function parseCertificateNoticeDays(text: string): number[] | null {
  const parts = text.split(/[\s,，、]+/).filter(Boolean)
  if (parts.some((part) => !/^\d{1,2}$/.test(part))) return null
  const days = [...new Set(parts.map(Number))].sort((left, right) => right - left)
  return validCertificateNoticeDays(days) ? days : null
}

function OtherPanel() {
  const { t, i18n } = useTranslation('systemGlobalSettings')
  const { message } = App.useApp()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = baselineOwnerKey(principal, sessionEpoch)
  const [document, setDocument] = useState<PlatformSystemOtherSettingsDocument | null>(null)
  const [draft, setDraft] = useState<PlatformSystemOtherSettings | null>(null)
  const [loading, setLoading] = useState(true)
  // Free-text notice days while typing; null shows the saved list.
  const [certificateNoticeDaysText, setCertificateNoticeDaysText] = useState<string | null>(null)
  const parsedCertificateNoticeDays = certificateNoticeDaysText === null ? null : parseCertificateNoticeDays(certificateNoticeDaysText)
  const [error, setError] = useState<ApiError | null>(null)
  const load = useCallback(async () => {
    const token = currentBaselineAccess(ownerKey)
    if (!token || !canRead) { if (token) setLoading(false); return }
    setLoading(true); setError(null)
    setDocument(null); setDraft(null)
    try {
      const value = await systemOtherSettingsApi.get(token)
      if (!currentBaselineAccess(ownerKey)) return
      setDocument(value); setDraft(value.value)
    } catch (reason) {
      if (currentBaselineAccess(ownerKey)) setError(reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error'))
    } finally {
      if (currentBaselineAccess(ownerKey)) setLoading(false)
    }
  }, [canRead, ownerKey])
  useEffect(() => { void load() }, [load, sessionEpoch])
  const write = useBaselineWrite<PlatformSystemOtherSettings, PlatformSystemOtherSettingsDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: 'other',
    submit: (token, attempt) => systemOtherSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey),
    onSuccess: (next) => { setDocument(next); setDraft(next.value); setCertificateNoticeDaysText(null); message.success(t('states.savedOther')) },
  })
  const refresh = () => { write.reset(); setCertificateNoticeDaysText(null); void load() }
  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={t('states.loadingOther')} /><Form labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} style={{ maxWidth: 520, opacity: 0.55 }}><Form.Item label={t('fields.sourceIPHeader')}><Input disabled /></Form.Item><Form.Item label={t('fields.syncBatch')}><Input disabled /></Form.Item></Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : t('states.errorOther')} subTitle={t(`errors.${error.code}`, { defaultValue: t('states.errorOther') })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null
  const update = <K extends keyof PlatformSystemOtherSettings>(key: K, value: PlatformSystemOtherSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const noticeDaysInvalid = certificateNoticeDaysText !== null && !parsedCertificateNoticeDays
  const save = () => { if (!noticeDaysInvalid) write.save(draft) }
  const dirty = noticeDaysInvalid || JSON.stringify(draft) !== JSON.stringify(document.value)
  const onOff = (value: boolean) => value ? t('v2.on') : t('v2.off')
  const repairLabel = t(`options.${({ off: 'repairOff', repair: 'repair', repair_delete_extra: 'repairDeleteExtra' } as const)[draft.record_repair_mode]}`)
  const syncValue = t('v2.other.syncValue', { scope: t(`options.${draft.sync_scope === 'region' ? 'region' : 'lineGroup'}`), count: draft.sync_batch })
  const noticeDays = draft.certificate_expiry_notice_days.join('/')
  const protectedHosts = draft.dns_protection.split(',').map((item) => item.trim()).filter(Boolean).length
  // fix-sysother：六张分组卡；卡头右侧是该组当前值，长说明进标签旁 (?)。
  const groups = [
    { id: 'other-network', title: t('v2.other.groups.network'), sub: `${draft.source_ip_header || t('v2.other.notSet')} · ${draft.http_proxy ? t('v2.other.proxyOn') : t('v2.other.proxyOff')}` },
    { id: 'other-records', title: t('v2.other.groups.records'), sub: protectedHosts ? `${repairLabel} · ${t('v2.other.protectedCount', { count: protectedHosts })}` : repairLabel },
    { id: 'other-sync', title: t('v2.other.groups.sync'), sub: syncValue },
    { id: 'other-api', title: t('v2.other.groups.api'), sub: `${t('v2.other.summary.apiKey')} ${onOff(draft.api_key_enabled)}` },
    { id: 'other-traffic', title: t('v2.other.groups.traffic'), sub: `${t('v2.other.rankValue', { count: draft.resource_rank })} · ${t('v2.other.tcpValue', { value: draft.tcp_factor })}` },
    { id: 'other-domain', title: t('v2.other.groups.domain'), sub: `${t(`domainOwnership.${draft.domain_ownership_policy}`)} · ${t('v2.other.noticesValue', { days: noticeDays })}` },
  ] as const
  const card = (index: number, body: ReactNode, impact = false) => {
    const group = groups[index]
    return <section id={group.id} className={`system-settings-config-card sys-setting-section-anchor sys-other-card${impact ? ' sys-setting-v2-impact' : ''}`} aria-labelledby={`${group.id}-title`}>
      <div className="sys-other-card-head">
        <h2 id={`${group.id}-title`} className="system-settings-config-card-title">{group.title}</h2>
        <span className="sys-other-card-sub">{group.sub}</span>
      </div>
      {body}
    </section>
  }
  const label = (name: string, hint?: string) => <span className="sys-other-label">{name}{hint ? <FieldHelp name={name} text={hint} /> : null}</span>
  const toggleCard = (key: 'disable_failed_sync_nodes' | 'api_key_enabled' | 'rule_intel_contribution', name: string, hint: string, impactWhenOff = false) => {
    const on = draft[key]
    return <div className={`sys-setting-v2-toggle${on ? ' is-on' : ''}${!on && impactWhenOff ? ' is-impact' : ''}`}>
      <span className="sys-setting-v2-toggle-text">
        <span className="sys-setting-v2-toggle-title">{label(name, hint)}</span>
        <span className="sys-setting-v2-toggle-state">{onOff(on)}</span>
      </span>
      <Switch checked={on} disabled={!canManage} onChange={(value) => update(key, value)} aria-label={name} />
    </div>
  }
  // A refusal of a field on this tab goes under it (fix-fielderr-be2).
  const { status: fieldStatus, shown: refusedShown } = refusedFieldStatus(write.error, ['source_ip_header', 'http_proxy', 'record_repair_mode', 'dns_protection',
    'sync_batch', 'sync_scope', 'resource_rank', 'tcp_factor', 'domain_ownership_policy', 'certificate_expiry_notice_days', 'l4_drain_max_seconds'], i18n.resolvedLanguage)
  return <div data-testid="system-settings-baseline-other" className="system-settings-baseline-panel sys-other" style={{ minWidth: 0 }}>
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={t('states.errorOther')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.errorOther') })} onClose={write.reset} /> : null}
    {write.saved ? <Alert type="success" showIcon message={t('states.savedOther')} style={{ marginBottom: 16 }} /> : null}
    <div className="sys-other-summary">
      <SystemSummary label={t('v2.summary.label')} items={[
        { target: 'other-network', label: t('v2.other.summary.sourceIP'), value: draft.source_ip_header || t('v2.other.notSet'), tone: draft.source_ip_header ? undefined : 'off' },
        { target: 'other-records', label: t('v2.other.summary.records'), value: repairLabel, tone: draft.record_repair_mode === 'off' ? 'off' : undefined },
        { target: 'other-sync', label: t('v2.other.summary.sync'), value: syncValue },
        { target: 'other-api', label: t('v2.other.summary.apiKey'), value: onOff(draft.api_key_enabled), tone: draft.api_key_enabled ? 'success' : 'warning' },
        { target: 'other-domain', label: t('v2.other.summary.domain'), value: t(`domainOwnership.${draft.domain_ownership_policy}`), tone: draft.domain_ownership_policy === 'off' ? 'warning' : undefined },
        { target: 'other-domain', label: t('v2.other.summary.notices'), value: t('v2.other.noticesValue', { days: noticeDays }) },
      ]} />
    </div>
    <Form className="sys-other-form" layout="vertical" colon={false} requiredMark={false}>
      <div className="sys-other-grid">
        {card(0, <>
          <Form.Item label={label(t('fields.sourceIPHeader'))} {...fieldStatus('source_ip_header')}><Input value={draft.source_ip_header} disabled={!canManage} onChange={(event) => update('source_ip_header', event.target.value)} aria-label={t('fields.sourceIPHeader')} /></Form.Item>
          <Form.Item label={label(t('fields.httpProxy'), t('hints.httpProxy'))} {...fieldStatus('http_proxy')}><Input value={draft.http_proxy} disabled={!canManage} onChange={(event) => update('http_proxy', event.target.value)} aria-label={t('fields.httpProxy')} /></Form.Item>
        </>)}
        {card(1, <>
          <Form.Item label={label(t('fields.recordRepairMode'))} {...fieldStatus('record_repair_mode')}>
            <Radio.Group name="other-record_repair_mode" value={draft.record_repair_mode} disabled={!canManage} onChange={(event) => update('record_repair_mode', event.target.value)} aria-label={t('fields.recordRepairMode')}>
              <Radio.Button value="off">{t('options.repairOff')}</Radio.Button>
              <Radio.Button value="repair">{t('options.repair')}</Radio.Button>
              <Radio.Button value="repair_delete_extra">{t('options.repairDeleteExtra')}</Radio.Button>
            </Radio.Group>
          </Form.Item>
          <Form.Item label={label(t('fields.dnsProtection'))} {...fieldStatus('dns_protection')}><Input value={draft.dns_protection} disabled={!canManage} onChange={(event) => update('dns_protection', event.target.value)} placeholder={t('placeholders.dnsProtection')} aria-label={t('fields.dnsProtection')} /></Form.Item>
        </>)}
        {card(2, <>
          <div className="sys-other-row">
            <Form.Item label={label(t('fields.syncBatch'))} {...fieldStatus('sync_batch')}><InputNumber min={1} max={10000} value={draft.sync_batch} disabled={!canManage} onChange={(value) => update('sync_batch', value ?? 1000)} style={{ width: '100%' }} aria-label={t('fields.syncBatch')} /></Form.Item>
            <Form.Item label={label(t('fields.syncScope'))} {...fieldStatus('sync_scope')}>
              <Radio.Group name="other-sync_scope" value={draft.sync_scope} disabled={!canManage} onChange={(event) => update('sync_scope', event.target.value)} aria-label={t('fields.syncScope')}>
                <Radio.Button value="region">{t('options.region')}</Radio.Button>
                <Radio.Button value="line_group">{t('options.lineGroup')}</Radio.Button>
              </Radio.Group>
            </Form.Item>
          </div>
          <div className="sys-other-toggles">{toggleCard('disable_failed_sync_nodes', t('fields.disableFailedSyncNodes'), t('hints.disableFailedSyncNodes'))}</div>
        </>)}
        {card(3, <div className="sys-other-toggles">
          {toggleCard('api_key_enabled', t('fields.apiKeyEnabled'), t('hints.apiKeyEnabled'), true)}
          {toggleCard('rule_intel_contribution', t('fields.ruleIntelContribution'), t('hints.ruleIntelContribution'))}
        </div>, !draft.api_key_enabled)}
        {card(4, <div className="sys-other-row">
          <Form.Item label={label(t('fields.resourceRank'))} {...fieldStatus('resource_rank')}><InputNumber min={1} max={1000} value={draft.resource_rank} disabled={!canManage} onChange={(value) => update('resource_rank', value ?? 100)} style={{ width: '100%' }} aria-label={t('fields.resourceRank')} /></Form.Item>
          <Form.Item label={label(t('fields.tcpFactor'))} {...fieldStatus('tcp_factor')}>
            {draft.tcp_factor === 1 || draft.tcp_factor === 1.1 ? (
              <Radio.Group name="other-tcp_factor" value={draft.tcp_factor} disabled={!canManage} onChange={(event) => update('tcp_factor', event.target.value)} aria-label={t('fields.tcpFactor')}>
                <Radio.Button value={1}>1.0</Radio.Button>
                <Radio.Button value={1.1}>1.1</Radio.Button>
              </Radio.Group>
            ) : (
              <InputNumber min={0.01} max={100} step={0.01} value={draft.tcp_factor} disabled={!canManage} onChange={(value) => update('tcp_factor', value ?? 1.1)} style={{ width: '100%' }} aria-label={t('fields.tcpFactor')} />
            )}
          </Form.Item>
        </div>)}
        {card(5, <>
          <Form.Item label={label(t('domainOwnership.label'), t('domainOwnership.hint'))} {...fieldStatus('domain_ownership_policy')}>
            <Radio.Group name="other-domain_ownership_policy" value={draft.domain_ownership_policy} disabled={!canManage} onChange={(event) => update('domain_ownership_policy', event.target.value)} aria-label={t('domainOwnership.label')}>
              {(['off', 'wildcard_only', 'all'] as const).map((policy) => <Radio.Button key={policy} value={policy}>{t(`domainOwnership.${policy}`)}</Radio.Button>)}
            </Radio.Group>
          </Form.Item>
          <Form.Item label={label(t('fields.certificateExpiryNoticeDays'), t('hints.certificateExpiryNoticeDays'))} {...fieldStatus('certificate_expiry_notice_days')}
            {...(noticeDaysInvalid ? { validateStatus: 'error' as const, help: t('v2.other.invalidDays') } : {})}>
            <Input value={certificateNoticeDaysText ?? draft.certificate_expiry_notice_days.join(' ')} disabled={!canManage}
              aria-label={t('fields.certificateExpiryNoticeDays')} addonAfter={t('units.days')}
              onChange={(event) => {
                setCertificateNoticeDaysText(event.target.value)
                const days = parseCertificateNoticeDays(event.target.value)
                if (days) update('certificate_expiry_notice_days', days)
              }} />
          </Form.Item>
        </>)}
      </div>
      {/* Expert item, folded (ADMIN-CURRENT-08); still saved with the rest of this tab. */}
      <div id="other-l4-drain" className="sys-other-expert">
      <Collapse size="small" items={[{
        key: 'l4-drain', label: t('scope.expert', { name: t('sections.l4Drain') }),
        extra: <span className="sys-other-card-sub">{draft.l4_drain_max_seconds === 0 ? t('v2.other.drainUnlimited') : t('v2.other.drainValue', { value: draft.l4_drain_max_seconds })}</span>,
        children: <Form.Item label={label(t('fields.l4DrainMaxSeconds'), t('hints.l4DrainMaxSeconds'))} {...fieldStatus('l4_drain_max_seconds')}>
          <InputNumber min={0} max={604800} step={3600} precision={0} value={draft.l4_drain_max_seconds} disabled={!canManage} onChange={(value) => update('l4_drain_max_seconds', value ?? 86400)} addonAfter={t('units.seconds')} style={{ width: 280, maxWidth: '100%' }} aria-label={t('fields.l4DrainMaxSeconds')} />
        </Form.Item>,
      }]} />
      </div>
    </Form>
    {/* fix-sysother：底部固定保存条，滚动中始终可见；只管上方分组卡；审批中心在其后单独保存。 */}
    <div className={`sys-setting-v2-savebar sys-other-savebar${dirty ? ' is-dirty' : ''}`}>
      <span>{noticeDaysInvalid ? t('v2.other.invalidDays') : dirty ? t('v2.other.unsaved') : t('v2.other.allSaved')}</span>
      <Typography.Text type="secondary">{t('metadata.revision')} {document.revision}</Typography.Text>
      <Space className="sys-other-savebar-actions">
        <Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button>
        <Button disabled={!canManage || write.uncertain || noticeDaysInvalid} loading={write.saving} type="primary" icon={<Save size={14} />} onClick={save}>{t('actions.save')}</Button>
      </Space>
    </div>
    <ApprovalCenterSettings />
  </div>
}

// FieldHelp: long field descriptions behind a focusable (?) instead of under the control.
function FieldHelp({ name, text }: { name: string; text: string }) {
  const { t } = useTranslation('systemGlobalSettings')
  return <Tooltip title={text} trigger={['hover', 'focus', 'click']} styles={{ root: { maxWidth: 360 } }}>
    <button type="button" className="sys-other-help" aria-label={t('v2.other.help', { name })}><CircleHelp size={14} aria-hidden /></button>
  </Tooltip>
}

function SystemPanel() {
  const { t, i18n } = useTranslation('systemGlobalSettings')
  const { message } = App.useApp()
  // fix-ui1026 #4: an active theme that names the product overrides the
  // system name and console titles shown after sign-in.
  const themeRuntime = useThemeRuntime()
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const themeBrandName = useThemeBrandName(locale)
  const themeName = localizedText(themeRuntime.document?.name, locale) || themeRuntime.document?.id || ''
  const feedback = useFeedback()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = baselineOwnerKey(principal, sessionEpoch)
  const [document, setDocument] = useState<PlatformSystemSettingsDocument | null>(null)
  const [draft, setDraft] = useState<PlatformSystemSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [brandAssets, setBrandAssets] = useState<Partial<Record<BrandAssetSlot, BrandAsset>>>({})
  const [brandAssetError, setBrandAssetError] = useState<ApiError | null>(null)
  const [rejectedBrandSlot, setRejectedBrandSlot] = useState<BrandAssetSlot | null>(null)
  const [brandUploadAttempt, setBrandUploadAttempt] = useState<BrandAssetUploadAttempt | null>(null)
  const [uploadingSlot, setUploadingSlot] = useState<BrandAssetSlot | null>(null)
  const [assetSaved, setAssetSaved] = useState(false)
  const brandAssetGeneration = useRef(0)
  const brandBindingSlot = useRef<BrandAssetSlot | null>(null)
  // MC01/B01: a refresh after the first read keeps the document, draft and revision until a new
  // snapshot arrives; its failure is a local error (refreshError), not the page error.
  const documentRef = useRef<PlatformSystemSettingsDocument | null>(null)
  documentRef.current = document
  const readGeneration = useRef(0)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshError, setRefreshError] = useState<ApiError | null>(null)

  const load = useCallback(async () => {
    brandAssetGeneration.current += 1
    const read = ++readGeneration.current
    const token = currentBaselineAccess(ownerKey)
    if (!token || !canRead) { if (token) setLoading(false); return }
    const reread = documentRef.current !== null
    const current = () => read === readGeneration.current && Boolean(currentBaselineAccess(ownerKey))
    setError(null); setRefreshError(null); setAssetSaved(false); setUploadingSlot(null)
    setBrandAssetError(null); setBrandUploadAttempt(null); brandBindingSlot.current = null
    if (reread) setRefreshing(true)
    else { setLoading(true); setDocument(null); setDraft(null); setBrandAssets({}) }
    try {
      const value = await systemSettingsApi.get(token)
      if (!current()) return
      setDocument(value); setDraft(value.value)
      try {
        const assets = await brandAssetApi.list(token)
        if (!currentBaselineAccess(ownerKey)) return
        setBrandAssets(Object.fromEntries(assets.assets.filter((asset) => asset.revision > 0).map((asset) => [asset.slot, asset])) as Partial<Record<BrandAssetSlot, BrandAsset>>)
      } catch {
        if (currentBaselineAccess(ownerKey)) {
          setBrandAssets({})
        }
      }
    } catch (reason) {
      if (!current()) return
      const apiError = reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error')
      if (reread) setRefreshError(apiError)
      else setError(apiError)
    } finally {
      if (current()) { setLoading(false); setRefreshing(false) }
    }
  }, [canRead, ownerKey])
  useEffect(() => { void load() }, [load, sessionEpoch])
  const write = useBaselineWrite<PlatformSystemSettings, PlatformSystemSettingsDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: 'system',
    submit: (token, attempt) => systemSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey),
    onSuccess: (next, attempt) => {
      setDocument(next)
      setDraft((current) => current && JSON.stringify(current) !== JSON.stringify(attempt.value) ? current : next.value)
      window.dispatchEvent(new Event(systemSettingsChangedEvent))
      message.success(t('states.saved'))
    },
  })
  const { status: fieldStatus, shown: refusedShown, key: refusedKey } = refusedFieldStatus(write.error, ['system_name', 'user_title', 'admin_title',
    'footer_links', 'footer_text', 'global_js', 'bound_domains', 'global_js_report_hosts', 'maintenance_message', 'purchase_notice'], i18n.resolvedLanguage)
  const brandBindingWrite = useBaselineWrite<PlatformSystemSettings, PlatformSystemSettingsDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: 'system-brand-binding',
    submit: (token, attempt) => systemSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey),
    onSuccess: (next) => {
      setDocument(next); setDraft(next.value); setAssetSaved(true)
      if (brandBindingSlot.current) window.dispatchEvent(new Event(publicBrandAssetUpdatedEvent))
      brandBindingSlot.current = null
      message.success(t('states.assetUploaded'))
    },
  })
  // MC01/B01: a write sent or of unknown outcome is not dropped by a plain refresh (disabled then);
  // 放弃并刷新 on an unknown outcome is the explicit abandonment.
  const writeInFlight = write.saving || brandBindingWrite.saving || uploadingSlot !== null
  const refresh = () => { write.reset(); brandBindingWrite.reset(); void load() }
  useBaselineAutoSave({
    draft,
    persisted: document?.value ?? null,
    enabled: Boolean(canManage && validSystemSettingsAutoSaveDraft(draft)),
    blocked: write.saving || write.uncertain || Boolean(write.error) || uploadingSlot !== null || brandBindingWrite.saving || brandBindingWrite.uncertain ||
      refreshing || Boolean(refreshError),
    save: write.save,
  })
  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={t('states.loading')} /><Form layout="vertical" style={{ maxWidth: 720, opacity: 0.55 }}>{(['system_name', 'user_title', 'admin_title'] as const).map((key) => <Form.Item key={key} label={t(`fields.${key}`)}><Input disabled /></Form.Item>)}<Typography.Title level={5}>{t('sections.package')}</Typography.Title></Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : t('states.error')} subTitle={t(`errors.${error.code}`, { defaultValue: t('states.error') })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null

  const update = <K extends keyof PlatformSystemSettings>(key: K, value: PlatformSystemSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const text = (key: keyof PlatformSystemSettings, placeholder?: string) => <Input value={String(draft[key] ?? '')} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`fields.${key}`)} />
  const toggle = (key: keyof PlatformSystemSettings) => <Switch checked={draft[key] as boolean} disabled={!canManage} onChange={(value) => update(key, value)} aria-label={t(`fields.${key}`)} />
  const runBrandAssetUpload = async (attempt: BrandAssetUploadAttempt) => {
    const token = currentBaselineAccess(ownerKey)
    const isCurrentUpload = () => brandAssetGeneration.current === attempt.generation && Boolean(currentBaselineAccess(attempt.ownerKey)) && attempt.ownerKey === ownerKey
    if (!token || !canManage || !document || !draft || !isCurrentUpload()) return
    setBrandAssetError(null)
    setUploadingSlot(attempt.slot)
    try {
      const asset = await brandAssetApi.upload(token, attempt.slot, attempt.revision, attempt.file, { requestId: attempt.requestId, idempotencyKey: attempt.idempotencyKey })
      if (!isCurrentUpload()) return
      const nextDraft = { ...draft, [attempt.slot]: asset.reference ?? '' }
      setBrandAssets((current) => ({ ...current, [attempt.slot]: asset }))
      setBrandUploadAttempt(null)
      setAssetSaved(false)
      brandBindingSlot.current = attempt.slot
      brandBindingWrite.save(nextDraft, 'system-brand-binding')
    } catch (reason) {
      if (isCurrentUpload()) {
        const apiError = reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error')
        setBrandAssetError(apiError)
        if (isUnknownBaselineWriteOutcome(reason)) setBrandUploadAttempt(attempt)
        else setBrandUploadAttempt(null)
        if (!isUnknownBaselineWriteOutcome(reason)) feedback.error(t(`errors.${apiError.code}`, { defaultValue: t('states.assetUploadError') }))
      }
    } finally {
      if (isCurrentUpload()) setUploadingSlot(null)
    }
  }
  const uploadBrandAsset = async (key: 'favicon' | 'logo' | 'login_ad', file: File) => {
    const token = currentBaselineAccess(ownerKey)
    if (!token || !ownerKey || !canManage || !document || !draft) return
    const generation = brandAssetGeneration.current
    const isCurrentUpload = () => brandAssetGeneration.current === generation && Boolean(currentBaselineAccess(ownerKey))
    const slot = key as BrandAssetSlot
    const allowed = slot === 'favicon' ? ['image/x-icon', 'image/vnd.microsoft.icon', 'image/png'] : slot === 'logo' ? ['image/png'] : ['image/jpeg']
    if (!allowed.includes(file.type) || file.size < 1 || file.size > 2 * 1024 * 1024) {
      // fix-feedbackui2: said in that asset's card, not in a dialog.
      setRejectedBrandSlot(slot)
      return
    }
    setRejectedBrandSlot(null)
    setBrandAssetError(null)
    brandBindingWrite.reset()
    try {
      const currentAsset = brandAssets[slot] ?? await brandAssetApi.get(token, slot)
      if (!isCurrentUpload()) return
      const requestId = `brand-asset-${slot}-${crypto.randomUUID()}`
      const attempt: BrandAssetUploadAttempt = { ownerKey, generation, slot, revision: currentAsset.revision, file, requestId, idempotencyKey: requestId }
      setBrandUploadAttempt(attempt)
      await runBrandAssetUpload(attempt)
    } catch (reason) {
      if (isCurrentUpload()) {
        const apiError = reason instanceof ApiError ? reason : new ApiError('API request failed', 0, 'network_error')
        setBrandAssetError(apiError)
        feedback.error(t(`errors.${apiError.code}`, { defaultValue: t('states.assetUploadError') }))
      }
    }
  }
  const brandUploadUncertain = Boolean(brandUploadAttempt && brandAssetError && isUnknownBaselineWriteOutcome(brandAssetError))
  const retryBrandAssetUpload = () => { if (brandUploadAttempt && brandUploadUncertain && uploadingSlot === null) void runBrandAssetUpload(brandUploadAttempt) }
  const assetField = (key: 'favicon' | 'logo' | 'login_ad') => {
    const asset = brandAssets[key]
    const previewPath = asset?.revision ? `/v1/brand-assets/${key}` : builtInBrandAsset(key)
    return <Upload accept={key === 'favicon' ? '.ico,.png,image/x-icon,image/png' : key === 'logo' ? '.png,image/png' : '.jpg,.jpeg,image/jpeg'} showUploadList={false} beforeUpload={(file) => { void uploadBrandAsset(key, file); return Upload.LIST_IGNORE }} disabled={!canManage || uploadingSlot !== null || brandUploadUncertain || brandBindingWrite.saving || brandBindingWrite.uncertain}>
      <span className={`system-settings-brand-asset-preview system-settings-brand-asset-preview--${key}`} role="button" tabIndex={canManage ? 0 : -1} aria-label={t(`fields.${key}`)}>
        <img src={previewPath} alt={t(`fields.${key}`)} />
      </span>
    </Upload>
  }
  const dirty = JSON.stringify(draft) !== JSON.stringify(document.value)
  const navigation = [
    { id: 'system-info', label: t('innerNav.systemInfo') },
    { id: 'system-brand', label: t('innerNav.brand') },
    { id: 'system-package', label: t('innerNav.package') },
    { id: 'system-maintenance', label: t('innerNav.maintenance') },
  ]
  return <div data-testid="system-settings-baseline-system" className="system-settings-baseline-panel">
    <SaveState visible={write.saving || brandBindingWrite.saving || uploadingSlot !== null} label={t('states.saving')} />
    <div className="system-settings-feedback-stack" aria-live="polite">
      {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={t('states.error')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.error') })} onClose={write.reset} /> : null}
      {brandBindingWrite.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={brandBindingWrite.saving} disabled={!canManage} onClick={brandBindingWrite.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : brandBindingWrite.error ? <FeedbackWhen title={t('states.error')} detail={t(`errors.${brandBindingWrite.error instanceof ApiError ? brandBindingWrite.error.code : 'network_error'}`, { defaultValue: t('states.error') })} onClose={brandBindingWrite.reset} /> : null}
      {brandUploadUncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.assetUploadTitle')} detail={t('uncertainty.assetUploadDescription')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={uploadingSlot !== null} disabled={!canManage} onClick={retryBrandAssetUpload}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : brandAssetError ? <FeedbackWhen type="warning" title={brandAssetError.code.startsWith('brand_asset_') ? t(`errors.${brandAssetError.code}`, { defaultValue: t('states.assetUploadUnavailable') }) : t('states.assetUploadUnavailable')} /> : null}
      {refreshError ? <FeedbackWhen title={t('states.refreshFailed')} detail={t(`errors.${refreshError.code}`, { defaultValue: t('states.error') })}
        action={<Button size="small" disabled={writeInFlight} onClick={() => void load()}>{t('actions.retry')}</Button>} onClose={() => setRefreshError(null)} /> : null}
      {(write.saved || assetSaved || brandBindingWrite.saved) ? <Alert type="success" showIcon message={assetSaved || brandBindingWrite.saved ? t('states.assetUploaded') : t('states.saved')} /> : null}
    </div>
    <SystemSummary items={[
      { target: 'system-info', label: t('v2.summary.name'), value: themeBrandName || draft.system_name || '-',
        tag: themeBrandName ? t('v2.summary.themeOverride') : undefined },
      { target: 'system-maintenance', label: t('fields.maintenance'), value: draft.maintenance ? t('v2.on') : t('v2.off'), tone: draft.maintenance ? 'warning' : 'off' },
      { target: 'system-package', label: t('fields.expiry_close'), value: draft.expiry_close ? t('v2.on') : t('v2.off'), tone: draft.expiry_close ? 'warning' : 'off' },
      { target: 'system-package', label: t('fields.traffic_close'), value: draft.traffic_close ? t('v2.on') : t('v2.off'), tone: draft.traffic_close ? 'warning' : 'off' },
      { target: 'system-maintenance', label: t('fields.auto_upgrade_node'), value: draft.auto_upgrade_node ? t('v2.on') : t('v2.off'), tone: draft.auto_upgrade_node ? 'success' : 'off' },
    ]} label={t('v2.summary.label')} />
    <Form className="system-settings-baseline-form" labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} labelAlign="right" colon={false} style={{ maxWidth: 840, width: '100%' }}>
      <SectionNavigation label={t('innerNavigation.system')} items={navigation} />
      <section id="system-info" className="system-settings-config-card system-settings-system-info sys-setting-section-anchor" aria-labelledby="system-info-title">
      <h2 id="system-info-title" className="system-settings-config-card-title">{t('innerNav.systemInfo')}</h2>
      {themeBrandName ? <Alert className="sys-setting-v2-theme-banner" type="warning" showIcon message={t('v2.themeBanner', { theme: themeName, name: themeBrandName })} /> : null}
      {(['system_name', 'user_title', 'admin_title', 'footer_links', 'footer_text', 'global_js', 'bound_domains'] as const).map((key) => (
        <Fragment key={key}>
        <Form.Item label={t(`fields.${key}`)} {...fieldStatus(key)} extra={key === 'global_js' ? <div className="system-settings-form-warning">{t('hints.globalJS')}</div>
          : themeBrandName && (key === 'system_name' || key === 'user_title' || key === 'admin_title')
            ? <div className="system-settings-form-warning" data-testid={`theme-override-${key}`}>{t('hints.themeOverride', { theme: themeName, name: themeBrandName })}</div>
            : undefined}>
          {key === 'global_js' || key === 'footer_links' ? <Input.TextArea value={draft[key]} disabled={!canManage} placeholder={key === 'global_js' ? t('hints.globalJSPlaceholder') : undefined} onChange={(event) => update(key, event.target.value)} autoSize={key === 'global_js' ? { minRows: 6, maxRows: 10 } : { minRows: 3, maxRows: 5 }} aria-label={t(`fields.${key}`)} /> : text(key, key === 'bound_domains' ? t('placeholders.boundDomains') : undefined)}
        </Form.Item>
        {key === 'global_js' ? <GlobalJSReportHostsField value={draft.global_js_report_hosts} disabled={!canManage}
          serverError={refusedKey === 'global_js_report_hosts' ? fieldStatus('global_js_report_hosts').help : undefined}
          label={t('fields.global_js_report_hosts')} placeholder={t('placeholders.globalJSReportHosts')} help={t('hints.globalJSReportHosts', { max: maxGlobalJSReportHosts })}
          invalid={t('hints.globalJSReportHostsInvalid', { max: maxGlobalJSReportHosts })}
          onChange={(hosts) => update('global_js_report_hosts', hosts)} /> : null}
        </Fragment>
      ))}
      </section>
      <section id="system-brand" className="system-settings-config-card system-settings-system-brand sys-setting-section-anchor" aria-labelledby="system-brand-title">
        <h2 id="system-brand-title" className="system-settings-config-card-title">{t('innerNav.brand')}</h2>
        <div className="system-settings-brand-grid">
          {(['favicon', 'logo', 'login_ad'] as const).map((key) => {
            const labelKey = key === 'login_ad' ? 'loginAd' : key
            return <article key={key} className="system-settings-brand-card">
              <div className="system-settings-brand-head">
                <span className="system-settings-brand-title">{t(`brandAssets.labels.${labelKey}`)}</span>
                <span className="system-settings-brand-meta">{t(`brandAssets.fileTypes.${labelKey}`)}</span>
              </div>
              <div className="system-settings-brand-preview">{assetField(key)}</div>
              <InlineNotice onClose={() => setRejectedBrandSlot(null)}>{rejectedBrandSlot === key ? t('states.assetUploadInvalid') : null}</InlineNotice>
            </article>
          })}
        </div>
      </section>
      <section id="system-package" className="system-settings-config-card sys-setting-section-anchor" aria-labelledby="system-package-title">
      <h2 id="system-package-title" className="system-settings-config-card-title">{t('sections.package')}</h2>
      {/* redesign-a：紧凑开关卡，开启时浅主色底；会关闭网站的两项开启时警示边。 */}
      <div className="sys-setting-v2-toggles">
        {(['expiry_close', 'traffic_close', 'allow_upgrade', 'allow_downgrade'] as const).map((key) => <div key={key}
          className={`sys-setting-v2-toggle${draft[key] ? ' is-on' : ''}${draft[key] && (key === 'expiry_close' || key === 'traffic_close') ? ' is-impact' : ''}`}>
          <span className="sys-setting-v2-toggle-text">
            <span className="sys-setting-v2-toggle-title">{t(`fields.${key}`)}</span>
            <span className="sys-setting-v2-toggle-state">{draft[key] ? t('v2.on') : t('v2.off')}</span>
          </span>
          {toggle(key)}
        </div>)}
      </div>
      <Form.Item className="system-settings-purchase-notice" label={t('fields.purchaseNotice')} {...fieldStatus('purchase_notice')} extra={<div className="system-settings-form-hint">{t('purchaseNoticeHint')}</div>}>
        <Input.TextArea value={String(draft.purchase_notice ?? '')} disabled={!canManage} placeholder={t('placeholders.purchaseNotice')} rows={8} aria-label={t('fields.purchaseNotice')} onChange={(event) => update('purchase_notice', event.target.value)} />
      </Form.Item>
      </section>
      <section id="system-maintenance" className={`system-settings-config-card sys-setting-section-anchor${draft.maintenance ? ' sys-setting-v2-impact' : ''}`} aria-labelledby="system-maintenance-title">
      <h2 id="system-maintenance-title" className="system-settings-config-card-title">{t('sections.maintenance')}</h2>
      <Form.Item label={t('fields.maintenance')} extra={draft.maintenance ? <span className="sys-setting-v2-impact-note">{t('v2.maintenanceOn')}</span> : undefined}>{toggle('maintenance')}</Form.Item>
      <Form.Item label={t('fields.maintenance_message')} {...fieldStatus('maintenance_message')}><Input value={draft.maintenance_message} disabled={!canManage} onChange={(event) => update('maintenance_message', event.target.value)} aria-label={t('fields.maintenance_message')} /></Form.Item>
      <Form.Item label={t('fields.auto_upgrade_node')}>{toggle('auto_upgrade_node')}</Form.Item>
      </section>
      {/* SET-002：后台 HTTPS 入口未接通（保存只存引用，不切换证书），按 10-25 "未接通不显示" 规则整段不渲染；
          certificate/private_key 仍随草稿原样回写，不丢已有引用。接通并能校验证书配对、切换入口后再恢复。 */}
    </Form>
    {/* redesign-a：底部固定自动保存状态条（原"刷新 · 修订版本"并入）；保存中仍由 SaveState 播报。 */}
    <div className={`sys-setting-v2-savebar${dirty ? ' is-dirty' : ''}`}>
      <span>{dirty ? t('v2.pending') : t('v2.allSaved')}</span>
      <Typography.Text type="secondary">{t('metadata.revision')} {document.revision}</Typography.Text>
      <Button icon={<RefreshCw size={14} />} loading={refreshing}
        disabled={writeInFlight || write.uncertain || brandBindingWrite.uncertain || brandUploadUncertain} onClick={refresh}>{t('actions.refresh')}</Button>
    </div>
  </div>
}

type SummaryItem = { target: string; label: string; value: string; tone?: 'warning' | 'success' | 'off'; tag?: string }

// SystemSummary: what is in force now; each item scrolls to its section and focuses the heading.
function SystemSummary({ items, label }: { items: SummaryItem[]; label: string }) {
  const jump = (target: string) => {
    const section = document.getElementById(target)
    section?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    const heading = section?.querySelector('h2')
    if (heading) { heading.setAttribute('tabindex', '-1'); heading.focus({ preventScroll: true }) }
  }
  return <nav className="sys-setting-v2-summary" aria-label={label}>
    <ul>
      {items.map((item) => <li key={item.label}>
        <button type="button" onClick={() => jump(item.target)}>
          <span className="sys-setting-v2-summary-label">{item.label}</span>
          <span className={`sys-setting-v2-summary-value${item.tone ? ` is-${item.tone}` : ''}`}>
            {item.value}{item.tag ? <Tag color="warning">{item.tag}</Tag> : null}</span>
        </button>
      </li>)}
    </ul>
  </nav>
}

export type SystemGlobalSettingsTab = BaselineTab

/** Tab order follows the competitor's /sys/setting (seven tabs, same names). */
const systemGlobalSettingsTabs =['system', 'cleanup', 'account', 'payment', 'mail', 'notification', 'other'] as const satisfies readonly BaselineTab[]

/** One line per tab: what the settings affect and how they are saved (ADMIN-CURRENT-08). */
function TabScope({ tab, onOpenTab }: { tab: BaselineTab; onOpenTab: (tab: BaselineTab) => void }) {
  const { t } = useTranslation('systemGlobalSettings')
  const links: Partial<Record<BaselineTab, BaselineTab[]>> = { mail: ['notification'], notification: ['mail'], payment: ['account'], account: ['payment'] }
  return <Alert className="system-settings-tab-scope" type="info" showIcon data-testid={`system-settings-scope-${tab}`}
    message={<span><strong>{t('scope.range')}</strong>{t(`scope.${tab}.range`)}</span>}
    description={<Space direction="vertical" size={2}>
      <span><strong>{t('scope.save')}</strong>{t(`scope.${tab}.save`)}</span>
      {links[tab] ? <Space size={12}>{links[tab].map((target) => <Typography.Link key={target} onClick={() => onOpenTab(target)}>{t('scope.open', { tab: t(`tabs.${target}`) })}</Typography.Link>)}</Space> : null}
    </Space>}
    style={{ marginBottom: 16, maxWidth: 840 }} />
}

export default function SystemGlobalSettingsPage({
  initialTab = 'system',
}: {
  initialTab?: SystemGlobalSettingsTab
}) {
  const { t } = useTranslation('systemGlobalSettings')
  const [searchParams, setSearchParams] = useSearchParams()
  const urlTab = systemGlobalSettingsTabs.find((item) => item === searchParams.get('tab'))
  const tab: BaselineTab = urlTab ?? initialTab
  // Account and payment edit one shared document; each panel follows the newest revision the other saved.
  const [sharedUserDocument, setSharedUserDocument] = useState<PlatformSystemUserSettingsDocument | null>(null)
  const openTab = useCallback((next: BaselineTab) => {
    setSearchParams((current) => { const params = new URLSearchParams(current); params.set('tab', next); return params }, { replace: true })
  }, [setSearchParams])

  useEffect(() => {
    const previousTitle = document.title
    document.title = t('pageTitle')
    return () => { document.title = previousTitle }
  }, [t])

  const panel = (key: BaselineTab): ReactNode => key === 'system' ? <SystemPanel /> : key === 'cleanup' ? <CleanupPanel />
    : key === 'account' || key === 'payment' ? <UserSettingsPanel mode={key} shared={sharedUserDocument} onShared={setSharedUserDocument} />
      : key === 'notification' ? <Suspense fallback={<div aria-busy="true"><Spin aria-label={t('states.loadingNotification')} /></div>}><NotificationSettingsPage mode="admin" embedded /></Suspense>
        : key === 'mail' ? <MailPanel /> : <OtherPanel />
  return (
    <div className="sys-setting-v2">
    <div data-testid="system-global-settings-page" className="system-settings-baseline-page sys-setting sys-setting-reference-page" style={{ minWidth: 0 }}>
      {/* Visited tabs stay mounted (destroyOnHidden=false) so unsaved drafts survive switching tabs. */}
      <Tabs
        activeKey={tab}
        destroyOnHidden={false}
        onChange={(value) => openTab(value as BaselineTab)}
        items={systemGlobalSettingsTabs.map((key) => ({ key, label: t(`tabs.${key}`), children: <><TabScope tab={key} onOpenTab={openTab} />{panel(key)}</> }))}
      />
    </div>
    </div>
  )
}
