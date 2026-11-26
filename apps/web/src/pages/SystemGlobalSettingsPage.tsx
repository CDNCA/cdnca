import { Fragment, lazy, Suspense, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Alert, App, Button, Checkbox, Collapse, ConfigProvider, Divider, Form, Input, InputNumber, Popconfirm, Radio, Result, Select, Space, Spin, Switch, Tag, Tooltip, Typography, Upload, type InputNumberProps } from 'antd'
import { Tabs } from '../components/Tabs'
import { CircleHelp, Ellipsis, RefreshCw, Save } from 'lucide-react'
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
import { kycIssuerKeys, kycProviderKeys, systemUserSettingsApi, termsPublished, type CaptchaSecretName, type PlatformSystemUserSettings, type PlatformSystemUserSettingsDocument, type UserSettingsSecretName, type UserSettingsSecrets } from '../api/systemUserSettings'
import { accountRegistrationApi, registrationReasons, type AccountRegistrationConfig } from '../api/accountRegistration'
import { RegistrationReadinessReasons } from '../components/RegistrationReadinessReasons'
import { NotificationChannelOffNotice, type NotificationChannel } from '../components/NotificationChannelSwitch'
import { notificationsApi, type NotificationChannelHealth, type NotificationChannels, type NotificationRuntimeHealth } from '../api/notifications'
import { useSessionStore } from '../auth/session'
import { systemSettingsChangedEvent } from '../components/useSystemBranding'
import { resetNavigationGuard, useNavigationGuardStore } from '../routes/navigationGuard'
import { localizedText } from '../api/theme'
import { builtInBrandAsset, useThemeBrandName, useThemeRuntime } from '../theme/runtime'
import MailProviderSection from './system/MailProviderSection'
import { useFeedback, FeedbackWhen, InlineNotice, OutcomeUnknown, fieldReasonText, submitErrorFields } from '@cdnca/ui'
import { ApprovalCenterSettings } from './ApprovalCenterSettings'
import ControlHostBindCard from './system-settings/ControlHostBindCard'
import { VisitorIPSetting, controlOriginAuthSection } from '../components/ControlOriginAuthNotice'
import '../i18n/controlHostBind'

const NotificationSettingsPage = lazy(() => import('./NotificationSettingsPage'))

const captchaTemplatePlaceholder = /\{\{\s*\.?captcha\s*\}\}|\$\{captcha\}/
const sensitiveTemplatePlaceholder = /\{\{\s*\.?password\s*\}\}|\$\{\s*password\s*\}/i

// The notification template fields of 用户注册 (folded
// below the sign-up rules) and the terms fields (folded behind 编辑协议).
const notificationTemplateKeys = ['registration_success_subject', 'registration_success_body', 'password_reset_subject', 'password_reset_body',
  'verification_template_channel', 'verification_subject', 'verification_body', 'verification_sms_body', 'verification_sms_template_id'] as const
const termsKeys = ['terms_title', 'terms_body'] as const

/** The first notification template field the controller would refuse and why (null: none): a password placeholder anywhere, or a verification template without the code. */
function invalidUserNotificationTemplate(value: PlatformSystemUserSettings): { key: keyof PlatformSystemUserSettings; reason: 'passwordPlaceholder' | 'captchaMissing' } | null {
  const templates = ['registration_success_subject', 'registration_success_body', 'password_reset_subject', 'password_reset_body',
    'verification_subject', 'verification_body', 'verification_sms_body'] as const
  const sensitive = templates.find((key) => sensitiveTemplatePlaceholder.test(value[key]))
  if (sensitive) return { key: sensitive, reason: 'passwordPlaceholder' }
  if (!captchaTemplatePlaceholder.test(value.verification_subject + value.verification_body)) return { key: 'verification_body', reason: 'captchaMissing' }
  if (!captchaTemplatePlaceholder.test(value.verification_sms_body)) return { key: 'verification_sms_body', reason: 'captchaMissing' }
  return null
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

// rc-input-number 9.5 hardcodes the step buttons' aria-label ("Increase Value" /
// "Decrease Value"); antd's locale does not reach them and a custom controls icon
// sits inside the labelled span. Name them after the field.
function NumberField(props: InputNumberProps<number>) {
  const { t } = useTranslation('systemGlobalSettings')
  const cls = useContext(ConfigProvider.ConfigContext).getPrefixCls('input-number')
  const ref = useRef<HTMLInputElement & { nativeElement: HTMLDivElement }>(null)
  const name = props['aria-label']
  useEffect(() => {
    const root = ref.current?.nativeElement
    if (!root || !name) return
    root.querySelector(`.${cls}-handler-up`)?.setAttribute('aria-label', t('stepper.increase', { name }))
    root.querySelector(`.${cls}-handler-down`)?.setAttribute('aria-label', t('stepper.decrease', { name }))
  })
  return <InputNumber<number> {...props} ref={ref} />
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

/** how much of the top of the scrolling area the
 * sticky section navigation covers, plus 8px: the scroll-margin-top a section
 * jumped to needs so its title and first control show below it. Scrolling the
 * window, the document's scroll-padding-top already keeps the console's fixed
 * top bar and pinned banners clear (styles.css), so only what the navigation
 * covers beyond that padding is added. */
function sectionScrollOffset(nav: HTMLElement): number {
  const scrollsY = (element: HTMLElement) => /(auto|scroll)/.test(getComputedStyle(element).overflowY) && element.scrollHeight > element.clientHeight
  const clipped = (element: HTMLElement) => { const style = getComputedStyle(element); return !/^(visible|clip)$/.test(style.overflowX) || !/^(visible|clip)$/.test(style.overflowY) }
  let port: HTMLElement | null = nav.parentElement
  while (port && port !== document.body && !scrollsY(port)) port = port.parentElement
  if (port === document.body) port = null
  // a sticky element sticks to its nearest clipping ancestor: in this scrolling area only when that is it
  let sticksTo: HTMLElement | null = nav.parentElement
  while (sticksTo && sticksTo !== document.body && !clipped(sticksTo)) sticksTo = sticksTo.parentElement
  if (sticksTo === document.body) sticksTo = null
  const style = getComputedStyle(nav)
  const stuck = style.position === 'sticky' && sticksTo === port ? (Number.parseFloat(style.top) || 0) + nav.getBoundingClientRect().height : 0
  const padding = port ? 0 : Number.parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0
  return Math.ceil(Math.max(stuck - padding, 0)) + 8
}

function SectionNavigation({ label, items }: { label: string; items: SectionNavigationItem[] }) {
  const [activeId, setActiveId] = useState(items[0]?.id ?? '')
  const itemIds = items.map((item) => item.id).join('|')
  // every section of this page (.sys-setting-section-anchor,
  // .system-settings-config-card) takes --section-scroll-offset as scroll-margin-top;
  // measured on mount, on resize and before each jump
  const nav = useRef<HTMLElement>(null)
  const measure = useCallback(() => {
    const element = nav.current
    element?.parentElement?.style.setProperty('--section-scroll-offset', `${sectionScrollOffset(element)}px`)
  }, [])
  useEffect(() => {
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [measure])
  const jump = (id: string) => {
    setActiveId(id)
    const target = document.getElementById(id)
    if (!target) return
    measure()
    target.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    // Tab goes on from this section: its title takes the focus (not scrolled again)
    const heading = target.querySelector<HTMLElement>('h2') ?? target
    if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1')
    heading.focus({ preventScroll: true })
  }

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

  return <nav ref={nav} className="system-settings-section-nav" aria-label={label}>
    <Space wrap size={[24, 10]}>
      {items.map((item) => <Button key={item.id} type="text" size="small" className={activeId === item.id ? 'is-active' : undefined}
        aria-current={activeId === item.id ? 'page' : undefined}
        onClick={() => jump(item.id)}>{item.label}</Button>)}
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

// The text limits of control-api systemsettings settingsFieldError (characters, as utf8.RuneCountInString).
const systemSettingsTextLimits = [
  ['system_name', 1, 128], ['user_title', 1, 256], ['admin_title', 1, 256], ['footer_links', 0, 16 << 10],
  ['footer_text', 0, 1024], ['global_js', 0, 256 << 10], ['bound_domains', 0, 8192], ['favicon', 0, 2048],
  ['logo', 0, 2048], ['login_ad', 0, 2048], ['purchase_notice', 0, 65536], ['maintenance_message', 0, 1024],
] as const satisfies readonly (readonly [keyof PlatformSystemSettings, number, number])[]

type SystemSettingsTextKey = typeof systemSettingsTextLimits[number][0]

/** the fields the controller would refuse and why (fielderr reasons), same rules as settingsFieldError. */
function systemSettingsFieldErrors(value: PlatformSystemSettings): Partial<Record<SystemSettingsTextKey, string>> {
  const errors: Partial<Record<SystemSettingsTextKey, string>> = {}
  for (const [key, min, max] of systemSettingsTextLimits) {
    const text = String(value[key] ?? '')
    const count = [...text].length
    if (/[\0\r]/.test(text)) errors[key] = 'invalid_format'
    else if (count === 0 && min > 0) errors[key] = 'required'
    else if (count < min) errors[key] = 'too_short'
    else if (count > max) errors[key] = 'too_long'
  }
  return errors
}

function validSystemSettingsAutoSaveDraft(value: PlatformSystemSettings | null): value is PlatformSystemSettings {
  const validReference = (reference: string | undefined) => !reference ||
    (reference.startsWith('vault://') && reference.length > 'vault://'.length) ||
    (reference.startsWith('kms-envelope://') && reference.length > 'kms-envelope://'.length)
  return Boolean(value && Object.keys(systemSettingsFieldErrors(value)).length === 0 &&
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

// KYC service fields: the basic connection, and the object storage /
// evidence issuer kept under 高级集成设置; each falls back to the runtime variable listed under 诊断详情.
const kycBasicKeys = ['kyc_provider_name', 'kyc_endpoint', 'kyc_api_key', 'kyc_callback_key_id', 'kyc_callback_hmac_key'] as const
const kycAdvancedKeys = ['kyc_object_endpoint', 'kyc_object_region', 'kyc_object_bucket', 'kyc_object_prefix', 'kyc_object_kms_key_id',
  'kyc_object_access_key_id', 'kyc_object_secret_access_key', 'kyc_object_session_token', 'kyc_issuer_enabled', ...kycIssuerKeys, 'kyc_issuer_server_private_key'] as const
const kycRuntimeVariables = {
  kyc_provider_name: 'IDENTITY_VERIFICATION_KYC_PROVIDER_NAME', kyc_endpoint: 'IDENTITY_VERIFICATION_KYC_ENDPOINT', kyc_api_key: 'IDENTITY_VERIFICATION_KYC_API_KEY',
  kyc_callback_key_id: 'IDENTITY_VERIFICATION_KYC_CALLBACK_KEY_ID', kyc_callback_hmac_key: 'IDENTITY_VERIFICATION_KYC_CALLBACK_HMAC_BASE64',
  kyc_object_endpoint: 'IDENTITY_VERIFICATION_OBJECT_ENDPOINT', kyc_object_region: 'IDENTITY_VERIFICATION_OBJECT_REGION', kyc_object_bucket: 'IDENTITY_VERIFICATION_OBJECT_BUCKET',
  kyc_object_prefix: 'IDENTITY_VERIFICATION_OBJECT_PREFIX', kyc_object_kms_key_id: 'IDENTITY_VERIFICATION_OBJECT_KMS_KEY_ID',
  kyc_object_access_key_id: 'IDENTITY_VERIFICATION_OBJECT_ACCESS_KEY_ID', kyc_object_secret_access_key: 'IDENTITY_VERIFICATION_OBJECT_SECRET_ACCESS_KEY',
  kyc_object_session_token: 'IDENTITY_VERIFICATION_OBJECT_SESSION_TOKEN', kyc_issuer_enabled: 'IDENTITY_VERIFICATION_ISSUER_ENABLED',
  kyc_issuer_listen_address: 'IDENTITY_VERIFICATION_ISSUER_MTLS_LISTEN_ADDR', kyc_issuer_server_certificate: 'IDENTITY_VERIFICATION_ISSUER_MTLS_SERVER_CERT_FILE',
  kyc_issuer_server_private_key: 'IDENTITY_VERIFICATION_ISSUER_MTLS_SERVER_PRIVATE_KEY_FILE', kyc_issuer_client_ca: 'IDENTITY_VERIFICATION_ISSUER_MTLS_CLIENT_CA_FILE',
  kyc_issuer_workload_identities: 'IDENTITY_VERIFICATION_ISSUER_WORKLOAD_IDENTITIES', kyc_issuer_kms_endpoint: 'IDENTITY_VERIFICATION_ISSUER_KMS_ENDPOINT',
} as const satisfies Record<typeof kycBasicKeys[number] | typeof kycAdvancedKeys[number], string>

type UserSettingsPanelMode = 'account' | 'payment'

function UserSettingsPanel({ mode, active = true, shared = null, onShared }: {
  mode: UserSettingsPanelMode
  /** The panel's tab is shown: the channel switches are read again (they are set on the 通知 tab). */
  active?: boolean
  /** Newest copy of the shared account/payment document saved by the sibling panel. */
  shared?: PlatformSystemUserSettingsDocument | null
  onShared?: (document: PlatformSystemUserSettingsDocument) => void
}) {
  const { t, i18n } = useTranslation('systemGlobalSettings')
  const { t: adminAccessT } = useTranslation('adminAccess')
  const { t: registrationT } = useTranslation('accountRegistration')
  const { message } = App.useApp()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' && (principal.permissions.includes('system_configuration.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = baselineOwnerKey(principal, sessionEpoch)
  const state = mode === 'account'
    ? { loading: t('states.loadingAccount'), error: t('states.errorAccount'), saved: t('states.savedAccount') }
    : { loading: t('states.loadingPayment'), error: t('states.errorPayment'), saved: t('states.savedPayment') }
  const [document, setDocument] = useState<PlatformSystemUserSettingsDocument | null>(null)
  const [draft, setDraft] = useState<PlatformSystemUserSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  // Write-only page secrets (CAPTCHA / enterprise verification); the ref holds
  // what the current attempt sends: undefined keeps, '' clears.
  const [secrets, setSecrets] = useState<UserSettingsSecrets>({})
  const secretsRef = useRef<UserSettingsSecrets>({})
  const [referencesOpen, setReferencesOpen] = useState(false)
  // the terms editor and the notification templates
  // start folded; a field among them refused on save, or invalid before it,
  // opens its area and takes the focus once the opened area is drawn (focusRequest)
  const [termsOpen, setTermsOpen] = useState(false)
  const [templatesOpen, setTemplatesOpen] = useState(false)
  // object storage and evidence issuing start folded
  const [kycAdvancedOpen, setKycAdvancedOpen] = useState(false)
  const [focusRequest, setFocusRequest] = useState<{ key: string } | null>(null)
  // a template refused before the request: its reason under that field, as a controller refusal shows (no dialog)
  const [localRefusal, setLocalRefusal] = useState<{ key: string; text: string } | null>(null)
  const panelRoot = useRef<HTMLDivElement>(null)
  const reveal = useCallback((key: string) => {
    if ((notificationTemplateKeys as readonly string[]).includes(key)) setTemplatesOpen(true)
    else if ((termsKeys as readonly string[]).includes(key)) setTermsOpen(true)
    else return
    setFocusRequest({ key })
  }, [])
  useEffect(() => {
    if (!focusRequest) return
    const { key } = focusRequest
    // a verification template of the channel not shown: its channel option
    const channel = key === 'verification_sms_body' || key === 'verification_sms_template_id' ? 'sms' : key === 'verification_subject' || key === 'verification_body' ? 'email' : ''
    // The opened area may still be drawing or animating (a folded Collapse keeps its content in the DOM, hidden):
    // try on the next frame (at once with reduced motion), again after the panel's transition ends and every 30ms,
    // until the field really holds the focus; one last try at 600ms.
    const started = Date.now()
    let timer = 0
    let frame = 0
    let done = false
    const find = () => {
      const root = panelRoot.current
      return root?.querySelector<HTMLElement>(`[data-setting-field="${key}"]`) ?? (channel ? root?.querySelector<HTMLElement>(`input[type="radio"][value="${channel}"]`) : null)
    }
    const attempt = () => {
      if (done) return
      const target = find()
      if (target && !target.closest('.ant-collapse-content-hidden')) target.focus()
      if (target && window.document.activeElement === target) { done = true; return }
      const left = 600 - (Date.now() - started)
      if (left > 0) timer = window.setTimeout(attempt, Math.min(30, left))
      else if (target) { done = true; target.focus() }
    }
    const onTransitionEnd = () => attempt()
    const root = panelRoot.current
    root?.addEventListener('transitionend', onTransitionEnd)
    root?.addEventListener('animationend', onTransitionEnd)
    const reduced = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduced || typeof window.requestAnimationFrame !== 'function') attempt()
    else frame = window.requestAnimationFrame(attempt)
    return () => {
      done = true
      window.clearTimeout(timer)
      if (frame) window.cancelAnimationFrame(frame)
      root?.removeEventListener('transitionend', onTransitionEnd)
      root?.removeEventListener('animationend', onTransitionEnd)
    }
  }, [focusRequest])
  // what the sign-up page sees, with the administrator's reasons
  const [readiness, setReadiness] = useState<AccountRegistrationConfig | null>(null)
  const loadReadiness = useCallback(async () => {
    const token = currentBaselineAccess(ownerKey)
    if (mode !== 'account' || !token || !canRead) return null
    const value = await accountRegistrationApi.registrationConfig(undefined, token)
    if (currentBaselineAccess(ownerKey)) setReadiness(value)
    return value
  }, [canRead, mode, ownerKey])
  useEffect(() => { void loadReadiness() }, [loadReadiness, sessionEpoch])
  // The notification channel switches: a verification or code login is in
  // effect only while its channel is on (systemusersettings.GetPublicTx).
  // 读取失败清掉旧状态（不再显示过时提示），只采用最新一次请求的结果。
  const [channels, setChannels] = useState<NotificationChannels | null>(null)
  const channelRequest = useRef(0)
  const loadChannels = useCallback(async () => {
    const token = currentBaselineAccess(ownerKey)
    if (mode !== 'account' || !token || !canRead) return
    const request = ++channelRequest.current
    const value = await notificationsApi.getChannels(token).catch(() => null)
    if (request === channelRequest.current && currentBaselineAccess(ownerKey)) setChannels(value)
  }, [canRead, mode, ownerKey])
  useEffect(() => { if (active) void loadChannels() }, [active, loadChannels, sessionEpoch])

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
    submit: (token, attempt) => systemUserSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey, secretsRef.current),
    onSuccess: (next) => {
      secretsRef.current = {}; setSecrets({}); setDocument(next); setDraft(next.value); onShared?.(next); message.success(state.saved)
      void loadChannels()
      // A verification is in effect only while its setting and its notification
      // channel switch are both on (config.*.required is the effective
      // value). Ticked but not in effect: sign-up goes on without a code. In effect
      // but not sendable: the sign-up page says it is not set up.
      void loadReadiness().then((config) => {
        if (!config || config.mode === 'closed') return
        const pick = (email: boolean, sms: boolean) => email && sms ? 'both' : email ? 'email' : sms ? 'sms' : null
        const pending = pick(next.value.email_verification_required && !config.email.required, next.value.phone_verification_required && !config.sms.required)
        if (pending) message.info(registrationT(`readiness.saveNotInEffect.${pending}`), 8)
        const missing = pick(config.email.required && !config.email.available, config.sms.required && !config.sms.available)
        if (missing) message.warning(registrationT('readiness.saveWarning', { channels: registrationT(`readiness.channels.${missing}`) }), 8)
      })
    },
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
  useEffect(() => {
    const { shown, key } = refusedFieldStatus(write.error, [...notificationTemplateKeys, ...termsKeys], undefined)
    if (shown && key) reveal(key)
  }, [reveal, write.error])
  const refresh = () => { write.reset(); void load() }

  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={state.loading} /><Form labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} style={{ maxWidth: 520, opacity: 0.55 }}>{(['session_ttl_seconds', 'user_login_domains', 'admin_login_domains'] as const).map((key) => <Form.Item key={key} label={t(`userFields.${key}`)}><Input disabled /></Form.Item>)}</Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : state.error} subTitle={t(`errors.${error.code}`, { defaultValue: state.error })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null

  const update = <K extends keyof PlatformSystemUserSettings>(key: K, value: PlatformSystemUserSettings[K]) => {
    setDraft((current) => current ? { ...current, [key]: value } : current)
    setLocalRefusal((current) => current?.key === key ? null : current)
  }
  const captchaSecrets = ['captcha_secret_id', 'captcha_secret_key', 'captcha_app_secret'] as const
  const kycSecrets = ['kyc_api_key', 'kyc_callback_hmac_key', 'kyc_object_access_key_id', 'kyc_object_secret_access_key', 'kyc_object_session_token', 'kyc_issuer_server_private_key'] as const
  const accountSecrets = [...captchaSecrets, 'captcha_turnstile_secret'] as const
  const shownSecrets: readonly UserSettingsSecretName[] = mode === 'account' ? accountSecrets : kycSecrets
  // clear: the saved secret to clear in this save (the "clear" button).
  const save = (clear?: UserSettingsSecretName) => {
    if (!draft) return
    const invalidTemplate = mode === 'account' ? invalidUserNotificationTemplate(draft) : null
    if (invalidTemplate) {
      // 补充：只写当前渠道的占位符，且是可直接复制的 ASCII 写法（插值传入，不经语言资源转写）。
      const text = invalidTemplate.reason === 'captchaMissing'
        ? t('errors.template_captchaMissing', { token: invalidTemplate.key === 'verification_sms_body' ? '${captcha}' : '{{captcha}}' })
        : t(`errors.template_${invalidTemplate.reason}`)
      setLocalRefusal({ key: invalidTemplate.key, text }); reveal(invalidTemplate.key); return
    }
    setLocalRefusal(null)
    secretsRef.current = Object.fromEntries(shownSecrets.map((name) => [name, name === clear ? '' : secrets[name] || undefined]))
    // Saving the identity tab makes its identity policy authoritative.
    write.save(mode === 'account' ? draft : { ...draft, identity_policy_saved: true })
  }
  const writeErrorCode = write.error instanceof ApiError ? write.error.code : 'network_error'
  // Keys shown in this mode; a refusal of a key shown here goes under it (fix-fielderr-be2).
  const accountKeys = ['session_ttl_seconds', 'user_login_domains', 'admin_login_domains', 'registration_success_subject', 'registration_success_body',
    'password_reset_subject', 'password_reset_body', 'verification_template_channel', 'verification_subject', 'verification_body', 'verification_sms_body',
    'verification_sms_template_id', 'terms_title', 'terms_body', 'email_verification_required', 'phone_verification_required', 'default_phone_country_code',
    'login_failure_limit_per_hour', 'login_captcha_threshold_per_hour', 'email_anti_abuse_mode', 'sms_anti_abuse_mode', 'captcha_provider',
    'captcha_secret_id_reference', 'captcha_secret_key_reference', 'captcha_app_id', 'captcha_app_secret_reference', 'captcha_turnstile_site_key', ...accountSecrets]
  const paymentKeys = ['identity_verification_method', ...kycProviderKeys, 'kyc_issuer_enabled', ...kycIssuerKeys, ...kycSecrets]
  const { status: refusedStatus, shown: refusedShown, key: refusedKey } = refusedFieldStatus(write.error,
    [...(mode === 'payment' ? [] : accountKeys), ...(mode === 'account' ? [] : paymentKeys)], i18n.resolvedLanguage)
  // turning a verification on without its sender is refused: say what is missing
  const fieldStatus = (...keys: string[]) => {
    if (localRefusal && keys.includes(localRefusal.key)) return { validateStatus: 'error' as const, help: localRefusal.text }
    const status = refusedStatus(...keys)
    return writeErrorCode === 'system_user_settings_verification_sender_unavailable' && 'help' in status
      ? { ...status, help: t(`errors.verification_sender_unavailable_${keys.includes('phone_verification_required') ? 'sms' : 'email'}`) }
      : status
  }
  const writeErrorKey = writeErrorCode === 'system_user_settings_revision_conflict'
    ? mode === 'account' ? 'errors.system_account_settings_revision_conflict' : 'errors.system_payment_settings_revision_conflict'
    : `errors.${writeErrorCode}`
  const formProps = { className: 'system-settings-baseline-form', labelCol: { flex: '170px' }, wrapperCol: { flex: '330px' }, labelAlign: 'right' as const, colon: false, style: { maxWidth: 840 } }
  const section = (key: string, children: ReactNode) => <section className="system-settings-config-card" id={`${mode}-${key}`} aria-labelledby={`${mode}-${key}-title`}><h2 id={`${mode}-${key}-title`}>{t(`userSections.${key}`)}</h2>{children}</section>
  const toggle = (key: keyof PlatformSystemUserSettings) => <Switch checked={Boolean(draft[key])} disabled={!canManage} onChange={(value) => update(key, value as never)} aria-label={t(`userFields.${key}`)} />
  const text = (key: keyof PlatformSystemUserSettings, placeholder?: string) => <Input value={String(draft[key])} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`userFields.${key}`)} />
  const busy = !canManage || write.uncertain || write.saving
  // multiline: a PEM secret (line breaks kept, CR dropped, trimmed on blur)
  const secretField = (name: UserSettingsSecretName, hint?: string, multiline?: boolean) => {
    const configured = Boolean(document[`${name}_configured`])
    return <Form.Item key={name} label={t(`userFields.${name}`)} {...fieldStatus(name)}
      extra={<><div>{configured ? t('secretField.set', { fingerprint: document[`${name}_fingerprint`] }) : t('secretField.unset')}</div>{hint ? <div>{hint}</div> : null}</>}>
      <Space.Compact style={{ width: '100%' }}>
        {multiline ? <Input.TextArea value={secrets[name] ?? ''} disabled={!canManage} autoComplete="off" spellCheck={false} rows={4} placeholder={configured ? t('secretField.keep') : ''}
          onChange={(event) => setSecrets((current) => ({ ...current, [name]: event.target.value.replace(/\r\n?/g, '\n') }))}
          onBlur={(event) => setSecrets((current) => ({ ...current, [name]: event.target.value.trim() }))} aria-label={t(`userFields.${name}`)} />
        : <Input.Password value={secrets[name] ?? ''} disabled={!canManage} autoComplete="new-password" placeholder={configured ? t('secretField.keep') : ''}
          onChange={(event) => setSecrets((current) => ({ ...current, [name]: event.target.value }))} aria-label={t(`userFields.${name}`)} />}
        {configured ? <Popconfirm title={t('secretField.clearConfirm', { name: t(`userFields.${name}`) })} disabled={busy} onConfirm={() => save(name)}>
          <Button disabled={busy}>{t('secretField.clear')}</Button>
        </Popconfirm> : null}
      </Space.Compact>
    </Form.Item>
  }
  // The *_reference fields stay as an advanced option, shown once opened or in use.
  const referenceFields = (names: readonly CaptchaSecretName[]) => referencesOpen || names.some((name) => draft[`${name}_reference`] !== '')
    ? <>{names.map((name) => <Form.Item key={`${name}_reference`} label={t(`userFields.${name}_reference`)} {...fieldStatus(`${name}_reference`)}>{text(`${name}_reference`, t('placeholders.secretReference'))}</Form.Item>)}
      <Form.Item label=" "><Typography.Text type="secondary">{t('secretField.referencesHint')}</Typography.Text></Form.Item></>
    : <Form.Item label=" "><Button type="link" style={{ padding: 0 }} onClick={() => setReferencesOpen(true)}>{t('smtpPassword.advanced')}</Button></Form.Item>
  // nb-kyc: the KYC service and its object store; an empty field falls back to the runtime environment (listed under 诊断详情).
  const kycHint = (key: string) => i18n.exists(`kycHints.${key}`, { ns: 'systemGlobalSettings' }) ? t(`kycHints.${key}`) : undefined
  const kycText = (key: typeof kycProviderKeys[number], placeholder?: string) => <Form.Item key={key} label={t(`userFields.${key}`)} {...fieldStatus(key)} extra={kycHint(key)}>
    <Input value={draft[key]} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value.trim())} aria-label={t(`userFields.${key}`)}
      // the server takes an origin: drop a trailing slash
      onBlur={key === 'kyc_endpoint' || key === 'kyc_object_endpoint' ? (event) => update(key, event.target.value.trim().replace(/\/+$/, '')) : undefined} />
  </Form.Item>
  // nb-kycissuer: the evidence issuer; the certificates are PEM text, the workload identities one per line.
  const kycIssuerText = (key: 'kyc_issuer_listen_address' | 'kyc_issuer_kms_endpoint', placeholder?: string) => <Form.Item key={key} label={t(`userFields.${key}`)} {...fieldStatus(key)} extra={kycHint(key)}>
    <Input value={draft[key]} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value.trim())} aria-label={t(`userFields.${key}`)}
      onBlur={key === 'kyc_issuer_kms_endpoint' ? (event) => update(key, event.target.value.trim().replace(/\/+$/, '')) : undefined} />
  </Form.Item>
  const kycIssuerPEM = (key: 'kyc_issuer_server_certificate' | 'kyc_issuer_client_ca') => <Form.Item key={key} label={t(`userFields.${key}`)} {...fieldStatus(key)} extra={kycHint(key)}>
    <Input.TextArea value={draft[key]} disabled={!canManage} rows={4} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" aria-label={t(`userFields.${key}`)}
      onChange={(event) => update(key, event.target.value.replace(/\r\n?/g, '\n'))} onBlur={(event) => update(key, event.target.value.trim())} />
  </Form.Item>
  const kycComplete = (['kyc_provider_name', 'kyc_endpoint', 'kyc_callback_key_id', 'kyc_object_endpoint', 'kyc_object_region', 'kyc_object_bucket', 'kyc_object_kms_key_id'] as const)
    .every((key) => draft[key] !== '') &&
    (['kyc_api_key', 'kyc_callback_hmac_key', 'kyc_object_access_key_id', 'kyc_object_secret_access_key'] as const).every((name) => document[`${name}_configured`] || Boolean(secrets[name]))
  // a template or terms field is its own labelled row
  // (no read-only 标题 prefix); data-setting-field: what reveal() focuses
  // 字段错误：help 带 id，输入框 aria-invalid 并 aria-describedby 到这一行，修正后随 fieldStatus 一起清掉。
  const rowStatus = (key: string) => {
    const status = fieldStatus(key)
    if (!('help' in status) || !status.help) return { item: status, input: {} }
    const id = `${mode}-${key}-help`
    return { item: { ...status, help: <span id={id}>{status.help}</span> }, input: { 'aria-invalid': true, 'aria-describedby': id } }
  }
  const textRow = (key: keyof PlatformSystemUserSettings) => { const st = rowStatus(key); return <Form.Item key={key} label={t(`userFields.${key}`)} htmlFor={`${mode}-${key}`} {...st.item}>
    <Input id={`${mode}-${key}`} data-setting-field={key} value={String(draft[key])} disabled={!canManage} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`userFields.${key}`)} {...st.input} />
  </Form.Item> }
  const bodyRow = (key: keyof PlatformSystemUserSettings, options: { rows?: number; extra?: ReactNode; placeholder?: string } = {}) => { const st = rowStatus(key); return <Form.Item key={key} label={t(`userFields.${key}`)} htmlFor={`${mode}-${key}`} extra={options.extra} {...st.item}>
    <Input.TextArea id={`${mode}-${key}`} data-setting-field={key} value={String(draft[key])} disabled={!canManage} rows={options.rows ?? 4} placeholder={options.placeholder}
      onChange={(event) => update(key, event.target.value as never)} aria-label={t(`userFields.${key}`)} {...st.input} />
  </Form.Item> }
  const templateGroup = (key: string, title: string, rows: ReactNode) => <div key={key} role="group" aria-labelledby={`${mode}-${key}-group`} className="system-settings-template-group">
    <h3 id={`${mode}-${key}-group`} className="system-settings-template-title">{title}</h3>{rows}
  </div>
  const published = termsPublished(document.value)
  // A setting that is on while its notification channel switch is off: the
  // reason (aria-describedby target) and a link to the 通知 tab. Unknown switches: nothing.
  const channelOff = (key: keyof PlatformSystemUserSettings, channel: NotificationChannel) => {
    if (!draft[key] || !channels || (channel === 'sms' ? channels.sms_enabled : channels.email_enabled)) return { describedBy: undefined, note: null }
    const id = `${mode}-${key}-channel-off`
    return { describedBy: id, note: <Typography.Text type="warning" data-testid={id}><span id={id}>{t(`channelOff.${channel}`)}</span> <Link to="/sys/setting?tab=notification">{t('channelOff.open')}</Link></Typography.Text> }
  }
  const codeLoginToggle = (key: 'email_code_login_enabled' | 'sms_code_login_enabled', channel: NotificationChannel) => {
    const off = channelOff(key, channel)
    return <Space wrap><Switch checked={draft[key]} disabled={!canManage} onChange={(value) => update(key, value)} aria-label={t(`userFields.${key}`)} aria-describedby={off.describedBy} />{off.note}</Space>
  }
  const requirement = (key: keyof PlatformSystemUserSettings, verification?: keyof PlatformSystemUserSettings, channel?: NotificationChannel) => { const field = t(`userFields.${key}`); const off = verification && channel ? channelOff(verification, channel) : { describedBy: undefined, note: null }; return <Space wrap role="group" aria-label={field}><Checkbox checked={Boolean(draft[key])} disabled={!canManage} aria-label={`${field} ${t('options.required')}`} onChange={(event) => { update(key, event.target.checked as never); if (!event.target.checked && verification) update(verification, false as never) }}>{t('options.required')}</Checkbox>{verification ? <Checkbox checked={Boolean(draft[verification])} disabled={!canManage || !draft[key]} aria-label={`${field} ${t('options.verified')}`} aria-describedby={off.describedBy} onChange={(event) => update(verification, event.target.checked as never)}>{t('options.verified')}</Checkbox> : null}{off.note}</Space> }
  // The KYC service is used by personal (a method chosen) and enterprise verification; a refusal of one of its fields shows it too.
  const refusedKyc = refusedShown && refusedKey ? refusedKey : ''
  const kycAdvancedShown = kycAdvancedOpen || (kycAdvancedKeys as readonly string[]).includes(refusedKyc)
  const kycShown = draft.identity_verification_method !== 'none' || draft.enterprise_verification_enabled || kycAdvancedShown ||
    (kycBasicKeys as readonly string[]).includes(refusedKyc)
  const navigation = mode === 'account'
    ? [{ id: 'account-login', label: t('userSections.login') }, { id: 'account-registration', label: t('userSections.registration') }, { id: 'account-security', label: t('userSections.security') }, { id: 'account-captcha', label: t('userSections.captcha') }]
    : [{ id: 'payment-identity', label: t('userSections.identity') }, { id: 'payment-enterprise', label: t('userSections.enterprise') }, ...(kycShown ? [{ id: 'payment-service', label: t('userSections.service') }] : [])]

  return <div ref={panelRoot} data-testid={`system-settings-baseline-${mode}`} style={{ minWidth: 0 }}>
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={state.error} detail={t(writeErrorKey, { defaultValue: state.error })} onClose={() => write.reset()} /> : null}
    <SectionNavigation label={t(`innerNavigation.${mode}`)} items={navigation} />
    <Form {...formProps}>
      {mode === 'account' ? <>
      {section('login', <>
        <Form.Item label={t('userFields.session_ttl_seconds')} {...fieldStatus('session_ttl_seconds')} extra={t('hints.sessionTtl')}><Space.Compact block><NumberField min={300} max={31536000} value={draft.session_ttl_seconds} disabled={!canManage} onChange={(value) => update('session_ttl_seconds', value ?? 300)} style={{ width: '100%' }} aria-label={t('userFields.session_ttl_seconds')} /><Input value={t('units.seconds')} readOnly tabIndex={-1} aria-hidden style={{ width: 48, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>
        <Form.Item label={t('userFields.user_login_domains')} {...fieldStatus('user_login_domains')}>{text('user_login_domains', t('placeholders.userLoginDomains'))}</Form.Item>
        <Form.Item label={t('userFields.admin_login_domains')} {...fieldStatus('admin_login_domains')}>{text('admin_login_domains', t('placeholders.adminLoginDomains'))}</Form.Item>
        <Form.Item label={t('userFields.email_code_login_enabled')}>{codeLoginToggle('email_code_login_enabled', 'email')}</Form.Item>
        <Form.Item label={t('userFields.sms_code_login_enabled')}>{codeLoginToggle('sms_code_login_enabled', 'sms')}</Form.Item>
      </>)}
      {section('registration', <>
        {readiness && !readiness.ready && readiness.mode !== 'closed' ? <RegistrationReadinessReasons title={registrationT('readiness.settingsTitle')} reasons={registrationReasons(readiness)} className="system-settings-registration-readiness" /> : null}
        <Form.Item label={t('userFields.registration_enabled')}>{toggle('registration_enabled')}</Form.Item>
        <Form.Item label={t('userFields.username_required')}>{requirement('username_required')}</Form.Item>
        <Form.Item label={t('userFields.email_required')} {...fieldStatus('email_verification_required')}>{requirement('email_required', 'email_verification_required', 'email')}</Form.Item>
        <Form.Item label={t('userFields.phone_required')} {...fieldStatus('phone_verification_required')}>{requirement('phone_required', 'phone_verification_required', 'sms')}</Form.Item>
        <Form.Item label={t('userFields.default_phone_country_code')} {...fieldStatus('default_phone_country_code')} extra={t('hints.defaultPhoneCountryCode')}><Input addonBefore="+" maxLength={4} inputMode="numeric" value={draft.default_phone_country_code} disabled={!canManage} onChange={(event) => update('default_phone_country_code', event.target.value.replace(/\D/g, '').slice(0, 4))} aria-label={t('userFields.default_phone_country_code')} style={{ width: 160 }} /></Form.Item>
        <Form.Item label={t('userFields.qq_required')}>{requirement('qq_required')}</Form.Item>
        {/* the terms show their published state; the editor opens on demand */}
        <Form.Item label={t('userFields.terms')}>
          <Space wrap>
            <Tag color={published ? 'success' : 'default'} data-testid={`${mode}-terms-state`}>{t(published ? 'registrationLayout.termsPublished' : 'registrationLayout.termsUnpublished')}</Tag>
            <Button size="small" aria-expanded={termsOpen} aria-controls={termsOpen ? `${mode}-terms-editor` : undefined} onClick={() => setTermsOpen((open) => !open)}>{t(termsOpen ? 'registrationLayout.hideTerms' : 'registrationLayout.editTerms')}</Button>
          </Space>
        </Form.Item>
        {termsOpen ? <div id={`${mode}-terms-editor`}>
          {textRow('terms_title')}
          {bodyRow('terms_body', { rows: 6, placeholder: t('registrationLayout.termsBodyPlaceholder'), extra: published ? undefined : t('registrationLayout.termsUnpublishedHint') })}
        </div> : null}
        <Collapse className="system-settings-template-collapse" activeKey={templatesOpen ? ['templates'] : []}
          onChange={(keys) => setTemplatesOpen((Array.isArray(keys) ? keys : [keys]).includes('templates'))}
          items={[{ key: 'templates', label: t('registrationLayout.templates'), children: <>
            {templateGroup('registration-success', t('userFields.registration_success_template'), <>{textRow('registration_success_subject')}{bodyRow('registration_success_body')}</>)}
            {templateGroup('password-reset', t('userFields.password_reset_template'), <>{textRow('password_reset_subject')}{bodyRow('password_reset_body')}</>)}
            {templateGroup('verification', t('userFields.verification_template'), <>
              <Form.Item label={t('userFields.verification_template_channel')} {...fieldStatus('verification_template_channel')}><Radio.Group value={draft.verification_template_channel} disabled={!canManage} onChange={(event) => update('verification_template_channel', event.target.value)}><Radio value="email">{t('options.emailTemplate')}</Radio><Radio value="sms">{t('options.smsTemplate')}</Radio></Radio.Group></Form.Item>
              {draft.verification_template_channel === 'email'
                ? <>{textRow('verification_subject')}{bodyRow('verification_body')}</>
                : <>{bodyRow('verification_sms_body', { rows: 3, extra: t('hints.smsTemplate') })}{textRow('verification_sms_template_id')}</>}
            </>)}
          </> }]} />
      </>)}
      {section('security', <>
        <Form.Item label=" "><Link to="/sys/admin-access">{adminAccessT('title')}</Link></Form.Item>
        <Form.Item label={t('userFields.login_failure_limit_per_hour')} {...fieldStatus('login_failure_limit_per_hour')} extra={t('hints.loginFailure')}><Space.Compact block><NumberField min={1} max={1000} value={draft.login_failure_limit_per_hour} disabled={!canManage} onChange={(value) => update('login_failure_limit_per_hour', value ?? 1)} style={{ width: '100%' }} aria-label={t('userFields.login_failure_limit_per_hour')} /><Input value={t('units.perHour')} readOnly tabIndex={-1} aria-hidden style={{ width: 80, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>
        <Form.Item label={t('userFields.login_captcha_threshold_per_hour')} {...fieldStatus('login_captcha_threshold_per_hour')} extra={t('hints.loginCaptcha')}><Space.Compact block><NumberField min={1} max={draft.login_failure_limit_per_hour} value={draft.login_captcha_threshold_per_hour} disabled={!canManage} onChange={(value) => update('login_captcha_threshold_per_hour', value ?? 1)} style={{ width: '100%' }} aria-label={t('userFields.login_captcha_threshold_per_hour')} /><Input value={t('units.perHour')} readOnly tabIndex={-1} aria-hidden style={{ width: 80, textAlign: 'center', pointerEvents: 'none' }} /></Space.Compact></Form.Item>
        <Form.Item label={t('userFields.session_region_check')} extra={t('hints.sessionRegion')}>{toggle('session_region_check')}</Form.Item>
        {(['email_anti_abuse_mode', 'sms_anti_abuse_mode'] as const).map((key) => <Form.Item key={key} label={t(`userFields.${key}`)} htmlFor={`${mode}-${key}`} {...fieldStatus(key)}><Select id={`${mode}-${key}`} value={draft[key]} disabled={!canManage} onChange={(value) => update(key, value)} options={(['none', 'native', 'tencent', 'geetest_v4'] as const).map((value) => ({ value, label: t(`antiAbuse.${value}`) }))} /></Form.Item>)}
      </>)}
      {section('captcha', <>
        <Form.Item label={<span id={`${mode}-captcha_provider-label`}>{t('userFields.captcha_provider')}</span>} {...fieldStatus('captcha_provider')}><div role="radiogroup" aria-labelledby={`${mode}-captcha_provider-label`}><Radio.Group value={draft.captcha_provider} disabled={!canManage} onChange={(event) => update('captcha_provider', event.target.value)}><Radio value="tencent">{t('options.tencent')}</Radio><Radio value="geetest_v4">{t('options.geetest')}</Radio></Radio.Group></div></Form.Item>
        {secretField('captcha_secret_id')}
        {secretField('captcha_secret_key')}
        <Form.Item label={t('userFields.captcha_app_id')} {...fieldStatus('captcha_app_id')}>{text('captcha_app_id')}</Form.Item>
        {secretField('captcha_app_secret')}
        {referenceFields(captchaSecrets)}
        <Form.Item label=" "><Typography.Text type="danger">{t('hints.captcha')}</Typography.Text></Form.Item>
        <Form.Item label={t('turnstile.siteKey')} {...fieldStatus('captcha_turnstile_site_key')} extra={t('turnstile.hint')}>{text('captcha_turnstile_site_key')}</Form.Item>
        {secretField('captcha_turnstile_secret')}
      </>)}
      </> : null}
      {mode === 'payment' ? <>
      {section('identity', <>
        {draft.identity_policy_saved ? null : <Alert type="info" showIcon message={t('hints.identityPolicyUnsaved')} style={{ marginBottom: 16, maxWidth: 760 }} />}
        <Form.Item label={t('userFields.identity_verification_method')} {...fieldStatus('identity_verification_method')}><Radio.Group data-testid="system-settings-identity-method" aria-label={t('hints.identityMethodLabel')} value={draft.identity_verification_method} disabled={!canManage} onChange={(event) => update('identity_verification_method', event.target.value)}><Space wrap><Radio value="none">{t('options.identityNone')}</Radio><Radio value="alipay">{t('options.alipayIdentity')}</Radio><Radio value="wechat_face">{t('options.wechatFace')}</Radio><Radio value="phone_three_factor">{t('options.phoneThreeFactor')}</Radio></Space></Radio.Group></Form.Item>
      </>)}
      {section('enterprise', <>
        <Form.Item label={t('userFields.enterprise_verification_enabled')} extra={t('hints.enterpriseEnabled')}>{toggle('enterprise_verification_enabled')}</Form.Item>
      </>)}
      {/* the service connection only once personal or enterprise verification uses it;
          object storage and evidence issuing folded under 高级集成设置, the runtime variables under 诊断详情. */}
      {kycShown ? section('service', <>
        <Form.Item label={t('kycGroups.status')}>{kycComplete ? <Tag color="success">{t('kycGroups.complete')}</Tag> : <Tag>{t('kycGroups.fallback')}</Tag>}</Form.Item>
        {kycText('kyc_provider_name', 'trusted-kyc')}
        {kycText('kyc_endpoint', 'https://kyc.example.com')}
        {secretField('kyc_api_key', t('hints.kycCredentials'))}
        {kycText('kyc_callback_key_id')}
        {secretField('kyc_callback_hmac_key', t('hints.kycCallbackKey'))}
        <div data-testid={`${mode}-kyc-advanced`}><Collapse className="system-settings-template-collapse" activeKey={kycAdvancedShown ? ['advanced'] : []}
          onChange={(keys) => setKycAdvancedOpen((Array.isArray(keys) ? keys : [keys]).includes('advanced'))}
          items={[{ key: 'advanced', label: t('kycGroups.advanced'), children: <>
            <Form.Item label=" "><Typography.Text strong>{t('kycGroups.objects')}</Typography.Text><div><Typography.Text type="secondary">{t('kycGroups.objectsHint')}</Typography.Text></div></Form.Item>
            {kycText('kyc_object_endpoint', 'https://s3.example.com')}
            {kycText('kyc_object_region', 'us-east-1')}
            {kycText('kyc_object_bucket')}
            {kycText('kyc_object_prefix')}
            {secretField('kyc_object_access_key_id')}
            {secretField('kyc_object_secret_access_key')}
            {secretField('kyc_object_session_token', kycHint('kyc_object_session_token'))}
            {kycText('kyc_object_kms_key_id')}
            <Form.Item label=" "><Typography.Text strong>{t('kycGroups.issuer')}</Typography.Text><div><Typography.Text type="secondary">{t('kycGroups.issuerHint')}</Typography.Text></div></Form.Item>
            <Form.Item label={t('userFields.kyc_issuer_enabled')}>{toggle('kyc_issuer_enabled')}</Form.Item>
            {kycIssuerText('kyc_issuer_listen_address', '0.0.0.0:19443')}
            {kycIssuerPEM('kyc_issuer_server_certificate')}
            {secretField('kyc_issuer_server_private_key', kycHint('kyc_issuer_server_private_key'), true)}
            {kycIssuerPEM('kyc_issuer_client_ca')}
            <Form.Item label={t('userFields.kyc_issuer_workload_identities')} {...fieldStatus('kyc_issuer_workload_identities')} extra={kycHint('kyc_issuer_workload_identities')}>
              <Input.TextArea value={draft.kyc_issuer_workload_identities.split(',').join('\n')} disabled={!canManage} rows={3} spellCheck={false}
                placeholder="spiffe://control.example/workload/kyc|kyc-issuer" aria-label={t('userFields.kyc_issuer_workload_identities')}
                onChange={(event) => update('kyc_issuer_workload_identities', event.target.value.replace(/\r/g, '').split('\n').map((line) => line.trim()).join(','))}
                onBlur={(event) => update('kyc_issuer_workload_identities', event.target.value.split('\n').map((line) => line.trim()).filter(Boolean).join(','))} />
            </Form.Item>
            {kycIssuerText('kyc_issuer_kms_endpoint', 'https://kms.us-east-1.amazonaws.com')}
          </> }]} /></div>
        <div data-testid={`${mode}-kyc-diagnostics`}><Collapse ghost className="system-settings-kyc-diagnostics" items={[{ key: 'diagnostics', label: t('kycDiagnostics.title'), children: <>
          <Typography.Paragraph type="secondary">{t('kycDiagnostics.fallback')}</Typography.Paragraph>
          <ul className="system-settings-kyc-variables">{Object.entries(kycRuntimeVariables).map(([key, variable]) => <li key={key}>{t('kycDiagnostics.item', { name: t(`userFields.${key}`), variable })}</li>)}</ul>
        </> }]} /></div>
      </>) : null}
      </> : null}
      {mode === 'payment' ? <Form.Item label=" "><Space wrap><Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" onClick={() => save()}>{t('actions.saveRecharge')}</Button></Space></Form.Item> : null}
    </Form>
    {mode === 'account' ? <><Divider /><Space wrap><Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button><Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" icon={<Save size={14} />} onClick={() => save()}>{t('actions.save')}</Button></Space></> : null}
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
    <NumberField min={0} max={max} value={draft[key]} disabled={!canManage} onChange={(value) => update(key, value ?? 0)} aria-label={t(`fields.${key}`)} style={{ width: '100%' }} />
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
          <NumberField min={0} max={3650} value={draft.audit_retention_days[category]} disabled={!canManage} aria-label={logCenterText(`categories.${category}`)} style={{ width: '100%' }}
            onChange={(value) => update('audit_retention_days', { ...draft.audit_retention_days, [category]: value ?? 0 })} />
          <Input value={t('units.days')} readOnly tabIndex={-1} aria-hidden style={{ width: 42, textAlign: 'center', pointerEvents: 'none' }} />
        </Space.Compact></Form.Item>)}
      </Form>
    </section>
    <section className="system-settings-config-card" aria-labelledby="system-settings-backup-title">
      <h2 id="system-settings-backup-title">{t('sections.backup')}</h2>
      <Typography.Paragraph type="secondary" data-testid="system-settings-backup-moved">{t('sections.backupMoved')} <Link to="/sys/op?tab=maintenance">{t('sections.backupMovedLink')}</Link>{t('sections.backupMovedSuffix')}</Typography.Paragraph>
    </section>
    <Divider /><Space wrap><Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button><Button disabled={!canManage || write.uncertain} loading={write.saving} type="primary" icon={<Save size={14} />} onClick={save}>{t('actions.save')}</Button></Space>
    {write.saved ? <Alert type="success" showIcon message={t('states.saved')} style={{ marginTop: 12 }} /> : null}
  </div>
}

/**
 * whether the HTTPS SMS gateway endpoints are deployed, from the
 * runtime health (null: not known). The environment SMS provider is read in
 * the explicit mode only; there, an SMS transport while the saved provider is
 * inherit or https_json can only be the https_json gateway (an environment
 * aliyun/submail needs the credential saved with that provider).
 */
function smsGatewayDeployed(health: NotificationRuntimeHealth | null, savedProvider: string): boolean | null {
  const sms = health?.channels?.sms
  if (!health?.mode || !sms) return null
  if (health.mode !== 'explicit') return false
  const transport = sms.state === 'ready' || sms.state === 'degraded' && (sms.reason === 'channel_switched_off' || sms.reason === 'worker_not_running')
  return transport && (savedProvider === '' || savedProvider === 'https_json')
}

/** What the HTTPS SMS gateway needs in the control environment (control.env). */
const smsGatewayDeployItems = [
  ['NOTIFICATION_RUNTIME_ENABLED=true', 'runtime'], ['NOTIFICATION_SMS_PROVIDER=https_json', 'provider'],
  ['NOTIFICATION_SMS_ENDPOINT', 'endpoint'], ['NOTIFICATION_SMS_READY_ENDPOINT', 'ready'], ['NOTIFICATION_SMS_AUTH_TOKEN', 'token'],
  ['ACCOUNT_RECOVERY_SMS_TEMPLATE_ID', 'templateID'], ['ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION', 'templateVersion'],
] as const

/** The one text (and accessible name) of a runtime SMS channel state. */
function smsHealthText(t: (key: string, options?: Record<string, unknown>) => string, health: NotificationChannelHealth): string {
  const state = t(`notificationSettings:health.states.${health.state}`, { defaultValue: health.state })
  return health.reason ? t('smsStatus.withReason', { state, reason: t(`notificationSettings:health.reasons.${health.reason}`, { defaultValue: health.reason }) }) : state
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
  // registration-ready: the restart note applies to the explicit notification
  // mode only (the auto mode picks saved senders up by itself)
  // the SMS section also shows the runtime SMS channel state (read
  // again after each save of this tab)
  const [notificationHealth, setNotificationHealth] = useState<NotificationRuntimeHealth | null>(null)
  // a failed read is shown in place with a retry; retrying keeps the draft
  const [healthFailed, setHealthFailed] = useState(false)
  const [healthAttempt, setHealthAttempt] = useState(0)
  const notificationMode = notificationHealth?.mode
  const healthRevision = document?.revision
  useEffect(() => {
    if (!accessToken) return
    let active = true
    void notificationsApi.getRuntimeHealth(accessToken)
      .then((health) => { if (active) { setNotificationHealth(health); setHealthFailed(false) } })
      .catch(() => { if (active) { setNotificationHealth(null); setHealthFailed(true) } })
    return () => { active = false }
  }, [accessToken, healthRevision, healthAttempt])
  const retryHealth = () => { setHealthFailed(false); setHealthAttempt((attempt) => attempt + 1) }

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
  // Write-only SMTP password; undefined keeps the stored one, '' clears it.
  const [smtpPassword, setSMTPPassword] = useState('')
  const smtpPasswordRef = useRef<string | undefined>(undefined)
  const [smtpReferenceOpen, setSMTPReferenceOpen] = useState(false)
  // Write-only HTTPS SMS gateway token, likewise.
  const [smsToken, setSMSToken] = useState('')
  const smsTokenRef = useRef<string | undefined>(undefined)
  const [smsReferenceOpen, setSMSReferenceOpen] = useState(false)
  // https_json: the gateway account (sms_access_key_id) is required at runtime
  const [gatewayAccountMissing, setGatewayAccountMissing] = useState(false)

  const write = useBaselineWrite<PlatformSystemMailSettings, PlatformSystemMailSettingsDocument>({
    ownerKey,
    canManage,
    revision: document?.revision,
    scope: 'mail',
    submit: (token, attempt) => systemMailSettingsApi.put(token, attempt.revision, attempt.value, attempt.requestId, attempt.idempotencyKey,
      { smsAccessKeySecret: smsSecretRef.current || undefined, mailSecret: mailSecretRef.current || undefined, smtpPassword: smtpPasswordRef.current,
        smsAuthToken: smsTokenRef.current }),
    onSuccess: (next, attempt) => {
      setDocument(next)
      if (attempt.scope === 'provider') {
        const sent = mailSecretRef.current
        mailSecretRef.current = ''
        setMailSecret((current) => current === sent ? '' : current)
      }
      if (attempt.scope === 'smtp' && smtpPasswordRef.current !== undefined) {
        const sent = smtpPasswordRef.current
        smtpPasswordRef.current = undefined
        setSMTPPassword((current) => current === sent ? '' : current)
      }
      if (attempt.scope === 'sms') {
        const sentSecret = smsSecretRef.current
        const sentToken = smsTokenRef.current
        smsSecretRef.current = ''
        smsTokenRef.current = undefined
        setSMSSecret((current) => current === sentSecret ? '' : current)
        setSMSToken((current) => current === sentToken ? '' : current)
      }
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
  const gatewayProvider = draft.sms_provider === 'https_json'
  const gatewayDeployed = smsGatewayDeployed(notificationHealth, document.value.sms_provider)
  // the gateway is saved once its endpoints are confirmed deployed: saved
  // earlier, an explicit runtime started later refuses a gateway without its
  // account. Unknown (health loading or unreadable): saved fields read-only.
  const gatewayUnknown = gatewayProvider && gatewayDeployed === null
  const gatewayBlocked = gatewayProvider && gatewayDeployed !== true
  const smsChannel = notificationHealth?.channels?.sms
  const smsStatusText = (health: NotificationChannelHealth) => {
    const status = smsHealthText(t, health)
    return <Typography.Text role="status" aria-label={status} type={health.state === 'ready' ? 'success' : 'secondary'}>{status}</Typography.Text>
  }
  const smsStatusItem = (label: string, health: NotificationChannelHealth) => <Form.Item label={label}>{smsStatusText(health)}</Form.Item>
  // health not known: reading, or the read failed (as opposed to a channel
  // reporting an unavailable reason, shown by smsStatusItem)
  const smsHealthUnknownItem = (label: string, detail?: string) => <Form.Item label={label} data-testid="system-settings-sms-health-unknown">
    {healthFailed
      ? <Alert type="error" showIcon message={t('smsStatus.failed')} description={detail} action={<Button size="small" onClick={retryHealth}>{t('actions.retry')}</Button>} />
      : <Space wrap role="status" aria-busy="true" aria-label={t('smsStatus.loading')}><Spin size="small" /><Typography.Text type="secondary">{t('smsStatus.loading')}</Typography.Text></Space>}
  </Form.Item>
  const update = <K extends keyof PlatformSystemMailSettings>(key: K, value: PlatformSystemMailSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const text = (key: keyof PlatformSystemMailSettings, placeholder?: string, locked = false) => <Input id={`system-mail-${key}`} value={String(draft[key])} disabled={!canManage || locked} placeholder={placeholder} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`fields.${key === 'smtp_password_reference' || key === 'sms_access_key_reference' ? 'smtpPasswordReference' : key === 'sms_access_key_id' ? 'accessKeyID' : key === 'smtp_address' ? 'smtpAddress' : key === 'smtp_user' ? 'smtpUser' : key === 'smtp_from' ? 'smtpFrom' : key === 'smtp_from_name' ? 'smtpFromName' : 'signatureName'}`)} />
  const save = (section: 'smtp' | 'sms' | 'provider', clearSecret = false) => {
    if (write.saving || write.uncertain || (section === 'sms' ? unsupportedProvider || gatewayBlocked : persistedUnsupportedProvider)) return
    if (section === 'sms' && gatewayProvider && draft.sms_access_key_id.trim() === '') { setGatewayAccountMissing(true); return }
    setGatewayAccountMissing(false)
    const value = section === 'smtp'
      ? { ...document.value, smtp_address: draft.smtp_address, smtp_ssl: draft.smtp_ssl, smtp_port: draft.smtp_port, smtp_user: draft.smtp_user, smtp_password_reference: draft.smtp_password_reference,
        smtp_from: draft.smtp_from, smtp_from_name: draft.smtp_from_name }
      : section === 'provider'
        // Only the sender fields: the SMTP section keeps its own draft.
        ? { ...document.value, mail_provider: draft.mail_provider, mail_region: mailProviderKind(draft.mail_provider) === 'official' ? draft.mail_region : document.value.mail_region,
            mail_access_key_id: draft.mail_provider === 'aliyun' ? draft.mail_access_key_id : document.value.mail_access_key_id,
            mail_from: draft.mail_from, mail_from_name: draft.mail_from_name }
        // only the chosen provider's fields; the others keep their
        // saved values (the template map exists for native providers only)
        : { ...document.value, sms_provider: draft.sms_provider, sms_template_map: nativeProvider ? draft.sms_template_map : '',
            ...(nativeProvider ? { sms_access_key_id: draft.sms_access_key_id, sms_access_key_reference: '', sms_signature_name: draft.sms_signature_name } : {}),
            ...(gatewayProvider ? { sms_access_key_id: draft.sms_access_key_id, sms_access_key_reference: draft.sms_access_key_reference, sms_signature_name: draft.sms_signature_name } : {}) }
    smsSecretRef.current = section === 'sms' && nativeProvider ? smsSecret : ''
    mailSecretRef.current = section === 'provider' && mailProviderKind(draft.mail_provider) === 'official' ? mailSecret : ''
    smtpPasswordRef.current = section !== 'smtp' ? undefined : clearSecret ? '' : smtpPassword || undefined
    smsTokenRef.current = section !== 'sms' || !gatewayProvider ? undefined : clearSecret ? '' : smsToken || undefined
    write.save(value, section)
  }
  // A refusal of a field on this tab goes under it (fix-fielderr-be2).
  const { status: fieldStatus, shown: refusedShown } = refusedFieldStatus(write.error, ['smtp_address', 'smtp_port', 'smtp_user', 'smtp_password', 'smtp_password_reference', 'smtp_from', 'smtp_from_name',
    'sms_provider', 'sms_access_key_id', 'sms_access_key_reference', 'sms_access_key_secret', 'sms_auth_token', 'sms_signature_name', 'sms_template_map',
    'mail_provider', 'mail_region', 'mail_access_key_id', 'mail_secret', 'mail_from', 'mail_from_name'], i18n.resolvedLanguage)
  const usingSMTP = mailProviderKind(draft.mail_provider) === 'smtp'
  const smtpSettings = <section className={usingSMTP ? 'system-settings-smtp-fields' : 'system-settings-config-card'} aria-labelledby="system-settings-smtp-title">
        {usingSMTP ? <h3 id="system-settings-smtp-title">{t('sections.smtp')}</h3> : <h2 id="system-settings-smtp-title">{t('sections.smtp')}</h2>}
        <Form.Item label={t('fields.smtpAddress')} {...fieldStatus('smtp_address')}>{text('smtp_address')}</Form.Item>
        <Form.Item label={t('fields.smtpSSL')}><Switch checked={draft.smtp_ssl} disabled={!canManage} onChange={(value) => update('smtp_ssl', value)} aria-label={t('fields.smtpSSL')} /></Form.Item>
        <Form.Item label={t('fields.smtpPort')} {...fieldStatus('smtp_port')}><NumberField min={1} max={65535} value={draft.smtp_port} disabled={!canManage} onChange={(value) => update('smtp_port', value ?? 465)} style={{ width: '100%' }} aria-label={t('fields.smtpPort')} /></Form.Item>
        <Form.Item label={t('fields.smtpUser')} {...fieldStatus('smtp_user')}>{text('smtp_user')}</Form.Item>
        <Form.Item label={t('fields.smtpPassword')} {...fieldStatus('smtp_password')}
          extra={document.smtp_password_configured ? t('smtpPassword.set', { fingerprint: document.smtp_password_fingerprint }) : t('smtpPassword.unset')}>
          <Space.Compact style={{ width: '100%' }}>
            <Input.Password id="system-mail-smtp_password" value={smtpPassword} disabled={!canManage} autoComplete="new-password" placeholder={document.smtp_password_configured ? t('smtpPassword.keep') : ''}
              onChange={(event) => setSMTPPassword(event.target.value)} aria-label={t('fields.smtpPassword')} />
            {document.smtp_password_configured ? <Popconfirm title={t('smtpPassword.clearConfirm')} disabled={!canManage || write.uncertain || write.saving || persistedUnsupportedProvider} onConfirm={() => save('smtp', true)}>
              <Button disabled={!canManage || write.uncertain || write.saving || persistedUnsupportedProvider}>{t('smtpPassword.clear')}</Button>
            </Popconfirm> : null}
          </Space.Compact>
        </Form.Item>
        <Form.Item label={t('fields.smtpFrom')} {...fieldStatus('smtp_from')} extra={t('smtpPassword.fromHint')}>{text('smtp_from')}</Form.Item>
        <Form.Item label={t('fields.smtpFromName')} {...fieldStatus('smtp_from_name')}>{text('smtp_from_name')}</Form.Item>
        {smtpReferenceOpen || draft.smtp_password_reference !== ''
          ? <Form.Item label={t('fields.smtpPasswordReference')} {...fieldStatus('smtp_password_reference')} extra={t('smtpPassword.advancedHint')}>{text('smtp_password_reference', t('placeholders.secretReference'))}</Form.Item>
          : <Form.Item label=" "><Button type="link" style={{ padding: 0 }} onClick={() => setSMTPReferenceOpen(true)}>{t('smtpPassword.advanced')}</Button></Form.Item>}
        <div><Button aria-label={t('mailActions.smtp')} aria-busy={write.saving && write.savingScope === 'smtp'} disabled={!canManage || write.uncertain || write.saving || persistedUnsupportedProvider} type="primary" loading={write.saving && write.savingScope === 'smtp'} onClick={() => save('smtp')}>{t('mailActions.smtp')}</Button></div>
      </section>
  return <div data-testid="system-settings-baseline-mail" className="system-settings-baseline-panel">
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={t('states.errorMail')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.errorMail') })} onClose={write.reset} /> : null}
    {persistedUnsupportedProvider ? <Alert type="warning" showIcon message={t('smsProviders.repair')} style={{ marginBottom: 16 }} /> : null}
    <NotificationChannelOffNotice channel="email" refreshKey={document.revision} canManage={canManage} />
    <Form className="system-settings-baseline-form system-settings-baseline-wide-form" labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} labelAlign="right" colon={false}>
      <MailProviderSection accessToken={accessToken} canManage={canManage} document={document} draft={draft} update={update} fieldStatus={fieldStatus} notificationMode={notificationMode}
        secret={mailSecret} onSecretChange={setMailSecret} saving={write.saving && write.savingScope === 'provider'}
        smtpSettings={usingSMTP ? smtpSettings : undefined} smtpPasswordPending={smtpPassword !== ''}
        disabled={write.uncertain || write.saving || persistedUnsupportedProvider} onSave={() => save('provider')} />
      {!usingSMTP ? smtpSettings : null}
      <section className="system-settings-config-card" aria-labelledby="system-settings-sms-title">
        <h2 id="system-settings-sms-title">{t('sections.sms')}</h2>
        <NotificationChannelOffNotice channel="sms" refreshKey={document.revision} canManage={canManage} />
        <Form.Item label={t('fields.smsProvider')} {...fieldStatus('sms_provider')}
          extra={nativeProvider && notificationMode === 'auto' ? t('smsProviders.hintAuto') : notificationMode === 'explicit' && !gatewayBlocked ? t('smsProviders.hintRestart') : undefined}>
          <Select value={draft.sms_provider} disabled={!canManage} aria-label={t('fields.smsProvider')} onChange={(value) => { setGatewayAccountMissing(false); update('sms_provider', value) }} options={[
            { value: '', label: t('smsProviders.inherit') }, { value: 'https_json', label: t('smsProviders.httpsJSON') },
            { value: 'aliyun', label: t('smsProviders.aliyun') }, { value: 'submail', label: t('smsProviders.submail') },
            ...(unsupportedProvider ? [{ value: draft.sms_provider, label: t('smsProviders.unsupported', { provider: draft.sms_provider }), disabled: true }] : []),
          ]} />
        </Form.Item>
        {draft.sms_provider === '' && smsChannel ? smsStatusItem(t('smsStatus.inherited'), smsChannel) : null}
        {draft.sms_provider === '' && !smsChannel ? smsHealthUnknownItem(t('smsStatus.inherited')) : null}
        {gatewayProvider && gatewayDeployed === false ? <Form.Item label={t('smsGateway.status')}>
          {/* status, short note and the expandable items stack in the one control column. */}
          <div className="system-settings-sms-gateway-setup" data-testid="system-settings-sms-gateway-deploy">
            {smsStatusText({ state: 'not_configured' })}
            <Typography.Text type="secondary">{t('smsGateway.deployShort')}</Typography.Text>
            <details className="system-settings-sms-gateway-env">
              <summary>{t('smsGateway.deployToggle')}</summary>
              <Typography.Paragraph type="secondary">{t('smsGateway.deployHint')}</Typography.Paragraph>
              <ul>
                {smsGatewayDeployItems.map(([name, label]) => <li key={name}>
                  <div className="system-settings-sms-gateway-env-key"><Typography.Text code copyable>{name}</Typography.Text></div>
                  <Typography.Text type="secondary">{t(`smsGateway.deployItems.${label}`)}</Typography.Text>
                </li>)}
              </ul>
            </details>
          </div>
        </Form.Item> : null}
        {gatewayProvider && gatewayDeployed !== false ? <>
          {gatewayDeployed && smsChannel ? smsStatusItem(t('smsGateway.status'), smsChannel) : null}
          {gatewayUnknown ? smsHealthUnknownItem(t('smsGateway.status'), t('smsStatus.gatewayLocked')) : null}
          <Form.Item label={t('smsGateway.token')} {...fieldStatus('sms_auth_token', 'sms_access_key_secret')}
            extra={document.sms_auth_token_configured ? t('secretField.set', { fingerprint: document.sms_auth_token_fingerprint }) : t('secretField.unset')}>
            <Space.Compact style={{ width: '100%' }}>
              <Input.Password value={smsToken} disabled={!canManage || gatewayUnknown} autoComplete="new-password" placeholder={document.sms_auth_token_configured ? t('secretField.keep') : ''}
                onChange={(event) => setSMSToken(event.target.value)} aria-label={t('smsGateway.token')} />
              {document.sms_auth_token_configured ? <Popconfirm title={t('secretField.clearConfirm', { name: t('smsGateway.token') })} disabled={!canManage || write.uncertain || write.saving || unsupportedProvider || gatewayBlocked} onConfirm={() => save('sms', true)}>
                <Button disabled={!canManage || write.uncertain || write.saving || unsupportedProvider || gatewayBlocked}>{t('secretField.clear')}</Button>
              </Popconfirm> : null}
            </Space.Compact>
          </Form.Item>
          <Form.Item label={t('smsGateway.account')} required {...fieldStatus('sms_access_key_id')}
            {...(gatewayAccountMissing && draft.sms_access_key_id.trim() === '' ? { validateStatus: 'error' as const, help: t('smsGateway.accountRequired') } : { extra: t('smsGateway.accountHint') })}>
            <Input id="system-mail-sms_access_key_id" value={draft.sms_access_key_id} disabled={!canManage || gatewayUnknown} onChange={(event) => update('sms_access_key_id', event.target.value)} aria-label={t('smsGateway.account')} />
          </Form.Item>
          <Form.Item label={t('smsGateway.signature')} {...fieldStatus('sms_signature_name')} extra={t('smsGateway.signatureHint')}>
            <Input id="system-mail-sms_signature_name" value={draft.sms_signature_name} disabled={!canManage || gatewayUnknown} onChange={(event) => update('sms_signature_name', event.target.value)} aria-label={t('smsGateway.signature')} />
          </Form.Item>
          {smsReferenceOpen || draft.sms_access_key_reference !== ''
            ? <Form.Item label={t('fields.smtpPasswordReference')} {...fieldStatus('sms_access_key_reference')} extra={t('secretField.smsAdvancedHint')}>{text('sms_access_key_reference', t('placeholders.secretReference'), gatewayUnknown)}</Form.Item>
            : <Form.Item label=" "><Button type="link" style={{ padding: 0 }} onClick={() => setSMSReferenceOpen(true)}>{t('smtpPassword.advanced')}</Button></Form.Item>}
        </> : null}
        {nativeProvider ? <>
          <Form.Item label={t('fields.accessKeyID')} {...fieldStatus('sms_access_key_id')}>{text('sms_access_key_id')}</Form.Item>
          <Form.Item label={t('fields.accessKeySecret')} {...fieldStatus('sms_access_key_secret', 'sms_access_key_reference')} extra={document.sms_secret_configured ? t('smsProviders.secretSet', { fingerprint: document.sms_secret_fingerprint }) : t('smsProviders.secretRequired')}>
            <Input.Password value={smsSecret} disabled={!canManage} autoComplete="new-password" placeholder={document.sms_secret_configured ? t('smsProviders.secretKeep') : ''} onChange={(event) => setSMSSecret(event.target.value)} aria-label={t('fields.accessKeySecret')} />
          </Form.Item>
          <Form.Item label={t('fields.signatureName')} {...fieldStatus('sms_signature_name')}>{text('sms_signature_name')}</Form.Item>
          <Form.Item label={t('fields.smsTemplateMap')} {...fieldStatus('sms_template_map')} extra={t('smsProviders.templateMapHint')}>
            <Input.TextArea value={draft.sms_template_map} disabled={!canManage} rows={5} onChange={(event) => update('sms_template_map', event.target.value)} aria-label={t('fields.smsTemplateMap')} />
          </Form.Item>
        </> : null}
        <div><Button aria-label={t('mailActions.sms')} aria-busy={write.saving && write.savingScope === 'sms'} disabled={!canManage || write.uncertain || write.saving || unsupportedProvider || gatewayBlocked} type="primary" loading={write.saving && write.savingScope === 'sms'} onClick={() => save('sms')}>{t('mailActions.sms')}</Button></div>
      </section>
    </Form>
    <Space wrap><Button icon={<RefreshCw size={14} />} disabled={write.saving || write.uncertain} onClick={refresh}>{t('actions.refresh')}</Button></Space>
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
  if (loading) return <div aria-busy="true"><Spin aria-label={t('states.loadingOther')} /><Form labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} style={{ maxWidth: 520, opacity: 0.55 }}><Form.Item label={t('fields.disableFailedSyncNodes')}><Input disabled /></Form.Item><Form.Item label={t('fields.certificateExpiryNoticeDays')}><Input disabled /></Form.Item></Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : t('states.errorOther')} subTitle={t(`errors.${error.code}`, { defaultValue: t('states.errorOther') })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null
  const update = <K extends keyof PlatformSystemOtherSettings>(key: K, value: PlatformSystemOtherSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  const noticeDaysInvalid = certificateNoticeDaysText !== null && !parsedCertificateNoticeDays
  const save = () => { if (!noticeDaysInvalid) write.save(draft) }
  const dirty = noticeDaysInvalid || JSON.stringify(draft) !== JSON.stringify(document.value)
  const onOff = (value: boolean) => value ? t('v2.on') : t('v2.off')
  // the summary and the card heads say what is in force, so they read the last
  // successful readback, never the unsaved draft (the bottom bar says a change is pending).
  const live = document.value
  const noticeDays = live.certificate_expiry_notice_days.join('/')
  // 分组卡；卡头右侧是该组当前值，长说明进标签旁 (?)。
  // 「访问与网络」放源IP请求头（选择 + 一行生效状态）与 http代理（DNS 服务商 API 请求经此代理，
  // 密码读回为 ********，原样回写即保留），随本页签保存即生效，占满一行。
  // DNS记录、同步批量/范围、资源排行、TCP系数无读取方，不再显示，旧值随草稿原样回写。
  const groups = [
    { id: 'other-network', title: t('v2.other.groups.network'), sub: '' },
    { id: 'other-sync', title: t('v2.other.groups.sync'), sub: `${t('fields.disableFailedSyncNodes')} ${onOff(live.disable_failed_sync_nodes)}` },
    { id: 'other-api', title: t('v2.other.groups.api'), sub: `${t('v2.other.summary.apiKey')} ${onOff(live.api_key_enabled)}` },
    { id: 'other-domain', title: t('v2.other.groups.domain'), sub: `${t(`domainOwnership.${live.domain_ownership_policy}`)} · ${t('v2.other.noticesValue', { days: noticeDays })}` },
  ] as const
  const card = (index: number, body: ReactNode, impact = false) => {
    const group = groups[index]
    return <section id={group.id} className={`system-settings-config-card sys-setting-section-anchor sys-other-card${impact ? ' sys-setting-v2-impact' : ''}`} aria-labelledby={`${group.id}-title`}>
      <div className="sys-other-card-head">
        <h2 id={`${group.id}-title`} className="system-settings-config-card-title">{group.title}</h2>
        {group.sub ? <span className="sys-other-card-sub">{group.sub}</span> : null}
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
  const { status: fieldStatus, shown: refusedShown } = refusedFieldStatus(write.error, ['source_ip_header', 'http_proxy', 'domain_ownership_policy', 'certificate_expiry_notice_days', 'l4_drain_max_seconds'], i18n.resolvedLanguage)
  return <div data-testid="system-settings-baseline-other" className="system-settings-baseline-panel sys-other" style={{ minWidth: 0 }}>
    <SaveState visible={write.saving} label={t('states.saving')} />
    {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={t('states.errorOther')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.errorOther') })} onClose={write.reset} /> : null}
    {write.saved ? <Alert type="success" showIcon message={t('states.savedOther')} style={{ marginBottom: 16 }} /> : null}
    <div className="sys-other-summary">
      <SystemSummary label={t('v2.summary.label')} items={[
        { target: 'other-api', label: t('v2.other.summary.apiKey'), value: onOff(live.api_key_enabled), tone: live.api_key_enabled ? 'success' : 'warning' },
        { target: 'other-domain', label: t('v2.other.summary.domain'), value: t(`domainOwnership.${live.domain_ownership_policy}`), tone: live.domain_ownership_policy === 'off' ? 'warning' : undefined },
        { target: 'other-domain', label: t('v2.other.summary.notices'), value: t('v2.other.noticesValue', { days: noticeDays }) },
      ]} />
    </div>
    <Form className="sys-other-form" layout="vertical" colon={false} requiredMark={false}>
      <div className="sys-other-grid">
        {/* 访客 IP 的唯一入口（原在「系统配置」页签）；?section=originauth 定位到源IP请求头。 */}
        {card(0, <>
          <VisitorIPSetting value={draft.source_ip_header} saved={live.source_ip_header} disabled={!canManage}
            onChange={(value) => update('source_ip_header', value)} field={fieldStatus('source_ip_header')} />
          <Form.Item label={label(t('fields.httpProxy'), t('hints.httpProxy'))} {...fieldStatus('http_proxy')} style={{ marginTop: 16, marginBottom: 0 }}>
            <Input value={draft.http_proxy} disabled={!canManage} onChange={(event) => update('http_proxy', event.target.value)}
              aria-label={t('fields.httpProxy')} autoComplete="off" spellCheck={false} style={{ width: '100%', maxWidth: 420 }} />
          </Form.Item>
        </>)}
        {card(1, <div className="sys-other-toggles">{toggleCard('disable_failed_sync_nodes', t('fields.disableFailedSyncNodes'), t('hints.disableFailedSyncNodes'))}</div>)}
        {card(2, <div className="sys-other-toggles">
          {toggleCard('api_key_enabled', t('fields.apiKeyEnabled'), t('hints.apiKeyEnabled'), true)}
          {toggleCard('rule_intel_contribution', t('fields.ruleIntelContribution'), t('hints.ruleIntelContribution'))}
        </div>, !draft.api_key_enabled)}
        {card(3, <>
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
          <NumberField min={0} max={604800} step={3600} precision={0} value={draft.l4_drain_max_seconds} disabled={!canManage} onChange={(value) => update('l4_drain_max_seconds', value ?? 86400)} addonAfter={t('units.seconds')} style={{ width: 280, maxWidth: '100%' }} aria-label={t('fields.l4DrainMaxSeconds')} />
        </Form.Item>,
      }]} />
      </div>
    </Form>
    {/* fix-sysother：底部固定保存条，滚动中始终可见；只管上方分组卡；审批中心在其后单独保存。 */}
    <div className={`sys-setting-v2-savebar sys-other-savebar${dirty ? ' is-dirty' : ''}`}>
      <span>{noticeDaysInvalid ? t('v2.other.invalidDays') : dirty ? t('v2.other.unsaved') : t('v2.other.allSaved')}</span>
      <Space wrap className="sys-other-savebar-actions">
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
  const { t: hostT } = useTranslation('controlHostBind')
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
  // An edit the controller would refuse is not auto-saved: its fields show why, and leaving the page asks first (the draft stays on cancel).
  const localErrors = draft ? systemSettingsFieldErrors(draft) : {}
  const invalidKeys = systemSettingsTextLimits.map(([key]) => key).filter((key) => localErrors[key])
  const unsavable = invalidKeys.length > 0 && Boolean(document) && JSON.stringify(draft) !== JSON.stringify(document?.value)
  useEffect(() => {
    useNavigationGuardStore.getState().setDirty(unsavable)
    if (!unsavable) return
    const onBeforeUnload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = '' }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => window.removeEventListener('beforeunload', onBeforeUnload)
  }, [unsavable])
  useEffect(() => () => resetNavigationGuard(), [])
  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  if (loading) return <div aria-busy="true"><Spin aria-label={t('states.loading')} /><Form layout="vertical" style={{ maxWidth: 720, opacity: 0.55 }}>{(['system_name', 'user_title', 'admin_title'] as const).map((key) => <Form.Item key={key} label={t(`fields.${key}`)}><Input disabled /></Form.Item>)}<Typography.Title level={5}>{t('sections.package')}</Typography.Title></Form></div>
  if (error) return <Result status={error.status === 403 ? '403' : 'error'} title={error.status === 403 ? '403' : t('states.error')} subTitle={t(`errors.${error.code}`, { defaultValue: t('states.error') })} extra={<Button onClick={() => void load()}>{t('actions.refresh')}</Button>} />
  if (!document || !draft) return null

  const update = <K extends keyof PlatformSystemSettings>(key: K, value: PlatformSystemSettings[K]) => setDraft((current) => current ? { ...current, [key]: value } : current)
  // A field's error: the local check first (the edit is not sent), else the controller's refusal; the input points at it.
  const reasonLocale = i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn'
  const itemStatus = (key: SystemSettingsTextKey) => {
    const reason = localErrors[key]
    const status = reason ? { validateStatus: 'error' as const, help: fieldReasonText(reason, reasonLocale) } : fieldStatus(key)
    if (!('help' in status) || !status.help) return { item: status, input: { id: `system-${key}` } }
    const id = `system-${key}-help`
    return { item: { ...status, help: <span id={id}>{status.help}</span> }, input: { id: `system-${key}`, 'aria-invalid': true, 'aria-describedby': id } }
  }
  const fieldLabel = (key: SystemSettingsTextKey) => t(key === 'purchase_notice' ? 'fields.purchaseNotice' : `fields.${key}`)
  const locateInvalid = (key: SystemSettingsTextKey) => {
    const input = window.document.getElementById(`system-${key}`)
    input?.scrollIntoView?.({ behavior: 'smooth', block: 'center' })
    input?.focus({ preventScroll: true })
  }
  const text = (key: SystemSettingsTextKey, placeholder?: string) => <Input value={String(draft[key] ?? '')} disabled={!canManage} placeholder={placeholder} onChange={(event) => update(key, event.target.value as never)} aria-label={t(`fields.${key}`)} {...itemStatus(key).input} />
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
    const previewPath = asset?.revision ? `/v1/brand-assets/${key}` : builtInBrandAsset(key, i18n.resolvedLanguage)
    return <Upload accept={key === 'favicon' ? '.ico,.png,image/x-icon,image/png' : key === 'logo' ? '.png,image/png' : '.jpg,.jpeg,image/jpeg'} showUploadList={false} beforeUpload={(file) => { void uploadBrandAsset(key, file); return Upload.LIST_IGNORE }} disabled={!canManage || uploadingSlot !== null || brandUploadUncertain || brandBindingWrite.saving || brandBindingWrite.uncertain}>
      <span className={`system-settings-brand-asset-preview system-settings-brand-asset-preview--${key}`} role="button" tabIndex={canManage ? 0 : -1} aria-label={t(`fields.${key}`)}>
        <img src={previewPath} alt={t(`fields.${key}`)} />
      </span>
    </Upload>
  }
  const dirty = JSON.stringify(draft) !== JSON.stringify(document.value)
  // unsaved and refused (here or by the controller): the field to go to
  const refusedTextKey = refusedShown ? systemSettingsTextLimits.map(([key]) => key).find((key) => key === refusedKey) : undefined
  const invalidTarget = invalidKeys[0] ?? (dirty ? refusedTextKey : undefined)
  const saveStatus = write.saving || brandBindingWrite.saving || uploadingSlot !== null ? 'saving'
    : invalidTarget ? 'invalid' : dirty && !write.error && !refreshError ? 'pending' : null
  const savedReceipt = !dirty && (write.saved || assetSaved || brandBindingWrite.saved) ? t(assetSaved || brandBindingWrite.saved ? 'states.assetUploaded' : 'states.saved') : null
  const navigation = [
    { id: 'system-info', label: t('innerNav.systemInfo') },
    { id: 'system-brand', label: t('innerNav.brand') },
    { id: 'system-package', label: t('innerNav.package') },
    { id: 'system-maintenance', label: t('innerNav.maintenance') },
    { id: 'system-host', label: hostT('title') },
  ]
  return <div data-testid="system-settings-baseline-system" className="system-settings-baseline-panel">
    <div className="system-settings-feedback-stack" aria-live="polite">
      {/* the one top status, only while saving, unsaved or unsavable; saved shows in the bar below. */}
      {saveStatus ? <div className={`sys-setting-save-state sys-setting-save-state--${saveStatus}`} role="status" data-testid="system-settings-save-status">
        {saveStatus === 'saving' ? <span className="sys-setting-save-icon sys-setting-save-icon--spin" aria-hidden="true">↻</span> : null}
        <span>{t(saveStatus === 'saving' ? 'states.saving' : saveStatus === 'invalid' ? 'v2.invalid' : 'v2.pending')}</span>
        {saveStatus === 'invalid' && invalidTarget ? <Button size="small" type="link" onClick={() => locateInvalid(invalidTarget)}>{t('v2.locate', { name: fieldLabel(invalidTarget) })}</Button> : null}
      </div> : null}
      {write.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={write.saving} disabled={!canManage} onClick={write.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : write.error && !refusedShown ? <FeedbackWhen title={t('states.error')} detail={t(`errors.${write.error instanceof ApiError ? write.error.code : 'network_error'}`, { defaultValue: t('states.error') })} onClose={write.reset} /> : null}
      {brandBindingWrite.uncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={brandBindingWrite.saving} disabled={!canManage} onClick={brandBindingWrite.retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : brandBindingWrite.error ? <FeedbackWhen title={t('states.error')} detail={t(`errors.${brandBindingWrite.error instanceof ApiError ? brandBindingWrite.error.code : 'network_error'}`, { defaultValue: t('states.error') })} onClose={brandBindingWrite.reset} /> : null}
      {brandUploadUncertain ? <OutcomeUnknown type="warning" title={t('uncertainty.assetUploadTitle')} detail={t('uncertainty.assetUploadDescription')} action={<Space wrap><Button icon={<RefreshCw size={14} />} loading={uploadingSlot !== null} disabled={!canManage} onClick={retryBrandAssetUpload}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} /> : brandAssetError ? <FeedbackWhen type="warning" title={brandAssetError.code.startsWith('brand_asset_') ? t(`errors.${brandAssetError.code}`, { defaultValue: t('states.assetUploadUnavailable') }) : t('states.assetUploadUnavailable')} /> : null}
      {refreshError ? <FeedbackWhen title={t('states.refreshFailed')} detail={t(`errors.${refreshError.code}`, { defaultValue: t('states.error') })}
        action={<Button size="small" disabled={writeInFlight} onClick={() => void load()}>{t('actions.retry')}</Button>} onClose={() => setRefreshError(null)} /> : null}
    </div>
    <Form className="system-settings-baseline-form" labelCol={{ flex: '170px' }} wrapperCol={{ flex: '330px' }} labelAlign="right" colon={false} style={{ maxWidth: 840, width: '100%' }}>
      <SectionNavigation label={t('innerNavigation.system')} items={navigation} />
      <section id="system-info" className="system-settings-config-card system-settings-system-info sys-setting-section-anchor" aria-labelledby="system-info-title">
      <h2 id="system-info-title" className="system-settings-config-card-title">{t('innerNav.systemInfo')}</h2>
      {themeBrandName ? <Alert className="sys-setting-v2-theme-banner" type="warning" showIcon message={t('v2.themeBanner', { theme: themeName, name: themeBrandName })} /> : null}
      {(['system_name', 'user_title', 'admin_title', 'footer_links', 'footer_text', 'global_js', 'bound_domains'] as const).map((key) => (
        <Fragment key={key}>
        <Form.Item label={t(`fields.${key}`)} {...itemStatus(key).item} extra={key === 'global_js' ? <div className="system-settings-form-warning">{t('hints.globalJS')}</div>
          : themeBrandName && (key === 'system_name' || key === 'user_title' || key === 'admin_title')
            ? <div className="system-settings-form-warning" data-testid={`theme-override-${key}`}>{t('hints.themeOverride', { theme: themeName, name: themeBrandName })}</div>
            : undefined}>
          {key === 'global_js' || key === 'footer_links' ? <Input.TextArea value={draft[key]} disabled={!canManage} placeholder={key === 'global_js' ? t('hints.globalJSPlaceholder') : undefined} onChange={(event) => update(key, event.target.value)} autoSize={key === 'global_js' ? { minRows: 6, maxRows: 10 } : { minRows: 3, maxRows: 5 }} aria-label={t(`fields.${key}`)} {...itemStatus(key).input} /> : text(key, key === 'bound_domains' ? t('placeholders.boundDomains') : undefined)}
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
      <Form.Item className="system-settings-purchase-notice" label={t('fields.purchaseNotice')} {...itemStatus('purchase_notice').item} extra={<div className="system-settings-form-hint">{t('purchaseNoticeHint')}</div>}>
        <Input.TextArea value={String(draft.purchase_notice ?? '')} disabled={!canManage} placeholder={t('placeholders.purchaseNotice')} rows={8} aria-label={t('fields.purchaseNotice')} onChange={(event) => update('purchase_notice', event.target.value)} {...itemStatus('purchase_notice').input} />
      </Form.Item>
      </section>
      <section id="system-maintenance" className={`system-settings-config-card sys-setting-section-anchor${draft.maintenance ? ' sys-setting-v2-impact' : ''}`} aria-labelledby="system-maintenance-title">
      <h2 id="system-maintenance-title" className="system-settings-config-card-title">{t('sections.maintenance')}</h2>
      <Form.Item label={t('fields.maintenance')} extra={draft.maintenance ? <span className="sys-setting-v2-impact-note">{t('v2.maintenanceOn')}</span> : undefined}>{toggle('maintenance')}</Form.Item>
      <Form.Item label={t('fields.maintenance_message')} {...itemStatus('maintenance_message').item}>{text('maintenance_message')}</Form.Item>
      <Form.Item label={t('fields.auto_upgrade_node')}>{toggle('auto_upgrade_node')}</Form.Item>
      </section>
      {/* ctl-bind-domain：管理端地址/绑定域名——只显示现状并给出 root 执行的 control-host bind 命令。 */}
      <ControlHostBindCard />
      {/* SET-002：后台 HTTPS 入口未接通（保存只存引用，不切换证书），按 10-25 "未接通不显示" 规则整段不渲染；
          certificate/private_key 仍随草稿原样回写，不丢已有引用。接通并能校验证书配对、切换入口后再恢复。 */}
    </Form>
    {/* redesign-a：底部固定动作条；只在真实保存回执后显示已保存（未保存/保存中/错误在顶部状态）。 */}
    <div className="sys-setting-v2-savebar">
      <span role="status" data-testid="system-settings-saved-receipt">{savedReceipt}</span>
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

/** One line per tab: what the settings affect and how they are saved. The system tab shows its
 * real save state instead and the payment tab its readiness rows. */
function TabScope({ tab, onOpenTab }: { tab: BaselineTab; onOpenTab: (tab: BaselineTab) => void }) {
  const { t } = useTranslation('systemGlobalSettings')
  if (tab === 'mail' || tab === 'notification' || tab === 'system' || tab === 'payment') return null
  // 账号与安全只提示与「认证与支付」共用一份设置（另一页的已保存修改会带入），不复述页签与保存按钮。
  if (tab === 'account') return <Alert className="system-settings-tab-scope" type="info" showIcon data-testid="system-settings-scope-account"
    message={<span>{t('scope.account.shared')} <Typography.Link onClick={() => onOpenTab('payment')}>{t('scope.open', { tab: t('tabs.payment') })}</Typography.Link></span>}
    style={{ marginBottom: 16, maxWidth: 840 }} />
  return <Alert className="system-settings-tab-scope" type="info" showIcon data-testid={`system-settings-scope-${tab}`}
    message={<span><strong>{t('scope.range')}</strong>{t(`scope.${tab}.range`)}</span>}
    description={<span><strong>{t('scope.save')}</strong>{t(`scope.${tab}.save`)}</span>}
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
  const section = searchParams.get('section')
  // 源IP请求头在「其它配置 → 访问与网络」；?section=originauth（含旧的 tab=system 深链）都打开该页签。
  const tab: BaselineTab = section === controlOriginAuthSection ? 'other' : urlTab ?? initialTab
  // Account and payment edit one shared document; each panel follows the newest revision the other saved.
  const [sharedUserDocument, setSharedUserDocument] = useState<PlatformSystemUserSettingsDocument | null>(null)
  // ?section= 只是进入时的落点：手动切换页签时去掉，免得旧落点把页签拉回去。
  const openTab = useCallback((next: BaselineTab) => {
    setSearchParams((current) => { const params = new URLSearchParams(current); params.set('tab', next); params.delete('section'); return params }, { replace: true })
  }, [setSearchParams])
  useEffect(() => {
    if (section === controlOriginAuthSection && urlTab !== 'other') {
      setSearchParams((current) => { const params = new URLSearchParams(current); params.set('tab', 'other'); return params }, { replace: true })
    }
  }, [section, urlTab, setSearchParams])

  // ?section=smtp|sms 打开发信配置时滚动到对应小节（面板异步加载，等标题出现，最多 3 秒）。
  useEffect(() => {
    if (!section || !/^[a-z]+$/.test(section)) return
    let tries = 0
    const timer = window.setInterval(() => {
      const heading = document.getElementById(`system-settings-${section}-title`)
      if (heading || ++tries > 30) {
        window.clearInterval(timer)
        heading?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
        if (heading) { heading.setAttribute('tabindex', '-1'); heading.focus({ preventScroll: true }) }
      }
    }, 100)
    return () => window.clearInterval(timer)
  }, [tab, section])

  useEffect(() => {
    const previousTitle = document.title
    document.title = t('pageTitle')
    return () => { document.title = previousTitle }
  }, [t])

  const panel = (key: BaselineTab): ReactNode => key === 'system' ? <SystemPanel /> : key === 'cleanup' ? <CleanupPanel />
    : key === 'account' || key === 'payment' ? <UserSettingsPanel mode={key} active={tab === key} shared={sharedUserDocument} onShared={setSharedUserDocument} />
      : key === 'notification' ? <Suspense fallback={<div aria-busy="true"><Spin aria-label={t('states.loadingNotification')} /></div>}><NotificationSettingsPage mode="admin" embedded /></Suspense>
        : key === 'mail' ? <MailPanel /> : <OtherPanel />
  return (
    <div className="sys-setting-v2">
    <div data-testid="system-global-settings-page" className="system-settings-baseline-page sys-setting sys-setting-reference-page" style={{ minWidth: 0 }}>
      {/* Visited tabs stay mounted (destroyOnHidden=false) so unsaved drafts survive switching tabs. */}
      <Tabs
        activeKey={tab}
        destroyOnHidden={false}
        more={{ icon: <span role="img" aria-label={t('tabs.more')}><Ellipsis size={16} aria-hidden /></span> }}
        onChange={(value) => openTab(value as BaselineTab)}
        items={systemGlobalSettingsTabs.map((key) => ({ key, label: t(`tabs.${key}`), children: <><TabScope tab={key} onOpenTab={openTab} />{panel(key)}</> }))}
      />
    </div>
    </div>
  )
}
