import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Form, Input, Radio } from 'antd'
import { ChartColumn, CircleCheck, DoorClosed, FileKey, Globe, LoaderCircle, MailCheck, ShieldCheck, TriangleAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import {
  AccountRegistrationApiError,
  accountRegistrationApi,
  registrationChannels,
  type AccountRegistrationConfig,
  type AccountRegistrationChallengeRequest,
  type AccountRegistrationChallengeResult,
  type AccountRegistrationCaptcha,
  type AccountRegistrationChallengeVerificationRequest,
  type AccountRegistrationMode,
  type AccountRegistrationRequest,
  type AccountRegistrationRequestMetadata,
  type AccountRegistrationResult,
  type AccountRegistrationVerificationChannel,
} from '../api/accountRegistration'
import { ApiError } from '../api/auth'
import { checkPassword, passwordPolicyLocale, passwordPolicyMessage } from '@cdnca/ui/password-policy'
import { PasswordStrengthPopover } from '@cdnca/ui'
import '../i18n/accountRegistration'
// LoginCaptchaField reads its labels from the sign-in CAPTCHA resources.
import '../i18n/passwordLoginChallenge'
import { LanguageMenu } from '../components/LanguageMenu'
import { PublicBrandAssetImage } from '../components/PublicBrandAssetImage'
import { localizedText } from '../api/theme'
import { useAuthStyle } from '../theme/authStyle'
import { useBrandName, useThemeRuntime } from '../theme/runtime'
import './RegisterPage.css'
import { LoginCaptchaField } from './login/LoginCaptchaField'
import { TurnstileWidget } from './registration/TurnstileWidget'
import {
  browserTurnstileAdapter,
  type TurnstileAdapter,
} from './registration/turnstileAdapter'

export const accountRegistrationTermsVersion = 'terms-2026-08'
const pageVerificationLimit = 5

interface AccountRegistrationForm {
  username: string
  display_name: string
  password: string
  email: string
  phone: string
  verification_channel: AccountRegistrationVerificationChannel
  terms_accepted: boolean
}

interface VerificationForm {
  otp: string
}

interface ChallengeSession {
  registration: AccountRegistrationRequest
  challenge: AccountRegistrationChallengeResult
}

interface FrozenAttempt<K extends 'challenge' | 'verification' | 'registration', T> {
  kind: K
  input: T
  metadata: AccountRegistrationRequestMetadata
  body: string
  registration: AccountRegistrationRequest
}

type AnyAttempt =
  | FrozenAttempt<'challenge', AccountRegistrationChallengeRequest>
  | FrozenAttempt<'verification', AccountRegistrationChallengeVerificationRequest>
  | FrozenAttempt<'registration', AccountRegistrationRequest>

type Stage =
  | 'details'
  | 'challenge-pending'
  | 'otp'
  | 'verification-pending'
  | 'registration-pending'
  | 'unknown'
  | 'failed'
  | 'accepted'

interface RegisterPageProps {
  turnstileAdapter?: TurnstileAdapter
  turnstileSiteKey?: string
  /** Fixed flow for tests; by default the server decides (login-methods registration_mode). */
  registrationMode?: AccountRegistrationMode
}

const usernamePattern = /^[a-z0-9][a-z0-9._-]{2,127}$/
const phonePattern = /^\+?[0-9]{6,20}$/
const otpPattern = /^[0-9]{6}$/

function requestIdentity(prefix: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `${prefix}-${suffix}`
}

function metadata(prefix: string): AccountRegistrationRequestMetadata {
  return {
    idempotencyKey: requestIdentity(prefix),
    requestId: requestIdentity(`${prefix}-request`),
  }
}

function unknownWriteResult(error: unknown): boolean {
  return !(error instanceof ApiError) ||
    error.status === 0 ||
    error.status === 408 ||
    error.status >= 500
}

function pendingStage(kind: AnyAttempt['kind']): Stage {
  if (kind === 'challenge') return 'challenge-pending'
  if (kind === 'verification') return 'verification-pending'
  return 'registration-pending'
}

export function RegisterPage({
  turnstileAdapter = browserTurnstileAdapter,
  turnstileSiteKey = import.meta.env.VITE_TURNSTILE_SITE_KEY ?? '',
  registrationMode,
}: RegisterPageProps = {}) {
  const { i18n, t } = useTranslation('accountRegistration')
  const [form] = Form.useForm<AccountRegistrationForm>()
  const [otpForm] = Form.useForm<VerificationForm>()
  const [stage, setStage] = useState<Stage>('details')
  const [session, setSession] = useState<ChallengeSession | null>(null)
  const [accepted, setAccepted] = useState<AccountRegistrationResult | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [unknownKind, setUnknownKind] = useState<AnyAttempt['kind'] | null>(null)
  const [remainingAttempts, setRemainingAttempts] = useState(pageVerificationLimit)
  const [humanToken, setHumanToken] = useState('')
  const [humanWasSolved, setHumanWasSolved] = useState(false)
  const [turnstileUnavailable, setTurnstileUnavailable] = useState(false)
  const [turnstileResetKey, setTurnstileResetKey] = useState(0)
  const [retryAt, setRetryAt] = useState<number | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const attemptRef = useRef<AnyAttempt | null>(null)
  const activeRef = useRef(true)
  // builtin registration: 'builtin' (no Turnstile service, e.g. a fresh install) uses the
  // built-in image CAPTCHA and registers in one request; null while unknown.
  const [mode, setMode] = useState<AccountRegistrationMode | null>(registrationMode ?? null)
  const [captcha, setCaptcha] = useState<AccountRegistrationCaptcha | null>(null)
  const [captchaReset, setCaptchaReset] = useState(0)
  const builtInRef = useRef<{ registration: AccountRegistrationRequest, captcha: AccountRegistrationCaptcha, metadata: AccountRegistrationRequestMetadata } | null>(null)

  useEffect(() => {
    if (registrationMode) return
    const controller = new AbortController()
    void accountRegistrationApi.registrationMode(controller.signal).then((value) => {
      if (!controller.signal.aborted) setMode(value)
    })
    return () => controller.abort()
  }, [registrationMode])

  // only the required and sendable channels are offered.
  const [config, setConfig] = useState<AccountRegistrationConfig | null | undefined>(undefined)
  // Read after the mode is known; a page given its mode (embedding, tests)
  // keeps the previous behaviour.
  useEffect(() => {
    if (registrationMode || mode === null || mode === 'closed') return
    const controller = new AbortController()
    void accountRegistrationApi.registrationConfig(controller.signal).then((value) => {
      if (!controller.signal.aborted) setConfig(value)
    })
    return () => controller.abort()
  }, [registrationMode, mode])
  const channels = registrationChannels(config ?? null)
  const requiredCount = config ? (config.email.required ? 1 : 0) + (config.sms.required ? 1 : 0) : 0
  // This page proves one channel (Turnstile) or none (built-in CAPTCHA); the
  // website pages (control-site) finish every combination.
  const verifyOnSite = Boolean(config && config.mode !== 'closed' && (requiredCount > 1 || (mode === 'builtin' && requiredCount > 0)))
  const verifyNotReady = Boolean(config && config.mode !== 'closed' && !config.ready)
  useEffect(() => {
    if (channels.length > 0 && !channels.includes(form.getFieldValue('verification_channel'))) form.setFieldValue('verification_channel', channels[0])
  }, [channels, form])

  useEffect(() => () => {
    activeRef.current = false
    attemptRef.current = null
  }, [])

  useEffect(() => {
    const expiresAt = session ? Date.parse(session.challenge.expires_at) : 0
    if (expiresAt <= Date.now() && (!retryAt || retryAt <= Date.now())) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [retryAt, session])

  const resetHuman = () => {
    setHumanToken('')
    setTurnstileResetKey((value) => value + 1)
  }

  const startOver = () => {
    attemptRef.current = null
    builtInRef.current = null
    setCaptcha(null)
    setCaptchaReset((value) => value + 1)
    setStage('details')
    setSession(null)
    setAccepted(null)
    setError(null)
    setUnknownKind(null)
    setRemainingAttempts(pageVerificationLimit)
    setRetryAt(null)
    setTurnstileUnavailable(false)
    setHumanWasSolved(false)
    resetHuman()
    form.resetFields()
    otpForm.resetFields()
  }

  const runAttempt = async (attempt: AnyAttempt) => {
    setStage(pendingStage(attempt.kind))
    setError(null)
    setUnknownKind(null)
    try {
      if (attempt.kind === 'challenge') {
        const result = await accountRegistrationApi.createChallenge(
          attempt.input,
          attempt.metadata,
          attempt.body,
        )
        if (!activeRef.current || attemptRef.current !== attempt) return
        attemptRef.current = null
        setSession({ registration: attempt.registration, challenge: result })
        setRemainingAttempts(pageVerificationLimit)
        setStage('otp')
        resetHuman()
        return
      }
      if (attempt.kind === 'verification') {
        await accountRegistrationApi.verifyChallenge(attempt.input, attempt.metadata, attempt.body)
        if (!activeRef.current || attemptRef.current !== attempt) return
        const registrationAttempt: FrozenAttempt<'registration', AccountRegistrationRequest> = {
          kind: 'registration',
          input: attempt.registration,
          metadata: metadata('registration'),
          body: accountRegistrationApi.serialize(attempt.registration),
          registration: attempt.registration,
        }
        attemptRef.current = registrationAttempt
        void runAttempt(registrationAttempt)
        return
      }
      const result = await accountRegistrationApi.register(attempt.input, attempt.metadata, attempt.body)
      if (!activeRef.current || attemptRef.current !== attempt) return
      attemptRef.current = null
      setAccepted(result)
      setStage('accepted')
    } catch (caught) {
      if (!activeRef.current || attemptRef.current !== attempt) return
      if (unknownWriteResult(caught)) {
        setError(caught)
        setUnknownKind(attempt.kind)
        setStage('unknown')
        return
      }
      attemptRef.current = null
      setError(caught)
      if (caught instanceof AccountRegistrationApiError && caught.retryAfterSeconds !== null) {
        const current = Date.now()
        setNow(current)
        setRetryAt(current + caught.retryAfterSeconds * 1000)
      }
      if (attempt.kind === 'challenge') {
        resetHuman()
        setStage('details')
        return
      }
      if (attempt.kind === 'verification') {
        const next = caught instanceof ApiError && caught.code === 'account_registration_challenge_invalid'
          ? Math.max(0, remainingAttempts - 1)
          : remainingAttempts
        setRemainingAttempts(next)
        otpForm.resetFields()
        setStage(next === 0 ? 'failed' : 'otp')
        return
      }
      setStage('failed')
    }
  }

  const runBuiltIn = async () => {
    const attempt = builtInRef.current
    if (!attempt) return
    setStage('registration-pending')
    setError(null)
    setUnknownKind(null)
    try {
      const result = await accountRegistrationApi.registerBuiltIn(attempt.registration, attempt.captcha, attempt.metadata)
      if (!activeRef.current || builtInRef.current !== attempt) return
      builtInRef.current = null
      setAccepted(result)
      setStage('accepted')
    } catch (caught) {
      if (!activeRef.current || builtInRef.current !== attempt) return
      setError(caught)
      if (unknownWriteResult(caught)) {
        setUnknownKind('registration')
        setStage('unknown')
        return
      }
      builtInRef.current = null
      // Every answered attempt spends the CAPTCHA, so show a new one.
      setCaptcha(null)
      setCaptchaReset((value) => value + 1)
      setStage('details')
    }
  }

  const submitChallenge = (values: AccountRegistrationForm) => {
    if (mode === 'builtin') {
      if (!captcha) return
      builtInRef.current = {
        registration: {
          username: values.username.trim().toLowerCase(),
          password: values.password,
          display_name: values.display_name.trim(),
          email: values.email.trim().toLowerCase(),
          phone: values.phone.trim(),
          terms_accepted: values.terms_accepted,
          terms_version: accountRegistrationTermsVersion,
          verification_channel: 'email',
        },
        captcha,
        metadata: metadata('registration'),
      }
      void runBuiltIn()
      return
    }
    if (!humanToken) {
      setTurnstileUnavailable(true)
      return
    }
    const registration: AccountRegistrationRequest = {
      username: values.username.trim().toLowerCase(),
      password: values.password,
      display_name: values.display_name.trim(),
      email: values.email.trim().toLowerCase(),
      phone: values.phone.trim(),
      terms_accepted: values.terms_accepted,
      terms_version: accountRegistrationTermsVersion,
      verification_channel: values.verification_channel,
    }
    const input: AccountRegistrationChallengeRequest = {
      username: registration.username,
      email: registration.email,
      phone: registration.phone,
      verification_channel: registration.verification_channel,
      human_token: humanToken,
    }
    const attempt: FrozenAttempt<'challenge', AccountRegistrationChallengeRequest> = {
      kind: 'challenge',
      input,
      metadata: metadata('registration-challenge'),
      body: accountRegistrationApi.serializeChallenge(input),
      registration,
    }
    attemptRef.current = attempt
    void runAttempt(attempt)
  }

  const submitVerification = ({ otp }: VerificationForm) => {
    if (!session || Date.parse(session.challenge.expires_at) <= Date.now() || remainingAttempts === 0) return
    const input: AccountRegistrationChallengeVerificationRequest = {
      challenge_id: session.challenge.challenge_id,
      username: session.registration.username,
      email: session.registration.email,
      phone: session.registration.phone,
      verification_channel: session.registration.verification_channel,
      otp,
    }
    const attempt: FrozenAttempt<'verification', AccountRegistrationChallengeVerificationRequest> = {
      kind: 'verification',
      input,
      metadata: metadata('registration-verification'),
      body: accountRegistrationApi.serializeVerification(input),
      registration: session.registration,
    }
    attemptRef.current = attempt
    void runAttempt(attempt)
  }

  const retrySame = () => {
    if (builtInRef.current) void runBuiltIn()
    else if (attemptRef.current) void runAttempt(attemptRef.current)
  }

  const expiresAt = session ? Date.parse(session.challenge.expires_at) : 0
  const secondsRemaining = session ? Math.max(0, Math.ceil((expiresAt - now) / 1000)) : 0
  const expired = session !== null && secondsRemaining === 0
  const retrySeconds = retryAt ? Math.max(0, Math.ceil((retryAt - now) / 1000)) : 0
  const pending = stage.endsWith('-pending')
  const locale = i18n.resolvedLanguage?.toLowerCase().startsWith('qps')
    ? 'en-US'
    : i18n.resolvedLanguage ?? 'zh-CN'
  // Same frame as the sign-in page: theme login layout, logo, footer text and
  // the user console plugin's auth-page CSS.
  const { layout } = useThemeRuntime()
  useAuthStyle()
  const brandName = useBrandName(i18n.resolvedLanguage ?? 'zh-CN')
  const footerText = localizedText(layout.footer_text, i18n.resolvedLanguage ?? 'zh-CN')
  const pageTitle = t('title')
  useEffect(() => {
    const previousTitle = document.title
    document.title = pageTitle
    return () => {
      document.title = previousTitle
    }
  }, [pageTitle])

  let errorMessage: string | null = null
  if (unknownKind) {
    const unknownMessage = t(`errors.${unknownKind === 'challenge'
      ? 'challengeUnknown'
      : unknownKind === 'verification'
        ? 'verificationUnknown'
        : 'registrationUnknown'}`)
    errorMessage = error instanceof ApiError && [
      'account_registration_challenge_unavailable',
      'account_registration_unavailable',
    ].includes(error.code)
      ? `${t(`errors.${error.code}`)} ${unknownMessage}`
      : unknownMessage
  } else if (error instanceof ApiError) {
    if (error.code === 'account_registration_challenge_rate_limited' && retrySeconds > 0) {
      errorMessage = t('errors.account_registration_challenge_rate_limited', { seconds: retrySeconds })
    } else if ([
      'account_registration_challenge_invalid',
      'account_registration_captcha_invalid',
      'account_registration_disabled',
      'account_registration_verification_unavailable',
      'account_registration_challenge_conflict',
      'account_registration_challenge_unavailable',
      'account_registration_invalid_input',
      'password_policy_unmet',
      'account_registration_terms_required',
      'account_registration_rate_limited',
      'account_registration_idempotency_conflict',
      'account_registration_unavailable',
      'permission_denied',
      'forbidden',
    ].includes(error.code)) {
      errorMessage = t(`errors.${error.code}`)
    } else {
      errorMessage = t('errors.requestFailed')
    }
  } else if (error) {
    errorMessage = t('errors.requestFailed')
  }

  const verifying = session !== null && ['otp', 'verification-pending'].includes(stage)
  const showForm = mode !== 'closed' && !verifyOnSite && !verifyNotReady && (stage === 'details' || stage === 'challenge-pending')
  const step = mode === 'verified' && showForm ? t('page.stepDetails') : verifying ? t('page.stepVerify') : null
  const features = [
    { key: 'access', Icon: Globe },
    { key: 'security', Icon: ShieldCheck },
    { key: 'certificates', Icon: FileKey },
    { key: 'analytics', Icon: ChartColumn },
  ] as const

  return (
    <div className={`login-page register-page is-layout-${layout.login_layout}`}>
      {layout.login_layout === 'background' ? (
        <PublicBrandAssetImage className="login-background" slot="login_background" alt="" />
      ) : null}
      <header className="login-header">
        <PublicBrandAssetImage slot="logo" alt={brandName} />
        <LanguageMenu className="login-language-trigger" />
      </header>
      <main className="register-stage">
        <div className="register-shell">
          <aside className="register-aside" aria-labelledby="register-aside-title">
            <div>
              <p className="register-aside-brand">{brandName}</p>
              <h2 id="register-aside-title" className="register-aside-title">{t('page.asideTitle')}</h2>
              <p className="register-aside-lead">{t('page.asideLead')}</p>
            </div>
            <ul className="register-features">
              {features.map(({ key, Icon }) => (
                <li className="register-feature" key={key}>
                  <span className="register-feature-icon" aria-hidden="true"><Icon size={18} strokeWidth={1.6} /></span>
                  <div>
                    <p className="register-feature-title">{t(`page.features.${key}.title`)}</p>
                    <p className="register-feature-text">{t(`page.features.${key}.text`)}</p>
                  </div>
                </li>
              ))}
            </ul>
            <p className="register-aside-foot">{t('page.asideFoot')}</p>
          </aside>

          <section className="register-panel" aria-labelledby="register-title">
            <div className="register-panel-head">
              {step ? <p className="register-step">{step}</p> : null}
              <h1 id="register-title" className="register-title">{t(mode === 'closed' ? 'page.closedTitle' : 'title')}</h1>
              {mode !== 'closed' && stage !== 'accepted' ? (
                <p className="register-switch">
                  {t('page.haveAccount')} <Link to="/login">{t('page.signIn')}</Link>
                </p>
              ) : null}
            </div>

            {errorMessage ? <Alert className="register-alert" type="error" showIcon message={errorMessage} /> : null}
            {mode === 'verified' && turnstileUnavailable && stage === 'details' ? (
              <Alert className="register-alert" type="warning" showIcon message={t('errors.turnstileUnavailable')} />
            ) : null}

            {mode !== 'closed' && (verifyNotReady || verifyOnSite) ? (
              <div className="register-state register-enter" role="status">
                <p className="register-state-text">{t(verifyNotReady ? 'page.verifyNotReady' : 'page.verifyOnSite')}</p>
                {!verifyNotReady ? <div className="register-actions"><a className="register-link-button" href="/register/">{t('page.verifyOnSiteAction')}</a></div> : null}
              </div>
            ) : null}
            {mode === 'closed' ? (
              <div className="register-state register-enter">
                <span className="register-state-icon" aria-hidden="true"><DoorClosed size={24} strokeWidth={1.6} /></span>
                <p className="register-state-text">{t('errors.account_registration_disabled')}</p>
                <p className="register-state-text">{t('page.closedText')}</p>
                <div className="register-actions">
                  <Link className="register-link-button" to="/login">{t('page.closedAction')}</Link>
                </div>
              </div>
            ) : null}

            {stage === 'accepted' && accepted ? (
              <div className="register-state register-enter" role="status">
                <span className="register-state-icon is-success" aria-hidden="true"><CircleCheck size={24} strokeWidth={1.6} /></span>
                <h2 className="register-state-title">{t(accepted.replayed ? 'states.replayed' : 'states.pendingVerification')}</h2>
                <p className="register-state-text">{t('page.acceptedText')}</p>
                <div className="register-actions">
                  <Link className="register-link-button" to="/login">{t('page.acceptedAction')}</Link>
                </div>
              </div>
            ) : null}

            {showForm ? (
              <Form<AccountRegistrationForm>
                form={form}
                className="login-form register-form"
                name="account-registration"
                aria-label={t('title')}
                layout="vertical"
                requiredMark={false}
                scrollToFirstError={{ block: 'center', focus: true }}
                initialValues={{ verification_channel: 'email', terms_accepted: false }}
                disabled={pending || retrySeconds > 0}
                onFinish={submitChallenge}
                onValuesChange={(changed) => {
                  if (humanToken && ['username', 'email', 'phone', 'verification_channel'].some((key) => key in changed)) {
                    resetHuman()
                  }
                }}
              >
                <fieldset className="register-fieldset">
                  <legend className="register-legend">{t('page.sectionAccount')}</legend>
                  <div className="register-grid">
                    <Form.Item
                      name="username"
                      label={t('fields.username')}
                      extra={t('page.usernameHint')}
                      rules={[{
                        validator: (_, value: string | undefined) =>
                          value && usernamePattern.test(value.trim().toLowerCase())
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('validation.username'))),
                      }]}
                    >
                      <Input autoComplete="username" aria-label={t('fields.username')} />
                    </Form.Item>
                    <Form.Item
                      name="display_name"
                      label={t('fields.displayName')}
                      extra={t('page.displayNameHint')}
                      rules={[{
                        validator: (_, value: string | undefined) =>
                          value && Array.from(value.trim()).length >= 1 && Array.from(value.trim()).length <= 128
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('validation.displayName'))),
                      }]}
                    >
                      <Input autoComplete="name" aria-label={t('fields.displayName')} />
                    </Form.Item>
                    <Form.Item
                      className="register-span"
                      name="password"
                      label={t('fields.password')}
                      rules={[{
                        validator: (_, value: string | undefined) => {
                          const unmet = checkPassword(value ?? '')
                          return unmet.length === 0
                            ? Promise.resolve()
                            : Promise.reject(new Error(passwordPolicyMessage(unmet, passwordPolicyLocale(locale))))
                        },
                      }]}
                    >
                      <PasswordStrengthPopover locale={passwordPolicyLocale(locale)}>
                        <Input.Password autoComplete="new-password" aria-label={t('fields.password')} />
                      </PasswordStrengthPopover>
                    </Form.Item>
                  </div>
                </fieldset>

                <fieldset className="register-fieldset">
                  <legend className="register-legend">{t('page.sectionContact')}</legend>
                  <p className="register-human-hint register-contact-hint">{t('page.contactHint')}</p>
                  <div className="register-grid">
                    <Form.Item
                      name="email"
                      label={t('fields.email')}
                      rules={[{ required: true, type: 'email', message: t('validation.email') }]}
                    >
                      <Input inputMode="email" autoComplete="email" aria-label={t('fields.email')} />
                    </Form.Item>
                    <Form.Item
                      name="phone"
                      label={t('fields.phone')}
                      rules={[{
                        validator: (_, value: string | undefined) =>
                          value && phonePattern.test(value.trim())
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('validation.phone'))),
                      }]}
                    >
                      <Input inputMode="tel" autoComplete="tel" aria-label={t('fields.phone')} />
                    </Form.Item>
                    {mode === 'verified' && channels.length < 2 ? <Form.Item hidden name="verification_channel"><Input /></Form.Item> : null}
                    {mode === 'verified' && channels.length > 1 ? <Form.Item className="register-span" name="verification_channel" label={t('fields.channel')}>
                      <Radio.Group
                        optionType="button"
                        buttonStyle="solid"
                        options={channels.map((channel) => ({ value: channel, label: t(`channels.${channel}`) }))}
                      />
                    </Form.Item> : null}
                  </div>
                </fieldset>

                <fieldset className="register-fieldset">
                  <legend className="register-legend">{t('page.sectionVerify')}</legend>
                  {mode === 'builtin' ? <Form.Item label={t('fields.captcha')} required>
                    <LoginCaptchaField resetKey={captchaReset} disabled={pending} onChange={setCaptcha} />
                  </Form.Item> : null}
                  {mode === 'verified' ? <Form.Item>
                    <TurnstileWidget
                      adapter={turnstileAdapter}
                      label={t('states.humanRequired')}
                      language={locale}
                      resetKey={turnstileResetKey}
                      siteKey={turnstileSiteKey}
                      onToken={(token) => {
                        setHumanToken(token)
                        setHumanWasSolved(true)
                        setTurnstileUnavailable(false)
                      }}
                      onExpired={resetHuman}
                      onError={() => {
                        setHumanToken('')
                        setTurnstileUnavailable(true)
                      }}
                    />
                    {!humanToken ? <div className="register-human-hint">{t('states.humanRequired')}</div> : null}
                  </Form.Item> : null}
                  <Form.Item
                    name="terms_accepted"
                    valuePropName="checked"
                    rules={[{
                      validator: (_, value: boolean | undefined) => value
                        ? Promise.resolve()
                        : Promise.reject(new Error(t('validation.terms'))),
                    }]}
                  >
                    <Checkbox>{t('fields.terms', { version: accountRegistrationTermsVersion })}</Checkbox>
                  </Form.Item>
                </fieldset>

                <Form.Item className="register-submit register-actions">
                  <Button
                    type="primary"
                    htmlType="submit"
                    block
                    loading={stage === 'challenge-pending'}
                    disabled={mode === null || retrySeconds > 0 || (mode === 'verified' && humanWasSolved && !humanToken) ||
                      (mode === 'builtin' && !captcha)}
                  >
                    {t(mode === 'builtin' ? 'actions.register' : 'actions.sendCode')}
                  </Button>
                </Form.Item>
              </Form>
            ) : null}

            {session && verifying ? (
              <div className="register-state register-enter">
                <span className={`register-state-icon${expired ? ' is-warning' : ''}`} aria-hidden="true">
                  {expired ? <TriangleAlert size={24} strokeWidth={1.6} /> : <MailCheck size={24} strokeWidth={1.6} />}
                </span>
                <h2 className="register-state-title">{t('page.otpTitle')}</h2>
                <Alert type={expired ? 'warning' : 'success'} showIcon message={t(expired ? 'states.expired' : 'states.deliveryQueued')} />
                {!expired ? (
                  <ul className="register-meta">
                    <li>{t('states.expiresAt', {
                      value: new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(expiresAt),
                    })}</li>
                    <li>{t('states.cooldown', { seconds: secondsRemaining })}</li>
                    <li>{t('states.remainingAttempts', { count: remainingAttempts })}</li>
                  </ul>
                ) : null}
                <Form<VerificationForm>
                  form={otpForm}
                  className="register-otp-form register-actions"
                  layout="vertical"
                  requiredMark={false}
                  disabled={stage === 'verification-pending'}
                  onFinish={submitVerification}
                >
                  <Form.Item
                    name="otp"
                    label={t('fields.otp')}
                    rules={[{
                      validator: (_, value: string | undefined) => value && otpPattern.test(value)
                        ? Promise.resolve()
                        : Promise.reject(new Error(t('validation.otp'))),
                    }]}
                  >
                    <Input
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      aria-label={t('fields.otp')}
                    />
                  </Form.Item>
                  <Button
                    type="primary"
                    htmlType="submit"
                    block
                    loading={stage === 'verification-pending'}
                    disabled={expired || remainingAttempts === 0}
                  >
                    {t('actions.verifyAndRegister')}
                  </Button>
                  {expired ? <Button block onClick={startOver}>{t('actions.startOver')}</Button> : null}
                </Form>
              </div>
            ) : null}

            {stage === 'registration-pending' ? (
              <Alert className="register-enter" type="info" showIcon icon={<LoaderCircle className="register-spin" size={16} aria-hidden="true" />} message={t('states.registering')} />
            ) : null}

            {stage === 'unknown' ? (
              <div className="register-state register-enter">
                <span className="register-state-icon is-warning" aria-hidden="true"><TriangleAlert size={24} strokeWidth={1.6} /></span>
                <h2 className="register-state-title">{t('page.unknownTitle')}</h2>
                <div className="register-actions">
                  <Button type="primary" block onClick={retrySame}>{t('actions.retrySame')}</Button>
                  <Button block onClick={startOver}>{t('actions.startOver')}</Button>
                </div>
              </div>
            ) : null}

            {stage === 'failed' ? (
              <div className="register-state register-enter">
                <span className="register-state-icon is-warning" aria-hidden="true"><TriangleAlert size={24} strokeWidth={1.6} /></span>
                <h2 className="register-state-title">{t('page.failedTitle')}</h2>
                <p className="register-state-text">{t('page.failedText')}</p>
                <div className="register-actions">
                  <Button block onClick={startOver}>{t('actions.startOver')}</Button>
                </div>
              </div>
            ) : null}
          </section>
        </div>
      </main>
      {footerText ? <footer className="register-footer">{footerText}</footer> : null}
    </div>
  )
}
