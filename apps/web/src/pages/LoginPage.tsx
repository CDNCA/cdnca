import { useEffect, useRef, useState } from 'react'
import { Alert, App, Button, Form, Input } from 'antd'
import { LockKeyhole, UserRound } from 'lucide-react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { ApiError, type AuthResponse, type LoginRequest, type LoginVerificationRequirement } from '../api/auth'
import { loginCaptchaConfig, passwordLoginMetadata, PasswordLoginChallengeError, sendPasswordLoginChallenge, type LoginCaptchaConfig, type PasswordLoginChallengeInput, type PasswordLoginChallengeReceipt, type PasswordLoginMetadata } from '../api/passwordLoginChallenge'
import { passwordLoginChallengeMessages } from '../i18n/passwordLoginChallenge'
import { TurnstileWidget } from './registration/TurnstileWidget'
import { browserTurnstileAdapter } from './registration/turnstileAdapter'
import { ExternalCaptchaWidget } from './login/ExternalCaptchaWidget'
import { LoginCaptchaField } from './login/LoginCaptchaField'
import { loginCaptchaNeeded } from '../api/loginCaptcha'
import { registrationAvailable } from '../api/registrationAvailability'
import { publicBranding } from '../api/publicBranding'
import { browserExternalCaptchaAdapter } from './login/externalCaptcha'
import { loginDestination, safeLoginReturnTo } from '../auth/loginNavigation'
import { homeForPrincipal, hydrateLoginSession, loginSession, useSessionStore } from '../auth/session'
import { localizedApiError } from '../i18n/apiError'
import { LanguageMenu } from '../components/LanguageMenu'
import { PublicBrandAssetImage } from '../components/PublicBrandAssetImage'
import { localizedText } from '../api/theme'
import { useBrandName, useThemeRuntime } from '../theme/runtime'
import { useAuthStyle } from '../theme/authStyle'
import { FeedbackWhen } from '@cdnca/ui'

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const passwordChanged = (location.state as { passwordChanged?: boolean } | null)?.passwordChanged
  const returnTo = passwordChanged ? null : safeLoginReturnTo(location.state)
  const { message } = App.useApp()
  const { t } = useTranslation('auth')
  const { t: commonT } = useTranslation('common')

  const [form] = Form.useForm<LoginRequest & { otp?: string }>()
  const [requirement, setRequirement] = useState<LoginVerificationRequirement | null>(null)
  const [receipt, setReceipt] = useState<PasswordLoginChallengeReceipt | null>(null)
  const [busy, setBusy] = useState<'login' | 'send' | null>(null)
  const [unknownKind, setUnknownKind] = useState<'login' | 'send' | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [sent, setSent] = useState(false)
  const [retryAt, setRetryAt] = useState(0)
  const [now, setNow] = useState(Date.now)
  const [humanRequired, setHumanRequired] = useState(false)
  const [humanToken, setHumanToken] = useState('')
  // null: Turnstile; set when the challenge channel uses Tencent or GeeTest (system settings).
  const [captcha, setCaptcha] = useState<LoginCaptchaConfig | null>(null)
  const [humanReset, setHumanReset] = useState(0)
  // Built-in sign-in CAPTCHA (identity login throttle).
  const [captchaShown, setCaptchaShown] = useState(false)
  const [captchaAnswer, setCaptchaAnswer] = useState<{ id: string; answer: string } | null>(null)
  const [captchaReset, setCaptchaReset] = useState(0)
  const active = useRef(true)
  const version = useRef(0)
  const inFlight = useRef(false)
  const sendAttempt = useRef<{ input: PasswordLoginChallengeInput; metadata: PasswordLoginMetadata; controller: AbortController } | null>(null)
  const loginAttempt = useRef<{ input: LoginRequest; key?: string; response?: AuthResponse; controller: AbortController } | null>(null)
  const sessionEpoch = useSessionStore(state => state.sessionEpoch)
  const { t: challengeT, i18n } = useTranslation('passwordLoginChallenge')
  // vis-1: the sign-up link only when the server says registration is open.
  const [canRegister, setCanRegister] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    void registrationAvailable(controller.signal).then(value => { if (!controller.signal.aborted) setCanRegister(value) })
    return () => controller.abort()
  }, [])
  // 登录页匿名读系统配置的系统名称；主题设了名称仍以主题为准（useBrandName）。
  const [systemName, setSystemName] = useState<string>()
  useEffect(() => {
    const controller = new AbortController()
    void publicBranding(controller.signal).then(value => { if (!controller.signal.aborted && value) setSystemName(value.systemName) })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (passwordChanged) useSessionStore.getState().clearSession()
  }, [passwordChanged])
  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
      version.current += 1
      sendAttempt.current?.controller.abort()
      loginAttempt.current?.controller.abort()
      sendAttempt.current = null
      loginAttempt.current = null
    }
  }, [])
  useEffect(() => {
    form.resetFields()
    inFlight.current = false
    sendAttempt.current?.controller.abort()
    loginAttempt.current?.controller.abort()
    sendAttempt.current = null
    loginAttempt.current = null
    setRequirement(null)
    setReceipt(null)
    setHumanToken('')
    setHumanRequired(false)
    setCaptcha(null)
    setSent(false)
    setUnknownKind(null)
    setBusy(null)
    setError(null)
    setRetryAt(0)
    setHumanReset(value => value + 1)
    setCaptchaShown(false)
    setCaptchaAnswer(null)
  }, [form, sessionEpoch])
  useEffect(() => {
    if (retryAt <= Date.now()) return
    const timer = window.setInterval(() => {
      setNow(Date.now())
      if (Date.now() >= retryAt) window.clearInterval(timer)
    }, 1000)
    return () => window.clearInterval(timer)
  }, [retryAt])

  const isCurrent = (revision: number, epoch: number) => active.current && version.current === revision &&
    useSessionStore.getState().sessionEpoch === epoch
  const unknown = (caught: unknown) => !(caught instanceof ApiError) || caught.status === 0 ||
    caught.status === 408 || caught.status >= 500 || caught.code === 'invalid_response'
  const resetChallenge = () => {
    version.current += 1
    inFlight.current = false
    sendAttempt.current?.controller.abort()
    loginAttempt.current?.controller.abort()
    sendAttempt.current = null
    loginAttempt.current = null
    setRequirement(null)
    setReceipt(null)
    setUnknownKind(null)
    setError(null)
    setSent(false)
    setBusy(null)
    setRetryAt(0)
    setHumanToken('')
    setHumanRequired(false)
    setCaptcha(null)
    setHumanReset(value => value + 1)
    form.setFieldValue('otp', undefined)
  }
  const errorText = (caught: unknown) => {
    if (caught instanceof ApiError && Object.hasOwn(passwordLoginChallengeMessages['zh-CN'].errors, caught.code)) {
      return challengeT(`errors.${caught.code}`, { minutes: Math.max(1, Math.ceil((caught.retryAfter ?? 3600) / 60)) })
    }
    return caught instanceof ApiError && caught.code === 'invalid_session'
      ? commonT('sessionRefreshFailed') : localizedApiError(caught)
  }
  // Every answered CAPTCHA is consumed by the server; show the next one when
  // the server still needs it, and remember that it needs one.
  const afterAttempt = (caught: unknown, carried: boolean) => {
    if (loginCaptchaNeeded(caught)) setCaptchaShown(true)
    if (carried || loginCaptchaNeeded(caught)) {
      setCaptchaAnswer(null)
      setCaptchaReset(value => value + 1)
    }
  }
  const submit = async (values: LoginRequest & { otp?: string }) => {
    if (inFlight.current) return
    if (requirement && !loginAttempt.current && (!receipt || Date.parse(receipt.expires_at) <= Date.now())) {
      setError(new ApiError('Login challenge is unavailable', 401, 'account_login_verification_invalid'))
      return
    }
    const revision = version.current, epoch = useSessionStore.getState().sessionEpoch
    inFlight.current = true
    setBusy('login')
    setError(null)
    try {
      const attempt = loginAttempt.current ?? {
        input: {
          username: values.username, password: values.password,
          ...(captchaShown && captchaAnswer && !(requirement && receipt) ? { captcha: captchaAnswer } : {}),
          ...(requirement && receipt ? {
            scope_id: requirement.scope_id,
            login_challenge: { challenge_id: receipt.challenge_id, otp: values.otp ?? '' },
          } : {}),
        },
        key: requirement ? passwordLoginMetadata().idempotencyKey : undefined,
        controller: new AbortController(),
      }
      loginAttempt.current = attempt
      const canApply = () => isCurrent(revision, epoch)
      const principal = attempt.response
        ? await hydrateLoginSession(attempt.response, canApply, attempt.controller.signal)
        : await loginSession(attempt.input, attempt.key, canApply, response => {
            if (isCurrent(revision, epoch)) attempt.response = response
          }, attempt.controller.signal)
      if (!active.current || version.current !== revision) return
      loginAttempt.current = null
      sendAttempt.current = null
      form.resetFields()
      setHumanToken('')
      message.success(t('loginSuccess'))
      navigate(loginDestination(returnTo, homeForPrincipal(principal)), { replace: true })
    } catch (caught) {
      if (!isCurrent(revision, epoch)) return
      if (caught instanceof ApiError && caught.code === 'login_verification_required' && caught.params) {
        setRequirement(caught.params)
        setReceipt(null)
        form.setFieldValue('otp', undefined)
        sendAttempt.current = null
        loginAttempt.current = null
        setUnknownKind(null)
        setSent(false)
        return
      }
      afterAttempt(caught, Boolean(loginAttempt.current?.input.captcha))
      const uncertain = Boolean(requirement && unknown(caught))
      if (!uncertain) loginAttempt.current = null
      setUnknownKind(uncertain ? 'login' : null)
      if (caught instanceof ApiError && caught.code === 'account_login_verification_invalid') {
        loginAttempt.current = null
        sendAttempt.current = null
        setReceipt(null)
        setSent(false)
        setUnknownKind(null)
        form.setFieldValue('otp', undefined)
      }
      setError(caught)
    } finally {
      if (isCurrent(revision, epoch)) {
        inFlight.current = false
        setBusy(null)
      }
    }
  }
  const sendCode = async () => {
    if (!requirement || inFlight.current || retryAt > Date.now()) return
    const revision = version.current, epoch = useSessionStore.getState().sessionEpoch
    inFlight.current = true
    setBusy('send')
    setError(null)
    setSent(false)
    try {
      const values = await form.validateFields(['username', 'password'])
      if (!isCurrent(revision, epoch)) return
      const attempt = sendAttempt.current ?? {
        input: {
          username: values.username, password: values.password, scope_id: requirement.scope_id,
          ...(humanToken ? { human_token: humanToken } : {}),
          ...(captchaShown && captchaAnswer ? { captcha: captchaAnswer } : {}),
        },
        metadata: passwordLoginMetadata(),
        controller: new AbortController(),
      }
      sendAttempt.current = attempt
      setReceipt(null)
      loginAttempt.current = null
      form.setFieldValue('otp', undefined)
      const result = await sendPasswordLoginChallenge(attempt.input, attempt.metadata, attempt.controller.signal)
      if (!isCurrent(revision, epoch)) return
      sendAttempt.current = null
      setReceipt(result)
      setUnknownKind(null)
      setSent(true)
      setHumanToken('')
      setHumanReset(value => value + 1)
    } catch (caught) {
      if (!isCurrent(revision, epoch)) return
      afterAttempt(caught, Boolean(sendAttempt.current?.input.captcha))
      const uncertain = unknown(caught)
      if (!uncertain) sendAttempt.current = null
      setUnknownKind(uncertain ? 'send' : null)
      setError(caught)
      if (caught instanceof PasswordLoginChallengeError && caught.retryAfterSeconds) {
        setNow(Date.now())
        setRetryAt(Date.now() + caught.retryAfterSeconds * 1000)
      }
      if (caught instanceof ApiError && ['account_login_human_verification_required', 'account_login_human_verification_invalid'].includes(caught.code)) {
        setHumanRequired(true)
        setHumanToken('')
        setHumanReset(value => value + 1)
        void loginCaptchaConfig(requirement.channel).catch(() => null).then(config => {
          if (isCurrent(revision, epoch)) setCaptcha(config)
        })
      }
    } finally {
      if (isCurrent(revision, epoch)) {
        inFlight.current = false
        setBusy(null)
      }
    }
  }
  const retrySeconds = Math.max(0, Math.ceil((retryAt - now) / 1000))
  // PA-17 layout slots: login layout variant and footer text.
  const { layout } = useThemeRuntime()
  // Theme plugin C: the user console plugin's sign-in page CSS (style only).
  useAuthStyle()
  const footerText = localizedText(layout.footer_text, i18n.resolvedLanguage ?? 'zh-CN')
  const brandName = useBrandName(i18n.resolvedLanguage ?? 'zh-CN', systemName)

  return (
    <div className={`login-page is-layout-${layout.login_layout}`}>
      {layout.login_layout === 'background' ? (
        <PublicBrandAssetImage className="login-background" slot="login_background" alt="" />
      ) : null}
      <header className="login-header">
        <PublicBrandAssetImage slot="logo" alt={brandName} />
        <LanguageMenu className="login-language-trigger" />
      </header>
      <main className="login-stage">
        <section className="login-container" aria-labelledby="login-title">
          {layout.login_layout === 'split' ? (
            <div className="login-ad" aria-hidden="true">
              <PublicBrandAssetImage slot="login_ad" alt="" />
            </div>
          ) : null}
          <div className="login-panel">
            <h1 id="login-title">{brandName}</h1>
            {passwordChanged ? (
              <Alert className="login-notice" type="success" showIcon message={t('passwordChanged')} />
            ) : null}
            {error ? <FeedbackWhen title={errorText(error)} /> : null}
            <Form<LoginRequest & { otp?: string }>
              className="login-form"
              form={form}
              clearOnDestroy
              layout="vertical"
              requiredMark={false}
              onFinish={(values) => void submit(values)}
              onValuesChange={(changed) => {
                if ('username' in changed || 'password' in changed) resetChallenge()
                else if ('otp' in changed) setError(null)
              }}
            >
              <Form.Item
                name="username"
                rules={[
                  { required: true, message: t('usernameRequired') },
                  { min: 3, message: t('usernameTooShort') },
                ]}
              >
                <Input
                  autoComplete="username"
                  prefix={<UserRound size={15} strokeWidth={1.4} aria-hidden="true" />}
                  placeholder={t('username')}
                  aria-label={t('username')}
                />
              </Form.Item>
              <Form.Item
                name="password"
                rules={[{ required: true, message: t('passwordRequired') }]}
              >
                <Input.Password
                  autoComplete="current-password"
                  prefix={<LockKeyhole size={15} strokeWidth={1.4} aria-hidden="true" />}
                  placeholder={t('passwordRequired')}
                  aria-label={t('password')}
                />
              </Form.Item>
              {captchaShown ? <Form.Item>
                <LoginCaptchaField resetKey={captchaReset} disabled={busy !== null} onChange={setCaptchaAnswer} />
              </Form.Item> : null}
              {requirement ? <>
                <Alert className="login-notice" type="info" showIcon message={challengeT(requirement.channel)} />
                {sent ? <Alert className="login-notice" type="success" message={challengeT('sent')} /> : null}
                {humanRequired && captcha ? <ExternalCaptchaWidget
                  adapter={browserExternalCaptchaAdapter}
                  config={captcha}
                  label={challengeT('human')}
                  doneLabel={challengeT('humanDone')}
                  unavailableLabel={challengeT('humanUnavailable')}
                  language={i18n.resolvedLanguage ?? 'zh-CN'}
                  resetKey={humanReset}
                  onToken={setHumanToken}
                  onError={() => setHumanToken('')}
                /> : humanRequired ? <TurnstileWidget
                  adapter={browserTurnstileAdapter}
                  label={challengeT('human')}
                  language={i18n.resolvedLanguage ?? 'zh-CN'}
                  resetKey={humanReset}
                  siteKey={import.meta.env.VITE_TURNSTILE_SITE_KEY ?? ''}
                  onToken={setHumanToken}
                  onExpired={() => setHumanToken('')}
                  onError={() => setHumanToken('')}
                /> : null}
                <Form.Item>
                  <Button block loading={busy === 'send'} disabled={busy !== null || retrySeconds > 0 || unknownKind === 'login' || (humanRequired && !humanToken)} onClick={() => void sendCode()}>
                    {retrySeconds ? challengeT('retryAfter', { seconds: retrySeconds }) : challengeT(unknownKind === 'send' ? 'retrySend' : 'send')}
                  </Button>
                </Form.Item>
                <Form.Item name="otp" preserve={false} rules={[
                  { required: true, message: challengeT('codeRequired') },
                  { pattern: /^\d{6}$/, message: challengeT('codeFormat') },
                ]}>
                  <Input.Password aria-label={challengeT('code')} placeholder={challengeT('code')} inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                    disabled={!receipt || busy !== null || unknownKind === 'login'} visibilityToggle={false} />
                </Form.Item>
              </> : null}
              <Form.Item className="login-submit-item">
                <Button
                  type="primary"
                  htmlType="submit"
                  block
                  loading={busy === 'login'}
                  disabled={busy === 'send' || Boolean(requirement && !receipt) || (captchaShown && !captchaAnswer && !(requirement && receipt))}
                >
                  {unknownKind === 'login' ? challengeT('retryLogin') : t('login')}
                </Button>
              </Form.Item>
              <div className="login-links">
                <Link to="/forgot-password">{t('forgotPassword')}</Link>
                {canRegister ? <Link to="/register">{t('register')}</Link> : null}
              </div>
            </Form>
          </div>
        </section>
      </main>
      {footerText ? <footer className="login-footer">{footerText}</footer> : null}
    </div>
  )
}
