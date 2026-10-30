import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Form, Input, Radio, Space } from 'antd'
import { useTranslation } from 'react-i18next'

import {
  AccountRegistrationApiError,
  accountRegistrationApi,
  type AccountRegistrationChallengeRequest,
  type AccountRegistrationChallengeResult,
  type AccountRegistrationChallengeVerificationRequest,
  type AccountRegistrationRequest,
  type AccountRegistrationRequestMetadata,
  type AccountRegistrationResult,
  type AccountRegistrationVerificationChannel,
} from '../api/accountRegistration'
import { ApiError } from '../api/auth'
import { checkPassword, passwordPolicyLocale, passwordPolicyMessage } from '@cdnca/ui/password-policy'
import { PasswordStrengthPopover } from '@cdnca/ui'
import '../i18n/accountRegistration'
import { AccountRecoveryLayout } from './account-recovery/shared'
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

  const submitChallenge = (values: AccountRegistrationForm) => {
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
    if (attemptRef.current) void runAttempt(attemptRef.current)
  }

  const expiresAt = session ? Date.parse(session.challenge.expires_at) : 0
  const secondsRemaining = session ? Math.max(0, Math.ceil((expiresAt - now) / 1000)) : 0
  const expired = session !== null && secondsRemaining === 0
  const retrySeconds = retryAt ? Math.max(0, Math.ceil((retryAt - now) / 1000)) : 0
  const pending = stage.endsWith('-pending')
  const locale = i18n.resolvedLanguage?.toLowerCase().startsWith('qps')
    ? 'en-US'
    : i18n.resolvedLanguage ?? 'zh-CN'

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

  return (
    <AccountRecoveryLayout title={t('title')}>
      <div className="recovery-tab">{t('title')}</div>
      {errorMessage ? <Alert className="recovery-alert" type="error" showIcon message={errorMessage} /> : null}
      {turnstileUnavailable && stage === 'details' ? (
        <Alert className="recovery-alert" type="warning" showIcon message={t('errors.turnstileUnavailable')} />
      ) : null}

      {stage === 'accepted' && accepted ? (
        <div className="recovery-result" role="status">
          <Alert
            type="success"
            showIcon
            message={t(accepted.replayed ? 'states.replayed' : 'states.pendingVerification')}
          />
        </div>
      ) : null}

      {stage === 'details' || stage === 'challenge-pending' ? (
        <Form<AccountRegistrationForm>
          form={form}
          className="recovery-form"
          name="account-registration"
          aria-label={t('title')}
          layout="vertical"
          requiredMark={false}
          initialValues={{ verification_channel: 'email', terms_accepted: false }}
          disabled={pending || retrySeconds > 0}
          onFinish={submitChallenge}
          onValuesChange={(changed) => {
            if (humanToken && ['username', 'email', 'phone', 'verification_channel'].some((key) => key in changed)) {
              resetHuman()
            }
          }}
        >
          <Form.Item
            name="username"
            label={t('fields.username')}
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
          <Form.Item
            name="email"
            label={t('fields.email')}
            rules={[{ required: true, type: 'email', message: t('validation.email') }]}
          >
            <Input autoComplete="email" aria-label={t('fields.email')} />
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
            <Input autoComplete="tel" aria-label={t('fields.phone')} />
          </Form.Item>
          <Form.Item name="verification_channel" label={t('fields.channel')}>
            <Radio.Group
              optionType="button"
              buttonStyle="solid"
              options={[
                { value: 'email', label: t('channels.email') },
                { value: 'sms', label: t('channels.sms') },
              ]}
            />
          </Form.Item>
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
          <Form.Item>
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
            {!humanToken ? <div>{t('states.humanRequired')}</div> : null}
          </Form.Item>
          <Form.Item className="recovery-submit-item">
            <Button
              type="primary"
              htmlType="submit"
              block
              loading={stage === 'challenge-pending'}
              disabled={retrySeconds > 0 || (humanWasSolved && !humanToken)}
            >
              {t('actions.sendCode')}
            </Button>
          </Form.Item>
        </Form>
      ) : null}

      {session && ['otp', 'verification-pending'].includes(stage) ? (
        <Space direction="vertical" size="small" style={{ width: '100%' }}>
          <Alert type={expired ? 'warning' : 'success'} showIcon message={t(expired ? 'states.expired' : 'states.deliveryQueued')} />
          {!expired ? (
            <>
              <div>{t('states.expiresAt', {
                value: new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(expiresAt),
              })}</div>
              <div>{t('states.cooldown', { seconds: secondsRemaining })}</div>
              <div>{t('states.remainingAttempts', { count: remainingAttempts })}</div>
            </>
          ) : null}
          <Form<VerificationForm>
            form={otpForm}
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
          </Form>
          {expired ? <Button block onClick={startOver}>{t('actions.startOver')}</Button> : null}
        </Space>
      ) : null}

      {stage === 'registration-pending' ? (
        <Alert type="info" showIcon message={t('states.registering')} />
      ) : null}

      {stage === 'unknown' ? (
        <Space direction="vertical" size="small" style={{ width: '100%' }}>
          <Button type="primary" block onClick={retrySame}>{t('actions.retrySame')}</Button>
          <Button block onClick={startOver}>{t('actions.startOver')}</Button>
        </Space>
      ) : null}

      {stage === 'failed' ? (
        <Button block onClick={startOver}>{t('actions.startOver')}</Button>
      ) : null}
    </AccountRecoveryLayout>
  )
}
