import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Button, Form, Input } from 'antd'
import { LockKeyhole } from 'lucide-react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import {
  accountRecoveryApi,
  AccountRecoveryApiError,
  type AccountRecoveryConfirmation,
} from '../../api/accountRecovery'
import { useSessionStore } from '../../auth/session'
import { localizedApiError } from '../../i18n/apiError'
import {
  isUnknownResult,
  keyForAttempt,
  type RecoveryAttempt,
} from './helpers'
import { AccountRecoveryLayout } from './shared'
import { FeedbackWhen } from '@cdnca/ui'
import { PASSWORD_POLICY_HINT, passwordPolicyLocale, passwordPolicyRule } from '@cdnca/ui/password-policy'

interface ConfirmationValues {
  new_password: string
  confirm_password: string
}

interface RecoveryLink {
  token: string
  recoveryContext: string
}

const tokenPattern = /^[A-Za-z0-9_-]{43}$/
const contextPattern = /^[A-Za-z0-9_-]{162}$/

function recoveryLinkFromFragment(hash: string): RecoveryLink | null {
  const fragment = new URLSearchParams(hash.replace(/^#/, ''))
  const token = fragment.getAll('token')
  const recoveryContext = fragment.getAll('recovery_context')
  const knownKeys = [...fragment.keys()].every((key) =>
    key === 'token' || key === 'recovery_context')

  if (!knownKeys || token.length !== 1 || recoveryContext.length !== 1 ||
      !tokenPattern.test(token[0]) || !contextPattern.test(recoveryContext[0])) {
    return null
  }
  return { token: token[0], recoveryContext: recoveryContext[0] }
}

export function AccountRecoveryResetPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const { t, i18n } = useTranslation('auth')
  const policyLocale = passwordPolicyLocale(i18n.resolvedLanguage)
  const [form] = Form.useForm<ConfirmationValues>()
  const [link, setLink] = useState(() => recoveryLinkFromFragment(location.hash))
  const [retryAt, setRetryAt] = useState<number | null>(null)
  const [terminalError, setTerminalError] = useState<AccountRecoveryApiError | null>(null)
  const attempt = useRef<RecoveryAttempt<AccountRecoveryConfirmation> | null>(null)

  useLayoutEffect(() => {
    if (location.search !== '' || location.hash !== '') {
      window.history.replaceState(
        window.history.state,
        '',
        window.location.pathname,
      )
    }
  }, [location.hash, location.search])

  useEffect(() => {
    if (location.search !== '' || location.hash !== '') {
      void navigate({ pathname: location.pathname, search: '', hash: '' }, { replace: true })
    }
  }, [location.hash, location.pathname, location.search, navigate])

  useEffect(() => {
    if (retryAt === null) return
    const remaining = retryAt - Date.now()
    if (remaining <= 0) {
      setRetryAt(null)
      return
    }
    const timer = window.setTimeout(() => setRetryAt(null), remaining)
    return () => window.clearTimeout(timer)
  }, [retryAt])

  const mutation = useMutation({
    mutationFn: (values: ConfirmationValues) => {
      if (!link) return Promise.reject(new Error('Recovery link is unavailable'))
      const input = {
        token: link.token,
        recovery_context: link.recoveryContext,
        ...values,
      }
      const key = keyForAttempt(attempt, 'confirm', input)
      return accountRecoveryApi.confirm(attempt.current!.body, key)
    },
    onSuccess: () => {
      attempt.current = null
      setRetryAt(null)
      setTerminalError(null)
      setLink(null)
      useSessionStore.getState().clearSession()
      void navigate('/login', { replace: true, state: { passwordChanged: true } })
    },
    onError: (error) => {
      if (error instanceof AccountRecoveryApiError && (
        error.code === 'account_recovery_invalid_token' ||
        error.code === 'account_recovery_principal_changed'
      )) {
        attempt.current = null
        setRetryAt(null)
        setLink(null)
        setTerminalError(error)
        return
      }
      if (error instanceof AccountRecoveryApiError && error.retryAfterSeconds !== null) {
        setRetryAt(Date.now() + error.retryAfterSeconds * 1000)
      }
      if (!isUnknownResult(error)) attempt.current = null
    },
  })
  const retryLocked = mutation.error !== null && isUnknownResult(mutation.error)
  const abandonUnknown = () => {
    form.resetFields()
    attempt.current = null
    setRetryAt(null)
    setTerminalError(null)
    setLink(null)
    mutation.reset()
    void navigate('/forgot-password', { replace: true })
  }

  return (
    <AccountRecoveryLayout title={t('recovery.resetPageTitle')}>
      <div className="recovery-tab">{t('recovery.confirmTab')}</div>

      {mutation.error && terminalError === null ? (
        <FeedbackWhen title={localizedApiError(mutation.error)} />
      ) : null}

      {!link ? (
        <div className="recovery-result">
          <FeedbackWhen title={terminalError ? localizedApiError(terminalError) : t('recovery.invalidLink')} />
          <Link className="recovery-primary-link" to="/forgot-password">
            {t('recovery.requestNewLink')}
          </Link>
        </div>
      ) : (
        <Form<ConfirmationValues>
          form={form}
          className="recovery-form"
          layout="vertical"
          requiredMark={false}
          onFinish={(values) => mutation.mutate(values)}
        >
          <Form.Item
            name="new_password"
            rules={[
              { required: true, message: t('recovery.newPasswordRequired') },
              passwordPolicyRule(policyLocale),
            ]}
            extra={PASSWORD_POLICY_HINT[policyLocale]}
          >
            <Input.Password
              autoComplete="new-password"
              prefix={<LockKeyhole size={15} strokeWidth={1.4} aria-hidden="true" />}
              placeholder={t('recovery.newPasswordPlaceholder')}
              aria-label={t('recovery.newPasswordLabel')}
              disabled={mutation.isPending || retryAt !== null || retryLocked}
            />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('recovery.confirmPasswordRequired') },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  return !value || getFieldValue('new_password') === value
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('recovery.passwordMismatch')))
                },
              }),
            ]}
          >
            <Input.Password
              autoComplete="new-password"
              prefix={<LockKeyhole size={15} strokeWidth={1.4} aria-hidden="true" />}
              placeholder={t('recovery.confirmPasswordPlaceholder')}
              aria-label={t('recovery.confirmPasswordLabel')}
              disabled={mutation.isPending || retryAt !== null || retryLocked}
            />
          </Form.Item>
          <Form.Item className="recovery-submit-item">
            <Button
              type="primary"
              htmlType="submit"
              block
              loading={mutation.isPending}
              disabled={mutation.isPending || retryAt !== null}
            >
              {t('recovery.resetPassword')}
            </Button>
          </Form.Item>
          {retryLocked ? (
            <Form.Item className="recovery-submit-item">
              <Button block onClick={abandonUnknown}>
                {t('recovery.requestNewLink')}
              </Button>
            </Form.Item>
          ) : null}
        </Form>
      )}
    </AccountRecoveryLayout>
  )
}
