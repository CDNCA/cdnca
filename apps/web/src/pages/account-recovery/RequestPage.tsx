import { useEffect, useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Alert, Button, Form, Input } from 'antd'
import { UserRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  accountRecoveryApi,
  AccountRecoveryApiError,
  type AccountRecoveryRequest,
} from '../../api/accountRecovery'
import { localizedApiError } from '../../i18n/apiError'
import {
  isUnknownResult,
  keyForAttempt,
  utf8Length,
  type RecoveryAttempt,
} from './helpers'
import { AccountRecoveryLayout } from './shared'
import { FeedbackWhen } from '@cdnca/ui'

export function AccountRecoveryRequestPage() {
  const { t } = useTranslation('auth')
  const [accepted, setAccepted] = useState(false)
  const [retryAt, setRetryAt] = useState<number | null>(null)
  const attempt = useRef<RecoveryAttempt<AccountRecoveryRequest> | null>(null)

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
    mutationFn: (input: AccountRecoveryRequest) => {
      const key = keyForAttempt(attempt, 'request', input)
      return accountRecoveryApi.request(attempt.current!.body, key)
    },
    onSuccess: () => {
      attempt.current = null
      setRetryAt(null)
      setAccepted(true)
    },
    onError: (error) => {
      if (error instanceof AccountRecoveryApiError && error.retryAfterSeconds !== null) {
        setRetryAt(Date.now() + error.retryAfterSeconds * 1000)
      }
      if (!isUnknownResult(error)) attempt.current = null
    },
  })
  const retryLocked = mutation.error !== null && isUnknownResult(mutation.error)
  const abandonUnknown = () => {
    attempt.current = null
    setRetryAt(null)
    mutation.reset()
  }

  return (
    <AccountRecoveryLayout title={t('recovery.requestPageTitle')}>
      <div className="recovery-tab">{t('recovery.requestTab')}</div>

      {mutation.error ? (
        <FeedbackWhen title={localizedApiError(mutation.error)} />
      ) : null}

      {!accepted ? (
        <Form<AccountRecoveryRequest>
          className="recovery-form"
          layout="vertical"
          requiredMark={false}
          onFinish={(values) => mutation.mutate({ username: values.username.trim() })}
        >
          <Form.Item
            name="username"
            rules={[
              {
                validator(_, value: string | undefined) {
                  if (!value || value.trim() === '') {
                    return Promise.reject(new Error(t('recovery.usernameRequired')))
                  }
                  return utf8Length(value.trim()) <= 1024
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('recovery.usernameTooLong')))
                },
              },
            ]}
          >
            <Input
              autoComplete="username"
              prefix={<UserRound size={15} strokeWidth={1.4} aria-hidden="true" />}
              placeholder={t('recovery.usernamePlaceholder')}
              aria-label={t('recovery.usernameLabel')}
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
              {t('recovery.sendInstructions')}
            </Button>
          </Form.Item>
          {retryLocked ? (
            <Form.Item className="recovery-submit-item">
              <Button block onClick={abandonUnknown}>
                {t('recovery.requestAgain')}
              </Button>
            </Form.Item>
          ) : null}
        </Form>
      ) : (
        <div className="recovery-result" role="status">
          <Alert type="success" showIcon message={t('recovery.accepted')} />
          <Button
            block
            onClick={() => {
              mutation.reset()
              setAccepted(false)
            }}
          >
            {t('recovery.requestAgain')}
          </Button>
        </div>
      )}
    </AccountRecoveryLayout>
  )
}
