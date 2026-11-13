import { useMemo, useState } from 'react'
import { Alert, Button, Form, Input, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link, useLocation } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { tenantMembersApi } from '../api/tenantMembers'
import { localizedApiError } from '../i18n/apiError'
import { memberInvitationAcceptMessages } from '../i18n/tenantMembers'
import { AccountRecoveryLayout } from './account-recovery/shared'
import { FeedbackWhen } from '@cdnca/ui'

interface AcceptValues {
  username: string
  display_name: string
  password: string
}

// Public page behind the invitation mail link (/accept-invitation#token=...).
// The token stays in the fragment so it never reaches server logs.
export default function MemberInvitationAcceptPage() {
  const { t } = useTranslation('memberInvitationAccept')
  const location = useLocation()
  const token = useMemo(() => new URLSearchParams(location.hash.replace(/^#/, '')).get('token') ?? '', [location.hash])
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const errorText = (caught: unknown) => caught instanceof ApiError && Object.hasOwn(memberInvitationAcceptMessages['zh-CN'].errors, caught.code)
    ? t(`errors.${caught.code}`) : localizedApiError(caught)
  const submit = async (values: AcceptValues) => {
    setBusy(true)
    try {
      await tenantMembersApi.acceptInvitation({ token, ...values })
      setDone(true)
      setError(null)
    } catch (caught) {
      setError(caught)
    } finally {
      setBusy(false)
    }
  }

  return (
    <AccountRecoveryLayout title={t('title')}>
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      {!token ? <Alert type="warning" showIcon message={t('missing')} /> : done ? (
        <Alert type="success" showIcon message={t('done')} action={<Link to="/login">{t('login')}</Link>} />
      ) : (
        <>
          <Typography.Paragraph>{t('intro')}</Typography.Paragraph>
          {error ? <FeedbackWhen title={errorText(error)} /> : null}
          <Form<AcceptValues> layout="vertical" onFinish={values => void submit(values)}>
            <Form.Item name="username" label={t('username')} rules={[{ required: true, min: 3, max: 128 }]}><Input autoComplete="username" /></Form.Item>
            <Form.Item name="display_name" label={t('displayName')} rules={[{ required: true, max: 128 }]}><Input autoComplete="name" /></Form.Item>
            <Form.Item name="password" label={t('password')} rules={[{ required: true, min: 12, max: 1024 }]}><Input.Password autoComplete="new-password" /></Form.Item>
            <Button type="primary" htmlType="submit" loading={busy} block>{t('submit')}</Button>
          </Form>
        </>
      )}
    </AccountRecoveryLayout>
  )
}
