import { useState } from 'react'
import { Alert, Button, Form, Input, Modal } from 'antd'
import { useFormSubmitError } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { usersApi } from '../api/users'
import { logoutSession, useSessionStore } from '../auth/session'
import { localizedApiError } from '../i18n/apiError'
import '../i18n/passwordChange'
import { PASSWORD_POLICY_HINT, passwordPolicyLocale, passwordPolicyRule } from '@cdnca/ui/password-policy'

// "Change the password at the next sign-in": an administrator required it,
// so the control plane refuses everything but the password change (403
// password_change_required). Ask for the current and a new password; the
// change signs the user out everywhere, so continue with a fresh sign-in.
const passwordFieldMap = { current_password: 'current', new_password: 'next' }

export function PasswordChangeDialog({ open, onChanged }: { open: boolean, onChanged: () => void }) {
  const { t, i18n } = useTranslation('passwordChange')
  const policyLocale = passwordPolicyLocale(i18n.resolvedLanguage)
  const accessToken = useSessionStore(state => state.accessToken)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [form] = Form.useForm<{ current: string, next: string, confirm: string }>()
  // A refused request field is marked under its box (fix-fielderr-be3).
  const markError = useFormSubmitError(form, passwordFieldMap)

  const submit = async (values: { current: string, next: string }) => {
    if (!accessToken) return
    setBusy(true)
    setError(null)
    try {
      await usersApi.changePassword(accessToken, { current_password: values.current, new_password: values.next })
      onChanged()
      await logoutSession()
    } catch (caught) {
      if (!markError(caught)) setError(caught)
    } finally {
      setBusy(false)
    }
  }
  const errorText = (caught: unknown) => caught instanceof ApiError && caught.code === 'invalid_credentials'
    ? t('wrongPassword') : caught instanceof ApiError && caught.code === 'validation_error' ? t('invalid') : localizedApiError(caught)

  return (
    <Modal open={open} title={t('title')} closable={false} maskClosable={false} keyboard={false}
      footer={[
        <Button key="logout" onClick={() => void logoutSession()}>{t('logout')}</Button>,
        <Button key="submit" type="primary" loading={busy} onClick={() => form.submit()}>{t('submit')}</Button>,
      ]}>
      <p>{t('body')}</p>
      <Form form={form} layout="vertical" onFinish={values => void submit(values)}>
        <Form.Item name="current" label={t('current')} rules={[{ required: true }]}>
          <Input.Password autoFocus autoComplete="current-password" />
        </Form.Item>
        <Form.Item name="next" label={t('next')} extra={PASSWORD_POLICY_HINT[policyLocale]} rules={[{ required: true }, passwordPolicyRule(policyLocale)]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item name="confirm" label={t('confirm')} dependencies={['next']} rules={[{ required: true },
          ({ getFieldValue }) => ({ validator: (_, value) => !value || value === getFieldValue('next') ? Promise.resolve() : Promise.reject(new Error(t('mismatch'))) })]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
      </Form>
      {error ? <Alert type="error" showIcon message={errorText(error)} /> : null}
    </Modal>
  )
}
