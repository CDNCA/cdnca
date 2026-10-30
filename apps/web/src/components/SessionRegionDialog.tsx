import { useState } from 'react'
import { Alert, Form, Input, Modal } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError, verifySessionRegion } from '../api/auth'
import { logoutSession, useSessionStore } from '../auth/session'
import { localizedApiError } from '../i18n/apiError'
import '../i18n/sessionRegion'

// Session region binding: when the control plane refuses a request because
// the session's IP moved to another country/province, ask for the password
// and reload once the session is re-bound.
export function SessionRegionDialog({ open, onVerified }: { open: boolean, onVerified: () => void }) {
  const { t } = useTranslation('sessionRegion')
  const accessToken = useSessionStore(state => state.accessToken)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const submit = async () => {
    if (!accessToken || !password) return
    setBusy(true)
    setError(null)
    try {
      await verifySessionRegion(accessToken, password)
      onVerified()
      setPassword('')
      window.location.reload()
    } catch (caught) {
      setError(caught)
    } finally {
      setBusy(false)
    }
  }
  const errorText = (caught: unknown) => caught instanceof ApiError && caught.code === 'invalid_credentials' ? t('wrongPassword') : localizedApiError(caught)

  // The only way out without the password is signing out (every dialog can be left).
  return (
    <Modal open={open} title={t('title')} okText={t('confirm')} confirmLoading={busy}
      okButtonProps={{ disabled: !password }} closable={false} maskClosable={false} keyboard={false}
      cancelText={t('logout')} cancelButtonProps={{ disabled: busy }} onCancel={() => void logoutSession()}
      onOk={() => void submit()}>
      <p>{t('body')}</p>
      <Form layout="vertical" onFinish={() => void submit()}>
        <Form.Item label={t('password')}>
          <Input.Password autoFocus autoComplete="current-password" aria-label={t('password')} value={password}
            onChange={event => setPassword(event.target.value)} />
        </Form.Item>
      </Form>
      {error ? <Alert type="error" showIcon message={errorText(error)} /> : null}
    </Modal>
  )
}
