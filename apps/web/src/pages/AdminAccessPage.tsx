import { useCallback, useEffect, useState } from 'react'
import { Alert, App, Button, Card, Input, Space, Switch, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { adminAccessApi, parseAllowlist, type AdminAccessPolicy } from '../api/adminAccess'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { localizedApiError } from '../i18n/apiError'
import { adminAccessMessages } from '../i18n/adminAccess'
import { FeedbackWhen } from '@cdnca/ui'

// Platform administration access allowlist: who may
// reach the console, with the "do not lock yourself out" rules spelled out.
export default function AdminAccessPage() {
  const { t } = useTranslation('adminAccess')
  const { message, modal } = App.useApp()
  const accessToken = useSessionStore(state => state.accessToken)
  const principal = useSessionStore(state => state.principal)
  const canManage = Boolean(principal?.permissions.includes('system_configuration.manage') || principal?.permissions.includes('platform.admin'))
  const [policy, setPolicy] = useState<AdminAccessPolicy | null>(null)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [saveError, setSaveError] = useState<unknown>(null)
  const [enabled, setEnabled] = useState(false)
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)

  const apply = (value: AdminAccessPolicy) => {
    setPolicy(value)
    setEnabled(value.enabled)
    setText(value.allowlist.join('\n'))
  }
  const load = useCallback(async () => {
    if (!accessToken) return
    try {
      apply(await adminAccessApi.get(accessToken))
      setLoadError(null)
    } catch (caught) {
      setLoadError(caught)
    }
  }, [accessToken])
  useEffect(() => { void load() }, [load])

  const errorText = (caught: unknown) => caught instanceof ApiError && Object.hasOwn(adminAccessMessages['zh-CN'].errors, caught.code)
    ? t(`errors.${caught.code}`) : localizedApiError(caught)
  const save = async () => {
    if (!accessToken || !policy) return
    setBusy(true)
    setSaveError(null)
    try {
      apply(await adminAccessApi.update(accessToken, { expected_revision: policy.revision, enabled, allowlist: parseAllowlist(text) }))
      message.success(t('saved'))
    } catch (caught) {
      setSaveError(caught)
    } finally {
      setBusy(false)
    }
  }
  // W4: saving can lock the operator out, so it always asks first and names
  // the current IP that the allowlist must contain.
  const confirmSave = () => void modal.confirm({
    title: t('confirmTitle'),
    content: t('confirmContent', { ip: policy?.current_ip || t('confirmUnknownIP') }),
    okText: t('confirmOk'), cancelText: t('confirmCancel'), okButtonProps: { danger: true },
    onOk: () => save(),
  })
  const addCurrent = () => {
    if (policy?.current_ip && !parseAllowlist(text).includes(policy.current_ip)) {
      setText(value => (value.trim() ? `${value.trim()}\n` : '') + policy.current_ip)
    }
  }

  return (
    <div className="page-stack">
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      {loadError ? <DataState status="error" description={localizedApiError(loadError)} onRetry={() => void load()} />
        : !policy ? <DataState status="loading" /> : <Card>
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Typography.Paragraph>{t('intro')}</Typography.Paragraph>
            {policy.current_ip ? <Typography.Text>{t('currentIP', { ip: policy.current_ip })}</Typography.Text>
              : <Alert type="warning" showIcon message={t('currentUnknown')} />}
            <Space>
              <Switch checked={enabled} disabled={!canManage || busy} onChange={setEnabled} aria-label={t('enabled')} />
              <span>{t('enabled')}</span>
            </Space>
            <label htmlFor="admin-access-allowlist">{t('allowlist')}</label>
            <Input.TextArea id="admin-access-allowlist" rows={6} value={text} disabled={!canManage || busy}
              placeholder={t('allowlistPlaceholder')} onChange={event => setText(event.target.value)} />
            <Space>
              <Button disabled={!canManage || busy || !policy.current_ip} onClick={addCurrent}>{t('addCurrent')}</Button>
              <Button type="primary" loading={busy} disabled={!canManage} onClick={confirmSave}>{t('save')}</Button>
            </Space>
            {saveError ? <FeedbackWhen title={errorText(saveError)} /> : null}
            <Alert type="info" showIcon message={t('recoveryTitle')} description={<>
              <div>{t('recovery')}</div>
              <Typography.Text code copyable>{t('recoveryCommand')}</Typography.Text>
              <div>{t('recoveryAfter')}</div>
            </>} />
          </Space>
        </Card>}
    </div>
  )
}
