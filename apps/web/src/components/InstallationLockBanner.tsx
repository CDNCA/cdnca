import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { installationLockApi } from '../api/installationLock'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/marketSupplier'
import { installationLockQueryKey, useInstallationLockCheck } from './useInstallationLockCheck'

// ADR 0014 §5.2 (LIC-BAN-06): every signed-in admin and tenant page shows the
// controller lock with its reason and lift time; writes answer 423 meanwhile.
export function InstallationLockBanner() {
  const { t, i18n } = useTranslation('marketSupplier')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const lock = useQuery({ queryKey: installationLockQueryKey, enabled: !!token, queryFn: () => installationLockApi.current(token), refetchInterval: 60_000, retry: false })
  const check = useInstallationLockCheck()
  const value = lock.data
  const checkButton = <Button size="small" loading={check.isPending} onClick={() => check.mutate()}>{check.isPending ? t('lock.checking') : t('lock.check')}</Button>
  // fix-ipswitch: shown as soon as the license service refuses this controller,
  // also while the current lease is still valid.
  if (value?.rebound) {
    return (
      <Alert type={value.locked ? 'error' : 'warning'} showIcon banner role="alert" style={{ marginBottom: 12 }} message={t('lock.rebound.title')}
        description={<Space direction="vertical" size={2}>
          <span>{t('lock.rebound.body')}</span>
          {value.locked ? <Typography.Text type="secondary">{t('lock.readonly')}</Typography.Text> : null}
          <span>{t('lock.rebound.action')}</span>
        </Space>}
        action={checkButton} />
    )
  }
  if (!value?.locked) return null
  const reason = t(`lock.reasons.${value.reason}`, { defaultValue: value.reason ?? '' })
  const until = value.until ? t('lock.until', { time: formatDateTime(value.until, i18n.resolvedLanguage ?? 'zh-CN') || value.until }) : t('lock.permanent')
  return (
    <Alert type="error" showIcon banner role="alert" style={{ marginBottom: 12 }} message={t('lock.title')}
      description={<Space direction="vertical" size={2}>
        <span>{reason}{value.reason_text ? ` · ${t('lock.reason', { text: value.reason_text })}` : ''}</span>
        <span>{until}</span>
        {value.ban_id ? <Typography.Text type="secondary" copyable={{ text: value.ban_id }}>ban_id {value.ban_id}</Typography.Text> : null}
        <span>{t(`lock.impact.${value.reason}`, { defaultValue: t('lock.impact.default') })}</span>
        <Typography.Text type="secondary">{t('lock.readonly')}</Typography.Text>
        <span>{t(`lock.actions.${value.reason}`, { defaultValue: t('lock.actions.default') })}</span>
      </Space>}
      action={checkButton} />
  )
}
