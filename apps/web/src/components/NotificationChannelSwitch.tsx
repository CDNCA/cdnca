import { useCallback, useEffect, useState } from 'react'
import { Alert, App, Button } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { newNotificationRequestKey, notificationsApi, type NotificationChannels } from '../api/notifications'
import { useSessionStore } from '../auth/session'
import '../i18n/accountRegistration'

export type NotificationChannel = 'email' | 'sms'

// the notification channel switches start off (migration
// 029) and saving a sender does not turn them on. These let the operator turn
// one on where the problem shows, through the same channel settings API (and
// permission) as the 通知 tab; nothing is switched on without a click.

/** Turns channel on, keeping the other switch as it is. */
async function enableNotificationChannel(accessToken: string, channel: NotificationChannel): Promise<NotificationChannels> {
  const current = await notificationsApi.getChannels(accessToken)
  if (channel === 'email' ? current.email_enabled : current.sms_enabled) return current
  return notificationsApi.putChannels(accessToken, {
    email_enabled: channel === 'email' ? true : current.email_enabled,
    sms_enabled: channel === 'sms' ? true : current.sms_enabled,
  }, current.revision, newNotificationRequestKey())
}

function enableFailureKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'channelSwitch.failed'
  if (error.status === 401 || error.status === 403) return 'channelSwitch.forbidden'
  if (error.status === 409 || error.status === 412) return 'channelSwitch.conflict'
  if (error.status === 400 || error.status === 422) return 'channelSwitch.unsupported'
  return 'channelSwitch.failed'
}

function useEnableChannel(channel: NotificationChannel, onEnabled?: (channels: NotificationChannels) => void) {
  const { t } = useTranslation('accountRegistration')
  const { message } = App.useApp()
  const accessToken = useSessionStore((state) => state.accessToken)
  const [busy, setBusy] = useState(false)
  const enable = useCallback(async () => {
    if (!accessToken || busy) return
    setBusy(true)
    try {
      const channels = await enableNotificationChannel(accessToken, channel)
      message.success(t(`channelSwitch.enabled.${channel}`))
      onEnabled?.(channels)
    } catch (error) {
      message.error(t(enableFailureKey(error)))
    } finally {
      setBusy(false)
    }
  }, [accessToken, busy, channel, message, onEnabled, t])
  return { enable, busy, available: Boolean(accessToken) }
}

// The auto notification runtime picks a saved sender up within 15 seconds
// (notificationAutoPollInterval); a channel not yet offered is read again once.
const senderPickupDelayMs = 16_000

/**
 * Shown on the mail/SMS settings tab when the channel can send (sender
 * configured, as the channel settings API reports it) but its switch is off.
 * refreshKey: change it after the sender settings are saved.
 */
export function NotificationChannelOffNotice({ channel, refreshKey, canManage }: {
  channel: NotificationChannel
  refreshKey: unknown
  canManage: boolean
}) {
  const { t } = useTranslation('accountRegistration')
  const accessToken = useSessionStore((state) => state.accessToken)
  const [channels, setChannels] = useState<NotificationChannels | null>(null)
  useEffect(() => {
    if (!accessToken) return
    let active = true
    let timer: number | undefined
    const read = (again: boolean) => {
      void notificationsApi.getChannels(accessToken).then((value) => {
        if (!active) return
        setChannels(value)
        const supported = channel === 'email' ? value.email_supported : value.sms_supported
        const enabled = channel === 'email' ? value.email_enabled : value.sms_enabled
        if (again && !supported && !enabled) timer = window.setTimeout(() => read(false), senderPickupDelayMs)
      }).catch(() => { if (active) setChannels(null) })
    }
    read(true)
    return () => { active = false; if (timer !== undefined) window.clearTimeout(timer) }
  }, [accessToken, channel, refreshKey])
  const { enable, busy } = useEnableChannel(channel, setChannels)
  if (!channels) return null
  const supported = channel === 'email' ? channels.email_supported : channels.sms_supported
  const enabled = channel === 'email' ? channels.email_enabled : channels.sms_enabled
  if (!supported || enabled) return null
  return <Alert
    type="warning"
    showIcon
    data-testid={`notification-channel-off-${channel}`}
    style={{ marginBottom: 16, maxWidth: 760 }}
    message={t(`channelSwitch.offTitle.${channel}`)}
    description={t('channelSwitch.offText')}
    action={canManage ? <Button type="primary" size="small" loading={busy} onClick={() => void enable()}>{t(`channelSwitch.enable.${channel}`)}</Button> : undefined}
  />
}
