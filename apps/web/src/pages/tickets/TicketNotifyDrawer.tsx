import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query'
import { Alert, Checkbox, Drawer, Skeleton, Typography } from 'antd'
import { Bell, Mail, MessageSquare } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  notificationsApi, type AccountNotificationEventType, type NotificationSubscription, type SubscriptionWrite,
} from '../../api/notifications'
import { useSessionStore } from '../../auth/session'
import '../../i18n/tickets'

// fix-ticket2 ②：工单通知按事件、按渠道个人选择（站内信 / 邮件 / 短信，可多选或全关）。
// 读写的是 /v1/account/notification-subscriptions/{event}（与“消息订阅”页同一份），
// 用户端是自己工单的回复与状态变化，管理端是新工单、用户回复、超时提醒。
const userEvents = ['ticket.replied', 'ticket.status_changed', 'ticket.created'] as const
const staffEvents = ['ticket.staff.created', 'ticket.staff.replied', 'ticket.staff.overdue'] as const
type Channel = 'inbox' | 'email' | 'sms'

function requestKey(): string {
  return `ticket-notify-${globalThis.crypto?.randomUUID?.() ?? Date.now().toString(36)}`
}

export function TicketNotifyDrawer({ staff, onClose }: { staff: boolean; onClose: () => void }) {
  const { t } = useTranslation('tickets')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const principal = useSessionStore((state) => state.principal)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const client = useQueryClient()
  const events: readonly AccountNotificationEventType[] = staff ? staffEvents : userEvents
  // 与订阅页同一查询键：任一处改过，另一处读到的是新值。
  const key = (event: string) => ['ticket-subscription', principal?.scope_id, principal?.user_id, epoch, event] as const
  const queries = useQueries({
    queries: events.map((event) => ({ queryKey: key(event), queryFn: () => notificationsApi.getSubscription(token, event), retry: false })),
  })
  const save = useMutation({
    mutationFn: ({ current, change }: { current: NotificationSubscription; change: SubscriptionWrite }) =>
      notificationsApi.putSubscription(token, current.event_type, change, current.revision, requestKey()),
    onSuccess: (value) => client.setQueryData(key(value.event_type), value),
    onError: (_, { current }) => { void client.invalidateQueries({ queryKey: key(current.event_type) }) },
  })
  const channels: Array<{ channel: Channel; label: string; icon: typeof Bell }> = [
    { channel: 'inbox', label: t('notify.inbox'), icon: Bell },
    { channel: 'email', label: t('notify.email'), icon: Mail },
    { channel: 'sms', label: t('notify.sms'), icon: MessageSquare },
  ]
  const toggle = (value: NotificationSubscription, channel: Channel, next: boolean) => {
    const change: SubscriptionWrite = { sms_enabled: value.sms_enabled, email_enabled: value.email_enabled,
      ...(value.inbox_enabled === undefined ? {} : { inbox_enabled: value.inbox_enabled }) }
    if (channel === 'inbox') change.inbox_enabled = next
    else if (channel === 'email') change.email_enabled = next
    else change.sms_enabled = next
    save.mutate({ current: value, change })
  }
  const failure = queries.find((query) => query.isError)?.error ?? save.error
  return (
    <Drawer open onClose={onClose} width="min(560px, 100vw)" title={t('notify.title')} destroyOnHidden className="ticket-notify">
      <Typography.Paragraph type="secondary">{staff ? t('notify.staffHint') : t('notify.userHint')}</Typography.Paragraph>
      {failure ? <Alert type="error" showIcon className="ticket-drawer-alert"
        message={t('errors.failed', { code: failure instanceof ApiError ? failure.code : 'request_failed' })} /> : null}
      <table className="ticket-notify-table">
        <thead>
          <tr>
            <th scope="col">{t('notify.event')}</th>
            {channels.map(({ channel, label, icon: Icon }) => (
              <th scope="col" key={channel}><span className="ticket-notify-channel"><Icon size={14} aria-hidden="true" />{label}</span></th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => {
            const label = t(`subscriptions.events.${event.replace(/\./g, '_')}`)
            const value = queries[index]?.data
            return (
              <tr key={event}>
                <th scope="row">{label}</th>
                {channels.map(({ channel, label: channelLabel }) => {
                  if (!value) return <td key={channel}><Skeleton.Button active size="small" /></td>
                  const supported = channel === 'inbox' ? value.inbox_enabled !== undefined
                    : channel === 'email' ? value.email_supported : value.sms_supported
                  const checked = channel === 'inbox' ? value.inbox_enabled === true
                    : channel === 'email' ? value.email_enabled : value.sms_enabled
                  return (
                    <td key={channel}>
                      <Checkbox aria-label={`${label} ${channelLabel}`} checked={supported && checked}
                        disabled={!supported || save.isPending}
                        title={supported ? undefined : t('notify.unsupported')}
                        onChange={(next) => toggle(value, channel, next.target.checked)} />
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>
    </Drawer>
  )
}
