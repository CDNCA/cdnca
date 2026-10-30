import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Modal, Space } from 'antd'
import { useTranslation } from 'react-i18next'

import { announcementsApi, newAnnouncementIdempotencyKey, type InboxMessage } from '../api/announcements'
import { announcementPopupLater, rememberAnnouncementPopupLater } from '../auth/announcementPopupLater'
import { useSessionStore } from '../auth/session'
import { AnnouncementBody } from './AnnouncementBody'

// Login announcement popup (tenant and platform announcements share the inbox).
// 「我已阅读，不再显示」marks the message read, so it never pops up again;
// 「稍后再看」hides it for this sign-in only (next sign-in shows it again).
// ×/Esc behave like 稍后再看.
export function AnnouncementPopup() {
  const { t } = useTranslation('announcements')
  const { message } = App.useApp()
  const queryClient = useQueryClient()
  const principal = useSessionStore((state) => state.principal)
  const token = useSessionStore((state) => state.accessToken)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const [hidden, setHidden] = useState<string[]>(announcementPopupLater)
  const enabled = Boolean(token && principal?.scope_kind === 'tenant' && principal.permissions.includes('announcements.read'))
  const queryKey = ['announcement-popups', principal?.scope_id, principal?.user_id, epoch]
  const query = useQuery({
    queryKey, enabled, retry: false, staleTime: 60_000,
    // 服务端只返回“未读且需弹窗”的公告（未读普通公告再多也不会漏弹）；
    // 一页最多 100 条，足以跳过本次登录里点过“稍后再看”的那些。
    queryFn: () => announcementsApi.inbox(token!, { filter: 'popup', limit: 100 }),
  })
  const keyOf = (value: InboxMessage) => `${principal?.user_id ?? ''}:${value.id}`
  const item = enabled
    ? query.data?.items.find((value) => value.popup && value.visible !== false && !value.read_at && !hidden.includes(keyOf(value)))
    : undefined
  const later = (value: InboxMessage) => {
    rememberAnnouncementPopupLater(keyOf(value))
    setHidden((current) => [...current, keyOf(value)])
  }
  const acknowledge = useMutation({
    mutationFn: (value: InboxMessage) =>
      announcementsApi.state(token!, value.id, 'read', value.state_revision, newAnnouncementIdempotencyKey('popup-read')),
    onSuccess: (_, value) => {
      setHidden((current) => [...current, keyOf(value)])
      void queryClient.invalidateQueries({ queryKey: ['account-messages'] })
    },
    onError: (_, value) => {
      // Not marked read: hide it for this sign-in only, it comes back next time.
      later(value)
      message.warning(t('popup.acknowledgeFailed'))
    },
  })
  const style = { color: item?.red ? 'var(--cdnca-color-error)' : undefined, fontWeight: item?.bold ? 700 : undefined }
  return <Modal open={Boolean(item)} title={<span style={style}>{item?.title}</span>}
    onCancel={() => { if (item && !acknowledge.isPending) later(item) }} maskClosable={false} destroyOnHidden
    footer={item ? <Space>
      <Button disabled={acknowledge.isPending} onClick={() => later(item)}>{t('popup.later')}</Button>
      <Button type="primary" loading={acknowledge.isPending} onClick={() => acknowledge.mutate(item)}>{t('popup.acknowledge')}</Button>
    </Space> : null}>
    {item ? <AnnouncementBody item={item} /> : null}
  </Modal>
}
