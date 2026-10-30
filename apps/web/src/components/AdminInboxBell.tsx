import { Badge, Tooltip } from 'antd'
import { Bell } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import { inboxApiFor, inboxPathFor, type InboxScope } from '../api/adminInbox'
import '../i18n/adminInbox'

export const adminInboxUnreadKey = ['admin-inbox', 'unread'] as const
export const inboxUnreadKey = (scope: InboxScope) => scope === 'admin' ? adminInboxUnreadKey : ['account-inbox', 'unread'] as const
export const adminInboxPollMs = 60_000

// Header bell with the unread count of the message center (platform or tenant).
export function AdminInboxBell({ accessToken, scope = 'admin' }: { accessToken: string | null; scope?: InboxScope }) {
  const { t } = useTranslation('adminInbox')
  const navigate = useNavigate()
  const unread = useQuery({
    queryKey: inboxUnreadKey(scope),
    queryFn: () => inboxApiFor(scope).unreadCount(accessToken ?? ''),
    enabled: Boolean(accessToken),
    refetchInterval: adminInboxPollMs,
    refetchIntervalInBackground: false,
    retry: false,
  })
  const count = unread.data?.unread ?? 0
  const label = t('bell', { count: String(count) })
  return (
    <Tooltip title={label}>
      <button className="header-icon-button" type="button" aria-label={label} onClick={() => navigate(inboxPathFor(scope))}>
        <Badge count={count} size="small" overflowCount={99}>
          <Bell size={17} aria-hidden="true" />
        </Badge>
      </button>
    </Tooltip>
  )
}
