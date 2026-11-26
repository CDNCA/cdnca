import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { useSessionStore } from '../auth/session'
import '../components/SiteCacheTabs.css'
import '../i18n/adminInbox'

export type AccountMessageView = 'inbox' | 'announcements' | 'events'

// 站内消息、公告、事件提醒在账户中心并列，两页共用这组导航链接
// （当前页 aria-current）；站内消息只对租户开放，与 /account/inbox 的路由一致。
export function AccountMessageNav({ current }: { current: AccountMessageView }) {
  const { t } = useTranslation('accountMessages')
  const { t: inbox } = useTranslation('adminInbox')
  const tenant = useSessionStore((state) => state.principal?.scope_kind === 'tenant')
  const links: Array<[AccountMessageView, string, string]> = [
    ...(tenant ? [['inbox', '/account/inbox', inbox('title')] as [AccountMessageView, string, string]] : []),
    ['announcements', '/account/message', t('filters.announcements')],
    ['events', '/account/message?category=events', t('filters.events')],
  ]
  return <nav className="site-cache-tabs account-messages-category" aria-label={t('filters.category')}>
    {links.map(([view, to, label]) => <Link key={view} className={`site-cache-tab${current === view ? ' is-active' : ''}`} to={to}
      aria-current={current === view ? 'page' : undefined}>{label}</Link>)}
  </nav>
}
