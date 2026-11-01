import NotificationSettingsPage from './NotificationSettingsPage'
import { useEventSubscriptionRows } from './tickets/useEventSubscriptionRows'
import { useSessionStore } from '../auth/session'
import './AccountSubscriptionsPage.css'

export default function AccountSubscriptionsPage() {
  const authenticated = useSessionStore((state) => Boolean(state.accessToken && state.principal))
  // 持有事件行 hook 的整张表按身份（作用域/用户/会话代际）重建，
  // 代登录进入、退出或到期后，上一身份的局部状态（分组写入失败、重试目标、在途 mutation）不带到新身份。
  const owner = useSessionStore((state) => state.principal
    ? `${state.principal.scope_id}:${state.principal.user_id}:${state.sessionEpoch}` : '')
  return authenticated ? <AccountSubscriptionsTable key={owner} /> : <NotificationSettingsPage mode="account" />
}

// tp-b7：公告与套餐/证书/工单事件同一张表；事件行只在登录后读取。
function AccountSubscriptionsTable() {
  const events = useEventSubscriptionRows()
  return (
    <div className="account-subscriptions-page" data-parity-surface="account-subscriptions">
      <NotificationSettingsPage mode="account" eventRows={events.rows} extraEventRows={events.extraRows} grouped={events.grouped} eventError={events.error} />
    </div>
  )
}
