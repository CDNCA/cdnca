import NotificationSettingsPage from './NotificationSettingsPage'
import { useEventSubscriptionRows } from './tickets/useEventSubscriptionRows'
import { useSessionStore } from '../auth/session'
import './AccountSubscriptionsPage.css'

export default function AccountSubscriptionsPage() {
  const authenticated = useSessionStore((state) => Boolean(state.accessToken && state.principal))
  return authenticated ? <AccountSubscriptionsTable /> : <NotificationSettingsPage mode="account" />
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
