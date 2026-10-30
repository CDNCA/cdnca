export interface AdminMessageQueryFilters {
  type?: string
  userID?: string
  packageID?: string
  siteID?: string
  /** fix-livefilter2: name or display-ID keywords when no ID was picked. */
  user?: string
  package?: string
  site?: string
  limit: number
  cursor?: string
}

export interface AdminMessage {
  id: string
  user_id: string | null
  type: string
  title: string | null
  package_id: string | null
  site_id: string | null
  created_at: string
  email_content: string | null
  sms_content: string | null
  // Delivery state of the original channel message; null = not generated.
  email_state: AdminMessageDeliveryState | null
  sms_state: AdminMessageDeliveryState | null
  // L1: current readable names; null when the object no longer exists.
  user_display_id: number | null
  username: string | null
  user_display_name: string | null
  site_domain: string | null
  package_name: string | null
}

export const adminMessageDeliveryStates = [
  'pending', 'dispatching', 'retry_wait', 'accepted', 'unknown', 'delivered', 'permanent_failed', 'exhausted', 'cancelled',
] as const
export type AdminMessageDeliveryState = typeof adminMessageDeliveryStates[number]

export interface AdminMessagePage {
  schema: 'cdnca.notification-message-query/v1'
  items: AdminMessage[]
  next_cursor?: string
  total: number
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const stableTypePattern = /^[a-z][a-z0-9._-]{0,95}$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

function nullableString(value: unknown): boolean {
  return value === null || typeof value === 'string'
}

function nullableState(value: unknown): boolean {
  return value === null || adminMessageDeliveryStates.includes(value as AdminMessageDeliveryState)
}

function isAdminMessage(value: unknown): value is AdminMessage {
  if (!isRecord(value) || !hasExactKeys(value, [
    'id', 'user_id', 'type', 'title', 'package_id', 'site_id', 'created_at', 'email_content', 'sms_content',
    'email_state', 'sms_state', 'user_display_id', 'username', 'user_display_name', 'site_domain', 'package_name',
  ])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    (value.user_id === null || typeof value.user_id === 'string' && uuidPattern.test(value.user_id)) &&
    typeof value.type === 'string' && stableTypePattern.test(value.type) &&
    nullableString(value.title) && nullableString(value.package_id) && nullableString(value.site_id) &&
    typeof value.created_at === 'string' && Number.isFinite(Date.parse(value.created_at)) &&
    nullableString(value.email_content) && nullableString(value.sms_content) &&
    nullableState(value.email_state) && nullableState(value.sms_state) &&
    (value.user_display_id === null || Number.isSafeInteger(value.user_display_id) && (value.user_display_id as number) > 0) &&
    nullableString(value.username) && nullableString(value.user_display_name) &&
    nullableString(value.site_domain) && nullableString(value.package_name)
}

export function isAdminMessagePage(value: unknown): value is AdminMessagePage {
  if (!isRecord(value)) return false
  const allowedKeys = Object.hasOwn(value, 'next_cursor')
    ? ['schema', 'items', 'next_cursor', 'total']
    : ['schema', 'items', 'total']
  return hasExactKeys(value, allowedKeys) && value.schema === 'cdnca.notification-message-query/v1' &&
    Array.isArray(value.items) && value.items.length <= 300 && value.items.every(isAdminMessage) &&
    (!Object.hasOwn(value, 'next_cursor') || (
      typeof value.next_cursor === 'string' && uuidPattern.test(value.next_cursor)
    )) && Number.isSafeInteger(value.total) && (value.total as number) >= 0
}

export function adminMessageSearchParams(filters: AdminMessageQueryFilters): string {
  const query = new URLSearchParams({ limit: String(filters.limit) })
  if (filters.type) query.set('type', filters.type)
  if (filters.userID) query.set('user_id', filters.userID)
  if (filters.packageID) query.set('package_id', filters.packageID)
  if (filters.siteID) query.set('site_id', filters.siteID)
  if (filters.user) query.set('user', filters.user)
  if (filters.package) query.set('package', filters.package)
  if (filters.site) query.set('site', filters.site)
  if (filters.cursor) query.set('cursor', filters.cursor)
  return query.toString()
}

// Message type -> key under adminMessageQuery:types. Every event type seeded
// into notification_event_policies must have an entry (adminMessageTypes.test.ts).
const typeTranslationKeys: Record<string, string> = {
  'announcement.published': 'announcementPublished',
  'package.monitor.traffic.triggered': 'trafficTriggered',
  'package.monitor.traffic.recovered': 'trafficRecovered',
  'package.monitor.bandwidth.triggered': 'bandwidthTriggered',
  'package.monitor.bandwidth.recovered': 'bandwidthRecovered',
  'package.monitor.connections.triggered': 'connectionsTriggered',
  'package.monitor.connections.recovered': 'connectionsRecovered',
  'package.monitor.expiration.triggered': 'expirationTriggered',
  'package.monitor.expiration.recovered': 'expirationRecovered',
  'package.auto_renew.succeeded': 'autoRenewSucceeded',
  'package.auto_renew.failed': 'autoRenewFailed',
  'package.monitor.cc_rule_auto_switch': 'ccRuleSwitch',
  'security.attack.detected': 'attackDetected',
  'security.waf.auto_exclusion_active': 'wafAutoExclusionActive',
  'security.waf.auto_exclusion_revoked': 'wafAutoExclusionRevoked',
  'security.waf.auto_exclusion_expired': 'wafAutoExclusionExpired',
  'certificate.expiring': 'certificateExpiring',
  'certificate.expired': 'certificateExpired',
  'node.availability.offline': 'nodeOffline',
  'node.availability.recovered': 'nodeRecovered',
  'node.bandwidth.exceeded': 'nodeBandwidthExceeded',
  'node.bandwidth.recovered': 'nodeBandwidthRecovered',
  'node.line_group.backup_ip_activated': 'lineBackupActivated',
  'node.line_group.primary_ip_restored': 'lineBackupRestored',
  'acme.http01.epoch_drift': 'http01EpochDrift',
  'payment.reconcile.mismatch': 'paymentReconcileMismatch',
  'payment.plugin.alert': 'paymentPluginAlert',
  'node.security.event': 'nodeSecurityEvent',
  'node.security.waf_ban': 'wafAutoBan',
  'node.security.list_truncated': 'listTruncated',
  'installation_ban.rejected': 'installationBanRejected',
  'node.install_trust.failed': 'nodeInstallTrustFailed',
  'node.certificate.recovered': 'nodeCertificateRecovered',
  'aggregated_edge.schedule.alert': 'aggregatedEdgeScheduleAlert',
  'probe.dnspup.degraded': 'dnspupProbeDegraded',
  'market.limit.warn80': 'marketLimitWarn80',
  'market.limit.warn95': 'marketLimitWarn95',
  'market.limit.reached': 'marketLimitReached',
  'market.limit.recovered': 'marketLimitRecovered',
  'market.prepaid.low': 'marketPrepaidLow',
  'market.prepaid.exhausted': 'marketPrepaidExhausted',
  'market.prepaid.restored': 'marketPrepaidRestored',
  'market.overdraft.warn': 'marketOverdraftWarn',
  'market.overdraft.capped': 'marketOverdraftCapped',
  'market.node.overloaded': 'marketNodeOverloaded',
  'market.node.recovered': 'marketNodeRecovered',
  'market.supply.all_overloaded': 'marketAllOverloaded',
  'market.plugin.unavailable': 'marketPluginUnavailable',
  'market.plugin.restored': 'marketPluginRestored',
  'market.terms.changed': 'marketTermsChanged',
  'market.renewal.stopped': 'marketRenewalStopped',
  'market.renewal.resumed': 'marketRenewalResumed',
  'market.renewal.compensated': 'marketRenewalCompensated',
  'market.feedback.opened': 'marketFeedbackOpened',
  'market.feedback.updated': 'marketFeedbackUpdated',
  'market.plugin.promo_charge': 'marketPluginPromoCharge',
  'market.downstream.attacked': 'marketDownstreamAttacked',
  'market.complaint.resolved': 'marketComplaintResolved',
  'market.complaint.actioned': 'marketComplaintActioned',
  'market.node.action': 'marketNodeAction',
  'market.site.paused': 'marketSitePaused',
  'market.site.resumed': 'marketSiteResumed',
  'market.commission.low': 'marketCommissionLow',
  'market.commission.exhausted': 'marketCommissionExhausted',
  'market.commission.restored': 'marketCommissionRestored',
  'market.supply.outage': 'marketSupplyOutage',
  'market.supply.restored': 'marketSupplyRestored',
  'market.supply.cancel_available': 'marketSupplyCancelAvailable',
  'market.supply.receipt_unconfirmed': 'marketSupplyReceiptUnconfirmed',
  'market.supply.node_delivery_failed': 'marketSupplyNodeDeliveryFailed',
  'market.direct_topup.paid': 'marketDirectTopupPaid',
  'market.direct_topup.received': 'marketDirectTopupReceived',
  'market.seller.deposit_mode': 'marketSellerDepositMode',
  'market.seller.deposit_shortfall': 'marketSellerDepositShortfall',
  'market.seller.default_compensated': 'marketSellerDefaultCompensated',
  'market.seller.defaulted': 'marketSellerDefaulted',
  'site.origin.failover': 'originFailover',
  'site.origin.recovered': 'originRecovered',
  'payment.market_topup.rejected': 'paymentMarketTopupRejected',
  'identity.migrated_account': 'migratedAccount',
  'identity.secondary_verification': 'secondaryVerification',
  'package.monitor.traffic.warning': 'trafficWarning',
  'package.monitor.bandwidth_over_limit': 'bandwidthOverLimit',
  'package.monitor.connections_over_limit': 'connectionsOverLimit',
  'ticket.created': 'ticketCreated', 'ticket.replied': 'ticketReplied', 'ticket.status_changed': 'ticketStatusChanged',
  'ticket.staff.created': 'ticketStaffCreated', 'ticket.staff.replied': 'ticketStaffReplied', 'ticket.staff.overdue': 'ticketStaffOverdue',
  'certificate.renew_failed': 'certificateRenewFailed',
  'node.dnspup.unreachable': 'dnspupNodeUnreachable',
  'node.dnspup.recovered': 'dnspupNodeRecovered',
  'probe.dnspup.balance_low': 'dnspupBalanceLow',
  'probe.dnspup.balance_exhausted': 'dnspupBalanceExhausted',
  'reseller.prepaid.low_balance': 'resellerPrepaidLow',
  'security.escalate.blackhole': 'escalateBlackhole',
  'security.escalate.blackhole_drop_confirmed': 'escalateBlackholeDropConfirmed',
  'security.escalate.cname_change_required': 'escalateCnameChangeRequired',
  'security.escalate.unlimited': 'escalateUnlimited',
  // Competitor-era values (release 581): never raised here, no longer offered in
  // the type filter; kept so historical rows still show a Chinese name.
  'package-expiring': 'packageExpiring',
  'package-expire': 'packageExpired',
  'traffic-exceeding': 'trafficExpiring',
  'traffic-exceed': 'trafficExceeded',
  'cc-switch': 'ccRuleSwitch',
  'bandwidth-exceed': 'bandwidthExceeded',
  'connection-exceed': 'connectionsExceeded',
  'cert-expire': 'certificateExpired',
  'cert-expiring': 'certificateExpiring',
  'account-auth2': 'secondaryVerification',
}

export function adminMessageTypeKey(value: string): string | undefined {
  return Object.hasOwn(typeTranslationKeys, value) ? typeTranslationKeys[value] : undefined
}
