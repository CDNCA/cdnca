import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Collapse, Empty, Input, InputNumber, Radio, Space, Spin, Switch, Tag, Typography } from 'antd'
import { ChevronDown, ChevronUp, RefreshCw, Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { newNotificationRequestKey, notificationsApi, type NotificationDeliveryPolicy, type NotificationDeliveryPolicyEvent } from '../api/notifications'
import { useSessionStore } from '../auth/session'
import '../i18n/notificationPolicy'
import './NotificationDeliveryPolicyPanel.css'
import { FeedbackWhen, OutcomeUnknown, fieldReasonText, submitErrorFields } from '@cdnca/ui'

type PolicyWrite = Omit<NotificationDeliveryPolicy, 'schema' | 'revision' | 'changed'>
type EventDraft = Omit<NotificationDeliveryPolicyEvent, 'repeat_count' | 'interval_hours'> & { repeat_count: number | null; interval_hours: number | null }
type Draft = Omit<PolicyWrite, 'events'> & { events: EventDraft[] }
type Attempt = { value: PolicyWrite; revision: number; requestKey: string }
// fix-fielderr-be5: a refused body field, resolved to the control it is about.
// events[n] is the n-th event of the submitted body, kept by its event_type.
type Refused = { reason: string } & ({ kind: 'window' | 'window_mode' | 'timezone' | 'events' } | { kind: 'event'; eventType: string; column: string })

const eventColumns: Record<string, string> = { event_type: 'event', enabled: 'enabled', sms_enabled: 'channels', email_enabled: 'channels', repeat_count: 'repeat', interval_hours: 'interval' }

function refusedField(error: unknown, attempt: Attempt): Refused | null {
  for (const { field, reason } of submitErrorFields(error)) {
    if (field === 'window_start' || field === 'window_end') return { kind: attempt.value.window_mode === 'custom' ? 'window' : 'window_mode', reason }
    if (field === 'window_mode' || field === 'timezone' || field === 'events') return { kind: field, reason }
    const match = /^events\[(\d+)\](?:\.([a-z_]+))?$/.exec(field)
    const eventType = match ? attempt.value.events[Number(match[1])]?.event_type : undefined
    if (match && eventType) return { kind: 'event', eventType, column: eventColumns[match[2] ?? ''] ?? 'event', reason }
  }
  return null
}

const eventNames: Record<string, string> = {
  'announcement.published': 'announcement',
  'package.monitor.traffic.triggered': 'trafficTriggered', 'package.monitor.traffic.warning': 'trafficWarning', 'package.monitor.traffic.recovered': 'trafficRecovered',
  'package.monitor.bandwidth.triggered': 'bandwidthTriggered', 'package.monitor.bandwidth.recovered': 'bandwidthRecovered', 'package.monitor.bandwidth_over_limit': 'bandwidthOverLimit',
  'package.monitor.connections.triggered': 'connectionsTriggered', 'package.monitor.connections.recovered': 'connectionsRecovered', 'package.monitor.connections_over_limit': 'connectionsOverLimit',
  'package.monitor.expiration.triggered': 'expirationTriggered', 'package.monitor.expiration.recovered': 'expirationRecovered',
  'package.auto_renew.succeeded': 'autoRenewSucceeded', 'package.auto_renew.failed': 'autoRenewFailed',
  'package.monitor.cc_rule_auto_switch': 'ccSwitch', 'security.attack.detected': 'attackDetected', 'certificate.expired': 'certificateExpired', 'certificate.expiring': 'certificateExpiring',
  'identity.secondary_verification': 'secondaryVerification',
  'security.waf.auto_exclusion_active': 'wafAutoExclusionActive', 'security.waf.auto_exclusion_revoked': 'wafAutoExclusionRevoked',
  'security.waf.auto_exclusion_expired': 'wafAutoExclusionExpired',
  'node.availability.offline': 'nodeOffline', 'node.availability.recovered': 'nodeRecovered',
  'node.bandwidth.exceeded': 'nodeBandwidthExceeded', 'node.bandwidth.recovered': 'nodeBandwidthRecovered',
  'node.line_group.backup_ip_activated': 'lineBackupActivated', 'node.line_group.primary_ip_restored': 'lineBackupRestored',
  'acme.http01.epoch_drift': 'http01EpochDrift',
  'payment.reconcile.mismatch': 'paymentReconcileMismatch', 'payment.plugin.alert': 'paymentPluginAlert',
  'node.security.event': 'nodeSecurityEvent', 'node.security.waf_ban': 'wafAutoBan', 'node.security.list_truncated': 'listTruncated', 'installation_ban.rejected': 'installationBanRejected', 'node.install_trust.failed': 'nodeInstallTrustFailed', 'node.certificate.recovered': 'nodeCertificateRecovered',
  'aggregated_edge.schedule.alert': 'aggregatedEdgeScheduleAlert', 'probe.dnspup.degraded': 'dnspupProbeDegraded',
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
  'certificate.renew_failed': 'certificateRenewFailed',
  'ticket.created': 'ticketCreated', 'ticket.replied': 'ticketReplied', 'ticket.status_changed': 'ticketStatusChanged',
  'ticket.staff.created': 'ticketStaffCreated', 'ticket.staff.replied': 'ticketStaffReplied', 'ticket.staff.overdue': 'ticketStaffOverdue',
}

const referenceEventOrder: Record<string, number> = {
  'package.monitor.traffic.triggered': 0, 'package.monitor.traffic.warning': 1,
  'package.monitor.cc_rule_auto_switch': 4, 'package.monitor.bandwidth_over_limit': 5,
  'package.monitor.connections_over_limit': 6, 'certificate.expired': 7,
  'certificate.expiring': 8, 'identity.secondary_verification': 9,
}

function ownerKey(principal: Principal, epoch: number) {
  return JSON.stringify([principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, epoch])
}

function currentAccess(owner: string, manage = false) {
  const { accessToken, principal, sessionEpoch, status } = useSessionStore.getState()
  if (status !== 'authenticated' || !accessToken || !principal || ownerKey(principal, sessionEpoch) !== owner ||
    principal.scope_kind !== 'platform' || !principal.permissions.includes('system_configuration.read') ||
    (manage && !principal.permissions.includes('system_configuration.manage'))) return null
  return accessToken
}

function policyValue(policy: NotificationDeliveryPolicy): PolicyWrite {
  const { window_mode, window_start, window_end, timezone, events } = policy
  return { window_mode, window_start, window_end, timezone, events }
}

function displayWindow(start: string, end: string) {
  const display = (time: string) => time.endsWith(':00') ? String(Number(time.slice(0, 2))) : time
  return `${display(start)}-${display(end)}`
}

function parseWindow(value: string): [string, string] | null {
  const match = /^\s*(\d{1,2})(?::(\d{2}))?\s*-\s*(\d{1,2})(?::(\d{2}))?\s*$/.exec(value)
  if (!match) return null
  const startHour = Number(match[1]), startMinute = Number(match[2] ?? 0), endHour = Number(match[3]), endMinute = Number(match[4] ?? 0)
  if (startHour > 23 || endHour > 23 || startMinute > 59 || endMinute > 59) return null
  return [`${String(startHour).padStart(2, '0')}:${String(startMinute).padStart(2, '0')}`, `${String(endHour).padStart(2, '0')}:${String(endMinute).padStart(2, '0')}`]
}

export default function NotificationDeliveryPolicyPanel() {
  const { t } = useTranslation('notificationPolicy')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  if (!principal || !accessToken) return null
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !principal.permissions.includes('system_configuration.read')) {
    return <Alert type="error" message={t('errors.forbidden')} />
  }
  const owner = ownerKey(principal, epoch)
  return <PolicyContent key={owner} owner={owner} canManage={principal.permissions.includes('system_configuration.manage')} />
}

function PolicyContent({ owner, canManage }: { owner: string; canManage: boolean }) {
  const { t } = useTranslation('notificationPolicy')
  const client = useQueryClient()
  const queryKey = ['notification-delivery-policy', owner] as const
  const [draft, setDraft] = useState<Draft | null>(null)
  const [customWindow, setCustomWindow] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string[]>([])
  const [pending, setPending] = useState<Attempt | null>(null)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [refused, setRefused] = useState<Refused | null>(null)
  const { i18n } = useTranslation()
  const query = useQuery({
    queryKey, staleTime: Infinity, refetchOnWindowFocus: false, refetchOnReconnect: false, retry: false,
    queryFn: () => {
      const token = currentAccess(owner)
      if (!token) throw new ApiError('Session changed', 401, 'authentication_required')
      return notificationsApi.getDeliveryPolicy(token)
    },
  })
  const mutation = useMutation({
    mutationKey: ['notification-delivery-policy-write', owner], gcTime: 0, retry: false,
    mutationFn: (attempt: Attempt) => {
      const token = currentAccess(owner, true)
      if (!token) throw new ApiError('Policy access denied', 403, 'notification_permission_denied')
      return notificationsApi.putDeliveryPolicy(token, attempt.value, attempt.revision, attempt.requestKey)
    },
    onSuccess: (value) => {
      if (!currentAccess(owner)) return
      client.setQueryData(queryKey, value)
      setDraft(null)
      setCustomWindow(null)
      setPending(null)
      setErrorKey(null)
      setSaved(true)
    },
    onError: (error, attempt) => {
      if (!currentAccess(owner)) return
      const status = error instanceof ApiError ? error.status : 0
      const unknown = status === 0 || status === 408 || status === 429 || status >= 500
      setPending(unknown ? attempt : null)
      const located = status === 400 ? refusedField(error, attempt) : null
      setRefused(located)
      if (located?.kind === 'event') setExpanded((keys) => keys.includes(located.eventType) ? keys : [...keys, located.eventType])
      setErrorKey(unknown || located ? null : status === 409 ? 'conflict' : status === 401 ? 'session' : status === 403 ? 'forbidden' : status === 400 ? 'validation' : 'write')
    },
  })
  const refresh = () => {
    if (mutation.isPending || !currentAccess(owner)) return
    setDraft(null)
    setCustomWindow(null)
    setPending(null)
    setErrorKey(null)
    setRefused(null)
    setSaved(false)
    mutation.reset()
    void query.refetch()
  }
  if (query.isPending) return <div className="notification-delivery-policy-loading" aria-label={t('loading')}><Spin size="small" /></div>
  if (query.isError || !query.data) return <FeedbackWhen title={t(query.error instanceof ApiError && query.error.status === 403 ? 'errors.forbidden' : 'errors.read')} action={<Button onClick={refresh}>{t('refresh')}</Button>} />

  const value = draft ?? policyValue(query.data)
  const windowValue = customWindow ?? displayWindow(value.window_start, value.window_end)
  const locked = mutation.isPending || pending !== null || query.isFetching
  const disabled = !canManage || locked || errorKey === 'conflict' || errorKey === 'forbidden' || errorKey === 'session'
  const dirty = draft !== null || customWindow !== null
  const eventLabel = (event: string) => eventNames[event] ? t(`events.${eventNames[event]}`) : t('unknownEvent', { event })
  const update = (change: Partial<Draft>) => {
    setDraft({ ...value, ...change })
    setErrorKey(null)
    setRefused(null)
    setSaved(false)
  }
  const reasonText = refused ? fieldReasonText(refused.reason, i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn') : ''
  const refusedLine = (text: string) => <div className="notification-policy-field-error" role="alert">{text}</div>
  const eventRefused = (eventType: string, column: string) => refused?.kind === 'event' && refused.eventType === eventType && refused.column === column
  const eventLine = (eventType: string, column: string, label: string) => eventRefused(eventType, column) ? refusedLine(`${label}：${reasonText}`) : null
  const updateEvent = (eventType: string, change: Partial<EventDraft>) => update({ events: value.events.map((event) => event.event_type === eventType ? { ...event, ...change } : event) })
  const save = () => {
    if (disabled || !currentAccess(owner, true)) return
    const window = value.window_mode === 'custom' ? parseWindow(windowValue) : ['00:00', '23:59']
    if (!window) { setErrorKey('window'); return }
    if (value.events.some((event) => !Number.isInteger(event.repeat_count) || event.repeat_count === null || event.repeat_count < 1 || event.repeat_count > 10 ||
      !Number.isInteger(event.interval_hours) || event.interval_hours === null || event.interval_hours < 1 || event.interval_hours > 168)) {
      setErrorKey('numbers'); return
    }
    setErrorKey(null)
    setSaved(false)
    mutation.mutate({ revision: query.data.revision, requestKey: newNotificationRequestKey(), value: {
      ...value, window_start: window[0], window_end: window[1], events: value.events as NotificationDeliveryPolicyEvent[],
    } })
  }

  return <section className="notification-delivery-policy" data-testid="notification-delivery-policy" aria-label={t('title')}>
    <div className="notification-policy-window">
      <span className="notification-policy-field-label">{t('window')}</span>
      <Radio.Group aria-label={t('window')} value={value.window_mode} disabled={disabled} onChange={(event) => {
        const mode = event.target.value as 'all_day' | 'custom'
        if (mode === 'custom' && value.window_mode === 'all_day') setCustomWindow('8-22')
        update({ window_mode: mode })
      }}>
        <Radio.Button value="all_day">{t('allDay')}</Radio.Button><Radio.Button value="custom">{t('custom')}</Radio.Button>
      </Radio.Group>
      {value.window_mode === 'custom' ? <Input aria-label={t('window')} value={windowValue} disabled={disabled} status={refused?.kind === 'window' ? 'error' : undefined}
        className="notification-policy-window-input" onChange={(event) => { setCustomWindow(event.target.value); setErrorKey(null); setRefused(null); setSaved(false) }} /> : null}
      <Typography.Text type="secondary">{t('timezone', { timezone: value.timezone })}</Typography.Text>
    </div>
    {refused?.kind === 'window' || refused?.kind === 'window_mode' ? refusedLine(reasonText) : null}
    {refused?.kind === 'timezone' ? refusedLine(`${t('timezone', { timezone: value.timezone })}：${reasonText}`) : null}
    {value.window_mode === 'custom' ? <div className="notification-policy-window-hint">{t('windowHint')}</div> : null}
    {pending ? <OutcomeUnknown title={t('uncertainty')} detail={t('uncertaintyDescription')} action={<Space wrap>
      <Button disabled={!canManage || mutation.isPending} loading={mutation.isPending} onClick={() => { if (currentAccess(owner, true)) mutation.mutate(pending) }}>{t('retrySame')}</Button>
      <Button disabled={mutation.isPending} onClick={refresh}>{t('closeAndRefresh')}</Button>
    </Space>} /> : null}
    {errorKey ? <Alert type="error" showIcon message={t(`errors.${errorKey}`)} /> : null}
    {saved ? <Alert className="notification-policy-saved" type="success" showIcon message={t('saved')} /> : null}
    {refused?.kind === 'events' ? refusedLine(reasonText) : null}
    <div className="notification-policy-expand-actions"><Space>
      <Button size="small" icon={<ChevronDown size={14} />} onClick={() => setExpanded(value.events.map((event) => event.event_type))}>{t('expandAll')}</Button>
      <Button size="small" icon={<ChevronUp size={14} />} onClick={() => setExpanded([])}>{t('collapseAll')}</Button>
    </Space></div>
    {value.events.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('empty')} /> : <Collapse activeKey={expanded} onChange={(keys) => setExpanded(typeof keys === 'string' ? [keys] : keys)}
      items={[...value.events].sort((left, right) => (referenceEventOrder[left.event_type] ?? 10) - (referenceEventOrder[right.event_type] ?? 10)).map((event) => {
        const label = eventLabel(event.event_type)
        const eventDisabled = disabled || !event.supported
        return { key: event.event_type, label: <div className="notification-policy-heading">
          <span className="notification-policy-title">{t('eventTitle', { event: label })}</span>
          {event.supported ? <>
            <span className={`notification-policy-status${event.enabled ? ' notification-policy-status--on' : ''}`}>{t(event.enabled ? 'statusOn' : 'statusOff')}</span>
            <span className="notification-policy-channels">{[event.email_enabled ? t('email') : '', event.sms_enabled ? t('sms') : ''].filter(Boolean).join(' / ') || t('noChannels')}</span>
          </> : <Tag>{t('unsupported')}</Tag>}
        </div>, children: <div className="notification-policy-event">
          {!event.supported ? <Typography.Text type="secondary">{t('unsupportedDescription')}</Typography.Text> : null}
          {eventRefused(event.event_type, 'event') ? refusedLine(`${label}：${reasonText}`) : null}
          <div className="notification-policy-row"><span className="notification-policy-field-label">{t('enabled')}</span>
            <Switch aria-label={`${label} ${t('enabled')}`} checked={event.enabled} disabled={eventDisabled} onChange={(enabled) => updateEvent(event.event_type, { enabled })} />
          </div>
          {eventLine(event.event_type, 'enabled', t('enabled'))}
          <div className="notification-policy-row"><span className="notification-policy-field-label">{t('channels')}</span>
            <Space wrap>
              <Checkbox aria-label={`${label} ${t('email')}`} checked={event.email_enabled} disabled={eventDisabled} onChange={(change) => updateEvent(event.event_type, { email_enabled: change.target.checked })}>{t('emailChannel')}</Checkbox>
              <Checkbox aria-label={`${label} ${t('sms')}`} checked={event.sms_enabled} disabled={eventDisabled} onChange={(change) => updateEvent(event.event_type, { sms_enabled: change.target.checked })}>{t('smsChannel')}</Checkbox>
            </Space>
          </div>
          {eventLine(event.event_type, 'channels', t('channels'))}
          <div className="notification-policy-row"><label className="notification-policy-field-label" htmlFor={`policy-repeat-${event.event_type}`}>{t('repeat')}</label>
            <InputNumber id={`policy-repeat-${event.event_type}`} aria-label={`${label} ${t('repeat')}`} min={1} max={10} precision={0} value={event.repeat_count} disabled={eventDisabled}
              status={eventRefused(event.event_type, 'repeat') ? 'error' : undefined} onChange={(repeat_count) => updateEvent(event.event_type, { repeat_count })} />
          </div>
          {eventLine(event.event_type, 'repeat', t('repeat'))}
          <div className="notification-policy-row"><label className="notification-policy-field-label" htmlFor={`policy-interval-${event.event_type}`}>{t('intervalLabel')}</label>
            <InputNumber id={`policy-interval-${event.event_type}`} aria-label={`${label} ${t('interval')}`} addonAfter={t('hours')} min={1} max={168} precision={0} value={event.interval_hours} disabled={eventDisabled}
              status={eventRefused(event.event_type, 'interval') ? 'error' : undefined} onChange={(interval_hours) => updateEvent(event.event_type, { interval_hours })} />
          </div>
          {eventLine(event.event_type, 'interval', t('interval'))}
        </div> }
      })} />}
    <Typography.Paragraph className="notification-policy-template-note" type="secondary">{t('templateBoundary')}</Typography.Paragraph>
    <div className="notification-policy-footer"><Space wrap>
      <Button type="primary" icon={<Save size={14} />} disabled={disabled || !dirty || value.events.length === 0} loading={mutation.isPending} onClick={save}>{t('save')}</Button>
      <Button icon={<RefreshCw size={14} />} disabled={mutation.isPending || pending !== null} loading={query.isFetching} onClick={refresh}>{t('refresh')}</Button>
      <Typography.Text type="secondary">{t('revision', { revision: query.data.revision })}</Typography.Text>
    </Space></div>
  </section>
}
