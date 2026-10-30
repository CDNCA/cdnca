import { useState } from 'react'
import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { notificationsApi, type NotificationSubscription, type SubscriptionWrite } from '../../api/notifications'
import { useSessionStore } from '../../auth/session'
import '../../i18n/tickets'

// 租户默认看到 6 个主消息类型，每类合并若干事件，
// 顺序固定；其余事件进表下方"更多消息类型"。读取也按这个顺序排队，先读可见的行。
const tenantGroups = [
  { key: 'expiration', events: ['package.monitor.expiration.triggered', 'package.monitor.expiration.recovered'] },
  { key: 'traffic', events: ['package.monitor.traffic.triggered', 'package.monitor.traffic.recovered'] },
  { key: 'ccSwitch', events: ['package.monitor.cc_rule_auto_switch'] },
  { key: 'bandwidth', events: ['package.monitor.bandwidth.triggered', 'package.monitor.bandwidth.recovered'] },
  { key: 'connections', events: ['package.monitor.connections.triggered', 'package.monitor.connections.recovered'] },
  { key: 'certificate', events: ['certificate.expiring', 'certificate.expired', 'certificate.renew_failed'] },
] as const
const tenantExtraEvents = [
  'package.auto_renew.failed', 'package.auto_renew.succeeded', 'security.attack.detected',
  'security.waf.auto_exclusion_active', 'security.waf.auto_exclusion_revoked', 'security.waf.auto_exclusion_expired',
  'ticket.created', 'ticket.replied', 'ticket.status_changed',
] as const
const tenantEvents = [...tenantGroups.flatMap((group) => group.events), ...tenantExtraEvents]
const staffEvents = ['ticket.staff.created', 'ticket.staff.replied', 'ticket.staff.overdue'] as const
type EventType = typeof tenantEvents[number] | typeof staffEvents[number]
type GroupKey = typeof tenantGroups[number]['key']
// 分组写入的目标：只改被切换的那个渠道，另一个渠道保留各事件自己的值。
type GroupTarget = { sms?: boolean; email?: boolean }

export type EventSubscriptionRow = {
  key: string
  label: string
  value: NotificationSubscription
  disabled: boolean
  onChange: (value: SubscriptionWrite) => void
  hint?: string
  // notif-sub A7：还没读到或读取失败的行也保留，显示状态；失败时可单项重试。
  notice?: string
  retry?: { label: string; run: () => void }
}

// notif-sub A8：这一页有 22 个事件，同时发出会让同一会话的读取在服务端排队。
// 事件读取最多同时 4 个，空出的名额直接交给下一个等待的读取。
const maxConcurrentReads = 4
let activeReads = 0
const waitingReads: Array<() => void> = []

async function limitedRead<T>(run: () => Promise<T>): Promise<T> {
  if (activeReads < maxConcurrentReads) activeReads += 1
  else await new Promise<void>((resolve) => waitingReads.push(resolve))
  try {
    return await run()
  } finally {
    const next = waitingReads.shift()
    if (next) next()
    else activeReads -= 1
  }
}

// 服务端暂时失败（网络、超时、限流、5xx）才自动重试；403/404 等确定结果不重试。
function transient(error: unknown): boolean {
  return error instanceof ApiError &&
    (error.status === 0 || error.status === 408 || error.status === 425 || error.status === 429 || error.status >= 500)
}
const failedRowRefetchMilliseconds = 10_000

function placeholder(eventType: NotificationSubscription['event_type']): NotificationSubscription {
  return { event_type: eventType, sms_enabled: false, email_enabled: false, sms_supported: false, email_supported: false, revision: 0, changed: false }
}

function requestKey(): string {
  return `ticket-subscription-${globalThis.crypto?.randomUUID?.() ?? Date.now().toString(36)}`
}

// tp-b7：原"套餐与工单通知"卡并进消息订阅表，每个事件一行，切换即保存
// （GET/PUT /v1/account/notification-subscriptions/{event}，请求体与原卡相同）。
// 租户的 rows 是 6 个主消息类型（每行合并组内事件），extraRows 是"更多消息类型"里逐事件的行；
// 平台工单成员（grouped=false）照旧逐事件一行。
export type EventSubscriptionRows = { rows: EventSubscriptionRow[]; extraRows: EventSubscriptionRow[]; grouped: boolean; error: unknown }

export function useEventSubscriptionRows(): EventSubscriptionRows {
  const { t } = useTranslation('tickets')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const principal = useSessionStore((state) => state.principal)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const client = useQueryClient()
  // Same lineage rule as the announcement subscription on this page: only a
  // well-formed tenant session reads or writes its own subscriptions.
  const tenant = principal?.scope_kind === 'tenant' && Boolean(principal.tenant_id)
  const staff = principal?.scope_kind === 'platform' && principal.tenant_id === null &&
    ['tickets.manage', 'platform.admin'].some((permission) => principal.permissions.includes(permission))
  const enabled = Boolean(token) && epoch >= 1 && (tenant || staff) && Boolean(principal?.scope_id) && Boolean(principal?.user_id)
  const eventTypes: readonly EventType[] = !enabled ? [] : staff ? staffEvents : tenantEvents
  const key = (event: EventType) => ['ticket-subscription', principal?.scope_id, principal?.user_id, epoch, event] as const
  const queries = useQueries({
    queries: eventTypes.map((event) => ({
      queryKey: key(event), queryFn: () => limitedRead(() => notificationsApi.getSubscription(token, event)),
      retry: (failures: number, error: unknown) => failures < 1 && transient(error),
      retryDelay: 1000,
      // 失败的行定时再读，服务恢复后不用刷新页面就能恢复显示。
      refetchInterval: (query: { state: { status: string; error: unknown } }) =>
        query.state.status === 'error' && transient(query.state.error) ? failedRowRefetchMilliseconds : false,
    })),
  })
  const save = useMutation({
    mutationFn: ({ current, change }: { current: NotificationSubscription; change: SubscriptionWrite }) =>
      notificationsApi.putSubscription(token, current.event_type, change, current.revision, requestKey()),
    onSuccess: (value) => client.setQueryData(key(value.event_type as EventType), value),
    onError: (_, { current }) => { void client.invalidateQueries({ queryKey: key(current.event_type as EventType) }) },
  })
  const [groupWrites, setGroupWrites] = useState<Partial<Record<GroupKey, { target: GroupTarget; pending: boolean; failed?: string }>>>({})
  const anyGroupPending = Object.values(groupWrites).some((write) => write?.pending)
  const byEvent = new Map(eventTypes.map((event, index) => [event, queries[index]]))

  // 一行写入同步到组内每个事件（逐个现有接口，与读取共用最多 4 个并发）：只改被切换的渠道、只写还没到目标的事件，
  // 所以重试只补失败的那几个。任何一个失败，该行显示失败与重试；失败事件重新读取拿到最新版本。
  const writeGroup = async (group: typeof tenantGroups[number], target: GroupTarget) => {
    setGroupWrites((current) => ({ ...current, [group.key]: { target, pending: true } }))
    const pendingEvents = group.events.flatMap((event) => {
      const current = client.getQueryData<NotificationSubscription>(key(event))
      if (!current) return []
      const sms = target.sms === undefined || !current.sms_supported ? current.sms_enabled : target.sms
      const email = target.email === undefined || !current.email_supported ? current.email_enabled : target.email
      if (sms === current.sms_enabled && email === current.email_enabled) return []
      const change: SubscriptionWrite = { sms_enabled: sms, email_enabled: email,
        ...(current.inbox_enabled === undefined ? {} : { inbox_enabled: current.inbox_enabled }) }
      return [{ current, change }]
    })
    const results = await Promise.allSettled(pendingEvents.map((item) => limitedRead(() => save.mutateAsync(item))))
    const failure = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
    setGroupWrites((current) => ({ ...current, [group.key]: failure
      ? { target, pending: false, failed: failure.reason instanceof ApiError ? failure.reason.code : 'request_failed' }
      : undefined }))
  }

  const eventRow = (event: EventType): EventSubscriptionRow => {
    const query = byEvent.get(event)!
    const label = t(`subscriptions.events.${event.replace(/\./g, '_')}`)
    const value = query.data
    if (value?.event_type === event) {
      return {
        key: event, label, value,
        disabled: save.isPending || anyGroupPending,
        onChange: (change: SubscriptionWrite) => save.mutate({ current: value, change }),
      }
    }
    const failed = query.isError && !query.isFetching
    return {
      key: event, label, value: placeholder(event), disabled: true, onChange: () => undefined,
      notice: failed
        ? t('subscriptions.loadFailed', { code: query.error instanceof ApiError ? query.error.code : 'request_failed' })
        : t('subscriptions.loading'),
      retry: failed ? { label: t('subscriptions.retry'), run: () => { void query.refetch() } } : undefined,
    }
  }

  // 一个消息类型一行：某渠道组内全部开启才显示为开；只要组内有事件支持该渠道就有开关。
  const groupRow = (group: typeof tenantGroups[number]): EventSubscriptionRow => {
    const label = t(`subscriptions.groups.${group.key}.label`)
    const hint = t(`subscriptions.groups.${group.key}.hint`)
    const members = group.events.map((event) => byEvent.get(event)!)
    const values = members.flatMap((query, index) => query.data?.event_type === group.events[index] ? [query.data] : [])
    if (values.length !== group.events.length) {
      const failed = members.filter((query) => query.isError && !query.isFetching)
      const code = failed[0]?.error instanceof ApiError ? failed[0].error.code : 'request_failed'
      return {
        key: group.key, label, hint, value: placeholder(group.events[0]), disabled: true, onChange: () => undefined,
        notice: failed.length ? t('subscriptions.loadFailed', { code }) : t('subscriptions.loading'),
        retry: failed.length ? { label: t('subscriptions.retry'), run: () => { failed.forEach((query) => { void query.refetch() }) } } : undefined,
      }
    }
    const smsValues = values.filter((value) => value.sms_supported)
    const emailValues = values.filter((value) => value.email_supported)
    const value: NotificationSubscription = {
      ...values[0],
      sms_supported: smsValues.length > 0, email_supported: emailValues.length > 0,
      sms_enabled: smsValues.length > 0 && smsValues.every((item) => item.sms_enabled),
      email_enabled: emailValues.length > 0 && emailValues.every((item) => item.email_enabled),
      inbox_enabled: undefined,
    }
    const write = groupWrites[group.key]
    return {
      key: group.key, label, hint, value,
      disabled: save.isPending || anyGroupPending,
      onChange: (change) => {
        const target: GroupTarget = change.sms_enabled !== value.sms_enabled ? { sms: change.sms_enabled } : { email: change.email_enabled }
        void writeGroup(group, target)
      },
      notice: write?.failed ? t('subscriptions.saveFailed', { code: write.failed }) : undefined,
      retry: write?.failed && !write.pending ? { label: t('subscriptions.retry'), run: () => { void writeGroup(group, write.target) } } : undefined,
    }
  }

  if (staff || !enabled) return { rows: eventTypes.map(eventRow), extraRows: [], grouped: false, error: save.error }
  return {
    rows: tenantGroups.map(groupRow),
    extraRows: tenantExtraEvents.map(eventRow),
    grouped: true,
    // 分组写入的失败显示在该行上（带重试），不再在页顶重复提示。
    error: Object.values(groupWrites).some(Boolean) ? null : save.error,
  }
}
