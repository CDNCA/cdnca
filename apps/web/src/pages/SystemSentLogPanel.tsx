import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Pagination, Select, Table, Tag, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { isNotificationHistoryID, notificationHistoryApi, type NotificationHistoryFact, type NotificationHistoryFilters } from '../api/notificationHistory'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { systemLogMessage } from '../i18n/systemLog'
import '../i18n/adminMessageQuery'
import '../i18n/systemSentLog'
import './SystemLogPage.css'
import './SystemSentLogPanel.css'
import { useSearchParams } from 'react-router-dom'
import { filterParam, useFilterUrl } from './filterUrl'
import { AdvancedFilters, FeedbackWhen, useLiveApply } from '@cdnca/ui'

const adminSentEventTypes = [
  'package-expiring', 'package-expire', 'traffic-exceeding', 'traffic-exceed', 'cc-switch',
  'bandwidth-exceed', 'connection-exceed', 'cert-expire', 'cert-expiring', 'account-auth2',
] as const

const eventTypeTranslationKeys: Record<string, string> = {
  'package-expiring': 'packageExpiring', 'package-expire': 'packageExpired',
  'traffic-exceeding': 'trafficExpiring', 'traffic-exceed': 'trafficExceeded',
  'cc-switch': 'ccRuleSwitch', 'bandwidth-exceed': 'bandwidthExceeded',
  'connection-exceed': 'connectionsExceeded', 'cert-expire': 'certificateExpired',
  'cert-expiring': 'certificateExpiring', 'account-auth2': 'secondaryVerification',
}

export default function SystemSentLogPanel() {
  const { t } = useTranslation('systemSentLog')
  const { accessToken, principal, sessionEpoch } = useSessionStore()
  if (!accessToken || !principal) return <Alert type="error" showIcon message={t('sessionExpired')} />
  // platform.admin 或 system_configuration.read 任一即可。
  const allowed = principal.permissions.includes('platform.admin') || principal.permissions.includes('system_configuration.read')
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !allowed) {
    return <Alert type="error" showIcon message={t('permissionDenied')} />
  }
  const owner = `${principal.scope_id}:${principal.user_id}:${sessionEpoch}`
  return <SentLogContent key={owner} owner={owner} accessToken={accessToken} />
}

function SentLogContent({ owner, accessToken }: { owner: string; accessToken: string }) {
  const { t, i18n } = useTranslation('systemSentLog')
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const text = (key: Parameters<typeof systemLogMessage>[1]) => systemLogMessage(language, key)
  // 已生效的用户ID/消息ID 写进 URL（user_id/message_id）。
  const [initialParams] = useSearchParams()
  const [userID, setUserID] = useState(() => filterParam(initialParams, 'user_id'))
  const [messageID, setMessageID] = useState(() => filterParam(initialParams, 'message_id'))
  const [eventType, setEventType] = useState<string>()
  const [channel, setChannel] = useState<NotificationHistoryFilters['channel']>()
  const [result, setResult] = useState<NotificationHistoryFilters['result']>()
  const [limit, setLimit] = useState(10)
  const [cursors, setCursors] = useState<string[]>([])
  // 用户ID/消息ID 先进草稿，停止输入 400ms 后生效（原先每次按键都查）。
  const [userDraft, setUserDraft] = useState(userID)
  const [messageDraft, setMessageDraft] = useState(messageID)
  const userValid = !userDraft || isNotificationHistoryID(userDraft, true)
  const messageValid = !messageDraft || isNotificationHistoryID(messageDraft)
  useLiveApply({ userID: userDraft, messageID: messageDraft }, { userID, messageID }, (next) => {
    setUserID(next.userID); setMessageID(next.messageID); setCursors([])
  }, { valid: userValid && messageValid })
  useFilterUrl({ user_id: userID, message_id: messageID })
  const filtersReady = userValid && messageValid
  const filters: NotificationHistoryFilters = { userID: userID || undefined, messageID: messageID || undefined, eventType, channel, result, limit, cursor: cursors.at(-1) }
  const query = useQuery({
    queryKey: ['notification-delivery-history', owner, filters],
    queryFn: ({ signal }) => notificationHistoryApi.list(accessToken, filters, signal),
    enabled: filtersReady,
    retry: false,
  })
  const resetPage = () => setCursors([])
  const eventLabel = (value: string) => {
    const key = eventTypeTranslationKeys[value]
    return key ? i18n.t(`adminMessageQuery:types.${key}`) : value
  }
  const columns: TableColumnsType<NotificationHistoryFact> = [
    { title: t('recipient'), width: '12.1%', render: (_, fact) => <span className="system-sent-recipient">
      <strong>{fact.recipient_user_display_id || fact.recipient_user_id
        ? t('user', { id: fact.recipient_user_display_id || fact.recipient_user_id })
        : t(fact.recipient_kind === 'anonymous' ? 'anonymous' : 'unknownRecipient')}</strong>
      <small>{fact.recipient_address_state === 'masked' ? fact.recipient_address : t('noSnapshot')}</small>
    </span> },
    { title: t('messageID'), dataIndex: 'message_id', width: '10.2%', render: (value: string) => <span className="system-sent-message-id">{value}</span> },
    { title: t('content'), width: '19.1%', render: () => <span className="system-sent-unavailable">{t('noSnapshot')}</span> },
    { title: t('channel'), dataIndex: 'channel', width: '9.5%', render: (value: string) => i18n.t(`notificationSettings:deliveries.channels.${value}`) },
    { title: t('failureCount'), dataIndex: 'failure_count', width: '8.9%', render: (value: number) => formatNumber(value, language) },
    { title: t('status'), dataIndex: 'state', width: '10.2%', render: (value: NotificationHistoryFact['state']) => <Tag
      color={value === 'delivered' ? 'success' : ['retry_wait', 'permanent_failed', 'exhausted'].includes(value) ? 'error' : 'default'}
      className="system-log-status-tag">{i18n.t(`notificationSettings:deliveries.states.${value}`)}</Tag> },
    { title: t('reason'), dataIndex: 'failure_code', width: '16.6%', render: (value: string | null) => value
      ? i18n.exists(`systemSentLog:reasons.${value}`) ? t(`reasons.${value}`) : t('unknownReason', { code: value })
      : '—' },
    { title: t('initiatedAt'), width: '13.4%', render: (_, fact) => <span className="system-sent-time">
      <span>{fact.provider_call_started_at ? formatDateTime(fact.provider_call_started_at, language) : t('notRecorded')}</span>
      <small>{t('recordedTime', { time: formatDateTime(fact.observed_at, language) })}</small>
    </span> },
  ]
  const total = filtersReady && !query.isError ? query.data?.total_count ?? 0 : 0
  const currentPage = cursors.length + 1
  const next = query.data?.next_cursor
  const canOpenPage = (page: number) => page >= 1 && !query.isFetching && !query.isError && filtersReady &&
    (page === 1 || page <= currentPage || page === currentPage + 1 && Boolean(next && !cursors.includes(next)))
  const errorKey = query.error instanceof ApiError && query.error.status === 403 ? 'permissionDenied'
    : query.error instanceof ApiError && query.error.status === 401 ? 'sessionExpired' : 'loadFailed'

  return <div className="system-sent-log-panel">
    <div className="system-sent-log-toolbar">
      <div className="system-sent-log-summary"><strong>{text('sent')}</strong><small>{t('summary', { count: formatNumber(total, language) })}</small></div>
      {/* 常显 类型、媒介、状态；用户ID、消息ID 收进高级筛选。条件改了即查（原样），刷新回第一页。 */}
      <AdvancedFilters
        className="system-sent-log-filters"
        storageKey="system-sent-log"
        columns={2}
        primary={<>
          <Select aria-label={t('allTypes')} value={eventType} allowClear placeholder={t('allTypes')}
            options={adminSentEventTypes.map((value) => ({ value, label: eventLabel(value) }))}
            onChange={(value) => { setEventType(value); resetPage() }} />
          <Select aria-label={t('allChannels')} value={channel} allowClear placeholder={t('allChannels')}
            options={(['sms', 'email'] as const).map((value) => ({ value, label: i18n.t(`notificationSettings:deliveries.channels.${value}`) }))}
            onChange={(value) => { setChannel(value); resetPage() }} />
          <Select<'' | 'success' | 'failure'> aria-label={t('allStates')} value={result ?? ''} allowClear
            options={[{ value: '', label: t('allStates') }, ...(['success', 'failure'] as const).map((value) => ({ value, label: t(value) }))]}
            onChange={(value) => { setResult(value || undefined); resetPage() }} />
        </>}
        items={[
          { key: 'userID', label: text('userIDColumn'), applied: userID,
            field: <Input aria-label={text('userIDColumn')} value={userDraft} placeholder={text('userPlaceholder')}
              status={!userValid ? 'error' : undefined} onChange={(event) => setUserDraft(event.target.value)} /> },
          { key: 'messageID', label: t('messageID'), applied: messageID,
            field: <Input aria-label={t('messageID')} value={messageDraft} placeholder={t('messagePlaceholder')}
              status={!messageValid ? 'error' : undefined} onChange={(event) => setMessageDraft(event.target.value)} /> },
        ]}
        queryText={text('refresh')}
        queryIcon={<RefreshCw size={15} />}
        queryLoading={query.isFetching}
        queryDisabled={!filtersReady || query.isFetching}
        onQuery={() => {
          if (cursors.length) resetPage()
          else void query.refetch()
        }}
        onClearAdvanced={() => { setUserDraft(''); setMessageDraft(''); setUserID(''); setMessageID(''); resetPage() }}
        onRemove={(key) => { if (key === 'userID') { setUserDraft(''); setUserID('') } else { setMessageDraft(''); setMessageID('') } resetPage() }}
      />
    </div>
    {!userValid ? <Alert type="error" showIcon message={text('invalidUser')} /> : null}
    {!messageValid ? <Alert type="error" showIcon message={t('invalidMessage')} /> : null}
    {query.isError ? <FeedbackWhen title={localizedUnknownApiError(query.error, t(errorKey))} /> : null}
    <div className="system-log-table-scroll">
      <Table<NotificationHistoryFact> rowKey="id" size="middle" columns={columns} tableLayout="fixed" pagination={false}
        loading={query.isFetching} dataSource={filtersReady && !query.isError ? query.data?.items ?? [] : []} locale={{ emptyText: t('empty') }} />
    </div>
    <div className="system-log-footer">
      <span>{i18n.t('adminMessageQuery:pagination.total', { total: formatNumber(total, language) })}</span>
      <div className="system-sent-pagination" aria-label={text('pagination')}>
        <Pagination current={currentPage} total={total} pageSize={limit} showSizeChanger={false} showTitle={false}
          disabled={query.isFetching || !filtersReady || query.isError} itemRender={(page, type, element) => type === 'page'
            ? <button type="button" aria-current={page === currentPage ? 'page' : undefined} disabled={!canOpenPage(page)}>{page}</button>
            : type === 'prev' || type === 'next' ? <span><Button aria-label={text(type === 'prev' ? 'previous' : 'next')}
              icon={type === 'prev' ? <ChevronLeft size={15} /> : <ChevronRight size={15} />}
              disabled={!canOpenPage(type === 'prev' ? currentPage - 1 : currentPage + 1) || type === 'prev' && currentPage === 1} /></span> : element}
          onChange={(page) => {
            if (!canOpenPage(page)) return
            if (page <= currentPage) setCursors((value) => value.slice(0, page - 1))
            else if (next) setCursors((value) => [...value, next])
          }} />
        <Select aria-label={text('pageSize')} value={limit} options={[10, 30, 100, 300].map((value) => ({ value, label: `${value} ${text('perPage')}` }))}
          onChange={(value) => { setLimit(value); resetPage() }} />
      </div>
    </div>
  </div>
}
