import { useCallback, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Modal, Pagination, Result, Segmented, Select, Space, Spin, Table, type TableColumnsType } from 'antd'
import { useFeedback, FeedbackWhen } from '@cdnca/ui'
import { Eye, MailOpen, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { announcementsApi, newAnnouncementIdempotencyKey, type InboxMessage, type InboxPage, type InboxState } from '../api/announcements'
import { ApiError } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import { AnnouncementBody } from '../components/AnnouncementBody'
import AccountEventMessages from './AccountEventMessages'
import './AccountMessagesPage.css'

export function SafeMarkdown({ value }: { value: string }) {
  return (
    <div className="announcement-markdown">
      {value.split(/\n{2,}/).map((block, index) => {
        const lines = block.split('\n')
        const first = lines[0] ?? ''
        if (/^#{1,3}\s/.test(first)) {
          const level = Math.min(first.match(/^#+/)?.[0].length ?? 1, 3)
          const text = first.replace(/^#{1,3}\s+/, '')
          return <div key={index} className={`announcement-markdown-h${level}`}>{text}</div>
        }
        if (lines.every((line) => /^[-*]\s+/.test(line))) {
          return <ul key={index}>{lines.map((line, lineIndex) => <li key={`${line}-${lineIndex}`}>{inlineMarkdown(line.slice(2))}</li>)}</ul>
        }
        return <p key={index}>{lines.map((line, lineIndex) => <span key={`${line}-${lineIndex}`}>{lineIndex > 0 ? <br /> : null}{inlineMarkdown(line)}</span>)}</p>
      })}
    </div>
  )
}

function inlineMarkdown(value: string) {
  const parts = value.split(/(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*]+\*)/g)
  return parts.map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>
    if ((part.startsWith('**') && part.endsWith('**')) || (part.startsWith('__') && part.endsWith('__'))) return <strong key={index}>{part.slice(2, -2)}</strong>
    if (part.startsWith('*') && part.endsWith('*')) return <em key={index}>{part.slice(1, -1)}</em>
    return <span key={index}>{part}</span>
  })
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

function errorText(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError) {
    if (error.code === 'permission_denied') return t('errors.permissionDenied')
    if (error.code === 'invalid_session') return t('errors.invalidSession')
    if (error.code === 'version_conflict' || error.code === 'idempotency_conflict') return t('errors.requestFailed')
  }
  return localizedUnknownApiError(error, t('errors.requestFailed'))
}

type StateAttempt = { item: InboxMessage; operation: 'delivered' | 'read'; key: string }

export default function AccountMessagesPage() {
  const { t } = useTranslation('accountMessages')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  // 平台管理员没有独立租户，此页展示管理员自己的收件箱，所以平台作用域按自身作用域放行。
  const selfScope =
    principal.scope_kind === 'tenant' ||
    (principal.scope_kind === 'platform' && principal.tenant_id === null)
  if (
    !selfScope ||
    !principal.permissions.includes('announcements.read')
  ) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permissionDenied')} />
  }

  return <AccountMessagesCategories key={`${principal.scope_id}:${sessionEpoch}`} accessToken={accessToken} scopeID={principal.scope_id} sessionEpoch={sessionEpoch} />
}

// SEC-ACCOUNT-07：公告保留原收件箱；事件提醒走本人通知事件投影（带事件时的网站/套餐 ID）。
function AccountMessagesCategories(props: { accessToken: string; scopeID: string; sessionEpoch: number }) {
  const { t } = useTranslation('accountMessages')
  const [category, setCategory] = useState<'announcements' | 'events'>('announcements')
  return (
    <section className="identity-page announcement-page account-messages-page" aria-labelledby="account-messages-title">
      {/* tp-b7：不放页内标题（面包屑即标题），h1 只留给读屏。 */}
      <h1 id="account-messages-title" className="visually-hidden">{t('title')}</h1>
      <Segmented className="account-messages-category" aria-label={t('filters.category')} value={category}
        onChange={(value) => setCategory(value as 'announcements' | 'events')}
        options={[{ value: 'announcements', label: t('filters.announcements') }, { value: 'events', label: t('filters.events') }]} />
      {category === 'announcements' ? <AccountMessagesContent {...props} /> : <AccountEventMessages {...props} />}
    </section>
  )
}

function AccountMessagesContent({
  accessToken,
  scopeID,
  sessionEpoch,
}: {
  accessToken: string
  scopeID: string
  sessionEpoch: number
}) {
  const { t, i18n } = useTranslation('accountMessages')
  const queryClient = useQueryClient()
  const feedback = useFeedback()
  const [filter, setFilter] = useState<'all' | 'unread' | 'read'>('all')
  // tp-b7：分页是"共 N 条 + 页码 + 条/页"，后端按 offset 返回同一筛选下的总数。
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [selected, setSelected] = useState<InboxMessage | null>(null)
  const [attempt, setAttempt] = useState<StateAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const offset = (page - 1) * pageSize

  const query = useQuery({
    queryKey: ['account-messages', scopeID, sessionEpoch, filter, pageSize, page],
    queryFn: () => announcementsApi.inbox(accessToken, { filter: filter === 'all' ? undefined : filter, limit: pageSize, offset: offset > 0 ? offset : undefined }),
  })

  const stateMutation = useMutation<InboxState, unknown, StateAttempt>({
    mutationFn: (value) => announcementsApi.state(accessToken, value.item.id, value.operation, value.item.state_revision, value.key),
    onSuccess: async (result, variables) => {
      setAttempt(null)
      setWriteError(null)
      setSelected((current) => current && current.id === variables.item.id
        ? { ...current, delivered_at: result.delivered_at, read_at: result.read_at, state_revision: result.revision }
        : current)
      queryClient.setQueriesData<InboxPage>({ queryKey: ['account-messages', scopeID, sessionEpoch] }, (page) => page ? {
        ...page,
        items: page.items.map((item) => item.id === variables.item.id
          ? { ...item, delivered_at: result.delivered_at, read_at: result.read_at, state_revision: result.revision }
          : item),
      } : page)
      if (variables.operation === 'read') await queryClient.invalidateQueries({ queryKey: ['account-messages', scopeID, sessionEpoch] })
    },
    onError: async (error, variables) => {
      setWriteError(error)
      if (outcomeUnknown(error)) {
        setAttempt(variables)
        return
      }
      setAttempt(null)
      if (error instanceof ApiError && error.code === 'version_conflict') {
        setSelected(null)
        await queryClient.invalidateQueries({ queryKey: ['account-messages', scopeID, sessionEpoch] })
      }
      feedback.error(errorText(error, t))
    },
  })
  const statePending = stateMutation.isPending
  const mutateState = stateMutation.mutate

  const beginState = useCallback((item: InboxMessage, operation: 'delivered' | 'read') => {
    if (attempt || statePending) return
    const nextAttempt = { item, operation, key: newAnnouncementIdempotencyKey(`message-${operation}`) }
    setAttempt(nextAttempt)
    setWriteError(null)
    mutateState(nextAttempt)
  }, [attempt, mutateState, statePending])

  const openDetail = useCallback((item: InboxMessage) => {
    setSelected(item)
    if (!item.delivered_at) beginState(item, 'delivered')
  }, [beginState])

  const retryState = () => { if (attempt) stateMutation.mutate(attempt) }
  const closeAndRefresh = () => {
    setAttempt(null)
    setWriteError(null)
    setSelected(null)
    void query.refetch()
  }
  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const writesLocked = stateMutation.isPending || uncertain
  const uncertainActions = uncertain ? <Space>
    <Button type="primary" loading={stateMutation.isPending} onClick={retryState}>{t('actions.retrySameRequest')}</Button>
    <Button disabled={stateMutation.isPending} onClick={closeAndRefresh}>{t('actions.closeAndRefresh')}</Button>
  </Space> : null

  // tp-b7：参考列为 所属用户ID / 类型 / 标题 / 用户套餐ID / 网站ID / 创建时间 / 操作。我方收件箱只有公告，
  // 没有类型、用户套餐、网站字段，这几列不做占位（见 b7.md 需后端）；"发布时间""状态"两列去掉，
  // 未读改为标题前的标记。创建时间就是这条消息投递给本人的时间（公告发布时间）。
  const columns = useMemo<TableColumnsType<InboxMessage>>(() => [
    {
      title: t('columns.title'), dataIndex: 'title', ellipsis: true,
      render: (value: string, item) => <span className="account-message-title">
        {!item.read_at ? <span className="account-message-unread-dot" role="img" aria-label={t('states.unread')} /> : null}
        <span style={{ color: item.red ? 'var(--cdnca-color-error)' : undefined, fontWeight: item.bold ? 700 : undefined }}>{value}</span>
      </span>,
    },
    { title: t('columns.createdAt'), dataIndex: 'published_at', width: 190, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value },
    {
      title: t('columns.action'), key: 'action', width: 190, align: 'right',
      render: (_value, item) => <span className="announcement-row-actions">
        <Button type="link" size="small" icon={<Eye size={14} />} disabled={writesLocked} onClick={(event) => { event.stopPropagation(); openDetail(item) }}>{t('actions.view')}</Button>
        {!item.read_at ? <Button type="link" size="small" icon={<MailOpen size={14} />} disabled={writesLocked} onClick={(event) => { event.stopPropagation(); setSelected(item); beginState(item, 'read') }}>{t('actions.markRead')}</Button> : null}
      </span>,
    },
  ], [beginState, i18n.resolvedLanguage, openDetail, t, writesLocked])

  if (query.isError && (query.error as ApiError)?.code === 'permission_denied') return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permissionDenied')} />
  const items = query.data?.items ?? []
  const total = query.data?.total ?? 0

  return (
    <>
      <div className="identity-toolbar account-messages-toolbar">
        <Select className="account-messages-filter" aria-label={t('filters.status')} value={filter} onChange={(value: 'all' | 'unread' | 'read') => { setFilter(value); setPage(1) }} options={[{ value: 'all', label: t('filters.all') }, { value: 'unread', label: t('states.unread') }, { value: 'read', label: t('states.read') }]} />
        <Button className="account-messages-refresh" icon={<RefreshCw size={14} />} onClick={() => void query.refetch()} loading={query.isFetching}>{t('actions.refresh')}</Button>
      </div>
      {writeError && !uncertain ? <FeedbackWhen title={errorText(writeError, t)} onClose={() => setWriteError(null)} /> : null}
      {query.isError && !(query.error instanceof ApiError && query.error.code === 'permission_denied') ? <FeedbackWhen title={errorText(query.error, t)} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <div className="identity-table-scroll account-messages-table-scroll" data-testid="account-messages-scroll" aria-busy={query.isPending || query.isFetching}>
        <Table<InboxMessage> rowKey="id" size="small" columns={columns} dataSource={items} loading={query.isPending} pagination={false} locale={{ emptyText: query.isError ? t('values.error') : t('values.empty') }} scroll={{ x: 760 }} onRow={(item) => writesLocked
          ? { 'aria-disabled': true, style: { cursor: 'default' } }
          : { onClick: () => openDetail(item), style: { cursor: 'pointer' } }} />
      </div>
      <Pagination
        className="account-messages-pagination"
        current={page}
        pageSize={pageSize}
        total={total}
        disabled={writesLocked}
        showSizeChanger
        pageSizeOptions={[10, 20, 50]}
        showTotal={(count) => t('values.total', { count: formatNumber(count, i18n.resolvedLanguage ?? 'zh-CN') })}
        onChange={(nextPage, nextSize) => { setPage(nextSize === pageSize ? nextPage : 1); setPageSize(nextSize) }}
      />
      <Modal
        className="announcement-detail-modal account-messages-detail-modal"
        open={Boolean(selected)}
        title={selected?.title}
        footer={uncertain
          ? uncertainActions
          : selected && !selected.read_at
            ? <Button type="primary" icon={<MailOpen size={15} />} loading={stateMutation.isPending} disabled={stateMutation.isPending} onClick={() => beginState(selected, 'read')}>{t('actions.markRead')}</Button>
            : <Button onClick={() => setSelected(null)}>{t('actions.close')}</Button>}
        closable={!writesLocked}
        maskClosable={!writesLocked}
        onCancel={uncertain ? closeAndRefresh : () => setSelected(null)}
        destroyOnHidden
      >
        {uncertain ? <Alert className="identity-alert" type="warning" showIcon message={t('uncertainty.title')} description={t('uncertainty.description')} /> : null}
        {selected && !selected.delivered_at && stateMutation.isPending ? (
          <Spin aria-label={t('values.delivering')} />
        ) : selected ? (
          <>
            <div className="announcement-detail-meta">{formatDateTime(selected.published_at, i18n.resolvedLanguage ?? 'zh-CN') || selected.published_at}</div>
            {selected.format === 'link' || /<[a-z][\s\S]*>/i.test(selected.body) ? <AnnouncementBody item={selected} /> : <SafeMarkdown value={selected.body} />}
          </>
        ) : null}
      </Modal>
    </>
  )
}
