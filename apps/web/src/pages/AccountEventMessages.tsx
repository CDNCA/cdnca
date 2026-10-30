import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Input, Modal, Pagination, Select, Space, Table, type TableColumnsType } from 'antd'
import { FeedbackWhen, IdOrNameInput, useLiveApply } from '@cdnca/ui'
import { Eye, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { accountNotificationEventTypes, notificationsApi, type OwnNotificationMessage } from '../api/notifications'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/tickets'
import { siteSearch } from './idNameSources'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const validKeyword = (value: string) => value.length <= 128 && ![...value].some((char) => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f)
// A full UUID filters by ID; other text is a name / display-ID keyword.
const filterFor = (value: string, id: 'siteID' | 'packageID', keyword: 'site' | 'package') => {
  if (!value) return {}
  return uuidPattern.test(value.toLowerCase()) ? { [id]: value.toLowerCase() } : { [keyword]: value }
}
// 事件提醒只列可订阅的运营事件；公告在公告分类，工单事件在工单页。
const eventTypes = accountNotificationEventTypes.filter((type) => type !== 'announcement.published' && !type.startsWith('ticket.'))

// SEC-ACCOUNT-07：本人事件消息（GET /v1/account/notification-messages），按类型/网站/用户套餐筛选，
// 网站与套餐 ID 是事件发生时记下的事实，不按当前套餐关系推断。
export default function AccountEventMessages({ accessToken, scopeID, sessionEpoch }: { accessToken: string; scopeID: string; sessionEpoch: number }) {
  const { t, i18n } = useTranslation('accountMessages')
  const { t: eventLabel } = useTranslation('tickets')
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const [type, setType] = useState<string>()
  const [siteDraft, setSiteDraft] = useState('')
  const [packageDraft, setPackageDraft] = useState('')
  // Site / user package take a full ID or a
  // name (domain, package name) or display ID and apply as typed; a picked site
  // suggestion filters by its ID. Over-long or control-character text is marked
  // on its box and not sent (field errors stay in place).
  const [applied, setApplied] = useState({ site: '', package: '' })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [selected, setSelected] = useState<OwnNotificationMessage | null>(null)

  const filters = { ...filterFor(applied.site, 'siteID', 'site'), ...filterFor(applied.package, 'packageID', 'package') }
  const query = useQuery({
    queryKey: ['account-event-messages', scopeID, sessionEpoch, type ?? '', filters, pageSize, page],
    queryFn: () => notificationsApi.listOwnMessages(accessToken, { type, ...filters, limit: pageSize, offset: (page - 1) * pageSize }),
  })
  const label = (value: string) => {
    const key = `subscriptions.events.${value.replace(/\./g, '_')}`
    return i18n.exists(key, { ns: 'tickets' }) ? eventLabel(key) : value
  }
  const draft = { site: siteDraft.trim(), package: packageDraft.trim() }
  const invalid = { site: !validKeyword(draft.site), package: !validKeyword(draft.package) }
  const apply = (next: typeof draft) => {
    setApplied(next)
    setPage(1)
  }
  useLiveApply(draft, applied, apply, { valid: !invalid.site && !invalid.package })
  // 查询：有未生效改动时立即生效，否则立即刷新。
  const search = () => {
    if (invalid.site || invalid.package) return
    if (draft.site !== applied.site || draft.package !== applied.package) apply(draft)
    else void query.refetch()
  }
  const siteOptions = useMemo(() => siteSearch(accessToken, 'id'), [accessToken])

  const columns = useMemo<TableColumnsType<OwnNotificationMessage>>(() => [
    { title: t('columns.type'), dataIndex: 'type', width: 180, render: (value: string) => label(value) },
    { title: t('columns.title'), dataIndex: 'title', ellipsis: true, render: (value: string | null) => value || t('events.noTitle') },
    { title: t('columns.packageID'), dataIndex: 'package_id', width: 150, ellipsis: true, render: (value: string | null) => value ?? t('events.none') },
    { title: t('columns.siteID'), dataIndex: 'site_id', width: 150, ellipsis: true, render: (value: string | null) => value ?? t('events.none') },
    { title: t('columns.createdAt'), dataIndex: 'created_at', width: 180, render: (value: string) => formatDateTime(value, language) || value },
    {
      title: t('columns.action'), key: 'action', width: 90, align: 'right',
      render: (_value, item) => <Button type="link" size="small" icon={<Eye size={14} />} onClick={(event) => { event.stopPropagation(); setSelected(item) }}>{t('actions.view')}</Button>,
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [language, t])

  const failure = query.isError
    ? (query.error instanceof ApiError && query.error.code === 'permission_denied' ? t('errors.permissionDenied') : localizedUnknownApiError(query.error, t('errors.requestFailed')))
    : null

  return <>
    <div className="identity-toolbar account-messages-toolbar">
      <Select allowClear className="account-messages-filter" aria-label={t('filters.type')} placeholder={t('filters.allTypes')} value={type}
        onChange={(value?: string) => { setType(value); setPage(1) }} style={{ width: 200 }}
        options={eventTypes.map((value) => ({ value, label: label(value) }))} />
      <IdOrNameInput aria-label={t('filters.siteID')} placeholder={t('filters.sitePlaceholder')} value={siteDraft} onChange={setSiteDraft} onPressEnter={search} style={{ width: 200 }}
        freeText isId={(text) => uuidPattern.test(text.toLowerCase())} search={siteOptions} status={invalid.site ? 'error' : undefined} />
      <Input aria-label={t('filters.packageID')} placeholder={t('filters.packagePlaceholder')} value={packageDraft} onChange={(event) => setPackageDraft(event.target.value)} onPressEnter={search} style={{ width: 200 }}
        status={invalid.package ? 'error' : undefined} aria-invalid={invalid.package || undefined} aria-describedby={invalid.site || invalid.package ? 'account-messages-filter-error' : undefined} />
      <Space>
        <Button type="primary" onClick={search}>{t('filters.search')}</Button>
        <Button className="account-messages-refresh" icon={<RefreshCw size={14} />} onClick={() => void query.refetch()} loading={query.isFetching}>{t('actions.refresh')}</Button>
      </Space>
    </div>
    {invalid.site || invalid.package ? <p id="account-messages-filter-error" className="account-messages-filter-error" role="alert">{t('filters.invalidKeyword')}</p> : null}
    <p className="account-messages-hint">{t('events.hint')}</p>
    {failure ? <FeedbackWhen title={failure} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
    <div className="identity-table-scroll account-messages-table-scroll" aria-busy={query.isPending || query.isFetching}>
      <Table<OwnNotificationMessage> rowKey="id" size="small" columns={columns} dataSource={query.data?.items ?? []} loading={query.isPending}
        pagination={false} scroll={{ x: 900 }} locale={{ emptyText: query.isError ? t('values.error') : t('values.empty') }}
        onRow={(item) => ({ onClick: () => setSelected(item), style: { cursor: 'pointer' } })} />
    </div>
    <Pagination className="account-messages-pagination" current={page} pageSize={pageSize} total={query.data?.total ?? 0}
      showSizeChanger pageSizeOptions={[10, 20, 50]}
      showTotal={(count) => t('values.total', { count: formatNumber(count, language) })}
      onChange={(nextPage, nextSize) => { setPage(nextSize === pageSize ? nextPage : 1); setPageSize(nextSize) }} />
    <Modal className="announcement-detail-modal account-messages-detail-modal" open={Boolean(selected)}
      title={selected ? selected.title || label(selected.type) : undefined}
      footer={<Button onClick={() => setSelected(null)}>{t('actions.close')}</Button>} onCancel={() => setSelected(null)} destroyOnHidden>
      {selected ? <>
        <div className="announcement-detail-meta">{label(selected.type)} · {formatDateTime(selected.created_at, language) || selected.created_at}</div>
        {selected.site_id ? <div className="announcement-detail-meta">{t('columns.siteID')}: {selected.site_id}</div> : null}
        {selected.package_id ? <div className="announcement-detail-meta">{t('columns.packageID')}: {selected.package_id}</div> : null}
        {/* 正文是投递时的纯文本快照，按文本显示，不当 HTML 渲染。 */}
        <p className="account-event-message-body">{selected.content || t('events.noContent')}</p>
      </> : null}
    </Modal>
  </>
}
