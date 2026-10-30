import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Modal, Select, Table, Tag, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { backupHistoryApi, type BackupHistoryRecord, type BackupHistoryState } from '../api/backupHistory'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { systemLogCodeMessage, systemLogMessage } from '../i18n/systemLog'
import './SystemLogPage.css'
import { FeedbackWhen } from '@cdnca/ui'

export default function SystemBackupLogPanel() {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const { accessToken, principal } = useSessionStore()
  const text = (key: Parameters<typeof systemLogMessage>[1], variables?: Record<string, string | number>) => systemLogMessage(language, key, variables)
  const [pageSize, setPageSize] = useState<10 | 30 | 100 | 300>(10)
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [details, setDetails] = useState<BackupHistoryRecord>()
  const canRead = principal?.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  // Competitor parity: the backup log has no filters, only refresh and paging.
  const filters = useMemo(() => ({ limit: pageSize, cursor: cursorStack.at(-1) }), [cursorStack, pageSize])
  const query = useQuery({
    queryKey: ['system-backup-history', principal?.scope_id, filters],
    queryFn: () => backupHistoryApi.list(accessToken!, filters),
    enabled: Boolean(accessToken && canRead),
    placeholderData: (previous, previousQuery) => previousQuery?.queryKey[1] === principal?.scope_id ? previous : undefined,
    retry: false,
  })
  const items = query.data?.items ?? []
  const total = query.data?.total_count ?? 0
  const currentPage = cursorStack.length + 1
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const resetPage = () => setCursorStack([])
  const statusLabel = (value: BackupHistoryState) => text(value === 'succeeded' ? 'backupStateSucceeded' : value === 'failed' ? 'backupStateFailed' : 'backupStateUnknown')
  const listStatusLabel = (value: BackupHistoryState) => value === 'succeeded' ? text('backupStateCompleted') : statusLabel(value)
  const resultLabel = (record: BackupHistoryRecord) => {
    if (record.outcome_unknown || record.state === 'unknown') return text('backupResultUnknown')
    if (record.result_code === 'backup_succeeded') return text('backupResultSucceeded')
    if (record.state === 'failed') return text('backupResultFailed')
    return text('backupResultUnknown')
  }
  const terminalStateLabel = (record: BackupHistoryRecord) => {
    if (record.outcome_unknown || record.terminal_state === 'unavailable') return text('backupOutcomeUnknown')
    return record.terminal_state === 'succeeded' || record.terminal_state === 'failed'
      ? statusLabel(record.terminal_state)
      : text('backupUnknownCode', { code: record.terminal_state })
  }
  const errorMessage = query.error instanceof ApiError && query.error.status === 403
    ? text('backupPermissionDenied')
    : query.error instanceof ApiError && query.error.status === 503
      ? text('backupUnavailable')
      : text('backupLoadFailed')
  const columns = useMemo<TableColumnsType<BackupHistoryRecord>>(() => [
    { title: text('backupTimeColumn'), dataIndex: 'started_at', width: '25%', render: (value?: string) => value ? formatDateTime(value, language) : <span className="system-log-muted">{text('notRecorded')}</span> },
    { title: text('completionTimeColumn'), dataIndex: 'completed_at', width: '25%', render: (value?: string) => value ? formatDateTime(value, language) : <span className="system-log-muted">{text('notRecorded')}</span> },
    { title: text('backupStateColumn'), dataIndex: 'state', width: '16%', render: (value: BackupHistoryState) => <Tag className="system-log-status-tag" color={value === 'succeeded' ? 'success' : value === 'failed' ? 'error' : 'warning'}>{listStatusLabel(value)}</Tag> },
    { title: text('backupResultColumn'), dataIndex: 'result_code', width: '34%', render: (_value: string, record: BackupHistoryRecord) => {
      const label = resultLabel(record)
      const description = record.outcome_unknown ? text('backupOutcomeUnknown') : systemLogCodeMessage(language, 'backup_result', record.result_code)
      return <span className="system-backup-result-cell"><strong>{label}</strong>{description !== label ? <small>{description}</small> : null}<Button type="link" onClick={() => setDetails(record)}>{text('viewDetails')}</Button></span>
    } },
  ], [language, text])

  if (!canRead) return <Alert type="error" showIcon message={text('backupPermissionDenied')} />

  return <div className="system-backup-log-panel">
    <div className="system-backup-log-toolbar">
      <div className="system-backup-log-summary"><strong>{text('backup')}</strong><small>{text('backupSummary', { count: formatNumber(total, language), page: formatNumber(items.length, language) })}</small></div>
      <Button icon={<RefreshCw size={15} />} loading={query.isFetching} disabled={query.isFetching} onClick={() => { if (cursorStack.length) resetPage(); else void query.refetch() }}>{text('refresh')}</Button>
    </div>
    {query.isError ? <FeedbackWhen title={errorMessage} action={<Button size="small" onClick={() => void query.refetch()}>{text('refresh')}</Button>} /> : null}
    <div className="system-log-table-scroll">
      <Table<BackupHistoryRecord> rowKey="backup_id" size="middle" loading={query.isFetching} columns={columns} className="system-log-table"
        dataSource={items} pagination={false} locale={{ emptyText: text(query.data?.unconfigured ? 'backupUnconfigured' : 'emptyBackup') }} tableLayout="fixed" />
    </div>
    <div className="system-log-footer">
      <span>{text('total', { count: formatNumber(total, language) })}</span>
      <div className="system-log-pagination" aria-label={text('pagination')}>
        <Button aria-label={text('previous')} icon={<ChevronLeft size={15} />} disabled={cursorStack.length === 0 || query.isFetching} onClick={() => setCursorStack((value) => value.slice(0, -1))} />
        {paginationItems(totalPages, currentPage).map((page, index) => {
          if (page === 'ellipsis') return <span key={`ellipsis-${index}`} className="system-log-pagination-ellipsis" aria-hidden="true">…</span>
          const pageCursor = cursorStack[page - 2]
          const canOpen = !query.isFetching && (page === 1 || Boolean(pageCursor) || page === currentPage + 1 && Boolean(query.data?.next_cursor))
          return <Button key={page} type="default" disabled={!canOpen} aria-current={page === currentPage ? 'page' : undefined}
            className={`system-log-page-button${page === currentPage ? ' is-current' : ''}`} onClick={() => {
              if (page === 1) setCursorStack([])
              else if (pageCursor) setCursorStack((value) => value.slice(0, page - 1))
              else if (page === currentPage + 1 && query.data?.next_cursor) setCursorStack((value) => [...value, query.data!.next_cursor!])
            }}>{page}</Button>
        })}
        <Button aria-label={text('next')} icon={<ChevronRight size={15} />} disabled={!query.data?.next_cursor || query.isFetching} onClick={() => query.data?.next_cursor && setCursorStack((value) => [...value, query.data!.next_cursor!])} />
        <Select aria-label={text('pageSize')} value={pageSize} options={[10, 30, 100, 300].map((value) => ({ value, label: `${value} ${text('perPage')}` }))} onChange={(value) => { setPageSize(value); resetPage() }} />
      </div>
    </div>
    <Modal className="system-backup-details-modal" title={text('backupDetails')} open={Boolean(details)} onCancel={() => setDetails(undefined)} footer={<Button onClick={() => setDetails(undefined)}>{text('close')}</Button>}>
      {details ? <dl className="system-log-recorded-fields">
        <div><dt>{text('backupID')}</dt><dd>{details.backup_id}</dd></div>
        <div><dt>{text('backupTimeColumn')}</dt><dd>{details.started_at ? formatDateTime(details.started_at, language) : text('notRecorded')}</dd></div>
        <div><dt>{text('completionTimeColumn')}</dt><dd>{details.completed_at ? formatDateTime(details.completed_at, language) : text('notRecorded')}</dd></div>
        <div><dt>{text('backupStateColumn')}</dt><dd>{statusLabel(details.state)}</dd></div>
        <div><dt>{text('backupResultColumn')}</dt><dd>{systemLogCodeMessage(language, 'backup_result', details.result_code)}</dd></div>
        <div><dt>{text('backupReason')}</dt><dd>{systemLogCodeMessage(language, 'backup_reason', details.reason_code)}</dd></div>
        <div><dt>{text('backupSignature')}</dt><dd>{details.signature_valid ? text('backupSignatureValid') : text('backupSignatureInvalid')}</dd></div>
        <div><dt>{text('backupTerminalState')}</dt><dd>{terminalStateLabel(details)}</dd></div>
        {details.manifest_sha256 ? <div><dt>{text('backupManifest')}</dt><dd>{details.manifest_sha256}</dd></div> : null}
        {details.recovery_point_at ? <div><dt>{text('backupRecoveryPoint')}</dt><dd>{formatDateTime(details.recovery_point_at, language)}</dd></div> : null}
        {details.observed_rpo_seconds !== undefined ? <div><dt>{text('backupObservedRPO')}</dt><dd>{details.observed_rpo_seconds} s</dd></div> : null}
      </dl> : null}
    </Modal>
  </div>
}

function paginationItems(totalPages: number, currentPage: number): Array<number | 'ellipsis'> {
  if (totalPages <= 5) return Array.from({ length: totalPages }, (_, index) => index + 1)
  const window = currentPage <= 3 ? [1, 2, 3] : currentPage >= totalPages - 2 ? [totalPages - 2, totalPages - 1, totalPages] : [currentPage - 1, currentPage, currentPage + 1]
  const pages = new Set<number>([1, totalPages, ...window])
  const sorted = [...pages].filter((page) => page >= 1 && page <= totalPages).sort((left, right) => left - right)
  const items: Array<number | 'ellipsis'> = []
  sorted.forEach((page, index) => { if (index > 0 && page - sorted[index - 1] > 1) items.push('ellipsis'); items.push(page) })
  return items
}
