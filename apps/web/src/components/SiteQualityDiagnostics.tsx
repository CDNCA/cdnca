import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Result, Spin, Table, Tag } from 'antd'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  qualityDiagnosticsApi,
  type QualityDiagnostic,
  type QualityDiagnosticsAudience,
  type QualityDiagnosticsFilters,
  type QualityDiagnosticsSnapshot,
} from '../api/qualityDiagnostics'
import '../i18n/qualityDiagnostics'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { FeedbackWhen } from '@cdnca/ui'

interface SiteQualityDiagnosticsProps {
  accessToken: string
  audience: QualityDiagnosticsAudience
  filters: Omit<QualityDiagnosticsFilters, 'cursor' | 'limit'>
}

interface PageCursor {
  cursor?: string
  snapshot?: string
}

function snapshotFingerprint(snapshot: QualityDiagnosticsSnapshot): string {
  return `${snapshot.at}|${snapshot.source_watermark}|${snapshot.finalized_through}|${snapshot.expires_at}`
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.requestFailed'
  if (error.status === 409 || error.code === 'quality_diagnostics_snapshot_conflict') return 'states.snapshot'
  if (error.status === 503 || error.code === 'quality_diagnostics_unavailable') return 'states.unavailable'
  if (error.status === 504 || error.code === 'quality_diagnostics_timeout') return 'states.timeout'
  if (error.status === 502 || error.code === 'quality_diagnostics_invalid_source_response' || error.code === 'invalid_response') return 'states.invalidResponse'
  return 'states.requestFailed'
}

export default function SiteQualityDiagnostics({ accessToken, audience, filters }: SiteQualityDiagnosticsProps) {
  const { t, i18n } = useTranslation('qualityDiagnostics')
  const [pages, setPages] = useState<PageCursor[]>([{}])
  const [pageIndex, setPageIndex] = useState(0)
  const page = pages[pageIndex]
  const queryFilters: QualityDiagnosticsFilters = { ...filters, limit: 20, cursor: page.cursor }
  const query = useQuery({
    queryKey: ['quality-diagnostics', audience, queryFilters],
    enabled: accessToken !== '',
    queryFn: ({ signal }) => qualityDiagnosticsApi.read(accessToken, audience, queryFilters, signal),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const snapshotMismatch = query.data !== undefined && page.snapshot !== undefined &&
    snapshotFingerprint(query.data.snapshot) !== page.snapshot
  const columns = [
    { title: t('columns.time'), dataIndex: 'occurred_at', key: 'time', width: 170, render: (value: string) => formatDateTime(value, language) },
    { title: t('columns.category'), dataIndex: 'category', key: 'category', width: 130, render: (value: QualityDiagnostic['category']) => <Tag>{t(`categories.${value}`)}</Tag> },
    { title: t('columns.cause'), dataIndex: 'cause_code', key: 'cause', width: 200, render: (value: QualityDiagnostic['cause_code']) => t(`causes.${value}`) },
    { title: t('columns.action'), dataIndex: 'action_code', key: 'action', width: 170, render: (value: QualityDiagnostic['action_code']) => t(`actions.${value}`) },
    { title: t('columns.status'), dataIndex: 'status_code', key: 'status', width: 90 },
    { title: t('columns.site'), dataIndex: 'site_id', key: 'site', width: 290 },
    { title: t('columns.config'), dataIndex: 'config_version_id', key: 'config', width: 290 },
    { title: t('columns.installation'), dataIndex: 'installation_id', key: 'installation', width: 290 },
    { title: t('columns.node'), dataIndex: 'node_id', key: 'node', width: 290 },
    { title: t('columns.request'), dataIndex: 'request_id', key: 'request', width: 190 },
    { title: t('columns.task'), dataIndex: 'task_id', key: 'task', width: 290, render: (value: string | null) => value ?? t('values.none') },
    { title: t('columns.trace'), dataIndex: 'trace_id', key: 'trace', width: 190 },
  ]

  if (!accessToken || query.error instanceof ApiError && (query.error.status === 401 || query.error.status === 403)) {
    return <Result status="403" title={t('states.permission')} />
  }
  const nextCursor = snapshotMismatch ? null : query.data?.next_cursor ?? null
  return <section className="analytics-diagnostics" aria-labelledby="quality-diagnostics-title">
    <h2 id="quality-diagnostics-title">{t('title')}</h2>
    {query.error ? <FeedbackWhen title={t(errorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
    {snapshotMismatch ? <Alert type="error" showIcon message={t('states.invalidResponse')} /> : null}
    {query.isPending ? <div className="analytics-chart-state" aria-label={t('states.loading')}><Spin size="small" /></div> : null}
    {query.data && !snapshotMismatch ? <>
      <div className="analytics-meta" aria-label={t('title')}>
        <span className="analytics-meta-item">{t('evidence.snapshot', { time: formatDateTime(query.data.snapshot.at, language) })}</span>
        <span className="analytics-meta-item">{t('evidence.watermark', { value: formatNumber(query.data.snapshot.source_watermark, language) })}</span>
        <span className="analytics-meta-item">{t('evidence.finalized', { time: formatDateTime(query.data.snapshot.finalized_through, language) })}</span>
        <span className="analytics-meta-item">{t('evidence.expires', { time: formatDateTime(query.data.snapshot.expires_at, language) })}</span>
      </div>
      <Table<QualityDiagnostic> size="small" rowKey="event_id" columns={columns} dataSource={query.data.items} pagination={false} scroll={{ x: 2400 }} locale={{ emptyText: t('states.empty') }} />
      <div className="analytics-pagination">
        <Button aria-label={t('actions.previous')} icon={<ChevronLeft size={15} />} disabled={pageIndex === 0} onClick={() => setPageIndex((value) => value - 1)} />
        <Button aria-label={t('actions.next')} icon={<ChevronRight size={15} />} disabled={!nextCursor} onClick={() => {
          if (!nextCursor || !query.data) return
          setPages((current) => [...current.slice(0, pageIndex + 1), {
            cursor: nextCursor,
            snapshot: snapshotFingerprint(query.data.snapshot),
          }])
          setPageIndex((value) => value + 1)
        }} />
      </div>
    </> : null}
  </section>
}
