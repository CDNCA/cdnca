import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, ConfigProvider, Input, Pagination, Select, Space, Table, Typography, type TableColumnsType } from 'antd'
import { FeedbackWhen } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { nodeMonitoringApi, type NodeScopeServingEvent, type NodeScopeServingEventQuery } from '../api/nodeMonitoring'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import './NodeListPage.locale'

// A10/N06：切换日志接真实 node_serving_events（节点何时因何被摘出/恢复解析）。
// 查询成功且 0 条才显示"暂无数据"；无权限、查询失败分别展示，不冒充 0 条。

const sources = ['availability_monitor', 'auto_disable', 'config_sync', 'external_probe'] as const
const events = ['held', 'released', 'protected', 'protection_cleared'] as const
const pageSize = 10
const windowMs = 31 * 24 * 60 * 60 * 1000

type Filters = { source?: typeof sources[number]; event?: typeof events[number]; ip: string; node: string }
const emptyFilters: Filters = { ip: '', node: '' }

function nodeIDOf(value: string): string | undefined {
  const trimmed = value.trim().toLowerCase()
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(trimmed) ? trimmed : undefined
}

export default function NodeServingSwitchLog({ ownerKey }: { ownerKey: string }) {
  const { t, i18n } = useTranslation('nodeMonitorSettings')
  const { t: nt } = useTranslation('nodes')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const canRead = Boolean(principal && (principal.permissions.includes('nodes.read') || principal.permissions.includes('platform.admin')))
  const [draft, setDraft] = useState<Filters>(emptyFilters)
  const [applied, setApplied] = useState<Filters>(emptyFilters)
  const [page, setPage] = useState(1)
  const [windowEnd] = useState(() => new Date())
  const nodeInvalid = applied.node.trim() !== '' && !nodeIDOf(applied.node)
  const query = useMemo<NodeScopeServingEventQuery>(() => ({
    from: new Date(windowEnd.getTime() - windowMs).toISOString(), to: windowEnd.toISOString(), page, limit: pageSize,
    ...(applied.source ? { source: applied.source } : {}), ...(applied.event ? { event: applied.event } : {}),
    ...(applied.ip.trim() ? { ip: applied.ip.trim() } : {}), ...(nodeIDOf(applied.node) ? { nodeID: nodeIDOf(applied.node) } : {}),
  }), [applied, page, windowEnd])
  const result = useQuery({
    queryKey: ['node-serving-switch-log', ownerKey, query],
    queryFn: ({ signal }) => nodeMonitoringApi.listScopeServingEvents(accessToken!, query, signal),
    enabled: Boolean(accessToken) && canRead && !nodeInvalid,
    retry: false,
    refetchOnWindowFocus: false,
  })
  const language = i18n.resolvedLanguage ?? 'zh-CN'

  const apply = (next: Filters) => {
    setDraft(next)
    setApplied(next)
    setPage(1)
  }
  const columns: TableColumnsType<NodeScopeServingEvent> = [
    { title: t('switchLogs.columns.switchedAt'), dataIndex: 'occurred_at', width: 177, render: (value: string) => formatDateTime(value, language) || value },
    { title: t('switchLogs.columns.type'), dataIndex: 'source', width: 150, render: (value: NodeScopeServingEvent['source']) => nt(`monitorLog.servingSources.${value}`) },
    { title: t('switchLogs.columns.node'), dataIndex: 'node_name', width: 180, render: (_value: string, row) => <Typography.Text title={row.node_id}>{row.node_name}</Typography.Text> },
    { title: 'IP', key: 'ip', width: 200, render: (_value: unknown, row) => [row.ipv4, row.ipv6].filter(Boolean).join(' / ') || '—' },
    { title: t('switchLogs.columns.action'), dataIndex: 'event', width: 170, render: (value: NodeScopeServingEvent['event']) => nt(`monitorLog.servingEvents.${value}`) },
    { title: t('switchLogs.columns.reason'), dataIndex: 'reason_code', width: 220, render: (value: string) => nt(`monitorLog.servingReasons.${value}`, { defaultValue: value }) },
  ]

  if (!canRead) return <Alert type="warning" showIcon message={t('switchLogs.permissionDenied')} />

  // 切换日志是只读查询，不继承外层监控配置表单的"无修改权限即禁用"。
  return (
    <ConfigProvider componentDisabled={false}>
    <div className="node-monitor-switch-logs">
      <div className="node-monitor-switch-log-filters" role="search">
        <Select aria-label={t('switchLogs.filters.type')} placeholder={t('switchLogs.filters.allTypes')} allowClear value={draft.source}
          options={sources.map((value) => ({ value, label: nt(`monitorLog.servingSources.${value}`) }))}
          onChange={(value) => apply({ ...draft, source: value ?? undefined })} />
        <Select aria-label={t('switchLogs.filters.action')} placeholder={t('switchLogs.filters.allActions')} allowClear value={draft.event}
          options={events.map((value) => ({ value, label: nt(`monitorLog.servingEvents.${value}`) }))}
          onChange={(value) => apply({ ...draft, event: value ?? undefined })} />
        <Space.Compact block className="node-monitor-switch-log-control">
          <span className="node-monitor-switch-log-addon">{t('switchLogs.filters.ip')}</span>
          <Input aria-label={t('switchLogs.filters.ip')} placeholder={t('switchLogs.filters.ipPlaceholder')} value={draft.ip}
            onChange={(event) => setDraft({ ...draft, ip: event.target.value })} onPressEnter={() => apply(draft)} />
        </Space.Compact>
        <Space.Compact block className="node-monitor-switch-log-control">
          <span className="node-monitor-switch-log-addon">{t('switchLogs.filters.nodeID')}</span>
          <Input aria-label={t('switchLogs.filters.nodeID')} placeholder={t('switchLogs.filters.nodePlaceholder')} value={draft.node}
            status={nodeInvalid ? 'error' : undefined}
            onChange={(event) => setDraft({ ...draft, node: event.target.value })} onPressEnter={() => apply(draft)} />
        </Space.Compact>
        <Button type="primary" onClick={() => apply(draft)}>{t('switchLogs.actions.query')}</Button>
        <Button type="link" onClick={() => apply(emptyFilters)}>{t('switchLogs.actions.clear')}</Button>
      </div>
      <p className="node-monitor-switch-log-hint">{t('switchLogs.windowHint')}</p>
      {nodeInvalid ? <Alert type="error" showIcon message={t('switchLogs.invalidNode')} /> : null}
      {result.isError ? <FeedbackWhen
        title={result.error instanceof ApiError && result.error.status === 403 ? t('switchLogs.permissionDenied')
          : result.error instanceof ApiError && result.error.status === 400 ? t('switchLogs.invalidFilter') : t('switchLogs.loadFailed')}
        action={<Button size="small" onClick={() => void result.refetch()}>{t('switchLogs.actions.retry')}</Button>} /> : null}
      <Table<NodeScopeServingEvent>
        className="node-monitor-switch-log-table"
        rowKey="id"
        size="small"
        columns={columns}
        loading={result.isFetching}
        dataSource={result.data?.items ?? []}
        locale={{ emptyText: result.isError ? t('switchLogs.loadFailed') : result.isSuccess ? t('switchLogs.empty') : ' ' }}
        scroll={{ x: 1097 }}
        pagination={false}
      />
      <Pagination
        className="node-monitor-switch-log-pagination"
        current={page}
        pageSize={pageSize}
        total={Math.min(result.data?.total ?? 0, 1000 * pageSize)}
        showSizeChanger={false}
        responsive={false}
        onChange={setPage}
        showTotal={(total) => result.isSuccess ? t('switchLogs.total', { total: result.data?.total ?? total }) : ''}
      />
    </div>
    </ConfigProvider>
  )
}
