import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Empty, Input, Result, Segmented, Spin, Table, Tag, Tooltip, Typography, type TableColumnsType } from 'antd'
import { RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { nodeIsolationApi, type NodeIsolationState, type NodeIsolationStatus } from '../api/nodeIsolation'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/nodeIsolation'
import './NodeIsolationPage.css'
import { FeedbackWhen } from '@cdnca/ui'

type Owner = readonly [string, string, number]
type Filter = 'all' | NodeIsolationStatus

function owner(principal: Principal, epoch: number): Owner | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null ||
    !principal.scope_id || !principal.user_id || epoch < 1) return null
  return [principal.scope_id, principal.user_id, epoch]
}

function canRead(principal: Principal): boolean {
  return principal.scope_kind === 'platform' && principal.tenant_id === null && principal.permissions.includes('nodes.read')
}

function currentAccess(ownerKey: string): string | null {
  const state = useSessionStore.getState()
  if (!state.accessToken || !state.principal || !canRead(state.principal)) return null
  const current = owner(state.principal, state.sessionEpoch)
  return current && JSON.stringify(current) === ownerKey ? state.accessToken : null
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.request_failed'
  return `errors.${['node_isolation_unavailable', 'network_error', 'invalid_response'].includes(error.code)
    ? error.code
    : 'request_failed'}`
}

export default function NodeIsolationPage() {
  const { t } = useTranslation('nodeIsolation')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken || !principal) return null
  const fixedOwner = owner(principal, sessionEpoch)
  if (!fixedOwner || !canRead(principal)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  const ownerKey = JSON.stringify(fixedOwner)
  return <NodeIsolationContent key={ownerKey} owner={fixedOwner} ownerKey={ownerKey} />
}

function NodeIsolationContent({ owner: fixedOwner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t, i18n } = useTranslation('nodeIsolation')
  const [filter, setFilter] = useState<Filter>('all')
  const [search, setSearch] = useState('')
  const query = useQuery({
    queryKey: ['node-isolation', ...fixedOwner],
    queryFn: async () => {
      const token = currentAccess(ownerKey)
      if (!token) throw new ApiError('Session lineage changed', 401, 'request_failed')
      const result = await nodeIsolationApi.list(token)
      if (!currentAccess(ownerKey)) throw new ApiError('Session lineage changed', 401, 'request_failed')
      return result
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  const items = query.data ?? []
  const normalizedSearch = search.trim().toLowerCase()
  const filtered = useMemo(() => items.filter((item) =>
    (filter === 'all' || item.status === filter) && (!normalizedSearch || [
      item.node_id, item.desired.config_version_id, item.reason_code, item.last_error_code,
    ].some((value) => value.toLowerCase().includes(normalizedSearch)))), [filter, items, normalizedSearch])
  const isolatedCount = items.filter((item) => item.status === 'isolated').length
  const language = i18n.resolvedLanguage ?? i18n.language
  const columns: TableColumnsType<NodeIsolationState> = [
    { title: t('columns.node'), dataIndex: 'node_id', width: 250, ellipsis: true,
      render: (value: string) => <Typography.Text copyable>{value}</Typography.Text> },
    { title: t('columns.status'), dataIndex: 'status', width: 115,
      render: (value: NodeIsolationStatus) => <Tag color={value === 'isolated' ? 'error' : 'success'}>{t(`status.${value}`)}</Tag> },
    { title: t('columns.desired'), key: 'desired', width: 250, ellipsis: true,
      render: (_, item) => <Typography.Text copyable>{item.desired.config_version_id}</Typography.Text> },
    { title: t('columns.failures'), dataIndex: 'consecutive_failures', width: 100, align: 'right' },
    { title: t('columns.confirmations'), dataIndex: 'consecutive_healthy', width: 115, align: 'right' },
    { title: t('columns.outcome'), dataIndex: 'last_outcome', width: 115,
      render: (value: string) => t(`outcome.${value}`) },
    { title: t('columns.reason'), dataIndex: 'reason_code', width: 210,
      render: (value: string) => t(`reasons.${value}`) },
    { title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180,
      render: (value: string) => formatDateTime(value, language) || value },
  ]

  if (query.error instanceof ApiError && query.error.status === 403) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  return (
    <section className="node-isolation-page" aria-labelledby="node-isolation-title">
      <header className="node-isolation-heading">
        <h1 id="node-isolation-title">{t('title')}</h1>
        <Tooltip title={t('actions.refresh')}>
          <Button aria-label={t('actions.refresh')} icon={<RefreshCw size={16} />} loading={query.isFetching} onClick={() => void query.refetch()} />
        </Tooltip>
      </header>
      {isolatedCount > 0 ? <Alert type="warning" showIcon message={t('summary.isolated', { count: isolatedCount })} /> : null}
      <div className="node-isolation-toolbar">
        <Segmented<Filter>
          aria-label={t('filters.status')}
          value={filter}
          options={(['all', 'isolated', 'active'] as const).map((value) => ({ value, label: t(`filters.${value}`) }))}
          onChange={setFilter}
        />
        <Input.Search allowClear value={search} aria-label={t('filters.search')} placeholder={t('filters.search')} onChange={(event) => setSearch(event.target.value)} />
      </div>
      {query.isLoading ? <div className="node-isolation-state"><Spin tip={t('states.loading')} /></div> : null}
      {query.error ? <FeedbackWhen title={t('errors.loadFailed')} detail={t(errorKey(query.error))} action={<Button onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      {!query.isLoading && !query.error && filtered.length === 0 ? <Empty description={t(items.length ? 'states.filteredEmpty' : 'states.empty')} /> : null}
      {!query.isLoading && !query.error && filtered.length > 0 ? (
        <Table<NodeIsolationState> rowKey="node_id" columns={columns} dataSource={filtered} pagination={{ pageSize: 20, showSizeChanger: true }} scroll={{ x: 1345 }} size="small" />
      ) : null}
    </section>
  )
}
