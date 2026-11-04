import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { logListQueryOptions, useLogListGeneration } from './logListQuery'
import { Alert, Button, Input, Select, Table, Tag, Tooltip, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  listMarketSecurityLogs, marketSecurityActions, type MarketSecurityAction, type MarketSecurityCounts, type MarketSecurityFilters,
  type MarketSecurityLog,
} from '../api/marketSecurity'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/marketSecurity'
import { FeedbackWhen, TimeRangeFilter, resolveTimeRangePreset, type TimeRangeValue } from '@cdnca/ui'

const pageSize = 10
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const maximumWindowMilliseconds = 31 * 24 * 60 * 60 * 1000

// 默认今天（当天 00:00 到次日 00:00）；最长 31 天，快捷项在点「查询」时按当前时钟重算。

interface Draft { tenantId: string; siteId: string; clientIp: string; host: string; action: MarketSecurityAction | '' }

// 拦截 / 挑战 / 封禁 / 仅记录 各自的回传请求数（meta.counts）。
const countKeys: Array<[keyof MarketSecurityCounts, MarketSecurityAction, string]> = [
  ['blocked', 'block', 'red'], ['challenged', 'challenge', 'orange'], ['banned', 'temporary_ban', 'volcano'], ['logged', 'log', 'blue'],
]

function draftWindow(value: TimeRangeValue) {
  return value.preset === 'custom' ? value.range : resolveTimeRangePreset(value.preset)
}

/** Attack log lines relayed by market leaf suppliers (ADR 0012 §19.1, ML-21). */
export default function MarketSecurityLogPanel() {
  const { t, i18n } = useTranslation('analyticsLogs')
  const { t: mt } = useTranslation('marketSecurity')
  const locale = i18n.resolvedLanguage
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const audience = principal?.scope_kind === 'platform' ? 'admin' : 'tenant'
  const [draft, setDraft] = useState<Draft>({ tenantId: '', siteId: '', clientIp: '', host: '', action: '' })
  const [timeRange, setTimeRange] = useState<TimeRangeValue>(() => ({ preset: 'today', range: draftWindow({ preset: 'today', range: null }) }))
  // A tenant sees today's relayed lines at once; a platform admin picks a tenant first.
  const [applied, setApplied] = useState<MarketSecurityFilters | null>(() => {
    const window = draftWindow(timeRange)
    return audience === 'tenant' && window ? { from: window[0].toISOString(), to: window[1].toISOString() } : null
  })
  const [error, setError] = useState<string | null>(null)
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined])
  const [pageIndex, setPageIndex] = useState(0)
  const cursor = cursors[pageIndex]

  const apply = () => {
    if (audience === 'admin' && !draft.tenantId.trim()) return setError(t('states.tenantRequired'))
    const ids = audience === 'admin' ? [draft.tenantId, draft.siteId] : [draft.siteId]
    if (ids.some((value) => value.trim() !== '' && !uuidPattern.test(value.trim()))) return setError(t('states.invalidUuid'))
    const window = draftWindow(timeRange)
    const from = window ? window[0].toDate() : new Date(Number.NaN)
    const to = window ? window[1].toDate() : new Date(Number.NaN)
    if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) return setError(t('states.invalidWindow'))
    if (to.getTime() - from.getTime() > maximumWindowMilliseconds) return setError(t('states.rangeTooLong'))
    setError(null)
    setApplied({
      from: from.toISOString(), to: to.toISOString(),
      ...(audience === 'admin' ? { tenantId: draft.tenantId.trim() } : {}),
      ...(draft.siteId.trim() ? { siteId: draft.siteId.trim() } : {}),
      ...(draft.clientIp.trim() ? { clientIp: draft.clientIp.trim() } : {}),
      ...(draft.host.trim() ? { host: draft.host.trim().toLowerCase() } : {}),
      ...(draft.action ? { action: draft.action } : {}),
    })
    setCursors([undefined])
    setPageIndex(0)
  }
  // control-log-ui：条件变了按新数据读；同一条件下翻页 30 秒内用缓存。
  const [generation] = useLogListGeneration(applied)
  const query = useQuery({
    queryKey: ['market-security-logs', audience, principal?.scope_id, generation, applied, cursor],
    queryFn: () => listMarketSecurityLogs(accessToken!, audience, applied!, pageSize, cursor),
    enabled: Boolean(accessToken && applied),
    retry: false,
    ...logListQueryOptions,
  })
  const columns: TableColumnsType<MarketSecurityLog> = [
    { title: t('table.occurredAt'), dataIndex: 'occurred_at', key: 'occurred_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: mt('table.source'), dataIndex: 'leaf_ref', key: 'source', width: 170, render: (value: string) => mt('source.marketLeaf', { leaf: value }) },
    { title: t('table.site'), dataIndex: 'site_id', key: 'site_id', width: 190, render: (value: string) => <code>{value}</code> },
    { title: t('table.host'), dataIndex: 'host', key: 'host', width: 190, render: (value: string) => <code>{value}</code> },
    { title: t('table.path'), dataIndex: 'path', key: 'path', width: 220, render: (value: string) => <code>{value}</code> },
    { title: t('table.clientIp'), dataIndex: 'client_ip', key: 'client_ip', width: 145, render: (value: string) => <code>{value}</code> },
    { title: mt('action.label'), dataIndex: 'action', key: 'action', width: 110, render: (value: string) => mt(`action.${value}`, { defaultValue: value || t('values.unknown') }) },
    { title: mt('table.detector'), dataIndex: 'detector', key: 'detector', width: 110, render: (value: string) => value || '-' },
    { title: t('table.rule'), dataIndex: 'rule_id', key: 'rule_id', width: 150, render: (value: string) => value ? <code>{value}</code> : '-' },
  ]
  const field = (key: keyof Draft, label: string) => (
    <label className="analytics-filter-field">
      <span>{label}</span>
      <Input aria-label={label} value={draft[key]} onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))} />
    </label>
  )
  return (
    <div className="analytics-panel" data-testid="market-security-panel">
      <Alert type="info" showIcon message={mt('hint')} />
      {/* 时间范围与本地节点页一样带上方标签，整栏底边对齐，按钮与输入框同一条线。 */}
      <div className="analytics-filter-bar market-security-filter-bar">
        {audience === 'admin' ? field('tenantId', t('filters.tenant')) : null}
        {field('siteId', t('filters.site'))}
        {field('host', t('filters.domain'))}
        {field('clientIp', t('filters.clientIp'))}
        <label className="analytics-filter-field">
          <span>{mt('action.label')}</span>
          <Select aria-label={mt('action.label')} virtual={false} value={draft.action}
            options={[{ value: '', label: mt('action.all') }, ...marketSecurityActions.map((value) => ({ value, label: mt(`action.${value}`) }))]}
            onChange={(value: Draft['action']) => setDraft((current) => ({ ...current, action: value }))} />
        </label>
        <div className="analytics-filter-field analytics-log-range-field"><span>{t('filters.timeRange')}</span>
          <TimeRangeFilter label={t('filters.timeRange')} allowClear={false} maxSpanMs={maximumWindowMilliseconds} value={timeRange} onChange={setTimeRange} /></div>
        <Button type="primary" onClick={apply}>{t('actions.query')}</Button>
      </div>
      {error ? <Alert className="analytics-page-error" type="error" showIcon message={error} /> : null}
      {query.data?.meta.counts ? (
        <div className="market-security-counts" data-testid="market-security-counts">
          <Tooltip title={mt('counts.hint')}><span>{mt('counts.label')}</span></Tooltip>
          {countKeys.map(([key, action, color]) => (
            <Tag key={key} color={color}>{mt(`action.${action}`)} {query.data!.meta.counts![key].toLocaleString(locale)}</Tag>
          ))}
        </div>
      ) : null}
      {query.error ? <FeedbackWhen title={t('states.requestFailed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <div className="analytics-log-table" data-testid="market-security-table">
        <Table<MarketSecurityLog>
          rowKey="cursor" size="small" columns={columns} dataSource={query.data?.data ?? []}
          loading={query.isFetching && (!query.data || query.isPlaceholderData)} pagination={false} scroll={{ x: 1500 }}
          locale={{ emptyText: applied ? t('states.empty') : t('states.selectTenant') }}
        />
      </div>
      <div className="analytics-pagination analytics-log-pagination">
        <Button aria-label={t('actions.previous')} icon={<ChevronLeft size={15} />} disabled={pageIndex === 0 || query.isFetching}
          onClick={() => setPageIndex((current) => Math.max(0, current - 1))} />
        <span>{t('pagination.page', { page: pageIndex + 1 })}</span>
        <Button aria-label={t('actions.next')} icon={<ChevronRight size={15} />} disabled={!query.data?.meta.next_cursor || query.isFetching}
          onClick={() => {
            const next = query.data?.meta.next_cursor
            if (!next) return
            setCursors((current) => [...current.slice(0, pageIndex + 1), next])
            setPageIndex((current) => current + 1)
          }} />
      </div>
    </div>
  )
}
