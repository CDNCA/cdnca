import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Descriptions, Drawer, Empty, Input, Result, Select, Space, Spin, Table, Tabs, Tag, Typography, type TableColumnsType } from 'antd'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import { auditLogCategories, auditLogsApi, type AuditLogCategory, type AuditLogFilters, type AuditLogItem } from '../api/auditLogs'
import { exportOwnerGuard } from '../auth/exportOwner'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/logCenter'
import { factRegion } from './logGeo'
import SystemBackupLogPanel from './SystemBackupLogPanel'
import SystemSentLogPanel from './SystemSentLogPanel'
import { useFilterUrl } from './filterUrl'
import { AdvancedFilters, TimeRangeFilter, resolveTimeRangePreset, useFeedback, useLiveApply, type TimeRangeValue } from '@cdnca/ui'
import './LogCenterPage.css'

// The attack and access logs are shown here, not linked out —
// the same components as /monitor/site/attack-log and /monitor/site/access-log.
const WafLogsPage = lazy(() => import('./WafLogsPage'))
const SiteAccessLogPage = lazy(() => import('./SiteAccessLogPage'))

// The old 系统日志 (/sys/log) merged in;
// 备份 / 发送记录 are its panels as they were.
type Tab = 'all' | 'auth' | 'operation' | 'backup' | 'sent' | 'attack' | 'access'
const tabOrder: readonly Tab[] = ['all', 'auth', 'operation', 'backup', 'sent', 'attack', 'access']
const operationCategories = auditLogCategories.filter((category) => category !== 'auth')

const resultColor: Record<AuditLogItem['result'], string> = { success: 'green', denied: 'orange', failure: 'red' }

function logCenterReadable(principal: Principal): boolean {
  return principal.scope_kind === 'platform' ? principal.permissions.includes('platform.admin') : principal.permissions.includes('identity.self.read')
}

// LogCenterPage is the unified log center: all / sign-in & security / operations
// (by category) share the filters, server-rendered sentences and the detail
// drawer; rows show tenant, username, object name, 国家-省-市 and UA (B6/B6b).
export default function LogCenterPage() {
  const { t, i18n } = useTranslation('logCenter')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const platform = principal?.scope_kind === 'platform'
  const canRead = Boolean(principal && logCenterReadable(principal))
  const lang = (i18n.resolvedLanguage ?? 'zh-CN').startsWith('en') ? 'en' : 'zh'
  // Old /sys/log?node_id=… links (redirected here) keep filtering by that object.
  const [searchParams] = useSearchParams()
  // 操作人/来源 IP/结果/对象 也可从分享链接带入。
  const linked = useMemo<AuditLogFilters>(() => {
    const value = (name: string) => searchParams.get(name)?.trim() || undefined
    const result = value('result')
    return Object.fromEntries(Object.entries({
      resourceId: value('node_id') ?? value('resource_id'), resourceType: value('resource_type'), actor: value('actor'), sourceIp: value('source_ip'),
      result: result === 'success' || result === 'denied' || result === 'failure' ? result : undefined,
    }).filter(([, item]) => item !== undefined)) as AuditLogFilters
  // 只在进入页面时读一次（之后由 useFilterUrl 回写）。
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const [tab, setTab] = useState<Tab>('all')
  const [operationCategory, setOperationCategory] = useState<AuditLogCategory>()
  const [draft, setDraft] = useState<AuditLogFilters>(linked)
  // Open until a range is chosen ('custom' with no window).
  const [range, setRange] = useState<TimeRangeValue>({ preset: 'custom', range: null })
  const [applied, setApplied] = useState<AuditLogFilters>(linked)
  // 已生效时的草稿与时间范围（比较是否有未生效改动）。
  const [appliedDraft, setAppliedDraft] = useState<{ draft: AuditLogFilters; range: TimeRangeValue }>({ draft: linked, range: { preset: 'custom', range: null } })
  const [cursors, setCursors] = useState<string[]>([])
  const [selected, setSelected] = useState<AuditLogItem>()
  const [exporting, setExporting] = useState(false)
  // 带着对象 ID 进来（旧 /sys/log?node_id=）时高级筛选默认展开（见 defaultOpen）。

  const external = tab === 'attack' || tab === 'access'
  const panel = tab === 'backup' || tab === 'sent'
  const filters = useMemo<AuditLogFilters>(() => ({
    ...applied,
    category: tab === 'auth' ? 'auth' : tab === 'operation' ? operationCategory : 'all',
    excludeCategory: tab === 'operation' && !operationCategory ? 'auth' : undefined,
    cursor: cursors.at(-1), limit: 50, lang,
  }), [applied, tab, operationCategory, cursors, lang])

  const page = useQuery({
    queryKey: ['audit-logs', filters],
    queryFn: () => auditLogsApi.list(accessToken ?? '', filters),
    enabled: Boolean(accessToken && canRead && !external && !panel),
  })

  // TEL-UX-EXPORT-OWNER：离开页面即取消；响应迟到时身份已变就丢弃，不下载也不提示。
  const exportAbortRef = useRef<AbortController | null>(null)
  useEffect(() => () => exportAbortRef.current?.abort(), [])
  // 文本条件 400ms 防抖、时间范围/下拉选完即生效（同一防抖，草稿变了就查）。
  useLiveApply({ draft: trimmed(draft), range }, { draft: trimmed(appliedDraft.draft), range: appliedDraft.range }, () => search(), { delay: 400 })
  useFilterUrl({ node_id: undefined, resource_id: applied.resourceId, resource_type: applied.resourceType, actor: applied.actor, source_ip: applied.sourceIp, result: applied.result })

  if (!accessToken || !principal || !canRead) return <Result status="403" title="403" subTitle={t('states.forbidden')} />

  function search(base: AuditLogFilters = draft, nextRange: TimeRangeValue = range) {
    // A quick range is relative: resolve it again when the user queries.
    const window = nextRange.preset === 'custom' ? nextRange.range : resolveTimeRangePreset(nextRange.preset)
    if (base !== draft) setDraft(base)
    setAppliedDraft({ draft: base, range: nextRange })
    setApplied({ ...base, since: window?.[0].toISOString(), until: window?.[1].toISOString() })
    setCursors([])
  }
  const reset = () => { setDraft({}); setRange({ preset: 'custom', range: null }); setAppliedDraft({ draft: {}, range: { preset: 'custom', range: null } }); setApplied({}); setCursors([]) }
  const download = async () => {
    exportAbortRef.current?.abort()
    const controller = new AbortController()
    exportAbortRef.current = controller
    const stillCurrent = exportOwnerGuard(logCenterReadable)
    setExporting(true)
    try {
      const blob = await auditLogsApi.export(accessToken, { ...filters, cursor: undefined }, { signal: controller.signal })
      if (controller.signal.aborted || !stillCurrent()) return
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = 'audit-logs.csv'
      anchor.click()
      URL.revokeObjectURL(url)
      message.success(t('states.exported'))
    } catch {
      if (controller.signal.aborted || !stillCurrent()) return
      feedback.error(t('states.error'))
    } finally {
      if (exportAbortRef.current === controller) setExporting(false)
    }
  }

  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  // redesign-a: 一行读成一句话——时间 · 谁（下一行租户）· 内容（下一行对象）· 来源（IP / 地理位置 / UA）· 结果；7 列不横向滚动。
  const columns: TableColumnsType<AuditLogItem> = [
    { title: t('columns.time'), dataIndex: 'time', width: 160, render: (value: string) => <span className="log-center-time">{value}</span> },
    { title: t('columns.actor'), key: 'actor', width: 150, render: (_, item) => <div className="log-center-cell">
      <span className="log-center-main">{item.actor_username || item.actor}</span>
      <span className="log-center-sub">{item.tenant_name || t('columns.platform')}</span>
    </div> },
    ...(tab === 'auth' ? [] : [{ title: t('columns.category'), dataIndex: 'category_label', width: 110 }]),
    { title: t('columns.summary'), key: 'summary', render: (_, item) => <div className="log-center-cell">
      <span className="log-center-main log-center-summary">{item.summary}</span>
      <span className="log-center-sub"><span className="log-center-sub-label">{t('columns.object')}</span>
        <span title={item.resource_id}>{objectLabel(item, t)}</span></span>
    </div> },
    { title: t('columns.source'), key: 'source', width: 220, render: (_, item) => {
      const region = factRegion({ geo_code: item.geo_code ?? '', geo_region: item.geo_region, geo_city: item.geo_city }, locale)
      const agent = !item.user_agent || item.user_agent === 'unknown' ? null : item.user_agent
      return <div className="log-center-cell">
        <span className="log-center-main log-center-ip">{item.source_ip || '-'}</span>
        {region ? <span className="log-center-sub">{region}</span> : null}
        {agent ? <span className="log-center-sub log-center-ua" title={agent}>{agent}</span> : null}
      </div>
    } },
    { title: t('columns.result'), dataIndex: 'result', width: 96, render: (value: AuditLogItem['result'], item) => <Tag color={resultColor[value]}>{item.result_label}</Tag> },
    { title: t('columns.detail'), key: 'detail', width: 72, render: (_, item) => <Button type="link" onClick={(event) => { event.stopPropagation(); setSelected(item) }}>{t('detail.open')}</Button> },
  ]

  // 读取失败就地报错：原因码翻成中文并附请求 ID，表格不再显示"没有符合条件的日志"（同 AccountLogPage）。
  const loadError = page.isError ? localizedUnknownApiError(page.error, t(errorKey(page.error))) : null
  const tabs = tabOrder.map((key) => ({ key, label: key === 'auth' ? t('categories.auth') : t(`tabs.${key}`) }))

  return <div data-testid="log-center" className="log-center-v2">
    <Typography.Title level={4}>{t('title')}</Typography.Title>
    <Typography.Paragraph type="secondary">{t('subtitle')}</Typography.Paragraph>
    <Tabs activeKey={tab} items={tabs}
      tabBarExtraContent={external || panel ? undefined : <Button loading={exporting} onClick={() => void download()}>{t('filters.export')}</Button>}
      onChange={(key) => { setTab(key as Tab); setCursors([]) }} />
    {tab === 'backup' ? <SystemBackupLogPanel /> : tab === 'sent' ? <SystemSentLogPanel /> : external
      ? <div data-testid={`log-center-${tab}`}><Suspense fallback={<Spin aria-label={t('states.loading')} />}>{tab === 'attack' ? <WafLogsPage /> : <SiteAccessLogPage />}</Suspense></div> : <>
      {/* 1440 宽下与查询/重置/高级筛选同一行——常显只留 时间范围、操作人；来源 IP、结果、分类、对象类型、对象 ID、作用域收进共享高级筛选。 */}
      <section className="log-center-filters" aria-label={t('filters.title')}>
        <AdvancedFilters
          storageKey="log-center"
          defaultOpen={Boolean(linked.resourceId)}
          columns={platform ? 4 : 3}
          primary={<>
            <TimeRangeFilter label={t('filters.range')} value={range} onChange={setRange} />
            <Input placeholder={t('filters.actor')} aria-label={t('filters.actor')} value={draft.actor ?? ''} onChange={(event) => setDraft({ ...draft, actor: event.target.value })} onPressEnter={() => search()} style={{ width: 160 }} />
          </>}
          items={[
            { key: 'sourceIp', label: t('filters.sourceIp'), applied: applied.sourceIp,
              field: <Input placeholder={t('filters.sourceIp')} aria-label={t('filters.sourceIp')} value={draft.sourceIp ?? ''} onChange={(event) => setDraft({ ...draft, sourceIp: event.target.value })} onPressEnter={() => search()} /> },
            { key: 'result', label: t('filters.result'), applied: applied.result ? t(`results.${applied.result}`) : '',
              field: <Select allowClear placeholder={t('filters.result')} aria-label={t('filters.result')} value={draft.result} onChange={(value) => setDraft({ ...draft, result: value })}
                options={(['success', 'denied', 'failure'] as const).map((value) => ({ value, label: t(`results.${value}`) }))} /> },
            ...(tab === 'operation' ? [{ key: 'category', label: t('filters.category'), applied: operationCategory ? t(`categories.${operationCategory}`) : '',
              field: <Select allowClear placeholder={t('filters.category')} aria-label={t('filters.category')} value={operationCategory}
                options={operationCategories.map((category) => ({ value: category, label: t(`categories.${category}`) }))}
                onChange={(value?: AuditLogCategory) => { setOperationCategory(value); setCursors([]) }} /> }] : []),
            { key: 'resourceType', label: t('filters.resourceType'), applied: applied.resourceType,
              field: <Input placeholder={t('filters.resourceType')} aria-label={t('filters.resourceType')} value={draft.resourceType ?? ''} onChange={(event) => setDraft({ ...draft, resourceType: event.target.value })} /> },
            { key: 'resourceId', label: t('filters.resourceId'), applied: applied.resourceId,
              field: <Input placeholder={t('filters.resourceId')} aria-label={t('filters.resourceId')} value={draft.resourceId ?? ''} onChange={(event) => setDraft({ ...draft, resourceId: event.target.value })} /> },
            ...(platform ? [{ key: 'scopeId', label: t('filters.scopeId'), applied: applied.scopeId,
              field: <Input placeholder={t('filters.scopeId')} aria-label={t('filters.scopeId')} value={draft.scopeId ?? ''} onChange={(event) => setDraft({ ...draft, scopeId: event.target.value.trim() })} /> }] : []),
          ]}
          queryText={t('filters.search')}
          onQuery={() => search()}
          onReset={reset}
          onClearAdvanced={() => { setOperationCategory(undefined); search({ ...draft, sourceIp: undefined, result: undefined, resourceType: undefined, resourceId: undefined, scopeId: undefined }) }}
          onRemove={(key) => { if (key === 'category') { setOperationCategory(undefined); setCursors([]) } else search({ ...draft, [key]: undefined }) }}
        />
      </section>
      {loadError ? <Alert type="error" showIcon role="alert" style={{ marginBottom: 16 }} message={loadError} data-testid="log-center-error" /> : null}
      <div className="log-center-table">
        <Table<AuditLogItem> rowKey="id" size="middle" columns={columns} dataSource={page.data?.items ?? []} loading={page.isFetching} pagination={false}
          scroll={{ x: 1100 }} tableLayout="fixed" rowClassName={(item) => `log-center-row--${item.result}`}
          onRow={(item) => ({ onClick: () => setSelected(item) })}
          locale={{ emptyText: <Empty description={loadError ?? t('states.empty')} /> }} />
        <div className="log-center-pager">
          <span>{page.data ? t('pager.count', { count: page.data.items.length }) : null}</span>
          <Space>
            <Button disabled={cursors.length === 0} onClick={() => setCursors(cursors.slice(0, -1))}>{t('pager.previous')}</Button>
            <Button disabled={!page.data?.next_cursor} onClick={() => page.data?.next_cursor && setCursors([...cursors, page.data.next_cursor])}>{t('pager.next')}</Button>
          </Space>
        </div>
      </div>
    </>}
    <Drawer open={Boolean(selected)} width={640} title={t('detail.title')} onClose={() => setSelected(undefined)}>
      {selected ? <LogDetail item={selected} /> : null}
    </Drawer>
  </div>
}

// 比较用：去掉首尾空格与空值（空格不算改动）。
function trimmed(filters: AuditLogFilters): Record<string, string> {
  return Object.fromEntries(Object.entries(filters).flatMap(([key, value]) => typeof value === 'string' && value.trim() ? [[key, value.trim()]] : []))
}

// errorKey: audit log refusal codes (auditloghttp/handler.go) to their message; others fall back to the generic one.
function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'states.error'
  if (error.code === 'audit_log_invalid_request') return 'states.invalidRequest'
  if (error.code === 'audit_log_unavailable') return 'states.unavailable'
  if (error.code === 'permission_denied') return 'states.forbidden'
  return 'states.error'
}

// objectLabel: the B6b name; a deleted object shows its ID prefix; else the ID.
function objectLabel(item: AuditLogItem, t: (key: string, options?: Record<string, string>) => string): string {
  if (item.resource_deleted && item.resource_id) return t('states.deletedObject', { id: item.resource_id.slice(0, 8) })
  return item.resource || item.resource_id || '-'
}

function LogDetail({ item }: { item: AuditLogItem }) {
  const { t } = useTranslation('logCenter')
  return <Space direction="vertical" size="large" style={{ width: '100%' }}>
    <div className="log-center-detail-head">
      <Space wrap size={8}>
        <Tag color={resultColor[item.result]}>{item.result_label}</Tag>
        <Typography.Text type="secondary">{item.time}</Typography.Text>
        <Typography.Text type="secondary">{item.category_label}</Typography.Text>
      </Space>
      <Typography.Paragraph data-testid="log-center-summary" className="log-center-detail-summary">{item.summary}</Typography.Paragraph>
    </div>
    <div>
      <Typography.Title level={5}>{t('detail.changes')}</Typography.Title>
      {item.changes.length === 0 ? <Typography.Text type="secondary">{t('detail.noChanges')}</Typography.Text>
        : <Table rowKey="field" size="small" pagination={false} dataSource={item.changes} columns={[
          { title: t('detail.field'), dataIndex: 'label' },
          { title: t('detail.before'), dataIndex: 'before', render: (value: string) => <span className="log-center-before">{value}</span> },
          { title: t('detail.after'), dataIndex: 'after', render: (value: string) => <strong>{value}</strong> },
        ]} />}
    </div>
    {item.fields.length > 0 ? <Descriptions title={t('detail.fields')} column={1} size="small" bordered
      items={item.fields.map((field) => ({ key: field.key, label: field.label, children: field.value }))} /> : null}
    <Descriptions title={t('detail.technical')} column={1} size="small" bordered items={[
      { key: 'actor', label: t('columns.actor'), children: item.actor },
      // resource is the backend-resolved name (site domain, node name, username), else the ID.
      { key: 'object', label: t('detail.object'), children: <span title={item.resource_id}>{`${item.resource_type} ${item.resource || item.resource_id}`}</span> },
      { key: 'action', label: t('detail.action'), children: item.action },
      { key: 'reason', label: t('detail.reason'), children: item.reason || item.reason_code || '-' },
      { key: 'request', label: t('detail.request'), children: item.request_id || '-' },
      { key: 'scope', label: t('detail.scope'), children: item.scope_id },
    ]} />
  </Space>
}
