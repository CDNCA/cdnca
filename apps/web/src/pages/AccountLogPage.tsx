import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Result, Select, Table, Tabs, Tag, type TableColumnsType } from 'antd'
import dayjs, { type Dayjs } from 'dayjs'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AdvancedFilters, TimeRangeFilter, clampTimeRange, resolveTimeRangePreset, liveFilterDelay, useFeedback, useLiveApply } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import { isIPAddress } from '../api/gateways'
import {
  observabilityLogCategories, observabilityLogsApi,
  type ObservabilityLogCategory, type ObservabilityLogFact, type ObservabilityLogFilters,
} from '../api/observabilityLogs'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/logCenter'
import { observabilityLogCodeMessage, observabilityLogMessage, type ObservabilityLogMessageKey } from '../i18n/observabilityLogs'
import { factRegion } from './logGeo'
import { useSearchParams } from 'react-router-dom'
import { filterParam, useFilterUrl } from './filterUrl'
import './AccountLogPage.css'

type LogTab = 'login' | 'operation' | 'notification'
type Verb = 'create' | 'update' | 'delete'

const pageSizes = [10, 20, 50]
const maxRangeMs = 31 * 24 * 60 * 60 * 1000
// 后端不传时间时只查最近 24 小时；这里默认最近 30 天（后端上限 31 天）。
const defaultRangeMs = 30 * 24 * 60 * 60 * 1000
const verbColor: Record<Verb, string> = { create: 'green', update: 'blue', delete: 'red' }
const verbText = { create: 'verbCreate', update: 'verbUpdate', delete: 'verbDelete' } as const satisfies Record<Verb, ObservabilityLogMessageKey>

// B6：账户中心「日志查询」，分「登录日志 / 操作日志 / 备份 / 发信」标签（SEC-ACCOUNT-10 补后两个）。
// 数据都来自 /v1/observability/logs：租户只读自己作用域里自己做的或针对自己的记录（后端强制）。
export default function AccountLogPage() {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const [tab, setTab] = useState<LogTab>('login')
  const text = useCallback((key: ObservabilityLogMessageKey) => observabilityLogMessage(language, key), [language])

  if (!accessToken || !principal) return null
  // 与 ObservabilityLogsPage 的 tenant 口径一致：租户，或没有租户的平台主体读自身作用域。
  const allowed = (principal.scope_kind === 'tenant' || (principal.scope_kind === 'platform' && principal.tenant_id === null)) &&
    principal.permissions.includes('identity.self.read')
  if (!allowed) return <Result status="403" title="403" subTitle={text('failed')} />

  return <section className="identity-page account-log-page" aria-label={text('title')} data-testid="account-log-page">
    <Tabs className="account-log-tabs" activeKey={tab} onChange={(value) => setTab(value as LogTab)} aria-label={text('logTabs')}
      items={[{ key: 'login', label: text('loginView') }, { key: 'operation', label: text('operationView') },
        { key: 'notification', label: text('notification') }]} />
    <AccountLogTable key={`${tab}:${principal.scope_id}:${sessionEpoch}`} tab={tab} accessToken={accessToken} language={language} />
  </section>
}

function AccountLogTable({ tab, accessToken, language }: { tab: LogTab; accessToken: string; language: string }) {
  const { t } = useTranslation('logCenter')
  const feedback = useFeedback()
  const text = useCallback((key: ObservabilityLogMessageKey) => observabilityLogMessage(language, key), [language])
  const [defaultFrom] = useState(() => new Date(Date.now() - defaultRangeMs).toISOString())
  // A3/A4：筛选项先进草稿，点「查询」或在输入框回车才发请求；校验不过就地标红，不发请求。
  const [status, setStatus] = useState<'success' | 'failed'>()
  const [verb, setVerb] = useState<Verb>()
  // No range = the default last 30 days with an open end; a quick range is resolved again on query.
  const [timePreset, setTimePreset] = useState('custom')
  const [range, setRange] = useState<[Dayjs, Dayjs] | null>(null)
  // 已生效的 IP 写进 URL（ip），分享链接带入。
  const [initialParams] = useSearchParams()
  const [sourceIP, setSourceIP] = useState(() => filterParam(initialParams, 'ip'))
  const [categoryDraft, setCategory] = useState<ObservabilityLogCategory>()
  const [objectDraft, setObject] = useState('')
  const [changeDraft, setChange] = useState('')
  const [fieldError, setFieldError] = useState<{ ip?: ObservabilityLogMessageKey; range?: ObservabilityLogMessageKey }>({})
  const [pageSize, setPageSize] = useState(pageSizes[0])
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  // advanced: the operation tab's 高级筛选 values to apply (a tag × or 清空 passes them with the cleared ones).
  type Advanced = { verb?: Verb; category?: ObservabilityLogCategory; object: string; change: string }
  const draft = ({ verb: action, category, object, change }: Advanced = { verb, category: categoryDraft, object: objectDraft, change: changeDraft }): ObservabilityLogFilters => {
    // Quick ranges are re-resolved on query; the end is clipped to now (today would otherwise end at midnight, which the backend refuses).
    const resolved = timePreset === 'custom' ? null : resolveTimeRangePreset(timePreset)
    const window = timePreset === 'custom' ? range : resolved && clampTimeRange(resolved, { maxDate: dayjs() })
    return {
    kinds: [tab],
    results: tab === 'login' && status ? (status === 'success' ? ['success'] : ['denied', 'failure']) : undefined,
    actionVerb: tab === 'operation' ? action : undefined,
    category: tab === 'operation' ? category : undefined,
    resourceId: tab === 'operation' ? object.trim() || undefined : undefined,
    change: tab === 'operation' ? change.trim() || undefined : undefined,
    sourceIp: sourceIP.trim() || undefined,
    from: window ? window[0].toDate().toISOString() : defaultFrom,
    to: window ? window[1].toDate().toISOString() : undefined,
  } }
  // 打开页面按默认条件查一次；之后边输入边生效
  // （文本 400ms 防抖，下拉/时间范围选完即查），「查询」立即刷新；校验不过不发请求并就地标错。
  const [applied, setApplied] = useState<ObservabilityLogFilters>(draft)
  const signature = (advanced: Advanced = { verb, category: categoryDraft, object: objectDraft, change: changeDraft }) =>
    JSON.stringify([tab, status, advanced.verb, timePreset, range?.map((value) => value.valueOf()), sourceIP.trim(), advanced.category, advanced.object.trim(), advanced.change.trim()])
  const [appliedSignature, setAppliedSignature] = useState(signature)
  const validate = () => {
    const ip = sourceIP.trim()
    return {
      ip: ip && !isIPAddress(ip) ? 'ipInvalid' as const : undefined,
      // 后端拒绝结束时间晚于当前 1 分钟以上（observabilitylog/service.go）。
      range: timePreset === 'custom' && range && range[1].valueOf() > Date.now() + 60_000 ? 'rangeFuture' as const : undefined,
    }
  }
  const submit = (advanced?: Advanced) => {
    if (advanced) { setVerb(advanced.verb); setCategory(advanced.category); setObject(advanced.object); setChange(advanced.change) }
    const errors = validate()
    setFieldError(errors)
    if (errors.ip || errors.range) return
    const next = signature(advanced)
    if (!advanced && next === appliedSignature) { void query.refetch(); return }
    setAppliedSignature(next)
    setApplied(draft(advanced))
    setCursors([])
  }
  const draftErrors = validate()
  // 输入停下 400ms 后仍不合法：就地标错，不发请求；改对后自动查询。
  useEffect(() => {
    if (!draftErrors.ip && !draftErrors.range) return
    const timer = window.setTimeout(() => setFieldError(draftErrors), liveFilterDelay)
    return () => window.clearTimeout(timer)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftErrors.ip, draftErrors.range])
  useLiveApply(signature(), appliedSignature, () => submit(), { valid: !draftErrors.ip && !draftErrors.range })
  useFilterUrl({ ip: applied.sourceIp })
  const onEnter = { onPressEnter: () => submit() }
  const filters: ObservabilityLogFilters = { ...applied, limit: pageSize, cursor }
  const query = useQuery({ queryKey: ['account-logs', filters], queryFn: () => observabilityLogsApi.list(accessToken, filters), retry: false })
  const cursorExpired = query.isError && query.error instanceof ApiError && query.error.code === 'observability_logs_cursor_expired'
  useEffect(() => {
    if (!cursorExpired || cursors.length === 0) return
    setCursors([])
    feedback.warning(text('cursorExpired'))
  }, [cursorExpired, cursors.length, feedback, text])

  const columns = useMemo<TableColumnsType<ObservabilityLogFact>>(() => {
    const region = (fact: ObservabilityLogFact) => factRegion(fact, language) ?? '—'
    const userAgent = { title: text('userAgent'), dataIndex: 'user_agent', width: 260, ellipsis: { showTitle: true },
      // 操作审计 490 之前的行、后台任务没有 UA，显示「—」（tp-b6b）。
      render: (value?: string) => !value || value === 'unknown' ? <span className="account-log-muted">—</span> : value }
    if (tab === 'notification') {
      // 发信结果码区分"服务商已接受"与"已送达"，原样显示，不合并成成功。
      return [
        { title: text('action'), dataIndex: 'action', width: 200, render: (value: string) => observabilityLogCodeMessage(language, 'action', value) },
        { title: text('result'), dataIndex: 'result_code', width: 140, render: (value: string) => <Tag className="account-log-status"
          color={value === 'success' || value === 'delivered' ? 'success' : value === 'accepted' || value === 'unknown' ? 'processing' : 'error'}>
          {observabilityLogCodeMessage(language, 'result', value)}</Tag> },
        { title: text('object'), key: 'object', width: 200, render: (_, fact) => <span className="account-log-muted">{objectLabel(fact, text)}</span> },
        { title: text('time'), dataIndex: 'occurred_at', width: 170, render: (value: string) => <DateTimeCell value={value} language={language} /> },
      ]
    }
    if (tab === 'login') {
      return [
        { title: text('ipAddress'), dataIndex: 'source_ip', width: 170, render: (value: string) => <span className="account-log-mono">{value === 'unknown' ? '—' : value}</span> },
        { title: text('geo'), key: 'region', width: 200, render: (_, fact) => region(fact) },
        userAgent,
        { title: text('loginTime'), dataIndex: 'occurred_at', width: 170, render: (value: string) => <DateTimeCell value={value} language={language} /> },
        { title: text('loginStatus'), dataIndex: 'result_code', width: 110, render: (value: string) => value === 'success'
          ? <Tag className="account-log-status" color="success">{text('statusSuccess')}</Tag>
          : <Tag className="account-log-status" color="error">{text('statusFailed')}</Tag> },
      ]
    }
    return [
      { title: text('categoryObject'), key: 'object', width: 160, render: (_, fact) => <div className="account-log-stack">
        <strong>{fact.category ? t(`categories.${fact.category}`) : '—'}</strong>
        <span className="account-log-muted">{objectLabel(fact, text)}</span>
      </div> },
      { title: text('verb'), dataIndex: 'action', width: 90, render: (value: string) => {
        const suffix = value.slice(value.lastIndexOf('.') + 1)
        if (suffix === 'create' || suffix === 'update' || suffix === 'delete') {
          return <Tag color={verbColor[suffix]}>{text(suffix === 'create' ? 'verbCreate' : suffix === 'update' ? 'verbUpdate' : 'verbDelete')}</Tag>
        }
        return <Tag>{observabilityLogCodeMessage(language, 'action', value)}</Tag>
      } },
      { title: text('changeContent'), dataIndex: 'change_summary', width: 200, ellipsis: { showTitle: true },
        render: (value?: string) => !value || value === '{}' ? <span className="account-log-muted">{text('noChange')}</span> : value },
      { ...userAgent, width: 180 },
      { title: text('ipLocation'), key: 'ip', width: 180, render: (_, fact) => <div className="account-log-stack">
        <strong className="account-log-mono">{fact.source_ip === 'unknown' ? '—' : fact.source_ip}</strong>
        <span className="account-log-muted">{region(fact)}</span>
      </div> },
      { title: text('operationTime'), dataIndex: 'occurred_at', width: 170, render: (value: string) => formatDateTime(value, language) || value },
    ]
  }, [language, t, tab, text])

  const loadError = query.isError && !cursorExpired ? localizedUnknownApiError(query.error, text(errorKey(query.error))) : null
  const total = query.data?.total_count ?? 0
  const pageNumber = cursors.length + 1

  return <div className="account-log-panel">
    {/* 常显 状态（登录日志）、时间范围、IP；操作日志的 动作 与 类别、对象、变更 一起收进高级筛选，1440 下按钮与条件同一行（登录/发信日志没有高级项，不显示按钮）。 */}
    <AdvancedFilters
      className={`account-log-filters${tab === 'operation' ? ' account-log-filters-boxed' : ''}`}
      storageKey="account-log"
      primary={<>
        {tab === 'login'
          ? <Select allowClear aria-label={text('loginStatus')} placeholder={text('allStatus')} value={status} onChange={setStatus} style={{ width: 160 }}
            options={[{ value: 'success', label: text('statusSuccess') }, { value: 'failed', label: text('statusFailed') }]} />
          : null}
        <FieldWithError error={fieldError.range && text(fieldError.range)} id={`account-log-range-${tab}`}>
          {/* The end may not pass the current minute (the backend refuses it), so today ends now; at most 31 days. */}
          <TimeRangeFilter maxSpanMs={maxRangeMs} maxDate={dayjs()}
            value={{ preset: timePreset, range }}
            onChange={({ preset, range: next }) => { setFieldError((current) => ({ ...current, range: undefined })); setTimePreset(preset); setRange(next) }} />
        </FieldWithError>
        <FieldWithError error={fieldError.ip && text(fieldError.ip)} id={`account-log-ip-${tab}`}>
          <Input addonBefore={text('ipAddress')} aria-label={text('ipAddress')} placeholder={text('ipAddressPlaceholder')} value={sourceIP}
            status={fieldError.ip ? 'error' : undefined} aria-invalid={Boolean(fieldError.ip)}
            aria-describedby={fieldError.ip ? `account-log-ip-${tab}` : undefined} {...onEnter}
            onChange={(event) => { setSourceIP(event.target.value); setFieldError((current) => ({ ...current, ip: undefined })) }} style={{ width: 210 }} />
        </FieldWithError>
      </>}
      items={tab === 'operation' ? [
        { key: 'verb', label: text('verb'), applied: applied.actionVerb ? text(verbText[applied.actionVerb]) : '',
          field: <Select allowClear aria-label={text('verb')} placeholder={text('allActions')} value={verb} onChange={setVerb}
            options={(['update', 'create', 'delete'] as Verb[]).map((value) => ({ value, label: text(verbText[value]) }))} /> },
        { key: 'category', label: text('category'), applied: applied.category ? t(`categories.${applied.category}`) : '',
          field: <Select allowClear showSearch optionFilterProp="label" aria-label={text('category')} placeholder={text('categoryPlaceholder')} value={categoryDraft}
            onChange={setCategory} options={observabilityLogCategories.map((value) => ({ value, label: t(`categories.${value}`) }))} /> },
        { key: 'object', label: text('object'), applied: applied.resourceId,
          field: <Input aria-label={text('object')} placeholder={text('objectPlaceholder')} value={objectDraft} onChange={(event) => setObject(event.target.value)} /> },
        { key: 'change', label: text('change'), applied: applied.change,
          field: <Input aria-label={text('change')} placeholder={text('changePlaceholder')} value={changeDraft} onChange={(event) => setChange(event.target.value)} /> },
      ] : []}
      queryText={text('query')}
      queryLoading={query.isFetching}
      onQuery={() => submit()}
      onClearAdvanced={() => submit({ verb: undefined, category: undefined, object: '', change: '' })}
      onRemove={(key) => submit({ verb, category: categoryDraft, object: objectDraft, change: changeDraft, [key]: key === 'category' || key === 'verb' ? undefined : '' })}
    />
    {loadError ? <Alert className="account-log-error" type="error" showIcon role="alert" message={loadError} /> : null}
    <div className="account-log-table" aria-busy={query.isFetching}>
      <Table<ObservabilityLogFact> rowKey="event_id" columns={columns} dataSource={query.data?.items ?? []} loading={query.isPending}
        pagination={false} scroll={{ x: tab === 'operation' ? 980 : 910 }} locale={{ emptyText: loadError ?? text('empty') }} />
    </div>
    <nav className="account-log-pager" aria-label={text('pagination')}>
      <span>{text('total').replace('{count}', String(total))}</span>
      <Button aria-label={text('previous')} icon={<ChevronLeft size={14} aria-hidden />} disabled={cursors.length === 0}
        onClick={() => setCursors((value) => value.slice(0, -1))} />
      <span className="account-log-page-number" aria-current="page">{pageNumber}</span>
      <Button aria-label={text('next')} icon={<ChevronRight size={14} aria-hidden />} disabled={!query.data?.next_cursor}
        onClick={() => { const next = query.data?.next_cursor; if (next) setCursors((value) => [...value, next]) }} />
      <Select aria-label={text('pageSize')} value={pageSize} onChange={(value) => { setPageSize(value); setCursors([]) }} style={{ width: 100 }}
        options={pageSizes.map((value) => ({ value, label: language.startsWith('en') ? `${value} / page` : `${value} 条/页` }))} />
    </nav>
  </div>
}

// 后端拒绝原因码翻成中文；其他错误统一「请稍后重试」，请求编号由 localizedUnknownApiError 附上。
function errorKey(error: unknown): ObservabilityLogMessageKey {
  if (!(error instanceof ApiError)) return 'failed'
  if (error.code === 'observability_logs_invalid_request') return 'invalidRequest'
  if (error.code === 'observability_logs_unavailable') return 'unavailable'
  if (error.code === 'permission_denied') return 'permissionDenied'
  return 'failed'
}

function FieldWithError({ error, id, children }: { error?: string; id: string; children: ReactNode }) {
  return <div className="account-log-field">
    {children}
    {error ? <div id={id} className="account-log-field-error" role="alert">{error}</div> : null}
  </div>
}

// 对象列显示对象名（后端按 resource_type + resource_id 批量反查）；对象已删除显示 ID 前 8 位。
function objectLabel(fact: ObservabilityLogFact, text: (key: ObservabilityLogMessageKey) => string): string {
  if (fact.resource_name) return fact.resource_name
  if (fact.resource_deleted && fact.resource_id) return text('deletedObject').replace('{id}', fact.resource_id.slice(0, 8))
  return fact.resource_id || fact.resource_type || '—'
}

function DateTimeCell({ value, language }: { value: string; language: string }) {
  const formatted = formatDateTime(value, language) || value
  const [date, time] = formatted.split(/\s+/, 2)
  return <div className="account-log-stack"><strong>{date}</strong><span className="account-log-muted">{time}</span></div>
}
