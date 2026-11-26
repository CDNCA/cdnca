import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { logListQueryOptions, useLogListGeneration } from './logListQuery'
import { Alert, Button, Checkbox, Input, Result, Select, Tag, type TableColumnsType } from 'antd'
import { Tabs } from '../components/Tabs'
import dayjs, { type Dayjs } from 'dayjs'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AdvancedFilters, DEFAULT_TIME_RANGE_PRESETS, TimeRangeFilter, clampTimeRange, resolveTimeRangePreset, liveFilterDelay, useFeedback, useLiveApply, Table } from '@cdnca/ui'

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
const logTabs: readonly LogTab[] = ['login', 'operation', 'notification']
// 默认查询就是「近30天」，页面选中这一项（不再是空白的「自定义」）。
const defaultPreset = 'last30d'
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
  // 页签取自 ?tab=（只认 operation / notification，缺省或其它值是登录日志），
  // 切换时写回 URL（默认的 login 不写，其它参数保留），刷新后停在原页签。
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab') as LogTab | null
  const tab: LogTab = requestedTab && logTabs.includes(requestedTab) ? requestedTab : 'login'
  const setTab = (next: LogTab) => setSearchParams((current) => {
    const params = new URLSearchParams(current)
    if (next === 'login') params.delete('tab')
    else params.set('tab', next)
    return params
  }, { replace: true })
  const text = useCallback((key: ObservabilityLogMessageKey) => observabilityLogMessage(language, key), [language])

  if (!accessToken || !principal) return null
  // 与 ObservabilityLogsPage 的 tenant 口径一致：租户，或没有租户的平台主体读自身作用域。
  const allowed = (principal.scope_kind === 'tenant' || (principal.scope_kind === 'platform' && principal.tenant_id === null)) &&
    principal.permissions.includes('identity.self.read')
  if (!allowed) return <Result status="403" title="403" subTitle={text('failed')} />

  return <section className="identity-page account-log-page" aria-label={text('title')} data-testid="account-log-page">
    {/* 各页签的表格放进自己的 tabpanel；切走即卸载，仍按 tab/scope/sessionEpoch 隔离筛选与游标 */}
    <Tabs className="account-log-tabs" activeKey={tab} onChange={(value) => setTab(value as LogTab)} aria-label={text('logTabs')} destroyOnHidden
      items={([['login', 'loginView'], ['operation', 'operationView'], ['notification', 'notification']] as const).map(([key, label]) => ({
        key, label: text(label),
        children: <AccountLogTable key={`${key}:${principal.scope_id}:${sessionEpoch}`} tab={key} accessToken={accessToken} language={language} />,
      }))} />
  </section>
}

function AccountLogTable({ tab, accessToken, language }: { tab: LogTab; accessToken: string; language: string }) {
  const { t } = useTranslation('logCenter')
  const feedback = useFeedback()
  const text = useCallback((key: ObservabilityLogMessageKey) => observabilityLogMessage(language, key), [language])
  const [defaultFrom] = useState(() => new Date(Date.now() - defaultRangeMs).toISOString())
  // 已生效的 IP 写进 URL（ip），分享链接带入。时间范围同样只写已生效值：快捷范围写 range，
  // 自定义写 range=custom 与 from/to；默认的近30天不写；非法或超出 31 天的值回到默认。
  const [initialParams] = useSearchParams()
  const [initialTime] = useState(() => timeFromUrl(initialParams))
  // A3/A4：筛选项先进草稿，点「查询」或在输入框回车才发请求；校验不过就地标红，不发请求。
  const [status, setStatus] = useState<'success' | 'failed'>()
  const [verb, setVerb] = useState<Verb>()
  // No range = the default last 30 days with an open end; a quick range is resolved again on query.
  const [timePreset, setTimePreset] = useState(initialTime.preset)
  const [range, setRange] = useState<[Dayjs, Dayjs] | null>(initialTime.range)
  const [appliedTime, setAppliedTime] = useState(initialTime)
  const [sourceIP, setSourceIP] = useState(() => filterParam(initialParams, 'ip'))
  const [categoryDraft, setCategory] = useState<ObservabilityLogCategory>()
  const [objectDraft, setObject] = useState('')
  const [changeDraft, setChange] = useState('')
  // 操作日志默认不列成功的会话续期（服务端过滤，总数与翻页一致）；
  // 高级筛选里勾「显示会话续期」看全部记录。续期失败始终列出。
  const [showRefreshDraft, setShowRefresh] = useState(false)
  const [fieldError, setFieldError] = useState<{ ip?: ObservabilityLogMessageKey; range?: ObservabilityLogMessageKey }>({})
  const [pageSize, setPageSize] = useState(pageSizes[0])
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  // advanced: the operation tab's 高级筛选 values to apply (a tag × or 清空 passes them with the cleared ones).
  type Advanced = { verb?: Verb; category?: ObservabilityLogCategory; object: string; change: string; showRefresh: boolean }
  const current: Advanced = { verb, category: categoryDraft, object: objectDraft, change: changeDraft, showRefresh: showRefreshDraft }
  const draft = ({ verb: action, category, object, change, showRefresh }: Advanced = current): ObservabilityLogFilters => {
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
    hideSessionRefresh: tab === 'operation' && !showRefresh ? true : undefined,
    sourceIp: sourceIP.trim() || undefined,
    from: window ? window[0].toDate().toISOString() : defaultFrom,
    to: window ? window[1].toDate().toISOString() : undefined,
  } }
  // 打开页面按默认条件查一次；之后边输入边生效
  // （文本 400ms 防抖，下拉/时间范围选完即查），「查询」立即刷新；校验不过不发请求并就地标错。
  const [applied, setApplied] = useState<ObservabilityLogFilters>(draft)
  const signature = (advanced: Advanced = current) =>
    JSON.stringify([tab, status, advanced.verb, timePreset, range?.map((value) => value.valueOf()), sourceIP.trim(), advanced.category, advanced.object.trim(), advanced.change.trim(), advanced.showRefresh])
  const [appliedSignature, setAppliedSignature] = useState(signature)
  const validate = () => {
    const ip = sourceIP.trim()
    return {
      ip: ip && !isIPAddress(ip) ? 'ipInvalid' as const : undefined,
      // 后端拒绝结束时间晚于当前 1 分钟以上（observabilitylog/service.go）。
      range: timePreset === 'custom' && range && range[1].valueOf() > Date.now() + 60_000 ? 'rangeFuture' as const : undefined,
    }
  }
  // control-log-ui：条件变了按新数据读；同一条件下翻页、切 tab 回来 30 秒内用缓存。
  const [generation, renew] = useLogListGeneration([applied, pageSize])
  const submit = (advanced?: Advanced) => {
    if (advanced) { setVerb(advanced.verb); setCategory(advanced.category); setObject(advanced.object); setChange(advanced.change); setShowRefresh(advanced.showRefresh) }
    const errors = validate()
    setFieldError(errors)
    if (errors.ip || errors.range) return
    const next = signature(advanced)
    if (!advanced && next === appliedSignature) { void query.refetch(); return }
    setAppliedSignature(next)
    setApplied(draft(advanced))
    setAppliedTime({ preset: timePreset, range })
    setCursors([])
    renew()
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
  useFilterUrl({ ip: applied.sourceIp, range: appliedTime.preset === defaultPreset || (appliedTime.preset === 'custom' && !appliedTime.range) ? undefined : appliedTime.preset,
    from: appliedTime.preset === 'custom' ? appliedTime.range?.[0].toISOString() : undefined,
    to: appliedTime.preset === 'custom' ? appliedTime.range?.[1].toISOString() : undefined })
  const onEnter = { onPressEnter: () => submit() }
  const filters: ObservabilityLogFilters = { ...applied, limit: pageSize, cursor }
  const query = useQuery({ queryKey: ['account-logs', generation, filters], queryFn: () => observabilityLogsApi.list(accessToken, filters), retry: false, ...logListQueryOptions })
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
          color={value === 'success' || value === 'delivered' ? 'success' : value === 'accepted' || value === 'dispatching' || value === 'unknown' ? 'processing' : 'error'}>
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
      instant
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
        { key: 'showRefresh', label: text('sessionRefresh'), applied: applied.hideSessionRefresh ? '' : text('sessionRefreshShown'), selfLabelled: true,
          field: <Checkbox checked={showRefreshDraft} onChange={(event) => setShowRefresh(event.target.checked)}>{text('showSessionRefresh')}</Checkbox> },
        { key: 'object', label: text('object'), applied: applied.resourceId,
          field: <Input aria-label={text('object')} placeholder={text('objectPlaceholder')} value={objectDraft} onChange={(event) => setObject(event.target.value)} /> },
        { key: 'change', label: text('change'), applied: applied.change,
          field: <Input aria-label={text('change')} placeholder={text('changePlaceholder')} value={changeDraft} onChange={(event) => setChange(event.target.value)} /> },
      ] : []}
      queryText={text('query')}
      queryLoading={query.isFetching && query.fetchStatus !== 'paused'}
      // 离线时查询暂停，按钮旁标明等待网络；恢复后 Query 自动读一次，标记随之消失。
      extra={query.fetchStatus === 'paused' ? <span className="account-log-waiting" role="status">{text('waitingNetwork')}</span> : undefined}
      onQuery={() => submit()}
      onClearAdvanced={() => submit({ verb: undefined, category: undefined, object: '', change: '', showRefresh: false })}
      onRemove={(key) => submit({ ...current, [key]: key === 'category' || key === 'verb' ? undefined : key === 'showRefresh' ? false : '' })}
    />
    {loadError ? <Alert className="account-log-error" type="error" showIcon role="alert" message={loadError} /> : null}
    <div className="account-log-table" aria-busy={query.isFetching}>
      <Table<ObservabilityLogFact> rowKey="event_id" columns={columns} dataSource={query.data?.items ?? []} loading={query.isPending || query.isPlaceholderData}
        pagination={false} scroll={{ x: tab === 'operation' ? 980 : 910 }} locale={{ emptyText: loadError ?? text('empty') }} />
    </div>
    <nav className="account-log-pager" aria-label={text('pagination')}>
      <span>{text('total').replace('{count}', String(total))}</span>
      <Button aria-label={text('previous')} icon={<ChevronLeft size={14} aria-hidden />} disabled={cursors.length === 0}
        onClick={() => setCursors((value) => value.slice(0, -1))} />
      <span className="account-log-page-number" aria-current="page">{pageNumber}</span>
      <Button aria-label={text('next')} icon={<ChevronRight size={14} aria-hidden />} disabled={!query.data?.next_cursor || query.isPlaceholderData}
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

// 已生效时间范围的 URL 形式：range=today|last7d|last30d，或 range=custom&from=…&to=…（不超过 31 天、结束不晚于现在）。
function timeFromUrl(params: URLSearchParams): { preset: string; range: [Dayjs, Dayjs] | null } {
  const preset = filterParam(params, 'range')
  if ((DEFAULT_TIME_RANGE_PRESETS as readonly string[]).includes(preset)) return { preset, range: null }
  if (preset === 'custom') {
    const from = dayjs(filterParam(params, 'from'))
    const to = dayjs(filterParam(params, 'to'))
    if (from.isValid() && to.isValid() && !from.isAfter(to) && to.diff(from) <= maxRangeMs && to.valueOf() <= Date.now() + 60_000) {
      return { preset, range: [from, to] }
    }
  }
  return { preset: defaultPreset, range: null }
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
