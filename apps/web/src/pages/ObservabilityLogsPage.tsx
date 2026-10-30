import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, Radio, Result, Select, Space, Table, Tag, type TableColumnsType } from 'antd'
import { useFeedback, FeedbackWhen, TimeRangeFilter } from '@cdnca/ui'
import { Download, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import dayjs from 'dayjs'

import { ApiError, type Principal } from '../api/auth'
import { observabilityLogsApi, type ObservabilityLogFact, type ObservabilityLogKind } from '../api/observabilityLogs'
import { exportOwnerGuard } from '../auth/exportOwner'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import { observabilityLogCodeMessage, observabilityLogMessage } from '../i18n/observabilityLogs'
import { factRegion } from './logGeo'

const canonicalScopeID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

type LogPageMode = 'event' | 'login' | 'frontend'

// 这些页面读取的是主体自身作用域的审计日志，因此平台作用域
// （无租户的管理员）同样按自身作用域放行，与后端 authorizeTarget 的放宽保持一致。
function observabilityLogsAllowed(audience: 'tenant' | 'platform', principal: Principal): boolean {
  return audience === 'tenant'
    ? (principal.scope_kind === 'tenant' ||
        (principal.scope_kind === 'platform' && principal.tenant_id === null)) &&
      principal.permissions.includes('identity.self.read')
    : principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
}

export default function ObservabilityLogsPage({ audience, initialKinds, mode = 'event' }: {
  audience: 'tenant' | 'platform'
  initialKinds?: ObservabilityLogKind[]
  mode?: LogPageMode
}) {
  const { i18n } = useTranslation()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const text = useCallback((key: Parameters<typeof observabilityLogMessage>[1]) => observabilityLogMessage(language, key), [language])

  if (!accessToken || !principal) return null
  if (!observabilityLogsAllowed(audience, principal)) return <Result status="403" title="403" subTitle={text('failed')} />

  return <ObservabilityLogsContent key={`${principal.scope_id}:${sessionEpoch}`} accessToken={accessToken} audience={audience} language={language} selfScopeID={principal.scope_id} initialKinds={initialKinds} mode={mode} />
}

function ObservabilityLogsContent({ accessToken, audience, language, selfScopeID, initialKinds = [], mode }: {
  accessToken: string
  audience: 'tenant' | 'platform'
  language: string
  selfScopeID: string
  initialKinds?: ObservabilityLogKind[]
  mode: LogPageMode
}) {
  const feedback = useFeedback()
  const effectiveKinds = mode === 'login' ? ['login' as const] : mode === 'frontend' ? ['frontend' as const] : initialKinds
  const [kinds, setKinds] = useState<ObservabilityLogKind[]>(effectiveKinds)
  const [result, setResult] = useState<string>()
  const [action, setAction] = useState('')
  const [sourceIP, setSourceIP] = useState('')
  const [actorUserID, setActorUserID] = useState('')
  // Open until a range is chosen; the window is fixed when it is picked (the list queries on every change).
  const [timePreset, setTimePreset] = useState('custom')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [targetScopeID, setTargetScopeID] = useState('')
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [showAudit, setShowAudit] = useState(false)
  const cursor = cursorStack.at(-1)
  const text = useCallback((key: Parameters<typeof observabilityLogMessage>[1]) => observabilityLogMessage(language, key), [language])
  const codeText = useCallback((category: Parameters<typeof observabilityLogCodeMessage>[1], code: string) => (
    observabilityLogCodeMessage(language, category, code)
  ), [language])
  const viewMode: LogPageMode = mode === 'login' && audience === 'platform' && showAudit ? 'event' : mode
  // 平台管理员没有独立租户，此页展示管理员自己的登录日志，此时不传 target_scope_id，后端按平台自身作用域读取。
  const scopeReady = audience === 'tenant'
    || (!targetScopeID && selfScopeID !== '00000000-0000-0000-0000-000000000000')
    || canonicalScopeID.test(targetScopeID)
  const actorUserIDReady = !actorUserID || canonicalScopeID.test(actorUserID)
  const queryKinds = viewMode === 'login' ? ['login' as const] : viewMode === 'frontend' ? ['frontend' as const] : kinds
  const filters = { kinds: queryKinds, results: result ? [result] : undefined, action: action || undefined, sourceIp: sourceIP || undefined,
    actorUserId: viewMode === 'login' && actorUserIDReady ? actorUserID || undefined : undefined,
    from: localInstant(from), to: localInstant(to), targetScopeId: audience === 'platform' && scopeReady ? targetScopeID : undefined,
    limit: 50, cursor }
  const query = useQuery({ queryKey:['observability-logs', audience, filters], queryFn:()=>observabilityLogsApi.list(accessToken, filters), enabled:scopeReady, retry:false })
  // A18：游标失效时保留筛选、清游标重查第一页（第一页无游标，不会循环）。
  const cursorExpired = query.isError && query.error instanceof ApiError && query.error.code === 'observability_logs_cursor_expired'
  useEffect(() => {
    if (!cursorExpired || cursorStack.length === 0) return
    setCursorStack([])
    feedback.warning(text('cursorExpired'))
  }, [cursorExpired, cursorStack.length, feedback, text])

  const columns = useMemo<TableColumnsType<ObservabilityLogFact>>(() => {
    const time = { title: text(mode === 'login' ? 'loginTime' : 'time'), dataIndex: 'occurred_at', width: 180, render: (value: string) => formatDateTime(value, language) || value }
    if (viewMode === 'login') {
      return [
        ...(audience === 'platform' ? [{ title: text('userId'), dataIndex: 'actor_user_id', width: 180, render: (value?: string) => value || '—' }] : []),
        { title: text('ipAddress'), dataIndex: 'source_ip', width: 160 },
        { title: text('geo'), dataIndex: 'geo_code', width: 180, render: (_: string, fact: ObservabilityLogFact) => factRegion(fact, language) ?? text('unknown') },
        time,
        { title: text('loginStatus'), dataIndex: 'result_code', width: 140, render: (value: string) => <Tag color={value === 'success' ? 'green' : 'red'}>{codeText('result', value)}</Tag> },
      ]
    }
    if (viewMode === 'frontend') {
      return [
        time,
        { title: text('info'), dataIndex: 'action', width: 220, ellipsis: true, render: (value: string) => codeText('action', value) },
        { title: text('triggerPage'), dataIndex: 'resource_id', width: 220, ellipsis: true, render: (value?: string) => value || '—' },
        { title: text('kind'), dataIndex: 'kind', width: 120, render: (value: ObservabilityLogKind) => text(value) },
        { title: text('detail'), dataIndex: 'reason_code', width: 220, ellipsis: true, render: (value: string) => codeText('reason', value) },
      ]
    }
    return [
      time,
      { title: text('kind'), dataIndex: 'kind', width: 120, render: (value: ObservabilityLogKind) => <Tag>{text(value)}</Tag> },
      { title: text('action'), dataIndex: 'action', width: 210, ellipsis: true, render: (value: string) => codeText('action', value) },
      { title: text('reason'), dataIndex: 'reason_code', width: 190, ellipsis: true, render: (value: string) => codeText('reason', value) },
      { title: text('result'), dataIndex: 'result_code', width: 150, render: (value: string) => <Tag color={value === 'success' || value === 'delivered' ? 'green' : value.includes('failed') ? 'red' : 'default'}>{codeText('result', value)}</Tag> },
      { title: text('sourceIp'), dataIndex: 'source_ip', width: 160 },
      { title: text('geo'), dataIndex: 'geo_code', width: 180, render: (_: string, fact: ObservabilityLogFact) => factRegion(fact, language) ?? text('unknown') },
    ]
  }, [audience, codeText, language, mode, viewMode, text])

  // TEL-UX-EXPORT-OWNER：离开页面即取消；响应迟到时身份已变就丢弃，不下载也不提示。
  const exportAbortRef = useRef<AbortController | null>(null)
  useEffect(() => () => exportAbortRef.current?.abort(), [])
  const exportCSV = async () => {
    if (!scopeReady) return
    exportAbortRef.current?.abort()
    const controller = new AbortController()
    exportAbortRef.current = controller
    const stillCurrent = exportOwnerGuard((principal) => observabilityLogsAllowed(audience, principal))
    try {
      const artifact = await observabilityLogsApi.exportCSV(accessToken, { ...filters, cursor:undefined, limit:undefined }, { signal: controller.signal })
      if (controller.signal.aborted || !stillCurrent()) return
      const href = URL.createObjectURL(new Blob([artifact.content], { type:'text/csv;charset=utf-8' }))
      const link = document.createElement('a'); link.href=href; link.download=`observability-logs-${artifact.sha256.slice(0,12)}.csv`; link.click(); URL.revokeObjectURL(href)
    } catch {
      if (controller.signal.aborted || !stillCurrent()) return
      feedback.error(text('exportFailed'))
    }
  }

  return <section className="identity-page" aria-labelledby="observability-log-title" data-testid={`observability-log-page-${mode}`}>
    <h1 id="observability-log-title">{viewMode === 'login' ? text('loginTitle') : viewMode === 'frontend' ? text('frontendTitle') : text('title')}</h1>
    <div className="identity-toolbar">
      {mode === 'login' && audience === 'platform' ? <Radio.Group size="small" value={showAudit ? 'audit' : 'login'} onChange={(event) => { setShowAudit(event.target.value === 'audit'); setCursorStack([]) }} options={[{ value: 'login', label: text('loginView') }, { value: 'audit', label: text('auditView') }]} /> : null}
      {viewMode === 'event' ? <>
        <Select mode="multiple" aria-label={text('kind')} value={kinds} onChange={(value: ObservabilityLogKind[]) => { setKinds(value); setCursorStack([]) }} style={{ minWidth: 220 }} options={(['login', 'operation', 'notification', 'frontend'] as ObservabilityLogKind[]).map((value) => ({ value, label: text(value) }))} placeholder={text('all')} />
        <Select allowClear aria-label={text('result')} value={result} onChange={(value) => { setResult(value); setCursorStack([]) }} style={{ minWidth: 150 }} options={['success', 'denied', 'failure', 'delivered', 'accepted', 'unknown', 'permanent_failed', 'exhausted', 'cancelled'].map((value) => ({ value, label: codeText('result', value) }))} placeholder={text('all')} />
        <Input aria-label={text('action')} value={action} onChange={(event) => { setAction(event.target.value); setCursorStack([]) }} style={{ width: 180 }} placeholder={text('action')} />
      </> : null}
      {viewMode === 'login' && audience === 'platform' ? <Input aria-label={text('userId')} value={actorUserID} onChange={(event) => { setActorUserID(event.target.value); setCursorStack([]) }} style={{ width: 180 }} placeholder={text('userIdPlaceholder')} status={actorUserID && !actorUserIDReady ? 'error' : undefined} /> : null}
      {viewMode === 'event' || viewMode === 'login' ? <Input aria-label={text('ipAddress')} value={sourceIP} onChange={(event) => { setSourceIP(event.target.value); setCursorStack([]) }} style={{ width: 180 }} placeholder={text('ipAddressPlaceholder')} /> : null}
      {viewMode === 'event' || viewMode === 'login' ? <TimeRangeFilter value={{ preset: timePreset, range: from && to ? [dayjs(from), dayjs(to)] : null }}
        onChange={({ preset, range }) => { setTimePreset(preset); setFrom(range?.[0].toISOString() ?? ''); setTo(range?.[1].toISOString() ?? ''); setCursorStack([]) }} /> : null}
      {audience==='platform'?<Input aria-label={text('targetScope')} value={targetScopeID} onChange={(event)=>{setTargetScopeID(event.target.value);setCursorStack([])}} style={{width:280}} placeholder={text('targetScopePlaceholder')} />:null}
      <Button icon={<RefreshCw size={15}/>} disabled={!scopeReady} loading={query.isFetching} onClick={()=>void query.refetch()}>{text('refresh')}</Button>
      <Button icon={<Download size={15}/>} disabled={!scopeReady} onClick={()=>void exportCSV()}>{text('export')}</Button>
    </div>
    {audience==='platform'&&!scopeReady?<Alert type={targetScopeID?'error':'info'} showIcon message={text(targetScopeID?'targetScopeInvalid':'targetScopeRequired')} />:null}
    {query.isError?<FeedbackWhen title={query.error instanceof ApiError&&query.error.code==='permission_denied'?text('failed'):text('failed')} />:null}
    <div className="identity-table-scroll" aria-busy={scopeReady && actorUserIDReady && (query.isPending || query.isFetching)} data-testid="observability-log-table">
      <Table<ObservabilityLogFact> rowKey="event_id" size="small" loading={scopeReady&&query.isPending} columns={columns} dataSource={query.data?.items??[]} pagination={false} locale={{emptyText:query.isError?text('failed'):text('empty')}} scroll={{x:1120}} />
    </div>
    <Space className="identity-pagination">
      <Button disabled={cursorStack.length===0} onClick={()=>setCursorStack((value)=>value.slice(0,-1))}>{text('previous')}</Button>
      <Button disabled={!query.data?.next_cursor} onClick={()=>query.data?.next_cursor&&setCursorStack((value)=>[...value,query.data!.next_cursor!])}>{text('next')}</Button>
    </Space>
  </section>
}

function localInstant(value: string): string | undefined {
  if (!value) return undefined
  const parsed = new Date(value)
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : undefined
}
