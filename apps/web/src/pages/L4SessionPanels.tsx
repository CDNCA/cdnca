import { useState, type ReactNode } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Input, InputNumber, Popconfirm, Select, Table, Tag, type TableColumnsType } from 'antd'
import { RefreshCw, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import type { L4RealtimeAudience } from '../api/l4Realtime'
import {
  l4EndReasons, l4SessionLogsApi, validClientFilter,
  type L4AllLiveConnection, type L4AllLiveFilters, type L4EndReason, type L4SessionLogFilters, type L4SessionLogRow,
} from '../api/l4SessionLogs'
import { streamsApi, streamGuardRulesMax, type Stream, type StreamGuardRule } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { formatAnalyticsBytes as formatBytes } from '../i18n/analyticsUnits'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/l4Realtime'
import { DataState } from '../components/DataState'
import { L4NodeSelect, L4TenantSelect, optionLabel } from './L4ScopeFilters'
import { guardRulesField, hasStreamManagePermission, hasStreamReadPermission, newGuardRuleID, streamFields, writeKey } from './streamForm'
import './L4RealtimeMonitorPage.css'
import '../styles/analyticsControlParity.css'
import { AdvancedFilters, FeedbackWhen, useLiveApply } from '@cdnca/ui'
import { useSearchParams } from 'react-router-dom'
import { filterParam, useFilterUrl } from './filterUrl'

function sessionToken(ownerKey: string): string {
  const state = useSessionStore.getState()
  const principal = state.principal
  if (!state.accessToken || !principal || `${principal.user_id}:${principal.scope_kind}:${principal.scope_id}` !== ownerKey) {
    throw new ApiError('Session changed', 403, 'l4_analytics_forbidden')
  }
  return state.accessToken
}

function errorKey(error: unknown): string {
  if (error instanceof ApiError && error.code === 'l4_session_log_unavailable') return 'sessionLog.storeUnavailable'
  if (error instanceof ApiError && error.status === 403) return 'states.permissionTitle'
  if (error instanceof ApiError && error.status === 400) return 'states.invalidRequest'
  return 'states.requestFailed'
}

// Stream picker shared by both panels (the caller's forwards).
function StreamSelect({ ownerKey, value, onChange, allowClear }: { ownerKey: string; value?: string; onChange: (value?: string, label?: string) => void; allowClear?: boolean }) {
  const { t } = useTranslation('l4Realtime')
  // GET /v1/streams needs streams.read; the access log page itself is visible with sites.read.
  const canListStreams = useSessionStore((state) => state.principal?.permissions.some((code) => code === 'streams.read' || code === 'platform.admin') ?? false)
  const streams = useQuery({
    queryKey: ['l4-session-streams', ownerKey],
    queryFn: () => streamsApi.list(sessionToken(ownerKey), { page: 1, limit: 100 }),
    enabled: canListStreams,
    retry: false, refetchOnWindowFocus: false,
  })
  if (!canListStreams) return <Alert type="warning" showIcon message={t('sessionLog.noStreamPermission')} />
  return <Select className="l4-session-stream" aria-label={t('sessionLog.stream')} placeholder={t('sessionLog.streamPlaceholder')}
    allowClear={allowClear} showSearch optionFilterProp="label" value={value} onChange={(next, option) => onChange(next ?? undefined, optionLabel(option))}
    loading={streams.isPending} style={{ minWidth: 260 }}
    options={(streams.data?.items ?? []).map((item) => ({ value: item.id,
      label: `${item.name} (${item.listen_port}/${item.protocol.toUpperCase()})${item.session_log_enabled ? '' : ` · ${t('sessionLog.notEnabled')}`}` }))} />
}

function SessionLogPanel({ audience, ownerKey }: { audience: L4RealtimeAudience; ownerKey: string }) {
  const { t, i18n } = useTranslation('l4Realtime')
  const [tenantId, setTenantId] = useState<string>()
  const [nodeId, setNodeId] = useState<string>()
  const [streamId, setStreamId] = useState<string>()
  // 客户端 IP/端口 可从分享链接带入，已生效后写回 URL。
  const [initialParams] = useSearchParams()
  const [client, setClient] = useState(() => filterParam(initialParams, 'client_ip'))
  const [port, setPort] = useState(() => filterParam(initialParams, 'port'))
  const [reason, setReason] = useState<L4EndReason>()
  const [range, setRange] = useState<L4SessionLogFilters['range']>('1h')
  const [validation, setValidation] = useState<string | null>(null)
  const [applied, setApplied] = useState<L4SessionLogFilters>({ range: '1h', limit: 50 })
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors[cursors.length - 1]
  const query = useQuery({
    queryKey: ['l4-session-logs', ownerKey, applied, cursor],
    queryFn: ({ signal }) => l4SessionLogsApi.readSessionLogs(sessionToken(ownerKey), audience, { ...applied, ...(cursor ? { cursor } : {}) }, signal),
    retry: false, refetchOnWindowFocus: false,
  })
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const [labels, setLabels] = useState<Record<string, string | undefined>>({})
  // A tag's × or 清空高级条件 clears those fields and queries again at once.
  const apply = (cleared: Partial<Record<'tenantId' | 'nodeId' | 'listenPort' | 'endReason', true>> = {}) => {
    const t2 = cleared.tenantId ? undefined : tenantId, n2 = cleared.nodeId ? undefined : nodeId
    const p2 = cleared.listenPort ? '' : port, r2 = cleared.endReason ? undefined : reason
    if (cleared.tenantId) setTenantId(undefined)
    if (cleared.nodeId) setNodeId(undefined)
    if (cleared.listenPort) setPort('')
    if (cleared.endReason) setReason(undefined)
    const listenPort = p2.trim() === '' ? undefined : Number(p2)
    if (listenPort !== undefined && (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535)) {
      setValidation(t('filters.invalidPort'))
      return
    }
    if (!validClientFilter(client)) {
      setValidation(t('sessionLog.invalidClient'))
      return
    }
    setValidation(null)
    setCursors([])
    setApplied({ range, limit: 50, ...(t2 ? { tenantId: t2 } : {}), ...(n2 ? { nodeId: n2 } : {}), ...(streamId ? { streamId } : {}), ...(listenPort ? { listenPort } : {}),
      ...(client.trim() ? { clientIp: client.trim() } : {}), ...(r2 ? { endReason: r2 } : {}) })
  }
  // 边输入边生效；下拉选完即查，文本 400ms 防抖；不合法时 apply 就地报错不发请求。
  const draftKey = JSON.stringify([range, tenantId, nodeId, streamId, port.trim(), client.trim(), reason])
  const [appliedKey, setAppliedKey] = useState(() => JSON.stringify(['1h', undefined, undefined, undefined, '', '', undefined]))
  useLiveApply(draftKey, appliedKey, () => { setAppliedKey(draftKey); apply() })
  useFilterUrl({ client_ip: applied.clientIp, port: applied.listenPort })
  const columns: TableColumnsType<L4SessionLogRow> = [
    { title: t('sessionLog.columns.finished'), dataIndex: 'finalized_at', key: 'finalized_at', width: 170, render: (value: string) => formatDateTime(value) },
    { title: t('sessionLog.columns.client'), key: 'client', width: 200, render: (_, row) => <>
      {row.client_ip}:{row.client_port}{row.peer_ip ? <div className="l4-session-muted">{t('sessionLog.via', { peer: row.peer_ip })}</div> : null}
    </> },
    { title: t('columns.port'), key: 'port', width: 110, render: (_, row) => `${row.listen_port}/${row.protocol.toUpperCase()}` },
    { title: t('sessionLog.columns.upstream'), key: 'upstream', width: 180, render: (_, row) => row.upstream_addr
      ? <>{row.upstream_addr}{row.upstream_connect_ms !== undefined ? <div className="l4-session-muted">{row.upstream_connect_ms} ms</div> : null}</> : '-' },
    { title: t('columns.bytesUp'), dataIndex: 'bytes_up', key: 'bytes_up', width: 100, render: (value: number) => formatBytes(value, language) },
    { title: t('columns.bytesDown'), dataIndex: 'bytes_down', key: 'bytes_down', width: 100, render: (value: number) => formatBytes(value, language) },
    { title: t('sessionLog.columns.duration'), key: 'duration', width: 100, render: (_, row) => `${((Date.parse(row.finalized_at) - Date.parse(row.started_at)) / 1000).toFixed(1)} s` },
    { title: t('sessionLog.columns.reason'), dataIndex: 'end_reason', key: 'end_reason', width: 130, render: (value: L4EndReason) =>
      <Tag color={value === 'closed' ? 'default' : value === 'killed' ? 'orange' : 'red'}>{t(`sessionLog.reasons.${value}`)}</Tag> },
  ]
  return <div className="l4-session-panel">
    {/* 常显 转发、客户端 IP、时间范围；租户、节点、端口、结束原因收进高级筛选。 */}
    <AdvancedFilters
      className="l4-realtime-baseline-filter"
      storageKey="l4-access-log"
      columns={audience === 'admin' ? 4 : 2}
      primary={<>
        <StreamSelect ownerKey={ownerKey} value={streamId} onChange={setStreamId} allowClear />
        <Input aria-label={t('sessionLog.client')} placeholder={t('sessionLog.clientPlaceholder')} value={client} onChange={(event) => setClient(event.target.value)} onPressEnter={() => apply()} style={{ width: 200 }} />
        <Select aria-label={t('filters.range')} value={range} onChange={setRange} style={{ width: 120 }}
          options={[{ value: '1h', label: t('ranges.one') }, { value: '6h', label: t('ranges.six') }, { value: '12h', label: t('ranges.twelve') }, { value: '24h', label: t('ranges.day') }]} />
      </>}
      items={[
        ...(audience === 'admin' ? [
          { key: 'tenantId', label: t('filters.tenant'), applied: applied.tenantId ? labels.tenantId ?? applied.tenantId : '',
            field: <L4TenantSelect ownerKey={ownerKey} value={tenantId} onChange={(value, label) => { setTenantId(value); setLabels((current) => ({ ...current, tenantId: label })) }} /> },
          { key: 'nodeId', label: t('filters.node'), applied: applied.nodeId ? labels.nodeId ?? applied.nodeId : '',
            field: <L4NodeSelect ownerKey={ownerKey} value={nodeId} onChange={(value, label) => { setNodeId(value); setLabels((current) => ({ ...current, nodeId: label })) }} /> },
        ] : []),
        { key: 'listenPort', label: t('filters.port'), applied: applied.listenPort ? String(applied.listenPort) : '',
          field: <Input aria-label={t('filters.port')} placeholder={t('filters.port')} value={port} onChange={(event) => setPort(event.target.value)} /> },
        { key: 'endReason', label: t('sessionLog.reason'), applied: applied.endReason ? t(`sessionLog.reasons.${applied.endReason}`) : '',
          field: <Select aria-label={t('sessionLog.reason')} placeholder={t('sessionLog.reason')} allowClear value={reason} onChange={setReason}
            options={l4EndReasons.map((value) => ({ value, label: t(`sessionLog.reasons.${value}`) }))} /> },
      ]}
      queryIcon={<Search size={15} />}
      queryText={t('actions.query')}
      queryLoading={query.isFetching}
      onQuery={() => apply()}
      onClearAdvanced={() => apply({ tenantId: true, nodeId: true, listenPort: true, endReason: true })}
      onRemove={(key) => apply({ [key]: true })}
    />
    <p className="l4-session-muted density-note">{t('sessionLog.help')}</p>
    {validation ? <Alert type="error" showIcon message={validation} /> : null}
    {query.error ? <FeedbackWhen title={t(errorKey(query.error))} /> : null}
    <Table<L4SessionLogRow> columns={columns} dataSource={query.data?.rows ?? []} rowKey="event_id" loading={query.isPending} pagination={false}
      locale={{ emptyText: t('sessionLog.empty') }} scroll={{ x: 1090 }} size="small" />
    <div className="l4-session-pager">
      {/* 会话日志在 ClickHouse，不做精确计数（tp-b7b）：已翻过的条数，还有下一页时显示 N+ */}
      {query.data ? <span>{t(query.data.next_cursor ? 'pager.totalMore' : 'pager.total', { count: cursors.length * (applied.limit ?? 50) + query.data.rows.length })}</span> : null}
      <Button disabled={cursors.length === 0} onClick={() => setCursors(cursors.slice(0, -1))}>{t('actions.previous')}</Button>
      <Button disabled={!query.data?.next_cursor} onClick={() => query.data?.next_cursor && setCursors([...cursors, query.data.next_cursor])}>{t('actions.next')}</Button>
    </div>
  </div>
}

type LiveRow = L4AllLiveConnection

export const quickBanDefaultSeconds = 3600

// withQuickBan returns item's guard rules with client banned for banSeconds:
// added to the first ban rule that only lists client IPs with this duration
// (one rule collects the quick bans), else a new such rule placed first so
// an allow rule cannot pass the client. null: already banned there, or no
// room for another rule.
export function withQuickBan(rules: readonly StreamGuardRule[], client: string, banSeconds: number): StreamGuardRule[] | null {
  const cidr = client.includes(':') ? `${client.toLowerCase()}/128` : `${client}/32`
  const index = rules.findIndex((rule) => rule.action === 'ban' && rule.threshold === 1 && rule.ban_seconds === banSeconds &&
    rule.client_ip !== undefined && !rule.client_ip.negate && !rule.first_packet && !rule.server_names && !rule.geo &&
    rule.client_ip.cidrs.length < 1024)
  if (index >= 0) {
    if (rules[index].client_ip!.cidrs.includes(cidr)) return null
    return rules.map((rule, position) => position === index ? { ...rule, client_ip: { cidrs: [...rule.client_ip!.cidrs, cidr] } } : rule)
  }
  if (rules.length >= streamGuardRulesMax) return null
  return [{ id: newGuardRuleID(), action: 'ban', ban_seconds: banSeconds, threshold: 1, client_ip: { cidrs: [cidr] } }, ...rules]
}

function LiveConnectionsPanel({ audience, ownerKey, canManage }: { audience: L4RealtimeAudience; ownerKey: string; canManage: boolean }) {
  const { t, i18n } = useTranslation('l4Realtime')
  const [tenantId, setTenantId] = useState<string>()
  const [nodeId, setNodeId] = useState<string>()
  const [streamId, setStreamId] = useState<string>()
  const [initialParams] = useSearchParams()
  const [port, setPort] = useState(() => filterParam(initialParams, 'port'))
  const [client, setClient] = useState(() => filterParam(initialParams, 'client_ip'))
  // Opened with no filter: every forward the session reaches (all tenants
  // for the platform), newest connection first.
  const [applied, setApplied] = useState<L4AllLiveFilters>({})
  const [validation, setValidation] = useState<string | null>(null)
  const [closedMessage, setClosedMessage] = useState<string | null>(null)
  const [banSeconds, setBanSeconds] = useState<number>(quickBanDefaultSeconds)
  const query = useQuery({
    queryKey: ['l4-live-all', ownerKey, applied],
    queryFn: ({ signal }) => l4SessionLogsApi.listAll(sessionToken(ownerKey), applied, signal),
    retry: false, refetchOnWindowFocus: false,
  })
  const rows: LiveRow[] = query.data?.connections ?? []
  const close = useMutation({
    mutationFn: async (targets: LiveRow[]) => {
      const groups = new Map<string, { stream: string; node: string; keys: string[] }>()
      for (const row of targets) {
        const key = `${row.stream_id}/${row.node_id}`
        const group = groups.get(key) ?? { stream: row.stream_id, node: row.node_id, keys: [] }
        group.keys.push(row.session_key)
        groups.set(key, group)
      }
      const results = await Promise.all([...groups.values()].map((group) => l4SessionLogsApi.closeLive(sessionToken(ownerKey), group.stream, group.node, group.keys)))
      return results.flatMap((result) => result.results).filter((item) => !item.error_code).length
    },
    onSuccess: (closed) => {
      setClosedMessage(t('live.closed', { count: closed }))
      void query.refetch()
    },
  })
  // 一键拉黑: a ban rule on the row's forward (published like any edit), then
  // the client's open connections on that forward are closed where the node can.
  const ban = useMutation({
    mutationFn: async (row: LiveRow) => {
      const token = sessionToken(ownerKey)
      const item: Stream = await streamsApi.get(token, row.stream_id)
      const rules = withQuickBan(item.guard_rules ?? [], row.client_ip, banSeconds)
      if (rules === null) return { ip: row.client_ip, added: false }
      await streamsApi.update(token, item.id, { ...streamFields(item), ...guardRulesField(rules), expected_revision: item.revision },
        writeKey(`ban-stream-${item.id}`))
      const open = rows.filter((other) => other.stream_id === row.stream_id && other.client_ip === row.client_ip && other.can_close)
      if (open.length) await close.mutateAsync(open).catch(() => undefined)
      return { ip: row.client_ip, added: true }
    },
    onSuccess: (result) => setClosedMessage(t(result.added ? 'live.banned' : 'live.alreadyBanned', { ip: result.ip, seconds: banSeconds })),
  })
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const problems = query.data?.problems ?? []
  const [labels, setLabels] = useState<Record<string, string | undefined>>({})
  const refresh = (cleared: Partial<Record<'tenantId' | 'nodeId' | 'listenPort', true>> = {}) => {
    const tenantId2 = cleared.tenantId ? undefined : tenantId, nodeId2 = cleared.nodeId ? undefined : nodeId, port2 = cleared.listenPort ? '' : port
    if (cleared.tenantId) setTenantId(undefined)
    if (cleared.nodeId) setNodeId(undefined)
    if (cleared.listenPort) setPort('')
    const listenPort = port2.trim() === '' ? undefined : Number(port2)
    if (listenPort !== undefined && (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535)) {
      setValidation(t('filters.invalidPort'))
      return
    }
    if (!validClientFilter(client)) {
      setValidation(t('sessionLog.invalidClient'))
      return
    }
    setValidation(null)
    setClosedMessage(null)
    const next: L4AllLiveFilters = { ...(tenantId2 ? { tenantId: tenantId2 } : {}), ...(nodeId2 ? { nodeId: nodeId2 } : {}), ...(streamId ? { streamId } : {}),
      ...(listenPort ? { listenPort } : {}), ...(client.trim() ? { clientIp: client.trim() } : {}) }
    if (JSON.stringify(next) === JSON.stringify(applied)) void query.refetch()
    else setApplied(next)
  }
  // 同上，边输入边生效。
  const draftKey = JSON.stringify([tenantId, nodeId, streamId, port.trim(), client.trim()])
  const [appliedKey, setAppliedKey] = useState(() => JSON.stringify([undefined, undefined, undefined, '', '']))
  useLiveApply(draftKey, appliedKey, () => { setAppliedKey(draftKey); refresh() })
  useFilterUrl({ client_ip: applied.clientIp, port: applied.listenPort })
  const columns: TableColumnsType<LiveRow> = [
    { title: t('live.columns.started'), key: 'started', width: 170, render: (_, row) => row.started_at ? formatDateTime(row.started_at) : t('live.untracked') },
    { title: t('columns.node'), dataIndex: 'node_name', key: 'node', width: 140 },
    { title: t('sessionLog.stream'), dataIndex: 'stream_name', key: 'stream', width: 160 },
    { title: t('sessionLog.columns.client'), key: 'client', width: 200, render: (_, row) => <>
      {row.client_ip}:{row.client_port}{row.peer_ip ? <div className="l4-session-muted">{t('sessionLog.via', { peer: row.peer_ip })}</div> : null}
    </> },
    { title: t('columns.port'), dataIndex: 'listen_port', key: 'port', width: 90 },
    { title: t('sessionLog.columns.upstream'), dataIndex: 'upstream', key: 'upstream', width: 170 },
    { title: t('live.columns.received'), key: 'received', width: 100, render: (_, row) => row.bytes_received === undefined ? '-' : formatBytes(row.bytes_received, language) },
    { title: t('live.columns.sent'), key: 'sent', width: 100, render: (_, row) => row.bytes_sent === undefined ? '-' : formatBytes(row.bytes_sent, language) },
    ...(canManage ? [{ title: t('live.columns.action'), key: 'action', width: 240, render: (_: unknown, row: LiveRow) => <span className="l4-session-actions">
      {row.can_close ? <>
        <Popconfirm title={t('live.confirmClose')} onConfirm={() => close.mutate([row])}><Button size="small" danger>{t('live.close')}</Button></Popconfirm>
        <Popconfirm title={t('live.confirmCloseIP', { ip: row.client_ip })}
          onConfirm={() => close.mutate(rows.filter((item) => item.client_ip === row.client_ip && item.can_close))}>
          <Button size="small">{t('live.closeIP')}</Button>
        </Popconfirm>
      </> : <span className="l4-session-muted">{t('live.viewOnly')}</span>}
      <Popconfirm title={t('live.confirmBan', { ip: row.client_ip })} description={<span className="l4-session-ban">
        {t('live.banSeconds')} <InputNumber aria-label={t('live.banSeconds')} size="small" min={1} max={86400} precision={0} value={banSeconds}
          onChange={(value) => setBanSeconds(value ?? quickBanDefaultSeconds)} />
        <div className="l4-session-muted">{t('live.banHelp')}</div></span>}
        onConfirm={() => ban.mutate(row)}>
        <Button size="small" danger loading={ban.isPending && ban.variables?.client_ip === row.client_ip}>{t('live.ban')}</Button>
      </Popconfirm>
    </span> }] : []),
  ]
  return <div className="l4-session-panel">
    {/* 常显 转发、客户端 IP；租户、节点、端口收进高级筛选（平台视角共 5 项）。 */}
    <AdvancedFilters
      className="l4-realtime-baseline-filter"
      storageKey="l4-live-connections"
      columns={audience === 'admin' ? 3 : 2}
      primary={<>
        <StreamSelect ownerKey={ownerKey} value={streamId} onChange={setStreamId} allowClear />
        <Input aria-label={t('sessionLog.client')} placeholder={t('sessionLog.clientPlaceholder')} value={client} onChange={(event) => setClient(event.target.value)} onPressEnter={() => refresh()} style={{ width: 200 }} />
      </>}
      items={[
        ...(audience === 'admin' ? [
          { key: 'tenantId', label: t('filters.tenant'), applied: applied.tenantId ? labels.tenantId ?? applied.tenantId : '',
            field: <L4TenantSelect ownerKey={ownerKey} value={tenantId} onChange={(value, label) => { setTenantId(value); setLabels((current) => ({ ...current, tenantId: label })) }} /> },
          { key: 'nodeId', label: t('filters.node'), applied: applied.nodeId ? labels.nodeId ?? applied.nodeId : '',
            field: <L4NodeSelect ownerKey={ownerKey} value={nodeId} onChange={(value, label) => { setNodeId(value); setLabels((current) => ({ ...current, nodeId: label })) }} /> },
        ] : []),
        { key: 'listenPort', label: t('filters.port'), applied: applied.listenPort ? String(applied.listenPort) : '',
          field: <Input aria-label={t('filters.port')} placeholder={t('filters.port')} value={port} onChange={(event) => setPort(event.target.value)} /> },
      ]}
      queryIcon={<RefreshCw size={15} />}
      queryText={t('actions.refresh')}
      queryLoading={query.isFetching}
      onQuery={() => refresh()}
      onClearAdvanced={() => refresh({ tenantId: true, nodeId: true, listenPort: true })}
      onRemove={(key) => refresh({ [key]: true })}
    />
    <p className="l4-session-muted density-note">{t('live.help')}</p>
    {validation ? <Alert type="error" showIcon message={validation} /> : null}
    {query.error ? <FeedbackWhen title={t(errorKey(query.error))} /> : null}
    {close.error ? <FeedbackWhen title={t('live.closeFailed')} /> : null}
    {ban.error ? <FeedbackWhen title={ban.error instanceof ApiError && ban.error.status === 409 ? t('live.banConflict') : t('live.banFailed')} /> : null}
    {closedMessage ? <Alert type="success" showIcon message={closedMessage} /> : null}
    {problems.length > 0 ? <Alert type="warning" showIcon message={t('live.problems')} description={<ul className="l4-session-problems">
      {problems.map((node) => <li key={node.node_id}>{node.node_name}: {t(`live.states.${node.state}`)}{node.error_code ? ` (${node.error_code})` : ''}</li>)}
    </ul>} /> : null}
    {query.data?.streams_truncated ? <Alert type="info" showIcon message={t('live.streamsTruncated', { count: query.data.streams })} /> : null}
    {query.data?.truncated ? <Alert type="info" showIcon message={t('live.truncated')} /> : null}
    <Table<LiveRow> columns={columns} dataSource={rows} rowKey={(row) => `${row.stream_id}/${row.node_id}/${row.session_key}`} loading={query.isFetching}
      pagination={{ pageSize: 50, hideOnSinglePage: true }} locale={{ emptyText: t('live.empty') }} scroll={{ x: 1290 }} size="small" />
  </div>
}

// The two pages: 四层访问日志 (same audience rule as 四层实时监控: tenant
// sites.read or platform.admin) and 四层实时连接 (streams.read, the route the
// live endpoint checks; disconnect needs streams.manage).
function scopedPrincipal(principal: Principal | null, tenantAllowed: (permissions: readonly string[]) => boolean, platformAllowed: (permissions: readonly string[]) => boolean): boolean {
  if (!principal) return false
  if (principal.scope_kind === 'tenant') return Boolean(principal.tenant_id) && tenantAllowed(principal.permissions)
  return principal.scope_kind === 'platform' && principal.tenant_id === null && platformAllowed(principal.permissions)
}

function SessionPage({ id, heading, children }: { id: string; heading: string; children: ReactNode }) {
  return <section className="l4-realtime-baseline-page" aria-labelledby={id}>
    <h1 className="visually-hidden" id={id}>{heading}</h1>
    <div className="l4-realtime-baseline-panel">{children}</div>
  </section>
}

export function L4AccessLogPage() {
  const { t } = useTranslation('l4Realtime')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken || !principal || !scopedPrincipal(principal, (permissions) => permissions.includes('sites.read'), (permissions) => permissions.includes('platform.admin'))) {
    return <DataState status="forbidden" className="identity-page" message={t('states.permissionTitle')} description={t('sessionLog.forbidden')} />
  }
  const audience: L4RealtimeAudience = principal.scope_kind === 'tenant' ? 'tenant' : 'admin'
  const ownerKey = `${principal.user_id}:${principal.scope_kind}:${principal.scope_id}`
  return <SessionPage id="l4-access-log-title" heading={t('sessionLog.heading')}><SessionLogPanel audience={audience} ownerKey={ownerKey} /></SessionPage>
}

export function L4LiveConnectionsPage() {
  const { t } = useTranslation('l4Realtime')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const canRead = (permissions: readonly string[]) => hasStreamReadPermission(principal?.scope_kind ?? 'tenant', permissions)
  if (!accessToken || !principal || !scopedPrincipal(principal, canRead, canRead)) {
    return <DataState status="forbidden" className="identity-page" message={t('states.permissionTitle')} description={t('live.forbidden')} />
  }
  const ownerKey = `${principal.user_id}:${principal.scope_kind}:${principal.scope_id}`
  return <SessionPage id="l4-live-title" heading={t('live.heading')}>
    <LiveConnectionsPanel audience={principal.scope_kind === 'tenant' ? 'tenant' : 'admin'} ownerKey={ownerKey} canManage={hasStreamManagePermission(principal.permissions)} />
  </SessionPage>
}
