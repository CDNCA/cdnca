import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Form, Input, InputNumber, Popconfirm, Radio, Result, Select, Spin, Switch, type FormInstance } from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { ArrowLeft, Pencil, Plus, RefreshCw, Trash2, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { ApiError, type ScopeKind } from '../api/auth'
import { streamsApi, type Stream, type StreamAdditionalListener, type StreamOrigin, type UpdateStreamRequest } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/streamGuard'
import '../i18n/originWeight'
import { streamOriginShares } from './originWeightShare'
import StreamPublicationModal from './StreamPublicationModal'
import { dropWriteRecovery, useWriteRecovery } from './streamWriteRecovery'
import StreamGroupSelect from './StreamGroupSelect'
import { StreamClientAddressField, StreamDNSFields, StreamFollowPortField, StreamGeoFields, StreamGuardRulesFields, StreamListenPortEndField, StreamNewConnectionRateFields, StreamSessionLogField, StreamTLSPassthroughFields } from './StreamPolicyFields'
import {
  currentPrincipalCanManageStreams, currentPrincipalCanReadStreams, defaultDomainDNSPolicy,
  errorMessage, hasStreamManagePermission, hasStreamReadPermission, isDomainName, isIPAddress,
  guardRuleRow, originRows, portLabel, portRangeFields, portRangeProblem, regionCIDRsInput, staleStreamRead, streamFields, streamFormFields, uuidPattern,
  validCIDR, writeKey, writeOutcomeUnknown, type StreamFormValues,
} from './streamForm'
import './StreamDetailPage.css'

interface DetailSession {
  id: string
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  canManage: boolean
}

// 同协议的监听（含端口范围）不得重叠。
function socketsOverlap(sockets: Array<{ protocol: string; port: number; port_end?: number | null }>): boolean {
  return sockets.some((socket, index) => sockets.slice(0, index).some((other) => other.protocol === socket.protocol &&
    socket.port <= (other.port_end || other.port) && other.port <= (socket.port_end || socket.port)))
}

function formValues(item: Stream): StreamFormValues {
  return {
    ...streamFields(item),
    listen_port_end: item.listen_port_end || undefined,
    upstream_follow_port: Boolean(item.upstream_follow_port),
    dns_policy: item.upstream_host ? item.dns_policy : defaultDomainDNSPolicy(),
    group_ids: item.groups.map((group) => group.id),
    upstream_mode: item.upstream_host ? 'host' : 'address',
    geo_trusted_proxy_cidrs: item.geo_policy.trusted_proxy_cidrs.join('\n'),
    geo_blocked_regions: item.geo_policy.blocked_regions.join(', '),
    geo_region_cidrs: regionCIDRsInput(item.geo_policy.region_cidrs),
    guard_rule_rows: (item.guard_rules ?? []).map(guardRuleRow),
    // 单个源站以 upstream_address / upstream_host 为准（服务端把单源站存为无列表）。
    origins: (item.origins.length > 1 ? item.origins : originRows({ ...item, origins: [] })).map((origin) => ({ ...origin })),
    acl_default: item.acl.default_action,
    acl_rules: item.acl.rules.map((rule) => ({ ...rule })),
    listen_ipv6: item.listen_ipv6,
  }
}

// 结果未知时页面显示待确认的那次请求（L4-007），不显示服务端旧值。
function pendingView(item: Stream, input: UpdateStreamRequest): Stream {
  const groups = input.group_ids?.map((groupID) => item.groups.find((group) => group.id === groupID) ?? { id: groupID, name: groupID, remark: '' })
  return {
    ...item, ...input, groups: groups ?? item.groups,
    origins: input.origins ?? [], acl: input.acl ?? { default_action: 'allow', rules: [] }, listen_ipv6: Boolean(input.listen_ipv6),
    listen_port_end: input.listen_port_end, upstream_follow_port: input.upstream_follow_port, guard_rules: input.guard_rules,
  }
}

// 单个源站可为 IP 或域名，多个只能是 IP（服务端 normalizeOrigins）。
function originAddressProblem(value: string): string | null {
  if (!value || isIPAddress(value) || isDomainName(value)) return null
  return value.includes(':') || /^[\d.]+$/u.test(value) ? 'form.invalidUpstream' : 'form.invalidUpstreamHost'
}

export default function StreamDetailPage() {
  const { id = '' } = useParams<{ id: string }>()
  const { t } = useTranslation('streams')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken || !principal) return null
  if (!hasStreamReadPermission(principal.scope_kind, principal.permissions)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  if (!uuidPattern.test(id)) return <Result status="404" title={t('detail.notFound')} extra={<Link to="/stream/list">{t('detail.back')}</Link>} />
  return <StreamDetailContent key={`${id}:${principal.scope_kind}:${principal.scope_id}:${sessionEpoch}`}
    id={id} scopeKind={principal.scope_kind} scopeID={principal.scope_id} sessionEpoch={sessionEpoch}
    canManage={hasStreamManagePermission(principal.permissions)} />
}

type DraftField = { name: Extract<Parameters<FormInstance<StreamFormValues>['getFieldValue']>[0], unknown[]>; value: unknown }
function changedFields(values: object, baseline: object, path: string[] = []): DraftField[] {
  return Object.entries(values).flatMap(([key, value]) => {
    const name = [...path, key]
    const previous = (baseline as Record<string, unknown>)[key]
    if (value && typeof value === 'object' && !Array.isArray(value)) return changedFields(value, previous && typeof previous === 'object' ? previous : {}, name)
    return JSON.stringify(value) === JSON.stringify(previous) ? [] : [{ name: name as DraftField['name'], value }]
  })
}

type DetailSection = 'all' | 'listener' | 'listeners'
type DetailWriteAttempt = { input: UpdateStreamRequest; key: string; section: DetailSection }

function StreamDetailContent({ id, scopeKind, scopeID, sessionEpoch, canManage }: DetailSession) {
  const { t, i18n } = useTranslation('streams')
  const { t: tGuard } = useTranslation('streamGuard')
  const { t: tW } = useTranslation('originWeight')
  const queryClient = useQueryClient()
  const [form] = Form.useForm<StreamFormValues>()
  const [messageApi, context] = useFeedbackMessage()
  const [tab, setTab] = useState<'basic' | 'access'>('basic')
  const [publicationOpen, setPublicationOpen] = useState(false)
  const [listenerOpen, setListenerOpen] = useState(false)
  const [listenerDraft, setListenerDraft] = useState<(Omit<StreamAdditionalListener, 'port'> & { port: number | null }) | null>(null)
  const [listenerError, setListenerError] = useState<string | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  // L4-007：结果未知的请求按 作用域/会话/转发 存在查询缓存里，离开再回来仍冻结编辑、只能按原请求重试。
  const recovery = useWriteRecovery<DetailWriteAttempt>({ scopeKind, scopeID, sessionEpoch }, `detail:${id}`)
  const retryAttempt = recovery.attempt
  const draft = useRef<DraftField[]>([])
  const writing = useRef(false)
  const advancedRef = useRef<HTMLDetailsElement>(null)
  const guard = useRef({ fetching: true, denied: false })
  const protocol = Form.useWatch('protocol', form)
  const listenPort = Form.useWatch('listen_port', form)
  const listenPortEnd = Form.useWatch('listen_port_end', form)
  const followPort = Form.useWatch('upstream_follow_port', form)
  const originValues = Form.useWatch('origins', { form, preserve: true }) as Array<StreamOrigin | undefined> | undefined
  const balanceWay = Form.useWatch('balance_way', form)
  const originShares = streamOriginShares(originValues ?? [])
  // 只有一个源站且是域名时才有 DNS 缓存策略（多源站只能是 IP）。
  const firstOrigin = originValues?.[0]?.address?.trim() ?? ''
  const domainOrigin = originValues?.length === 1 && firstOrigin !== '' && !isIPAddress(firstOrigin)
  const geoEnabled = Form.useWatch(['geo_policy', 'enabled'], form)
  const tlsPassthrough = Form.useWatch('tls_passthrough', form)
  const queryKey = ['stream-detail', scopeKind, scopeID, sessionEpoch, id]
  const mayRead = () => currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)
  const mayWrite = () => mayRead() && !guard.current.fetching && !guard.current.denied &&
    currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)
  const query = useQuery({
    queryKey,
    queryFn: async () => {
      if (!mayRead()) throw staleStreamRead
      const item = await streamsApi.get(useSessionStore.getState().accessToken ?? '', id)
      if (!mayRead()) throw staleStreamRead
      return item
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  const item = query.data
  const additionalListeners = item?.additional_listeners ?? []
  const hasUDP = protocol === 'udp' || additionalListeners.some((listener) => listener.protocol === 'udp')
  const tcpOnly = Boolean(item?.tls_passthrough || tlsPassthrough)
  const readError = query.error instanceof ApiError ? query.error : null
  guard.current = { fetching: query.isFetching, denied: query.isError || writeError?.status === 403 || writeError?.code === 'version_conflict' }
  useEffect(() => {
    if (!item) return
    form.setFieldsValue(formValues(retryAttempt ? pendingView(item, retryAttempt.input) : item))
    form.setFields(draft.current)
  }, [form, item, retryAttempt])
  const rememberDraft = () => {
    if (!item) return
    draft.current = changedFields(form.getFieldsValue(true) as StreamFormValues, formValues(item))
  }
  useEffect(() => {
    if (!hasUDP) return
    form.setFieldsValue({ proxy_protocol_inbound: false, proxy_protocol_v1: false, toa: false, geo_trusted_proxy_cidrs: '' })
  }, [form, hasUDP])
  useEffect(() => {
    if (canManage) return
    setListenerOpen(false)
    recovery.clear()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- 只在失去管理权限时清除
  }, [canManage])
  useEffect(() => () => {
    if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) {
      queryClient.removeQueries({ queryKey: ['stream-detail', scopeKind, scopeID, sessionEpoch] })
      dropWriteRecovery(queryClient, { scopeKind, scopeID, sessionEpoch })
    }
  }, [queryClient, scopeKind, scopeID, sessionEpoch])
  const mutation = useMutation({
    mutationFn: (attempt: DetailWriteAttempt) => {
      if (!mayWrite()) throw new ApiError('permission denied', 403, 'permission_denied')
      return streamsApi.update(useSessionStore.getState().accessToken ?? '', id, attempt.input, attempt.key)
    },
    onSuccess: async (updated, attempt) => {
      if (!mayRead() || !currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)) return
      recovery.settle(attempt, false)
      setWriteError(null)
      if (attempt.section === 'all') draft.current = []
      else {
        const saved: Array<keyof StreamFormValues> = attempt.section === 'listener'
          ? ['listen_port', 'listen_port_end', 'protocol'] : []
        if ((attempt.input.protocol === 'udp' || attempt.input.additional_listeners?.some((listener) => listener.protocol === 'udp'))) saved.push('proxy_protocol_inbound', 'proxy_protocol_v1', 'geo_trusted_proxy_cidrs')
        draft.current = draft.current.filter((field) => !saved.includes(field.name[0] as keyof StreamFormValues))
      }
      setListenerOpen(false); setListenerDraft(null); setListenerError(null)
      queryClient.setQueryData(queryKey, updated)
      form.setFieldsValue(formValues(updated))
      form.setFields(draft.current)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['streams', scopeKind, scopeID, sessionEpoch] }),
        queryClient.invalidateQueries({ queryKey }),
      ])
      if (mayRead()) messageApi.success(t('notices.updated'))
    },
    onError: (error, attempt) => {
      if (!mayRead() || !currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)) return
      setWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
      recovery.settle(attempt, writeOutcomeUnknown(error))
    },
    onSettled: () => { writing.current = false },
  })
  const locked = !canManage || mutation.isPending || query.isFetching || query.isError || Boolean(retryAttempt) || writeError?.status === 403 || writeError?.code === 'version_conflict'
  const saveListeners = (listeners: StreamAdditionalListener[], primary?: StreamAdditionalListener) => {
    if (!item || !mayWrite() || writing.current || retryAttempt) return
    const nextProtocol = primary?.protocol ?? item.protocol
    const nextPort = primary?.port ?? item.listen_port
    const nextPortEnd = primary ? primary.port_end : item.listen_port_end
    if (socketsOverlap([{ protocol: nextProtocol, port: nextPort, port_end: nextPortEnd }, ...listeners])) { setListenerError(t('detail.duplicateListener')); return }
    const rangeProblem = [{ port: nextPort, port_end: nextPortEnd }, ...listeners]
      .map((socket) => portRangeProblem(socket.port, socket.port_end, Boolean(item.tls_passthrough))).find(Boolean)
    if (rangeProblem) { setListenerError(t(`form.${rangeProblem}`)); return }
    if (item.tls_passthrough && (nextProtocol !== 'tcp' || listeners.some((listener) => listener.protocol !== 'tcp'))) { setListenerError(t('form.tlsPassthroughTCPOnly')); return }
    rememberDraft()
    // listen_port_end: undefined 不进请求体，单端口时清掉原范围。
    const fields = { ...streamFields(item), listen_port_end: undefined, protocol: nextProtocol, listen_port: nextPort, ...portRangeFields(nextPortEnd, item.upstream_follow_port),
      ...(item.upstream_follow_port ? { upstream_port: nextPort } : {}), additional_listeners: listeners }
    if (nextProtocol === 'udp' || listeners.some((listener) => listener.protocol === 'udp')) {
      fields.proxy_protocol_inbound = false
      fields.proxy_protocol_v1 = false
      fields.toa = false
      fields.geo_policy = { ...fields.geo_policy, trusted_proxy_cidrs: [] }
    }
    setWriteError(null)
    writing.current = true
    mutation.mutate({ input: { ...fields, expected_revision: item.revision }, key: writeKey(`update-stream-${id}`), section: primary ? 'listener' : 'listeners' })
  }
  const saveListenerDraft = () => {
    if (!listenerDraft || locked) return
    if (!Number.isInteger(listenerDraft.port) || Number(listenerDraft.port) < 1 || Number(listenerDraft.port) > 65535) {
      setListenerError(t('form.listenPortRange')); return
    }
    const { port_end: draftEnd, ...draftListener } = listenerDraft
    const listener: StreamAdditionalListener = { ...draftListener, port: Number(listenerDraft.port), id: listenerDraft.id || crypto.randomUUID(), ...(draftEnd ? { port_end: draftEnd } : {}) }
    saveListeners(listenerDraft.id ? additionalListeners.map((current) => current.id === listener.id ? listener : current) : [...additionalListeners, listener])
  }
  const removeListener = (listenerID: string) => {
    if (listenerID === id) {
      const [primary, ...rest] = additionalListeners
      if (primary) saveListeners(rest, primary)
    } else saveListeners(additionalListeners.filter((listener) => listener.id !== listenerID))
  }
  const submit = async (section: DetailSection = 'all') => {
    if (!item || !mayWrite() || writing.current || retryAttempt) return
    try {
      await form.validateFields(section === 'listener' ? ['listen_port', 'listen_port_end', 'protocol'] : undefined)
      const values = form.getFieldsValue(true) as StreamFormValues
      if (!mayWrite() || writing.current || retryAttempt) return
      rememberDraft()
      let fields = streamFields(item)
      if (section === 'all') {
        // L4-001/L4-002：源站列表、访问控制、IPv6 都从表单组装（后端整行更新，缺省即清除）。
        // 一个源站按地址/域名写 upstream_*（域名带 DNS 策略）；多个时带 origins，只能是 IP、DNS 为空。
        const origins = (values.origins ?? []).map((origin) => ({ address: origin.address.trim(), weight: origin.weight, down: Boolean(origin.down) }))
        const first = origins[0]?.address ?? ''
        const host = origins.length === 1 && !isIPAddress(first)
        const edited = streamFormFields({ ...values, upstream_mode: host ? 'host' : 'address', upstream_address: host ? '' : first, upstream_host: host ? first : '' })
        const aclRules = (values.acl_rules ?? []).map((rule) => ({ cidr: rule.cidr.trim(), action: rule.action }))
        const aclDefault = values.acl_default ?? 'allow'
        fields = {
          ...edited,
          ...(origins.length > 1 ? { origins } : {}),
          ...(values.listen_ipv6 ? { listen_ipv6: true } : {}),
          ...(aclDefault === 'deny' || aclRules.length > 0 ? { acl: { default_action: aclDefault, rules: aclRules } } : {}),
        }
      } else if (section === 'listener') {
        if (socketsOverlap([{ protocol: values.protocol, port: values.listen_port, port_end: values.listen_port_end }, ...additionalListeners])) {
          setListenerError(t('detail.duplicateListener')); return
        }
        if (item.tls_passthrough && values.protocol !== 'tcp') { setListenerError(t('form.tlsPassthroughTCPOnly')); return }
        fields = { ...fields, listen_port_end: undefined, listen_port: values.listen_port, protocol: values.protocol, ...portRangeFields(values.listen_port_end, item.upstream_follow_port),
          ...(item.upstream_follow_port ? { upstream_port: values.listen_port } : {}) }
        if (values.protocol === 'udp' || additionalListeners.some((listener) => listener.protocol === 'udp')) fields = { ...fields, proxy_protocol_inbound: false, proxy_protocol_v1: false, toa: false, geo_policy: { ...fields.geo_policy, trusted_proxy_cidrs: [] } }
      }
      setWriteError(null)
      writing.current = true
      mutation.mutate({ input: { ...fields, expected_revision: item.revision, ...(section === 'all' ? { group_ids: values.group_ids ?? [] } : {}) }, key: writeKey(`update-stream-${id}`), section })
    } catch {
      const invalid = form.getFieldsError().filter((field) => field.errors.length > 0).map((field) => String(field.name[0]))
      setTab(invalid.some((name) => name.startsWith('geo') || name === 'guard_rule_rows' || name === 'acl_rules') ? 'access' : 'basic')
      if (invalid.some((name) => ['name', 'connect_timeout_ms', 'response_timeout_ms', 'max_connections_per_client', 'max_new_connections_per_client_per_second', 'new_connection_burst', 'new_connection_ban_seconds', 'dns_policy'].includes(name)) && advancedRef.current) advancedRef.current.open = true
      if (invalid.includes('listen_port') || invalid.includes('listen_port_end')) setListenerOpen(true)
    }
  }
  const refresh = async () => {
    setWriteError(null)
    const response = await query.refetch()
    if (response.data && mayRead()) { form.setFieldsValue(formValues(response.data)); form.setFields(draft.current) }
  }
  const [operationLabel, operationTone] = !item ? ['', undefined]
    : item.admin_status !== 'normal' ? [t(`adminStatus.${item.admin_status}`), 'is-warning']
      : item.eligibility_state === 'ineligible' ? [t('states.ineligible'), 'is-warning']
        : item.enabled ? [t('states.normal'), 'is-normal'] : [t('states.disabled'), undefined]
  const aclActions = [{ value: 'allow', label: t('acl.allow') }, { value: 'deny', label: t('acl.deny') }]
  const date = (value?: string | null) => value ? formatDateTime(value, i18n.resolvedLanguage ?? i18n.language) : t('values.unavailable')
  if (readError?.status === 403) return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  if (readError?.status === 404) return <Result status="404" title={t('detail.notFound')} extra={<Link to="/stream/list">{t('detail.back')}</Link>} />
  return <section className="stream-detail-page" aria-labelledby="stream-detail-title">
    {context}
    <div className="stream-detail-inner">
      <header className="stream-detail-header">
        <Link to="/stream/list" aria-label={t('detail.back')}><ArrowLeft size={20} /></Link>
        <h1 id="stream-detail-title">{item ? t('detail.portTitle', { port: item.listen_port }) : t('detail.loading')}</h1>
        <Button className="stream-detail-refresh" icon={<RefreshCw size={14} />} disabled={mutation.isPending || Boolean(retryAttempt)} loading={query.isFetching} onClick={() => void refresh()}>{t('actions.refresh')}</Button>
      </header>
      <div className="stream-detail-tabs" role="tablist" aria-label={t('detail.tabs')}>
        {(['basic', 'access'] as const).map((value) => <button key={value} id={`stream-tab-${value}`} type="button" role="tab" aria-selected={tab === value} aria-controls={`stream-panel-${value}`} className={tab === value ? 'is-active' : undefined} onClick={() => setTab(value)}>{t(`detail.${value}`)}</button>)}
      </div>
      {query.isPending ? <div className="stream-detail-loading"><Spin aria-label={t('detail.loading')} /></div> : null}
      {query.isError ? <FeedbackWhen title={t('detail.loadFailed')} /> : null}
      {retryAttempt || writeError ? (retryAttempt ? <OutcomeUnknown type="error" title={t('detail.unknown')} action={canManage ? <Button size="small" loading={mutation.isPending} disabled={query.isFetching || mutation.isPending} onClick={() => { if (mayWrite() && !writing.current) { writing.current = true; mutation.mutate(retryAttempt) } }}>{t('detail.retryExact')}</Button> : null} /> : writeError ? <FeedbackWhen title={errorMessage(writeError, t)} /> : null) : null}
      {item ? <Form form={form} layout="vertical" requiredMark={false} disabled={locked} initialValues={formValues(item)} onValuesChange={rememberDraft}>
        <div id="stream-panel-basic" role="tabpanel" aria-labelledby="stream-tab-basic" hidden={tab !== 'basic'}>
          <section className="stream-detail-section">
            <h2>{t('detail.information')}</h2><p>{t('detail.informationHint')}</p>
            <dl className="stream-detail-facts">
              {/* L4-008：运营状态（人工状态 > 套餐不可用 > 启停，与列表同一取值）与配置同步并列。 */}
              <div><dt>{t('detail.operationStatus')}</dt><dd className={operationTone}>{operationLabel}</dd></div>
              <div><dt>{t('detail.syncStatus')}</dt><dd className={`stream-sync stream-sync--${item.sync_state}`}>{t(`syncState.${item.sync_state}`)}
                {item.sync_state === 'failed' ? <Button type="link" size="small" className="stream-detail-publication-link" onClick={() => setPublicationOpen(true)}>{t('actions.publicationDetails')}</Button> : null}</dd></div>
              <div><dt>{t('detail.createdAt')}</dt><dd>{date(item.created_at)}</dd></div>
              <div><dt>{t('columns.updatedAt')}</dt><dd>{date(item.updated_at)}</dd></div>
              <div className="stream-detail-fact-wide"><dt>{t('columns.cname')}</dt><dd>{item.cname || t('values.unavailable')}</dd></div>
            </dl>
          </section>
          <section className="stream-detail-section">
            <h2>{t('detail.configuration')}</h2><p>{t('detail.configurationHint')}</p>
            <div className="stream-detail-two-columns">
              <div className="stream-detail-box"><h3>{t('detail.ownership')}</h3>
                <Form.Item name="group_ids" label={t('form.group')}><StreamGroupSelect open={!locked} scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch} targetScopeID={item.scope_id} groups={item.groups} /></Form.Item>
              </div>
              <div className="stream-detail-box"><h3>{t('detail.listener')}</h3>
                <div className="stream-listener-chips">
                  {[{ id, port: listenPort ?? item.listen_port, port_end: listenPortEnd ?? undefined, protocol: protocol ?? item.protocol, address: '*' as const }, ...additionalListeners].map((listener) => <div className="stream-listener-entry" key={listener.id}>
                    <button type="button" className="stream-listener-chip" disabled={locked} aria-label={listener.id === id ? t('detail.editListener') : t('detail.editAdditionalListener', { port: listener.port, protocol: listener.protocol.toUpperCase() })} onClick={() => { setListenerDraft(listener.id === id ? null : listener); setListenerOpen(true); setListenerError(null) }}>{portLabel(listener.port, listener.port_end)}/{listener.protocol} {canManage ? <Pencil size={12} /> : null}</button>
                    {canManage ? <Popconfirm title={t('detail.removeListenerConfirm', { port: listener.port, protocol: listener.protocol.toUpperCase() })} okText={t('actions.confirm')} cancelText={t('actions.cancel')} onConfirm={() => removeListener(listener.id)} disabled={locked || additionalListeners.length === 0}>
                      <Button type="text" size="small" icon={<X size={12} />} aria-label={t('detail.removeListener', { port: listener.port, protocol: listener.protocol.toUpperCase() })} disabled={locked || additionalListeners.length === 0} />
                    </Popconfirm> : null}
                  </div>)}
                  {canManage ? <Button size="small" disabled={locked || additionalListeners.length >= 63} onClick={() => { setListenerDraft({ id: '', protocol: 'tcp', address: '*', port: null }); setListenerOpen(true); setListenerError(null) }}>{t('detail.addListener')}</Button> : null}
                </div>
                <div className="stream-listener-editor" hidden={!listenerOpen}>
                  <Form.Item name={listenerDraft ? undefined : 'listen_port'} htmlFor="stream-listener-port" label={t('form.listenPort')} rules={listenerDraft ? undefined : [{ required: true, message: t('form.listenPortRequired') }, { type: 'integer', min: 1, max: 65535, message: t('form.listenPortRange') }]}><InputNumber<number> id="stream-listener-port" min={1} max={65535} precision={0} {...(listenerDraft ? { value: listenerDraft.port, onChange: (port) => setListenerDraft({ ...listenerDraft, port }) } : {})} /></Form.Item>
                  {listenerDraft
                    ? <Form.Item htmlFor="stream-listener-port-end" label={t('form.listenPortEnd')} extra={t('form.listenPortEndHelp')}><InputNumber<number> id="stream-listener-port-end" min={2} max={65535} precision={0} placeholder={t('form.listenPortEndPlaceholder')} value={listenerDraft.port_end ?? null} onChange={(end) => setListenerDraft({ ...listenerDraft, port_end: end ?? undefined })} /></Form.Item>
                    : <StreamListenPortEndField form={form} />}
                  <Form.Item name={listenerDraft ? undefined : 'protocol'} htmlFor="stream-listener-protocol" label={t('form.protocol')}><Select id="stream-listener-protocol" {...(listenerDraft ? { value: listenerDraft.protocol, onChange: (value: 'tcp' | 'udp') => setListenerDraft({ ...listenerDraft, protocol: value }) } : {})} options={[{ value: 'tcp', label: t('values.tcp') }, { value: 'udp', label: t('values.udp'), disabled: tcpOnly }]} /></Form.Item>
                  <Button disabled={locked} onClick={() => listenerDraft ? saveListenerDraft() : void submit('listener')}>{t(listenerDraft?.id === '' ? 'detail.addListenerSubmit' : 'detail.updateListener')}</Button>
                </div>
                {listenerError ? <FeedbackWhen title={listenerError} /> : null}
                <StreamTLSPassthroughFields form={form} />
                <Form.Item name="listen_ipv6" label={t('acl.ipv6')} valuePropName="checked"><Switch /></Form.Item>
                <Form.Item name="enabled" label={t('form.enabled')} valuePropName="checked"><Switch /></Form.Item>
              </div>
            </div>
          </section>
          <section className="stream-detail-section">
            <h2>{t('detail.origins')}</h2><p>{t('detail.originsHint')}</p>
            <Form.List name="origins" rules={[{
              validator: (_, value: StreamOrigin[] | undefined) => {
                const list = value ?? []
                if (list.length === 0) return Promise.reject(new Error(t('origins.required')))
                if (list.length > 64) return Promise.reject(new Error(t('origins.tooMany')))
                if (list.every((origin) => origin?.down)) return Promise.reject(new Error(t('origins.allDown')))
                if (list.length > 1 && list.some((origin) => !isIPAddress(origin?.address?.trim() ?? ''))) return Promise.reject(new Error(t('origins.multipleNeedIP')))
                return Promise.resolve()
              },
            }]}>
              {(fields, { add, remove }, { errors }) => <div className="stream-origin-table">
                <table>
                  <thead><tr><th>{t('origins.address')}</th><th>{t('origins.weight')}</th><th>{t('origins.state')}</th><th>{t('detail.originShare')}</th><th>{t('columns.actions')}</th></tr></thead>
                  <tbody>{fields.map((field) => <tr key={field.key}>
                    <td data-label={t('origins.address')}><Form.Item name={[field.name, 'address']} rules={[{ required: true, whitespace: true, message: t('origins.addressRequired') }, {
                      validator: (_, value: string) => { const problem = originAddressProblem(value?.trim() ?? ''); return problem ? Promise.reject(new Error(t(problem))) : Promise.resolve() },
                    }]}><Input aria-label={t('origins.address')} placeholder={t('origins.addressPlaceholder')} /></Form.Item></td>
                    <td data-label={t('origins.weight')}><Form.Item name={[field.name, 'weight']} rules={[{ type: 'number', min: 1, max: 100, required: true, message: t('origins.weightRange') }]}>
                      <InputNumber aria-label={t('origins.weight')} min={1} max={100} precision={0} />
                    </Form.Item></td>
                    <td data-label={t('origins.state')}><Form.Item name={[field.name, 'down']} getValueProps={(down: boolean) => ({ value: down ? 'down' : 'up' })} getValueFromEvent={(value: string) => value === 'down'}>
                      <Select aria-label={t('origins.state')} options={[{ value: 'up', label: t('origins.up') }, { value: 'down', label: t('origins.down') }]} />
                    </Form.Item></td>
                    <td className="stream-origin-share" data-label={t('detail.originShare')} aria-live="polite">{originShares[field.name] == null ? tW('down') : tW('share', { share: originShares[field.name] })}</td>
                    <td>{canManage ? <Button type="text" aria-label={t('origins.remove')} icon={<Trash2 size={14} />} disabled={locked || fields.length === 1} onClick={() => remove(field.name)} /> : t('values.placeholder')}</td>
                  </tr>)}</tbody>
                </table>
                <div className="stream-origin-table-footer">
                  {canManage ? <Button size="small" icon={<Plus size={14} />} disabled={locked || fields.length >= 64} onClick={() => add({ address: '', weight: 1, down: false })}>{t('origins.add')}</Button> : null}
                  <p className="stream-origin-weight-help">{tW('help')} {tW(`stream.${balanceWay === 'ip_hash' ? 'ip_hash' : 'rr'}`)}</p>
                  <Form.ErrorList errors={errors} />
                </div>
              </div>}
            </Form.List>
            <div className="stream-detail-origin-settings">
              <Form.Item name="balance_way" label={t('defaults.settingBalanceWay')}><Radio.Group optionType="button" buttonStyle="solid" options={[{ value: 'rr', label: t('detail.roundRobin') }, { value: 'ip_hash', label: t('detail.ipHash') }]} /></Form.Item>
              <StreamFollowPortField />
              <Form.Item name="upstream_port" label={t('detail.originPort')} hidden={Boolean(followPort)} rules={followPort ? [] : [{ required: true, message: t('form.upstreamPortRequired') }, { type: 'integer', min: 1, max: 65535, message: t('form.upstreamPortRange') }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item>
              <StreamClientAddressField form={form} disabled={locked} />
            </div>
            <Form.Item name="remark" label={t('form.remark')} rules={[{ max: 256, message: t('form.remarkTooLong') }]}><Input.TextArea rows={2} placeholder={t('form.remarkPlaceholder')} /></Form.Item>
            <details ref={advancedRef} className="stream-detail-advanced"><summary>{t('detail.advanced')}</summary>
              <div className="stream-form-grid">
                <Form.Item name="name" label={t('form.name')} rules={[{ required: true, whitespace: true, message: t('form.nameRequired') }, { max: 128, message: t('form.nameTooLong') }]}><Input /></Form.Item>
                <Form.Item name="connect_timeout_ms" label={t('form.connectTimeout')} rules={[{ required: true, message: t('form.connectTimeoutRequired') }, { type: 'integer', min: 50, max: 30000, message: t('form.connectTimeoutRange') }]}><InputNumber min={50} max={30000} precision={0} /></Form.Item>
                <Form.Item name="response_timeout_ms" label={t('form.responseTimeout')} rules={[{ required: true, message: t('form.responseTimeoutRequired') }, { type: 'integer', min: 100, max: 600000, message: t('form.responseTimeoutRange') }]}><InputNumber min={100} max={600000} precision={0} /></Form.Item>
                <Form.Item name="max_connections_per_client" label={t('form.maxConnectionsPerClient')} rules={[{ required: true, message: t('form.maxConnectionsRequired') }, { type: 'integer', min: 1, max: 10000, message: t('form.maxConnectionsRange') }]}><InputNumber min={1} max={10000} precision={0} /></Form.Item>
                <StreamNewConnectionRateFields />
                <StreamSessionLogField />
              </div>
              {domainOrigin ? <StreamDNSFields form={form} /> : null}
            </details>
          </section>
        </div>
        <div id="stream-panel-access" role="tabpanel" aria-labelledby="stream-tab-access" hidden={tab !== 'access'}>
          {/* L4-002：访问 Tab 顺序 IP 访问控制 → 区域限制 → 连接防护。 */}
          <section className="stream-detail-section"><h2>{t('detail.acl')}</h2><p>{t('detail.aclHint')}</p>
            <Form.Item name="acl_default" label={t('acl.defaultAction')}><Radio.Group optionType="button" buttonStyle="solid" options={aclActions} /></Form.Item>
            <Form.Item label={t('acl.rules')}>
              <Form.List name="acl_rules">
                {(fields, { add, remove }) => <div className="stream-acl-list">
                  {fields.length === 0 ? <span className="stream-acl-empty">{t('acl.empty')}</span> : null}
                  {fields.map((field) => <div className="stream-acl-row" key={field.key}>
                    <Form.Item name={[field.name, 'cidr']} rules={[{
                      validator: (_, value: string) => validCIDR(value?.trim() ?? '') || isIPAddress(value?.trim() ?? '') ? Promise.resolve() : Promise.reject(new Error(t('acl.cidrInvalid'))),
                    }]}><Input aria-label={t('acl.ip')} placeholder={t('acl.ipPlaceholder')} /></Form.Item>
                    <Form.Item name={[field.name, 'action']}><Select aria-label={t('acl.action')} options={aclActions} /></Form.Item>
                    {canManage ? <Button type="text" aria-label={t('acl.remove')} icon={<Trash2 size={14} />} disabled={locked} onClick={() => remove(field.name)} /> : null}
                  </div>)}
                  {canManage ? <Button size="small" icon={<Plus size={14} />} disabled={locked || fields.length >= 1024} onClick={() => add({ cidr: '', action: 'deny' })}>{t('acl.add')}</Button> : null}
                </div>}
              </Form.List>
            </Form.Item>
          </section>
          <section className="stream-detail-section"><h2>{t('detail.geo')}</h2><p>{t('detail.geoHint')}</p>
            <Form.Item name={['geo_policy', 'enabled']} label={t('form.geoEnabled')} valuePropName="checked"><Switch /></Form.Item>
            {geoEnabled ? <><Form.Item name="proxy_protocol_inbound" label={t('form.proxyInbound')} valuePropName="checked"><Switch disabled={locked || hasUDP} /></Form.Item><StreamGeoFields form={form} /></> : null}
          </section>
          <section className="stream-detail-section"><h2>{tGuard('title')}</h2><p>{tGuard('hint')}</p>
            <StreamGuardRulesFields form={form} disabled={locked} />
          </section>
        </div>
        {canManage && writeError?.status !== 403 ? <div className="stream-detail-footer"><Button type="primary" loading={mutation.isPending} disabled={locked} onClick={() => void submit()}>{t('actions.save')}</Button><span>{t('detail.saveHint')}</span></div> : null}
      </Form> : null}
      <StreamPublicationModal item={publicationOpen ? item ?? null : null} onClose={() => setPublicationOpen(false)} />
    </div>
  </section>
}
