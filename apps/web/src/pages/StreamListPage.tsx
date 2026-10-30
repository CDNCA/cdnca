import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Collapse,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Pagination,
  Radio,
  Result,
  Select,
  Switch,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { AdvancedFilters, applyFormSubmitError, useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown, IdOrNameInput, useLiveApply, type AdvancedFilterItem } from '@cdnca/ui'
import { streamSearch, userSearch } from './idNameSources'
import { ChevronDown, ChevronLeft, ChevronRight, Ellipsis, Plus, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError, type ScopeKind } from '../api/auth'
import { formatDateTime } from '../i18n/formatters'
import {
  streamsApi,
  type BatchStreamActionInput,
  type BatchStreamActionValue,
  type CreateStreamRequest,
  type StreamAdditionalListener,
  type Stream,
  type StreamAdminStatus,
  type StreamFields,
  type StreamListParams,
  type UpdateStreamRequest,
} from '../api/streams'
import { useSessionStore } from '../auth/session'
import { ResourceID } from '../components/ResourceID'
import StreamGroupsPanel from './StreamGroupsPanel'
import StreamDefaultsPanel from './StreamDefaultsPanel'
import StreamGroupSelect from './StreamGroupSelect'
import StreamFilterSelect from './StreamFilterSelect'
import StreamOwnerSelect from './StreamOwnerSelect'
import StreamBatchModifyModal, { type StreamBatchACLPatch } from './StreamBatchModifyModal'
import StreamBatchCreatePanel from './StreamBatchCreatePanel'
import { draftFallback, useApplyDraftDefaults, useStreamDraftDefaults, type DraftDefaultField } from './streamDraftDefaults'
import { streamOriginShares } from './originWeightShare'
import '../i18n/originWeight'
import StreamLineFilterSelect from './StreamLineFilterSelect'
import StreamOverrideModal, { type StreamOverrideAction } from './StreamOverrideModal'
import StreamPublicationModal from './StreamPublicationModal'
import { dropWriteRecovery, useWriteRecovery } from './streamWriteRecovery'
import { StreamClientAddressField, StreamDNSFields, StreamFollowPortField, StreamGeoFields, StreamNewConnectionRateFields, StreamSessionLogField, StreamTLSPassthroughFields } from './StreamPolicyFields'
import {
  currentPrincipalCanManageStreams, currentPrincipalCanReadStreams,
  defaultDomainDNSPolicy, emptyGeoPolicy, errorMessage,
  hasStreamManagePermission, hasStreamReadPermission, originRows, parseListenPorts, parseOrigin, portLabel, portRangeProblem,
  staleStreamRead, streamErrorFormField, streamFields, streamFormFields, uuidPattern,
  writeKey, writeOutcomeUnknown, type StreamFormValues,
} from './streamForm'
import './StreamListPage.css'
import '../i18n/siteCnameRegeneration'
import { cnameFailureText } from './site-edit/cnameFailureText'
import CnameFailureActions from './site-edit/CnameFailureActions'

type StreamWriteAttempt =
  | { kind: 'create'; input: CreateStreamRequest; key: string }
  | { kind: 'update'; id: string; input: UpdateStreamRequest; key: string }
  | { kind: 'delete'; item: Stream; key: string }
  | {
      kind: 'batch'
      action: 'enable' | 'disable' | 'delete' | 'modify'
      items: Array<{ item: Stream; key: string }>
      acl?: StreamBatchACLPatch
      // modify：只覆盖勾选的字段，其余沿用每条转发当前值。
      patch?: Partial<UpdateStreamRequest>
    }
  // 更多操作（平台）：一次请求、一个幂等键，结果未知时只能按原请求确认。
  | { kind: 'action'; input: BatchStreamActionInput; key: string; targets: Stream[] }

type StreamListFilters = Omit<StreamListParams, 'page' | 'limit' | 'search'>
type StreamFilterDraft = Omit<StreamListFilters, 'listen_port'> & { listen_port?: string }

function dateTime(value: string, language: string): string {
  return formatDateTime(value, language) || value
}

function publicationTarget(item: Stream) {
  const runtime = item.publish_intent.runtime_spec
  return { streamID: runtime.stream_id, revision: runtime.revision }
}

// 「添加转发」是居中弹窗：标签 单个/批量；单个只露出 用户选择（平台）、用户套餐、监听端口、源地址:端口，
// 虚线「展开更多」（默认收起）后是 所属分组、备注。其余字段按批量修改的分组（基本设置 / 源站设置 /
// 访问控制）放进展开区的折叠面板，另加 监听设置 与 连接限制 两组，默认全部收起。
function StreamFormModal({
  isAdmin,
  open,
  pending,
  scopeKind,
  scopeID,
  sessionEpoch,
  batchPanel,
  writeError,
  onCancel,
  onSubmit,
}: {
  isAdmin: boolean
  open: boolean
  pending: boolean
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  batchPanel: ReactNode
  /** L4-007：确定失败（4xx）显示在弹窗内并定位字段；结果未知时为 null（列表上冻结写并按原请求重试）。 */
  writeError: ApiError | null
  onCancel: () => void
  onSubmit: (values: StreamFormValues) => void
}) {
  const { t } = useTranslation('streams')
  const [form] = Form.useForm<StreamFormValues>()
  const [mode, setMode] = useState<'single' | 'batch'>('single')
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [panels, setPanels] = useState<string[]>([])
  // L4-005：用户只填「源地址:端口」（origin_text），upstream_mode 到提交才解析；DNS 区按输入的解析结果显隐。
  const originText = Form.useWatch('origin_text', form)
  const followPort = Form.useWatch('upstream_follow_port', form)
  const parsedOrigin = parseOrigin(originText, Boolean(followPort))
  const domainOrigin = 'mode' in parsedOrigin && parsedOrigin.mode === 'host'
  const geoEnabled = Form.useWatch(['geo_policy', 'enabled'], form)
  const targetScopeID = Form.useWatch('target_scope_id', form)
  const ownerID = Form.useWatch('owner_id', form)
  const groupIDs = Form.useWatch('group_ids', form)
  // L4-DEFAULT-01：按归属与所选分组读取「默认设置」预填；用户改过的字段不再被默认覆盖。
  const touched = useRef(new Set<DraftDefaultField>())
  const { defaults, ready: defaultsReady } = useStreamDraftDefaults({ open, isAdmin, scopeKind, scopeID, sessionEpoch, targetScopeID, ownerID, groupIDs })
  const listenText = Form.useWatch('listen_ports_text', form)
  const parsedPorts = parseListenPorts(listenText, defaults.protocol)
  const hasUDP = 'entries' in parsedPorts && parsedPorts.entries.some((entry) => entry.protocol === 'udp')
  const createScopeID = isAdmin ? targetScopeID?.trim().toLowerCase() ?? '' : scopeID
  const permissions = useSessionStore((state) => state.principal?.permissions)
  const canPickOwner = isAdmin && Boolean(permissions?.some((entry) => entry === 'identity.users.manage' || entry === 'platform.admin'))

  useEffect(() => {
    if (!open) return
    setMode('single')
    setAdvancedOpen(false)
    setPanels([])
    touched.current = new Set()
    form.resetFields()
    form.setFieldsValue({
      protocol: draftFallback.protocol,
      listen_address: '*',
      listen_ports_text: '',
      origin_text: '',
      remark: '',
      group_ids: [],
      upstream_mode: 'address',
      upstream_address: '',
      upstream_host: '',
      dns_policy: defaultDomainDNSPolicy(),
      geo_policy: emptyGeoPolicy(),
      geo_trusted_proxy_cidrs: '',
      geo_blocked_regions: '',
      geo_region_cidrs: '',
      connect_timeout_ms: 3000,
      response_timeout_ms: 30000,
      max_connections_per_client: 100,
      max_new_connections_per_client_per_second: 0,
      new_connection_burst: 0,
      new_connection_ban_seconds: 0,
      session_log_enabled: false,
      upstream_follow_port: false,
      proxy_protocol_inbound: draftFallback.proxy_protocol_inbound,
      proxy_protocol_v1: false,
      toa: false,
      balance_way: draftFallback.balance_way,
      enabled: true,
      tls_passthrough: false,
      server_names: [],
    })
  }, [form, open])

  useApplyDraftDefaults(defaults, defaultsReady, (values) => {
    // 协议由端口文本推导（未写 /tcp|/udp 的取默认协议），这里只写负载方式与接收 PROXY。
    const rest = { ...values }
    delete rest.protocol
    if (hasUDP) delete rest.proxy_protocol_inbound
    form.setFieldsValue(rest)
  }, () => touched.current, open)

  // 单行端口与源地址展开到原有字段：协议跟随第一个端口，其余端口成为附加监听；上游类型由源地址判定。
  useEffect(() => {
    if (!('entries' in parsedPorts)) return
    const [first, ...rest] = parsedPorts.entries
    const previous = (form.getFieldValue('additional_listeners') ?? []) as StreamAdditionalListener[]
    form.setFieldsValue({
      protocol: first!.protocol,
      listen_port: first!.port,
      listen_port_end: first!.port_end,
      additional_listeners: rest.length === 0 ? undefined : rest.map((entry, index) => ({
        id: previous[index]?.id ?? globalThis.crypto.randomUUID(),
        protocol: entry.protocol, address: '*' as const, port: entry.port, ...(entry.port_end ? { port_end: entry.port_end } : {}),
      })),
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form, listenText, defaults.protocol])

  useEffect(() => {
    if (hasUDP) {
      form.setFieldValue('proxy_protocol_inbound', false)
      form.setFieldValue('proxy_protocol_v1', false)
      form.setFieldValue('toa', false)
      form.setFieldValue('geo_trusted_proxy_cidrs', '')
    }
  }, [form, hasUDP])

  // A refused field is marked on its Form.Item and scrolled
  // into view (shared applyFormSubmitError). The in-dialog Alert stays (L4-007:
  // it carries the request ID).
  useEffect(() => {
    if (!writeError) return
    applyFormSubmitError(form, writeError, {
      map: streamErrorFormField as Record<string, string>, message: () => errorMessage(writeError, t),
    })
  }, [form, t, writeError])

  const applyOrigin = (values: StreamFormValues): StreamFormValues | null => {
    const origin = parseOrigin(values.origin_text, Boolean(values.upstream_follow_port))
    if ('problem' in origin) return null
    return {
      ...values,
      upstream_mode: origin.mode,
      upstream_address: origin.mode === 'address' ? origin.host : '',
      upstream_host: origin.mode === 'host' ? origin.host : '',
      upstream_port: origin.port ?? values.listen_port,
    }
  }
  const submit = () => void form.validateFields().then((values) => {
    const next = applyOrigin({ ...form.getFieldsValue(true) as StreamFormValues, ...values })
    if (next) onSubmit(next)
  }, () => { setAdvancedOpen(true); setPanels(['basic', 'listen', 'origin', 'access', 'connection']) })

  const panel = (key: string, label: string, children: ReactNode) => ({ key, label, children, forceRender: true })
  return (
    <Modal
      className="identity-modal stream-modal"
      title={t('form.addTitle')}
      open={open}
      width={560}
      centered={false}
      maskClosable={false}
      onCancel={onCancel}
      footer={mode === 'batch' ? null : <>
        <Button type="primary" loading={pending} disabled={pending} onClick={submit}>{t('form.confirm')}</Button>
        <Button onClick={onCancel} disabled={pending}>{t('actions.cancel')}</Button>
      </>}
      destroyOnHidden
    >
      <div className="stream-create-tabs" role="tablist" aria-label={t('form.createMode')}>
        <button type="button" role="tab" aria-selected={mode === 'single'} className={mode === 'single' ? 'is-active' : undefined} onClick={() => setMode('single')}>{t('form.singleMode')}</button>
        <button type="button" role="tab" aria-selected={mode === 'batch'} className={mode === 'batch' ? 'is-active' : undefined} onClick={() => setMode('batch')}>{t('form.batchMode')}</button>
      </div>
      {writeError && mode === 'single' ? <Alert className="identity-alert" type="error" showIcon role="alert" message={errorMessage(writeError, t)}
        description={writeError.requestId ? t('errors.requestId', { id: writeError.requestId }) : undefined} /> : null}
      {mode === 'batch' ? batchPanel : (
      <Form form={form} layout="horizontal" labelCol={{ flex: '110px' }} wrapperCol={{ flex: 1 }} labelWrap requiredMark={false}
        onValuesChange={(changed) => {
          if ('balance_way' in changed) touched.current.add('balance_way')
          if ('proxy_protocol_inbound' in changed) touched.current.add('proxy_protocol_inbound')
          if ('target_scope_id' in changed) form.setFieldsValue({ group_ids: [] })
        }}>
        {isAdmin && canPickOwner ? <>
          <Form.Item name="target_scope_id" hidden><Input /></Form.Item>
          <Form.Item name="owner_id" label={t('form.ownerSelect')} rules={[{ required: true, message: t('form.ownerSelectRequired') }]}>
            <StreamOwnerSelect scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch}
              onPick={(user) => form.setFieldsValue({ owner_id: user?.id, target_scope_id: user?.scope_id ?? '', group_ids: [] })} />
          </Form.Item>
        </> : isAdmin ? <>
          <Form.Item name="target_scope_id" label={t('form.targetScopeId')} rules={[
            { required: true, message: t('form.targetScopeRequired') },
            { pattern: uuidPattern, message: t('form.targetScopeInvalid') },
          ]}>
            <Input placeholder={t('form.uuidPlaceholder')} />
          </Form.Item>
          <Form.Item name="owner_id" label={t('form.ownerId')} rules={[
            { required: true, message: t('form.ownerRequired') },
            { pattern: uuidPattern, message: t('form.ownerInvalid') },
          ]}>
            <Input placeholder={t('form.uuidPlaceholder')} />
          </Form.Item>
        </> : null}
        <Form.Item name="listen_ports_text" label={t('form.listenPorts')} dependencies={['tls_passthrough']} rules={[{
          validator: (_, value: string) => {
            const parsed = parseListenPorts(value)
            if ('problem' in parsed) return Promise.reject(new Error(t(`form.${parsed.problem}`)))
            // 端口范围沿用原「结束端口」的校验（最多 1000 个、不覆盖节点自身端口、不能与 TLS 透传同用）。
            const tls = Boolean(form.getFieldValue('tls_passthrough'))
            const problem = parsed.entries.map((entry) => portRangeProblem(entry.port, entry.port_end, tls)).find(Boolean)
            return problem ? Promise.reject(new Error(t(`form.${problem}`))) : Promise.resolve()
          },
        }]}>
          <Input placeholder={t('form.listenPortsPlaceholder')} />
        </Form.Item>
        <Form.Item name="origin_text" label={t('form.origin')} dependencies={['upstream_follow_port']} rules={[{
          validator: (_, value: string) => {
            const parsed = parseOrigin(value, Boolean(form.getFieldValue('upstream_follow_port')))
            return 'problem' in parsed ? Promise.reject(new Error(t(`form.${parsed.problem}`))) : Promise.resolve()
          },
        }]}>
          <Input placeholder={t('form.originPlaceholder')} />
        </Form.Item>
        {/* 展开后的字段由单行输入推导或在折叠组里，未展开时仍保留在 store 中。 */}
        <Form.Item name="protocol" hidden><Input /></Form.Item>
        <Form.Item name="listen_port" hidden><Input /></Form.Item>
        <Form.Item name="listen_port_end" hidden><Input /></Form.Item>
        <Form.Item name="upstream_mode" hidden><Input /></Form.Item>
        <div className="stream-advanced-divider">
          <button className="stream-advanced-toggle" type="button" aria-expanded={advancedOpen} onClick={() => setAdvancedOpen((value) => !value)}>
            {t('form.expandMore')} <ChevronDown size={14} aria-hidden="true" className={advancedOpen ? 'is-open' : undefined} />
          </button>
        </div>
        <div hidden={!advancedOpen}>
          <Form.Item name="group_ids" label={t('form.group')}>
            <StreamGroupSelect open={open} scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch}
              targetScopeID={createScopeID} groups={[]} />
          </Form.Item>
          <Form.Item name="remark" label={t('form.remark')} rules={[{ max: 256, message: t('form.remarkTooLong') }]}>
            <Input placeholder={t('form.remarkPlaceholder')} />
          </Form.Item>
          <Collapse className="stream-form-collapse" activeKey={panels} onChange={(keys) => setPanels(keys as string[])} items={[
            panel('basic', t('form.groupBasic'), <>
              <Form.Item name="name" label={t('form.name')} rules={[{ max: 128, message: t('form.nameTooLong') }]}>
                <Input placeholder={t('form.namePlaceholder')} />
              </Form.Item>
              <Form.Item name="enabled" label={t('form.enabled')} valuePropName="checked"><Switch /></Form.Item>
              <StreamSessionLogField />
            </>),
            panel('listen', t('form.groupListen'), <>
              <Form.Item name="listen_address" label={t('form.listenAddress')} rules={[{ required: true, message: t('form.listenAddressRequired') }]}>
                <Select options={[{ value: '*', label: t('form.allAddresses') }]} />
              </Form.Item>
              <StreamTLSPassthroughFields form={form} />
            </>),
            panel('origin', t('form.groupOrigin'), <>
              <Form.Item name="balance_way" label={t('form.balanceWay')}>
                <Radio.Group optionType="button" buttonStyle="solid" options={[
                  { value: 'rr', label: t('detail.roundRobin') }, { value: 'ip_hash', label: t('detail.ipHash') },
                ]} />
              </Form.Item>
              <StreamFollowPortField />
              <StreamClientAddressField form={form} />
              {domainOrigin ? <StreamDNSFields form={form} /> : null}
            </>),
            panel('access', t('form.groupAccess'), <>
              <Form.Item name={['geo_policy', 'enabled']} label={t('form.geoEnabled')} valuePropName="checked"><Switch /></Form.Item>
              <Form.Item name="proxy_protocol_inbound" label={t('form.proxyInbound')} valuePropName="checked">
                <Switch disabled={hasUDP || !geoEnabled} />
              </Form.Item>
              {geoEnabled ? <StreamGeoFields form={form} /> : null}
            </>),
            panel('connection', t('form.groupConnection'), <>
              <Form.Item name="connect_timeout_ms" label={t('form.connectTimeout')} rules={[
                { required: true, message: t('form.connectTimeoutRequired') },
                { type: 'number', min: 50, max: 30000, message: t('form.connectTimeoutRange') },
              ]}>
                <InputNumber min={50} max={30000} precision={0} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="response_timeout_ms" label={t('form.responseTimeout')} rules={[
                { required: true, message: t('form.responseTimeoutRequired') },
                { type: 'number', min: 100, max: 600000, message: t('form.responseTimeoutRange') },
              ]}>
                <InputNumber min={100} max={600000} precision={0} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="max_connections_per_client" label={t('form.maxConnectionsPerClient')} rules={[
                { required: true, message: t('form.maxConnectionsRequired') },
                { type: 'number', min: 1, max: 10000, message: t('form.maxConnectionsRange') },
              ]}>
                <InputNumber min={1} max={10000} precision={0} style={{ width: '100%' }} />
              </Form.Item>
              <StreamNewConnectionRateFields />
            </>),
          ]} />
        </div>
      </Form>
      )}
    </Modal>
  )
}

export default function StreamListPage() {
  const { t } = useTranslation('streams')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  if (!hasStreamReadPermission(principal.scope_kind, principal.permissions)) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  return (
    <StreamListContent
      key={`${principal.scope_kind}:${principal.scope_id}:${sessionEpoch}`}
      accessToken={accessToken}
      scopeKind={principal.scope_kind}
      scopeID={principal.scope_id}
      sessionEpoch={sessionEpoch}
      permissions={principal.permissions}
    />
  )
}

function StreamListContent({
  accessToken,
  scopeKind,
  scopeID,
  sessionEpoch,
  permissions,
}: {
  accessToken: string
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  permissions: string[]
}) {
  const { t, i18n } = useTranslation('streams')
  const { t: tW } = useTranslation('originWeight')
  const streamShareText = (share: number | null) => share === null ? tW('down') : tW('share', { share })
  const { t: tCname, i18n: i18nInstance } = useTranslation('siteCnameRegeneration')
  const protocolOptions = [
    { value: 'tcp', label: t('values.tcp') },
    { value: 'udp', label: t('values.udp') },
  ]
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const isAdmin = scopeKind === 'platform'
  const canManageStreams = hasStreamManagePermission(permissions)
  const canManagePublications = scopeKind === 'platform' &&
    (permissions.includes('edge_publications.manage') || permissions.includes('platform.admin'))
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [modalApi, modalContext] = Modal.useModal()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [quickField, setQuickField] = useState<keyof StreamFilterDraft>('listen_port')
  const [quickDraft, setQuickDraft] = useState<StreamFilterDraft>({})
  const [quickFilters, setQuickFilters] = useState<StreamListFilters>({})
  const [filterDraft, setFilterDraft] = useState<StreamFilterDraft>({})
  const [filters, setFilters] = useState<StreamListFilters>({})
  const [filterError, setFilterError] = useState('')
  // 行内快捷查询与高级筛选由同一个「查询/应用」一起生效；校验不过或同一字段取值冲突时都不生效。
  const normalizeFilters = (draft: StreamFilterDraft): StreamListFilters | string => {
    const port = draft.listen_port?.trim() ?? ''
    const displayID = draft.display_id?.trim() ?? ''
    const ownerDisplayID = draft.owner_display_id?.trim() ?? ''
    const upstream = draft.upstream?.trim() ?? ''
    if (port && (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535)) return 'filters.invalidPort'
    if (displayID && (!/^[1-9][0-9]{0,18}$/.test(displayID) || BigInt(displayID) > 9223372036854775807n)) return 'filters.invalidDisplayID'
    if (ownerDisplayID && (!/^[1-9][0-9]{0,18}$/.test(ownerDisplayID) || BigInt(ownerDisplayID) > 9223372036854775807n)) return 'filters.invalidOwnerDisplayID'
    if (upstream && ([...upstream].length > 253 || /\p{Cc}/u.test(upstream))) return 'filters.invalidUpstream'
    return Object.fromEntries(Object.entries({
      ...draft, listen_port: port ? Number(port) : undefined, upstream: upstream || undefined,
      display_id: displayID || undefined, owner_display_id: ownerDisplayID || undefined,
      cname_domain: draft.cname_domain?.trim() || undefined, cname_hostname: draft.cname_hostname?.trim() || undefined,
    }).filter(([, value]) => value !== undefined && value !== '')) as StreamListFilters
  }
  const applyFilters = (advancedDraft: StreamFilterDraft = filterDraft) => {
    setFilterDraft(advancedDraft)
    const quick = normalizeFilters(quickDraft)
    const advanced = normalizeFilters(advancedDraft)
    if (typeof quick === 'string') { setFilterError(quick); return }
    if (typeof advanced === 'string') { setFilterError(advanced); return }
    if (Object.entries(quick).some(([field, value]) => {
      const previous = advanced[field as keyof StreamListFilters]
      return previous !== undefined && (field === 'upstream'
        ? String(previous).toLowerCase() !== String(value).toLowerCase()
        : previous !== value)
    })) { setFilterError('filters.quickConflict'); return }
    setFilterError('')
    setQuickFilters(quick)
    setFilters(advanced)
    setPage(1)
  }
  // 快捷查询与高级条件边输入边生效（400ms 防抖，下拉即查）；
  // 校验不过/同字段冲突时就地报错不发请求（applyFilters 内）。比较的是草稿本身，已报错的同一草稿不反复校验。
  const draftKey = JSON.stringify([quickDraft, filterDraft])
  const [appliedDraftKey, setAppliedDraftKey] = useState(draftKey)
  useLiveApply(draftKey, appliedDraftKey, () => { setAppliedDraftKey(draftKey); applyFilters() })
  const resetFilters = () => { setAppliedDraftKey(JSON.stringify([{}, {}])); setQuickField('listen_port'); setQuickDraft({}); setQuickFilters({}); setFilterDraft({}); setFilters({}); setFilterError(''); setPage(1) }
  const effectiveFilters = { ...filters, ...quickFilters }
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [publicationDetail, setPublicationDetail] = useState<Stream | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  // L4-007：结果未知的写入放在会话级缓存里，离开列表再回来仍只能按原请求重试。
  const recovery = useWriteRecovery<StreamWriteAttempt>({ scopeKind, scopeID, sessionEpoch }, 'list')
  const retryAttempt = recovery.attempt
  const setRetryAttempt = (attempt: StreamWriteAttempt | null) => { if (attempt) recovery.settle(attempt, true); else recovery.clear() }
  const [batchBusy, setBatchBusy] = useState(false)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [batchModifyOpen, setBatchModifyOpen] = useState(false)
  const [section, setSection] = useState<'list' | 'groups' | 'defaults'>('list')
  const rowActionConfirmRef = useRef<{
    action: 'enable' | 'disable' | 'delete'
    instance: ReturnType<typeof modalApi.confirm>
  } | null>(null)
  const streamSubnavRef = useRef<HTMLDivElement>(null)
  const serverForbiddenRef = useRef(false)
  const listFetchingRef = useRef(false)
  const language = i18n.resolvedLanguage ?? i18n.language
  const statusOptions = [
    { value: 'enabled', label: t('states.enabled') },
    { value: 'disabled', label: t('states.disabled') },
  ]
  const publicationOptions = (['unknown', 'pending', 'leased', 'retrying', 'reconciling', 'succeeded', 'failed', 'superseded'] as const)
    .map((value) => ({ value, label: t(`publication.states.${value}`) }))
  const syncOptions = (['done', 'pending', 'failed'] as const).map((value) => ({ value, label: t(`syncState.${value}`) }))
  const adminStatusOptions = (['normal', 'locked', 'traffic_exceeded', 'package_expired'] as const).map((value) => ({ value, label: t(`adminStatus.${value}`) }))
	const quickFields = [
		// admin 顺序：监听端口、监听协议、源IP、转发ID、用户ID、基础套餐、区域、线路分组、CNAME域名、CNAME主机名、启用、同步状态、状态。
		['listen_port', 'listenPortLabel'], ['protocol', 'protocol'], ['upstream', 'sourceIP'], ['display_id', 'displayID'],
		['owner_display_id', 'ownerDisplayID'],
		...(isAdmin ? [['region_id', 'region'], ['node_group_id', 'lineGroup']] : []),
		['cname_domain', 'cnameDomain'], ['cname_hostname', 'cnameHostname'], ['enabled', 'enabled'],
		['sync_state', 'syncState'], ['admin_status', 'adminStatus'], ['publication_state', 'publicationState'],
	].map(([value, label]) => ({ value, label: t(`filters.${label}`) }))
  // 转发列表其余条件进共享 AdvancedFilters；标签显示已生效的值（下拉项显示其名称，分组/区域/线路分组显示 ID）。
  const optionLabel = (options: Array<{ value: string; label: string }>, value?: string) => value ? options.find((option) => option.value === value)?.label ?? value : undefined
  const enabledDraft = (draft: { enabled?: boolean }) => draft.enabled === undefined ? undefined : draft.enabled ? 'enabled' : 'disabled'
  // 转发ID 可按转发名称/端口、用户ID 可按用户名联想，选中后按展示 ID 过滤。
  const idSearchToken = useSessionStore((state) => state.accessToken) ?? ''
  const idSearches = useMemo(() => ({ display_id: streamSearch(idSearchToken), owner_display_id: userSearch(idSearchToken, 'display_id') }), [idSearchToken])
  const idField = (key: string, value: string, onChange: (next: string) => void, placeholder: string, ariaLabel: string, onPressEnter?: () => void) =>
    key === 'display_id' || key === 'owner_display_id'
      ? <IdOrNameInput key={key} aria-label={ariaLabel} value={value} placeholder={placeholder} isId={(text) => /^\d+$/.test(text)}
        search={idSearches[key]} onChange={onChange} onPressEnter={onPressEnter} />
      : null
  const textItem = (key: 'listen_port' | 'upstream' | 'display_id' | 'owner_display_id' | 'cname_domain' | 'cname_hostname', label: string, placeholder: string, ariaLabel = label): AdvancedFilterItem => ({
    key, label, applied: filters[key] === undefined ? undefined : String(filters[key]),
    field: idField(key, filterDraft[key] ?? '', (next) => setFilterDraft({ ...filterDraft, [key]: next }), placeholder, ariaLabel)
      ?? <Input aria-label={ariaLabel} value={filterDraft[key] ?? ''} placeholder={placeholder} onChange={(event) => setFilterDraft({ ...filterDraft, [key]: event.target.value })} />,
  })
  const advancedItems: AdvancedFilterItem[] = [
    textItem('listen_port', t('filters.listenPortLabel'), t('filters.listenPortAdvancedPlaceholder')),
    { key: 'protocol', label: t('filters.protocol'), applied: optionLabel(protocolOptions, filters.protocol),
      field: <Select aria-label={t('filters.protocolLabel')} allowClear placeholder={t('filters.unlimited')} value={filterDraft.protocol} options={protocolOptions} onChange={(value) => setFilterDraft({ ...filterDraft, protocol: value })} /> },
    textItem('upstream', t('filters.sourceIP'), t('filters.sourceIPPlaceholder')),
    textItem('display_id', t('filters.displayID'), t('filters.displayIDPlaceholder')),
    textItem('owner_display_id', t('filters.ownerDisplayID'), t('filters.ownerDisplayIDPlaceholder')),
    { key: 'group_id', label: t('filters.group'), applied: filters.group_id,
      field: <StreamFilterSelect kind="group" scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch} value={filterDraft.group_id} onChange={(value) => setFilterDraft({ ...filterDraft, group_id: value })} /> },
    textItem('cname_domain', t('filters.cnameDomain'), t('filters.cnameDomainPlaceholder')),
    textItem('cname_hostname', t('filters.cnameHostname'), t('filters.cnameHostnamePlaceholder')),
    { key: 'enabled', label: t('filters.enabled'), applied: optionLabel(statusOptions, enabledDraft(filters)),
      field: <Select aria-label={t('filters.statusLabel')} allowClear placeholder={t('filters.unlimited')} value={enabledDraft(filterDraft)} options={statusOptions} onChange={(value) => setFilterDraft({ ...filterDraft, enabled: value === undefined ? undefined : value === 'enabled' })} /> },
    ...(isAdmin ? [
      { key: 'region_id', label: t('filters.region'), applied: filters.region_id,
        field: <StreamLineFilterSelect kind="region" enabled={advancedOpen} value={filterDraft.region_id} onChange={(value) => setFilterDraft({ ...filterDraft, region_id: value })} /> },
      { key: 'node_group_id', label: t('filters.lineGroup'), applied: filters.node_group_id,
        field: <StreamLineFilterSelect kind="line_group" enabled={advancedOpen} value={filterDraft.node_group_id} onChange={(value) => setFilterDraft({ ...filterDraft, node_group_id: value })} /> },
    ] : []),
    { key: 'sync_state', label: t('filters.syncState'), applied: optionLabel(syncOptions, filters.sync_state),
      field: <Select aria-label={t('filters.syncState')} allowClear placeholder={t('filters.unlimited')} value={filterDraft.sync_state} options={syncOptions} onChange={(value) => setFilterDraft({ ...filterDraft, sync_state: value })} /> },
    { key: 'admin_status', label: t('filters.adminStatus'), applied: optionLabel(adminStatusOptions, filters.admin_status),
      field: <Select aria-label={t('filters.adminStatus')} allowClear placeholder={t('filters.unlimited')} value={filterDraft.admin_status} options={adminStatusOptions} onChange={(value) => setFilterDraft({ ...filterDraft, admin_status: value })} /> },
    { key: 'publication_state', label: t('filters.publicationState'), applied: optionLabel(publicationOptions, filters.publication_state),
      field: <Select aria-label={t('filters.publicationState')} allowClear placeholder={t('filters.unlimited')} value={filterDraft.publication_state} options={publicationOptions} onChange={(value) => setFilterDraft({ ...filterDraft, publication_state: value })} /> },
  ]
  const quickSearchInput = () => {
    const common = { 'aria-label': t('filters.searchLabel'), allowClear: true, placeholder: t('filters.unlimited') }
    if (quickField === 'protocol') return <Select {...common} value={quickDraft.protocol} options={protocolOptions} onChange={(value) => setQuickDraft({ protocol: value })} />
    if (quickField === 'enabled') return <Select {...common} value={quickDraft.enabled === undefined ? undefined : quickDraft.enabled ? 'enabled' : 'disabled'} options={statusOptions} onChange={(value) => setQuickDraft({ enabled: value === undefined ? undefined : value === 'enabled' })} />
    if (quickField === 'publication_state') return <Select {...common} value={quickDraft.publication_state} options={publicationOptions} onChange={(value) => setQuickDraft({ publication_state: value })} />
    if (quickField === 'sync_state') return <Select {...common} value={quickDraft.sync_state} options={syncOptions} onChange={(value) => setQuickDraft({ sync_state: value })} />
    if (quickField === 'admin_status') return <Select {...common} value={quickDraft.admin_status} options={adminStatusOptions} onChange={(value) => setQuickDraft({ admin_status: value })} />
    if (quickField === 'region_id') return <StreamLineFilterSelect kind="region" value={quickDraft.region_id} onChange={(value) => setQuickDraft({ region_id: value })} />
    if (quickField === 'node_group_id') return <StreamLineFilterSelect kind="line_group" value={quickDraft.node_group_id} onChange={(value) => setQuickDraft({ node_group_id: value })} />
	const field = quickField as 'listen_port' | 'upstream' | 'display_id' | 'owner_display_id' | 'cname_domain' | 'cname_hostname'
	const placeholder = {
		listen_port: 'listenPortPlaceholder', upstream: 'sourceIPPlaceholder', display_id: 'displayIDPlaceholder',
		owner_display_id: 'ownerDisplayIDPlaceholder', cname_domain: 'cnameDomainPlaceholder', cname_hostname: 'cnameHostnamePlaceholder',
	}[field]
    return idField(field, quickDraft[field] ?? '', (next) => setQuickDraft({ [field]: next }), t(`filters.${placeholder}`), t('filters.searchLabel'), () => applyFilters())
      ?? <Input aria-label={t('filters.searchLabel')} allowClear value={quickDraft[field] ?? ''} placeholder={t(`filters.${placeholder}`)} onChange={(event) => setQuickDraft({ [field]: event.target.value })} onPressEnter={() => applyFilters()} />
  }

  useEffect(() => {
    if (canManageStreams) return
    setModalOpen(false)
    setBatchModifyOpen(false)
    setSelectedRowKeys([])
  }, [canManageStreams])

  const cnamePendingSinceRef = useRef<number | null>(null)
  const query = useQuery({
    queryKey: ['streams', scopeKind, scopeID, sessionEpoch, page, limit, effectiveFilters],
    queryFn: async () => {
      if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
      try {
        const result = await streamsApi.list(accessTokenRef.current, { page, limit, ...effectiveFilters })
        if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
        return result
      } catch (error) {
        if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
        throw error
      }
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    // Like the site list: while a stream's own CNAME is 生成中, poll every 2 s
    // for at most 60 s.
    refetchInterval: (current) => {
      const pending = current.state.data?.items.some((item) => item.cname_state === 'pending') ?? false
      if (!pending) {
        cnamePendingSinceRef.current = null
        return false
      }
      cnamePendingSinceRef.current ??= Date.now()
      return Date.now() - cnamePendingSinceRef.current < streamCnamePendingPollWindowMs ? streamCnamePendingPollIntervalMs : false
    },
  })

  useEffect(() => () => {
    if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) {
      queryClient.removeQueries({ queryKey: ['streams', scopeKind, scopeID, sessionEpoch] })
      dropWriteRecovery(queryClient, { scopeKind, scopeID, sessionEpoch })
    }
  }, [queryClient, scopeID, scopeKind, sessionEpoch])
  const error = query.error instanceof ApiError ? query.error : null
  const forbidden = error?.status === 403
  serverForbiddenRef.current = forbidden
  listFetchingRef.current = query.isFetching
  const canWrite = () => !serverForbiddenRef.current && !listFetchingRef.current &&
    currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)

  const finishWrite = async (notice: string) => {
    if (serverForbiddenRef.current) return
    setRetryAttempt(null)
    setWriteError(null)
    setModalOpen(false)
    setBatchModifyOpen(false)
    setSelectedRowKeys([])
    await queryClient.invalidateQueries({ queryKey: ['streams', scopeKind, scopeID, sessionEpoch] })
    messageApi.success(notice)
  }

  const failWrite = (error: unknown, failed: StreamWriteAttempt) => {
    if (serverForbiddenRef.current) return
    const unknown = writeOutcomeUnknown(error)
    setRetryAttempt(unknown ? failed : null)
    setWriteError(error instanceof ApiError ? error : new ApiError(t('errors.operationFailed')))
    if (unknown) setModalOpen(false)
  }

  const createMutation = useMutation({
    mutationFn: (attempt: Extract<StreamWriteAttempt, { kind: 'create' }>) => {
      if (!canWrite()) {
        throw new ApiError('permission denied', 403, 'permission_denied')
      }
      return streamsApi.create(accessTokenRef.current, attempt.input, attempt.key)
    },
    onSuccess: () => void finishWrite(t('notices.created')),
    onError: failWrite,
  })
  const updateMutation = useMutation({
    mutationFn: (attempt: Extract<StreamWriteAttempt, { kind: 'update' }>) => {
      if (!canWrite()) {
        throw new ApiError('permission denied', 403, 'permission_denied')
      }
      return streamsApi.update(accessTokenRef.current, attempt.id, attempt.input, attempt.key)
    },
    onSuccess: () => void finishWrite(t('notices.updated')),
    onError: failWrite,
  })
  const deleteMutation = useMutation({
    mutationFn: (attempt: Extract<StreamWriteAttempt, { kind: 'delete' }>) => {
      if (!canWrite()) {
        throw new ApiError('permission denied', 403, 'permission_denied')
      }
      return streamsApi.remove(accessTokenRef.current, attempt.item, attempt.key)
    },
    onSuccess: () => void finishWrite(t('notices.deleted')),
    onError: failWrite,
  })

  const mutateCreate = (attempt: Extract<StreamWriteAttempt, { kind: 'create' }>) => {
    if (canWrite()) createMutation.mutate(attempt)
  }
  const mutateUpdate = (attempt: Extract<StreamWriteAttempt, { kind: 'update' }>) => {
    if (canWrite()) updateMutation.mutate(attempt)
  }
  const mutateDelete = (attempt: Extract<StreamWriteAttempt, { kind: 'delete' }>) => {
    if (canWrite()) deleteMutation.mutate(attempt)
  }

  const submit = (values: StreamFormValues) => {
    if (!canWrite() || retryAttempt) return
    setWriteError(null)
    const fields = streamFormFields(values)
    mutateCreate({
      kind: 'create',
      input: {
        ...fields,
        group_ids: values.group_ids ?? [],
        ...(isAdmin ? { target_scope_id: values.target_scope_id?.trim(), owner_id: values.owner_id?.trim() } : {}),
      },
      key: writeKey('create-stream'),
    })
  }

  const toggle = (item: Stream) => {
    if (!canWrite() || retryAttempt) return
    setWriteError(null)
    mutateUpdate({
      kind: 'update',
      id: item.id,
      input: {
        ...streamFields(item),
        enabled: !item.enabled,
        expected_revision: item.revision,
      },
      key: writeKey(`update-stream-${item.id}`),
    })
  }

  const runBatch = async (attempt: Extract<StreamWriteAttempt, { kind: 'batch' }>) => {
    if (!canWrite()) return
    setBatchBusy(true)
    setWriteError(null)
    for (let index = 0; index < attempt.items.length; index += 1) {
      if (!currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)) {
        setBatchBusy(false)
        return
      }
      const target = attempt.items[index]!
      try {
        if (attempt.action === 'delete') {
          await streamsApi.remove(accessTokenRef.current, target.item, target.key)
        } else {
          const current = streamFields(target.item)
          const next: StreamFields & { group_ids?: string[] } = attempt.action === 'modify'
            ? { ...current, ...attempt.patch }
            : { ...current, enabled: attempt.action === 'enable' }
          if (attempt.acl) {
            // 只勾了 ACL默认行为 或 ACL规则 时，另一项保留这条转发原值。
            next.acl = { default_action: attempt.acl.default_action ?? target.item.acl.default_action, rules: attempt.acl.rules ?? target.item.acl.rules }
          }
          const groupsChanged = next.group_ids !== undefined &&
            [...next.group_ids].sort().join() !== target.item.groups.map((group) => group.id).sort().join()
          if (JSON.stringify({ ...next, group_ids: undefined }) === JSON.stringify(current) && !groupsChanged) continue
          await streamsApi.update(accessTokenRef.current, target.item.id, {
            ...next,
            expected_revision: target.item.revision,
          }, target.key)
        }
      } catch (error) {
        if (!currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)) {
          setBatchBusy(false)
          return
        }
        failWrite(error, { ...attempt, items: attempt.items.slice(index) })
        await queryClient.invalidateQueries({ queryKey: ['streams', scopeKind, scopeID, sessionEpoch] })
        setBatchBusy(false)
        return
      }
    }
    setBatchBusy(false)
    await finishWrite(t(`notices.batch.${attempt.action}`, { count: attempt.items.length }))
  }

  const selectedStreams = (query.data?.items ?? []).filter((item) => selectedRowKeys.includes(item.id))

  const beginBatch = (action: 'enable' | 'disable' | 'delete' | 'modify', patch?: Partial<UpdateStreamRequest>, acl?: StreamBatchACLPatch) => {
    if (selectedStreams.length === 0 || !canWrite() || retryAttempt) return
    const attempt: Extract<StreamWriteAttempt, { kind: 'batch' }> = {
      kind: 'batch',
      action,
      items: selectedStreams.map((item) => ({ item, key: writeKey(`batch-${action}-${item.id}`) })),
      ...(patch ? { patch } : {}),
      ...(acl ? { acl } : {}),
    }
    modalApi.confirm({
      title: t(`confirm.batch.${action}Title`, { count: selectedStreams.length }),
      content: t('confirm.batch.description'),
      okText: action === 'delete' ? t('actions.confirmDelete') : t('actions.confirm'),
      cancelText: t('actions.cancel'),
      okButtonProps: { danger: action === 'delete' },
      onOk: () => runBatch(attempt),
    })
  }

  // 更多操作（平台）：设置状态 / 修改CNAME域名 / 修改CNAME生成模式 / 修改线路分组。
  // 一次请求，逐条带修订；有冲突的行单独列出。
  const [statusOpen, setStatusOpen] = useState(false)
  const [statusValue, setStatusValue] = useState<StreamAdminStatus>('normal')
  const [overrideAction, setOverrideAction] = useState<StreamOverrideAction | null>(null)
  const submitBatchAction = (value: BatchStreamActionValue, targets: Stream[] = selectedStreams) => {
    if (retryAttempt?.kind === 'action') { void runAction(retryAttempt); return }
    if (!canWrite() || targets.length === 0 || retryAttempt) return
    void runAction({ kind: 'action', targets, key: writeKey(`batch-${value.action}`),
      input: { ...value, items: targets.map((item) => ({ id: item.id, expected_revision: item.revision })) } })
  }
  const runAction = async (attempt: Extract<StreamWriteAttempt, { kind: 'action' }>) => {
    if (!canWrite() || batchBusy) return
    const { input: value, targets } = attempt
    setBatchBusy(true)
    setWriteError(null)
    try {
      const result = await streamsApi.batchAction(accessTokenRef.current, value, attempt.key)
      if (serverForbiddenRef.current) return
      setRetryAttempt(null)
      const failed = result.items.filter((item) => item.status === 'failed')
      setStatusOpen(false)
      setOverrideAction(null)
      if (failed.length > 0) {
        const names = new Map(targets.map((item) => [item.id, item.display_id]))
        feedback.warning(t('notices.batch.statusPartial', {
          updated: result.items.length - failed.length,
          failed: failed.map((item) => `#${names.get(item.id) ?? item.id}（${t(`errors.${item.error?.code ?? 'operationFailed'}`, { defaultValue: item.error?.code })}）`).join('、'),
        }))
        setSelectedRowKeys([])
        await queryClient.invalidateQueries({ queryKey: ['streams', scopeKind, scopeID, sessionEpoch] })
      } else {
        await finishWrite(t(value.action === 'set_status' ? 'notices.batch.status'
          : value.action === 'cname_regenerate' ? 'notices.batch.cnameRegenerate' : 'notices.batch.override', { count: result.items.length }))
      }
    } catch (error) {
      failWrite(error, attempt)
    } finally {
      setBatchBusy(false)
    }
  }

  const beginRowAction = (item: Stream, action: 'enable' | 'disable' | 'delete') => {
    if (!canWrite() || retryAttempt) return
    const instance = modalApi.confirm({
      title: action === 'delete'
        ? t('confirm.deleteTitle')
        : action === 'enable' ? t('confirm.enableTitle') : t('confirm.disableTitle'),
      content: action === 'delete' ? t('confirm.deleteDescription') : t('confirm.stateDescription'),
      okText: action === 'delete' ? t('actions.confirmDelete') : t('actions.confirm'),
      cancelText: t('actions.cancel'),
      okButtonProps: { danger: action === 'delete' },
      afterClose: () => { rowActionConfirmRef.current = null },
      onOk: () => {
        if (action === 'delete') mutateDelete({ kind: 'delete', item, key: writeKey(`delete-stream-${item.id}`) })
        else if (item.enabled !== (action === 'enable')) toggle(item)
      },
    })
    rowActionConfirmRef.current = { action, instance }
  }

  const retryWrite = () => {
    if (!canWrite() || !retryAttempt) return
    if (retryAttempt.kind === 'create') mutateCreate(retryAttempt)
    else if (retryAttempt.kind === 'update') mutateUpdate(retryAttempt)
    else if (retryAttempt.kind === 'delete') mutateDelete(retryAttempt)
    else if (retryAttempt.kind === 'action') void runAction(retryAttempt)
    else void runBatch(retryAttempt)
  }

  const pending = createMutation.isPending || updateMutation.isPending || deleteMutation.isPending || batchBusy
  const writesLocked = pending || Boolean(retryAttempt) || query.isFetching
  useEffect(() => {
    const active = rowActionConfirmRef.current
    if (!active) return
    active.instance.update({
      okButtonProps: {
        danger: active.action === 'delete',
        disabled: writesLocked,
        loading: writesLocked,
      },
    })
  }, [writesLocked])

  if (forbidden) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const publicationLabel = (item: Stream) => t(`values.${({
    unknown: 'publishUnknown',
    pending: 'publishPending',
    leased: 'publishLeased',
    retrying: 'publishRetrying',
    reconciling: 'publishReconciling',
    succeeded: 'publishSucceeded',
    failed: 'publishFailed',
    superseded: 'publishSuperseded',
  } as const)[item.publish_intent.state]}`, { version: item.publish_intent.version })

  const renderActions = (_: unknown, item: Stream) => {
    const target = publicationTarget(item)
    const menuItems = [
      ...(canManageStreams ? [
        { key: 'enable', label: t('actions.enable'), disabled: writesLocked || item.enabled },
        { key: 'disable', label: t('actions.disable'), disabled: writesLocked || !item.enabled },
        { key: 'delete', label: t('actions.delete'), danger: true, disabled: writesLocked },
        { type: 'divider' as const },
      ] : []),
      { key: 'publication', label: t('actions.publicationDetails') },
      ...(canManagePublications ? [{
        key: 'publish',
        label: <Link to={`/site/publications?target_scope_id=${encodeURIComponent(item.scope_id)}&stream_id=${encodeURIComponent(target.streamID)}&stream_revision=${target.revision}`}>{t('actions.publishConfiguration')}</Link>,
      }] : []),
    ]
    return <div className="stream-row-actions">
      <Link to={`/stream/list/${encodeURIComponent(item.id)}`}>{t('actions.manage')}</Link>
      <Dropdown
        trigger={['click']}
        menu={{
          items: menuItems,
          onClick: ({ key }) => {
            if (key === 'publication') setPublicationDetail(item)
            if (key === 'enable' || key === 'disable' || key === 'delete') beginRowAction(item, key)
          },
        }}
      >
        <Button type="link" size="small" aria-label={t('actions.rowMore')} disabled={writesLocked && canManageStreams}>
          <Ellipsis size={14} aria-hidden="true" />
        </Button>
      </Dropdown>
      <span className="visually-hidden">{publicationLabel(item)}</span>
    </div>
  }
  const bracket = (address: string) => address.includes(':') ? `[${address}]` : address
  const origins = (item: Stream) => originRows(item)
  // 状态列：设置状态（锁定/流量超限/套餐过期）优先，其次套餐不可用、禁用。
  const streamStatus = (item: Stream): [string, string] => {
    if (item.admin_status !== 'normal') return [t(`adminStatus.${item.admin_status}`), 'warning']
    if (item.eligibility_state === 'ineligible') return [t('states.ineligible'), 'warning']
    return item.enabled ? [t('states.normal'), 'normal'] : [t('states.disabled'), 'disabled']
  }
  const columns: TableColumnsType<Stream> = [
    {
      title: t('columns.id'), dataIndex: 'display_id', width: 78,
      render: (_: string, item) => <>
        <ResourceID internalId={item.id} displayId={item.display_id} />
        <span className="visually-hidden">{item.name}</span>
      </>,
    },
    {
      title: t('columns.listenPort'), key: 'listen', width: 128,
      render: (_, item) => <div className="stream-cell-stack" title={t('values.listenMeta', { id: item.display_id, time: dateTime(item.created_at, language) })}>
        <strong>{portLabel(item.listen_port, item.listen_port_end)}</strong>
        <span>{item.protocol.toUpperCase()}</span>
        {/* admin：监听端口下一行「用户 名称 (2)」。 */}
        {isAdmin && item.owner ? <span className="stream-owner-line">{t('columns.owner')} <em>{item.owner.display_name}</em></span> : null}
        {item.additional_listeners?.map((listener) => <span key={listener.id}>{portLabel(listener.port, listener.port_end)}/{listener.protocol.toUpperCase()}</span>)}
      </div>,
    },
    {
      title: t('columns.cname'), key: 'cname', width: 190,
      // 已生成 / 生成中 / 失败可重试, as the site list's CNAME column.
      render: (_, item) => item.cname_state === 'failed' ? (
        <span className="site-cname-cell site-cname-failed" data-testid="stream-cname-failed">
          <CnameFailureActions
            code={item.cname_failure_code}
            reason={cnameFailureText(item.cname_failure_code, item.cname_domain, tCname, i18nInstance.exists, isAdmin)}
            admin={isAdmin}
            onRegenerate={isAdmin && canManageStreams ? () => { submitBatchAction({ action: 'cname_regenerate' }, [item]) } : undefined}
            regenerateDisabled={pending || Boolean(retryAttempt) || batchBusy}
          />
        </span>
      ) : item.cname_state === 'pending' && !item.cname ? (
        <Tag color="processing" data-testid="stream-cname-pending">{tCname('cell.pending')}</Tag>
      ) : item.cname ? <span title={item.cname}>{item.cname}</span> : <span className="stream-unavailable">{t('values.unavailable')}</span>,
    },
    {
      title: t('columns.origin'), key: 'origin', width: 240,
      render: (_, item) => <div className="stream-cell-stack">
        {origins(item).length === 0 ? <span className="stream-unavailable">{t('values.unavailable')}</span> : origins(item).map((entry, index, list) => <div key={entry.address} className="stream-origin-cell">
          <strong>{bracket(entry.address)}</strong>
          <span>{t('values.originMeta', { port: item.upstream_port, weight: entry.weight, state: t(entry.down ? 'origins.down' : 'origins.up') })}{' · '}{streamShareText(streamOriginShares(list)[index] ?? null)}</span>
        </div>)}
      </div>,
    },
    {
      title: t('columns.group'), key: 'group', width: 160,
      render: (_, item) => <div className="stream-package-group" title={isAdmin && item.owner ? t('values.ownerMeta', { owner: item.owner.display_name }) : undefined}>
        <span>{item.groups.length > 0 ? item.groups.map((group) => group.name).join('、') : t('values.unavailable')}</span>
      </div>,
    },
    // 「线路」列（用户端没有）：区域 (线路分组)，如「默认 (test)」。
    ...(isAdmin ? [{
      title: t('columns.region'), key: 'region', width: 150,
      render: (_: unknown, item: Stream) => item.line.node_group_name || item.line.region_name
        ? <span className="stream-line">{item.line.region_name || t('values.placeholder')} ({item.line.node_group_name || t('values.placeholder')})</span>
        : <span className="stream-unavailable">{t('values.unavailable')}</span>,
    }] : []),
    {
      title: t('columns.status'), key: 'status', width: 104,
      render: (_, item) => {
        const [label, tone] = streamStatus(item)
        return <div className="stream-cell-stack">
          <span className={`stream-status stream-status--${tone}`}>{label}</span>
          <span className={`stream-sync stream-sync--${item.sync_state}`}>{t(`syncState.${item.sync_state}`)}</span>
        </div>
      },
    },
    { title: t('columns.actions'), key: 'actions', width: 118, fixed: 'right', render: renderActions },
  ]

  return (
    <section className="identity-page stream-page" aria-labelledby="stream-list-title">
      {messageContext}
      {modalContext}
      <h1 id="stream-list-title" className="visually-hidden">{t('title')}</h1>
      <nav className="site-subnav stream-subnav" aria-label={t('subnav.label')}>
        <button
          className="site-subnav-arrow"
          type="button"
          aria-label={t('subnav.previous')}
          onClick={() => streamSubnavRef.current?.scrollBy({ left: -120, behavior: 'smooth' })}
        >
          <ChevronLeft size={16} aria-hidden="true" />
        </button>
        <div ref={streamSubnavRef} className="site-subnav-scroll">
          {([['list', t('subnav.list')], ['groups', t('subnav.groups')], ['defaults', t('subnav.defaults')]] as const).map(([key, label]) => (
            <button
              className={section === key ? 'is-active' : undefined}
              type="button"
              key={key}
              aria-current={section === key ? 'page' : undefined}
              onClick={() => setSection(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <button
          className="site-subnav-arrow"
          type="button"
          aria-label={t('subnav.next')}
          onClick={() => streamSubnavRef.current?.scrollBy({ left: 120, behavior: 'smooth' })}
        >
          <ChevronRight size={16} aria-hidden="true" />
        </button>
      </nav>
      {section === 'list' ? <>
      <div className="stream-toolbar">
        <AdvancedFilters
          className="stream-advanced-filters"
          storageKey="stream-list"
          columns={4}
          onOpenChange={setAdvancedOpen}
          primary={<>
            <div className="stream-toolbar-actions">
              {canManageStreams ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => { setWriteError(null); setModalOpen(true) }}>{t('actions.add')}</Button> : null}
              {canManageStreams ? <Button disabled={writesLocked || selectedStreams.length === 0} onClick={() => setBatchModifyOpen(true)}>{t('actions.batchEdit')}</Button> : null}
              {canManageStreams ? <Dropdown trigger={['click']} menu={{
                items: [
                  { key: 'enable', label: t('actions.enable'), disabled: writesLocked || selectedStreams.length === 0 },
                  { key: 'disable', label: t('actions.disable'), disabled: writesLocked || selectedStreams.length === 0 },
                  { key: 'delete', label: t('actions.delete'), danger: true, disabled: writesLocked || selectedStreams.length === 0 },
                  // admin 另有 设置状态 / CNAME域名 / CNAME模式 / 线路分组；后三项是转发自己的值，不设则跟随所属套餐。
                  ...(isAdmin ? [
                    { key: 'status', label: t('actions.setStatus'), disabled: writesLocked || selectedStreams.length === 0 },
                    { key: 'cname_domain', label: t('actions.cnameDomain'), disabled: writesLocked || selectedStreams.length === 0 },
                    { key: 'cname_mode', label: t('actions.cnameMode'), disabled: writesLocked || selectedStreams.length === 0 },
                    { key: 'line_group', label: t('actions.lineGroup'), disabled: writesLocked || selectedStreams.length === 0 },
                  ] : []),
                ],
                onClick: ({ key }) => {
                  if (key === 'status') { setStatusValue('normal'); setStatusOpen(true); return }
                  if (key === 'cname_domain' || key === 'cname_mode' || key === 'line_group') { setOverrideAction(key); return }
                  beginBatch(key as 'enable' | 'disable' | 'delete')
                },
              }}>
                <Button disabled={writesLocked || selectedStreams.length === 0}>{t('actions.more')}<ChevronDown size={14} /></Button>
              </Dropdown> : null}
            </div>
            <div className="stream-search-control">
              <Select aria-label={t('filters.searchFieldLabel')} virtual={false} value={quickField} options={quickFields} onChange={(value) => { setQuickField(value); setQuickDraft({}); setQuickFilters({}); setFilterError(''); setPage(1) }} />
              {quickSearchInput()}
            </div>
          </>}
          items={advancedItems}
          queryText={t('actions.search')}
          onQuery={() => applyFilters()}
          onReset={resetFilters}
          onClearAdvanced={() => applyFilters({})}
          onRemove={(key) => applyFilters({ ...filterDraft, [key]: undefined })}
          extra={<Button icon={<RefreshCw size={15} />} loading={query.isFetching} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>}
        />
      </div>

      {filterError ? <Alert className="identity-alert" type="error" showIcon message={t(filterError)} /> : null}
      {/* 结果未知的记录离开页面后仍在（L4-007），回来时没有 writeError 也要显示原请求重试。 */}
      {retryAttempt ? <OutcomeUnknown className="identity-alert" title={writeError ? errorMessage(writeError, t) : t('detail.unknown')} action={canManageStreams ? <Button size="small" loading={pending || query.isFetching} disabled={query.isFetching} onClick={retryWrite}>{t('actions.retry')}</Button> : undefined} />
        : writeError && !modalOpen ? <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} /> : null}
      {query.isError ? <FeedbackWhen title={t('errors.listFailed')} detail={error ? errorMessage(error, t) : t('errors.requestFailed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <div className="identity-table-scroll" data-testid="stream-table-scroll" aria-busy={query.isPending || query.isFetching}>
        <Table<Stream> rowKey="id" size="small" rowSelection={canManageStreams ? { selectedRowKeys, onChange: (keys) => setSelectedRowKeys(keys.map(String)) } : undefined} columns={columns} dataSource={query.data?.items ?? []} loading={query.isPending || query.isFetching} pagination={false} locale={{ emptyText: query.isPending ? ' ' : t('values.empty') }} scroll={{ x: 1580 }} />
      </div>
      <Pagination className="identity-pagination" current={page} pageSize={limit} total={query.data?.total ?? 0} pageSizeOptions={[10, 20, 50, 100]} showSizeChanger showTotal={(count) => t('values.total', { count })} onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} />

      <StreamFormModal
        isAdmin={isAdmin}
        open={canManageStreams && modalOpen}
        pending={pending || query.isFetching}
        scopeKind={scopeKind}
        scopeID={scopeID}
        sessionEpoch={sessionEpoch}
        writeError={modalOpen && !retryAttempt ? writeError : null}
        batchPanel={<StreamBatchCreatePanel
          isAdmin={isAdmin}
          scopeKind={scopeKind}
          scopeID={scopeID}
          sessionEpoch={sessionEpoch}
          disabled={writesLocked}
          onCancel={() => { setModalOpen(false) }}
          onCreated={(result) => {
            void queryClient.invalidateQueries({ queryKey: ['streams', scopeKind, scopeID, sessionEpoch] })
            if (result.failed === 0) { setModalOpen(false); messageApi.success(t('batchCreate.committed', { created: result.created, failed: 0 })) }
          }}
        />}
        onCancel={() => { if (writesLocked) return; setModalOpen(false) }}
        onSubmit={submit}
      />
      <StreamBatchModifyModal
        open={canManageStreams && batchModifyOpen}
        items={selectedStreams}
        busy={batchBusy}
        locked={writesLocked}
        scopeKind={scopeKind}
        scopeID={scopeID}
        sessionEpoch={sessionEpoch}
        onCancel={() => setBatchModifyOpen(false)}
        onApply={(patch, acl) => { setBatchModifyOpen(false); beginBatch('modify', patch, acl) }}
      />
      <Modal
        className="identity-modal stream-status-modal"
        title={t('statusModal.title')}
        open={isAdmin && statusOpen}
        width={420}
        okText={t('form.confirm')}
        cancelText={t('actions.cancel')}
        confirmLoading={batchBusy}
        onOk={() => submitBatchAction({ action: 'set_status', admin_status: statusValue })}
        onCancel={() => { if (!batchBusy) setStatusOpen(false) }}
        destroyOnHidden
      >
        <label className="stream-status-field">{t('statusModal.status')}
          <Select aria-label={t('statusModal.status')} disabled={Boolean(retryAttempt)} options={adminStatusOptions} onChange={setStatusValue}
            value={retryAttempt?.kind === 'action' && retryAttempt.input.action === 'set_status' ? retryAttempt.input.admin_status : statusValue} />
        </label>
      </Modal>
      {isAdmin ? <StreamOverrideModal action={overrideAction} busy={batchBusy} onCancel={() => setOverrideAction(null)}
        frozen={retryAttempt?.kind === 'action' ? retryAttempt.input : null}
        onSubmit={(value) => submitBatchAction(value)} /> : null}
      <StreamPublicationModal item={publicationDetail} onClose={() => setPublicationDetail(null)} />
      </> : section === 'groups' ? <StreamGroupsPanel
        accessToken={accessToken}
        scopeKind={scopeKind}
        scopeID={scopeID}
        sessionEpoch={sessionEpoch}
        isAdmin={isAdmin}
        canManageGroups={canManageStreams}
        lockWrites={writesLocked}
      /> : <StreamDefaultsPanel
        accessToken={accessToken}
        scopeKind={scopeKind}
        scopeID={scopeID}
        sessionEpoch={sessionEpoch}
        isAdmin={isAdmin}
        canManageDefaults={canManageStreams}
        lockWrites={writesLocked}
      />}
    </section>
  )
}

const streamCnamePendingPollIntervalMs = 2000
const streamCnamePendingPollWindowMs = 60_000
