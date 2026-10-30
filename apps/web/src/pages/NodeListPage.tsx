import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Checkbox,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Result,
  Select,
  Switch,
  Table,
  Tag,
  Tabs,
  Tooltip,
  type MenuProps,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown, submitErrorFields, useFormSubmitError, type FormErrorMap } from '@cdnca/ui'
import { ArrowDown, ArrowUp, ChevronDown, ChevronLeft, ChevronRight, Copy, Plus, RefreshCw, RotateCcw, Search } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  isSchedule302Hostname,
  validNodeStorageDirectory,
  nativeRuntimeSummary,
  nodeStorageDirectoriesOverlap,
  nodeStorageInstallDefaults,
  nodeStorageMaxCacheGB,
  nodesApi,
  type BatchNodeAdminStateItemResult,
  type BatchNodeAdminStateRequest,
  type EnrollmentPurpose,
  type IssuedEnrollmentToken,
  type ManagedNodeAdminState,
  type NodeAdminState,
  type NodeInventoryItem,
  type NodeMetricsLatest,
  type NodeStorageStatus,
  type NodePresence,
  type NodePresenceStatus,
  type UpdateNodeRequest,
} from '../api/nodes'
import { nodeIPLocationFields, type NodeIPLocationField } from '../api/nodes'
import { nodeSchedulingApi } from '../api/nodeScheduling'
import { supplyInUse } from '../api/marketSupplier'
import { nodeMonitoringApi, type NodeMonitoringLatest, type NodeMonitoringLatestBatch } from '../api/nodeMonitoring'
import { nodeInstallationTicketsApi } from '../api/nodeInstallationTickets'
import { NodeFrozenTag } from '../components/NodeFrozenTag'
import { useSessionStore } from '../auth/session'
import { ResourceID } from '../components/ResourceID'
import { formatBandwidth, formatBytes, formatDateTime, formatNumber } from '../i18n/formatters'
import i18n from '../i18n'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/marketSupplier'
import '../i18n/nodeInventoryDetail'
import './NodeListEditModal.locale'
import './NodeListPage.locale'
import './NodeListPage.css'
import RegionManagementPanel from './NodeRegionManagement'
import { NodeRegionSelect, useRegionCatalogNames } from './NodeRegionSelect'
import NodeInstallCommand from './NodeInstallCommand'
import NodeSSHInstall from './NodeSSHInstall'
import { NodeBatchMonitorConfigModal, NodeMonitorConfigModal, NodeMonitorLogModal } from './NodeListMonitorModals'
import { NodeGatewayPortBatchModal } from './NodeGatewayPortBatchModal'
import { themeColor } from '../theme/themeColor'
import {
  clearNodeUpdateRetry, persistNodeUpdateRetry, restoreNodeUpdateRetry,
  type NodeUpdateRequestAttempt, type NodeUpdateRetryOwner, type NodeUpdateRetryRecord,
} from './nodeUpdateRetryRecord'

interface NodeFormValues {
  name: string
  description: string
  region: string
  ipv4: string
  ipv6: string
  issue_enrollment_token: boolean
  enrollment_purpose: EnrollmentPurpose
  enrollment_token_ttl_seconds: number
}

interface TokenFormValues {
  purpose: EnrollmentPurpose
  ttl_seconds: number
}

interface NodeEditFormValues {
  name: string
  description: string
  region: string
  sort: number
  ipv4: string
  ipv6: string
  type: 'L1' | 'L2'
  external_probe: boolean
  proxy_cache_dir: string
  proxy_cache_max_size: number | null
  logs_dir: string
  country: string
  province: string
  city: string
  isp: string
  country_code: string
  bandwidth_limit: number | null
  bandwidth_unit: 'Mbps' | 'Gbps'
  traffic_enabled: boolean
  traffic_from_day: number
  traffic_from_hour: string
  traffic_total: number
  traffic_types: Array<'outbound' | 'inbound'>
  excluded_interfaces: string
  disabled_periods: string
  sub_ips: string
  schedule302_hostname: string
}

interface UpdateAttempt {
  kind: 'update'
  request: NodeUpdateRequestAttempt
  replay: boolean
  ownerKey: string
}

interface BatchAttempt {
  kind: 'batch'
  input: BatchNodeAdminStateRequest
  key: string
  ownerKey: string
}

type RetryAttempt = CreateAttempt | UpdateAttempt | BatchAttempt
type NodeListTab = 'list' | 'pending' | 'failed' | 'regions'
type NodeOwner = readonly ['platform', string, null, string, number]
type NodePermission = 'read' | 'manage'

interface CreateAttempt {
  kind: 'create'
  input: Parameters<typeof nodesApi.create>[1]
  key: string
  ownerKey: string
}

interface TokenAttempt {
  node: NodeInventoryItem
  ownerKey: string
  values: TokenFormValues
}

const staleNodeRead = new Error('Node inventory session owner changed during read')
// Region filter value for nodes without a region (no region name is empty).
const unsetRegionFilter = '\u0000unset'

const staleNodeWrite = new Error('Node inventory session owner changed during write')
const pageSizes = [10, 30, 100, 300] as const

function nodeOwner(principal: Principal, sessionEpoch: number): NodeOwner | null {
  if (
    principal.scope_kind !== 'platform'
    || principal.tenant_id !== null
    || !principal.scope_id
    || !principal.user_id
    || sessionEpoch <= 0
  ) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function nodeCanRead(principal: Principal): boolean {
  return principal.permissions.includes('platform.admin') || principal.permissions.includes('nodes.read')
}

function nodeCanManage(principal: Principal): boolean {
  return principal.permissions.includes('platform.admin') || principal.permissions.includes('nodes.manage')
}

function currentNodeAccess(ownerKey: string, permission: NodePermission): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = nodeOwner(principal, sessionEpoch)
  if (!owner || JSON.stringify(owner) !== ownerKey || !nodeCanRead(principal)) return null
  if (permission === 'manage' && !nodeCanManage(principal)) return null
  return accessToken
}

const stateMeta: Record<NodeAdminState, { color: string; dot: () => string }> = {
  pending: { color: 'warning', dot: () => themeColor('--cdnca-color-status-pending', '#faad14') },
  active: { color: 'success', dot: () => themeColor('--cdnca-color-success', '#19be6b') },
  draining: { color: 'processing', dot: () => themeColor('--cdnca-color-primary', '#2d8cf0') },
  disabled: { color: 'error', dot: () => themeColor('--cdnca-color-error', '#ed4014') },
  retired: { color: 'error', dot: () => themeColor('--cdnca-color-error', '#ed4014') },
}

const presenceMeta: Record<NodePresenceStatus, { color: string }> = {
  online: { color: 'success' },
  offline: { color: 'default' },
  unknown: { color: 'warning' },
}

const freshnessKey = {
  fresh: 'presence.fresh',
  stale: 'presence.stale',
  never: 'presence.never',
} as const

const leaseKey = {
  present: 'presence.leasePresent',
  absent: 'presence.leaseAbsent',
  unavailable: 'presence.leaseUnavailable',
} as const

function PresenceCell({ state, presence }: { state: NodeAdminState; presence: NodePresence }) {
  const { t } = useTranslation('nodes')
  const sequence = presence.session_epoch && presence.heartbeat_sequence
    ? `e${presence.session_epoch} / #${presence.heartbeat_sequence}`
    : t('empty.notReported')
  const details = [
    `${t('monitor.adminState')}: ${t(`states.${state}`)}`,
    `${t('monitor.presence')}: ${t(`presence.${presence.status}`)}`,
    `${t('monitor.projection')}: ${t(freshnessKey[presence.projection_freshness])}`,
    `${t('monitor.lease')}: ${t(leaseKey[presence.lease_signal])}`,
    `${t('monitor.agent')}: ${presence.agent_version || t('empty.notReported')}`,
    `${t('monitor.openResty')}: ${presence.openresty_version || t('empty.notReported')}`,
    `${t('monitor.nativeRuntime')}: ${presence.native_runtime_state
      ? nativeRuntimeSummary(presence, t(`monitor.nativeRuntimeStates.${presence.native_runtime_state}`), t('monitor.nativeRuntimePrevious'))
      : t('empty.notReported')}`,
    `${t('monitor.sequence')}: ${sequence}`,
    `${t('monitor.marketProbe')}: ${presence.market_probe_role
      ? t(`monitor.marketProbeRoles.${presence.market_probe_role}`)
      : t('empty.notReported')}`,
  ].join(' · ')
  return (
    <Tooltip title={details} trigger={['hover', 'focus', 'click']}>
      <span className="node-state-cell" tabIndex={0} aria-label={details} title={details}>
        <span className="node-state-dot" style={{ background: stateMeta[state].dot() }} />
        <span>{state === 'active' ? t('list.stateActive') : t(`states.${state}`)}</span>
      </span>
    </Tooltip>
  )
}

function writeKey(operation: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `${operation}-${suffix}`
}

function writeOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

function dateTime(value: string, language: string): string {
  return formatDateTime(value, language) || value
}

function optional(value: string): string | undefined {
  return value.trim() || undefined
}

function isIPv4(value: string): boolean {
  const parts = value.trim().split('.')
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function isIPv6(value: string): boolean {
  const candidate = value.trim()
  if (!candidate.includes(':') || !/^[0-9a-f:]+$/i.test(candidate)) return false
  const sides = candidate.split('::')
  if (sides.length > 2) return false
  const groups = sides.flatMap((side) => side ? side.split(':') : [])
  return groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group)) &&
    (sides.length === 2 ? groups.length < 8 : groups.length === 8)
}

// A17：删除回执须是同一节点、admin_state=retired、修订号严格递增，缺一不当作删除完成。
function deleteAcknowledged(item: Pick<NodeInventoryItem, 'id' | 'revision'>, ack: Pick<NodeInventoryItem, 'id' | 'revision' | 'admin_state'>): boolean {
  return ack.id === item.id && ack.admin_state === 'retired' && ack.revision > item.revision
}

function allowedTargets(state: NodeAdminState): ManagedNodeAdminState[] {
  switch (state) {
    case 'pending':
      return ['retired']
    case 'active':
      return ['draining', 'disabled', 'retired']
    case 'draining':
      return ['active', 'disabled', 'retired']
    case 'disabled':
      return ['active', 'retired']
    case 'retired':
      // A row left by a release before physical deletion: it can only be
      // deleted.
      return ['retired']
  }
}

function stateLabel(state: ManagedNodeAdminState, t: TFunction<'nodes'>): string {
  if (state === 'retired') return t('actions.delete')
  return state === 'active' ? t('states.activateAuthorized') : t(`states.${state}`)
}

function errorCodeMessage(code: string, t: TFunction<'nodes'>): string {
  switch (code) {
    case 'version_conflict':
    case 'node_not_found':
    case 'node_identity_required':
    case 'node_state_transition_denied':
    case 'node_ip_conflict':
    case 'node_retired':
    case 'node_in_use':
    case 'node_address_in_use':
    case 'node_region_in_use':
      return t(`errors.${code}`)
    default:
      return t('errors.requestFailed')
  }
}

function errorMessage(error: ApiError, t: TFunction<'nodes'>): string {
  const inUse = supplyInUse(error)
  if (inUse) return i18n.t('marketSupplier:supplyInUse', { online: inUse.online_available, normal: inUse.normal_subscriptions })
  return localizedUnknownApiError(error, errorCodeMessage(error.code, t))
}

/** What the node runs (NodeTelemetry.storage) and the outcome of the last settings. */
function NodeStorageEffective({ storage }: { storage: NodeStorageStatus | undefined }) {
  const { t } = useTranslation('nodes')
  if (!storage) {
    return <p className="node-list-storage-effective">{t('editModal.storage.effective')}：{t('editModal.storage.notReported')}</p>
  }
  return (
    <div className="node-list-storage-effective" role="status">
      <p>{t('editModal.storage.effective')}：{t('editModal.storage.effectiveCache', {
        directory: storage.cache_directory, limit: formatBytes(storage.cache_max_bytes),
      })}；{t('editModal.storage.effectiveLogs', { directory: storage.log_directory })}</p>
      <p>{t(`editModal.storage.state.${storage.state}`, { directory: storage.requested_log_directory ?? '' })}
        {storage.reason ? `（${t('editModal.storage.reason', { reason: storage.reason })}）` : ''}</p>
    </div>
  )
}

type NodeIPLocationResolution = NonNullable<Awaited<ReturnType<typeof nodesApi.getIPLocation>>['resolution']>

/** IP 归属: the latest automatic resolution (time, IP library) or why none. */
function IPLocationStatus({ loading, failed, resolution }: {
  loading: boolean
  failed: boolean
  resolution: NodeIPLocationResolution | null
}) {
  const { t, i18n: { resolvedLanguage, language } } = useTranslation('nodes')
  const locale = resolvedLanguage ?? language
  let text: string
  if (loading) text = t('editModal.ipLocation.loading')
  else if (failed) text = t('editModal.ipLocation.loadFailed')
  else if (!resolution) text = t('editModal.ipLocation.pending')
  else {
    const time = formatDateTime(resolution.resolved_at, locale) || resolution.resolved_at
    const library = resolution.library_version || String(resolution.library_revision)
    text = resolution.outcome === 'resolved'
      ? t('editModal.ipLocation.resolved', { address: resolution.address ?? '', time, library })
      : resolution.outcome === 'unresolved'
        ? t('editModal.ipLocation.unresolved', { time, library })
        : t('editModal.ipLocation.noLibrary', { time })
  }
  return <p className="node-ip-location-status" role="status">{text}</p>
}

/** A field's source tag (自动解析 / 人工修正) and its 恢复自动 action. */
function IPLocationSource({ field, manual, disabled, onRestore }: {
  field: NodeIPLocationField
  manual: boolean
  disabled: boolean
  onRestore: (field: NodeIPLocationField) => void
}) {
  const { t } = useTranslation('nodes')
  if (!manual) return <Tag className="node-ip-location-tag">{t('editModal.ipLocation.automatic')}</Tag>
  return (
    <>
      <Tag className="node-ip-location-tag" color="warning">{t('editModal.ipLocation.manual')}</Tag>
      <Button size="small" type="link" disabled={disabled} onClick={() => onRestore(field)}
        aria-label={t('editModal.ipLocation.restoreField', { field: t(`editModal.fields.${field === 'country_code' ? 'countryCode' : field}`) })}>
        {t('editModal.ipLocation.restore')}
      </Button>
    </>
  )
}

// Update-body fields as the edit modal's tab and form field.
const nodeEditFieldTabs: Record<string, [tab: string, field: string]> = {
  name: ['basic', 'name'], description: ['basic', 'description'], region: ['basic', 'region'], ipv4: ['basic', 'ipv4'], ipv6: ['basic', 'ipv6'],
  'management_settings.sort': ['basic', 'sort'], 'management_settings.node_type': ['basic', 'type'],
  'management_settings.cache_directory': ['node', 'proxy_cache_dir'], 'management_settings.cache_limit_gb': ['node', 'proxy_cache_max_size'],
  'management_settings.log_directory': ['node', 'logs_dir'],
  'management_settings.auto_disable.bandwidth_limit': ['auto-disable', 'bandwidth_limit'],
  'management_settings.auto_disable.bandwidth_unit': ['auto-disable', 'bandwidth_unit'],
  'management_settings.auto_disable.traffic_total_gb': ['auto-disable', 'traffic_total'],
  'management_settings.auto_disable.traffic_from_day': ['auto-disable', 'traffic_from_day'],
  'management_settings.auto_disable.traffic_from_time': ['auto-disable', 'traffic_from_hour'],
  'management_settings.auto_disable.traffic_types': ['auto-disable', 'traffic_types'],
  'management_settings.auto_disable.excluded_interfaces': ['auto-disable', 'excluded_interfaces'],
  'management_settings.auto_disable.disabled_periods': ['auto-disable', 'disabled_periods'],
  'management_settings.secondary_ips': ['sub-ip', 'sub_ips'], 'management_settings.schedule302_hostname': ['sub-ip', 'schedule302_hostname'],
}
const nodeEditErrorMaps = Object.fromEntries(['basic', 'node', 'auto-disable', 'sub-ip'].map((tab) => [tab, Object.fromEntries(
  Object.entries(nodeEditFieldTabs).filter(([, [owner]]) => owner === tab).map(([field, [, name]]) => [field, name]))])) as Record<string, FormErrorMap>
// management_settings.secondary_ips[n]: the one sub-IP textarea.
for (let index = 0; index < 64; index++) nodeEditErrorMaps['sub-ip'][`management_settings.secondary_ips[${index}]`] = 'sub_ips'

function NodeEditModal({
  item,
  open,
  pending,
  uncertain,
  error,
  submitError,
  readOnly,
  regionNames,
  regionsLoading,
  onCancel,
  onSubmit,
}: {
  item: NodeInventoryItem
  open: boolean
  pending: boolean
  uncertain: boolean
  error: ApiError | null
  /** A field refusal of the last save, marked on its tab. */
  submitError: ApiError | null
  readOnly: boolean
  regionNames: string[]
  regionsLoading: boolean
  onCancel: () => void
  onSubmit: (input: UpdateNodeRequest) => void
}) {
  const { t } = useTranslation('nodes')
  const [basicFormInstance] = Form.useForm<NodeEditFormValues>()
  const [nodeFormInstance] = Form.useForm<NodeEditFormValues>()
  const [ipLocationFormInstance] = Form.useForm<NodeEditFormValues>()
  const [autoDisableFormInstance] = Form.useForm<NodeEditFormValues>()
  const [subIPFormInstance] = Form.useForm<NodeEditFormValues>()
  const [activeTab, setActiveTab] = useState('basic')
  const [fieldMarked, setFieldMarked] = useState(false)
  const markBasic = useFormSubmitError(basicFormInstance, nodeEditErrorMaps.basic)
  const markNode = useFormSubmitError(nodeFormInstance, nodeEditErrorMaps.node)
  const markAutoDisable = useFormSubmitError(autoDisableFormInstance, nodeEditErrorMaps['auto-disable'])
  const markSubIP = useFormSubmitError(subIPFormInstance, nodeEditErrorMaps['sub-ip'])
  useEffect(() => {
    if (!submitError) { setFieldMarked(false); return }
    const field = submitErrorFields(submitError)[0]?.field.replace(/\[\d+\]$/, '')
    const tab = field ? nodeEditFieldTabs[field]?.[0] : undefined
    const mark = ({ basic: markBasic, node: markNode, 'auto-disable': markAutoDisable, 'sub-ip': markSubIP } as Record<string, typeof markBasic>)[tab ?? '']
    const marked = Boolean(tab && mark?.(submitError))
    if (marked && tab) setActiveTab(tab)
    setFieldMarked(marked)
  }, [markAutoDisable, markBasic, markNode, markSubIP, submitError])

  useEffect(() => {
    if (!open) return
    setActiveTab('basic')
    basicFormInstance.resetFields()
    nodeFormInstance.resetFields()
    ipLocationFormInstance.resetFields()
    autoDisableFormInstance.resetFields()
    subIPFormInstance.resetFields()
    basicFormInstance.setFieldsValue({
      name: item.name,
      description: item.description,
      region: item.region,
      sort: item.management_settings.sort,
      ipv4: item.ipv4 ?? '',
      ipv6: item.ipv6 ?? '',
      type: item.management_settings.node_type,
      external_probe: item.management_settings.external_probe,
    })
    nodeFormInstance.setFieldsValue({
      proxy_cache_dir: item.management_settings.cache_directory,
      // 0 is "node default"; shown as an empty field holding the default.
      proxy_cache_max_size: item.management_settings.cache_limit_gb || null,
      logs_dir: item.management_settings.log_directory,
    })
    ipLocationFormInstance.setFieldsValue({
      ...item.management_settings.ip_location,
    })
    autoDisableFormInstance.setFieldsValue({
      // 0 is "no limit"; the reference shows it as an empty "留空不限制" field.
      bandwidth_limit: item.management_settings.auto_disable.bandwidth_limit || null,
      bandwidth_unit: item.management_settings.auto_disable.bandwidth_unit,
      traffic_enabled: item.management_settings.auto_disable.traffic_enabled,
      traffic_from_day: item.management_settings.auto_disable.traffic_from_day,
      traffic_from_hour: item.management_settings.auto_disable.traffic_from_time,
      traffic_total: item.management_settings.auto_disable.traffic_total_gb,
      traffic_types: item.management_settings.auto_disable.traffic_types,
      excluded_interfaces: item.management_settings.auto_disable.excluded_interfaces,
      disabled_periods: item.management_settings.auto_disable.disabled_periods,
    })
    subIPFormInstance.setFieldsValue({
      sub_ips: item.management_settings.secondary_ips.join('\n'),
      schedule302_hostname: item.management_settings.schedule302_hostname ?? '',
    })
  }, [autoDisableFormInstance, basicFormInstance, ipLocationFormInstance, item, nodeFormInstance, open, subIPFormInstance])

  // 节点设置 (NODE_STORAGE): editable once the node's agent declares the
  // capability; what the node runs comes from its latest telemetry.
  const storageQuery = useQuery({
    queryKey: ['node-storage-latest', item.id],
    enabled: open,
    retry: false,
    queryFn: async () => {
      const token = useSessionStore.getState().accessToken
      if (!token) throw new ApiError('Session expired', 401, 'unauthorized')
      try {
        return await nodesApi.getLatestMetrics(token, item.id)
      } catch (error) {
        // never reported: an agent that cannot take the settings yet
        if (error instanceof ApiError && error.status === 404) return null
        throw error
      }
    },
  })
  // IP 归属: which fields are manual, and the IP library's
  // automatic values they otherwise follow.
  const ipLocationQuery = useQuery({
    queryKey: ['node-ip-location', item.id, item.revision],
    enabled: open,
    retry: false,
    queryFn: async () => {
      const token = useSessionStore.getState().accessToken
      if (!token) throw new ApiError('Session expired', 401, 'unauthorized')
      return nodesApi.getIPLocation(token, item.id)
    },
  })
  const resolution = ipLocationQuery.data?.resolution ?? null
  const [manualFields, setManualFields] = useState<NodeIPLocationField[]>([])
  useEffect(() => {
    if (open) setManualFields(item.management_settings.ip_location_manual ?? [])
  }, [item, open])
  const markManual = (field: NodeIPLocationField) =>
    setManualFields((current) => current.includes(field) ? current : [...current, field])
  const restoreAutomatic = (field: NodeIPLocationField) => {
    setManualFields((current) => current.filter((value) => value !== field))
    ipLocationFormInstance.setFieldValue(field, resolution?.automatic[field] ?? '')
  }
  const storageSupport = storageQuery.isPending ? undefined : storageQuery.data?.storage_supported === true
  const storageLocked = storageSupport !== true
  const storageStatus = storageQuery.data?.telemetry?.storage
  // What an empty field runs: the node's report of that field when it runs
  // its default there (state default, or applied with the field unset: the
  // Agent falls back per field, dynroute cacheRoot/cacheBudget/logRootFor),
  // else the installer layout; an empty cache limit is the automatic budget
  // (edge-agent defaultCacheBytes).
  const saved = item.management_settings
  const reportsDefault = (unset: boolean) => storageStatus !== undefined &&
    (storageStatus.state === 'default' || (storageStatus.state === 'applied' && unset))
  const storageDefaults = {
    cacheDirectory: reportsDefault(saved.cache_directory === '') ? storageStatus!.cache_directory : nodeStorageInstallDefaults.cacheDirectory,
    logDirectory: reportsDefault(saved.log_directory === '') ? storageStatus!.log_directory : nodeStorageInstallDefaults.logDirectory,
    cacheLimit: reportsDefault(saved.cache_limit_gb === 0)
      ? String(Math.round(storageStatus!.cache_max_bytes / 2 ** 30 * 10) / 10)
      : t('editModal.storage.cacheLimitAuto'),
  }
  const watchedCacheDirectory = Form.useWatch('proxy_cache_dir', nodeFormInstance)
  const watchedCacheLimit = Form.useWatch('proxy_cache_max_size', nodeFormInstance)
  const watchedLogDirectory = Form.useWatch('logs_dir', nodeFormInstance)
  const storageAllDefault = (watchedCacheDirectory ?? '').trim() === '' && watchedCacheLimit == null &&
    (watchedLogDirectory ?? '').trim() === ''
  const storageDirectoryRules = (other: 'proxy_cache_dir' | 'logs_dir') => [{
    validator: (_: unknown, value: string | undefined) => {
      const directory = (value ?? '').trim()
      if (directory === '' || storageLocked) return Promise.resolve()
      if (!validNodeStorageDirectory(directory)) return Promise.reject(new Error(t('editModal.storage.invalidDirectory')))
      const otherDirectory = String(nodeFormInstance.getFieldValue(other) ?? '').trim()
      if (otherDirectory !== '' && nodeStorageDirectoriesOverlap(directory, otherDirectory)) {
        return Promise.reject(new Error(t('editModal.storage.overlap')))
      }
      return Promise.resolve()
    },
  }]

  // unavailable: the tab's settings cannot be applied on this node, so saving
  // them would be a no-op; the confirm button stays disabled and says why.
  const formActions = (unavailable?: string) => (
    <div className="node-list-form-actions">
      <Tooltip title={unavailable}>
        <Button
          type="primary"
          htmlType="submit"
          loading={pending}
          disabled={readOnly || uncertain || !!unavailable}
        >
          {t('editModal.actions.confirm')}
        </Button>
      </Tooltip>
      {/* C38/ND01: a read-only or unavailable form still closes; only the fields and submit are locked. */}
      <Button disabled={false} onClick={onCancel}>{readOnly || unavailable ? t('editModal.actions.close') : t('editModal.actions.cancel')}</Button>
    </div>
  )

  const basicForm = (
    <Form
      form={basicFormInstance}
      className="node-list-edit-form"
      layout="horizontal"
      colon={false}
      labelWrap
      labelCol={{ flex: '80px' }}
      wrapperCol={{ flex: 1 }}
      requiredMark={false}
      disabled={pending || uncertain || readOnly}
      onFinish={(values) => {
        onSubmit({
          name: values.name,
          description: values.description,
          region: values.region ?? '',
          // Each address family has its own field; neither is guessed.
          ipv4: (values.ipv4 ?? '').trim(),
          ipv6: (values.ipv6 ?? '').trim(),
          management_settings: {
            ...item.management_settings,
            sort: values.sort,
            node_type: values.type,
            external_probe: values.external_probe,
          },
        })
      }}
    >
      <Form.Item name="name" label={t('editModal.fields.name')} rules={[{ required: true, whitespace: true, max: 128 }]}>
        <Input placeholder={t('editModal.placeholders.name')} />
      </Form.Item>
      <Form.Item name="description" label={t('editModal.fields.description')} rules={[{ max: 1024 }]}>
        <Input placeholder={t('editModal.placeholders.description')} />
      </Form.Item>
      <Form.Item name="region" label={t('region.label')} extra={t('region.initializeHelp')}>
        <NodeRegionSelect names={regionNames} loading={regionsLoading} />
      </Form.Item>
      <Form.Item name="sort" label={t('editModal.fields.sort')} rules={[{ required: true, type: 'integer', min: 0, max: 999999, message: t('updateRetry.sortInteger') }]}>
        <InputNumber className="node-list-number-input" placeholder={t('editModal.placeholders.sort')} />
      </Form.Item>
      <Form.Item
        name="ipv4"
        label={t('editModal.fields.ipv4')}
        rules={[{
          validator: (_, value: string) => !value?.trim() || isIPv4(value.trim())
            ? Promise.resolve()
            : Promise.reject(new Error(t('editModal.validation.invalidIPv4'))),
        }]}
      >
        <Input placeholder={t('editModal.placeholders.ipv4')} />
      </Form.Item>
      <Form.Item
        name="ipv6"
        label={t('editModal.fields.ipv6')}
        extra={t('editModal.help.ip')}
        rules={[{
          validator: (_, value: string) => !value?.trim() || isIPv6(value.trim())
            ? Promise.resolve()
            : Promise.reject(new Error(t('editModal.validation.invalidIPv6'))),
        }]}
      >
        <Input placeholder={t('editModal.placeholders.ipv6')} />
      </Form.Item>
      <Form.Item name="type" label={t('editModal.fields.type')} extra={<span className="node-list-type-help">
        {t('editModal.help.type')} <Link to="/node/l2-config">{t('editModal.help.typeLink')}</Link>
      </span>}>
        <Radio.Group>
          <Radio value="L1">{t('editModal.options.l1')}</Radio>
          <Radio value="L2">{t('editModal.options.l2')}</Radio>
        </Radio.Group>
      </Form.Item>
      <Form.Item name="external_probe" label={t('editModal.fields.externalProbe')} valuePropName="checked"
        extra={t('editModal.help.externalProbe')}>
        <Switch aria-label={t('editModal.fields.externalProbe')} />
      </Form.Item>
      {formActions()}
    </Form>
  )

  const nodeForm = (
    <Form
      form={nodeFormInstance}
      className="node-list-edit-form"
      layout="horizontal"
      colon={false}
      labelWrap
      labelCol={{ flex: '80px' }}
      wrapperCol={{ flex: 1 }}
      requiredMark={false}
      disabled={pending || uncertain || readOnly || storageLocked}
      onFinish={(values) => onSubmit({
        management_settings: {
          ...item.management_settings,
          // empty = node default: untouched defaults are never written as settings
          cache_directory: (values.proxy_cache_dir ?? '').trim(),
          cache_limit_gb: values.proxy_cache_max_size ?? 0,
          log_directory: (values.logs_dir ?? '').trim(),
        },
      })}
    >
      {storageLocked
        ? <Alert className="node-modal-alert cdnca-alert-compact" type="info" showIcon
          message={storageSupport === undefined ? t('editModal.storage.unknown') : t('editModal.storage.unsupportedTitle')}
          description={storageSupport === undefined ? undefined : t('editModal.storage.unsupported')} />
        : <Alert className="node-modal-alert cdnca-alert-compact" type="info" showIcon message={t('editModal.storage.help')}
          description={t('editModal.storage.oldDirectoryKept')} />}
      <NodeStorageEffective storage={storageStatus} />
      <Form.Item name="proxy_cache_dir" label={t('editModal.fields.cacheDirectory')} dependencies={['logs_dir']}
        rules={storageDirectoryRules('logs_dir')}>
        <Input placeholder={storageDefaults.cacheDirectory} />
      </Form.Item>
      <Form.Item label={t('editModal.fields.cacheLimit')} htmlFor="node-list-proxy-cache-max-size"
        extra={t('editModal.storage.cacheLimitDefault')}>
        <div className="node-list-input-addon">
          <Form.Item name="proxy_cache_max_size" noStyle
            rules={[{ type: 'integer', min: 1, max: nodeStorageMaxCacheGB, message: t('editModal.storage.limitRange') }]}>
            <InputNumber id="node-list-proxy-cache-max-size" min={1} precision={0} placeholder={storageDefaults.cacheLimit} />
          </Form.Item>
          <span>GB</span>
        </div>
      </Form.Item>
      <Form.Item name="logs_dir" label={t('editModal.fields.logDirectory')} dependencies={['proxy_cache_dir']}
        rules={storageDirectoryRules('proxy_cache_dir')}>
        <Input placeholder={storageDefaults.logDirectory} />
      </Form.Item>
      <div className="node-list-storage-restore">
        <Button icon={<RotateCcw size={14} aria-hidden="true" />} disabled={storageAllDefault}
          onClick={() => nodeFormInstance.setFieldsValue({ proxy_cache_dir: '', proxy_cache_max_size: null, logs_dir: '' })}>
          {t('editModal.storage.restoreDefaults')}
        </Button>
        <span className="node-list-item-help">{t('editModal.storage.restoreDefaultsHelp')}</span>
      </div>
      {formActions(storageLocked ? t('editModal.storage.unsupportedTitle') : undefined)}
    </Form>
  )

  const ipLocationForm = (
    <Form
      form={ipLocationFormInstance}
      className="node-list-edit-form"
      layout="horizontal"
      colon={false}
      labelWrap
      labelCol={{ flex: '80px' }}
      wrapperCol={{ flex: 1 }}
      requiredMark={false}
      disabled={pending || uncertain || readOnly}
      onFinish={(values) => onSubmit({
        management_settings: {
          ...item.management_settings,
          ip_location: {
            country: values.country.trim(),
            province: values.province.trim(),
            city: values.city.trim(),
            isp: values.isp.trim(),
            country_code: values.country_code.trim().toUpperCase(),
          },
          ip_location_manual: nodeIPLocationFields.filter((field) => manualFields.includes(field)),
        },
      })}
    >
      <Form.Item label={t('editModal.fields.explanation')}>
        <div className="node-list-item-help">{t('editModal.help.ipLocation')}</div>
      </Form.Item>
      <IPLocationStatus loading={ipLocationQuery.isPending} failed={ipLocationQuery.isError} resolution={resolution} />
      <Form.Item label={t('editModal.fields.country')} htmlFor="node-ip-location-country">
        <div className="node-ip-location-field">
          <Form.Item name="country" noStyle>
            <Input id="node-ip-location-country" placeholder={t('editModal.placeholders.country')} onChange={() => markManual('country')} />
          </Form.Item>
          <IPLocationSource field="country" manual={manualFields.includes('country')} disabled={pending || uncertain || readOnly}
            onRestore={restoreAutomatic} />
        </div>
      </Form.Item>
      <Form.Item label={t('editModal.fields.province')} htmlFor="node-ip-location-province">
        <div className="node-ip-location-field">
          <Form.Item name="province" noStyle>
            <Input id="node-ip-location-province" placeholder={t('editModal.placeholders.province')} onChange={() => markManual('province')} />
          </Form.Item>
          <IPLocationSource field="province" manual={manualFields.includes('province')} disabled={pending || uncertain || readOnly}
            onRestore={restoreAutomatic} />
        </div>
      </Form.Item>
      <Form.Item label={t('editModal.fields.city')} htmlFor="node-ip-location-city">
        <div className="node-ip-location-field">
          <Form.Item name="city" noStyle>
            <Input id="node-ip-location-city" placeholder={t('editModal.placeholders.city')} onChange={() => markManual('city')} />
          </Form.Item>
          <IPLocationSource field="city" manual={manualFields.includes('city')} disabled={pending || uncertain || readOnly}
            onRestore={restoreAutomatic} />
        </div>
      </Form.Item>
      <Form.Item label={t('editModal.fields.isp')} htmlFor="node-ip-location-isp">
        <div className="node-ip-location-field">
          <Form.Item name="isp" noStyle>
            <Input id="node-ip-location-isp" placeholder={t('editModal.placeholders.isp')} onChange={() => markManual('isp')} />
          </Form.Item>
          <IPLocationSource field="isp" manual={manualFields.includes('isp')} disabled={pending || uncertain || readOnly}
            onRestore={restoreAutomatic} />
        </div>
      </Form.Item>
      <Form.Item label={t('editModal.fields.countryCode')} htmlFor="node-ip-location-country_code">
        <div className="node-ip-location-field">
          <Form.Item name="country_code" noStyle rules={[{ pattern: /^(?:|[A-Za-z]{2})$/ }]}>
            <Input id="node-ip-location-country_code" placeholder={t('editModal.placeholders.countryCode')} onChange={() => markManual('country_code')} />
          </Form.Item>
          <IPLocationSource field="country_code" manual={manualFields.includes('country_code')} disabled={pending || uncertain || readOnly}
            onRestore={restoreAutomatic} />
        </div>
      </Form.Item>
      {formActions()}
    </Form>
  )

  const autoDisableForm = (
    <Form
      form={autoDisableFormInstance}
      className="node-list-edit-form node-list-auto-disable-form"
      layout="horizontal"
      colon={false}
      labelWrap
      labelCol={{ flex: '100px' }}
      wrapperCol={{ flex: 1 }}
      requiredMark={false}
      disabled={pending || uncertain || readOnly}
      onFinish={(values) => onSubmit({
        management_settings: {
          ...item.management_settings,
          auto_disable: {
            bandwidth_limit: values.bandwidth_limit ?? 0,
            bandwidth_unit: values.bandwidth_unit,
            traffic_enabled: values.traffic_enabled,
            traffic_from_day: values.traffic_from_day,
            // empty = the default period start (node.DefaultNodeManagementSettings)
            traffic_from_time: (values.traffic_from_hour ?? '').trim() || '00:00:00',
            traffic_total_gb: values.traffic_total,
            traffic_types: values.traffic_types,
            excluded_interfaces: values.excluded_interfaces.trim(),
            disabled_periods: values.disabled_periods.trim(),
          },
        },
      })}
    >
      <Form.Item label={t('editModal.fields.bandwidthLimit')} htmlFor="node-list-bandwidth-limit">
        <div className="node-list-bandwidth-control">
          <Form.Item name="bandwidth_limit" noStyle rules={[{ type: 'integer', min: 0, max: 1_000_000_000 }]}>
            <InputNumber id="node-list-bandwidth-limit" precision={0} placeholder={t('editModal.placeholders.bandwidthLimit')} />
          </Form.Item>
          <Form.Item name="bandwidth_unit" noStyle>
            <Select
              aria-label={t('editModal.fields.bandwidthLimit')}
              placement="bottomLeft"
              virtual={false}
              listHeight={200}
              popupMatchSelectWidth
              classNames={{ popup: { root: 'node-select-popup node-bandwidth-unit-popup' } }}
              options={[
                { value: 'Mbps', label: 'Mbps' },
                { value: 'Gbps', label: 'Gbps' },
              ]}
            />
          </Form.Item>
        </div>
      </Form.Item>
      <Form.Item name="traffic_enabled" label={t('editModal.fields.trafficLimit')} valuePropName="checked">
        <Switch
          checkedChildren={t('editModal.options.enabled')}
          unCheckedChildren={t('editModal.options.disabled')}
        />
      </Form.Item>
      <Form.Item label={t('editModal.fields.statisticsPeriod')} htmlFor="node-list-traffic-from-day">
        <div className="node-list-traffic-period">
          <span>{t('editModal.options.everyMonth')}</span>
          <Form.Item name="traffic_from_day" noStyle rules={[{ required: true, type: 'number', min: 1, max: 28 }]}>
            <InputNumber id="node-list-traffic-from-day" />
          </Form.Item>
          <span>{t('editModal.options.daySuffix')}</span>
          <Form.Item name="traffic_from_hour" noStyle>
            <Input aria-label={t('editModal.placeholders.startTime')} placeholder={t('editModal.placeholders.startTime')} />
          </Form.Item>
          <span>{t('editModal.options.monthFrom')}</span>
        </div>
      </Form.Item>
      <Form.Item label={t('editModal.fields.trafficTotal')} htmlFor="node-list-traffic-total">
        <div className="node-list-input-addon">
          <Form.Item name="traffic_total" noStyle rules={[{ required: true, type: 'number', min: 0, max: 1_000_000_000 }]}>
            <InputNumber id="node-list-traffic-total" />
          </Form.Item>
          <span>GB</span>
        </div>
      </Form.Item>
      <Form.Item name="traffic_types" label={t('editModal.fields.trafficType')} rules={[{ required: true }]}>
        <Checkbox.Group
          options={[
            { value: 'outbound', label: t('editModal.options.outbound') },
            { value: 'inbound', label: t('editModal.options.inbound') },
          ]}
        />
      </Form.Item>
      <Form.Item name="excluded_interfaces" label={t('editModal.fields.interfaceFilter')}>
        <Input placeholder={t('editModal.placeholders.interfaceFilter')} />
      </Form.Item>
      <Form.Item name="disabled_periods" label={t('editModal.fields.disabledPeriods')} rules={[{
        validator: (_, value: string) => !value || value.trim().split(/\s+/).every((period) => {
          const parts = period.split('-')
          return parts.length === 2 && parts[0] !== parts[1] && parts.every((part) => /^(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(part))
        }) ? Promise.resolve() : Promise.reject(new Error(t('editModal.validation.invalidPeriods'))),
      }]}>
        <Input placeholder={t('editModal.placeholders.disabledPeriods')} />
      </Form.Item>
      <p className="node-list-item-help">{t('editModal.help.autoDisable')}</p>
      {formActions()}
    </Form>
  )

  const subIPForm = (
    <Form
      form={subIPFormInstance}
      className="node-list-edit-form"
      layout="horizontal"
      colon={false}
      labelWrap
      labelCol={{ flex: '80px' }}
      wrapperCol={{ flex: 1 }}
      requiredMark={false}
      disabled={pending || uncertain || readOnly}
      onFinish={(values) => {
        const settings = { ...item.management_settings }
        delete settings.schedule302_hostname
        const hostname = values.schedule302_hostname.trim().toLowerCase().replace(/\.$/u, '')
        onSubmit({
          management_settings: {
            ...settings,
            secondary_ips: values.sub_ips.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
            ...(hostname ? { schedule302_hostname: hostname } : {}),
          },
        })
      }}
    >
      <Form.Item name="sub_ips" label={t('editModal.fields.subIP')} extra={t('editModal.help.subIP')} rules={[{
        validator: (_, value: string) => {
          const addresses = value.split(/\r?\n/).map((address) => address.trim()).filter(Boolean)
          return addresses.length <= 64 && new Set(addresses).size === addresses.length && addresses.every((address) => isIPv4(address) || isIPv6(address))
            ? Promise.resolve()
            : Promise.reject(new Error(t('editModal.validation.invalidSubIPs')))
        },
      }]}>
        <Input.TextArea rows={5} placeholder={t('editModal.placeholders.subIP')} />
      </Form.Item>
      <Form.Item name="schedule302_hostname" label={t('editModal.fields.schedule302Hostname')}
        extra={t('editModal.help.schedule302Hostname')} rules={[{
          validator: (_, value: string | undefined) => {
            const hostname = (value ?? '').trim().toLowerCase().replace(/\.$/u, '')
            return hostname === '' || isSchedule302Hostname(hostname)
              ? Promise.resolve()
              : Promise.reject(new Error(t('editModal.validation.invalidSchedule302Hostname')))
          },
        }]}>
        <Input placeholder="edge-01.cdnca.com" aria-label={t('editModal.fields.schedule302Hostname')} />
      </Form.Item>
      {formActions()}
    </Form>
  )

  return (
    <Modal
      className="node-modal node-list-modal"
      title={t('editModal.title')}
      open={open}
      width={520}
      footer={null}
      onCancel={onCancel}
      destroyOnHidden
    >
      {uncertain ? (
        <Alert
          className="node-modal-alert cdnca-alert-compact"
          type="warning"
          showIcon
          message={t('form.createUnknownTitle')}
          description={t('form.createUnknownDescription')}
        />
      ) : error && !fieldMarked ? <Alert className="node-modal-alert cdnca-alert-compact" type="error" showIcon message={errorMessage(error, t)} /> : null}
      <Tabs
        type="card"
        animated={false}
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'basic', label: t('editModal.tabs.basic'), children: basicForm, forceRender: true },
          { key: 'node', label: t('editModal.tabs.node'), children: nodeForm, forceRender: true },
          { key: 'ip-location', label: t('editModal.tabs.ipLocation'), children: ipLocationForm, forceRender: true },
          { key: 'auto-disable', label: t('editModal.tabs.autoDisable'), children: autoDisableForm, forceRender: true },
          { key: 'sub-ip', label: t('editModal.tabs.subIP'), children: subIPForm, forceRender: true },
        ]}
      />
    </Modal>
  )
}

function NodeFormModal({
  item,
  open,
  pending,
  uncertain,
  error,
  submitError,
  readOnly,
  regionNames,
  regionsLoading,
  onCancel,
  onSubmit,
  onUpdate,
}: {
  item: NodeInventoryItem | null
  open: boolean
  pending: boolean
  uncertain: boolean
  error: ApiError | null
  /** A field refusal of the last create/update, marked on the form. */
  submitError: ApiError | null
  readOnly: boolean
  regionNames: string[]
  regionsLoading: boolean
  onCancel: () => void
  onSubmit: (values: NodeFormValues) => void
  onUpdate: (input: UpdateNodeRequest) => void
}) {
  const { t } = useTranslation('nodes')
  const [form] = Form.useForm<NodeFormValues>()
  const issueToken = Form.useWatch('issue_enrollment_token', form)
  // A create refusal naming a field stays in the open form, marked under it.
  const markSubmitError = useFormSubmitError(form)
  const [fieldMarked, setFieldMarked] = useState(false)
  useEffect(() => {
    setFieldMarked(Boolean(!item && submitError && markSubmitError(submitError)))
  }, [item, markSubmitError, submitError])

  useEffect(() => {
    if (!open) return
    if (item) {
      form.setFieldsValue({
        name: item.name,
        description: item.description,
        region: item.region,
        ipv4: item.ipv4 ?? '',
        ipv6: item.ipv6 ?? '',
      })
      return
    }
    form.resetFields()
    form.setFieldsValue({
      description: '',
      region: '',
      ipv4: '',
      ipv6: '',
      issue_enrollment_token: true,
      enrollment_purpose: 'initial_enrollment',
      enrollment_token_ttl_seconds: 600,
    })
  }, [form, item, open])

  if (item) {
    return (
      <NodeEditModal
        item={item}
        open={open}
        pending={pending}
        uncertain={uncertain}
        error={error}
        submitError={submitError}
        readOnly={readOnly}
        regionNames={regionNames}
        regionsLoading={regionsLoading}
        onCancel={onCancel}
        onSubmit={onUpdate}
      />
    )
  }

  return (
    <Modal
      className="node-modal"
      title={item ? t('form.editTitle') : t('form.addTitle')}
      open={open}
      width={680}
      confirmLoading={pending}
      okButtonProps={{ disabled: uncertain }}
      okText={t('actions.save')}
      cancelText={t('actions.cancel')}
      onCancel={onCancel}
      onOk={() => void form.validateFields().then(onSubmit).catch(() => undefined)}
      destroyOnHidden
    >
      {uncertain ? (
        <Alert
          className="node-modal-alert"
          type="warning"
          showIcon
          message={t('form.createUnknownTitle')}
          description={t('form.createUnknownDescription')}
        />
      ) : error && !fieldMarked ? <Alert className="node-modal-alert" type="error" showIcon message={errorMessage(error, t)} /> : null}
      <Form form={form} layout="vertical" requiredMark={false} disabled={pending || uncertain}>
        <div className="node-form-grid">
          <Form.Item name="name" label={t('form.name')} rules={[{ required: true, whitespace: true, max: 128 }]}>
            <Input placeholder={t('form.namePlaceholder')} />
          </Form.Item>
          <Form.Item name="region" label={t('form.region')} rules={[{ max: 64 }]}>
            <NodeRegionSelect names={regionNames} loading={regionsLoading} />
          </Form.Item>
          <Form.Item name="ipv4" label={t('form.ipv4')} rules={[{
            validator: (_, value: string) => !value || isIPv4(value)
              ? Promise.resolve()
              : Promise.reject(new Error(t('form.invalidIPv4'))),
          }]}>
            <Input placeholder="192.0.2.10" />
          </Form.Item>
          <Form.Item name="ipv6" label={t('form.ipv6')} rules={[{
            validator: (_, value: string) => !value || isIPv6(value)
              ? Promise.resolve()
              : Promise.reject(new Error(t('form.invalidIPv6'))),
          }]}>
            <Input placeholder="2001:db8::10" />
          </Form.Item>
          <Form.Item className="node-form-span" name="description" label={t('form.description')} rules={[{ max: 1024 }]}>
            <Input.TextArea rows={3} placeholder={t('form.descriptionPlaceholder')} />
          </Form.Item>
        </div>
        {!item ? (
          <div className="node-token-fields">
            <Form.Item name="issue_enrollment_token" valuePropName="checked">
              <Checkbox>{t('form.issueToken')}</Checkbox>
            </Form.Item>
            {issueToken ? (
              <div className="node-form-grid">
                <Form.Item name="enrollment_purpose" label={t('form.tokenPurpose')} rules={[{ required: true }]}>
                  <Select
                    placement="bottomLeft"
                    virtual={false}
                    listHeight={200}
                    popupMatchSelectWidth
                    classNames={{ popup: { root: 'node-select-popup node-enrollment-purpose-popup' } }}
                    options={[
                    { value: 'initial_enrollment', label: t('form.initialEnrollment') },
                    { value: 're_enrollment', label: t('form.reEnrollment') },
                    ]}
                  />
                </Form.Item>
                <Form.Item
                  name="enrollment_token_ttl_seconds"
                  label={t('form.ttlSeconds')}
                  rules={[{ required: true, type: 'number', min: 60, max: 86400 }]}
                >
                  <InputNumber min={60} max={86400} precision={0} />
                </Form.Item>
              </div>
            ) : null}
          </div>
        ) : null}
      </Form>
    </Modal>
  )
}

function TokenIssueModal({
  item,
  initialPurpose,
  open,
  pending,
  uncertain,
  error,
  onCancel,
  onSubmit,
}: {
  item: NodeInventoryItem | null
  initialPurpose: EnrollmentPurpose
  open: boolean
  pending: boolean
  uncertain: boolean
  error: ApiError | null
  onCancel: () => void
  onSubmit: (values: TokenFormValues) => void
}) {
  const { t } = useTranslation('nodes')
  const [form] = Form.useForm<TokenFormValues>()
  useEffect(() => {
    if (open) form.setFieldsValue({ purpose: initialPurpose, ttl_seconds: 600 })
  }, [form, initialPurpose, open])
  return (
    <Modal
      className="node-modal"
      title={t('token.issueTitle')}
      open={open}
      width={500}
      confirmLoading={pending}
      okButtonProps={{ disabled: uncertain }}
      okText={t('actions.issue')}
      cancelText={t('actions.cancel')}
      onCancel={onCancel}
      onOk={() => void form.validateFields().then(onSubmit).catch(() => undefined)}
      destroyOnHidden
    >
      <p className="node-modal-target">{item?.name}</p>
      {uncertain ? (
        <Alert
          className="node-modal-alert"
          type="warning"
          showIcon
          message={t('token.issueUnknownTitle')}
          description={t('token.issueUnknownDescription')}
        />
      ) : error ? <Alert className="node-modal-alert" type="error" showIcon message={errorMessage(error, t)} /> : null}
      <Form form={form} layout="vertical" requiredMark={false} disabled={pending || uncertain}>
        <Form.Item name="purpose" label={t('form.tokenPurpose')} rules={[{ required: true }]}>
          <Select
            placement="bottomLeft"
            virtual={false}
            listHeight={200}
            popupMatchSelectWidth
            classNames={{ popup: { root: 'node-select-popup node-token-purpose-popup' } }}
            options={[
            { value: 'initial_enrollment', label: t('form.initialEnrollment') },
            { value: 're_enrollment', label: t('form.reEnrollment') },
            ]}
          />
        </Form.Item>
        <Form.Item name="ttl_seconds" label={t('form.ttlSeconds')} rules={[{ required: true, type: 'number', min: 60, max: 86400 }]}>
          <InputNumber min={60} max={86400} precision={0} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

function TokenResultModal({ token, onClose }: { token: IssuedEnrollmentToken | null; onClose: () => void }) {
  const { t, i18n } = useTranslation('nodes')
  const [messageApi, messageContext] = useFeedbackMessage()
  const copy = async () => {
    if (!token) return
    await navigator.clipboard.writeText(token.token)
    messageApi.success(t('actions.copied'))
  }
  if (!token) return <>{messageContext}</>
  return (
    <>
      {messageContext}
      <Modal
        className="node-modal"
        title={t('token.resultTitle')}
        open
        footer={<Button type="primary" onClick={onClose}>{t('actions.savedToken')}</Button>}
        closable={false}
        maskClosable={false}
      >
        <Alert
          className="node-modal-alert"
          type="warning"
          showIcon
          message={t('token.cannotViewAgain')}
          description={t('token.expiresAt', { date: dateTime(token.expires_at, i18n.resolvedLanguage ?? i18n.language) })}
        />
        <div className="node-token-result">
          <Input.TextArea aria-label={t('token.rawTokenLabel')} value={token.token} readOnly autoSize={{ minRows: 2, maxRows: 3 }} />
          <Tooltip title={t('actions.copyToken')}>
            <Button aria-label={t('actions.copyToken')} icon={<Copy size={16} />} onClick={() => void copy()} />
          </Tooltip>
        </div>
      </Modal>
    </>
  )
}

function InstallNodeModal({ onClose, getAccessToken }: {
  onClose: () => void
  getAccessToken: () => string | null
}) {
  const { t } = useTranslation('nodes')
  const { t: sshT } = useTranslation('nodeSSHInstall')

  return (
    <>
      <Modal
        className="node-modal node-install-modal"
        title={t('install.title')}
        open
        width={860}
        footer={null}
        onCancel={onClose}
        destroyOnHidden
      >
        <Tabs items={[
          { key: 'command', label: sshT('commandTab'), children: <>
            <h4 className="node-install-step">{t('install.commandStep')}</h4>
            <p className="node-install-description">{t('install.description')}</p>
            <NodeInstallCommand getAccessToken={getAccessToken} errorText={(error) => errorMessage(error, t)} />
          </> },
          { key: 'ssh', label: sshT('tab'), children: <NodeSSHInstall getAccessToken={getAccessToken}
            errorText={(error) => error.code === 'ssh_install_in_progress' ? sshT('errors.ssh_install_in_progress') : errorMessage(error, t)} /> },
        ]} />
        <h4 className="node-install-step">{t('install.initializeStep')}</h4>
        <p className="node-install-description">{t('install.initializeDescription')}</p>
        <details className="node-install-description">
          <summary>{t('install.initializeDetailsTitle')}</summary>
          {t('install.initializeDetails')}
        </details>
      </Modal>
    </>
  )
}

// The region picked in the initialize confirmation; the confirm content is
// rendered once, so it reports the choice through onChange.
function InitializeRegionField({ names, initial, onChange }: {
  names: string[]
  initial: string
  onChange: (value: string) => void
}) {
  const { t } = useTranslation('nodes')
  const [value, setValue] = useState(initial)
  return (
    <div className="node-initialize-region">
      <label htmlFor="node-initialize-region">{t('region.label')}</label>
      <NodeRegionSelect id="node-initialize-region" names={names} value={value}
        onChange={(next) => { setValue(next); onChange(next) }} />
      <p className="node-list-item-help">{t('region.initializeHelp')}</p>
    </div>
  )
}

interface RegionBatchResult { id: string; name: string; status: 'updated' | 'failed'; message?: string }

export default function NodeListPage() {
  const { t } = useTranslation('nodes')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken || !principal) return null
  const owner = nodeOwner(principal, sessionEpoch)
  if (!owner || !nodeCanRead(principal)) {
    return (
      <Result
        className="node-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }
  const ownerKey = JSON.stringify(owner)
  return (
    <NodeListContent
      key={ownerKey}
      owner={owner}
      ownerKey={ownerKey}
      canManage={nodeCanManage(principal)}
      canViewLineGroups={principal.permissions.includes('node_scheduling.read')}
    />
  )
}

// Like the reference list, the cell shows only the configured addresses; the
// automatic-report verification state stays in the tooltip and accessible name.
function NodeNetworkAddresses({ item }: { item: NodeInventoryItem }) {
  const { t, i18n } = useTranslation('nodes')
  const describe = (family: 'ipv4' | 'ipv6') => {
    const state = item.network_inventory?.[`${family}_state`] ?? 'legacy'
    const address = item[family] || t('empty.placeholder')
    const label = t('network.addressStatus', { family: family === 'ipv4' ? 'IPv4' : 'IPv6', address, status: t(`network.states.${state}`) })
    const description = [label, t(`network.hints.${state}`), item.network_inventory?.received_at
      ? t('network.receivedAt', { date: formatDateTime(item.network_inventory.received_at, i18n.resolvedLanguage ?? i18n.language) }) : ''].filter(Boolean).join(' ')
    return { label, description }
  }
  const families = (['ipv4', 'ipv6'] as const).filter((family) => item[family])
  if (families.length === 0) {
    const both = (['ipv4', 'ipv6'] as const).map(describe)
    return <div className="node-addresses">
      <Tooltip title={both.map((entry) => entry.description).join(' ')} trigger={['hover', 'focus', 'click']}>
        <span role="note" aria-label={both.map((entry) => entry.label).join(' ')} tabIndex={0}>{t('empty.placeholder')}</span>
      </Tooltip>
    </div>
  }
  return <div className="node-addresses">
    {families.map((family) => {
      const { label, description } = describe(family)
      return <Tooltip key={family} title={description} trigger={['hover', 'focus', 'click']}>
        <span role="note" aria-label={label} tabIndex={0}>{item[family]}</span>
      </Tooltip>
    })}
  </div>
}

function nodeBandwidthState(sample: NodeMetricsLatest | undefined, serverTime: string, startedAt: number, now: number) {
  if (!sample || !sample.known) return { state: 'notReported' as const }
  const initialAge = Date.parse(serverTime) - Date.parse(sample.observed_at)
  const age = Math.max(0, initialAge + Math.max(0, now - startedAt))
  if (initialAge < -5000) return { state: 'clockSkew' as const, age }
  // Host-only sampling is 10s but reaches the server ~14s late and the list
  // polls every 10s, so allow 60s. Probe sampling may be 300s plus a 60s probe;
  // the batch DTO has no interval, so allow that maximum plus 30s delivery.
  if (age > (sample.record_kind === 'host_metric' ? 60_000 : 390_000)) return { state: 'stale' as const, age }
  const selection = sample.telemetry?.network_selection
  if (selection?.source !== 'default_route' || selection.interfaces.length === 0) return { state: 'egressUnknown' as const, age }
  const interfaces = new Map(sample.telemetry!.network_interfaces.map((item) => [item.name, item]))
  let outbound = 0
  let inbound = 0
  for (const name of new Set(selection.interfaces)) {
    const item = interfaces.get(name)
    if (!item) return { state: 'invalid' as const, age }
    outbound += item.tx_bandwidth_bps
    inbound += item.rx_bandwidth_bps
  }
  if (!Number.isSafeInteger(outbound) || !Number.isSafeInteger(inbound)) return { state: 'invalid' as const, age }
  return { state: 'available' as const, age, outbound, inbound, interfaces: selection.interfaces.join(', ') }
}

function NodeBandwidthCell({ sample, serverTime, startedAt, now, error }: {
  sample?: NodeMetricsLatest
  serverTime?: string
  startedAt: number
  now: number
  error: unknown
}) {
  const { t, i18n } = useTranslation('nodes')
  const locale = i18n.resolvedLanguage ?? i18n.language
  const result = serverTime ? nodeBandwidthState(sample, serverTime, startedAt, now) : { state: 'loading' as const }
  const state = error ? (error instanceof ApiError && error.status === 404 ? 'notFound'
    : error instanceof ApiError && ['invalid_response', 'validation_error'].includes(error.code ?? '') ? 'invalid' : 'unavailable') : result.state
  const description = sample ? [
    t('bandwidth.sampleTime', { time: formatDateTime(sample.observed_at, locale) }),
    'age' in result ? t('bandwidth.sampleAge', { seconds: formatNumber(Math.floor((result.age ?? 0) / 1000), locale) }) : '',
    result.state === 'available' ? t('bandwidth.interfaces', { names: result.interfaces }) : '',
  ].filter(Boolean).join(' · ') : t(`bandwidth.${state}`)
  return <Tooltip title={description} trigger={['hover', 'focus', 'click']}>
    <span className="node-bandwidth" tabIndex={0}>
      {state === 'available' && result.state === 'available' ? <>
        <span className="node-bandwidth-outbound" aria-label={t('bandwidth.outbound', { value: formatBandwidth(result.outbound!, locale) })}>
          {formatBandwidth(result.outbound!, locale)}<ArrowUp size={12} aria-hidden="true" />
        </span>
        <span className="node-bandwidth-inbound" aria-label={t('bandwidth.inbound', { value: formatBandwidth(result.inbound!, locale) })}>
          {formatBandwidth(result.inbound!, locale)}<ArrowDown size={12} aria-hidden="true" />
        </span>
      </> : <span className="node-bandwidth-state">{t(`bandwidth.${state}`)}</span>}
    </span>
  </Tooltip>
}

/** The node's XDP filter mode from its latest sample, with the reason when it falls back. */
export function NodeXDPCell({ sample }: { sample?: NodeMetricsLatest }) {
  const { t, i18n } = useTranslation('nodes')
  const status = sample?.known ? sample.telemetry?.xdp : undefined
  const protection = sample?.known ? sample.telemetry?.ddos_protection : undefined
  // A DDoS table that failed to apply or cannot run is a protection fault,
  // shown before the XDP mode.
  if (protection && (protection.state === 'failed' || protection.state === 'unavailable')) {
    const reason = protection.state === 'unavailable' ? t(`ddosProtection.reasons.${protection.reason}`) : t('ddosProtection.failedHint')
    const lines = [reason, protection.detail ? t('xdp.detail', { detail: protection.detail }) : '']
    return <Tooltip title={lines.filter(Boolean).join(' · ')} trigger={['hover', 'focus', 'click']}>
      <span className={`node-xdp-state node-ddos-${protection.state}`} tabIndex={0} role="status">
        {t(`ddosProtection.states.${protection.state}`)}
      </span>
    </Tooltip>
  }
  if (!status) return <span className="node-xdp-state">{t('xdp.notReported')}</span>
  const locale = i18n.resolvedLanguage ?? i18n.language
  const attached = status.mode === 'native' || status.mode === 'generic'
  const drops = status.drops ?? []
  const lines = attached ? [
    t('xdp.interfaces', { names: (status.interfaces ?? []).map((nic) => {
      const [name, mode] = nic.split('=')
      return `${name} (${t(`xdp.modes.${mode}`)})`
    }).join(', ') }),
    drops.length === 0 ? t('xdp.noDrops') : t('xdp.drops', {
      summary: drops.map((drop) => `${t(`xdp.kinds.${drop.kind}`)} ${formatNumber(drop.packets, locale)}`).join(' / '),
    }),
  ] : [
    t('xdp.fallback', { reason: t(`xdp.reasons.${status.reason}`) }),
    status.detail ? t('xdp.detail', { detail: status.detail }) : '',
  ]
  return <Tooltip title={lines.filter(Boolean).join(' · ')} trigger={['hover', 'focus', 'click']}>
    <span className={`node-xdp-state node-xdp-${status.mode}`} tabIndex={0}>
      {t(`xdp.modes.${status.mode}`)}
      {status.mode === 'nftables' ? <span className="node-xdp-reason">{t('xdp.reasonInline', { reason: t(`xdp.short.${status.reason}`) })}</span> : null}
    </span>
  </Tooltip>
}

// 月流量 shows the period's accumulated bytes whenever two counter points
// exist (as the competitor's column does); data gaps and counter restarts are
// explained in the tooltip, restarts also by a small badge.
function NodeMonthlyTrafficCell({ sample }: { sample?: NodeMetricsLatest }) {
  const { t, i18n } = useTranslation('nodes')
  const monthly = sample?.monthly_traffic
  if (!monthly) return <span className="node-monthly-traffic-state">{t('monthlyTraffic.states.unavailable')}</span>
  if (monthly.state === 'insufficient_data') {
    return <Tooltip title={t('monthlyTraffic.stateHint', { state: t('monthlyTraffic.states.insufficient_data') })}>
      <span className="node-monthly-traffic-state" tabIndex={0}>{t('monthlyTraffic.states.insufficient_data')}</span>
    </Tooltip>
  }
  const locale = i18n.resolvedLanguage ?? i18n.language
  const resets = monthly.counter_resets ?? (monthly.state === 'counter_reset' ? 1 : 0)
  const hint = [
    t('monthlyTraffic.sampleHint', { period: monthly.period_key, timezone: monthly.timezone }),
    monthly.state === 'available' || monthly.state === 'counter_reset' ? '' : t('monthlyTraffic.stateHint', { state: t(`monthlyTraffic.states.${monthly.state}`) }),
    resets > 0 ? t('monthlyTraffic.resetHint', { count: resets }) : '',
  ].filter(Boolean).join(' ')
  return <Tooltip title={hint} trigger={['hover', 'focus', 'click']}>
    <span className="node-monthly-traffic-value" tabIndex={0}>
      {formatBytes(monthly.usage_bytes, locale)}
      {resets > 0 ? <span className="node-monthly-traffic-reset" role="img" aria-label={t('monthlyTraffic.resetBadge', { count: resets })}>
        <RotateCcw size={11} aria-hidden="true" />
      </span> : null}
    </span>
  </Tooltip>
}

function nodeMonitoringState(batch: NodeMonitoringLatestBatch | undefined, item: NodeMonitoringLatest | undefined, startedAt: number, now: number) {
  if (!batch || !item) return { state: 'loading' as const, age: null, sampleState: null }
  const initialAge = item.sample ? Date.parse(batch.observed_at) - Date.parse(item.sample.observed_at) : null
  const age = initialAge === null ? null : Math.max(0, initialAge + Math.max(0, now - startedAt))
  const sampleState = !item.sample ? 'notReported'
    : item.freshness === 'clock_skew' || initialAge! < -5000 ? 'clockSkew'
      : item.revision_state === 'rolled_back' ? 'rolledBack'
        : item.revision_state !== 'current' ? 'oldConfiguration'
          : item.freshness !== 'fresh' || age! > item.stale_after_ms! ? 'stale'
            : item.sample.healthy ? 'healthy' : 'unhealthy'
  const result = { age, sampleState }
  const config = batch.configuration
  if (config.state === 'unconfigured') return { ...result, state: 'unconfigured' as const }
  if (config.state === 'not_activated') return { ...result, state: 'notActivated' as const }
  if (config.head_revision > config.active_revision!) return { ...result, state: 'savedNotActivated' as const }
  // The control plane delivers the active policy only to enabled nodes that
  // serve a signed configuration; any older sample is not current monitoring.
  if (item.delivery_state === 'awaiting_configuration') return { ...result, state: 'awaitingConfiguration' as const }
  if (item.delivery_state === 'inactive') return { ...result, state: 'nodeInactive' as const }
  // A saved disabled policy is not proof that the Agent stopped probing. The
  // state becomes stopped only after the durable host-sample receipt matches
  // the active configuration revision.
  if (!(item.effective_policy ?? config.policy!).enabled) {
    const receipt = item.apply_receipt
    if (receipt?.state === 'applied' && receipt.config_revision === String(item.effective_revision ?? config.active_revision)) {
      return { ...result, state: 'disabled' as const }
    }
    return { ...result, state: 'disablePending' as const }
  }
  return { ...result, state: sampleState }
}

const monitorTone = {
  healthy: 'success', unhealthy: 'danger', stale: 'danger', clockSkew: 'danger', rolledBack: 'danger',
  notReported: 'pending', oldConfiguration: 'pending', savedNotActivated: 'pending',
  awaitingConfiguration: 'pending', nodeInactive: 'pending',
} as const

function NodeMonitoringCell({ batch, item, startedAt, now, error, onConfigure, onLog, onServingLog }: {
  batch?: NodeMonitoringLatestBatch
  item?: NodeMonitoringLatest
  startedAt: number
  now: number
  error: unknown
  onConfigure: () => void
  onLog: () => void
  onServingLog: () => void
}) {
  const { t, i18n } = useTranslation('nodes')
  const locale = i18n.resolvedLanguage ?? i18n.language
  const result = nodeMonitoringState(batch, item, startedAt, now)
  const state = error ? (error instanceof ApiError && error.status === 404 ? 'notFound'
    : error instanceof ApiError && ['invalid_response', 'validation_error'].includes(error.code) ? 'invalid' : 'unavailable') : result.state
  const sample = item?.sample
  const config = batch?.configuration
  // A node override replaces the platform policy for this node only.
  const effectivePolicy = item?.effective_policy ?? config?.policy
  const details = [
    t(`monitor.states.${state}`),
    config ? t('monitor.revisions', { head: formatNumber(config.head_revision, locale),
      active: config.active_revision === null ? t('monitor.noActive') : formatNumber(config.active_revision, locale) }) : '',
    effectivePolicy ? t('monitor.requestedProtocol', { protocol: t(`monitor.protocols.${effectivePolicy.requested_protocol}`) }) : '',
    item?.effective_revision ? t('monitor.nodeOverride', { revision: formatNumber(item.effective_revision, locale) }) : '',
    sample ? t('monitor.source') : '',
    sample ? t('monitor.scopeHint') : '',
    sample && !error ? t('monitor.sampleState', { state: t(`monitor.states.${result.sampleState}`) }) : '',
    sample ? t('monitor.probePort', { port: formatNumber(sample.probe_port, locale) }) : '',
    sample ? t('monitor.sampleTime', { time: formatDateTime(sample.observed_at, locale) }) : '',
    result.age !== null ? t('monitor.sampleAge', { seconds: formatNumber(Math.floor(result.age / 1000), locale) }) : '',
    sample ? t('monitor.sampleRevision', { config: formatNumber(sample.config_revision, locale), active: formatNumber(sample.active_config_revision, locale) }) : '',
    sample ? t('monitor.publication', { sequence: sample.publication_sequence }) : '',
    sample ? t('monitor.lastProbe', { result: t(sample.probe_succeeded ? 'monitor.succeeded' : 'monitor.failed') }) : '',
    state === 'disablePending' ? t('monitor.disableHint') : '',
    state === 'awaitingConfiguration' ? t('monitor.awaitingConfigurationHint') : '',
    state === 'nodeInactive' ? t('monitor.nodeInactiveHint') : '',
  ].filter(Boolean).join(' · ')
  const holds = error ? [] : item?.serving_holds ?? []
  const protectedGroups = Math.max(0, ...holds.map((hold) => hold.protected_groups))
  const holdDetails = [
    ...holds.map((hold) => t('monitor.pausedHint', {
      source: t(`monitorLog.servingSources.${hold.source}`),
      reason: t(`monitorLog.servingReasons.${hold.reason_code}`, { defaultValue: hold.reason_code }),
      time: formatDateTime(hold.held_since, locale),
    })),
    protectedGroups > 0 ? t('monitor.pausedProtectedHint', { count: protectedGroups }) : '',
  ].filter(Boolean).join(' · ')
  // Reference: a paused node is marked next to its monitoring; it opens the pause log.
  const paused = holds.length > 0 ? <Tooltip title={holdDetails} trigger={['hover', 'focus', 'click']}>
    <button type="button" className="node-monitor-link node-monitor-paused" aria-label={holdDetails} onClick={onServingLog}>
      {t(protectedGroups > 0 ? 'monitor.pausedProtected' : 'monitor.paused')}
    </button>
  </Tooltip> : null
  // Reference layout: "<protocol> [日志]" for an active policy, "未配置" otherwise.
  // Health is carried by the tone class and the tooltip, never by fabricated text.
  const policy = state in monitorTone ? effectivePolicy : undefined
  const tone = policy ? monitorTone[state as keyof typeof monitorTone] : undefined
  // Reference behaviour: the protocol opens the node's "配置监控" dialog and
  // "[日志]" opens its availability log, both in place.
  const content = policy ? <>
    <button type="button" className="node-monitor-link node-monitor-protocol" onClick={onConfigure}>{policy.requested_protocol}</button>
    <button type="button" className="node-monitor-link" onClick={onLog}>{t('monitor.log')}</button>
  </> : state === 'unconfigured' || state === 'notActivated'
    ? <Link to="/node/monitor-setting">{state === 'unconfigured' ? t('monitor.notConfigured') : t(`monitor.states.${state}`)}</Link>
    : <span>{t(`monitor.states.${state}`)}</span>
  // Only the TCP probe actually runs; a requested HTTP/Ping policy is never shown as healthy.
  const toneClass = tone === 'success' && policy?.requested_protocol !== 'tcp' ? 'pending' : tone
  return <div className="node-monitor-cell-stack">
    <Tooltip title={details} trigger={['hover', 'focus', 'click']}>
      <div className={`node-monitor-cell${toneClass ? ` is-${toneClass}` : ''}`} data-state={state} style={{ maxWidth: '100%' }}
        role="group" tabIndex={0} aria-label={details} title={details}>
        {content}
      </div>
    </Tooltip>
    {paused}
  </div>
}

function NodeListContent({
  owner,
  ownerKey,
  canManage,
  canViewLineGroups,
}: {
  owner: NodeOwner
  ownerKey: string
  canManage: boolean
  canViewLineGroups: boolean
}) {
  const { t, i18n } = useTranslation('nodes')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [confirm, confirmContext] = Modal.useModal()
  const queryOwner = useRef(owner).current
  const lineageActiveRef = useRef(true)
  const retryOwner = useMemo<NodeUpdateRetryOwner>(() => ['platform', owner[1], owner[3]], [owner])
  const [restoredUpdate] = useState(() => restoreNodeUpdateRetry(retryOwner))
  const [updateRecord, setUpdateRecord] = useState(restoredUpdate.record)
  const [updateStorageBlocked, setUpdateStorageBlocked] = useState(restoredUpdate.blocked)
  const updateSending = useRef(false)
  const updateReading = useRef(false)
  const [readingUpdate, setReadingUpdate] = useState(false)
  const [status, setStatus] = useState<NodeAdminState>()
  const [nodeTab, setNodeTab] = useState<NodeListTab>('list')
  const [presence, setPresence] = useState<NodePresenceStatus>()
  const [searchParams] = useSearchParams()
  // ?region=unset (the line-resolution "去设置" link) lists nodes without a region.
  const [region, setRegion] = useState(() => searchParams.get('region') === 'unset' ? unsetRegionFilter : '')
  const [limit, setLimit] = useState(10)
  const [cursorHistory, setCursorHistory] = useState<Array<string | undefined>>([undefined])
  const [pageIndex, setPageIndex] = useState(0)
  const [searchDraft, setSearchDraft] = useState('')
  const [search, setSearch] = useState('')
  const [installOpen, setInstallOpen] = useState(false)
  const [editing, setEditing] = useState<NodeInventoryItem | null>(null)
  const [batchMonitorNodes, setBatchMonitorNodes] = useState<{ id: string; name: string }[] | null>(null)
  const [monitorModal, setMonitorModal] = useState<{ kind: 'config' | 'log'; nodeID: string; logType?: 'aval' | 'serving' } | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [createUnknown, setCreateUnknown] = useState(false)
  const [tokenNode, setTokenNode] = useState<NodeInventoryItem | null>(null)
  const [tokenModalOpen, setTokenModalOpen] = useState(false)
  const [tokenPurpose, setTokenPurpose] = useState<EnrollmentPurpose>('re_enrollment')
  const [tokenUnknown, setTokenUnknown] = useState(false)
  const [issuedToken, setIssuedToken] = useState<IssuedEnrollmentToken | null>(null)
  const [selectedKeys, setSelectedKeys] = useState<React.Key[]>([])
  const [portBatch, setPortBatch] = useState<{ token: string, nodes: Array<{ id: string, name: string, revision: number }> } | null>(null)
  const [batchOpen, setBatchOpen] = useState(false)
  const [batchTarget, setBatchTarget] = useState<ManagedNodeAdminState>()
  const [batchResults, setBatchResults] = useState<BatchNodeAdminStateItemResult[] | null>(null)
  const [batchResultAttempt, setBatchResultAttempt] = useState<BatchAttempt | null>(null)
  const [regionBatchOpen, setRegionBatchOpen] = useState(false)
  const [regionBatchValue, setRegionBatchValue] = useState('')
  const [regionBatchPending, setRegionBatchPending] = useState(false)
  const [regionBatchResults, setRegionBatchResults] = useState<RegionBatchResult[] | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  // A create/update refusal naming a field: the form stays open with it marked.
  const [fieldError, setFieldError] = useState<ApiError | null>(null)
  const [retryAttempt, setRetryAttempt] = useState<RetryAttempt | null>(() => restoredUpdate.record?.phase === 'unknown'
    ? { kind: 'update', request: restoredUpdate.record.attempt, replay: true, ownerKey } : null)
  const [terminalForbidden, setTerminalForbidden] = useState(false)
  const createResultsRef = useRef(new WeakMap<CreateAttempt, Awaited<ReturnType<typeof nodesApi.create>>>())
  const tokenResultsRef = useRef(new WeakMap<TokenAttempt, IssuedEnrollmentToken>())
  const writeLocked = retryAttempt !== null || updateRecord !== null || updateStorageBlocked
  const openTokenIssue = (item: NodeInventoryItem, purpose: EnrollmentPurpose) => {
    setWriteError(null)
    setTokenPurpose(purpose)
    setTokenNode(item)
    setTokenModalOpen(true)
  }
  const allStateOptions = (Object.keys(stateMeta) as NodeAdminState[])
    .map((value) => ({ value, label: t(`states.${value}`) }))
  // Deleted nodes are removed, so "retired" is not a list filter.
  const stateOptions = allStateOptions.filter((option) => option.value !== 'retired')
  const managedStateOptions = allStateOptions.filter(
    (option): option is { value: ManagedNodeAdminState; label: string } => option.value !== 'pending',
  )
  const presenceOptions = (Object.keys(presenceMeta) as NodePresenceStatus[])
    .map((value) => ({ value, label: t(`presence.${value}`) }))

  const queryPrefix = useMemo(() => ['nodes', ...queryOwner] as const, [queryOwner])
  const bandwidthPrefix = useMemo(() => ['node-bandwidth', ...queryOwner] as const, [queryOwner])
  const monitoringPrefix = useMemo(() => ['node-monitoring', ...queryOwner] as const, [queryOwner])
  const mutationPrefix = useMemo(() => ['nodes-write', ...queryOwner] as const, [queryOwner])
  const currentSessionAccess = useCallback((permission: NodePermission) => (
    lineageActiveRef.current ? currentNodeAccess(ownerKey, permission) : null
  ), [ownerKey])
  const targetScopeID = queryOwner[1]
  const lineGroupsQueryKey = useMemo(
    () => ['node-line-groups', ...queryOwner, 'platform', targetScopeID] as const,
    [queryOwner, targetScopeID],
  )
  const lineGroupsQuery = useQuery({
    queryKey: lineGroupsQueryKey,
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw staleNodeRead
      return nodeSchedulingApi.list(token, { kind: 'platform', targetScopeId: targetScopeID })
    },
    enabled: canViewLineGroups && nodeTab !== 'regions',
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const lineGroupCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const group of lineGroupsQuery.data?.items ?? []) {
      for (const name of [group.region, ...(group.endpoints ?? []).map((endpoint) => endpoint.region)]) {
        const key = (name ?? '').trim()
        if (!key) continue
        counts.set(key, (counts.get(key) ?? 0) + 1)
      }
    }
    return counts
  }, [lineGroupsQuery.data?.items])
  const cursor = cursorHistory[pageIndex]
  const queryKey = useMemo(
    () => [...queryPrefix, 'management_sort_desc', status ?? '', presence ?? '', limit, cursor ?? ''] as const,
    [cursor, limit, presence, queryPrefix, status],
  )
  const queryIdentity = JSON.stringify(queryKey)
  const activeQueryIdentityRef = useRef(queryIdentity)
  activeQueryIdentityRef.current = queryIdentity
  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw staleNodeRead
      try {
        const result = await nodesApi.list(token, { order: 'management_sort_desc', status, presence, limit, cursor })
        if (!currentSessionAccess('read') || activeQueryIdentityRef.current !== queryIdentity) throw staleNodeRead
        return result
      } catch (error) {
        if (!currentSessionAccess('read') || activeQueryIdentityRef.current !== queryIdentity) throw staleNodeRead
        if (error instanceof ApiError && error.status === 403) denyCurrentOwner()
        throw error
      }
    },
    enabled: !terminalForbidden && nodeTab !== 'regions',
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  // Read the catalog only when a region is shown or picked: a node without a
  // region is listed (unset mark, initialize), or a node form is open.
  const needsRegionCatalog = formOpen || regionBatchOpen ||
    (query.data?.items ?? []).some((item) => !item.region.trim())
  const regionCatalog = useRegionCatalogNames(ownerKey, canManage && !terminalForbidden && needsRegionCatalog)
  const regionNames = useMemo(() => regionCatalog.data ?? [], [regionCatalog.data])
  const regions = useMemo(() => [...new Set((query.data?.items ?? [])
    .map((item) => item.region.trim())
    .filter(Boolean))].sort((left, right) => left.localeCompare(right)), [query.data?.items])

  const removeOwnerCache = useCallback(() => {
    queryClient.removeQueries({ queryKey: queryPrefix })
    queryClient.removeQueries({ queryKey: bandwidthPrefix })
    queryClient.removeQueries({ queryKey: monitoringPrefix })
    const mutationCache = queryClient.getMutationCache()
    for (const mutation of mutationCache.findAll({ mutationKey: mutationPrefix })) mutationCache.remove(mutation)
  }, [bandwidthPrefix, monitoringPrefix, mutationPrefix, queryClient, queryPrefix])

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentNodeAccess(ownerKey, 'read')) {
        removeOwnerCache()
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) removeOwnerCache()
      })
    }
  }, [ownerKey, removeOwnerCache])

  useEffect(() => setSelectedKeys([]), [cursor, limit, presence, region, status])

  const visibleItems = useMemo(() => {
    const items = query.data?.items ?? []
    const needle = search.trim().toLocaleLowerCase()
    return items.filter((item) => (!region || item.region.trim() === (region === unsetRegionFilter ? '' : region)) && (
      !needle || [item.name, item.description, item.region, item.ipv4, item.ipv6, item.presence.agent_version]
        .some((value) => value?.toLocaleLowerCase().includes(needle))
    ))
  }, [query.data?.items, region, search])

  const bandwidthIDs = useMemo(() => (query.data?.items ?? []).map((item) => item.id), [query.data?.items])
  const bandwidthKey = useMemo(() => [...bandwidthPrefix, queryIdentity, bandwidthIDs] as const, [bandwidthIDs, bandwidthPrefix, queryIdentity])
  const bandwidthIdentity = JSON.stringify([bandwidthKey, nodeTab])
  const activeBandwidthIdentity = useRef(bandwidthIdentity)
  activeBandwidthIdentity.current = bandwidthIdentity
  const bandwidthEnabled = !terminalForbidden && nodeTab === 'list' && query.isSuccess && bandwidthIDs.length > 0
  const bandwidthQuery = useQuery({
    queryKey: bandwidthKey,
    queryFn: async ({ signal }) => {
      const token = currentSessionAccess('read')
      if (!token || activeBandwidthIdentity.current !== bandwidthIdentity) throw staleNodeRead
      const startedAt = performance.now()
      try {
        const result = await nodesApi.getLatestMetricsBatch(token, bandwidthIDs, signal)
        if (!currentSessionAccess('read') || activeBandwidthIdentity.current !== bandwidthIdentity) throw staleNodeRead
        return { result, startedAt }
      } catch (error) {
        if (!currentSessionAccess('read') || activeBandwidthIdentity.current !== bandwidthIdentity) throw staleNodeRead
        if (error instanceof ApiError && error.status === 403) denyCurrentOwner()
        throw error
      }
    },
    enabled: bandwidthEnabled,
    retry: false,
    refetchInterval: bandwidthEnabled ? 10_000 : false,
    refetchIntervalInBackground: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const [bandwidthClock, setBandwidthClock] = useState(() => performance.now())
  useEffect(() => {
    // Cached samples remain visible after an inventory refresh error.
    if (terminalForbidden || nodeTab !== 'list' || bandwidthIDs.length === 0) return
    const timer = window.setInterval(() => setBandwidthClock(performance.now()), 1000)
    return () => window.clearInterval(timer)
  }, [bandwidthIDs.length, nodeTab, terminalForbidden])
  const bandwidthMetrics = useMemo(() => new Map(bandwidthQuery.data?.result.items.map((item) => [item.node_id, item])), [bandwidthQuery.data])

  const monitoringKey = useMemo(() => [...monitoringPrefix, queryIdentity, bandwidthIDs] as const, [bandwidthIDs, monitoringPrefix, queryIdentity])
  const monitoringIdentity = JSON.stringify([monitoringKey, nodeTab])
  const activeMonitoringIdentity = useRef(monitoringIdentity)
  activeMonitoringIdentity.current = monitoringIdentity
  const monitoringQuery = useQuery({
    queryKey: monitoringKey,
    queryFn: async ({ signal }) => {
      const token = currentSessionAccess('read')
      if (!token || activeMonitoringIdentity.current !== monitoringIdentity) throw staleNodeRead
      const startedAt = performance.now()
      try {
        const result = await nodeMonitoringApi.getLatest(token, bandwidthIDs, signal)
        if (!currentSessionAccess('read') || activeMonitoringIdentity.current !== monitoringIdentity) throw staleNodeRead
        return { result, startedAt }
      } catch (error) {
        if (!currentSessionAccess('read') || activeMonitoringIdentity.current !== monitoringIdentity) throw staleNodeRead
        if (error instanceof ApiError && error.status === 403) denyCurrentOwner()
        throw error
      }
    },
    enabled: bandwidthEnabled,
    retry: false,
    refetchInterval: bandwidthEnabled ? 10_000 : false,
    refetchIntervalInBackground: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const monitoringItems = useMemo(() => new Map(monitoringQuery.data?.result.items.map((item) => [item.node_id, item])), [monitoringQuery.data])

  // Frozen nodes (expired service ticket) are tagged in the
  // status column; a failed read only leaves the tag out.
  const ticketKey = useMemo(() => [...monitoringPrefix, 'installation-tickets', queryIdentity, bandwidthIDs] as const,
    [bandwidthIDs, monitoringPrefix, queryIdentity])
  const ticketQuery = useQuery({
    queryKey: ticketKey,
    queryFn: async ({ signal }) => {
      const token = currentSessionAccess('read')
      if (!token) throw staleNodeRead
      const result = await nodeInstallationTicketsApi.get(token, bandwidthIDs, signal)
      if (!currentSessionAccess('read')) throw staleNodeRead
      return result
    },
    enabled: bandwidthEnabled,
    retry: false,
    refetchInterval: bandwidthEnabled ? 60_000 : false,
    refetchIntervalInBackground: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const ticketItems = useMemo(() => new Map(ticketQuery.data?.items.map((item) => [item.node_id, item])), [ticketQuery.data])

  const selectedItems = useMemo(() => {
    const keys = new Set(selectedKeys.map(String))
    return (query.data?.items ?? []).filter((item) => keys.has(item.id))
  }, [query.data?.items, selectedKeys])

  const batchTargets = useMemo(() => {
    if (selectedItems.length === 0) return []
    return allowedTargets(selectedItems[0].admin_state).filter((target) =>
      selectedItems.every((item) => allowedTargets(item.admin_state).includes(target)),
    )
  }, [selectedItems])

  // C38/ND04: status changes (no delete) every selected node allows, and why a
  // target is not available; every entry point uses these.
  const batchStatusTargets: ManagedNodeAdminState[] = batchTargets.filter((target) => target !== 'retired')
  const blockedReason = (target: ManagedNodeAdminState): string | undefined => {
    if (selectedItems.length === 0) return t('batch.selectFirst')
    if (batchTargets.includes(target)) return undefined
    if (selectedItems.some((item) => item.admin_state === 'pending')) return t('batch.pendingFirst')
    return t('batch.notAllowed', { state: stateLabel(target, t) })
  }

  const resetPagination = () => {
    setCursorHistory([undefined])
    setPageIndex(0)
  }

  const refreshNodes = () => queryClient.invalidateQueries({ queryKey: queryPrefix })

  const handleKnownConflict = (error: ApiError) => {
    if (error.code === 'version_conflict') void refreshNodes()
  }

  const denyCurrentOwner = useCallback(() => {
    lineageActiveRef.current = false
    setTerminalForbidden(true)
    setInstallOpen(false)
    setEditing(null)
    setFormOpen(false)
    setCreateUnknown(false)
    setTokenNode(null)
    setTokenModalOpen(false)
    setTokenUnknown(false)
    setIssuedToken(null)
    setSelectedKeys([])
    setBatchOpen(false)
    setBatchTarget(undefined)
    setBatchResults(null)
    setBatchResultAttempt(null)
    setWriteError(null)
    setRetryAttempt(null)
    queueMicrotask(removeOwnerCache)
  }, [removeOwnerCache])

  useEffect(() => {
    if (query.error instanceof ApiError && query.error.status === 403 && currentSessionAccess('read')) {
      denyCurrentOwner()
    }
  }, [currentSessionAccess, denyCurrentOwner, query.error])

  const readbackNodeUpdate = async (record: NodeUpdateRetryRecord) => {
    if (record.phase !== 'readback' || updateReading.current || updateStorageBlocked) return
    const token = currentSessionAccess('manage')
    if (!token) return
    updateReading.current = true
    setReadingUpdate(true)
    try {
      if (record.attempt.input.admin_state === 'retired') {
        // A17：删除是物理删除，对象 GET 必然 404，不能走修改回读。v2 记录只在删除回执校验通过后写入；
        // 旧 v1 记录用同幂等键、同请求体重放取原回执再确认，不接受任意 404 当成删除成功。
        if (record.version !== 2) {
          const { item, input, key } = record.attempt
          const replayed = await nodesApi.update(token, item, input, key)
          if (!currentSessionAccess('manage')) return
          if (!deleteAcknowledged(item, replayed) || replayed.revision !== record.confirmedRevision) {
            throw new ApiError('Invalid node delete acknowledgement', 200, 'invalid_response')
          }
        }
        if (!clearNodeUpdateRetry(retryOwner, record.attempt)) {
          setUpdateStorageBlocked(true)
          return
        }
        const deletedID = record.attempt.item.id
        setSelectedKeys((keys) => keys.filter((key) => key !== deletedID))
        setUpdateRecord(null)
        setRetryAttempt(null)
        setWriteError(null)
        messageApi.success(t('notices.deleted'))
        try {
          await queryClient.invalidateQueries({ queryKey: queryPrefix }, { throwOnError: true })
        } catch {
          // 删除已确认；列表刷新失败只给只读刷新入口（列表错误提示自带重试），不再锁写入。
          if (currentSessionAccess('manage')) feedback.warning(t('notices.deletedListFailed'))
        }
        return
      }
      const saved = await nodesApi.get(token, record.attempt.item.id)
      if (!currentSessionAccess('manage')) return
      if (saved.revision < Number(record.confirmedRevision)) throw new ApiError('Stale node readback', 200, 'invalid_response')
      if (record.attempt.input.management_settings) {
        // A sort write can move this node across the old keyset boundary.
        // Confirm a fresh first page, never refetch the obsolete cursor.
        await queryClient.cancelQueries({ queryKey: queryPrefix })
        await queryClient.invalidateQueries({ queryKey: queryPrefix, refetchType: 'none' })
        await queryClient.fetchQuery({
          queryKey: [...queryPrefix, 'management_sort_desc', status ?? '', presence ?? '', limit, ''],
          queryFn: async () => {
            const readToken = currentSessionAccess('read')
            if (!readToken) throw staleNodeRead
            const firstPage = await nodesApi.list(readToken, { order: 'management_sort_desc', status, presence, limit })
            if (!currentSessionAccess('read')) throw staleNodeRead
            return firstPage
          },
          retry: false,
          staleTime: 0,
        })
        if (!currentSessionAccess('manage')) return
        resetPagination()
      } else {
        await queryClient.invalidateQueries({ queryKey: queryPrefix }, { throwOnError: true })
      }
      if (!currentSessionAccess('manage')) return
      if (!clearNodeUpdateRetry(retryOwner, record.attempt)) {
        setUpdateStorageBlocked(true)
        return
      }
      setUpdateRecord(null)
      setRetryAttempt(null)
      setWriteError(null)
      messageApi.success(record.attempt.input.admin_state
          ? t('notices.stateUpdated', { state: t(`states.${record.attempt.input.admin_state}`) })
          : t('notices.updated'))
    } catch (error) {
      if (!currentSessionAccess('manage')) return
      if (error instanceof ApiError && error.status === 403) denyCurrentOwner()
      else setWriteError(error instanceof ApiError ? error : new ApiError(t('errors.requestFailed')))
    } finally {
      updateReading.current = false
      if (currentSessionAccess('manage')) setReadingUpdate(false)
    }
  }

  const updateMutation = useMutation({
    mutationKey: [...mutationPrefix, 'update'],
    mutationFn: async (attempt: UpdateAttempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('manage') : null
      if (!token) throw staleNodeWrite
      try {
        const { item, input, key } = attempt.request
        const result = await nodesApi.update(token, item, input, key)
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        if (result.revision <= item.revision) throw new ApiError('Invalid node write revision', 200, 'invalid_response')
        if (input.admin_state === 'retired' && !deleteAcknowledged(item, result)) {
          throw new ApiError('Invalid node delete acknowledgement', 200, 'invalid_response')
        }
        return result
      } catch (error) {
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        throw error
      }
    },
    onSuccess: async (result, attempt) => {
      if (attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      const record = persistNodeUpdateRetry(retryOwner, attempt.request, result.revision)
      setRetryAttempt(null)
      setWriteError(null)
      setEditing(null)
      setFormOpen(false)
      if (!record) {
        setUpdateStorageBlocked(true)
        return
      }
      setUpdateRecord(record)
      await readbackNodeUpdate(record)
    },
    onError: (error, attempt) => {
      if (error === staleNodeWrite || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.updateFailed'))
      if (apiError.status === 403) {
        denyCurrentOwner()
        return
      }
      const unknown = attempt.replay || writeOutcomeUnknown(error) || apiError.code === 'invalid_response' || apiError.status === 429
      let cleared = false
      if (unknown) setRetryAttempt({ ...attempt, replay: true })
      else if (clearNodeUpdateRetry(retryOwner, attempt.request)) {
        cleared = true
        setRetryAttempt(null)
        setUpdateRecord(null)
      } else setUpdateStorageBlocked(true)
      setWriteError(apiError)
      if (!unknown) handleKnownConflict(apiError)
      if (cleared && submitErrorFields(apiError).length > 0) {
        setFieldError(apiError)
        return
      }
      setEditing(null)
      setFormOpen(false)
    },
    onSettled: () => { updateSending.current = false },
    retry: false,
  })

  const batchMutation = useMutation({
    mutationKey: [...mutationPrefix, 'batch'],
    mutationFn: async (attempt: BatchAttempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('manage') : null
      if (!token) throw staleNodeWrite
      try {
        const result = await nodesApi.batchAdminState(token, attempt.input, attempt.key)
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        return result
      } catch (error) {
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        throw error
      }
    },
    onSuccess: async (result, attempt) => {
      if (attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      setRetryAttempt(null)
      setWriteError(null)
      setBatchResults(result.items)
      setBatchResultAttempt(attempt)
      setBatchOpen(true)
      setSelectedKeys([])
      await refreshNodes()
    },
    onError: (error, attempt) => {
      if (error === staleNodeWrite || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.batchFailed'))
      if (apiError.status === 403) {
        denyCurrentOwner()
        return
      }
      const unknown = writeOutcomeUnknown(error)
      setRetryAttempt(unknown ? attempt : null)
      setWriteError(apiError)
      setBatchOpen(false)
      if (!unknown) handleKnownConflict(apiError)
    },
  })

  const createMutation = useMutation({
    mutationKey: [...mutationPrefix, 'create'],
    mutationFn: async (attempt: CreateAttempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('manage') : null
      if (!token) throw staleNodeWrite
      try {
        const result = await nodesApi.create(token, attempt.input, attempt.key)
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        createResultsRef.current.set(attempt, result)
        return { ...result, enrollment_token: undefined }
      } catch (error) {
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        throw error
      }
    },
    onSuccess: async (_, attempt) => {
      const result = createResultsRef.current.get(attempt)
      createResultsRef.current.delete(attempt)
      if (!result || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      setRetryAttempt(null)
      setWriteError(null)
      setCreateUnknown(false)
      setFormOpen(false)
      setIssuedToken(result.enrollment_token ?? null)
      await refreshNodes()
      if (currentSessionAccess('manage')) messageApi.success(t('notices.created'))
    },
    onError: (error, attempt) => {
      createResultsRef.current.delete(attempt)
      if (error === staleNodeWrite || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.createFailed'))
      if (apiError.status === 403) {
        denyCurrentOwner()
        return
      }
      const unknown = writeOutcomeUnknown(error)
      setCreateUnknown(unknown)
      setWriteError(apiError)
      setFieldError(!unknown && submitErrorFields(apiError).length > 0 ? apiError : null)
      setRetryAttempt(unknown ? attempt : null)
      if (unknown) {
        setFormOpen(false)
        setEditing(null)
      }
    },
  })

  const tokenMutation = useMutation({
    mutationKey: [...mutationPrefix, 'token'],
    mutationFn: async (attempt: TokenAttempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('manage') : null
      if (!token) throw staleNodeWrite
      try {
        const result = await nodesApi.issueEnrollmentToken(token, attempt.node.id, attempt.values)
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        tokenResultsRef.current.set(attempt, result)
        return { ...result, token: '' }
      } catch (error) {
        if (!currentSessionAccess('manage')) throw staleNodeWrite
        throw error
      }
    },
    onSuccess: (_, attempt) => {
      const token = tokenResultsRef.current.get(attempt)
      tokenResultsRef.current.delete(attempt)
      if (!token || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      setTokenUnknown(false)
      setTokenModalOpen(false)
      setTokenNode(null)
      setIssuedToken(token)
    },
    onError: (error, attempt) => {
      tokenResultsRef.current.delete(attempt)
      if (error === staleNodeWrite || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.tokenFailed'))
      if (apiError.status === 403) {
        denyCurrentOwner()
        return
      }
      const unknown = writeOutcomeUnknown(error)
      setTokenUnknown(unknown)
      setWriteError(apiError)
    },
  })

  const queryError = query.error instanceof ApiError ? query.error : null
  if (terminalForbidden || queryError?.status === 403) {
    return (
      <Result
        className="node-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const submitNode = (values: NodeFormValues) => {
    if (writeLocked || !canManage || !currentSessionAccess('manage')) return
    setWriteError(null)
    setFieldError(null)
    createMutation.mutate({
      kind: 'create',
      ownerKey,
      key: writeKey('create-node'),
      input: {
        name: values.name.trim(),
        description: optional(values.description),
        region: optional(values.region),
        ipv4: optional(values.ipv4),
        ipv6: optional(values.ipv6),
        issue_enrollment_token: values.issue_enrollment_token,
        ...(values.issue_enrollment_token ? {
          enrollment_purpose: values.enrollment_purpose,
          enrollment_token_ttl_seconds: values.enrollment_token_ttl_seconds,
        } : {}),
      },
    })
  }

  const submitNodeUpdate = (input: UpdateNodeRequest) => {
    if (!editing || writeLocked || !canManage || !currentSessionAccess('manage')) return
    beginNodeUpdate({
      item: { id: editing.id, revision: editing.revision },
      input,
      key: writeKey(`update-node-${editing.id}`),
    })
  }

  const beginNodeUpdate = (request: NodeUpdateRequestAttempt, replay = false) => {
    if (updateSending.current || updateReading.current || updateStorageBlocked ||
      !currentSessionAccess('manage') || (!replay && writeLocked)) return
    const record = persistNodeUpdateRetry(retryOwner, request)
    if (!record) {
      setFormOpen(false)
      setEditing(null)
      setUpdateStorageBlocked(true)
      return
    }
    updateSending.current = true
    setUpdateRecord(record)
    setWriteError(null)
    setFieldError(null)
    const attempt: UpdateAttempt = { kind: 'update', request, replay, ownerKey }
    setRetryAttempt(attempt)
    updateMutation.mutate(attempt)
  }

  const changeState = (item: NodeInventoryItem, target: ManagedNodeAdminState) => {
    if (writeLocked || !canManage || !currentSessionAccess('manage')) return
    const targetLabel = t(`states.${target}`)
    // Initializing a self-registered pending node is the pending -> active
    // transition; the server requires a completed enrollment.
    const initializing = item.admin_state === 'pending' && target === 'active'
    const deleting = target === 'retired'
    // Initializing is where a self-registered node gets its region (D8): it
    // has none, and line groups only take nodes of their own region.
    const chooseRegion = initializing && !item.region.trim() && regionNames.length > 0
    let chosenRegion = chooseRegion && regionNames.length === 1 ? regionNames[0]! : ''
    confirm.confirm({
      title: initializing
        ? t('pending.initializeTitle', { name: item.name })
        : deleting
          ? t('confirm.deleteTitle', { name: item.name })
          : t('confirm.stateTitle', { name: item.name, state: targetLabel }),
      content: initializing ? (
        <>
          <p>{t('pending.initializeContent')}</p>
          {chooseRegion ? <InitializeRegionField names={regionNames} initial={chosenRegion}
            onChange={(value) => { chosenRegion = value }} /> : null}
        </>
      ) : target === 'active' ? t('confirm.activationRequiresIdentity') : deleting ? t('confirm.retireNodeWarning') : undefined,
      okText: t('actions.confirm'),
      cancelText: t('actions.cancel'),
      okButtonProps: { danger: target === 'retired' },
      onOk: () => {
        if (writeLocked || !currentSessionAccess('manage')) return
        beginNodeUpdate({
          item: { id: item.id, revision: item.revision },
          input: chooseRegion && chosenRegion ? { admin_state: target, region: chosenRegion } : { admin_state: target },
          key: writeKey(`node-state-${item.id}`),
        })
      },
    })
  }

  const retry = () => {
    if (!retryAttempt || retryAttempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
    if (retryAttempt.kind === 'create') createMutation.mutate(retryAttempt)
    else if (retryAttempt.kind === 'update') beginNodeUpdate(retryAttempt.request, true)
    else batchMutation.mutate(retryAttempt)
  }

  const openBatch = () => {
    if (writeLocked) return
    setBatchResults(null)
    setBatchResultAttempt(null)
    if (batchStatusTargets.length === 0) return
    setBatchTarget(batchStatusTargets[0])
    setBatchOpen(true)
  }

  const openRegionBatch = () => {
    if (writeLocked || selectedItems.length === 0) return
    setRegionBatchValue('')
    setRegionBatchResults(null)
    setRegionBatchOpen(true)
  }

  // One PATCH per node with its own revision: a node a line group of another
  // region still uses is refused (node_region_in_use) and the others change.
  const submitRegionBatch = async () => {
    if (!regionBatchValue || regionBatchPending || writeLocked || !canManage) return
    const items = selectedItems.filter((item) => item.region !== regionBatchValue)
    setRegionBatchPending(true)
    const results: RegionBatchResult[] = []
    for (const item of items) {
      const token = currentSessionAccess('manage')
      if (!token) break
      try {
        await nodesApi.update(token, { id: item.id, revision: item.revision }, { region: regionBatchValue },
          writeKey(`node-region-${item.id}`))
        results.push({ id: item.id, name: item.name, status: 'updated' })
      } catch (error) {
        const apiError = error instanceof ApiError ? error : new ApiError(t('errors.updateFailed'))
        if (apiError.status === 403) {
          denyCurrentOwner()
          return
        }
        results.push({ id: item.id, name: item.name, status: 'failed', message: errorMessage(apiError, t) })
      }
    }
    setRegionBatchPending(false)
    setRegionBatchResults(results)
    setSelectedKeys([])
    void refreshNodes()
  }

  const openBatchFor = (target: ManagedNodeAdminState) => {
    if (writeLocked || selectedItems.length === 0 || !batchTargets.includes(target)) return
    setBatchResults(null)
    setBatchResultAttempt(null)
    setBatchTarget(target)
    setBatchOpen(true)
  }

  const submitBatch = () => {
    if (!batchTarget || writeLocked || !canManage || !currentSessionAccess('manage')) return
    const input: BatchNodeAdminStateRequest = {
      admin_state: batchTarget,
      items: selectedItems.map((item) => ({ id: item.id, expected_revision: item.revision })),
    }
    batchMutation.mutate({ kind: 'batch', input, key: writeKey('batch-node-state'), ownerKey })
  }

  const retryFailedBatch = () => {
    if (!batchResults || !batchResultAttempt || writeLocked || !currentSessionAccess('manage')) return
    const failedIDs = new Set(batchResults.filter((result) => result.status === 'failed').map((result) => result.id))
    const currentItems = new Map((query.data?.items ?? []).map((item) => [item.id, item]))
    const items = batchResultAttempt.input.items
      .filter((item) => failedIDs.has(item.id))
      .map((item) => ({ id: item.id, expected_revision: currentItems.get(item.id)?.revision ?? item.expected_revision }))
    if (items.length === 0) return
    batchMutation.mutate({
      kind: 'batch',
      input: { admin_state: batchResultAttempt.input.admin_state, items },
      key: writeKey('batch-node-state-retry'),
      ownerKey,
    })
  }

  const columns: TableColumnsType<NodeInventoryItem> = [
    {
      title: t('columns.id'), dataIndex: 'display_id', width: 64,
      render: (_: string, item) => <ResourceID internalId={item.id} displayId={item.display_id} />,
    },
    {
      title: t('columns.name'), dataIndex: 'name', width: 150, ellipsis: true,
      render: (value: string, item) => (
        <Button
          type="link"
          size="small"
          className="node-list-name-link"
          onClick={() => { setWriteError(null); setEditing(item); setFormOpen(true) }}
        >
          {value}
        </Button>
      ),
    },
    {
      title: t('columns.region'), dataIndex: 'region', width: 140,
      render: (value: string) => (
        <div className="node-region-cell">
          {/* Line groups only take catalogued regions: once the catalog has
              regions an empty one keeps the node out of every line group. */}
          {!value?.trim() && regionNames.length > 0
            ? <Tag className="node-region-unset" color="warning">{t('region.unset')}</Tag>
            : <span>{value || t('region.default')}</span>}
          {canViewLineGroups ? (
            <Link to="/node/line-group">
              {t('region.lineGroupCount', { count: lineGroupCounts.get(value?.trim() ?? '') ?? 0 })}
            </Link>
          ) : null}
        </div>
      ),
    },
    {
      title: t('columns.addresses'), key: 'addresses', width: 160,
      render: (_, item) => <NodeNetworkAddresses item={item} />,
    },
    {
      title: <span>{t('columns.monitor')} <Tooltip title={t('monitor.refresh')}>
        <Button type="text" size="small" aria-label={t('monitor.refresh')} icon={<RefreshCw size={12} aria-hidden="true" />}
          loading={monitoringQuery.isFetching} disabled={!bandwidthEnabled}
          onClick={() => { if (currentSessionAccess('read')) void monitoringQuery.refetch({ cancelRefetch: false }) }} />
      </Tooltip></span>, key: 'monitor', width: 120,
      render: (_, item) => <NodeMonitoringCell batch={monitoringQuery.data?.result} item={monitoringItems.get(item.id)}
        startedAt={monitoringQuery.data?.startedAt ?? bandwidthClock} now={Math.max(bandwidthClock, performance.now())} error={monitoringQuery.error}
        onConfigure={() => setMonitorModal({ kind: 'config', nodeID: item.id })} onLog={() => setMonitorModal({ kind: 'log', nodeID: item.id })}
        onServingLog={() => setMonitorModal({ kind: 'log', nodeID: item.id, logType: 'serving' })} />,
    },
    {
      title: t('columns.bandwidth'), key: 'bandwidth', width: 120,
      render: (_, item) => <NodeBandwidthCell sample={bandwidthMetrics.get(item.id)}
        serverTime={bandwidthQuery.data?.result.observed_at} startedAt={bandwidthQuery.data?.startedAt ?? bandwidthClock}
        now={Math.max(bandwidthClock, performance.now())} error={bandwidthQuery.error} />,
    },
    {
      title: (
        <span className="node-monthly-traffic-heading">
          {t('columns.monthlyTraffic')}
          <Tooltip title={t('columns.monthlyTrafficHint')}>？</Tooltip>
        </span>
      ),
      key: 'monthlyTraffic', width: 105, render: (_, item) => <NodeMonthlyTrafficCell sample={bandwidthMetrics.get(item.id)} />,
    },
    {
      title: (
        <span className="node-xdp-heading">
          {t('xdp.column')}
          <Tooltip title={t('xdp.columnHint')}>？</Tooltip>
        </span>
      ),
      key: 'xdp', width: 110, render: (_, item) => <NodeXDPCell sample={bandwidthMetrics.get(item.id)} />,
    },
    {
      title: t('columns.status'), dataIndex: 'admin_state', width: 110,
      render: (value: NodeAdminState, item) => <span className="node-status-cell">
        <PresenceCell state={value} presence={item.presence} />
        <NodeFrozenTag ticket={ticketItems.get(item.id)} />
        {/* Reference: "[任务]" only follows a non-normal state and opens that node's tasks. */}
        {value !== 'active' ? <Link to={`/sys/task?resource_id=${encodeURIComponent(item.id)}`} aria-label={t('list.tasksLabel')}>{t('list.tasks')}</Link> : null}
      </span>,
    },
    {
      // 备注省略显示，悬浮看全文。
      title: t('columns.description'), dataIndex: 'description', width: 140, ellipsis: { showTitle: false },
      render: (value: string) => value ? <Tooltip title={value} placement="topLeft"><span>{value}</span></Tooltip> : t('empty.placeholder'),
    },
    {
      title: t('columns.sort'), key: 'sort', width: 56,
      render: (_, item) => formatNumber(item.management_settings.sort, i18n.resolvedLanguage ?? i18n.language),
    },
    {
      title: t('columns.actions'), key: 'actions', width: 120, align: 'center',
      render: (_, item) => {
        const manageButton = (
          <Button
            type="link"
            size="small"
            onClick={() => { setWriteError(null); setEditing(item); setFormOpen(true) }}
          >
            {t('actions.manage')}
          </Button>
        )
        const advancedLink = (
          <Link className="ant-btn ant-btn-link ant-btn-sm" to={`/node/list/${item.id}`}>
            <span>{t('editModal.advancedDetails')}</span>
          </Link>
        )
        if (!canManage) return <div className="node-row-actions">{manageButton}{advancedLink}</div>
        // Deleting has its own menu entry; the status submenu only changes state.
        const statusTargets = allowedTargets(item.admin_state).filter((target) => target !== 'retired')
        const rowMenu: MenuProps = {
          items: [
            {
              key: 'edit',
              label: t('actions.edit'),
              disabled: writeLocked || item.admin_state === 'retired',
              onClick: () => { setWriteError(null); setEditing(item); setFormOpen(true) },
            },
            {
              key: 'token',
              label: t('actions.token'),
              disabled: writeLocked || item.admin_state === 'retired',
              onClick: () => openTokenIssue(item, 're_enrollment'),
            },
            {
              key: 'advanced',
              label: <Link to={`/node/list/${item.id}`}>{t('editModal.advancedDetails')}</Link>,
            },
            {
              key: 'delete',
              label: t('actions.delete'),
              danger: true,
              disabled: writeLocked,
            },
            statusTargets.length > 0 ? {
              key: 'status',
              label: t('actions.status'),
              children: statusTargets.map((target) => ({ key: target, label: stateLabel(target, t) })),
            } : null,
          ].filter((entry): entry is NonNullable<typeof entry> => entry !== null),
          onClick: ({ key }) => {
            if (key === 'delete') changeState(item, 'retired')
            else if (key !== 'edit' && key !== 'token' && key !== 'status' && key !== 'advanced') changeState(item, key as ManagedNodeAdminState)
          },
        }
        return (
          <div className="node-row-actions">
            {manageButton}
            <Dropdown menu={rowMenu} trigger={['click']} placement="bottomLeft" align={{ offset: [-5, 10] }} overlayClassName="node-dropdown-popup node-row-dropdown-popup">
              <Button type="link" size="small" disabled={writeLocked}>{t('actions.moreRow')}<ChevronDown size={14} /></Button>
            </Dropdown>
          </div>
        )
      },
    },
  ]

  const pendingColumns: TableColumnsType<NodeInventoryItem> = [
    {
      title: t('columns.id'), dataIndex: 'display_id', width: 64,
      render: (_: string, item) => <ResourceID internalId={item.id} displayId={item.display_id} />,
    },
    {
      title: t('columns.addresses'),
      key: 'addresses',
      width: 160,
      render: (_, item) => <NodeNetworkAddresses item={item} />,
    },
    {
      title: t('columns.createdAt'),
      dataIndex: 'created_at',
      width: 160,
      render: (value: string) => dateTime(value, i18n.resolvedLanguage ?? i18n.language),
    },
    {
      title: t('columns.actions'),
      key: 'actions',
      width: 190,
      render: (_, item) => (
        <div className="node-row-actions node-pending-actions">
          <Button type="link" size="small" disabled={writeLocked || !canManage} onClick={() => changeState(item, 'active')}>{t('actions.initialize')}</Button>
          <Button type="link" size="small" disabled={writeLocked || !canManage} onClick={() => openTokenIssue(item, 're_enrollment')}>{t('actions.replace')}</Button>
          <Button type="link" size="small" danger disabled={writeLocked} onClick={() => changeState(item, 'retired')}>{t('actions.delete')}</Button>
        </div>
      ),
    },
  ]

  const failedColumns: TableColumnsType<NodeInventoryItem> = [
    {
      title: t('columns.id'), dataIndex: 'display_id', width: 64,
      render: (_: string, item) => <ResourceID internalId={item.id} displayId={item.display_id} />,
    },
    { title: t('columns.name'), dataIndex: 'name', width: 100 },
    { title: t('columns.description'), dataIndex: 'description', width: 100, render: (value: string) => value || t('empty.placeholder') },
    {
      title: t('columns.disabledAt'),
      dataIndex: 'updated_at',
      width: 160,
      render: (value: string) => dateTime(value, i18n.resolvedLanguage ?? i18n.language),
    },
    {
      title: t('columns.actions'),
      key: 'actions',
      width: 100,
      render: (_, item) => (
        <Button
          type="link"
          size="small"
          disabled={writeLocked || !canManage || !allowedTargets(item.admin_state).includes('active')}
          onClick={() => changeState(item, 'active')}
        >
          {t('actions.enable')}
        </Button>
      ),
    },
  ]

  const retryPending = updateMutation.isPending || batchMutation.isPending || readingUpdate
  const failedBatchCount = batchResults?.filter((result) => result.status === 'failed').length ?? 0

  return (
    <section className="node-page" aria-labelledby="node-list-title">
      {messageContext}
      {confirmContext}
      <h1 id="node-list-title" className="visually-hidden">{t('title')}</h1>
      <h3 className="node-page-heading">{t('heading')}</h3>
      <Tabs
        className="node-tabs"
        activeKey={nodeTab}
        onChange={(key) => {
          const next = key as NodeListTab
          setNodeTab(next)
          setSearchDraft('')
          setSearch('')
          setPresence(undefined)
          setRegion('')
          resetPagination()
          if (next === 'list' || next === 'regions') setStatus(undefined)
          if (next === 'pending') setStatus('pending')
          if (next === 'failed') setStatus('disabled')
        }}
        items={[
          { key: 'list', label: t('tabs.list') },
          { key: 'pending', label: t('tabs.pending') },
          { key: 'failed', label: t('tabs.syncFailed') },
          { key: 'regions', label: t('tabs.regions') },
        ]}
      />
      <div className="node-toolbar">
        <div className="node-toolbar-actions">
          {canManage && nodeTab === 'list' ? (
            <>
              <Button aria-label={t('actions.install')} type="primary" disabled={writeLocked} onClick={() => setInstallOpen(true)}>
                <Plus size={15} aria-hidden="true" />
                <span className="node-install-label node-install-label-desktop">{t('actions.install')}</span>
                <span className="node-install-label node-install-label-mobile">{t('actions.installMobile')}</span>
              </Button>
              <Tooltip title={blockedReason('disabled') ?? t('actions.disable')}>
                <Button aria-label={t('actions.disable')} disabled={writeLocked || !!blockedReason('disabled')} onClick={() => openBatchFor('disabled')}>
                  {t('actions.disable')}
                </Button>
              </Tooltip>
              <Tooltip title={blockedReason('active') ?? t('actions.enable')}>
                <Button aria-label={t('actions.enable')} disabled={writeLocked || !!blockedReason('active')} onClick={() => openBatchFor('active')}>
                  {t('actions.enable')}
                </Button>
              </Tooltip>
              <Dropdown
                placement="bottomLeft"
                align={{ offset: [-5, 10] }}
                overlayClassName="node-dropdown-popup node-batch-dropdown-popup"
                menu={{
                  items: [
                    {
                      key: 'enable-ip',
                      label: t('actions.enableIP'),
                      title: blockedReason('active'),
                      disabled: writeLocked || !!blockedReason('active'),
                      onClick: () => openBatchFor('active'),
                    },
                    {
                      key: 'disable-ip',
                      label: t('actions.disableIP'),
                      title: blockedReason('disabled'),
                      disabled: writeLocked || !!blockedReason('disabled'),
                      onClick: () => openBatchFor('disabled'),
                    },
                    {
                      key: 'delete-ip',
                      label: t('actions.deleteIP'),
                      danger: true,
                      disabled: writeLocked || !!blockedReason('retired'),
                      onClick: () => openBatchFor('retired'),
                    },
                    {
                      key: 'edit-monitor',
                      label: t('actions.editMonitor'),
                      disabled: writeLocked || selectedItems.length === 0,
                      onClick: () => { if (!writeLocked && selectedItems.length) setBatchMonitorNodes(selectedItems.map((item) => ({ id: item.id, name: item.name }))) },
                    },
                    { type: 'divider' as const },
                    {
                      key: 'batch-status',
                      label: t('actions.batchStatus'),
                      title: selectedItems.length === 0 ? t('batch.selectFirst')
                        : batchStatusTargets.length === 0 ? (selectedItems.some((item) => item.admin_state === 'pending') ? t('batch.pendingFirst') : t('batch.noCommonState')) : undefined,
                      disabled: writeLocked || batchStatusTargets.length === 0,
                      onClick: openBatch,
                    },
                    {
                      key: 'batch-region',
                      label: t('region.batchAction'),
                      disabled: writeLocked || selectedItems.length === 0,
                      onClick: openRegionBatch,
                    },
                    {
                      key: 'batch-gateway-port',
                      label: i18n.t('nodeInventoryDetail:transition.batch.action'),
                      disabled: writeLocked || selectedItems.length === 0,
                      onClick: () => {
                        const token = currentSessionAccess('manage')
                        if (!token || writeLocked) return
                        setPortBatch({ token, nodes: selectedItems.map((item) => ({ id: item.id, name: item.name, revision: item.revision })) })
                      },
                    },
                    {
                      key: 'advanced-register',
                      label: t('actions.advancedRegister'),
                      disabled: writeLocked,
                      onClick: () => { setCreateUnknown(false); setEditing(null); setFormOpen(true) },
                    },
                  ],
                }}
                disabled={writeLocked}
              >
                <Button>{t('actions.more')} <ChevronDown size={14} aria-hidden="true" /></Button>
              </Dropdown>
            </>
          ) : null}
          {canManage && nodeTab === 'pending' ? (
            <>
              <Button type="primary" disabled={query.isFetching} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>
              <Button danger disabled={writeLocked || selectedItems.length === 0 || !batchTargets.includes('retired')} onClick={() => openBatchFor('retired')}>
                {t('actions.delete')}
              </Button>
            </>
          ) : null}
          {canManage && nodeTab === 'failed' ? (
            <Button
              type="primary"
              disabled={writeLocked || selectedItems.length === 0 || !batchTargets.includes('active')}
              onClick={() => openBatchFor('active')}
            >
              {t('actions.enable')}
            </Button>
          ) : null}
        </div>
        {nodeTab === 'list' ? <div className="node-toolbar-filters">
          <Tooltip title={t('bandwidth.refresh')}>
            <Button aria-label={t('bandwidth.refresh')} icon={<RefreshCw size={14} aria-hidden="true" />}
              loading={bandwidthQuery.isFetching} disabled={!bandwidthEnabled}
              onClick={() => { if (currentSessionAccess('read')) void bandwidthQuery.refetch({ cancelRefetch: false }) }} />
          </Tooltip>
          <Select
            className="node-region-select"
            classNames={{ popup: { root: 'node-select-popup node-region-popup' } }}
            aria-label={t('filters.regionLabel')}
            allowClear
            placement="bottomLeft"
            virtual={false}
            listHeight={200}
            popupMatchSelectWidth
            placeholder={t('filters.allRegions')}
            value={region || undefined}
            options={[{ value: unsetRegionFilter, label: t('region.filterUnset') }, ...regions.map((value) => ({ value, label: value }))]}
            onChange={(value) => { setRegion(value ?? ''); resetPagination() }}
          />
          <Select
            classNames={{ popup: { root: 'node-select-popup node-status-popup' } }}
            aria-label={t('filters.statusLabel')}
            allowClear
            placement="bottomLeft"
            virtual={false}
            listHeight={200}
            popupMatchSelectWidth
            placeholder={t('filters.allStatuses')}
            value={status}
            options={stateOptions}
            onChange={(value) => { setStatus(value); resetPagination() }}
          />
          <Select
            classNames={{ popup: { root: 'node-select-popup node-presence-popup' } }}
            aria-label={t('filters.presenceLabel')}
            allowClear
            placement="bottomLeft"
            virtual={false}
            listHeight={200}
            popupMatchSelectWidth
            placeholder={t('filters.allTypes')}
            value={presence}
            options={presenceOptions}
            onChange={(value) => { setPresence(value); resetPagination() }}
          />
          <div className="node-search">
            <Input
              id="node-list-search"
              aria-label={t('filters.searchLabel')}
              value={searchDraft}
              placeholder={t('filters.searchPlaceholder')}
              suffix={(
                <button
                  className="node-search-icon-button"
                  type="button"
                  aria-label={t('actions.search')}
                  onClick={() => setSearch(searchDraft)}
                >
                  <Search size={14} aria-hidden="true" />
                </button>
              )}
              onChange={(event) => setSearchDraft(event.target.value)}
              onPressEnter={() => setSearch(searchDraft)}
            />
          </div>
        </div> : null}
      </div>

      {updateStorageBlocked ? (
        <Alert className="node-alert" type="error" showIcon message={t('updateRetry.storageBlocked')}
          description={t('updateRetry.storageBlockedDescription')} />
      ) : updateRecord?.phase === 'readback' ? (
        <Alert className="node-alert" type="warning" showIcon message={t('updateRetry.readbackPending')}
          description={t('updateRetry.readbackDescription')}
          action={<Button size="small" loading={readingUpdate} disabled={!canManage}
            onClick={() => void readbackNodeUpdate(updateRecord)}>{t('updateRetry.readback')}</Button>} />
      ) : (writeError || retryAttempt?.kind === 'update') && !formOpen && !tokenModalOpen ? (
        (retryAttempt ? <OutcomeUnknown title={t('errors.outcomeUnknown')} detail={t('errors.retryDescription')} action={<Button size="small" loading={retryPending} disabled={!canManage} onClick={retry}>{t('actions.retrySameRequest')}</Button>} className="node-alert" /> : <FeedbackWhen title={errorMessage(writeError!, t)} onClose={() => setWriteError(null)} />)
      ) : null}

      {nodeTab !== 'regions' && query.isError ? (
        <FeedbackWhen title={t('errors.listFailed')} detail={queryError ? errorMessage(queryError, t) : t('errors.requestFailed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      {nodeTab === 'regions' ? <RegionManagementPanel /> : (
      <div
        className={`node-table-scroll node-table-scroll--${nodeTab}`}
        data-testid="node-table-scroll"
        aria-busy={query.isPending || query.isFetching}
      >
        <Table<NodeInventoryItem>
            rowKey="id"
            size="small"
            columns={nodeTab === 'pending' ? pendingColumns : nodeTab === 'failed' ? failedColumns : columns}
            dataSource={visibleItems}
            loading={query.isPending || query.isFetching}
            pagination={false}
            locale={{
              emptyText: query.isPending
                ? ' '
                : search
                  ? t('empty.filtered')
                  : nodeTab === 'pending'
                    ? t('pending.empty')
                    : nodeTab === 'failed'
                      ? t('failed.empty')
                      : t('empty.nodes'),
            }}
            scroll={{ x: nodeTab === 'list' ? 1330 : nodeTab === 'pending' ? 630 : 580 }}
            rowSelection={canManage ? {
              selectedRowKeys: selectedKeys,
              onChange: setSelectedKeys,
              getCheckboxProps: (item) => ({
                disabled: writeLocked,
                'aria-label': item.name,
              }),
            } : undefined}
          />
      </div>
      )}
      {nodeTab === 'regions' ? null : (
      <div className="node-pagination">
        <span className="node-total">{t('pagination.total', { count: query.data?.items.length ?? 0 })}</span>
        <Tooltip title={t('actions.previousPage')}>
          <Button
            aria-label={t('actions.previousPage')}
            icon={<ChevronLeft size={16} />}
            disabled={pageIndex === 0 || query.isFetching}
            onClick={() => setPageIndex((value) => Math.max(0, value - 1))}
          />
        </Tooltip>
        <span className="node-page-number" aria-current="page">{pageIndex + 1}</span>
        <Tooltip title={t('actions.nextPage')}>
          <Button
            aria-label={t('actions.nextPage')}
            icon={<ChevronRight size={16} />}
            disabled={!query.data?.next_cursor || query.isFetching}
            onClick={() => {
              if (!query.data?.next_cursor) return
              setCursorHistory((history) => [...history.slice(0, pageIndex + 1), query.data?.next_cursor])
              setPageIndex((value) => value + 1)
            }}
          />
        </Tooltip>
        <Select
          classNames={{ popup: { root: 'node-select-popup node-page-size-popup' } }}
          aria-label={t('filters.pageSizeLabel')}
          placement="bottomLeft"
          virtual={false}
          listHeight={200}
          popupMatchSelectWidth
          value={limit}
          options={pageSizes.map((value) => ({ value, label: t('filters.pageSize', { count: value }) }))}
          onChange={(value) => { setLimit(value); resetPagination() }}
        />
      </div>
      )}

      {canManage && installOpen && <InstallNodeModal onClose={() => setInstallOpen(false)} getAccessToken={() => currentSessionAccess('manage')} />}

      {monitorModal?.kind === 'config' ? <NodeMonitorConfigModal key={monitorModal.nodeID} nodeID={monitorModal.nodeID} open
        canManage={canManage && !writeLocked} queryOwner={queryOwner} getAccessToken={currentSessionAccess}
        onSaved={() => { if (currentSessionAccess('read')) void monitoringQuery.refetch({ cancelRefetch: false }) }}
        onClose={() => setMonitorModal(null)} /> : null}
      {batchMonitorNodes ? <NodeBatchMonitorConfigModal nodes={batchMonitorNodes} open canManage={canManage && !writeLocked}
        getAccessToken={currentSessionAccess} onDenied={() => { setBatchMonitorNodes(null); denyCurrentOwner() }}
        onDone={() => { setSelectedKeys([]); if (currentSessionAccess('read')) void monitoringQuery.refetch({ cancelRefetch: false }) }}
        onClose={() => setBatchMonitorNodes(null)} /> : null}
      {monitorModal?.kind === 'log' ? <NodeMonitorLogModal key={monitorModal.nodeID} nodeID={monitorModal.nodeID} open
        initialType={monitorModal.logType} queryOwner={queryOwner} getAccessToken={() => currentSessionAccess('read')} onClose={() => setMonitorModal(null)} /> : null}
      <NodeFormModal
        item={editing}
        open={formOpen}
        pending={createMutation.isPending || updateMutation.isPending}
        uncertain={createUnknown}
        error={writeError}
        submitError={formOpen ? fieldError : null}
        readOnly={!canManage || updateStorageBlocked || updateRecord !== null}
        regionNames={regionNames}
        regionsLoading={regionCatalog.isFetching}
        onCancel={() => {
          if (createMutation.isPending || updateMutation.isPending) return
          // The marked refusal belongs to the form: closing it drops the refusal too.
          if (fieldError && writeError === fieldError) setWriteError(null)
          setFieldError(null)
          setFormOpen(false)
          setEditing(null)
          if (createUnknown) void refreshNodes()
          setCreateUnknown(false)
        }}
        onSubmit={submitNode}
        onUpdate={submitNodeUpdate}
      />
      <TokenIssueModal
        item={tokenNode}
        initialPurpose={tokenPurpose}
        open={tokenModalOpen}
        pending={tokenMutation.isPending}
        uncertain={tokenUnknown}
        error={writeError}
        onCancel={() => {
          if (tokenMutation.isPending) return
          setTokenModalOpen(false)
          setTokenNode(null)
          setTokenUnknown(false)
        }}
        onSubmit={(values) => {
          if (tokenNode && !writeLocked && canManage && currentSessionAccess('manage')) {
            tokenMutation.mutate({ node: tokenNode, values, ownerKey })
          }
        }}
      />
      <TokenResultModal token={issuedToken} onClose={() => setIssuedToken(null)} />
      <NodeGatewayPortBatchModal open={portBatch !== null} accessToken={portBatch?.token ?? ''} nodes={portBatch?.nodes ?? []}
        onClose={() => { setPortBatch(null); void query.refetch() }} />

      <Modal
        className="node-modal"
        title={batchResults ? t('batch.resultsTitle') : batchTarget === 'retired'
          ? t('batch.deleteTitle', { count: selectedItems.length }) : t('batch.title', { count: selectedItems.length })}
        open={batchOpen}
        confirmLoading={batchMutation.isPending}
        okButtonProps={{ disabled: !batchTarget, danger: batchTarget === 'retired' }}
        okText={batchTarget === 'retired' ? t('batch.deleteConfirm', { count: selectedItems.length }) : t('actions.confirmChange')}
        cancelText={t('actions.cancel')}
        footer={batchResults ? (
          <>
            <Button onClick={() => { setBatchOpen(false); setBatchResults(null); setBatchResultAttempt(null) }}>{t('actions.close')}</Button>
            {failedBatchCount > 0 ? (
              <Button type="primary" loading={batchMutation.isPending} onClick={retryFailedBatch}>{t('actions.retryFailed')}</Button>
            ) : null}
          </>
        ) : undefined}
        onCancel={() => {
          if (batchMutation.isPending) return
          setBatchOpen(false)
          setBatchResults(null)
          setBatchResultAttempt(null)
        }}
        onOk={batchResults ? undefined : submitBatch}
      >
        {batchResults ? (
          <div className="node-result-list cdnca-dialog-scroll">
            {batchResults.map((result) => {
              // A deleted node is gone from the refreshed list; its result
              // carries the last snapshot.
              const resultNode = query.data?.items.find((item) => item.id === result.id) ?? result.node
              return (
                <div key={result.id}>
                  <span className="node-result-id" title={result.id}>
                    {resultNode?.display_id ?? resultNode?.name ?? t('empty.placeholder')}
                  </span>
                  {result.status === 'updated' ? (
                    <Tag color="success">{batchResultAttempt?.input.admin_state === 'retired' ? t('batch.deleted') : t('batch.updated')}</Tag>
                  ) : (
                    <Tag color="error">{result.error?.code ? errorCodeMessage(result.error.code, t) : t('batch.failed')}</Tag>
                  )}
                </div>
              )
            })}
          </div>
        ) : batchTarget === 'retired' ? (
          <>
            <ul className="node-result-list cdnca-dialog-scroll">{selectedItems.map((item) => <li key={item.id}>{item.display_id} {item.name}</li>)}</ul>
            <Alert type="warning" showIcon message={t('confirm.retireNodeWarning')} />
          </>
        ) : (
          <>
            <Select
              aria-label={t('filters.batchTarget')}
              className="node-batch-state"
              classNames={{ popup: { root: 'node-select-popup node-batch-state-popup' } }}
              placement="bottomLeft"
              virtual={false}
              listHeight={200}
              popupMatchSelectWidth
              value={batchTarget}
              options={managedStateOptions
                .filter((option) => batchStatusTargets.includes(option.value))
                .map((option) => ({ ...option, label: stateLabel(option.value, t) }))}
              onChange={setBatchTarget}
            />
            {batchTarget === 'active' ? <Alert type="info" showIcon message={t('confirm.batchActivationRequiresIdentity')} /> : null}
          </>
        )}
      </Modal>
      <Modal
        className="node-modal"
        title={regionBatchResults ? t('batch.resultsTitle') : t('region.batchTitle', { count: selectedItems.length })}
        open={regionBatchOpen}
        confirmLoading={regionBatchPending}
        okButtonProps={{ disabled: !regionBatchValue }}
        okText={t('actions.confirm')}
        cancelText={t('actions.cancel')}
        footer={regionBatchResults ? (
          <Button onClick={() => { setRegionBatchOpen(false); setRegionBatchResults(null) }}>{t('actions.close')}</Button>
        ) : undefined}
        onCancel={() => {
          if (regionBatchPending) return
          setRegionBatchOpen(false)
          setRegionBatchResults(null)
        }}
        onOk={regionBatchResults ? undefined : () => void submitRegionBatch()}
        destroyOnHidden
      >
        {regionBatchResults ? (
          <div className="node-result-list cdnca-dialog-scroll">
            {regionBatchResults.map((result) => (
              <div key={result.id}>
                <span className="node-result-id" title={result.id}>{result.name}</span>
                {result.status === 'updated'
                  ? <Tag color="success">{t('batch.updated')}</Tag>
                  : <Tag color="error">{result.message ?? t('batch.failed')}</Tag>}
              </div>
            ))}
          </div>
        ) : (
          <>
            <NodeRegionSelect names={regionNames} loading={regionCatalog.isFetching}
              value={regionBatchValue} onChange={setRegionBatchValue} />
            <Alert type="info" showIcon message={t('region.batchHelp')} />
          </>
        )}
      </Modal>
    </section>
  )
}
