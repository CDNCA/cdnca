import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Checkbox,
  Form,
  Input,
  InputNumber,
  Radio,
  Result,
  Space,
  Spin,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { RefreshCw, Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  newNotificationRequestKey,
  notificationsApi,
  type NotificationChannels,
  type NotificationDeliveryPolicy,
  type SwitchWrite,
} from '../api/notifications'
import {
  newSystemConfigurationIdempotencyKey,
  newSystemConfigurationRequestId,
  systemConfigurationApi,
  type NodeMonitoringConfiguration,
  type SystemConfigurationCategory,
  type SystemConfigurationDocument,
  type SystemConfigurationLifecycleResult,
  type SystemConfigurationRollbackResult,
} from '../api/systemConfiguration'
import { nodeMonitoringApi, type NodeMonitoringLatest } from '../api/nodeMonitoring'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { dnspupNodeMonitoringApi } from '../api/probeDNSPup'
import { useSessionStore } from '../auth/session'
import { formatNumber } from '../i18n/formatters'
import NodeServingSwitchLog from './NodeServingSwitchLog'
import '../i18n/nodeMonitorSettings'
import './NodeMonitorSettingsPage.css'
import { PendingCategoriesNotice, usePendingActivationConfirm } from './system-settings/PendingCategories'

type Owner = readonly ['platform', string, null, string, number]
type Access = 'configuration.read' | 'configuration.manage'
type SaveAttempt = {
  value: NodeMonitoringConfiguration
  expectedHeadRevision: number
  idempotencyKey: string
  requestId: string
  ownerKey: string
}

type NotificationSnapshot = {
  channels: NotificationChannels
  policy: NotificationDeliveryPolicy
}

type NotificationPolicyValue = Omit<NotificationDeliveryPolicy, 'schema' | 'revision' | 'changed'>
type NotificationWriteAttempt = {
  ownerKey: string
  requestKey: string
} & (
  | { kind: 'channels'; revision: number; value: SwitchWrite }
  | { kind: 'policy'; revision: number; value: NotificationPolicyValue }
)
type NotificationWriteResult =
  | { kind: 'channels'; value: NotificationChannels }
  | { kind: 'policy'; value: NotificationDeliveryPolicy }

type LifecycleAttempt = {
  ownerKey: string
  idempotencyKey: string
  requestId: string
} & (
  | { kind: 'preflight'; revision: number; snapshotSHA256: string; expectedPendingCategories: SystemConfigurationCategory[] }
  | { kind: 'activate'; revision: number; expectedActiveRevision: number; expectedPendingCategories: SystemConfigurationCategory[] }
  | { kind: 'rollback'; targetRevision: number; expectedHeadRevision: number; expectedActiveRevision: number }
)

const monitorGroupValues = ['domestic', 'telecom', 'unicom', 'mobile', 'overseas'] as const
type MonitorGroup = typeof monitorGroupValues[number]

const monitorDefaults = {
  monitor_enabled: true,
  protocol: 'tcp' as const,
  monitor_port: 80,
  monitor_groups: ['domestic'] as MonitorGroup[],
  monitor_action: 'pause' as const,
  failure_ratio: 50,
  bandwidth_over_limit: 3,
}

const staleRead = new Error('node monitor settings owner changed during read')

function hasPermission(principal: Principal, permission: string): boolean {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

function ownerFor(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null ||
    !principal.scope_id.trim() || !principal.user_id.trim() || sessionEpoch < 1) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function currentAccess(ownerKey: string, access: Access): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, sessionEpoch)
  if (!owner || JSON.stringify(owner) !== ownerKey) return null
  const permission = access === 'configuration.read'
    ? 'system_configuration.read'
    : 'system_configuration.manage'
  return hasPermission(principal, permission) ? accessToken : null
}

// NODE-N02: the nodes shown (getLatest takes at most 300).
const nodeExecutionLimit = 300

interface NodeExecutionRow { node: NodeInventoryItem; latest: NodeMonitoringLatest; activeRevision: number | null }

/** The node's execution of the active monitoring policy, from its own receipt and probe sample. */
function nodeExecutionState(latest: NodeMonitoringLatest): 'applied' | 'awaiting' | 'inactive' | 'different' | 'rolledBack' | 'notReported' | 'stale' {
  if (latest.delivery_state === 'inactive') return 'inactive'
  if (latest.delivery_state === 'awaiting_configuration') return 'awaiting'
  if (latest.revision_state === 'rolled_back') return 'rolledBack'
  if (latest.freshness === 'not_reported') return 'notReported'
  if (latest.freshness === 'stale' || latest.freshness === 'clock_skew') return 'stale'
  if (latest.revision_state === 'different') return 'different'
  return 'applied'
}

/** Why: a serving hold wins (the node is out of DNS), else the freshness / revision detail. */
function nodeExecutionReason(latest: NodeMonitoringLatest): string {
  const hold = latest.serving_holds?.[0]
  if (hold) return `hold_${hold.source}`
  if (latest.delivery_state !== 'serving') return latest.delivery_state
  if (latest.freshness !== 'fresh') return latest.freshness
  return latest.revision_state === 'current' ? (latest.sample?.healthy ? 'healthy' : 'unhealthy') : latest.revision_state
}

function unknownWriteOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500
}

function writeErrorText(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError) {
    if (error.status === 403 || error.code === 'system_configuration_permission_denied') return t('errors.permissionDenied')
    if (error.status === 409 || error.code === 'system_configuration_revision_conflict') return t('errors.conflict')
    if (error.status === 400 || error.code === 'system_configuration_validation_error') return t('errors.invalid')
  }
  return t('errors.write')
}

function lifecycleErrorText(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError) {
    if (error.status === 403 || error.code === 'system_configuration_permission_denied') return t('lifecycle.errors.permissionDenied')
    if (error.code === 'system_configuration_revision_not_found') return t('lifecycle.errors.targetNotFound')
    if (error.code === 'system_configuration_pending_categories_changed') return t('lifecycle.errors.pendingChanged')
    if (error.code === 'system_configuration_invalid_transition') return t('lifecycle.errors.invalidTransition')
    if (error.status === 409 || error.code === 'system_configuration_revision_conflict') return t('lifecycle.errors.conflict')
    if (error.status === 422 || error.code === 'system_configuration_publication_failed') return t('lifecycle.errors.publicationFailed')
    if (error.status === 400 || error.code === 'system_configuration_validation_error') return t('lifecycle.errors.invalid')
  }
  return t('lifecycle.errors.write')
}

function notificationWriteErrorText(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError) {
    if (error.status === 403 || error.code === 'notification_permission_denied') return t('notifications.errors.permissionDenied')
    if (error.status === 409 || error.code === 'version_conflict') return t('notifications.errors.conflict')
    if (error.status === 400 || error.code === 'validation_error') return t('notifications.errors.invalid')
    if (error.code === 'notification_channel_unsupported') return t('notifications.errors.unsupported')
  }
  return t('notifications.errors.write')
}

function notificationPolicyValue(policy: NotificationDeliveryPolicy, overrides: Partial<NotificationPolicyValue> = {}): NotificationPolicyValue {
  return {
    window_mode: policy.window_mode,
    window_start: policy.window_start,
    window_end: policy.window_end,
    timezone: policy.timezone,
    events: policy.events.map((event) => ({ ...event })),
    ...overrides,
  }
}

function notificationWindowText(policy: NotificationDeliveryPolicy): string {
  if (policy.window_mode === 'all_day') return '8-22'
  const compact = (value: string) => value.endsWith(':00') ? String(Number(value.slice(0, 2))) : value
  return `${compact(policy.window_start)}-${compact(policy.window_end)}`
}

function parseNotificationWindow(value: string): { start: string; end: string } | null {
  const match = /^\s*(\d{1,2})(?::([0-5]\d))?\s*-\s*(\d{1,2})(?::([0-5]\d))?\s*$/.exec(value)
  if (!match) return null
  const startHour = Number(match[1])
  const endHour = Number(match[3])
  if (startHour > 23 || endHour > 23) return null
  return {
    start: `${String(startHour).padStart(2, '0')}:${match[2] ?? '00'}`,
    end: `${String(endHour).padStart(2, '0')}:${match[4] ?? '00'}`,
  }
}

function configurationValue(values: NodeMonitoringConfiguration): NodeMonitoringConfiguration {
  const result = { ...monitorDefaults, ...values }
  if (values.port_mode === 'default') {
    delete result.custom_port
    return result
  }
  return result
}

function formValues(values: NodeMonitoringConfiguration): NodeMonitoringConfiguration {
  return { ...monitorDefaults, ...values, monitor_groups: values.monitor_groups?.length ? values.monitor_groups : monitorDefaults.monitor_groups }
}

function monitoringConfigurationState(configuration: SystemConfigurationDocument<'node_monitoring'>) {
  if (configuration.head_revision === 0) return 'initialDraft'
  if (configuration.active_revision === 0) return configuration.status === 'validated' ? 'validated' : 'saved'
  if (configuration.head_revision > configuration.active_revision) return 'newerDraft'
  return 'activePending'
}

export default function NodeMonitorSettingsPage() {
  const { t } = useTranslation('nodeMonitorSettings')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, sessionEpoch)
  if (!owner || !hasPermission(principal, 'system_configuration.read')) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  const ownerKey = JSON.stringify(owner)
  return (
    <NodeMonitorSettingsContent
      key={ownerKey}
      owner={owner}
      ownerKey={ownerKey}
      canManage={hasPermission(principal, 'system_configuration.manage')}
      canManageDNSPup={hasPermission(principal, 'system.probe_dnspup.manage')}
      canReadNodes={hasPermission(principal, 'nodes.read')}
    />
  )
}

function NodeMonitorSettingsContent({ owner, ownerKey, canManage, canManageDNSPup, canReadNodes }: {
  owner: Owner
  ownerKey: string
  canManage: boolean
  canManageDNSPup: boolean
  // NODE-N02: the node execution status needs nodes.read (no implicit upgrade)
  canReadNodes: boolean
}) {
  const { t, i18n } = useTranslation('nodeMonitorSettings')
  const [form] = Form.useForm<NodeMonitoringConfiguration>()
  const queryClient = useQueryClient()
  const confirmPending = usePendingActivationConfirm('node_monitoring')
  const [messageApi, messageContext] = useFeedbackMessage()
  const [attempt, setAttempt] = useState<SaveAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [notificationAttempt, setNotificationAttempt] = useState<NotificationWriteAttempt | null>(null)
  const [notificationWriteError, setNotificationWriteError] = useState<unknown>(null)
  const [notificationWindowDraft, setNotificationWindowDraft] = useState('8-22')
  const [notificationWindowInvalid, setNotificationWindowInvalid] = useState(false)
  const [activeTab, setActiveTab] = useState('monitor')
  const [lifecycleAttempt, setLifecycleAttempt] = useState<LifecycleAttempt | null>(null)
  const [lifecycleError, setLifecycleError] = useState<unknown>(null)
  const [showPublications, setShowPublications] = useState(false)
  const [rollbackTargetRevision, setRollbackTargetRevision] = useState<number | null>(null)
  const [rollbackSourceRevision, setRollbackSourceRevision] = useState<number | null>(null)
  const ownerRef = useRef(owner).current
  const ownerPrefix = useMemo(() => ['node-monitor-settings', ...ownerRef] as const, [ownerRef])
  const configKey = useMemo(() => [...ownerPrefix, 'node_monitoring'] as const, [ownerPrefix])
  const mutationKey = useMemo(() => ['node-monitor-settings-write', ...ownerRef] as const, [ownerRef])
  const notificationKey = useMemo(() => [...ownerPrefix, 'notifications'] as const, [ownerPrefix])
  const notificationMutationKey = useMemo(() => ['node-monitor-notification-write', ...ownerRef] as const, [ownerRef])
  const lifecycleMutationKey = useMemo(() => ['node-monitor-lifecycle-write', ...ownerRef] as const, [ownerRef])

  const configQuery = useQuery({
    queryKey: configKey,
    queryFn: async () => {
      const token = currentAccess(ownerKey, 'configuration.read')
      if (!token) throw staleRead
      const result = await systemConfigurationApi.get(token, 'node_monitoring')
      if (!currentAccess(ownerKey, 'configuration.read')) throw staleRead
      return result
    },
    retry: false,
    refetchOnWindowFocus: false,
  })
  // NODE-POLICY-HELP-01: the effective external decision source. dnspup node
  // probing state needs its own permission (no implicit upgrade); a fresh
  // per-node verdict decides only while probing runs (plugin active, interval > 0).
  const dnspupStatusQuery = useQuery({
    queryKey: [...ownerPrefix, 'dnspup-node-monitoring'],
    enabled: canManageDNSPup,
    queryFn: () => {
      const token = useSessionStore.getState().accessToken
      if (!token) throw staleRead
      return dnspupNodeMonitoringApi.status(token)
    },
  })
  const effectiveSource = !canManageDNSPup ? 'unknown'
    : dnspupStatusQuery.isError ? 'error'
      : !dnspupStatusQuery.data ? null
        : dnspupStatusQuery.data.plugin_active && dnspupStatusQuery.data.effective_interval_seconds > 0 ? 'dnspup' : 'peers'

  const notificationQuery = useQuery({
    queryKey: notificationKey,
    queryFn: async (): Promise<NotificationSnapshot> => {
      const token = currentAccess(ownerKey, 'configuration.read')
      if (!token) throw staleRead
      const [channels, policy] = await Promise.all([
        notificationsApi.getChannels(token),
        notificationsApi.getDeliveryPolicy(token),
      ])
      if (!currentAccess(ownerKey, 'configuration.read')) throw staleRead
      return { channels, policy }
    },
    enabled: activeTab === 'notification',
    retry: false,
    refetchOnWindowFocus: false,
  })
  const activeRevision = configQuery.data?.active_revision ?? 0
  // NODE-N02: 查看节点执行状态 answers from the nodes' own monitoring receipts
  // (GET /v1/nodes/monitoring/latest, nodes.read), not tenant site publications.
  const publicationKey = useMemo(
    () => [...ownerPrefix, 'node-monitoring-execution', activeRevision] as const,
    [activeRevision, ownerPrefix],
  )
  const publicationQuery = useQuery({
    queryKey: publicationKey,
    queryFn: async ({ signal }): Promise<NodeExecutionRow[]> => {
      const token = currentAccess(ownerKey, 'configuration.read')
      if (!token || activeRevision < 1) throw staleRead
      const nodes: NodeInventoryItem[] = []
      let cursor: string | undefined
      do {
        const page = await nodesApi.list(token, { limit: nodeExecutionLimit, cursor })
        nodes.push(...page.items)
        cursor = page.next_cursor
      } while (cursor && nodes.length < nodeExecutionLimit)
      const shown = nodes.slice(0, nodeExecutionLimit)
      if (shown.length === 0) return []
      const latest = await nodeMonitoringApi.getLatest(token, shown.map((node) => node.id), signal)
      if (!currentAccess(ownerKey, 'configuration.read')) throw staleRead
      return shown.map((node, index) => ({ node, latest: latest.items[index]!, activeRevision: latest.configuration.active_revision }))
    },
    enabled: showPublications && activeRevision > 0 && canReadNodes,
    retry: false,
    refetchOnWindowFocus: false,
  })
  const publicationEmptyRef = useRef<HTMLDivElement>(null)
  const publicationsEmpty = showPublications && publicationQuery.isSuccess && !publicationQuery.isFetching &&
    publicationQuery.data.length === 0
  useEffect(() => {
    if (publicationsEmpty) publicationEmptyRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' })
  }, [publicationsEmpty, publicationQuery.dataUpdatedAt])
  const portMode = Form.useWatch('port_mode', form)
  const recoveryNotificationEnabled = Form.useWatch('recovery_notification_enabled', form)
  const probeInterval = Form.useWatch('probe_interval_ms', form)
  const intervalOptions = [
    { value: 10_000, label: t('values.tenSeconds') },
    { value: 30_000, label: t('values.thirtySeconds') },
    { value: 60_000, label: t('values.oneMinute') },
    { value: 300_000, label: t('values.fiveMinutes') },
  ]
  if (typeof probeInterval === 'number' && Number.isInteger(probeInterval) &&
    probeInterval >= 1_000 && probeInterval <= 300_000 &&
    !intervalOptions.some(({ value }) => value === probeInterval)) {
    intervalOptions.push({
      value: probeInterval,
      label: `${t('values.customCurrentInterval')} ${formatNumber(probeInterval, i18n.language)} ${t('values.millisecondsUnit')}`,
    })
  }

  useEffect(() => {
    if (configQuery.data) form.setFieldsValue(formValues(configQuery.data.value))
  }, [configQuery.data, form])

  useEffect(() => {
    if (!notificationQuery.data) return
    setNotificationWindowDraft(notificationWindowText(notificationQuery.data.policy))
    setNotificationWindowInvalid(false)
  }, [notificationQuery.data])

  useEffect(() => () => {
    if (currentAccess(ownerKey, 'configuration.read')) return
    queryClient.removeQueries({ queryKey: ownerPrefix })
    for (const mutation of queryClient.getMutationCache().findAll({ mutationKey })) {
      queryClient.getMutationCache().remove(mutation)
    }
    for (const mutation of queryClient.getMutationCache().findAll({ mutationKey: notificationMutationKey })) {
      queryClient.getMutationCache().remove(mutation)
    }
    for (const mutation of queryClient.getMutationCache().findAll({ mutationKey: lifecycleMutationKey })) {
      queryClient.getMutationCache().remove(mutation)
    }
  }, [lifecycleMutationKey, mutationKey, notificationMutationKey, ownerKey, ownerPrefix, queryClient])

  const mutation = useMutation({
    mutationKey,
    retry: false,
    mutationFn: (nextAttempt: SaveAttempt) => {
      const token = currentAccess(nextAttempt.ownerKey, 'configuration.manage')
      if (!token) return Promise.reject(new ApiError('Permission denied', 403, 'system_configuration_permission_denied'))
      return systemConfigurationApi.put(
        token,
        'node_monitoring',
        nextAttempt.value,
        nextAttempt.expectedHeadRevision,
        nextAttempt.idempotencyKey,
        nextAttempt.requestId,
      )
    },
    onSuccess: (document) => {
      setAttempt(null)
      setWriteError(null)
      setRollbackSourceRevision(null)
      queryClient.setQueryData(configKey, document)
      form.setFieldsValue(formValues(document.value))
      messageApi.success(t('notices.saved'))
    },
    onError: (error, failedAttempt) => {
      setWriteError(error)
      setAttempt(unknownWriteOutcome(error) ? failedAttempt : null)
    },
  })

  const lifecycleMutation = useMutation({
    mutationKey: lifecycleMutationKey,
    retry: false,
    mutationFn: async (nextAttempt: LifecycleAttempt): Promise<
      SystemConfigurationLifecycleResult | SystemConfigurationRollbackResult
    > => {
      const token = currentAccess(nextAttempt.ownerKey, 'configuration.manage')
      if (!token) throw new ApiError('Permission denied', 403, 'system_configuration_permission_denied')
      if (nextAttempt.kind === 'preflight') {
        return systemConfigurationApi.preflight(
          token, nextAttempt.revision, nextAttempt.snapshotSHA256,
          nextAttempt.idempotencyKey, nextAttempt.requestId, nextAttempt.expectedPendingCategories,
        )
      }
      if (nextAttempt.kind === 'activate') {
        return systemConfigurationApi.activate(
          token, nextAttempt.revision, nextAttempt.expectedActiveRevision,
          nextAttempt.idempotencyKey, nextAttempt.requestId, nextAttempt.expectedPendingCategories,
        )
      }
      return systemConfigurationApi.rollback(
        token, nextAttempt.targetRevision, nextAttempt.expectedHeadRevision,
        nextAttempt.expectedActiveRevision, nextAttempt.idempotencyKey, nextAttempt.requestId,
      )
    },
    onSuccess: (result) => {
      setLifecycleAttempt(null)
      setLifecycleError(null)
      if (result.status === 'draft') {
        setRollbackSourceRevision(result.source_revision)
        setRollbackTargetRevision(null)
        setShowPublications(false)
        queryClient.setQueryData<SystemConfigurationDocument<'node_monitoring'>>(configKey, (current) => current ? {
          ...current,
          head_revision: result.revision,
          revision: result.revision,
          status: 'draft',
          snapshot_sha256: result.snapshot_sha256,
        } : current)
        messageApi.success(t('lifecycle.notices.rollbackDraft'))
        return
      }
      queryClient.setQueryData<SystemConfigurationDocument<'node_monitoring'>>(configKey, (current) => {
        if (!current || current.revision !== result.revision || current.snapshot_sha256 !== result.snapshot_sha256) return current
        return {
          ...current,
          status: result.status,
          active_revision: result.status === 'active' ? result.revision : current.active_revision,
        }
      })
      if (result.status === 'active') {
        const activatingRollback = rollbackSourceRevision !== null
        setRollbackSourceRevision(null)
        setShowPublications(true)
        if (activatingRollback) void configQuery.refetch()
      }
      messageApi.success(t(result.status === 'active' ? 'lifecycle.notices.activated' : 'lifecycle.notices.validated'))
    },
    onError: (error, failedAttempt) => {
      setLifecycleError(error)
      setLifecycleAttempt(unknownWriteOutcome(error) ? failedAttempt : null)
    },
  })

  const notificationMutation = useMutation({
    mutationKey: notificationMutationKey,
    retry: false,
    mutationFn: async (nextAttempt: NotificationWriteAttempt): Promise<NotificationWriteResult> => {
      const token = currentAccess(nextAttempt.ownerKey, 'configuration.manage')
      if (!token) throw new ApiError('Permission denied', 403, 'notification_permission_denied')
      if (nextAttempt.kind === 'channels') {
        return {
          kind: 'channels',
          value: await notificationsApi.putChannels(token, nextAttempt.value, nextAttempt.revision, nextAttempt.requestKey),
        }
      }
      return {
        kind: 'policy',
        value: await notificationsApi.putDeliveryPolicy(token, nextAttempt.value, nextAttempt.revision, nextAttempt.requestKey),
      }
    },
    onSuccess: (result) => {
      setNotificationAttempt(null)
      setNotificationWriteError(null)
      queryClient.setQueryData<NotificationSnapshot>(notificationKey, (current) => {
        if (!current) return current
        return result.kind === 'channels'
          ? { ...current, channels: result.value }
          : { ...current, policy: result.value }
      })
      messageApi.success(t('notices.notificationSaved'))
    },
    onError: (error, failedAttempt) => {
      setNotificationWriteError(error)
      setNotificationAttempt(unknownWriteOutcome(error) ? failedAttempt : null)
    },
  })

  const save = async (overrides: Partial<NodeMonitoringConfiguration> = {}) => {
    if (!configQuery.data || !canManage || rollbackSourceRevision !== null) return
    const values = { ...await form.validateFields(), ...overrides }
    if (values.recovery_notification_enabled === undefined) {
      values.recovery_notification_enabled = configQuery.data.value.recovery_notification_enabled
    }
    const nextAttempt: SaveAttempt = {
      value: configurationValue(values),
      expectedHeadRevision: configQuery.data.head_revision,
      idempotencyKey: newSystemConfigurationIdempotencyKey('node_monitoring'),
      requestId: newSystemConfigurationRequestId('node_monitoring'),
      ownerKey,
    }
    setWriteError(null)
    mutation.mutate(nextAttempt)
  }

  const abandon = () => {
    setAttempt(null)
    setWriteError(null)
    mutation.reset()
    for (const cached of queryClient.getMutationCache().findAll({ mutationKey })) {
      queryClient.getMutationCache().remove(cached)
    }
    void configQuery.refetch()
  }

  const runLifecycle = (kind: 'preflight' | 'activate') => {
    if (!configQuery.data || configQuery.data.revision < 1 || !canManage || lifecycleAttempt || lifecycleMutation.isPending) return
    const base = {
      ownerKey,
      revision: configQuery.data.revision,
      idempotencyKey: newSystemConfigurationIdempotencyKey('node_monitoring'),
      requestId: newSystemConfigurationRequestId('node_monitoring'),
    }
    const { snapshot_sha256: snapshotSHA256, active_revision: expectedActiveRevision } = configQuery.data
    const expectedPendingCategories = configQuery.data.pending_categories
    const run = () => {
      setLifecycleError(null)
      lifecycleMutation.mutate(kind === 'preflight'
        ? { ...base, kind, snapshotSHA256, expectedPendingCategories }
        : { ...base, kind, expectedActiveRevision, expectedPendingCategories })
    }
    // Activation makes every pending category effective; confirm the others first.
    if (kind === 'activate') confirmPending(expectedPendingCategories, run)
    else run()
  }

  const runRollback = () => {
    if (!configQuery.data || !canManage || lifecycleAttempt || lifecycleMutation.isPending ||
      rollbackTargetRevision === null || !Number.isInteger(rollbackTargetRevision) ||
      rollbackTargetRevision < 1 || rollbackTargetRevision >= configQuery.data.active_revision) return
    setLifecycleError(null)
    lifecycleMutation.mutate({
      kind: 'rollback',
      ownerKey,
      targetRevision: rollbackTargetRevision,
      expectedHeadRevision: configQuery.data.head_revision,
      expectedActiveRevision: configQuery.data.active_revision,
      idempotencyKey: newSystemConfigurationIdempotencyKey('node_monitoring'),
      requestId: newSystemConfigurationRequestId('node_monitoring'),
    })
  }

  const abandonLifecycle = () => {
    setLifecycleAttempt(null)
    setLifecycleError(null)
    lifecycleMutation.reset()
    for (const cached of queryClient.getMutationCache().findAll({ mutationKey: lifecycleMutationKey })) {
      queryClient.getMutationCache().remove(cached)
    }
    void configQuery.refetch()
  }

  const saveNotificationChannels = (value: SwitchWrite) => {
    if (!notificationQuery.data || !canManage || notificationAttempt || notificationMutation.isPending) return
    setNotificationWriteError(null)
    notificationMutation.mutate({
      kind: 'channels',
      value,
      revision: notificationQuery.data.channels.revision,
      requestKey: newNotificationRequestKey(),
      ownerKey,
    })
  }

  const saveNotificationPolicy = (value: NotificationPolicyValue) => {
    if (!notificationQuery.data || !canManage || notificationAttempt || notificationMutation.isPending) return
    setNotificationWriteError(null)
    notificationMutation.mutate({
      kind: 'policy',
      value,
      revision: notificationQuery.data.policy.revision,
      requestKey: newNotificationRequestKey(),
      ownerKey,
    })
  }

  const saveNotificationWindow = () => {
    if (!notificationQuery.data || notificationQuery.data.policy.window_mode !== 'custom') return
    const parsed = parseNotificationWindow(notificationWindowDraft)
    if (!parsed) {
      setNotificationWindowInvalid(true)
      return
    }
    setNotificationWindowInvalid(false)
    if (parsed.start === notificationQuery.data.policy.window_start && parsed.end === notificationQuery.data.policy.window_end) return
    saveNotificationPolicy(notificationPolicyValue(notificationQuery.data.policy, {
      window_mode: 'custom',
      window_start: parsed.start,
      window_end: parsed.end,
    }))
  }

  const abandonNotification = () => {
    setNotificationAttempt(null)
    setNotificationWriteError(null)
    setNotificationWindowInvalid(false)
    notificationMutation.reset()
    for (const cached of queryClient.getMutationCache().findAll({ mutationKey: notificationMutationKey })) {
      queryClient.getMutationCache().remove(cached)
    }
    void notificationQuery.refetch()
  }

  if (configQuery.isLoading) {
    return <div className="route-loading" aria-label={t('loading')}><Spin size="small" /></div>
  }
  if (configQuery.error instanceof ApiError && (
    configQuery.error.status === 403 || configQuery.error.code === 'system_configuration_permission_denied'
  )) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  if (configQuery.error) {
    return (
      <Result
        status="error"
        title={t('errors.load')}
        extra={<Button icon={<RefreshCw size={15} />} onClick={() => { void configQuery.refetch() }}>{t('actions.retry')}</Button>}
      />
    )
  }
  if (!configQuery.data) {
    return <Result status="error" title={t('errors.load')} />
  }

  const configuration = configQuery.data
  const configurationLocked = attempt !== null || mutation.isPending
  const notificationLocked = notificationAttempt !== null || notificationMutation.isPending
  const lifecycleLocked = lifecycleAttempt !== null || lifecycleMutation.isPending
  const locked = configurationLocked || notificationLocked || lifecycleLocked
  const publicationColumns: TableColumnsType<NodeExecutionRow> = [
    { title: t('lifecycle.columns.node'), key: 'node', width: 200, render: (_, row) => <span>{row.node.name}{row.node.ipv4 ? <Typography.Text type="secondary"> {row.node.ipv4}</Typography.Text> : null}</span> },
    { title: t('lifecycle.columns.targetRevision'), key: 'target', width: 110, render: (_, row) => row.latest.effective_revision ?? row.activeRevision ?? '-' },
    { title: t('lifecycle.columns.actualRevision'), key: 'actual', width: 110, render: (_, row) => row.latest.apply_receipt?.config_revision ?? row.latest.sample?.active_config_revision ?? '-' },
    { title: t('lifecycle.columns.execution'), key: 'state', width: 150, render: (_, row) => {
      const state = nodeExecutionState(row.latest)
      return <Tag color={state === 'applied' ? 'success' : state === 'awaiting' || state === 'inactive' ? 'default' : 'warning'}>{t(`lifecycle.execution.${state}`)}</Tag>
    } },
    { title: t('lifecycle.columns.reason'), key: 'reason', width: 220, render: (_, row) => t(`lifecycle.reasons.${nodeExecutionReason(row.latest)}`) },
    { title: t('lifecycle.columns.observedAt'), key: 'at', width: 180, render: (_, row) => row.latest.apply_receipt?.observed_at ?? row.latest.sample?.observed_at ?? '-' },
  ]

  return (
    <section className="node-monitor-settings-page node-monitor-setting-card" data-testid="node-monitor-settings-page" style={{ minWidth: 0 }}>
      {messageContext}
      <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
        <div className="node-monitor-setting-heading">
          <Typography.Title level={3} className="node-monitor-setting-title">{t('title')}</Typography.Title>
        </div>
        {/* probe-node ④: dnspup checkpoint probing is configured on the plugin page (its own permission). */}
        {canManageDNSPup ? (
          <Typography.Paragraph type="secondary" style={{ margin: 0 }} data-testid="node-monitor-dnspup-probe-entry">
            {t('dnspupProbe.hint')} <Link to="/sys/probe-dnspup">{t('dnspupProbe.open')}</Link>
          </Typography.Paragraph>
        ) : null}
        <PendingCategoriesNotice current="node_monitoring" pending={configuration.pending_categories} />
        {attempt ? (
          <OutcomeUnknown title={t('errors.unknownTitle')} detail={t('errors.unknownDescription')} action={(
              <Space wrap>
                <Button icon={<RefreshCw size={15} />} loading={mutation.isPending} onClick={() => mutation.mutate(attempt)}>
                  {t('actions.retrySame')}
                </Button>
                <Button disabled={mutation.isPending} onClick={abandon}>{t('actions.abandon')}</Button>
              </Space>
            )} />
        ) : notificationAttempt ? (
          <OutcomeUnknown title={t('notifications.errors.unknownTitle')} detail={t('notifications.errors.unknownDescription')} action={(
              <Space wrap>
                <Button icon={<RefreshCw size={15} />} loading={notificationMutation.isPending} onClick={() => notificationMutation.mutate(notificationAttempt)}>
                  {t('actions.retrySame')}
                </Button>
                <Button disabled={notificationMutation.isPending} onClick={abandonNotification}>{t('actions.abandon')}</Button>
              </Space>
            )} />
        ) : lifecycleAttempt ? (
          <OutcomeUnknown title={t('lifecycle.errors.unknownTitle')} detail={t('lifecycle.errors.unknownDescription')} action={(
              <Space wrap>
                <Button icon={<RefreshCw size={15} />} loading={lifecycleMutation.isPending} onClick={() => lifecycleMutation.mutate(lifecycleAttempt)}>
                  {t('actions.retrySame')}
                </Button>
                <Button disabled={lifecycleMutation.isPending} onClick={abandonLifecycle}>{t('actions.abandon')}</Button>
              </Space>
            )} />
        ) : writeError ? <FeedbackWhen title={writeErrorText(writeError, t)} />
          : notificationWriteError ? <FeedbackWhen title={notificationWriteErrorText(notificationWriteError, t)} />
            : lifecycleError ? <FeedbackWhen title={lifecycleErrorText(lifecycleError, t)} /> : null}
        <Form form={form} layout="vertical" disabled={locked || !canManage} style={{ maxWidth: 1220 }}>
          <Tabs
            className="node-monitor-settings-tabs"
            activeKey={activeTab}
            onChange={setActiveTab}
            items={[
              {
                key: 'monitor',
                label: t('lineGroups.monitorTab'),
                children: (
                  <>
          <div className="node-monitor-setting-section node-monitor-setting-section--primary">
            <div className="node-monitor-setting-section-head">
              <div>
                <div className="node-monitor-setting-section-title">{t('lineGroups.probeSectionTitle')}</div>
                <p className="node-monitor-setting-section-desc">{t('lineGroups.probeSectionDescription')}</p>
              </div>
              <div className="node-monitor-setting-status">
                {t(`monitoringState.${monitoringConfigurationState(configuration)}`)}
              </div>
            </div>
            <div className="node-monitor-compatibility-fields">
            <Form.Item name="monitor_enabled" label={t('fields.monitorEnabled')} valuePropName="checked">
              <Switch checkedChildren={t('values.enabled')} unCheckedChildren={t('values.disabled')} />
            </Form.Item>
            <Form.Item name="protocol" label={t('fields.legacyProtocol')} rules={[{ required: true, message: t('validation.required') }]}>
              <Radio.Group optionType="button" options={[
                { value: 'http', label: 'HTTP' }, { value: 'tcp', label: 'TCP' }, { value: 'ping', label: 'PING' },
              ]} />
            </Form.Item>
            <Form.Item name="monitor_port" label={t('fields.legacyPort')} rules={[{
              required: true, type: 'integer', min: 1, max: 65_535, message: t('validation.monitorPort'),
            }]}>
              <InputNumber min={1} max={65_535} precision={0} controls={false} />
            </Form.Item>
            {/* A10/N01：探测超时只注册一次，单位毫秒，范围与服务端契约一致（100–60000 且不大于探测间隔）。 */}
            <Form.Item name="probe_timeout_ms" label={t('fields.probeTimeout')} dependencies={['probe_interval_ms']} rules={[
              { required: true, type: 'integer', min: 100, max: 60_000, message: t('validation.probeTimeout') },
              ({ getFieldValue }) => ({
                validator: (_, next) => typeof next !== 'number' || next <= getFieldValue('probe_interval_ms')
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('validation.probeTimeout'))),
              }),
            ]}>
              <InputNumber min={100} max={60_000} precision={0} suffix={t('values.millisecondsUnit')} controls={false} />
            </Form.Item>
            </div>
          </div>
          <div className="node-monitor-setting-section node-monitor-setting-section--policy">
            <div className="node-monitor-setting-section-head">
              <div>
                <div className="node-monitor-setting-section-title">{t('lineGroups.policySectionTitle')}</div>
                <p className="node-monitor-setting-section-desc">{t('lineGroups.policySectionDescription')}</p>
              </div>
            </div>
            <div className="node-monitor-compatibility-fields">
            <Form.Item label={t('fields.legacyMonitorGroup')}>
              <div className="node-monitor-setting-policy-control">
                <Form.Item name="monitor_groups" noStyle rules={[{ required: true, type: 'array', min: 1, message: t('validation.monitorGroups') }]}>
                  <Checkbox.Group
                    className="node-monitor-checkbox-buttons"
                    options={monitorGroupValues.map((value) => ({ value, label: t(`values.${value}`) }))}
                  />
                </Form.Item>
                <div className="node-monitor-setting-policy-help" data-testid="node-monitor-policy-help">{t('lineGroups.policyHelp')}</div>
                {effectiveSource ? (
                  <div className="node-monitor-setting-policy-help" data-testid="node-monitor-effective-source">
                    {t('lineGroups.effectiveSource', { source: t(`lineGroups.effectiveSources.${effectiveSource}`) })}
                  </div>
                ) : null}
              </div>
            </Form.Item>
            <Form.Item name="monitor_action" label={t('fields.legacyAction')} rules={[{ required: true, message: t('validation.required') }]}
              extra={<span className="node-monitor-setting-policy-help">{t('lineGroups.actionHelp')}</span>}>
              <Radio.Group optionType="button" options={(['none', 'pause'] as const).map((value) => ({ value, label: t(value === 'none' ? 'values.noAction' : 'values.pause') }))} />
            </Form.Item>
            <Form.Item label={t('fields.legacyInterval')} required>
              <div className="node-monitor-setting-interval">
                <Form.Item name="probe_interval_ms" noStyle rules={[{
                  required: true, type: 'integer', min: 1_000, max: 300_000, message: t('validation.probeInterval'),
                }]}>
                  <Radio.Group optionType="button" options={intervalOptions} />
                </Form.Item>
                <InputNumber aria-label={t('fields.probeInterval')} min={1_000} max={300_000} precision={0} controls={false}
                  suffix={t('values.millisecondsUnit')} value={probeInterval}
                  onChange={(next) => form.setFieldValue('probe_interval_ms', next ?? undefined)} />
              </div>
            </Form.Item>
            <Form.Item name="failure_threshold" label={t('fields.legacyFailureCount')} rules={[{ required: true, type: 'integer', min: 1, max: 20, message: t('validation.threshold') }]}>
              <InputNumber min={1} max={20} precision={0} controls={false} />
            </Form.Item>
            <Form.Item name="failure_ratio" label={t('fields.legacyFailureRatio')} rules={[{ required: true, type: 'integer', min: 1, max: 100, message: t('validation.failureRatio') }]}>
              <InputNumber min={1} max={100} precision={0} suffix="%" controls={false} />
            </Form.Item>
            <Form.Item name="bandwidth_over_limit" label={t('fields.legacyBandwidthOverLimit')} rules={[{ required: true, type: 'integer', min: 1, max: 20, message: t('validation.bandwidthOverLimit') }]}>
              <InputNumber min={1} max={20} precision={0} controls={false} />
            </Form.Item>
            </div>
          </div>
          <details className="node-monitor-setting-advanced">
            <summary>{t('lineGroups.advancedTitle')}</summary>
            <div className="node-monitor-setting-advanced-fields">
          <Form.Item name="port_mode" label={t('fields.portMode')} rules={[{ required: true, message: t('validation.required') }]}>
            <Radio.Group optionType="button" buttonStyle="solid" options={[
              { value: 'default', label: t('values.defaultPort') },
              { value: 'custom', label: t('values.customPort') },
            ]} />
          </Form.Item>
          {portMode === 'custom' ? (
            <Form.Item name="custom_port" label={t('fields.customPort')} rules={[{
              required: true, type: 'integer', min: 1, max: 65_535, message: t('validation.customPort'),
            }]}>
              <InputNumber min={1} max={65_535} precision={0} style={{ width: '100%' }} />
            </Form.Item>
          ) : null}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0 16px' }}>
            <Form.Item name="recovery_threshold" label={t('fields.recoveryThreshold')} rules={[{
              required: true, type: 'integer', min: 1, max: 20, message: t('validation.threshold'),
            }]}>
              <InputNumber min={1} max={20} precision={0} style={{ width: '100%' }} />
            </Form.Item>
            {(['failure_debounce_ms', 'recovery_debounce_ms'] as const).map((name) => (
              <Form.Item key={name} name={name} label={t(name === 'failure_debounce_ms' ? 'fields.failureDebounce' : 'fields.recoveryDebounce')} rules={[{
                required: true, type: 'integer', min: 0, max: 3_600_000, message: t('validation.debounce'),
              }]}>
                <InputNumber min={0} max={3_600_000} precision={0} style={{ width: '100%' }} />
              </Form.Item>
            ))}
          </div>
            </div>
          </details>
                  </>
                ),
              },
              {
                key: 'notification',
                label: t('lineGroups.notificationTab'),
                children: (
                  <div className="node-monitor-notification-settings">
                    {notificationQuery.isPending ? (
                      <div className="node-monitor-notification-loading" aria-label={t('notifications.loading')}><Spin size="small" /></div>
                    ) : notificationQuery.error ? (
                      <FeedbackWhen title={t('notifications.errors.load')} action={<Button icon={<RefreshCw size={14} />} onClick={() => { void notificationQuery.refetch() }}>{t('actions.retry')}</Button>} />
                    ) : notificationQuery.data ? (
                      <>
                        <div className="node-monitor-setting-section node-monitor-notification-section">
                          <div className="node-monitor-setting-section-head">
                            <div>
                              <div className="node-monitor-setting-section-title">{t('notifications.channelsTitle')}</div>
                              <p className="node-monitor-setting-section-desc">{t('notifications.channelsDescription')}</p>
                            </div>
                          </div>
                          <Form.Item label={t('notifications.window')} validateStatus={notificationWindowInvalid ? 'error' : undefined} help={notificationWindowInvalid ? t('notifications.errors.window') : undefined}>
                            <div className="node-monitor-notification-window">
                              <Radio.Group
                                optionType="button"
                                value={notificationQuery.data.policy.window_mode === 'all_day' ? 'allDay' : 'custom'}
                                options={[
                                  { value: 'allDay', label: t('notifications.allDay') },
                                  { value: 'custom', label: t('notifications.custom') },
                                ]}
                                onChange={(event) => {
                                  const mode = event.target.value === 'allDay' ? 'all_day' : 'custom'
                                  if (mode === notificationQuery.data.policy.window_mode) return
                                  if (mode === 'all_day') {
                                    setNotificationWindowInvalid(false)
                                    saveNotificationPolicy(notificationPolicyValue(notificationQuery.data.policy, {
                                      window_mode: 'all_day', window_start: '00:00', window_end: '23:59',
                                    }))
                                    return
                                  }
                                  const parsed = parseNotificationWindow(notificationWindowDraft)
                                  if (!parsed) {
                                    setNotificationWindowInvalid(true)
                                    return
                                  }
                                  setNotificationWindowInvalid(false)
                                  saveNotificationPolicy(notificationPolicyValue(notificationQuery.data.policy, {
                                    window_mode: 'custom', window_start: parsed.start, window_end: parsed.end,
                                  }))
                                }}
                              />
                              <Input
                                value={notificationWindowDraft}
                                aria-label={t('notifications.windowFormat')}
                                status={notificationWindowInvalid ? 'error' : undefined}
                                disabled={notificationQuery.data.policy.window_mode !== 'custom'}
                                onChange={(event) => {
                                  setNotificationWindowDraft(event.target.value)
                                  if (notificationWindowInvalid) setNotificationWindowInvalid(false)
                                }}
                                onBlur={saveNotificationWindow}
                                onPressEnter={saveNotificationWindow}
                              />
                              <Typography.Text type="secondary" data-testid="node-monitor-notification-timezone">
                                {t('notifications.timezone', { timezone: notificationQuery.data.policy.timezone })}
                              </Typography.Text>
                            </div>
                          </Form.Item>
                          <Form.Item label={t('notifications.methods')} extra={!notificationQuery.data.channels.email_supported || !notificationQuery.data.channels.sms_supported ? (
                            <span>{t('notifications.channelUnconfigured')} <Link to="/sys/setting?tab=mail">{t('notifications.openChannels')}</Link></span>
                          ) : undefined}>
                            <Checkbox.Group
                              className="node-monitor-checkbox-buttons"
                              value={[
                                ...(notificationQuery.data.channels.email_enabled ? ['email'] : []),
                                ...(notificationQuery.data.channels.sms_enabled ? ['sms'] : []),
                              ]}
                              options={[
                                { value: 'email', label: t('notifications.email'), disabled: !notificationQuery.data.channels.email_supported },
                                { value: 'sms', label: t('notifications.sms'), disabled: !notificationQuery.data.channels.sms_supported },
                              ]}
                              onChange={(values) => saveNotificationChannels({
                                email_enabled: values.includes('email'),
                                sms_enabled: values.includes('sms'),
                              })}
                            />
                          </Form.Item>
                          <Form.Item label={t('notifications.subscriptions')}>
                            <Checkbox.Group
                              className="node-monitor-checkbox-buttons"
                              value={recoveryNotificationEnabled ? ['availability'] : []}
                              options={[{ value: 'availability', label: t('notifications.availability') }]}
                              onChange={(values) => {
                                const enabled = values.includes('availability')
                                form.setFieldValue('recovery_notification_enabled', enabled)
                                void save({ recovery_notification_enabled: enabled })
                              }}
                            />
                          </Form.Item>
                          <Alert className="node-monitor-notification-scope" type="info" showIcon
                            message={t('notifications.unwiredEvents')} />
                          <Form.Item label={t('notifications.recipients')}>
                            <span className="node-monitor-setting-section-desc">
                              {t('notifications.recipientsDescription')} <Link to="/sys/user">{t('notifications.openMembers')}</Link>
                            </span>
                          </Form.Item>
                          <Form.Item name="recovery_notification_enabled" hidden valuePropName="checked"><Switch /></Form.Item>
                        </div>
                        <div className="node-monitor-setting-section node-monitor-template-section">
                          <div className="node-monitor-setting-section-head">
                            <div>
                              <div className="node-monitor-setting-section-title">{t('notifications.templatesTitle')}</div>
                              <p className="node-monitor-setting-section-desc">
                                {t('notifications.templatesDescription')} <Link to="/sys/setting?tab=notification">{t('notifications.openTemplates')}</Link>
                              </p>
                            </div>
                          </div>
                        </div>
                      </>
                    ) : null}
                  </div>
                ),
              },
              {
                key: 'logs',
                label: t('lineGroups.switchLogTab'),
                children: <NodeServingSwitchLog ownerKey={ownerKey} />,
              },
            ]}
          />
          {activeTab === 'monitor' ? (
            <div className="node-monitor-lifecycle" aria-label={t('lifecycle.title')}>
              <div className="node-monitor-lifecycle-head">
                <div>
                  <div className="node-monitor-setting-section-title">{t('lifecycle.title')}</div>
                  <p className="node-monitor-setting-section-desc">{t(configuration.revision === 0 ? 'lifecycle.saveFirst' : 'lifecycle.description')}</p>
                </div>
                <Tag color={configuration.status === 'active' ? 'success' : configuration.status === 'validated' ? 'processing' : 'default'}>
                  {t(`lifecycle.statuses.${configuration.status}`)}
                </Tag>
              </div>
              <div className="node-monitor-lifecycle-meta">
                <span>{t('lifecycle.revision', { revision: configuration.revision })}</span>
                <span>{t('lifecycle.activeRevision', { revision: configuration.active_revision })}</span>
              </div>
              {rollbackSourceRevision !== null ? (
                <Alert
                  type="info"
                  showIcon
                  message={t('lifecycle.rollbackDraft', { source: rollbackSourceRevision, revision: configuration.revision })}
                  description={t('lifecycle.rollbackDraftDescription')}
                />
              ) : null}
              <Space wrap>
                {configuration.status === 'draft' ? (
                  <Button type="primary" loading={lifecycleMutation.isPending} disabled={!canManage || locked || configuration.revision < 1} onClick={() => runLifecycle('preflight')}>
                    {t('lifecycle.actions.preflight')}
                  </Button>
                ) : null}
                {configuration.status === 'validated' ? (
                  <Button type="primary" loading={lifecycleMutation.isPending} disabled={!canManage || locked} onClick={() => runLifecycle('activate')}>
                    {t('lifecycle.actions.activate')}
                  </Button>
                ) : null}
                {configuration.active_revision > 1 ? (
                  <Space.Compact>
                    <InputNumber
                      aria-label={t('lifecycle.rollbackTargetLabel')}
                      min={1}
                      max={configuration.active_revision - 1}
                      precision={0}
                      value={rollbackTargetRevision}
                      placeholder={t('lifecycle.rollbackTargetPlaceholder')}
                      disabled={!canManage || locked}
                      onChange={(value) => setRollbackTargetRevision(typeof value === 'number' ? value : null)}
                    />
                    <Button
                      danger
                      loading={lifecycleMutation.isPending}
                      disabled={!canManage || locked || rollbackTargetRevision === null ||
                        rollbackTargetRevision < 1 || rollbackTargetRevision >= configuration.active_revision}
                      onClick={runRollback}
                    >
                      {t('lifecycle.actions.rollback')}
                    </Button>
                  </Space.Compact>
                ) : null}
                {configuration.active_revision > 0 ? (
                  <Button icon={<RefreshCw size={14} />} loading={publicationQuery.isFetching} disabled={lifecycleLocked || !canReadNodes}
                    title={canReadNodes ? undefined : t('lifecycle.nodesReadRequired')} onClick={() => {
                    setShowPublications(true)
                    if (showPublications) void publicationQuery.refetch()
                  }}>
                    {t('lifecycle.actions.publications')}
                  </Button>
                ) : null}
              </Space>
              {showPublications ? (
                publicationQuery.error ? (
                  <FeedbackWhen title={t('lifecycle.errors.publications')} action={<Button onClick={() => { void publicationQuery.refetch() }}>{t('actions.retry')}</Button>} />
                ) : publicationQuery.isSuccess && !publicationQuery.isFetching && publicationQuery.data.length === 0 ? (
                  // 10-22 W9：空列表时给明确提示并滚到视口内，避免点了按钮像没反应。
                  <div ref={publicationEmptyRef} className="node-monitor-publication-empty">
                    <Alert type="info" showIcon message={t('lifecycle.empty')} description={t('lifecycle.emptyHint', { revision: activeRevision })} />
                  </div>
                ) : (
                  <Table<NodeExecutionRow>
                    className="node-monitor-publication-table"
                    rowKey={(row) => row.node.id}
                    size="small"
                    loading={publicationQuery.isPending || publicationQuery.isFetching}
                    columns={publicationColumns}
                    dataSource={publicationQuery.data ?? []}
                    locale={{ emptyText: publicationQuery.isPending ? ' ' : t('lifecycle.empty') }}
                    pagination={false}
                    scroll={{ x: 860 }}
                  />
                )
              ) : null}
            </div>
          ) : null}
          {activeTab === 'monitor' ? <Space wrap className="node-monitor-setting-actions">
            <Button type="primary" icon={<Save size={15} />} loading={mutation.isPending} disabled={!canManage || locked || rollbackSourceRevision !== null} onClick={() => { void save() }}>
              {t('actions.save')}
            </Button>
            <Button icon={<RefreshCw size={15} />} disabled={locked} onClick={() => { void configQuery.refetch() }}>
              {t('actions.refresh')}
            </Button>
          </Space> : null}
        </Form>
      </Space>
    </section>
  )
}
