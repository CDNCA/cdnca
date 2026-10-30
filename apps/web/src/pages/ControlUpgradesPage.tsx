import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useInfiniteQuery, useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntApp,
  Alert,
  Button,
  Descriptions,
  Drawer,
  Modal,
  Result,
  Space,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { CircleCheck, FileText, RefreshCw, UploadCloud } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  controlUpgradesApi,
  maintenanceUpgradeReasons,
  type MaintenanceUpgradeCandidate,
  type MaintenanceUpgradeNode,
  createControlUpgradeRequestMetadata,
  type ControlUpgradeNodeState,
  type ControlUpgradePlanState,
  type ControlUpgradeRequestMetadata,
  type ControlUpgradeRolloutDetail,
} from '../api/controlUpgrades'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import ControlUpgradesNative from './ControlUpgradesPage.native'
import NodeInstallCommand from './NodeInstallCommand'
import ControlBackupPanel from './ControlBackupPanel'
import NodeGatewayAddressPanel from './NodeGatewayAddressPanel'
import { nativeControlUpgradesApi } from '../api/controlUpgrades.native'
import UpgradeLogModal from './UpgradeLogModal'
import { masterProgramLogLines, masterRunLogLines, masterUpgradeLogLines, nodeUpgradeLogLines } from './controlUpgradeLogs'
import { runLogMessage } from '../i18n/controlUpgradeRunLog'
import { maintenanceUpgradeCandidateHint, maintenanceUpgradeMessage, maintenanceUpgradeReasonMessage } from '../i18n/maintenanceUpgrade'
import './ControlUpgradesPage.css'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

// A node upgrade is one rollout plan with fixed safe defaults: the selected
// nodes, the first selected node as the only canary, one node per batch and
// automatic rollback. planID is kept after create so a retry resumes at start.
interface UpgradeAttempt {
  nodeIDs: string[]
  createMetadata: ControlUpgradeRequestMetadata
  startMetadata: ControlUpgradeRequestMetadata
  planID?: string
}

// Recent rollout plans read to project node upgrade progress.
const rolloutFactsPageSize = 10
const activeRolloutStates = new Set<ControlUpgradePlanState>(['queued', 'canary', 'running', 'paused', 'rolling_back'])

type NodeRolloutStatus = 'waiting' | 'upgrading' | 'paused' | 'rollingBack' | 'failed' | 'rolledBack'

function nodeRolloutStatus(plan: ControlUpgradeRolloutDetail, state: ControlUpgradeNodeState): NodeRolloutStatus | undefined {
  if (activeRolloutStates.has(plan.state)) {
    if (state === 'pending') return 'waiting'
    if (state === 'dispatched') return plan.state === 'rolling_back' ? 'rollingBack' : plan.state === 'paused' ? 'paused' : 'upgrading'
  }
  if (state === 'failed') return 'failed'
  if (state === 'rolled_back') return 'rolledBack'
  return undefined
}

function hasPermission(permission: string): boolean {
  const principal = useSessionStore.getState().principal
  return principal?.scope_kind === 'platform' &&
    (principal.permissions.includes(permission) || principal.permissions.includes('platform.admin'))
}

function unknownOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.code === 'network_error' || error.code === 'invalid_response' ||
    error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

function compareMaintenanceNodeID(left: NodeInventoryItem, right: NodeInventoryItem): number {
  const a = BigInt(left.display_id)
  const b = BigInt(right.display_id)
  return a < b ? -1 : a > b ? 1 : 0
}

function errorText(error: unknown, operation: 'read' | 'write', t: TFunction<'controlUpgrades'>): string {
  if (!(error instanceof ApiError)) return t('errors.requestFailed')
  const known = new Set([
    'invalid_request', 'invalid_idempotency_key', 'permission_denied', 'forbidden',
    'control_upgrade_rollout_not_found', 'rollout_not_found', 'node_not_found', 'idempotency_conflict',
    'revision_conflict', 'rollout_revision_conflict', 'control_upgrade_rollout_invalid_transition',
    'rollout_transition_invalid', 'control_upgrade_rollout_blocked', 'rollout_blocked',
    'control_upgrade_cohort_incompatible', 'cohort_incompatible', 'control_upgrade_grant_invalid',
    'control_upgrade_execution_invalid', 'control_upgrade_artifact_invalid', 'control_upgrade_artifact_unavailable',
    'control_upgrade_license_outcome_unknown',
    'upgrade_license_outcome_unknown', 'control_upgrade_license_unavailable',
    'control_upgrade_runtime_unavailable', 'control_upgrade_resource_unavailable',
    'control_upgrade_unavailable', 'invalid_response', 'network_error',
  ])
  const key = known.has(error.code) ? `errors.codes.${error.code}` : 'errors.requestFailed'
  const message = t(key, { operation })
  return error.requestId ? t('errors.withRequestId', { message, requestId: error.requestId }) : message
}

// 节点设置：fix-nodegw「更换主控连接地址」（签名指令经网关下发，节点探测成功才切换）；
// 其他设置只列出对应入口（日志走 Agent 直报，不再有 ES/filebeat），不提供草稿表单或灰按钮。
function MaintenanceActionsPanel({ accessToken, canManage, canNodeRead, canNodeManage }: {
  accessToken: string
  canManage: boolean
  canNodeRead: boolean
  canNodeManage: boolean
}) {
  const { i18n } = useTranslation()
  const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage(i18n.resolvedLanguage ?? 'zh-CN', key)

  // fix-maintui: backup/migration on top; node connection below on the same main column + side column grid.
  return <div className="maintenance-action-panel" aria-labelledby="control-backup-title">
    <ControlBackupPanel accessToken={accessToken} canManage={canManage} />

    <section className="maintenance-node-settings" aria-labelledby="node-settings-title">
      <div className="maintenance-section-heading">
        <div>
          <h2 id="node-settings-title">{mt('nodeSettingsTitle')}</h2>
          <p>{mt('nodeSettingsDescription')}</p>
        </div>
      </div>
      <div className={`control-backup-layout${canNodeRead ? '' : ' is-single'}`}>
        {canNodeRead && <div className="control-backup-main">
          <div className="control-backup-card">
            <NodeGatewayAddressPanel accessToken={accessToken} canRead={canNodeRead} canManage={canNodeManage} />
          </div>
        </div>}
        <aside className="control-backup-side">
          <div className="control-backup-card maintenance-node-settings-card">
            <h3>{mt('nodeSettingsUnavailableTitle')}</h3>
            <ul className="maintenance-node-settings-paths">
              <li>{mt('nodeSettingsPathMaster')}</li>
              <li>{mt('nodeSettingsPathLogs')}</li>
              <li>{mt('nodeSettingsPathPerNode')}</li>
            </ul>
            <div className="maintenance-operation-actions maintenance-settings-actions">
              <Button href="/dashboard/sys/gateways">{mt('nodeSettingsGateways')}</Button>
              <Button href="/dashboard/node/list">{mt('nodeSettingsNodeList')}</Button>
            </div>
          </div>
        </aside>
      </div>
    </section>
  </div>
}

function MaintenanceOverview({
  accessToken,
  ownerKey,
  canNodeRead,
  canNodeManage,
  canManage,
  selectedNodeIDs,
  onSelectedNodeIDsChange,
}: {
  accessToken: string
  ownerKey: string
  canNodeRead: boolean
  canNodeManage: boolean
  canManage: boolean
  selectedNodeIDs: string[]
  onSelectedNodeIDsChange: (ids: string[]) => void
}) {
  const { i18n } = useTranslation()
  const { t } = useTranslation('controlUpgrades')
  const { message } = AntApp.useApp()
  const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage(i18n.resolvedLanguage ?? 'zh-CN', key)
  const reasonText = (reason: string) => maintenanceUpgradeReasonMessage(i18n.resolvedLanguage ?? 'zh-CN', reason)
  const queryClient = useQueryClient()
  // ?tab=maintenance 直达维护操作（系统设置「数据备份」链接到这里）。
  const [searchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState<'system' | 'maintenance'>(searchParams.get('tab') === 'maintenance' ? 'maintenance' : 'system')
  // Once opened, the maintenance panel stays mounted (hidden) so switching tabs
  // keeps unsaved backup settings.
  const [maintenanceOpened, setMaintenanceOpened] = useState(false)
  if (activeTab === 'maintenance' && !maintenanceOpened) setMaintenanceOpened(true)
  const [buildDetailsOpen, setBuildDetailsOpen] = useState(false)
  const [masterLogOpen, setMasterLogOpen] = useState(false)
  const [nodeLogID, setNodeLogID] = useState<string | null>(null)
  const controlQuery = useQuery({
    queryKey: ['maintenance-upgrade-status', ownerKey],
    queryFn: () => controlUpgradesApi.maintenanceStatus(accessToken),
    refetchInterval: 30000,
    retry: false,
  })
  const nodeQuery = useInfiniteQuery({
    queryKey: ['maintenance-node-inventory', ownerKey],
    queryFn: ({ pageParam }) => nodesApi.list(accessToken, { limit: 100, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last, _pages, _lastParam, pageParams) =>
      last.next_cursor && !pageParams.includes(last.next_cursor) ? last.next_cursor : undefined,
    enabled: canNodeRead,
    retry: false,
  })
  const nodeStatusQueries = useQueries({
    queries: [...new Map((nodeQuery.data?.pages ?? []).map((page) => {
      const ids = page.items.map((node) => node.id).sort()
      return [ids.join(','), ids]
    })).values()].filter((ids) => ids.length > 0).map((ids) => ({
      queryKey: ['maintenance-node-upgrade-status', ownerKey, ids],
      queryFn: () => controlUpgradesApi.maintenanceStatus(accessToken, ids),
      enabled: canNodeRead,
      refetchInterval: 30000,
      retry: false,
    })),
  })
  // Node upgrade progress comes from the real rollout plans: recent plans that
  // are still active or recorded a failed/rolled-back node are read in detail.
  const rolloutQuery = useQuery({
    queryKey: ['maintenance-node-rollouts', ownerKey],
    queryFn: async () => {
      const list = await controlUpgradesApi.list(accessToken, { page: 1, pageSize: rolloutFactsPageSize })
      const relevant = list.data.filter((plan) => activeRolloutStates.has(plan.state) || plan.failed_nodes > 0 || plan.rolled_back_nodes > 0)
      return Promise.all(relevant.map(async (plan) => (await controlUpgradesApi.detail(accessToken, plan.id)).data))
    },
    enabled: canNodeRead,
    refetchInterval: (query) => query.state.data?.some((plan) => activeRolloutStates.has(plan.state)) ? 5000 : 30000,
    retry: false,
  })
  // The master upgrade log is the native runner's checkpoint journal; it is
  // read only while its dialog is open.
  const masterLogQuery = useQuery({
    queryKey: ['maintenance-master-upgrade-log', ownerKey],
    queryFn: () => nativeControlUpgradesApi.status(accessToken),
    enabled: canManage && masterLogOpen,
    refetchInterval: masterLogOpen ? 5000 : false,
    retry: false, gcTime: 0,
  })
  // The runner's step-by-step log. While this run has none yet ("unavailable")
  // the checkpoint timeline above is shown; a failed read is a read failure.
  const masterRunLogQuery = useQuery({
    queryKey: ['maintenance-master-upgrade-run-log', ownerKey],
    queryFn: () => nativeControlUpgradesApi.runLog(accessToken),
    enabled: canManage && masterLogOpen,
    refetchInterval: masterLogOpen ? 5000 : false,
    retry: false, gcTime: 0,
  })
  const masterLogError = (error: Error | null) => error
    ? mt(error instanceof ApiError && error.status === 403 ? 'logPermissionDenied' : 'logLoadFailed') : undefined
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const rl = (key: string) => runLogMessage(language, key) ?? key
  const masterLogSections = () => {
    const status = masterLogQuery.data && !masterLogQuery.isError ? masterLogQuery.data : undefined
    const runLog = masterRunLogQuery.data?.state === 'available' ? masterRunLogQuery.data.run_log : null
    // The phase records stand in only for a run log the API reports as not
    // (yet) available, never for a failed read (shown as the dialog error).
    const history = status && masterRunLogQuery.data?.state === 'unavailable' && !masterRunLogQuery.isError
      ? masterUpgradeLogLines(status, mt) : []
    return [
      { key: 'script' as const, label: rl('tabScript'), emptyText: rl('scriptEmpty'),
        lines: runLog ? masterRunLogLines(runLog, language) : history,
        notice: !runLog && history.length > 0 ? rl('fallbackNotice') : undefined },
      { key: 'program' as const, label: rl('tabProgram'), emptyText: rl('programEmpty'),
        lines: runLog ? masterProgramLogLines(runLog, language) : [] },
    ]
  }
  const rolloutPlans = canNodeRead && !rolloutQuery.isError ? rolloutQuery.data : undefined
  // Plans are newest first, so the first plan naming a node describes it.
  const nodeRollouts = new Map<string, { plan: ControlUpgradeRolloutDetail; state: ControlUpgradeNodeState }>()
  for (const plan of rolloutPlans ?? []) {
    for (const node of plan.nodes) if (!nodeRollouts.has(node.node_id)) nodeRollouts.set(node.node_id, { plan, state: node.state })
  }
  const rows = canNodeRead ? [...new Map((nodeQuery.data?.pages ?? []).flatMap((page) => page.items).map((node) => [node.id, node])).values()] : []
  const nodeStates = new Map((canNodeRead ? nodeStatusQueries : []).flatMap((query) => query.isError ? [] : query.data?.nodes ?? []).map((node) => [node.node_id, node]))
  const control = controlQuery.isError ? undefined : controlQuery.data?.control
  const knownReasons = new Set<string>(maintenanceUpgradeReasons)
  const now = Date.now()
  const [, updateClock] = useState(0)
  const nextExpiry = Math.min(...[control?.candidate, ...[...nodeStates.values()].map((node) => node.candidate)]
    .map((candidate) => candidate?.expires_at ? Date.parse(candidate.expires_at) : Infinity)
    .filter((expiry) => expiry > now))
  useEffect(() => {
    if (!Number.isFinite(nextExpiry)) return
    const timer = window.setTimeout(() => updateClock((clock) => clock + 1), Math.min(nextExpiry - Date.now() + 1, 2147483647))
    return () => window.clearTimeout(timer)
  }, [nextExpiry])
  const freshCandidate = (candidate?: MaintenanceUpgradeCandidate) => Boolean(candidate &&
    knownReasons.has(candidate.reason) && ({ available: 'upgrade_available', up_to_date: 'same_version', rollback_required: 'target_is_older', unavailable: '' })[candidate.state] === candidate.reason &&
    candidate.expires_at && Date.parse(candidate.expires_at) > now)
  const nodeEligible = (node?: MaintenanceUpgradeNode) => Boolean(node && node.eligible && node.reason === 'eligible' &&
    node.runtime.ready && node.runtime.reason === 'ready' && freshCandidate(node.candidate) &&
    node.candidate.state === 'available' && node.current_version && node.current_version !== node.candidate.version)
  const controlUpToDate = Boolean(control && freshCandidate(control.candidate) && control.candidate.state === 'up_to_date' &&
    control.current_version && control.current_version === control.candidate.version && control.configured_version_matches === true &&
    control.authorization.state === 'valid' && control.authorization.reason === 'eligible' && control.runtime.ready && control.runtime.reason === 'ready')
  // The signed master upgrade is offered only when a fresh newer candidate exists.
  const controlUpgradeAvailable = Boolean(control && !controlQuery.isError && freshCandidate(control.candidate) &&
    control.candidate.state === 'available')
  const nodeUpToDate = (node?: MaintenanceUpgradeNode) => Boolean(node && ['eligible', 'same_version'].includes(node.reason) &&
    node.runtime.ready && node.runtime.reason === 'ready' && freshCandidate(node.candidate) &&
    node.candidate.state === 'up_to_date' && node.current_version && node.current_version === node.candidate.version)
  const candidateText = (candidate?: MaintenanceUpgradeCandidate) => {
    if (!candidate) return mt('pendingCheck')
    if (candidate.expires_at && Date.parse(candidate.expires_at) <= now) return reasonText('candidate_expired')
    if (!freshCandidate(candidate)) return reasonText(candidate.reason)
    return mt(candidate.state === 'up_to_date' ? 'latest' : candidate.state === 'rollback_required' ? 'rollbackRequired' : 'available')
  }
  const lastCursor = nodeQuery.data?.pages.at(-1)?.next_cursor
  const cursorRepeated = Boolean(lastCursor && nodeQuery.data?.pageParams.includes(lastCursor))
  const requiredVersions = new Set(rows.map((node) => {
    const candidate = nodeStates.get(node.id)?.candidate
    return freshCandidate(candidate) ? candidate?.version : undefined
  }))
  const requiredVersion = !rows.length || requiredVersions.has(undefined) || nodeQuery.hasNextPage || nodeQuery.isError || cursorRepeated
    ? mt('versionUnconfirmed') : requiredVersions.size === 1 ? [...requiredVersions][0] : mt('requiredVersionMixed')
  // A node already named by an active plan is never put into a second plan.
  const nodeInActiveRollout = (id: string) => {
    const rollout = nodeRollouts.get(id)
    return Boolean(rollout && activeRolloutStates.has(rollout.plan.state))
  }
  const nodeUpgradable = (id: string) => Boolean(rolloutPlans) && nodeEligible(nodeStates.get(id)) && !nodeInActiveRollout(id)
  const refresh = () => Promise.all([
    controlQuery.refetch(),
    ...(canNodeRead ? [nodeQuery.refetch(), rolloutQuery.refetch(), queryClient.invalidateQueries({ queryKey: ['maintenance-node-upgrade-status', ownerKey] })] : []),
  ])
  const [confirmNodeIDs, setConfirmNodeIDs] = useState<string[] | null>(null)
  const [unknownAttempt, setUnknownAttempt] = useState<UpgradeAttempt | null>(null)
  const [upgradeError, setUpgradeError] = useState<unknown>(null)
  const upgradableNodeIDs = canNodeRead && canManage ? rows.map((n) => n.id).filter(nodeUpgradable) : []
  const canUpgradeSelection = upgradableNodeIDs.length > 0 && !unknownAttempt
  const upgradeMutation = useMutation({
    mutationFn: async (attempt: UpgradeAttempt) => {
      if (!accessToken || !hasPermission('control.upgrades.manage')) throw new ApiError('Permission changed', 403, 'permission_denied')
      let plan: ControlUpgradeRolloutDetail | undefined
      if (!attempt.planID) {
        plan = (await controlUpgradesApi.create(accessToken, {
          schema: 'cdnca.control-upgrade-rollout.create/v1',
          node_ids: [...attempt.nodeIDs].sort(),
          canary_node_ids: [attempt.nodeIDs[0]],
          batch_size: 1,
          automatic_rollback: true,
        }, attempt.createMetadata)).data
        // A retry after an unknown start outcome must not create another plan.
        attempt.planID = plan.id
      } else {
        plan = (await controlUpgradesApi.detail(accessToken, attempt.planID)).data
      }
      if (plan.state !== 'queued') return plan
      return (await controlUpgradesApi.start(accessToken, plan.id, { expected_revision: plan.revision, reason: 'operator_upgrade' },
        attempt.startMetadata)).data
    },
    onSuccess: () => {
      setUnknownAttempt(null)
      setUpgradeError(null)
      setConfirmNodeIDs(null)
      message.success(mt('upgradeStarted'))
      void refresh()
    },
    onError: (error, attempt) => {
      setUpgradeError(error)
      setConfirmNodeIDs(null)
      setUnknownAttempt(unknownOutcome(error) ? attempt : null)
      void refresh()
    },
  })
  const openUpgrade = (ids: string[]) => {
    if (!canManage || unknownAttempt || upgradeMutation.isPending || !ids.length) return
    setUpgradeError(null)
    setConfirmNodeIDs(ids)
  }
  const confirmVersions = new Set((confirmNodeIDs ?? []).map((id) => nodeStates.get(id)?.candidate.version))

  const rolloutStatus = (item: NodeInventoryItem) => {
    const rollout = nodeRollouts.get(item.id)
    const status = rollout ? nodeRolloutStatus(rollout.plan, rollout.state) : undefined
    // A finished plan's failure no longer describes a node that is now current.
    return status && (activeRolloutStates.has(rollout!.plan.state) || !nodeUpToDate(nodeStates.get(item.id))) ? status : undefined
  }
  const rolloutStatusKeys = {
    waiting: 'nodeUpgradeWaiting', upgrading: 'nodeUpgrading', paused: 'nodeUpgradePaused',
    rollingBack: 'nodeUpgradeRollingBack', failed: 'nodeUpgradeFailed', rolledBack: 'nodeUpgradeRolledBack',
  } as const
  const rolloutStatusColors: Record<NodeRolloutStatus, string> = {
    waiting: 'processing', upgrading: 'processing', rollingBack: 'processing', paused: 'warning', failed: 'error', rolledBack: 'warning',
  }
  const maintenanceNodeStatus = (item: NodeInventoryItem) => {
    const node = nodeStates.get(item.id)
    const rollout = rolloutStatus(item)
    if (rollout) return mt(rolloutStatusKeys[rollout])
    if (node && ['node_disabled', 'node_offline', 'node_capability_unavailable', 'version_unavailable'].includes(node.reason)) {
      return reasonText(node.reason)
    }
    return nodeUpToDate(node) ? mt('noUpgrade') : nodeEligible(node) ? mt('canUpgrade') :
      !node ? mt('nodeStatusUnavailable') : !freshCandidate(node.candidate) ? candidateText(node.candidate) :
        node.candidate.state === 'rollback_required' ? mt('rollbackRequired') :
          !node.runtime.ready || node.runtime.reason !== 'ready' ? reasonText(node.runtime.reason) : node.reason === 'eligible' ? candidateText(node.candidate) : reasonText(node.reason)
  }
  const statusCollator = new Intl.Collator(i18n.resolvedLanguage ?? 'zh-CN')
  const nodeColumns: TableColumnsType<NodeInventoryItem> = [
    { title: mt('nodeID'), dataIndex: 'display_id', width: '15%', sorter: compareMaintenanceNodeID, render: (value: string, item) => value || item.id },
    { title: mt('nodeName'), dataIndex: 'name', width: '15%' },
    { title: mt('currentVersion'), key: 'current_version', width: '15%', render: (_, item) => <strong>{nodeStates.get(item.id)?.current_version ?? mt('versionUnconfirmed')}</strong> },
    { title: mt('requiredVersion'), key: 'required_version', width: '15%', render: (_, item) => {
      const candidate = nodeStates.get(item.id)?.candidate
      return <strong>{freshCandidate(candidate) ? candidate?.version : mt('versionUnconfirmed')}</strong>
    } },
    { title: mt('status'), key: 'status', width: '25%', sorter: (left, right) => statusCollator.compare(maintenanceNodeStatus(left), maintenanceNodeStatus(right)),
      render: (_, item) => {
        const rollout = rolloutStatus(item)
        const current = !rollout && nodeUpToDate(nodeStates.get(item.id))
        return <Tag color={rollout ? rolloutStatusColors[rollout] : nodeEligible(nodeStates.get(item.id)) ? 'warning' : undefined}
          className={current ? 'maintenance-current-status' : undefined}
          icon={current ? <CircleCheck size={12} aria-hidden="true" /> : undefined}>{maintenanceNodeStatus(item)}</Tag>
      } },
    { title: mt('action'), key: 'actions', width: '15%', render: (_, item) => <Space size={4} wrap={false}>
      <Button type="link" size="small" className="maintenance-row-action" icon={<FileText size={14} />} onClick={() => setNodeLogID(item.id)}>{mt('logs')}</Button>
      <Button type="link" size="small" icon={<UploadCloud size={14} />} onClick={() => openUpgrade([item.id])} disabled={!canManage || Boolean(unknownAttempt) || !nodeUpgradable(item.id)}>{mt('upgrade')}</Button>
    </Space> },
  ]

  return <section className="maintenance-overview" aria-label={mt('typeLabel')}>
    <div className="maintenance-overview-tabs" role="tablist" aria-label={mt('typeLabel')}>
      <button type="button" role="tab" aria-selected={activeTab === 'system'} className={activeTab === 'system' ? 'is-active' : ''} onClick={() => setActiveTab('system')}>{mt('system')}</button>
      <button type="button" role="tab" aria-selected={activeTab === 'maintenance'} className={activeTab === 'maintenance' ? 'is-active' : ''} onClick={() => setActiveTab('maintenance')}>{mt('maintenance')}</button>
    </div>
    {maintenanceOpened && <div hidden={activeTab !== 'maintenance'}><MaintenanceActionsPanel accessToken={accessToken} canManage={canManage}
      canNodeRead={canNodeRead} canNodeManage={canNodeManage} /></div>}
    {activeTab === 'maintenance' ? null : <>
      <section className="maintenance-card control-upgrade-summary" aria-labelledby="maintenance-overview-title">
        <div className="maintenance-section-heading"><div><h2 id="maintenance-overview-title">{mt('controlTitle')}</h2><p>{mt('controlDescription')}</p></div><Button disabled={!canManage} title={canManage ? undefined : mt('logPermissionDenied')} className="maintenance-view-logs" icon={<FileText size={14} />} onClick={() => setMasterLogOpen(true)}>{mt('viewLogs')}</Button></div>
        <div className="maintenance-stat-grid">
          <div><span>{mt('currentVersion')}</span><button type="button" className="maintenance-version-value" aria-label={mt('versionDetails')} disabled={!control} onClick={() => setBuildDetailsOpen(true)}><strong>{control?.current_version ?? mt('versionUnconfirmed')}</strong></button></div>
          <div><span>{mt('latestVersion')}</span><strong>{freshCandidate(control?.candidate) ? control?.candidate.version : mt('versionUnconfirmed')}</strong></div>
          <div><span>{mt('versionUpgrade')}</span><Tag color={freshCandidate(control?.candidate) && control?.candidate.state === 'available' ? 'warning' : undefined}
            className={controlUpToDate ? 'maintenance-current-status' : undefined}
            icon={controlUpToDate ? <CircleCheck size={12} aria-hidden="true" /> : undefined}>{controlQuery.isError
              ? mt(controlQuery.error instanceof ApiError && controlQuery.error.status === 403 ? 'statusPermissionDenied' : 'statusLoadFailed')
              : !control ? mt('pendingCheck') : !freshCandidate(control.candidate) ? candidateText(control.candidate)
                : controlUpToDate ? mt('latest') : control.candidate.state === 'up_to_date' ? mt('reasonUnknown') : candidateText(control.candidate)}</Tag>
            {control && !controlQuery.isError && !freshCandidate(control.candidate)
              ? <span className="maintenance-candidate-hint">{maintenanceUpgradeCandidateHint(language, control.candidate.expires_at && Date.parse(control.candidate.expires_at) <= now ? 'candidate_expired' : control.candidate.reason)}</span> : null}
            {controlUpgradeAvailable ? <ControlUpgradesNative variant="inline" /> : null}</div>
        </div>
      </section>
      <section className="maintenance-card node-upgrade-section" aria-labelledby="node-upgrade-title">
        <div className="maintenance-section-heading"><div><h2 id="node-upgrade-title">{mt('nodeTitle')}</h2><p>{mt('nodeDescription')}</p></div><Space><Button type="primary" icon={<UploadCloud size={15} />} disabled={!canUpgradeSelection} onClick={() => openUpgrade(selectedNodeIDs.length > 0 ? selectedNodeIDs.filter(nodeUpgradable) : upgradableNodeIDs)}>{selectedNodeIDs.length ? `${mt('upgradeNodes')}（${selectedNodeIDs.length}）` : mt('upgradeNodes')}</Button><Button icon={<RefreshCw size={15} />} loading={controlQuery.isFetching || nodeQuery.isFetching || rolloutQuery.isFetching || nodeStatusQueries.some((query) => query.isFetching)} onClick={() => void refresh()}>{mt('refresh')}</Button></Space></div>
        <div className="maintenance-pills" aria-label={mt('nodeVersionSummary')}><span>{mt('requiredVersion')} <strong>{requiredVersion}</strong></span><span>{mt(nodeQuery.hasNextPage || cursorRepeated || nodeQuery.isError ? 'loadedNodes' : 'nodeCount')} <strong>{canNodeRead && nodeQuery.data ? formatNumber(rows.length, i18n.resolvedLanguage) : mt('nodeCountUnavailable')}</strong></span></div>
        {!canNodeRead ? <Alert type="info" showIcon message={mt('noNodePermission')} /> : null}
        {nodeQuery.error ? <FeedbackWhen title={mt('nodeLoadFailed')} /> : null}
        {nodeStatusQueries.some((query) => query.isError) ? <FeedbackWhen title={mt('nodeStatusLoadFailed')} /> : null}
        {cursorRepeated ? <Alert type="error" showIcon message={mt('nodeCursorRepeated')} /> : null}
        {canNodeRead && rolloutQuery.isError ? <FeedbackWhen title={mt('nodeRolloutLoadFailed')} /> : null}
        {unknownAttempt ? <OutcomeUnknown title={mt('upgradeOutcomeUnknown')} detail={upgradeError ? errorText(upgradeError, 'write', t) : undefined} action={<Space wrap>
            <Button size="small" type="primary" loading={upgradeMutation.isPending} onClick={() => upgradeMutation.mutate(unknownAttempt)}>{t('actions.retrySameRequest')}</Button>
            <Button size="small" onClick={() => { setUnknownAttempt(null); setUpgradeError(null); void refresh() }}>{t('actions.closeAndRefresh')}</Button>
          </Space>} className="maintenance-write-result" /> : upgradeError ? <FeedbackWhen title={errorText(upgradeError, 'write', t)} /> : null}
        <div className="maintenance-node-table"><Table<NodeInventoryItem> rowKey="id" size="small" tableLayout="fixed" columns={nodeColumns} dataSource={rows} loading={canNodeRead && nodeQuery.isPending} locale={{ emptyText: nodeQuery.isError ? <DataState status="error" message={mt('nodeLoadFailed')} onRetry={() => void nodeQuery.refetch()} /> : mt('noNodes') }} rowSelection={canNodeRead ? { columnWidth: '5%', selectedRowKeys: selectedNodeIDs, onChange: (keys) => onSelectedNodeIDsChange(keys.map(String)) } : undefined} pagination={false} scroll={{ x: 1000 }} /></div>
        {nodeQuery.hasNextPage ? <Button loading={nodeQuery.isFetchingNextPage} onClick={() => void nodeQuery.fetchNextPage()}>{mt('loadMoreNodes')}</Button> : null}
        {canNodeRead && canNodeManage ? <div className="maintenance-node-footer"><a href="/dashboard/node/list">{mt('installNewNode')}</a></div> : null}
      </section>
      <UpgradeLogModal title={mt('masterLogTitle')} open={masterLogOpen} contentLabel={mt('logContent')} refreshLabel={mt('logRefresh')}
        copyLabel={rl('copy')} copiedLabel={rl('copied')} copyFailedLabel={rl('copyFailed')}
        loading={masterLogQuery.isFetching || masterRunLogQuery.isFetching}
        onRefresh={() => { void masterLogQuery.refetch(); void masterRunLogQuery.refetch() }} onClose={() => setMasterLogOpen(false)}
        error={masterLogError(masterLogQuery.isError ? masterLogQuery.error : masterRunLogQuery.isError ? masterRunLogQuery.error : null)}
        sections={masterLogSections()} />
      <UpgradeLogModal title={mt('nodeLogTitle')} open={nodeLogID !== null} contentLabel={mt('logContent')} refreshLabel={mt('logRefresh')}
        copyLabel={rl('copy')} copiedLabel={rl('copied')} copyFailedLabel={rl('copyFailed')}
        loading={rolloutQuery.isFetching} onRefresh={() => void rolloutQuery.refetch()} onClose={() => setNodeLogID(null)}
        error={rolloutQuery.isError ? mt('logLoadFailed') : undefined}
        sections={[
          { key: 'script', label: rl('tabScript'), emptyText: mt('logEmpty'),
            lines: nodeLogID && nodeRollouts.has(nodeLogID) ? nodeUpgradeLogLines(nodeRollouts.get(nodeLogID)!.plan, nodeLogID, mt, language) : [] },
          { key: 'program', label: rl('tabProgram'), emptyText: rl('nodeProgramEmpty'), lines: [] },
        ]} />
      <Modal title={mt('upgradeConfirmTitle')} open={Boolean(confirmNodeIDs)} okText={mt('upgradeConfirm')} cancelText={mt('upgradeCancel')}
        confirmLoading={upgradeMutation.isPending} maskClosable={!upgradeMutation.isPending} closable={!upgradeMutation.isPending}
        onCancel={() => { if (!upgradeMutation.isPending) setConfirmNodeIDs(null) }}
        onOk={() => {
          if (!confirmNodeIDs || upgradeMutation.isPending) return
          upgradeMutation.mutate({ nodeIDs: confirmNodeIDs, createMetadata: createControlUpgradeRequestMetadata('create'),
            startMetadata: createControlUpgradeRequestMetadata('start') })
        }} destroyOnHidden>
        <p>{mt('upgradeConfirmMessage')}</p>
        <Descriptions size="small" column={1} items={[
          { key: 'nodes', label: mt('upgradeConfirmNodes'), children: (confirmNodeIDs ?? []).map((id) => rows.find((node) => node.id === id)?.name ?? id).join('、') },
          { key: 'version', label: mt('requiredVersion'), children: confirmVersions.size === 1 ? [...confirmVersions][0] : mt('requiredVersionMixed') },
        ]} />
        <p className="maintenance-command-note">{mt('upgradeConfirmNote')}</p>
      </Modal>
      <section className="maintenance-card node-install-section" aria-labelledby="node-install-title">
        <div className="maintenance-section-heading"><div><h2 id="node-install-title">{mt('installTitle')}</h2><p>{mt('installDescription')}</p></div></div>
        {canNodeManage ? <NodeInstallCommand getAccessToken={() => useSessionStore.getState().accessToken}
          errorText={(error) => mt(error.status === 403 ? 'installTokenPermissionDenied' : 'installTokenError')} />
          : <Alert type="info" showIcon message={mt('installTokenPermissionDenied')} />}
      </section>
    </>}
    <Drawer title={mt('versionDetails')} open={buildDetailsOpen} width={640} onClose={() => setBuildDetailsOpen(false)} destroyOnHidden>
      <Descriptions size="small" column={1} className="maintenance-build-facts" items={[
        { key: 'version', label: mt('currentVersion'), children: control?.current_version ?? mt('versionUnconfirmed') },
        { key: 'authorization', label: mt('authorization'), children: control ? reasonText(control.authorization.reason) : mt('statusUnavailable') },
        { key: 'runtime', label: mt('status'), children: control ? reasonText(control.runtime.reason) : mt('statusUnavailable') },
        { key: 'source', label: mt('sourceCommit'), children: <code>{control?.build?.source_commit ?? mt('buildFactUnavailable')}</code> },
        { key: 'tree', label: mt('sourceTree'), children: <code>{control?.build?.source_tree ?? mt('buildFactUnavailable')}</code> },
        { key: 'built', label: mt('builtAt'), children: control?.build?.built_at ? formatDateTime(control.build.built_at, i18n.resolvedLanguage) : mt('buildFactUnavailable') },
        { key: 'binary', label: mt('binarySHA256'), children: <code>{control?.build?.binary_sha256 ?? mt('buildFactUnavailable')}</code> },
      ]} />
      {control?.configured_version_matches === false ? <Alert type="warning" showIcon message={mt('configuredVersionMismatch')} /> : null}
    </Drawer>
  </section>
}

export default function ControlUpgradesPage() {
  const { t } = useTranslation('controlUpgrades')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = principal?.scope_kind === 'platform' &&
    (principal.permissions.includes('control.upgrades.read') || principal.permissions.includes('platform.admin'))
  const canManage = principal?.scope_kind === 'platform' &&
    (principal.permissions.includes('control.upgrades.manage') || principal.permissions.includes('platform.admin'))
  const canNodeRead = principal?.scope_kind === 'platform' &&
    (principal.permissions.includes('nodes.read') || principal.permissions.includes('platform.admin'))
  const canNodeManage = principal?.scope_kind === 'platform' &&
    (principal.permissions.includes('nodes.manage') || principal.permissions.includes('platform.admin'))
  const ownerKey = `${sessionEpoch}:${principal?.scope_id ?? ''}:${principal?.user_id ?? ''}`
  const [selectedNodeIDs, setSelectedNodeIDs] = useState<string[]>([])

  if (!canRead) {
    return <Result className="identity-page identity-forbidden" status="403"
      title={t('errors.forbiddenTitle')} subTitle={t('errors.permissionDenied')} />
  }

  return <section className="identity-page maintenance-page" aria-labelledby="control-upgrades-title">
    <h1 id="control-upgrades-title">{t('title')}</h1>
    <MaintenanceOverview
      key={`${ownerKey}:${canNodeRead}:${canNodeManage}`}
      accessToken={accessToken!}
      ownerKey={ownerKey}
      canNodeRead={Boolean(canNodeRead)}
      canNodeManage={Boolean(canNodeManage)}
      canManage={Boolean(canManage)}
      selectedNodeIDs={selectedNodeIDs}
      onSelectedNodeIDsChange={setSelectedNodeIDs}
    />
  </section>
}
