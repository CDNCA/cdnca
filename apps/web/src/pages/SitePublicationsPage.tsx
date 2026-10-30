import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Popconfirm,
  Result,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import {
  Ban,
  ChevronLeft,
  ChevronRight,
  Eye,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  ServerCog,
} from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import { nodeSchedulingApi } from '../api/nodeScheduling'
import TenantScopeSelect from '../components/TenantScopeSelect'
import { automaticFailureTitle } from './siteAutomaticFailure'
import {
  lineGroupTargetFromSnapshot,
  newSitePublicationWriteMetadata,
  sitePublicationOutcomeUnknown,
  sitePublicationsApi,
  type AdminSiteRollback,
  type DeploymentWarning,
  type AdminSitePublication,
  type AdminSiteRollout,
  type RollbackSitePublicationInput,
  type SitePublicationAudience,
  type SitePublicationWriteMetadata,
  type SiteRolloutCommandInput,
  type TenantSiteDeployment,
  type TenantSitePublication,
  type TenantSiteRollout,
} from '../api/sitePublications'
import { useSessionStore } from '../auth/session'
import '../i18n/sitePublications'
import { challengePolicyRefusalText } from '../i18n/crsRepublish'
import { formatDateTime } from '../i18n/formatters'
import LineGroupSwitchPanel from './site-publications/LineGroupSwitchPanel'

import './SitePublicationsPage.css'

type Publication = TenantSitePublication | AdminSitePublication
type Rollout = TenantSiteRollout | AdminSiteRollout
type TabKey = 'publications' | 'rollouts'
type WriteKind = 'rollback' | 'start' | 'pause' | 'resume' | 'cancel' | 'retry'

interface CursorState {
  key: string
  cursors: string[]
}

interface OwnedSelection {
  ownerKey: string
  scopeKey: string
  id: string
}

// fix-nopub: site configuration is published automatically after every save;
// this page only reads records and rolls back, with these rollout defaults.
const rollbackDefaults = {
  activation_timeout_ms: 60_000,
  observation_window_ms: 30_000,
  required_consecutive_successes: 3,
  max_attempts: 5,
  deadline_minutes: 30,
  canary_size: 1,
  batch_size: 10,
  failure_threshold: 1,
}

interface WriteAttempt {
  kind: WriteKind
  ownerKey: string
  scopeKey: string
  scopeID: string
  publicationID?: string
  rolloutID?: string
  metadata: SitePublicationWriteMetadata
  body: RollbackSitePublicationInput | SiteRolloutCommandInput
}

interface ScopedError {
  ownerKey: string
  scopeKey: string
  error: unknown
}

const canonicalUUIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

const publicationQueryRoots = new Set([
  'site-publications',
  'site-rollouts',
  'site-publication-detail',
  'site-rollout-detail',
  'site-rollout-deployments',
  'site-publication-line-groups',
  'site-publication-tenants',
])

const rolloutColors: Record<Rollout['state'], string> = {
  queued: 'default',
  running: 'processing',
  paused: 'warning',
  succeeded: 'success',
  partial_failed: 'warning',
  failed: 'error',
  cancelled: 'default',
}

function canReadPublications(scopeKind: 'platform' | 'tenant' | undefined, permissions: readonly string[]): boolean {
  const wildcard = permissions.includes('platform.admin')
  return scopeKind === 'platform'
    ? wildcard || permissions.includes('edge_publications.read')
    : scopeKind === 'tenant' && (wildcard || permissions.includes('sites.read'))
}

function canManagePublications(scopeKind: 'platform' | 'tenant' | undefined, permissions: readonly string[]): boolean {
  return scopeKind === 'platform' &&
    (permissions.includes('platform.admin') || permissions.includes('edge_publications.manage'))
}

function sitePublicationOwner(principal: Principal, sessionEpoch: number): readonly [
  Principal['scope_kind'], string, string | null, string, number,
] | null {
  if (!principal.scope_id || !principal.user_id || !sessionEpoch) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  if (principal.scope_kind === 'tenant' && (
    !principal.tenant_id
  )) return null
  return [
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
  ]
}

function currentSessionCanManage(expectedOwnerKey: string): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return false
  const currentOwner = sitePublicationOwner(principal, sessionEpoch)
  if (!currentOwner) return false
  const currentOwnerKey = JSON.stringify(currentOwner)
  return currentOwnerKey === expectedOwnerKey &&
    canManagePublications(principal.scope_kind, principal.permissions)
}

// The release is refused as a whole; list every node the server named
// (error.capability), as SecurityActivationPanel does, never server text.
function capabilityRefusalText(error: ApiError, t: TFunction<'sitePublications'>): string {
  const refusal = error.capability
  if (!refusal) return t('errors.capabilityRefusal')
  const nodes = [...new Set([refusal.node_id, ...refusal.other_node_ids])].join('、')
  if (refusal.capability === 'CAPABILITY_NAME_IP_INTEL') {
    return `${t('errors.ipIntelRefusal')} ${t('errors.ipIntelNodes', { nodes })}`
  }
  const capability = refusal.capability.replace(/^CAPABILITY_NAME_/, '')
  return `${t('errors.capabilityRefusalNamed', { capability, version: refusal.required_version })} ${t('errors.capabilityNodes', { nodes })}`
}

// rule_pack_unavailable: the release is held until the packs reach the
// nodes; list every node the server named (error.rule_packs).
function rulePackRefusalText(error: ApiError, t: TFunction<'sitePublications'>): string {
  const refusal = error.rulePacks
  if (!refusal) return t('errors.rulePackRefusal')
  const nodes = [...new Set([refusal.node_id, ...refusal.other_node_ids])].join('、')
  return `${t('errors.rulePackRefusal')} ${t('errors.rulePackNodes', { nodes })}`
}

function errorText(error: unknown, t: TFunction<'sitePublications'>): string {
  if (!(error instanceof ApiError)) return t('errors.requestFailed')
  switch (error.code) {
    case 'permission_denied': return t('errors.permissionDenied')
    case 'publication_resource_not_found': return t('errors.notFound')
    case 'idempotency_conflict': return t('errors.idempotencyConflict')
    case 'target_snapshot_conflict': return t('errors.snapshotConflict')
    case 'publication_state_conflict': return t('errors.stateConflict')
    case 'revision_conflict': return t('errors.revisionConflict')
    case 'source_revision_already_published': return t('errors.alreadyPublished')
    case 'publication_not_allowed': return t('errors.notAllowed')
    case 'publication_not_ready': return t('errors.notReady')
    case 'challenge_policy_unavailable': return challengePolicyRefusalText(error) ?? t('errors.notReady')
    case 'node_capability_unavailable': return capabilityRefusalText(error, t)
    case 'rule_pack_unavailable': return rulePackRefusalText(error, t)
    case 'rule_pack_out_of_profile': return t('errors.rulePackOutOfProfile')
    case 'publication_service_unavailable': return t('errors.serviceUnavailable')
    case 'invalid_response': return t('errors.invalidResponse')
    default:
      if (error.status === 403) return t('errors.permissionDenied')
      if (error.status === 404) return t('errors.notFound')
      if ([502, 503, 504].includes(error.status)) return t('errors.serviceUnavailable')
      return t('errors.requestFailed')
  }
}

function CursorPagination({
  label,
  page,
  canNext,
  previous,
  next,
  t,
}: {
  label: string
  page: number
  canNext: boolean
  previous: () => void
  next: () => void
  t: TFunction<'sitePublications'>
}) {
  return (
    <nav className="site-publications-pagination" aria-label={label}>
      <Button
        aria-label={t('actions.previous')}
        title={t('actions.previous')}
        icon={<ChevronLeft size={16} />}
        disabled={page === 1}
        onClick={previous}
      />
      <span>{t('pagination.page', { page })}</span>
      <Button
        aria-label={t('actions.next')}
        title={t('actions.next')}
        icon={<ChevronRight size={16} />}
        disabled={!canNext}
        onClick={next}
      />
    </nav>
  )
}

export default function SitePublicationsPage() {
  const { t, i18n } = useTranslation('sitePublications')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const permissions = principal?.permissions ?? []
  const isPlatform = principal?.scope_kind === 'platform'
  const owner = principal && accessToken ? sitePublicationOwner(principal, sessionEpoch) : null
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const canRead = Boolean(owner) && canReadPublications(principal?.scope_kind, permissions)
  const canManage = Boolean(owner) && canManagePublications(principal?.scope_kind, permissions)
  const ownerKeyRef = useRef(ownerKey)
  ownerKeyRef.current = ownerKey
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedTarget = isPlatform ? (searchParams.get('target_scope_id') ?? '') : ''
  const targetScopeID = canonicalUUIDPattern.test(requestedTarget) ? requestedTarget : ''
  const targetScopeError = Boolean(requestedTarget && !targetScopeID)
  const canListTenants = Boolean(owner) && isPlatform &&
    (permissions.includes('identity.users.manage') || permissions.includes('platform.admin'))

  const scopeID = principal ? (isPlatform ? targetScopeID : principal.scope_id) : ''
  const audience = useMemo<SitePublicationAudience | null>(() => {
    if (!principal) return null
    if (principal.scope_kind === 'tenant') return { kind: 'tenant' }
    return targetScopeID ? { kind: 'platform', targetScopeId: targetScopeID } : null
  }, [principal, targetScopeID])
  const scopeKey = ownerKey && audience ? JSON.stringify([ownerKey, audience.kind, scopeID]) : ''
  const scopeKeyRef = useRef(scopeKey)
  scopeKeyRef.current = scopeKey
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [activeTab, setActiveTab] = useState<TabKey>('publications')
  const [publicationPages, setPublicationPages] = useState<CursorState>({ key: '', cursors: [] })
  const [rolloutPages, setRolloutPages] = useState<CursorState>({ key: '', cursors: [] })
  const [deploymentPages, setDeploymentPages] = useState<CursorState>({ key: '', cursors: [] })
  const publicationCursors = publicationPages.key === scopeKey ? publicationPages.cursors : []
  const rolloutCursors = rolloutPages.key === scopeKey ? rolloutPages.cursors : []
  const publicationCursor = publicationCursors.at(-1)
  const rolloutCursor = rolloutCursors.at(-1)
  const [selectedPublication, setSelectedPublication] = useState<OwnedSelection | null>(null)
  const [selectedRollout, setSelectedRollout] = useState<OwnedSelection | null>(null)
  const [deploymentRollout, setDeploymentRollout] = useState<OwnedSelection | null>(null)
  const visiblePublication = selectedPublication?.ownerKey === ownerKey &&
    selectedPublication.scopeKey === scopeKey ? selectedPublication : null
  const visibleRollout = selectedRollout?.ownerKey === ownerKey &&
    selectedRollout.scopeKey === scopeKey ? selectedRollout : null
  const visibleDeploymentRollout = deploymentRollout?.ownerKey === ownerKey &&
    deploymentRollout.scopeKey === scopeKey ? deploymentRollout : null
  const deploymentKey = `${scopeKey}:${visibleDeploymentRollout?.id ?? ''}`
  const deploymentCursors = deploymentPages.key === deploymentKey ? deploymentPages.cursors : []
  const deploymentCursor = deploymentCursors.at(-1)
  const [writeAttempts, setWriteAttempts] = useState<Map<string, WriteAttempt>>(() => new Map())
  const writeAttemptsRef = useRef(writeAttempts)
  writeAttemptsRef.current = writeAttempts
  const [writeError, setWriteError] = useState<ScopedError | null>(null)
  const [factsRefreshAttempts, setFactsRefreshAttempts] = useState<Map<string, WriteAttempt>>(() => new Map())
  const factsRefreshAttemptsRef = useRef(factsRefreshAttempts)
  factsRefreshAttemptsRef.current = factsRefreshAttempts
  const scopedWriteAttempt = writeAttempts.get(scopeKey)
  const visibleWriteAttempt = scopedWriteAttempt?.ownerKey === ownerKey ? scopedWriteAttempt : null
  const visibleWriteError = writeError?.ownerKey === ownerKey &&
    writeError.scopeKey === scopeKey ? writeError.error : null
  const scopedFactsRefreshAttempt = factsRefreshAttempts.get(scopeKey)
  const visibleFactsRefreshAttempt = scopedFactsRefreshAttempt?.ownerKey === ownerKey
    ? scopedFactsRefreshAttempt
    : null
  const previousOwnerKeyRef = useRef(ownerKey)

  useEffect(() => {
    const previousOwnerKey = previousOwnerKeyRef.current
    if (previousOwnerKey && previousOwnerKey !== ownerKey) {
      queryClient.removeQueries({
        predicate: (query) => publicationQueryRoots.has(String(query.queryKey[0])) &&
          query.queryKey[1] === previousOwnerKey,
      })
      setWriteAttempts(new Map())
      setFactsRefreshAttempts(new Map())
    }
    previousOwnerKeyRef.current = ownerKey
    setSelectedPublication(null)
    setSelectedRollout(null)
    setDeploymentRollout(null)
    setPublicationPages({ key: scopeKey, cursors: [] })
    setRolloutPages({ key: scopeKey, cursors: [] })
    setDeploymentPages({ key: '', cursors: [] })
    setWriteError(null)
  }, [ownerKey, queryClient, scopeKey])

  useEffect(() => {
    if (!canManage) setWriteError(null)
  }, [canManage])

  const publicationsQuery = useQuery({
    queryKey: ['site-publications', ownerKey, scopeKey, publicationCursor],
    queryFn: () => audience?.kind === 'platform'
      ? sitePublicationsApi.listPublications(accessToken!, audience, { limit: 20, cursor: publicationCursor })
      : sitePublicationsApi.listPublications(accessToken!, { kind: 'tenant' }, { limit: 20, cursor: publicationCursor }),
    enabled: Boolean(accessToken && ownerKey && canRead && audience),
  })
  const rolloutsQuery = useQuery({
    queryKey: ['site-rollouts', ownerKey, scopeKey, rolloutCursor],
    queryFn: () => sitePublicationsApi.listRollouts(accessToken!, audience!, { limit: 20, cursor: rolloutCursor }),
    enabled: Boolean(accessToken && ownerKey && canRead && audience && activeTab === 'rollouts'),
  })
  const publicationDetailQuery = useQuery({
    queryKey: ['site-publication-detail', ownerKey, scopeKey, visiblePublication?.id],
    queryFn: () => sitePublicationsApi.getPublication(accessToken!, audience!, visiblePublication!.id),
    enabled: Boolean(accessToken && ownerKey && canRead && audience && visiblePublication),
  })
  const rolloutDetailQuery = useQuery({
    queryKey: ['site-rollout-detail', ownerKey, scopeKey, visibleRollout?.id],
    queryFn: () => sitePublicationsApi.getRollout(accessToken!, audience!, visibleRollout!.id),
    enabled: Boolean(accessToken && ownerKey && canRead && audience && visibleRollout),
  })
  const deploymentsQuery = useQuery({
    queryKey: ['site-rollout-deployments', ownerKey, scopeKey, visibleDeploymentRollout?.id, deploymentCursor],
    queryFn: () => sitePublicationsApi.listDeployments(
      accessToken!, audience!, visibleDeploymentRollout!.id, { limit: 20, cursor: deploymentCursor },
    ),
    enabled: Boolean(accessToken && ownerKey && canRead && audience && visibleDeploymentRollout),
  })
  const lineGroupsQuery = useQuery({
    queryKey: ['site-publication-line-groups', ownerKey, targetScopeID],
    queryFn: () => nodeSchedulingApi.list(accessToken!, {
      kind: 'platform', targetScopeId: targetScopeID,
    }),
    enabled: Boolean(accessToken && ownerKey && canManage && isPlatform && targetScopeID),
  })
  const lineSwitchSnapshots = (lineGroupsQuery.data?.items ?? []).map((group) => ({
    id: group.id,
    label: t('publish.lineGroupOption', { name: group.name, revision: group.revision }),
  }))

  const loadLineSwitchSnapshot = async (lineGroupID: string) => {
    const group = lineGroupsQuery.data?.items.find((item) => item.id === lineGroupID)
    if (!group || !scopeID) throw new ApiError('Snapshot unavailable', 409, 'target_snapshot_conflict')
    const snapshot = await nodeSchedulingApi.getTargetSnapshot(
      accessToken!, { kind: 'platform', targetScopeId: scopeID }, group.id, group.revision,
    )
    const target = lineGroupTargetFromSnapshot(snapshot, scopeID, group.id, group.revision)
    return { id: target.snapshot_id, revision: target.revision, sha256: target.resolver_sha256 }
  }

  const invalidateScopeFacts = async (throwOnError = false) => {
    const options = { throwOnError }
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['site-publications', ownerKey, scopeKey] }, options),
      queryClient.invalidateQueries({ queryKey: ['site-rollouts', ownerKey, scopeKey] }, options),
      queryClient.invalidateQueries({ queryKey: ['site-rollout-deployments', ownerKey, scopeKey] }, options),
      queryClient.invalidateQueries({ queryKey: ['site-publication-line-groups', ownerKey, targetScopeID] }, options),
      queryClient.invalidateQueries({ queryKey: ['node-line-groups'] }, options),
    ])
  }

  const refreshUnknownWriteFacts = async (attempt: WriteAttempt) => {
    if (attempt.ownerKey !== ownerKeyRef.current || attempt.scopeKey !== scopeKeyRef.current ||
      factsRefreshAttemptsRef.current.has(attempt.scopeKey)) return
    setFactsRefreshAttempts((current) => new Map(current).set(attempt.scopeKey, attempt))
    try {
      await invalidateScopeFacts(true)
      if (!currentSessionCanManage(attempt.ownerKey) || attempt.ownerKey !== ownerKeyRef.current ||
        attempt.scopeKey !== scopeKeyRef.current ||
        writeAttemptsRef.current.get(attempt.scopeKey) !== attempt) return
      setWriteAttempts((current) => {
        if (current.get(attempt.scopeKey) !== attempt) return current
        const next = new Map(current)
        next.delete(attempt.scopeKey)
        return next
      })
      setWriteError((current) => current?.ownerKey === attempt.ownerKey && current.scopeKey === attempt.scopeKey
        ? null
        : current)
    } catch {
      // The failed query retains its localized error while the original write remains retryable.
    } finally {
      setFactsRefreshAttempts((current) => {
        if (current.get(attempt.scopeKey) !== attempt) return current
        const next = new Map(current)
        next.delete(attempt.scopeKey)
        return next
      })
    }
  }

  const writeMutation = useMutation<AdminSitePublication | AdminSiteRollback | AdminSiteRollout, unknown, WriteAttempt>({
    gcTime: 0,
    mutationFn: async (attempt) => {
      if (!currentSessionCanManage(attempt.ownerKey) || attempt.scopeKey !== scopeKeyRef.current) {
        throw new ApiError('Permission changed', 403, 'permission_denied')
      }
      if (attempt.kind === 'rollback') {
        return sitePublicationsApi.rollback(
          accessToken!, attempt.publicationID!, attempt.body as RollbackSitePublicationInput, attempt.metadata,
        )
      }
      const command = attempt.body as SiteRolloutCommandInput
      switch (attempt.kind) {
        case 'start': return sitePublicationsApi.startRollout(accessToken!, attempt.rolloutID!, command, attempt.metadata)
        case 'pause': return sitePublicationsApi.pauseRollout(accessToken!, attempt.rolloutID!, command, attempt.metadata)
        case 'resume': return sitePublicationsApi.resumeRollout(accessToken!, attempt.rolloutID!, command, attempt.metadata)
        case 'cancel': return sitePublicationsApi.cancelRollout(accessToken!, attempt.rolloutID!, command, attempt.metadata)
        default: return sitePublicationsApi.retryFailedRollout(accessToken!, attempt.rolloutID!, command, attempt.metadata)
      }
    },
    onSuccess: (_result, attempt) => {
      if (attempt.ownerKey !== ownerKeyRef.current || attempt.scopeKey !== scopeKeyRef.current) return
      setWriteError(null)
      messageApi.success(t(`notices.${attempt.kind}`))
      if (writeAttemptsRef.current.get(attempt.scopeKey) === attempt) {
        void refreshUnknownWriteFacts(attempt)
      } else {
        void invalidateScopeFacts()
      }
    },
    onError: (error, attempt) => {
      const outcomeUnknown = sitePublicationOutcomeUnknown(error)
      if (outcomeUnknown && attempt.ownerKey === ownerKeyRef.current) {
        setWriteAttempts((current) => new Map(current).set(attempt.scopeKey, attempt))
      }
      if (attempt.ownerKey !== ownerKeyRef.current || attempt.scopeKey !== scopeKeyRef.current) return
      setWriteError({ ownerKey: attempt.ownerKey, scopeKey: attempt.scopeKey, error })
      if (!outcomeUnknown && error instanceof ApiError && [409, 412].includes(error.status)) {
        void invalidateScopeFacts()
      }
    },
  })

  if (!accessToken) return null
  const forbidden = !canRead || publicationsQuery.error instanceof ApiError && publicationsQuery.error.status === 403 ||
    rolloutsQuery.error instanceof ApiError && rolloutsQuery.error.status === 403
  if (forbidden) {
    return <Result status="error" icon={<Ban size={72} aria-hidden="true" />} title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }

  const applyTargetScope = (candidate: string) => {
    if (!canonicalUUIDPattern.test(candidate)) return
    setSearchParams({ target_scope_id: candidate }, { replace: true })
  }

  const beginRolloutCommand = (kind: 'start' | 'pause' | 'resume' | 'cancel' | 'retry', rollout: Rollout) => {
    if (!canManage || !currentSessionCanManage(ownerKey) || !('configuration_scope_id' in rollout) ||
      rollout.configuration_scope_id !== scopeID || writeMutation.isPending || visibleWriteAttempt) return
    const body: SiteRolloutCommandInput = {
      configuration_scope_id: scopeID,
      expected_revision: rollout.revision,
    }
    writeMutation.mutate({
      kind, ownerKey, scopeKey, scopeID, rolloutID: rollout.id,
      metadata: newSitePublicationWriteMetadata(kind), body,
    })
  }

  const beginRollback = (publication: Publication) => {
    if (!canManage || !currentSessionCanManage(ownerKey) || !('configuration_scope_id' in publication) ||
      publication.configuration_scope_id !== scopeID || publication.target.kind !== 'line_group_snapshot' ||
      writeMutation.isPending || visibleWriteAttempt) return
    const body: RollbackSitePublicationInput = {
      configuration_scope_id: scopeID,
      target: {
        kind: 'line_group_snapshot', snapshot_id: publication.target.snapshot_id,
        revision: publication.target.revision, resolver_sha256: publication.target.resolver_sha256,
      },
      health_check: {
        activation_timeout_ms: rollbackDefaults.activation_timeout_ms,
        observation_window_ms: rollbackDefaults.observation_window_ms,
        required_consecutive_successes: rollbackDefaults.required_consecutive_successes,
      },
      max_attempts: rollbackDefaults.max_attempts,
      deadline: new Date(Date.now() + rollbackDefaults.deadline_minutes * 60_000).toISOString(),
      rollout: {
        strategy: 'canary', canary_size: rollbackDefaults.canary_size,
        batch_size: rollbackDefaults.batch_size,
        failure_threshold: rollbackDefaults.failure_threshold, auto_start: true,
      },
    }
    writeMutation.mutate({
      kind: 'rollback', ownerKey, scopeKey, scopeID, publicationID: publication.id,
      metadata: newSitePublicationWriteMetadata('rollback'), body,
    })
  }

  const publicationColumns: TableColumnsType<Publication> = [
    { title: t('columns.publicationId'), dataIndex: 'id', width: 245, render: (value: string) => <code>{value}</code> },
    { title: t('columns.sourceRevision'), dataIndex: 'source_revision', width: 105 },
    { title: t('columns.target'), width: 150, render: (_, item) => <Tag>{t(`targets.${item.target.kind}`)}</Tag> },
    { title: t('columns.nodes'), dataIndex: 'node_count', width: 90 },
    {
      title: t('columns.createdAt'), dataIndex: 'created_at', width: 180,
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value,
    },
    {
      title: t('columns.actions'), width: 260, fixed: 'right', render: (_, item) => (
        <Space size={4} wrap>
          <Button
            type="link"
            icon={<Eye size={15} />}
            onClick={() => setSelectedPublication({ ownerKey, scopeKey, id: item.id })}
          >
            {t('actions.viewPublication')}
          </Button>
          {canManage && 'configuration_scope_id' in item && item.target.kind === 'line_group_snapshot' ? (
            <Popconfirm
              title={t('confirm.rollback')}
              okText={t('actions.confirmRollback')}
              cancelText={t('actions.close')}
              onConfirm={() => beginRollback(item)}
            >
              <Button type="link" icon={<RotateCcw size={15} />}>{t('actions.rollback')}</Button>
            </Popconfirm>
          ) : null}
        </Space>
      ),
    },
  ]

  const progressSummary = (progress: Rollout['progress']) => t(
    progress.superseded > 0 ? 'progress.summaryWithSuperseded' : 'progress.summary',
    { succeeded: progress.succeeded, total: progress.total, failed: progress.failed, superseded: progress.superseded },
  ) + (progress.frozen > 0 ? t('progress.frozenSuffix', { frozen: progress.frozen }) : '')

  const rolloutColumns: TableColumnsType<Rollout> = [
    { title: t('columns.rolloutId'), dataIndex: 'id', width: 245, render: (value: string) => <code>{value}</code> },
    { title: t('columns.action'), dataIndex: 'action', width: 100, render: (value: Rollout['action']) => t(`rolloutActions.${value}`) },
    {
      title: t('columns.state'), dataIndex: 'state', width: 120,
      render: (value: Rollout['state']) => <Tag color={rolloutColors[value]}>{t(`states.${value}`)}</Tag>,
    },
    {
      title: t('columns.progress'), width: 180,
      render: (_, item) => progressSummary(item.progress),
    },
    {
      title: t('rollout.releasedCohort'), width: 130,
      render: (_, item) => item.rollout
        ? `${item.rollout.released_cohort + 1}/${item.rollout.cohort_count}`
        : t('values.placeholder'),
    },
    { title: t('columns.revision'), dataIndex: 'revision', width: 90 },
    {
      title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180,
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value,
    },
    {
      title: t('columns.actions'), width: 310, fixed: 'right', render: (_, item) => (
        <Space size={4} wrap>
          <Button type="link" icon={<Eye size={15} />} onClick={() => setSelectedRollout({ ownerKey, scopeKey, id: item.id })}>
            {t('actions.viewRollout')}
          </Button>
          <Button type="link" icon={<ServerCog size={15} />} onClick={() => {
            setDeploymentPages({ key: `${scopeKey}:${item.id}`, cursors: [] })
            setDeploymentRollout({ ownerKey, scopeKey, id: item.id })
          }}>
            {t('actions.viewDeployments')}
          </Button>
          {canManage && item.can_start ? (
            <Button type="link" icon={<Play size={15} />} onClick={() => beginRolloutCommand('start', item)}>
              {t('actions.start')}
            </Button>
          ) : null}
          {canManage && item.can_pause ? (
            <Button type="link" icon={<Pause size={15} />} onClick={() => beginRolloutCommand('pause', item)}>
              {t('actions.pause')}
            </Button>
          ) : null}
          {canManage && item.can_resume ? (
            <Button type="link" icon={<Play size={15} />} onClick={() => beginRolloutCommand('resume', item)}>
              {t('actions.resume')}
            </Button>
          ) : null}
          {canManage && item.can_cancel ? (
            <Popconfirm title={t('confirm.cancel')} onConfirm={() => beginRolloutCommand('cancel', item)}>
              <Button type="link" danger icon={<Ban size={15} />}>{t('actions.cancel')}</Button>
            </Popconfirm>
          ) : null}
          {canManage && item.can_retry ? (
            <Button type="link" icon={<RotateCcw size={15} />} onClick={() => beginRolloutCommand('retry', item)}>
              {t('actions.retryFailed')}
            </Button>
          ) : null}
        </Space>
      ),
    },
  ]

  const deploymentColumns: TableColumnsType<TenantSiteDeployment & { node_id?: string }> = [
    ...(isPlatform ? [{
      title: t('columns.nodeId'), dataIndex: 'node_id', width: 245,
      render: (value: string) => <code>{value}</code>,
    }] : []),
    { title: t('columns.attempt'), width: 100, render: (_, item) => `${item.attempt}/${item.max_attempts}` },
    { title: t('rollout.cohort'), dataIndex: 'cohort', width: 90, render: (value?: number) => value === undefined ? t('values.placeholder') : value + 1 },
    { title: t('rollout.released'), dataIndex: 'released', width: 100, render: (value?: boolean) => value === undefined ? t('values.placeholder') : t(value ? 'values.yes' : 'values.no') },
    {
      title: t('columns.state'), dataIndex: 'state', width: 130,
      // fix-cfgflow2 §1: the node ignored an old release; not a failure.
      render: (value: string, item) => item.frozen
        // fix-stoppolicy2: refused while the node is frozen; redelivered after renewal.
        ? <Tooltip title={t('frozen.hint')}><Tag color="warning">{t('frozen.label')}</Tag></Tooltip>
        : item.superseded
          ? <Tooltip title={t('superseded.hint')}><Tag color="default">{t('superseded.label')}</Tag></Tooltip>
          : <Tag>{t(`deploymentStates.${value}`)}</Tag>,
    },
    {
      title: t('columns.errorCode'), dataIndex: 'error_code', width: 190,
      render: (value: string | undefined, item) => item.superseded && value
        ? t(`superseded.reasons.${value}`, { defaultValue: t('superseded.label') })
        : value ?? t('values.placeholder'),
    },
    ...(isPlatform ? [{
      title: t('columns.warnings'), dataIndex: 'warnings', width: 220,
      render: (value?: DeploymentWarning[]) => value?.length
        ? value.map((warning) => <Tooltip key={warning} title={t(`deploymentWarnings.${warning}.hint`)}>
          <Tag color="error">{t(`deploymentWarnings.${warning}.label`)}</Tag>
        </Tooltip>)
        : t('values.placeholder'),
    }] : []),
    {
      title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180,
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value,
    },
  ]

  const publicationLoading = publicationsQuery.isFetching
  const rolloutLoading = rolloutsQuery.isFetching
  const publicationError = publicationsQuery.error && !publicationsQuery.isFetching && !(publicationsQuery.error instanceof ApiError && publicationsQuery.error.status === 403)
  const rolloutError = rolloutsQuery.error && !rolloutsQuery.isFetching && !(rolloutsQuery.error instanceof ApiError && rolloutsQuery.error.status === 403)

  const publicationContent = (
    <>
      {publicationError ? (
        <FeedbackWhen title={t('errors.publicationLoadFailed')} detail={errorText(publicationsQuery.error, t)} action={<Button onClick={() => void publicationsQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      <div className="site-publications-table" aria-label={t('accessibility.publicationTable')} aria-busy={publicationLoading}>
        <Table<Publication>
          rowKey="id"
          size="middle"
          columns={publicationColumns}
          dataSource={publicationsQuery.data?.items ?? []}
          loading={publicationLoading}
          pagination={false}
          scroll={{ x: 1030 }}
          locale={{ emptyText: publicationsQuery.error ? ' ' : t('empty.publications') }}
        />
      </div>
      <CursorPagination
        label={t('pagination.publications')}
        page={publicationCursors.length + 1}
        canNext={Boolean(publicationsQuery.data?.next_cursor)}
        previous={() => setPublicationPages({ key: scopeKey, cursors: publicationCursors.slice(0, -1) })}
        next={() => {
          if (publicationsQuery.data?.next_cursor) {
            setPublicationPages({ key: scopeKey, cursors: [...publicationCursors, publicationsQuery.data.next_cursor] })
          }
        }}
        t={t}
      />
    </>
  )

  const rolloutContent = (
    <>
      {rolloutError ? (
        <FeedbackWhen title={t('errors.rolloutLoadFailed')} detail={errorText(rolloutsQuery.error, t)} action={<Button onClick={() => void rolloutsQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      <div className="site-publications-table" aria-label={t('accessibility.rolloutTable')} aria-busy={rolloutLoading}>
        <Table<Rollout>
          rowKey="id"
          size="middle"
          columns={rolloutColumns}
          dataSource={rolloutsQuery.data?.items ?? []}
          loading={rolloutLoading}
          pagination={false}
          scroll={{ x: 1225 }}
          locale={{ emptyText: rolloutsQuery.error ? ' ' : t('empty.rollouts') }}
        />
      </div>
      <CursorPagination
        label={t('pagination.rollouts')}
        page={rolloutCursors.length + 1}
        canNext={Boolean(rolloutsQuery.data?.next_cursor)}
        previous={() => setRolloutPages({ key: scopeKey, cursors: rolloutCursors.slice(0, -1) })}
        next={() => {
          if (rolloutsQuery.data?.next_cursor) {
            setRolloutPages({ key: scopeKey, cursors: [...rolloutCursors, rolloutsQuery.data.next_cursor] })
          }
        }}
        t={t}
      />
    </>
  )

  return (
    <section className="site-publications-page" aria-labelledby="site-publications-title">
      {messageContext}
      <div className="site-publications-heading">
        <div>
          <h1 id="site-publications-title">{t('title')}</h1>
          <p>{t('subtitle')}</p>
        </div>
        <Space wrap>
          <Button
            icon={<RefreshCw size={15} />}
            disabled={!audience}
            onClick={() => {
              // refetch() ignores `enabled`; without a target tenant it would hit the tenant endpoint.
              if (!audience) return
              if (activeTab === 'publications') void publicationsQuery.refetch()
              else void rolloutsQuery.refetch()
            }}
          >
            {t('actions.refresh')}
          </Button>
        </Space>
      </div>

      {isPlatform ? (
        <div className="site-publications-target">
          <TenantScopeSelect
            accessToken={accessToken}
            ownerKey={ownerKey}
            canList={canListTenants}
            queryKeyPrefix="site-publication-tenants"
            ariaLabel={t('targetScope.label')}
            placeholder={t('targetScope.placeholder')}
            value={targetScopeID}
            status={targetScopeError ? 'error' : undefined}
            onChange={applyTargetScope}
            emptyText={t('targetScope.empty')}
          />
        </div>
      ) : null}
      {isPlatform && !audience ? (
        <Alert
          className="site-publications-alert"
          type={targetScopeError ? 'error' : 'info'}
          showIcon
          message={t(targetScopeError ? 'targetScope.invalid' : 'targetScope.required')}
        />
      ) : null}

      {publicationsQuery.data?.pending_modules?.length ? (
        <Alert
          className="site-publications-alert"
          type="warning"
          showIcon
          data-testid="site-publications-pending-modules"
          message={t('pendingModules.title')}
          description={t('pendingModules.description', {
            modules: publicationsQuery.data.pending_modules.map((item) => item.module).join(', '),
          })}
        />
      ) : null}

      {publicationsQuery.data?.automatic_failure ? (
        <FeedbackWhen title={automaticFailureTitle(publicationsQuery.data.automatic_failure, t)} detail={t(`automaticFailure.${publicationsQuery.data.automatic_failure.reason}.description`, {
            revision: publicationsQuery.data.automatic_failure.source_revision,
          })} />
      ) : null}

      {visibleWriteAttempt ? (
        <OutcomeUnknown title={t('errors.outcomeUnknown')} detail={t('errors.outcomeUnknownDescription')} action={canManage ? (
            <Space wrap>
              <Button
                loading={writeMutation.isPending}
                disabled={Boolean(visibleFactsRefreshAttempt)}
                onClick={() => writeMutation.mutate(visibleWriteAttempt)}
              >
                {t('actions.retrySame')}
              </Button>
              <Button
                loading={Boolean(visibleFactsRefreshAttempt)}
                onClick={() => void refreshUnknownWriteFacts(visibleWriteAttempt)}
              >
                {t('actions.refreshFacts')}
              </Button>
            </Space>
          ) : null} className="site-publications-alert" />
      ) : visibleWriteError ? (
        <FeedbackWhen title={t('errors.writeFailed')} detail={errorText(visibleWriteError, t)} />
      ) : null}

      {canManage && audience?.kind === 'platform' && publicationsQuery.data?.current_source_revision ? (
        lineGroupsQuery.error ? (
          <FeedbackWhen title={t('errors.lineGroupsUnavailable')} action={<Button onClick={() => void lineGroupsQuery.refetch()}>{t('actions.retry')}</Button>} />
        ) : (
          <LineGroupSwitchPanel
            accessToken={accessToken}
            scopeID={scopeID}
            currentSourceRevision={publicationsQuery.data.current_source_revision}
            snapshots={lineSwitchSnapshots}
            canManage={canManage}
            loadSnapshot={loadLineSwitchSnapshot}
            onChanged={() => void invalidateScopeFacts()}
          />
        )
      ) : null}

      {audience ? (
        <Tabs
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key as TabKey)}
          items={[
            { key: 'publications', label: t('tabs.publications'), children: publicationContent },
            { key: 'rollouts', label: t('tabs.rollouts'), children: rolloutContent },
          ]}
        />
      ) : null}

      {visiblePublication ? <Drawer
        className="site-publications-drawer"
        title={t('detail.publicationTitle')}
        width={720}
        open
        closable={{ 'aria-label': t('actions.close') }}
        onClose={() => setSelectedPublication(null)}
      >
        {publicationDetailQuery.error ? (
          <Alert type="error" showIcon message={t('errors.detailLoadFailed')} description={errorText(publicationDetailQuery.error, t)} action={
            <Button onClick={() => void publicationDetailQuery.refetch()}>{t('actions.retry')}</Button>
          } />
        ) : publicationDetailQuery.data ? (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t('detail.publicationId')}><code>{publicationDetailQuery.data.id}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.configVersion')}><code>{publicationDetailQuery.data.config_version_id}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.rolloutId')}><code>{publicationDetailQuery.data.rollout_id}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.sourceRevision')}>{publicationDetailQuery.data.source_revision}</Descriptions.Item>
            <Descriptions.Item label={t('detail.target')}>{t(`targets.${publicationDetailQuery.data.target.kind}`)}</Descriptions.Item>
            <Descriptions.Item label={t('detail.nodeCount')}>{publicationDetailQuery.data.node_count}</Descriptions.Item>
            {'artifact_sha256' in publicationDetailQuery.data &&
            typeof publicationDetailQuery.data.artifact_sha256 === 'string' ? (
              <Descriptions.Item label={t('detail.artifactDigest')}><code>{publicationDetailQuery.data.artifact_sha256}</code></Descriptions.Item>
            ) : null}
            <Descriptions.Item label={t('detail.createdAt')}>
              {formatDateTime(publicationDetailQuery.data.created_at, i18n.resolvedLanguage)}
            </Descriptions.Item>
          </Descriptions>
        ) : <div className="site-publications-loading">{t('accessibility.loading')}</div>}
      </Drawer> : null}

      {visibleRollout ? <Drawer
        className="site-publications-drawer"
        title={t('detail.rolloutTitle')}
        width={720}
        open
        closable={{ 'aria-label': t('actions.close') }}
        onClose={() => setSelectedRollout(null)}
      >
        {rolloutDetailQuery.error ? (
          <Alert type="error" showIcon message={t('errors.detailLoadFailed')} description={errorText(rolloutDetailQuery.error, t)} action={
            <Button onClick={() => void rolloutDetailQuery.refetch()}>{t('actions.retry')}</Button>
          } />
        ) : rolloutDetailQuery.data ? (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t('detail.rolloutId')}><code>{rolloutDetailQuery.data.id}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.configVersion')}><code>{rolloutDetailQuery.data.config_version_id}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.state')}>{t(`states.${rolloutDetailQuery.data.state}`)}</Descriptions.Item>
            <Descriptions.Item label={t('detail.revision')}>{rolloutDetailQuery.data.revision}</Descriptions.Item>
            <Descriptions.Item label={t('detail.progress')}>
              {progressSummary(rolloutDetailQuery.data.progress)}
            </Descriptions.Item>
            {rolloutDetailQuery.data.rollout ? <>
              <Descriptions.Item label={t('rollout.strategy')}>{t('rollout.canary')}</Descriptions.Item>
              <Descriptions.Item label={t('rollout.canarySize')}>{rolloutDetailQuery.data.rollout.canary_size}</Descriptions.Item>
              <Descriptions.Item label={t('rollout.batchSize')}>{rolloutDetailQuery.data.rollout.batch_size}</Descriptions.Item>
              <Descriptions.Item label={t('rollout.failureThreshold')}>{rolloutDetailQuery.data.rollout.failure_threshold}</Descriptions.Item>
              <Descriptions.Item label={t('rollout.releasedCohort')}>
                {rolloutDetailQuery.data.rollout.released_cohort + 1}/{rolloutDetailQuery.data.rollout.cohort_count}
              </Descriptions.Item>
            </> : null}
          </Descriptions>
        ) : <div className="site-publications-loading">{t('accessibility.loading')}</div>}
      </Drawer> : null}

      {visibleDeploymentRollout ? <Drawer
        className="site-publications-drawer"
        title={t('deployments.title')}
        width={isPlatform ? 900 : 720}
        open
        closable={{ 'aria-label': t('actions.close') }}
        onClose={() => setDeploymentRollout(null)}
      >
        {deploymentsQuery.error ? (
          <Alert type="error" showIcon message={t('errors.deploymentLoadFailed')} description={errorText(deploymentsQuery.error, t)} action={
            <Button onClick={() => void deploymentsQuery.refetch()}>{t('actions.retry')}</Button>
          } />
        ) : null}
        <Table
          rowKey="id"
          size="small"
          columns={deploymentColumns}
          dataSource={(deploymentsQuery.data?.items ?? []) as Array<TenantSiteDeployment & { node_id?: string }>}
          loading={deploymentsQuery.isLoading}
          pagination={false}
          scroll={{ x: isPlatform ? 900 : 650 }}
          locale={{ emptyText: t('empty.deployments') }}
        />
        <CursorPagination
          label={t('pagination.deployments')}
          page={deploymentCursors.length + 1}
          canNext={Boolean(deploymentsQuery.data?.next_cursor)}
          previous={() => setDeploymentPages({ key: deploymentKey, cursors: deploymentCursors.slice(0, -1) })}
          next={() => {
            if (deploymentsQuery.data?.next_cursor) {
              setDeploymentPages({ key: deploymentKey, cursors: [...deploymentCursors, deploymentsQuery.data.next_cursor] })
            }
          }}
          t={t}
        />
      </Drawer> : null}
    </section>
  )
}
