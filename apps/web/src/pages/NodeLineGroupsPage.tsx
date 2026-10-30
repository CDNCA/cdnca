import { useCallback, useEffect, useMemo, useRef, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Modal, Result, Select, Table, Tag, Tooltip, type TableColumnsType } from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, InlineNotice, OutcomeUnknown, submitErrorFields } from '@cdnca/ui'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  l2TopologyApi,
  nodeSchedulingApi,
  type NodeLineGroup,
  type NodeLineGroupSnapshotInput,
  type NodeLineGroupWriteResult,
  type NodeSchedulingWriteMetadata,
} from '../api/nodeScheduling'
import { regionsApi } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import LineGroupSnapshotModal from './node-scheduling/LineGroupSnapshotModal'
import './node-scheduling/messages'
import {
  outcomeUnknown,
  requestMetadata,
  revisionMetadata,
  schedulingError,
  schedulingScope,
} from './node-scheduling/shared'
import './NodeSchedulingPage.css'
import './NodeLineGroupsPage.css'

interface LineWriteAttempt {
  kind: 'create' | 'update'
  groupID?: string
  input: NodeLineGroupSnapshotInput
  metadata: NodeSchedulingWriteMetadata
  ownerKey: string
  queryKey: LineGroupsQueryKey
}

interface LineWriteError {
  error: unknown
  ownerKey: string
}

interface LineDeleteTarget {
  groupID: string
  name: string
  revision: number
  metadata: NodeSchedulingWriteMetadata
}

interface LineDeleteAttempt {
  targets: LineDeleteTarget[]
  ownerKey: string
  queryKey: LineGroupsQueryKey
}

class LineDeleteBatchError extends Error {
  constructor(
    readonly failure: unknown,
    readonly remaining: LineDeleteTarget[],
    readonly completedGroupIDs: string[],
  ) {
    super('Line-group delete batch did not complete')
  }
}

type LineGroupsQueryKey = readonly [
  'node-line-groups',
  Principal['scope_kind'],
  string,
  string | null,
  string,
  number,
  NodeSchedulingScopeKind,
  string,
]

type LineGroupsOwner = readonly [Principal['scope_kind'], string, string | null, string, number]
type NodeSchedulingScopeKind = 'tenant' | 'platform' | ''
type LineGroupsPermission = 'read' | 'manage'

const allRegionsValue = '__all_regions__'
const staleLineGroupsRead = new Error('Line-group session owner changed during read')
const staleLineGroupsWrite = new Error('Line-group session owner changed during write')

function lineGroupsOwner(principal: Principal, sessionEpoch: number): LineGroupsOwner | null {
  if (!principal.scope_id || !principal.user_id || !sessionEpoch) return null
  if (principal.scope_kind === 'tenant') {
    if (!principal.tenant_id) return null
  } else if (principal.tenant_id !== null) {
    return null
  }
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function lineGroupsCanRead(principal: Principal): boolean {
  return principal.permissions.includes('node_scheduling.read')
}

function lineGroupsCanManage(principal: Principal): boolean {
  return lineGroupsCanRead(principal) && principal.permissions.includes('node_scheduling.manage')
}

function currentLineGroupsAccess(ownerKey: string, permission: LineGroupsPermission): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = lineGroupsOwner(principal, sessionEpoch)
  if (!owner || JSON.stringify(owner) !== ownerKey || !lineGroupsCanRead(principal)) return null
  if (permission === 'manage' && !lineGroupsCanManage(principal)) return null
  return accessToken
}

function lineWriteOutcomeUnknown(error: unknown): boolean {
  if (!outcomeUnknown(error)) return false
  return !(error instanceof ApiError && error.status >= 500 &&
    !['invalid_response', 'node_scheduling_unavailable', 'request_failed'].includes(error.code))
}

function lineGroupRegions(group: NodeLineGroup): string[] {
  return [...new Set([
    group.region,
    ...group.endpoints.map((endpoint) => endpoint.region),
  ].filter(Boolean))]
}

function lineGroupResolvedValues(group: NodeLineGroup): string[] {
  const ipv4ResolvedValue = group.ipv4_resolved_value?.trim()
  return [ipv4ResolvedValue
    ? `${group.resolved_value}（IPv4: ${ipv4ResolvedValue}）`
    : group.resolved_value]
}

export default function NodeLineGroupsPage() {
  const { t } = useTranslation('nodeScheduling')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  const owner = lineGroupsOwner(principal, sessionEpoch)
  if (!owner || !lineGroupsCanRead(principal)) {
    return (
      <Result
        className="node-scheduling-page"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const ownerKey = JSON.stringify(owner)
  return (
    <NodeLineGroupsContent
      key={ownerKey}
      principal={principal}
      owner={owner}
      ownerKey={ownerKey}
      canManage={lineGroupsCanManage(principal)}
    />
  )
}

function NodeLineGroupsContent({
  principal,
  owner,
  ownerKey,
  canManage,
}: {
  principal: Principal
  owner: LineGroupsOwner
  ownerKey: string
  canManage: boolean
}) {
  const { t, i18n } = useTranslation('nodeScheduling')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const queryOwner = useRef(owner).current
  const lineageActiveRef = useRef(true)
  const scope = schedulingScope(principal, principal.scope_kind === 'platform' ? principal.scope_id : '')
  const canManageCurrentScope = canManage
  const [searchDraft, setSearchDraft] = useState('')
  const [search, setSearch] = useState('')
  const [region, setRegion] = useState('')
  const [pageSize, setPageSize] = useState(10)
  const [pageIndex, setPageIndex] = useState(0)
  const [selectedKeys, setSelectedKeys] = useState<Key[]>([])
  const [selectNotice, setSelectNotice] = useState(false)
  const [editing, setEditing] = useState<NodeLineGroup | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [writeAttempt, setWriteAttempt] = useState<LineWriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<LineWriteError | null>(null)
  const [fieldError, setFieldError] = useState<unknown>(null)
  const [deleteTargets, setDeleteTargets] = useState<NodeLineGroup[]>([])
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  // UX-LG-EMPTY-01：刚建的空线路组（还没有 IP）给出下一步。
  const [createdEmpty, setCreatedEmpty] = useState<{ id: string; name: string; ownerKey: string } | null>(null)
  const [deleteAttempt, setDeleteAttempt] = useState<LineDeleteAttempt | null>(null)
  const [deleteError, setDeleteError] = useState<LineWriteError | null>(null)
  const queryPrefix = useMemo(() => ['node-line-groups', ...queryOwner] as const, [queryOwner])
  const mutationPrefix = useMemo(() => ['node-line-groups-write', ...queryOwner] as const, [queryOwner])
  const scopeKind: NodeSchedulingScopeKind = scope?.kind ?? ''
  const targetScope = scope?.kind === 'platform' ? scope.targetScopeId : ''
  const queryKey = useMemo<LineGroupsQueryKey>(
    () => [...queryPrefix, scopeKind, targetScope],
    [queryPrefix, scopeKind, targetScope],
  )
  const mutationKey = useMemo(
    () => [...mutationPrefix, scopeKind, targetScope] as const,
    [mutationPrefix, scopeKind, targetScope],
  )
  const queryIdentity = JSON.stringify(queryKey)
  const activeQueryIdentityRef = useRef(queryIdentity)
  activeQueryIdentityRef.current = queryIdentity
  const currentSessionAccess = useCallback((permission: LineGroupsPermission) => (
    lineageActiveRef.current ? currentLineGroupsAccess(ownerKey, permission) : null
  ), [ownerKey])
  const activeWriteAttempt = writeAttempt?.ownerKey === ownerKey ? writeAttempt : null
  const activeWriteError = writeError?.ownerKey === ownerKey ? writeError.error : null
  const activeDeleteAttempt = deleteAttempt?.ownerKey === ownerKey ? deleteAttempt : null
  const activeDeleteError = deleteError?.ownerKey === ownerKey ? deleteError.error : null
  const activeOperationAttempt = activeWriteAttempt ?? activeDeleteAttempt
  const activeOperationError = activeWriteError ?? activeDeleteError

  const groupsQuery = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw staleLineGroupsRead
      try {
        const result = await nodeSchedulingApi.list(token, scope!)
        if (!currentSessionAccess('read') || activeQueryIdentityRef.current !== queryIdentity) {
          throw staleLineGroupsRead
        }
        return result
      } catch (error) {
        if (!currentSessionAccess('read') || activeQueryIdentityRef.current !== queryIdentity) {
          throw staleLineGroupsRead
        }
        throw error
      }
    },
    enabled: Boolean(scope),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })

  useEffect(() => {
    lineageActiveRef.current = true
    const cleanupOwnerCache = () => {
      queryClient.removeQueries({ queryKey: queryPrefix })
      const mutationCache = queryClient.getMutationCache()
      for (const mutation of mutationCache.findAll({ mutationKey: mutationPrefix })) {
        mutationCache.remove(mutation)
      }
    }
    return () => {
      lineageActiveRef.current = false
      if (!currentLineGroupsAccess(ownerKey, 'read')) {
        cleanupOwnerCache()
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) cleanupOwnerCache()
      })
    }
  }, [mutationPrefix, ownerKey, queryClient, queryPrefix])

  useEffect(() => () => {
    if (activeQueryIdentityRef.current !== queryIdentity) {
      queryClient.removeQueries({ queryKey, exact: true })
    }
  }, [queryClient, queryIdentity, queryKey])

  useEffect(() => {
    setSelectedKeys([])
  }, [queryIdentity])

  const visibleGroups = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase()
    const groups = groupsQuery.data?.items ?? []
    if (!needle && !region) return groups
    return groups.filter((group) => [
      group.id,
      group.display_id,
      group.name,
      group.region,
      group.resolved_value,
      ...group.endpoints.flatMap((endpoint) => [endpoint.address, endpoint.region, endpoint.carrier]),
    ].some((value) => value.toLocaleLowerCase().includes(needle)) && (
      !region || lineGroupRegions(group).includes(region)
    ))
  }, [groupsQuery.data?.items, region, search])
  const regions = useMemo(() => [...new Set((groupsQuery.data?.items ?? [])
    .flatMap(lineGroupRegions))].sort(), [groupsQuery.data?.items])
  // Packages only accept a line group whose region is a catalogued region, so
  // the create dialog must offer the region catalog, not only the regions
  // existing groups already use (a fresh install has none).
  const canReadRegions = principal.permissions.includes('platform.admin') || principal.permissions.includes('regions.read')
  const catalogRegionsQuery = useQuery({
    queryKey: [...queryPrefix, 'region-catalog'],
    queryFn: async () => {
      const names: string[] = []
      for (let page = 1; ; page += 1) {
        const token = currentSessionAccess('read')
        if (!token) throw staleLineGroupsRead
        const result = await regionsApi.list(token, { page, page_size: 300 })
        names.push(...result.data.map((item) => item.name))
        if (page * 300 >= result.count) return names
      }
    },
    enabled: Boolean(scope) && canReadRegions && canManageCurrentScope,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const createRegionOptions = useMemo(() => [...new Set([...(catalogRegionsQuery.data ?? []), ...regions])],
    [catalogRegionsQuery.data, regions])
  // L2配置 is an L2 topology configuration (节点管理 > L2配置, migration 504),
  // never another line group: its region is empty (any) or the group's.
  const l2ConfigsQuery = useQuery({
    queryKey: [...queryKey, 'l2-configs'],
    queryFn: async () => {
      const token = currentSessionAccess('read')
      if (!token) throw staleLineGroupsRead
      return l2TopologyApi.configs(token, scope!)
    },
    // read only when a name is shown or the editor offers the choice
    enabled: Boolean(scope) && (Boolean(editing) ||
      (groupsQuery.data?.items ?? []).some((group) => group.l2_config_id)),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const l2ConfigNames = useMemo(() => new Map((l2ConfigsQuery.data?.items ?? [])
    .map((config) => [config.id, config.name])), [l2ConfigsQuery.data?.items])
  const l2ConfigOptions = useMemo(() => (l2ConfigsQuery.data?.items ?? [])
    .filter((config) => config.region === '' || config.region === editing?.region)
    .map((config) => ({ value: config.id, label: config.name })), [editing?.region, l2ConfigsQuery.data?.items])
  const pageCount = Math.max(1, Math.ceil(visibleGroups.length / pageSize))
  const safePageIndex = Math.min(pageIndex, pageCount - 1)
  const pageItems = visibleGroups.slice(safePageIndex * pageSize, (safePageIndex + 1) * pageSize)

  const writeMutation = useMutation<NodeLineGroupWriteResult, unknown, LineWriteAttempt>({
    mutationKey,
    mutationFn: async (attempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('manage') : null
      if (!token) throw staleLineGroupsWrite
      try {
        const result = await (attempt.kind === 'create'
          ? nodeSchedulingApi.create(token, attempt.input, attempt.metadata)
          : nodeSchedulingApi.update(token, attempt.groupID!, attempt.input, attempt.metadata))
        if (!currentSessionAccess('manage')) throw staleLineGroupsWrite
        return result
      } catch (error) {
        if (!currentSessionAccess('manage')) throw staleLineGroupsWrite
        throw error
      }
    },
    onSuccess: async (result, attempt) => {
      if (attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      setCreatedEmpty(attempt.kind === 'create' && result.group.endpoints.length === 0
        ? { id: result.group.id, name: result.group.name, ownerKey: attempt.ownerKey } : null)
      setWriteAttempt(null)
      setWriteError(null)
      setModalOpen(false)
      setEditing(null)
      messageApi.success(t(attempt.kind === 'create' ? 'notices.created' : 'notices.updated'))
      await queryClient.invalidateQueries({ queryKey: attempt.queryKey })
    },
    onError: (error, attempt) => {
      if (error === staleLineGroupsWrite || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      // A refused field stays in the open form, marked where it is (fix-fielderr-be).
      if (submitErrorFields(error).length > 0) {
        setWriteAttempt(null)
        setFieldError(error)
        return
      }
      setWriteError({ error, ownerKey: attempt.ownerKey })
      setModalOpen(false)
      if (lineWriteOutcomeUnknown(error)) {
        setWriteAttempt(attempt)
      } else {
        setWriteAttempt(null)
        if (error instanceof ApiError && [409, 412].includes(error.status)) {
          void queryClient.invalidateQueries({ queryKey: attempt.queryKey, exact: true })
        }
      }
    },
    retry: false,
  })

  // fix-nopkg (migration 533): the platform default line group, platform scope only.
  const platformDefaultMutation = useMutation<unknown, unknown, { groupID: string; isDefault: boolean }>({
    mutationFn: async ({ groupID, isDefault }) => {
      const token = currentSessionAccess('manage')
      if (!token) throw staleLineGroupsWrite
      return nodeSchedulingApi.setPlatformDefault(token, groupID, isDefault, requestMetadata('platform-default'))
    },
    onSuccess: async (_, { isDefault }) => {
      messageApi.success(t(isDefault ? 'notices.platformDefaultSet' : 'notices.platformDefaultUnset'))
      await queryClient.invalidateQueries({ queryKey })
    },
    onError: (error) => {
      if (error === staleLineGroupsWrite) return
      feedback.error(schedulingError(error, t))
    },
    retry: false,
  })

  const deleteMutation = useMutation<string[], unknown, LineDeleteAttempt>({
    mutationKey,
    mutationFn: async (attempt) => {
      const completedGroupIDs: string[] = []
      for (let index = 0; index < attempt.targets.length; index += 1) {
        const target = attempt.targets[index]
        const token = attempt.ownerKey === ownerKey ? currentSessionAccess('manage') : null
        if (!token) throw staleLineGroupsWrite
        try {
          await nodeSchedulingApi.remove(token, target.groupID, target.metadata)
          if (!currentSessionAccess('manage')) throw staleLineGroupsWrite
          completedGroupIDs.push(target.groupID)
        } catch (error) {
          if (!currentSessionAccess('manage')) throw staleLineGroupsWrite
          throw new LineDeleteBatchError(error, attempt.targets.slice(index), completedGroupIDs)
        }
      }
      return completedGroupIDs
    },
    onSuccess: async (completedGroupIDs, attempt) => {
      if (attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      setDeleteAttempt(null)
      setDeleteError(null)
      setDeleteConfirmOpen(false)
      setDeleteTargets([])
      setSelectedKeys((current) => current.filter((key) => !completedGroupIDs.includes(String(key))))
      messageApi.success(t(completedGroupIDs.length === 1 ? 'notices.deleted' : 'notices.batchDeleted', {
        count: completedGroupIDs.length,
      }))
      await queryClient.invalidateQueries({ queryKey: attempt.queryKey })
    },
    onError: (error, attempt) => {
      if (error === staleLineGroupsWrite || attempt.ownerKey !== ownerKey || !currentSessionAccess('manage')) return
      const failure = error instanceof LineDeleteBatchError ? error : new LineDeleteBatchError(error, attempt.targets, [])
      setDeleteConfirmOpen(false)
      setDeleteTargets([])
      setSelectedKeys(failure.remaining.map((target) => target.groupID))
      setDeleteError({ error: failure.failure, ownerKey: attempt.ownerKey })
      if (lineWriteOutcomeUnknown(failure.failure)) {
        setDeleteAttempt({ ...attempt, targets: failure.remaining })
      } else {
        setDeleteAttempt(null)
      }
      if (failure.completedGroupIDs.length > 0 || failure.failure instanceof ApiError && [404, 409, 412].includes(failure.failure.status)) {
        void queryClient.invalidateQueries({ queryKey: attempt.queryKey, exact: true })
      }
    },
    retry: false,
  })

  const operationPending = writeMutation.isPending || deleteMutation.isPending

  if (groupsQuery.error instanceof ApiError && groupsQuery.error.status === 403) {
    return (
      <Result
        className="node-scheduling-page"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const submitSnapshot = (input: NodeLineGroupSnapshotInput) => {
    if (!canManageCurrentScope || !currentSessionAccess('manage') || operationPending || activeOperationAttempt) return
    const attempt: LineWriteAttempt = editing ? {
      kind: 'update',
      groupID: editing.id,
      input,
      metadata: revisionMetadata('update', editing.revision),
      ownerKey,
      queryKey,
    } : {
      kind: 'create',
      input,
      metadata: revisionMetadata('create', 0),
      ownerKey,
      queryKey,
    }
    setWriteError(null)
    setFieldError(null)
    writeMutation.mutate(attempt)
  }

  const requestDelete = (targets: NodeLineGroup[]) => {
    if (!canManageCurrentScope || operationPending || activeOperationAttempt || targets.length === 0) return
    setDeleteError(null)
    setDeleteTargets(targets)
    setDeleteConfirmOpen(true)
  }

  const confirmDelete = () => {
    if (!canManageCurrentScope || operationPending || activeOperationAttempt || deleteTargets.length === 0 ||
      !currentSessionAccess('manage')) return
    const attempt: LineDeleteAttempt = {
      ownerKey,
      queryKey,
      targets: deleteTargets.map((group) => ({
        groupID: group.id,
        name: group.name,
        revision: group.revision,
        metadata: revisionMetadata(`delete-${group.id}`, group.revision),
      })),
    }
    setDeleteError(null)
    deleteMutation.mutate(attempt)
  }

  const reconcileUnknown = async () => {
    await groupsQuery.refetch()
  }

  const columns: TableColumnsType<NodeLineGroup> = [
    {
      title: t('columns.id'),
      dataIndex: 'id',
      className: 'node-line-group-col-id',
      width: 69,
      render: (value: string, group) => <span title={value}>{group.display_id}</span>,
    },
    {
      title: t('columns.name'),
      dataIndex: 'name',
      className: 'node-line-group-col-name',
      width: 105,
      ellipsis: true,
      render: (value: string, group) => (
        <>
          <Button
            type="link"
            className="node-line-group-name"
            disabled={operationPending || Boolean(activeOperationAttempt)}
            onClick={() => { setEditing(group); setWriteError(null); setModalOpen(true) }}
          >
            {value}
          </Button>
          {group.is_platform_default ? (
            <Tag color="blue" data-testid="line-group-platform-default">{t('notices.platformDefaultTag')}</Tag>
          ) : null}
        </>
      ),
    },
    {
      title: t('columns.region'),
      className: 'node-line-group-col-region',
      width: 95,
      ellipsis: true,
      render: (_, group) => lineGroupRegions(group).join(', ') || t('values.defaultRegion'),
    },
    {
      title: t('columns.addresses'),
      className: 'node-line-group-col-addresses',
      width: 195,
      ellipsis: true,
      render: (_, group) => (
        <>
          {(group.backup_states ?? []).filter((state) => state.state === 'backup_active').map((state) => {
            const family = state.address_family === 6 ? 'IPv6' : 'IPv4'
            const detail = t('notices.backupActiveDetail', {
              family, addresses: state.backup_addresses.join('、'),
              changedAt: formatDateTime(state.changed_at, i18n.language) || state.changed_at,
            })
            return (
              <Tooltip key={state.address_family} title={detail} trigger={['hover', 'focus']}>
                <Tag className="node-line-group-backup-tag" color="warning" tabIndex={0} aria-label={detail} data-testid="line-group-backup-active">
                  {t('notices.backupActiveTag', { family })}
                </Tag>
              </Tooltip>
            )
          })}
          <div className="node-line-group-resolved">{lineGroupResolvedValues(group)[0] || t('values.placeholder')}</div>
        </>
      ),
    },
    {
      title: t('columns.statistics'),
      className: 'node-line-group-col-statistics',
      width: 225,
      render: (_, group) => group.statistics ? (
        <div className="node-line-group-statistics">
          {t('values.lineGroupStatistics', {
            nodeCount: group.statistics.node_count,
            siteCount: group.statistics.site_count,
            forwardCount: group.statistics.forward_count,
          })}
        </div>
      ) : t('values.placeholder'),
    },
    {
      title: t('columns.l2Configuration'),
      className: 'node-line-group-col-l2',
      width: 115,
      render: (_, group) => group.l2_config_id
        ? l2ConfigNames.get(group.l2_config_id) ?? group.l2_config_id
        : t('values.placeholder'),
    },
    {
      title: t('columns.sort'),
      className: 'node-line-group-col-sort',
      width: 76,
      render: (_, group) => group.sort_order,
    },
    {
      title: t('columns.actions'),
      className: 'node-line-group-col-actions',
      width: 156,
      align: 'center',
      render: (_, group) => canManageCurrentScope ? (
        <div className="node-line-group-actions">
          <Button type="link" onClick={() => navigate(`/node/line-group/line/${encodeURIComponent(group.id)}`)}>
            {t('actions.configureResolution')}
          </Button>
          <Button
            type="link"
            disabled={operationPending || Boolean(activeOperationAttempt)}
            onClick={() => { setEditing(group); setWriteError(null); setModalOpen(true) }}
          >
            {t('actions.edit')}
          </Button>
          {scopeKind === 'platform' ? (
            <Button
              type="link"
              disabled={operationPending || Boolean(activeOperationAttempt) || platformDefaultMutation.isPending}
              onClick={() => platformDefaultMutation.mutate({ groupID: group.id, isDefault: !group.is_platform_default })}
            >
              {t(group.is_platform_default ? 'actions.unsetPlatformDefault' : 'actions.setPlatformDefault')}
            </Button>
          ) : null}
          <Button
            type="link"
            disabled={operationPending || Boolean(activeOperationAttempt)}
            aria-label={t('actions.deleteLineGroup')}
            onClick={() => requestDelete([group])}
          >
            {t('actions.delete')}
          </Button>
        </div>
      ) : t('values.placeholder'),
    },
  ]

  return (
    <section className="node-scheduling-page node-line-groups-page" aria-labelledby="node-line-groups-title">
      {messageContext}
      <h1 id="node-line-groups-title">{t('titles.lineGroups')}</h1>
      <div className="node-line-groups-filter-toolbar">
        <div className="node-scheduling-toolbar-actions" role="toolbar" aria-label={t('aria.lineGroupActions')}>
          {canManageCurrentScope ? (
            <>
              <Button
                type="primary"
                className="node-line-primary-action"
                icon={<span className="node-line-reference-icon node-line-reference-icon-add" aria-hidden="true" />}
                disabled={!scope || operationPending || Boolean(activeOperationAttempt)}
                onClick={() => {
              setEditing(null)
              setWriteError(null)
              setModalOpen(true)
                }}
              >
                {t('actions.add')}
              </Button>
              <Button
                danger
                disabled={operationPending || Boolean(activeOperationAttempt)}
                className="node-line-delete-action"
                icon={<span className="node-line-reference-icon node-line-reference-icon-trash" aria-hidden="true" />}
                onClick={() => {
                  if (selectedKeys.length === 0) {
                    // fix-feedbackui2: said under the toolbar, not in a dialog.
                    setSelectNotice(true)
                    return
                  }
                  setSelectNotice(false)
                  requestDelete((groupsQuery.data?.items ?? []).filter((group) => selectedKeys.includes(group.id)))
                }}
              >
                {t('actions.delete')}
              </Button>
            </>
          ) : null}
        </div>
        <div className="node-scheduling-toolbar-filters" role="search" aria-label={t('aria.lineGroupFilters')}>
          <Select
            className="node-line-groups-region"
            aria-label={t('filters.regionLabel')}
            value={region || allRegionsValue}
            suffixIcon={<span className="node-line-reference-icon node-line-reference-icon-down" aria-hidden="true" />}
            options={[
              { value: allRegionsValue, label: t('filters.allRegions') },
              ...regions.map((value) => ({ value, label: value })),
            ]}
            onChange={(value) => { setRegion(value === allRegionsValue ? '' : value); setPageIndex(0) }}
          />
          <div className="node-line-search">
            <Input
              className="node-scheduling-search"
              aria-label={t('filters.searchLabel')}
              placeholder={t('filters.searchPlaceholder')}
              value={searchDraft}
              onChange={(event) => setSearchDraft(event.target.value)}
              onPressEnter={() => { setSearch(searchDraft); setPageIndex(0) }}
              suffix={(
                <Button
                  type="text"
                  className="node-line-search-submit"
                  aria-label={t('actions.search')}
                  icon={<span className="node-line-reference-icon node-line-reference-icon-search" aria-hidden="true" />}
                  onClick={() => { setSearch(searchDraft); setPageIndex(0) }}
                />
              )}
            />
          </div>
          <Button
            type="link"
            className="node-line-clear"
            onClick={() => {
              setSearchDraft('')
              setSearch('')
              setRegion('')
              setPageIndex(0)
            }}
          >
            {t('actions.clear')}
          </Button>
        </div>
      </div>
      <InlineNotice type="warning" onClose={() => setSelectNotice(false)}>
        {selectNotice && selectedKeys.length === 0 ? t('values.selectBeforeDelete') : null}
      </InlineNotice>

      {activeOperationAttempt && lineWriteOutcomeUnknown(activeOperationError) ? (
        <OutcomeUnknown title={t('errors.outcomeUnknown')} detail={t('errors.outcomeUnknownDescription')} action={(
            <div className="node-scheduling-toolbar">
              <Button
                loading={operationPending}
                disabled={!canManageCurrentScope || operationPending}
                onClick={() => {
                  if (!canManageCurrentScope || operationPending) return
                  if (activeWriteAttempt) writeMutation.mutate(activeWriteAttempt)
                  else if (activeDeleteAttempt) deleteMutation.mutate(activeDeleteAttempt)
                }}
              >
                {t('actions.retrySame')}
              </Button>
              <Button
                loading={groupsQuery.isFetching}
                disabled={operationPending}
                onClick={() => void reconcileUnknown()}
              >
                {t('actions.refreshReconcile')}
              </Button>
            </div>
          )} className="node-scheduling-alert" />
      ) : activeOperationError ? (
        <FeedbackWhen title={t(activeDeleteError ? 'errors.deleteFailed' : 'errors.writeFailed')} detail={schedulingError(activeOperationError, t)} />
      ) : null}

      {groupsQuery.error && !(groupsQuery.error instanceof ApiError && groupsQuery.error.status === 403) ? (
        <FeedbackWhen title={t('errors.loadFailed')} detail={schedulingError(groupsQuery.error, t)} action={<Button onClick={() => void groupsQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}

      {createdEmpty?.ownerKey === ownerKey && canManageCurrentScope ? (
        <Alert
          className="node-scheduling-alert"
          type="info"
          showIcon
          closable
          onClose={() => setCreatedEmpty(null)}
          data-testid="node-line-groups-empty-next"
          message={t('notices.createdEmpty', { name: createdEmpty.name })}
          description={t('notices.createdEmptyNext')}
          action={(
            <Button size="small" type="primary" onClick={() => navigate(`/node/line-group/line/${encodeURIComponent(createdEmpty.id)}`)}>
              {t('actions.configureResolution')}
            </Button>
          )}
        />
      ) : null}

      <div className="node-scheduling-table-scroll node-line-groups-table-scroll" data-testid="node-line-groups-table" aria-busy={groupsQuery.isLoading}>
        <Table<NodeLineGroup>
          rowKey="id"
          size="middle"
          loading={groupsQuery.isLoading}
          columns={columns}
          dataSource={pageItems}
          pagination={false}
          scroll={{ x: '100%' }}
          tableLayout="fixed"
          rowSelection={canManageCurrentScope ? { columnWidth: 56, selectedRowKeys: selectedKeys, onChange: setSelectedKeys } : undefined}
          locale={{ emptyText: t(search ? 'empty.filtered' : 'empty.groups') }}
        />
      </div>
      <div className="node-scheduling-pagination">
        <span className="node-line-groups-total">{t('pagination.total', { count: visibleGroups.length })}</span>
        <Button
          aria-label={t('actions.previous')}
          icon={<span className="node-line-reference-icon node-line-reference-icon-back" aria-hidden="true" />}
          disabled={safePageIndex === 0}
          onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
        />
        <span className="node-scheduling-page-number" aria-current="page">{safePageIndex + 1}</span>
        <Button
          aria-label={t('actions.next')}
          icon={<span className="node-line-reference-icon node-line-reference-icon-forward" aria-hidden="true" />}
          disabled={safePageIndex + 1 >= pageCount}
          onClick={() => setPageIndex((current) => current + 1)}
        />
        <Select
          aria-label={t('filters.pageSizeLabel')}
          value={pageSize}
          suffixIcon={<span className="node-line-reference-icon node-line-reference-icon-down" aria-hidden="true" />}
          options={[10, 20, 50].map((count) => ({ value: count, label: t('filters.pageSize', { count }) }))}
          onChange={(value) => { setPageSize(value); setPageIndex(0) }}
        />
      </div>

      <Modal
        className="node-line-groups-delete-modal"
        title={t('dialogs.deleteTitle')}
        open={deleteConfirmOpen}
        onCancel={() => {
          if (deleteMutation.isPending) return
          setDeleteConfirmOpen(false)
          setDeleteTargets([])
        }}
        footer={[
          <Button
            key="cancel"
            disabled={deleteMutation.isPending}
            onClick={() => { setDeleteConfirmOpen(false); setDeleteTargets([]) }}
          >
            {t('actions.cancel')}
          </Button>,
          <Button
            key="confirm"
            type="primary"
            danger
            loading={deleteMutation.isPending}
            onClick={confirmDelete}
          >
            {t('actions.confirm')}
          </Button>,
        ]}
        destroyOnHidden
      >
        <p>{t('dialogs.deleteDescription', {
          ids: deleteTargets.map((group) => group.display_id).join(','),
        })}</p>
      </Modal>

      <LineGroupSnapshotModal
        item={editing}
        open={modalOpen}
        pending={writeMutation.isPending}
        regionOptions={createRegionOptions}
        l2ConfigOptions={l2ConfigOptions}
        submitError={modalOpen ? fieldError : null}
        onCancel={() => { if (!writeMutation.isPending) { setModalOpen(false); setFieldError(null) } }}
        onSubmit={submitSnapshot}
      />
    </section>
  )
}
