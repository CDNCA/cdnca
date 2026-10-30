import { useEffect, useMemo, useRef, useState, type HTMLAttributes } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, InputNumber, Popconfirm, Select, Space, Switch, Table, Tag, Tooltip, type TableColumnsType } from 'antd'
import { Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type ScopeKind } from '../../api/auth'
import { writeOutcomeUnknown } from './writeOutcome'
import {
  originRoutingApi,
  ORIGIN_BALANCE_METHODS,
  type OriginPool,
  type OriginRoute,
  type OriginRoutingDocument,
  type OriginRoutingState,
  sortOriginDocument,
  validateOriginRoutingState,
} from '../../api/siteOriginRouting'
import { useSessionStore } from '../../auth/session'
import '../../i18n/siteOriginRouting'
import { SettingRow, SettingSection } from './SiteEditFields'
import ConditionalOriginRouteDialog from './ConditionalOriginRouteDialog'
import { OutcomeUnknown, FeedbackWhen } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { useCommitRequest, useInstantFeedback } from './instantSave'

export interface ConditionalOriginSiteTabProps {
  siteId: string
  accessToken: string
  scopeKind: ScopeKind
  scopeId: string
  tenantId: string | null
  userId: string
  sessionEpoch: number
  permissions: readonly string[]
  canManage: boolean
  lockedForTenant: boolean
  // SITE-CURRENT-02：未保存草稿、请求中、结果未知都报给编辑页，统一离开/刷新保护。
  onWorkflowStateChange?: (state: { dirty: boolean; uncertain: boolean; pending: boolean }) => void
}

const staleLineage = new Error('stale origin routing lineage')
type OriginRoutingOwner = readonly [ScopeKind, string, string | null, string, number]
type WriteFailureKind = 'forbidden' | 'notFound' | 'conflict' | 'validation' | 'request' | 'unknown'

interface ReplaceAttempt {
  identity: string
  owner: OriginRoutingOwner
  siteId: string
  expectedVersion: number
  document: OriginRoutingDocument
  idempotencyKey: string
}

interface WriteFailure {
  identity: string
  kind: WriteFailureKind
  attempt: ReplaceAttempt | null
}

function hasPermission(props: ConditionalOriginSiteTabProps, permission: string): boolean {
  return props.permissions.includes(permission) || props.permissions.includes('platform.admin')
}

function currentAccess(props: ConditionalOriginSiteTabProps, permission: string): string | null {
  const session = useSessionStore.getState()
  const principal = session.principal
  if (!session.accessToken || !principal || !hasPermission({ ...props, permissions: principal.permissions }, permission)) return null
  if (session.sessionEpoch !== props.sessionEpoch || principal.scope_kind !== props.scopeKind || principal.scope_id !== props.scopeId || principal.tenant_id !== props.tenantId || principal.user_id !== props.userId) return null
  return session.accessToken
}

function errorState(error: unknown): 'forbidden' | 'notFound' | 'conflict' | 'request' {
  if (!(error instanceof ApiError)) return 'request'
  if (error.status === 403) return 'forbidden'
  if (error.status === 404) return 'notFound'
  if (error.status === 409 || error.status === 412) return 'conflict'
  return 'request'
}

function writeFailureKind(error: unknown): WriteFailureKind {
  if (error === staleLineage) return 'forbidden'
  if (!(error instanceof ApiError)) return 'unknown'
  if (writeOutcomeUnknown(error)) return 'unknown'
  if (error.status === 403) return 'forbidden'
  if (error.status === 404) return 'notFound'
  if (error.status === 409 || error.status === 412) return 'conflict'
  if (error.status === 422) return 'validation'
  return 'request'
}

function cloneDocument(document: OriginRoutingDocument): OriginRoutingDocument {
  return JSON.parse(JSON.stringify(document)) as OriginRoutingDocument
}

export default function ConditionalOriginSiteTab(props: ConditionalOriginSiteTabProps) {
  const { t } = useTranslation('siteOriginRouting')
  const queryClient = useQueryClient()
  const owner = useMemo<OriginRoutingOwner>(() => [props.scopeKind, props.scopeId, props.tenantId, props.userId, props.sessionEpoch], [props.scopeId, props.scopeKind, props.tenantId, props.userId, props.sessionEpoch])
  const key = useMemo(() => [...owner, props.siteId] as const, [owner, props.siteId])
  const identity = useMemo(() => JSON.stringify(key), [key])
  const identityRef = useRef(identity)
  identityRef.current = identity
  const canRead = hasPermission(props, 'sites.read')
  const canWrite = props.canManage && !props.lockedForTenant && hasPermission(props, 'sites.manage')
  const [document, setDocument] = useState<OriginRoutingDocument | null>(null)
  // CU-SITE-01：草稿基线（草稿所基于的服务端版本与文档）与远端最新快照分开。
  // 保存用基线版本；远端快照只在草稿未改动、或内容与基线相同（只是版本前进）时接管。
  const [baseline, setBaseline] = useState<{ identity: string; state: OriginRoutingState } | null>(null)
  // 草稿有改动时远端出现了不同内容：保留草稿与原版本，提示用户，由用户决定是否载入最新。
  const [remoteChanged, setRemoteChanged] = useState<OriginRoutingState | null>(null)
  const [writeFailure, setWriteFailure] = useState<WriteFailure | null>(null)
  const [routeEditor, setRouteEditor] = useState<{ originalId: string | null } | null>(null)
  const [reloading, setReloading] = useState(false)
  const instantFeedback = useInstantFeedback()
  // fix-siteinstant: the document a save sent; an edit made while it ran stays and is saved next.
  const sentRef = useRef<string | null>(null)
  const documentRef = useRef<OriginRoutingDocument | null>(null)
  documentRef.current = document
  const baselineRef = useRef(baseline)
  baselineRef.current = baseline

  const query = useQuery({
    queryKey: ['site-origin-routing', ...key],
    enabled: canRead,
    retry: false,
    queryFn: async () => {
      const token = currentAccess(props, 'sites.read')
      if (!token) throw staleLineage
      const result = await originRoutingApi.get(token, props.siteId)
      if (!currentAccess(props, 'sites.read')) throw staleLineage
      return result
    },
  })

  const adopt = (state: OriginRoutingState) => {
    setBaseline({ identity: identityRef.current, state })
    setDocument(sortOriginDocument(cloneDocument(state.document)))
    setRemoteChanged(null)
  }

  useEffect(() => {
    const remote = query.data
    if (!remote || !validateOriginRoutingState(remote)) return
    const base = baselineRef.current
    const draft = documentRef.current
    const sameAsBase = (doc: OriginRoutingDocument | null) => Boolean(base && doc &&
      JSON.stringify(sortOriginDocument(cloneDocument(doc))) === JSON.stringify(sortOriginDocument(cloneDocument(base.state.document))))
    if (!base || base.identity !== identityRef.current || !draft || (sameAsBase(draft) && sentRef.current === null)) {
      adopt(remote)
      return
    }
    if (sameAsBase(remote.document)) {
      // 内容没变、只是版本前进（自己的保存回写或相同内容的重新读取）：草稿换到新版本上，继续保留。
      setBaseline({ identity: base.identity, state: remote })
      setRemoteChanged(null)
      return
    }
    setRemoteChanged(remote)
  }, [query.data])

  useEffect(() => () => {
    const session = useSessionStore.getState()
    const principal = session.principal
    if (principal && session.sessionEpoch === props.sessionEpoch && principal.scope_kind === props.scopeKind && principal.scope_id === props.scopeId && principal.tenant_id === props.tenantId && principal.user_id === props.userId) return
    queryClient.removeQueries({ queryKey: ['site-origin-routing', ...key], exact: true })
  }, [key, props.scopeId, props.scopeKind, props.sessionEpoch, props.tenantId, props.userId, queryClient])

  const mutation = useMutation({
    retry: false,
    mutationFn: async (attempt: ReplaceAttempt) => {
      if (attempt.identity !== identityRef.current) throw staleLineage
      if (!validateOriginRoutingState({ ...query.data, version: attempt.expectedVersion, document: attempt.document })) throw new ApiError('Invalid document', 422, 'validation_error')
      const token = currentAccess(props, 'sites.manage')
      if (!token) throw staleLineage
      return originRoutingApi.replace(
        token,
        attempt.siteId,
        attempt.expectedVersion,
        cloneDocument(attempt.document),
        attempt.idempotencyKey,
      )
    },
    onSuccess: (saved: OriginRoutingState, attempt) => {
      if (attempt.identity !== identityRef.current || !currentAccess(props, 'sites.read')) return
      const editedSince = sentRef.current !== null && JSON.stringify(documentRef.current) !== sentRef.current
      sentRef.current = null
      // 保存成功：基线前进到返回的版本；发出后又改过的草稿保留，等下一次提交。
      setBaseline({ identity: attempt.identity, state: saved })
      setRemoteChanged(null)
      if (!editedSince) setDocument(sortOriginDocument(cloneDocument(saved.document)))
      instantFeedback.success()
      setWriteFailure(null)
      queryClient.setQueryData(['site-origin-routing', ...attempt.owner, attempt.siteId], saved)
    },
    onError: (error, attempt) => {
      if (attempt.identity !== identityRef.current) return
      const kind = writeFailureKind(error)
      setWriteFailure({ identity: attempt.identity, kind, attempt: kind === 'unknown' ? attempt : null })
      sentRef.current = null
      // A refused change goes back to the saved document; an unknown outcome keeps it for the exact retry.
      const base = baselineRef.current
      if (kind !== 'unknown' && base && base.identity === attempt.identity) {
        setDocument(sortOriginDocument(cloneDocument(base.state.document)))
      }
      if (kind === 'conflict') void query.refetch()
    },
  })

  const activeFailure = writeFailure?.identity === identity ? writeFailure : null
  const activePending = mutation.isPending && mutation.variables?.identity === identity
  const editLocked = !canWrite || activeFailure?.kind === 'unknown'
  const activeBaseline = baseline?.identity === identity ? baseline.state : null
  const documentDirty = Boolean(document && activeBaseline &&
    JSON.stringify(document) !== JSON.stringify(sortOriginDocument(cloneDocument(activeBaseline.document))))
  // 用户自己改回了基线：没有草稿要保护，直接接管已到的远端快照。
  useEffect(() => {
    if (remoteChanged && !documentDirty && !activePending) adopt(remoteChanged)
  }, [remoteChanged, documentDirty, activePending])
  const { onWorkflowStateChange } = props
  useEffect(() => {
    onWorkflowStateChange?.({ dirty: documentDirty, uncertain: activeFailure?.kind === 'unknown', pending: activePending })
  }, [activeFailure?.kind, activePending, documentDirty, onWorkflowStateChange])
  useEffect(() => () => {
    onWorkflowStateChange?.({ dirty: false, uncertain: false, pending: false })
  }, [onWorkflowStateChange])

  useEffect(() => {
    setRouteEditor(null)
  }, [canWrite, identity])

  const conflictPending = Boolean(remoteChanged && documentDirty)
  // 冲突期间不自动提交（必然被版本冲突拒绝）；用户在提示条上选择载入最新或用自己的修改覆盖。
  const save = (overwrite?: OriginRoutingState) => {
    if (!document || !activeBaseline || !canWrite || activePending || activeFailure?.kind === 'unknown' || !documentDirty) return
    if (conflictPending && !overwrite) return
    sentRef.current = JSON.stringify(document)
    const attempt: ReplaceAttempt = {
      identity,
      owner,
      siteId: props.siteId,
      expectedVersion: overwrite ? overwrite.version : activeBaseline.version,
      document: sortOriginDocument(cloneDocument(document)),
      idempotencyKey: crypto.randomUUID(),
    }
    setWriteFailure(null)
    mutation.mutate(attempt)
  }

  const commits = useCommitRequest(() => save(), mutation.isPending || query.isFetching)

  const retryExact = () => {
    if (activeFailure?.kind === 'unknown' && activeFailure.attempt && !activePending && !reloading) {
      mutation.mutate(activeFailure.attempt)
    }
  }

  // 放弃本次未知结果并重新读取服务端快照。refetch 拿到与之前相同的 JSON 时 TanStack 结构共享会保留
  // query.data 的引用，上面的 effect 不会触发，所以按 refetch 的返回值显式恢复表单（B14）。
  // 读取失败时保留原来的服务端快照，"结果未知"锁保留（结果仍然未知）；身份已变则清空、不恢复。
  // 重载期间不清空表单（表单本来就被锁住）：清空会让整块切到加载态、恢复条卸载重挂，说明弹窗再弹一次。
  const abandonAndReload = async () => {
    if (activePending || reloading) return
    const reloadIdentity = identity
    const previous = query.data
    setReloading(true)
    const result = await query.refetch().finally(() => setReloading(false))
    // 会话/身份已变：不恢复任何结果，也不再显示上一身份的快照。
    if (reloadIdentity !== identityRef.current || !currentAccess(props, 'sites.read')) {
      setDocument(null)
      setBaseline(null)
      return
    }
    if (result.status === 'success' && validateOriginRoutingState(result.data)) {
      mutation.reset()
      setWriteFailure(null)
      adopt(result.data)
      return
    }
    if (previous && validateOriginRoutingState(previous)) adopt(previous)
  }

  const updateDocument = (update: (current: OriginRoutingDocument) => OriginRoutingDocument) => {
    setDocument((current) => current ? sortOriginDocument(update(cloneDocument(current))) : current)
    setWriteFailure(null)
    commits.requestUnlessTyping()
  }

  const openRouteEditor = (route?: OriginRoute) => {
    if (!document || editLocked) return
    setRouteEditor({ originalId: route?.id ?? null })
  }

  const routesWith = (current: OriginRoutingDocument, originalId: string | null, route: OriginRoute) => sortOriginDocument({
    ...current,
    routes: originalId === null ? [...current.routes, route] : current.routes.map((item) => item.id === originalId ? route : item),
  })

  const applyRoute = (route: OriginRoute) => {
    if (!routeEditor || !document || editLocked) return
    updateDocument(() => routesWith(document, routeEditor.originalId, route))
    setRouteEditor(null)
  }

  if (!canRead) return <SiteEditState status="forbidden" title={t('states.forbidden')} />
  if (query.isPending || (query.isFetching && !document)) return <section className="site-edit-tab-panel" aria-label={t('title')} aria-busy="true"><SiteEditState status="loading" label={t('states.loading')} /></section>
  // 已有服务端快照时读取失败不清掉表单：保留旧快照，在下方提示加载失败（B14）。
  const reloadFailed = Boolean(query.error && query.error !== staleLineage && query.data)
  if (query.error && query.error !== staleLineage && !query.data) {
    const state = errorState(query.error)
    if (state === 'forbidden') return <section className="site-edit-tab-panel" aria-label={t('title')}><SiteEditState status="forbidden" title={t('states.forbidden')} /></section>
    if (state === 'notFound') return <section className="site-edit-tab-panel" aria-label={t('title')}><SiteEditState status="empty" title={t('states.empty')} /></section>
    return <section className="site-edit-tab-panel" aria-label={t('title')}><SiteEditState status="error" title={state === 'conflict' ? t('states.conflict') : t('states.loadError')} onRetry={state === 'request' ? () => void query.refetch() : undefined} /></section>
  }
  if (!query.data || !document) return <section className="site-edit-tab-panel" aria-label={t('title')}><SiteEditState status="empty" title={t('states.empty')} /></section>

  const poolOptions = document.pools.map((pool) => ({ label: pool.id, value: pool.id }))
  // 被默认池、默认备用池或条件规则引用的池，以及最后一个池，都不能删除（与改版前同一判定）。
  const poolInUse = (poolId: string) => document.pools.length <= 1 || poolId === document.default_pool_id || poolId === document.default_fallback_pool_id ||
    document.routes.some((route) => route.pool_id === poolId || route.fallback_pool_id === poolId)
  const updateRetry = (changes: Partial<OriginRoutingDocument['retry']>) => updateDocument((current) => ({ ...current, retry: { ...current.retry, ...changes } }))
  const msSuffix = t('units.ms')

  const poolColumns: TableColumnsType<OriginPool> = [
    { title: t('columns.poolName'), dataIndex: 'id', width: 160, render: (id: string) => <span className="site-origin-routing-name">{id}</span> },
    {
      title: t('fields.balance'), width: 180,
      render: (_, pool) => <Select aria-label={`${pool.id} ${t('fields.balance')}`} className="site-origin-routing-balance" value={pool.balance_method ?? 'round_robin'} disabled={editLocked}
        options={ORIGIN_BALANCE_METHODS.map((method) => ({ label: t(`algorithms.${method}`), value: method }))}
        onChange={(value: OriginPool['balance_method']) => updateDocument((current) => ({ ...current, pools: current.pools.map((item) => item.id === pool.id ? { ...item, balance_method: value } : item) }))} />,
    },
    {
      title: t('fields.endpoint'),
      render: (_, pool) => <div className="site-origin-routing-endpoints">{pool.endpoints.map((endpoint) => <Tag key={endpoint.id}>{endpoint.host}:{endpoint.port}<span className="site-origin-routing-muted">{t('labels.weight', { weight: endpoint.weight })}</span></Tag>)}</div>,
    },
    ...(canWrite ? [{
      title: t('columns.actions'), width: 96,
      render: (_: unknown, pool: OriginPool) => {
        const blocked = poolInUse(pool.id)
        const button = (
          <Popconfirm title={t('actions.confirmDeletePool', { id: pool.id })} okText={t('actions.delete')} cancelText={t('actions.cancel')} disabled={editLocked || blocked}
            onConfirm={() => updateDocument((current) => ({ ...current, pools: current.pools.filter((item) => item.id !== pool.id) }))}>
            <Button danger type="link" size="small" disabled={editLocked || blocked}>{t('actions.deletePool')}</Button>
          </Popconfirm>
        )
        return blocked ? <Tooltip title={t('hints.poolInUse')}><span className="site-origin-routing-blocked" tabIndex={0}>{button}</span></Tooltip> : button
      },
    }] : []),
  ]

  const routeColumns: TableColumnsType<OriginRoute> = [
    { title: t('fields.routeId'), dataIndex: 'id', width: 160, render: (id: string) => <span className="site-origin-routing-name">{id}</span> },
    {
      title: t('columns.conditions'),
      render: (_, route) => <div className="site-origin-routing-conditions">
        {route.path_prefix ? <span>{t('labels.path', { value: route.path_prefix })}</span> : null}
        {route.node_regions?.length ? <span>{t('labels.regions', { value: route.node_regions.join(', ') })}</span> : null}
        {route.client_cidrs?.length ? <span>{t('labels.cidrs', { value: route.client_cidrs.join(', ') })}</span> : null}
      </div>,
    },
    { title: t('columns.target'), width: 200, render: (_, route) => <>{route.pool_id}{route.fallback_pool_id ? <span className="site-origin-routing-muted">{t('labels.fallback', { id: route.fallback_pool_id })}</span> : null}</> },
    { title: t('fields.priority'), dataIndex: 'priority', width: 90 },
    ...(canWrite ? [{
      title: t('columns.actions'), width: 132,
      render: (_: unknown, route: OriginRoute) => (
        <Space size={4}>
          <Button type="link" size="small" disabled={editLocked} aria-label={t('actions.editRoute', { id: route.id })} onClick={() => openRouteEditor(route)}>{t('actions.edit')}</Button>
          <Popconfirm title={t('actions.confirmDeleteRoute', { id: route.id })} okText={t('actions.delete')} cancelText={t('actions.cancel')} disabled={editLocked}
            onConfirm={() => updateDocument((current) => ({ ...current, routes: current.routes.filter((item) => item.id !== route.id) }))}>
            <Button danger type="link" size="small" disabled={editLocked}>{t('actions.delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    }] : []),
  ]

  return (
    <section className="site-edit-tab-panel site-origin-routing" aria-label={t('title')} {...commits.typingProps}>
      <div className="site-origin-routing-feedback">
        {!canWrite ? <Alert type="warning" showIcon message={t('states.readOnly')} /> : null}
        {remoteChanged && conflictPending && !activePending ? <Alert type="warning" showIcon message={t('states.remoteChanged')}
          action={<Space wrap><Button size="small" onClick={() => adopt(remoteChanged)}>{t('actions.loadLatest')}</Button><Button size="small" type="primary" disabled={editLocked} onClick={() => save(remoteChanged)}>{t('actions.overwriteLatest')}</Button></Space>} /> : null}
        {reloadFailed ? <Alert type="error" showIcon message={t('states.loadError')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
        {activeFailure?.kind === 'unknown' ? <OutcomeUnknown title={t('states.unknownResult')}
          action={<Space wrap><Button size="small" disabled={activePending} loading={reloading} onClick={() => void abandonAndReload()}>{t('actions.abandonAndReload')}</Button><Button size="small" type="primary" disabled={reloading} loading={activePending} onClick={retryExact}>{t('actions.retryExact')}</Button></Space>} />
          : activeFailure ? <FeedbackWhen title={activeFailure.kind === 'forbidden' ? t('errors.permission') : activeFailure.kind === 'notFound' ? t('errors.notFound') : activeFailure.kind === 'conflict' ? t('states.conflict') : activeFailure.kind === 'validation' ? t('errors.validation') : t('states.saveError')} /> : null}
      </div>
      <SettingSection title={t('sections.default')}>
        <p className="site-origin-routing-intro">{t('description')}</p>
        <SettingRow label={t('fields.ingressSource')} help={t('hints.ingressSource')}>
          <Switch aria-label={t('fields.ingressSource')} checked={document.ingress_source_enabled} disabled={editLocked} onChange={(checked) => updateDocument((current) => ({ ...current, ingress_source_enabled: checked }))} />
        </SettingRow>
        <SettingRow label={t('fields.pool')} help={t('hints.pool')}>
          <Select aria-label={t('fields.pool')} value={document.default_pool_id} disabled={editLocked} options={poolOptions} onChange={(value) => updateDocument((current) => ({ ...current, default_pool_id: value }))} />
        </SettingRow>
        <SettingRow label={t('fields.fallbackPool')} help={t('hints.fallbackPool')}>
          <Select aria-label={t('fields.fallbackPool')} allowClear placeholder={t('placeholders.none')} value={document.default_fallback_pool_id} disabled={editLocked} options={poolOptions.filter((option) => option.value !== document.default_pool_id)} onChange={(value) => updateDocument((current) => ({ ...current, default_fallback_pool_id: value || undefined }))} />
        </SettingRow>
      </SettingSection>
      <SettingSection title={t('sections.pools')}>
        <Table<OriginPool> className="site-origin-table" size="small" rowKey="id" pagination={false} columns={poolColumns} dataSource={document.pools}
          onRow={(pool) => ({ 'data-testid': `origin-pool-${pool.id}` }) as HTMLAttributes<HTMLElement>} />
      </SettingSection>
      <SettingSection title={t('sections.routes')}>
        <div className="site-origin-routing-section-heading">
          <p className="site-origin-routing-intro">{t('hints.routes')}</p>
          {canWrite ? <Button icon={<Plus size={15} aria-hidden="true" />} disabled={editLocked} onClick={() => openRouteEditor()}>{t('actions.addRoute')}</Button> : null}
        </div>
        <Table<OriginRoute> className="site-origin-table" size="small" rowKey="id" pagination={false} columns={routeColumns} dataSource={document.routes}
          locale={{ emptyText: t('states.noRoutes') }} onRow={(route) => ({ 'data-testid': `origin-route-${route.id}` }) as HTMLAttributes<HTMLElement>} />
      </SettingSection>
      <SettingSection title={t('sections.retry')}>
        <SettingRow label={t('fields.retryMethods')} help={t('hints.retryMethods')}>
          <Select mode="multiple" aria-label={t('fields.retryMethods')} value={document.retry.methods} disabled={editLocked} options={['GET', 'HEAD'].map((method) => ({ label: method, value: method }))} onChange={(value: Array<'GET' | 'HEAD'>) => updateRetry({ methods: value })} />
        </SettingRow>
        <SettingRow label={t('fields.maxAttempts')} help={t('hints.maxAttempts')}>
          <InputNumber aria-label={t('fields.maxAttempts')} value={document.retry.max_attempts} disabled={editLocked} min={1} max={8} addonAfter={t('units.times')} onChange={(value) => value !== null && updateRetry({ max_attempts: value })} />
        </SettingRow>
        <SettingRow label={t('fields.connectTimeout')}>
          <InputNumber aria-label={t('fields.connectTimeout')} value={document.retry.connect_timeout_ms} disabled={editLocked} min={10} max={60000} addonAfter={msSuffix} onChange={(value) => value !== null && updateRetry({ connect_timeout_ms: value })} />
        </SettingRow>
        <SettingRow label={t('fields.readTimeout')}>
          <InputNumber aria-label={t('fields.readTimeout')} value={document.retry.read_timeout_ms} disabled={editLocked} min={10} max={60000} addonAfter={msSuffix} onChange={(value) => value !== null && updateRetry({ read_timeout_ms: value })} />
        </SettingRow>
        <SettingRow label={t('fields.totalBudget')} help={t('hints.totalBudget')}>
          <InputNumber aria-label={t('fields.totalBudget')} value={document.retry.total_budget_ms} disabled={editLocked} min={20} max={120000} addonAfter={msSuffix} onChange={(value) => value !== null && updateRetry({ total_budget_ms: value })} />
        </SettingRow>
      </SettingSection>
      {routeEditor ? (
        <ConditionalOriginRouteDialog
          route={routeEditor.originalId === null ? undefined : document.routes.find((item) => item.id === routeEditor.originalId)}
          poolIds={document.pools.map((pool) => pool.id)}
          defaultPoolId={document.default_pool_id}
          takenIds={document.routes.map((item) => item.id).filter((id) => id !== routeEditor.originalId)}
          allowFallback
          disabled={editLocked}
          validate={(route) => validateOriginRoutingState({ ...query.data, document: routesWith(document, routeEditor.originalId, route) })}
          onCancel={() => setRouteEditor(null)}
          onApply={applyRoute}
        />
      ) : null}
    </section>
  )
}
