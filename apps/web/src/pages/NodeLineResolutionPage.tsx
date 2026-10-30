import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Dropdown,
  Input,
  InputNumber,
  Modal,
  Result,
  Select,
  Table,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import {
  ArrowLeft,
  ArrowLeftRight,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  CircleX,
  Pause,
  Play,
  Plus,
  Search,
  Trash2,
} from 'lucide-react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { dnsProviderSplitsCarrierLines } from '../api/dns'
import '../i18n/dnsConfig'
import { dnsPlatformApi } from '../api/dnsPlatform'
import {
  nodeSchedulingApi,
  validateLineResolutionWriteResponse,
  validateNodeLineGroupResponse,
  type NodeLineEndpoint,
  type NodeSchedulingScope,
} from '../api/nodeScheduling'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import {
  clearLineResolutionRetry,
  persistLineResolutionRetry,
  restoreLineResolutionRetry,
  type LineResolutionAttempt,
  type LineResolutionAccepted,
  type LineResolutionRetryOwner,
} from './lineResolutionRetryRecord'
import '../i18n/nodeL2Topology'
import './node-scheduling/messages'
import {
  outcomeUnknown,
  revisionMetadata,
  schedulingAccess,
  schedulingError,
  schedulingScope,
  snapshotFromGroup,
  uuidPattern,
} from './node-scheduling/shared'
import './NodeSchedulingPage.css'
import './NodeL2TopologyDetailPage.css'

type Candidate = { key: string; node: NodeInventoryItem; address: string }
type Action =
  | 'add'
  | 'addStandby'
  | 'enable'
  | 'disable'
  | 'delete'
  | 'standby'
  | 'cancelStandby'
  | 'weight'
  | 'sort'
type LineAttempt = LineResolutionAttempt
type LineReadback = { attempt: LineAttempt; accepted: LineResolutionAccepted | null }

// Carrier line values written into endpoint.carrier (cnamelines maps them
// to the provider's 电信/联通/移动 lines).
const carrierLineValues = ['电信', '联通', '移动']

export default function NodeLineResolutionPage() {
  const { t } = useTranslation('nodeScheduling')
  const principal = useSessionStore((state) => state.principal)
  const token = useSessionStore((state) => state.accessToken)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const { id = '' } = useParams<{ id: string }>()
  const [params] = useSearchParams()
  const targetScopeID =
    params.get('target_scope_id') ??
    (principal?.scope_kind === 'platform' ? principal.scope_id : '')
  const scope = schedulingScope(principal, targetScopeID)
  const { canRead } = schedulingAccess(principal, targetScopeID)
  if (!token) return null
  if (
    !principal ||
    !principal.user_id ||
    !uuidPattern.test(principal.scope_id) ||
    epoch <= 0 ||
    !canRead ||
    !scope ||
    (principal.scope_kind === 'tenant'
      ? !principal.tenant_id
      : principal.tenant_id !== null)
  )
    return (
      <Result
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  if (!uuidPattern.test(id))
    return (
      <Result
        status="error"
        title={t('errors.loadFailed')}
        subTitle={t('errors.node_scheduling_invalid_request')}
      />
    )
  const ownerKey = JSON.stringify([
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    epoch,
  ])
  return (
    <LineResolutionContent
      key={`${ownerKey}:${targetScopeID}:${id}`}
      id={id}
      ownerKey={ownerKey}
      scope={scope}
      targetScopeID={targetScopeID}
    />
  )
}

function LineResolutionContent({
  id,
  ownerKey,
  scope,
  targetScopeID,
}: {
  id: string
  ownerKey: string
  scope: NodeSchedulingScope
  targetScopeID: string
}) {
  const { t } = useTranslation('nodeScheduling')
  const { t: l2T } = useTranslation('nodeL2Topology')
  const principal = useSessionStore((state) => state.principal)
  const { canManage } = schedulingAccess(principal, targetScopeID)
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const active = useRef(true)
  const sending = useRef(false)
  const readbackPending = useRef(false)
  const inventoryDenied = useRef(false)
  const retryOwner = useRef<LineResolutionRetryOwner>([
    JSON.parse(ownerKey)[0], JSON.parse(ownerKey)[1], JSON.parse(ownerKey)[3],
  ]).current
  const scopeID = scope.kind === 'platform' ? scope.targetScopeId : retryOwner[1]
  const [restored] = useState(() => restoreLineResolutionRetry(retryOwner, scopeID, id))
  const stickyUnknown = useRef(Boolean(restored.record))
  const [storageBlocked, setStorageBlocked] = useState(restored.blocked)
  const [readbackAttempt, setReadbackAttempt] = useState<LineReadback | null>(
    restored.record?.phase === 'readback'
      ? { attempt: restored.record.attempt, accepted: restored.record.accepted ?? null } : null,
  )
  const [readingBack, setReadingBack] = useState(false)
  const prefix = useRef(['line-resolution', ownerKey, targetScopeID, id] as const).current
  const [denied, setDenied] = useState(false)
  const [nodeReadDenied, setNodeReadDenied] = useState(false)
  const [availableSearch, setAvailableSearch] = useState('')
  const [configuredSearch, setConfiguredSearch] = useState('')
  const [carrier, setCarrier] = useState('')
  const [availableKeys, setAvailableKeys] = useState<string[]>([])
  const [selectedIDs, setSelectedIDs] = useState<string[]>([])
  const [dialog, setDialog] = useState<Action | null>(null)
  const [weight, setWeight] = useState<number | null>(1)
  const [sortOrder, setSortOrder] = useState<number | null>(100)
  const [attempt, setAttempt] = useState<LineAttempt | null>(
    restored.record?.phase === 'unknown' ? restored.record.attempt : null,
  )
  const [error, setError] = useState<unknown>(null)
  const access = (manage = false, inventory = false) => {
    const current = useSessionStore.getState()
    const actor = current.principal
    if (
      !active.current ||
      !current.accessToken ||
      !actor ||
      JSON.stringify([
        actor.scope_kind,
        actor.scope_id,
        actor.tenant_id,
        actor.user_id,
        current.sessionEpoch,
      ]) !== ownerKey
    )
      throw new Error('Line resolution session changed')
    const allowed = schedulingAccess(actor, targetScopeID)
    if (!allowed.canRead || (manage && !allowed.canManage))
      throw new Error('Line resolution access changed')
    if (
      inventory &&
      (inventoryDenied.current || !actor.permissions.some((permission) => ['nodes.read', 'platform.admin'].includes(permission)))
    )
      throw new Error('Line inventory access changed')
    return current.accessToken
  }
  const denyCurrentOwner = () => {
    active.current = false
    setDenied(true)
    setDialog(null)
    queueMicrotask(() => queryClient.removeQueries({ queryKey: prefix }))
  }
  const validateGroup = (value: unknown) => {
    const group = validateNodeLineGroupResponse(value)
    if (group.tenant_scope_id !== scopeID)
      throw new ApiError('Invalid line group', 200, 'invalid_response')
    return group
  }
  const readGroup = async () => {
    try {
      const result = await nodeSchedulingApi.get(access(), scope, id)
      access()
      validateGroup(result)
      if (result.id !== id) throw new ApiError('Invalid line group', 200, 'invalid_response')
      return result
    } catch (failure) {
      access()
      if (failure instanceof ApiError && failure.status === 403) denyCurrentOwner()
      throw failure
    }
  }
  const groupQuery = useQuery({
    queryKey: [...prefix, 'group'],
    queryFn: readGroup,
    enabled: !denied,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const readGroups = async () => {
    try {
      const result = await nodeSchedulingApi.list(access(), scope)
      access()
      if (!Array.isArray(result.items))
        throw new ApiError('Invalid line groups', 200, 'invalid_response')
      return result.items.map(validateGroup)
    } catch (failure) {
      access()
      if (failure instanceof ApiError && failure.status === 403) denyCurrentOwner()
      throw failure
    }
  }
  const groupsQuery = useQuery({
    queryKey: [...prefix, 'groups'],
    queryFn: readGroups,
    enabled: !denied,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  // The installation's DNS provider (platform administrators only): name.com
  // cannot split by carrier, so the carrier line selector is disabled.
  const canReadPlatformDNS = principal?.scope_kind === 'platform' && Boolean(principal.permissions.includes('dns.read'))
  const dnsConfigQuery = useQuery({
    queryKey: [...prefix, 'dns-provider'],
    queryFn: () => dnsPlatformApi.config(access()),
    enabled: canReadPlatformDNS && !denied,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  // Carrier line capability of the installation's DNS provider. New carrier
  // lines are offered only when the provider is known to write them; without
  // dns.read, while loading or after a failed read only the lines already in
  // use stay selectable, and with no provider or a provider without lines the
  // selector is disabled.
  const providerType = dnsConfigQuery.data?.provider_type
  const lineCapability: 'unknown' | 'loading' | 'failed' | 'unconfigured' | 'unsupported' | 'supported' =
    !canReadPlatformDNS ? 'unknown'
      : dnsConfigQuery.isError ? 'failed'
        : !dnsConfigQuery.data ? 'loading'
          : !providerType ? 'unconfigured'
            : dnsProviderSplitsCarrierLines(providerType) ? 'supported' : 'unsupported'
  const carrierLines = lineCapability !== 'unconfigured' && lineCapability !== 'unsupported'
  const canReadNodes =
    Boolean(
      principal?.permissions.some((permission) =>
        ['nodes.read', 'platform.admin'].includes(permission),
      ),
    ) &&
    (scope.kind === 'tenant' || scope.targetScopeId === principal?.scope_id)
  const readNodes = async () => {
    try {
      const nodes: NodeInventoryItem[] = []
      const seen = new Set<string>()
      let cursor: string | undefined
      do {
        const result = await nodesApi.list(access(false, true), { limit: 100, cursor })
        access(false, true)
        nodes.push(...result.items)
        cursor = result.next_cursor
        if (cursor && seen.has(cursor))
          throw new ApiError('Invalid node cursor', 200, 'invalid_response')
        if (cursor) seen.add(cursor)
      } while (cursor)
      return nodes
    } catch (failure) {
      access()
      if (failure instanceof ApiError && failure.status === 403) {
        inventoryDenied.current = true
        setNodeReadDenied(true)
        setAvailableKeys([])
        queueMicrotask(() => queryClient.removeQueries({ queryKey: [...prefix, 'nodes'] }))
      }
      throw failure
    }
  }
  const nodesQuery = useQuery({
    queryKey: [...prefix, 'nodes'],
    queryFn: readNodes,
    enabled: !denied && !nodeReadDenied && canReadNodes,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
      queueMicrotask(() => {
        if (active.current) return
        queryClient.removeQueries({ queryKey: prefix })
        for (const item of queryClient.getMutationCache().findAll({ mutationKey: prefix }))
          queryClient.getMutationCache().remove(item)
      })
    }
  }, [prefix, queryClient])
  useEffect(() => {
    if (
      [groupQuery.error, groupsQuery.error].some(
        (failure) => failure instanceof ApiError && failure.status === 403,
      )
    ) {
      active.current = false
      setDenied(true)
      setDialog(null)
      queryClient.removeQueries({ queryKey: prefix })
    }
  }, [groupQuery.error, groupsQuery.error, prefix, queryClient])
  useEffect(() => {
    if (nodesQuery.error instanceof ApiError && nodesQuery.error.status === 403) {
      inventoryDenied.current = true
      setNodeReadDenied(true)
    }
    if (!canReadNodes || nodeReadDenied)
      queryClient.removeQueries({ queryKey: [...prefix, 'nodes'] })
  }, [canReadNodes, nodeReadDenied, nodesQuery.error, prefix, queryClient])
  useEffect(() => {
    setAvailableKeys([])
    setSelectedIDs([])
  }, [groupQuery.data, nodesQuery.data, canReadNodes])
  const reconcileSaved = async ({ attempt: write, accepted }: LineReadback) => {
    if (readbackPending.current || storageBlocked) return
    try { access() } catch { return }
    readbackPending.current = true
    setReadingBack(true)
    try {
      await queryClient.cancelQueries({ queryKey: prefix })
      access()
      if (accepted) {
        const exact = await nodeSchedulingApi.getRevision(access(), scope, id, accepted.revision)
        access()
        validateGroup(exact)
        if (exact.id !== id || exact.revision !== accepted.revision || exact.configuration_digest !== accepted.configurationDigest)
          throw new ApiError('Invalid accepted line revision', 200, 'invalid_response')
      }
      const saved = await readGroup()
      access()
      if (accepted && (saved.revision < accepted.revision ||
        (saved.revision === accepted.revision && saved.configuration_digest !== accepted.configurationDigest)))
        throw new ApiError('Invalid current line revision', 200, 'invalid_response')
      const groups = await readGroups()
      access()
      const listed = groups.filter((item) => item.id === id)
      if (listed.length !== 1 || listed[0]!.revision < saved.revision ||
        (listed[0]!.revision === saved.revision && listed[0]!.configuration_digest !== saved.configuration_digest))
        throw new ApiError('Invalid listed line revision', 200, 'invalid_response')
      const current = listed[0]!
      queryClient.setQueryData([...prefix, 'group'], current)
      queryClient.setQueryData([...prefix, 'groups'], groups)
      // A legacy readback record has no accepted revision/digest to reconcile.
      if (!accepted) { setError(null); return }
      if (!clearLineResolutionRetry(retryOwner, scopeID, id, write, accepted)) {
        setStorageBlocked(true)
        return
      }
      setReadbackAttempt(null)
      setAttempt(null)
      setError(null)
      setSelectedIDs([])
      setAvailableKeys([])
      stickyUnknown.current = false
      if (current.revision > accepted.revision) feedback.warning(l2T('line.savedLater'))
      else messageApi.success(l2T('line.saved'))
    } catch (failure) {
      try {
        access()
        if (failure instanceof ApiError && failure.status === 403) denyCurrentOwner()
        else setError(failure)
      } catch { /* A stale or denied owner cannot publish results. */ }
    } finally {
      readbackPending.current = false
      try { access(); setReadingBack(false) } catch { /* Preserve the departed owner's retry record. */ }
    }
  }
  const mutation = useMutation({
    mutationKey: prefix,
    mutationFn: async (write: LineAttempt) => {
      const result = await nodeSchedulingApi.update(access(true), id, write.input, write.metadata)
      access(true)
      return validateLineResolutionWriteResponse(result, id, scopeID, write.metadata.expectedRevision)
    },
    onSuccess: async (saved, write) => {
      try {
        access(true)
      } catch {
        return
      }
      setDialog(null)
      const accepted = { revision: saved.revision, configurationDigest: saved.configuration_digest }
      const readback = { attempt: write, accepted }
      setAttempt(null)
      setReadbackAttempt(readback)
      if (!persistLineResolutionRetry(retryOwner, scopeID, id, write, 'readback', accepted)) {
        setStorageBlocked(true)
        return
      }
      setError(null)
      await reconcileSaved(readback)
    },
    onError: (failure, write) => {
      try {
        access(true)
      } catch {
        return
      }
      if (failure instanceof ApiError && failure.status === 403) {
        denyCurrentOwner()
        return
      }
      setError(failure)
      setDialog(null)
      if (outcomeUnknown(failure) || stickyUnknown.current) {
        stickyUnknown.current = true
        setAttempt(write)
      } else if (clearLineResolutionRetry(retryOwner, scopeID, id, write)) setAttempt(null)
      else setStorageBlocked(true)
      void queryClient.invalidateQueries({ queryKey: prefix })
    },
    onSettled: () => { sending.current = false },
    retry: false,
  })
  const group = groupQuery.data
  // 境外 is not a carrier: an endpoint answers on the overseas line by its
  // region (cnamelines.EndpointScope), so only the carriers are offered.
  const lineOptions = [...new Set([
    '',
    ...(lineCapability === 'supported' ? carrierLineValues : []),
    ...(group?.endpoints ?? []).map((endpoint) => endpoint.carrier),
  ])]
  const inventory = canReadNodes && !nodeReadDenied ? (nodesQuery.data ?? []) : []
  const nodes = new Map(inventory.map((node) => [node.id, node]))
  const allGroups = groupsQuery.data ?? (group ? [group] : [])
  const selectedRegion = group?.region ?? ''
  const groupOptions = allGroups.filter((item) => item.region === selectedRegion)
  const regionOptions = [...new Set(allGroups.map((item) => item.region))]
  // Only the current carrier line's addresses are excluded: one IP may be put
  // on several carrier lines (NET-02, migration 500 keys on carrier).
  const configuredAddresses = new Set(
    (group?.endpoints ?? [])
      .filter((endpoint) => endpoint.carrier === carrier)
      .map((endpoint) => `${endpoint.node_id}:${endpoint.address}`),
  )
  const assignable = inventory.filter((node) => !['retired', 'pending'].includes(node.admin_state))
  // Only nodes of the group's region are candidates; say how many are left out
  // only because they have no region yet instead of showing an empty list (D8).
  const unsetRegionCount = group?.region
    ? assignable.filter((node) => node.region.trim() === '').length
    : 0
  const available: Candidate[] = assignable
    .filter((node) => node.region === (group?.region ?? ''))
    .flatMap((node) =>
      [
        ...new Set(
          [node.ipv4, node.ipv6, ...node.management_settings.secondary_ips].filter(
            (address): address is string => Boolean(address),
          ),
        ),
      ].map((address) => ({ key: `${node.id}:${address}`, node, address })),
    )
    .filter(
      (item) =>
        !configuredAddresses.has(item.key) &&
        [item.node.name, item.address].some((value) =>
          value.toLocaleLowerCase().includes(availableSearch.trim().toLocaleLowerCase()),
        ),
    )
  const configured = (group?.endpoints ?? []).filter(
    (endpoint) =>
      endpoint.carrier === carrier &&
      [nodes.get(endpoint.node_id)?.name ?? '', endpoint.address].some((value) =>
        value.toLocaleLowerCase().includes(configuredSearch.trim().toLocaleLowerCase()),
      ),
  )
  const selected = configured.filter((endpoint) => selectedIDs.includes(endpoint.id))
  const busy = mutation.isPending || Boolean(attempt) || Boolean(readbackAttempt) || storageBlocked
  const actionsDisabled = !canManage || busy || !group || groupQuery.isFetching || groupsQuery.isFetching || groupQuery.isError || groupsQuery.isError
  const addDisabled = actionsDisabled || !canReadNodes || nodeReadDenied || nodesQuery.isFetching || nodesQuery.isError
  const openAction = (action: Action) => {
    const adding = action === 'add' || action === 'addStandby'
    try { access(true, adding) } catch { return }
    if (adding ? addDisabled : actionsDisabled) return
    if (adding ? !available.some((item) => availableKeys.includes(item.key)) : !selected.length) {
      feedback.warning(l2T(adding ? 'line.selectNodes' : 'line.selectIPs'))
      return
    }
    setWeight(selected[0]?.weight ?? 1)
    setSortOrder(selected[0]?.sort_order ?? 100)
    setDialog(action)
  }
  const confirmAction = () => {
    try { access(true) } catch { return }
    if (!group || !dialog || !canManage || busy || sending.current) return
    const input = snapshotFromGroup(group)
    if (dialog === 'add' || dialog === 'addStandby') {
      const additions = available.filter((item) => availableKeys.includes(item.key))
      if (!additions.length || !globalThis.crypto?.randomUUID) return
      input.endpoints.push(
        ...additions.map((item) => ({
          id: crypto.randomUUID(),
          node_id: item.node.id,
          address: item.address,
          port: 443,
          region: group.region,
          carrier,
          priority: dialog === 'addStandby' ? 1 : 0,
          weight: 100,
          enabled: true,
        })),
      )
    } else {
      const ids = new Set(selected.map((endpoint) => endpoint.id))
      if (!ids.size) return
      if (
        dialog === 'weight' &&
        (!Number.isInteger(weight) || weight === null || weight < 1 || weight > 100)
      )
        return
      if (
        dialog === 'sort' &&
        (!Number.isInteger(sortOrder) || sortOrder === null || sortOrder < 1 || sortOrder > 999999)
      )
        return
      input.endpoints = input.endpoints.flatMap((endpoint) => {
        if (!ids.has(endpoint.id)) return [endpoint]
        if (dialog === 'delete') return []
        if (dialog === 'enable' || dialog === 'disable')
          return [{ ...endpoint, enabled: dialog === 'enable' }]
        if (dialog === 'standby' || dialog === 'cancelStandby')
          return [
            { ...endpoint, priority: dialog === 'standby' ? Math.max(1, endpoint.priority) : 0 },
          ]
        if (dialog === 'sort') return [{ ...endpoint, sort_order: sortOrder! }]
        return [{ ...endpoint, weight: weight! }]
      })
    }
    const write = { input, metadata: revisionMetadata('line-resolution', group.revision) }
    if (!persistLineResolutionRetry(retryOwner, scopeID, id, write, 'unknown')) {
      setDialog(null)
      setStorageBlocked(true)
      return
    }
    stickyUnknown.current = false
    sending.current = true
    setError(null)
    mutation.mutate(write)
  }
  const availableColumns: TableColumnsType<Candidate> = [
    { title: t('lineDetail.columns.name'), className: 'node-line-resolution-name', render: (_, item) => item.node.name },
    { title: t('lineDetail.columns.ipAddress'), className: 'node-line-resolution-address', dataIndex: 'address' },
    {
      title: t('lineDetail.columns.status'),
      width: 90,
      render: (_, item) => l2T(`nodes.${item.node.presence.status}`),
    },
  ]
  // NET-UX-5: primary/standby as node_line_endpoint_published (migration 501)
  // decides it: per carrier and address family, the lowest priority among the
  // enabled IPs is primary and higher ones are standby.
  const familyOf = (address: string) => (address.includes(':') ? 'v6' : 'v4')
  const primaryPriority = new Map<string, number>()
  for (const endpoint of group?.endpoints ?? []) {
    if (!endpoint.enabled) continue
    const key = `${endpoint.carrier}/${familyOf(endpoint.address)}`
    primaryPriority.set(key, Math.min(primaryPriority.get(key) ?? endpoint.priority, endpoint.priority))
  }
  const configuredColumns: TableColumnsType<NodeLineEndpoint> = [
    {
      title: t('columns.id'),
      width: 55,
      render: (_, endpoint) => <span title={endpoint.id}>{endpoint.display_id ?? t('values.unavailable')}</span>,
    },
    {
      title: t('lineDetail.columns.name'),
      className: 'node-line-resolution-name',
      render: (_, endpoint) => nodes.get(endpoint.node_id)?.name ?? t('values.unavailable'),
    },
    { title: t('lineDetail.columns.ipAddress'), className: 'node-line-resolution-address', dataIndex: 'address', width: 220 },
    {
      title: t('lineDetail.columns.onlineStatus'),
      width: 100,
      render: (_, endpoint) => {
        const status = nodes.get(endpoint.node_id)?.presence.status ?? 'unknown'
        return (
          <span className={`node-line-resolution-presence is-${status}`}>
            {status === 'online' ? <CheckCircle2 size={12} aria-hidden="true" />
              : status === 'offline' ? <CircleX size={12} aria-hidden="true" />
                : <CircleHelp size={12} aria-hidden="true" />}
            {l2T(`nodes.${status}`)}
          </span>
        )
      },
    },
    {
      title: l2T('line.columns.enabled'),
      width: 75,
      render: (_, endpoint) => (
        <span className={`node-line-resolution-enabled is-${endpoint.enabled ? 'on' : 'off'}`}>
          {endpoint.enabled ? l2T('line.values.enabled') : l2T('line.values.disabled')}
        </span>
      ),
    },
    {
      title: l2T('line.columns.role'),
      width: 60,
      render: (_, endpoint) => {
        const primary = primaryPriority.get(`${endpoint.carrier}/${familyOf(endpoint.address)}`)
        if (!endpoint.enabled || primary === undefined) return t('values.placeholder')
        return l2T(endpoint.priority > primary ? 'line.values.standby' : 'line.values.primary')
      },
    },
    {
      title: <Tooltip title={l2T('line.probeHelp')}>{l2T('line.columns.probe')}</Tooltip>,
      width: 75,
      render: (_, endpoint) => l2T(`line.values.${endpoint.health.status}`),
    },
    {
      title: <Tooltip title={l2T('line.publishedHelp')}>{l2T('line.columns.published')}</Tooltip>,
      width: 75,
      render: (_, endpoint) => endpoint.published === undefined ? t('values.placeholder')
        : l2T(endpoint.published ? 'line.values.published' : 'line.values.unpublished'),
    },
    { title: t('columns.weight'), dataIndex: 'weight', width: 65 },
    {
      title: t('columns.sort'),
      width: 65,
      render: (_, endpoint) => endpoint.sort_order ?? 100,
    },
  ]
  if (denied)
    return (
      <Result
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  return (
    <section
      className="node-scheduling-page node-l2-topology-detail-page node-line-resolution-detail-page"
      aria-label={l2T('line.title')}
    >
      {messageContext}
      <div className="node-line-resolution-navigation">
        <Button
          type="text"
          icon={<ArrowLeft size={17} />}
          onClick={() => navigate('/node/line-group')}
        >
          {l2T('line.back')}
        </Button>
        <label>
          {l2T('line.regionLabel')}
          <Select
            aria-label={l2T('filters.region')}
            value={selectedRegion}
            options={regionOptions.map((value) => ({
              value,
              label: value || l2T('values.defaultRegion'),
            }))}
            onChange={(value) => {
              const first = allGroups.find((item) => item.region === value)
              if (first)
                navigate(
                  `/node/line-group/line/${first.id}${scope.kind === 'platform' ? `?target_scope_id=${encodeURIComponent(scope.targetScopeId)}` : ''}`,
                )
            }}
          />
        </label>
        <label>
          {l2T('line.groupLabel')}
          <Select
            aria-label={l2T('line.group')}
            value={groupOptions.some((item) => item.id === id) ? id : undefined}
            options={groupOptions.map((item) => ({ value: item.id, label: item.name }))}
            onChange={(value) =>
              navigate(
                `/node/line-group/line/${value}${scope.kind === 'platform' ? `?target_scope_id=${encodeURIComponent(scope.targetScopeId)}` : ''}`,
              )
            }
          />
        </label>
      </div>
      {[groupQuery.error, groupsQuery.error, nodesQuery.error]
        .filter(Boolean)
        .map((failure, index) => (
          <Alert
            key={index}
            className="node-scheduling-alert"
            type="error"
            message={t('errors.loadFailed')}
            description={schedulingError(failure, t)}
            action={
              <Button onClick={() => void queryClient.invalidateQueries({ queryKey: prefix })}>
                {t('actions.retry')}
              </Button>
            }
          />
        ))}
      {lineCapability === 'unsupported' || lineCapability === 'unconfigured' ? (
        <Alert className="node-scheduling-alert" type="warning" role="note"
          message={lineCapability === 'unconfigured' ? l2T('line.carrierLinesUnconfigured')
            : l2T('line.carrierLinesUnsupported', { provider: t(`providers.${providerType}`, { ns: 'dnsConfig', defaultValue: providerType }) })} />
      ) : lineCapability === 'failed' ? (
        <Alert className="node-scheduling-alert" type="warning" role="note" message={l2T('line.carrierLinesUnknown')}
          action={<Button size="small" onClick={() => void dnsConfigQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      {!canReadNodes || nodeReadDenied ? (
        <Alert
          className="node-scheduling-alert"
          type="info"
          message={l2T('line.nodesPermission')}
        />
      ) : null}
      {storageBlocked ? (
        <Alert className="node-scheduling-alert" type="error" message={l2T('retry.storageBlocked')}
          description={l2T('retry.storageBlockedDescription')} />
      ) : readbackAttempt ? (
        <Alert className="node-scheduling-alert" type="warning"
          message={l2T(readbackAttempt.accepted ? 'retry.readbackPending' : 'line.legacyReadback')}
          description={l2T(readbackAttempt.accepted ? 'line.readbackDescription' : 'line.legacyReadbackDescription')}
          action={<Button loading={readingBack} onClick={() => void reconcileSaved(readbackAttempt)}>
            {l2T('retry.read')}
          </Button>} />
      ) : attempt ? (
        <OutcomeUnknown title={t('errors.outcomeUnknown')} action={
            <Button
              disabled={!canManage}
              loading={mutation.isPending}
              onClick={() => {
                try { access(true) } catch { return }
                if (sending.current || mutation.isPending || storageBlocked || readbackAttempt) return
                if (!persistLineResolutionRetry(retryOwner, scopeID, id, attempt, 'unknown')) {
                  setStorageBlocked(true)
                  return
                }
                stickyUnknown.current = true
                sending.current = true
                mutation.mutate(attempt)
              }}
            >
              {t('actions.retrySame')}
            </Button>
          } className="node-scheduling-alert" />
      ) : error ? (
        <FeedbackWhen title={t('errors.writeFailed')} detail={schedulingError(error, t)} />
      ) : null}
      <div className="node-line-resolution-panes">
        <section>
          {unsetRegionCount > 0 ? (
            <Alert
              className="node-scheduling-alert"
              type="warning"
              showIcon
              message={l2T('line.unsetRegion', { count: unsetRegionCount })}
              action={<Link to="/node/list?region=unset">{l2T('line.unsetRegionLink')}</Link>}
            />
          ) : null}
          <h2>
            <CircleHelp size={16} />
            {l2T('line.available')}
          </h2>
          <div className="node-line-resolution-actions">
            <Button
              type="primary"
              icon={<Plus size={14} />}
              disabled={addDisabled}
              onClick={() => openAction('add')}
            >
              {t('lineDetail.actions.batchAdd')}
            </Button>
            <Button
              icon={<ArrowLeftRight size={14} />}
              disabled={addDisabled}
              onClick={() => openAction('addStandby')}
            >
              {t('lineDetail.actions.batchStandby')}
            </Button>
            <Input
              type="search"
              className="node-line-resolution-search"
              suffix={<Search size={14} aria-hidden="true" />}
              aria-label={t('lineDetail.filters.availableSearch')}
              placeholder={t('lineDetail.filters.searchPlaceholder')}
              value={availableSearch}
              onChange={(event) => { setAvailableSearch(event.target.value); setAvailableKeys([]) }}
            />
            <Button
              type="link"
              onClick={() => {
                setAvailableSearch('')
                setAvailableKeys([])
              }}
            >
              {l2T('line.clear')}
            </Button>
          </div>
          <div
            className="node-line-resolution-table-scroll"
            data-testid="available-line-ip-table-scroll"
          >
            <Table<Candidate>
              rowKey="key"
              size="small"
              tableLayout="fixed"
              columns={availableColumns}
              dataSource={available}
              loading={nodesQuery.isLoading && canReadNodes}
              pagination={false}
              scroll={{ x: 480 }}
              rowSelection={{
                columnWidth: 50,
                selectedRowKeys: availableKeys,
                onChange: (keys) => setAvailableKeys(keys.map(String)),
                getCheckboxProps: () => ({ disabled: addDisabled }),
              }}
              locale={{ emptyText: l2T('line.empty') }}
            />
          </div>
        </section>
        <section>
          <h2>
            <CheckCircle2 size={16} />
            {l2T('line.configured')}
            <Select
              aria-label={l2T('line.currentLine')}
              value={carrier}
              virtual={false}
              disabled={!carrierLines}
              options={lineOptions.map((value) => ({ value, label: value || l2T('values.defaultRegion') }))}
              onChange={(value) => {
                setCarrier(value)
                setSelectedIDs([])
                setAvailableKeys([])
              }}
            />
          </h2>
          <div className="node-line-resolution-actions">
            <Button
              className="line-enable"
              type="primary"
              icon={<Play size={12} fill="currentColor" strokeWidth={0} />}
              disabled={actionsDisabled}
              onClick={() => openAction('enable')}
            >
              {t('lineDetail.actions.enable')}
            </Button>
            <Button
              className="line-disable"
              type="primary"
              icon={<Pause size={12} fill="currentColor" strokeWidth={0} />}
              disabled={actionsDisabled}
              onClick={() => openAction('disable')}
            >
              {t('lineDetail.actions.disable')}
            </Button>
            <Button
              className="line-delete"
              type="primary"
              danger
              icon={<Trash2 size={12} />}
              disabled={actionsDisabled}
              onClick={() => openAction('delete')}
            >
              {t('lineDetail.actions.delete')}
            </Button>
            <Dropdown
              trigger={['click']}
              disabled={actionsDisabled}
              menu={{
                items: [
                  { key: 'standby', label: l2T('line.standby') },
                  { key: 'cancelStandby', label: l2T('line.cancelStandby') },
                  { key: 'weight', label: l2T('line.weight') },
                  {
                    key: 'defaultBackup',
                    label: (
                      <Tooltip title={l2T('line.unsupportedDefaultBackup')}>
                        {l2T('line.defaultBackup')}
                      </Tooltip>
                    ),
                    disabled: true,
                  },
                  {
                    key: 'cancelDefaultBackup',
                    label: (
                      <Tooltip title={l2T('line.unsupportedDefaultBackup')}>
                        {l2T('line.cancelDefaultBackup')}
                      </Tooltip>
                    ),
                    disabled: true,
                  },
                  {
                    key: 'sort',
                    label: l2T('line.sort'),
                  },
                ],
                onClick: ({ key }) => openAction(key as Action),
              }}
            >
              <Button>
                {t('lineDetail.actions.more')}
                <ChevronDown size={12} />
              </Button>
            </Dropdown>
            <Input
              type="search"
              className="node-line-resolution-search"
              suffix={<Search size={14} aria-hidden="true" />}
              aria-label={t('lineDetail.filters.configuredSearch')}
              placeholder={t('lineDetail.filters.searchPlaceholder')}
              value={configuredSearch}
              onChange={(event) => { setConfiguredSearch(event.target.value); setSelectedIDs([]) }}
            />
          </div>
          <div
            className="node-line-resolution-table-scroll"
            data-testid="configured-line-ip-table-scroll"
          >
            <Table<NodeLineEndpoint>
              rowKey="id"
              size="small"
              tableLayout="fixed"
              columns={configuredColumns}
              dataSource={configured}
              loading={groupQuery.isLoading}
              pagination={
                configured.length > 10
                  ? { defaultPageSize: 10, showSizeChanger: true, pageSizeOptions: [10, 20, 50],
                    onChange: () => setSelectedIDs([]) }
                  : false
              }
              scroll={{ x: 860 }}
              rowSelection={{
                columnWidth: 44,
                selectedRowKeys: selectedIDs,
                onChange: (keys) => setSelectedIDs(keys.map(String)),
                getCheckboxProps: () => ({ disabled: actionsDisabled }),
              }}
              locale={{ emptyText: l2T('line.empty') }}
            />
          </div>
        </section>
      </div>
      <Modal
        width={dialog === 'weight' || dialog === 'sort' ? 350 : 460}
        title={l2T(dialog === 'weight' ? 'line.weightTitle' : dialog === 'sort' ? 'line.sortTitle' : 'line.confirmTitle')}
        open={Boolean(dialog)}
        okText={l2T('actions.confirm')}
        cancelText={l2T('actions.cancel')}
        confirmLoading={mutation.isPending}
        onCancel={() => {
          if (!mutation.isPending) setDialog(null)
        }}
        onOk={confirmAction}
        okButtonProps={{
          disabled: (dialog === 'weight' &&
            (weight === null || !Number.isInteger(weight) || weight < 1 || weight > 100)) ||
            (dialog === 'sort' &&
              (sortOrder === null || !Number.isInteger(sortOrder) || sortOrder < 1 || sortOrder > 999999)),
        }}
      >
        {dialog === 'weight' ? (
          <>
            <InputNumber
              style={{ width: '100%' }}
              aria-label={l2T('nodes.weight')}
              value={weight}
              onChange={setWeight}
              precision={0}
            />
            <p className="node-l2-condition-help">{l2T('line.weightHelp')}</p>
          </>
        ) : dialog === 'sort' ? (
          <>
            <InputNumber
              style={{ width: '100%' }}
              aria-label={l2T('line.sortTitle')}
              value={sortOrder}
              onChange={setSortOrder}
              min={1}
              max={999999}
              precision={0}
            />
            <p className="node-l2-condition-help">{l2T('line.sortHelp')}</p>
          </>
        ) : (
          <p>
            {l2T('line.confirm', {
              count:
                dialog === 'add' || dialog === 'addStandby'
                  ? availableKeys.length
                  : selected.length,
            })}
          </p>
        )}
      </Modal>
    </section>
  )
}
