import { useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Modal, Result, Select, Table, Tabs, type TableColumnsType } from 'antd'
import { type Dayjs } from 'dayjs'

import { blockWindow } from './blockWindow'
import { Download, Unlock } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import type { AnalyticsAudience } from '../api/analytics'
import {
  analyticsLogsApi,
  type BlockEdgeProgress,
  type BlockHistory,
  type BlockStateFilters,
  type CCBan,
  type CurrentBlock,
  type SiteBlacklistCount,
} from '../api/analyticsLogs'
import { ApiError, type Principal } from '../api/auth'
import { securityPoliciesApi } from '../api/securityPolicies'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import '../i18n/blockLogCCBans'
import './SiteBlockLogPage.css'
import { FeedbackWhen, TimeRangeFilter } from '@cdnca/ui'

type BlockOwner = readonly [Principal['scope_kind'], string, string | null, string, number]
type BlockView = 'current' | 'count' | 'history' | 'ccBans'
type BlockFilterKey = 'ip' | 'site' | 'filter'

// The history tab searches by IP and site only; `filter` is a current-blocks field.
const historyKeys: readonly Extract<BlockFilterKey, 'ip' | 'site'>[] = ['ip', 'site']
type BlockStateRow = CurrentBlock | BlockHistory

const pageSizeOptions = [10, 30, 100, 300]

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleBlockRead = new Error('Block-state owner changed during read')

function downloadCsv(filename: string, header: string[], rows: string[][]): void {
  const escape = (value: string) => `"${value.replaceAll('"', '""')}"`
  const body = [header, ...rows].map((row) => row.map(escape).join(',')).join('\r\n')
  const url = URL.createObjectURL(new Blob([`\uFEFF${body}`], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function blockOwner(principal: Principal, sessionEpoch: number): BlockOwner | null {
  if (!principal.scope_id?.trim() || !principal.user_id?.trim() || sessionEpoch < 1) return null
  if (principal.scope_kind === 'tenant' && !principal.tenant_id) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canReadBlocks(principal: Principal): boolean {
  return principal.permissions.includes('sites.read') ||
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
}

function currentBlockAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canReadBlocks(principal)) return null
  const owner = blockOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function blockErrorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'blockState.states.requestFailed'
  if (error.status === 400) return 'blockState.states.invalidRequest'
  if (error.status === 401 || error.status === 403) return 'blockState.states.permissionDenied'
  if (error.status === 404) return 'blockState.states.notFound'
  if (error.status === 409) return 'blockState.states.conflict'
  if (error.status === 503) return 'blockState.states.storageUnavailable'
  if (error.status === 504) return 'blockState.states.timeout'
  return 'blockState.states.requestFailed'
}

function createUnlockKey(): string {
  if (typeof crypto.randomUUID === 'function') return `unlock-${crypto.randomUUID()}`
  const bytes = new Uint32Array(4)
  crypto.getRandomValues(bytes)
  return `unlock-${Array.from(bytes, (value) => value.toString(16).padStart(8, '0')).join('')}`
}

// The unlock candidate's progress on the nodes (blockEdgeProgressSQL): state, ready/total, failed, and the
// nodes that ignored it as an old release (they already run a newer revision; not a failure).
function BlockEdgeProgressText({ progress }: { progress?: BlockEdgeProgress }) {
  const { t } = useTranslation('analyticsLogs')
  if (!progress) return null
  return (
    <span className="block-edge-progress" data-testid="block-edge-progress">
      <span className={progress.failed_nodes > 0 ? 'block-edge-progress-failed' : undefined}>
        {t('blockState.values.progress', {
          state: t(`blockState.progress.${progress.state}`),
          ready: progress.ready_nodes, total: progress.total_nodes, failed: progress.failed_nodes,
        })}
      </span>
      {progress.superseded_nodes > 0 ? (
        <span>{t('blockState.values.superseded', { n: progress.superseded_nodes })}</span>
      ) : null}
    </span>
  )
}

// Block rows carry the ACL security policy that produced them; listing those needs security_policies.read
// (platform.admin also passes, identity.Authorize). Without it the page keeps the plain ID input.
function canListPolicies(principal: Principal): boolean {
  return principal.permissions.includes('security_policies.read') || principal.permissions.includes('platform.admin')
}

function filterName(
  t: (key: string, options?: Record<string, unknown>) => string, id: string, policyNames?: ReadonlyMap<string, string>,
): string {
  const policyName = policyNames?.get(id)
  if (policyName) return t('blockState.filterNames.policy', { name: policyName, id })
  const custom = id.match(/extra_f_(\d+)/)
  if (custom) return t('blockState.filterNames.customRule', { index: custom[1], id })
  const known = ['block_region', 'block_proxy', 'block_page_num_limit', 'waf_auto_block']
  return known.includes(id)
    ? t(`blockState.filterNames.${id}`, { id })
    : t('blockState.filterNames.unknown', { id })
}

// Filter state is owned by the page so switching tabs keeps the applied filters.
type BlockFilterState = {
  drafts: Record<BlockFilterKey, string>
  changeDraft: (key: BlockFilterKey, value: string) => void
  applied: BlockStateFilters
  /** The history tab narrows by occurrence window instead of by filter id. */
  timeRange: readonly [Dayjs | null, Dayjs | null]
  /** TimeRangeFilter preset key, or 'custom' (also when no window is set). */
  timePreset: string
  applyWindow: (value: readonly [Dayjs | null, Dayjs | null], preset?: string) => void
  clearFilters: () => void
  page: number
  setPage: (page: number) => void
  pageSize: number
  setPageSize: (pageSize: number) => void
}

const emptyDrafts: Record<BlockFilterKey, string> = { ip: '', site: '', filter: '' }

function useBlockFilterState(): BlockFilterState {
  const [drafts, setDrafts] = useState<Record<BlockFilterKey, string>>(emptyDrafts)
  const [applied, setApplied] = useState<BlockStateFilters>({})
  const [timeRange, setTimeRange] = useState<readonly [Dayjs | null, Dayjs | null]>([null, null])
  const [timePreset, setTimePreset] = useState('custom')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  // The site filter is a UUID: a partial entry is kept in the draft but never sent, so a half-typed id
  // cannot trigger a 400 from the block-state endpoint.
  const applyFilter = (key: BlockFilterKey, value: string) => {
    if (key === 'site' && value && !uuidPattern.test(value)) return
    setApplied((current) => {
      const updated = { ...current }
      if (key === 'ip') {
        if (value) updated.cidr = value
        else delete updated.cidr
      }
      if (key === 'site') {
        if (value) updated.siteId = value
        else delete updated.siteId
      }
      if (key === 'filter') {
        if (value) updated.policyId = value
        else delete updated.policyId
      }
      return updated
    })
    setPage(1)
  }

  const changeDraft = (key: BlockFilterKey, value: string) => {
    setDrafts((current) => ({ ...current, [key]: value }))
    applyFilter(key, value.trim())
  }

  const applyWindow = (value: readonly [Dayjs | null, Dayjs | null], preset = 'custom') => {
    setTimeRange(value)
    setTimePreset(preset)
    setApplied((current) => {
      const updated = { ...current }
      delete updated.start
      delete updated.end
      return { ...updated, ...blockWindow(value[0], value[1]) }
    })
    setPage(1)
  }

  const clearFilters = () => {
    setDrafts(emptyDrafts)
    setTimeRange([null, null])
    setTimePreset('custom')
    setApplied({})
    setPage(1)
  }

  return {
    drafts, changeDraft, applied, timeRange, timePreset, applyWindow, clearFilters,
    page, setPage, pageSize, setPageSize,
  }
}

function BlockStatePanel({ view, owner, ownerKey, principal, filters }: {
  view: 'current' | 'history'
  owner: BlockOwner
  ownerKey: string
  principal: Principal
  filters: BlockFilterState
}) {
  const { t, i18n } = useTranslation('analyticsLogs')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const audience: AnalyticsAudience = owner[0] === 'platform' ? 'admin' : 'tenant'
  const {
    drafts, changeDraft, applied, timeRange, timePreset, applyWindow, clearFilters,
    page, setPage, pageSize, setPageSize,
  } = filters
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [selected, setSelected] = useState<CurrentBlock | null>(null)
  const [unlockKey, setUnlockKey] = useState('')
  const [unlocking, setUnlocking] = useState(false)
  const [unlockError, setUnlockError] = useState<string | null>(null)
  const [siteUnlockOpen, setSiteUnlockOpen] = useState(false)
  const [siteUnlockId, setSiteUnlockId] = useState('')
  const [siteUnlocking, setSiteUnlocking] = useState(false)
  const [siteUnlockError, setSiteUnlockError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [selectionHint, setSelectionHint] = useState(false)
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const canManage = principal.permissions.includes('security_policies.manage')
  const ready = true
  const offset = (page - 1) * pageSize
  const queryKey = ['analytics-block-state', ownerKey, view, applied, pageSize, offset] as const
  const policyPicker = canListPolicies(principal)
  // Block rows come from ACL policies only (block_state_postgres.go keeps KindACL), so the picker lists those.
  const policyQuery = useQuery({
    queryKey: ['analytics-block-state-policies', ownerKey],
    queryFn: async () => {
      const token = currentBlockAccess(ownerKey)
      if (!token) throw staleBlockRead
      return securityPoliciesApi.list(token, { page: 1, limit: 100, kind: 'acl' })
    },
    enabled: policyPicker && Boolean(currentBlockAccess(ownerKey)),
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  })
  const policyNames = useMemo(
    () => new Map((policyQuery.data?.items ?? []).map((policy) => [policy.id, policy.name] as const)),
    [policyQuery.data],
  )

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentBlockAccess(ownerKey)
      if (!token) throw staleBlockRead
      const filters: BlockStateFilters = { ...applied, limit: pageSize, offset }
      const result = audience === 'admin'
        ? view === 'current'
          ? await analyticsLogsApi.listCurrentBlocks(token, 'admin', filters)
          : await analyticsLogsApi.listBlockHistory(token, 'admin', filters)
        : view === 'current'
          ? await analyticsLogsApi.listCurrentBlocks(token, 'tenant', filters)
          : await analyticsLogsApi.listBlockHistory(token, 'tenant', filters)
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      return result
    },
    enabled: ready && Boolean(currentBlockAccess(ownerKey)),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })

  const rows = query.data?.data ?? []
  const unlockableRows = rows.filter((row): row is CurrentBlock => 'unlockable' in row && row.unlockable)
  const total = query.data?.total_count ?? 0
  const hasFilters = Object.keys(applied).length > 0

  const openUnlock = (block: CurrentBlock) => {
    setSelected(block)
    setUnlockKey(createUnlockKey())
    setUnlockError(null)
  }

  const exportBlacklist = () => {
    const stamp = new Date().toISOString().slice(0, 19).replaceAll(':', '-')
    downloadCsv(
      `block-${view}-${stamp}.csv`,
      view === 'current'
        ? [t('blockState.table.site'), t('blockState.table.domain'), t('blockState.table.cidr'),
          t('blockState.table.location'), t('blockState.table.filter'), t('blockState.table.blockedAt')]
        : [t('blockState.table.site'), t('blockState.table.domain'), t('blockState.table.cidr'),
          t('blockState.table.location'), t('blockState.table.filter'), t('blockState.table.blockedAt'),
          t('blockState.table.autoUnlock')],
      rows.map((row) => (view === 'current'
        ? [
          String(row.site_display_id), row.domain, row.cidr, row.position, filterName(t, row.policy_id, policyNames),
          (row as CurrentBlock).blocked_at,
        ]
        : [
          String(row.site_display_id), row.domain, row.cidr, row.position, filterName(t, row.policy_id, policyNames),
          (row as BlockHistory).requested_at,
          (row as BlockHistory).auto_unlock ? t('blockState.values.no') : t('blockState.values.yes'),
        ])),
    )
  }

  const unlockRows = async (targets: CurrentBlock[]): Promise<{ accepted: number; failed: number }> => {
    const token = currentBlockAccess(ownerKey)
    if (!token) return { accepted: 0, failed: targets.length }
    let accepted = 0
    let failed = 0
    for (const target of targets) {
      const input = {
        blockId: target.id,
        idempotencyKey: createUnlockKey(),
        ...(audience === 'admin' ? { tenantId: target.tenant_id } : {}),
      }
      try {
        if (audience === 'admin') {
          await analyticsLogsApi.unlockCurrentBlock(token, 'admin', input as {
            blockId: string; idempotencyKey: string; tenantId: string
          })
        } else {
          await analyticsLogsApi.unlockCurrentBlock(token, 'tenant', input)
        }
        if (!currentBlockAccess(ownerKey)) {
          failed += 1
          break
        }
        accepted += 1
      } catch {
        failed += 1
        break
      }
    }
    return { accepted, failed }
  }

  const unlockSelected = async () => {
    const targets = unlockableRows.filter((row) => selectedKeys.includes(row.id))
    if (targets.length === 0) {
      setSuccess(null)
      setSelectionHint(true)
      return
    }
    setSelectionHint(false)
    setSiteUnlocking(true)
    setSuccess(null)
    const { accepted, failed } = await unlockRows(targets)
    setSiteUnlocking(false)
    setSelectedKeys([])
    setSuccess(t('blockState.states.batchAccepted', { accepted, failed }))
    await queryClient.invalidateQueries({ queryKey: ['analytics-block-state', ownerKey] })
  }

  const unlockSite = async () => {
    const site = siteUnlockId.trim()
    if (!site) {
      setSiteUnlockError(t('blockState.states.siteIdRequired'))
      return
    }
    if (!/^\d+$/.test(site) || Number(site) < 1) {
      setSiteUnlockError(t('blockState.states.siteIdInvalid'))
      return
    }
    const token = currentBlockAccess(ownerKey)
    if (!token) {
      setSiteUnlockError(t('blockState.states.permissionDenied'))
      return
    }
    setSiteUnlocking(true)
    setSiteUnlockError(null)
    try {
      const filters: BlockStateFilters = { ...applied, limit: 100, offset: 0 }
      const result = audience === 'admin'
        ? await analyticsLogsApi.listCurrentBlocks(token, 'admin', filters)
        : await analyticsLogsApi.listCurrentBlocks(token, 'tenant', filters)
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      const targets = result.data.filter((row) => row.site_display_id === Number(site) && row.unlockable)
      if (targets.length === 0) {
        setSiteUnlockError(t('blockState.states.siteHasNoBlocks'))
        return
      }
      const siteScopes = new Set(targets.map((row) => `${row.tenant_id}:${row.site_id}`))
      if (audience === 'admin' && siteScopes.size > 1) {
        setSiteUnlockError(t('blockState.states.siteIdAmbiguous'))
        return
      }
      const { accepted, failed } = await unlockRows(targets)
      setSiteUnlockOpen(false)
      setSiteUnlockId('')
      setSuccess(t('blockState.states.siteUnlockAccepted', { accepted, failed }))
      await queryClient.invalidateQueries({ queryKey: ['analytics-block-state', ownerKey] })
    } catch (error) {
      setSiteUnlockError(t(blockErrorKey(error)))
    } finally {
      setSiteUnlocking(false)
    }
  }

  const confirmUnlock = async () => {
    if (!selected || !unlockKey) return
    const token = currentBlockAccess(ownerKey)
    if (!token) {
      setUnlockError(t('blockState.states.permissionDenied'))
      return
    }
    setUnlocking(true)
    setUnlockError(null)
    try {
      const result = audience === 'admin'
        ? await analyticsLogsApi.unlockCurrentBlock(token, 'admin', {
          blockId: selected.id, tenantId: selected.tenant_id, idempotencyKey: unlockKey,
        })
        : await analyticsLogsApi.unlockCurrentBlock(token, 'tenant', {
          blockId: selected.id, idempotencyKey: unlockKey,
        })
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      setSelected(null)
      setUnlockKey('')
      setSuccess(t('blockState.states.unlockAccepted', { candidate: result.candidate_id }))
      await queryClient.invalidateQueries({ queryKey: ['analytics-block-state', ownerKey] })
    } catch (error) {
      setUnlockError(t(blockErrorKey(error)))
    } finally {
      setUnlocking(false)
    }
  }

  const currentColumns: TableColumnsType<BlockStateRow> = [
    {
      title: t('blockState.table.site'), dataIndex: 'site_display_id', key: 'site_display_id',
      width: 100, align: 'center',
    },
    { title: t('blockState.table.domain'), dataIndex: 'domain', key: 'domain', width: 200, ellipsis: true },
    { title: t('blockState.table.cidr'), dataIndex: 'cidr', key: 'cidr', width: 180 },
    { title: t('blockState.table.location'), dataIndex: 'position', key: 'position', width: 180 },
    {
      title: t('blockState.table.filter'), key: 'filter', width: 200, ellipsis: true,
      render: (_value, row) => filterName(t, row.policy_id, policyNames),
    },
    {
      title: t('blockState.table.blockedAt'), dataIndex: 'blocked_at', key: 'blocked_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      // Empty, except while an unlock is on its way to the edge.
      title: t('blockState.table.unlockedAt'), key: 'unlocked_at', width: 180,
      render: (_value, row) => <BlockEdgeProgressText progress={row.edge_progress} />,
    },
    {
      title: t('blockState.table.actions'), key: 'actions', width: 130,
      render: (_value, row) => (
        <div className="analytics-inline-actions">
          <Button
            type="link"
            size="small"
            disabled={!canManage || !('unlockable' in row) || !row.unlockable}
            onClick={() => openUnlock(row as CurrentBlock)}
          >
            {t('blockState.actions.unlock')}
          </Button>
          <Button
            type="link"
            size="small"
            onClick={() => navigate(`/monitor/site/access-log?addr=${encodeURIComponent(row.cidr)}`)}
          >
            {t('blockState.actions.viewLog')}
          </Button>
        </div>
      ),
    },
  ]

  const historyColumns: TableColumnsType<BlockStateRow> = [
    {
      title: t('blockState.table.site'), dataIndex: 'site_display_id', key: 'site_display_id',
      width: 100, align: 'center',
    },
    { title: t('blockState.table.domain'), dataIndex: 'domain', key: 'domain', width: 200, ellipsis: true },
    { title: t('blockState.table.cidr'), dataIndex: 'cidr', key: 'cidr', width: 150 },
    { title: t('blockState.table.location'), dataIndex: 'position', key: 'position', width: 150 },
    {
      title: t('blockState.table.filter'), key: 'filter', width: 150, ellipsis: true,
      render: (_value, row) => filterName(t, row.policy_id, policyNames),
    },
    {
      title: t('blockState.table.blockedAt'), dataIndex: 'requested_at', key: 'requested_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('blockState.table.autoUnlock'), key: 'auto_unlock', width: 100, align: 'center',
      render: (_value, row) => (
        <>
          {'auto_unlock' in row && row.auto_unlock ? t('blockState.values.no') : t('blockState.values.yes')}
          {/* Until the unlock is live on every node, its edge progress sits under the value. */}
          {row.edge_progress && row.edge_progress.state !== 'promoted' ? (
            <BlockEdgeProgressText progress={row.edge_progress} />
          ) : null}
        </>
      ),
    },
  ]

  const clear = () => {
    clearFilters()
    setSelectedKeys([])
  }

  // The clear link is rendered unconditionally next to the inputs; only the tag row is conditional.
  const clearButton = <Button type="link" size="small" onClick={clear}>{t('blockState.actions.clear')}</Button>

  return (
    <div className="block-log-view" role="tabpanel" aria-label={t(`blockState.tabs.${view}`)}>
        <div className="analytics-filter-bar block-log-toolbar">
          <div className="block-log-toolbar-actions">
            {view === 'current' ? (
              <>
                {/* 「解锁IP」在未选中任何行时仍是实心蓝
                    rgb(45,140,240)/白字，不是禁用灰，所以只按权限禁用。
                    未选中时 unlockSelected 提示「请先选择要解锁的记录」（10-22 W4）。 */}
                <Button
                  type="primary"
                  icon={<Unlock size={15} />}
                  disabled={!canManage}
                  loading={siteUnlocking && selectedKeys.length > 0}
                  onClick={() => void unlockSelected()}
                >
                  {t('blockState.actions.unlockIp')}
                </Button>
                <Button disabled={!canManage} onClick={() => { setSiteUnlockId(''); setSiteUnlockError(null); setSiteUnlockOpen(true) }}>
                  {t('blockState.actions.unlockSite')}
                </Button>
              </>
            ) : null}
            <Button
              type={view === 'history' ? 'primary' : 'default'}
              icon={<Download size={15} />}
              disabled={rows.length === 0}
              onClick={exportBlacklist}
            >
              {t('blockState.actions.exportBlacklist')}
            </Button>
          </div>
          <div className="block-log-toolbar-filters">
            {historyKeys.map((key) => (
              <Input
                key={key}
                addonBefore={t(`blockState.filterLabels.${key}`)}
                placeholder={t(`blockState.filters.${key}`)}
                value={drafts[key]}
                onChange={(event) => changeDraft(key, event.target.value)}
              />
            ))}
            {view === 'current' && policyPicker ? (
              <Select
                aria-label={t('blockState.filterLabels.filter')}
                prefix={t('blockState.filterLabels.filter')}
                placeholder={t('blockState.filters.filterSelect')}
                allowClear
                showSearch
                optionFilterProp="label"
                loading={policyQuery.isFetching}
                notFoundContent={policyQuery.error ? t('blockState.filters.filterUnavailable') : undefined}
                value={drafts.filter || undefined}
                options={(policyQuery.data?.items ?? []).map((policy) => ({ value: policy.id, label: policy.name }))}
                onChange={(value?: string) => changeDraft('filter', value ?? '')}
              />
            ) : view === 'current' ? (
              <Input
                addonBefore={t('blockState.filterLabels.filter')}
                placeholder={t('blockState.filters.filter')}
                value={drafts.filter}
                onChange={(event) => changeDraft('filter', event.target.value)}
              />
            ) : (
              // History has no default window (open until a range is chosen); both ends are inclusive seconds (blockWindow).
              <TimeRangeFilter precision="second" endInclusive
                value={{ preset: timePreset, range: timeRange[0] && timeRange[1] ? [timeRange[0], timeRange[1]] : null }}
                onChange={({ preset, range }) => applyWindow(range ?? [null, null], preset)} />
            )}
            {clearButton}
          </div>
        </div>
        {hasFilters ? (
          <div className="analytics-filter-bar">
            {historyKeys.filter((key) => drafts[key].trim()).map((key) => (
              <span key={key} className="analytics-filter-tag">
                {`${t(`blockState.filterLabels.${key}`)}：${drafts[key].trim()}`}
              </span>
            ))}
            {view === 'current' && drafts.filter.trim() ? (
              <span className="analytics-filter-tag">
                {`${t('blockState.filterLabels.filter')}：${policyNames.get(drafts.filter.trim()) ?? drafts.filter.trim()}`}
              </span>
            ) : null}
            {timeRange[0] && timeRange[1] ? (
              <span className="analytics-filter-tag">
                {`${t('blockState.filterLabels.timeRange')}：${timeRange[0].format('YYYY-MM-DD HH:mm:ss')} - ${timeRange[1].format('YYYY-MM-DD HH:mm:ss')}`}
              </span>
            ) : null}
          </div>
        ) : null}
        {selectionHint ? <Alert type="warning" showIcon message={t('blockState.states.selectFirst')} /> : null}
        {success ? <Alert type="success" showIcon message={success} /> : null}
        {query.error && !query.isFetching ? (
          <FeedbackWhen title={t(blockErrorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
        ) : null}
        <div className="analytics-meta">
          {query.data?.snapshot_at ? (
            <span>{t('blockState.snapshot', { time: formatDateTime(query.data.snapshot_at, locale) })}</span>
          ) : null}
        </div>
        <Table<BlockStateRow>
          data-testid={`block-state-${view}`}
          rowKey="id"
          size="small"
          columns={view === 'current' ? currentColumns : historyColumns}
          dataSource={rows as BlockStateRow[]}
          loading={ready && query.isFetching && !query.data}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            pageSizeOptions: pageSizeOptions.map(String),
            showTotal: (count) => t('blockState.pagination.total', { count: formatNumber(count, locale) }),
            onChange: (nextPage, nextSize) => {
              setPage(nextSize === pageSize ? nextPage : 1)
              setPageSize(nextSize)
            },
          }}
          rowSelection={view === 'current' ? {
            selectedRowKeys: selectedKeys,
            onChange: (keys) => {
              setSelectedKeys(keys as string[])
              if (keys.length > 0) setSelectionHint(false)
            },
            getCheckboxProps: (row) => ({ disabled: !('unlockable' in row) || !row.unlockable }),
          } : undefined}
          locale={{ emptyText: query.error ? ' ' : t(`blockState.states.empty.${view}`) }}
        />
      <Modal
        title={t('blockState.unlock.title')}
        open={selected !== null}
        okText={t('blockState.unlock.confirm')}
        cancelText={t('blockState.unlock.cancel')}
        okButtonProps={{ danger: true }}
        confirmLoading={unlocking}
        onOk={() => void confirmUnlock()}
        onCancel={() => {
          if (!unlocking) {
            setSelected(null)
            setUnlockKey('')
            setUnlockError(null)
          }
        }}
      >
        <p>{t('blockState.unlock.description', { cidr: selected?.cidr ?? '' })}</p>
        <p>{t('blockState.unlock.reason')}</p>
        {unlockError ? <Alert type="error" showIcon message={unlockError} /> : null}
      </Modal>
      <Modal
        title={t('blockState.unlock.siteTitle')}
        width={300}
        open={siteUnlockOpen}
        okText={t('blockState.unlock.confirm')}
        cancelText={t('blockState.unlock.cancel')}
        okButtonProps={{ danger: true }}
        confirmLoading={siteUnlocking}
        onOk={() => void unlockSite()}
        onCancel={() => {
          if (!siteUnlocking) {
            setSiteUnlockOpen(false)
            setSiteUnlockError(null)
          }
        }}
      >
        <Input
          placeholder={t('blockState.filters.site')}
          value={siteUnlockId}
          onChange={(event) => setSiteUnlockId(event.target.value)}
        />
        {siteUnlockError ? <Alert type="error" showIcon message={siteUnlockError} /> : null}
      </Modal>
    </div>
  )
}

const ccBanWindowDays = 7

// The admin CC-ban endpoint is scoped to one tenant (tenants.id). Operators who can
// list users pick a tenant owner; others enter the tenant ID directly.
function canLookupTenants(principal: Principal): boolean {
  return principal.permissions.includes('identity.users.manage') || principal.permissions.includes('platform.admin')
}

// NF34: IPs auto-banned by CC rules in the last 7 days, aggregated from the
// security log. The platform view lists every tenant; a tenant only narrows it.
function CCBanPanel({ owner, ownerKey, principal }: { owner: BlockOwner; ownerKey: string; principal: Principal }) {
  const { t, i18n } = useTranslation('analyticsLogs')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const audience: AnalyticsAudience = owner[0] === 'platform' ? 'admin' : 'tenant'
  const tenantLookup = audience === 'admin' && canLookupTenants(principal)
  const [draftIp, setDraftIp] = useState('')
  const [clientIp, setClientIp] = useState('')
  const [draftTenant, setDraftTenant] = useState('')
  const [tenantId, setTenantId] = useState('')
  const [tenantError, setTenantError] = useState(false)
  const [tenantSearch, setTenantSearch] = useState('')
  const window = useMemo(() => {
    const to = new Date(Math.ceil(Date.now() / 60_000) * 60_000)
    return { from: new Date(to.getTime() - ccBanWindowDays * 86_400_000).toISOString(), to: to.toISOString() }
  }, [])
  const tenants = useQuery({
    queryKey: ['analytics-cc-ban-tenants', ownerKey, tenantSearch] as const,
    queryFn: async () => {
      const token = currentBlockAccess(ownerKey)
      if (!token) throw staleBlockRead
      const result = await usersApi.list(token, { page: 1, limit: 20, search: tenantSearch, status: 'active', role: 'tenant_owner' })
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      return result
    },
    enabled: tenantLookup && Boolean(currentBlockAccess(ownerKey)),
    retry: false,
    refetchOnWindowFocus: false,
  })
  const tenantOptions = (tenants.data?.items ?? [])
    .filter((item) => item.tenant_id && uuidPattern.test(item.tenant_id))
    .map((item) => ({ value: item.tenant_id, label: `${item.username}（${item.display_id}）` }))
  const search = () => {
    setClientIp(draftIp.trim())
    if (audience === 'admin' && !tenantLookup) {
      const tenant = draftTenant.trim()
      setTenantError(tenant !== '' && !uuidPattern.test(tenant))
      setTenantId(uuidPattern.test(tenant) ? tenant : '')
    }
  }
  const query = useQuery({
    queryKey: ['analytics-cc-bans', ownerKey, tenantId, window.from, clientIp] as const,
    queryFn: async () => {
      const token = currentBlockAccess(ownerKey)
      if (!token) throw staleBlockRead
      const filters = { ...window, ...(clientIp ? { clientIp } : {}) }
      const result = audience === 'admin'
        ? await analyticsLogsApi.listCCBans(token, 'admin', { ...filters, ...(tenantId ? { tenantId } : {}) })
        : await analyticsLogsApi.listCCBans(token, 'tenant', filters)
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      return result
    },
    enabled: !tenantError && Boolean(currentBlockAccess(ownerKey)),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const columns: TableColumnsType<CCBan> = [
    { title: t('blockState.table.domain'), dataIndex: 'host', key: 'host', width: 200, ellipsis: true },
    { title: t('blockState.table.cidr'), dataIndex: 'client_ip', key: 'client_ip', width: 180 },
    { title: t('blockState.ccBans.rule'), dataIndex: 'rule_id', key: 'rule_id', width: 300, ellipsis: true },
    {
      title: t('blockState.ccBans.count'), dataIndex: 'ban_count', key: 'ban_count', width: 100, align: 'center',
      render: (value: number) => formatNumber(value, locale),
    },
    {
      title: t('blockState.ccBans.firstBannedAt'), dataIndex: 'first_banned_at', key: 'first_banned_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('blockState.ccBans.lastBannedAt'), dataIndex: 'last_banned_at', key: 'last_banned_at', width: 180,
      render: (value: string) => formatDateTime(value, locale),
    },
  ]
  return (
    <div className="block-log-view" role="tabpanel" aria-label={t('blockState.tabs.ccBans')}>
      <div className="analytics-filter-bar">
        {tenantLookup ? (
          <Select
            aria-label={t('blockState.ccBans.tenant')}
            prefix={t('blockState.ccBans.tenant')}
            placeholder={t('blockState.ccBans.tenantPlaceholder')}
            style={{ width: 260 }}
            allowClear
            showSearch
            filterOption={false}
            loading={tenants.isFetching}
            value={tenantId || undefined}
            options={tenantOptions}
            notFoundContent={tenants.error ? t('blockState.ccBans.tenantLookupFailed') : undefined}
            onSearch={(value) => setTenantSearch(value.trim())}
            onChange={(value?: string) => setTenantId(value ?? '')}
          />
        ) : audience === 'admin' ? (
          <Input
            aria-label={t('filters.tenant')}
            addonBefore={t('filters.tenant')}
            style={{ width: 380 }}
            allowClear
            status={tenantError ? 'error' : undefined}
            value={draftTenant}
            onChange={(event) => setDraftTenant(event.target.value)}
            onPressEnter={search}
          />
        ) : null}
        <Input
          allowClear
          style={{ width: 220 }}
          placeholder={t('blockState.filters.ip')}
          value={draftIp}
          onChange={(event) => setDraftIp(event.target.value)}
          onPressEnter={search}
        />
        <Button type="primary" onClick={search}>{t('blockState.ccBans.search')}</Button>
        <span>{t('blockState.ccBans.window', { days: ccBanWindowDays })}</span>
      </div>
      {tenantError ? <Alert type="error" showIcon message={t('states.invalidUuid')} /> : null}
      {query.error && !query.isFetching ? (
        <FeedbackWhen title={t(blockErrorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      {query.data?.truncated ? <Alert type="info" showIcon message={t('blockState.ccBans.truncated')} /> : null}
      <Table<CCBan>
        data-testid="block-state-cc-bans"
        rowKey={(row) => `${row.site_id}:${row.client_ip}:${row.rule_id}`}
        size="small"
        columns={columns}
        dataSource={query.data?.data ?? []}
        loading={query.isFetching && !query.data}
        pagination={{ pageSize: 10, showSizeChanger: true, pageSizeOptions: pageSizeOptions.map(String) }}
        locale={{ emptyText: query.error ? ' ' : t('blockState.ccBans.empty') }}
      />
    </div>
  )
}

function BlacklistCountPanel({ owner, ownerKey }: { owner: BlockOwner; ownerKey: string }) {
  const { t, i18n } = useTranslation('analyticsLogs')
  const audience: AnalyticsAudience = owner[0] === 'platform' ? 'admin' : 'tenant'
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryKey = ['analytics-blacklist-count', ownerKey] as const

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentBlockAccess(ownerKey)
      if (!token) throw staleBlockRead
      const result = audience === 'admin'
        ? await analyticsLogsApi.listSiteBlacklistCounts(token, 'admin')
        : await analyticsLogsApi.listSiteBlacklistCounts(token, 'tenant')
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      return result
    },
    enabled: Boolean(currentBlockAccess(ownerKey)),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })

  const rows = query.data?.data ?? []
  const start = (page - 1) * pageSize
  const pageRows = rows.slice(start, start + pageSize)

  const columns: TableColumnsType<SiteBlacklistCount> = [
    {
      title: t('blockState.stats.rank'), key: 'rank', width: 100, align: 'center',
      render: (_value, _row, index) => formatNumber(start + index + 1, locale),
    },
    {
      title: t('blockState.stats.site'), dataIndex: 'site_display_id', key: 'site_display_id',
      width: 100, align: 'center',
    },
    {
      title: t('blockState.stats.count'), dataIndex: 'count', key: 'count', width: 150,
      render: (value: number) => formatNumber(value, locale),
    },
  ]

  return (
    <div className="block-log-view" role="tabpanel" aria-label={t('blockState.tabs.count')}>
        <div className="analytics-filter-bar">
          <Button onClick={() => void query.refetch()}>{t('blockState.actions.refresh')}</Button>
        </div>
        {query.error && !query.isFetching ? (
          <FeedbackWhen title={t(blockErrorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
        ) : null}
        <Table<SiteBlacklistCount>
          data-testid="block-state-count"
          rowKey={(row) => `${row.tenant_id}:${row.site_id}`}
          size="small"
          columns={columns}
          dataSource={pageRows}
          loading={query.isFetching && !query.data}
          pagination={{
            current: page,
            pageSize,
            total: rows.length,
            showSizeChanger: true,
            pageSizeOptions: pageSizeOptions.map(String),
            showTotal: (count) => t('blockState.pagination.total', { count: formatNumber(count, locale) }),
            onChange: (nextPage, nextSize) => {
              setPage(nextSize === pageSize ? nextPage : 1)
              setPageSize(nextSize)
            },
          }}
          locale={{ emptyText: query.error ? ' ' : t('blockState.states.empty.count') }}
        />
    </div>
  )
}

export default function SiteBlockLogPage() {
  const { t } = useTranslation('analyticsLogs')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const [view, setView] = useState<BlockView>('current')
  const filters = useBlockFilterState()
  const owner = useMemo(() => principal ? blockOwner(principal, sessionEpoch) : null, [principal, sessionEpoch])

  if (!accessToken || !principal) return null
  if (!owner || !canReadBlocks(principal)) {
    return (
      <Result
        className="analytics-page analytics-page-error"
        status="403"
        title={t('states.permissionTitle')}
        subTitle={t('states.permissionDescription')}
      />
    )
  }
  const ownerKey = JSON.stringify(owner)

  return (
    <section className="analytics-page analytics-log-page site-block-log-page" aria-labelledby="analytics-block-log-title">
      <div className="analytics-panel">
        {/* 卡片里只有 tab 行，没有页面标题。 */}
        <h1 id="analytics-block-log-title" className="visually-hidden">{t('title.block')}</h1>
        <Tabs
          className="analytics-log-tabs"
          activeKey={view}
          animated={false}
          onChange={(key) => setView(key as BlockView)}
          items={(['current', 'count', 'history', 'ccBans'] as BlockView[]).map((key) => ({
            key, label: t(`blockState.tabs.${key}`),
          }))}
        />
        {view === 'ccBans' ? <CCBanPanel key={`${ownerKey}:ccBans`} owner={owner} ownerKey={ownerKey} principal={principal} /> : view === 'count'
          ? <BlacklistCountPanel key={`${ownerKey}:count`} owner={owner} ownerKey={ownerKey} />
          : <BlockStatePanel
            key={`${ownerKey}:${view}`}
            view={view}
            owner={owner}
            ownerKey={ownerKey}
            principal={principal}
            filters={filters}
          />}
      </div>
    </section>
  )
}
