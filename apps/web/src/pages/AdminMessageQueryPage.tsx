import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Modal, Result, Select, Table, Tooltip, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'

import { ApiError, networkApiError, responseApiError, type Principal } from '../api/auth'
import { notificationsApi } from '../api/notifications'
import { sitesApi } from '../api/sites'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/adminMessageQuery'
import {
  adminMessageSearchParams,
  adminMessageTypeKey,
  isAdminMessagePage,
  type AdminMessage,
  type AdminMessageDeliveryState,
  type AdminMessagePage,
  type AdminMessageQueryFilters,
} from './AdminMessageQueryPage.adapter'
import './AdminMessageQueryPage.css'
import { FeedbackWhen, IdOrNameInput, useLiveApply, type IdOrNameOption } from '@cdnca/ui'
import { filterParam, useFilterUrl } from './filterUrl'

type Owner = readonly ['platform', string, null, string, number]

const staleRead = new Error('admin message query owner changed during read')
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const pageSizes = [10, 20, 50, 100] as const
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

type FilterKind = 'user' | 'site'
type FilterTexts = Record<FilterKind, string>
const filterKinds: FilterKind[] = ['user', 'site']

const filterPermissions: Record<FilterKind, string> = {
  user: 'identity.users.manage', site: 'sites.read',
}

// The filters take an ID or
// a name and apply as typed. Suggestions come from the existing list APIs
// (users: username/display name/email/phone or numeric user ID; sites: domain
// or numeric site ID); a picked suggestion or a pasted UUID filters by the
// object ID, any other text is sent as the user/site keyword (name substring or exact display
// ID, matched by the message query itself, so it works without list access).
async function searchFilterOptions(kind: FilterKind, accessToken: string, term: string): Promise<IdOrNameOption[]> {
  if (kind === 'user') {
    const result = await usersApi.list(accessToken, {
      page: 1, limit: 20, include_platform_admins: true,
      ...(/^\d+$/u.test(term) ? { display_id: term } : term ? { search: term } : {}),
    })
    return result.items.map((user) => ({ id: user.id, name: user.username, code: String(user.display_id) }))
  }
  const result = await sitesApi.list(accessToken, { page: 1, limit: 20, ...(term ? { domain: term.slice(0, 253) } : {}) })
  return result.items.map((site) => ({ id: site.id, name: site.domain, code: String(site.display_id) }))
}

/** A picked suggestion or pasted UUID filters by ID; other text is a keyword. */
function filterParams(texts: FilterTexts): Pick<AdminMessageQueryFilters, 'userID' | 'siteID' | 'user' | 'site'> {
  const result: ReturnType<typeof filterParams> = {}
  for (const kind of filterKinds) {
    const value = texts[kind].trim()
    if (!value) continue
    const id = value.toLowerCase()
    if (uuidPattern.test(id)) result[`${kind}ID`] = id
    else result[kind] = value.slice(0, 128)
  }
  return result
}

function NameOrIDFilter({ kind, ownerKey, value, onChange }: {
  kind: FilterKind
  ownerKey: string
  value: string
  onChange: (next: string) => void
}) {
  const { t } = useTranslation('adminMessageQuery')
  const canSearch = useSessionStore((state) => state.principal?.permissions.some((code) =>
    code === filterPermissions[kind] || code === 'platform.admin') ?? false)
  const search = useMemo(() => canSearch ? async (term: string) => {
    const token = currentAccess(ownerKey)
    if (!token) throw staleRead
    const result = await searchFilterOptions(kind, token, term)
    if (!currentAccess(ownerKey)) throw staleRead
    return result
  } : undefined, [canSearch, kind, ownerKey])
  const label = t(`filters.${kind}Id`)
  return (
    <label className={`admin-message-filter-group admin-message-filter-${kind}`}>
      <span className="admin-message-filter-label">{label}</span>
      <IdOrNameInput aria-label={label} placeholder={t(`filters.${kind}Placeholder`)} value={value}
        freeText isId={(text) => uuidPattern.test(text.toLowerCase())} search={search} onChange={onChange} />
    </label>
  )
}

function ownerFor(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null ||
    !principal.scope_id.trim() || !principal.user_id.trim() || sessionEpoch < 1) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.permissions.includes('system_configuration.read')
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal)) return null
  const owner = ownerFor(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function forbidden(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 403 || error.code === 'permission_denied')
}

async function listAdminMessages(accessToken: string, filters: AdminMessageQueryFilters): Promise<AdminMessagePage> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/notifications/messages?${adminMessageSearchParams(filters)}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const value: unknown = await response.json().catch(() => null)
  if (!isAdminMessagePage(value)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return value
}

export default function AdminMessageQueryPage() {
  const { t } = useTranslation('adminMessageQuery')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, sessionEpoch)
  if (!owner || !canRead(principal)) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <AdminMessageQueryContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}

function AdminMessageQueryContent({ owner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t, i18n } = useTranslation('adminMessageQuery')
  const queryClient = useQueryClient()
  const ownerRef = useRef(owner).current
  const queryPrefix = useMemo(() => ['admin-message-query', ...ownerRef] as const, [ownerRef])
  // Applied filters live in the URL (shareable); drafts apply 400ms after typing.
  const [initialParams] = useSearchParams()
  const [type, setType] = useState<string | undefined>(() => filterParam(initialParams, 'type') || undefined)
  const initialFilters = useRef<FilterTexts>({
    user: filterParam(initialParams, 'user'), site: filterParam(initialParams, 'site'),
  }).current
  const [draft, setDraft] = useState<FilterTexts>(initialFilters)
  const [applied, setApplied] = useState<FilterTexts>(initialFilters)
  const params = useMemo(() => filterParams(applied), [applied])
  const [detailMessage, setDetailMessage] = useState<AdminMessage | null>(null)
  const [limit, setLimit] = useState<(typeof pageSizes)[number]>(10)
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)

  const query = useQuery({
    queryKey: [...queryPrefix, type ?? null, params, limit, cursor ?? null],
    queryFn: async () => {
      const token = currentAccess(ownerKey)
      if (!token) throw staleRead
      const result = await listAdminMessages(token, {
        ...(type ? { type } : {}), ...params,
        limit, ...(cursor ? { cursor } : {}),
      })
      if (!currentAccess(ownerKey)) throw staleRead
      return result
    },
    retry: false,
    refetchOnWindowFocus: false,
  })

  const catalog = useQuery({
    queryKey: [...queryPrefix, 'event-catalog'],
    queryFn: async () => {
      const token = currentAccess(ownerKey)
      if (!token) throw staleRead
      const policy = await notificationsApi.getDeliveryPolicy(token)
      return [...new Set(policy.events.map((event) => event.event_type))]
    },
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 5 * 60_000,
  })

  useEffect(() => () => {
    if (currentAccess(ownerKey)) return
    queryClient.removeQueries({ queryKey: queryPrefix })
  }, [ownerKey, queryClient, queryPrefix])

  const resetPage = () => {
    setCursors([])
  }
  const applyFilters = (next: FilterTexts) => {
    setApplied(next)
    resetPage()
  }
  const trimmedDraft = { user: draft.user.trim(), site: draft.site.trim() }
  useLiveApply(trimmedDraft, applied, applyFilters)
  useFilterUrl({ type, ...applied })
  const editFilter = (kind: FilterKind) => (next: string) => setDraft((current) => ({ ...current, [kind]: next }))
  const nextPage = () => {
    const next = query.data?.next_cursor
    if (!next || next === cursor || cursors.includes(next)) return
    setCursors((current) => [...current, next])
  }
  const previousPage = () => {
    setCursors((current) => current.slice(0, -1))
  }
  const unknown = (value: string | null) => {
    const display = value?.trim()
    return display || <span className="admin-message-unknown">{t('unknown')}</span>
  }
  const messageType = (value: string) => {
    const key = adminMessageTypeKey(value)
    return key ? t(`types.${key}`) : t('types.other')
  }
  // Filter labels: an uncatalogued type is "other" plus its raw value so two
  // unknown types stay distinguishable.
  const typeLabel = (value: string) => {
    const key = adminMessageTypeKey(value)
    return key ? t(`types.${key}`) : t('filters.otherType', { type: value })
  }
  const typeOptions = [
    { value: '', label: t('filters.allTypes') },
    ...(catalog.data ?? []).map((value) => ({ value, label: typeLabel(value) }))
      .sort((left, right) => left.label.localeCompare(right.label, i18n.resolvedLanguage)),
  ]
  const channelState = (state: AdminMessageDeliveryState | null) =>
    state ? t(`deliveryStates.${state}`) : t('details.notGenerated')
  const time = (value: string) => formatDateTime(value, i18n.resolvedLanguage) || t('unknown')

  // L1: show who/what a row is about by name; the raw ID stays in the tooltip.
  const withID = (id: string | null, content: ReactNode) => id
    ? <Tooltip title={`ID: ${id}`}><span className="admin-message-named">{content}</span></Tooltip>
    : content
  const userCell = (_: unknown, record: AdminMessage) => {
    if (!record.username) return withID(record.user_id, unknown(null))
    const label = record.user_display_name && record.user_display_name !== record.username
      ? `${record.user_display_name}（${record.username}）` : record.username
    return withID(record.user_id, record.user_display_id
      ? <Link to={`/sys/user?display_id=${record.user_display_id}`}>{label}</Link>
      : label)
  }
  const titleCell = (_: unknown, record: AdminMessage) => record.title?.trim() || (
    <Tooltip title={t('titleFallbackHelp')}><span className="admin-message-unknown">{t('titleFallback', { type: messageType(record.type) })}</span></Tooltip>
  )
  // An event without a site shows a dash; the tooltip says why.
  const unlinked = (help: string) => (
    <Tooltip title={help}><span className="admin-message-unknown" aria-label={help}>—</span></Tooltip>
  )
  const siteCell = (_: unknown, record: AdminMessage) => record.site_id
    ? withID(record.site_id, record.site_domain
      ? <Link to={`/site/${encodeURIComponent(record.site_id)}/edit`}>{record.site_domain}</Link>
      : unknown(null))
    : unlinked(t('columns.siteUnlinked'))
  const columns: TableColumnsType<AdminMessage> = [
    { title: t('columns.user'), key: 'user', width: 180, render: userCell },
    { title: t('columns.type'), dataIndex: 'type', width: 150, render: messageType },
    { title: t('columns.title'), key: 'title', width: 240, render: titleCell },
    { title: t('columns.site'), key: 'site', width: 160, render: siteCell },
    { title: t('columns.createdAt'), dataIndex: 'created_at', width: 168, render: time },
    { title: t('columns.actions'), key: 'actions', width: 88, render: (_, record) => (
      <Button type="link" size="small" onClick={() => setDetailMessage(record)}>{t('actions.details')}</Button>
    ) },
  ]

  if (forbidden(query.error)) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }

  return (
    <section className="identity-page admin-message-query-page" aria-label={t('title')}>
      <div className="identity-toolbar admin-message-toolbar">
        <Select
          className="admin-message-filter-type"
          aria-label={t('filters.type')}
          value={type ?? ''}
          loading={catalog.isPending}
          status={catalog.isError ? 'warning' : undefined}
          showSearch
          optionFilterProp="label"
          options={typeOptions}
          onChange={(value: string) => {
            setType(value || undefined)
            resetPage()
          }}
        />
        {filterKinds.map((kind) => (
          <NameOrIDFilter key={kind} kind={kind} ownerKey={ownerKey} value={draft[kind]} onChange={editFilter(kind)} />
        ))}
        <Button className="admin-message-refresh" icon={<RefreshCw size={14} />} onClick={() => void query.refetch()}>
          {t('actions.refresh')}
        </Button>
      </div>
      {catalog.isError ? <Alert className="identity-alert" type="warning" showIcon message={t('errors.catalog')} /> : null}
      <div className="admin-message-table-scroll" data-testid="admin-message-deliveries" aria-busy={query.isPending || query.isFetching}>
        {query.isError ? (
          <FeedbackWhen title={t('errors.load')} action={(
            <Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>
          )} />
        ) : (
          <Table
            rowKey="id"
            size="small"
            loading={query.isPending || query.isFetching}
            columns={columns}
            dataSource={query.data?.items ?? []}
            pagination={false}
            scroll={{ x: 1127 }}
            locale={{ emptyText: query.isPending ? ' ' : t('empty') }}
          />
        )}
      </div>
      <div className="identity-pagination admin-message-pagination">
        <span className="admin-message-total">{t('pagination.total', { total: query.data?.total ?? 0 })}</span>
        <Button aria-label={t('actions.previous')} icon={<ChevronLeft size={14} />}
          disabled={cursors.length === 0 || query.isFetching} onClick={previousPage} />
        <Button className="admin-message-current-page" aria-current="page">{cursors.length + 1}</Button>
        <Button aria-label={t('actions.next')} icon={<ChevronRight size={14} />}
          disabled={!query.data?.next_cursor || query.isFetching || cursors.includes(query.data.next_cursor)} onClick={nextPage} />
        <Select
          aria-label={t('filters.pageSize')}
          value={limit}
          options={pageSizes.map((value) => ({ value, label: t('pagination.pageSize', { count: value }) }))}
          onChange={(value) => {
            setLimit(value)
            resetPage()
          }}
        />
      </div>
      <Modal
        title={t('details.title')}
        open={detailMessage !== null}
        onCancel={() => setDetailMessage(null)}
        footer={null}
        destroyOnHidden
      >
        {detailMessage ? (
          <div className="admin-message-detail" data-testid="admin-message-detail">
            <dl className="admin-message-detail-grid">
              <dt>{t('details.type')}</dt><dd>{messageType(detailMessage.type)}</dd>
              <dt>{t('details.user')}</dt><dd>{detailMessage.username ?? t('unknown')}</dd>
              <dt>{t('details.userId')}</dt><dd>{detailMessage.user_id ?? t('unknown')}</dd>
              <dt>{t('details.createdAt')}</dt><dd>{time(detailMessage.created_at)}</dd>
              <dt>{t('details.messageTitle')}</dt><dd>{detailMessage.title?.trim() || t('unknown')}</dd>
              <dt>{t('details.siteId')}</dt><dd>{detailMessage.site_id
                ? `${detailMessage.site_domain ?? t('unknown')}（${detailMessage.site_id}）` : t('details.noSubject')}</dd>
              <dt>{t('details.messageId')}</dt><dd>{detailMessage.id}</dd>
            </dl>
            <p className="admin-message-detail-hint">{t('details.deliveryHint')}</p>
            <div className="admin-message-detail-channel">
              <h3>{t('details.email')}<span className="admin-message-detail-state">{channelState(detailMessage.email_state)}</span></h3>
              <pre className="cdnca-dialog-scroll">{detailMessage.email_state ? detailMessage.email_content?.trim() || t('details.empty') : t('details.notGeneratedHelp')}</pre>
            </div>
            <div className="admin-message-detail-channel">
              <h3>{t('details.sms')}<span className="admin-message-detail-state">{channelState(detailMessage.sms_state)}</span></h3>
              <pre className="cdnca-dialog-scroll">{detailMessage.sms_state ? detailMessage.sms_content?.trim() || t('details.empty') : t('details.notGeneratedHelp')}</pre>
            </div>
          </div>
        ) : null}
      </Modal>
    </section>
  )
}
