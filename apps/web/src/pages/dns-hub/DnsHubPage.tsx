import { useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Alert, Button, Checkbox, Empty, Input, Result, Select, Space, Tag, Tooltip, Typography, type TableColumnsType } from 'antd'
import { Layers, Pencil, Plus, RefreshCw, RotateCw, Search, ShieldCheck, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { PageSection, Table } from '@cdnca/ui'
import { useNavigate } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import { dnsApi, ownDNSProviders, type DNSProvider } from '../../api/dns'
import { dnsHubApi, dnsHubRecordTypes, type DNSHubDomain, type DNSHubRecord, type DNSHubRecordType, type DNSHubRecordValue } from '../../api/dnsHub'
import { useSessionStore } from '../../auth/session'
import { DataState } from '../../components/DataState'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/dnsHub'
import { DnsHubBatchModal } from './DnsHubBatchModal'
import { DnsHubRecordModal, ManagedConfirm } from './DnsHubRecordModal'
import { dnsHubErrorKey, domainKey, managedUsage, newIdempotencyKey, providerCodeKey } from './dnsHubShared'
import './DnsHubPage.css'

const pageSize = 50

export default function DnsHubPage() {
  const { t } = useTranslation('dnsHub')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  if (!accessToken || !principal) return null
  // 用户端页面：只认租户作用域；平台副本账号（managed_by='platform'）由后端与 ownDNSProviders 双重排除。
  if (principal.scope_kind !== 'tenant' || !principal.permissions.includes('dns.read')) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  // 刷新域名清单与后端 hubWritePermissions 一致
  const canRefresh = principal.permissions.includes('dns.manage') || principal.permissions.includes('dns.records.manage')
  return <DnsHubContent key={`${principal.scope_id}:${principal.user_id}`} canManage={principal.permissions.includes('dns.manage')} canRefresh={canRefresh} />
}

function DnsHubContent({ canManage, canRefresh }: { canManage: boolean; canRefresh: boolean }) {
  const { t, i18n } = useTranslation('dnsHub')
  const { t: tp } = useTranslation('dnsProviders')
  const { message, modal } = App.useApp()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const token = () => useSessionStore.getState().accessToken ?? ''
  const [providerFilter, setProviderFilter] = useState<string>('')
  const [domainSearch, setDomainSearch] = useState('')
  const [domainQuery, setDomainQuery] = useState('')
  const [selected, setSelected] = useState<DNSHubDomain>()
  const [checked, setChecked] = useState<Map<string, DNSHubDomain>>(new Map())
  const [typeFilter, setTypeFilter] = useState<DNSHubRecordType | ''>('')
  const [recordSearch, setRecordSearch] = useState('')
  const [editing, setEditing] = useState<{ record?: DNSHubRecord } | null>(null)
  const [batchOpen, setBatchOpen] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  // 自动首次刷新：已发起过的账号（ref 去重、state 供渲染），请求本身失败时就地显示并可重试
  const autoRefreshStarted = useRef(new Set<string>())
  const [autoRefreshed, setAutoRefreshed] = useState<ReadonlySet<string>>(new Set())
  const [refreshError, setRefreshError] = useState<string>()

  const providers = useQuery({ queryKey: ['dns-hub', 'providers'], queryFn: () => dnsApi.list(token()).then((list) => ownDNSProviders(list.items)) })
  const providerByID = useMemo(() => new Map((providers.data ?? []).map((item) => [item.id, item])), [providers.data])

  const domains = useInfiniteQuery({
    queryKey: ['dns-hub', 'domains', providerFilter, domainQuery],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => dnsHubApi.domains(token(), {
      provider_id: providerFilter || undefined, q: domainQuery || undefined, cursor: pageParam, limit: pageSize,
    }),
    getNextPageParam: (last) => last.next_cursor || undefined,
    enabled: (providers.data?.length ?? 0) > 0,
  })
  const domainItems = useMemo(() => domains.data?.pages.flatMap((page) => page.items) ?? [], [domains.data])
  // 账号可选线路/权重来自域名列表的 accounts（契约 v1，每页都返回全部账号）
  const hubAccounts = useMemo(() => domains.data?.pages[0]?.accounts ?? [], [domains.data])
  const accountByID = useMemo(() => new Map(hubAccounts.map((item) => [item.provider_id, item])), [hubAccounts])
  // 已验证但从未拉取过域名清单（last_listed_at 为空）的账号
  const unlistedIDs = useMemo(() => canRefresh
    ? hubAccounts.filter((item) => item.status === 'verified' && !item.last_listed_at).map((item) => item.provider_id)
    : [], [canRefresh, hubAccounts])

  const records = useQuery({
    queryKey: ['dns-hub', 'records', selected?.provider_id, selected?.apex],
    queryFn: () => dnsHubApi.records(token(), selected!.provider_id, selected!.apex),
    enabled: Boolean(selected),
  })
  const visibleRecords = useMemo(() => {
    const keyword = recordSearch.trim().toLowerCase()
    return (records.data?.items ?? []).filter((item) => (!typeFilter || item.type === typeFilter) &&
      (!keyword || item.name.toLowerCase().includes(keyword) || item.value.toLowerCase().includes(keyword)))
  }, [records.data, recordSearch, typeFilter])

  const providerLabel = (type: string) => tp(`providers.${type}`, { defaultValue: tp('providers.unknown', { type }) })
  const selectedProvider = selected ? providerByID.get(selected.provider_id) : undefined
  const reloadRecords = () => queryClient.invalidateQueries({ queryKey: ['dns-hub', 'records', selected?.provider_id, selected?.apex] })

  const showError = (error: unknown) => {
    const key = dnsHubErrorKey(error)
    if (key === 'errors.conflict') void reloadRecords()
    message.error(t(key))
  }

  // auto：首次自动刷新的账号，结果不弹提示，由域名清单的 last_listed_at/list_error 呈现
  async function refreshDomains(auto?: string[]) {
    setRefreshing(true)
    try {
      if (auto) {
        await Promise.all(auto.map((id) => dnsHubApi.refresh(token(), id)))
        setRefreshError(undefined)
        await queryClient.invalidateQueries({ queryKey: ['dns-hub', 'domains'] })
        return
      }
      const result = await dnsHubApi.refresh(token(), providerFilter || undefined)
      setRefreshError(undefined)
      const failed = result.results.filter((item) => item.state === 'failed').length
      const throttled = result.results.find((item) => item.state === 'throttled')
      if (failed) message.warning(t('refresh.partial', { failed }))
      else if (throttled && result.results.every((item) => item.state === 'throttled' || item.state === 'skipped')) {
        message.info(t('refresh.throttled', { seconds: throttled.retry_after_seconds || 60 }))
      } else message.success(t('refresh.done'))
      await queryClient.invalidateQueries({ queryKey: ['dns-hub', 'domains'] })
    } catch (error) {
      if (auto) {
        if (!(error instanceof ApiError && error.status === 429)) setRefreshError(dnsHubErrorKey(error))
        await queryClient.invalidateQueries({ queryKey: ['dns-hub', 'domains'] })
      } else if (error instanceof ApiError && error.status === 429) message.info(t('refresh.throttled', { seconds: 60 }))
      else showError(error)
    } finally {
      setRefreshing(false)
    }
  }

  useEffect(() => {
    const pending = unlistedIDs.filter((id) => !autoRefreshStarted.current.has(id))
    if (!pending.length) return
    pending.forEach((id) => autoRefreshStarted.current.add(id))
    setAutoRefreshed((current) => new Set([...current, ...pending]))
    void refreshDomains(pending)
    // 只随账号清单变化触发；refreshDomains 每次渲染都是新函数
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unlistedIDs])

  // 首次刷新进行中沿用加载态；刷新失败（请求失败或账号 list_error）不显示空态而是就地重试
  const firstListing = refreshing || unlistedIDs.some((id) => !autoRefreshed.has(id))
  const failedAccount = hubAccounts.find((item) => item.list_error)
  const listFailure = refreshError ? t(refreshError)
    : failedAccount ? t('errors.listError', { reason: t(providerCodeKey(failedAccount.list_error)) }) : undefined

  async function saveRecord(input: DNSHubRecordValue, confirmManaged: boolean) {
    if (!selected) return
    const record = editing?.record
    const result = record
      ? await dnsHubApi.update(token(), selected.provider_id, selected.apex, record, input, confirmManaged, newIdempotencyKey('dns-hub-update'))
      : await dnsHubApi.create(token(), selected.provider_id, selected.apex, input, newIdempotencyKey('dns-hub-create'))
    if (result.state === 'uncertain') message.warning(t('result.uncertain'))
    else message.success(t(record ? 'result.updated' : 'result.created'))
    setEditing(null)
    await reloadRecords()
  }

  function confirmDelete(record: DNSHubRecord) {
    if (!selected) return
    const domain = selected
    let acknowledged = !record.managed
    const instance = modal.confirm({
      title: record.managed ? t('managed.confirmTitle') : t('deleteConfirm.title'),
      content: (
        <div className="dns-hub-confirm">
          <p>{t('deleteConfirm.body', { name: record.name, type: record.type, value: record.value })}</p>
          {record.managed ? (
            <ManagedConfirm usage={managedUsage(t, record.managed)} onChange={(value) => {
              acknowledged = value
              instance.update({ okButtonProps: { danger: true, disabled: !value } })
            }} />
          ) : null}
        </div>
      ),
      okText: t('deleteConfirm.ok'),
      cancelText: t('deleteConfirm.cancel'),
      okButtonProps: { danger: true, disabled: !acknowledged },
      onOk: async () => {
        try {
          const result = await dnsHubApi.remove(token(), domain.provider_id, domain.apex, record, Boolean(record.managed), newIdempotencyKey('dns-hub-delete'))
          if (result.state === 'uncertain') message.warning(t('result.uncertain'))
          else message.success(t('result.deleted'))
          await reloadRecords()
        } catch (error) {
          showError(error)
        }
      },
    })
  }

  function toggleChecked(domain: DNSHubDomain, value: boolean) {
    setChecked((current) => {
      const next = new Map(current)
      if (value) next.set(domainKey(domain), domain)
      else next.delete(domainKey(domain))
      return next
    })
  }

  const columns: TableColumnsType<DNSHubRecord> = [
    { title: t('columns.name'), dataIndex: 'name', width: 160, render: (value: string) => <span className="dns-hub-mono">{value}</span> },
    { title: t('columns.type'), dataIndex: 'type', width: 80, render: (value: string) => <Tag className="dns-hub-type-tag">{value}</Tag> },
    { title: t('columns.line'), dataIndex: 'line', width: 72 },
    { title: t('columns.value'), dataIndex: 'value', ellipsis: { showTitle: false }, render: (value: string) => (
      <Tooltip title={value} placement="topLeft"><span className="dns-hub-mono">{value}</span></Tooltip>
    ) },
    { title: t('columns.ttl'), dataIndex: 'ttl', width: 72, align: 'right' },
    { title: t('columns.managed'), key: 'managed', width: 128, render: (_value, record) => record.managed ? (
      <Tooltip title={managedUsage(t, record.managed)}>
        <Tag color="blue" icon={<ShieldCheck size={12} aria-hidden="true" />} className="dns-hub-managed-tag">{t('managed.tag')}</Tag>
      </Tooltip>
    ) : null },
    ...(canManage ? [{
      title: t('columns.actions'), key: 'actions', width: 156, fixed: 'right' as const,
      render: (_value: unknown, record: DNSHubRecord) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<Pencil size={14} aria-hidden="true" />} onClick={() => setEditing({ record })}
            aria-label={`${t('records.edit')} ${record.name} ${record.type}`}>{t('records.edit')}</Button>
          <Button type="link" size="small" danger icon={<Trash2 size={14} aria-hidden="true" />} onClick={() => confirmDelete(record)}
            aria-label={`${t('records.delete')} ${record.name} ${record.type}`}>{t('records.delete')}</Button>
        </Space>
      ),
    }] : []),
  ]

  if (providers.isPending) return <PageSection className="dns-hub-page"><DataState status="loading" /></PageSection>
  if (providers.isError) return <PageSection className="dns-hub-page"><DataState status="error" message={t(dnsHubErrorKey(providers.error))} onRetry={() => void providers.refetch()} /></PageSection>

  const header = (
    <header className="dns-hub-header">
      <div>
        <Typography.Title level={4}>{t('title')}</Typography.Title>
        <Typography.Paragraph>{t('description')}</Typography.Paragraph>
      </div>
      {providers.data.length ? (
        <Space wrap>
          {canManage ? (
            <Button icon={<Layers size={16} aria-hidden="true" />} disabled={checked.size === 0} onClick={() => setBatchOpen(true)}>
              {t('batch.open')}{checked.size ? ` (${checked.size})` : ''}
            </Button>
          ) : null}
          {/* Refresh needs dns.manage or dns.records.manage (hubWritePermissions); a read-only member would be refused. */}
          {canRefresh ? (
            <Button icon={<RefreshCw size={16} aria-hidden="true" />} loading={refreshing} onClick={() => void refreshDomains()}>{t('refresh.action')}</Button>
          ) : null}
        </Space>
      ) : null}
    </header>
  )

  if (!providers.data.length) {
    return (
      <PageSection className="dns-hub-page">
        {header}
        <Empty className="dns-hub-empty" description={<><div>{t('accounts.empty')}</div><div className="dns-hub-muted">{t('accounts.emptyHint')}</div></>}>
          <Button type="primary" onClick={() => navigate('/site/list', { state: { siteSubnav: 'dnsApi' } })}>{t('accounts.goAdd')}</Button>
        </Empty>
      </PageSection>
    )
  }

  return (
    <PageSection className="dns-hub-page">
      {header}
      {!canManage ? <Alert className="dns-hub-alert" type="info" showIcon message={t('errors.readonly')} /> : null}
      <div className="dns-hub-layout">
        <nav className="dns-hub-accounts" aria-label={t('accounts.title')}>
          <div className="dns-hub-pane-title">{t('accounts.title')}</div>
          <ul>
            <li><AccountButton active={!providerFilter} onClick={() => setProviderFilter('')} label={t('accounts.all')} /></li>
            {providers.data.map((item: DNSProvider) => (
              <li key={item.id}>
                <AccountButton active={providerFilter === item.id} onClick={() => setProviderFilter(item.id)} label={item.name}
                  hint={providerLabel(item.provider_type)}
                  status={item.status === 'disabled' ? t('accounts.disabled') : item.status === 'unverified' ? t('accounts.unverified') : undefined} />
              </li>
            ))}
          </ul>
        </nav>

        <section className="dns-hub-domains" aria-label={t('domains.title')}>
          <Input allowClear prefix={<Search size={14} aria-hidden="true" />} placeholder={t('domains.search')} aria-label={t('domains.search')}
            value={domainSearch} onChange={(event) => { setDomainSearch(event.target.value); if (!event.target.value) setDomainQuery('') }}
            onPressEnter={() => setDomainQuery(domainSearch.trim().toLowerCase())} />
          {canManage && checked.size ? (
            <div className="dns-hub-selection">
              <span>{t('domains.selected', { count: checked.size })}</span>
              <Button type="link" size="small" onClick={() => setChecked(new Map())}>{t('domains.clearSelection')}</Button>
            </div>
          ) : null}
          {domainItems.length > 0 && listFailure && !refreshing ? (
            <DataState status="error" message={listFailure} onRetry={canRefresh ? () => void refreshDomains() : undefined} />
          ) : null}
          {domains.isPending ? <DataState status="loading" /> : domains.isError ? (
            <DataState status="error" message={t(dnsHubErrorKey(domains.error))} onRetry={() => void domains.refetch()} />
          ) : !domainItems.length ? (
            firstListing ? <DataState status="loading" />
              : listFailure ? <DataState status="error" message={listFailure} onRetry={canRefresh ? () => void refreshDomains() : undefined} />
                : <DataState status="empty" message={t(domainQuery ? 'domains.emptyFiltered' : 'domains.empty')} />
          ) : (
            <ul className="dns-hub-domain-list">
              {domainItems.map((domain) => {
                const key = domainKey(domain)
                const active = selected !== undefined && domainKey(selected) === key
                return (
                  <li key={key} className={active ? 'is-active' : undefined}>
                    {canManage ? (
                      <Checkbox checked={checked.has(key)} onChange={(event) => toggleChecked(domain, event.target.checked)}
                        aria-label={domain.apex} />
                    ) : null}
                    <button type="button" className="dns-hub-domain" aria-current={active ? 'true' : undefined}
                      onClick={() => { setSelected(domain); setTypeFilter(''); setRecordSearch('') }}>
                      <span className="dns-hub-domain-apex">{domain.apex}</span>
                      <span className="dns-hub-domain-meta">
                        {domain.provider_name} · {domain.record_count === null ? t('domains.recordsUnknown') : t('domains.records', { count: domain.record_count })}
                      </span>
                      {domain.list_error ? (
                        <span className="dns-hub-domain-error">{t('errors.listError', { reason: t(providerCodeKey(domain.list_error)) })}</span>
                      ) : (
                        <span className="dns-hub-domain-meta">
                          {domain.last_listed_at ? t('domains.listedAt', { time: formatDateTime(domain.last_listed_at, i18n.language as never) }) : t('domains.neverListed')}
                        </span>
                      )}
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
          {domains.hasNextPage ? (
            <Button block loading={domains.isFetchingNextPage} onClick={() => void domains.fetchNextPage()}>{t('domains.loadMore')}</Button>
          ) : null}
        </section>

        <section className="dns-hub-records" aria-label={t('records.title')}>
          {!selected ? <DataState status="empty" className="dns-hub-pick" message={t('records.pickDomain')} /> : (
            <>
              <div className="dns-hub-records-head">
                <div>
                  <Typography.Title level={5}>{selected.apex}</Typography.Title>
                  <span className="dns-hub-muted">{t('records.provider', { provider: selected.provider_name, type: providerLabel(selected.provider_type) })}</span>
                </div>
                <Space wrap>
                  <Button icon={<RotateCw size={14} aria-hidden="true" />} onClick={() => void reloadRecords()} loading={records.isFetching}>{t('records.reload')}</Button>
                  {canManage ? (
                    <Button type="primary" icon={<Plus size={14} aria-hidden="true" />} disabled={!records.data}
                      onClick={() => setEditing({})}>{t('records.add')}</Button>
                  ) : null}
                </Space>
              </div>
              <Space wrap className="dns-hub-records-toolbar">
                <Select value={typeFilter} onChange={setTypeFilter} aria-label={t('columns.type')} style={{ width: 120 }}
                  options={[{ value: '', label: t('records.allTypes') }, ...dnsHubRecordTypes.map((type) => ({ value: type, label: type }))]} />
                <Input allowClear prefix={<Search size={14} aria-hidden="true" />} placeholder={t('records.search')} aria-label={t('records.search')}
                  value={recordSearch} onChange={(event) => setRecordSearch(event.target.value)} style={{ width: 240 }} />
              </Space>
              {records.isError ? (
                <DataState status="error" message={t(dnsHubErrorKey(records.error))} onRetry={() => void records.refetch()} />
              ) : (
                <Table<DNSHubRecord> rowKey="record_ref" size="middle" columns={columns} dataSource={visibleRecords} loading={records.isPending}
                  pagination={visibleRecords.length > 50 ? { pageSize: 50, showSizeChanger: false } : false} scroll={{ x: 780 }}
                  locale={{ emptyText: t(records.data?.items.length ? 'records.emptyFiltered' : 'records.empty') }} />
              )}
              {records.data?.skipped ? <p className="dns-hub-muted dns-hub-note">{t('records.skipped', { count: records.data.skipped })}</p> : null}
              <p className="dns-hub-muted dns-hub-note">{t('records.typesNote')}</p>
            </>
          )}
        </section>
      </div>

      {editing && selected && records.data ? (
        <DnsHubRecordModal open record={editing.record} providerType={selectedProvider?.provider_type ?? selected.provider_type}
          lines={accountByID.get(selected.provider_id)?.supported_lines ?? []}
          supportsWeight={accountByID.get(selected.provider_id)?.supports_weight ?? false} onCancel={() => setEditing(null)} onSubmit={saveRecord} onError={showError} />
      ) : null}
      {batchOpen ? (
        <DnsHubBatchModal open targets={[...checked.values()]} onClose={(changed) => {
          setBatchOpen(false)
          if (changed) void queryClient.invalidateQueries({ queryKey: ['dns-hub'] })
        }} />
      ) : null}
    </PageSection>
  )
}

function AccountButton({ active, label, hint, status, onClick }: { active: boolean; label: string; hint?: string; status?: string; onClick: () => void }) {
  return (
    <button type="button" className={`dns-hub-account${active ? ' is-active' : ''}`} aria-pressed={active} onClick={onClick}>
      <span className="dns-hub-account-name">{label}</span>
      {hint ? <span className="dns-hub-account-hint">{hint}</span> : null}
      {status ? <Tag className="dns-hub-account-status">{status}</Tag> : null}
    </button>
  )
}
