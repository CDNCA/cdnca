import { useMemo, useState } from 'react'
import { Button, Input, Pagination, Select, Space, Table, Tag, type TableColumnsType } from 'antd'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { FeedbackWhen, IdOrNameInput, useFeedbackMessage, useLiveApply } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import { dnsApi, ownDNSProviders } from '../api/dns'
import { siteDefaultsApi } from '../api/siteDefaults'
import { sitesApi, type SiteAutoDNSStatus, type SiteListItem } from '../api/sites'
import { useSessionStore } from '../auth/session'
import '../i18n/siteListTabs'
import { siteSearch } from './idNameSources'

// 网站列表 > 解析检测（用户端）：全站域名一张表，不再要求先勾选网站。
// 解析状态取「DNS API 自动添加记录」任务：写入服务商且回查一致即正常，
// 全网传播检测是非阻塞诊断，在「详细检测」（/site/:id/dns-reconcile）里看。

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const siteIDList = (text: string) => text.split(/[\s,，]+/).filter(Boolean)
const allUUIDs = (text: string) => { const ids = siteIDList(text); return ids.length > 0 && ids.every((id) => uuidPattern.test(id)) }

type Row = { key: string; index: number; site: SiteListItem; domain: string; code?: string }
type Filter = 'all' | 'failed' | 'unconfigured' | 'pending'

// DC-UX-DETAIL-01（审测卡 12）：详细检测带着被点的域名与它的解析事实进入，返回时恢复筛选和页码。
export interface SiteDnsCheckContext {
  siteID: string
  siteDisplayID: string
  domain: string
  cname: string
  provider: { id: string; name: string } | null
  task: { state: 'pending' | 'done' | 'failed'; code?: string; attempts: number; updatedAt: string } | null
  resolve: 'done' | 'failed' | 'pending' | 'none'
  back: { filter: Filter; page: number; limit: number; search: { domain: string; siteIds: string } }
}

function resolveState(site: SiteListItem, code?: string): 'done' | 'failed' | 'pending' | 'none' {
  const task = site.auto_dns
  if (!task) return 'none'
  if (task.state === 'pending') return 'pending'
  return code || task.state === 'failed' ? 'failed' : 'done'
}

export default function SiteDnsCheckPanel({ onConfigureDnsApi, restore }: {
  onConfigureDnsApi: () => void
  restore?: SiteDnsCheckContext['back']
}) {
  const { t } = useTranslation('siteListTabs')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canSync = Boolean(principal?.permissions.includes('sites.manage') && principal.permissions.includes('dns.manage'))
  // 同步只接受网站所属用户的 DNS 账号；平台管理员的账号列表是平台自己的，不给选，按网站原账号重试。
  const tenantScope = principal?.scope_kind === 'tenant'
  const [page, setPage] = useState(restore?.page ?? 1)
  const [limit, setLimit] = useState(restore?.limit ?? 10)
  const [filter, setFilter] = useState<Filter>(restore?.filter ?? 'all')
  const [domainDraft, setDomainDraft] = useState(restore?.search.domain ?? '')
  const [siteIdDraft, setSiteIdDraft] = useState(restore?.search.siteIds ?? '')
  const [search, setSearch] = useState(restore?.search ?? { domain: '', siteIds: '' })
  const [selected, setSelected] = useState<string[]>([])
  const [provider, setProvider] = useState<string | undefined>()
  const [syncing, setSyncing] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [messageApi, messageContext] = useFeedbackMessage()

  // 域名/网站ID 边输入边生效（400ms 防抖、输入法组字中不生效）；
  // 网站ID 也可输入域名或展示 ID，从联想中选中按网站 UUID 过滤。
  const draftSearch = { domain: domainDraft.trim(), siteIds: siteIdDraft.trim() }
  const applySearch = (next: typeof draftSearch) => { setPage(1); setSearch(next) }
  useLiveApply(draftSearch, search, applySearch)
  const submitSearch = () => {
    if (JSON.stringify(draftSearch) !== JSON.stringify(search)) applySearch(draftSearch)
    else void query.refetch()
  }
  const accessToken = useSessionStore((state) => state.accessToken)
  const siteOptions = useMemo(() => siteSearch(accessToken ?? '', 'id'), [accessToken])
  const token = (permission: string) => {
    const state = useSessionStore.getState()
    return state.accessToken && state.principal?.permissions.includes(permission) ? state.accessToken : null
  }
  const query = useQuery({
    queryKey: ['site-dns-check', principal?.scope_id, sessionEpoch, page, limit, search],
    queryFn: async () => {
      const accessToken = token('sites.read')
      if (!accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      // 网站ID 全是 UUID 时按 site_ids，否则按 site（域名子串或展示 ID，与网站列表同一参数）。
      const byID = allUUIDs(search.siteIds)
      return sitesApi.list(accessToken, { page, limit, domain: search.domain || undefined,
        site_ids: byID ? siteIDList(search.siteIds).join(',').toLowerCase() : undefined, site: !byID && search.siteIds ? search.siteIds : undefined })
    },
  })
  const providers = useQuery({
    queryKey: ['site-dns-check-providers', principal?.scope_id, sessionEpoch],
    enabled: canSync && tenantScope,
    queryFn: async () => {
      const accessToken = token('dns.read')
      if (!accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      return dnsApi.list(accessToken)
    },
  })

  const rows = useMemo<Row[]>(() => {
    const result: Row[] = []
    for (const site of query.data?.items ?? []) {
      const domains = site.domains?.length ? site.domains : [site.domain]
      for (const domain of domains) {
        const code = site.auto_dns?.results.find((item) => item.domain === domain)?.code
        result.push({ key: `${site.id}:${domain}`, index: result.length + 1, site, domain, code })
      }
    }
    return result
  }, [query.data])
  const counts = {
    all: rows.length,
    failed: rows.filter((row) => resolveState(row.site, row.code) === 'failed').length,
    unconfigured: rows.filter((row) => !row.site.auto_dns).length,
    pending: rows.filter((row) => resolveState(row.site, row.code) === 'pending').length,
  }
  const visible = rows.filter((row) => filter === 'all' ||
    (filter === 'unconfigured' ? !row.site.auto_dns : resolveState(row.site, row.code) === filter))

  const failureText = (task: SiteAutoDNSStatus | null | undefined, code?: string) => {
    const value = code ?? task?.failure_code ?? ''
    const base = value.replace(/^retries_exhausted:/u, '')
    return t(`dnsCheck.failure.${base}`, { defaultValue: t('dnsCheck.failure.other', { code: value }) })
  }

  // 同步解析：按网站提交（同一网站多个域名只提交一次）；重复提交只是再跑一轮，结果幂等。
  const sync = async () => {
    const accessToken = token('dns.manage')
    if (!accessToken) return
    const siteIDs = [...new Set(rows.filter((row) => selected.includes(row.key)).map((row) => row.site.id))]
    setSyncing(true)
    setNotice(null)
    let failed = 0
    for (const siteID of siteIDs) {
      try {
        await siteDefaultsApi.syncAutoDNS(accessToken, siteID, provider)
      } catch {
        failed++
      }
    }
    setSyncing(false)
    setSelected([])
    if (failed) setNotice(t('dnsCheck.syncFailed', { count: failed }))
    else void messageApi.success(t('dnsCheck.synced', { count: siteIDs.length }))
    await queryClient.invalidateQueries({ queryKey: ['site-dns-check'] })
  }

  const columns: TableColumnsType<Row> = [
    { title: t('dnsCheck.columns.id'), dataIndex: 'index', width: 70 },
    { title: t('dnsCheck.columns.siteId'), key: 'site', width: 90, render: (_, row) => row.site.display_id },
    { title: t('dnsCheck.columns.domain'), dataIndex: 'domain', ellipsis: true },
    { title: t('dnsCheck.columns.cname'), key: 'cname', ellipsis: true, render: (_, row) => row.site.cname || '-' },
    {
      title: t('dnsCheck.columns.resolve'), key: 'resolve', width: 130,
      render: (_, row) => {
        const state = resolveState(row.site, row.code)
        const color = state === 'done' ? 'success' : state === 'failed' ? 'error' : state === 'pending' ? 'processing' : 'default'
        return <Tag color={color} title={state === 'failed' ? failureText(row.site.auto_dns, row.code) : undefined}>{t(`dnsCheck.resolve.${state}`)}</Tag>
      },
    },
    {
      title: t('dnsCheck.columns.dnsApi'), key: 'dnsApi', width: 150, ellipsis: true,
      render: (_, row) => row.site.auto_dns ? row.site.auto_dns.provider_name : <Tag color="warning">{t('dnsCheck.dnsApi.unconfigured')}</Tag>,
    },
    {
      title: t('dnsCheck.columns.task'), key: 'task', width: 110,
      render: (_, row) => <Tag>{t(`dnsCheck.task.${row.site.auto_dns?.state ?? 'none'}`)}</Tag>,
    },
    {
      title: t('dnsCheck.columns.actions'), key: 'actions', width: 100,
      // 详细检测路由只给租户（RoleRoute user），平台管理员不显示，避免点进 404。
      render: (_, row) => principal?.scope_kind === 'tenant' && principal.permissions.includes('dns.read') ? (
        <Button type="link" size="small" onClick={() => {
          const task = row.site.auto_dns
          const context: SiteDnsCheckContext = {
            siteID: row.site.id, siteDisplayID: String(row.site.display_id), domain: row.domain, cname: row.site.cname,
            provider: task ? { id: task.provider_id, name: task.provider_name } : null,
            task: task ? { state: task.state, code: row.code ?? task.failure_code ?? undefined, attempts: task.attempts,
              updatedAt: task.updated_at } : null,
            resolve: resolveState(row.site, row.code), back: { filter, page, limit, search },
          }
          navigate(`/site/${row.site.id}/dns-reconcile`, { state: { dnsCheck: context } })
        }}>{t('dnsCheck.detail')}</Button>
      ) : null,
    },
  ]

  const filters: Array<{ key: Filter; label: string }> = [
    { key: 'all', label: t('dnsCheck.filters.all') },
    { key: 'failed', label: t('dnsCheck.filters.failed') },
    { key: 'unconfigured', label: t('dnsCheck.filters.unconfigured') },
    { key: 'pending', label: t('dnsCheck.filters.pending') },
  ]

  return (
    <section className="site-dns-check-panel" aria-label={t('dnsCheck.columns.resolve')}>
      {messageContext}
      <div className="site-dns-check-toolbar">
        {canSync ? (
          <Space size={8}>
            <Button type="primary" loading={syncing} disabled={selected.length === 0} onClick={() => void sync()}>{t('dnsCheck.sync')}</Button>
            {tenantScope ? <Select allowClear className="site-dns-check-provider" aria-label={t('dnsCheck.columns.dnsApi')}
              placeholder={t('dnsCheck.columns.dnsApi')} value={provider} onChange={setProvider} loading={providers.isFetching}
              options={ownDNSProviders(providers.data?.items ?? []).filter((item) => item.status === 'verified').map((item) => ({ value: item.id, label: item.name }))} /> : null}
            {selected.length === 0 ? <span className="site-dns-check-hint">{t('dnsCheck.syncHint')}</span> : null}
          </Space>
        ) : null}
        <Space.Compact className="site-dns-check-search">
          <Button tabIndex={-1} className="site-dns-check-addon">{t('dnsCheck.search.domain')}</Button>
          <Input aria-label={t('dnsCheck.search.domain')} value={domainDraft} placeholder={t('dnsCheck.search.domainPlaceholder')}
            onChange={(event) => setDomainDraft(event.target.value)} onPressEnter={submitSearch} />
        </Space.Compact>
        <Space.Compact className="site-dns-check-search">
          <Button tabIndex={-1} className="site-dns-check-addon">{t('dnsCheck.search.siteId')}</Button>
          <IdOrNameInput aria-label={t('dnsCheck.search.siteId')} value={siteIdDraft} placeholder={t('dnsCheck.search.siteIdPlaceholder')}
            freeText isId={allUUIDs} search={siteOptions} onChange={setSiteIdDraft} onPressEnter={submitSearch} />
        </Space.Compact>
        <Button type="text" onClick={() => { setDomainDraft(''); setSiteIdDraft(''); setPage(1); setSearch({ domain: '', siteIds: '' }) }}>
          {t('dnsCheck.search.clear')}
        </Button>
      </div>
      <div className="site-dns-check-stats" role="group" aria-label={t('dnsCheck.stats')}>
        {filters.map((item) => (
          <button key={item.key} type="button" aria-pressed={filter === item.key} className={filter === item.key ? 'is-active' : undefined}
            onClick={() => setFilter(item.key)}>
            {item.label} <strong>{counts[item.key]}</strong>
          </button>
        ))}
        {counts.unconfigured > 0 && principal?.permissions.includes('dns.read') ? (
          <Button type="link" size="small" onClick={onConfigureDnsApi}>{t('dnsCheck.filters.configure')}</Button>
        ) : null}
        <span className="site-dns-check-scope">{t('dnsCheck.stats')}</span>
      </div>
      {notice ? <FeedbackWhen title={notice} onClose={() => setNotice(null)} /> : null}
      {query.error ? <FeedbackWhen title={t('defaults.errors.loadFailed')}
        action={<Button size="small" onClick={() => void query.refetch()}>{t('defaults.actions.retry')}</Button>} /> : null}
      <Table rowKey="key" size="small" columns={columns} dataSource={visible} pagination={false} scroll={{ x: 900 }}
        loading={query.isPending || query.isFetching} locale={{ emptyText: query.isPending ? ' ' : t('dnsCheck.empty') }}
        rowSelection={canSync ? { selectedRowKeys: selected, onChange: (keys) => setSelected(keys.map(String)) } : undefined} />
      <div className="identity-pagination">
        <Pagination current={page} pageSize={limit} total={query.data?.total ?? 0} showSizeChanger pageSizeOptions={[10, 20, 50]}
          showTotal={(count) => t('dnsCheck.total', { count })}
          onChange={(next, size) => { setPage(size === limit ? next : 1); setLimit(size) }} />
      </div>
    </section>
  )
}
