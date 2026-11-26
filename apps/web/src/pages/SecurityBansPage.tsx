import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Select, Space, Tag, Typography, type TableColumnsType } from 'antd'
import { Plus, RefreshCw, Unlock } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  securityBansApi,
  type SecurityBan,
  type SecurityBanAudience,
  type SecurityBanCreateInput,
  type SecurityBanDelivery,
  type SecurityBanDeliveryState,
  type SecurityBanState,
} from '../api/securityBans'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/securityBans'
import { cacheWriteIdentity, cacheWriteOwner, pendingCacheWriteKey, rememberCacheWrite, settleCacheWrite } from './cacheWriteJournal'
import { writeOutcomeUnknown } from './site-edit/writeOutcome'
import { FeedbackWhen, IdOrNameInput, PageSection, liveFilterDelay, useLiveApply, Table } from '@cdnca/ui'
import { isIPOrCIDR } from '../api/addressRules'
import { FilterField, filterFieldProps, useFieldFocus } from '../components/FilterFieldError'
import { siteSearch as siteNameSearch } from './idNameSources'
import { filterParam, useFilterUrl } from './filterUrl'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const stateColors: Record<SecurityBanState, string> = { active: 'red', released: 'green', expired: 'default' }
// an active ban of a site served by market leaves (or by no node) shows how it is enforced.
const deliveryColors: Record<SecurityBanDeliveryState, string> = {
  effective: 'red', delivering: 'processing', pending: 'default', no_nodes: 'warning', unsupported: 'warning',
  failed: 'error', refused: 'error',
}
// Durations offered for a manual ban (the server allows 1 minute to 30 days).
const durations = [{ key: 'm10', seconds: 600 }, { key: 'h1', seconds: 3600 }, { key: 'd1', seconds: 86400 },
  { key: 'd7', seconds: 7 * 86400 }, { key: 'd30', seconds: 30 * 86400 }] as const
// At most this many bans per submission (one request each).
const maxBatch = 200

// fix-cidrban: a network (x/24, x/48) is one ban; the server checks the rest
// (libs/edgeconfig/securityban CanonicalClient). The widest: IPv4 /8, IPv6 /32.
const minNetworkBits = { v4: 8, v6: 32 }

function isNetwork(client: string): boolean {
  return client.includes('/')
}

// tooWide: a network wider than the server allows (or with a bad length).
function tooWide(client: string): boolean {
  const [address, bits, extra] = client.split('/')
  if (bits === undefined) return false
  const ipv6 = address.includes(':')
  const length = /^\d{1,3}$/.test(bits) ? Number(bits) : -1
  return extra !== undefined || length < (ipv6 ? minNetworkBits.v6 : minNetworkBits.v4) || length > (ipv6 ? 128 : 32)
}

// parseClients splits the textarea into distinct addresses and networks.
function parseClients(text: string): { clients: string[]; network: boolean; tooWide: boolean } {
  const items = [...new Set(text.split(/[\s,，;；]+/).map((item) => item.trim()).filter(Boolean))]
  return { clients: items, network: items.some(isNetwork), tooWide: items.some(tooWide) }
}

interface CreateFailure { ip: string; site: string; reason: string }
interface ResultMessage { type: 'success' | 'error'; text: string; failures?: CreateFailure[] }

interface Filters {
  site: string
  ip: string
  state: '' | SecurityBanState
}

const ipFieldID = 'security-bans-filter-ip'
const banStates = ['active', 'released', 'expired'] as const
const pageSizes = [20, 50, 100]
// 新建封禁的网站搜索停顿后才查（清空立即生效）。
const siteSearchDelay = 250

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.failed'
  switch (error.code) {
    case 'validation_error': return 'errors.invalid'
    case 'site_not_found': return 'errors.siteNotFound'
    case 'security_ban_exists': return 'errors.exists'
    case 'security_ban_not_active': return 'errors.notActive'
    case 'security_ban_limit': return 'errors.limit'
  }
  return error.status === 403 ? 'errors.permission' : 'errors.failed'
}

export default function SecurityBansPage() {
  const { t, i18n } = useTranslation('securityBans')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const audience: SecurityBanAudience = principal?.scope_kind === 'platform' ? 'admin' : 'tenant'
  const canManage = principal?.permissions.includes('security_policies.manage') ||
    principal?.permissions.includes('platform.admin') || false
  // 已生效的网站、IP、状态、页码与每页条数写进 URL（默认值不写），刷新或打开链接时读回；
  // 链接里的网站不是 UUID、状态或页码不认识时用默认值；IP 不合法时放进输入框标错，不生效。
  const [searchParams] = useSearchParams()
  const [linked] = useState(() => {
    const site = filterParam(searchParams, 'site_id').toLowerCase()
    const ip = filterParam(searchParams, 'client_ip')
    const state = filterParam(searchParams, 'state')
    const pageNumber = Number(filterParam(searchParams, 'page'))
    const limit = Number(filterParam(searchParams, 'limit'))
    const filters: Filters = {
      site: uuidPattern.test(site) ? site : '', ip,
      state: state === 'all' ? '' : (banStates as readonly string[]).includes(state) ? state as SecurityBanState : 'active',
    }
    const valid = ip === '' || isIPOrCIDR(ip, minNetworkBits)
    return {
      draft: filters, applied: valid ? filters : { ...filters, ip: '' },
      page: valid && Number.isSafeInteger(pageNumber) && pageNumber > 1 ? pageNumber : 1,
      pageSize: pageSizes.includes(limit) ? limit : 20,
    }
  })
  const [draft, setDraft] = useState<Filters>(linked.draft)
  const [applied, setApplied] = useState<Filters>(linked.applied)
  const [page, setPage] = useState(linked.page)
  const [pageSize, setPageSize] = useState(linked.pageSize)
  useFilterUrl({
    site_id: applied.site, client_ip: applied.ip, state: applied.state === 'active' ? undefined : applied.state || 'all',
    page: page > 1 ? page : undefined, limit: pageSize !== 20 ? pageSize : undefined,
  })
  const [creating, setCreating] = useState(false)
  const [releasing, setReleasing] = useState<SecurityBan | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<ResultMessage | null>(null)
  // The result of a submission that banned nothing, shown inside the dialog.
  const [createError, setCreateError] = useState<ResultMessage | null>(null)
  const [form] = Form.useForm<{ site_ids: string[]; client_ips: string; seconds: number; reason: string }>()
  const [siteTyping, setSiteTyping] = useState('')
  const [siteSearch, setSiteSearch] = useState('')
  useEffect(() => {
    const term = siteTyping.trim()
    if (!term) { setSiteSearch(''); return undefined }
    const timer = window.setTimeout(() => setSiteSearch(term), siteSearchDelay)
    return () => window.clearTimeout(timer)
  }, [siteTyping])
  const sites = useQuery({
    queryKey: ['security-ban-sites', audience, principal?.scope_id, siteSearch],
    enabled: creating && Boolean(accessToken),
    queryFn: () => sitesApi.list(accessToken ?? '', { page: 1, limit: 100, ...(siteSearch ? { domain: siteSearch } : {}) }),
  })
  const siteItems = sites.data?.items ?? []
  const onlySite = !siteSearch && sites.data?.total === 1 ? siteItems[0]?.id : undefined
  // A customer with a single site gets it preselected.
  useEffect(() => {
    if (onlySite && (form.getFieldValue('site_ids') ?? []).length === 0) form.setFieldValue('site_ids', [onlySite])
  }, [onlySite, form])
  const queryKey = ['security-bans', audience, principal?.scope_id, applied, page, pageSize] as const
  const query = useQuery({
    queryKey,
    queryFn: () => securityBansApi.list(accessToken ?? '', audience, {
      page, limit: pageSize, site_id: applied.site || undefined, client_ip: applied.ip || undefined,
      state: applied.state || undefined,
    }),
    enabled: Boolean(accessToken && principal),
    retry: false,
    refetchOnWindowFocus: false,
  })
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['security-bans'] })
  // 筛选边输入边生效；网站也可输入域名从联想中选中（接口只认网站 UUID，
  // 未选中的域名只联想不过滤）。查询按钮：无未生效改动时刷新。
  const applyFilters = (next: Filters) => { setApplied(next); setPage(1) }
  // 客户端 IP 按服务端同一规则（地址或网段，IPv4 最大 /8、IPv6 最大 /32）先校验，
  // 错误挂在 IP 输入框上；服务端仍拒绝（validation_error，如保留地址段）时同样记在该字段，并回到上次成功的条件与结果。
  const siteValid = draft.site === '' || uuidPattern.test(draft.site)
  const [refusedIP, setRefusedIP] = useState<string | null>(null)
  const ipValid = (draft.ip === '' || isIPOrCIDR(draft.ip, minNetworkBits)) && draft.ip !== refusedIP
  const [ipErrorShown, setIPErrorShown] = useState(false)
  const focusField = useFieldFocus()
  // 边输入边校验：停下与自动生效同样的时长后才标错，输入中途不闪错误。
  useEffect(() => {
    if (ipValid) { setIPErrorShown(false); return undefined }
    const timer = window.setTimeout(() => setIPErrorShown(true), liveFilterDelay)
    return () => window.clearTimeout(timer)
  }, [draft.ip, ipValid])
  const ipError = !ipValid && (ipErrorShown || draft.ip === refusedIP) ? t('filters.invalidIp') : null
  useLiveApply(draft, applied, applyFilters, { valid: siteValid && ipValid })
  const search = () => {
    if (!ipValid) { setIPErrorShown(true); focusField(ipFieldID); return }
    if (JSON.stringify(draft) !== JSON.stringify(applied)) applyFilters(draft)
    else void query.refetch()
  }
  const lastGood = useRef({ filters: applied, page })
  useEffect(() => {
    if (query.isSuccess) lastGood.current = { filters: applied, page }
  }, [query.isSuccess, applied, page])
  const ipRefused = query.error instanceof ApiError && query.error.code === 'validation_error' && applied.ip !== '' && applied.ip !== lastGood.current.filters.ip
  useEffect(() => {
    if (!ipRefused) return
    setRefusedIP(applied.ip)
    setApplied(lastGood.current.filters)
    setPage(lastGood.current.page)
  }, [ipRefused, applied.ip])
  const siteOptions = useMemo(() => siteNameSearch(accessToken ?? '', 'id'), [accessToken])
  const marketSites = (query.data?.items ?? []).some((item) => (item.delivery?.leaves ?? 0) > 0)
  const deliveryReason = (reason: string) => (i18n.exists(`delivery.reasons.${reason}`, { ns: 'securityBans' })
    ? t(`delivery.reasons.${reason}`) : t('delivery.reasons.unknown', { code: reason }))
  const deliveryCell = (value: SecurityBanDelivery) => (
    <Space direction="vertical" size={2}>
      <Tag color={deliveryColors[value.state]}>{t(`delivery.${value.state}`)}</Tag>
      {value.reason ? <Typography.Text type="secondary">{deliveryReason(value.reason)}</Typography.Text> : null}
      {value.leaves > 1 ? <Typography.Text type="secondary">{t('delivery.leaves', { effective: value.effective, leaves: value.leaves })}</Typography.Text> : null}
      {value.own_nodes > 0 ? <Typography.Text type="secondary">{t('delivery.ownNodes', { count: value.own_nodes })}</Typography.Text> : null}
    </Space>
  )

  // One request per (site, address); the results are summed up, every
  // failure with its reason.
  const submitCreate = async () => {
    // Invalid input stays in the form with its field errors; the rejection is handled here.
    // 校验不过时滚到并聚焦第一个出错的字段。
    const values = await form.validateFields().catch((error: { errorFields?: Array<{ name: (string | number)[] }> }) => {
      const first = error.errorFields?.[0]?.name
      if (first) form.scrollToField(first, { block: 'center', focus: true })
      return null
    })
    if (!values) return
    const { clients } = parseClients(values.client_ips)
    const domains = new Map(siteItems.map((item) => [item.id, item.domain]))
    let created = 0
    const failures: CreateFailure[] = []
    const journalOwner = cacheWriteOwner(principal?.scope_id ?? '', principal?.user_id ?? '', `security-ban:${audience}`)
    setCreateError(null)
    setBusy(true)
    try {
      for (const siteID of values.site_ids) {
        for (const client of clients) {
          const input: SecurityBanCreateInput = { site_id: siteID, client_ip: client, duration_seconds: values.seconds,
            reason: (values.reason ?? '').trim() }
          // fix-cacheflow6: a ban whose outcome is unknown keeps its key, so
          // sending the same ban again (also after leaving or reloading) is
          // replayed by the server instead of refused as already banned.
          const identity = cacheWriteIdentity('create', input)
          const key = pendingCacheWriteKey(journalOwner, identity) ?? `security-ban-${globalThis.crypto.randomUUID()}`
          try {
            await securityBansApi.create(accessToken ?? '', audience, input, key)
            settleCacheWrite(journalOwner, identity, key)
            created++
          } catch (error) {
            if (writeOutcomeUnknown(error)) rememberCacheWrite(journalOwner, identity, key)
            else settleCacheWrite(journalOwner, identity, key)
            failures.push({ ip: client, site: domains.get(siteID) ?? siteID, reason: t(errorKey(error)) })
          }
        }
      }
      if (created === 0 && failures.length > 0) {
        // Nothing was banned: keep the dialog and what was typed, with each failed line, to fix and retry.
        setCreateError({ type: 'error', text: t('success.createdPartly', { count: 0, failed: failures.length }), failures })
        return
      }
      setMessage(failures.length === 0
        ? { type: 'success', text: t('success.createdMany', { count: created }) }
        : { type: 'success', text: t('success.createdPartly', { count: created, failed: failures.length }), failures })
      setCreating(false)
      form.resetFields()
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  const confirmRelease = async () => {
    if (!releasing) return
    setBusy(true)
    try {
      const ban = await securityBansApi.release(accessToken ?? '', audience, releasing.id)
      setMessage({ type: 'success', text: t('success.released', { ip: ban.client_ip }) })
      setReleasing(null)
      await refresh()
    } catch (error) {
      setMessage({ type: 'error', text: t(errorKey(error)) })
      setReleasing(null)
    } finally {
      setBusy(false)
    }
  }

  const resultAlert = (result: ResultMessage, onClose: () => void) => (
    <Alert type={result.type} showIcon closable message={result.text} onClose={onClose} style={{ marginBottom: 12 }}
      description={result.failures?.length ? <ul className="security-ban-failures">{result.failures.map((item) =>
        <li key={`${item.site}-${item.ip}`}>{t('failureLine', { ip: item.ip, site: item.site, reason: item.reason })}</li>)}</ul> : undefined} />
  )

  const columns: TableColumnsType<SecurityBan> = [
    { title: t('columns.site'), dataIndex: 'site_domain', key: 'site' },
    {
      title: t('columns.ip'), dataIndex: 'client_ip', key: 'ip',
      render: (value: string) => (isNetwork(value) ? <Space size={4}>{value}<Tag color="blue">{t('network')}</Tag></Space> : value),
    },
    {
      title: t('columns.source'), dataIndex: 'source', key: 'source',
      render: (value: SecurityBan['source'], row: SecurityBan) => (row.market ? (
        <Space direction="vertical" size={2}>
          {t(`source.${value}`)}
          <Typography.Text type="secondary">{t('market.origin', { subscription: row.market.subscription.slice(0, 8),
            source: i18n.exists(`source.${row.market.buyer_source}`, { ns: 'securityBans' }) ? t(`source.${row.market.buyer_source}`) : row.market.buyer_source })}</Typography.Text>
        </Space>
      ) : t(`source.${value}`)),
    },
    { title: t('columns.rule'), dataIndex: 'rule_id', key: 'rule', render: (value: string) => value || '-' },
    { title: t('columns.reason'), dataIndex: 'reason', key: 'reason', render: (value: string) => value || '-' },
    { title: t('columns.bannedAt'), dataIndex: 'banned_at', key: 'bannedAt', render: (value: string) => formatDateTime(value, locale) },
    { title: t('columns.bannedUntil'), dataIndex: 'banned_until', key: 'bannedUntil', render: (value: string) => formatDateTime(value, locale) },
    {
      title: t('columns.state'), dataIndex: 'state', key: 'state',
      render: (value: SecurityBanState, row: SecurityBan) => (row.delivery
        ? deliveryCell(row.delivery)
        : <Tag color={stateColors[value]}>{t(`state.${value}`)}</Tag>),
    },
    {
      title: t('columns.releasedAt'), dataIndex: 'released_at', key: 'releasedAt',
      render: (value: string | null) => (value ? formatDateTime(value, locale) : '-'),
    },
    {
      title: t('columns.actions'), key: 'actions', width: 110, fixed: 'right',
      render: (_: unknown, row: SecurityBan) => (canManage && row.state === 'active' ? (
        <Button size="small" icon={<Unlock size={14} aria-hidden />} onClick={() => setReleasing(row)}>{t('actions.release')}</Button>
      ) : null),
    },
  ]

  return (
    <PageSection>
      <Typography.Title level={4}>{t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      {message ? resultAlert(message, () => setMessage(null)) : null}
      {marketSites ? <Alert type="info" showIcon message={t('delivery.hint')} style={{ marginBottom: 12 }} /> : null}
      <Space wrap style={{ marginBottom: 12 }}>
        <IdOrNameInput aria-label={t('filters.site')} placeholder={t('filters.sitePlaceholder')} value={draft.site} style={{ width: 300 }}
          isId={(text) => uuidPattern.test(text.toLowerCase())} search={siteOptions} onPressEnter={search}
          onChange={(site) => setDraft((current) => ({ ...current, site: site.trim().toLowerCase() }))} />
        <FilterField id={ipFieldID} error={ipError}>
          <Input aria-label={t('filters.ip')} placeholder={t('filters.ip')} value={draft.ip} style={{ width: 220 }} onPressEnter={search}
            {...filterFieldProps(ipFieldID, ipError)}
            onChange={(event) => { const ip = event.target.value.trim(); setDraft((current) => ({ ...current, ip })) }} />
        </FilterField>
        <Select aria-label={t('filters.state')} value={draft.state} style={{ width: 140 }}
          onChange={(value) => setDraft((current) => ({ ...current, state: value }))}
          options={[{ value: '', label: t('filters.all') }, ...banStates.map((value) => ({ value, label: t(`state.${value}`) }))]} />
        <Button type="primary" disabled={!siteValid} onClick={search}>{t('filters.search')}</Button>
        <Button onClick={() => { const empty: Filters = { site: '', ip: '', state: 'active' }; setDraft(empty); setApplied(empty); setPage(1) }}>{t('filters.reset')}</Button>
        <Button icon={<RefreshCw size={14} aria-hidden />} onClick={() => void refresh()}>{t('actions.refresh')}</Button>
        {canManage ? <Button icon={<Plus size={14} aria-hidden />} onClick={() => setCreating(true)}>{t('actions.create')}</Button> : null}
      </Space>
      {query.isError && !ipRefused ? <FeedbackWhen title={t('errors.load')} /> : null}
      <Table<SecurityBan>
        rowKey="id"
        loading={query.isFetching}
        columns={columns}
        dataSource={query.data?.items ?? []}
        locale={{ emptyText: t('empty') }}
        // 表格在自己的容器里横向滚动，操作列固定在右侧，不撑宽页面。
        scroll={{ x: 'max-content' }}
        pagination={{
          current: page, pageSize, total: query.data?.total ?? 0, showSizeChanger: true, pageSizeOptions: pageSizes,
          showTotal: (count) => t('total', { count }),
          onChange: (next, size) => { setPage(size !== pageSize ? 1 : next); setPageSize(size) },
        }}
      />
      <Modal open={creating} title={t('actions.create')} okText={t('actions.submit')} cancelText={t('actions.cancel')}
        confirmLoading={busy} onOk={() => void submitCreate()} onCancel={() => { setCreating(false); setCreateError(null) }} destroyOnHidden>
        {createError ? resultAlert(createError, () => setCreateError(null)) : null}
        <Form form={form} layout="vertical" initialValues={{ site_ids: [], seconds: 3600, reason: '' }}>
          <Form.Item name="site_ids" label={t('form.site')} rules={[{ required: true, type: 'array', min: 1, message: t('errors.siteRequired') }]}>
            <Select mode="multiple" showSearch filterOption={false} onSearch={setSiteTyping} loading={sites.isFetching || siteTyping.trim() !== siteSearch}
              placeholder={t('form.sitePlaceholder')} aria-label={t('form.site')} notFoundContent={sites.isFetching ? null : t('form.noSites')}
              options={siteItems.map((item) => ({ value: item.id, label: item.domain, title: item.domain }))} />
          </Form.Item>
          <Form.Item name="client_ips" label={t('form.ip')} extra={t('form.ipHint', { max: maxBatch })} rules={[{ required: true, message: t('errors.invalid') }, {
            validator: async (_, value: string | undefined) => {
              const { clients, tooWide: wide } = parseClients(value ?? '')
              if (wide) throw new Error(t('errors.network'))
              if (clients.length > maxBatch) throw new Error(t('errors.tooMany', { max: maxBatch }))
            },
          }]}>
            <Input.TextArea rows={4} placeholder={t('form.ipPlaceholder')} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.client_ips !== next.client_ips}>
            {() => (parseClients(form.getFieldValue('client_ips') ?? '').network
              ? <Alert type="info" showIcon message={t('form.networkHint')} style={{ marginBottom: 16 }} />
              : null)}
          </Form.Item>
          <Form.Item name="seconds" label={t('form.duration')} rules={[{ required: true, message: t('errors.invalid') }]}>
            <Select aria-label={t('form.duration')}
              options={durations.map((item) => ({ value: item.seconds, label: t(`durations.${item.key}`), title: t(`durations.${item.key}`) }))} />
          </Form.Item>
          <Form.Item name="reason" label={t('form.reason')}>
            <Input maxLength={256} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal open={releasing !== null} title={t('actions.release')} okText={t('actions.confirmRelease')} cancelText={t('actions.cancel')}
        confirmLoading={busy} onOk={() => void confirmRelease()} onCancel={() => setReleasing(null)}>
        {releasing ? t('releaseConfirm', { ip: releasing.client_ip, site: releasing.site_domain }) : null}
      </Modal>
    </PageSection>
  )
}
