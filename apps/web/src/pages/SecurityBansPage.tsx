import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Select, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { Plus, RefreshCw, Unlock } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  securityBansApi,
  type SecurityBan,
  type SecurityBanAudience,
  type SecurityBanCreateInput,
  type SecurityBanState,
} from '../api/securityBans'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/securityBans'
import { cacheWriteIdentity, cacheWriteOwner, pendingCacheWriteKey, rememberCacheWrite, settleCacheWrite } from './cacheWriteJournal'
import { writeOutcomeUnknown } from './site-edit/writeOutcome'
import { FeedbackWhen } from '@cdnca/ui'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const stateColors: Record<SecurityBanState, string> = { active: 'red', released: 'green', expired: 'default' }
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
  const [draft, setDraft] = useState<Filters>({ site: '', ip: '', state: 'active' })
  const [applied, setApplied] = useState<Filters>(draft)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [creating, setCreating] = useState(false)
  const [releasing, setReleasing] = useState<SecurityBan | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<ResultMessage | null>(null)
  // The result of a submission that banned nothing, shown inside the dialog.
  const [createError, setCreateError] = useState<ResultMessage | null>(null)
  const [form] = Form.useForm<{ site_ids: string[]; client_ips: string; seconds: number; reason: string }>()
  const [siteSearch, setSiteSearch] = useState('')
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

  // One request per (site, address); the results are summed up, every
  // failure with its reason.
  const submitCreate = async () => {
    // Invalid input stays in the form with its field errors; the rejection is handled here.
    const values = await form.validateFields().catch(() => null)
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
    { title: t('columns.source'), dataIndex: 'source', key: 'source', render: (value: SecurityBan['source']) => t(`source.${value}`) },
    { title: t('columns.rule'), dataIndex: 'rule_id', key: 'rule', render: (value: string) => value || '-' },
    { title: t('columns.reason'), dataIndex: 'reason', key: 'reason', render: (value: string) => value || '-' },
    { title: t('columns.bannedAt'), dataIndex: 'banned_at', key: 'bannedAt', render: (value: string) => formatDateTime(value, locale) },
    { title: t('columns.bannedUntil'), dataIndex: 'banned_until', key: 'bannedUntil', render: (value: string) => formatDateTime(value, locale) },
    {
      title: t('columns.state'), dataIndex: 'state', key: 'state',
      render: (value: SecurityBanState) => <Tag color={stateColors[value]}>{t(`state.${value}`)}</Tag>,
    },
    {
      title: t('columns.releasedAt'), dataIndex: 'released_at', key: 'releasedAt',
      render: (value: string | null) => (value ? formatDateTime(value, locale) : '-'),
    },
    {
      title: t('columns.actions'), key: 'actions',
      render: (_: unknown, row: SecurityBan) => (canManage && row.state === 'active' ? (
        <Button size="small" icon={<Unlock size={14} aria-hidden />} onClick={() => setReleasing(row)}>{t('actions.release')}</Button>
      ) : null),
    },
  ]

  return (
    <div className="page-container">
      <Typography.Title level={4}>{t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      {message ? resultAlert(message, () => setMessage(null)) : null}
      <Space wrap style={{ marginBottom: 12 }}>
        <Input aria-label={t('filters.site')} placeholder={t('filters.site')} value={draft.site} style={{ width: 300 }}
          onChange={(event) => setDraft({ ...draft, site: event.target.value.trim() })} />
        <Input aria-label={t('filters.ip')} placeholder={t('filters.ip')} value={draft.ip} style={{ width: 220 }}
          onChange={(event) => setDraft({ ...draft, ip: event.target.value.trim() })} />
        <Select aria-label={t('filters.state')} value={draft.state} style={{ width: 140 }}
          onChange={(value) => setDraft({ ...draft, state: value })}
          options={[{ value: '', label: t('filters.all') }, ...(['active', 'released', 'expired'] as const).map((value) => ({ value, label: t(`state.${value}`) }))]} />
        <Button type="primary" disabled={draft.site !== '' && !uuidPattern.test(draft.site)}
          onClick={() => { setApplied(draft); setPage(1) }}>{t('filters.search')}</Button>
        <Button onClick={() => { const empty: Filters = { site: '', ip: '', state: 'active' }; setDraft(empty); setApplied(empty); setPage(1) }}>{t('filters.reset')}</Button>
        <Button icon={<RefreshCw size={14} aria-hidden />} onClick={() => void refresh()}>{t('actions.refresh')}</Button>
        {canManage ? <Button icon={<Plus size={14} aria-hidden />} onClick={() => setCreating(true)}>{t('actions.create')}</Button> : null}
      </Space>
      {query.isError ? <FeedbackWhen title={t('errors.load')} /> : null}
      <Table<SecurityBan>
        rowKey="id"
        loading={query.isFetching}
        columns={columns}
        dataSource={query.data?.items ?? []}
        locale={{ emptyText: t('empty') }}
        pagination={{
          current: page, pageSize, total: query.data?.total ?? 0, showSizeChanger: true, pageSizeOptions: [20, 50, 100],
          showTotal: (count) => t('total', { count }),
          onChange: (next, size) => { setPage(size !== pageSize ? 1 : next); setPageSize(size) },
        }}
      />
      <Modal open={creating} title={t('actions.create')} okText={t('actions.submit')} cancelText={t('actions.cancel')}
        confirmLoading={busy} onOk={() => void submitCreate()} onCancel={() => { setCreating(false); setCreateError(null) }} destroyOnHidden>
        {createError ? resultAlert(createError, () => setCreateError(null)) : null}
        <Form form={form} layout="vertical" initialValues={{ site_ids: [], seconds: 3600, reason: '' }}>
          <Form.Item name="site_ids" label={t('form.site')} rules={[{ required: true, type: 'array', min: 1, message: t('errors.siteRequired') }]}>
            <Select mode="multiple" showSearch filterOption={false} onSearch={setSiteSearch} loading={sites.isFetching}
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
    </div>
  )
}
