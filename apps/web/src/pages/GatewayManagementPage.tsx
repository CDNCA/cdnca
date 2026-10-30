import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Form, Input, Modal, Popconfirm, Result, Space, Table, Tag, Typography } from 'antd'
import { useFeedbackMessage, FeedbackWhen } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { dashboardApi } from '../api/dashboard'
import { DataState } from '../components/DataState'
import {
  buildEnableGatewayAccessCommand, buildGatewayInstallCommand, gatewaysApi, isIPAddress, parseEntrypoints, parseTrustedProxies,
  type Gateway, type GatewayCreated, type GatewaySettings, type GatewayStatus,
} from '../api/gateways'
import { useSessionStore } from '../auth/session'
import { businessTimeZone, formatDateTime } from '../i18n/formatters'
import '../i18n/gatewayManagement'

export const gatewayManagePermission = 'system.gateway.manage'

const statusColor: Record<GatewayStatus, string> = { pending: 'gold', bound: 'blue', active: 'green', disabled: 'default', deleted: 'red' }
const hostPattern = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/

type InstallRuntime = { __CDNCA_LICENSING_SERVER__?: string }

function hasPermission(principal: Principal, permission: string): boolean {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

export default function GatewayManagementPage() {
  const { t } = useTranslation('gatewayManagement')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken || !principal) return null
  if (principal.scope_kind !== 'platform' || !hasPermission(principal, gatewayManagePermission)) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <GatewayManagementContent />
    <GatewaySettingsCard />
  </Space>
}

function errorText(t: (key: string) => string, error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return t('errors.permissionDenied')
    if (error.code === 'gateway_name_taken') return t('errors.nameTaken')
    if (error.status === 409) return t('errors.conflict')
    if (error.status === 422 || error.status === 400) return t('errors.invalid')
  }
  return t('errors.failed')
}

function GatewayManagementContent() {
  const { t, i18n } = useTranslation('gatewayManagement')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [form] = Form.useForm<{ name: string; host: string }>()
  const [adding, setAdding] = useState(false)
  const [created, setCreated] = useState<GatewayCreated | null>(null)
  const [copied, setCopied] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [editingIPs, setEditingIPs] = useState<Gateway | null>(null)
  const [ipText, setIPText] = useState('')
  const [ipError, setIPError] = useState<string | null>(null)
  const token = () => useSessionStore.getState().accessToken ?? ''
  const queryKey = ['gateways'] as const

  const query = useQuery({ queryKey, queryFn: () => gatewaysApi.list(token()) })
  const refresh = () => queryClient.invalidateQueries({ queryKey })

  const showToken = (result: GatewayCreated) => { setCreated(result); setCopied(false); setFailure(null); void refresh() }
  const create = useMutation({
    mutationFn: (input: { name: string; host: string }) => gatewaysApi.create(token(), input),
    onSuccess: (result) => { setAdding(false); form.resetFields(); showToken(result) },
    onError: (error) => setFailure(errorText(t, error)),
  })
  const issue = useMutation({
    mutationFn: (id: string) => gatewaysApi.issueToken(token(), id),
    onSuccess: showToken,
    onError: (error) => setFailure(errorText(t, error)),
  })
  const change = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'disable' | 'enable' | 'remove' }) => gatewaysApi[action](token(), id),
    onSuccess: (_, { action }) => {
      setFailure(null)
      messageApi.success(t(action === 'disable' ? 'done.disabled' : action === 'enable' ? 'done.enabled' : 'done.deleted'))
      void refresh()
    },
    onError: (error) => setFailure(errorText(t, error)),
  })

  const saveIPs = useMutation({
    mutationFn: ({ id, ips }: { id: string; ips: string[] }) => gatewaysApi.setAllowedIPs(token(), id, ips),
    onSuccess: () => { setEditingIPs(null); messageApi.success(t('done.allowedIPs')); void refresh() },
    onError: (error) => setIPError(errorText(t, error)),
  })
  const openIPs = (row: Gateway) => { setEditingIPs(row); setIPText((row.allowed_ips ?? []).join('\n')); setIPError(null) }
  const submitIPs = () => {
    if (!editingIPs) return
    const ips = ipText.split('\n').map((item) => item.trim()).filter(Boolean)
    if (ips.length === 0 || ips.length > 16 || !ips.every(isIPAddress)) { setIPError(t('allowedIPs.invalid')); return }
    saveIPs.mutate({ id: editingIPs.id, ips })
  }

  const installer = (window as InstallRuntime).__CDNCA_LICENSING_SERVER__ ?? ''
  let command = ''
  if (created) {
    try { command = buildGatewayInstallCommand(created.binding_token, window.location.origin, installer, created.gateway.host) } catch { command = '' }
  }
  const copy = async () => {
    try { await navigator.clipboard.writeText(command); setCopied(true) } catch { setFailure(t('command.copyFailed')) }
  }
  const date = (value: string | null) => (value ? formatDateTime(value, locale) || value : '-')
  const busy = create.isPending || issue.isPending || change.isPending || saveIPs.isPending

  const columns = [
    { title: t('columns.name'), dataIndex: 'name', key: 'name' },
    { title: t('columns.host'), dataIndex: 'host', key: 'host' },
    { title: t('columns.ports'), key: 'ports', render: (_: unknown, row: Gateway) => (row.enrollment_port ? `${row.enrollment_port} / ${row.agent_port}` : '-') },
    { title: t('columns.status'), key: 'status', render: (_: unknown, row: Gateway) => <Tag color={statusColor[row.status]}>{t(`status.${row.status}`)}</Tag> },
    { title: t('columns.version'), key: 'version', render: (_: unknown, row: Gateway) => row.version || '-' },
    {
      title: t('columns.certificates'), key: 'certificates', render: (_: unknown, row: Gateway) => (row.client_certificate_expires_at
        ? <Space direction="vertical" size={0}>
          <small>{t('certificate.client', { date: date(row.client_certificate_expires_at) })}</small>
          <small>{t('certificate.server', { date: date(row.server_certificate_expires_at) })}</small>
        </Space> : '-'),
    },
    {
      title: t('columns.allowedIPs'), key: 'allowed_ips', render: (_: unknown, row: Gateway) => ((row.allowed_ips ?? []).length
        ? <Space direction="vertical" size={0}>{(row.allowed_ips ?? []).map((ip) => <small key={ip}>{ip}</small>)}</Space> : '-'),
    },
    {
      title: t('columns.actions'), key: 'actions', render: (_: unknown, row: Gateway) => <Space wrap size={4}>
        {['bound', 'active', 'disabled'].includes(row.status) && <Button size="small" disabled={busy} onClick={() => openIPs(row)}>{t('actions.allowedIPs')}</Button>}
        {row.status === 'pending' && <Button size="small" disabled={busy} onClick={() => issue.mutate(row.id)}>{t('actions.token')}</Button>}
        {['bound', 'active'].includes(row.status) && <Popconfirm title={t('confirm.disable')} okText={t('confirm.ok')} cancelText={t('confirm.cancel')}
          onConfirm={() => change.mutate({ id: row.id, action: 'disable' })}>
          <Button size="small" disabled={busy}>{t('actions.disable')}</Button>
        </Popconfirm>}
        {row.status === 'disabled' && <Button size="small" disabled={busy} onClick={() => change.mutate({ id: row.id, action: 'enable' })}>{t('actions.enable')}</Button>}
        {row.status !== 'deleted' && <Popconfirm title={t('confirm.delete')} okText={t('confirm.ok')} cancelText={t('confirm.cancel')}
          okButtonProps={{ danger: true }} onConfirm={() => change.mutate({ id: row.id, action: 'remove' })}>
          <Button size="small" danger disabled={busy}>{t('actions.delete')}</Button>
        </Popconfirm>}
      </Space>,
    },
  ]

  // "Add Gateway" only appears once standalone access is open: binding is refused otherwise.
  const open = query.data?.standalone_access_open === true
  return <Card title={t('title')} extra={<Space>
    <Button onClick={() => void refresh()}>{t('refresh')}</Button>
    {open && <Button type="primary" onClick={() => { setFailure(null); setAdding(true) }}>{t('add')}</Button>}
  </Space>}>
    {messageContext}
    {query.data && <LocalGatewayNote open={open} installer={installer} />}
    {open && <Typography.Paragraph type="secondary" className="density-note">{t('description')}</Typography.Paragraph>}
    {query.isError && <FeedbackWhen title={errorText(t, query.error) === t('errors.failed') ? t('errors.load') : errorText(t, query.error)} />}
    {failure && <FeedbackWhen title={failure} />}
    <Table<Gateway> rowKey="id" size="small" loading={query.isPending} columns={columns}
      dataSource={(query.data?.items ?? []).filter((row) => row.status !== 'deleted')}
      locale={{ emptyText: query.isError ? <DataState status="error" message={t('errors.load')} onRetry={() => void query.refetch()} /> : t('empty') }} pagination={false} />

    <Modal title={t('form.title')} open={adding} okText={t('form.submit')} cancelText={t('form.cancel')} confirmLoading={create.isPending}
      onCancel={() => setAdding(false)} onOk={() => void form.validateFields().then((values) => create.mutate({ name: values.name.trim(), host: values.host.trim().toLowerCase() })).catch(() => undefined)}>
      <Form form={form} layout="vertical">
        <Form.Item name="name" label={t('form.name')} rules={[{ required: true, whitespace: true, max: 64, message: t('form.nameRequired') }]}>
          <Input placeholder={t('form.namePlaceholder')} />
        </Form.Item>
        <Form.Item name="host" label={t('form.host')} rules={[{ required: true, pattern: hostPattern, message: t('form.hostRequired') }]}>
          <Input placeholder={t('form.hostPlaceholder')} />
        </Form.Item>
      </Form>
    </Modal>

    <Modal title={t('allowedIPs.title')} open={Boolean(editingIPs)} okText={t('allowedIPs.save')} cancelText={t('form.cancel')}
      confirmLoading={saveIPs.isPending} onCancel={() => setEditingIPs(null)} onOk={submitIPs}>
      <Typography.Paragraph type="secondary">{t('allowedIPs.description', { source: editingIPs?.source_ip ?? '-' })}</Typography.Paragraph>
      {ipError && <Alert type="error" showIcon message={ipError} style={{ marginBottom: 8 }} />}
      <Input.TextArea aria-label={t('allowedIPs.label')} value={ipText} onChange={(event) => setIPText(event.target.value)} autoSize={{ minRows: 3, maxRows: 10 }} />
    </Modal>

    <Modal title={t('command.title')} open={Boolean(created)} onCancel={() => setCreated(null)}
      footer={<Space>
        {command && <Button type="primary" onClick={() => void copy()}>{t(copied ? 'command.copied' : 'command.copy')}</Button>}
        <Button onClick={() => setCreated(null)}>{t('command.close')}</Button>
      </Space>}>
      {created && <>
        <Typography.Paragraph>{t('command.description', { expires: date(created.token_expires_at) })}</Typography.Paragraph>
        {command
          ? <>
            <Input.TextArea aria-label={t('command.label')} value={command} readOnly autoSize={{ minRows: 3, maxRows: 8 }} />
            <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>{t('command.publicCertificate')}</Typography.Paragraph>
          </>
          : <>
            <Alert type="warning" showIcon message={t('command.noInstaller')} style={{ marginBottom: 8 }} />
            <Input.TextArea aria-label={t('command.token')} value={created.binding_token} readOnly autoSize />
          </>}
      </>}
    </Modal>
  </Card>
}

// Fixed note above the list: the co-located Gateway is what nodes use; standalone
// Gateways are optional. When access is closed it shows how to open it instead
// of an "Add Gateway" that would be refused. The node count comes from the
// admin dashboard and is left out when that is unavailable.
function LocalGatewayNote({ open, installer }: { open: boolean; installer: string }) {
  const { t, i18n } = useTranslation('gatewayManagement')
  // Chinese sentences join without a space; English ones with one.
  const sep = (i18n.resolvedLanguage ?? 'zh-CN').startsWith('en') ? ' ' : ''
  const [copied, setCopied] = useState(false)
  const nodes = useQuery({
    queryKey: ['gateway-local-node-count'],
    queryFn: ({ signal }) => dashboardApi.admin(useSessionStore.getState().accessToken ?? '', 'seven_days', businessTimeZone, signal),
    select: (result) => (result.node_health.available ? result.node_health.value.total : null),
    retry: false,
  })
  const command = buildEnableGatewayAccessCommand(installer)
  const copy = async () => {
    try { await navigator.clipboard.writeText(command); setCopied(true) } catch { setCopied(false) }
  }
  return <Alert type="info" showIcon style={{ marginBottom: 12 }} message={<>
    {t('local.current')}
    {typeof nodes.data === 'number' && <>{sep}{t('local.nodes', { count: nodes.data })}</>}
    {sep}{t('local.optional')}
  </>} description={open ? undefined : <>
    <Typography.Paragraph style={{ marginBottom: 8 }}>{t('local.closed')}</Typography.Paragraph>
    <Input.TextArea aria-label={t('local.command')} value={command} readOnly autoSize={{ minRows: 1, maxRows: 6 }} />
    <Space style={{ marginTop: 8 }}>
      <Button size="small" onClick={() => void copy()}>{t(copied ? 'local.copied' : 'local.copy')}</Button>
      <Typography.Text type="secondary">{t('local.after')}</Typography.Text>
    </Space>
  </>} />
}

function GatewaySettingsCard() {
  const { t } = useTranslation('gatewayManagement')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [proxies, setProxies] = useState<string | null>(null)
  const [entrypoints, setEntrypoints] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  // W4: publishing reaches every Gateway and node, so it is confirmed first.
  const [pending, setPending] = useState<GatewaySettings | null>(null)
  // 卡 8：草稿基于哪份设置编辑，就用那份的 ETag 做 CAS；后台重取到的新 ETag 不能借给旧草稿。
  const [draftETag, setDraftETag] = useState<string | null>(null)
  const token = () => useSessionStore.getState().accessToken ?? ''
  const queryKey = ['gateway-settings'] as const
  const query = useQuery({ queryKey, queryFn: () => gatewaysApi.settings(token()) })
  const loaded = query.data?.settings
  const edit = (set: (value: string) => void) => (value: string) => {
    if (draftETag === null && query.data) setDraftETag(query.data.etag)
    set(value)
  }
  const proxyText = proxies ?? (loaded?.trusted_proxies ?? []).map((item) => (item.header ? `${item.cidr}=${item.header}` : item.cidr)).join('\n')
  const entryText = entrypoints ?? (loaded?.entrypoints ?? [])
    .map((item) => [item.address, item.server_name, item.transport, item.tunnel_host].filter(Boolean).join(' ')).join('\n')
  const save = useMutation({
    mutationFn: ({ settings, etag }: { settings: GatewaySettings; etag: string }) => gatewaysApi.updateSettings(token(), settings, etag),
    onSuccess: (saved) => {
      queryClient.setQueryData(queryKey, saved)
      setProxies(null); setEntrypoints(null); setDraftETag(null); setFailure(null)
      messageApi.success(t('settings.saved'))
    },
    onError: (error) => {
      // G1: someone saved after this form was loaded; show theirs instead of overwriting it.
      if (error instanceof ApiError && error.code === 'gateway_settings_changed') {
        setProxies(null); setEntrypoints(null); setDraftETag(null); setFailure(t('settings.changed'))
        void queryClient.invalidateQueries({ queryKey })
        return
      }
      setFailure(errorText(t, error))
    },
  })
  const submit = () => {
    const parsedProxies = parseTrustedProxies(proxyText)
    const parsedEntrypoints = parseEntrypoints(entryText)
    if (!parsedProxies) { setFailure(t('settings.invalidProxies')); return }
    if (!parsedEntrypoints) { setFailure(t('settings.invalidEntrypoints')); return }
    setFailure(null)
    setPending({ trusted_proxies: parsedProxies, entrypoints: parsedEntrypoints })
  }
  return <Card title={t('settings.title')} extra={<Button type="primary" disabled={!loaded || save.isPending} onClick={submit}>{t('settings.save')}</Button>}>
    {messageContext}
    <Modal open={!!pending} title={t('settings.confirmTitle')} okText={t('settings.confirmOk')} cancelText={t('settings.confirmCancel')}
      onCancel={() => setPending(null)} onOk={() => { if (pending && query.data) save.mutate({ settings: pending, etag: draftETag ?? query.data.etag }); setPending(null) }}>
      {t('settings.confirmContent')}
    </Modal>
    {failure && <FeedbackWhen title={failure} />}
    {query.isError && !loaded ? <DataState status="error" message={t('settings.loadFailed')} onRetry={() => void query.refetch()} /> : <div className="density-split">
      <div>
        <Typography.Paragraph type="secondary">{t('settings.proxiesHint')}</Typography.Paragraph>
        <Input.TextArea aria-label={t('settings.proxies')} value={proxyText} disabled={!loaded}
          onChange={(event) => edit(setProxies)(event.target.value)} autoSize={{ minRows: 4, maxRows: 12 }} />
      </div>
      <div>
        <Typography.Paragraph type="secondary">{t('settings.entrypointsHint')}</Typography.Paragraph>
        <Input.TextArea aria-label={t('settings.entrypoints')} value={entryText} disabled={!loaded}
          onChange={(event) => edit(setEntrypoints)(event.target.value)} autoSize={{ minRows: 4, maxRows: 12 }} />
      </div>
    </div>}
  </Card>
}
