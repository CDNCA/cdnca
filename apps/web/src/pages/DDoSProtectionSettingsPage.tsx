import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Checkbox, Form, Input, InputNumber, Result, Select, Space, Spin, Switch, Table, Tag, Typography } from 'antd'
import { useFeedbackMessage, FeedbackWhen } from '@cdnca/ui'
import { Check, CheckCircle, RefreshCw, Rocket, Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { nodesApi, type NodeInventoryItem, type NodeMetricsLatest } from '../api/nodes'
import { formatDateTime } from '../i18n/formatters'
import {
  newSystemConfigurationIdempotencyKey,
  newSystemConfigurationRequestId,
  systemConfigurationApi,
  type CCKernelBanMode,
  type DDoSProtectionConfiguration,
  type SystemConfigurationDocument,
  type TCPFlagType,
  tcpFlagTypes,
} from '../api/systemConfiguration'
import { useSessionStore } from '../auth/session'
import '../i18n/ddosProtectionSettings'
import { PendingCategoriesNotice, usePendingActivationConfirm } from './system-settings/PendingCategories'
import { SiteTabSummary, type SummaryItem } from './site-edit/SiteTabSummary'
import './site-edit/SiteEditV4.css'
import './DDoSProtectionV2.css'

type Document = SystemConfigurationDocument<'ddos_protection'>

interface FormValues {
  max_connections_per_ip: number
  new_connections_per_second: number
  new_connections_per_minute: number
  rate_ban_seconds: number
  max_connections_per_port: number
  empty_enabled: boolean
  idle_seconds: number
  threshold: number
  window_seconds: number
  ban_seconds: number
  cc_kernel_ban: CCKernelBanMode
  allow_networks: string
  tcp_flag_filter: boolean
  tcp_flag_types: TCPFlagType[]
  drop_invalid: boolean
}

const emptyDefaults = { idle_seconds: 10, threshold: 20, window_seconds: 60, ban_seconds: 1800 }

function hasPermission(principal: Principal, permission: string): boolean {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

// An IPv4/IPv6 address with an optional prefix length; the server
// canonicalizes and is the authority.
const networkPattern = /^(?:(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|[0-9a-fA-F:]*:[0-9a-fA-F:.]*(?:\/\d{1,3})?)$/

export function toFormValues(value: DDoSProtectionConfiguration): FormValues {
  return {
    max_connections_per_ip: value.max_connections_per_ip,
    new_connections_per_second: value.new_connections_per_second,
    new_connections_per_minute: value.new_connections_per_minute,
    rate_ban_seconds: value.rate_ban_seconds,
    max_connections_per_port: value.max_connections_per_port,
    empty_enabled: value.empty_connection !== undefined,
    ...(value.empty_connection ?? emptyDefaults),
    cc_kernel_ban: value.cc_kernel_ban,
    allow_networks: value.allow_networks.join('\n'),
    tcp_flag_filter: value.tcp_flag_filter === true,
    tcp_flag_types: value.tcp_flag_types ?? [],
    drop_invalid: value.drop_invalid === true,
  }
}

export function fromFormValues(values: FormValues): DDoSProtectionConfiguration {
  const value: DDoSProtectionConfiguration = {
    max_connections_per_ip: values.max_connections_per_ip ?? 0,
    new_connections_per_second: values.new_connections_per_second ?? 0,
    new_connections_per_minute: values.new_connections_per_minute ?? 0,
    rate_ban_seconds: values.rate_ban_seconds ?? 0,
    max_connections_per_port: values.max_connections_per_port ?? 0,
    allow_networks: (values.allow_networks ?? '').split('\n').map((line) => line.trim()).filter(Boolean),
    cc_kernel_ban: values.cc_kernel_ban,
  }
  // Canonical order; the types are kept while the switch is off.
  const types = tcpFlagTypes.filter((kind) => (values.tcp_flag_types ?? []).includes(kind))
  if (types.length > 0) value.tcp_flag_types = types
  if (values.tcp_flag_filter) value.tcp_flag_filter = true
  if (values.drop_invalid) value.drop_invalid = true
  if (values.empty_enabled) {
    value.empty_connection = {
      idle_seconds: values.idle_seconds, threshold: values.threshold,
      window_seconds: values.window_seconds, ban_seconds: values.ban_seconds,
    }
  }
  return value
}

export default function DDoSProtectionSettingsPage() {
  const { t } = useTranslation('ddosProtectionSettings')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken || !principal) return null
  if (principal.scope_kind !== 'platform' || !hasPermission(principal, 'system_configuration.read')) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  return <DDoSProtectionSettingsContent canManage={hasPermission(principal, 'system_configuration.manage')}
    canReadNodes={hasPermission(principal, 'nodes.read')} />
}

/**
 * NodeReceipts is the third layer of the page (连接防护三层表达): what each node reports its DDoS table runs
 * (NodeTelemetry.ddos_protection), next to the global baseline and the port group overrides above.
 * Not shown without nodes.read.
 */
function NodeReceipts() {
  const { t, i18n } = useTranslation('ddosProtectionSettings')
  const token = useSessionStore((state) => state.accessToken)
  const query = useQuery({
    queryKey: ['ddos-protection-node-receipts'],
    enabled: Boolean(token),
    retry: false,
    queryFn: async () => {
      const nodes: NodeInventoryItem[] = []
      let cursor: string | undefined
      const seen = new Set<string>()
      do {
        const page = await nodesApi.list(token!, { limit: 300, ...(cursor ? { cursor } : {}) })
        nodes.push(...page.items)
        if (cursor) seen.add(cursor)
        cursor = page.next_cursor && !seen.has(page.next_cursor) ? page.next_cursor : undefined
      } while (cursor)
      const latest = new Map<string, NodeMetricsLatest>()
      for (let index = 0; index < nodes.length; index += 300) {
        const batch = await nodesApi.getLatestMetricsBatch(token!, nodes.slice(index, index + 300).map((node) => node.id))
        for (const item of batch.items) latest.set(item.node_id, item)
      }
      return nodes.map((node) => ({ node, sample: latest.get(node.id) }))
    },
  })
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  return (
    <Card title={t('receipts.title')} size="small" data-testid="ddos-node-receipts"
      extra={<Button size="small" icon={<RefreshCw size={14} />} loading={query.isFetching} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>}>
      <Typography.Paragraph type="secondary">{t('receipts.hint')}</Typography.Paragraph>
      {query.isError ? <FeedbackWhen title={t('receipts.loadFailed')} /> : (
        <Table
          size="small"
          rowKey={(row) => row.node.id}
          loading={query.isPending}
          dataSource={query.data ?? []}
          pagination={(query.data?.length ?? 0) > 20 ? { pageSize: 20, showSizeChanger: false } : false}
          locale={{ emptyText: t('receipts.empty') }}
          scroll={{ x: 'max-content' }}
          columns={[
            { title: t('receipts.columns.node'), key: 'node', render: (_, row) => row.node.name },
            {
              title: t('receipts.columns.state'), key: 'state',
              render: (_, row) => {
                const protection = row.sample?.known ? row.sample.telemetry?.ddos_protection : undefined
                if (!protection) return <Tag>{t('receipts.notReported')}</Tag>
                const color = protection.state === 'applied' ? 'green' : protection.state === 'failed' || protection.state === 'unavailable' ? 'red' : 'default'
                return <Tag color={color}>{t(`receipts.states.${protection.state}`)}</Tag>
              },
            },
            {
              title: t('receipts.columns.detail'), key: 'detail',
              render: (_, row) => {
                const protection = row.sample?.known ? row.sample.telemetry?.ddos_protection : undefined
                if (!protection) return '—'
                if (protection.state === 'unavailable' && protection.reason) return t(`receipts.reasons.${protection.reason}`)
                return protection.detail ?? '—'
              },
            },
            {
              // fz-x11: node × port group — whether each layer 4 port group override is in effect on the node.
              title: t('receipts.portGroups.column'), key: 'portGroups',
              render: (_, row) => <PortGroupOverrideTags sample={row.sample} />,
            },
            {
              title: t('receipts.columns.observedAt'), key: 'observedAt',
              render: (_, row) => row.sample?.known ? formatDateTime(row.sample.observed_at, language) : '—',
            },
          ]}
        />
      )}
    </Card>
  )
}

/** The node's port group override receipts (NodeTelemetry.port_group_overrides, NODE_TELEMETRY_DETAIL v1). */
function PortGroupOverrideTags({ sample }: { sample?: NodeMetricsLatest }) {
  const { t } = useTranslation('ddosProtectionSettings')
  if (!sample?.known) return <>—</>
  if (!sample.telemetry_detail) return <Tag data-testid="port-group-version-not-reported">{t('receipts.portGroups.versionNotReported')}</Tag>
  const overrides = sample.telemetry?.port_group_overrides ?? []
  if (overrides.length === 0) return <Typography.Text type="secondary">{t('receipts.portGroups.none')}</Typography.Text>
  return (
    <Space direction="vertical" size={2}>
      {overrides.map((item) => {
        const color = item.state === 'applied' ? 'green' : item.state === 'standby' ? 'blue' : item.state === 'failed' ? 'red' : 'default'
        const name = item.port_group_id === 'web-tcp' ? t('receipts.portGroups.web') : item.port_group_id
        return (
          <span key={item.port_group_id} data-testid={`port-group-override-${item.port_group_id}`}>
            {name}{' '}
            <Tag color={color}>{t(`receipts.portGroups.states.${item.state}`)}</Tag>
            {item.reason ? <Typography.Text type="secondary">{t(`receipts.portGroups.reasons.${item.reason}`)}</Typography.Text> : null}
          </span>
        )
      })}
    </Space>
  )
}

function errorText(t: (key: string) => string, error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return t('errors.permissionDenied')
    if (error.code === 'system_configuration_pending_categories_changed') return t('errors.pendingChanged')
    if (error.status === 409 || error.code === 'system_configuration_revision_conflict') return t('errors.conflict')
    if (error.status === 400 || error.code === 'system_configuration_validation_error') return t('errors.invalid')
  }
  return t(fallback)
}

/** The keys of the loaded revision that differ from the form (allow list compared line by line, normalized). */
function changedFields(loaded: FormValues, current: Partial<FormValues>): number {
  const normalize = (key: keyof FormValues, value: unknown) => {
    if (key === 'allow_networks') return String(value ?? '').split('\n').map((line) => line.trim()).filter(Boolean).join('\n')
    if (key === 'tcp_flag_types') return tcpFlagTypes.filter((kind) => ((value as TCPFlagType[] | undefined) ?? []).includes(kind)).join(',')
    return value ?? null
  }
  const loadedEmpty = !loaded.empty_enabled
  return (Object.keys(loaded) as Array<keyof FormValues>).filter((key) => {
    // The empty connection numbers only count while the detection is on in both.
    if (['idle_seconds', 'threshold', 'window_seconds', 'ban_seconds'].includes(key) && (loadedEmpty || !current.empty_enabled)) return false
    return normalize(key, loaded[key]) !== normalize(key, current[key])
  }).length
}

function DDoSProtectionSettingsContent({ canManage, canReadNodes }: { canManage: boolean; canReadNodes: boolean }) {
  const { t } = useTranslation('ddosProtectionSettings')
  const [form] = Form.useForm<FormValues>()
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [failure, setFailure] = useState<string | null>(null)
  const queryKey = ['system-configuration', 'ddos_protection'] as const
  const token = () => useSessionStore.getState().accessToken ?? ''
  const confirmPending = usePendingActivationConfirm('ddos_protection')

  const query = useQuery({
    queryKey,
    queryFn: () => systemConfigurationApi.get(token(), 'ddos_protection'),
  })
  const document = query.data
  const emptyEnabled = Form.useWatch('empty_enabled', form)
  const flagFilter = Form.useWatch('tcp_flag_filter', form)
  // Every field, for the unsaved change count of the save bar.
  const watched = Form.useWatch([], form) as Partial<FormValues> | undefined
  useEffect(() => {
    if (document) form.setFieldsValue(toFormValues(document.value))
  }, [document, form])

  const save = useMutation({
    mutationFn: async (values: FormValues) => {
      if (!document) throw new Error('not loaded')
      return systemConfigurationApi.put(token(), 'ddos_protection', fromFormValues(values), document.head_revision,
        newSystemConfigurationIdempotencyKey('ddos_protection'), newSystemConfigurationRequestId('ddos_protection'))
    },
    onSuccess: (next) => {
      setFailure(null)
      queryClient.setQueryData<Document>(queryKey, next)
      messageApi.success(t('notices.saved'))
    },
    onError: (error) => setFailure(errorText(t, error, 'errors.write')),
  })

  const lifecycle = useMutation({
    mutationFn: async (kind: 'preflight' | 'activate') => {
      if (!document) throw new Error('not loaded')
      if (kind === 'preflight') {
        return systemConfigurationApi.preflight(token(), document.revision, document.snapshot_sha256,
          newSystemConfigurationIdempotencyKey('ddos_protection'), newSystemConfigurationRequestId('ddos_protection'),
          document.pending_categories)
      }
      return systemConfigurationApi.activate(token(), document.revision, document.active_revision,
        newSystemConfigurationIdempotencyKey('ddos_protection'), newSystemConfigurationRequestId('ddos_protection'),
        document.pending_categories)
    },
    onSuccess: (result) => {
      setFailure(null)
      queryClient.setQueryData<Document>(queryKey, (current) => current && current.revision === result.revision ? {
        ...current, status: result.status,
        active_revision: result.status === 'active' ? result.revision : current.active_revision,
      } : current)
      messageApi.success(t(result.status === 'active' ? 'notices.activated' : 'notices.validated'))
    },
    onError: (error) => setFailure(errorText(t, error, 'errors.lifecycle')),
  })

  if (query.isPending) return <Spin aria-label={t('loading')} />
  if (query.isError || !document) {
    return <Result status="warning" title={t('errors.load')} extra={<Button onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>} />
  }

  const statusText = document.head_revision === 0
    ? t('status.none')
    : document.status === 'active'
      ? t('status.active', { revision: document.revision })
      : t(document.status === 'validated' ? 'status.validated' : 'status.draft', { revision: document.revision })
  const busy = save.isPending || lifecycle.isPending
  const loaded = toFormValues(document.value)
  const dirty = canManage && watched ? changedFields(loaded, watched) : 0
  const seconds = t('units.seconds')
  const number = (name: keyof FormValues, label: string, max: number, extra?: string) => (
    <Form.Item name={name} label={label} extra={extra} rules={[{ required: true, type: 'integer', min: 0, max }]}>
      <InputNumber min={0} max={max} precision={0} disabled={!canManage} />
    </Form.Item>
  )
  // A field of a four-field row shows its short label; the full
  // name is the help tooltip and the input's accessible name
  type ShortField = 'maxConnectionsPerIP' | 'newPerSecond' | 'newPerMinute' | 'rateBanSeconds'
    | 'idleSeconds' | 'threshold' | 'windowSeconds' | 'banSeconds'
  const short = (key: ShortField) => ({ label: t(`shortFields.${key}`), tooltip: t(`fields.${key}`) })
  const shortNumber = (name: keyof FormValues, key: ShortField, max: number) => (
    <Form.Item name={name} {...short(key)} rules={[{ required: true, type: 'integer', min: 0, max }]}>
      <InputNumber min={0} max={max} precision={0} disabled={!canManage} aria-label={t(`fields.${key}`)} />
    </Form.Item>
  )
  return (
    <div className="ddos-protection-settings ddos-v2">
      {messageContext}
      <div className="ddos-v2-head">
        <div>
          <Typography.Title level={4}>{t('title')}</Typography.Title>
          <Typography.Text type="secondary">{t('description')}</Typography.Text>
        </div>
        <div className="ddos-v2-revision">
          <span>{t('status.label')}</span>
          <Tag color={document.status === 'active' ? 'green' : 'orange'}>{statusText}</Tag>
          <Button icon={<RefreshCw size={14} />} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>
        </div>
      </div>
      <Alert type="info" showIcon message={<>{t('notes.unit')}<br />{t('notes.exempt')}<br />{t('notes.udp')}</>} />
      <DDoSSummary value={document.value} />
      <PendingCategoriesNotice current="ddos_protection" pending={document.pending_categories} />
      {failure && <FeedbackWhen title={failure} />}
      <section className="ddos-v2-layer" aria-labelledby="ddos-layer-global">
        <header>
          <h2 id="ddos-layer-global" data-testid="ddos-global-baseline">{t('layers.global')}</h2>
          <p>{t('layers.globalHint')}</p>
        </header>
        <Form<FormValues> form={form} layout="vertical" disabled={!canManage || busy}
          onFinish={(values) => save.mutate(values)}>
          <div className="ddos-v2-grid">
            {/* Two columns of about equal height. Left, the per-connection
                limits and the CC kernel ban; right, packet filtering and the exemptions. The shorter column's
                last card stretches. */}
            <div className="ddos-v2-col">
              <section className="ddos-v2-section" id="ddos-section-client">
                <h3>{t('sections.perClient')}</h3>
                <div className="ddos-v2-fields is-four">
                  {shortNumber('max_connections_per_ip', 'maxConnectionsPerIP', 1_000_000)}
                  {shortNumber('new_connections_per_second', 'newPerSecond', 1_000_000)}
                  {shortNumber('new_connections_per_minute', 'newPerMinute', 60_000_000)}
                  <Form.Item name="rate_ban_seconds" {...short('rateBanSeconds')}
                    dependencies={['new_connections_per_second', 'new_connections_per_minute']}
                    rules={[{ required: true, type: 'integer', min: 0, max: 604_800 }, ({ getFieldValue }) => ({
                      validator: (_, value: number) => value > 0 && !getFieldValue('new_connections_per_second') &&
                        !getFieldValue('new_connections_per_minute')
                        ? Promise.reject(new Error(t('errors.banWithoutRate'))) : Promise.resolve(),
                    })]}>
                    <InputNumber min={0} max={604_800} precision={0} suffix={seconds} aria-label={t('fields.rateBanSeconds')} />
                  </Form.Item>
                </div>
                <Typography.Paragraph type="secondary" className="ddos-v2-note">{t('help.rateBan')}</Typography.Paragraph>
              </section>
              <section className="ddos-v2-section" id="ddos-section-port">
                <h3>{t('sections.port')}</h3>
                <div className="ddos-v2-fields">
                  {number('max_connections_per_port', t('fields.maxConnectionsPerPort'), 10_000_000)}
                </div>
              </section>
              <section className="ddos-v2-section" id="ddos-section-empty">
                <h3>{t('sections.empty')}</h3>
                <Form.Item className="ddos-v2-switch" name="empty_enabled" label={t('fields.emptyEnabled')} valuePropName="checked" extra={t('help.empty')}>
                  <Switch />
                </Form.Item>
                {emptyEnabled && (
                  <div className="ddos-v2-fields is-four">
                    <Form.Item name="idle_seconds" {...short('idleSeconds')} rules={[{ required: true, type: 'integer', min: 5, max: 600 }]}>
                      <InputNumber min={5} max={600} precision={0} suffix={seconds} aria-label={t('fields.idleSeconds')} />
                    </Form.Item>
                    <Form.Item name="threshold" {...short('threshold')} rules={[{ required: true, type: 'integer', min: 3, max: 10_000 }]}>
                      <InputNumber min={3} max={10_000} precision={0} suffix={t('units.times')} aria-label={t('fields.threshold')} />
                    </Form.Item>
                    <Form.Item name="window_seconds" {...short('windowSeconds')} rules={[{ required: true, type: 'integer', min: 10, max: 3_600 }]}>
                      <InputNumber min={10} max={3_600} precision={0} suffix={seconds} aria-label={t('fields.windowSeconds')} />
                    </Form.Item>
                    <Form.Item name="ban_seconds" {...short('banSeconds')} rules={[{ required: true, type: 'integer', min: 1, max: 604_800 }]}>
                      <InputNumber min={1} max={604_800} precision={0} suffix={seconds} aria-label={t('fields.banSeconds')} />
                    </Form.Item>
                  </div>
                )}
              </section>
              <section className="ddos-v2-section" id="ddos-section-cc">
                <h3>{t('sections.cc')}</h3>
                <div className="ddos-v2-fields">
                  <Form.Item name="cc_kernel_ban" label={t('fields.ccKernelBan')}>
                    <Select options={(['off', 'exclusive_ports', 'site_ports'] as const).map((mode) => ({
                      value: mode, label: t(`ccModes.${mode}`),
                    }))} />
                  </Form.Item>
                </div>
                <Typography.Paragraph type="secondary" className="ddos-v2-note">{t('help.cc')}</Typography.Paragraph>
              </section>
            </div>
            <div className="ddos-v2-col">
              <section className="ddos-v2-section" id="ddos-section-packets">
                <h3>{t('sections.packets')}</h3>
                <Form.Item className="ddos-v2-switch" name="tcp_flag_filter" label={t('fields.tcpFlagFilter')} valuePropName="checked" extra={t('help.tcpFlagFilter')}>
                  <Switch />
                </Form.Item>
                <Form.Item name="tcp_flag_types" label={t('fields.tcpFlagTypes')} extra={t('help.tcpFlagTypes')}
                  dependencies={['tcp_flag_filter']}
                  rules={[({ getFieldValue }) => ({
                    validator: (_, value: TCPFlagType[] | undefined) => getFieldValue('tcp_flag_filter') && !(value?.length)
                      ? Promise.reject(new Error(t('errors.tcpFlagTypes'))) : Promise.resolve(),
                  })]}>
                  <Checkbox.Group disabled={!canManage || !flagFilter} options={tcpFlagTypes.map((kind) => ({
                    value: kind, label: t(`tcpFlagTypes.${kind}`),
                  }))} />
                </Form.Item>
                <Form.Item className="ddos-v2-switch" name="drop_invalid" label={t('fields.dropInvalid')} valuePropName="checked" extra={t('help.dropInvalid')}>
                  <Switch />
                </Form.Item>
              </section>
              <section className="ddos-v2-section" id="ddos-section-allow">
                <h3>{t('sections.allow')}</h3>
                <Form.Item name="allow_networks" label={t('fields.allowNetworks')} rules={[{
                  validator: (_, value: string | undefined) => {
                    const lines = (value ?? '').split('\n').map((line) => line.trim())
                    const bad = lines.findIndex((line) => line !== '' && !networkPattern.test(line))
                    return bad >= 0 ? Promise.reject(new Error(t('errors.network', { line: bad + 1 }))) : Promise.resolve()
                  },
                }]}>
                  <Input.TextArea rows={4} spellCheck={false} />
                </Form.Item>
              </section>
            </div>
          </div>
          {canManage && (
            <div className={`site-edit-savebar${dirty > 0 ? ' is-dirty' : ''}`} data-testid="ddos-savebar">
              <div className="ddos-v2-savebar-left">
                <LifecycleSteps status={document.head_revision === 0 ? null : document.status} />
                <span className="site-edit-savebar-status" role="status">
                  {dirty > 0
                    ? <><Tag color="warning">{t('v2.dirty')}</Tag>{t('v2.dirtyCount', { count: dirty })}</>
                    : <span className="site-edit-savebar-clean">{t('v2.clean')}</span>}
                </span>
              </div>
              <div className="site-edit-savebar-actions">
                {dirty > 0 && <Button disabled={busy} onClick={() => form.setFieldsValue(loaded)}>{t('v2.discard')}</Button>}
                <Button type="primary" htmlType="submit" icon={<Save size={14} />} loading={save.isPending}>{t('actions.save')}</Button>
                <Button icon={<CheckCircle size={14} />} disabled={document.status !== 'draft' || busy}
                  onClick={() => lifecycle.mutate('preflight')}>{t('actions.preflight')}</Button>
                <Button icon={<Rocket size={14} />} disabled={document.status !== 'validated' || busy}
                  onClick={() => confirmPending(document.pending_categories, () => lifecycle.mutate('activate'))}>{t('actions.activate')}</Button>
              </div>
            </div>
          )}
        </Form>
      </section>
      {canReadNodes ? <NodeReceipts /> : null}
    </div>
  )
}

/** DDoSSummary: the stored revision's key values, each a jump to its section. */
function DDoSSummary({ value }: { value: DDoSProtectionConfiguration }) {
  const { t } = useTranslation('ddosProtectionSettings')
  const limit = (amount: number, format?: (value: number) => string): Pick<SummaryItem, 'value' | 'tone'> => amount > 0
    ? { value: format ? format(amount) : String(amount), tone: 'plain' } : { value: t('v2.off'), tone: 'off' }
  const flag = (on: boolean | undefined): Pick<SummaryItem, 'value' | 'tone'> => on ? { value: t('v2.on'), tone: 'on' } : { value: t('v2.off'), tone: 'off' }
  const rates = [
    value.new_connections_per_second > 0 ? t('v2.perSecond', { value: value.new_connections_per_second }) : '',
    value.new_connections_per_minute > 0 ? t('v2.perMinute', { value: value.new_connections_per_minute }) : '',
  ].filter(Boolean).join(' · ')
  const items: SummaryItem[] = [
    { key: 'ip', label: t('fields.maxConnectionsPerIP'), target: 'ddos-section-client', ...limit(value.max_connections_per_ip) },
    { key: 'rate', label: t('v2.rate'), target: 'ddos-section-client', ...(rates ? { value: rates, tone: 'plain' as const } : { value: t('v2.off'), tone: 'off' as const }) },
    { key: 'port', label: t('fields.maxConnectionsPerPort'), target: 'ddos-section-port', ...limit(value.max_connections_per_port) },
    { key: 'empty', label: t('sections.empty'), target: 'ddos-section-empty', ...flag(value.empty_connection !== undefined) },
    { key: 'flags', label: t('fields.tcpFlagFilter'), target: 'ddos-section-packets', ...flag(value.tcp_flag_filter) },
    { key: 'invalid', label: t('fields.dropInvalid'), target: 'ddos-section-packets', ...flag(value.drop_invalid) },
    { key: 'cc', label: t('sections.cc'), target: 'ddos-section-cc', ...(value.cc_kernel_ban === 'off'
      ? { value: t('v2.off'), tone: 'off' as const } : { value: t(`ccModes.${value.cc_kernel_ban}`), tone: 'on' as const }) },
    { key: 'allow', label: t('sections.allow'), target: 'ddos-section-allow', value: t('v2.allowCount', { count: value.allow_networks.length }) },
  ]
  return <SiteTabSummary items={items} />
}

/** LifecycleSteps: 保存草稿 → 检查 → 启用下发, marked from the stored revision's status. */
function LifecycleSteps({ status }: { status: Document['status'] | null }) {
  const { t } = useTranslation('ddosProtectionSettings')
  // Index of the step to do next; 3 = every step done (the revision is active).
  const next = status === null ? 0 : status === 'draft' ? 1 : status === 'validated' ? 2 : 3
  const steps = ['save', 'preflight', 'activate'] as const
  return (
    <ol className="ddos-v2-steps" aria-label={t('v2.steps.label')}>
      {steps.map((step, index) => {
        const state = index < next ? 'is-done' : index === next ? 'is-current' : ''
        return (
          <li key={step} className={state} aria-current={index === next ? 'step' : undefined}>
            <span className="ddos-v2-step-mark" aria-hidden="true">{index < next ? <Check size={12} strokeWidth={3} /> : index + 1}</span>
            {t(`v2.steps.${step}`)}
          </li>
        )
      })}
    </ol>
  )
}
