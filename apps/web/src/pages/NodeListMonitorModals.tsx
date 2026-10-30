import { useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Form, Input, Modal, Radio, Select, Switch, Table, Tag, Tooltip } from 'antd'
import dayjs, { type Dayjs } from 'dayjs'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  nodeMonitoringApi, nodeMonitoringHistoryMaxWindowMs, nodeServingEventsMaxWindowMs,
  type NodeDNSPupGroup, type NodeDNSPupHistoryItem, type NodeMonitoringHistoryItem, type NodePeerHistoryItem, type NodeMonitoringOverrideFields,
  type NodeServingEvent,
} from '../api/nodeMonitoring'
import { probeDNSPupModule } from '../api/probeDNSPup'
import { useGrantedModules } from '../components/useGrantedModules'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { TimeRangeFilter } from '@cdnca/ui'

const monitorGroups = ['domestic', 'telecom', 'unicom', 'mobile', 'overseas'] as const

type MonitorConfigForm = {
  enabled: boolean
  protocol: 'tcp' | 'http' | 'ping'
  timeout: string
  port: string
  action: 'none' | 'pause'
}

function writeKey(operation: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `${operation}-${suffix}`
}

// Edits this node's monitoring override. A field equal to the active platform
// policy is saved as null (inherit), so the node keeps following later global
// changes for it. Monitor groups stay unavailable (no carrier probe points).
export function NodeMonitorConfigModal({ nodeID, open, canManage, queryOwner, getAccessToken, onSaved, onClose }: {
  nodeID: string
  open: boolean
  canManage: boolean
  queryOwner: readonly unknown[]
  getAccessToken: (permission: 'read' | 'manage') => string | null
  onSaved: () => void
  onClose: () => void
}) {
  const { t, i18n } = useTranslation('nodes')
  const locale = i18n.resolvedLanguage ?? i18n.language
  const [form] = Form.useForm<MonitorConfigForm>()
  const [saveError, setSaveError] = useState<ApiError | null>(null)
  const query = useQuery({
    queryKey: ['node-monitoring-override', ...queryOwner, nodeID] as const,
    enabled: open,
    retry: false,
    queryFn: async ({ signal }) => {
      const token = getAccessToken('read')
      if (!token) throw new ApiError('Node access changed', 403, 'permission_denied')
      return nodeMonitoringApi.getOverride(token, nodeID, signal)
    },
  })
  const view = query.data
  const policy = view?.effective_policy ?? null
  const initial = useMemo<MonitorConfigForm | null>(() => view ? {
    enabled: policy?.enabled ?? view.override.monitor_enabled ?? true,
    protocol: policy?.requested_protocol ?? view.override.protocol ?? 'tcp',
    timeout: policy ? String(policy.probe_timeout_ms / 1000)
      : view.override.probe_timeout_ms === null ? '' : String(view.override.probe_timeout_ms / 1000),
    port: policy?.requested_port != null ? String(policy.requested_port)
      : view.override.monitor_port === null ? '' : String(view.override.monitor_port),
    action: (view.effective_action || view.override.monitor_action) === 'pause' ? 'pause' : 'none',
  } : null, [policy, view])
  const save = useMutation({
    mutationFn: async (values: MonitorConfigForm) => {
      const token = getAccessToken('manage')
      if (!token || !view) throw new ApiError('Node access changed', 403, 'permission_denied')
      // A field left as shown and not yet overridden stays null (inherit); the
      // shown value of such a field is the platform policy's.
      const untouched = (field: keyof NodeMonitoringOverrideFields, key: keyof MonitorConfigForm) =>
        view.override[field] === null && String(values[key]).trim() === String(initial?.[key] ?? '').trim()
      const timeout = values.timeout.trim()
      const port = values.port.trim()
      const override: NodeMonitoringOverrideFields = {
        monitor_enabled: untouched('monitor_enabled', 'enabled') ? null : values.enabled,
        protocol: untouched('protocol', 'protocol') ? null : values.protocol,
        probe_timeout_ms: timeout === '' || untouched('probe_timeout_ms', 'timeout') ? null : Math.round(Number(timeout) * 1000),
        monitor_port: port === '' || untouched('monitor_port', 'port') ? null : Number(port),
        monitor_action: untouched('monitor_action', 'action') ? null : values.action,
      }
      return nodeMonitoringApi.putOverride(token, nodeID, view.revision, override, writeKey(`node-monitoring-override-${nodeID}`))
    },
    onSuccess: async () => {
      setSaveError(null)
      await query.refetch()
      onSaved()
      onClose()
    },
    onError: (error) => setSaveError(error instanceof ApiError ? error : new ApiError('', 0, 'unavailable')),
  })
  const loadError = query.error instanceof ApiError ? query.error : query.error ? new ApiError('', 0, 'unavailable') : null
  const intervalSeconds = policy ? policy.probe_interval_ms / 1000 : 60
  const editable = canManage && !!view && !save.isPending
  const saveMessage = saveError ? t(`monitorConfig.saveErrors.${['version_conflict', 'probe_timeout_exceeds_interval', 'validation_error', 'permission_denied']
    .includes(saveError.code) ? saveError.code : 'unavailable'}`) : null
  return (
    <Modal className="node-modal node-monitor-config-modal" title={t('monitorConfig.title')} open={open} width={550}
      onCancel={onClose} destroyOnHidden footer={[
        <Tooltip key="confirm" title={canManage ? undefined : t('monitorConfig.manageRequired')}>
          <Button type="primary" disabled={!editable} loading={save.isPending} onClick={() => form.submit()}>{t('monitorConfig.confirm')}</Button>
        </Tooltip>,
        <Button key="cancel" onClick={onClose}>{t('monitorConfig.cancel')}</Button>,
      ]}>
      {loadError ? <Alert className="node-modal-alert" type="error" showIcon
        message={loadError.status === 404 ? t('monitorLog.notFound') : t('monitorConfig.loadFailed')} /> : null}
      {view && view.platform_state !== 'active' ? <Alert className="node-modal-alert" type="info" showIcon
        message={t('monitorConfig.notActive')}
        description={<>{t('monitorConfig.notActiveDescription')} <Link to="/node/monitor-setting">{t('monitorConfig.openSettings')}</Link></>} /> : null}
      {view && view.platform_state === 'active' && view.delivery_state !== 'serving' ? <Alert className="node-modal-alert" type="info" showIcon
        message={t(`monitorConfig.delivery.${view.delivery_state}`)} /> : null}
      {saveMessage ? <Alert className="node-modal-alert" type="error" showIcon message={saveMessage} /> : null}
      {initial ? <Form<MonitorConfigForm> key={`${view?.revision}-${view?.effective_revision}`} form={form} initialValues={initial}
        className="node-monitor-config-form" layout="horizontal" colon={false}
        labelCol={{ flex: '90px' }} wrapperCol={{ flex: 1 }} disabled={!editable}
        onFinish={(values) => { setSaveError(null); save.mutate(values) }}>
        <Form.Item name="enabled" label={t('monitorConfig.fields.enabled')} valuePropName="checked">
          <Switch aria-label={t('monitorConfig.fields.enabled')} />
        </Form.Item>
        <Form.Item name="protocol" label={t('monitorConfig.fields.protocol')}>
          <Radio.Group name="node-monitor-config-protocol" aria-label={t('monitorConfig.fields.protocol')}>
            {(['http', 'ping', 'tcp'] as const).map((protocol) => (
              <Radio key={protocol} value={protocol}>{t(`monitor.protocols.${protocol}`)}</Radio>
            ))}
          </Radio.Group>
        </Form.Item>
        <Form.Item label={t('monitorConfig.fields.timeout')} htmlFor="node-monitor-config-timeout" required={!!policy}>
          <div className="node-list-input-addon">
            <Form.Item name="timeout" noStyle rules={[{
              validator: async (_, value: string) => {
                const text = String(value ?? '').trim()
                const seconds = Number(text)
                if (text === '' && !policy) return
                if (!/^\d+(\.\d{1,3})?$/.test(text) || seconds < 0.1 || seconds > Math.min(60, intervalSeconds)) {
                  throw new Error(t('monitorConfig.timeoutRange', { max: formatNumber(Math.min(60, intervalSeconds), locale) }))
                }
              },
            }]}>
              <Input id="node-monitor-config-timeout" inputMode="decimal" />
            </Form.Item>
            <span>{t('monitorConfig.seconds')}</span>
          </div>
        </Form.Item>
        <Form.Item name="port" label={t('monitorConfig.fields.port')} htmlFor="node-monitor-config-port" rules={[{
          validator: async (_, value: string) => {
            const text = String(value ?? '').trim()
            if (text !== '' && (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65535)) throw new Error(t('monitorConfig.portRange'))
          },
        }]}>
          <Input id="node-monitor-config-port" inputMode="numeric" placeholder={t('monitorConfig.defaultPort')} />
        </Form.Item>
        <Form.Item label={t('monitorConfig.fields.groups')} extra={<span className="node-list-item-help">{t('monitorConfig.groupsHelp')}</span>}>
          <Tooltip title={t('monitorConfig.groupsUnavailable')}>
            <span className="node-monitor-disabled-group">
              <Checkbox.Group aria-label={t('monitorConfig.fields.groups')} value={[]} disabled
                options={monitorGroups.map((group) => ({ value: group, label: t(`monitorConfig.groups.${group}`) }))} />
            </span>
          </Tooltip>
        </Form.Item>
        <Form.Item name="action" label={t('monitorConfig.fields.action')} extra={<span className="node-list-item-help">
          {t('monitorConfig.actionHelp')}{view?.override.monitor_action === null ? ` ${t('monitorConfig.actionInherited')}` : ''}</span>}>
          <Radio.Group name="node-monitor-config-action" aria-label={t('monitorConfig.fields.action')}
            options={[{ value: 'none', label: t('monitorConfig.actions.none') }, { value: 'pause', label: t('monitorConfig.actions.pause') }]} />
        </Form.Item>
      </Form> : null}
      {view ? <p className="node-list-item-help">{t('monitorConfig.overrideHint', {
        revision: formatNumber(view.revision, locale),
        effective: view.effective_revision === null ? t('monitor.noActive') : formatNumber(view.effective_revision, locale),
      })}</p> : null}
    </Modal>
  )
}

export function NodeMonitorLogModal({ nodeID, open, initialType, queryOwner, getAccessToken, onClose }: {
  nodeID: string
  open: boolean
  initialType?: 'aval' | 'serving'
  queryOwner: readonly unknown[]
  getAccessToken: () => string | null
  onClose: () => void
}) {
  const { t, i18n } = useTranslation('nodes')
  const locale = i18n.resolvedLanguage ?? i18n.language
  const [type, setType] = useState<'aval' | 'serving'>(initialType ?? 'aval')
  // Default today (00:00 to now); quick ranges are today / last 7 days / last 30 days / custom.
  const [rangePreset, setRangePreset] = useState('today')
  const [range, setRange] = useState<[Dayjs, Dayjs]>(() => {
    const now = dayjs()
    return [now.startOf('day'), now]
  })
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  // Data source: dnspup carrier checkpoints when
  // module.probe.dnspup is granted (the default then), the controller + peer
  // node probe log (the default without dnspup) or the node-local probe log.
  // The monitor group filters the dnspup checkpoints only.
  const dnspupInstalled = useGrantedModules(getAccessToken()).includes(probeDNSPupModule)
  // The chosen source is remembered per node in this browser; a
  // remembered dnspup without the plugin falls back below.
  const sourceKey = `cdnca.ui.nodeMonitorSource.${nodeID}`
  const [chosenSource, setChosenSource] = useState<'dnspup' | 'peer' | 'local' | null>(() => {
    const saved = window.localStorage.getItem(sourceKey)
    return saved === 'dnspup' || saved === 'peer' || saved === 'local' ? saved : null
  })
  const setSource = (value: 'dnspup' | 'peer' | 'local') => {
    setChosenSource(value)
    window.localStorage.setItem(sourceKey, value)
  }
  const source = chosenSource === 'dnspup' && !dnspupInstalled ? 'peer' : chosenSource ?? (dnspupInstalled ? 'dnspup' : 'peer')
  const [group, setGroup] = useState<'all' | NodeDNSPupGroup>('all')
  const dnspupLog = source === 'dnspup'
  const peerLog = source === 'peer'
  const maxWindow = type === 'serving' ? nodeServingEventsMaxWindowMs : nodeMonitoringHistoryMaxWindowMs
  const rangeValid = range[0].isBefore(range[1]) && range[1].diff(range[0]) <= maxWindow
  const historyWindow = useMemo(() => ({ from: range[0].toISOString(), to: range[1].toISOString() }), [range])
  const query = useQuery({
    queryKey: ['node-monitoring-history', ...queryOwner, nodeID, historyWindow.from, historyWindow.to, page, limit] as const,
    enabled: open && rangeValid && type === 'aval' && source === 'local',
    retry: false,
    queryFn: async ({ signal }) => {
      const token = getAccessToken()
      if (!token) throw new ApiError('Node access changed', 403, 'permission_denied')
      return nodeMonitoringApi.getHistory(token, nodeID, { ...historyWindow, page, limit }, signal)
    },
  })
  const dnspupQuery = useQuery({
    queryKey: ['node-dnspup-history', ...queryOwner, nodeID, group, historyWindow.from, historyWindow.to, page, limit] as const,
    enabled: open && rangeValid && type === 'aval' && dnspupLog,
    retry: false,
    queryFn: async ({ signal }) => {
      const token = getAccessToken()
      if (!token) throw new ApiError('Node access changed', 403, 'permission_denied')
      return nodeMonitoringApi.getDNSPupHistory(token, nodeID,
        { ...historyWindow, page, limit, group: group === 'all' ? '' : group }, signal)
    },
  })
  const peerQuery = useQuery({
    queryKey: ['node-peer-probe-history', ...queryOwner, nodeID, historyWindow.from, historyWindow.to, page, limit] as const,
    enabled: open && rangeValid && type === 'aval' && peerLog,
    retry: false,
    queryFn: async ({ signal }) => {
      const token = getAccessToken()
      if (!token) throw new ApiError('Node access changed', 403, 'permission_denied')
      return nodeMonitoringApi.getPeerHistory(token, nodeID, { ...historyWindow, page, limit }, signal)
    },
  })
  const servingQuery = useQuery({
    queryKey: ['node-serving-events', ...queryOwner, nodeID, historyWindow.from, historyWindow.to, page, limit] as const,
    enabled: open && rangeValid && type === 'serving',
    retry: false,
    queryFn: async ({ signal }) => {
      const token = getAccessToken()
      if (!token) throw new ApiError('Node access changed', 403, 'permission_denied')
      return nodeMonitoringApi.getServingEvents(token, nodeID, { ...historyWindow, page, limit }, signal)
    },
  })
  const active = type === 'serving' ? servingQuery : dnspupLog ? dnspupQuery : peerLog ? peerQuery : query
  const error = active.error instanceof ApiError ? active.error : active.error ? new ApiError('', 0, 'unavailable') : null
  const pagination = {
    current: page, pageSize: limit, total: active.data?.total ?? 0, showSizeChanger: true,
    pageSizeOptions: [10, 20, 50, 100], position: ['bottomLeft' as const],
    onChange: (nextPage: number, nextLimit: number) => {
      if (nextLimit !== limit) { setLimit(nextLimit); setPage(1) } else setPage(Math.min(nextPage, 1000))
    },
  }
  return (
    <Modal className="node-modal node-monitor-log-modal" title={t('monitorLog.title')} open={open} width={500}
      footer={null} onCancel={onClose} destroyOnHidden>
      <Form className="node-monitor-log-form" layout="horizontal" colon={false} labelCol={{ flex: '80px' }} wrapperCol={{ flex: 1 }}>
        <Form.Item label={t('monitorLog.fields.type')}>
          <Select aria-label={t('monitorLog.fields.type')} value={type} virtual={false} popupMatchSelectWidth
            onChange={(value: 'aval' | 'serving') => { setType(value); setPage(1) }}
            options={[{ value: 'aval', label: t('monitorLog.types.aval') }, { value: 'serving', label: t('monitorLog.types.serving') }]} />
        </Form.Item>
        <Form.Item label={t('monitorLog.fields.range')} validateStatus={rangeValid ? undefined : 'error'}
          help={rangeValid ? undefined : t(type === 'serving' ? 'monitorLog.servingRangeTooWide' : 'monitorLog.rangeTooWide')}>
          {/* Quick ranges count back from now; the longest window follows the log type (7 or 31 days). */}
          <TimeRangeFilter className="node-monitor-log-range" label={t('monitorLog.fields.range')} precision="second" allowClear={false}
            maxSpanMs={maxWindow} value={{ preset: rangePreset, range }}
            onChange={({ preset, range: next }) => {
              if (!next) return
              setRangePreset(preset)
              setRange(next)
              setPage(1)
            }} />
        </Form.Item>
        <Form.Item label={t('monitorLog.fields.source')}>
          <Select aria-label={t('monitorLog.fields.source')} value={source} virtual={false} popupMatchSelectWidth
            disabled={type === 'serving'} onChange={(value: typeof source) => { setSource(value); setPage(1) }}
            options={[...(dnspupInstalled ? [{ value: 'dnspup' as const, label: t('monitorLog.sources.dnspup') }] : []),
              { value: 'peer' as const, label: t('monitorLog.sources.peer') },
              { value: 'local' as const, label: t('monitorLog.sources.local') }]} />
        </Form.Item>
        <Form.Item label={t('monitorLog.fields.group')}>
          {dnspupInstalled ? <Select aria-label={t('monitorLog.fields.group')} value={group} virtual={false}
            disabled={type === 'serving' || !dnspupLog} onChange={(value: typeof group) => { setGroup(value); setPage(1) }}
            options={[{ value: 'all', label: t('monitorLog.allGroups') },
              ...monitorGroups.map((value) => ({ value, label: t(`monitorConfig.groups.${value}`) }))]} />
            : <Tooltip title={t('monitorLog.groupUnavailable')}>
              <span className="node-monitor-disabled-group">
                <Select aria-label={t('monitorLog.fields.group')} value="all" disabled
                  options={[{ value: 'all', label: t('monitorLog.allGroups') }]} />
              </span>
            </Tooltip>}
        </Form.Item>
      </Form>
      {error ? <Alert className="node-modal-alert" type="error" showIcon
        message={error.status === 404 ? t('monitorLog.notFound') : t('monitorLog.loadFailed')} /> : null}
      {type === 'serving' ? <Table<NodeServingEvent>
        className="node-monitor-log-table"
        size="small"
        rowKey="id"
        loading={servingQuery.isFetching}
        dataSource={servingQuery.data?.items ?? []}
        locale={{ emptyText: t('monitorLog.empty') }}
        columns={[
          { title: t('monitorLog.servingColumns.time'), dataIndex: 'occurred_at', render: (value: string) => formatDateTime(value, locale) },
          { title: t('monitorLog.servingColumns.event'), dataIndex: 'event', render: (value: NodeServingEvent['event']) => t(`monitorLog.servingEvents.${value}`) },
          { title: t('monitorLog.servingColumns.source'), dataIndex: 'source', render: (value: NodeServingEvent['source']) => t(`monitorLog.servingSources.${value}`) },
          { title: t('monitorLog.servingColumns.reason'), dataIndex: 'reason_code',
            render: (value: string) => t(`monitorLog.servingReasons.${value}`, { defaultValue: value }) },
        ]}
        pagination={pagination}
      /> : dnspupLog ? <Table<NodeDNSPupHistoryItem>
        className="node-monitor-log-table"
        size="small"
        rowKey={(item) => `${item.observed_at}-${item.address}-${item.port}`}
        loading={dnspupQuery.isFetching}
        dataSource={dnspupQuery.data?.items ?? []}
        locale={{ emptyText: t('monitorLog.dnspupEmpty') }}
        expandable={{
          rowExpandable: (item) => item.checkpoints.length > 0,
          expandedRowRender: (item) => <ul className="node-monitor-dnspup-points">
            {item.checkpoints.map((point) => <li key={point.id}>
              {t(`monitorConfig.groups.${point.group}`)} {point.location || point.id}
              {' '}{point.ok ? t('monitorLog.pointOK') : t('monitorLog.pointFailed')}
              {point.ok && point.latency_ms ? ` ${formatNumber(point.latency_ms, locale)} ms` : ''}
            </li>)}
          </ul>,
        }}
        columns={[
          { title: t('monitorLog.columns.time'), dataIndex: 'observed_at', render: (value: string) => formatDateTime(value, locale) },
          { title: t('monitorLog.columns.address'), key: 'address',
            render: (_: unknown, item: NodeDNSPupHistoryItem) => item.address.includes(':') ? `[${item.address}]:${item.port}` : `${item.address}:${item.port}` },
          { title: t('monitorLog.columns.failed'), dataIndex: 'failed_checks', render: (value: number) => formatNumber(value, locale) },
          { title: t('monitorLog.columns.total'), dataIndex: 'total_checks', render: (value: number) => formatNumber(value, locale) },
        ]}
        pagination={pagination}
      /> : peerLog ? <Table<NodePeerHistoryItem>
        className="node-monitor-log-table"
        size="small"
        rowKey={(item) => `${item.observed_at}-${item.address}-${item.port}`}
        loading={peerQuery.isFetching}
        dataSource={peerQuery.data?.items ?? []}
        locale={{ emptyText: t('monitorLog.peerEmpty') }}
        expandable={{
          rowExpandable: (item) => item.checkpoints.length > 0,
          expandedRowRender: (item) => <ul className="node-monitor-dnspup-points">
            {item.checkpoints.map((point) => <li key={point.id}>
              {point.id === 'controller' ? t('monitorLog.controllerPoint')
                : point.address ? `${point.name || point.id}（${point.address}）` : point.name || point.id}
              {' '}{point.ok ? t('monitorLog.pointOK') : t('monitorLog.pointFailed')}
              {point.ok && point.latency_ms ? ` ${formatNumber(point.latency_ms, locale)} ms` : ''}
            </li>)}
          </ul>,
        }}
        columns={[
          { title: t('monitorLog.columns.time'), dataIndex: 'observed_at', render: (value: string) => formatDateTime(value, locale) },
          { title: t('monitorLog.columns.address'), key: 'address',
            render: (_: unknown, item: NodePeerHistoryItem) => item.address.includes(':') ? `[${item.address}]:${item.port}` : `${item.address}:${item.port}` },
          { title: t('monitorLog.columns.failed'), dataIndex: 'failed_checks', render: (value: number) => formatNumber(value, locale) },
          { title: t('monitorLog.columns.total'), dataIndex: 'total_checks', render: (value: number) => formatNumber(value, locale) },
        ]}
        pagination={pagination}
      /> : <Table<NodeMonitoringHistoryItem>
        className="node-monitor-log-table"
        size="small"
        rowKey={(item) => `${item.observed_at}-${item.config_revision}`}
        loading={query.isFetching}
        dataSource={query.data?.items ?? []}
        locale={{ emptyText: t('monitorLog.empty') }}
        columns={[
          { title: t('monitorLog.columns.time'), dataIndex: 'observed_at', render: (value: string) => formatDateTime(value, locale) },
          { title: t('monitorLog.columns.failed'), dataIndex: 'failed_checks', render: (value: number) => formatNumber(value, locale) },
          { title: t('monitorLog.columns.total'), dataIndex: 'total_checks', render: (value: number) => formatNumber(value, locale) },
        ]}
        pagination={pagination}
      />}
      <p className="node-list-item-help">{t(type === 'serving' ? 'monitorLog.servingScopeHint'
        : dnspupLog ? 'monitorLog.dnspupScopeHint' : peerLog ? 'monitorLog.peerScopeHint' : 'monitorLog.scopeHint')}</p>
    </Modal>
  )
}

type BatchMonitorForm = {
  enabled: 'keep' | 'on' | 'off'
  protocol: 'keep' | 'tcp' | 'http' | 'ping'
  timeout: string
  port: string
  action: 'keep' | 'none' | 'pause'
}

export type BatchMonitorResult = {
  id: string
  name: string
  status: 'updated' | 'failed' | 'unknown'
  code?: string
  // Kept for an exact replay of a write whose outcome is unknown.
  replay?: { revision: number; override: NodeMonitoringOverrideFields; key: string }
}

export function batchMonitorOverride(current: NodeMonitoringOverrideFields, values: BatchMonitorForm): NodeMonitoringOverrideFields {
  const timeout = values.timeout.trim()
  const port = values.port.trim()
  return {
    monitor_enabled: values.enabled === 'keep' ? current.monitor_enabled : values.enabled === 'on',
    protocol: values.protocol === 'keep' ? current.protocol : values.protocol,
    probe_timeout_ms: timeout === '' ? current.probe_timeout_ms : Math.round(Number(timeout) * 1000),
    monitor_port: port === '' ? current.monitor_port : Number(port),
    monitor_action: values.action === 'keep' ? current.monitor_action : values.action,
  }
}

function unknownWrite(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

// 批量修改监控（「更多操作 → 修改监控」）：每个节点读当前覆盖版本后单独
// PUT（自带修订号与幂等键），只改填写的项，未填写的项保留节点原有设置。
// 结果逐项列出；结果未知的请求只允许原样重试，失败项可重新读取后再试。
export function NodeBatchMonitorConfigModal({ nodes, open, canManage, getAccessToken, onDenied, onDone, onClose }: {
  nodes: readonly { id: string; name: string }[]
  open: boolean
  canManage: boolean
  getAccessToken: (permission: 'read' | 'manage') => string | null
  onDenied: () => void
  onDone: () => void
  onClose: () => void
}) {
  const { t } = useTranslation('nodes')
  const [form] = Form.useForm<BatchMonitorForm>()
  const [pending, setPending] = useState(false)
  const [results, setResults] = useState<BatchMonitorResult[] | null>(null)
  const [values, setValues] = useState<BatchMonitorForm | null>(null)
  const run = async (targets: readonly { id: string; name: string }[], formValues: BatchMonitorForm, previous: BatchMonitorResult[] | null) => {
    setPending(true)
    const next = new Map((previous ?? []).map((item) => [item.id, item]))
    for (const node of targets) {
      const token = getAccessToken('manage')
      if (!token) { onDenied(); setPending(false); return }
      const prior = next.get(node.id)
      let replay = prior?.status === 'unknown' ? prior.replay : undefined
      try {
        if (!replay) {
          const view = await nodeMonitoringApi.getOverride(token, node.id)
          replay = { revision: view.revision, override: batchMonitorOverride(view.override, formValues), key: writeKey(`node-monitoring-override-${node.id}`) }
        }
        await nodeMonitoringApi.putOverride(token, node.id, replay.revision, replay.override, replay.key)
        next.set(node.id, { id: node.id, name: node.name, status: 'updated' })
      } catch (error) {
        if (error instanceof ApiError && error.status === 403) { onDenied(); setPending(false); return }
        next.set(node.id, unknownWrite(error) && replay
          ? { id: node.id, name: node.name, status: 'unknown', replay }
          : { id: node.id, name: node.name, status: 'failed', code: error instanceof ApiError ? error.code : 'unavailable' })
      }
    }
    setResults(nodes.map((node) => next.get(node.id)).filter((item): item is BatchMonitorResult => Boolean(item)))
    setPending(false)
    onDone()
  }
  const retryTargets = (results ?? []).filter((item) => item.status !== 'updated')
  const closable = !pending && !retryTargets.some((item) => item.status === 'unknown')
  const errorText = (code?: string) => t(`monitorConfig.saveErrors.${['version_conflict', 'probe_timeout_exceeds_interval', 'validation_error', 'permission_denied', 'node_not_found']
    .includes(code ?? '') ? code : 'unavailable'}`)
  return (
    <Modal className="node-modal node-monitor-config-modal" open={open} width={550} destroyOnHidden maskClosable={false}
      title={results ? t('batchMonitor.resultsTitle') : t('batchMonitor.title', { count: nodes.length })}
      closable={closable} onCancel={() => { if (closable) onClose() }}
      footer={results ? [
        retryTargets.length ? <Button key="retry" type="primary" loading={pending} onClick={() => values && void run(retryTargets, values, results)}>
          {t('batchMonitor.retry', { count: retryTargets.length })}</Button> : null,
        <Button key="close" disabled={!closable} onClick={onClose}>{t('actions.close')}</Button>,
      ] : [
        <Tooltip key="confirm" title={canManage ? undefined : t('monitorConfig.manageRequired')}>
          <Button type="primary" disabled={!canManage || nodes.length === 0} loading={pending} onClick={() => form.submit()}>{t('monitorConfig.confirm')}</Button>
        </Tooltip>,
        <Button key="cancel" disabled={pending} onClick={onClose}>{t('monitorConfig.cancel')}</Button>,
      ]}>
      {results ? (
        <>
          {retryTargets.some((item) => item.status === 'unknown') ? <Alert className="node-modal-alert" type="warning" showIcon message={t('batchMonitor.unknownHint')} /> : null}
          <div className="node-result-list cdnca-dialog-scroll">
            {results.map((item) => (
              <div key={item.id}>
                <span className="node-result-id" title={item.id}>{item.name}</span>
                {item.status === 'updated' ? <Tag color="success">{t('batchMonitor.updated')}</Tag>
                  : item.status === 'unknown' ? <Tag color="warning">{t('batchMonitor.unknown')}</Tag>
                    : <Tag color="error">{errorText(item.code)}</Tag>}
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          <Alert className="node-modal-alert" type="info" showIcon message={t('batchMonitor.help')} />
          <Form<BatchMonitorForm> form={form} layout="horizontal" colon={false} labelCol={{ flex: '90px' }} wrapperCol={{ flex: 1 }}
            disabled={pending || !canManage}
            initialValues={{ enabled: 'keep', protocol: 'keep', timeout: '', port: '', action: 'keep' }}
            onFinish={(formValues) => {
              const changed = formValues.enabled !== 'keep' || formValues.protocol !== 'keep' || formValues.action !== 'keep' ||
                formValues.timeout.trim() !== '' || formValues.port.trim() !== ''
              if (!changed) { form.setFields([{ name: 'enabled', errors: [t('batchMonitor.nothing')] }]); return }
              setValues(formValues)
              void run(nodes, formValues, null)
            }}>
            <Form.Item name="enabled" label={t('monitorConfig.fields.enabled')}>
              <Radio.Group name="node-batch-monitor-enabled" options={[
                { value: 'keep', label: t('batchMonitor.keep') }, { value: 'on', label: t('batchMonitor.on') }, { value: 'off', label: t('batchMonitor.off') }]} />
            </Form.Item>
            <Form.Item name="protocol" label={t('monitorConfig.fields.protocol')}>
              <Radio.Group name="node-batch-monitor-protocol" options={[{ value: 'keep', label: t('batchMonitor.keep') },
                ...(['http', 'ping', 'tcp'] as const).map((protocol) => ({ value: protocol, label: t(`monitor.protocols.${protocol}`) }))]} />
            </Form.Item>
            <Form.Item name="timeout" label={t('monitorConfig.fields.timeout')} rules={[{
              validator: async (_, value: string) => {
                const text = String(value ?? '').trim()
                if (text !== '' && (!/^\d+(\.\d{1,3})?$/.test(text) || Number(text) < 0.1 || Number(text) > 60)) throw new Error(t('batchMonitor.timeoutRange'))
              },
            }]}>
              <Input id="node-batch-monitor-timeout" inputMode="decimal" placeholder={t('batchMonitor.blankKeeps')} suffix={t('monitorConfig.seconds')} />
            </Form.Item>
            <Form.Item name="port" label={t('monitorConfig.fields.port')} rules={[{
              validator: async (_, value: string) => {
                const text = String(value ?? '').trim()
                if (text !== '' && (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65535)) throw new Error(t('monitorConfig.portRange'))
              },
            }]}>
              <Input id="node-batch-monitor-port" inputMode="numeric" placeholder={t('batchMonitor.blankKeeps')} />
            </Form.Item>
            <Form.Item name="action" label={t('monitorConfig.fields.action')} extra={<span className="node-list-item-help">{t('monitorConfig.actionHelp')}</span>}>
              <Radio.Group name="node-batch-monitor-action" options={[{ value: 'keep', label: t('batchMonitor.keep') },
                { value: 'none', label: t('monitorConfig.actions.none') }, { value: 'pause', label: t('monitorConfig.actions.pause') }]} />
            </Form.Item>
          </Form>
        </>
      )}
    </Modal>
  )
}
