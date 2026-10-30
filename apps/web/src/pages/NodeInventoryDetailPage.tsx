import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { nodeInstallationTicketsApi } from '../api/nodeInstallationTickets'
import { NodeFrozenTag, useNodeFrozenText } from '../components/NodeFrozenTag'
import { Alert, App, Button, Descriptions, Form, Input, InputNumber, Modal, Result, Space, Spin, Tag, Typography } from 'antd'
import { Check, Plus, RefreshCw, RotateCcw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  nativeRuntimeSummary,
  nodesApi,
  type CreateNodeGatewayPortTransitionRequest,
  type NodeGatewayPortTransition,
  type NodeDDoSProtection,
  type NodeInventoryItem,
} from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { NodeConfigurationScopesPanel } from '../components/NodeConfigurationScopesPanel'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/nodeInventoryDetail'
import './NodeListPage.locale'
import { FeedbackWhen } from '@cdnca/ui'

type Owner = readonly ['platform', string, null, string, number]

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleRead = new Error('Node inventory detail owner changed during read')
const queryRoot = 'node-inventory-detail'

const stateColors: Record<NodeInventoryItem['admin_state'], string> = {
  pending: 'warning', active: 'success', draining: 'processing', disabled: 'default', retired: 'error',
}
const presenceColors: Record<NodeInventoryItem['presence']['status'], string> = {
  online: 'success', offline: 'default', unknown: 'warning',
}
const freshnessColors: Record<NodeInventoryItem['presence']['projection_freshness'], string> = {
  fresh: 'success', stale: 'warning', never: 'default',
}
const leaseColors: Record<NodeInventoryItem['presence']['lease_signal'], string> = {
  present: 'success', absent: 'default', unavailable: 'warning',
}

function detailOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null ||
    !principal.scope_id.trim() || !principal.user_id.trim() || sessionEpoch < 1) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.permissions.includes('nodes.read') || principal.permissions.includes('platform.admin')
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal)) return null
  const owner = detailOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function canManage(principal: Principal): boolean {
  return principal.permissions.includes('nodes.manage') || principal.permissions.includes('platform.admin')
}

function displayTime(value: string | undefined, locale: string, fallback: string): string {
  return value ? formatDateTime(value, locale) || fallback : fallback
}

interface TransitionFormValues {
  oldAddress: string
  oldListenAddress: string
  oldServerName: string
  newAddress: string
  newListenAddress: string
  newServerName: string
  compatibilityMinutes: number
  rollbackMinutes: number
}

function endpointFromForm(values: TransitionFormValues, prefix: 'old' | 'new') {
  return {
    address: values[`${prefix}Address`],
    listen_address: values[`${prefix}ListenAddress`],
    server_name: values[`${prefix}ServerName`],
  }
}

function deadline(minutes: number): string {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString()
}

function transitionErrorMessage(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError) {
    if (error.code === 'node_port_transition_conflict') return t('errors.transitionConflict')
    if (error.code === 'node_port_transition_invalid') return t('errors.transitionInvalid')
    if (error.code === 'node_port_transition_not_found') return t('errors.transitionNotFound')
  }
  return t('errors.transitionUnavailable')
}

function TransitionPanel({
  accessToken,
  nodeID,
  transition,
  onChange,
}: {
  accessToken: string
  nodeID: string
  transition: NodeGatewayPortTransition
  onChange: (next: NodeGatewayPortTransition) => void
}) {
  const { t, i18n } = useTranslation('nodeInventoryDetail')
  const { message } = App.useApp()
  const [pendingAction, setPendingAction] = useState<'finalize' | 'rollback' | null>(null)
  const [actionError, setActionError] = useState('')
  const locale = i18n.resolvedLanguage ?? i18n.language
  const canFinalize = transition.state === 'switched'
  const canRollback = transition.state === 'switching' || transition.state === 'switched' || transition.state === 'failed'

  const action = async (name: 'finalize' | 'rollback') => {
    setPendingAction(name)
    setActionError('')
    try {
      const next = await nodesApi.gatewayPortTransitionAction(accessToken, nodeID, transition.id, name, crypto.randomUUID())
      onChange(next)
      message.success(name === 'finalize' ? t('transition.finalized') : t('transition.rollbackAccepted'))
    } catch (error) {
      setActionError(transitionErrorMessage(error, t))
    } finally {
      setPendingAction(null)
    }
  }

  return (
    <section className="node-port-transition" aria-labelledby="node-port-transition-title">
      <header className="identity-page-header">
        <div>
          <Typography.Title level={4} id="node-port-transition-title">{t('transition.title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('transition.revision', { revision: transition.revision })}</Typography.Paragraph>
        </div>
        <Tag color={transition.state === 'failed' ? 'error' : transition.state === 'finalized' ? 'success' : 'processing'}>
          {t(`transition.states.${transition.state}`)}
        </Tag>
      </header>
      {actionError && <FeedbackWhen title={actionError} />}
      <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
        <Descriptions.Item label={t('transition.fields.oldEndpoint')}>
          <Typography.Text code>{transition.old_endpoint.address}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('transition.fields.newEndpoint')}>
          <Typography.Text code>{transition.new_endpoint.address}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('transition.fields.activeEndpoint')}>
          <Typography.Text code>{transition.active_endpoint.address}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('transition.fields.compatibilityDeadline')}>
          {displayTime(transition.compatibility_deadline, locale, t('telemetry.notReported'))}
        </Descriptions.Item>
        <Descriptions.Item label={t('transition.fields.rollbackDeadline')}>
          {displayTime(transition.rollback_deadline, locale, t('telemetry.notReported'))}
        </Descriptions.Item>
        <Descriptions.Item label={t('transition.fields.statusRevision')}>
          {transition.status_revision}
        </Descriptions.Item>
      </Descriptions>
      {(canFinalize || canRollback) && (
        <Space className="node-port-transition-actions" wrap>
          {canFinalize && (
            <Button type="primary" icon={<Check size={16} aria-hidden="true" />} loading={pendingAction === 'finalize'} onClick={() => void action('finalize')}>
              {t('transition.actions.finalize')}
            </Button>
          )}
          {canRollback && (
            <Button icon={<RotateCcw size={16} aria-hidden="true" />} loading={pendingAction === 'rollback'} onClick={() => void action('rollback')}>
              {t('transition.actions.rollback')}
            </Button>
          )}
        </Space>
      )}
    </section>
  )
}

const protectionColors: Record<NodeDDoSProtection['state'], string> = {
  applied: 'green', off: 'default', pending: 'blue', failed: 'red', unavailable: 'orange',
}

// The node's DDoS protection table state (telemetry ddos_protection)
// in its own block; the node list only shows faults in the XDP column.
function ProtectionPanel({ nodeID, queryKey, accessToken }: {
  nodeID: string; queryKey: readonly unknown[]; accessToken: () => string | null
}) {
  const { t, i18n } = useTranslation('nodeInventoryDetail')
  const { t: tn } = useTranslation('nodes')
  const latest = useQuery({
    // Under the owner-scoped detail key: a new session drops it with the detail.
    queryKey: [...queryKey, 'protection'],
    queryFn: () => {
      const token = accessToken()
      if (!token) throw staleRead
      return nodesApi.getLatestMetrics(token, nodeID)
    },
    retry: false,
    refetchOnWindowFocus: false,
  })
  const locale = i18n.resolvedLanguage ?? i18n.language
  const protection = latest.data?.known ? latest.data.telemetry?.ddos_protection : undefined
  return (
    <section className="node-inventory-protection" aria-labelledby="node-inventory-protection-title">
      <Typography.Title level={4} id="node-inventory-protection-title">{t('protection.title')}</Typography.Title>
      {latest.isPending ? <Spin size="small" />
        : latest.isError ? <Alert type="warning" showIcon message={t('protection.loadFailed')} />
          : !protection ? <Typography.Text type="secondary">{t('protection.notReported')}</Typography.Text>
            : (
              <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
                <Descriptions.Item label={t('protection.state')}>
                  <Tag color={protectionColors[protection.state]}>{tn(`ddosProtection.states.${protection.state}`)}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label={t('protection.observedAt')}>
                  {displayTime(latest.data?.observed_at, locale, t('telemetry.notReported'))}
                </Descriptions.Item>
                {protection.state === 'unavailable' || protection.state === 'failed' ? (
                  <Descriptions.Item label={t('protection.reason')} span={2}>
                    {protection.state === 'unavailable' ? tn(`ddosProtection.reasons.${protection.reason}`) : tn('ddosProtection.failedHint')}
                  </Descriptions.Item>
                ) : null}
                {protection.detail ? (
                  <Descriptions.Item label={t('protection.detail')} span={2}>
                    <Typography.Text code>{protection.detail}</Typography.Text>
                  </Descriptions.Item>
                ) : null}
              </Descriptions>
            )}
    </section>
  )
}

function DetailContent({ owner, ownerKey, nodeID }: { owner: Owner; ownerKey: string; nodeID: string }) {
  const { t, i18n } = useTranslation('nodeInventoryDetail')
  const { message } = App.useApp()
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const lineageActiveRef = useRef(true)
  const prefix = useMemo(() => [queryRoot, ...fixedOwner] as const, [fixedOwner])
  const queryKey = useMemo(() => [...prefix, nodeID] as const, [nodeID, prefix])
  const currentSessionAccess = useCallback(
    () => lineageActiveRef.current ? currentAccess(ownerKey) : null,
    [ownerKey],
  )
  const canManageSession = useCallback(() => {
    const { principal } = useSessionStore.getState()
    return lineageActiveRef.current && !!principal && canManage(principal) && !!currentSessionAccess()
  }, [currentSessionAccess])
  const [transition, setTransition] = useState<NodeGatewayPortTransition | null>(null)
  const [transitionOpen, setTransitionOpen] = useState(false)
  const [transitionSubmitting, setTransitionSubmitting] = useState(false)
  const [transitionError, setTransitionError] = useState('')
  const [transitionForm] = Form.useForm<TransitionFormValues>()
  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token) throw staleRead
      try {
        const result = await nodesApi.get(token, nodeID)
        if (!currentSessionAccess()) throw staleRead
        return result
      } catch (error) {
        if (!currentSessionAccess()) throw staleRead
        throw error
      }
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  // The node's last reported service ticket; frozen shows
  // reason and recovery here. A failed read leaves the row as not reported.
  const ticketQuery = useQuery({
    queryKey: [...queryKey, 'installation-ticket'],
    queryFn: async ({ signal }) => {
      const token = currentSessionAccess()
      if (!token) throw staleRead
      const result = await nodeInstallationTicketsApi.get(token, [nodeID], signal)
      if (!currentSessionAccess()) throw staleRead
      return result.items[0]
    },
    // Read with the detail it belongs to (and again on its refresh).
    enabled: query.isSuccess,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const frozenDetails = useNodeFrozenText(ticketQuery.data)

  const submitTransition = async (values: TransitionFormValues) => {
    const token = currentSessionAccess()
    if (!token || !canManageSession()) return
    if (values.rollbackMinutes <= values.compatibilityMinutes) {
      setTransitionError(t('errors.rollbackWindow'))
      return
    }
    setTransitionSubmitting(true)
    setTransitionError('')
    const input: CreateNodeGatewayPortTransitionRequest = {
      expected_node_revision: query.data?.revision ?? 0,
      old_endpoint: endpointFromForm(values, 'old'),
      new_endpoint: endpointFromForm(values, 'new'),
      compatibility_deadline: deadline(values.compatibilityMinutes),
      rollback_deadline: deadline(values.rollbackMinutes),
    }
    try {
      const created = await nodesApi.createGatewayPortTransition(token, nodeID, input, crypto.randomUUID())
      setTransition(created)
      setTransitionOpen(false)
      transitionForm.resetFields()
      message.success(t('transition.created'))
    } catch (error) {
      setTransitionError(transitionErrorMessage(error, (key) => t(key)))
    } finally {
      setTransitionSubmitting(false)
    }
  }

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      void queryClient.cancelQueries({ queryKey: prefix })
      queryClient.removeQueries({ queryKey: prefix })
    }
  }, [prefix, queryClient])

  const error = query.error instanceof ApiError ? query.error : null
  if (error?.status === 403) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  if (error?.status === 404) {
    return <Result status="404" title={t('errors.notFoundTitle')} subTitle={t('errors.notFoundDescription')} />
  }
  if (query.isPending) {
    return (
      <div className="data-state" aria-label={t('data.loading')} aria-busy="true">
        <Spin size="small" />
      </div>
    )
  }
  if (query.isError || !query.data) {
    const message = error?.code === 'invalid_response' ? t('errors.invalidResponse') : t('errors.unavailable')
    return <DataState status="error" message={message} onRetry={() => void query.refetch()} />
  }

  const item = query.data
  const presence = item.presence
  const locale = i18n.resolvedLanguage ?? i18n.language
  const fallback = t('telemetry.notReported')
  return (
    <section className="identity-page node-inventory-detail-page" aria-labelledby="node-inventory-detail-title">
      <header className="identity-page-header">
        <div>
          <Typography.Title level={2} id="node-inventory-detail-title">{item.name}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('title')}</Typography.Paragraph>
        </div>
        <Space wrap>
          {canManageSession() && (
            <Button type="primary" icon={<Plus size={16} aria-hidden="true" />} onClick={() => {
              setTransitionError('')
              transitionForm.setFieldsValue({ compatibilityMinutes: 30, rollbackMinutes: 60 })
              setTransitionOpen(true)
            }}>
              {t('transition.actions.start')}
            </Button>
          )}
          <Button icon={<RefreshCw size={16} aria-hidden="true" />} loading={query.isFetching} onClick={() => { void query.refetch(); void ticketQuery.refetch() }}>
            {t('actions.refresh')}
          </Button>
        </Space>
      </header>
      <Descriptions bordered size="small" column={{ xs: 1, sm: 2, lg: 3 }}>
        <Descriptions.Item label={t('fields.id')}>{item.id}</Descriptions.Item>
        <Descriptions.Item label={t('fields.adminState')}>
          <Tag color={stateColors[item.admin_state]}>{t(`states.${item.admin_state}`)}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.revision')}>{t('telemetry.revision', { revision: item.revision })}</Descriptions.Item>
        <Descriptions.Item label={t('fields.region')}>{item.region || t('telemetry.notSet')}</Descriptions.Item>
        <Descriptions.Item label={t('fields.ipv4')}>{item.ipv4 || t('telemetry.notSet')}</Descriptions.Item>
        <Descriptions.Item label={t('fields.ipv6')}>{item.ipv6 || t('telemetry.notSet')}</Descriptions.Item>
        <Descriptions.Item label={t('fields.description')}>{item.description || t('telemetry.notSet')}</Descriptions.Item>
        <Descriptions.Item label={t('fields.createdAt')}>{displayTime(item.created_at, locale, fallback)}</Descriptions.Item>
        <Descriptions.Item label={t('fields.updatedAt')}>{displayTime(item.updated_at, locale, fallback)}</Descriptions.Item>
        <Descriptions.Item label={t('fields.presence')}>
          <Tag color={presenceColors[presence.status]}>{t(`presence.${presence.status}`)}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.agentVersion')}>{presence.agent_version || fallback}</Descriptions.Item>
        <Descriptions.Item label={t('fields.openRestyVersion')}>{presence.openresty_version || fallback}</Descriptions.Item>
        <Descriptions.Item label={t('fields.nativeRuntime')}>
          {presence.native_runtime_state
            ? nativeRuntimeSummary(presence, t(`nativeRuntimeStates.${presence.native_runtime_state}`), t('fields.nativeRuntimePrevious'))
            : fallback}
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.marketProbe')}>
          {presence.market_probe_role ? t(`marketProbeRoles.${presence.market_probe_role}`) : fallback}
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.sequence')}>
          {presence.session_epoch && presence.heartbeat_sequence
            ? t('telemetry.sequence', { epoch: presence.session_epoch, sequence: presence.heartbeat_sequence })
            : fallback}
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.lastHeartbeat')}>
          {displayTime(presence.last_heartbeat_at, locale, fallback)}
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.projection')}>
          <Tag color={freshnessColors[presence.projection_freshness]}>
            {t(`freshness.${presence.projection_freshness}`)}
          </Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.lease')}>
          <Tag color={leaseColors[presence.lease_signal]}>{t(`lease.${presence.lease_signal}`)}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.projectedAt')}>
          {displayTime(presence.projected_at, locale, fallback)}
        </Descriptions.Item>
        <Descriptions.Item label={t('fields.ticket')} span={frozenDetails.length > 0 ? 3 : 1}>
          {frozenDetails.length > 0
            ? <div className="node-frozen-detail" role="status">
              <NodeFrozenTag ticket={ticketQuery.data} />
              {frozenDetails.map((line) => <div key={line}>{line}</div>)}
            </div>
            : ticketQuery.data?.not_after
              ? t('telemetry.ticketUntil', { time: displayTime(ticketQuery.data.not_after, locale, fallback) })
              : fallback}
        </Descriptions.Item>
      </Descriptions>
      <ProtectionPanel nodeID={nodeID} queryKey={queryKey} accessToken={currentSessionAccess} />
      <NodeConfigurationScopesPanel nodeID={nodeID} queryKey={queryKey} accessToken={currentSessionAccess} />
      {transition && (
        <TransitionPanel accessToken={currentSessionAccess() ?? ''} nodeID={nodeID} transition={transition} onChange={setTransition} />
      )}
      <Modal
        open={transitionOpen}
        title={t('transition.modalTitle')}
        okText={t('transition.actions.create')}
        cancelText={t('transition.actions.cancel')}
        confirmLoading={transitionSubmitting}
        onCancel={() => setTransitionOpen(false)}
        onOk={() => void transitionForm.submit()}
        destroyOnClose
      >
        {transitionError && <Alert type="error" showIcon message={transitionError} />}
        <Form form={transitionForm} layout="vertical" onFinish={submitTransition} initialValues={{ compatibilityMinutes: 30, rollbackMinutes: 60 }}>
          <Form.Item label={t('transition.fields.oldAddress')} name="oldAddress" rules={[{ required: true }]}>
            <Input placeholder={t('transition.placeholders.endpoint')} />
          </Form.Item>
          <Form.Item label={t('transition.fields.oldListenAddress')} name="oldListenAddress" rules={[{ required: true }]}>
            <Input placeholder={t('transition.placeholders.listenAddress')} />
          </Form.Item>
          <Form.Item label={t('transition.fields.oldServerName')} name="oldServerName" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item label={t('transition.fields.newAddress')} name="newAddress" rules={[{ required: true }]}>
            <Input placeholder={t('transition.placeholders.endpoint')} />
          </Form.Item>
          <Form.Item label={t('transition.fields.newListenAddress')} name="newListenAddress" rules={[{ required: true }]}>
            <Input placeholder={t('transition.placeholders.listenAddress')} />
          </Form.Item>
          <Form.Item label={t('transition.fields.newServerName')} name="newServerName" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Space wrap>
            <Form.Item label={t('transition.fields.compatibilityMinutes')} name="compatibilityMinutes" rules={[{ required: true }]}> 
              <InputNumber min={1} max={1440} />
            </Form.Item>
            <Form.Item label={t('transition.fields.rollbackMinutes')} name="rollbackMinutes" rules={[{ required: true }]}> 
              <InputNumber min={2} max={2880} />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </section>
  )
}

export default function NodeInventoryDetailPage() {
  const { t } = useTranslation('nodeInventoryDetail')
  const { id = '' } = useParams<{ id: string }>()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(
    () => principal ? detailOwner(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )

  if (!accessToken || !principal) return null
  if (!owner || !canRead(principal)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  if (!uuidPattern.test(id)) {
    return <Result status="404" title={t('errors.notFoundTitle')} subTitle={t('errors.notFoundDescription')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <DetailContent key={ownerKey} owner={owner} ownerKey={ownerKey} nodeID={id} />
}
