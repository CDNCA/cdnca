import { useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Modal, Space, Tag, Tooltip, Typography } from 'antd'
import { Table } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { useSessionStore } from '../auth/session'
import {
  nodeScopeServingAfterRollbackFailure, nodeScopeSourceVersion, nodesApi, type NodeConfigurationScope, type NodeScopeRejection,
} from '../api/nodes'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/nodeConfigurationScopes'
import { DataState } from './DataState'

const deploymentColors: Record<string, string> = {
  queued: 'default', delivered: 'processing', agent_queued: 'gold', started: 'processing', staged: 'processing',
  prechecked: 'processing', activated: 'processing', healthy: 'success', failed: 'error', reverting: 'warning',
  reverted: 'default', rollback_failed: 'error', cancelled: 'default',
}
const applyColors: Record<string, string> = {
  healthy: 'success', failed: 'error', reverted: 'default', rollback_failed: 'error', superseded: 'purple',
}
// The refusals of an operator-confirmed version have their own explanation.
const reconcileFailureCodes = new Set(['reconciliation_version_not_source', 'reconciliation_source_unverifiable'])
// the supplemental confirmation explains
// its refusals in its own words (it has no "untick and retry" way out).
const supplementFailureCodes = new Set(['reconciliation_supplement_not_eligible', 'reconciliation_version_not_source',
  'reconciliation_source_unverifiable'])
// The supplemental confirmation of one source deployment attempt of a scope.
const supplementKey = (scope: NodeConfigurationScope) => scope.source_confirmation
  ? `${scope.scope_id}:${scope.source_confirmation.source_deployment_id}:${scope.source_confirmation.source_deployment_attempt}` : ''
// the tables keep their columns and scroll
// sideways inside .identity-table-scroll on narrow screens.
const scopeTableWidth = 720
const rejectionTableWidth = 560

/**
 * Lists the tenants (configuration scopes) a node serves with their versions
 * and apply progress, and publications refused for conflicting with them.
 * The only action is ending a scope's wait for reconciliation with what the
 * node reports; the access token getter returns
 * null once the session changed.
 */
export function NodeConfigurationScopesPanel({ nodeID, queryKey, accessToken }: {
  nodeID: string
  queryKey: readonly unknown[]
  accessToken: () => string | null
}) {
  const { t, i18n } = useTranslation('nodeConfigurationScopes')
  const locale = i18n.resolvedLanguage ?? i18n.language
  const query = useQuery({
    queryKey: [...queryKey, 'configuration-scopes'],
    queryFn: async () => {
      const token = accessToken()
      if (!token) throw new Error('Node configuration scopes session changed')
      return nodesApi.getConfigurationScopes(token, nodeID)
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  // 对账是写操作，与服务端 POST /v1/admin/site-rollouts/reconciliations 同一权限
  // （平台身份且 edge_publications.manage 或 platform.admin）；只读者照常看状态、原部署与上报信息。
  const canReconcile = useSessionStore((state) => state.principal?.scope_kind === 'platform' &&
    (state.principal.permissions.includes('platform.admin') || state.principal.permissions.includes('edge_publications.manage')))
  // the scope whose reconciliation is being
  // confirmed, in a centred dialog (an anchored popover left the viewport
  // once the table scrolled sideways); whether
  // its "still serves the original release" option is ticked (never by
  // default).
  const [dialogScope, setDialogScope] = useState<NodeConfigurationScope | null>(null)
  const [servingSource, setServingSource] = useState(false)
  const reconcile = useMutation({
    mutationFn: async ({ scope, sourceVersion }: { scope: NodeConfigurationScope; sourceVersion?: string }) => {
      const token = accessToken()
      if (!token) throw new Error('Node configuration scopes session changed')
      await nodesApi.reconcileConfigurationScope(token, nodeID, scope, sourceVersion)
    },
    onSuccess: () => { void query.refetch() },
  })
  // the scope reconciled without a
  // version whose source release is being confirmed, and whether its option
  // is ticked (never by default; the confirmation needs it).
  const [supplementScope, setSupplementScope] = useState<NodeConfigurationScope | null>(null)
  const [supplementTicked, setSupplementTicked] = useState(false)
  // the confirmations the control plane
  // accepted (201) here. Their entry stays gone and their receipt stays
  // shown whatever the scope readback does (slow, failed); the readback only
  // updates the rest. the receipt takes the focus
  // once the dialog has closed.
  const [supplementWritten, setSupplementWritten] = useState<ReadonlySet<string>>(() => new Set())
  const [supplementReceipt, setSupplementReceipt] = useState<string | null>(null)
  const receiptRef = useRef<HTMLDivElement>(null)
  const focusReceipt = useRef(false)
  const supplement = useMutation({
    mutationFn: async (scope: NodeConfigurationScope) => {
      const token = accessToken()
      if (!token) throw new Error('Node configuration scopes session changed')
      await nodesApi.confirmConfigurationScopeSource(token, nodeID, scope)
    },
    onSuccess: (_, scope) => {
      setSupplementWritten((written) => new Set(written).add(supplementKey(scope)))
      setSupplementReceipt(scope.tenant_name || t(`scopeKinds.${scope.scope_kind}`))
      focusReceipt.current = true
      void query.refetch()
    },
  })
  const failureCode = reconcile.error instanceof ApiError ? reconcile.error.code : 'unknown'
  const supplementFailureCode = supplement.error instanceof ApiError ? supplement.error.code : 'unknown'
  const failureMessage = (code: string) => reconcileFailureCodes.has(code)
    ? t(`reconcile.failedCodes.${code}`) : t('reconcile.failed', { code })
  const supplementFailureMessage = (code: string) => supplementFailureCodes.has(code)
    ? t(`supplement.failedCodes.${code}`) : t('reconcile.failed', { code })
  const openSupplement = (scope: NodeConfigurationScope) => {
    supplement.reset()
    setSupplementTicked(false)
    setSupplementScope(scope)
  }
  const confirmSupplement = async () => {
    if (!supplementScope || !supplementTicked || supplement.isPending) return
    // Already accepted (a stale row): never a second write.
    if (supplementWritten.has(supplementKey(supplementScope))) {
      setSupplementScope(null)
      return
    }
    try {
      await supplement.mutateAsync(supplementScope)
      setSupplementScope(null)
    } catch {
      // The refusal is shown in the dialog.
    }
  }
  const refreshAfterRefusal = () => {
    setSupplementScope(null)
    void query.refetch()
  }
  const supplementConfirmation = supplementScope?.source_confirmation
  const supplementVersion = supplementConfirmation?.config_version_id.slice(0, 8) ?? ''
  const dialogSource = dialogScope ? nodeScopeSourceVersion(dialogScope) : null
  const openDialog = (scope: NodeConfigurationScope) => {
    reconcile.reset()
    setServingSource(false)
    setDialogScope(scope)
  }
  const confirmDialog = async () => {
    if (!dialogScope) return
    try {
      await reconcile.mutateAsync({ scope: dialogScope, sourceVersion: dialogSource && servingSource ? dialogSource : undefined })
      setDialogScope(null)
    } catch {
      // The refusal is shown in the dialog; the operator may untick and retry.
    }
  }
  const dialogReconciliation = dialogScope?.reconciliation
  const time = (value: string | null | undefined) => value ? formatDateTime(value, locale) : t('noVersion')
  // 复制按钮按列与租户命名，不用默认的「复制」，名称里不放完整 UUID
  const tenantLabel = (scope: NodeConfigurationScope) => scope.tenant_name || t(`scopeKinds.${scope.scope_kind}`)
  const version = (value: string | null, which: 'current' | 'previous', scope: NodeConfigurationScope) => value
    ? <Typography.Text code copyable={{ text: value, tooltips: [t(`copy.${which}`, { name: tenantLabel(scope) })] }}>{value.slice(0, 8)}</Typography.Text>
    : <Typography.Text type="secondary">{t('noVersion')}</Typography.Text>
  // The write's receipt, apart from the readback (which may still run or have failed).
  const receipt = supplementReceipt ? (
    <div ref={receiptRef} tabIndex={-1} data-testid="node-scope-supplement-receipt" style={{ marginBottom: 12 }}>
      <Alert type="success" showIcon role="status"
        message={t('supplement.done', { tenant: supplementReceipt })}
        description={query.isFetching ? t('supplement.readingBack')
          : query.isError ? t('supplement.readbackFailed') : undefined} />
    </div>
  ) : null

  if (query.isError) {
    const invalid = query.error instanceof ApiError && query.error.code === 'invalid_response'
    return (
      <section className="node-configuration-scopes" aria-labelledby="node-configuration-scopes-title">
        <Typography.Title level={4} id="node-configuration-scopes-title">{t('title')}</Typography.Title>
        {receipt}
        <DataState status="error" message={invalid ? t('errors.invalidResponse') : t('errors.unavailable')}
          onRetry={() => void query.refetch()} />
      </section>
    )
  }
  const scopes = query.data?.scopes ?? []
  const rejections = query.data?.rejections ?? []
  const regressions = query.data?.capability_regressions ?? []
  const tenantName = (scopeID: string) => {
    const scope = scopes.find((item) => item.scope_id === scopeID)
    return scope ? scope.tenant_name || t(`scopeKinds.${scope.scope_kind}`) : scopeID.slice(0, 8)
  }
  return (
    <section className="node-configuration-scopes" aria-labelledby="node-configuration-scopes-title">
      <Typography.Title level={4} id="node-configuration-scopes-title">{t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      {regressions.map((regression) => (
        <Alert
          key={`${regression.scope_id}:${regression.feature}`}
          type="warning"
          showIcon
          role="alert"
          style={{ marginBottom: 12 }}
          message={t('regressions.title')}
          description={(
            <>
              <div>{t('regressions.message', {
                tenant: tenantName(regression.scope_id), version: regression.config_version_id.slice(0, 8),
                feature: t(`regressions.features.${regression.feature}`),
                agent: regression.agent_version || t('regressions.unknownAgent'),
                capability: regression.capability.replace(/^CAPABILITY_NAME_/, ''),
                declared: regression.declared, required: regression.required,
              })}</div>
              <div>{t('regressions.remedy')}</div>
            </>
          )}
        />
      ))}
      {reconcile.isSuccess ? (
        <Alert type="success" showIcon role="status" style={{ marginBottom: 12 }}
          message={reconcile.variables?.sourceVersion ? t('reconcile.doneServing') : t('reconcile.done')} />
      ) : null}
      {receipt}
      <Modal
        open={supplementScope !== null}
        centered
        title={t('supplement.title')}
        okText={t('supplement.ok')}
        cancelText={t('reconcile.cancel')}
        okButtonProps={{ disabled: !supplementTicked }}
        confirmLoading={supplement.isPending}
        onOk={() => void confirmSupplement()}
        onCancel={() => setSupplementScope(null)}
        afterClose={() => {
          // After a confirmation its entry is gone: the focus goes to the
          // receipt (a cancel returns it to the entry as usual).
          if (focusReceipt.current) receiptRef.current?.focus()
          focusReceipt.current = false
        }}
        destroyOnClose
      >
        {supplementScope && supplementConfirmation ? (
          <div data-testid="node-scope-supplement-dialog">
            <Typography.Paragraph>{t('supplement.body', {
              time: time(supplementConfirmation.reconciled_at),
              deployment: supplementConfirmation.source_deployment_id.slice(0, 8), version: supplementVersion,
            })}</Typography.Paragraph>
            <Checkbox checked={supplementTicked} onChange={(event) => setSupplementTicked(event.target.checked)}>
              {t('supplement.option', { version: supplementVersion })}
            </Checkbox>
            <Typography.Text type="secondary" style={{ display: 'block' }}>{t('supplement.checkNodeFirst')}</Typography.Text>
            {supplement.isError ? (
              <Alert type="error" showIcon role="alert" style={{ marginTop: 12 }}
                message={supplementFailureMessage(supplementFailureCode)}
                description={supplementFailureCode === 'reconciliation_source_unverifiable' ? (
                  <Space wrap>
                    <Button size="small" onClick={refreshAfterRefusal}>{t('supplement.refresh')}</Button>
                    <Link to={`/site/publications?target_scope_id=${encodeURIComponent(supplementScope.scope_id)}`}>
                      {t('supplement.viewPublications')}
                    </Link>
                  </Space>
                ) : undefined} />
            ) : null}
          </div>
        ) : null}
      </Modal>
      <Modal
        open={dialogScope !== null}
        centered
        title={dialogScope?.reconciliation?.observation === 'unconfirmed' ? t('reconcile.unconfirmedTitle') : t('reconcile.confirmTitle')}
        okText={t('reconcile.ok')}
        cancelText={t('reconcile.cancel')}
        confirmLoading={reconcile.isPending}
        onOk={() => void confirmDialog()}
        onCancel={() => setDialogScope(null)}
        destroyOnClose
      >
        {dialogReconciliation ? (
          <div data-testid="node-scope-reconcile-dialog">
            {dialogReconciliation.observation === 'unconfirmed' ? (
              <>
                <Typography.Paragraph>
                  {dialogSource && servingSource
                    ? t('reconcile.servingSourceBody', { version: dialogSource.slice(0, 8) })
                    : t('reconcile.unconfirmedBody')}
                </Typography.Paragraph>
                {dialogSource ? (
                  <div>
                    <Checkbox checked={servingSource} onChange={(event) => setServingSource(event.target.checked)}>
                      {t('reconcile.servingSource', { version: dialogSource.slice(0, 8) })}
                    </Checkbox>
                    <Typography.Text type="secondary" style={{ display: 'block' }}>{t('reconcile.checkNodeFirst')}</Typography.Text>
                  </div>
                ) : (
                  <Typography.Paragraph type="secondary">{t('reconcile.checkNodeFirst')}</Typography.Paragraph>
                )}
              </>
            ) : (
              <Typography.Paragraph>
                {t('reconcile.confirmBody', {
                  version: dialogReconciliation.reported_config_version_id?.slice(0, 8) ?? t('reconcile.none'),
                  time: dialogReconciliation.reported_at ? time(dialogReconciliation.reported_at) : t('reconcile.unknownTime'),
                })}
              </Typography.Paragraph>
            )}
            {/* what leaving the option unticked does, next to the buttons. */}
            {dialogReconciliation.observation === 'unconfirmed' && dialogSource && !servingSource ? (
              <Typography.Paragraph type="warning" style={{ marginTop: 12, marginBottom: 0 }} data-testid="node-scope-reconcile-held-note">
                {t('reconcile.uncheckedHeldNote')}
              </Typography.Paragraph>
            ) : null}
            {reconcile.isError ? (
              <Alert type="error" showIcon role="alert" style={{ marginTop: 12 }} message={failureMessage(failureCode)} />
            ) : null}
          </div>
        ) : null}
      </Modal>
      <div className="identity-table-scroll" data-testid="node-scope-table-scroll">
        <Table<NodeConfigurationScope>
          size="small"
          rowKey="scope_id"
          loading={query.isPending}
          dataSource={scopes}
          pagination={false}
          scroll={{ x: scopeTableWidth }}
          locale={{ emptyText: t('empty') }}
          columns={[
            {
              title: t('columns.tenant'), key: 'tenant',
              render: (_, scope) => (
                <>
                  <div>{tenantLabel(scope)}</div>
                  <Typography.Text type="secondary" copyable={{ text: scope.scope_id, tooltips: [t('copy.tenant', { name: tenantLabel(scope) })] }}>{scope.scope_id.slice(0, 8)}</Typography.Text>
                  {scope.reconciliation_required && <Tag color="error">{t('reconciliation')}</Tag>}
                  {scope.reconciliation_required && scope.reconciliation && (
                    <div data-testid="node-scope-reconciliation">
                      <Typography.Paragraph type="secondary" style={{ marginBottom: 4 }}>
                        {t('reconcile.reason', { deployment: scope.reconciliation.source_deployment_id.slice(0, 8),
                          attempt: scope.reconciliation.source_deployment_attempt })}
                      </Typography.Paragraph>
                      {/* 节点上报未确认时不以「空配置」为依据，写明未确认，只给人工确认。 */}
                      {scope.reconciliation.observation === 'unconfirmed' ? (
                        <Typography.Paragraph type="warning" style={{ marginBottom: 4 }} data-testid="node-scope-unconfirmed">
                          {t('reconcile.unconfirmed', { reason: i18n.exists(`nodeConfigurationScopes:reconcile.unconfirmedReasons.${scope.reconciliation.unconfirmed_reason}`)
                            ? t(`reconcile.unconfirmedReasons.${scope.reconciliation.unconfirmed_reason}`)
                            : t('reconcile.unconfirmedReasons.default', { code: scope.reconciliation.unconfirmed_reason }) })}
                        </Typography.Paragraph>
                      ) : null}
                      {canReconcile ? (
                        <Button size="small" loading={reconcile.isPending && reconcile.variables?.scope.scope_id === scope.scope_id}
                          onClick={() => openDialog(scope)}>
                          {scope.reconciliation.observation === 'unconfirmed' ? t('reconcile.unconfirmedAction') : t('reconcile.action')}
                        </Button>
                      ) : null}
                    </div>
                  )}
                  {/* the row says the state and offers the action; the dialog explains. */}
                  {!scope.reconciliation_required && scope.source_confirmation && !supplementWritten.has(supplementKey(scope)) && (
                    <div data-testid="node-scope-source-confirmation">
                      <Tag>{t('supplement.rowState')}</Tag>
                      {canReconcile ? (
                        <Button size="small" onClick={() => openSupplement(scope)}>{t('supplement.action')}</Button>
                      ) : null}
                    </div>
                  )}
                  {scope.telemetry_excluded && (
                    <Tooltip title={t(`telemetryExcluded.${scope.telemetry_excluded}`)}>
                      <Tag color="warning">{t('telemetryExcluded.tag')}</Tag>
                    </Tooltip>
                  )}
                </>
              ),
            },
            { title: t('columns.current'), key: 'current', render: (_, scope) => version(scope.current_config_version_id, 'current', scope) },
            { title: t('columns.previous'), key: 'previous', render: (_, scope) => version(scope.previous_config_version_id, 'previous', scope) },
            {
              title: t('columns.deployment'), key: 'deployment',
              render: (_, scope) => scope.latest_deployment
                ? (
                  <>
                    <Tag color={deploymentColors[scope.latest_deployment.state]}>
                      {t(`deploymentStates.${scope.latest_deployment.state}`)}
                    </Tag>
                    <Typography.Text type="secondary">{t('attempt', { attempt: scope.latest_deployment.attempt })}</Typography.Text>
                  </>
                )
                : <Typography.Text type="secondary">{t('noVersion')}</Typography.Text>,
            },
            {
              title: t('columns.apply'), key: 'apply',
              // a failed rollback says what to do; the raw
              // error and the latest recovery record are folded under it.
              render: (_, scope) => scope.last_apply
                ? (
                  <>
                    <Tag color={nodeScopeServingAfterRollbackFailure(scope) ? 'warning' : applyColors[scope.last_apply.state]}>
                      {nodeScopeServingAfterRollbackFailure(scope) ? t('lastApply.servingAfterRollbackFailure')
                        : scope.last_apply.state === 'rollback_failed' && scope.reconciliation_required
                          ? t('lastApply.needsReconciliation') : t(`applyStates.${scope.last_apply.state}`)}
                    </Tag>
                    {scope.last_apply.error_code || scope.last_apply.state === 'rollback_failed' ? (
                      <details data-testid="node-scope-apply-detail">
                        <summary>{t('lastApply.details')}</summary>
                        <div>{t('lastApply.error', { code: scope.last_apply.error_code ?? t('noVersion') })}</div>
                        <div>{t('lastApply.finishedAt', { time: time(scope.last_apply.finished_at) })}</div>
                        <div>
                          {scope.reconciliation?.reported_at
                            ? t('lastApply.recovery', {
                              version: scope.reconciliation.reported_config_version_id?.slice(0, 8) ?? t('reconcile.none'),
                              time: time(scope.reconciliation.reported_at),
                            })
                            : t('lastApply.noRecovery')}
                        </div>
                      </details>
                    ) : null}
                  </>
                )
                : <Typography.Text type="secondary">{t('noVersion')}</Typography.Text>,
            },
            { title: t('columns.updatedAt'), key: 'updated', render: (_, scope) => time(scope.updated_at) },
          ]}
        />
      </div>
      <Typography.Title level={5} id="node-scope-rejections-title">{t('rejections.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('rejections.description')}</Typography.Paragraph>
      <div className="identity-table-scroll" data-testid="node-scope-rejections-scroll">
        <Table<NodeScopeRejection>
          size="small"
          rowKey={(rejection) => rejection.request_id + rejection.occurred_at}
          loading={query.isPending}
          dataSource={rejections}
          pagination={false}
          scroll={{ x: rejectionTableWidth }}
          locale={{ emptyText: t('rejections.empty') }}
          aria-labelledby="node-scope-rejections-title"
          columns={[
            { title: t('rejections.columns.tenant'), key: 'tenant', render: (_, rejection) => rejection.tenant_name || rejection.scope_id.slice(0, 8) },
            { title: t('rejections.columns.reason'), dataIndex: 'reason', key: 'reason' },
            { title: t('rejections.columns.requestId'), dataIndex: 'request_id', key: 'request' },
            { title: t('rejections.columns.occurredAt'), key: 'time', render: (_, rejection) => time(rejection.occurred_at) },
          ]}
        />
      </div>
    </section>
  )
}
