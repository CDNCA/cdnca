import { useQuery } from '@tanstack/react-query'
import { Alert, Table, Tag, Tooltip, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { nodesApi, type NodeConfigurationScope, type NodeScopeRejection } from '../api/nodes'
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

/**
 * Lists the tenants (configuration scopes) a node serves with their versions
 * and apply progress, and publications refused for conflicting with them.
 * Read-only; the access token getter returns null once the session changed.
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
  const time = (value: string | null | undefined) => value ? formatDateTime(value, locale) : t('noVersion')
  const version = (value: string | null) => value
    ? <Typography.Text code copyable={{ text: value }}>{value.slice(0, 8)}</Typography.Text>
    : <Typography.Text type="secondary">{t('noVersion')}</Typography.Text>

  if (query.isError) {
    const invalid = query.error instanceof ApiError && query.error.code === 'invalid_response'
    return (
      <section className="node-configuration-scopes" aria-labelledby="node-configuration-scopes-title">
        <Typography.Title level={4} id="node-configuration-scopes-title">{t('title')}</Typography.Title>
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
      <Table<NodeConfigurationScope>
        size="small"
        rowKey="scope_id"
        loading={query.isPending}
        dataSource={scopes}
        pagination={false}
        locale={{ emptyText: t('empty') }}
        columns={[
          {
            title: t('columns.tenant'), key: 'tenant',
            render: (_, scope) => (
              <>
                <div>{scope.tenant_name || t(`scopeKinds.${scope.scope_kind}`)}</div>
                <Typography.Text type="secondary" copyable={{ text: scope.scope_id }}>{scope.scope_id.slice(0, 8)}</Typography.Text>
                {scope.reconciliation_required && <Tag color="error">{t('reconciliation')}</Tag>}
                {scope.telemetry_excluded && (
                  <Tooltip title={t(`telemetryExcluded.${scope.telemetry_excluded}`)}>
                    <Tag color="warning">{t('telemetryExcluded.tag')}</Tag>
                  </Tooltip>
                )}
              </>
            ),
          },
          { title: t('columns.current'), key: 'current', render: (_, scope) => version(scope.current_config_version_id) },
          { title: t('columns.previous'), key: 'previous', render: (_, scope) => version(scope.previous_config_version_id) },
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
            render: (_, scope) => scope.last_apply
              ? (
                <>
                  <Tag color={applyColors[scope.last_apply.state]}>{t(`applyStates.${scope.last_apply.state}`)}</Tag>
                  {scope.last_apply.error_code && <Typography.Text type="danger">{scope.last_apply.error_code}</Typography.Text>}
                </>
              )
              : <Typography.Text type="secondary">{t('noVersion')}</Typography.Text>,
          },
          { title: t('columns.updatedAt'), key: 'updated', render: (_, scope) => time(scope.updated_at) },
        ]}
      />
      <Typography.Title level={5} id="node-scope-rejections-title">{t('rejections.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('rejections.description')}</Typography.Paragraph>
      <Table<NodeScopeRejection>
        size="small"
        rowKey={(rejection) => rejection.request_id + rejection.occurred_at}
        loading={query.isPending}
        dataSource={rejections}
        pagination={false}
        locale={{ emptyText: t('rejections.empty') }}
        aria-labelledby="node-scope-rejections-title"
        columns={[
          { title: t('rejections.columns.tenant'), key: 'tenant', render: (_, rejection) => rejection.tenant_name || rejection.scope_id.slice(0, 8) },
          { title: t('rejections.columns.reason'), dataIndex: 'reason', key: 'reason' },
          { title: t('rejections.columns.requestId'), dataIndex: 'request_id', key: 'request' },
          { title: t('rejections.columns.occurredAt'), key: 'time', render: (_, rejection) => time(rejection.occurred_at) },
        ]}
      />
    </section>
  )
}
