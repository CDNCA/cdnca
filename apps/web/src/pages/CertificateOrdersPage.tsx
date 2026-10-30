import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Input, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  certificateOrderStatusApi,
  type CertificateOrderLifecycle,
  type CertificateOrderStatusItem,
} from '../api/certificateOrderStatus'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import '../i18n/certificateOrderStatus'
import { CertificateFailureReason } from '../components/CertificateFailureReason'
import { formatDateTime } from '../i18n/formatters'

type CertificateOrderOwner = readonly [Principal['scope_kind'], string, string, string, number]

function certificateOrderOwner(
  principal: Principal | null,
  sessionEpoch: number,
): CertificateOrderOwner | null {
  if (!principal || principal.scope_kind !== 'tenant' || !principal.scope_id ||
    !principal.tenant_id || !principal.user_id || sessionEpoch < 1) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function currentSessionAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal?.permissions.includes('certificates.read')) return null
  const owner = certificateOrderOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid certificate order response', 502, 'invalid_response')
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.code === 'invalid_response') return 'errors.invalidResponse'
  if (error.code === 'network_error') return 'errors.networkError'
  if (error.code === 'certificate_order_unavailable') return 'errors.serviceUnavailable'
  if (error.status === 401) return 'errors.authenticationRequired'
  if (error.status === 404) return 'errors.notFound'
  if (error.status === 409) return 'errors.conflict'
  if (error.status === 412) return 'errors.preconditionFailed'
  if (error.status === 429) return 'errors.rateLimited'
  if (error.status >= 500) return 'errors.serviceUnavailable'
  return 'errors.requestFailed'
}

function statusColor(status: CertificateOrderLifecycle): string {
  if (status === 'active') return 'green'
  if (status === 'failed' || status === 'revoked') return 'red'
  if (status === 'renewal_due') return 'orange'
  if (status === 'issued' || status === 'deploying') return 'blue'
  return 'default'
}

const statusOptions: CertificateOrderLifecycle[] = [
  'pending', 'validating', 'issuing', 'issued', 'deploying', 'active',
  'renewal_due', 'failed', 'revoked',
]

function CertificateOrdersContent({ owner, ownerKey }: {
  owner: CertificateOrderOwner
  ownerKey: string
}) {
  const { t, i18n } = useTranslation('certificateOrderStatus')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const activeRef = useRef(true)
  const queryKey = useMemo(() => ['certificate-order-status', ...fixedOwner] as const, [fixedOwner])
  const [domain, setDomain] = useState('')
  const [status, setStatus] = useState<CertificateOrderLifecycle | ''>('')

  useEffect(() => {
    activeRef.current = true
    return () => {
      activeRef.current = false
      queueMicrotask(() => {
        const current = useSessionStore.getState()
        const currentOwner = certificateOrderOwner(current.principal, current.sessionEpoch)
        if (!currentOwner || JSON.stringify(currentOwner) !== ownerKey) {
          queryClient.removeQueries({ queryKey, exact: true })
        }
      })
    }
  }, [ownerKey, queryClient, queryKey])

  const query = useQuery({
    queryKey,
    queryFn: async ({ signal }) => {
      const token = activeRef.current ? currentSessionAccess(ownerKey) : null
      if (!token) throw invalidResponse()
      try {
        const value = await certificateOrderStatusApi.list(token, signal)
        if (!activeRef.current || !currentSessionAccess(ownerKey) ||
          value.items.some((item) => item.scope_id !== fixedOwner[1])) {
          throw invalidResponse()
        }
        return value
      } catch (error) {
        if (!activeRef.current || !currentSessionAccess(ownerKey)) throw invalidResponse()
        throw error
      }
    },
  })

  const filtered = useMemo(() => {
    const term = domain.trim().toLocaleLowerCase()
    return (query.data?.items ?? []).filter((item) => (
      (!term || item.domains.some((value) => value.toLocaleLowerCase().includes(term))) &&
      (!status || item.status === status)
    ))
  }, [domain, query.data?.items, status])

  const columns: TableColumnsType<CertificateOrderStatusItem> = [
    {
      title: t('columns.domains'), dataIndex: 'domains', width: 260,
      render: (domains: string[]) => <span title={domains.join(', ')}>{domains.join(', ')}</span>,
    },
    {
      title: t('columns.challenge'), dataIndex: 'challenge_type', width: 110,
      render: (value: CertificateOrderStatusItem['challenge_type']) => t(`challenges.${value.replace('-', '_')}`),
    },
    {
      title: t('columns.status'), dataIndex: 'status', width: 110,
      render: (value: CertificateOrderLifecycle) => <Tag color={statusColor(value)}>{t(`states.${value}`)}</Tag>,
    },
    {
      title: t('columns.autoRenew'), dataIndex: 'auto_renew', width: 120,
      render: (value: boolean) => t(value ? 'values.enabled' : 'values.disabled'),
    },
    {
      title: t('columns.renewal'), dataIndex: 'renewal_of_order_id', width: 290,
      render: (value?: string) => value ? (
        <Space size={6}><Tag>{t('values.renewalOrder')}</Tag><Typography.Text code>{value}</Typography.Text></Space>
      ) : t('values.firstIssue'),
    },
    {
      title: t('columns.notAfter'), dataIndex: 'not_after', width: 180,
      render: (value?: string) => value ? formatDateTime(value, i18n.resolvedLanguage) : t('values.pending'),
    },
    {
      title: t('columns.issuedAt'), dataIndex: 'issued_at', width: 180,
      render: (value?: string) => value ? formatDateTime(value, i18n.resolvedLanguage) : t('values.pending'),
    },
    { title: t('columns.version'), dataIndex: 'version', width: 80 },
    {
      title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180,
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage),
    },
    {
      title: t('columns.failure'), dataIndex: 'failure_code', width: 200,
      render: (_: unknown, order: CertificateOrderStatusItem) => <CertificateFailureReason order={order} fallback={t('values.none')} />,
    },
  ]

  const forbidden = query.error instanceof ApiError && query.error.status === 403

  return (
    <section className="identity-page certificate-orders-page">
      <div className="identity-page-header">
        <Typography.Title level={1}>{t('title')}</Typography.Title>
        <Typography.Text type="secondary">{t('summary.count', { count: query.data?.items.length ?? 0 })}</Typography.Text>
      </div>
      <div className="identity-toolbar">
        <Input
          aria-label={t('filters.domain')}
          placeholder={t('filters.domainPlaceholder')}
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          allowClear
        />
        <label>
          <span className="sr-only">{t('filters.status')}</span>
          <select
            aria-label={t('filters.status')}
            value={status}
            onChange={(event) => setStatus(event.target.value as CertificateOrderLifecycle | '')}
          >
            <option value="">{t('filters.allStatuses')}</option>
            {statusOptions.map((value) => <option key={value} value={value}>{t(`states.${value}`)}</option>)}
          </select>
        </label>
      </div>

      {query.isPending ? <DataState status="loading" message={t('data.loading')} /> : forbidden ? (
        <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} />
      ) : query.isError ? (
        <DataState status="error" message={t(errorKey(query.error))} onRetry={() => void query.refetch()} />
      ) : query.data.items.length === 0 ? (
        <DataState status="empty" message={t('data.empty')} />
      ) : filtered.length === 0 ? (
        <DataState status="empty" message={t('data.filteredEmpty')} />
      ) : (
        <Table<CertificateOrderStatusItem>
          rowKey="id"
          columns={columns}
          dataSource={filtered}
          scroll={{ x: 1510 }}
          pagination={{ defaultPageSize: 10, showSizeChanger: true }}
        />
      )}
    </section>
  )
}

export default function CertificateOrdersPage() {
  const { t } = useTranslation('certificateOrderStatus')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = certificateOrderOwner(principal, sessionEpoch)

  if (!accessToken || !owner || !principal?.permissions.includes('certificates.read')) {
    return (
      <section className="identity-page certificate-orders-page">
        <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} />
      </section>
    )
  }

  const ownerKey = JSON.stringify(owner)
  return <CertificateOrdersContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}
