import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Result, Select, Space, Table, Tag, Tooltip, Typography, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  identityVerificationReviewQueueApi,
  type IdentityVerificationReviewCase,
  type IdentityVerificationReviewKind,
  type IdentityVerificationReviewStatus,
} from '../api/identityVerificationReviewQueue'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/identityVerificationReviewQueue'

type Owner = readonly ['tenant', string, string, number]

const staleRead = new Error('Identity verification reviewer owner changed during read')
const pageSizes = [20, 50, 100] as const
const kinds: IdentityVerificationReviewKind[] = [
  'personal_initial', 'personal_reverification', 'enterprise',
]
const statuses: IdentityVerificationReviewStatus[] = [
  'draft', 'submitted', 'reviewing', 'approved', 'rejected', 'withdrawn', 'expired',
]
const statusColors: Record<IdentityVerificationReviewStatus, string> = {
  draft: 'default',
  submitted: 'warning',
  reviewing: 'processing',
  approved: 'success',
  rejected: 'error',
  withdrawn: 'default',
  expired: 'default',
}

function reviewerOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (
    principal.scope_kind !== 'tenant' || !principal.tenant_id ||
    !principal.scope_id || !principal.user_id || sessionEpoch <= 0
  ) return null
  return ['tenant', principal.scope_id, principal.user_id, sessionEpoch]
}

function canReview(principal: Principal): boolean {
  return principal.permissions.includes('identity_verification.read') &&
    principal.permissions.includes('identity_verification.review')
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canReview(principal)) return null
  const owner = reviewerOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 401) return 'errors.unauthorized'
  if ([
    'identity_verification_unavailable',
    'identity_verification_request_timeout',
    'identity_verification_request_canceled',
    'identity_verification_invalid_request',
  ].includes(error.code)) return `errors.${error.code}`
  return 'errors.requestFailed'
}

export default function IdentityVerificationReviewQueuePage() {
  const { t } = useTranslation('identityVerificationReviewQueue')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? reviewerOwner(principal, sessionEpoch) : null

  if (!accessToken || !principal) return null
  if (!owner || !canReview(principal)) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const ownerKey = JSON.stringify(owner)
  return <ReviewQueueContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}

function ReviewQueueContent({ owner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t, i18n } = useTranslation('identityVerificationReviewQueue')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const lineageActiveRef = useRef(true)
  const [kind, setKind] = useState<IdentityVerificationReviewKind>()
  const [status, setStatus] = useState<IdentityVerificationReviewStatus>()
  const [limit, setLimit] = useState<20 | 50 | 100>(20)
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  const page = cursors.length + 1
  const prefix = useMemo(
    () => ['identity-verification-review-queue', ...fixedOwner] as const,
    [fixedOwner],
  )
  const queryKey = useMemo(
    () => [...prefix, kind ?? '', status ?? '', limit, cursor ?? ''] as const,
    [cursor, kind, limit, prefix, status],
  )
  const identity = JSON.stringify(queryKey)
  const activeIdentityRef = useRef(identity)
  activeIdentityRef.current = identity

  const currentSessionAccess = useCallback(
    () => lineageActiveRef.current ? currentAccess(ownerKey) : null,
    [ownerKey],
  )

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentSessionAccess()
      if (!token) throw staleRead
      try {
        const result = await identityVerificationReviewQueueApi.list(token, {
          kind, status, limit, cursor,
        })
        if (!currentSessionAccess() || activeIdentityRef.current !== identity) throw staleRead
        return result
      } catch (error) {
        if (!currentSessionAccess() || activeIdentityRef.current !== identity) throw staleRead
        throw error
      }
    },
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentAccess(ownerKey)) {
        queryClient.removeQueries({ queryKey: prefix })
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) queryClient.removeQueries({ queryKey: prefix })
      })
    }
  }, [ownerKey, prefix, queryClient])

  const language = i18n.resolvedLanguage ?? i18n.language
  const resetPagination = () => setCursors([])
  const columns: TableColumnsType<IdentityVerificationReviewCase> = [
    {
      title: t('columns.id'), dataIndex: 'id', width: 295,
      render: (value: string) => <Link to={`/sys/identity-verification/${value}`}>{value}</Link>,
    },
    { title: t('columns.applicant'), dataIndex: 'applicant_user_id', width: 290 },
    {
      title: t('columns.kind'), dataIndex: 'kind', width: 150,
      render: (value: IdentityVerificationReviewKind) => t(`kinds.${value}`),
    },
    {
      title: t('columns.status'), dataIndex: 'status', width: 115,
      render: (value: IdentityVerificationReviewStatus) => (
        <Tag color={statusColors[value]}>{t(`states.${value}`)}</Tag>
      ),
    },
    {
      title: t('columns.reviewer'), dataIndex: 'reviewer_user_id', width: 290,
      render: (value?: string) => value ?? t('values.unassigned'),
    },
    { title: t('columns.revision'), dataIndex: 'revision', width: 90 },
    {
      title: t('columns.changedAt'), dataIndex: 'state_changed_at', width: 190,
      render: (value: string) => formatDateTime(value, language) || value,
    },
  ]

  const error = query.error instanceof ApiError ? query.error : null
  if (error?.status === 403) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }

  const items = query.data?.items ?? []
  return (
    <section className="identity-page identity-verification-review-queue-page">
      <header className="identity-page-header">
        <div>
          <Typography.Title level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
        <Button icon={<RefreshCw size={16} />} loading={query.isFetching} onClick={() => void query.refetch()}>
          {t('actions.refresh')}
        </Button>
      </header>

      <Space wrap className="identity-toolbar">
        <Select<IdentityVerificationReviewKind>
          allowClear
          aria-label={t('filters.kindLabel')}
          placeholder={t('filters.kindPlaceholder')}
          value={kind}
          options={kinds.map((value) => ({ value, label: t(`kinds.${value}`) }))}
          onChange={(value) => {
            setKind(value)
            resetPagination()
          }}
        />
        <Select<IdentityVerificationReviewStatus>
          allowClear
          aria-label={t('filters.statusLabel')}
          placeholder={t('filters.statusPlaceholder')}
          value={status}
          options={statuses.map((value) => ({ value, label: t(`states.${value}`) }))}
          onChange={(value) => {
            setStatus(value)
            resetPagination()
          }}
        />
        <Select<20 | 50 | 100>
          aria-label={t('filters.limitLabel')}
          value={limit}
          options={pageSizes.map((value) => ({ value, label: String(value) }))}
          onChange={(value) => {
            setLimit(value)
            resetPagination()
          }}
        />
      </Space>

      {query.isPending ? (
        <DataState status="loading" message={t('data.loading')} />
      ) : query.isError ? (
        <DataState status="error" message={t(errorKey(query.error))} onRetry={() => void query.refetch()} />
      ) : items.length === 0 ? (
        <DataState status="empty" message={t('data.empty')} />
      ) : (
        <div aria-busy={query.isFetching}>
          <Table<IdentityVerificationReviewCase>
            columns={columns}
            dataSource={items}
            pagination={false}
            rowKey="id"
            scroll={{ x: 1420 }}
            size="middle"
          />
        </div>
      )}

      <footer className="identity-pagination">
        <Tooltip title={t('actions.previous')}>
          <Button
            aria-label={t('actions.previous')}
            icon={<ChevronLeft size={16} />}
            disabled={cursors.length === 0 || query.isFetching}
            onClick={() => setCursors((value) => value.slice(0, -1))}
          />
        </Tooltip>
        <span>{t('pagination.page', { page })}</span>
        <Tooltip title={t('actions.next')}>
          <Button
            aria-label={t('actions.next')}
            icon={<ChevronRight size={16} />}
            disabled={!query.data?.next_cursor || query.isFetching}
            onClick={() => {
              if (query.data?.next_cursor) setCursors((value) => [...value, query.data.next_cursor!])
            }}
          />
        </Tooltip>
      </footer>
    </section>
  )
}
