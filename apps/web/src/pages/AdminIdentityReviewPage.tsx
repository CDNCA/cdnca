import { useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Drawer, Result, Select, Space, Table, Tabs, Tag, Typography, type TableColumnsType } from 'antd'
import { useFeedbackMessage } from '@cdnca/ui'
import { RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  adminIdentityReviewApi,
  type AdminIdentityRejectReason,
  type AdminIdentityReviewDecision,
  type AdminIdentityReviewSummary,
} from '../api/adminIdentityReview'
import type { IdentityVerificationReviewStatus } from '../api/identityVerificationReviewQueue'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import { adminIdentityReviewNamespace as namespace } from '../i18n/adminIdentityReview'

const tabs = ['submitted', 'reviewing', 'approved', 'rejected'] as const
const statusColors: Record<IdentityVerificationReviewStatus, string> = {
  draft: 'default', submitted: 'warning', reviewing: 'processing', approved: 'success',
  rejected: 'error', withdrawn: 'default', expired: 'default',
}
const rejectReasons: AdminIdentityRejectReason[] = [
  'identity_mismatch', 'evidence_incomplete', 'evidence_unreadable',
  'organization_mismatch', 'authorization_invalid', 'suspected_fraud',
]

const token = () => useSessionStore.getState().accessToken ?? ''

function errorText(t: (key: string) => string, error: unknown): string {
  if (error instanceof ApiError && t(`errors.${error.code}`) !== `errors.${error.code}`) return t(`errors.${error.code}`)
  return t('errors.action')
}

/** Admin console identity review (fix-decide1027b item 3): every tenant's cases, reviewed as the administrator. */
export default function AdminIdentityReviewPage() {
  const { t } = useTranslation(namespace)
  const principal = useSessionStore((state) => state.principal)
  if (!principal) return null
  if (principal.scope_kind !== 'platform' || !principal.permissions.includes('platform.admin')) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  return <AdminIdentityReviewContent />
}

function AdminIdentityReviewContent() {
  const { t, i18n } = useTranslation(namespace)
  const [status, setStatus] = useState<(typeof tabs)[number]>('submitted')
  const [selected, setSelected] = useState<AdminIdentityReviewSummary | null>(null)
  const language = i18n.resolvedLanguage ?? i18n.language
  const query = useInfiniteQuery({
    queryKey: ['admin-identity-review', status],
    queryFn: ({ pageParam }) => adminIdentityReviewApi.list(token(), { status, cursor: pageParam, limit: 50 }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor,
  })
  const rows = query.data?.pages.flatMap((page) => page.items) ?? []
  const columns: TableColumnsType<AdminIdentityReviewSummary> = [
    { title: t('columns.tenant'), dataIndex: 'tenant_name' },
    { title: t('columns.applicant'), dataIndex: 'applicant_username' },
    { title: t('columns.kind'), dataIndex: 'kind', render: (value: string) => t(`kinds.${value}`) },
    {
      title: t('columns.status'), dataIndex: 'status',
      render: (value: IdentityVerificationReviewStatus) => <Tag color={statusColors[value]}>{t(`states.${value}`)}</Tag>,
    },
    {
      title: t('columns.submittedAt'), dataIndex: 'submitted_at',
      render: (value?: string) => value ? formatDateTime(value, language) : '-',
    },
    {
      title: t('columns.actions'), key: 'actions',
      render: (_, row) => <Button size="small" onClick={() => setSelected(row)}>{t('actions.review')}</Button>,
    },
  ]
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div>
        <Typography.Title level={4}>{t('title')}</Typography.Title>
        <Typography.Text type="secondary">{t('description')}</Typography.Text>
      </div>
      <Tabs activeKey={status} onChange={(key) => setStatus(key as (typeof tabs)[number])}
        items={tabs.map((key) => ({ key, label: t(`tabs.${key}`) }))}
        tabBarExtraContent={<Button icon={<RefreshCw size={14} />} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>} />
      {query.isError && <Alert type="error" showIcon message={t('errors.load')} />}
      <Table rowKey="id" columns={columns} dataSource={rows} loading={query.isPending} pagination={false}
        locale={{ emptyText: t('empty') }} />
      {query.hasNextPage && (
        <Button loading={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{t('actions.more')}</Button>
      )}
      <ReviewDrawer row={selected} onClose={() => setSelected(null)} />
    </Space>
  )
}

function ReviewDrawer({ row, onClose }: { row: AdminIdentityReviewSummary | null; onClose: () => void }) {
  const { t } = useTranslation(namespace)
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [reason, setReason] = useState<AdminIdentityRejectReason>('evidence_incomplete')
  const [failure, setFailure] = useState<string | null>(null)
  const adminID = useSessionStore((state) => state.principal?.user_id)
  const queryKey = ['admin-identity-review-case', row?.tenant_scope_id, row?.id] as const
  const detail = useQuery({
    queryKey,
    queryFn: () => adminIdentityReviewApi.get(token(), row!.id, row!.tenant_scope_id),
    enabled: row !== null,
  })
  const settle = (next: Awaited<ReturnType<typeof adminIdentityReviewApi.get>>, notice: string) => {
    setFailure(null)
    queryClient.setQueryData(queryKey, next)
    void queryClient.invalidateQueries({ queryKey: ['admin-identity-review'] })
    messageApi.success(t(notice))
  }
  const claim = useMutation({
    mutationFn: () => adminIdentityReviewApi.claim(token(), row!.id, row!.tenant_scope_id, detail.data!.revision),
    onSuccess: (next) => settle(next, 'notices.claimed'),
    onError: (error) => setFailure(errorText(t, error)),
  })
  const decide = useMutation({
    mutationFn: (decision: AdminIdentityReviewDecision) =>
      adminIdentityReviewApi.decide(token(), row!.id, row!.tenant_scope_id, detail.data!.revision, decision),
    onSuccess: (next) => settle(next, next.status === 'approved' ? 'notices.approved' : 'notices.rejected'),
    onError: (error) => setFailure(errorText(t, error)),
  })
  const current = detail.data
  const busy = claim.isPending || decide.isPending
  const mine = current?.status === 'reviewing' && current.reviewer_user_id === adminID
  return (
    <Drawer open={row !== null} onClose={() => { setFailure(null); onClose() }} title={t('detail.title')} width={520} destroyOnClose>
      {messageContext}
      {row && (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          {failure && <Alert type="error" showIcon message={failure} />}
          {detail.isError && <Alert type="error" showIcon message={t('errors.load')} />}
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label={t('detail.tenant')}>{row.tenant_name}</Descriptions.Item>
            <Descriptions.Item label={t('detail.applicant')}>{row.applicant_username}</Descriptions.Item>
            <Descriptions.Item label={t('detail.kind')}>{t(`kinds.${row.kind}`)}</Descriptions.Item>
            {current && (
              <>
                <Descriptions.Item label={t('detail.status')}>
                  <Tag color={statusColors[current.status]}>{t(`states.${current.status}`)}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label={t('detail.materials')}>{t('detail.materialCount', { count: current.materials.length })}</Descriptions.Item>
                {current.decision_reason_code && (
                  <Descriptions.Item label={t('detail.reason')}>{t(`reasons.${current.decision_reason_code}`)}</Descriptions.Item>
                )}
              </>
            )}
          </Descriptions>
          {current?.status === 'submitted' && (
            <Button type="primary" loading={claim.isPending} disabled={busy} onClick={() => claim.mutate()}>{t('actions.claim')}</Button>
          )}
          {current?.status === 'reviewing' && (
            <Space direction="vertical" style={{ width: '100%' }}>
              <Space wrap>
                <Button type="primary" disabled={!mine || busy} loading={decide.isPending && decide.variables?.decision === 'approved'}
                  onClick={() => decide.mutate({ decision: 'approved', reason_code: 'evidence_verified' })}>{t('actions.approve')}</Button>
                <Select aria-label={t('detail.rejectReason')} value={reason} onChange={setReason} style={{ minWidth: 180 }}
                  options={rejectReasons.map((value) => ({ value, label: t(`reasons.${value}`) }))} disabled={!mine || busy} />
                <Button danger disabled={!mine || busy} loading={decide.isPending && decide.variables?.decision === 'rejected'}
                  onClick={() => decide.mutate({ decision: 'rejected', reason_code: reason })}>{t('actions.reject')}</Button>
              </Space>
              {!mine && <Typography.Text type="secondary">{t('errors.identity_verification_review_assignment_required')}</Typography.Text>}
            </Space>
          )}
        </Space>
      )}
    </Drawer>
  )
}
