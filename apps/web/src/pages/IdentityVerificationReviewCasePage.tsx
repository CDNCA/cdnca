import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Descriptions, Popconfirm, Result, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  createIdentityVerificationReviewWriteMetadata,
  identityVerificationReviewCaseApi,
  type IdentityVerificationReviewMaterial,
  type IdentityVerificationReviewWriteMetadata,
} from '../api/identityVerificationReviewCase'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { localizedUnknownApiError } from '../i18n/apiError'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/identityVerificationReviewCase'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

type Owner = readonly ['tenant', string, string, string, number]
interface ClaimAttempt {
  caseID: string
  revision: number
  metadata: IdentityVerificationReviewWriteMetadata
}

const caseIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const queryRoot = 'identity-verification-review-case'
const requiredPermissions = ['identity_verification.read', 'identity_verification.review'] as const
const staleRead = new Error('Identity review owner changed during read')
const localizedErrorCodes = new Set([
  'network_error', 'invalid_response', 'invalid_request', 'identity_verification_invalid_request',
  'identity_verification_unauthenticated', 'identity_verification_permission_denied',
  'identity_verification_not_found', 'identity_verification_revision_conflict',
  'identity_verification_idempotency_conflict', 'identity_verification_active_review',
  'identity_verification_invalid_transition', 'identity_verification_self_review_forbidden',
  'identity_verification_review_assignment_required', 'identity_verification_request_canceled',
  'identity_verification_request_timeout', 'identity_verification_response_too_large',
  'identity_verification_unavailable',
])

function reviewOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.scope_id || !principal.tenant_id ||
    !principal.user_id || sessionEpoch < 1) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canReview(principal: Principal): boolean {
  return requiredPermissions.every((permission) => principal.permissions.includes(permission))
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canReview(principal)) return null
  const owner = reviewOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 503 || error.status === 504 || error.code === 'invalid_response'
}

function errorMessage(error: unknown, t: TFunction<'identityVerificationReviewCase'>): string {
  return error instanceof ApiError && localizedErrorCodes.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.requestFailed'))
}

function materialSize(bytes: number, locale: string): string {
  if (bytes % 1024 === 0) return `${new Intl.NumberFormat(locale).format(bytes / 1024)} KB`
  return `${new Intl.NumberFormat(locale).format(bytes)} B`
}

function IdentityVerificationReviewCaseContent({ owner, caseID }: { owner: Owner; caseID: string }) {
  const { t, i18n } = useTranslation('identityVerificationReviewCase')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const ownerKey = JSON.stringify(fixedOwner)
  const lineageActiveRef = useRef(true)
  const prefix = useMemo(() => [queryRoot, ...fixedOwner] as const, [fixedOwner])
  const queryKey = useMemo(() => [...prefix, caseID] as const, [caseID, prefix])
  const [attempt, setAttempt] = useState<ClaimAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const currentSessionAccess = useCallback(
    () => lineageActiveRef.current ? currentAccess(ownerKey) : null,
    [ownerKey],
  )

  const query = useQuery({
    queryKey,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
    queryFn: async ({ signal }) => {
      const token = currentSessionAccess()
      if (!token) throw staleRead
      try {
        const result = await identityVerificationReviewCaseApi.getCase(token, caseID, signal)
        if (!currentSessionAccess()) throw staleRead
        return result
      } catch (error) {
        if (!currentSessionAccess()) throw staleRead
        throw error
      }
    },
  })

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      void queryClient.cancelQueries({ queryKey: prefix })
      queryClient.removeQueries({ queryKey: prefix })
    }
  }, [prefix, queryClient])

  const executeClaim = async (nextAttempt: ClaimAttempt) => {
    if (writePending) return
    const token = currentSessionAccess()
    if (!token) return
    setWritePending(true)
    setWriteError(null)
    try {
      const result = await identityVerificationReviewCaseApi.claim(
        token, nextAttempt.caseID, nextAttempt.revision, nextAttempt.metadata,
      )
      if (!currentSessionAccess()) return
      if (result.reviewer_user_id !== fixedOwner[3]) {
        throw new ApiError('Invalid identity verification review response', 502, 'invalid_response')
      }
      queryClient.setQueryData(queryKey, result)
      setAttempt(null)
    } catch (error) {
      if (!currentSessionAccess()) return
      setWriteError(error)
      if (!outcomeUnknown(error)) setAttempt(null)
    } finally {
      if (currentSessionAccess()) setWritePending(false)
    }
  }

  const claim = () => {
    if (!query.data || writePending || attempt) return
    const nextAttempt = {
      caseID: query.data.id,
      revision: query.data.revision,
      metadata: createIdentityVerificationReviewWriteMetadata(),
    }
    setAttempt(nextAttempt)
    void executeClaim(nextAttempt)
  }

  const abandon = () => {
    setAttempt(null)
    setWriteError(null)
    setWritePending(false)
    void query.refetch()
  }

  if (query.error instanceof ApiError && query.error.status === 403) {
    return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  if (query.error instanceof ApiError && query.error.status === 404) {
    return <Result status="404" title={t('notFound.title')} subTitle={t('notFound.description')} />
  }

  const item = query.data
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const canClaim = item?.status === 'submitted' && !item.reviewer_user_id
  const canDecide = item?.status === 'reviewing' && item.reviewer_user_id === fixedOwner[3]
  const columns: TableColumnsType<IdentityVerificationReviewMaterial> = [
    { title: t('materials.kind'), dataIndex: 'kind', render: (kind) => t(`materialKinds.${kind}`) },
    { title: t('materials.mime'), dataIndex: 'mime_type' },
    { title: t('materials.size'), dataIndex: 'size_bytes', render: (size) => materialSize(size, locale) },
    { title: t('materials.createdAt'), dataIndex: 'created_at', render: (value) => formatDateTime(value, locale) },
    {
      title: t('materials.custody'), dataIndex: 'encrypted_envelope_present',
      render: (present) => present ? t('materials.encrypted') : t('materials.unavailable'),
    },
  ]

  return (
    <section className="identity-page">
      <Typography.Title level={1}>{t('title')}</Typography.Title>
      {uncertain ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap>
            <Button type="primary" loading={writePending} onClick={() => attempt && void executeClaim(attempt)}>
              {t('actions.retrySameRequest')}
            </Button>
            <Button disabled={writePending} onClick={abandon}>{t('actions.abandonRefresh')}</Button>
          </Space>} className="identity-alert" />
      ) : writeError ? (
        <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} />
      ) : null}

      {query.isPending && !item ? <DataState status="loading" message={t('loading')} /> :
        query.isError ? <DataState
          status="error"
          message={errorMessage(query.error, t)}
          onRetry={() => void query.refetch()}
        /> : item ? (
          <>
            <Descriptions size="small" bordered column={{ xs: 1, sm: 2, lg: 3 }}>
              <Descriptions.Item label={t('details.applicant')}>{item.applicant_user_id}</Descriptions.Item>
              <Descriptions.Item label={t('details.kind')}>{t(`kinds.${item.kind}`)}</Descriptions.Item>
              <Descriptions.Item label={t('details.status')}>
                <Tag color={item.status === 'approved' ? 'success' : item.status === 'rejected' ? 'error' : 'blue'}>
                  {t(`states.${item.status}`)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label={t('details.reviewer')}>
                {item.reviewer_user_id ?? t('details.unassigned')}
              </Descriptions.Item>
              <Descriptions.Item label={t('details.revision')}>v{item.revision}</Descriptions.Item>
              {item.submitted_at ? <Descriptions.Item label={t('details.submittedAt')}>
                {formatDateTime(item.submitted_at, locale)}
              </Descriptions.Item> : null}
              {item.expires_at ? <Descriptions.Item label={t('details.expiresAt')}>
                {formatDateTime(item.expires_at, locale)}
              </Descriptions.Item> : null}
              <Descriptions.Item label={t('details.retention')}>
                {t(`retention.${item.retention.reason_code}`)}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={2}>{t('materials.title')}</Typography.Title>
            <Table<IdentityVerificationReviewMaterial>
              rowKey="id"
              size="small"
              columns={columns}
              dataSource={item.materials}
              pagination={false}
              locale={{ emptyText: t('materials.empty') }}
              scroll={{ x: 720 }}
            />
            <Space className="identity-toolbar" wrap>
              <Button icon={<RefreshCw size={15} aria-hidden="true" />} onClick={() => void query.refetch()}>
                {t('actions.refresh')}
              </Button>
              {canClaim ? <Popconfirm
                title={t('confirmations.claim')}
                okText={t('actions.confirmClaim')}
                onConfirm={claim}
              >
                <Button type="primary" icon={<ShieldCheck size={15} aria-hidden="true" />} disabled={writePending}>
                  {t('actions.claim')}
                </Button>
              </Popconfirm> : null}
              {canDecide ? <Link to={`/sys/identity-verification/${item.id}/decision`}>
                {t('actions.decision')}
              </Link> : null}
            </Space>
          </>
        ) : null}
    </section>
  )
}

export default function IdentityVerificationReviewCasePage() {
  const { t } = useTranslation('identityVerificationReviewCase')
  const { caseId = '' } = useParams<{ caseId: string }>()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(
    () => principal ? reviewOwner(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )

  if (!principal || !accessToken) return null
  if (!owner || !canReview(principal)) {
    return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  if (!caseIDPattern.test(caseId)) {
    return <Result status="404" title={t('invalidCase.title')} subTitle={t('invalidCase.description')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <IdentityVerificationReviewCaseContent key={ownerKey} owner={owner} caseID={caseId} />
}
