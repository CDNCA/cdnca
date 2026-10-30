import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Popconfirm, Radio, Result, Space, Tag } from 'antd'
import { RefreshCw } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  createIdentityVerificationReviewDecisionMetadata,
  identityVerificationReviewDecisionApi,
  type IdentityVerificationReviewDecisionInput,
  type IdentityVerificationReviewDecisionMetadata,
  type IdentityVerificationReviewReason,
} from '../api/identityVerificationReviewDecision'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/identityVerificationReviewDecision'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

type Owner = readonly ['tenant', string, string, string, number]
type WriteAttempt = {
  input: IdentityVerificationReviewDecisionInput
  revision: number
  metadata: IdentityVerificationReviewDecisionMetadata
}

const queryRoot = 'identity-verification-review-decision'
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const rejectionReasons: IdentityVerificationReviewReason[] = [
  'identity_mismatch', 'evidence_incomplete', 'evidence_unreadable',
  'organization_mismatch', 'authorization_invalid', 'suspected_fraud',
]
const localizedErrorCodes = new Set([
  'network_error', 'invalid_response', 'invalid_request', 'identity_verification_invalid_request',
  'identity_verification_unauthenticated', 'identity_verification_permission_denied',
  'identity_verification_not_found', 'identity_verification_revision_conflict',
  'identity_verification_idempotency_conflict', 'identity_verification_invalid_transition',
  'identity_verification_review_assignment_mismatch', 'identity_verification_request_canceled',
  'identity_verification_request_timeout', 'identity_verification_response_too_large',
  'identity_verification_unavailable',
])

function reviewOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.scope_id || !principal.tenant_id ||
    !principal.user_id || sessionEpoch < 1) return null
  if (!principal.permissions.includes('identity_verification.read') ||
    !principal.permissions.includes('identity_verification.review')) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = reviewOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

function errorMessage(error: unknown, t: TFunction<'identityVerificationReviewDecision'>): string {
  return error instanceof ApiError && localizedErrorCodes.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.requestFailed'))
}

function formatDateTime(value: string, locale: string): string {
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
}

function ReviewDecisionContent({ owner, caseID }: { owner: Owner; caseID: string }) {
  const { t, i18n } = useTranslation('identityVerificationReviewDecision')
  const queryClient = useQueryClient()
  const ownerKey = JSON.stringify(owner)
  const [decision, setDecision] = useState<'approved' | 'rejected'>('approved')
  const [reason, setReason] = useState<IdentityVerificationReviewReason>('evidence_verified')
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)

  const queryKey = [queryRoot, ...owner, caseID] as const
  const query = useQuery({
    queryKey,
    enabled: uuidPattern.test(caseID),
    staleTime: Infinity,
    queryFn: async ({ signal }) => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw new ApiError('Session owner changed', 403, 'identity_verification_permission_denied')
      const result = await identityVerificationReviewDecisionApi.getCase(accessToken, caseID, signal)
      if (!currentAccess(ownerKey)) {
        throw new ApiError('Session owner changed', 403, 'identity_verification_permission_denied')
      }
      return result
    },
  })
  const currentCase = query.data
  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const writesLocked = writePending || uncertain
  const forbidden = (query.error instanceof ApiError && query.error.status === 403) ||
    (writeError instanceof ApiError && writeError.status === 403)
  const notFound = query.error instanceof ApiError && query.error.status === 404

  const execute = async (nextAttempt: WriteAttempt) => {
    if (writePending || !currentAccess(ownerKey)) return
    setWritePending(true)
    setWriteError(null)
    try {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) return
      const result = await identityVerificationReviewDecisionApi.decide(
        accessToken, caseID, nextAttempt.revision, nextAttempt.input, nextAttempt.metadata,
      )
      if (!currentAccess(ownerKey)) return
      if (result.reviewer_user_id !== owner[3]) {
        throw new ApiError('Invalid identity verification review response', 502, 'invalid_response')
      }
      queryClient.setQueryData(queryKey, result)
      setAttempt(null)
      setWriteError(null)
    } catch (error) {
      if (!currentAccess(ownerKey)) return
      setWriteError(error)
      if (!outcomeUnknown(error)) setAttempt(null)
    } finally {
      if (currentAccess(ownerKey)) setWritePending(false)
    }
  }

  const submit = () => {
    if (!currentCase || currentCase.status !== 'reviewing' ||
      currentCase.reviewer_user_id !== owner[3] || writesLocked) return
    const nextAttempt: WriteAttempt = {
      input: { decision, reason_code: decision === 'approved' ? 'evidence_verified' : reason },
      revision: currentCase.revision,
      metadata: createIdentityVerificationReviewDecisionMetadata(),
    }
    setAttempt(nextAttempt)
    void execute(nextAttempt)
  }

  const abandon = () => {
    setAttempt(null)
    setWriteError(null)
    setWritePending(false)
    void query.refetch()
  }

  if (forbidden) {
    return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }

  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  return (
    <section className="identity-review-page" aria-labelledby="identity-review-decision-title">
      <h1 id="identity-review-decision-title">{t('title')}</h1>
      <Alert type="info" showIcon message={t('introduction')} />
      <Space className="identity-toolbar">
        <Link to={`/sys/identity-verification/${caseID}`}>{t('actions.back')}</Link>
        <Button
          icon={<RefreshCw size={15} aria-hidden="true" />}
          loading={query.isFetching}
          disabled={writesLocked}
          onClick={() => void query.refetch()}
        >
          {t('actions.refresh')}
        </Button>
      </Space>

      {uncertain ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space>
            <Button type="primary" loading={writePending} onClick={() => attempt && void execute(attempt)}>
              {t('actions.retrySameRequest')}
            </Button>
            <Button disabled={writePending} onClick={abandon}>{t('actions.abandonRefresh')}</Button>
          </Space>} />
      ) : writeError ? (
        <FeedbackWhen title={errorMessage(writeError, t)} />
      ) : null}

      <div aria-label={t('details.title')} aria-busy={query.isPending}>
        {query.isPending ? <DataState status="loading" /> : notFound ? (
          <DataState status="empty" message={t('notFound.title')} />
        ) : query.isError ? (
          <DataState status="error" message={errorMessage(query.error, t)} onRetry={() => void query.refetch()} />
        ) : currentCase ? (
          <>
            <Descriptions size="small" bordered column={{ xs: 1, sm: 2, lg: 3 }}>
              <Descriptions.Item label={t('details.id')}>{currentCase.id}</Descriptions.Item>
              <Descriptions.Item label={t('details.applicant')}>{currentCase.applicant_user_id}</Descriptions.Item>
              <Descriptions.Item label={t('details.kind')}>{t(`kinds.${currentCase.kind}`)}</Descriptions.Item>
              <Descriptions.Item label={t('details.status')}>
                <Tag color={currentCase.status === 'approved' ? 'success' : currentCase.status === 'rejected' ? 'error' : 'blue'}>
                  {t(`states.${currentCase.status}`)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label={t('details.revision')}>v{currentCase.revision}</Descriptions.Item>
              <Descriptions.Item label={t('details.changedAt')}>
                {formatDateTime(currentCase.state_changed_at, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('details.materialCount')}>{currentCase.materials.length}</Descriptions.Item>
            </Descriptions>
            {currentCase.status === 'reviewing' && currentCase.reviewer_user_id === owner[3] ? (
              <div className="identity-review-form">
                <div>{t('decision.title')}</div>
                <Radio.Group
                  value={decision}
                  disabled={writesLocked}
                  onChange={(event) => {
                    const next = event.target.value as 'approved' | 'rejected'
                    setDecision(next)
                    setReason(next === 'approved' ? 'evidence_verified' : 'identity_mismatch')
                  }}
                >
                  <Radio value="approved">{t('decisions.approved')}</Radio>
                  <Radio value="rejected">{t('decisions.rejected')}</Radio>
                </Radio.Group>
                <div>{t('decision.reason')}</div>
                {decision === 'approved' ? <Radio checked disabled>{t('reasons.evidence_verified')}</Radio> : (
                  <Radio.Group
                    value={reason}
                    disabled={writesLocked}
                    onChange={(event) => setReason(event.target.value as IdentityVerificationReviewReason)}
                  >
                    {rejectionReasons.map((value) => (
                      <Radio key={value} value={value}>{t(`reasons.${value}`)}</Radio>
                    ))}
                  </Radio.Group>
                )}
                <Popconfirm
                  title={t('confirmations.submit')}
                  okText={t('actions.confirmSubmit')}
                  onConfirm={submit}
                >
                  <Button type="primary" loading={writePending} disabled={writesLocked}>
                    {t('actions.submit')}
                  </Button>
                </Popconfirm>
              </div>
            ) : null}
          </>
        ) : <DataState status="empty" />}
      </div>
    </section>
  )
}

export default function IdentityVerificationReviewDecisionPage() {
  const { t } = useTranslation('identityVerificationReviewDecision')
  const { caseId = '' } = useParams<{ caseId: string }>()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const queryClient = useQueryClient()
  const owner = useMemo(
    () => principal ? reviewOwner(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const previousOwner = useRef<Owner | null>(owner)

  useEffect(() => {
    const previous = previousOwner.current
    if (previous && JSON.stringify(previous) !== ownerKey) {
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] === queryRoot &&
          query.queryKey.slice(1, 6).every((value, index) => value === previous[index]),
      })
    }
    previousOwner.current = owner
  }, [owner, ownerKey, queryClient])

  if (!principal || !accessToken) return null
  if (!owner) {
    return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  return <ReviewDecisionContent key={ownerKey} owner={owner} caseID={caseId} />
}
