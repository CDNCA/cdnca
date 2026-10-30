import { useId, useState, useSyncExternalStore } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Result,
  Select,
  Space,
  Spin,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import type { TFunction } from 'i18next'
import { Copy, Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../../api/auth'
import {
  createMfaWriteMetadata,
  mfaApi,
  type ActivateMfaEnrollmentInput,
  type BeginMfaEnrollmentInput,
  type CreateStepUpProofInput,
  type MfaActivationResult,
  type MfaAuthenticationMethod,
  type MfaEnrollmentResult,
  type MfaStepUpProofResult,
  type MfaTerminalInput,
  type MfaWriteMetadata,
} from '../../api/mfa'
import { useSessionStore } from '../../auth/session'
import '../../i18n/accountMfa'
import { localizedUnknownApiError } from '../../i18n/apiError'
import { formatDateTime } from '../../i18n/formatters'

interface EnrollmentFormValues {
  account_label: string
}

interface ActivationFormValues {
  code: string
}

interface TerminalFormValues {
  method: MfaAuthenticationMethod
  code: string
  reason: string
}

interface StepUpFormValues {
  tenant_id: string
  audience: string
  action: string
  method: MfaAuthenticationMethod
  code: string
  ttl_seconds: number
  max_uses: number
}

type WriteOwner = {
  identity: string
  sessionEpoch: number
}

type WriteAttempt = (
  | { kind: 'enroll'; input: BeginMfaEnrollmentInput; metadata: MfaWriteMetadata }
  | {
      kind: 'activate'
      credentialID: string
      input: ActivateMfaEnrollmentInput
      metadata: MfaWriteMetadata
    }
  | { kind: 'disable' | 'reset'; input: MfaTerminalInput; metadata: MfaWriteMetadata }
  | { kind: 'step-up'; input: CreateStepUpProofInput; metadata: MfaWriteMetadata }
) & { owner: WriteOwner }

type SetupReceipt = Extract<MfaEnrollmentResult, { replayed: false }>
type RecoveryReceipt = Extract<MfaActivationResult, { replayed: false }>
type StepUpReceipt = Extract<MfaStepUpProofResult, { replayed: false }>
type ReplayNotice = 'enrollment' | 'activation' | 'step-up' | null
type WriteGeneration = {
  inFlight: number
  revision: number
}
type AuthenticationFailureStatus = 401 | 403
type AuthenticationFence = {
  revision: number
  status: AuthenticationFailureStatus | null
}
type WriteTombstone = {
  generation: WriteGeneration
  kind: WriteAttempt['kind']
  credentialID?: string
  metadata: MfaWriteMetadata
  owner: WriteOwner
}

const unresolvedWrites = new Map<string, WriteTombstone>()
const writeGenerations = new Map<string, WriteGeneration>()
const authenticationFences = new Map<string, AuthenticationFence>()
const unresolvedWriteListeners = new Set<() => void>()
const openAuthenticationFence: AuthenticationFence = { revision: 0, status: null }

function emitUnresolvedWriteChange() {
  for (const listener of unresolvedWriteListeners) listener()
}

function subscribeToUnresolvedWrites(listener: () => void) {
  unresolvedWriteListeners.add(listener)
  return () => unresolvedWriteListeners.delete(listener)
}

function unresolvedWrite(identity: string | null): WriteTombstone | null {
  return identity ? unresolvedWrites.get(identity) ?? null : null
}

function sameWrite(left: WriteTombstone, attempt: WriteAttempt): boolean {
  return left.owner.identity === attempt.owner.identity &&
    left.owner.sessionEpoch === attempt.owner.sessionEpoch &&
    left.metadata.idempotencyKey === attempt.metadata.idempotencyKey
}

function writeGenerationKey(owner: WriteOwner): string {
  return JSON.stringify([owner.identity, owner.sessionEpoch])
}

function authenticationFence(owner: WriteOwner | null): AuthenticationFence {
  return owner ? authenticationFences.get(writeGenerationKey(owner)) ?? openAuthenticationFence
    : openAuthenticationFence
}

function invalidateAuthenticationFence(owner: WriteOwner, status: AuthenticationFailureStatus) {
  const current = authenticationFence(owner)
  if (current.status !== null) return
  authenticationFences.set(writeGenerationKey(owner), { revision: current.revision + 1, status })
  emitUnresolvedWriteChange()
}

function writeInFlight(owner: WriteOwner | null): boolean {
  return Boolean(owner && writeGenerations.get(writeGenerationKey(owner))?.inFlight)
}

function beginWriteGeneration(owner: WriteOwner): boolean {
  if (authenticationFence(owner).status !== null) return false
  const key = writeGenerationKey(owner)
  const generation = writeGenerations.get(key) ?? { inFlight: 0, revision: 0 }
  if (generation.inFlight > 0) return false
  generation.inFlight = 1
  generation.revision += 1
  writeGenerations.set(key, generation)
  emitUnresolvedWriteChange()
  return true
}

function finishWriteGeneration(owner: WriteOwner) {
  const key = writeGenerationKey(owner)
  const generation = writeGenerations.get(key)
  if (!generation) return
  generation.inFlight = Math.max(0, generation.inFlight - 1)
  generation.revision += 1
  const tombstone = unresolvedWrites.get(owner.identity)
  if (generation.inFlight === 0 && tombstone?.generation !== generation) {
    writeGenerations.delete(key)
  }
  emitUnresolvedWriteChange()
}

function rememberUnresolvedWrite(attempt: WriteAttempt) {
  const current = unresolvedWrites.get(attempt.owner.identity)
  if (current && (
    current.owner.sessionEpoch > attempt.owner.sessionEpoch ||
    current.owner.sessionEpoch === attempt.owner.sessionEpoch && !sameWrite(current, attempt)
  )) return
  const generation = writeGenerations.get(writeGenerationKey(attempt.owner))
  if (!generation) return
  unresolvedWrites.set(attempt.owner.identity, {
    generation,
    kind: attempt.kind,
    credentialID: attempt.kind === 'activate' ? attempt.credentialID : undefined,
    metadata: attempt.metadata,
    owner: attempt.owner,
  })
  emitUnresolvedWriteChange()
}

function settledGenerationRevision(tombstone: WriteTombstone | null): number | null {
  return tombstone && tombstone.generation.inFlight === 0 ? tombstone.generation.revision : null
}

function forgetObservedUnresolvedWrite(
  identity: string,
  observed: WriteTombstone | null,
  settledRevision: number | null,
) {
  if (!observed || settledRevision === null || unresolvedWrites.get(identity) !== observed ||
    observed.generation.inFlight !== 0 || observed.generation.revision !== settledRevision) return
  unresolvedWrites.delete(identity)
  writeGenerations.delete(writeGenerationKey(observed.owner))
  emitUnresolvedWriteChange()
}

function principalIdentity(principal: Principal | null): string | null {
  if (!principal?.scope_id || !principal.user_id || principal.impersonation) return null
  if (principal.scope_kind === 'platform' ? principal.tenant_id !== null
    : principal.scope_kind !== 'tenant' || !principal.tenant_id) return null
  return JSON.stringify([
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
  ])
}

const localizedErrorCodes = new Set([
  'network_error',
  'invalid_response',
  'invalid_request',
  'crypto_unavailable',
  'request_failed',
  'mfa_invalid_request',
  'mfa_route_not_found',
  'mfa_method_not_allowed',
  'mfa_request_too_large',
  'mfa_unauthenticated',
  'mfa_principal_changed',
  'mfa_proof_binding',
  'mfa_tenant_unavailable',
  'mfa_already_enabled',
  'mfa_enrollment_pending',
  'mfa_already_active',
  'mfa_idempotency_conflict',
  'mfa_code_replayed',
  'mfa_recovery_code_used',
  'mfa_proof_consumed',
  'mfa_enrollment_expired',
  'mfa_proof_expired',
  'mfa_not_active',
  'mfa_invalid_code',
  'mfa_invalid_proof',
  'mfa_request_canceled',
  'mfa_request_timeout',
  'mfa_encryption_unavailable',
  'mfa_response_too_large',
  'mfa_unavailable',
])
// 后端 /v1/account/mfa* 只要求本人会话（mfahttp actorFromSession + mfa lockPrincipal），
// 不校验任何权限码；代登录会话由 identity.mfa.* 敏感动作拒绝。前端按同一条件判断：
// 本人、非代登录、scope 形状一致即可管理自己的 MFA。
function canManageOwnMfa(principal: Principal | null): boolean {
  return principalIdentity(principal) !== null
}

const mfaStateRowStyle = {
  display: 'flex',
  width: '100%',
  minWidth: 0,
  alignItems: 'flex-start',
  justifyContent: 'space-between',
  gap: 16,
  padding: '4px 0 12px',
  flexWrap: 'wrap' as const,
}

const mfaStateContentStyle = {
  minWidth: 0,
  flex: '1 1 280px',
}

function outcomeUnknown(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  if (error.status === 401 || error.status === 403) return false
  return error.status === 0 || error.status === 408 || error.status === 429 ||
    error.status >= 500 || error.code === 'invalid_response'
}

function errorMessage(error: unknown, t: TFunction<'accountMfa'>): string {
  if (error instanceof ApiError && localizedErrorCodes.has(error.code)) {
    return t(`errors.${error.code}`)
  }
  return localizedUnknownApiError(error, t('errors.request_failed'))
}

function AccountMfaPanelSession({
  accessToken,
  authenticationFailureStatus,
  sessionEpoch,
  principal,
}: {
  accessToken: string | null
  authenticationFailureStatus: AuthenticationFailureStatus | null
  sessionEpoch: number | null
  principal: Principal | null
}) {
  const { t, i18n } = useTranslation('accountMfa')
  const formPrefix = useId()
  const [enrollmentForm] = Form.useForm<EnrollmentFormValues>()
  const [activationForm] = Form.useForm<ActivationFormValues>()
  const [terminalForm] = Form.useForm<TerminalFormValues>()
  const [stepUpForm] = Form.useForm<StepUpFormValues>()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [enrollmentOpen, setEnrollmentOpen] = useState(false)
  const [terminalAction, setTerminalAction] = useState<'disable' | 'reset' | null>(null)
  const [stepUpOpen, setStepUpOpen] = useState(false)
  const [setupReceipt, setSetupReceipt] = useState<SetupReceipt | null>(null)
  const [recoveryReceipt, setRecoveryReceipt] = useState<RecoveryReceipt | null>(null)
  const [stepUpReceipt, setStepUpReceipt] = useState<StepUpReceipt | null>(null)
  const [setupVisible, setSetupVisible] = useState(false)
  const [recoveryVisible, setRecoveryVisible] = useState(false)
  const [stepUpVisible, setStepUpVisible] = useState(false)
  const [writeAttempt, setWriteAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [writeErrorKind, setWriteErrorKind] = useState<WriteAttempt['kind'] | null>(null)
  const [writePending, setWritePending] = useState(false)
  const [confirmingUnknown, setConfirmingUnknown] = useState(false)
  const [replayNotice, setReplayNotice] = useState<ReplayNotice>(null)
  const ownerIdentity = principalIdentity(principal)
  const owner = ownerIdentity && sessionEpoch ? { identity: ownerIdentity, sessionEpoch } : null
  const activeTombstone = useSyncExternalStore(
    subscribeToUnresolvedWrites,
    () => unresolvedWrite(ownerIdentity),
    () => null,
  )
  const unresolved = Boolean(activeTombstone)
  const sharedWritePending = useSyncExternalStore(
    subscribeToUnresolvedWrites,
    () => writeInFlight(owner),
    () => false,
  )

  const isCurrentOwner = (expected: WriteOwner): boolean => {
    const state = useSessionStore.getState()
    return state.sessionEpoch === expected.sessionEpoch &&
      principalIdentity(state.principal) === expected.identity
  }

  const isCurrentAttempt = (expected: WriteOwner, expectedFenceRevision: number): boolean => {
    const fence = authenticationFence(expected)
    return isCurrentOwner(expected) && fence.status === null &&
      fence.revision === expectedFenceRevision
  }

  const clearSensitiveReceipts = () => {
    setSetupReceipt(null)
    setRecoveryReceipt(null)
    setStepUpReceipt(null)
    setSetupVisible(false)
    setRecoveryVisible(false)
    setStepUpVisible(false)
  }

  const clearAuthenticationState = (status: AuthenticationFailureStatus) => {
    if (owner) invalidateAuthenticationFence(owner, status)
    clearSensitiveReceipts()
    if (enrollmentOpen) enrollmentForm.resetFields()
    if (query.data?.status === 'enrollment_pending') activationForm.resetFields()
    if (terminalAction) terminalForm.resetFields()
    if (stepUpOpen) stepUpForm.resetFields()
    setEnrollmentOpen(false)
    setTerminalAction(null)
    setStepUpOpen(false)
    setWriteAttempt(null)
    setWriteError(null)
    setWriteErrorKind(null)
    setReplayNotice(null)
  }

  const allowed = Boolean(
    accessToken && sessionEpoch && authenticationFailureStatus === null &&
    ownerIdentity,
  )
  const canManageMfa = canManageOwnMfa(principal)
  const query = useQuery({
    queryKey: [
      'account-mfa-status',
      principal?.scope_kind,
      principal?.scope_id,
      principal?.tenant_id,
      principal?.user_id,
      sessionEpoch,
    ],
    queryFn: async () => {
      if (!owner || !isCurrentOwner(owner)) throw new Error('MFA session owner changed')
      const requestFenceRevision = authenticationFence(owner).revision
      const observedTombstone = unresolvedWrite(owner.identity)
      // A status fact can clear uncertainty only when no write overlaps the entire read.
      const settledRevision = settledGenerationRevision(observedTombstone)
      try {
        const status = await mfaApi.getStatus(accessToken!)
        if (!isCurrentAttempt(owner, requestFenceRevision)) throw new Error('MFA session owner changed')
        forgetObservedUnresolvedWrite(owner.identity, observedTombstone, settledRevision)
        return status
      } catch (error) {
        if (isCurrentAttempt(owner, requestFenceRevision) && error instanceof ApiError &&
          (error.status === 401 || error.status === 403)) {
          clearAuthenticationState(error.status)
        }
        throw error
      }
    },
    enabled: allowed,
  })

  const copy = (value: string) => {
    if (!navigator.clipboard) {
      feedback.error(t('notices.copyFailed'))
      return
    }
    void navigator.clipboard.writeText(value).then(
      () => messageApi.success(t('notices.copied')),
      () => feedback.error(t('notices.copyFailed')),
    )
  }

  const metadata = (kind: WriteAttempt['kind']): MfaWriteMetadata | null => {
    try {
      return createMfaWriteMetadata(kind)
    } catch (error) {
      const apiError = error instanceof ApiError
        ? error
        : new ApiError('MFA request failed', 0, 'request_failed')
      setWriteError(apiError)
      setWriteErrorKind(kind)
      return null
    }
  }

  const execute = async (attempt: WriteAttempt) => {
    const currentPrincipal = useSessionStore.getState().principal
    if (!accessToken || !canManageOwnMfa(currentPrincipal) ||
      !isCurrentOwner(attempt.owner) || writePending || confirmingUnknown) return
    const requestFenceRevision = authenticationFence(attempt.owner).revision
    if (!beginWriteGeneration(attempt.owner)) return
    let refreshAfterSettled = false
    setWritePending(true)
    setWriteError(null)
    setWriteErrorKind(null)
    setReplayNotice(null)
    try {
      switch (attempt.kind) {
        case 'enroll': {
          const result = await mfaApi.beginEnrollment(accessToken, attempt.input, attempt.metadata)
          if (!isCurrentAttempt(attempt.owner, requestFenceRevision)) return
          setEnrollmentOpen(false)
          enrollmentForm.resetFields()
          if (result.replayed) {
            setSetupReceipt(null)
            setReplayNotice('enrollment')
          } else {
            setSetupVisible(false)
            setSetupReceipt(result)
          }
          break
        }
        case 'activate': {
          const result = await mfaApi.activateEnrollment(
            accessToken,
            attempt.credentialID,
            attempt.input,
            attempt.metadata,
          )
          if (!isCurrentAttempt(attempt.owner, requestFenceRevision)) return
          activationForm.resetFields()
          if (result.replayed) {
            setRecoveryReceipt(null)
            setReplayNotice('activation')
          } else {
            setRecoveryVisible(false)
            setRecoveryReceipt(result)
          }
          break
        }
        case 'disable':
        case 'reset':
          await mfaApi[attempt.kind](accessToken, attempt.input, attempt.metadata)
          if (!isCurrentAttempt(attempt.owner, requestFenceRevision)) return
          terminalForm.resetFields()
          setTerminalAction(null)
          messageApi.success(t(attempt.kind === 'disable' ? 'notices.disabled' : 'notices.reset'))
          break
        case 'step-up': {
          const result = await mfaApi.createStepUpProof(accessToken, attempt.input, attempt.metadata)
          if (!isCurrentAttempt(attempt.owner, requestFenceRevision)) return
          stepUpForm.resetFields()
          setStepUpOpen(false)
          if (result.replayed) {
            setStepUpReceipt(null)
            setReplayNotice('step-up')
          } else {
            setStepUpVisible(false)
            setStepUpReceipt(result)
          }
          break
        }
      }
      setWriteAttempt(null)
      setWriteErrorKind(null)
      refreshAfterSettled = true
    } catch (error) {
      const apiError = error instanceof ApiError
        ? error
        : new ApiError('MFA request failed', 0, 'network_error')
      const authenticationFailure = apiError.status === 401 || apiError.status === 403
      const unknown = !authenticationFailure && outcomeUnknown(apiError)
      if (!isCurrentOwner(attempt.owner)) return
      if (!isCurrentAttempt(attempt.owner, requestFenceRevision)) {
        if (unknown) rememberUnresolvedWrite(attempt)
        return
      }
      if (authenticationFailure) {
        clearAuthenticationState(apiError.status)
        return
      }
      if (unknown) rememberUnresolvedWrite(attempt)
      setWriteError(apiError)
      setWriteErrorKind(attempt.kind)
      const currentTombstone = unresolvedWrite(attempt.owner.identity)
      const remainsUnresolved = Boolean(currentTombstone && sameWrite(currentTombstone, attempt))
      if (unknown || remainsUnresolved) {
        setWriteAttempt(attempt)
        if (unknown) {
          if (attempt.kind === 'enroll') {
            enrollmentForm.resetFields()
            setEnrollmentOpen(false)
          }
          if (attempt.kind === 'activate') activationForm.resetFields()
          if (attempt.kind === 'disable' || attempt.kind === 'reset') {
            terminalForm.resetFields()
            setTerminalAction(null)
          }
          if (attempt.kind === 'step-up') {
            stepUpForm.resetFields()
            setStepUpOpen(false)
          }
        }
      } else {
        setWriteAttempt(null)
      }
    } finally {
      finishWriteGeneration(attempt.owner)
      if (!refreshAfterSettled) setWritePending(false)
    }
    if (refreshAfterSettled && isCurrentAttempt(attempt.owner, requestFenceRevision)) {
      await query.refetch()
      setWritePending(false)
    }
  }

  const cancelUnknownAndRefresh = async () => {
    if (!writeAttempt || !isCurrentOwner(writeAttempt.owner) || confirmingUnknown) return
    const attempt = writeAttempt
    const requestFenceRevision = authenticationFence(attempt.owner).revision
    setConfirmingUnknown(true)
    setEnrollmentOpen(false)
    setTerminalAction(null)
    setStepUpOpen(false)
    stepUpForm.resetFields()
    const result = await query.refetch()
    if (!isCurrentAttempt(attempt.owner, requestFenceRevision)) return
    if (result.isSuccess && result.data) {
      if (attempt.kind === 'enroll' && result.data.status === 'enrollment_pending') {
        setReplayNotice('enrollment')
      }
      if (attempt.kind === 'activate' && result.data.status === 'active') {
        setReplayNotice('activation')
      }
      setWriteAttempt(null)
      setWriteError(null)
      setWriteErrorKind(null)
    } else {
      const refreshError = result.error instanceof ApiError
        ? result.error
        : new ApiError('MFA request failed', 0, 'network_error')
      if (refreshError.status === 401 || refreshError.status === 403) {
        clearAuthenticationState(refreshError.status)
        return
      }
      setWriteError(refreshError)
      setWriteErrorKind(attempt.kind)
    }
    setConfirmingUnknown(false)
  }

  const accessError = writeError ?? query.error
  if (!accessToken || authenticationFailureStatus === 401 ||
    accessError instanceof ApiError && accessError.status === 401) {
    return (
      <section className="account-form-section" aria-labelledby="account-mfa-title">
        <h2 id="account-mfa-title">{t('title')}</h2>
        <Result
          status="403"
          title={t('errors.unauthorizedTitle')}
          subTitle={t('errors.unauthorizedDescription')}
        />
      </section>
    )
  }
  if (!principal || !ownerIdentity || authenticationFailureStatus === 403 ||
    accessError instanceof ApiError && accessError.status === 403) {
    return (
      <section className="account-form-section" aria-labelledby="account-mfa-title">
        <h2 id="account-mfa-title">{t('title')}</h2>
        <Result
          status="403"
          title={t('errors.forbiddenTitle')}
          subTitle={t('errors.forbiddenDescription')}
        />
      </section>
    )
  }
  if (unresolved && !writeAttempt) {
    return (
      <section className="account-form-section" aria-labelledby="account-mfa-title">
        <h2 id="account-mfa-title">{t('title')}</h2>
        <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('uncertainty.reauthenticatedDescription')} action={(
            <Button size="small" loading={query.isFetching} onClick={() => void query.refetch()}>
              {t('actions.refreshStatus')}
            </Button>
          )} />
      </section>
    )
  }
  if (query.isPending) {
    return (
      <section className="account-form-section" aria-label={t('loading')}>
        <Spin size="small" />
      </section>
    )
  }
  if ((query.isError && !writeAttempt && !setupReceipt && !recoveryReceipt && !stepUpReceipt) || !query.data) {
    return (
      <section className="account-form-section" aria-labelledby="account-mfa-title">
        <h2 id="account-mfa-title">{t('title')}</h2>
        <FeedbackWhen title={t('errors.loadTitle')} detail={errorMessage(query.error, t)} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      </section>
    )
  }

  const uncertain = Boolean(writeAttempt)
  const status = query.data
  const writesLocked = sharedWritePending || writePending || confirmingUnknown || uncertain
  const enrollmentDialogError = !uncertain && enrollmentOpen && writeErrorKind === 'enroll' ? writeError : null
  const activationFormError = !uncertain && status.status === 'enrollment_pending' &&
    writeErrorKind === 'activate' ? writeError : null
  const terminalDialogError = !uncertain && terminalAction === writeErrorKind ? writeError : null
  const stepUpDialogError = !uncertain && stepUpOpen && writeErrorKind === 'step-up' ? writeError : null
  const writeErrorOwnedByForm = Boolean(
    enrollmentDialogError || activationFormError || terminalDialogError || stepUpDialogError,
  )

  return (
    <section className="account-form-section account-mfa-panel" aria-labelledby="account-mfa-title">
      {messageContext}
      <h2 id="account-mfa-title">{t('title')}</h2>

      {replayNotice ? (
        <Alert
          className="identity-alert"
          type="warning"
          showIcon
          message={t(replayNotice === 'enrollment'
            ? 'notices.enrollmentReplayed'
            : replayNotice === 'activation' ? 'notices.activationReplayed' : 'notices.stepUpReplayed')}
        />
      ) : null}

      {canManageMfa && uncertain ? (
        <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={(
            <Space wrap>
              <Button
                size="small"
                loading={writePending}
                disabled={writePending || confirmingUnknown}
                onClick={() => { if (writeAttempt) void execute(writeAttempt) }}
              >
                {t('actions.retrySameRequest')}
              </Button>
              <Button
                size="small"
                loading={confirmingUnknown}
                disabled={writePending || confirmingUnknown}
                onClick={() => void cancelUnknownAndRefresh()}
              >
                {t('actions.cancelRefresh')}
              </Button>
            </Space>
          )} className="identity-alert" />
      ) : writeError && !writeErrorOwnedByForm ? (
        <FeedbackWhen title={errorMessage(writeError, t)} />
      ) : null}

      {!uncertain && status.status === 'inactive' ? (
        <div className="account-mfa-state" style={mfaStateRowStyle}>
          <Space direction="vertical" size={8} style={mfaStateContentStyle}>
            <Tag>{t('states.inactive')}</Tag>
            <Typography.Text type="secondary">{t('descriptions.inactive')}</Typography.Text>
            {canManageMfa ? (
              <Button
                type="primary"
                disabled={writesLocked}
                onClick={() => {
                  setWriteError(null)
                  setWriteErrorKind(null)
                  setReplayNotice(null)
                  enrollmentForm.setFieldsValue({ account_label: principal.username })
                  setEnrollmentOpen(true)
                }}
              >
                {t('actions.enroll')}
              </Button>
            ) : null}
          </Space>
        </div>
      ) : null}

      {!uncertain && status.status === 'enrollment_pending' ? (
        <div className="account-mfa-state" style={mfaStateRowStyle}>
          <Space direction="vertical" size={8} style={{ ...mfaStateContentStyle, width: '100%' }}>
            <Tag color="processing">{t('states.pending')}</Tag>
            <Typography.Text type="secondary">
              {t('descriptions.pending', {
                expiresAt: formatDateTime(status.enrollment_expires_at, i18n.resolvedLanguage),
              })}
            </Typography.Text>
            {canManageMfa ? (
              <Form<ActivationFormValues>
                name={`${formPrefix}-activation`}
                form={activationForm}
                style={{ width: 'min(580px, 100%)' }}
                layout="vertical"
                clearOnDestroy
                disabled={writesLocked}
                onFinish={(values) => {
                  if (!owner) return
                  const writeMetadata = metadata('activate')
                  if (!writeMetadata) return
                  const attempt: WriteAttempt = {
                    kind: 'activate',
                    credentialID: status.credential_id,
                    input: { code: values.code },
                    metadata: writeMetadata,
                    owner,
                  }
                  void execute(attempt)
                }}
              >
                {activationFormError ? (
                  <Alert
                    className="identity-alert"
                    type="error"
                    showIcon
                    message={errorMessage(activationFormError, t)}
                  />
                ) : null}
                <Form.Item
                  name="code"
                  label={t('labels.code')}
                  rules={[
                    { required: true, message: t('validation.codeRequired') },
                    { pattern: /^\d{6}$/, message: t('validation.codeFormat') },
                  ]}
                >
                  <Input.Password inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={writePending} disabled={writesLocked}>
                  {t('actions.activate')}
                </Button>
              </Form>
            ) : null}
          </Space>
        </div>
      ) : null}

      {!uncertain && status.status === 'active' ? (
        <div className="account-mfa-state" style={mfaStateRowStyle}>
          <Space direction="vertical" size={8} style={mfaStateContentStyle}>
            <Tag color="success">{t('states.active')}</Tag>
            <Typography.Text type="secondary">{t('descriptions.active')}</Typography.Text>
            {canManageMfa ? <Space wrap>
              <Button
                danger
                disabled={writesLocked}
                onClick={() => {
                  setWriteError(null)
                  setWriteErrorKind(null)
                  terminalForm.resetFields()
                  terminalForm.setFieldsValue({ method: 'totp' })
                  setTerminalAction('disable')
                }}
              >
                {t('actions.disable')}
              </Button>
              <Button
                disabled={writesLocked}
                onClick={() => {
                  setWriteError(null)
                  setWriteErrorKind(null)
                  terminalForm.resetFields()
                  terminalForm.setFieldsValue({ method: 'totp' })
                  setTerminalAction('reset')
                }}
              >
                {t('actions.reset')}
              </Button>
              {principal.scope_kind === 'tenant' ? <Button
                disabled={writesLocked}
                onClick={() => {
                  setWriteError(null)
                  setWriteErrorKind(null)
                  setReplayNotice(null)
                  stepUpForm.resetFields()
                  stepUpForm.setFieldsValue({
                    tenant_id: principal?.tenant_id ?? '',
                    method: 'totp',
                    ttl_seconds: 60,
                    max_uses: 1,
                  })
                  setStepUpOpen(true)
                }}
              >
                {t('actions.createStepUp')}
              </Button> : null}
            </Space> : null}
          </Space>
        </div>
      ) : null}

      {canManageMfa && principal.scope_kind === 'tenant' && stepUpOpen ? (
        <Modal
          open
          title={t('dialogs.stepUp')}
          okText={t('actions.confirm')}
          cancelText={t('actions.cancel')}
          confirmLoading={writePending}
          okButtonProps={{ disabled: writesLocked }}
          cancelButtonProps={{ disabled: writePending }}
          onOk={() => stepUpForm.submit()}
          onCancel={() => {
            if (writePending) return
            setStepUpOpen(false)
            setWriteError(null)
            setWriteErrorKind(null)
            stepUpForm.resetFields()
          }}
        >
          {stepUpDialogError ? (
            <Alert className="identity-alert" type="error" showIcon message={errorMessage(stepUpDialogError, t)} />
          ) : null}
          <Form<StepUpFormValues>
            name={`${formPrefix}-step-up`}
            form={stepUpForm}
            layout="vertical"
            clearOnDestroy
            disabled={writesLocked}
            onFinish={(values) => {
              if (!owner) return
              const writeMetadata = metadata('step-up')
              if (!writeMetadata) return
              const input: CreateStepUpProofInput = {
                tenant_id: values.tenant_id,
                audience: values.audience.trim(),
                action: values.action.trim(),
                authentication: { method: values.method, code: values.code },
                ttl_seconds: values.ttl_seconds,
                max_uses: values.max_uses,
              }
              void execute({ kind: 'step-up', input, metadata: writeMetadata, owner })
            }}
          >
            <Form.Item name="tenant_id" label={t('labels.tenantId')} rules={[{ required: true }]}> 
              <Input readOnly autoComplete="off" />
            </Form.Item>
            <Form.Item
              name="audience"
              label={t('labels.audience')}
              rules={[
                { required: true, message: t('validation.audienceRequired') },
                { max: 128, message: t('validation.audienceLength') },
                { pattern: /^\S(?:[\s\S]*\S)?$/, message: t('validation.audienceFormat') },
              ]}
            >
              <Input autoComplete="off" maxLength={128} />
            </Form.Item>
            <Form.Item
              name="action"
              label={t('labels.action')}
              rules={[
                { required: true, message: t('validation.actionRequired') },
                { max: 128, message: t('validation.actionLength') },
                { pattern: /^\S(?:[\s\S]*\S)?$/, message: t('validation.actionFormat') },
              ]}
            >
              <Input autoComplete="off" maxLength={128} />
            </Form.Item>
            <Space wrap>
              <Form.Item name="ttl_seconds" label={t('labels.ttlSeconds')} rules={[{ required: true }]}> 
                <InputNumber min={1} max={300} precision={0} />
              </Form.Item>
              <Form.Item name="max_uses" label={t('labels.maxUses')} rules={[{ required: true }]}> 
                <InputNumber min={1} max={5} precision={0} />
              </Form.Item>
            </Space>
            <Form.Item name="method" label={t('labels.authenticationMethod')} rules={[{ required: true }]}> 
              <Select options={[
                { value: 'totp', label: t('methods.totp') },
                { value: 'recovery_code', label: t('methods.recovery_code') },
              ]} onChange={() => { void stepUpForm.validateFields(['code']).catch(() => undefined) }} />
            </Form.Item>
            <Form.Item
              name="code"
              label={t('labels.authenticationCode')}
              dependencies={['method']}
              rules={[
                { required: true, message: t('validation.authenticationCodeRequired') },
                {
                  validator: (_, value: unknown) => {
                    if (typeof value !== 'string' || value.length === 0) return Promise.resolve()
                    const method = stepUpForm.getFieldValue('method') as MfaAuthenticationMethod
                    const valid = method === 'totp'
                      ? /^\d{6}$/.test(value)
                      : /^[A-Z2-7]{8}(?:-[A-Z2-7]{8}){3}$/.test(value)
                    return valid
                      ? Promise.resolve()
                      : Promise.reject(new Error(t(method === 'totp'
                        ? 'validation.totpCodeFormat'
                        : 'validation.recoveryCodeFormat')))
                  },
                },
              ]}
            >
              <Input.Password autoComplete="one-time-code" maxLength={64} />
            </Form.Item>
          </Form>
        </Modal>
      ) : null}

      {canManageMfa && enrollmentOpen ? (
        <Modal
          open
          title={t('dialogs.enrollment')}
          okText={t('actions.confirm')}
          cancelText={t('actions.cancel')}
          confirmLoading={writePending}
          okButtonProps={{ disabled: writesLocked }}
          cancelButtonProps={{ disabled: writePending }}
          onOk={() => enrollmentForm.submit()}
          onCancel={() => {
            if (writePending) return
            setEnrollmentOpen(false)
            setWriteError(null)
            setWriteErrorKind(null)
            enrollmentForm.resetFields()
          }}
        >
          {enrollmentDialogError ? (
            <Alert
              className="identity-alert"
              type="error"
              showIcon
              message={errorMessage(enrollmentDialogError, t)}
            />
          ) : null}
          <Form<EnrollmentFormValues>
            name={`${formPrefix}-enrollment`}
            form={enrollmentForm}
            layout="vertical"
            clearOnDestroy
            disabled={writesLocked}
            onFinish={(values) => {
              if (!owner) return
              const writeMetadata = metadata('enroll')
              if (!writeMetadata) return
              const attempt: WriteAttempt = {
                kind: 'enroll',
                input: { account_label: values.account_label.trim() },
                metadata: writeMetadata,
                owner,
              }
              void execute(attempt)
            }}
          >
            <Form.Item
              name="account_label"
              label={t('labels.accountLabel')}
              rules={[
                { required: true, whitespace: true, message: t('validation.accountLabelRequired') },
                { max: 254, message: t('validation.accountLabelLength') },
                {
                  validator: (_, value: unknown) => {
                    const hasControlCharacter = typeof value === 'string' && [...value].some((character) => {
                      const codePoint = character.codePointAt(0)!
                      return codePoint <= 0x1f || codePoint >= 0x7f && codePoint <= 0x9f ||
                        codePoint === 0x2028 || codePoint === 0x2029
                    })
                    return typeof value !== 'string' || value.trim() !== value ||
                      /[:/\\]/.test(value) || hasControlCharacter
                      ? Promise.reject(new Error(t('validation.accountLabelFormat')))
                      : Promise.resolve()
                  },
                },
              ]}
            >
              <Input autoComplete="off" maxLength={254} />
            </Form.Item>
          </Form>
        </Modal>
      ) : null}

      {canManageMfa && terminalAction ? (
        <Modal
          open
          title={t(terminalAction === 'reset' ? 'dialogs.reset' : 'dialogs.disable')}
          okText={t('actions.confirm')}
          cancelText={t('actions.cancel')}
          confirmLoading={writePending}
          okButtonProps={{ disabled: writesLocked }}
          cancelButtonProps={{ disabled: writePending }}
          onOk={() => terminalForm.submit()}
          onCancel={() => {
            if (writePending) return
            setTerminalAction(null)
            setWriteError(null)
            setWriteErrorKind(null)
            terminalForm.resetFields()
          }}
        >
          {terminalDialogError ? (
            <Alert
              className="identity-alert"
              type="error"
              showIcon
              message={errorMessage(terminalDialogError, t)}
            />
          ) : null}
          <Form<TerminalFormValues>
            name={`${formPrefix}-terminal`}
            form={terminalForm}
            layout="vertical"
            clearOnDestroy
            disabled={writesLocked}
            onFinish={(values) => {
              if (!owner) return
              const writeMetadata = metadata(terminalAction)
              if (!writeMetadata) return
              const attempt: WriteAttempt = {
                kind: terminalAction,
                input: {
                  authentication: { method: values.method, code: values.code },
                  reason: values.reason.trim(),
                },
                metadata: writeMetadata,
                owner,
              }
              void execute(attempt)
            }}
          >
            <Form.Item name="method" label={t('labels.authenticationMethod')} initialValue="totp">
              <Select options={[
                { value: 'totp', label: t('methods.totp') },
                { value: 'recovery_code', label: t('methods.recovery_code') },
              ]} onChange={() => { void terminalForm.validateFields(['code']).catch(() => undefined) }} />
            </Form.Item>
            <Form.Item
              name="code"
              label={t('labels.authenticationCode')}
              dependencies={['method']}
              rules={[
                { required: true, message: t('validation.authenticationCodeRequired') },
                {
                  validator: (_, value: unknown) => {
                    if (typeof value !== 'string' || value.length === 0) return Promise.resolve()
                    const method = terminalForm.getFieldValue('method') as MfaAuthenticationMethod
                    const valid = method === 'totp'
                      ? /^\d{6}$/.test(value)
                      : /^[A-Z2-7]{8}(?:-[A-Z2-7]{8}){3}$/.test(value)
                    return valid
                      ? Promise.resolve()
                      : Promise.reject(new Error(t(method === 'totp'
                        ? 'validation.totpCodeFormat'
                        : 'validation.recoveryCodeFormat')))
                  },
                },
              ]}
            >
              <Input.Password autoComplete="one-time-code" maxLength={64} />
            </Form.Item>
            <Form.Item
              name="reason"
              label={t('labels.reason')}
              rules={[
                { required: true, whitespace: true, message: t('validation.reasonRequired') },
                { max: 512, message: t('validation.reasonLength') },
              ]}
            >
              <Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} maxLength={512} />
            </Form.Item>
          </Form>
        </Modal>
      ) : null}

      {stepUpReceipt ? (
        <Modal
          open
          title={t('dialogs.stepUpReceipt')}
          closable={false}
          maskClosable={false}
          keyboard={false}
          footer={[
            <Button
              key="saved"
              type="primary"
              onClick={() => {
                setStepUpReceipt(null)
                setStepUpVisible(false)
              }}
            >
              {t('actions.saved')}
            </Button>,
          ]}
        >
          <Alert className="identity-alert" type="warning" showIcon message={t('sensitive.stepUpWarning')} />
          <Form layout="vertical">
            <Form.Item label={t('labels.proofId')}>
              <Input value={stepUpReceipt.proof_id} readOnly />
            </Form.Item>
            <Form.Item label={t('labels.stepUpToken')}>
              <Space.Compact block>
                <Input.Password
                  aria-label={t('labels.stepUpToken')}
                  value={stepUpReceipt.token}
                  readOnly
                  visibilityToggle={{ visible: stepUpVisible, onVisibleChange: setStepUpVisible }}
                />
                <Tooltip title={t('actions.copyStepUpToken')}>
                  <Button
                    aria-label={t('actions.copyStepUpToken')}
                    icon={<Copy size={15} />}
                    onClick={() => copy(stepUpReceipt.token)}
                  />
                </Tooltip>
              </Space.Compact>
            </Form.Item>
            <Typography.Text type="secondary">
              {t('descriptions.stepUpReceipt', {
                expiresAt: formatDateTime(stepUpReceipt.expires_at, i18n.resolvedLanguage),
                maxUses: stepUpReceipt.max_uses,
              })}
            </Typography.Text>
          </Form>
        </Modal>
      ) : null}

      {setupReceipt ? (
        <Modal
          open
          title={t('dialogs.setupReceipt')}
          closable={false}
          maskClosable={false}
          keyboard={false}
          footer={[
            <Button
              key="saved"
              type="primary"
              onClick={() => {
                setSetupReceipt(null)
                setSetupVisible(false)
              }}
            >
              {t('actions.saved')}
            </Button>,
          ]}
        >
          <Alert className="identity-alert" type="warning" showIcon message={t('sensitive.setupWarning')} />
          <Form layout="vertical">
            <Form.Item label={t('labels.secret')}>
              <Space.Compact block>
                <Input.Password
                  aria-label={t('labels.secret')}
                  value={setupReceipt.secret}
                  readOnly
                  visibilityToggle={{ visible: setupVisible, onVisibleChange: setSetupVisible }}
                />
                <Tooltip title={t('actions.copySecret')}>
                  <Button
                    aria-label={t('actions.copySecret')}
                    icon={<Copy size={15} />}
                    onClick={() => copy(setupReceipt.secret)}
                  />
                </Tooltip>
              </Space.Compact>
            </Form.Item>
            <Form.Item label={t('labels.provisioningUri')}>
              <Space.Compact block>
                <Input.Password
                  aria-label={t('labels.provisioningUri')}
                  value={setupReceipt.provisioning_uri}
                  readOnly
                  visibilityToggle={{ visible: setupVisible, onVisibleChange: setSetupVisible }}
                />
                <Tooltip title={t('actions.copyProvisioningUri')}>
                  <Button
                    aria-label={t('actions.copyProvisioningUri')}
                    icon={<Copy size={15} />}
                    onClick={() => copy(setupReceipt.provisioning_uri)}
                  />
                </Tooltip>
              </Space.Compact>
            </Form.Item>
          </Form>
        </Modal>
      ) : null}

      {recoveryReceipt ? (
        <Modal
          open
          title={t('dialogs.recoveryReceipt')}
          closable={false}
          maskClosable={false}
          keyboard={false}
          footer={[
            <Button
              key="saved"
              type="primary"
              onClick={() => {
                setRecoveryReceipt(null)
                setRecoveryVisible(false)
              }}
            >
              {t('actions.saved')}
            </Button>,
          ]}
        >
          <Alert className="identity-alert" type="warning" showIcon message={t('sensitive.recoveryWarning')} />
          {recoveryVisible ? (
            <ul aria-label={t('dialogs.recoveryReceipt')}>
              {recoveryReceipt.recovery_codes.map((code, index) => (
                <li key={index}><code>{code}</code></li>
              ))}
            </ul>
          ) : (
            <Typography.Text type="secondary">{t('sensitive.recoveryHidden')}</Typography.Text>
          )}
          <Space wrap style={{ marginTop: 12 }}>
            <Tooltip title={t(recoveryVisible ? 'actions.hideRecoveryCodes' : 'actions.showRecoveryCodes')}>
              <Button
                aria-label={t(recoveryVisible ? 'actions.hideRecoveryCodes' : 'actions.showRecoveryCodes')}
                icon={recoveryVisible ? <EyeOff size={15} /> : <Eye size={15} />}
                onClick={() => setRecoveryVisible((visible) => !visible)}
              />
            </Tooltip>
            <Tooltip title={t('actions.copyRecoveryCodes')}>
              <Button
                aria-label={t('actions.copyRecoveryCodes')}
                icon={<Copy size={15} />}
                onClick={() => copy(recoveryReceipt.recovery_codes.join('\n'))}
              />
            </Tooltip>
          </Space>
        </Modal>
      ) : null}
    </section>
  )
}

export default function AccountMfaPanel() {
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const principal = useSessionStore((state) => state.principal)
  const ownerIdentity = principalIdentity(principal)
  const owner = ownerIdentity && sessionEpoch ? { identity: ownerIdentity, sessionEpoch } : null
  const authFence = useSyncExternalStore(
    subscribeToUnresolvedWrites,
    () => authenticationFence(owner),
    () => openAuthenticationFence,
  )
  const identityBoundary = [
    principal?.scope_kind ?? 'none',
    principal?.scope_id ?? 'none',
    principal?.tenant_id ?? 'none',
    principal?.user_id ?? 'none',
    sessionEpoch ?? 'none',
    canManageOwnMfa(principal) ? 'manage' : 'read-only',
    authFence.revision,
  ].join(':')
  return (
    <AccountMfaPanelSession
      key={identityBoundary}
      accessToken={accessToken}
      authenticationFailureStatus={authFence.status}
      sessionEpoch={sessionEpoch}
      principal={principal}
    />
  )
}
