import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Descriptions,
  Empty,
  Form,
  Input,
  Popconfirm,
  Result,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
  type TableColumnsType,
} from 'antd'
import { RefreshCw, Search, ShieldCheck } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  createIdentityVerificationWriteMetadata,
  identityVerificationApi,
  type IdentityVerificationCase,
  type IdentityVerificationCreateInput,
  type IdentityVerificationMaterialKind,
  type IdentityVerificationProviderContentType,
  type IdentityVerificationProviderSession,
  type IdentityVerificationProviderUpload,
  type IdentityVerificationProviderUploadInput,
  type IdentityVerificationWriteMetadata,
} from '../api/identityVerification'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import { formatBytes, formatDateTime } from '../i18n/formatters'
import '../i18n/accountIdentityVerification'
import './AccountIdentityVerificationPage.css'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

type Owner = readonly ['tenant', string, string, string, number]
type CreateValues = IdentityVerificationCreateInput
type ProviderValues = { kind: IdentityVerificationCase['kind']; provider: string }
type SanitizedProviderSession = Omit<IdentityVerificationProviderSession, 'evidence_token'>
type WriteAttempt =
  | { kind: 'create'; input: IdentityVerificationCreateInput; metadata: IdentityVerificationWriteMetadata }
  | {
      kind: 'submit' | 'withdraw' | 'expire'
      caseID: string
      revision: number
      metadata: IdentityVerificationWriteMetadata
    }
type ProviderAttempt = {
  input: ProviderValues
  metadata: IdentityVerificationWriteMetadata
}
type UploadAttempt =
  | {
      phase: 'create'
      sessionID: string
      input: IdentityVerificationProviderUploadInput
      file: File
      metadata: IdentityVerificationWriteMetadata
    }
  | {
      phase: 'put'
      upload: IdentityVerificationProviderUpload
      input: IdentityVerificationProviderUploadInput
      file: File
    }
  | {
      phase: 'finalize'
      sessionID: string
      uploadID: string
      revision: number
      metadata: IdentityVerificationWriteMetadata
    }

const caseIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const evidencePattern = /^[A-Za-z0-9][A-Za-z0-9._~-]{31,511}$/
const providerPattern = /^[a-z][a-z0-9._-]{0,63}$/
const queryRoot = 'identity-verification-case'
const uploadContentTypes = new Set<IdentityVerificationProviderContentType>([
  'image/jpeg', 'image/png', 'application/pdf', 'video/mp4',
])
const uploadMaterialKinds: IdentityVerificationMaterialKind[] = [
  'identity_document', 'liveness_evidence', 'business_license', 'legal_person_identity',
  'agent_identity', 'authorization_letter', 'supplementary',
]
const retryableProviderStates = new Set(['creating', 'pending', 'processing', 'unknown'])

function ownerFor(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.scope_id || !principal.tenant_id ||
    !principal.user_id || !sessionEpoch) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal ||
    !principal.permissions.includes('identity_verification.self.manage')) return null
  const owner = ownerFor(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function rateLimited(error: unknown): boolean {
  return error instanceof ApiError && (
    error.status === 429 || error.code === 'rate_limited' ||
    error.code === 'identity_verification_rate_limited'
  )
}

function outcomeUnknown(error: unknown): boolean {
  if (rateLimited(error)) return false
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status >= 500 || error.code === 'invalid_response'
}

const localizedErrorCodes = new Set([
  'network_error', 'invalid_response', 'invalid_request',
  'identity_verification_invalid_request', 'identity_verification_unauthenticated',
  'identity_verification_permission_denied', 'identity_verification_not_found',
  'identity_verification_revision_conflict', 'identity_verification_idempotency_conflict',
  'identity_verification_active_review', 'identity_verification_invalid_transition',
  'identity_verification_initial_approval_required', 'identity_verification_identity_mismatch',
  'identity_verification_already_verified', 'identity_verification_case_expired',
  'identity_verification_case_not_expired', 'identity_verification_evidence_settlement_pending',
  'identity_verification_evidence_invalid', 'identity_verification_trusted_resolver_required',
  'identity_verification_evidence_unavailable', 'identity_verification_request_canceled',
  'identity_verification_request_timeout', 'identity_verification_response_too_large',
  'identity_verification_unavailable', 'identity_verification_provider_result_unknown',
])

function errorMessage(error: unknown, t: TFunction<'accountIdentityVerification'>): string {
  if (rateLimited(error)) return t('errors.rateLimited')
  return error instanceof ApiError && localizedErrorCodes.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.requestFailed'))
}

function clearAttemptSensitiveInput(attempt: WriteAttempt | null): void {
  if (attempt?.kind === 'create') attempt.input.evidence_token = ''
}

async function fileBytes(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new ApiError('Invalid private material', 400, 'invalid_request'))
    reader.onload = () => reader.result instanceof ArrayBuffer
      ? resolve(reader.result)
      : reject(new ApiError('Invalid private material', 400, 'invalid_request'))
    reader.readAsArrayBuffer(file)
  })
}

async function sha256File(file: File): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new ApiError('Digest unavailable', 400, 'invalid_request')
  const digest = await globalThis.crypto.subtle.digest('SHA-256', await fileBytes(file))
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, '0')).join('')
}

function AccountIdentityVerificationContent({ owner }: { owner: Owner }) {
  const { t, i18n } = useTranslation('accountIdentityVerification')
  const [createForm] = Form.useForm<CreateValues>()
  const [providerForm] = Form.useForm<ProviderValues>()
  const queryClient = useQueryClient()
  const ownerKey = JSON.stringify(owner)
  const [caseIDInput, setCaseIDInput] = useState('')
  const [activeCaseID, setActiveCaseID] = useState('')
  const [latestCase, setLatestCase] = useState<IdentityVerificationCase | null>(null)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const attemptRef = useRef<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const [providerSession, setProviderSession] = useState<SanitizedProviderSession | null>(null)
  const [providerAttempt, setProviderAttempt] = useState<ProviderAttempt | null>(null)
  const providerAttemptRef = useRef<ProviderAttempt | null>(null)
  const providerEvidenceRef = useRef<string | null>(null)
  const [providerError, setProviderError] = useState<unknown>(null)
  const [providerPending, setProviderPending] = useState(false)
  const selectedFileRef = useRef<File | null>(null)
  const uploadAttemptRef = useRef<UploadAttempt | null>(null)
  const [uploadRetryAvailable, setUploadRetryAvailable] = useState(false)
  const [uploadState, setUploadState] = useState<IdentityVerificationProviderUpload['state'] | null>(null)
  const [uploadMaterialKind, setUploadMaterialKind] = useState<IdentityVerificationMaterialKind>('identity_document')
  const [uploadError, setUploadError] = useState<unknown>(null)
  const [uploadPending, setUploadPending] = useState(false)

  const clearAttempt = (scrubSensitiveInput = true) => {
    if (scrubSensitiveInput) clearAttemptSensitiveInput(attemptRef.current)
    attemptRef.current = null
    setAttempt(null)
  }

  useEffect(() => () => {
    clearAttemptSensitiveInput(attemptRef.current)
    attemptRef.current = null
    providerAttemptRef.current = null
    providerEvidenceRef.current = null
    selectedFileRef.current = null
    uploadAttemptRef.current = null
  }, [])

  const query = useQuery({
    queryKey: [queryRoot, ownerKey, activeCaseID],
    enabled: Boolean(activeCaseID),
    staleTime: Infinity,
    queryFn: async ({ signal }) => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw new ApiError('Session owner changed', 403, 'identity_verification_permission_denied')
      const result = await identityVerificationApi.getCase(accessToken, activeCaseID, signal)
      if (!currentAccess(ownerKey)) {
        throw new ApiError('Session owner changed', 403, 'identity_verification_permission_denied')
      }
      if (result.applicant_user_id !== owner[3]) {
        throw new ApiError('Invalid identity verification response', 502, 'invalid_response')
      }
      return result
    },
  })

  const currentCase = query.data ?? (latestCase?.id === activeCaseID ? latestCase : undefined)
  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const writesLocked = writePending || uncertain
  const forbidden = (query.error instanceof ApiError && query.error.status === 403) ||
    (writeError instanceof ApiError && writeError.status === 403)
  const unauthorized = (query.error instanceof ApiError && query.error.status === 401) ||
    (writeError instanceof ApiError && writeError.status === 401)

  const execute = async (nextAttempt: WriteAttempt) => {
    if (writePending || !currentAccess(ownerKey)) return
    setWritePending(true)
    setWriteError(null)
    if (nextAttempt.kind === 'create') createForm.resetFields()
    try {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) return
      let result: IdentityVerificationCase
      if (nextAttempt.kind === 'create') {
        result = await identityVerificationApi.createDraft(
          accessToken, nextAttempt.input, nextAttempt.metadata,
        )
      } else {
        result = await identityVerificationApi[nextAttempt.kind](
          accessToken,
          nextAttempt.caseID,
          nextAttempt.revision,
          nextAttempt.metadata,
        )
      }
      if (!currentAccess(ownerKey)) return
      if (result.applicant_user_id !== owner[3]) {
        throw new ApiError('Invalid identity verification response', 502, 'invalid_response')
      }
      queryClient.setQueryData([queryRoot, ownerKey, result.id], result)
      setLatestCase(result)
      setCaseIDInput(result.id)
      setActiveCaseID(result.id)
      clearAttempt(false)
      setWriteError(null)
    } catch (error) {
      if (!currentAccess(ownerKey)) return
      setWriteError(error)
      if (!outcomeUnknown(error)) clearAttempt()
    } finally {
      if (currentAccess(ownerKey)) setWritePending(false)
    }
  }

  const createDraft = (values: CreateValues) => {
    if (writesLocked) return
    const nextAttempt: WriteAttempt = {
      kind: 'create',
      input: { kind: values.kind, evidence_token: values.evidence_token },
      metadata: createIdentityVerificationWriteMetadata('create'),
    }
    clearAttemptSensitiveInput(attemptRef.current)
    attemptRef.current = nextAttempt
    setAttempt(nextAttempt)
    void execute(nextAttempt)
  }

  const executeProvider = async (nextAttempt: ProviderAttempt) => {
    if (providerPending) return
    const accessToken = currentAccess(ownerKey)
    if (!accessToken) return
    setProviderPending(true)
    setProviderError(null)
    try {
      const result = await identityVerificationApi.startProviderSession(
        accessToken, nextAttempt.input, nextAttempt.metadata,
      )
      if (!currentAccess(ownerKey)) return
      const { evidence_token: evidenceToken, ...sanitized } = result
      providerEvidenceRef.current = result.state === 'succeeded' ? evidenceToken ?? null : null
      setProviderSession(sanitized)
      if (!retryableProviderStates.has(result.state)) {
        providerAttemptRef.current = null
        setProviderAttempt(null)
      }
      setProviderError(null)
      selectedFileRef.current = null
      uploadAttemptRef.current = null
      setUploadRetryAvailable(false)
      setUploadState(null)
      setUploadError(null)
    } catch (error) {
      if (!currentAccess(ownerKey)) return
      setProviderError(error)
      if (!outcomeUnknown(error)) {
        providerAttemptRef.current = null
        setProviderAttempt(null)
      }
    } finally {
      if (currentAccess(ownerKey)) setProviderPending(false)
    }
  }

  const startProvider = (values: ProviderValues) => {
    if (providerPending) return
    const nextAttempt: ProviderAttempt = {
      input: { kind: values.kind, provider: values.provider.trim() },
      metadata: createIdentityVerificationWriteMetadata('provider-session'),
    }
    providerEvidenceRef.current = null
    providerAttemptRef.current = nextAttempt
    setProviderAttempt(nextAttempt)
    setProviderSession(null)
    void executeProvider(nextAttempt)
  }

  const abandonProvider = () => {
    providerAttemptRef.current = null
    providerEvidenceRef.current = null
    selectedFileRef.current = null
    uploadAttemptRef.current = null
    setProviderAttempt(null)
    setProviderSession(null)
    setProviderError(null)
    setUploadRetryAvailable(false)
    setUploadState(null)
    setUploadError(null)
  }

  const createDraftFromProvider = () => {
    const evidenceToken = providerEvidenceRef.current
    if (!providerSession || providerSession.state !== 'succeeded' || !evidenceToken) return
    const nextAttempt: WriteAttempt = {
      kind: 'create',
      input: { kind: providerSession.kind, evidence_token: evidenceToken },
      metadata: createIdentityVerificationWriteMetadata('create'),
    }
    providerEvidenceRef.current = null
    clearAttemptSensitiveInput(attemptRef.current)
    attemptRef.current = nextAttempt
    setAttempt(nextAttempt)
    void execute(nextAttempt)
  }

  const executeUpload = async (initialAttempt: UploadAttempt) => {
    if (uploadPending) return
    setUploadPending(true)
    setUploadError(null)
    setUploadRetryAvailable(false)
    let currentAttempt = initialAttempt
    try {
      while (true) {
        uploadAttemptRef.current = currentAttempt
        if (currentAttempt.phase === 'put') {
          await identityVerificationApi.putProviderUpload(
            currentAttempt.upload, currentAttempt.input, currentAttempt.file,
          )
          currentAttempt = {
            phase: 'finalize',
            sessionID: currentAttempt.upload.session_id,
            uploadID: currentAttempt.upload.id,
            revision: currentAttempt.upload.revision,
            metadata: createIdentityVerificationWriteMetadata('provider-finalize'),
          }
          continue
        }
        const accessToken = currentAccess(ownerKey)
        if (!accessToken) return
        if (currentAttempt.phase === 'create') {
          const upload = await identityVerificationApi.createProviderUpload(
            accessToken,
            currentAttempt.sessionID,
            currentAttempt.input,
            currentAttempt.metadata,
          )
          if (!currentAccess(ownerKey)) return
          currentAttempt = {
            phase: 'put', upload, input: currentAttempt.input, file: currentAttempt.file,
          }
          continue
        }
        const finalized = await identityVerificationApi.finalizeProviderUpload(
          accessToken,
          currentAttempt.sessionID,
          currentAttempt.uploadID,
          currentAttempt.revision,
          currentAttempt.metadata,
        )
        if (!currentAccess(ownerKey)) return
        uploadAttemptRef.current = null
        selectedFileRef.current = null
        setUploadState(finalized.state)
        return
      }
    } catch (error) {
      if (!currentAccess(ownerKey)) return
      setUploadError(error)
      const retry = outcomeUnknown(error)
      setUploadRetryAvailable(retry)
      if (!retry) {
        uploadAttemptRef.current = null
        selectedFileRef.current = null
      }
    } finally {
      if (currentAccess(ownerKey)) setUploadPending(false)
    }
  }

  const uploadMaterial = async () => {
    const file = selectedFileRef.current
    if (!providerSession || !file || uploadPending ||
      !uploadContentTypes.has(file.type as IdentityVerificationProviderContentType) ||
      file.size < 1 || file.size > 20 * 1024 * 1024) return
    try {
      const input: IdentityVerificationProviderUploadInput = {
        material_kind: uploadMaterialKind,
        content_type: file.type as IdentityVerificationProviderContentType,
        size_bytes: file.size,
        sha256: await sha256File(file),
      }
      const nextAttempt: UploadAttempt = {
        phase: 'create',
        sessionID: providerSession.id,
        input,
        file,
        metadata: createIdentityVerificationWriteMetadata('provider-upload'),
      }
      void executeUpload(nextAttempt)
    } catch (error) {
      setUploadError(error)
    }
  }

  const selectMaterial = (event: ChangeEvent<HTMLInputElement>) => {
    selectedFileRef.current = event.target.files?.[0] ?? null
    uploadAttemptRef.current = null
    setUploadRetryAvailable(false)
    setUploadState(null)
    setUploadError(null)
  }

  const abandonUpload = () => {
    uploadAttemptRef.current = null
    selectedFileRef.current = null
    setUploadRetryAvailable(false)
    setUploadError(null)
  }

  const transition = (kind: 'submit' | 'withdraw' | 'expire') => {
    if (!currentCase || writesLocked) return
    const nextAttempt: WriteAttempt = {
      kind,
      caseID: currentCase.id,
      revision: currentCase.revision,
      metadata: createIdentityVerificationWriteMetadata(kind),
    }
    clearAttemptSensitiveInput(attemptRef.current)
    attemptRef.current = nextAttempt
    setAttempt(nextAttempt)
    void execute(nextAttempt)
  }

  const abandon = () => {
    const abandonedKind = attempt?.kind
    clearAttempt()
    setWriteError(null)
    setWritePending(false)
    createForm.resetFields()
    if (abandonedKind === 'create') {
      setCaseIDInput('')
      setActiveCaseID('')
      return
    }
    if (activeCaseID) void query.refetch()
  }

  if (forbidden) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  if (unauthorized) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('unauthorized.title')} subTitle={t('unauthorized.description')} />
  }

  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const canSubmit = currentCase?.status === 'draft'
  const canWithdraw = currentCase?.status === 'draft' || currentCase?.status === 'submitted'
  const canExpire = Boolean(
    currentCase?.expires_at &&
    (currentCase.status === 'submitted' || currentCase.status === 'reviewing') &&
    Date.parse(currentCase.expires_at) <= Date.now(),
  )
  const materialColumns: TableColumnsType<IdentityVerificationCase['materials'][number]> = [
    { title: t('materialSummary.kind'), dataIndex: 'kind', render: (kind) => t(`materials.${kind}`) },
    { title: t('materialSummary.mime'), dataIndex: 'mime_type' },
    { title: t('materialSummary.size'), dataIndex: 'size_bytes', render: (size) => formatBytes(size, locale) },
    {
      title: t('materialSummary.custody'),
      dataIndex: 'encrypted_envelope_present',
      render: (present) => present ? t('materialSummary.custodyEncrypted') : t('materialSummary.custodyUnavailable'),
    },
    { title: t('materialSummary.createdAt'), dataIndex: 'created_at', render: (value) => formatDateTime(value, locale) },
  ]

  return (
    <section className="identity-page account-identity-verification-page" aria-labelledby="account-identity-verification-title">
      <h1 id="account-identity-verification-title" className="visually-hidden">{t('title')}</h1>
      <Alert className="identity-alert identity-introduction" type="info" showIcon message={t('introduction')} />

      <Typography.Title className="identity-section-title" level={2}>{t('lookup.title')}</Typography.Title>
      <div className="identity-toolbar identity-lookup-toolbar">
        <Input
          aria-label={t('lookup.caseId')}
          value={caseIDInput}
          placeholder={t('lookup.placeholder')}
          maxLength={36}
          disabled={writesLocked}
          onChange={(event) => setCaseIDInput(event.target.value.trim().toLowerCase())}
          status={caseIDInput && !caseIDPattern.test(caseIDInput) ? 'error' : undefined}
        />
        <Button
          type="primary"
          icon={<Search size={15} aria-hidden="true" />}
          disabled={!caseIDPattern.test(caseIDInput) || writesLocked}
          onClick={() => {
            setWriteError(null)
            setLatestCase(null)
            setActiveCaseID(caseIDInput)
          }}
        >
          {t('actions.lookup')}
        </Button>
        <Button
          icon={<RefreshCw size={15} aria-hidden="true" />}
          disabled={!activeCaseID || writesLocked}
          loading={query.isFetching}
          onClick={() => void query.refetch()}
        >
          {t('actions.refresh')}
        </Button>
      </div>

      <Typography.Title className="identity-section-title" level={2}>{t('create.title')}</Typography.Title>
      <Form<CreateValues>
        className="identity-form identity-create-form"
        form={createForm}
        layout="inline"
        initialValues={{ kind: 'personal_initial' }}
        disabled={writesLocked}
        onFinish={createDraft}
      >
        <Form.Item name="kind" label={t('create.kind')} rules={[{ required: true }]}>
          <Select
            style={{ minWidth: 190 }}
            options={(['personal_initial', 'personal_reverification', 'enterprise'] as const)
              .map((value) => ({ value, label: t(`kinds.${value}`) }))}
          />
        </Form.Item>
        <Form.Item
          name="evidence_token"
          label={t('create.evidenceToken')}
          rules={[
            { required: true, message: t('validation.evidenceRequired') },
            { pattern: evidencePattern, message: t('validation.evidenceFormat') },
          ]}
        >
          <Input.Password
            autoComplete="off"
            maxLength={512}
            placeholder={t('create.evidencePlaceholder')}
          />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" icon={<ShieldCheck size={15} aria-hidden="true" />} loading={writePending}>
            {t('actions.create')}
          </Button>
        </Form.Item>
      </Form>

      <Typography.Title className="identity-section-title" level={2}>{t('provider.title')}</Typography.Title>
      <Form<ProviderValues>
        className="identity-form identity-provider-form"
        form={providerForm}
        layout="inline"
        initialValues={{ kind: 'personal_initial', provider: '' }}
        disabled={providerPending || uploadPending}
        onFinish={startProvider}
      >
        <Form.Item name="kind" label={t('provider.kind')} rules={[{ required: true }]}>
          <Select
            style={{ minWidth: 190 }}
            options={(['personal_initial', 'personal_reverification', 'enterprise'] as const)
              .map((value) => ({ value, label: t(`kinds.${value}`) }))}
          />
        </Form.Item>
        <Form.Item
          name="provider"
          label={t('provider.provider')}
          rules={[
            { required: true, message: t('validation.providerRequired') },
            { pattern: providerPattern, message: t('validation.providerFormat') },
          ]}
        >
          <Input autoComplete="off" maxLength={64} />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={providerPending}>
            {t('provider.start')}
          </Button>
        </Form.Item>
      </Form>

      {providerAttempt && providerError && outcomeUnknown(providerError) ? (
        <OutcomeUnknown title={t('provider.pending')} action={<Space>
            <Button
              type="primary"
              loading={providerPending}
              onClick={() => providerAttemptRef.current && void executeProvider(providerAttemptRef.current)}
            >
              {t('provider.retrySameRequest')}
            </Button>
            <Button disabled={providerPending} onClick={abandonProvider}>{t('actions.abandonRefresh')}</Button>
          </Space>} className="identity-alert" />
      ) : providerError ? (
        <FeedbackWhen title={errorMessage(providerError, t)} />
      ) : providerSession ? (
        <Alert
          className="identity-alert"
          type={providerSession.state === 'succeeded' ? 'success' : (
            ['failed', 'canceled', 'expired'].includes(providerSession.state) ? 'error' : 'info'
          )}
          showIcon
          message={t(`provider.states.${providerSession.state}`)}
          action={providerSession.state === 'succeeded' && providerEvidenceRef.current ? (
            <Button type="primary" onClick={createDraftFromProvider}>{t('provider.createDraft')}</Button>
          ) : retryableProviderStates.has(providerSession.state) && providerAttempt ? (
            <Space>
              <Button
                type="primary"
                loading={providerPending}
                onClick={() => providerAttemptRef.current && void executeProvider(providerAttemptRef.current)}
              >
                {t('provider.retrySameRequest')}
              </Button>
              <Button disabled={providerPending} onClick={abandonProvider}>{t('actions.abandonRefresh')}</Button>
            </Space>
          ) : undefined}
        />
      ) : null}

      {providerSession ? (
        <div className="identity-toolbar identity-upload-toolbar">
          <Select
            aria-label={t('upload.kind')}
            value={uploadMaterialKind}
            disabled={uploadPending}
            style={{ minWidth: 190 }}
            options={uploadMaterialKinds.map((value) => ({ value, label: t(`materials.${value}`) }))}
            onChange={setUploadMaterialKind}
          />
          <input
            type="file"
            aria-label={t('upload.file')}
            accept="image/jpeg,image/png,application/pdf,video/mp4"
            disabled={uploadPending}
            onChange={selectMaterial}
          />
          <Button type="primary" loading={uploadPending} onClick={() => void uploadMaterial()}>
            {t('upload.submit')}
          </Button>
        </div>
      ) : null}
      {uploadState ? (
        <Alert
          className="identity-alert"
          type={uploadState === 'finalized' ? 'success' : 'info'}
          showIcon
          message={t(`upload.states.${uploadState}`)}
        />
      ) : uploadRetryAvailable && uploadError ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space>
            <Button
              type="primary"
              loading={uploadPending}
              onClick={() => uploadAttemptRef.current && void executeUpload(uploadAttemptRef.current)}
            >
              {t('provider.retrySameRequest')}
            </Button>
            <Button disabled={uploadPending} onClick={abandonUpload}>{t('actions.abandonRefresh')}</Button>
          </Space>} className="identity-alert" />
      ) : uploadError ? (
        <FeedbackWhen title={errorMessage(uploadError, t)} />
      ) : null}

      {uncertain ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space>
            <Button type="primary" loading={writePending} onClick={() => attempt && void execute(attempt)}>
              {t('actions.retrySameRequest')}
            </Button>
            <Button disabled={writePending} onClick={abandon}>{t('actions.abandonRefresh')}</Button>
          </Space>} className="identity-alert" />
      ) : writeError ? (
        <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} />
      ) : null}

      <div aria-label={t('details.title')} aria-busy={query.isPending && Boolean(activeCaseID)}>
        {query.isPending && activeCaseID && !currentCase ? <Spin /> : query.isError ? (
          <FeedbackWhen title={t('errors.loadFailed')} detail={errorMessage(query.error, t)} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
        ) : !currentCase ? <Empty description={t('empty.description')} /> : (
          <>
            <Descriptions size="small" bordered column={{ xs: 1, sm: 2, lg: 3 }}>
              <Descriptions.Item label={t('details.id')}>{currentCase.id}</Descriptions.Item>
              <Descriptions.Item label={t('details.kind')}>{t(`kinds.${currentCase.kind}`)}</Descriptions.Item>
              <Descriptions.Item label={t('details.status')}>
                <Tag color={currentCase.status === 'approved' ? 'success' : currentCase.status === 'rejected' ? 'error' : 'blue'}>
                  {t(`states.${currentCase.status}`)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label={t('details.revision')}>v{currentCase.revision}</Descriptions.Item>
              <Descriptions.Item label={t('details.createdAt')}>{formatDateTime(currentCase.created_at, locale)}</Descriptions.Item>
              <Descriptions.Item label={t('details.changedAt')}>{formatDateTime(currentCase.state_changed_at, locale)}</Descriptions.Item>
              {currentCase.expires_at ? <Descriptions.Item label={t('details.expiresAt')}>{formatDateTime(currentCase.expires_at, locale)}</Descriptions.Item> : null}
              {currentCase.status === 'rejected' && currentCase.decision_reason_code ? (
                <Descriptions.Item label={t('details.decisionReason')}>
                  {t(`decisionReasons.${currentCase.decision_reason_code}`)}
                </Descriptions.Item>
              ) : null}
              <Descriptions.Item label={t('details.retention')}>{t(`retention.${currentCase.retention.reason_code}`)}</Descriptions.Item>
              <Descriptions.Item label={t('details.materialCount')}>{currentCase.materials.length}</Descriptions.Item>
              {currentCase.agent_relationship ? <Descriptions.Item label={t('details.relationship')}>{t(`relationships.${currentCase.agent_relationship}`)}</Descriptions.Item> : null}
            </Descriptions>
            <Alert className="identity-alert" type="info" showIcon message={t(`guidance.${currentCase.kind}`)} />
            <Typography.Title className="identity-section-title" level={2}>{t('materialSummary.title')}</Typography.Title>
            <Table
              rowKey="id"
              size="small"
              columns={materialColumns}
              dataSource={currentCase.materials}
              pagination={false}
              locale={{ emptyText: t('materialSummary.empty') }}
              scroll={{ x: 680 }}
            />
            <Space className="identity-toolbar identity-case-actions">
              {canSubmit ? <Popconfirm
                title={t('confirmations.submit')}
                okText={t('actions.confirmSubmit')}
                onConfirm={() => transition('submit')}
              ><Button type="primary" disabled={writesLocked}>{t('actions.submit')}</Button></Popconfirm> : null}
              {canWithdraw ? <Popconfirm
                title={t('confirmations.withdraw')}
                okText={t('actions.confirmWithdraw')}
                onConfirm={() => transition('withdraw')}
              ><Button danger disabled={writesLocked}>{t('actions.withdraw')}</Button></Popconfirm> : null}
              {canExpire ? <Popconfirm
                title={t('confirmations.expire')}
                okText={t('actions.confirmExpire')}
                onConfirm={() => transition('expire')}
              ><Button danger disabled={writesLocked}>{t('actions.expire')}</Button></Popconfirm> : null}
            </Space>
          </>
        )}
      </div>
    </section>
  )
}

export default function AccountIdentityVerificationPage() {
  const { t } = useTranslation('accountIdentityVerification')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const queryClient = useQueryClient()
  const owner = useMemo(
    () => principal ? ownerFor(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const previousOwnerKey = useRef(ownerKey)

  useEffect(() => {
    const previous = previousOwnerKey.current
    if (previous && previous !== ownerKey) {
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] === queryRoot && query.queryKey[1] === previous,
      })
    }
    previousOwnerKey.current = ownerKey
  }, [ownerKey, queryClient])

  if (!principal || !accessToken) return null
  if (!owner || !principal.permissions.includes('identity_verification.self.manage')) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  return <AccountIdentityVerificationContent key={ownerKey} owner={owner} />
}
