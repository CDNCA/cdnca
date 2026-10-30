import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Descriptions, Drawer, Form, Input, Modal, Result, Select, Space, Table, Tag, Typography, type FormInstance, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, Eye, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  createOriginAuthCredentialWriteMetadata,
  originAuthCredentialsApi,
  type OriginAuthCredential,
  type OriginAuthCredentialSecret,
  type OriginAuthCredentialStatus,
  type OriginAuthCredentialWriteMetadata,
  type OriginAuthProvider,
} from '../api/originAuthCredentials'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/originAuthCredentials'
import { OutcomeUnknown } from '@cdnca/ui'

const readPermission = 'origin_auth.read'
const managePermission = 'origin_auth.manage'
const queryRoots = new Set(['origin-auth-credentials', 'origin-auth-credential'])
const staleRead = new Error('stale origin authentication read')

type Owner = readonly ['tenant', string, string, string, number]
type ProviderFilter = OriginAuthProvider | 'all'
type StatusFilter = OriginAuthCredentialStatus | 'all'
type SecretFormValues = OriginAuthCredentialSecret
type CreateFormValues = SecretFormValues & { provider: OriginAuthProvider; name: string }
type WriteAttemptInput =
  | { kind: 'create'; input: { provider: OriginAuthProvider; name: string; secret: OriginAuthCredentialSecret } }
  | { kind: 'replace'; credentialID: string; revision: number; input: { secret: OriginAuthCredentialSecret } }
  | { kind: 'verify' | 'disable' | 'delete'; credentialID: string; revision: number }
type WriteAttempt = WriteAttemptInput & { metadata: OriginAuthCredentialWriteMetadata }

function credentialOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.scope_id ||
    !principal.tenant_id || !principal.user_id || sessionEpoch < 1) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.permissions.includes(readPermission)
}

function canManage(principal: Principal): boolean {
  return principal.permissions.includes(managePermission)
}

function currentAccess(ownerKey: string): { token: string; scopeID: string } | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal)) return null
  const owner = credentialOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey
    ? { token: accessToken, scopeID: owner[1] }
    : null
}

function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && (
    error.status === 403 || error.code === 'origin_auth_permission_denied' ||
    error.code === 'permission_denied' || error.code === 'origin_auth_entitlement_denied'
  )
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (isForbidden(error)) return 'errors.forbiddenTitle'
  if (error.status === 404 || error.code === 'origin_auth_not_found') return 'errors.notFound'
  if (error.status === 412 || error.code === 'origin_auth_revision_conflict') return 'errors.revisionConflict'
  if (error.status === 409 || error.code.includes('conflict')) return 'errors.conflict'
  if (error.status === 422 || error.code.includes('validation') || error.code.includes('rejected')) return 'errors.validation'
  if (error.status === 429) return 'errors.rateLimited'
  if (error.status === 503 || error.code.includes('unavailable')) return 'errors.unavailable'
  if (error.code === 'network_error') return 'errors.network'
  if (error.code === 'origin_auth_invalid_response' || error.code === 'invalid_response') return 'errors.invalidResponse'
  return 'errors.requestFailed'
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status >= 500 || error.code === 'origin_auth_invalid_response' ||
    error.code === 'invalid_response'
}

function clearAttemptSecrets(attempt: WriteAttempt | null): void {
  if (!attempt || attempt.kind !== 'create' && attempt.kind !== 'replace') return
  attempt.input.secret.access_key_id = ''
  attempt.input.secret.secret_access_key = ''
  delete attempt.input.secret.session_token
  attempt.input.secret.not_before = ''
  attempt.input.secret.expires_at = ''
}

function normalizedSecret(values: SecretFormValues): OriginAuthCredentialSecret {
  return {
    access_key_id: values.access_key_id,
    secret_access_key: values.secret_access_key,
    ...(values.session_token ? { session_token: values.session_token } : {}),
    not_before: values.not_before,
    expires_at: values.expires_at,
  }
}

export default function OriginAuthCredentialsPage() {
  const { t } = useTranslation('originAuthCredentials')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(
    () => principal ? credentialOwner(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const previousOwnerKey = useRef(ownerKey)
  const queryClient = useQueryClient()

  useEffect(() => {
    const previous = previousOwnerKey.current
    if (previous && previous !== ownerKey) {
      const previousOwner = JSON.parse(previous) as Owner
      queryClient.removeQueries({
        predicate: (query) => queryRoots.has(String(query.queryKey[0])) &&
          JSON.stringify(query.queryKey.slice(1, 6)) === JSON.stringify(previousOwner),
      })
    }
    previousOwnerKey.current = ownerKey
  }, [ownerKey, queryClient])

  if (!principal || !accessToken) return null
  if (!owner || !canRead(principal)) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }
  return (
    <OriginAuthCredentialsContent
      key={ownerKey}
      owner={owner}
      ownerKey={ownerKey}
      mayManage={canManage(principal)}
    />
  )
}

function OriginAuthCredentialsContent({
  owner,
  ownerKey,
  mayManage,
}: {
  owner: Owner
  ownerKey: string
  mayManage: boolean
}) {
  const { t, i18n } = useTranslation('originAuthCredentials')
  const { message, modal } = App.useApp()
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const [provider, setProvider] = useState<ProviderFilter>('all')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined])
  const [selectedID, setSelectedID] = useState<string>()
  const [createOpen, setCreateOpen] = useState(false)
  const [replaceCredential, setReplaceCredential] = useState<OriginAuthCredential>()
  const writeAttemptRef = useRef<WriteAttempt | null>(null)
  const [writeAttempt, setWriteAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const [abandonPending, setAbandonPending] = useState(false)
  const [createForm] = Form.useForm<CreateFormValues>()
  const [replaceForm] = Form.useForm<SecretFormValues>()
  const cursor = cursors.at(-1)
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const uncertain = Boolean(writeAttempt && writeError && outcomeUnknown(writeError))
  const writesLocked = writePending || abandonPending || uncertain

  function clearWriteAttempt(): void {
    clearAttemptSecrets(writeAttemptRef.current)
    writeAttemptRef.current = null
    setWriteAttempt(null)
  }

  useEffect(() => () => {
    clearAttemptSecrets(writeAttemptRef.current)
    writeAttemptRef.current = null
  }, [])

  async function guardedRead<T>(read: (access: { token: string; scopeID: string }) => Promise<T>): Promise<T> {
    const access = currentAccess(ownerKey)
    if (!access) throw staleRead
    try {
      const value = await read(access)
      if (!currentAccess(ownerKey)) throw staleRead
      return value
    } catch (error) {
      if (!currentAccess(ownerKey)) throw staleRead
      throw error
    }
  }

  const listQuery = useQuery({
    queryKey: [
      'origin-auth-credentials', ...fixedOwner,
      provider === 'all' ? null : provider,
      status === 'all' ? null : status,
      20,
      cursor ?? null,
    ],
    queryFn: ({ signal }) => guardedRead((access) => originAuthCredentialsApi.list(
      access.token,
      access.scopeID,
      {
        ...(provider === 'all' ? {} : { provider }),
        ...(status === 'all' ? {} : { status }),
        limit: 20,
        cursor,
      },
      signal,
    )),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  const detailQuery = useQuery({
    queryKey: ['origin-auth-credential', ...fixedOwner, selectedID ?? null],
    queryFn: ({ signal }) => guardedRead((access) => originAuthCredentialsApi.get(
      access.token, access.scopeID, selectedID!, signal,
    )),
    enabled: Boolean(selectedID),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  async function executeWrite(attempt: WriteAttempt): Promise<void> {
    const access = currentAccess(ownerKey)
    if (!access || !mayManage || writePending) return
    setWritePending(true)
    setWriteError(null)
    try {
      let result: OriginAuthCredential
      if (attempt.kind === 'create') {
        result = await originAuthCredentialsApi.create(access.token, access.scopeID, attempt.input, attempt.metadata)
      } else if (attempt.kind === 'replace') {
        result = await originAuthCredentialsApi.replace(
          access.token, access.scopeID, attempt.credentialID, attempt.revision, attempt.input, attempt.metadata,
        )
      } else {
        result = await originAuthCredentialsApi[attempt.kind](
          access.token, access.scopeID, attempt.credentialID, attempt.revision, attempt.metadata,
        )
      }
      if (!currentAccess(ownerKey)) return
      clearWriteAttempt()
      setWriteError(null)
      queryClient.setQueryData(['origin-auth-credential', ...fixedOwner, result.id], result)
      await queryClient.invalidateQueries({ queryKey: ['origin-auth-credentials', ...fixedOwner] })
      void message.success(t('write.succeeded'))
    } catch (error) {
      if (!currentAccess(ownerKey)) return
      setWriteError(error)
      if (!outcomeUnknown(error)) clearWriteAttempt()
    } finally {
      if (currentAccess(ownerKey)) setWritePending(false)
    }
  }

  function beginWrite(attempt: WriteAttemptInput): void {
    if (writesLocked || !mayManage || !currentAccess(ownerKey)) return
    const complete = { ...attempt, metadata: createOriginAuthCredentialWriteMetadata() } as WriteAttempt
    clearAttemptSecrets(writeAttemptRef.current)
    writeAttemptRef.current = complete
    setWriteAttempt(complete)
    void executeWrite(complete)
  }

  async function abandonWrite(): Promise<void> {
    if (!writeAttempt || writePending || abandonPending) return
    clearWriteAttempt()
    setWriteError(null)
    setAbandonPending(true)
    try {
      await Promise.all([
        listQuery.refetch(),
        ...(selectedID ? [detailQuery.refetch()] : []),
      ])
    } finally {
      if (currentAccess(ownerKey)) setAbandonPending(false)
    }
  }

  function submitCreate(values: CreateFormValues): void {
    if (Date.parse(values.not_before) >= Date.parse(values.expires_at)) {
      createForm.setFields([{ name: 'expires_at', errors: [t('validation.interval')] }])
      return
    }
    const input = {
      provider: values.provider,
      name: values.name,
      secret: normalizedSecret(values),
    }
    setCreateOpen(false)
    createForm.resetFields()
    beginWrite({ kind: 'create', input })
  }

  function submitReplace(values: SecretFormValues): void {
    if (!replaceCredential) return
    if (Date.parse(values.not_before) >= Date.parse(values.expires_at)) {
      replaceForm.setFields([{ name: 'expires_at', errors: [t('validation.interval')] }])
      return
    }
    const current = replaceCredential
    setReplaceCredential(undefined)
    replaceForm.resetFields()
    beginWrite({
      kind: 'replace', credentialID: current.id, revision: current.revision,
      input: { secret: normalizedSecret(values) },
    })
  }

  function confirmTransition(item: OriginAuthCredential, kind: 'verify' | 'disable' | 'delete'): void {
    const title = t(`dialogs.${kind}Title`)
    const content = t(`dialogs.${kind}Description`)
    modal.confirm({
      title,
      content,
      okText: t('actions.confirm'),
      cancelText: t('actions.cancel'),
      okButtonProps: kind === 'delete' ? { danger: true } : undefined,
      onOk: () => beginWrite({ kind, credentialID: item.id, revision: item.revision }),
    })
  }

  const columns: TableColumnsType<OriginAuthCredential> = [
    { title: t('columns.name'), dataIndex: 'name', width: 190 },
    { title: t('columns.provider'), dataIndex: 'provider', width: 130, render: (value: OriginAuthProvider) => t(`providers.${value}`) },
    { title: t('columns.status'), dataIndex: 'status', width: 120, render: (value: OriginAuthCredentialStatus) => (
      <Tag color={value === 'verified' ? 'success' : value === 'pending' ? 'processing' : 'default'}>{t(`statuses.${value}`)}</Tag>
    ) },
    { title: t('columns.revision'), dataIndex: 'revision', width: 80 },
    { title: t('columns.expiresAt'), dataIndex: 'expires_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180, render: (value: string) => formatDateTime(value, locale) },
    { title: t('columns.actions'), key: 'actions', width: mayManage ? 320 : 110, render: (_, item) => (
      <Space size={4} wrap>
        <Button size="small" icon={<Eye size={14} />} onClick={() => setSelectedID(item.id)}>{t('actions.detail')}</Button>
        {mayManage ? <>
          <Button size="small" disabled={writesLocked} onClick={() => setReplaceCredential(item)}>{t('actions.replace')}</Button>
          {item.status === 'pending' ? <Button size="small" disabled={writesLocked} icon={<ShieldCheck size={14} />} onClick={() => confirmTransition(item, 'verify')}>{t('actions.verify')}</Button> : null}
          {item.status !== 'disabled' && item.status !== 'deleted' ? <Button size="small" disabled={writesLocked} onClick={() => confirmTransition(item, 'disable')}>{t('actions.disable')}</Button> : null}
          {item.status !== 'deleted' ? <Button size="small" disabled={writesLocked} danger icon={<Trash2 size={14} />} onClick={() => confirmTransition(item, 'delete')}>{t('actions.delete')}</Button> : null}
        </> : null}
      </Space>
    ) },
  ]

  if (isForbidden(listQuery.error)) {
    return <DataState status="forbidden" className="identity-page" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} />
  }

  return (
    <section className="identity-page">
      <header className="page-heading">
        <div><Typography.Title level={2}>{t('title')}</Typography.Title><Typography.Text type="secondary">{t('description')}</Typography.Text></div>
        <Space>
          <Button icon={<RefreshCw size={15} />} onClick={() => void listQuery.refetch()}>{t('actions.refresh')}</Button>
          {mayManage ? <Button type="primary" disabled={writesLocked} icon={<Plus size={15} />} onClick={() => setCreateOpen(true)}>{t('actions.create')}</Button> : null}
        </Space>
      </header>

      <Space className="table-toolbar" wrap>
        <Select
          aria-label={t('filters.provider')}
          value={provider}
          style={{ width: 180 }}
          options={[
            { value: 'all', label: t('filters.allProviders') },
            ...(['s3', 'oss', 'cos'] as const).map((value) => ({ value, label: t(`providers.${value}`) })),
          ]}
          onChange={(value: ProviderFilter) => { setProvider(value); setCursors([undefined]) }}
        />
        <Select
          aria-label={t('filters.status')}
          value={status}
          style={{ width: 180 }}
          options={[
            { value: 'all', label: t('filters.allStatuses') },
            ...(['pending', 'verified', 'disabled', 'deleted'] as const).map((value) => ({ value, label: t(`statuses.${value}`) })),
          ]}
          onChange={(value: StatusFilter) => { setStatus(value); setCursors([undefined]) }}
        />
      </Space>

      {writeAttempt && writeError && uncertain ? (
        <OutcomeUnknown title={t('write.unknownTitle')} detail={t('write.unknownDescription')} action={<Space>
            <Button size="small" loading={writePending} disabled={abandonPending} onClick={() => void executeWrite(writeAttempt)}>{t('actions.exactRetry')}</Button>
            <Button size="small" loading={abandonPending} disabled={writePending} onClick={() => { void abandonWrite() }}>{t('actions.abandon')}</Button>
          </Space>} />
      ) : writeError ? <DataState status="error" message={t(errorKey(writeError))} /> : null}

      {listQuery.isPending ? <DataState status="loading" message={t('data.loading')} />
        : listQuery.isError ? <DataState status="error" message={t(errorKey(listQuery.error))} onRetry={() => void listQuery.refetch()} />
          : listQuery.data.items.length === 0 ? <DataState status="empty" message={t('data.empty')} />
            : <Table rowKey="id" size="small" pagination={false} scroll={{ x: 1100 }} columns={columns} dataSource={listQuery.data.items} />}

      <nav className="identity-pagination" aria-label={t('pagination.page', { page: cursors.length })}>
        <Button icon={<ChevronLeft size={16} />} aria-label={t('actions.previous')} disabled={cursors.length === 1} onClick={() => setCursors((current) => current.slice(0, -1))} />
        <span>{t('pagination.page', { page: cursors.length })}</span>
        <Button icon={<ChevronRight size={16} />} aria-label={t('actions.next')} disabled={!listQuery.data?.next_cursor} onClick={() => setCursors((current) => [...current, listQuery.data?.next_cursor])} />
      </nav>

      <Drawer title={t('actions.detail')} open={Boolean(selectedID)} width={680} onClose={() => setSelectedID(undefined)}>
        {detailQuery.isPending ? <DataState status="loading" message={t('data.detailLoading')} />
          : isForbidden(detailQuery.error) ? <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} />
            : detailQuery.isError ? <DataState status="error" message={t(errorKey(detailQuery.error))} onRetry={detailQuery.error instanceof ApiError && detailQuery.error.status === 404 ? undefined : () => void detailQuery.refetch()} />
              : detailQuery.data ? <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label={t('columns.id')}>{detailQuery.data.id}</Descriptions.Item>
                <Descriptions.Item label={t('columns.scope')}>{detailQuery.data.tenant_scope_id}</Descriptions.Item>
                <Descriptions.Item label={t('columns.name')}>{detailQuery.data.name}</Descriptions.Item>
                <Descriptions.Item label={t('columns.provider')}>{t(`providers.${detailQuery.data.provider}`)}</Descriptions.Item>
                <Descriptions.Item label={t('columns.status')}>{t(`statuses.${detailQuery.data.status}`)}</Descriptions.Item>
                <Descriptions.Item label={t('columns.revision')}>{detailQuery.data.revision}</Descriptions.Item>
                <Descriptions.Item label={t('columns.revisionRef')}>{detailQuery.data.revision_ref}</Descriptions.Item>
                <Descriptions.Item label={t('columns.notBefore')}>{formatDateTime(detailQuery.data.not_before, locale)}</Descriptions.Item>
                <Descriptions.Item label={t('columns.expiresAt')}>{formatDateTime(detailQuery.data.expires_at, locale)}</Descriptions.Item>
                <Descriptions.Item label={t('columns.verifiedAt')}>{detailQuery.data.verified_at ? formatDateTime(detailQuery.data.verified_at, locale) : t('values.none')}</Descriptions.Item>
              </Descriptions> : null}
      </Drawer>

      <Modal
        title={t('dialogs.createTitle')}
        open={createOpen}
        okText={t('actions.submit')}
        cancelText={t('actions.cancel')}
        confirmLoading={writePending}
        onOk={() => void createForm.submit()}
        onCancel={() => { setCreateOpen(false); createForm.resetFields() }}
        destroyOnHidden
      >
        <CredentialForm form={createForm} includeIdentity onFinish={submitCreate} />
      </Modal>

      <Modal
        title={t('dialogs.replaceTitle')}
        open={Boolean(replaceCredential)}
        okText={t('actions.submit')}
        cancelText={t('actions.cancel')}
        confirmLoading={writePending}
        onOk={() => void replaceForm.submit()}
        onCancel={() => { setReplaceCredential(undefined); replaceForm.resetFields() }}
        destroyOnHidden
      >
        <CredentialForm form={replaceForm} includeIdentity={false} onFinish={submitReplace} />
      </Modal>
    </section>
  )
}

function CredentialForm<T extends SecretFormValues>({
  form,
  includeIdentity,
  onFinish,
}: {
  form: FormInstance<T>
  includeIdentity: boolean
  onFinish: (values: T) => void
}) {
  const { t } = useTranslation('originAuthCredentials')
  return (
    <Form form={form} layout="vertical" preserve={false} onFinish={onFinish}>
      {includeIdentity ? <>
        <Form.Item name="provider" label={t('fields.provider')} rules={[{ required: true, message: t('validation.required') }]}>
          <Select options={(['s3', 'oss', 'cos'] as const).map((value) => ({ value, label: t(`providers.${value}`) }))} />
        </Form.Item>
        <Form.Item name="name" label={t('fields.name')} rules={[{ required: true, min: 1, max: 128, whitespace: true, message: t('validation.name') }]}>
          <Input maxLength={128} />
        </Form.Item>
      </> : null}
      <Form.Item name="access_key_id" label={t('fields.accessKey')} rules={[{ required: true, min: 1, max: 256, message: t('validation.accessKey') }]}>
        <Input autoComplete="off" maxLength={256} />
      </Form.Item>
      <Form.Item name="secret_access_key" label={t('fields.secretKey')} rules={[{ required: true, min: 1, max: 512, message: t('validation.secretKey') }]}>
        <Input.Password autoComplete="new-password" maxLength={512} visibilityToggle={false} />
      </Form.Item>
      <Form.Item name="session_token" label={t('fields.sessionToken')} rules={[{ max: 4096 }]}>
        <Input.Password autoComplete="new-password" maxLength={4096} visibilityToggle={false} />
      </Form.Item>
      <Form.Item name="not_before" label={t('fields.notBefore')} rules={[{ required: true, pattern: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/, message: t('validation.timestamp') }]}>
        <Input placeholder={t('fields.timestampPlaceholder')} />
      </Form.Item>
      <Form.Item name="expires_at" label={t('fields.expiresAt')} rules={[{ required: true, pattern: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/, message: t('validation.timestamp') }]}>
        <Input placeholder={t('fields.timestampPlaceholder')} />
      </Form.Item>
    </Form>
  )
}
