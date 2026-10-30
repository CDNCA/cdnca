import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Pagination,
  Popconfirm,
  Result,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown, fieldReasonText, useFormSubmitError, type FormErrorMap, type SubmitFieldError } from '@cdnca/ui'
import type { TFunction } from 'i18next'
import { Copy, KeyRound, Pencil, Plus, Power, RefreshCw, ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type ScopeKind } from '../api/auth'
import { formatDateTime } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import { sitesApi } from '../api/sites'
import {
  urlAuthPoliciesApi,
  type URLAuthPolicy,
  type URLAuthPolicyFields,
  type URLAuthSecretWriteResult,
  type URLAuthWriteResult,
} from '../api/urlAuthPolicies'
import { useSessionStore } from '../auth/session'
import TenantScopeSelect from '../components/TenantScopeSelect'

interface PolicyFormValues {
  target_scope_id?: string
  owner_id?: string
  site_id: string
  name: string
  enabled: boolean
  signature_parameter: string
  expiration_parameter: string
  key_id_parameter: string
  bind_client_ip: boolean
  max_clock_skew_seconds: number
  max_validity_seconds: number
  max_signature_uses: number
  excluded_query_parameters: string
  trusted_proxy_cidrs: string
}

type WriteAttempt =
  | { kind: 'create'; input: URLAuthPolicyFields & { target_scope_id?: string; owner_id?: string }; key: string }
  | { kind: 'update'; id: string; version: number; input: URLAuthPolicyFields; key: string }
  | { kind: 'enable' | 'disable'; id: string; version: number; key: string }
  | { kind: 'rotate'; id: string; version: number; key: string }
  | { kind: 'revoke'; id: string; version: number; keyID: string; key: string }

const canonicalUUIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function writeKey(kind: WriteAttempt['kind']): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `url-auth-${kind}-${suffix}`
}

function unknownOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

function errorMessage(error: unknown, t: TFunction<'urlAuthPolicies'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const known = new Set([
    'validation_error', 'permission_denied', 'version_conflict', 'idempotency_conflict',
    'url_auth_policy_conflict', 'url_auth_key_not_revocable', 'credential_encryption_unavailable',
    'network_error', 'request_failed',
  ])
  return known.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.request_failed'))
}

function dateTime(value: string, locale: string): string {
  return formatDateTime(value, locale) || value
}

// fix-fielderr-be4: list entries (excluded_query_parameters[n], trusted_proxy_cidrs[n])
// are one-per-line text boxes; the refused entry is named in the message.
const listFields = ['excluded_query_parameters', 'trusted_proxy_cidrs'] as const
const policyErrorMap: FormErrorMap = Object.fromEntries(listFields.flatMap((name) =>
  Array.from({ length: 64 }, (_, index) => [`${name}[${index}]`, name] as const)))

function splitValues(value: string): string[] {
  return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)
}

function policyFields(item: URLAuthPolicy): URLAuthPolicyFields {
  return {
    site_id: item.site.id,
    name: item.name,
    enabled: item.enabled,
    algorithm: 'hmac-sha256',
    signature_parameter: item.signature_parameter,
    expiration_parameter: item.expiration_parameter,
    key_id_parameter: item.key_id_parameter,
    bind_client_ip: item.bind_client_ip,
    max_clock_skew_seconds: item.max_clock_skew_seconds,
    max_validity_seconds: item.max_validity_seconds,
    max_signature_uses: item.max_signature_uses,
    excluded_query_parameters: [...item.excluded_query_parameters],
    trusted_proxy_cidrs: [...item.trusted_proxy_cidrs],
  }
}

function hasURLAuthReadPermission(permissions: readonly string[]): boolean {
  return permissions.includes('url_auth_policies.read') || permissions.includes('platform.admin')
}

function hasURLAuthManagePermission(permissions: readonly string[]): boolean {
  return permissions.includes('url_auth_policies.manage') || permissions.includes('platform.admin')
}

function urlAuthSessionMatches(
  scopeKind: ScopeKind,
  scopeID: string,
  userID: string,
  sessionEpoch: number,
): boolean {
  const current = useSessionStore.getState()
  return current.sessionEpoch === sessionEpoch &&
    current.principal?.scope_kind === scopeKind &&
    current.principal.scope_id === scopeID &&
    current.principal.user_id === userID
}

function currentURLAuthWriteToken(
  scopeKind: ScopeKind,
  scopeID: string,
  userID: string,
  sessionEpoch: number,
): string | null {
  const current = useSessionStore.getState()
  if (current.sessionEpoch !== sessionEpoch ||
    current.principal?.scope_kind !== scopeKind ||
    current.principal.scope_id !== scopeID ||
    current.principal.user_id !== userID ||
    !hasURLAuthManagePermission(current.principal.permissions)) {
    return null
  }
  return current.accessToken
}

export default function UrlAuthPoliciesPage() {
  const { t } = useTranslation('urlAuthPolicies')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  if (!hasURLAuthReadPermission(principal.permissions)) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }

  return (
    <UrlAuthPoliciesContent
      key={`${principal.scope_kind}:${principal.scope_id}:${principal.user_id}:${sessionEpoch}`}
      accessToken={accessToken}
      scopeKind={principal.scope_kind}
      scopeID={principal.scope_id}
      userID={principal.user_id}
      sessionEpoch={sessionEpoch}
      permissions={principal.permissions}
    />
  )
}

function UrlAuthPoliciesContent({
  accessToken,
  scopeKind,
  scopeID,
  userID,
  sessionEpoch,
  permissions,
}: {
  accessToken: string
  scopeKind: ScopeKind
  scopeID: string
  userID: string
  sessionEpoch: number
  permissions: string[]
}) {
  const { t, i18n } = useTranslation('urlAuthPolicies')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const isPlatform = scopeKind === 'platform'
  const canManage = hasURLAuthManagePermission(permissions)
  const queryClient = useQueryClient()
  const [form] = Form.useForm<PolicyFormValues>()
  // The last submitted body, to name a refused list entry by its value.
  const submittedRef = useRef<URLAuthPolicyFields | null>(null)
  const markSubmitError = useFormSubmitError(form, policyErrorMap, { message: ({ field, reason }: SubmitFieldError) => {
    const match = /^(excluded_query_parameters|trusted_proxy_cidrs)\[(\d+)\]$/.exec(field)
    const value = match ? submittedRef.current?.[match[1] as typeof listFields[number]]?.[Number(match[2])] : undefined
    const locale = i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn'
    return value === undefined ? undefined : `${value}：${fieldReasonText(reason, locale)}`
  } })
  const platformTargetScopeID = Form.useWatch('target_scope_id', form)
  const platformOwnerID = Form.useWatch('owner_id', form)
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(20)
  const [nameDraft, setNameDraft] = useState('')
  const [name, setName] = useState('')
  const [status, setStatus] = useState<'enabled' | 'disabled'>()
  const [editor, setEditor] = useState<URLAuthPolicy | 'create' | null>(null)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [issued, setIssued] = useState<{ secret: string; keyID: string } | null>(null)
  const [siteSearch, setSiteSearch] = useState('')
  const [confirmingOutcome, setConfirmingOutcome] = useState(false)
  const [terminalForbidden, setTerminalForbidden] = useState(false)
  const serverForbiddenRef = useRef(false)
  const mutationResultRef = useRef<URLAuthWriteResult | URLAuthSecretWriteResult | null>(null)
  const listQueryPrefix = ['url-auth-policies', scopeKind, scopeID, userID, sessionEpoch] as const
  const sessionMatches = () => urlAuthSessionMatches(scopeKind, scopeID, userID, sessionEpoch)
  const latchServerForbidden = () => {
    if (!sessionMatches()) return
    serverForbiddenRef.current = true
    setTerminalForbidden(true)
  }
  const targetScopeID = isPlatform && editor === 'create' ? platformTargetScopeID?.trim() ?? '' : scopeID
  const targetOwnerID = isPlatform && editor === 'create' ? platformOwnerID?.trim() ?? '' : userID
  const hasValidSiteTarget = !isPlatform || editor !== 'create' ||
    (canonicalUUIDPattern.test(targetScopeID) && canonicalUUIDPattern.test(targetOwnerID))

  const query = useQuery({
    queryKey: [...listQueryPrefix, page, limit, name, status],
    queryFn: async () => {
      try {
        return await urlAuthPoliciesApi.list(accessTokenRef.current, { page, limit, name: name || undefined, status })
      } catch (error) {
        if (error instanceof ApiError && error.status === 403) latchServerForbidden()
        throw error
      }
    },
    enabled: !terminalForbidden,
  })
  const sitesQuery = useQuery({
    queryKey: [
      'url-auth-policy-sites', scopeKind, scopeID, userID, sessionEpoch,
      targetScopeID, targetOwnerID, siteSearch,
    ],
    queryFn: async () => {
      try {
        return await sitesApi.list(accessTokenRef.current, {
          page: 1,
          limit: 100,
          ...(siteSearch ? { domain: siteSearch } : {}),
          ...(isPlatform && editor === 'create' ? { owner: targetOwnerID } : {}),
        })
      } catch (error) {
        if (error instanceof ApiError && error.status === 403) latchServerForbidden()
        throw error
      }
    },
    enabled: Boolean(!terminalForbidden && canManage && editor && hasValidSiteTarget),
  })

  const queryError = query.error instanceof ApiError ? query.error : null
  const writeToken = () => serverForbiddenRef.current
    ? null
    : currentURLAuthWriteToken(scopeKind, scopeID, userID, sessionEpoch)
  const canApplyWriteResult = () => Boolean(writeToken())

  const mutation = useMutation<void, Error, WriteAttempt>({
    mutationFn: async (next) => {
      mutationResultRef.current = null
      const token = writeToken()
      if (!token) throw new ApiError('permission denied', 403, 'permission_denied')
      const request = (() => {
        switch (next.kind) {
          case 'create':
            return urlAuthPoliciesApi.create(token, next.input, next.key)
          case 'update':
            return urlAuthPoliciesApi.update(token, next.id, next.version, next.input, next.key)
          case 'enable':
            return urlAuthPoliciesApi.enable(token, next.id, next.version, next.key)
          case 'disable':
            return urlAuthPoliciesApi.disable(token, next.id, next.version, next.key)
          case 'rotate':
            return urlAuthPoliciesApi.rotate(token, next.id, next.version, next.key)
          case 'revoke':
            return urlAuthPoliciesApi.revoke(token, next.id, next.version, next.keyID, next.key)
        }
      })()
      const result = await request
      if (!canApplyWriteResult()) return
      mutationResultRef.current = result
    },
    onSuccess: async (_, completed) => {
      const result = mutationResultRef.current
      mutationResultRef.current = null
      if (!result || !canApplyWriteResult()) return
      setAttempt(null)
      setWriteError(null)
      if (completed.kind === 'create' || completed.kind === 'update') form.resetFields()
      setEditor(null)
      if ('secret' in result && result.secret) {
        setIssued({ secret: result.secret, keyID: result.policy.current_key.key_id })
      } else if (result.replayed && (completed.kind === 'create' || completed.kind === 'rotate')) {
        feedback.warning(t('notices.replayedNoSecret'))
      }
      await queryClient.invalidateQueries({ queryKey: listQueryPrefix })
      if (!canApplyWriteResult()) return
      if (!('secret' in result && result.secret) && !(result.replayed && (completed.kind === 'create' || completed.kind === 'rotate'))) {
        messageApi.success(t(`notices.${completed.kind}`))
      }
    },
    onError: (error, failed) => {
      mutationResultRef.current = null
      if (!canApplyWriteResult()) return
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      if (unknownOutcome(error)) {
        setAttempt(failed)
        return
      }
      setAttempt(null)
      // A refused field of the open editor is said under it, not in a dialog.
      if ((failed.kind === 'create' || failed.kind === 'update') && markSubmitError(error)) {
        setWriteError(null)
        return
      }
      if (apiError.code === 'version_conflict') {
        setEditor(null)
        setWriteError(null)
        form.resetFields()
        void queryClient.invalidateQueries({ queryKey: listQueryPrefix })
        feedback.error(t('notices.conflictRefreshed'))
      }
    },
  })

  const siteOptions = useMemo(() => {
    const options = (sitesQuery.data?.items ?? []).map((site) => ({ label: site.domain, value: site.id }))
    if (editor !== null && editor !== 'create' && !options.some((option) => option.value === editor.site.id)) {
      options.unshift({ label: editor.site.domain, value: editor.site.id })
    }
    return options
  }, [editor, sitesQuery.data?.items])

  useEffect(() => {
    if (!editor) return
    if (editor === 'create') {
      form.setFieldsValue({
        enabled: true,
        bind_client_ip: false,
        signature_parameter: 'sig',
        expiration_parameter: 'exp',
        key_id_parameter: 'kid',
        max_clock_skew_seconds: 30,
        max_validity_seconds: 600,
        max_signature_uses: 1,
        excluded_query_parameters: '',
        trusted_proxy_cidrs: '',
      })
      return
    }
    form.setFieldsValue({
      ...policyFields(editor),
      excluded_query_parameters: editor.excluded_query_parameters.join('\n'),
      trusted_proxy_cidrs: editor.trusted_proxy_cidrs.join('\n'),
    })
  }, [editor, form])

  useEffect(() => {
    if (editor === 'create' && isPlatform) {
      form.setFieldValue('site_id', undefined)
      setSiteSearch('')
    }
  }, [editor, form, isPlatform, platformOwnerID, platformTargetScopeID])

  useEffect(() => {
    if (canManage) return
    setEditor(null)
    setAttempt(null)
    setWriteError(null)
    setIssued(null)
    mutationResultRef.current = null
    form.resetFields()
  }, [canManage, form])

  if (terminalForbidden || queryError?.status === 403) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }

  const uncertain = Boolean(attempt && writeError && unknownOutcome(writeError))
  const writesLocked = mutation.isPending || uncertain || Boolean(issued)

  const submit = (next: WriteAttempt) => {
    if (writesLocked || !writeToken()) return
    setAttempt(next)
    setWriteError(null)
    mutation.mutate(next)
  }

  const openCreate = () => {
    if (writesLocked || !writeToken()) return
    setWriteError(null)
    setEditor('create')
  }

  const openEdit = (item: URLAuthPolicy) => {
    if (writesLocked || !writeToken()) return
    setWriteError(null)
    setEditor(item)
  }

  const closeAndRefresh = async () => {
    if (!sessionMatches() || serverForbiddenRef.current) return
    setConfirmingOutcome(true)
    const refreshed = await query.refetch()
    if (!sessionMatches() || serverForbiddenRef.current ||
      (refreshed.error instanceof ApiError && refreshed.error.status === 403)) return
    setConfirmingOutcome(false)
    if (!refreshed.isSuccess) {
      feedback.error(t('errors.refreshFailed'))
      return
    }
    setAttempt(null)
    setWriteError(null)
    setEditor(null)
    form.resetFields()
  }

  const onFinish = (values: PolicyFormValues) => {
    const fields: URLAuthPolicyFields = {
      site_id: values.site_id,
      name: values.name.trim(),
      enabled: values.enabled,
      algorithm: 'hmac-sha256',
      signature_parameter: values.signature_parameter.trim(),
      expiration_parameter: values.expiration_parameter.trim(),
      key_id_parameter: values.key_id_parameter.trim(),
      bind_client_ip: values.bind_client_ip,
      max_clock_skew_seconds: values.max_clock_skew_seconds,
      max_validity_seconds: values.max_validity_seconds,
      max_signature_uses: values.max_signature_uses,
      excluded_query_parameters: splitValues(values.excluded_query_parameters),
      trusted_proxy_cidrs: splitValues(values.trusted_proxy_cidrs),
    }
    submittedRef.current = fields
    if (editor === 'create') {
      submit({
        kind: 'create', input: { ...fields, target_scope_id: values.target_scope_id?.trim() || undefined, owner_id: values.owner_id?.trim() || undefined },
        key: writeKey('create'),
      })
    } else if (editor) {
      submit({ kind: 'update', id: editor.id, version: editor.version, input: fields, key: writeKey('update') })
    }
  }

  const toggle = (item: URLAuthPolicy) => submit({
    kind: item.enabled ? 'disable' : 'enable', id: item.id, version: item.version,
    key: writeKey(item.enabled ? 'disable' : 'enable'),
  })

  const columns: TableColumnsType<URLAuthPolicy> = [
    ...(isPlatform ? [
      { title: t('columns.scope'), dataIndex: 'scope_id', width: 240, ellipsis: true },
      { title: t('columns.owner'), dataIndex: ['owner', 'display_name'], width: 180, ellipsis: true },
    ] as TableColumnsType<URLAuthPolicy> : []),
    { title: t('columns.site'), dataIndex: ['site', 'domain'], width: 190, ellipsis: true },
    { title: t('columns.name'), dataIndex: 'name', width: 170, ellipsis: true },
    {
      title: t('columns.algorithm'), key: 'algorithm', width: 145,
      render: (_, item) => (
        <Space size={4}>
          <Tag>HMAC-SHA256</Tag>
          {item.migration_marker ? <Tooltip title={t(`migration.${item.migration_marker}`)}><Tag color="warning">{t('migration.provenance')}</Tag></Tooltip> : null}
        </Space>
      ),
    },
    {
      title: t('columns.keys'), key: 'keys', width: 250,
      render: (_, item) => (
        <Space direction="vertical" size={0}>
          <code>{t('keys.current')}: {item.current_key.key_id}</code>
          {item.previous_key ? <code>{t('keys.previous')}: {item.previous_key.key_id}</code> : null}
        </Space>
      ),
    },
    { title: t('columns.ipBinding'), dataIndex: 'bind_client_ip', width: 100, render: (value: boolean) => t(value ? 'values.yes' : 'values.no') },
    { title: t('columns.status'), dataIndex: 'enabled', width: 100, render: (value: boolean) => <Tag color={value ? 'success' : 'default'}>{t(value ? 'states.enabled' : 'states.disabled')}</Tag> },
    { title: t('columns.version'), dataIndex: 'version', width: 80 },
    { title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180, render: (value: string) => dateTime(value, locale) },
    {
      title: t('columns.actions'), key: 'actions', width: 190,
      render: (_, item) => canManage ? (
        <Space size={2}>
          <Tooltip title={t('actions.edit')}>
            <Button type="text" size="small" aria-label={t('actions.editNamed', { name: item.name })} icon={<Pencil size={15} />} disabled={writesLocked} onClick={() => openEdit(item)} />
          </Tooltip>
          <Popconfirm title={t('confirm.rotate')} description={t('confirm.rotateDescription')} okText={t('actions.confirm')} cancelText={t('actions.cancel')} destroyOnHidden onConfirm={() => submit({ kind: 'rotate', id: item.id, version: item.version, key: writeKey('rotate') })}>
            <Tooltip title={t('actions.rotate')}><Button type="text" size="small" aria-label={t('actions.rotateNamed', { name: item.name })} icon={<RefreshCw size={15} />} disabled={writesLocked} /></Tooltip>
          </Popconfirm>
          {item.previous_key ? (
            <Popconfirm title={t('confirm.revoke')} description={t('confirm.revokeDescription')} okText={t('actions.confirm')} cancelText={t('actions.cancel')} onConfirm={() => submit({ kind: 'revoke', id: item.id, version: item.version, keyID: item.previous_key!.key_id, key: writeKey('revoke') })}>
              <Tooltip title={t('actions.revoke')}><Button danger type="text" size="small" aria-label={t('actions.revokeNamed', { name: item.name })} icon={<ShieldOff size={15} />} disabled={writesLocked} /></Tooltip>
            </Popconfirm>
          ) : null}
          <Popconfirm title={t(item.enabled ? 'confirm.disable' : 'confirm.enable')} okText={t('actions.confirm')} cancelText={t('actions.cancel')} onConfirm={() => toggle(item)}>
            <Tooltip title={t(item.enabled ? 'actions.disable' : 'actions.enable')}><Button type="text" size="small" aria-label={t(item.enabled ? 'actions.disableNamed' : 'actions.enableNamed', { name: item.name })} icon={item.enabled ? <Power size={15} /> : <KeyRound size={15} />} disabled={writesLocked} /></Tooltip>
          </Popconfirm>
        </Space>
      ) : null,
    },
  ]

  return (
    <section className="identity-page" aria-labelledby="url-auth-title">
      {messageContext}
      <h2 id="url-auth-title" style={{ margin: '0 0 14px', fontSize: 16 }}>{t('title')}</h2>
      {uncertain ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap><Button size="small" disabled={confirmingOutcome} onClick={() => attempt && mutation.mutate(attempt)}>{t('actions.retrySameRequest')}</Button><Button size="small" loading={confirmingOutcome} onClick={() => void closeAndRefresh()}>{t('actions.closeAndRefresh')}</Button></Space>} className="identity-alert" />
      ) : writeError ? <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} /> : null}
      <div className="identity-toolbar">
        {canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={openCreate}>{t('actions.create')}</Button> : null}
        <div className="identity-search">
          <Input value={nameDraft} placeholder={t('filters.name')} onChange={(event) => setNameDraft(event.target.value)} onPressEnter={() => { setPage(1); setName(nameDraft.trim()) }} />
          <Button onClick={() => { setPage(1); setName(nameDraft.trim()) }}>{t('actions.search')}</Button>
        </div>
        <Select allowClear value={status} placeholder={t('filters.status')} options={[{ value: 'enabled', label: t('states.enabled') }, { value: 'disabled', label: t('states.disabled') }]} onChange={(value) => { setPage(1); setStatus(value) }} />
        <Tooltip title={t('actions.refresh')}><Button aria-label={t('actions.refresh')} icon={<RefreshCw size={15} />} onClick={() => void query.refetch()} /></Tooltip>
      </div>
      {query.isError ? (
        <FeedbackWhen title={t('errors.loadFailed')} detail={queryError ? errorMessage(queryError, t) : t('errors.request_failed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : (
        <>
          <div className="identity-table-scroll" data-testid="url-auth-policy-table-scroll" aria-busy={query.isFetching}>
            <Table rowKey="id" size="small" loading={query.isLoading} columns={columns} dataSource={query.data?.items ?? []} pagination={false} scroll={{ x: isPlatform ? 1900 : 1500 }} locale={{ emptyText: t('values.empty') }} />
          </div>
          <div data-testid="url-auth-policy-pagination-scroll" style={{ maxWidth: '100%', overflowX: 'auto' }}>
            <Pagination className="identity-pagination" current={page} pageSize={limit} total={query.data?.total ?? 0} showSizeChanger pageSizeOptions={[10, 20, 50, 100]} showTotal={(total) => t('values.total', { count: total })} onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} />
          </div>
        </>
      )}

      <Modal className="identity-modal" width={720} open={Boolean(editor && canManage)} title={editor === 'create' ? t('editor.createTitle') : t('editor.editTitle')} okText={t('actions.save')} cancelText={t('actions.cancel')} confirmLoading={mutation.isPending} okButtonProps={{ disabled: uncertain || sitesQuery.isError }} onOk={() => form.submit()} onCancel={() => { if (!mutation.isPending && !uncertain) { setEditor(null); form.resetFields(); setWriteError(null) } }} styles={{ body: { maxHeight: 'calc(100dvh - 240px)', overflowY: 'auto' } }} destroyOnHidden>
        {sitesQuery.isError ? <Alert className="identity-alert" type="error" showIcon message={t('errors.sitesLoadFailed')} action={<Button size="small" onClick={() => void sitesQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
        <Form form={form} layout="vertical" onFinish={onFinish} disabled={mutation.isPending || uncertain}>
          {editor === 'create' && isPlatform ? <><Form.Item name="target_scope_id" label={t('editor.targetScope')} rules={[{ required: true, message: t('validation.targetScopeRequired') }, { pattern: canonicalUUIDPattern, message: t('validation.targetScopeInvalid') }]}><TenantScopeSelect accessToken={accessToken} ownerKey={`${scopeKind}:${scopeID}:${userID}:${sessionEpoch}`} canList={permissions.includes('identity.users.manage') || permissions.includes('platform.admin')} queryKeyPrefix="url-auth-tenants" ariaLabel={t('editor.targetScope')} placeholder={t('editor.targetScopePlaceholder')} emptyText={t('editor.targetScopeEmpty')} value={platformTargetScopeID ?? ''} onChange={(next) => { form.setFieldValue('target_scope_id', next); form.setFieldValue('site_id', undefined); setSiteSearch('') }} onPickUser={(user) => { if (user) form.setFieldValue('owner_id', user.id) }} /></Form.Item><Form.Item name="owner_id" label={t('editor.owner')} rules={[{ required: true, message: t('validation.ownerRequired') }, { pattern: canonicalUUIDPattern, message: t('validation.ownerInvalid') }]}><Input /></Form.Item></> : null}
          <Form.Item name="site_id" label={t('editor.site')} rules={[{ required: true, message: t('validation.siteRequired') }]}><Select showSearch filterOption={false} loading={sitesQuery.isFetching} options={siteOptions} onSearch={(value) => setSiteSearch(value.trim())} /></Form.Item>
          <Form.Item name="name" label={t('editor.name')} rules={[{ required: true, whitespace: true, message: t('validation.nameRequired') }, { max: 128, message: t('validation.nameTooLong') }]}><Input /></Form.Item>
          <Form.Item label={t('editor.algorithm')}><Input value="HMAC-SHA256" disabled /></Form.Item>
          <Space size={12} wrap style={{ width: '100%' }}>
            <Form.Item name="signature_parameter" label={t('editor.signatureParameter')} rules={[{ required: true, message: t('validation.parameterRequired') }, { pattern: /^[A-Za-z0-9_.~-]{1,64}$/, message: t('validation.parameterInvalid') }]}><Input style={{ width: 190 }} /></Form.Item>
            <Form.Item name="expiration_parameter" label={t('editor.expirationParameter')} rules={[{ required: true, message: t('validation.parameterRequired') }, { pattern: /^[A-Za-z0-9_.~-]{1,64}$/, message: t('validation.parameterInvalid') }]}><Input style={{ width: 190 }} /></Form.Item>
            <Form.Item name="key_id_parameter" label={t('editor.keyIDParameter')} rules={[{ required: true, message: t('validation.parameterRequired') }, { pattern: /^[A-Za-z0-9_.~-]{1,64}$/, message: t('validation.parameterInvalid') }]}><Input style={{ width: 190 }} /></Form.Item>
          </Space>
          <Space size={12} wrap style={{ width: '100%' }}>
            <Form.Item name="max_clock_skew_seconds" label={t('editor.clockSkew')} rules={[{ required: true, message: t('validation.clockSkewRequired') }, { type: 'number', min: 0, max: 300, message: t('validation.clockSkewRange') }]}><InputNumber min={0} max={300} style={{ width: 180 }} /></Form.Item>
            <Form.Item name="max_validity_seconds" label={t('editor.validity')} rules={[{ required: true, message: t('validation.validityRequired') }, { type: 'number', min: 1, max: 86400, message: t('validation.validityRange') }]}><InputNumber min={1} max={86400} style={{ width: 180 }} /></Form.Item>
            <Form.Item name="max_signature_uses" label={t('editor.signatureUses')} rules={[{ required: true, message: t('validation.signatureUsesRequired') }, { type: 'number', min: 0, max: 1000000, message: t('validation.signatureUsesRange') }]}><InputNumber min={0} max={1000000} style={{ width: 180 }} /></Form.Item>
          </Space>
          <Form.Item name="excluded_query_parameters" label={t('editor.excludedParameters')}><Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} /></Form.Item>
          <Form.Item name="trusted_proxy_cidrs" label={t('editor.trustedProxies')}><Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} /></Form.Item>
          <Space size={28} wrap><Form.Item name="bind_client_ip" label={t('editor.bindClientIP')} valuePropName="checked"><Switch /></Form.Item><Form.Item name="enabled" label={t('editor.enabled')} valuePropName="checked"><Switch /></Form.Item></Space>
        </Form>
      </Modal>

      {issued && canManage ? (
        <Modal aria-label={t('secret.title')} open title={t('secret.title')} closable={false} maskClosable={false} keyboard={false} footer={[<Button key="close" type="primary" onClick={() => { setIssued(null); mutation.reset() }}>{t('secret.saved')}</Button>]} destroyOnHidden>
          <Alert className="identity-alert" type="warning" showIcon message={t('secret.warning')} />
          <Space.Compact block>
            <Input aria-label={t('secret.ariaLabel')} value={issued.secret} readOnly />
            <Tooltip title={t('actions.copy')}><Button aria-label={t('actions.copy')} icon={<Copy size={14} />} onClick={() => { void navigator.clipboard.writeText(issued.secret).then(() => messageApi.success(t('notices.copied')), () => feedback.error(t('errors.copyFailed'))) }} /></Tooltip>
          </Space.Compact>
          <div style={{ marginTop: 10 }}><code>{issued.keyID}</code></div>
        </Modal>
      ) : null}
    </section>
  )
}
