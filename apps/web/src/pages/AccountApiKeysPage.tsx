import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Form,
  Input,
  Modal,
  Popconfirm,
  Result,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tag,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import { MODAL_WIDTH, applyFormSubmitError, useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import type { TFunction } from 'i18next'
import { Copy, Eye, KeyRound, Pencil, RefreshCw, Search, ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { formatDateTime } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import {
  apiKeysApi,
  validateAPIKeyIPAllowlist,
  type APIKeyFields,
  type APIKeyRecord,
  type IssuedAPIKey,
} from '../api/apiKeys'
import { useSessionStore } from '../auth/session'
import '../i18n/apiKeyAllowlist'
import '../i18n/apiKeyCompatibility'
import { permissionName } from '../i18n/permissionNames'
import './AccountApiKeysPage.css'

interface APIKeyFormValues {
  name: string
  scopes: string[]
  ip_allowlist?: string
  expires_at?: string
}

const API_KEY_PAGE_SIZE = 10
const apiKeyIDPattern = /^cfk_[A-Za-z0-9_-]{22}$/

// simple：来自简单版卡片（开关开启 / 重置密钥），一次性密钥用分栏弹窗显示 api_key 与 api_secret。
type WriteAttempt =
  | { kind: 'create'; input: APIKeyFields; key: string; simple?: boolean }
  | { kind: 'update'; id: string; revision: number; input: APIKeyFields; key: string }
  | { kind: 'activate' | 'rotate' | 'revoke'; id: string; revision: number; ipAllowlist: string[]; key: string; simple?: boolean }

function writeKey(kind: WriteAttempt['kind']): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `api-key-${kind}-${suffix}`
}

function writeOutcomeUnknown(error: unknown): boolean {
  return (
    !(error instanceof ApiError) ||
    error.status === 0 ||
    error.status === 408 ||
    error.status === 429 ||
    error.status >= 500 ||
    error.code === 'invalid_response'
  )
}

function errorMessage(error: unknown, t: TFunction<'apiKeys'>, tAllowlist?: TFunction<'apiKeyAllowlist'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  switch (error.code) {
    case 'validation_error':
    case 'permission_denied':
    case 'version_conflict':
    case 'idempotency_conflict':
    case 'api_key_state_conflict':
    case 'api_key_not_found':
    case 'api_key_unavailable':
    case 'invalid_request':
    case 'invalid_session':
    case 'network_error':
    case 'request_failed':
    case 'invalid_response':
      return t(`errors.${error.code}`)
    case 'api_key_ip_allowlist_invalid_cidr':
    case 'api_key_ip_allowlist_unsupported_prefix':
    case 'api_key_ip_allowlist_duplicate':
    case 'api_key_ip_allowlist_overlap':
    case 'api_key_ip_allowlist_too_many':
      return tAllowlist?.(`validation.${error.code}`) ?? t('errors.request_failed')
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

function dateTime(value: string | undefined, locale: string, empty: string): string {
  if (!value) return empty
  return formatDateTime(value, locale) || value
}

function dateTimeLocalValue(value: string | undefined): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return undefined
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
}

function isIssued(value: IssuedAPIKey | APIKeyRecord): value is IssuedAPIKey {
  return 'key' in value && 'secret' in value
}

function safeScope(permission: string): boolean {
  return permission !== 'platform.admin' &&
    !permission.startsWith('identity.') &&
    !permission.startsWith('api_keys.')
}

function splitAllowlist(value: string | undefined): string[] {
  return (value ?? '').split(/[\r\n,|]+/u).map((entry) => entry.trim()).filter(Boolean)
}

// 简单版白名单：单个 IP 补成 /32（IPv6 /128），兼容"多个 IP 以 | 分隔"的写法；网段原样交给校验。
function simpleAllowlistEntries(value: string): string[] {
  return splitAllowlist(value).map((entry) => {
    if (entry.includes('/')) return entry
    if (entry.includes(':')) {
      try {
        return `${new URL(`http://[${entry}]/`).hostname.slice(1, -1)}/128`
      } catch {
        return entry
      }
    }
    return `${entry}/32`
  })
}

function sameEntries(left: readonly string[], right: readonly string[]): boolean {
  const a = [...left].sort()
  const b = [...right].sort()
  return a.length === b.length && a.every((value, index) => value === b[index])
}

function allowlistTags(values: string[], unrestricted: string) {
  return values.length > 0
    ? <Space size={[4, 4]} wrap>{values.map((value) => <Tag key={value}>{value}</Tag>)}</Space>
    : <Tag>{unrestricted}</Tag>
}

export default function AccountApiKeysPage() {
  const { t } = useTranslation('apiKeys')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  // 高级密钥管理默认收起；展开状态只是界面偏好，换会话时不重置。
  const [advancedOpen, setAdvancedOpen] = useState(false)

  if (!accessToken || !principal) return null
  if (principal.scope_kind !== 'tenant' || !principal.permissions.includes('api_keys.self.manage')) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  return (
    <AccountApiKeysContent
      key={`${principal.user_id}:${sessionEpoch}`}
      advancedOpen={advancedOpen}
      onAdvancedOpenChange={setAdvancedOpen}
      accessToken={accessToken}
      ownerID={principal.user_id}
      sessionEpoch={sessionEpoch}
      permissions={principal.permissions}
    />
  )
}

function AccountApiKeysContent({
  accessToken,
  ownerID,
  sessionEpoch,
  permissions,
  advancedOpen,
  onAdvancedOpenChange,
}: {
  accessToken: string
  ownerID: string
  sessionEpoch: number
  permissions: string[]
  advancedOpen: boolean
  onAdvancedOpenChange: (open: boolean) => void
}) {
  const { t, i18n } = useTranslation('apiKeys')
  const { t: tAllowlist } = useTranslation('apiKeyAllowlist')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const [form] = Form.useForm<APIKeyFormValues>()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [editor, setEditor] = useState<{ mode: 'create' | 'edit'; item?: APIKeyRecord } | null>(null)
  const [issued, setIssued] = useState<IssuedAPIKey | null>(null)
  const [simpleIssued, setSimpleIssued] = useState<IssuedAPIKey | null>(null)
  const [allowlistDraft, setAllowlistDraft] = useState<{ keyRevision: string; value: string } | null>(null)
  const [allowlistError, setAllowlistError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<APIKeyRecord['status'] | 'all'>('all')
  const [page, setPage] = useState(1)
  const [detailID, setDetailID] = useState<string | null>(null)

  const normalizedSearch = search.trim()
  const keyID = apiKeyIDPattern.test(normalizedSearch) ? normalizedSearch : ''
  const name = keyID ? '' : normalizedSearch
  const statusFilter = status === 'all' ? '' : status
  const offset = (page - 1) * API_KEY_PAGE_SIZE
  const listRoot = useMemo(
    () => ['account-api-keys', ownerID, sessionEpoch] as const,
    [ownerID, sessionEpoch],
  )
  const detailRoot = useMemo(
    () => ['account-api-key', ownerID, sessionEpoch] as const,
    [ownerID, sessionEpoch],
  )
  const compatibilityRoot = useMemo(
    () => ['account-api-key-compatibility', ownerID, sessionEpoch] as const,
    [ownerID, sessionEpoch],
  )

  useEffect(() => () => {
    queryClient.removeQueries({ queryKey: listRoot })
    queryClient.removeQueries({ queryKey: detailRoot })
    queryClient.removeQueries({ queryKey: compatibilityRoot })
  }, [compatibilityRoot, detailRoot, listRoot, queryClient])

  const compatibilityQuery = useQuery({
    queryKey: [...compatibilityRoot, 2, 'active'],
    queryFn: ({ signal }) => apiKeysApi.list(accessTokenRef.current, {
      limit: 2,
      status: 'active',
    }, signal),
  })

  const query = useQuery({
    queryKey: [...listRoot, API_KEY_PAGE_SIZE, statusFilter, name, keyID, offset],
    queryFn: ({ signal }) => apiKeysApi.list(accessTokenRef.current, {
      limit: API_KEY_PAGE_SIZE,
      ...(statusFilter ? { status: statusFilter } : {}),
      ...(name ? { name } : {}),
      ...(keyID ? { key_id: keyID } : {}),
      ...(offset ? { offset } : {}),
    }, signal),
  })

  // Keep the last known total while the next page loads so the pager does not jump.
  const totalRef = useRef(0)
  if (query.data?.total !== undefined) totalRef.current = query.data.total

  const detailQuery = useQuery({
    queryKey: [...detailRoot, detailID],
    queryFn: () => apiKeysApi.get(accessTokenRef.current, detailID!),
    enabled: Boolean(detailID),
  })

  const resetList = () => {
    setPage(1)
    void queryClient.invalidateQueries({ queryKey: listRoot })
    void queryClient.invalidateQueries({ queryKey: compatibilityRoot })
  }

  const mutation = useMutation({
    mutationFn: (next: WriteAttempt) => {
      switch (next.kind) {
        case 'create':
          return apiKeysApi.create(accessTokenRef.current, next.input, next.key)
        case 'update':
          return apiKeysApi.update(accessTokenRef.current, next.id, next.revision, next.input, next.key)
        default:
          // 简单版"重置密钥"=轮换 + 权限刷新为全部；高级管理里的轮换保持原权限。
          return next.kind === 'rotate' && next.simple
            ? apiKeysApi.action(accessTokenRef.current, next.id, next.revision, next.kind, next.ipAllowlist, next.key, { grantAllScopes: true })
            : apiKeysApi.action(accessTokenRef.current, next.id, next.revision, next.kind, next.ipAllowlist, next.key)
      }
    },
    onSuccess: (result, completed) => {
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      if (completed.kind === 'create' || completed.kind === 'update') form.resetFields()
      const simple = 'simple' in completed && Boolean(completed.simple)
      if (isIssued(result)) {
        if (simple) setSimpleIssued(result)
        else setIssued(result)
      }
      if (completed.kind === 'update') setAllowlistDraft(null)
      resetList()
      // 简单版签发由一次性密钥弹窗本身确认结果，不再弹提示条压住"只显示一次"的警告。
      if (!simple) messageApi.success(t(`notices.${completed.kind}`))
    },
    onError: (error, failed) => {
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      if (writeOutcomeUnknown(error)) {
        setAttempt(failed)
        return
      }
      setAttempt(null)
      // fix-feedbackui2: a refused allowlist is said under its field, not in a dialog.
      if (apiError.code.startsWith('api_key_ip_allowlist_') && applyFormSubmitError(form,
        { code: 'validation_error', field: 'ip_allowlist' }, { message: () => errorMessage(apiError, t, tAllowlist) })) {
        setWriteError(null)
        return
      }
      if (apiError.code === 'version_conflict') {
        setEditor(null)
        form.resetFields()
        setWriteError(null)
        resetList()
        feedback.error(t('notices.conflictRefreshed'))
      }
    },
  })

  const scopeOptions = useMemo(
    () => permissions.filter(safeScope).sort().map((permission) => ({
      label: permissionName(permission),
      value: permission,
      search: `${permissionName(permission)} ${permission}`,
    })),
    [permissions],
  )
  const queryError = query.error instanceof ApiError ? query.error : null
  const compatibilityError = compatibilityQuery.error instanceof ApiError ? compatibilityQuery.error : null
  if (queryError?.status === 403 || compatibilityError?.status === 403) {
    return (
      <Result
        className="identity-page identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  const uncertain = Boolean(attempt && writeError && writeOutcomeUnknown(writeError))
  const writesLocked = mutation.isPending || uncertain || Boolean(issued) || Boolean(simpleIssued)
  const activeKeys = (compatibilityQuery.data?.items ?? []).filter((item) => item.status === 'active')
  const multipleActiveKeys = Boolean(activeKeys.length > 1 || activeKeys.length > 0 && compatibilityQuery.data?.has_more)
  const primaryKey = !multipleActiveKeys && activeKeys.length === 1 ? activeKeys[0] : null
  const compatibilityEnabled = activeKeys.length > 0
  const activeCountLabel = t(
    compatibilityQuery.data?.has_more ? 'compatibility.activeCountMore' : 'compatibility.activeCount',
    { count: activeKeys.length },
  )

  // "全部权限"= 会话权限里允许授予 API 密钥的全部（与高级创建的可选范围一致），名称默认"默认密钥"、不过期。
  const allScopes = scopeOptions.map((option) => option.value)
  const primaryRevision = primaryKey ? `${primaryKey.id}:${primaryKey.revision}` : ''
  const allowlistValue = allowlistDraft && allowlistDraft.keyRevision === primaryRevision
    ? allowlistDraft.value
    : (primaryKey?.ip_allowlist ?? []).join(' | ')

  const copyText = (value: string) => {
    void navigator.clipboard.writeText(value)
      .then(() => messageApi.success(t('notices.copied')))
      .catch(() => feedback.error(t('errors.copyFailed')))
  }

  const submit = (next: WriteAttempt) => {
    if (writesLocked) return
    setAttempt(next)
    setWriteError(null)
    mutation.mutate(next)
  }

  const openCreate = () => {
    if (writesLocked) return
    setWriteError(null)
    setEditor({ mode: 'create' })
  }

  const openEdit = (item: APIKeyRecord) => {
    if (writesLocked) return
    form.setFieldsValue({
      name: item.name,
      scopes: item.scopes,
      ip_allowlist: item.ip_allowlist.join('\n'),
      expires_at: dateTimeLocalValue(item.expires_at),
    })
    setWriteError(null)
    setEditor({ mode: 'edit', item })
  }

  const closeAndRefresh = () => {
    setAttempt(null)
    setWriteError(null)
    setEditor(null)
    form.resetFields()
    resetList()
  }


  const runAction = (kind: 'activate' | 'rotate' | 'revoke', item: APIKeyRecord, simple = false) => {
    submit({ kind, id: item.id, revision: item.revision, ipAllowlist: item.ip_allowlist, key: writeKey(kind), simple })
  }

  const enableSimple = () => {
    if (writesLocked || allScopes.length === 0) return
    submit({
      kind: 'create',
      input: { name: t('compatibility.defaultKeyName'), scopes: allScopes, ip_allowlist: [] },
      key: writeKey('create'),
      simple: true,
    })
  }

  const saveAllowlist = () => {
    if (!primaryKey || writesLocked) return
    const entries = simpleAllowlistEntries(allowlistValue)
    const invalid = validateAPIKeyIPAllowlist(entries)
    if (invalid) {
      setAllowlistError(tAllowlist(`validation.${invalid}`))
      return
    }
    setAllowlistError(null)
    if (sameEntries(entries, primaryKey.ip_allowlist)) {
      setAllowlistDraft(null)
      return
    }
    submit({
      kind: 'update',
      id: primaryKey.id,
      revision: primaryKey.revision,
      input: {
        name: primaryKey.name,
        scopes: primaryKey.scopes,
        ip_allowlist: entries,
        ...(primaryKey.expires_at ? { expires_at: primaryKey.expires_at } : {}),
      },
      key: writeKey('update'),
    })
  }

  const writeErrorAlert = writeError ? (
    (uncertain ? <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={(
        <Space wrap>
          <Button size="small" loading={mutation.isPending} disabled={mutation.isPending} onClick={() => { if (attempt) mutation.mutate(attempt) }}>
            {t('actions.retrySameRequest')}
          </Button>
          <Button size="small" disabled={mutation.isPending} onClick={closeAndRefresh}>
            {t('actions.closeAndRefresh')}
          </Button>
        </Space>
      )} className="identity-alert" /> : <FeedbackWhen title={errorMessage(writeError, t, tAllowlist)} />)
  ) : null

  const columns: TableColumnsType<APIKeyRecord> = [
    { title: t('columns.name'), dataIndex: 'name', width: 170, ellipsis: true },
    {
      title: t('columns.prefix'), dataIndex: 'key_prefix', width: 250,
      render: (value: string) => <code>{value}********</code>,
    },
    {
      title: t('columns.scopes'), dataIndex: 'scopes', minWidth: 260,
      render: (values: string[]) => (
        <Space size={[4, 4]} wrap>{values.map((value) => <Tag key={value} title={value}>{permissionName(value)}</Tag>)}</Space>
      ),
    },
    {
      title: tAllowlist('label'), dataIndex: 'ip_allowlist', minWidth: 260,
      render: (values: string[]) => allowlistTags(values, tAllowlist('unrestricted')),
    },
    {
      title: t('columns.status'), dataIndex: 'status', width: 130,
      render: (status: APIKeyRecord['status']) => (
        <Tag color={status === 'active' ? 'success' : status === 'revoked' ? 'default' : 'processing'}>
          {t(`statuses.${status}`)}
        </Tag>
      ),
    },
    {
      title: t('columns.expiresAt'), dataIndex: 'expires_at', width: 180,
      render: (value: string | undefined) => dateTime(value, locale, t('values.never')),
    },
    {
      title: t('columns.lastUsedAt'), dataIndex: 'last_used_at', width: 180,
      render: (value: string | undefined) => dateTime(value, locale, t('values.neverUsed')),
    },
    {
      title: t('columns.actions'), key: 'actions', width: 210, fixed: 'right',
      render: (_, item) => (
        <Space size={4}>
          <Tooltip title={t('actions.view')}>
            <Button
              type="text"
              size="small"
              aria-label={t('actions.viewNamed', { name: item.name })}
              icon={<Eye size={15} />}
              onClick={() => setDetailID(item.id)}
            />
          </Tooltip>
          {item.status !== 'revoked' ? (
            <Tooltip title={t('actions.edit')}>
              <Button
                type="text"
                size="small"
                aria-label={t('actions.editNamed', { name: item.name })}
                icon={<Pencil size={15} />}
                disabled={writesLocked}
                onClick={() => openEdit(item)}
              />
            </Tooltip>
          ) : null}
          {item.status === 'pending_activation' ? (
            <Popconfirm
              title={t('confirm.activate')}
              okText={t('actions.activate')}
              cancelText={t('actions.cancel')}
              onConfirm={() => runAction('activate', item)}
            >
              <Tooltip title={t('actions.activate')}>
                <Button type="text" size="small" aria-label={t('actions.activateNamed', { name: item.name })} icon={<KeyRound size={15} />} disabled={writesLocked} />
              </Tooltip>
            </Popconfirm>
          ) : null}
          {item.status === 'active' ? (
            <Popconfirm
              title={t('confirm.rotate')}
              description={t('confirm.rotateDescription')}
              okText={t('actions.rotate')}
              cancelText={t('actions.cancel')}
              onConfirm={() => runAction('rotate', item)}
            >
              <Tooltip title={t('actions.rotate')}>
                <Button type="text" size="small" aria-label={t('actions.rotateNamed', { name: item.name })} icon={<RefreshCw size={15} />} disabled={writesLocked} />
              </Tooltip>
            </Popconfirm>
          ) : null}
          {item.status !== 'revoked' ? (
            <Popconfirm
              title={t('confirm.revoke')}
              description={t('confirm.revokeDescription')}
              okText={t('actions.revoke')}
              cancelText={t('actions.cancel')}
              okButtonProps={{ danger: true }}
              onConfirm={() => runAction('revoke', item)}
            >
              <Tooltip title={t('actions.revoke')}>
                <Button danger type="text" size="small" aria-label={t('actions.revokeNamed', { name: item.name })} icon={<ShieldOff size={15} />} disabled={writesLocked} />
              </Tooltip>
            </Popconfirm>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <section className="identity-page account-api-keys-page" aria-labelledby="account-api-keys-title">
      {messageContext}
      <div className="account-api-key-compatibility" data-testid="api-key-compatibility">
        <header className="account-api-key-compatibility-header">
          <div>
            <h1 id="account-api-keys-title">{t('compatibility.title')}</h1>
            <p>{t('compatibility.description')}</p>
          </div>
          <Tag color={compatibilityQuery.isError ? 'error' : compatibilityEnabled ? 'success' : 'warning'}>
            {compatibilityQuery.isPending
              ? t('compatibility.loading')
              : compatibilityQuery.isError
                ? t('compatibility.unknown')
                : compatibilityEnabled
                  ? t('compatibility.enabled')
                  : t('compatibility.disabled')}
          </Tag>
        </header>

        {compatibilityQuery.isError ? (
          <FeedbackWhen title={t('errors.loadFailed')} detail={errorMessage(compatibilityQuery.error, t, tAllowlist)} action={<Button size="small" onClick={() => void compatibilityQuery.refetch()}>{t('actions.retry')}</Button>} />
        ) : null}

        <div className="account-api-key-compatibility-grid">
          <div className="account-api-key-compatibility-item account-api-key-status-item">
            <div className="account-api-key-compatibility-copy">
              <h2>{t('compatibility.status')}</h2>
              <p>{primaryKey ? t('compatibility.statusHelp') : t('compatibility.enableHint')}</p>
            </div>
            <div className="account-api-key-compatibility-control">
              {primaryKey ? (
                <Popconfirm
                  title={t('compatibility.disableConfirm')}
                  description={t('compatibility.disableDescription')}
                  okText={t('actions.revoke')}
                  cancelText={t('actions.cancel')}
                  okButtonProps={{ danger: true }}
                  onConfirm={() => runAction('revoke', primaryKey)}
                >
                  <Switch
                    checked
                    aria-label={t('compatibility.status')}
                    disabled={writesLocked || compatibilityQuery.isFetching}
                  />
                </Popconfirm>
              ) : (
                <Switch
                  checked={compatibilityEnabled}
                  loading={mutation.isPending && attempt?.kind === 'create' && Boolean(attempt.simple)}
                  aria-label={t('compatibility.status')}
                  disabled={multipleActiveKeys || writesLocked || allScopes.length === 0 ||
                    compatibilityQuery.isPending || compatibilityQuery.isError}
                  onChange={(checked) => { if (checked) enableSimple() }}
                />
              )}
              {multipleActiveKeys ? <span>{activeCountLabel}</span> : null}
            </div>
            {multipleActiveKeys ? <p className="account-api-key-compatibility-note">{t('compatibility.multipleHint')}</p> : null}
            {!compatibilityEnabled && !compatibilityQuery.isPending && allScopes.length === 0
              ? <p className="account-api-key-compatibility-note">{t('compatibility.noScopes')}</p>
              : null}
          </div>

          <div className="account-api-key-compatibility-item">
            <div className="account-api-key-compatibility-copy">
              <h2><label htmlFor="api-key-simple-allowlist">{t('compatibility.allowlist')}</label></h2>
              <p>{t('compatibility.allowlistHelp')}</p>
            </div>
            <div className="account-api-key-compatibility-value" data-testid="api-key-compatibility-allowlist">
              {compatibilityQuery.isPending ? <Spin size="small" /> : null}
              {!compatibilityQuery.isPending && primaryKey ? (
                <div className="account-api-key-allowlist-field">
                  <Input
                    id="api-key-simple-allowlist"
                    value={allowlistValue}
                    placeholder={t('compatibility.allowlistPlaceholder')}
                    status={allowlistError ? 'error' : undefined}
                    aria-invalid={Boolean(allowlistError)}
                    aria-describedby="api-key-simple-allowlist-hint"
                    disabled={writesLocked}
                    onChange={(event) => {
                      setAllowlistError(null)
                      setAllowlistDraft({ keyRevision: primaryRevision, value: event.target.value })
                    }}
                    onBlur={saveAllowlist}
                    onPressEnter={saveAllowlist}
                  />
                  <span id="api-key-simple-allowlist-hint" role={allowlistError ? 'alert' : undefined}
                    className={allowlistError ? 'account-api-key-allowlist-error' : undefined}>
                    {allowlistError ?? t('compatibility.allowlistSaveHint')}
                  </span>
                </div>
              ) : null}
              {!compatibilityQuery.isPending && multipleActiveKeys ? <span>{t('compatibility.multipleHint')}</span> : null}
              {!compatibilityQuery.isPending && !compatibilityEnabled && !compatibilityQuery.isError
                ? <span>{t('compatibility.allowlistDisabled')}</span>
                : null}
            </div>
          </div>

          <div className="account-api-key-compatibility-item account-api-key-compatibility-wide">
            <div className="account-api-key-compatibility-copy">
              <h2>{t('compatibility.keyInfo')}</h2>
              <p>{t('compatibility.keyInfoHelp')}</p>
            </div>
            <div className="account-api-key-compatibility-value" data-testid="api-key-compatibility-key-info">
              {compatibilityQuery.isPending ? <Spin size="small" /> : null}
              {!compatibilityQuery.isPending && primaryKey ? (
                <div className="account-api-key-simple-keys">
                  <dl>
                    <div>
                      <dt>{t('compatibility.apiKey')}</dt>
                      <dd>
                        <code>{primaryKey.key_id}</code>
                        <Tooltip title={t('compatibility.copyKey')}>
                          <Button type="text" size="small" aria-label={t('compatibility.copyKey')} icon={<Copy size={15} />}
                            onClick={() => copyText(primaryKey.key_id)} />
                        </Tooltip>
                      </dd>
                    </div>
                    <div>
                      <dt>{t('compatibility.apiSecret')}</dt>
                      <dd><span>{t('compatibility.secretHidden')}</span></dd>
                    </div>
                  </dl>
                  <Popconfirm
                    title={t('compatibility.resetConfirm')}
                    description={t('compatibility.resetDescription')}
                    okText={t('compatibility.reset')}
                    cancelText={t('actions.cancel')}
                    onConfirm={() => runAction('rotate', primaryKey, true)}
                  >
                    <Button icon={<RefreshCw size={15} />} disabled={writesLocked}>{t('compatibility.reset')}</Button>
                  </Popconfirm>
                </div>
              ) : null}
              {!compatibilityQuery.isPending && multipleActiveKeys
                ? <span>{activeCountLabel}</span>
                : null}
              {!compatibilityQuery.isPending && !compatibilityEnabled && !compatibilityQuery.isError
                ? <span>{t('compatibility.keyInfoDisabled')}</span>
                : null}
            </div>
          </div>
        </div>
      </div>

      {editor ? null : writeErrorAlert}

      <Collapse
        className="account-api-key-advanced"
        data-testid="api-key-advanced"
        ghost
        activeKey={advancedOpen ? ['advanced'] : []}
        onChange={(keys) => onAdvancedOpenChange((Array.isArray(keys) ? keys : [keys]).includes('advanced'))}
        items={[{
          key: 'advanced',
          label: (
            <div className="account-api-key-advanced-heading">
              <h2>{t('compatibility.advancedTitle')}</h2>
              <p>{t('compatibility.advancedDescription')}</p>
            </div>
          ),
          children: (
            <>
              <div className="identity-toolbar">
                <Input
                  allowClear
                  aria-label={t('filters.searchLabel')}
                  placeholder={t('filters.searchPlaceholder')}
                  prefix={<Search size={15} />}
                  value={search}
                  style={{ minWidth: 0, flex: '1 1 260px' }}
                  onChange={(event) => { setSearch(event.target.value); setPage(1) }}
                />
                <Select
                  aria-label={t('filters.statusLabel')}
                  value={status}
                  options={[
                    { value: 'all', label: t('filters.allStatuses') },
                    { value: 'pending_activation', label: t('statuses.pending_activation') },
                    { value: 'active', label: t('statuses.active') },
                    { value: 'revoked', label: t('statuses.revoked') },
                  ]}
                  onChange={(value) => { setStatus(value); setPage(1) }}
                />
                <Button type="primary" icon={<KeyRound size={15} />} disabled={writesLocked} onClick={openCreate}>
                  {t('actions.create')}
                </Button>
              </div>

              {query.isError ? (
                <FeedbackWhen title={t('errors.loadFailed')} detail={errorMessage(query.error, t, tAllowlist)} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
              ) : null}

              <div className="identity-table-scroll" data-testid="api-key-table-scroll" aria-busy={query.isPending || query.isFetching}>
                <Table<APIKeyRecord>
                  rowKey="id"
                  size="small"
                  columns={columns}
                  dataSource={query.data?.items ?? []}
                  loading={query.isPending || query.isFetching}
                  pagination={{
                    current: page,
                    pageSize: API_KEY_PAGE_SIZE,
                    showSizeChanger: false,
                    showQuickJumper: true,
                    total: totalRef.current,
                    showTotal: (count) => t('values.total', { count }),
                    onChange: setPage,
                  }}
                  locale={{ emptyText: query.isPending ? ' ' : t('values.empty') }}
                  scroll={{ x: 1640 }}
                />
              </div>
            </>
          ),
        }]}
      />

      <Modal
        className="account-api-key-detail-modal identity-modal"
        title={t('detail.title')}
        open={Boolean(detailID)}
        footer={<Button onClick={() => setDetailID(null)}>{t('actions.close')}</Button>}
        onCancel={() => setDetailID(null)}
        destroyOnHidden
      >
        {detailQuery.isPending ? <Spin /> : null}
        {detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message={t('errors.detailFailed')}
            description={errorMessage(detailQuery.error, t, tAllowlist)}
          />
        ) : null}
        {detailQuery.data ? (
          <Descriptions column={1} size="small" bordered items={[
            { key: 'name', label: t('columns.name'), children: detailQuery.data.name },
            { key: 'prefix', label: t('columns.prefix'), children: <code>{detailQuery.data.key_prefix}********</code> },
            { key: 'scopes', label: t('columns.scopes'), children: detailQuery.data.scopes.map(permissionName).join('、') },
            { key: 'allowlist', label: tAllowlist('label'), children: allowlistTags(detailQuery.data.ip_allowlist, tAllowlist('unrestricted')) },
            { key: 'status', label: t('columns.status'), children: t(`statuses.${detailQuery.data.status}`) },
            { key: 'expires', label: t('columns.expiresAt'), children: dateTime(detailQuery.data.expires_at, locale, t('values.never')) },
            { key: 'used', label: t('columns.lastUsedAt'), children: dateTime(detailQuery.data.last_used_at, locale, t('values.neverUsed')) },
          ]} />
        ) : null}
      </Modal>

      <Modal
        className="account-api-key-editor-modal"
        title={editor?.mode === 'edit' ? t('editor.editTitle') : t('editor.createTitle')}
        open={Boolean(editor)}
        confirmLoading={mutation.isPending}
        okText={editor?.mode === 'edit' ? t('actions.save') : t('actions.create')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ disabled: writesLocked && !mutation.isPending }}
        maskClosable={!mutation.isPending}
        closable={!mutation.isPending}
        onCancel={() => { if (!mutation.isPending) { setEditor(null); form.resetFields() } }}
        onOk={() => form.submit()}
        destroyOnHidden
      >
        {editor ? writeErrorAlert : null}
        <Form<APIKeyFormValues>
          form={form}
          layout="vertical"
          disabled={mutation.isPending || uncertain}
          onFinish={(values) => {
            if (!editor) return
            const input: APIKeyFields = {
              name: values.name.trim(),
              scopes: values.scopes,
              ip_allowlist: splitAllowlist(values.ip_allowlist),
              ...(values.expires_at ? { expires_at: new Date(values.expires_at).toISOString() } : {}),
            }
            const allowlistError = validateAPIKeyIPAllowlist(input.ip_allowlist)
            if (allowlistError) {
              form.setFields([{ name: 'ip_allowlist', errors: [tAllowlist(`validation.${allowlistError}`)] }])
              return
            }
            if (editor.mode === 'edit' && editor.item) {
              submit({ kind: 'update', id: editor.item.id, revision: editor.item.revision, input, key: writeKey('update') })
            } else {
              submit({ kind: 'create', input, key: writeKey('create') })
            }
          }}
        >
          <Form.Item name="name" label={t('editor.name')} rules={[
            { required: true, whitespace: true, message: t('editor.validation.nameRequired') },
            { max: 128, message: t('editor.validation.nameMax') },
          ]}>
            <Input maxLength={128} autoComplete="off" />
          </Form.Item>
          <Form.Item name="scopes" label={t('editor.scopes')} rules={[{ required: true, message: t('editor.validation.scopesRequired') }]}>
            <Select mode="multiple" options={scopeOptions} optionFilterProp="search" maxTagCount="responsive" virtual={false} />
          </Form.Item>
          <Form.Item name="ip_allowlist" label={tAllowlist('label')} extra={tAllowlist('help')}>
            <Input.TextArea aria-label={tAllowlist('label')} placeholder={tAllowlist('placeholder')} autoSize={{ minRows: 3, maxRows: 8 }} />
          </Form.Item>
          <Form.Item name="expires_at" label={t('editor.expiresAt')}>
            <Input type="datetime-local" min={dateTimeLocalValue(new Date().toISOString())} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        className="account-api-key-secret-modal"
        title={t('secret.title')}
        open={Boolean(issued)}
        footer={[
          <Button key="close" type="primary" onClick={() => setIssued(null)}>{t('actions.secretSaved')}</Button>,
        ]}
        closable={false}
        maskClosable={false}
        keyboard={false}
        destroyOnHidden
      >
        <Alert type="warning" showIcon message={t('secret.warning')} />
        <Input.TextArea
          aria-label={t('secret.ariaLabel')}
          value={issued ? `${issued.key.key_id}.${issued.secret}` : ''}
          readOnly
          autoSize={{ minRows: 3, maxRows: 5 }}
        />
        <Button
          icon={<Copy size={15} />}
          onClick={() => {
            if (!issued) return
            void navigator.clipboard.writeText(`${issued.key.key_id}.${issued.secret}`)
              .then(() => messageApi.success(t('notices.copied')))
              .catch(() => feedback.error(t('errors.copyFailed')))
          }}
        >
          {t('actions.copy')}
        </Button>
      </Modal>
      <Modal
        className="account-api-key-secret-modal account-api-key-simple-secret-modal"
        title={t('compatibility.issuedTitle')}
        width={MODAL_WIDTH.M}
        open={Boolean(simpleIssued)}
        footer={[
          <Button key="close" type="primary" onClick={() => setSimpleIssued(null)}>{t('actions.secretSaved')}</Button>,
        ]}
        closable={false}
        maskClosable={false}
        keyboard={false}
        destroyOnHidden
      >
        <Alert type="warning" showIcon message={t('compatibility.issuedWarning')} />
        {simpleIssued ? (
          <dl className="account-api-key-issued-pair">
            {([
              ['apiKey', simpleIssued.key.key_id, 'copyKey'],
              ['apiSecret', simpleIssued.secret, 'copySecret'],
            ] as const).map(([label, value, copy]) => (
              <div key={label}>
                <dt>{t(`compatibility.${label}`)}</dt>
                <dd>
                  <Input readOnly value={value} aria-label={t(`compatibility.${label}`)} />
                  <Button icon={<Copy size={15} />} aria-label={t(`compatibility.${copy}`)} onClick={() => copyText(value)}>
                    {t('compatibility.copy')}
                  </Button>
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
        <p className="account-api-key-issued-usage">{t('compatibility.usage')}</p>
      </Modal>
    </section>
  )
}
