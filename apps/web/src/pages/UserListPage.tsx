import { useCallback, useEffect, useMemo, useRef, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Dropdown,
  Form,
  Input,
  Modal,
  Pagination,
  Popconfirm,
  Radio,
  Result,
  Select,
  Switch,
  Tabs,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { AdvancedFilters, useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown, useFormSubmitError, useLiveApply, type FormErrorMap } from '@cdnca/ui'
import { filterParam, useFilterUrl } from './filterUrl'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ChevronDown, CheckCircle2, Plus, RefreshCw, XCircle } from 'lucide-react'

import { ApiError, type Principal } from '../api/auth'
import { createImpersonationWriteMetadata, impersonationApi } from '../api/impersonation'
import { createMfaWriteMetadata, mfaApi } from '../api/mfa'
import { MfaSetupButton } from '../components/MfaSetupButton'
import {
  createUserWriteMetadata,
  isPlatformAdministrator,
  usersApi,
  validUserMetadataValue,
  type BatchUpdateUserRequest,
  type CreateUserRequest,
  type ListedUser,
  type ManagedUser,
  type ManagedUserRole,
  type ManagedUserLoginSecurity,
  type ManagedUserSecondaryVerification,
  type ResetManagedUserPasswordRequest,
  type UpdateUserRequest,
  type UpdateUserLoginSecurityRequest,
  type UpdateUserSecondaryVerificationRequest,
  type UserRole,
  type UserStatus,
  type UserRealNameStatus,
  type UserGroup,
  type UserWriteMetadata,
} from '../api/users'
import { homeForPrincipal, useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import AccountQuotaPanel from './users/AccountQuotaPanel'
import { PASSWORD_POLICY_HINT, passwordPolicyLocale, passwordPolicyRule } from '@cdnca/ui/password-policy'

interface UserFormValues {
  username: string
  password?: string
  email?: string
  remark?: string
  phone?: string
  qq?: string
  role: ManagedUserRole
  group_id?: string
  enabled: boolean
  personal_verified: boolean
  company_verified: boolean
  secondary_verification: boolean
  secondary_verification_deadline?: string
  verification_expiry_action: 'none' | 'lock_sites'
  verification_status: boolean
  login_verification: 'none' | 'sms' | 'email'
  login_allowlist?: string
}

interface UserSearchDrafts {
  username: string
  displayName: string
  remark: string
  email: string
  qq: string
  phone: string
}

interface PasswordResetFormValues {
  new_password: string
  confirm_password: string
  code: string
}

interface PasswordResetAttempt {
  key: string
  ownerKey: string
  input: ResetManagedUserPasswordRequest
  metadata: UserWriteMetadata
}

type WriteIntent =
  | { kind: 'create'; input: CreateUserRequest }
  | { kind: 'update'; id: string; input: UpdateUserRequest }
  | { kind: 'security'; user: ListedUser }
  | { kind: 'batch'; input: BatchUpdateUserRequest[]; status: UserStatus }
  | { kind: 'delete'; id: string; expectedRevision: number }

interface WriteAttempt {
  intent: WriteIntent
  key: string
  metadata: UserWriteMetadata
  ownerKey: string
  loginSecurity?: { input: UpdateUserLoginSecurityRequest; metadata: UserWriteMetadata }
  secondaryVerification?: { input: UpdateUserSecondaryVerificationRequest; metadata: UserWriteMetadata }
  completedUser?: ListedUser
  // Policies already saved in this attempt, so a resubmission after a later failure uses their new revision.
  savedLoginSecurity?: ManagedUserLoginSecurity
}

type PlatformUsersOwner = readonly ['platform', string, null, string, number]
const staleManagedUsersRead = new Error('stale managed users read')
const staleManagedUsersWrite = new Error('stale managed users write')

function platformUsersOwner(principal: Principal, sessionEpoch: number): PlatformUsersOwner | null {
  if (
    principal.scope_kind !== 'platform' ||
    !principal.scope_id ||
    principal.tenant_id !== null ||
    !principal.user_id ||
    !sessionEpoch
  ) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function canManageUsers(principal: Principal): boolean {
  return principal.permissions.includes('identity.users.manage') ||
    principal.permissions.includes('platform.admin')
}

function canImpersonateUsers(principal: Principal): boolean {
  return principal.permissions.includes('identity.impersonation.manage')
}

function impersonationErrorKey(error: unknown): string {
  if (!(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 ||
    error.status >= 500) return 'switchErrors.unknown'
  if (error.code === 'impersonation_principal_changed') return 'switchErrors.principal'
  if (error.code === 'impersonation_permission_denied') return 'switchErrors.denied'
  return 'switchErrors.request'
}

function currentPlatformUsersAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canManageUsers(principal)) return null
  const owner = platformUsersOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

// Platform-created users are CDN customers (tenant_owner, can create sites).
// Read-only members are invited from the tenant's own member page; they only
// appear here when editing an existing member so the type can be corrected.
function roleOptions(t: TFunction<'users'>, editing: boolean) {
  return [
    { value: 'tenant_owner', label: t('roles.owner') },
    ...(editing ? [{ value: 'tenant_viewer', label: t('roles.viewer') }] : []),
  ]
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

function dateTime(value: string, locale: string): string {
  return formatDateTime(value, locale) || value
}

function nullable(value?: string): string | null {
  return value?.trim() || null
}

function userProfileChanged(user: ListedUser, values: UserFormValues): boolean {
  return nullable(values.email) !== user.email || nullable(values.phone) !== user.phone ||
    nullable(values.remark) !== (user.metadata?.remark ?? null) ||
    nullable(values.qq) !== (user.metadata?.qq ?? null) ||
    values.enabled !== (user.status === 'active') || (values.group_id ?? null) !== user.group_id ||
    !isPlatformAdministrator(user) && values.role !== user.role
}

function loginAllowlist(value?: string): string[] {
  return [...new Set(value?.trim().split(/\s+/).filter(Boolean) ?? [])].sort()
}

function loginSecurityChanged(policy: ManagedUserLoginSecurity | null, values: UserFormValues): boolean {
  return values.login_verification !== (policy?.login_verification ?? 'none') ||
    JSON.stringify(loginAllowlist(values.login_allowlist)) !== JSON.stringify([...(policy?.login_allowlist ?? [])].sort())
}

const deadlinePattern = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/

// The deadline field is local time "YYYY-MM-DD HH:mm:ss"; empty means no deadline.
function parseLocalDeadline(value?: string): string | null | undefined {
  const text = value?.trim() ?? ''
  if (!text) return null
  const match = deadlinePattern.exec(text)
  if (!match) return undefined
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number)
  const date = new Date(year, month - 1, day, hour, minute, second)
  if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day ||
    date.getHours() !== hour || date.getMinutes() !== minute || date.getSeconds() !== second) return undefined
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function formatLocalDeadline(value: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

// A user without a stored request reads as revision 0, disabled (backend ReadSecondaryVerificationTx).
const absentSecondaryVerification = {
  revision: 0, enabled: false, deadline: null, expiry_action: 'none',
} as const satisfies Pick<ManagedUserSecondaryVerification, 'revision' | 'enabled' | 'deadline' | 'expiry_action'>

function secondaryVerificationRequest(
  policy: Pick<ManagedUserSecondaryVerification, 'revision' | 'enabled' | 'deadline' | 'expiry_action'>,
  values: UserFormValues,
): UpdateUserSecondaryVerificationRequest | undefined {
  const enabled = Boolean(values.secondary_verification)
  const deadline = enabled ? parseLocalDeadline(values.secondary_verification_deadline) : null
  const expiryAction = enabled ? values.verification_expiry_action : 'none'
  if (deadline === undefined || enabled === policy.enabled && deadline === policy.deadline && expiryAction === policy.expiry_action) {
    return undefined
  }
  return { expected_revision: policy.revision, enabled, deadline, expiry_action: expiryAction }
}

function errorMessage(error: unknown, t: TFunction<'users'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  switch (error.code) {
    case 'username_conflict':
    case 'version_conflict':
    case 'idempotency_conflict':
    case 'validation_error':
    case 'user_not_found':
    case 'permission_denied':
    case 'network_error':
    case 'request_failed':
    case 'invalid_response':
    case 'user_group_not_found':
    case 'user_group_name_conflict':
    case 'user_group_in_use':
    case 'mfa_step_up_required':
    case 'managed_password_reset_unavailable':
    case 'login_security_contact_required':
    case 'account_login_method_disabled':
    case 'login_security_unavailable':
    case 'user_protected':
      return t(`errors.${error.code}`)
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

type GroupWriteIntent =
  | { kind: 'create'; name: string }
  | { kind: 'update'; group: UserGroup; name: string }
  | { kind: 'delete'; group: UserGroup }

interface GroupWriteAttempt {
  intent: GroupWriteIntent
  metadata: UserWriteMetadata
}

function UserGroupsPanel({ ownerKey, onChanged }: { ownerKey: string; onChanged: () => void }) {
  const { t, i18n } = useTranslation('users')
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(20)
  const [searchDraft, setSearchDraft] = useState('')
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState<UserGroup | null>(null)
  const [name, setName] = useState('')
  const [touchedName, setTouchedName] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [forbidden, setForbidden] = useState(false)
  const mountedRef = useRef(true)
  const attemptRef = useRef<GroupWriteAttempt | null>(null)

  useEffect(() => () => {
    mountedRef.current = false
    attemptRef.current = null
  }, [])

  const query = useQuery({
    queryKey: ['managed-user-groups', ownerKey, page, limit, search],
    queryFn: async () => {
      const token = currentPlatformUsersAccess(ownerKey)
      if (!token || !mountedRef.current) throw staleManagedUsersRead
      try {
        const value = await usersApi.listGroups(token, page, limit, search)
        if (!currentPlatformUsersAccess(ownerKey) || !mountedRef.current) throw staleManagedUsersRead
        return value
      } catch (error) {
        if (!currentPlatformUsersAccess(ownerKey) || !mountedRef.current) throw staleManagedUsersRead
        if (error instanceof ApiError && error.status === 403) setForbidden(true)
        throw error
      }
    },
    enabled: !forbidden,
  })

  const mutation = useMutation({
    mutationKey: ['managed-user-group-write', ownerKey],
    mutationFn: async (attempt: GroupWriteAttempt) => {
      const token = currentPlatformUsersAccess(ownerKey)
      if (!token || !mountedRef.current || attemptRef.current !== attempt) throw staleManagedUsersWrite
      const result = attempt.intent.kind === 'create'
        ? await usersApi.createGroup(token, attempt.intent.name, attempt.metadata)
        : attempt.intent.kind === 'update'
          ? await usersApi.updateGroup(token, {
              id: attempt.intent.group.id, revision: attempt.intent.group.revision, name: attempt.intent.name,
            }, attempt.metadata)
          : await usersApi.deleteGroup(token, attempt.intent.group, attempt.metadata)
      if (!currentPlatformUsersAccess(ownerKey) || !mountedRef.current || attemptRef.current !== attempt) {
        throw staleManagedUsersWrite
      }
      return result
    },
    onSuccess: async (_result, attempt) => {
      if (!currentPlatformUsersAccess(ownerKey) || !mountedRef.current || attemptRef.current !== attempt) return
      attemptRef.current = null
      setWriteError(null)
      setModalOpen(false)
      setEditing(null)
      setName('')
      await query.refetch()
      onChanged()
    },
    onError: (error, attempt) => {
      if (!currentPlatformUsersAccess(ownerKey) || !mountedRef.current || attemptRef.current !== attempt) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.request_failed'))
      if (apiError.status === 403) {
        setForbidden(true)
        attemptRef.current = null
        setWriteError(null)
        return
      }
      setWriteError(apiError)
      if (!writeOutcomeUnknown(apiError)) {
        attemptRef.current = null
        if (apiError.code === 'version_conflict' || apiError.code === 'user_group_not_found') {
          setModalOpen(false)
          setEditing(null)
          setName('')
          void query.refetch()
          onChanged()
        }
      }
    },
  })

  const start = (intent: GroupWriteIntent) => {
    const operation = intent.kind === 'create' ? 'create-user-group' : `${intent.kind}-user-group`
    const attempt = { intent, metadata: createUserWriteMetadata(operation) }
    attemptRef.current = attempt
    setWriteError(null)
    mutation.mutate(attempt)
  }
  const uncertain = Boolean(attemptRef.current && writeError && writeOutcomeUnknown(writeError))
  const retry = () => {
    if (attemptRef.current && !mutation.isPending && currentPlatformUsersAccess(ownerKey)) {
      mutation.mutate(attemptRef.current)
    }
  }
  const abandon = () => {
    attemptRef.current = null
    setWriteError(null)
    setModalOpen(false)
    setEditing(null)
    setName('')
    void query.refetch()
    onChanged()
  }

  if (forbidden) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }
  return (
    <div className="identity-groups">
      <div className="identity-toolbar">
        <Button type="primary" disabled={mutation.isPending || uncertain} onClick={() => {
          setEditing(null); setName(''); setTouchedName(false); setWriteError(null); setModalOpen(true)
        }}>{t('groups.add')}</Button>
        <div className="identity-search">
          <Input aria-label={t('groups.searchLabel')} value={searchDraft} placeholder={t('groups.searchPlaceholder')}
            onChange={(event) => setSearchDraft(event.target.value)} onPressEnter={() => { setSearch(searchDraft.trim()); setPage(1) }} />
          <Button onClick={() => { setSearch(searchDraft.trim()); setPage(1) }}>{t('actions.search')}</Button>
        </div>
      </div>
      {writeError && !modalOpen ? (uncertain ? <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('groups.uncertain')} action={<div className="identity-row-actions"><Button size="small" onClick={retry}>{t('actions.retrySameRequest')}</Button>
          <Button size="small" onClick={abandon}>{t('actions.closeAndRefresh')}</Button></div>} /> : <FeedbackWhen title={errorMessage(writeError, t)} />) : null}
      {query.isError ? <FeedbackWhen title={t('groups.loadFailed')} detail={errorMessage(query.error, t)} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : <>
        <div className="identity-table-scroll" aria-busy={query.isPending || query.isFetching}>
          <Table<UserGroup> rowKey="id" size="small" pagination={false} scroll={{ x: 900 }} loading={query.isPending || query.isFetching}
            dataSource={query.data?.items ?? []} locale={{ emptyText: query.isPending ? ' ' : t('groups.empty') }} columns={[
              { title: t('columns.id'), dataIndex: 'id', width: 240, ellipsis: true },
              { title: t('groups.name'), dataIndex: 'name', ellipsis: true },
              { title: t('groups.members'), dataIndex: 'member_count', width: 120 },
              { title: t('columns.createdAt'), dataIndex: 'created_at', width: 180,
                render: (value: string) => dateTime(value, i18n.resolvedLanguage === 'en-US' ? 'en-US' : 'zh-CN') },
              { title: t('columns.actions'), key: 'actions', width: 140, render: (_, group) => <div className="identity-row-actions">
                <Button type="link" size="small" disabled={mutation.isPending || uncertain} onClick={() => {
                  setEditing(group); setName(group.name); setTouchedName(false); setWriteError(null); setModalOpen(true)
                }}>{t('actions.edit')}</Button>
                <Popconfirm title={t('groups.deleteTitle')} description={t('groups.deleteDescription')}
                  okText={t('groups.confirmDelete')} cancelText={t('actions.cancel')} disabled={group.member_count > 0 || mutation.isPending || uncertain}
                  onConfirm={() => start({ kind: 'delete', group })}>
                  <Button danger type="link" size="small" disabled={group.member_count > 0 || mutation.isPending || uncertain}>{t('groups.delete')}</Button>
                </Popconfirm>
              </div> },
            ]} />
        </div>
        <Pagination current={page} pageSize={limit} total={query.data?.total ?? 0} showSizeChanger pageSizeOptions={[10, 20, 50, 100]}
          showTotal={(count) => t('values.total', { count: formatNumber(count, i18n.resolvedLanguage) })}
          onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} />
      </>}
      <Modal open={modalOpen} title={editing ? t('groups.editTitle') : t('groups.addTitle')}
        okText={t(uncertain ? 'actions.retrySameRequest' : 'actions.confirm')}
        cancelText={t(uncertain ? 'actions.closeAndRefresh' : 'actions.cancel')}
        confirmLoading={mutation.isPending}
        onCancel={() => { if (!mutation.isPending) { if (uncertain) abandon(); else { setModalOpen(false); setEditing(null); setWriteError(null); attemptRef.current = null } } }}
        onOk={() => {
          if (uncertain) {
            retry()
            return
          }
          const trimmed = name.trim()
          if (!trimmed) { setTouchedName(true); return }
          if (trimmed) start(editing ? { kind: 'update', group: editing, name: trimmed } : { kind: 'create', name: trimmed })
        }}>
        <Form layout="vertical" component="div">
          <Form.Item label={t('groups.name')} htmlFor="user-group-name" required
            validateStatus={!uncertain && !name.trim() && touchedName ? 'error' : undefined}
            help={!uncertain && !name.trim() && touchedName ? t('groups.nameRequired') : undefined}>
            <Input id="user-group-name" value={name} maxLength={128} disabled={mutation.isPending || uncertain}
              placeholder={t('groups.searchPlaceholder')}
              onChange={(event) => { setName(event.target.value); setTouchedName(true) }} />
          </Form.Item>
        </Form>
        {writeError ? <Alert className="identity-alert" type="error" showIcon
          message={uncertain ? t('uncertainty.title') : errorMessage(writeError, t)}
          description={uncertain ? t('groups.uncertain') : undefined} /> : null}
      </Modal>
    </div>
  )
}

// Server user fields with another name on the form:
// display_name is derived from email / username, status is the 启用 switch.
const userErrorMap: FormErrorMap = { display_name: 'username', status: 'enabled' }

function UserFormModal({
  user,
  loginSecurity,
  secondaryVerification,
  partialSaved,
  open,
  pending,
  uncertain,
  error,
  onCancel,
  onRetry,
  onSubmit,
  groups,
  selfID,
  usersAccess,
}: {
  user: ListedUser | null
  loginSecurity: ManagedUserLoginSecurity | null
  secondaryVerification: ManagedUserSecondaryVerification | null
  partialSaved: boolean
  open: boolean
  pending: boolean
  uncertain: boolean
  error: ApiError | null
  onCancel: () => void
  onRetry: () => void
  onSubmit: (values: UserFormValues) => void
  groups: UserGroup[]
  selfID: string
  /** 编辑租户用户时的「刷新预热额度」页签；不传则不显示。 */
  usersAccess?: { accessToken: () => string | null }
}) {
  const { t, i18n: userFormI18n } = useTranslation('users')
  const { t: tc } = useTranslation('cacheOperations')
  const canReadAccountQuota = useSessionStore((state) => Boolean(state.principal?.permissions.some(
    (permission) => permission === 'sites.read' || permission === 'platform.admin',
  )))
  const canManageAccountQuota = useSessionStore((state) => Boolean(state.principal && canManageUsers(state.principal)))
  const policyLocale = passwordPolicyLocale(userFormI18n.resolvedLanguage)
  const [form] = Form.useForm<UserFormValues>()
  const [activeTab, setActiveTab] = useState('basic')
  const [unsupportedError, setUnsupportedError] = useState(false)
  const initialized = useRef(false)
  const locked = pending || uncertain
  // A refused field is marked under it on the 基本信息 tab instead of the alert.
  const [fieldMarked, setFieldMarked] = useState(false)
  const markSubmitError = useFormSubmitError(form, userErrorMap)
  useEffect(() => {
    if (!error || uncertain || partialSaved) {
      setFieldMarked(false)
      return
    }
    setActiveTab('basic')
    const timer = setTimeout(() => setFieldMarked(markSubmitError(error)))
    return () => clearTimeout(timer)
  }, [error, markSubmitError, partialSaved, uncertain])
  // Platform administrators keep their type and group; their password and login
  // security are managed from the account security page, not this tenant flow.
  const platformAdmin = Boolean(user && isPlatformAdministrator(user))
  const editingSelf = user?.id === selfID
  const enabledValue = Form.useWatch('enabled', form)
  const [modalApi, modalContext] = Modal.useModal()

  useEffect(() => {
    if (!open) { initialized.current = false; return }
    if (initialized.current) return
    initialized.current = true
    setActiveTab('basic')
    setUnsupportedError(false)
    form.resetFields()
    const defaults: UserFormValues = {
      username: '',
      password: '',
      email: undefined,
      remark: '',
      phone: undefined,
      qq: '',
      role: 'tenant_owner',
      group_id: undefined,
      enabled: true,
      personal_verified: false,
      company_verified: false,
      secondary_verification: false,
      secondary_verification_deadline: '',
      verification_expiry_action: 'none',
      verification_status: false,
      login_verification: loginSecurity?.login_verification ?? 'none',
      login_allowlist: loginSecurity?.login_allowlist.join(' ') ?? '',
    }
    if (user) {
      form.setFieldsValue({
        ...defaults,
        username: user.username,
        email: user.email ?? undefined,
        phone: user.phone ?? undefined,
        remark: user.metadata?.remark ?? '',
        qq: user.metadata?.qq ?? '',
        role: user.role,
        group_id: user.group_id ?? undefined,
        enabled: user.status === 'active',
        personal_verified: user.verification?.personal_verified ?? false,
        company_verified: user.verification?.company_verified ?? false,
        secondary_verification: secondaryVerification?.enabled ?? false,
        secondary_verification_deadline: formatLocalDeadline(secondaryVerification?.deadline ?? null),
        verification_expiry_action: secondaryVerification?.expiry_action ?? 'none',
        verification_status: secondaryVerification?.completed ?? false,
      })
    } else {
      form.setFieldsValue(defaults)
    }
  }, [form, open, user, loginSecurity, secondaryVerification])

  useEffect(() => {
    if (partialSaved) form.setFieldValue('password', '')
  }, [form, partialSaved])

  const submit = async () => {
    if (uncertain) {
      onRetry()
      return
    }
    try {
      await form.validateFields()
      const values = form.getFieldsValue(true)
      const supportedChanged = Boolean(user && (userProfileChanged(user, values) || loginSecurityChanged(loginSecurity, values)))
      const unsupportedChanged = Boolean(
        values.personal_verified !== undefined && values.personal_verified !== (user?.verification?.personal_verified ?? false) ||
        values.company_verified !== undefined && values.company_verified !== (user?.verification?.company_verified ?? false) ||
        // Secondary verification is saved through its own endpoint after the tenant user exists;
        // platform administrators have no request.
        user && !secondaryVerification && (values.secondary_verification ||
          values.secondary_verification_deadline?.trim() ||
          values.verification_expiry_action !== undefined && values.verification_expiry_action !== 'none') ||
        user && values.username.trim() !== user.username ||
        user && Boolean(values.password) && supportedChanged ||
        platformAdmin && Boolean(values.password) ||
        !user && !values.enabled
      )
      if (unsupportedChanged) {
        setUnsupportedError(true)
        return
      }
      setUnsupportedError(false)
      if (editingSelf && user?.status === 'active' && !values.enabled) {
        void modalApi.confirm({
          title: t('confirm.selfDisableTitle'),
          content: t('confirm.selfDisableDescription'),
          okText: t('actions.confirmSelfDisable'),
          okButtonProps: { danger: true },
          cancelText: t('actions.cancel'),
          onOk: () => onSubmit(values),
        })
        return
      }
      onSubmit(values)
    } catch {
      setActiveTab('basic')
    }
  }

  return (
    <Modal
      className="identity-modal user-form-modal"
      width={760}
      style={{ top: 48 }}
      title={user ? t('form.editTitle') : t('form.addTitle')}
      open={open}
      confirmLoading={pending}
      okText={uncertain ? t('actions.retrySameRequest') : t('actions.confirm')}
      cancelText={uncertain ? t('actions.closeAndRefresh') : t('actions.close')}
      cancelButtonProps={{ disabled: pending }}
      closable={!pending}
      maskClosable={!pending}
      keyboard={!pending}
      onCancel={onCancel}
      onOk={() => void submit()}
      destroyOnHidden
    >
      {error && !fieldMarked ? (
        <Alert
          className="identity-alert"
          type="error"
          showIcon
          message={uncertain ? t('uncertainty.title') : errorMessage(error, t)}
          description={partialSaved ? t('form.partialSaved') : uncertain ? t('uncertainty.formDescription') : undefined}
        />
      ) : null}
      {unsupportedError ? (
        <Alert
          className="identity-alert"
          type="warning"
          showIcon
          message={t('form.unsupportedTitle')}
          description={t('form.unsupportedDescription')}
        />
      ) : null}
      {modalContext}
      {platformAdmin ? (
        <Alert className="identity-alert" type="info" showIcon message={t('form.platformAdminNotice')} />
      ) : null}
      {editingSelf && user?.status === 'active' && enabledValue === false ? (
        <Alert className="identity-alert" type="warning" showIcon message={t('confirm.selfDisableDescription')} />
      ) : null}
      <Form
        form={form}
        layout="horizontal"
        labelCol={{ flex: '110px' }}
        wrapperCol={{ flex: 'auto' }}
        requiredMark={false}
        disabled={pending || uncertain}
        onValuesChange={() => setUnsupportedError(false)}
      >
        <Tabs
          className="user-form-tabs"
          activeKey={activeTab}
          onChange={setActiveTab}
          items={[
            {
              key: 'basic',
              label: t('form.tabs.basic'),
              children: (
                <div className="user-form-tab-panel">
                  <Form.Item
                    name="email"
                    label={t('form.email')}
                    rules={[
                      { required: true, message: t('form.validation.emailRequired') },
                      { type: 'email', message: t('form.validation.email') },
                    ]}
                  >
                    <Input autoComplete="email" disabled={locked} placeholder={t('form.placeholders.email')} />
                  </Form.Item>
                  <Form.Item
                    name="username"
                    label={t('form.username')}
                    rules={[
                      { required: true, message: t('form.validation.usernameRequired') },
                      { min: 3, max: 128, message: t('form.validation.usernameLength') },
                      { pattern: /^[a-z0-9][a-z0-9._-]*$/, message: t('form.validation.usernamePattern') },
                    ]}
                  >
                    <Input disabled={locked} autoComplete="off" placeholder={t('form.placeholders.username')} />
                  </Form.Item>
                  <Form.Item name="remark" label={t('form.remark')} rules={[{
                    validator: (_, value: string | undefined) => validUserMetadataValue(value ?? null, 'remark')
                      ? Promise.resolve() : Promise.reject(new Error(t('form.validation.remark'))),
                  }]}>
                    <Input.TextArea rows={2} disabled={locked} placeholder={t('form.placeholders.remark')} />
                  </Form.Item>
                  <Form.Item
                    name="phone"
                    label={t('form.phone')}
                    rules={[{ pattern: /^\+?[0-9]{6,20}$/, message: t('form.validation.phone') }]}
                  >
                    <Input autoComplete="tel" disabled={locked} placeholder={t('form.placeholders.phone')} />
                  </Form.Item>
                  <Form.Item name="qq" label={t('form.qq')} rules={[{
                    validator: (_, value: string | undefined) => validUserMetadataValue(value ?? null, 'qq')
                      ? Promise.resolve() : Promise.reject(new Error(t('form.validation.qq'))),
                  }]}>
                    <Input disabled={locked} placeholder={t('form.placeholders.qq')} />
                  </Form.Item>
                  <Form.Item
                    name="password"
                    label={t('form.password')}
                    extra={!user ? PASSWORD_POLICY_HINT[policyLocale] : undefined}
                    rules={!user ? [
                      { required: true, message: t('form.validation.passwordRequired') },
                      passwordPolicyRule(policyLocale),
                    ] : []}
                  >
                    <Input.Password autoComplete="new-password" disabled={locked || platformAdmin} placeholder={t('form.placeholders.password')} />
                  </Form.Item>
                  <Form.Item name="group_id" label={t('form.group')}>
                    <Select
                      allowClear
                      options={groups.map((group) => ({ value: group.id, label: group.name }))}
                      disabled={locked || platformAdmin}
                      placeholder={t('form.placeholders.group')}
                    />
                  </Form.Item>
                  {!platformAdmin ? (
                    <Form.Item name="role" label={t('form.role')} rules={[{ required: true }]}>
                      <Radio.Group
                        optionType="button"
                        buttonStyle="outline"
                        disabled={locked}
                        options={roleOptions(t, Boolean(user))}
                      />
                    </Form.Item>
                  ) : null}
                  <Form.Item name="enabled" label={t('form.enabled')} valuePropName="checked">
                    <Switch disabled={locked} />
                  </Form.Item>
                </div>
              ),
            },
            {
              key: 'identity',
              label: t('form.tabs.identity'),
              children: (
                <div className="user-form-tab-panel">
                  {/* ADMIN-CURRENT-07：实名结论只走认证审批链（用户本人在「账户实名」提交，
                      租户审核队列审批）；这里只读展示服务端结论，不提供资料编辑。 */}
                  <Alert className="identity-alert" type="info" showIcon message={t('form.identityReadOnlyTitle')}
                    description={t(user && !user.verification ? 'form.identityNotLoaded' : 'form.identityReadOnlyDescription')} />
                  <Form.Item name="personal_verified" label={t('form.personalVerified')} valuePropName="checked">
                    <Switch disabled />
                  </Form.Item>
                  <Form.Item name="company_verified" label={t('form.companyVerified')} valuePropName="checked">
                    <Switch disabled />
                  </Form.Item>
                  <div className="user-form-section-title"><span>{t('form.secondaryVerification')}</span></div>
                  <Form.Item label={t('form.toggle')}>
                    <div className="user-form-switch-help">
                      <Form.Item name="secondary_verification" valuePropName="checked" noStyle>
                        <Switch disabled={locked} />
                      </Form.Item>
                      <span>{t('form.secondaryVerificationHelp')}</span>
                    </div>
                  </Form.Item>
                  <Form.Item
                    name="secondary_verification_deadline"
                    label={t('form.deadline')}
                    dependencies={['secondary_verification', 'verification_expiry_action']}
                    rules={[({ getFieldValue }) => ({
                      validator: (_, value?: string) => {
                        if (!getFieldValue('secondary_verification')) return Promise.resolve()
                        const deadline = parseLocalDeadline(value)
                        if (deadline === undefined) return Promise.reject(new Error(t('form.validation.deadlineFormat')))
                        if (deadline === null && getFieldValue('verification_expiry_action') === 'lock_sites') {
                          return Promise.reject(new Error(t('form.validation.deadlineRequired')))
                        }
                        return Promise.resolve()
                      },
                    })]}
                  >
                    <Input disabled={locked} placeholder={t('form.placeholders.deadline')} />
                  </Form.Item>
                  <Form.Item name="verification_expiry_action" label={t('form.verificationExpiry')}>
                    <Radio.Group
                      optionType="button"
                      buttonStyle="outline"
                      options={[
                        { value: 'none', label: t('form.expiryActions.none') },
                        { value: 'lock_sites', label: t('form.expiryActions.lockSites') },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item name="verification_status" label={t('form.verificationStatus')} valuePropName="checked"
                    extra={t('form.verificationStatusHelp')}>
                    <Switch disabled />
                  </Form.Item>
                </div>
              ),
            },
            {
              key: 'security',
              label: t('form.tabs.security'),
              disabled: platformAdmin,
              children: (
                <div className="user-form-tab-panel user-form-security-panel">
                  <Form.Item name="login_verification" label={t('form.loginVerification')}>
                    <Radio.Group
                      optionType="button"
                      buttonStyle="outline"
                      options={[
                        { value: 'none', label: t('form.loginVerificationOptions.none') },
                        { value: 'sms', label: t('form.loginVerificationOptions.sms') },
                        { value: 'email', label: t('form.loginVerificationOptions.email') },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item name="login_allowlist" label={t('form.loginAllowlist')}>
                    <Input.TextArea rows={2} disabled={locked} placeholder={t('form.placeholders.loginAllowlist')} />
                  </Form.Item>
                </div>
              ),
            },
            // 该账号今日刷新预热用量，可刷新、可单独设置上限（独立保存）。
            ...(user && !platformAdmin && usersAccess && canReadAccountQuota ? [{
              key: 'cache_quota',
              label: tc('accountQuota.tab'),
              children: (
                <AccountQuotaPanel scopeID={user.scope_id} accessToken={usersAccess.accessToken}
                  canManage={canManageAccountQuota} />
              ),
            }] : []),
          ]}
        />
      </Form>
    </Modal>
  )
}

function UserListContent({
  owner,
  ownerKey,
  canImpersonate,
}: {
  owner: PlatformUsersOwner
  ownerKey: string
  canImpersonate: boolean
}) {
  const { t, i18n } = useTranslation('users')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const queryOwner = useRef(owner).current
  const queryPrefix = useMemo(() => ['managed-users', ...queryOwner] as const, [queryOwner])
  const mutationKey = useMemo(() => ['managed-users-write', ...queryOwner] as const, [queryOwner])
  const passwordResetMutationKey = useMemo(
    () => ['managed-user-password-reset', ...queryOwner] as const,
    [queryOwner],
  )
  const lineageActiveRef = useRef(true)
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [switchingUserID, setSwitchingUserID] = useState<string | null>(null)
  // 「切换」直接以该用户身份登录：创建一次性授权后立即交换，
  // 不再经过填写工单号/原因/动态验证码的表单页。
  const switchToUser = async (user: ManagedUser) => {
    const { accessToken, sessionEpoch } = useSessionStore.getState()
    if (!accessToken || switchingUserID) return
    setSwitchingUserID(user.id)
    try {
      const created = await impersonationApi.createGrant(accessToken, {
        tenant_id: user.tenant_id, tenant_scope_id: user.scope_id, subject_user_id: user.id,
      }, createImpersonationWriteMetadata('create'))
      if (useSessionStore.getState().sessionEpoch !== sessionEpoch) return
      const session = await impersonationApi.exchange({
        tenant_id: user.tenant_id, tenant_scope_id: user.scope_id,
        authorization_code: created.authorization_code,
      }, createImpersonationWriteMetadata('exchange'))
      const applied = useSessionStore.getState().transitionPrincipal(
        sessionEpoch, { ...session.principal, impersonation: session.banner },
      )
      if (applied) navigate(homeForPrincipal(session.principal), { replace: true })
    } catch (error) {
      if (useSessionStore.getState().sessionEpoch === sessionEpoch) feedback.error(t(impersonationErrorKey(error)))
    } finally {
      setSwitchingUserID(null)
    }
  }
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  // `?display_id=` (e.g. from the site list owner link) opens the list filtered to that user.
  const [searchParams] = useSearchParams()
  const initialDisplayID = filterParam(searchParams, 'display_id').replace(/\D/gu, '')
  const [displayIDDraft, setDisplayIDDraft] = useState(initialDisplayID)
  const [displayID, setDisplayID] = useState(initialDisplayID)
  // `?username=` (ticket detail "查看用户") prefills the username filter.
  const initialUsername = filterParam(searchParams, 'username')
  // 其余文本条件同样可从 URL 带入（分享链接）。
  const fromURL = (name: string) => filterParam(searchParams, name)
  const [searchDrafts, setSearchDrafts] = useState<UserSearchDrafts>({
    username: initialUsername, displayName: fromURL('display_name'), remark: fromURL('remark'), email: fromURL('email'), qq: fromURL('qq'), phone: fromURL('phone'),
  })
  const [fieldFilters, setFieldFilters] = useState({ username: initialUsername, display_name: fromURL('display_name'), email: fromURL('email'), phone: fromURL('phone') })
  const [remark, setRemark] = useState(fromURL('remark'))
  const [qq, setQQ] = useState(fromURL('qq'))
  const status: UserStatus | undefined = undefined
  const role: UserRole | undefined = undefined
  const [groupID, setGroupID] = useState<string | undefined>()
  const [realNameStatus, setRealNameStatus] = useState<UserRealNameStatus | undefined>()
  const [activeTab, setActiveTab] = useState<'users' | 'groups'>('users')
  const [editing, setEditing] = useState<ListedUser | null>(null)
  const [editingLoginSecurity, setEditingLoginSecurity] = useState<ManagedUserLoginSecurity | null>(null)
  const [editingSecondaryVerification, setEditingSecondaryVerification] = useState<ManagedUserSecondaryVerification | null>(null)
  const [partialSaved, setPartialSaved] = useState(false)
  const [editingLoading, setEditingLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedUserIDs, setSelectedUserIDs] = useState<Key[]>([])
  const [batchTarget, setBatchTarget] = useState<UserStatus | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ListedUser | null>(null)
  const [passwordResetForm] = Form.useForm<PasswordResetFormValues>()
  const [passwordResetTarget, setPasswordResetTarget] = useState<ManagedUser | null>(null)
  const selfID = queryOwner[3]
  const [passwordResetPending, setPasswordResetPending] = useState(false)
  const [passwordResetError, setPasswordResetError] = useState<ApiError | null>(null)
  const passwordResetAttemptRef = useRef<PasswordResetAttempt | null>(null)
  const writeAttemptRef = useRef<WriteAttempt | null>(null)
  const [attemptKey, setAttemptKey] = useState<string | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const serverForbiddenRef = useRef(false)
  const [serverForbidden, setServerForbidden] = useState(false)
  const currentSessionCanManage = useCallback(() => (
    lineageActiveRef.current && Boolean(currentPlatformUsersAccess(ownerKey))
  ), [ownerKey])

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentPlatformUsersAccess(ownerKey)) {
        queryClient.removeQueries({ queryKey: queryPrefix })
        queryClient.removeQueries({ queryKey: ['managed-user-groups', ownerKey] })
        queryClient.removeQueries({ queryKey: ['managed-user-group-options', ...queryOwner] })
        for (const entry of queryClient.getMutationCache().findAll({ mutationKey, exact: true })) {
          queryClient.getMutationCache().remove(entry)
        }
        for (const entry of queryClient.getMutationCache().findAll({
          mutationKey: passwordResetMutationKey, exact: true,
        })) {
          queryClient.getMutationCache().remove(entry)
        }
        for (const entry of queryClient.getMutationCache().findAll({
          mutationKey: ['managed-user-group-write', ownerKey], exact: true,
        })) {
          queryClient.getMutationCache().remove(entry)
        }
        writeAttemptRef.current = null
        passwordResetAttemptRef.current = null
      }
    }
  }, [mutationKey, ownerKey, passwordResetMutationKey, queryClient, queryPrefix])

  const clearWriteAttempt = () => {
    writeAttemptRef.current = null
    setAttemptKey(null)
  }

  const query = useQuery({
    queryKey: [...queryPrefix, page, limit, fieldFilters, status, role, groupID, realNameStatus, displayID, remark, qq],
    queryFn: async () => {
      const token = currentPlatformUsersAccess(ownerKey)
      if (!token || !lineageActiveRef.current) throw staleManagedUsersRead
      if (serverForbiddenRef.current) {
        throw new ApiError(t('errors.permission_denied'), 403, 'permission_denied')
      }
      try {
        const result = await usersApi.list(token, {
          page, limit, display_id: displayID, ...fieldFilters, status, role, group_id: groupID, remark, qq,
          include_verification: true, real_name_status: realNameStatus, include_platform_admins: true,
        })
        if (!currentSessionCanManage()) throw staleManagedUsersRead
        return result
      } catch (error) {
        if (!currentSessionCanManage()) throw staleManagedUsersRead
        if (error instanceof ApiError && error.status === 403) {
          serverForbiddenRef.current = true
          writeAttemptRef.current = null
          setAttemptKey(null)
          setWriteError(null)
          setServerForbidden(true)
        }
        throw error
      }
    },
    enabled: !serverForbidden,
  })

  const groupOptionsQuery = useQuery({
    queryKey: ['managed-user-group-options', ...queryOwner],
    queryFn: async () => {
      const token = currentPlatformUsersAccess(ownerKey)
      if (!token || !lineageActiveRef.current) throw staleManagedUsersRead
      const result = await usersApi.listGroups(token, 1, 100)
      if (!currentSessionCanManage()) throw staleManagedUsersRead
      return result
    },
    enabled: !serverForbidden,
  })

  const execute = async (key: string) => {
    const attempt = writeAttemptRef.current
    const token = attempt?.ownerKey === ownerKey && lineageActiveRef.current
      ? currentPlatformUsersAccess(attempt.ownerKey)
      : null
    if (serverForbiddenRef.current || !attempt || attempt.key !== key || !token) {
      throw staleManagedUsersWrite
    }
    try {
      const result = attempt.completedUser ?? (attempt.intent.kind === 'create'
        ? await usersApi.create(token, attempt.intent.input, attempt.metadata)
        : attempt.intent.kind === 'update'
          ? await usersApi.update(token, attempt.intent.id, attempt.intent.input, attempt.metadata)
          : attempt.intent.kind === 'security'
            ? attempt.intent.user
            : attempt.intent.kind === 'batch'
              ? await usersApi.batchUpdate(token, attempt.intent.input, attempt.metadata)
              : await usersApi.deleteUser(token, attempt.intent.id, attempt.intent.expectedRevision, attempt.metadata))
      if (!currentSessionCanManage() || writeAttemptRef.current !== attempt) throw staleManagedUsersWrite
      if (attempt.loginSecurity && (attempt.intent.kind === 'create' || attempt.intent.kind === 'update' || attempt.intent.kind === 'security')) {
        const target = result as ListedUser
        if (attempt.intent.kind !== 'security') attempt.completedUser = target
        attempt.savedLoginSecurity = await usersApi.updateLoginSecurity(token, target.id, target.scope_id,
          attempt.loginSecurity.input, attempt.loginSecurity.metadata)
        if (!currentSessionCanManage() || writeAttemptRef.current !== attempt) throw staleManagedUsersWrite
      }
      if (attempt.secondaryVerification && (attempt.intent.kind === 'create' || attempt.intent.kind === 'update' || attempt.intent.kind === 'security')) {
        const target = result as ListedUser
        if (attempt.intent.kind !== 'security') attempt.completedUser = target
        await usersApi.updateSecondaryVerification(token, target.id, target.scope_id,
          attempt.secondaryVerification.input, attempt.secondaryVerification.metadata)
        if (!currentSessionCanManage() || writeAttemptRef.current !== attempt) throw staleManagedUsersWrite
      }
      return result
    } catch (error) {
      if (!currentSessionCanManage() || writeAttemptRef.current !== attempt) throw staleManagedUsersWrite
      throw error
    }
  }

  const mutation = useMutation({
    mutationKey,
    mutationFn: execute,
    onSuccess: async (_, key) => {
      const attempt = writeAttemptRef.current
      if (!currentSessionCanManage() || !attempt || attempt.key !== key || attempt.ownerKey !== ownerKey) return
      const disabled = attempt.intent.kind === 'update' && attempt.intent.input.status === 'disabled'
      const batchStatus = attempt.intent.kind === 'batch' ? attempt.intent.status : null
      const operation = attempt.intent.kind
      clearWriteAttempt()
      setWriteError(null)
      setPartialSaved(false)
      setModalOpen(false)
      setEditing(null)
      setDeleteTarget(null)
      setSelectedUserIDs([])
      await queryClient.invalidateQueries({ queryKey: queryPrefix })
      if (!currentSessionCanManage()) return
      messageApi.success(
        operation === 'create'
          ? t('notices.created')
          : operation === 'batch'
            ? t(batchStatus === 'disabled' ? 'notices.batchDisabled' : 'notices.batchEnabled')
          : operation === 'delete'
            ? t('notices.deleted')
          : disabled
            ? t('notices.disabled')
            : t('notices.updated'),
      )
    },
    onError: async (error, key) => {
      const attempt = writeAttemptRef.current
      if (
        serverForbiddenRef.current ||
        !currentSessionCanManage() ||
        !attempt ||
        attempt.key !== key ||
        attempt.ownerKey !== ownerKey
      ) return
      const apiError = error instanceof ApiError
        ? error
        : new ApiError(t('errors.request_failed'))
      if (apiError.status === 403 && apiError.code !== 'account_login_method_disabled') {
        serverForbiddenRef.current = true
        writeAttemptRef.current = null
        setAttemptKey(null)
        setWriteError(null)
        setEditing(null)
        setModalOpen(false)
        setServerForbidden(true)
        return
      }
      if (attempt.completedUser && (attempt.loginSecurity || attempt.secondaryVerification)) {
        const target = attempt.completedUser
        setPartialSaved(true)
        setEditing(target)
        if (attempt.savedLoginSecurity) setEditingLoginSecurity(attempt.savedLoginSecurity)
        // A just-created tenant user has no secondary verification request yet.
        if (attempt.intent.kind === 'create' && !isPlatformAdministrator(target)) {
          setEditingSecondaryVerification({ ...absentSecondaryVerification, user_id: target.id, tenant_scope_id: target.scope_id,
            requested_at: null, completed: false, enforced_at: null })
        }
      }
      setWriteError(apiError)
      if (writeOutcomeUnknown(error)) {
        return
      }
      clearWriteAttempt()
      if (apiError.code === 'version_conflict') {
        setWriteError(null)
        setModalOpen(false)
        setEditing(null)
        await queryClient.invalidateQueries({ queryKey: queryPrefix })
        if (currentSessionCanManage()) feedback.error(t('notices.conflictRefreshed'))
      }
    },
  })

  const passwordResetMutation = useMutation({
    mutationKey: passwordResetMutationKey,
    mutationFn: (key: string) => {
      const attempt = passwordResetAttemptRef.current
      const token = attempt?.ownerKey === ownerKey && lineageActiveRef.current
        ? currentPlatformUsersAccess(attempt.ownerKey)
        : null
      if (!attempt || attempt.key !== key || !token) throw staleManagedUsersWrite
      return usersApi.resetPassword(token, attempt.input, attempt.metadata).then(
        (result) => {
          if (!currentSessionCanManage() || passwordResetAttemptRef.current !== attempt) {
            throw staleManagedUsersWrite
          }
          return result
        },
        (error: unknown) => {
          if (!currentSessionCanManage() || passwordResetAttemptRef.current !== attempt) {
            throw staleManagedUsersWrite
          }
          throw error
        },
      )
    },
    onSuccess: async (_, key) => {
      const attempt = passwordResetAttemptRef.current
      if (!currentSessionCanManage() || !attempt || attempt.key !== key) return
      passwordResetAttemptRef.current = null
      setPasswordResetError(null)
      setPasswordResetTarget(null)
      passwordResetForm.resetFields()
      await queryClient.invalidateQueries({ queryKey: queryPrefix })
      if (currentSessionCanManage()) messageApi.success(t('notices.passwordReset'))
    },
    onError: (error, key) => {
      const attempt = passwordResetAttemptRef.current
      if (!currentSessionCanManage() || !attempt || attempt.key !== key) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.request_failed'))
      if (apiError.status === 403) {
        passwordResetAttemptRef.current = null
        setPasswordResetError(null)
        setPasswordResetTarget(null)
        serverForbiddenRef.current = true
        setServerForbidden(true)
        return
      }
      setPasswordResetError(apiError)
      if (!writeOutcomeUnknown(apiError)) passwordResetAttemptRef.current = null
    },
  })

  const beginWrite = (intent: WriteIntent, security?: UpdateUserLoginSecurityRequest,
    secondary?: UpdateUserSecondaryVerificationRequest) => {
    if (serverForbiddenRef.current || !currentSessionCanManage()) return
    const operation = intent.kind === 'security' ? 'login-security' : intent.kind === 'create'
      ? 'create-user'
      : intent.kind === 'update'
        ? `update-user-${intent.id}`
        : intent.kind === 'batch'
          ? 'batch-update-users'
          : `delete-user-${intent.id}`
    const metadata = createUserWriteMetadata(operation)
    const nextAttempt: WriteAttempt = { intent, key: metadata.idempotencyKey, metadata, ownerKey,
      loginSecurity: security ? { input: security, metadata: createUserWriteMetadata('login-security') } : undefined,
      secondaryVerification: secondary
        ? { input: secondary, metadata: createUserWriteMetadata('secondary-verification') } : undefined }
    writeAttemptRef.current = nextAttempt
    setAttemptKey(nextAttempt.key)
    setWriteError(null)
    mutation.mutate(nextAttempt.key)
  }

  const retryWrite = () => {
    if (
      !serverForbiddenRef.current &&
      currentSessionCanManage() &&
      attemptKey &&
      writeAttemptRef.current?.key === attemptKey &&
      writeAttemptRef.current.ownerKey === ownerKey
    ) {
      mutation.mutate(attemptKey)
    }
  }

  const uncertain = Boolean(attemptKey && writeError && writeOutcomeUnknown(writeError))
  const passwordResetUncertain = Boolean(passwordResetAttemptRef.current && passwordResetError &&
    writeOutcomeUnknown(passwordResetError))
  const passwordResetBusy = passwordResetPending || passwordResetMutation.isPending
  const writesLocked = editingLoading || mutation.isPending || uncertain || passwordResetBusy || passwordResetUncertain

  const openEditor = async (user: ListedUser) => {
    if (writesLocked || serverForbiddenRef.current || !currentSessionCanManage()) return
    setWriteError(null)
    setEditingLoading(true)
    try {
      const token = currentPlatformUsersAccess(ownerKey)
      if (!token) return
      const current = user.metadata ? user : await usersApi.get(token, user.id)
      if (!currentSessionCanManage() || serverForbiddenRef.current) return
      const security = isPlatformAdministrator(user) ? null : await usersApi.getLoginSecurity(token, user.id, user.scope_id)
      if (!currentSessionCanManage() || serverForbiddenRef.current) return
      const secondary = isPlatformAdministrator(user) ? null : await usersApi.getSecondaryVerification(token, user.id, user.scope_id)
      if (!currentSessionCanManage() || serverForbiddenRef.current) return
      if (!current.metadata) throw new ApiError(t('errors.invalid_response'), 502, 'invalid_response')
      setEditing(current)
      setEditingLoginSecurity(security)
      setEditingSecondaryVerification(secondary)
      setPartialSaved(false)
      setModalOpen(true)
    } catch (error) {
      if (!currentSessionCanManage()) return
      if (error instanceof ApiError && error.status === 403) {
        serverForbiddenRef.current = true
        setServerForbidden(true)
      } else {
        setWriteError(error instanceof ApiError ? error : new ApiError(t('errors.request_failed')))
      }
    } finally {
      if (lineageActiveRef.current) setEditingLoading(false)
    }
  }

  const closeAndRefresh = () => {
    clearWriteAttempt()
    setWriteError(null)
    setModalOpen(false)
    setEditing(null)
    setDeleteTarget(null)
    if (!serverForbiddenRef.current && currentSessionCanManage()) void query.refetch()
  }

  const submit = (values: UserFormValues) => {
    setWriteError(null)
    const security = loginSecurityChanged(editingLoginSecurity, values) ? {
      expected_revision: editingLoginSecurity?.revision ?? 0,
      login_verification: values.login_verification,
      login_allowlist: loginAllowlist(values.login_allowlist),
    } : undefined
    const secondary = !editing
      ? secondaryVerificationRequest(absentSecondaryVerification, values)
      : editingSecondaryVerification && !isPlatformAdministrator(editing)
        ? secondaryVerificationRequest(editingSecondaryVerification, values) : undefined
    if (editing) {
      if (values.password && !isPlatformAdministrator(editing)) {
        const target = editing
        passwordResetAttemptRef.current = null
        setPasswordResetError(null)
        passwordResetForm.setFieldsValue({
          new_password: values.password,
          confirm_password: values.password,
          code: '',
        })
        setModalOpen(false)
        setEditing(null)
        setPasswordResetTarget(target)
        return
      }
      if ((security || secondary) && !userProfileChanged(editing, values)) {
        beginWrite({ kind: 'security', user: editing }, security, secondary)
        return
      }
      beginWrite({
        kind: 'update',
        id: editing.id,
        input: {
          expected_revision: editing.revision,
          display_name: editing.display_name,
          email: nullable(values.email),
          phone: nullable(values.phone),
          remark: nullable(values.remark),
          qq: nullable(values.qq),
          status: values.enabled ? 'active' : 'disabled',
          role: isPlatformAdministrator(editing) ? editing.role : values.role,
          group_id: values.group_id ?? null,
        },
      }, security, secondary)
      return
    }
    beginWrite({
      kind: 'create',
      input: {
        username: values.username.trim(),
        password: values.password ?? '',
        display_name: values.email?.trim() || values.username.trim(),
        email: nullable(values.email),
        phone: nullable(values.phone),
        remark: nullable(values.remark),
        qq: nullable(values.qq),
        role: values.role as UserRole,
        group_id: values.group_id ?? null,
      },
    }, security, secondary)
  }

  const closePasswordReset = () => {
    passwordResetAttemptRef.current = null
    setPasswordResetError(null)
    setPasswordResetTarget(null)
    passwordResetForm.resetFields()
  }

  const executePasswordReset = (attempt: PasswordResetAttempt) => {
    if (passwordResetAttemptRef.current === attempt) passwordResetMutation.mutate(attempt.key)
  }

  const submitPasswordReset = async (values: PasswordResetFormValues) => {
    const target = passwordResetTarget
    const token = currentPlatformUsersAccess(ownerKey)
    if (!target || !token || passwordResetBusy || passwordResetAttemptRef.current) return
    setPasswordResetPending(true)
    setPasswordResetError(null)
    try {
      const proof = await mfaApi.createStepUpProof(token, {
        tenant_id: target.tenant_id,
        audience: 'identity.user.password.reset',
        action: 'identity.user.password.reset',
        authentication: { method: 'totp', code: values.code },
        ttl_seconds: 300,
        max_uses: 1,
      }, createMfaWriteMetadata('step-up'))
      if (proof.replayed) throw new ApiError(t('errors.invalid_response'), 502, 'invalid_response')
      if (!currentSessionCanManage() || passwordResetTarget !== target) return
      const metadata = createUserWriteMetadata('reset-user-password')
      const attempt: PasswordResetAttempt = {
        key: metadata.idempotencyKey,
        ownerKey,
        input: {
          user_id: target.id,
          tenant_id: target.tenant_id,
          tenant_scope_id: target.scope_id,
          expected_revision: target.revision,
          new_password: values.new_password,
          step_up_token: proof.token,
        },
        metadata,
      }
      passwordResetAttemptRef.current = attempt
      setPasswordResetPending(false)
      executePasswordReset(attempt)
    } catch (error) {
      if (!currentSessionCanManage()) return
      setPasswordResetError(error instanceof ApiError ? error : new ApiError(t('errors.request_failed')))
    } finally {
      if (lineageActiveRef.current) setPasswordResetPending(false)
    }
  }

  // drafts / id: the values to apply (a tag × or 清空 passes them with the cleared fields).
  const applySearch = (drafts: UserSearchDrafts = searchDrafts, id: string = displayIDDraft) => {
    if (drafts !== searchDrafts) setSearchDrafts(drafts)
    setDisplayID(id.trim())
    setRemark(drafts.remark.trim())
    setQQ(drafts.qq.trim())
    setFieldFilters({
      username: drafts.username.trim(),
      display_name: drafts.displayName.trim(),
      email: drafts.email.trim(),
      phone: drafts.phone.trim(),
    })
    setPage(1)
  }

  // 用户ID、用户名及高级里的文本条件边输入边生效（400ms 防抖）。
  useLiveApply(
    { id: displayIDDraft.trim(), username: searchDrafts.username.trim(), display_name: searchDrafts.displayName.trim(), email: searchDrafts.email.trim(), phone: searchDrafts.phone.trim(), remark: searchDrafts.remark.trim(), qq: searchDrafts.qq.trim() },
    { id: displayID, ...fieldFilters, remark, qq },
    () => applySearch(),
  )
  useFilterUrl({ display_id: displayID, ...fieldFilters, remark, qq })

  const updateSearchDraft = (key: keyof UserSearchDrafts, value: string) => {
    setSearchDrafts((current) => ({ ...current, [key]: value }))
  }

  const selectedUsers = (query.data?.items ?? []).filter((user) => selectedUserIDs.includes(user.id))
  const batchUsers = batchTarget
    ? selectedUsers.filter((user) => user.status !== batchTarget)
    : []

  const beginBatch = () => {
    if (!batchTarget || batchUsers.length === 0) return
    const input = batchUsers.map((user): BatchUpdateUserRequest => ({
      id: user.id,
      expected_revision: user.revision,
      display_name: user.display_name,
      email: user.email,
      phone: user.phone,
      status: batchTarget,
      role: user.role,
      group_id: user.group_id,
    }))
    const status = batchTarget
    setBatchTarget(null)
    beginWrite({ kind: 'batch', input, status })
  }

  const columns: TableColumnsType<ListedUser> = [
      {
        title: t('columns.userInfo'),
        key: 'user_info',
        width: 240,
        render: (_, user) => (
          <div className="user-list-cell-stack">
            <span className="visually-hidden">{user.display_name}</span>
            <span className="user-list-cell-primary" title={user.email ?? undefined}>{user.email || t('values.emailMissing')}</span>
            <span className="user-list-cell-secondary">
              <span>{t('values.userID', { id: user.display_id })}</span>
              <span title={user.username}>{user.username}</span>
              {user.id === selfID ? <Tag className="user-list-self-tag">{t('values.self')}</Tag> : null}
            </span>
          </div>
        ),
      },
      {
        title: t('columns.contact'),
        key: 'contact',
        width: 160,
        render: (_, user) => (
          <div className="user-list-cell-stack user-list-cell-muted">
            <span title={user.phone ?? undefined}>{user.phone || t('values.phoneMissing')}</span>
            <span title={user.metadata?.qq ?? undefined}>{user.metadata ? user.metadata.qq ?? t('values.qqMissing') : t('values.notProvided')}</span>
          </div>
        ),
      },
      {
        title: t('columns.remark'),
        key: 'remark',
        width: 180,
        ellipsis: true,
        render: (_, user) => <span className="user-list-cell-muted" title={user.metadata?.remark ?? undefined}>{
          user.metadata ? user.metadata.remark ?? t('values.remarkMissing') : t('values.notProvided')
        }</span>,
      },
      {
        title: t('columns.realName'),
        key: 'real_name',
        width: 120,
        render: (_, user) => {
          if (!user.verification) return <Tag className="user-list-state-tag is-muted">{t('values.notProvided')}</Tag>
          const verified = user.verification.personal_verified || user.verification.company_verified
          return <Tag className={`user-list-state-tag ${verified ? 'is-active' : 'is-unverified'}`}
            icon={verified ? <CheckCircle2 aria-hidden="true" size={12} /> : <XCircle aria-hidden="true" size={12} />}>
            {verified ? t('states.verified') : t('states.unverified')}
          </Tag>
        },
      },
      {
        title: t('columns.enabled'),
        dataIndex: 'status',
        width: 100,
        render: (value: UserStatus) => (
          <Tag
            className={`user-list-state-tag ${value === 'active' ? 'is-active' : 'is-disabled'}`}
            icon={value === 'active'
              ? <CheckCircle2 aria-hidden="true" size={12} />
              : <XCircle aria-hidden="true" size={12} />}
          >
            {value === 'active' ? t('states.enabled') : t('states.disabled')}
          </Tag>
        ),
      },
      {
        title: t('columns.type'),
        dataIndex: 'role',
        width: 120,
        render: (value: ManagedUserRole) => {
          return <Tag className={`user-list-role-tag ${value === 'tenant_viewer' ? '' : 'is-owner'}`}>
            {value === 'platform_owner' ? t('roles.platformOwner') : value === 'platform_admin'
              ? t('roles.platformAdmin') : value === 'tenant_owner' ? t('roles.owner') : t('roles.viewer')}
          </Tag>
        },
      },
      {
        title: t('columns.createdAt'),
        dataIndex: 'created_at',
        width: 150,
        render: (value: string) => {
          const locale = i18n.resolvedLanguage === 'en-US' ? 'en-US' : 'zh-CN'
          const formatted = dateTime(value, locale)
          return locale === 'zh-CN' ? formatted.replaceAll('/', '-') : formatted
        },
      },
      {
        title: t('columns.actions'),
        key: 'actions',
        width: 100,
        render: (_, user) => (
          <div className="identity-row-actions">
            {canImpersonate && !isPlatformAdministrator(user) ? (
              <Button
                type="link"
                size="small"
                disabled={writesLocked || (switchingUserID !== null && switchingUserID !== user.id)}
                loading={switchingUserID === user.id}
                onClick={() => void switchToUser(user)}
              >
                {t('actions.switch')}
              </Button>
            ) : null}
            <Button
              type="link"
              size="small"
              disabled={writesLocked}
              onClick={() => void openEditor(user)}
            >
              {t('actions.edit')}
            </Button>
          </div>
        ),
      },
  ]

  const error = query.error instanceof ApiError ? query.error : null
  const forbidden = serverForbidden || error?.status === 403

  if (forbidden) {
    return (
      <Result
        className="identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  return (
    <section className="identity-page user-list-page" aria-labelledby="managed-user-title">
      {messageContext}
      <h1 id="managed-user-title" className="visually-hidden">
        {t('title')}
      </h1>
      <Tabs activeKey={activeTab} onChange={(key) => setActiveTab(key as 'users' | 'groups')} items={[
        { key: 'users', label: t('tabs.users') },
        { key: 'groups', label: t('tabs.groups') },
      ]} />
      {activeTab === 'groups' ? <UserGroupsPanel ownerKey={ownerKey} onChanged={() => {
        void groupOptionsQuery.refetch()
        void query.refetch()
      }} /> : <>
      <div className="user-list-toolbar">
        <div className="user-list-toolbar-primary">
          <div className="user-list-toolbar-actions">
            <Button
              type="primary"
              icon={<Plus aria-hidden="true" size={15} />}
              disabled={writesLocked}
              onClick={() => {
                setWriteError(null)
                setEditing(null)
                setEditingLoginSecurity(null)
                setEditingSecondaryVerification(null)
                setPartialSaved(false)
                setModalOpen(true)
              }}
            >
              {t('actions.add')}
            </Button>
            <Dropdown
              trigger={['click']}
              menu={{
                items: [
                  {
                    key: 'enable',
                    label: t('actions.batchEnable'),
                    disabled: writesLocked || !selectedUsers.some((user) => user.status !== 'active'),
                  },
                  {
                    key: 'disable',
                    label: t('actions.batchDisable'),
                    danger: true,
                    disabled: writesLocked || !selectedUsers.some((user) => user.status !== 'disabled'),
                  },
                  {
                    key: 'delete',
                    label: t('actions.delete'),
                    danger: true,
                    // The backend also refuses deleting yourself or the last platform_owner.
                    disabled: writesLocked || selectedUsers.length !== 1 || selectedUsers[0]?.id === selfID,
                  },
                ],
                onClick: ({ key }) => {
                  if (key === 'delete') {
                    setDeleteTarget(selectedUsers[0] ?? null)
                    return
                  }
                  setBatchTarget(key === 'enable' ? 'active' : 'disabled')
                },
              }}
            >
              <Button disabled={writesLocked}>
                {t('actions.more')}
                <ChevronDown aria-hidden="true" size={14} />
              </Button>
            </Dropdown>
          </div>
          <div className="user-list-toolbar-filters">
            <Select<UserRealNameStatus | 'all'>
              aria-label={t('filters.realNameStatusLabel')}
              value={realNameStatus ?? 'all'}
              options={[
                { value: 'all', label: t('filters.allRealNameStatuses') },
                { value: 'verified', label: t('states.verified') },
                { value: 'unverified', label: t('states.unverified') },
              ]}
              onChange={(value) => {
                setRealNameStatus(value === 'all' ? undefined : value)
                setPage(1)
              }}
            />
            <Select
              aria-label={t('filters.groupLabel')}
              allowClear
              loading={groupOptionsQuery.isPending || groupOptionsQuery.isFetching}
              placeholder={t('filters.allGroups')}
              value={groupID}
              options={(groupOptionsQuery.data?.items ?? []).map((group) => ({ value: group.id, label: group.name }))}
              onChange={(value) => {
                setGroupID(value)
                setPage(1)
              }}
            />
            <Button
              icon={<RefreshCw aria-hidden="true" size={14} />}
              loading={query.isFetching}
              onClick={() => {
                void query.refetch()
              }}
            >
              {t('actions.refresh')}
            </Button>
          </div>
        </div>
        {/* 常显 用户ID、用户名；姓名、备注、邮箱、QQ、手机号收进高级筛选（已生效的以标签显示）。 */}
        <AdvancedFilters
          className="user-list-search-row"
          storageKey="user-list"
          columns={3}
          primary={<>
            <Input
              addonBefore={t('filters.displayID')}
              aria-label={t('filters.displayIDLabel')}
              inputMode="numeric"
              value={displayIDDraft}
              placeholder={t('filters.displayIDPlaceholder')}
              onChange={(event) => setDisplayIDDraft(event.target.value.replace(/\D/gu, ''))}
              onPressEnter={() => applySearch()}
            />
            <Input
              addonBefore={t('filters.username')}
              aria-label={t('filters.searchLabel')}
              value={searchDrafts.username}
              placeholder={t('filters.usernamePlaceholder')}
              onChange={(event) => updateSearchDraft('username', event.target.value)}
              onPressEnter={() => applySearch()}
            />
          </>}
          items={([
            ['displayName', fieldFilters.display_name],
            ['remark', remark],
            ['email', fieldFilters.email],
            ['qq', qq],
            ['phone', fieldFilters.phone],
          ] as const).map(([key, applied]) => ({
            key, label: t(`filters.${key}`), applied,
            field: <Input aria-label={t(`filters.${key}Label`)} value={searchDrafts[key]} placeholder={t(`filters.${key}Placeholder`)}
              onChange={(event) => updateSearchDraft(key, event.target.value)} />,
          }))}
          onQuery={() => applySearch()}
          onReset={() => {
            setDisplayIDDraft('')
            applySearch({ username: '', displayName: '', remark: '', email: '', qq: '', phone: '' }, '')
          }}
          onClearAdvanced={() => applySearch({ ...searchDrafts, displayName: '', remark: '', email: '', qq: '', phone: '' })}
          onRemove={(key) => applySearch({ ...searchDrafts, [key]: '' })}
        />
      </div>

      {writeError && !modalOpen ? (
        (uncertain ? <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('uncertainty.pageDescription')} action={(
            <div className="identity-row-actions">
              <Button size="small" loading={mutation.isPending} onClick={retryWrite}>{t('actions.retrySameRequest')}</Button>
              <Button size="small" disabled={mutation.isPending} onClick={closeAndRefresh}>{t('actions.closeAndRefresh')}</Button>
            </div>
          )} className="identity-alert" /> : <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} />)
      ) : null}

      {query.isError ? (
        <FeedbackWhen title={t('errors.listLoadFailed')} detail={errorMessage(query.error, t)} action={(
            <Button
              size="small"
              onClick={() => {
                if (!serverForbiddenRef.current) void query.refetch()
              }}
            >
              {t('actions.retry')}
            </Button>
          )} />
      ) : (
        <>
          <div className="identity-table-scroll" aria-busy={query.isPending || query.isFetching}>
            <Table<ListedUser>
              rowKey="id"
              size="small"
              columns={columns}
              dataSource={query.data?.items ?? []}
              loading={query.isPending || query.isFetching}
              pagination={false}
              rowSelection={{
                columnWidth: 56,
                selectedRowKeys: selectedUserIDs,
                onChange: setSelectedUserIDs,
              }}
              locale={{ emptyText: query.isPending ? ' ' : t('values.empty') }}
              scroll={{ x: 1306 }}
            />
          </div>
          <Pagination
            className="identity-pagination"
            current={page}
            pageSize={limit}
            total={query.data?.total ?? 0}
            pageSizeOptions={[10, 20, 50, 100]}
            showSizeChanger
            showTotal={(count) => t('values.total', {
              count: formatNumber(count, i18n.resolvedLanguage),
            })}
            onChange={(nextPage, nextLimit) => {
              setPage(nextLimit === limit ? nextPage : 1)
              setLimit(nextLimit)
            }}
          />
        </>
      )}

      <UserFormModal
        usersAccess={{ accessToken: () => currentPlatformUsersAccess(ownerKey) }}
        user={editing}
        loginSecurity={editingLoginSecurity}
        secondaryVerification={editingSecondaryVerification}
        partialSaved={partialSaved}
        open={modalOpen}
        pending={mutation.isPending}
        uncertain={uncertain}
        error={modalOpen ? writeError : null}
        onCancel={() => {
          if (mutation.isPending) return
          if (uncertain || partialSaved) {
            closeAndRefresh()
            return
          }
          clearWriteAttempt()
          setWriteError(null)
          setModalOpen(false)
          setEditing(null)
        }}
        onRetry={retryWrite}
        onSubmit={submit}
        groups={groupOptionsQuery.data?.items ?? []}
        selfID={selfID}
      />
      <Modal
        open={batchTarget !== null}
        title={t(batchTarget === 'disabled' ? 'confirm.batchDisableTitle' : 'confirm.batchEnableTitle', {
          count: batchUsers.length,
        })}
        okText={t(batchTarget === 'disabled' ? 'actions.confirmBatchDisable' : 'actions.confirmBatchEnable')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ danger: batchTarget === 'disabled', disabled: batchUsers.length === 0 }}
        onCancel={() => setBatchTarget(null)}
        onOk={beginBatch}
        destroyOnHidden
      >
        {t(batchTarget === 'disabled' ? 'confirm.batchDisableDescription' : 'confirm.batchEnableDescription')}
        {batchTarget === 'disabled' && batchUsers.some((user) => user.id === selfID) ? (
          <Alert className="identity-alert" type="warning" showIcon message={t('confirm.selfDisableDescription')} />
        ) : null}
      </Modal>
      <Modal
        open={deleteTarget !== null}
        title={t('confirm.deleteTitle')}
        okText={t('actions.confirmDelete')}
        cancelText={t('actions.cancel')}
        confirmLoading={mutation.isPending}
        okButtonProps={{ danger: true, disabled: !deleteTarget || uncertain }}
        onCancel={() => {
          if (mutation.isPending) return
          if (uncertain) {
            closeAndRefresh()
            return
          }
          setDeleteTarget(null)
        }}
        onOk={() => {
          if (deleteTarget && deleteTarget.id !== selfID) {
            beginWrite({ kind: 'delete', id: deleteTarget.id, expectedRevision: deleteTarget.revision })
          }
        }}
        footer={uncertain ? (
          <div className="identity-row-actions">
            <Button loading={mutation.isPending} onClick={retryWrite}>{t('actions.retrySameRequest')}</Button>
            <Button disabled={mutation.isPending} onClick={closeAndRefresh}>{t('actions.closeAndRefresh')}</Button>
          </div>
        ) : undefined}
        destroyOnHidden
      >
        {t('confirm.deleteDescription', { name: deleteTarget?.display_name ?? '' })}
      </Modal>
      <Modal
        open={passwordResetTarget !== null}
        title={t('passwordReset.title', { name: passwordResetTarget?.display_name ?? '' })}
        okText={t('actions.confirmResetPassword')}
        cancelText={t('actions.cancel')}
        confirmLoading={passwordResetBusy}
        okButtonProps={{ disabled: passwordResetUncertain }}
        onOk={() => passwordResetForm.submit()}
        onCancel={() => {
          if (passwordResetBusy) return
          const refresh = passwordResetUncertain
          closePasswordReset()
          if (refresh && currentSessionCanManage()) void query.refetch()
        }}
        footer={passwordResetUncertain ? (
          <div className="identity-row-actions">
            <Button
              loading={passwordResetBusy}
              onClick={() => {
                const attempt = passwordResetAttemptRef.current
                if (attempt) void executePasswordReset(attempt)
              }}
            >
              {t('actions.retrySameRequest')}
            </Button>
            <Button disabled={passwordResetBusy} onClick={() => {
              closePasswordReset()
              if (currentSessionCanManage()) void query.refetch()
            }}>
              {t('actions.closeAndRefresh')}
            </Button>
          </div>
        ) : undefined}
        destroyOnHidden
      >
        {passwordResetError ? (
          <Alert
            className="identity-alert"
            type="error"
            showIcon
            message={passwordResetUncertain ? t('uncertainty.title') : errorMessage(passwordResetError, t)}
            description={passwordResetUncertain ? t('passwordReset.uncertain') : undefined}
          />
        ) : null}
        <Form<PasswordResetFormValues>
          form={passwordResetForm}
          layout="vertical"
          onFinish={(values) => void submitPasswordReset(values)}
          disabled={passwordResetBusy || passwordResetUncertain}
        >
          <Form.Item
            name="new_password"
            label={t('passwordReset.newPassword')}
            extra={PASSWORD_POLICY_HINT[passwordPolicyLocale(i18n.resolvedLanguage)]}
            rules={[
              { required: true, message: t('passwordReset.newPasswordRequired') },
              passwordPolicyRule(passwordPolicyLocale(i18n.resolvedLanguage)),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('passwordReset.confirmPassword')}
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('passwordReset.confirmPasswordRequired') },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  return !value || getFieldValue('new_password') === value
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('passwordReset.passwordMismatch')))
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="code"
            label={t('passwordReset.mfaCode')}
            rules={[
              { required: true, message: t('passwordReset.mfaCodeRequired') },
              { pattern: /^\d{6}$/, message: t('passwordReset.mfaCodeInvalid') },
            ]}
          >
            <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
          </Form.Item>
          <MfaSetupButton disabled={passwordResetBusy || passwordResetUncertain} />
        </Form>
      </Modal>
      </>}
    </section>
  )
}

export default function UserListPage() {
  const { t } = useTranslation('users')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null

  const owner = platformUsersOwner(principal, sessionEpoch)
  if (!owner || !canManageUsers(principal)) {
    return (
      <Result
        className="identity-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.permission_denied')}
      />
    )
  }

  const ownerKey = JSON.stringify(owner)
  return (
    <UserListContent
      key={ownerKey}
      owner={owner}
      ownerKey={ownerKey}
      canImpersonate={canImpersonateUsers(principal)}
    />
  )
}
