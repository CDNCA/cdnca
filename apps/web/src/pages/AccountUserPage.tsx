import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Form, Input, Result, Spin } from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, useFormSubmitError } from '@cdnca/ui'
import type { TFunction } from 'i18next'
import { LockKeyhole, Mail, MonitorSmartphone, Pencil, Smartphone, UserRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { identityVerificationApi, type IdentityVerificationSelfStatusValue } from '../api/identityVerification'
import { mfaApi } from '../api/mfa'
import { usersApi, type ChangePasswordRequest, type UpdateProfileRequest } from '../api/users'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import { formatDateTime as dateTime } from '../i18n/formatters'
import '../i18n/accountMfa'
import './AccountUserPage.css'
import { PASSWORD_POLICY_HINT, passwordPolicyLocale, passwordPolicyRule } from '@cdnca/ui/password-policy'

const AccountMfaPanel = lazy(() => import('./account/AccountMfaPanel'))

interface ProfileFormValues {
  display_name: string
  email?: string
  phone?: string
  profile_current_password?: string
}

interface BindFormValues {
  phone?: string
  email?: string
  bind_current_password?: string
}

interface PasswordFormValues extends ChangePasswordRequest {
  confirm_password: string
}

type ProfileQueryKey = readonly [
  'account-profile',
  string | undefined,
  string | undefined,
  string | null | undefined,
  string | undefined,
  number,
]

const staleProfileAttempt = new Error('Profile session owner changed')
const stalePasswordAttempt = new Error('Password session owner changed')

// 手机/邮箱绑定走 PATCH /v1/account/profile 行内表单；实名认证跳到租户的 /account/verification；
// 登录安全设置展开真实的两步验证（MFA）面板，状态徽章读 GET /v1/account/mfa。
type BindableCheck = 'phoneBinding' | 'emailBinding'
type ExpandableCheck = BindableCheck | 'loginSecurityItem'
const bindableChecks: ReadonlySet<string> = new Set<BindableCheck>(['phoneBinding', 'emailBinding'])
// 实名徽章与说明按 GET /v1/identity-verification/status 的四种状态显示。
const realNameRows = {
  unverified: { descriptionKey: 'realNameDescription', statusKey: 'statusUnverified' },
  pending: { descriptionKey: 'realNamePendingDescription', statusKey: 'statusPending' },
  verified: { descriptionKey: 'realNameVerifiedDescription', statusKey: 'statusVerified' },
  rejected: { descriptionKey: 'realNameRejectedDescription', statusKey: 'statusRejected' },
} as const satisfies Record<IdentityVerificationSelfStatusValue, { descriptionKey: string; statusKey: string }>

function profileOwnerKey(
  scopeKind: string | undefined,
  scopeID: string | undefined,
  tenantID: string | null | undefined,
  userID: string | undefined,
  sessionEpoch: number,
): string | null {
  if (!scopeID || !userID || !sessionEpoch) return null
  // 平台管理员没有独立租户，此页展示管理员自己的资料，所以平台作用域按自身作用域处理。
  if (scopeKind === 'tenant') {
    if (!tenantID) return null
    return JSON.stringify([scopeKind, scopeID, tenantID, userID, sessionEpoch])
  }
  if (scopeKind === 'platform' && (tenantID === null || tenantID === undefined)) {
    return JSON.stringify([scopeKind, scopeID, scopeID, userID, sessionEpoch])
  }
  return null
}

function currentProfileSessionCan(owner: string, permission: string): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  return Boolean(
    accessToken &&
    principal?.permissions.includes(permission) &&
    profileOwnerKey(
      principal.scope_kind,
      principal.scope_id,
      principal.tenant_id,
      principal.user_id,
      sessionEpoch,
    ) === owner,
  )
}

function writeKey(): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `update-profile-${suffix}`
}

function writeOutcomeUnknown(error: unknown): boolean {
  if (error instanceof ApiError && (error.status === 429 || error.code === 'rate_limited')) return false
  return (
    !(error instanceof ApiError) ||
    error.status === 0 ||
    error.status === 408 ||
    error.status >= 500 ||
    error.code === 'invalid_response'
  )
}

function profileErrorMessage(error: unknown, t: TFunction<'accountProfile'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  if (error.status === 429 || error.code === 'rate_limited') return t('errors.rate_limited')
  switch (error.code) {
    case 'version_conflict':
    case 'idempotency_conflict':
    case 'validation_error':
    case 'invalid_credentials':
    case 'permission_denied':
    case 'network_error':
    case 'request_failed':
    case 'invalid_response':
      return t(`errors.${error.code}`)
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

function passwordErrorMessage(error: unknown, t: TFunction<'accountProfile'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  if (error.status === 429) return t('errors.rate_limited')
  switch (error.code) {
    case 'invalid_credentials':
    case 'validation_error':
    case 'permission_denied':
    case 'rate_limited':
    case 'network_error':
    case 'request_failed':
    case 'invalid_response':
      return t(`errors.${error.code}`)
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

function AccountUserPageSession({
  accessToken,
  owner,
  profileQueryKey,
  canUpdateProfile,
  canChangePassword,
}: {
  accessToken: string
  owner: string
  profileQueryKey: ProfileQueryKey
  canUpdateProfile: boolean
  canChangePassword: boolean
}) {
  const { t, i18n } = useTranslation('accountProfile')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const queryClient = useQueryClient()
  const [profileForm] = Form.useForm<ProfileFormValues>()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const mountedProfileQueryKeyRef = useRef(profileQueryKey)
  // 绑定请求的资料快照与当前密码只放在 ref 里，按一次性 handle 取用，不进 MutationCache。
  const profileInputsRef = useRef(new Map<string, UpdateProfileRequest & { current_password: string }>())
  const cleanupGenerationRef = useRef(0)
  const profileMutationKey = ['account-profile-update', owner] as const
  const passwordMutationKey = ['account-password-change', owner] as const
  // 点行内按钮展开一个 padding 16px、左边距 66px 的内联表单，再点收起。
  const [bindForm] = Form.useForm<BindFormValues>()
  const [openedCheck, setOpenedCheck] = useState<ExpandableCheck | null>(null)
  // 「登录密码 ******」旁的铅笔可点开改密码；密码只放在 ref 里，不进 mutation 缓存。
  const navigate = useNavigate()
  const [passwordForm] = Form.useForm<PasswordFormValues>()
  // A refused current_password / new_password is marked under it (fix-fielderr-be3).
  const markPasswordError = useFormSubmitError(passwordForm)
  const [passwordOpen, setPasswordOpen] = useState(false)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const passwordInputsRef = useRef(new Map<string, ChangePasswordRequest>())

  const query = useQuery({
    queryKey: profileQueryKey,
    queryFn: () => {
      if (!currentProfileSessionCan(owner, 'identity.self.read')) {
        throw new ApiError('Permission denied', 403, 'permission_denied')
      }
      return usersApi.profile(accessTokenRef.current)
    },
  })
  const refetchProfile = () => {
    if (currentProfileSessionCan(owner, 'identity.self.read')) void query.refetch()
  }

  // 资料读到后才读 MFA 状态，避免换身份时用新令牌提前请求。
  const mfaBadgeQueryKey = ['account-user-mfa-badge', owner] as const
  const mfaBadgeQuery = useQuery({
    queryKey: mfaBadgeQueryKey,
    enabled: Boolean(query.data),
    retry: false,
    queryFn: () => {
      if (!currentProfileSessionCan(owner, 'identity.self.read')) {
        throw new ApiError('Permission denied', 403, 'permission_denied')
      }
      return mfaApi.getStatus(accessTokenRef.current)
    },
  })

  // 实名徽章读 GET /v1/identity-verification/status；只有租户且有实名权限时才有本人状态可读。
  const identityStatusQueryKey = ['account-user-identity-status', owner] as const
  const canReadIdentityStatus = currentProfileSessionCan(owner, 'identity_verification.self.manage') &&
    useSessionStore.getState().principal?.scope_kind === 'tenant'
  const identityStatusQuery = useQuery({
    queryKey: identityStatusQueryKey,
    enabled: Boolean(query.data) && canReadIdentityStatus,
    retry: false,
    queryFn: ({ signal }) => {
      if (!currentProfileSessionCan(owner, 'identity_verification.self.manage')) {
        throw new ApiError('Permission denied', 403, 'permission_denied')
      }
      return identityVerificationApi.getStatus(accessTokenRef.current, signal)
    },
  })

  useEffect(() => {
    if (!query.data) return
    profileForm.setFieldsValue({
      display_name: query.data.display_name,
      email: query.data.email ?? undefined,
      phone: query.data.phone ?? undefined,
    })
  }, [profileForm, query.data])

  useEffect(() => {
    const generation = ++cleanupGenerationRef.current
    const cleanupOwnerCache = () => {
      profileInputsRef.current.clear()
      passwordInputsRef.current.clear()
      queryClient.removeQueries({ queryKey: mountedProfileQueryKeyRef.current, exact: true })
      queryClient.removeQueries({ queryKey: ['account-user-mfa-badge', owner], exact: true })
      queryClient.removeQueries({ queryKey: ['account-user-identity-status', owner], exact: true })
      const mutationCache = queryClient.getMutationCache()
      for (const mutationKey of [profileMutationKey, passwordMutationKey]) {
        for (const mutation of mutationCache.findAll({ mutationKey, exact: true })) {
          mutationCache.remove(mutation)
        }
      }
    }
    return () => {
      const state = useSessionStore.getState()
      const currentOwner = profileOwnerKey(
        state.principal?.scope_kind,
        state.principal?.scope_id,
        state.principal?.tenant_id,
        state.principal?.user_id,
        state.sessionEpoch,
      )
      if (currentOwner !== owner) {
        cleanupOwnerCache()
        return
      }
      queueMicrotask(() => {
        // eslint-disable-next-line react-hooks/exhaustive-deps -- The current generation cancels StrictMode's stale cleanup.
        if (cleanupGenerationRef.current === generation) cleanupOwnerCache()
      })
    }
  }, [owner, queryClient])

  const bindMutation = useMutation({
    mutationKey: profileMutationKey,
    mutationFn: (attempt: { item: 'phoneBinding' | 'emailBinding'; value: string; key: string }) => {
      const source = profileInputsRef.current.get(attempt.key)
      profileInputsRef.current.delete(attempt.key)
      if (!source || !currentProfileSessionCan(owner, 'identity.self.update')) throw staleProfileAttempt
      return usersApi.bindContact(
        accessTokenRef.current,
        attempt.item === 'phoneBinding'
          ? { expected_revision: source.expected_revision, display_name: source.display_name, phone: attempt.value, current_password: source.current_password }
          : { expected_revision: source.expected_revision, display_name: source.display_name, email: attempt.value, current_password: source.current_password },
        attempt.key,
      )
    },
    onSuccess: (profile, attempt) => {
      profileInputsRef.current.delete(attempt.key)
      if (!currentProfileSessionCan(owner, 'identity.self.update')) return
      queryClient.setQueryData(profileQueryKey, profile)
      profileForm.setFieldsValue({ display_name: profile.display_name, email: profile.email ?? undefined, phone: profile.phone ?? undefined })
      bindForm.resetFields()
      setOpenedCheck(null)
      messageApi.success(t('notices.profileSaved'))
    },
    onError: (error, attempt) => {
      profileInputsRef.current.delete(attempt.key)
      if (error === staleProfileAttempt || !currentProfileSessionCan(owner, 'identity.self.update')) return
      bindForm.setFieldValue('bind_current_password', '')
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.request_failed'))
      // fp-role ID-05：确定失败标在展开的绑定表单里（密码错 → 当前密码；号码/邮箱不可用 → 该输入框），不弹全局提示。
      const contactField = attempt.item === 'phoneBinding' ? 'phone' : 'email'
      if (!writeOutcomeUnknown(error) && apiError.code === 'invalid_credentials') {
        bindForm.setFields([{ name: 'bind_current_password', errors: [t('errors.invalid_credentials')] }])
        return
      }
      if (!writeOutcomeUnknown(error) && apiError.code === 'validation_error') {
        bindForm.setFields([{ name: contactField, errors: [t(`errors.${contactField}Unavailable`)] }])
        return
      }
      feedback.error(writeOutcomeUnknown(error) ? t('uncertainty.title') : profileErrorMessage(apiError, t))
    },
  })
  const passwordMutation = useMutation({
    mutationKey: passwordMutationKey,
    mutationFn: (handle: string) => {
      const input = passwordInputsRef.current.get(handle)
      passwordInputsRef.current.delete(handle)
      if (!input || !currentProfileSessionCan(owner, 'identity.password.change')) throw stalePasswordAttempt
      return usersApi.changePassword(accessTokenRef.current, input)
    },
    onSuccess: () => {
      if (!currentProfileSessionCan(owner, 'identity.password.change')) return
      passwordForm.resetFields()
      // 登录页收到 passwordChanged 后清空本地会话并提示重新登录。
      void navigate('/login', { replace: true, state: { passwordChanged: true } })
    },
    onError: (error) => {
      if (error === stalePasswordAttempt || !currentProfileSessionCan(owner, 'identity.password.change')) return
      passwordForm.setFieldValue('current_password', '')
      if (markPasswordError(error)) return
      setPasswordError(passwordErrorMessage(error, t))
    },
  })
  const passwordControlsDisabled = !canChangePassword || passwordMutation.isPending
  const togglePassword = () => {
    if (!canChangePassword) return
    setPasswordOpen((open) => !open)
    setPasswordError(null)
    passwordForm.resetFields()
  }

  if (query.isPending) {
    return (
      <section className="identity-page account-user-shell account-profile-loading" aria-label={t('loading')}>
        <Spin size="small" />
      </section>
    )
  }

  const error = query.error instanceof ApiError ? query.error : null
  if (error?.status === 403) {
    return (
      <section className="identity-page account-user-shell">
        <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
      </section>
    )
  }
  if (query.isError || !query.data) {
    return (
      <section className="identity-page account-user-shell">
        <FeedbackWhen title={t('errors.profileLoadFailed')} detail={profileErrorMessage(query.error, t)} action={<Button size="small" onClick={refetchProfile}>{t('actions.retry')}</Button>} />
      </section>
    )
  }

  // 徽章与按钮文案按真实数据决定：已绑定显示绿色「已绑定」+「更换绑定」，未绑定显示橙色「未绑定」+「立即绑定」。
  const mfaActive = mfaBadgeQuery.data?.status === 'active'
  // 实名状态未读到（无权限、平台账号、加载中或读取失败）时不显示徽章，避免显示与事实不符的状态。
  const identityStatus: IdentityVerificationSelfStatusValue | undefined = canReadIdentityStatus
    ? identityStatusQuery.data?.status
    : undefined
  // 无实名权限、平台账号或实名接口未挂载（404）时，实名认证对本账号未开放：不催促认证，也不给入口。
  const identityUnavailable = !canReadIdentityStatus ||
    (identityStatusQuery.error instanceof ApiError && identityStatusQuery.error.status === 404)
  const identityRow = identityStatus
    ? realNameRows[identityStatus]
    : identityUnavailable
      ? { descriptionKey: 'realNameUnavailableDescription', statusKey: 'statusUnverified' } as const
      : realNameRows.unverified
  const boundHandles = { realName: identityStatus === 'verified', phoneBinding: Boolean(query.data.phone), emailBinding: Boolean(query.data.email), loginSecurityItem: mfaActive }
  const canOpenVerification = canReadIdentityStatus
  const checkRows = [
    ['realName', identityRow.descriptionKey, 'verify', identityRow.statusKey],
    ['phoneBinding', 'phoneDescription', query.data.phone ? 'emailRebind' : 'bind', query.data.phone ? 'statusBound' : 'statusUnbound'],
    ['emailBinding', query.data.email ? 'emailDescription' : 'emailUnboundDescription', query.data.email ? 'emailRebind' : 'bind', query.data.email ? 'statusBound' : 'statusUnbound'],
    ['loginSecurityItem', 'loginSecurityDescription', 'setup', mfaActive ? 'statusSet' : 'statusUnset'],
  ] as const
  const checkEnabled = (item: (typeof checkRows)[number][0]) => {
    if (item === 'realName') return canOpenVerification
    if (item === 'loginSecurityItem') return true
    return canUpdateProfile && !bindMutation.isPending
  }
  // 点行内按钮展开一个 padding 16px、左边距 66px 的内联表单，再点收起。
  const toggleCheck = (item: string) => {
    if (item === 'realName') {
      if (canOpenVerification) void navigate('/account/verification')
      return
    }
    if (item !== 'phoneBinding' && item !== 'emailBinding' && item !== 'loginSecurityItem') return
    const next = openedCheck === item ? null : item
    if (openedCheck === 'loginSecurityItem') void queryClient.invalidateQueries({ queryKey: mfaBadgeQueryKey, exact: true })
    setOpenedCheck(next)
    bindForm.resetFields()
  }
  const submitBind = async (item: 'phoneBinding' | 'emailBinding') => {
    if (!query.data || !currentProfileSessionCan(owner, 'identity.self.update') || bindMutation.isPending) return
    // 先跑表单规则（手机号/邮箱格式、当前密码必填），格式不对不发请求。
    const values = await bindForm.validateFields().catch(() => null)
    if (!values || !query.data || !currentProfileSessionCan(owner, 'identity.self.update')) return
    const value = (item === 'phoneBinding' ? values.phone : values.email)?.trim() ?? ''
    const password = values.bind_current_password ?? ''
    if (!value || !password) return
    const handle = writeKey()
    profileInputsRef.current.set(handle, {
      expected_revision: query.data.revision,
      display_name: query.data.display_name,
      email: query.data.email,
      phone: query.data.phone,
      current_password: password,
    } as UpdateProfileRequest & { current_password: string })
    bindMutation.mutate({ item, value, key: handle })
  }

  return (
    <section className="identity-page account-profile-page account-user-page" aria-labelledby="account-profile-title">
      {messageContext}
      <h1 id="account-profile-title" className="visually-hidden">{t('title')}</h1>
      <section className="account-user-shell">
        <section className="account-compatibility-summary account-user-summary" aria-label={t('profile.sectionTitle')}>
          <div className="account-compatibility-summary-grid account-user-summary-grid">
            <div className="account-user-info-item">
              <span className="account-user-info-label">{t('profile.username')}</span>
              {/* 展示格；下方表单里的同名只读输入仍是可访问名称的唯一来源。 */}
              <span className="account-user-info-value">{query.data.username}</span>
            </div>
            <div className="account-user-info-item">
              <span className="account-user-info-label">{t('profile.compatibility.qq')}</span>
              <span className="account-user-info-value account-user-muted-value">
                {t('profile.compatibility.unavailable')}
                <Pencil className="account-user-edit-icon" size={14} aria-hidden="true" />
              </span>
            </div>
            <div className="account-user-info-item">
              <span className="account-user-info-label">{t('profile.compatibility.registration')}</span>
              <span className="account-user-info-value account-user-muted-value">{dateTime(query.data.created_at, locale)}</span>
            </div>
            <div className="account-user-info-item">
              <span className="account-user-info-label">{t('password.current')}</span>
              <span className="account-user-info-value account-user-muted-value">
                ******
                <Button
                  type="text"
                  size="small"
                  className="account-user-edit-button"
                  aria-label={t('actions.changePassword')}
                  aria-expanded={passwordOpen}
                  disabled={passwordControlsDisabled}
                  icon={<Pencil className="account-user-edit-icon" size={14} aria-hidden="true" />}
                  onClick={togglePassword}
                />
              </span>
            </div>
          </div>
          {passwordOpen && canChangePassword ? (
            <div className="account-user-bind-form account-user-password-form">
              {passwordError ? <FeedbackWhen title={passwordError} /> : null}
              <Form<PasswordFormValues>
                form={passwordForm}
                colon={false}
                layout="vertical"
                disabled={passwordControlsDisabled}
                onFinish={(values) => {
                  if (passwordControlsDisabled || !currentProfileSessionCan(owner, 'identity.password.change')) return
                  setPasswordError(null)
                  const handle = writeKey()
                  passwordInputsRef.current.set(handle, {
                    current_password: values.current_password,
                    new_password: values.new_password,
                  })
                  passwordMutation.mutate(handle)
                }}
              >
                <Form.Item name="current_password" label={t('password.current')} rules={[{ required: true, message: t('password.validation.currentRequired') }]}>
                  <Input.Password size="large" autoComplete="current-password" />
                </Form.Item>
                <Form.Item
                  name="new_password"
                  label={t('password.new')}
                  extra={PASSWORD_POLICY_HINT[passwordPolicyLocale(i18n.resolvedLanguage)]}
                  rules={[
                    { required: true, message: t('password.validation.newRequired') },
                    passwordPolicyRule(passwordPolicyLocale(i18n.resolvedLanguage)),
                  ]}
                >
                  <Input.Password size="large" autoComplete="new-password" />
                </Form.Item>
                <Form.Item
                  name="confirm_password"
                  label={t('password.confirm')}
                  dependencies={['new_password']}
                  rules={[
                    { required: true, message: t('password.validation.confirmRequired') },
                    ({ getFieldValue }) => ({
                      validator(_, value) {
                        return !value || getFieldValue('new_password') === value
                          ? Promise.resolve()
                          : Promise.reject(new Error(t('password.validation.mismatch')))
                      },
                    }),
                  ]}
                >
                  <Input.Password size="large" autoComplete="new-password" />
                </Form.Item>
                <div className="account-user-bind-actions">
                  <Button size="large" disabled={passwordMutation.isPending} onClick={togglePassword}>
                    {t('profile.compatibility.bindForm.cancel')}
                  </Button>
                  <Button type="primary" size="large" htmlType="submit" loading={passwordMutation.isPending}>
                    {t('profile.compatibility.bindForm.submit')}
                  </Button>
                </div>
              </Form>
            </div>
          ) : null}
        </section>
        <section className="account-compatibility-checks account-user-checks" aria-label={t('profile.compatibility.loginSecurity')}>
          <h2 className="account-user-card-title">{t('profile.compatibility.loginSecurity')}</h2>
          {checkRows.map(([titleKey, descriptionKey, actionKey, statusKey]) => (
            <div className="account-user-check-block" key={titleKey}>
              <div className="account-compatibility-check account-user-check">
                <span className="account-user-check-icon" aria-hidden="true">
                  {titleKey === 'realName' ? <UserRound size={28} strokeWidth={1.35} /> : titleKey === 'phoneBinding' ? <Smartphone size={28} strokeWidth={1.35} /> : titleKey === 'emailBinding' ? <Mail size={28} strokeWidth={1.35} /> : <LockKeyhole size={28} strokeWidth={1.35} />}
                </span>
                <div className="account-user-action-main">
                  <span className="account-user-action-title-line">
                    <span className="account-user-check-title">{t(`profile.compatibility.${titleKey}`)}</span>
                    {/* 实名与 MFA 状态未读到前不显示徽章，避免显示与事实不符的状态。 */}
                    {(titleKey === 'loginSecurityItem' && !mfaBadgeQuery.data) || (titleKey === 'realName' && !identityStatus) ? null : (
                      <span className={boundHandles[titleKey] ? 'account-user-status is-ok' : 'account-user-status is-warn'}>
                        {t(`profile.compatibility.${statusKey}`)}
                      </span>
                    )}
                  </span>
                  <span className="account-user-check-desc">{t(`profile.compatibility.${descriptionKey}`)}</span>
                </div>
                {/* 已认证或实名未开放时不显示「立即认证」。 */}
                {titleKey === 'realName' && (identityStatus === 'verified' || identityUnavailable) ? null : (
                  <Button
                    disabled={!checkEnabled(titleKey)}
                    aria-expanded={titleKey === 'realName' ? undefined : openedCheck === titleKey}
                    onClick={() => toggleCheck(titleKey)}
                  >{t(`profile.compatibility.${actionKey}`)}</Button>
                )}
              </div>
              {openedCheck === titleKey && bindableChecks.has(titleKey) ? (
                <div className="account-user-bind-form">
                  <Form form={bindForm} colon={false} layout="vertical" disabled={bindMutation.isPending}>
                    <Form.Item
                      name={titleKey === 'phoneBinding' ? 'phone' : 'email'}
                      label={t(`profile.compatibility.${titleKey}`)}
                      rules={titleKey === 'phoneBinding'
                        ? [{ required: true, pattern: /^\+?[0-9]{6,20}$/, message: t('profile.validation.phone') }]
                        : [{ required: true, type: 'email', message: t('profile.validation.email') }]}
                    >
                      <Input size="large" autoComplete={titleKey === 'phoneBinding' ? 'tel' : 'email'} placeholder={titleKey === 'phoneBinding' ? t('profile.compatibility.bindForm.phonePlaceholder') : t('profile.compatibility.bindForm.emailPlaceholder')} />
                    </Form.Item>
                    <Form.Item
                      name="bind_current_password"
                      label={t('password.current')}
                      rules={[{ required: true, message: t('password.validation.currentRequired') }]}
                    >
                      <Input.Password size="large" autoComplete="current-password" placeholder={t('profile.compatibility.bindForm.currentPassword')} />
                    </Form.Item>
                    <p className="account-user-bind-hint">{t('profile.compatibility.bindForm.hint')}</p>
                    <div className="account-user-bind-actions">
                      <Button size="large" disabled={bindMutation.isPending} onClick={() => toggleCheck(titleKey)}>
                        {t('profile.compatibility.bindForm.cancel')}
                      </Button>
                      <Button type="primary" size="large" loading={bindMutation.isPending} onClick={() => { void submitBind(titleKey as BindableCheck) }}>
                        {t('profile.compatibility.bindForm.submit')}
                      </Button>
                    </div>
                  </Form>
                </div>
              ) : null}
              {openedCheck === titleKey && titleKey === 'loginSecurityItem' ? (
                <div className="account-user-bind-form account-user-mfa-form">
                  <Suspense fallback={<Spin size="small" aria-label={t('loading')} />}>
                    <AccountMfaPanel />
                  </Suspense>
                </div>
              ) : null}
            </div>
          ))}
          {/* fp-role ID-03：登录会话（/account/sessions）原先没有任何入口。 */}
          <div className="account-user-check-block">
            <div className="account-compatibility-check account-user-check">
              <span className="account-user-check-icon" aria-hidden="true"><MonitorSmartphone size={28} strokeWidth={1.35} /></span>
              <div className="account-user-action-main">
                <span className="account-user-action-title-line"><span className="account-user-check-title">{t('profile.compatibility.sessionsItem')}</span></span>
                <span className="account-user-check-desc">{t('profile.compatibility.sessionsDescription')}</span>
              </div>
              <Button onClick={() => void navigate('/account/sessions')}>{t('profile.compatibility.sessionsOpen')}</Button>
            </div>
          </div>
        </section>
      </section>
    </section>
  )
}

export default function AccountUserPage() {
  const { t } = useTranslation('accountProfile')
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken) return null

  const owner = profileOwnerKey(
    principal?.scope_kind,
    principal?.scope_id,
    principal?.tenant_id,
    principal?.user_id,
    sessionEpoch,
  )
  if (!principal || !owner || !principal.permissions.includes('identity.self.read')) {
    return (
      <section className="identity-page">
        <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
      </section>
    )
  }

  const profileQueryKey: ProfileQueryKey = [
    'account-profile',
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
  ]
  return (
    <AccountUserPageSession
      key={owner}
      accessToken={accessToken}
      owner={owner}
      profileQueryKey={profileQueryKey}
      canUpdateProfile={principal.permissions.includes('identity.self.update')}
      canChangePassword={principal.permissions.includes('identity.password.change')}
    />
  )
}
