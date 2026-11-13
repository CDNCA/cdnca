import { useCallback, useEffect, useState } from 'react'
import { App, Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { ownedResourcesOf, tenantMembersApi, type CreateTenantMemberInput, type TenantMember, type TenantMemberInvitation } from '../api/tenantMembers'
import { useSessionStore } from '../auth/session'
import { useRuntimeFeatureOff } from '../components/useRuntimeFeatures'
import { localizedApiError } from '../i18n/apiError'
import { tenantMembersMessages } from '../i18n/tenantMembers'
import { FeedbackWhen, PageSection } from '@cdnca/ui'

// Tenant members and sub-accounts; permissions beyond read-only are granted
// through the custom roles page (/v1/custom-rbac).
export default function TenantMembersPage() {
  const { t, i18n } = useTranslation('tenantMembers')
  const { message } = App.useApp()
  const accessToken = useSessionStore(state => state.accessToken)
  const principal = useSessionStore(state => state.principal)
  // Custom roles need the optional custom-RBAC runtime; no link when it is off.
  const customRBACOff = useRuntimeFeatureOff('custom_rbac', accessToken)
  const canRoles = Boolean(principal?.permissions.includes('identity.roles.manage')) && !customRBACOff
  const [members, setMembers] = useState<TenantMember[] | null>(null)
  const [invitations, setInvitations] = useState<TenantMemberInvitation[]>([])
  // 套餐成员数上限：-1 不限，0 当前套餐未开通。
  const [error, setError] = useState<unknown>(null)
  const [creating, setCreating] = useState(false)
  const [inviting, setInviting] = useState(false)
  const [temporaryPassword, setTemporaryPassword] = useState<string | null>(null)
  // A reset whose outcome is unknown (network error/5xx): retrieved with the
  // same Idempotency-Key, never sent as a new reset (TENANT-PWRESET-UNKNOWN).
  const [pendingReset, setPendingReset] = useState<{ member: TenantMember, key: string } | null>(null)
  const [resetting, setResetting] = useState(false)
  // Deleting or suspending with a handover: the member leaving and the action.
  const [handover, setHandover] = useState<{ member: TenantMember, action: 'remove' | 'suspend' } | null>(null)
  const [transferTo, setTransferTo] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm<CreateTenantMemberInput>()
  const [inviteForm] = Form.useForm<{ email: string }>()

  const errorText = (caught: unknown) => {
    const owned = ownedResourcesOf(caught)
    if (owned && owned.package_subscriptions + owned.l4_forwards + owned.package_sites > 0) {
      return t('ownsPinned', { subscriptions: owned.package_subscriptions, forwards: owned.l4_forwards, sites: owned.package_sites })
    }
    if (owned) return t('ownsTransferable', { count: owned.transferable })
    return caught instanceof ApiError && Object.hasOwn(tenantMembersMessages['zh-CN'].errors, caught.code)
      ? t(`errors.${caught.code}`) : localizedApiError(caught)
  }
  const load = useCallback(async () => {
    if (!accessToken) return
    try {
      const [loadedMembers, loadedInvitations] = await Promise.all([
        tenantMembersApi.list(accessToken), tenantMembersApi.listInvitations(accessToken),
      ])
      setMembers(loadedMembers)
      setInvitations(loadedInvitations)
      setError(null)
    } catch (caught) {
      setError(caught)
    }
  }, [accessToken])
  useEffect(() => { void load() }, [load])

  // run performs one write, reports success and reloads.
  const run = async (write: (token: string) => Promise<unknown>, successKey: string) => {
    if (!accessToken) return false
    setBusy(true)
    try {
      await write(accessToken)
      message.success(t(successKey))
      await load()
      return true
    } catch (caught) {
      setError(caught)
      return false
    } finally {
      setBusy(false)
    }
  }
  const create = async (values: CreateTenantMemberInput) => {
    if (await run(token => tenantMembersApi.create(token, { ...values, email: values.email ?? '' }), 'created')) {
      setCreating(false)
      form.resetFields()
    }
  }
  const invite = async (values: { email: string }) => {
    if (await run(token => tenantMembersApi.invite(token, values.email), 'invited')) {
      setInviting(false)
      inviteForm.resetFields()
    }
  }
  const sendReset = async (member: TenantMember, key: string) => {
    if (!accessToken || resetting) return
    setResetting(true)
    try {
      const result = await tenantMembersApi.resetPassword(accessToken, member.user_id, key)
      setPendingReset(null)
      setTemporaryPassword(result.temporary_password)
      setError(null)
      await load()
    } catch (caught) {
      const unknown = !(caught instanceof ApiError) || caught.status === 0 || caught.status === 408 || caught.status === 429 || caught.status >= 500
      setPendingReset(unknown ? { member, key } : null)
      setError(unknown ? null : caught)
    } finally {
      setResetting(false)
    }
  }
  const resetPassword = (member: TenantMember) => sendReset(member, `member-reset-${crypto.randomUUID()}`)
  const openHandover = (member: TenantMember, action: 'remove' | 'suspend') => {
    setTransferTo(undefined)
    setHandover({ member, action })
  }
  const confirmHandover = async () => {
    if (!handover) return
    const { member, action } = handover
    const done = action === 'remove'
      ? await run(token => tenantMembersApi.remove(token, member.user_id, transferTo), 'removed')
      : await run(token => tenantMembersApi.suspend(token, member.user_id, transferTo), 'suspended')
    if (done) setHandover(null)
  }
  // Members that can receive resources: active, not the one leaving.
  const receivers = (members ?? []).filter(item => item.status === 'active' && item.user_id !== handover?.member.user_id)
  const copyPassword = async () => {
    if (!temporaryPassword) return
    await navigator.clipboard?.writeText(temporaryPassword)
    message.success(t('copied'))
  }
  const formatter = new Intl.DateTimeFormat(i18n.resolvedLanguage ?? 'zh-CN', { dateStyle: 'medium' })
  const timeFormatter = new Intl.DateTimeFormat(i18n.resolvedLanguage ?? 'zh-CN', { dateStyle: 'medium', timeStyle: 'short' })
  const roleLabel = (role: string) => Object.hasOwn(tenantMembersMessages['zh-CN'].roleNames, role) ? t(`roleNames.${role}`) : role

  const memberActions = (member: TenantMember) => {
    if (member.owner || member.user_id === principal?.user_id) return null
    return (
      <Space size={0} wrap>
        {member.status === 'active'
          ? <Button type="link" danger onClick={() => openHandover(member, 'suspend')}>{t('suspend')}</Button>
          : member.status === 'suspended'
            ? <Button type="link" onClick={() => void run(token => tenantMembersApi.resume(token, member.user_id), 'resumed')}>{t('resume')}</Button>
            : null}
        {pendingReset?.member.user_id === member.user_id
          ? <Button type="link" loading={resetting} onClick={() => void sendReset(pendingReset.member, pendingReset.key)}>{t('retrieveReset')}</Button>
          : <Popconfirm title={t('resetConfirm')} okText={t('resetPassword')} cancelText={t('cancel')} onConfirm={() => void resetPassword(member)}>
              <Button type="link" disabled={resetting || pendingReset !== null}>{t('resetPassword')}</Button>
            </Popconfirm>}
        {member.password_change_required
          ? <Button type="link" onClick={() => void run(token => tenantMembersApi.setPasswordChange(token, member.user_id, false), 'passwordChangeReleased')}>
              {t('releasePasswordChange')}
            </Button>
          : <Popconfirm title={t('requirePasswordChangeConfirm')} okText={t('requirePasswordChange')} cancelText={t('cancel')}
              onConfirm={() => void run(token => tenantMembersApi.setPasswordChange(token, member.user_id, true), 'passwordChangeRequired')}>
              <Button type="link">{t('requirePasswordChange')}</Button>
            </Popconfirm>}
        <Button type="link" danger onClick={() => openHandover(member, 'remove')}>{t('remove')}</Button>
      </Space>
    )
  }

  return (
    <PageSection className="page-stack">
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      <Typography.Paragraph>{t('intro')}</Typography.Paragraph>
      <Space wrap>
        <Button type="primary" onClick={() => setCreating(true)}>{t('add')}</Button>
        <Button onClick={() => setInviting(true)}>{t('invite')}</Button>
        {canRoles ? <Link to="/account/custom-roles">{t('roles')}</Link> : null}
      </Space>
      {error ? <FeedbackWhen title={errorText(error)} /> : null}
      {pendingReset ? (
        <FeedbackWhen type="warning" title={t('resetUnknownTitle', { name: pendingReset.member.display_name || pendingReset.member.username })}
          detail={t('resetUnknownHint')}
          action={<Space wrap>
            <Button type="primary" size="small" loading={resetting} onClick={() => void sendReset(pendingReset.member, pendingReset.key)}>{t('retrieveReset')}</Button>
            <Button size="small" disabled={resetting} onClick={() => setPendingReset(null)}>{t('abandonRetrieve')}</Button>
          </Space>} />
      ) : null}
      <Table<TenantMember>
        rowKey="user_id"
        loading={members === null && !error}
        dataSource={members ?? []}
        pagination={false}
        scroll={{ x: 'max-content' }}
        columns={[
          { title: t('username'), dataIndex: 'username', render: (value: string, member) => <Space>{value}{member.owner ? <Tag>{t('owner')}</Tag> : null}</Space> },
          { title: t('displayName'), dataIndex: 'display_name' },
          { title: t('role'), dataIndex: 'role', render: roleLabel },
          {
            title: t('status'), dataIndex: 'status', render: (value: TenantMember['status'], member) => (
              <Space size={4} wrap>
                <Tag color={value === 'active' ? 'green' : 'red'}>{t(`statuses.${value}`)}</Tag>
                {member.password_change_required ? <Tag color="orange">{t('passwordChangePending')}</Tag> : null}
              </Space>
            ),
          },
          { title: t('createdAt'), dataIndex: 'created_at', render: (value: string) => formatter.format(new Date(value)) },
          { title: t('actions'), key: 'actions', render: (_, member) => memberActions(member) },
        ]}
      />
      {invitations.length > 0 ? (
        <>
          <Typography.Title level={4}>{t('invitations')}</Typography.Title>
          <Table<TenantMemberInvitation>
            rowKey="id"
            dataSource={invitations}
            pagination={false}
            scroll={{ x: 'max-content' }}
            columns={[
              { title: t('inviteEmail'), dataIndex: 'email' },
              { title: t('invitationStatus'), dataIndex: 'status', render: (value: TenantMemberInvitation['status']) => <Tag color={value === 'pending' ? 'blue' : value === 'accepted' ? 'green' : 'default'}>{t(`invitationStatuses.${value}`)}</Tag> },
              { title: t('expiresAt'), dataIndex: 'expires_at', render: (value: string) => timeFormatter.format(new Date(value)) },
              {
                title: t('actions'), key: 'actions', render: (_, invitation) => invitation.status === 'pending'
                  ? <Button type="link" onClick={() => void run(token => tenantMembersApi.revokeInvitation(token, invitation.id), 'revoked')}>{t('revoke')}</Button>
                  : null,
              },
            ]}
          />
        </>
      ) : null}
      <Modal open={creating} title={t('add')} okText={t('submit')} cancelText={t('cancel')} confirmLoading={busy}
        onCancel={() => setCreating(false)} onOk={() => form.submit()} destroyOnHidden>
        <Form form={form} layout="vertical" onFinish={values => void create(values)}>
          <Form.Item name="username" label={t('username')} rules={[{ required: true, min: 3, max: 128 }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="display_name" label={t('displayName')} rules={[{ required: true, max: 128 }]}><Input /></Form.Item>
          <Form.Item name="email" label={t('email')} rules={[{ type: 'email' }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="password" label={t('password')} rules={[{ required: true, min: 12, max: 1024 }]}><Input.Password autoComplete="new-password" /></Form.Item>
        </Form>
      </Modal>
      <Modal open={inviting} title={t('inviteTitle')} okText={t('inviteSubmit')} cancelText={t('cancel')} confirmLoading={busy}
        onCancel={() => setInviting(false)} onOk={() => inviteForm.submit()} destroyOnHidden>
        <Typography.Paragraph type="secondary">{t('inviteHint')}</Typography.Paragraph>
        <Form form={inviteForm} layout="vertical" onFinish={values => void invite(values)}>
          <Form.Item name="email" label={t('inviteEmail')} rules={[{ required: true, type: 'email', max: 254 }]}><Input type="email" autoComplete="off" /></Form.Item>
        </Form>
      </Modal>
      <Modal open={handover !== null}
        title={handover?.action === 'remove' ? t('removeTitle', { name: handover.member.username }) : t('suspendTitle', { name: handover?.member.username ?? '' })}
        okText={handover?.action === 'remove' ? t('remove') : t('suspend')} okButtonProps={{ danger: true }} cancelText={t('cancel')} confirmLoading={busy}
        onCancel={() => setHandover(null)} onOk={() => void confirmHandover()} destroyOnHidden>
        <Typography.Paragraph>{handover?.action === 'remove' ? t('removeConfirm') : t('suspendConfirm')}</Typography.Paragraph>
        <Form layout="vertical">
          <Form.Item label={t('transferTo')} extra={t('transferHint')}>
            <Select allowClear aria-label={t('transferTo')} placeholder={t('transferNone')} value={transferTo} onChange={value => setTransferTo(value)}
              options={receivers.map(item => ({ value: item.user_id, label: `${item.display_name} (${item.username})` }))} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal open={temporaryPassword !== null} title={t('resetTitle')} onCancel={() => setTemporaryPassword(null)} destroyOnHidden
        footer={[
          <Button key="copy" onClick={() => void copyPassword()}>{t('copy')}</Button>,
          <Button key="close" type="primary" onClick={() => setTemporaryPassword(null)}>{t('close')}</Button>,
        ]}>
        <Typography.Paragraph>{t('resetHint')}</Typography.Paragraph>
        <Typography.Text code aria-label={t('resetTitle')}>{temporaryPassword}</Typography.Text>
      </Modal>
    </PageSection>
  )
}
