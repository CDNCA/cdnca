import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Form, Input, Modal, Result, Select, Space, Tag, Typography, type InputRef } from 'antd'
import { Table } from '@cdnca/ui'
import type { TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, Plus, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { customRbacApi } from '../api/customRbac'
import { tenantMembersApi } from '../api/tenantMembers'
import { useSessionStore } from '../auth/session'
import { useMfaActive } from '../hooks/useMfaActive'
import { DataState } from '../components/DataState'
import '../i18n/customRolesPage'
import { permissionName } from '../i18n/permissionNames'
import './CustomRolesPage.css'
import { SearchInput } from '../components/SearchInput'

type Owner = readonly ['tenant', string, string, string, number]
type Role = Awaited<ReturnType<typeof customRbacApi.listRoles>>['data'][number]
type Grant = Awaited<ReturnType<typeof customRbacApi.listGrants>>['data'][number]
type Permission = Awaited<ReturnType<typeof customRbacApi.listPermissions>>['data'][number]
type Editor = { kind: 'create' } | { kind: 'rename' | 'publish' | 'deactivate' | 'assign'; role: Role } | { kind: 'revoke'; grant: Grant }
type PendingWrite = { run: () => Promise<void>; successKey: string }

const staleOwner = new Error('custom RBAC owner changed during request')

function ownerFor(principal: Principal, epoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.tenant_id || !principal.scope_id || !principal.user_id || epoch < 1 ||
    !principal.permissions.includes('identity.roles.manage')) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, epoch]
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 403 || error.code === 'custom_rbac_permission_denied')
}

function isUnknown(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 0 || error.code === 'network_error' || error.code === 'custom_rbac_write_unknown')
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.load'
  switch (error.code) {
    case 'custom_rbac_revision_conflict': return 'errors.revisionConflict'
    case 'custom_rbac_step_up_required': return 'errors.stepUpRequired'
    case 'custom_rbac_permission_not_delegable': return 'errors.permissionNotDelegable'
    case 'custom_rbac_store_unavailable': return 'errors.serviceUnavailable'
    case 'custom_rbac_name_conflict': return 'errors.nameConflict'
    case 'custom_rbac_role_inactive': return 'errors.roleInactive'
    case 'custom_rbac_self_assignment_denied': return 'errors.selfAssignment'
    case 'custom_rbac_validation_error': return 'errors.validation'
    default: return error.status === 503 ? 'errors.serviceUnavailable' : 'errors.load'
  }
}

// the role editor lists the delegable
// permissions by domain (first segment of the code); unknown domains go to "other".
const permissionGroups: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['sites', ['sites', 'site_capture', 'site_protocols', 'certificates', 'challenge_policies', 'error_pages', 'http_policies',
    'origin_auth', 'url_auth_policies', 'security_policies', 'openresty_security', 'waf_adapt', 'firewall', 'streams', 'edge', 'edge_publications']],
  ['dns', ['dns', 'domains']],
  ['billing', ['billing', 'billing_bridge', 'packages', 'package_subscriptions', 'traffic_packages', 'tcp_billing', 'promotions', 'reseller']],
  ['identity', ['identity', 'identity_verification', 'api_keys', 'approvals', 'jobs']],
  ['messages', ['announcements', 'tickets']],
  ['plugins', ['marketplace', 'plugin_installations', 'plugin_webhooks', 'probes', 'tenant_theme']],
]

function permissionGroup(code: string): string {
  const domain = code.split('.')[0]
  return permissionGroups.find(([, domains]) => domains.includes(domain))?.[0] ?? 'other'
}

// The name only; the explanation some names carry after "：" is not repeated on this page.
function shortPermissionName(code: string): string {
  return permissionName(code).split('：')[0]
}

function PermissionPicker({ permissions, value, onChange, errorId }: {
  permissions: Permission[]
  value: string[]
  onChange: (value: string[]) => void
  /** Set while 至少选择一项权限 shows: the picker is described by that error. */
  errorId?: string
}) {
  const { t } = useTranslation('customRolesPage')
  const [search, setSearch] = useState('')
  const keyword = search.trim().toLowerCase()
  const groups = [...permissionGroups.map(([group]) => group), 'other'].map((group) => ({
    group,
    items: permissions.filter((permission) => permissionGroup(permission.name) === group && (!keyword ||
      permission.name.toLowerCase().includes(keyword) || shortPermissionName(permission.name).toLowerCase().includes(keyword))),
  })).filter((entry) => entry.items.length > 0)
  const toggle = (code: string, checked: boolean) =>
    onChange(checked ? [...value.filter((item) => item !== code), code] : value.filter((item) => item !== code))
  return <Space direction="vertical" style={{ width: '100%' }} role="group" aria-label={t('fields.permissions')}
    aria-invalid={errorId ? true : undefined} aria-describedby={errorId} className="custom-roles-permission-picker">
    <SearchInput allowClear aria-label={t('fields.permissionSearch')} placeholder={t('fields.permissionSearchPlaceholder')}
      value={search} onChange={(event) => setSearch(event.target.value)} />
    <Typography.Text type="secondary">{t('values.selectedCount', { count: value.length })}</Typography.Text>
    <div className="custom-roles-permission-list cdnca-dialog-scroll">
      {groups.length === 0
        ? <Typography.Text type="secondary">{t(permissions.length === 0 ? 'data.emptyPermissions' : 'data.noPermissionMatch')}</Typography.Text>
        : groups.map(({ group, items }) => <div key={group} role="group" aria-label={t(`groups.${group}`)}>
          <Typography.Text strong>{t(`groups.${group}`)}</Typography.Text>
          <Space direction="vertical" size={2} style={{ display: 'flex', margin: '4px 0 12px' }}>
            {items.map((permission) => {
              const checked = value.includes(permission.name)
              return <Checkbox key={permission.name} checked={checked} onChange={(event) => toggle(permission.name, event.target.checked)}>
                <Space size={4}>
                  <span title={permission.name}>{shortPermissionName(permission.name)}</span>
                  {checked && permission.step_up_required ? <Tag color="warning">{t('values.stepUp')}</Tag> : null}
                </Space>
              </Checkbox>
            })}
          </Space>
        </div>)}
    </div>
  </Space>
}

function randomHex(bytes: number): string {
  const value = new Uint8Array(bytes)
  crypto.getRandomValues(value)
  return [...value].map((item) => item.toString(16).padStart(2, '0')).join('')
}

function writeMetadata(kind: string, stepUpProof: string) {
  const suffix = randomHex(12)
  return {
    idempotencyKey: `custom-rbac-${kind}-${suffix}`,
    requestId: `custom-rbac-${kind}-request-${suffix}`,
    traceparent: `00-${randomHex(16)}-${randomHex(8)}-01`,
    ...(stepUpProof ? { stepUpProof } : {}),
  }
}

export default function CustomRolesPage() {
  const { t } = useTranslation('customRolesPage')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, epoch)
  if (!owner) return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  const ownerKey = JSON.stringify(owner)
  return <CustomRolesContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}

function CustomRolesContent({ owner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t } = useTranslation('customRolesPage')
  const queryClient = useQueryClient()
  const ownerRef = useRef(owner).current
  const prefix = useMemo(() => ['custom-rbac', ...ownerRef] as const, [ownerRef])
  const [includeDeactivated, setIncludeDeactivated] = useState(false)
  const [roleCursor, setRoleCursor] = useState<string>()
  const [roleHistory, setRoleHistory] = useState<Array<string | undefined>>([])
  const [grantCursor, setGrantCursor] = useState<string>()
  const [grantHistory, setGrantHistory] = useState<Array<string | undefined>>([])
  const [editor, setEditor] = useState<Editor>()
  const [name, setName] = useState('')
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([])
  const [subjectUserID, setSubjectUserID] = useState('')
  const [stepUpProof, setStepUpProof] = useState('')
  // 未启用 MFA：不显示二次验证凭据输入。
  const requireMfaCode = useMfaActive() !== false
  const [formError, setFormError] = useState<string>()
  // 空名称、未选权限、未选用户各自标在字段上并关联，聚焦首个错误。
  type FieldError = 'name' | 'permissions' | 'subject'
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<FieldError, string>>>({})
  const nameInput = useRef<InputRef>(null)
  const subjectInput = useRef<{ focus: () => void } | null>(null)
  const editorBody = useRef<HTMLDivElement>(null)
  const markFields = (errors: Partial<Record<FieldError, string>>) => {
    setFieldErrors(errors)
    if (errors.name) nameInput.current?.focus()
    else if (errors.permissions) (editorBody.current?.querySelector<HTMLInputElement>('.custom-roles-permission-list input[type="checkbox"]')
      ?? editorBody.current?.querySelector<HTMLInputElement>('.custom-roles-permission-picker input'))?.focus()
    else if (errors.subject) subjectInput.current?.focus()
  }
  // 旧页上角色刚被停用，写入被 409 拒绝时关窗、提示并刷新
  const [roleInactiveNotice, setRoleInactiveNotice] = useState(false)
  const [pendingWrite, setPendingWrite] = useState<PendingWrite>()
  const [writing, setWriting] = useState(false)
  const active = useRef(true)

  const guardedRead = async <T,>(read: (token: string) => Promise<T>) => {
    const token = active.current ? currentAccess(ownerKey) : null
    if (!token) throw staleOwner
    const value = await read(token)
    if (!active.current || !currentAccess(ownerKey)) throw staleOwner
    return value
  }
  const permissionsQuery = useQuery({
    queryKey: [...prefix, 'permissions'], queryFn: () => guardedRead((token) => customRbacApi.listPermissions(token)), retry: false,
  })
  const rolesQuery = useQuery({
    queryKey: [...prefix, 'roles', includeDeactivated, roleCursor ?? null],
    queryFn: () => guardedRead((token) => customRbacApi.listRoles(token, {
      limit: 20, ...(roleCursor ? { cursor: roleCursor } : {}), includeDeactivated,
    })), retry: false,
  })
  // Members to assign a role to (GET /v1/tenant/members accepts identity.roles.manage).
  const membersQuery = useQuery({
    queryKey: [...prefix, 'members'], queryFn: () => guardedRead((token) => tenantMembersApi.list(token)), retry: false,
  })
  const grantsQuery = useQuery({
    queryKey: [...prefix, 'grants', grantCursor ?? null],
    queryFn: () => guardedRead((token) => customRbacApi.listGrants(token, {
      limit: 20, ...(grantCursor ? { cursor: grantCursor } : {}), state: 'active',
    })), retry: false,
  })

  useEffect(() => () => {
    active.current = false
    queryClient.removeQueries({ queryKey: prefix })
  }, [prefix, queryClient])

  const resetForm = () => {
    setName('')
    setSelectedPermissions([])
    setSubjectUserID('')
    setStepUpProof('')
    setFormError(undefined)
    setFieldErrors({})
  }
  const closeEditor = () => { setEditor(undefined); resetForm() }
  const openEditor = (next: Editor) => {
    resetForm()
    if (next.kind === 'rename') setName(next.role.name)
    if (next.kind === 'publish') setSelectedPermissions([...next.role.permissions])
    setEditor(next)
  }
  const refresh = async () => {
    await Promise.all([permissionsQuery.refetch(), rolesQuery.refetch(), grantsQuery.refetch()])
  }
  const execute = async (operation: PendingWrite) => {
    setWriting(true)
    setFormError(undefined)
    try {
      await operation.run()
      setPendingWrite(undefined)
      closeEditor()
      await refresh()
    } catch (error) {
      if (isUnknown(error)) {
        setPendingWrite(operation)
        closeEditor()
      } else if (error instanceof ApiError && error.code === 'custom_rbac_role_inactive') {
        closeEditor()
        setRoleInactiveNotice(true)
        void refresh()
      } else setFormError(errorKey(error))
    } finally {
      setWriting(false)
    }
  }
  const save = () => {
    if (!editor) return
    if (!currentAccess(ownerKey)) return
    const writeToken = () => {
      const token = currentAccess(ownerKey)
      if (!token) throw staleOwner
      return token
    }
    const proof = requireMfaCode ? stepUpProof.trim() : ''
    let operation: PendingWrite
    if (editor.kind === 'create') {
      if (!name.trim() || selectedPermissions.length === 0) {
        markFields({ name: name.trim() ? undefined : t('errors.nameRequired'), permissions: selectedPermissions.length ? undefined : t('errors.permissionsRequired') })
        return
      }
      const input = { name: name.trim(), permissions: [...selectedPermissions].sort() }
      const metadata = writeMetadata('create', proof)
      operation = { successKey: 'notices.saved', run: async () => { await customRbacApi.createRole(writeToken(), input, metadata) } }
    } else if (editor.kind === 'rename') {
      if (!name.trim()) { markFields({ name: t('errors.nameRequired') }); return }
      const input = { name: name.trim() }
      const metadata = writeMetadata('rename', proof)
      operation = { successKey: 'notices.saved', run: async () => { await customRbacApi.renameRole(writeToken(), editor.role.id, editor.role.current_revision, input, metadata) } }
    } else if (editor.kind === 'publish') {
      if (selectedPermissions.length === 0) { markFields({ permissions: t('errors.permissionsRequired') }); return }
      const input = { permissions: [...selectedPermissions].sort() }
      const metadata = writeMetadata('publish', proof)
      operation = { successKey: 'notices.published', run: async () => { await customRbacApi.publishRole(writeToken(), editor.role.id, editor.role.current_revision, input, metadata) } }
    } else if (editor.kind === 'deactivate') {
      const metadata = writeMetadata('deactivate', proof)
      operation = { successKey: 'notices.deactivated', run: async () => { await customRbacApi.deactivateRole(writeToken(), editor.role.id, editor.role.current_revision, metadata) } }
    } else if (editor.kind === 'assign') {
      if (!subjectUserID.trim()) { markFields({ subject: t('errors.subjectRequired') }); return }
      const input = { role_id: editor.role.id, subject_user_id: subjectUserID.trim() }
      const metadata = writeMetadata('assign', proof)
      operation = { successKey: 'notices.assigned', run: async () => { await customRbacApi.assignGrant(writeToken(), editor.role.current_revision, input, metadata) } }
    } else if ('grant' in editor) {
      const metadata = writeMetadata('revoke', proof)
      const grantID = editor.grant.id
      operation = { successKey: 'notices.revoked', run: async () => { await customRbacApi.revokeGrant(writeToken(), grantID, metadata) } }
    } else return
    setStepUpProof('')
    void execute(operation)
  }

  const permissions = permissionsQuery.data?.data ?? []
  const roles = rolesQuery.data?.data ?? []
  const grants = grantsQuery.data?.data ?? []
  const roleColumns: TableColumnsType<Role> = [
    { title: t('fields.name'), dataIndex: 'name' },
    { title: t('fields.permissions'), dataIndex: 'permissions', render: (value: string[]) => <Space wrap>{value.map((item) => <Tag key={item} title={item}>{shortPermissionName(item)}</Tag>)}</Space> },
    { title: t('fields.status'), key: 'status', width: 110, render: (_, row) => <Tag color={row.deactivated_at ? 'default' : 'success'}>{t(row.deactivated_at ? 'statuses.deactivated' : 'statuses.active')}</Tag> },
    // 已停用角色的改名、发布、分配、停用都会被服务端拒绝（custom_rbac_role_inactive），不显示这组写入口；停用状态与历史授权照常可读
    { title: t('fields.actions'), key: 'actions', width: 360, render: (_, row) => row.deactivated_at ? null : <Space size={4} wrap>
      <Button size="small" onClick={() => openEditor({ kind: 'rename', role: row })}>{t('actions.rename')}</Button>
      <Button size="small" onClick={() => openEditor({ kind: 'publish', role: row })}>{t('actions.publish')}</Button>
      <Button size="small" onClick={() => openEditor({ kind: 'assign', role: row })}>{t('actions.assign')}</Button>
      <Button danger size="small" onClick={() => openEditor({ kind: 'deactivate', role: row })}>{t('actions.deactivate')}</Button>
    </Space> },
  ]
  const members = membersQuery.data ?? []
  const memberLabel = (member: { username: string; display_name: string }) =>
    member.display_name && member.display_name !== member.username ? `${member.display_name}（${member.username}）` : member.username
  const memberName = (id: string) => {
    const member = members.find((item) => item.user_id === id)
    return member ? memberLabel(member) : id
  }
  const roleName = (id: string) => roles.find((item) => item.id === id)?.name ?? id
  const grantColumns: TableColumnsType<Grant> = [
    { title: t('fields.role'), dataIndex: 'role_id', width: 270, render: (value: string) => <span title={value}>{roleName(value)}</span> },
    { title: t('fields.subjectUser'), dataIndex: 'subject_user_id', width: 270, render: (value: string) => <span title={value}>{memberName(value)}</span> },
    { title: t('fields.status'), key: 'state', width: 100, render: (_, row) => t(row.revoked_at ? 'statuses.revoked' : 'statuses.active') },
    { title: t('fields.actions'), key: 'actions', width: 130, render: (_, row) => row.revoked_at ? null : <Button danger size="small" onClick={() => openEditor({ kind: 'revoke', grant: row })}>{t('actions.revoke')}</Button> },
  ]
  // 没有上一页也没有下一页时不显示分页区。
  const pageControls = (kind: 'roles' | 'grants', history: Array<string | undefined>, next: string | undefined, previous: () => void, forward: () => void) => history.length === 0 && !next ? null : (
    <Space role="group" aria-label={t(`pagination.${kind}`)}>
      <Button aria-label={t('actions.previous')} disabled={history.length === 0} icon={<ChevronLeft size={14} />} onClick={previous} />
      <Button aria-label={t('actions.next')} disabled={!next} icon={<ChevronRight size={14} />} onClick={forward} />
    </Space>
  )

  if ([permissionsQuery.error, rolesQuery.error, grantsQuery.error].some(isForbidden)) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  const loading = permissionsQuery.isPending || rolesQuery.isPending || grantsQuery.isPending
  const readError = permissionsQuery.error ?? rolesQuery.error ?? grantsQuery.error
  const editorTitle = editor ? t(`dialogs.${editor.kind}Title`) : ''

  return <section className="identity-page" aria-labelledby="custom-roles-title">
    <header className="identity-page-header"><div><Typography.Title level={2} id="custom-roles-title">{t('title')}</Typography.Title></div><Space><Button type="primary" icon={<Plus size={16} />} onClick={() => openEditor({ kind: 'create' })}>{t('actions.create')}</Button><Button icon={<RefreshCw size={16} />} onClick={() => void refresh()}>{t('actions.refresh')}</Button></Space></header>
    {loading ? <DataState status="loading" message={t('data.loadingRoles')} /> : readError ? <DataState status="error" message={t(errorKey(readError))} onRetry={() => void refresh()} /> : <>
      <Typography.Title level={3}>{t('sections.roles')}</Typography.Title>
      {roleInactiveNotice ? <Alert type="warning" showIcon closable role="alert" message={t('errors.roleInactive')} onClose={() => setRoleInactiveNotice(false)} /> : null}
      <Checkbox checked={includeDeactivated} onChange={(event) => { setIncludeDeactivated(event.target.checked); setRoleCursor(undefined); setRoleHistory([]) }}>{t('fields.includeDeactivated')}</Checkbox>
      <Table rowKey="id" size="small" columns={roleColumns} dataSource={roles} pagination={false} scroll={{ x: 1050 }} locale={{ emptyText: t('data.emptyRoles') }} />
      {pageControls('roles', roleHistory, rolesQuery.data?.page.next_cursor, () => { setRoleCursor(roleHistory.at(-1)); setRoleHistory((value) => value.slice(0, -1)) }, () => { const next = rolesQuery.data?.page.next_cursor; if (next) { setRoleHistory((value) => [...value, roleCursor]); setRoleCursor(next) } })}
      <Typography.Title level={3}>{t('sections.grants')}</Typography.Title>
      <Table rowKey="id" size="small" columns={grantColumns} dataSource={grants} pagination={false} scroll={{ x: 900 }} locale={{ emptyText: t('data.emptyGrants') }} />
      {pageControls('grants', grantHistory, grantsQuery.data?.page.next_cursor, () => { setGrantCursor(grantHistory.at(-1)); setGrantHistory((value) => value.slice(0, -1)) }, () => { const next = grantsQuery.data?.page.next_cursor; if (next) { setGrantHistory((value) => [...value, grantCursor]); setGrantCursor(next) } })}
    </>}
    <Modal open={Boolean(editor)} title={editorTitle} destroyOnHidden onCancel={closeEditor} footer={<Space><Button onClick={closeEditor}>{t('actions.cancel')}</Button><Button type="primary" loading={writing} onClick={save}>{t(editor?.kind === 'publish' ? 'actions.publishConfirm' : editor?.kind === 'deactivate' ? 'actions.deactivateConfirm' : editor?.kind === 'assign' ? 'actions.assignConfirm' : editor?.kind === 'revoke' ? 'actions.revokeConfirm' : 'actions.save')}</Button></Space>}>
      <div ref={editorBody}><Form layout="vertical">
        {editor?.kind === 'create' || editor?.kind === 'rename' ? <Form.Item label={t('fields.name')} validateStatus={fieldErrors.name ? 'error' : undefined}
          help={fieldErrors.name ? <span id="custom-role-name-error">{fieldErrors.name}</span> : undefined}>
          <Input ref={nameInput} aria-label={t('fields.name')} value={name} aria-invalid={fieldErrors.name ? true : undefined}
            aria-describedby={fieldErrors.name ? 'custom-role-name-error' : undefined}
            onChange={(event) => { setName(event.target.value); setFieldErrors((current) => ({ ...current, name: undefined })) }} /></Form.Item> : null}
        {editor?.kind === 'create' || editor?.kind === 'publish' ? <Form.Item label={t('fields.permissions')} validateStatus={fieldErrors.permissions ? 'error' : undefined}
          help={fieldErrors.permissions ? <span id="custom-role-permissions-error">{fieldErrors.permissions}</span> : undefined}>
          <PermissionPicker permissions={permissions} value={selectedPermissions} errorId={fieldErrors.permissions ? 'custom-role-permissions-error' : undefined}
            onChange={(next) => { setSelectedPermissions(next); setFieldErrors((current) => ({ ...current, permissions: undefined })) }} /></Form.Item> : null}
        {editor?.kind === 'assign' ? (
          membersQuery.isError
            // Without the member list, fall back to the user ID.
            ? <Form.Item label={t('fields.subjectUserId')} validateStatus={fieldErrors.subject ? 'error' : undefined}
              help={fieldErrors.subject ? <span id="custom-role-subject-error">{fieldErrors.subject}</span> : undefined}>
              <Input aria-label={t('fields.subjectUserId')} value={subjectUserID} aria-invalid={fieldErrors.subject ? true : undefined}
                aria-describedby={fieldErrors.subject ? 'custom-role-subject-error' : undefined}
                ref={(element) => { subjectInput.current = element }}
                onChange={(event) => { setSubjectUserID(event.target.value); setFieldErrors((current) => ({ ...current, subject: undefined })) }} /></Form.Item>
            : <Form.Item label={t('fields.subjectUser')} validateStatus={fieldErrors.subject ? 'error' : undefined}
              help={fieldErrors.subject ? <span id="custom-role-subject-error">{fieldErrors.subject}</span> : undefined}>
              <Select ref={(element) => { subjectInput.current = element }} aria-label={t('fields.subjectUser')} showSearch optionFilterProp="label" virtual={false}
                aria-invalid={fieldErrors.subject ? true : undefined} aria-describedby={fieldErrors.subject ? 'custom-role-subject-error' : undefined}
                placeholder={t('fields.subjectUserPlaceholder')} loading={membersQuery.isFetching}
                value={subjectUserID || undefined} onChange={(value: string) => { setSubjectUserID(value); setFieldErrors((current) => ({ ...current, subject: undefined })) }}
                options={members.filter((member) => member.status === 'active').map((member) => ({
                  value: member.user_id, label: `${memberLabel(member)}${member.email ? ` · ${member.email}` : ''}`,
                }))} />
            </Form.Item>
        ) : null}
        {editor && requireMfaCode ? <Form.Item label={t('fields.stepUpProof')}><Input.Password autoComplete="off" aria-label={t('fields.stepUpProof')} value={stepUpProof} onChange={(event) => setStepUpProof(event.target.value)} /></Form.Item> : null}
        {formError ? <Alert type="error" showIcon message={t(formError)} /> : null}
      </Form></div>
    </Modal>
    <Modal open={Boolean(pendingWrite)} title={t('dialogs.unknownTitle')} closable={false} footer={<Space><Button onClick={() => { setPendingWrite(undefined); void refresh() }}>{t('actions.abandon')}</Button><Button type="primary" loading={writing} onClick={() => { if (pendingWrite) void execute(pendingWrite) }}>{t('actions.exactRetry')}</Button></Space>}><Typography.Paragraph>{t('dialogs.unknownDescription')}</Typography.Paragraph></Modal>
  </section>
}
