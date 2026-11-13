import { fireEvent, screen, waitFor, within } from '@testing-library/react'

import { useQueryClient } from '@tanstack/react-query'

import * as session from '../auth/session'
import { runtimeFeaturesQueryKey } from '../components/useRuntimeFeatures'
import MemberInvitationAcceptPage from '../pages/MemberInvitationAcceptPage'
import TenantMembersPage from '../pages/TenantMembersPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { memberInvitationAcceptMessages, tenantMembersMessages } from '../i18n/tenantMembers'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const noContent = () => new Response(null, { status: 204 })
const owner = { user_id: '11111111-1111-4111-8111-111111111111', username: 'boss', display_name: 'Boss', email: null, status: 'active', role: 'tenant_owner', owner: true, created_at: '2026-10-01T00:00:00Z', password_change_required: false }
const alice = { user_id: '22222222-2222-4222-8222-222222222222', username: 'alice', display_name: 'Alice', email: null, status: 'active', role: 'tenant_viewer', owner: false, created_at: '2026-10-02T00:00:00Z', password_change_required: false }
const invitation = { id: '33333333-3333-4333-8333-333333333333', email: 'new@example.com', status: 'pending', created_at: '2026-10-03T00:00:00Z', expires_at: '2026-10-06T00:00:00Z' }
const none = { items: [] }

function renderPage() {
  const actor = principal({ user_id: owner.user_id, permissions: ['identity.self.read', 'identity.roles.manage'] })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(<TenantMembersPage />, ['/account/members'])
}

async function confirmPopover(name: string) {
  const confirm = await screen.findByRole('tooltip')
  fireEvent.click(within(confirm).getByRole('button', { name }))
}

it('lists members, creates a sub-account and suspends a member', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json(alice, 201))
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json({ ...alice, status: 'suspended' }))
    .mockResolvedValueOnce(json({ items: [owner, { ...alice, status: 'suspended' }] })).mockResolvedValueOnce(json(none))
  renderPage()
  expect(await screen.findByText('boss')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: '自定义角色与授权' })).toHaveAttribute('href', '/account/custom-roles')
  fireEvent.click(screen.getByRole('button', { name: '新建子账号' }))
  const dialog = await screen.findByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('用户名'), { target: { value: 'alice' } })
  fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: 'Alice' } })
  fireEvent.change(within(dialog).getByLabelText('初始密码（至少 12 位）'), { target: { value: 'a long enough password' } })
  fireEvent.click(within(dialog).getByRole('button', { name: '创建' }))
  await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(5))
  expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({ username: 'alice', display_name: 'Alice', email: '', password: 'a long enough password' })
  expect(await screen.findByText('alice')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '停用' }))
  const suspendDialog = await screen.findByRole('dialog', { name: '停用成员 alice' })
  fireEvent.click(within(suspendDialog).getByRole('button', { name: '停用' }))
  await waitFor(() => expect(String(fetchSpy.mock.calls[5]?.[0])).toMatch(/\/v1\/tenant\/members\/22222222-2222-4222-8222-222222222222\/suspend$/))
  expect(await screen.findByText('已停用', { selector: '.ant-tag' })).toBeInTheDocument()
})

it('resets a password shown once, explains a refusal and deletes with a handover', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json({ user_id: alice.user_id, temporary_password: 'Temp-Password-Once-123456', password_change_required: true, replayed: false, result_expires_at: '2099-01-01T00:10:00Z' }))
    .mockResolvedValueOnce(json({ items: [owner, { ...alice, password_change_required: true }] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json({ error: { code: 'tenant_member_owns_resources', message: 'x', request_id: 'r',
      resources: { package_subscriptions: 0, l4_forwards: 0, package_sites: 0, transferable: 3 } } }, 409))
    .mockResolvedValueOnce(noContent())
    .mockResolvedValueOnce(json({ items: [owner] })).mockResolvedValueOnce(json(none))
  renderPage()
  expect(await screen.findByText('alice')).toBeInTheDocument()
  // The owner row has no actions.
  expect(screen.getAllByRole('button', { name: '重置密码' })).toHaveLength(1)

  fireEvent.click(screen.getByRole('button', { name: '重置密码' }))
  await confirmPopover('重置密码')
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('新密码（只显示这一次）')).toBeInTheDocument()
  expect(within(dialog).getByText('Temp-Password-Once-123456')).toBeInTheDocument()
  expect(String(fetchSpy.mock.calls[2][0])).toMatch(/\/v1\/tenant\/members\/22222222-2222-4222-8222-222222222222\/password-reset$/)
  expect(new Headers(fetchSpy.mock.calls[2][1]?.headers).get('Idempotency-Key')).toMatch(/^member-reset-/)
  fireEvent.click(within(dialog).getByRole('button', { name: '关闭' }))
  await waitFor(() => expect(screen.queryByText('Temp-Password-Once-123456')).not.toBeInTheDocument())

  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  // Without a receiving member the refusal says how much would move.
  fireEvent.click(screen.getByRole('button', { name: '删除' }))
  // The reset dialog left antd's shared title id behind, so match by text.
  let removeDialog = await screen.findByRole('dialog')
  expect(within(removeDialog).getByText('删除子账号 alice')).toBeInTheDocument()
  fireEvent.click(within(removeDialog).getByRole('button', { name: '删除' }))
  // The refusal opens as a feedback dialog over the still-open delete dialog.
  const refusal = (await screen.findByText('该成员名下还有 3 项网站、证书或规则，请选择接收的成员后再操作。')).closest('.cdnca-feedback') as HTMLElement
  expect(refusal).not.toBeNull()
  expect(String(fetchSpy.mock.calls[5][0])).toMatch(/\/v1\/tenant\/members\/22222222-2222-4222-8222-222222222222$/)
  fireEvent.click(within(refusal).getByRole('button', { name: '知道了' }))
  // Choose the owner as the receiver.
  removeDialog = screen.getByText('删除子账号 alice').closest('[role="dialog"]') as HTMLElement
  fireEvent.mouseDown(within(removeDialog).getByRole('combobox', { name: '名下资源转给' }))
  fireEvent.click(await screen.findByText('Boss (boss)', { selector: '.ant-select-item-option-content' }))
  fireEvent.click(within(removeDialog).getByRole('button', { name: '删除' }))
  await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(9))
  expect(fetchSpy.mock.calls[6][1]?.method).toBe('DELETE')
  expect(String(fetchSpy.mock.calls[6][0])).toMatch(/\/v1\/tenant\/members\/22222222-2222-4222-8222-222222222222\?transfer_to=11111111-1111-4111-8111-111111111111$/)
  await waitFor(() => expect(screen.queryByText('alice')).not.toBeInTheDocument())
})

it('explains resources that cannot move', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json({ error: { code: 'tenant_member_owns_resources', message: 'x', request_id: 'r',
      resources: { package_subscriptions: 1, l4_forwards: 2, package_sites: 0, transferable: 0 } } }, 409))
  renderPage()
  fireEvent.click(await screen.findByRole('button', { name: '删除' }))
  const removeDialog = await screen.findByRole('dialog', { name: '删除子账号 alice' })
  fireEvent.click(within(removeDialog).getByRole('button', { name: '删除' }))
  expect(await screen.findByText('该成员名下有 1 个有效套餐、2 个四层转发、0 个绑定套餐或 CNAME 的网站，这些无法转移，请先删除或等待到期。')).toBeInTheDocument()
})

it('requires and withdraws a password change at the next sign-in', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json({ ...alice, password_change_required: true }))
    .mockResolvedValueOnce(json({ items: [owner, { ...alice, password_change_required: true }] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json(alice))
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
  renderPage()
  fireEvent.click(await screen.findByRole('button', { name: '要求改密' }))
  await confirmPopover('要求改密')
  expect(await screen.findByText('待改密', { selector: '.ant-tag' })).toBeInTheDocument()
  expect(fetchSpy.mock.calls[2][1]?.method).toBe('PUT')
  expect(String(fetchSpy.mock.calls[2][0])).toMatch(/\/v1\/tenant\/members\/22222222-2222-4222-8222-222222222222\/password-change$/)
  expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({ required: true })
  fireEvent.click(screen.getByRole('button', { name: '取消改密要求' }))
  await waitFor(() => expect(screen.queryByText('待改密', { selector: '.ant-tag' })).not.toBeInTheDocument())
  expect(JSON.parse(String(fetchSpy.mock.calls[5][1]?.body))).toEqual({ required: false })
})

it('invites by email and withdraws a pending invitation', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json(invitation, 201))
    .mockResolvedValueOnce(json({ items: [owner] })).mockResolvedValueOnce(json({ items: [invitation] }))
    .mockResolvedValueOnce(noContent())
    .mockResolvedValueOnce(json({ items: [owner] })).mockResolvedValueOnce(json({ items: [{ ...invitation, status: 'revoked' }] }))
  renderPage()
  expect(await screen.findByText('boss')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '邮件邀请' }))
  const dialog = await screen.findByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('被邀请人邮箱'), { target: { value: 'new@example.com' } })
  fireEvent.click(within(dialog).getByRole('button', { name: '发送邀请' }))
  await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(5))
  expect(String(fetchSpy.mock.calls[2][0])).toMatch(/\/v1\/tenant\/member-invitations$/)
  expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({ email: 'new@example.com' })
  expect(await screen.findByText('待接受')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '撤回' }))
  await waitFor(() => expect(String(fetchSpy.mock.calls[5]?.[0])).toMatch(/\/v1\/tenant\/member-invitations\/33333333-3333-4333-8333-333333333333\/revoke$/))
  expect(await screen.findByText('已撤回')).toBeInTheDocument()
})

it('accepts an invitation anonymously with the token from the link fragment', async () => {
  const token = 'A'.repeat(43)
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ error: { code: 'tenant_member_invitation_invalid', message: 'x' } }, 410))
    .mockResolvedValueOnce(json({ ...alice, username: 'newbie' }, 201))
  renderWithProviders(<MemberInvitationAcceptPage />, [`/accept-invitation#token=${token}`])
  fireEvent.change(await screen.findByLabelText('用户名'), { target: { value: 'newbie' } })
  fireEvent.change(screen.getByLabelText('名称'), { target: { value: 'Newbie' } })
  fireEvent.change(screen.getByLabelText('密码（至少 12 位）'), { target: { value: 'a long enough password' } })
  fireEvent.click(screen.getByRole('button', { name: '创建账号' }))
  expect(await screen.findByText(memberInvitationAcceptMessages['zh-CN'].errors.tenant_member_invitation_invalid)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '创建账号' }))
  expect(await screen.findByText('账号已创建，请使用新账号登录。')).toBeInTheDocument()
  const [url, init] = fetchSpy.mock.calls[1]
  expect(String(url)).toMatch(/\/v1\/auth\/member-invitations\/accept$/)
  expect(new Headers(init?.headers).has('Authorization')).toBe(false)
  expect(JSON.parse(String(init?.body))).toEqual({ token, username: 'newbie', display_name: 'Newbie', password: 'a long enough password' })
})

it('asks to reopen the mail when the link has no token', async () => {
  renderWithProviders(<MemberInvitationAcceptPage />, ['/accept-invitation'])
  expect(await screen.findByText('邀请链接不完整，请从邀请邮件中重新打开。')).toBeInTheDocument()
})

it('ships the same keys in zh-CN, en-US and qps-ploc', () => {
  const flatten = (value: unknown, prefix = ''): string[] => typeof value === 'string' ? [prefix]
    : Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => flatten(child, prefix ? `${prefix}.${key}` : key))
  for (const messages of [tenantMembersMessages, memberInvitationAcceptMessages]) {
    const keys = flatten(messages['zh-CN']).sort()
    expect(flatten(messages['en-US']).sort()).toEqual(keys)
    expect(flatten(messages['qps-ploc']).sort()).toEqual(keys)
  }
})

// TENANT-PWRESET-UNKNOWN: a lost reset response is retrieved with the same
// Idempotency-Key, never sent as a second reset.
it('retrieves a reset whose response was lost with the same key instead of resetting again', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
    .mockRejectedValueOnce(new TypeError('network down'))
    .mockResolvedValueOnce(json({ user_id: alice.user_id, temporary_password: 'Retrieved-Password-12345', password_change_required: true, replayed: true, result_expires_at: '2099-01-01T00:10:00Z' }))
    .mockResolvedValueOnce(json({ items: [owner, { ...alice, password_change_required: true }] })).mockResolvedValueOnce(json(none))
  renderPage()
  expect(await screen.findByText('alice')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '重置密码' }))
  await confirmPopover('重置密码')
  // Outcome unknown: the row offers retrieval, not another reset.
  const notice = (await screen.findByText('没有收到「Alice」的重置结果')).closest('.cdnca-feedback') as HTMLElement
  expect(within(notice).getByText(/不要再次重置/)).toBeInTheDocument()
  fireEvent.click(within(notice).getByRole('button', { name: '知道了' }))
  expect(screen.queryByRole('button', { name: '重置密码' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '取回结果' }))
  const dialog = await screen.findByRole('dialog', { name: '新密码（只显示这一次）' })
  expect(within(dialog).getByText('Retrieved-Password-12345')).toBeInTheDocument()
  const firstKey = new Headers(fetchSpy.mock.calls[2][1]?.headers).get('Idempotency-Key')
  expect(firstKey).toMatch(/^member-reset-/)
  expect(new Headers(fetchSpy.mock.calls[3][1]?.headers).get('Idempotency-Key')).toBe(firstKey)
  expect(String(fetchSpy.mock.calls[3][0])).toMatch(/\/password-reset$/)
  fireEvent.click(within(dialog).getByRole('button', { name: '关闭' }))
  // Back to a normal row: the next reset is a new operation.
  expect(await screen.findByRole('button', { name: '重置密码' })).toBeInTheDocument()
})

it('explains an already retrieved result without resetting again', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ items: [owner, alice] })).mockResolvedValueOnce(json(none))
    .mockResolvedValueOnce(json({ error: { code: 'tenant_member_password_reset_result_gone', message: 'x', request_id: 'r' } }, 410))
  renderPage()
  expect(await screen.findByText('alice')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '重置密码' }))
  await confirmPopover('重置密码')
  expect(await screen.findByText(/重置结果已取回过或已超过 10 分钟/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '取回结果' })).not.toBeInTheDocument()
})

function SeedRuntimeFeatures({ features }: { features: string[] }) {
  useQueryClient().setQueryData(runtimeFeaturesQueryKey, features)
  return null
}

it('hides the custom-role link once the shell reports the custom-RBAC runtime off', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ items: [owner] })).mockResolvedValueOnce(json(none))
  const actor = principal({ user_id: owner.user_id, permissions: ['identity.self.read', 'identity.roles.manage'] })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  renderWithProviders(<><SeedRuntimeFeatures features={['cache_control']} /><TenantMembersPage /></>, ['/account/members'])
  expect(await screen.findByText('boss')).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: '自定义角色与授权' })).not.toBeInTheDocument()
})
