import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { wafRuleSubscriptionsApi } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// fix-fielderr-be3：规则库保存被拒且能定位字段（details.field = rules[n]...）时，
// 编辑弹窗不关、原因标在对应规则的字段下，不弹错误窗。

const policy: SecurityPolicy = {
  id: '33333333-3333-4333-8333-333333333333', scope_id: '22222222-2222-4222-8222-222222222222',
  kind: 'cc', name: 'Login protection', description: '', enabled: true, default_action: 'allow', version: 1,
  created_at: '2026-07-22T12:00:00Z', updated_at: '2026-07-22T12:00:00Z',
  rules: [{
    id: '44444444-4444-4444-8444-444444444444', name: 'Block login', priority: 100, enabled: true,
    conditions: [{ field: 'path', operator: 'prefix', values: ['/login'] }],
    action: 'block', flow: 'stop', action_config: {},
  }, {
    id: '55555555-5555-4555-8555-555555555555', name: 'Block admin', priority: 200, enabled: true,
    conditions: [{ field: 'path', operator: 'prefix', values: ['/admin'] }],
    action: 'block', flow: 'stop', action_config: {},
  }],
}

function refusal(field: string, reason: string) {
  const error = new ApiError('invalid', 400, 'validation_error')
  error.field = field
  error.reason = reason
  return error
}

const dialogNamed = (name: string) => screen.queryAllByRole('dialog').find((node) =>
  node.querySelector('.ant-modal-title')?.textContent?.trim() === name) ?? null

beforeEach(() => {
  vi.restoreAllMocks()
  const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
  useSessionStore.getState().setSession(authResponse(user), user)
  vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([])
  vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
})

describe('SecurityPoliciesPage field errors', () => {
  it('marks a refused rule value under that rule and keeps the editor open', async () => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const update = vi.spyOn(securityPoliciesApi, 'update').mockRejectedValue(refusal('rules[1].conditions[0].values', 'invalid_format'))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    await user.click(await screen.findByRole('button', { name: `编辑${policy.name}` }))
    await waitFor(() => expect(dialogNamed('编辑安全规则集')).not.toBeNull())
    await user.click(within(dialogNamed('编辑安全规则集')!).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())

    const editor = dialogNamed('编辑安全规则集')!
    expect(editor).not.toBeNull()
    const values = within(editor).getAllByDisplayValue(/^\/(login|admin)$/)
    const refused = values.find((node) => (node as HTMLTextAreaElement).value === '/admin')!
    const item = refused.closest('.ant-form-item')!
    await waitFor(() => expect(item).toHaveClass('ant-form-item-has-error'))
    expect(await within(item as HTMLElement).findByText('格式不正确')).toBeInTheDocument()
    const other = values.find((node) => (node as HTMLTextAreaElement).value === '/login')!.closest('.ant-form-item')!
    expect(other).not.toHaveClass('ant-form-item-has-error')
    // No error dialog besides the editor.
    expect(screen.queryAllByRole('dialog').filter((node) => node !== editor && node.querySelector('.cdnca-feedback-dialog, .ant-modal-confirm'))).toHaveLength(0)
    expect(screen.queryByText('规则内容校验失败，请检查字段组合')).not.toBeInTheDocument()
  }, 20_000)

  it('marks a refused policy name on create', async () => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockRejectedValue(refusal('name', 'too_long'))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    await user.click(await screen.findByRole('button', { name: '添加规则组' }))
    await waitFor(() => expect(dialogNamed('添加安全规则集')).not.toBeNull())
    const dialog = dialogNamed('添加安全规则集')!
    await user.type(within(dialog).getByLabelText('名称'), 'Login protection')
    await user.type(within(dialog).getByLabelText('规则名称'), 'Block login')
    await user.type(within(dialog).getByLabelText('匹配值'), '/login')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())

    const item = within(dialogNamed('添加安全规则集')!).getByLabelText('名称').closest('.ant-form-item')!
    await waitFor(() => expect(item).toHaveClass('ant-form-item-has-error'))
    expect(await within(item as HTMLElement).findByText('长度超过上限')).toBeInTheDocument()
  }, 20_000)

  it('a refusal without a field on this form still shows the dialog', async () => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    vi.spyOn(securityPoliciesApi, 'update').mockRejectedValue(new ApiError('invalid', 400, 'validation_error'))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    await user.click(await screen.findByRole('button', { name: `编辑${policy.name}` }))
    await waitFor(() => expect(dialogNamed('编辑安全规则集')).not.toBeNull())
    await user.click(within(dialogNamed('编辑安全规则集')!).getByRole('button', { name: '保存' }))
    expect(await screen.findByText('规则内容校验失败，请检查字段组合')).toBeInTheDocument()
  }, 20_000)
})
