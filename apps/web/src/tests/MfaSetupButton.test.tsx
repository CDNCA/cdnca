import { Form, Input } from 'antd'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { useSessionStore } from '../auth/session'
import { MfaSetupButton } from '../components/MfaSetupButton'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

describe('MfaSetupButton nested form labels', () => {
  it.each([
    { status: 'enrollment_pending', action: null, title: '管理身份验证器', label: '六位验证码', field: 'code' },
    { status: 'inactive', action: '设置身份验证器', title: '设置身份验证器', label: '账户标签', field: 'account_label' },
    { status: 'active', action: '停用 MFA', title: '确认停用 MFA', label: '验证码或恢复码', field: 'code' },
    { status: 'active', action: '创建短期授权凭据', title: '创建短期授权凭据', label: '验证码或恢复码', field: 'code' },
  ])('associates $title labels with their own inputs beside an outer $field field', async (test) => {
    const actor = principal({ permissions: ['identity.self.read', 'identity.self.update'] })
    useSessionStore.getState().setSession(authResponse(actor), actor, 'new')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      status: test.status,
      ...(test.status === 'inactive' ? {} : { credential_id: '11111111-1111-4111-8111-111111111111', method: 'totp' }),
      ...(test.status === 'enrollment_pending' ? { enrollment_expires_at: '2030-08-02T10:00:00Z' } : {}),
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<Form initialValues={{ [test.field]: 'outer-draft' }}>
      <Form.Item name={test.field} label="外层字段"><Input /></Form.Item>
      <MfaSetupButton />
    </Form>)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '管理身份验证器' }))
    const entry = await screen.findByRole('dialog', { name: '管理身份验证器' })
    if (test.action) await user.click(await within(entry).findByRole('button', { name: test.action }))
    const title = await screen.findByText(test.title, { selector: '.ant-modal-title' })
    const dialog = title.closest('[role=dialog]') as HTMLElement
    const input = await within(dialog).findByLabelText(test.label)
    const label = within(dialog).getByText(test.label, { selector: 'label' }) as HTMLLabelElement
    expect(label.control).toBe(input)
    expect(input).not.toBe(screen.getByLabelText('外层字段'))
    await user.clear(input)
    await user.type(input, '123456')
    expect(screen.getByLabelText('外层字段')).toHaveValue('outer-draft')
  })
})
