import { fireEvent, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { parsePreviewHeaders, securityPoliciesApi } from '../api/securityPolicies'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

describe('SEC-11 security policy matchers', () => {
	it('canonicalizes repeated preview headers without overwriting values', () => {
		expect(parsePreviewHeaders('X-Mode: strict\nx-mode: relaxed\nX-Trace: one')).toEqual({
			'x-mode': ['strict', 'relaxed'],
			'x-trace': ['one'],
		})
	})

  it.each([
    ['tenant', principal({ permissions: ['security_policies.read', 'security_policies.manage'] })],
    ['platform', principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })],
  ])('exposes bounded count matchers and matching preview facts to %s', async (_role, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const policy = {
      id: '33333333-3333-4333-8333-333333333333', scope_id: actor.scope_id, kind: 'cc' as const,
      name: 'SEC-11 policy', description: '', enabled: true, default_action: 'allow' as const, version: 1,
      created_at: '2026-08-07T00:00:00Z', updated_at: '2026-08-07T00:00:00Z',
      rules: [{
        id: '44444444-4444-4444-8444-444444444444', name: 'Count matcher', priority: 1, enabled: true,
        conditions: [{ field: 'distinct_user_agents' as const, operator: 'number_gte', values: ['3'] }],
        action: 'rate_limit' as const, flow: 'stop' as const,
        action_config: { rate_limit: { window_seconds: 60, max_requests: 10 } },
      }],
    }
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则组' }))
    const editor = await screen.findByRole('dialog', { name: '添加安全规则集' })
    const field = within(editor).getByRole('combobox', { name: '匹配字段' })
    fireEvent.mouseDown(field.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    expect(await screen.findByText('独立 UA 数量', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.getByText('404 状态码数量', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
		// G1-f（d42986650）起 CC 规则可按请求头/UA/Referer 匹配；fix-ja4rule ③（CC v7）起也可按 JA4 匹配。
		expect(screen.getByText('请求头', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
		expect(screen.getByText('TLS 指纹（JA4）', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await user.click(within(editor).getByRole('button', { name: '取消' }))

    await user.click(screen.getByRole('button', { name: `评估${policy.name}` }))
    const preview = await screen.findByRole('dialog', { name: '策略评估预览' })
    expect(within(preview).getByLabelText('独立 UA 数量')).toBeInTheDocument()
    expect(within(preview).getByLabelText('已完成 404 数量')).toBeInTheDocument()
  })
})
