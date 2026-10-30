import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { approvalCenterApi, type ApprovalRequest } from '../api/approvalCenter'
import * as approvalApi from '../api/approvalCenter'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import ApprovalCenterPage from './ApprovalCenterPage'
import { ApprovalCenterSettings } from './ApprovalCenterSettings'

const pending: ApprovalRequest = {
  id: '11111111-1111-4111-8111-111111111111', rule: 'firewall.policy', step_count: 1,
  steps: [{ method: 'PUT', path: '/v1/firewall/policy', body: '{"rules":[]}' }], reason: '修复误封',
  requested_by_user_id: 'u1', requested_by_name: '张三', requested_at: '2026-10-25T10:00:00Z', expires_at: '2026-10-26T10:00:00Z',
  state: 'pending', decision_note: '', self_approved: false, revision: 1,
}

function authenticate(permissions: string[]) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'approver' }, actor)
}

describe('ApprovalCenterPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(approvalCenterApi, 'list').mockResolvedValue([pending])
  })

  // 社区版：没有充值退款与余额调整页面，不再链接过去。
  it('lists pending requests without links to the removed billing approvals (Q1)', async () => {
    authenticate(['approvals.read'])
    renderWithProviders(<ApprovalCenterPage />)
    expect(await screen.findByText('修复误封')).toBeInTheDocument()
    expect(screen.getByText('修改或恢复全局防火墙')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '充值退款与作废' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '人工余额调整' })).not.toBeInTheDocument()
    expect(approvalCenterApi.list).toHaveBeenCalledWith('approver', 'pending')
  })

  it('asks an approver with MFA for the code and sends the step-up proof (Q3)', async () => {
    authenticate(['approvals.read', 'approvals.approve'])
    vi.spyOn(approvalCenterApi, 'get').mockResolvedValue({ approval: pending, stepUpRequired: true })
    const stepUp = vi.spyOn(approvalApi, 'createApprovalStepUp').mockResolvedValue('proof-token')
    const decide = vi.spyOn(approvalCenterApi, 'decide').mockResolvedValue({ ...pending, state: 'executed', revision: 3 })
    const user = userEvent.setup()
    renderWithProviders(<ApprovalCenterPage />)
    await user.click(await screen.findByRole('button', { name: '查看' }))
    const approve = await screen.findByRole('button', { name: '批准并执行' })
    expect(approve).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: '二次验证码' }), '123456')
    await user.click(approve)
    await waitFor(() => expect(decide).toHaveBeenCalledWith('approver', pending.id, 'approve', { expected_revision: 1, note: '', step_up_token: 'proof-token' }))
    expect(stepUp).toHaveBeenCalledWith('approver', '123456')
  })

  it('lets an approver without MFA approve without a code', async () => {
    authenticate(['approvals.read', 'approvals.approve'])
    vi.spyOn(approvalCenterApi, 'get').mockResolvedValue({ approval: pending, stepUpRequired: false })
    const decide = vi.spyOn(approvalCenterApi, 'decide').mockResolvedValue({ ...pending, state: 'executed', step_up: 'none', revision: 3 })
    const user = userEvent.setup()
    renderWithProviders(<ApprovalCenterPage />)
    await user.click(await screen.findByRole('button', { name: '查看' }))
    expect(screen.queryByRole('textbox', { name: '二次验证码' })).not.toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '批准并执行' }))
    await waitFor(() => expect(decide).toHaveBeenCalledWith('approver', pending.id, 'approve', { expected_revision: 1, note: '' }))
  })

  it('hides the decision buttons from readers', async () => {
    authenticate(['approvals.read'])
    vi.spyOn(approvalCenterApi, 'get').mockResolvedValue({ approval: pending, stepUpRequired: false })
    const user = userEvent.setup()
    renderWithProviders(<ApprovalCenterPage />)
    await user.click(await screen.findByRole('button', { name: '查看' }))
    expect(await screen.findByText('PUT /v1/firewall/policy', { exact: false })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '批准并执行' })).not.toBeInTheDocument()
  })

  it('tells the approver to check the original page when the outcome is unknown (遗留 5)', async () => {
    authenticate(['approvals.read', 'approvals.approve'])
    const unknown: ApprovalRequest = { ...pending, state: 'unknown', step_up: 'none', decided_by_name: '李四', decided_at: '2026-10-25T10:05:00Z', revision: 3 }
    vi.spyOn(approvalCenterApi, 'get').mockResolvedValue({ approval: unknown, stepUpRequired: false })
    const user = userEvent.setup()
    renderWithProviders(<ApprovalCenterPage />)
    await user.click(await screen.findByRole('button', { name: '查看' }))
    expect(await screen.findByText(/系统不会自动重试/)).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: '去处理' }).some((link) => link.getAttribute('href') === '/config/firewall-action')).toBe(true)
    expect(screen.queryByRole('button', { name: '批准并执行' })).not.toBeInTheDocument()
  })
})

describe('ApprovalCenterSettings', () => {
  it('starts off with the first batch preselected and saves the choice', async () => {
    authenticate(['approvals.manage'])
    vi.spyOn(approvalCenterApi, 'settings').mockResolvedValue({
      enabled: false, rules: [], revision: 0,
      catalog: approvalApi.approvalRules.map((name, index) => ({ name, default: index < 4, grouped: name === 'stream.batch_delete', target_path: '/' })),
    })
    const save = vi.spyOn(approvalCenterApi, 'saveSettings').mockImplementation(async (_token, input) => ({ ...input, revision: 1, catalog: [] }))
    const user = userEvent.setup()
    renderWithProviders(<ApprovalCenterSettings />)
    const toggle = await screen.findByRole('switch', { name: '启用审批中心' })
    expect(toggle).not.toBeChecked()
    expect(screen.getByText('审批人：平台所有者与平台管理员。')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /批量删除网站/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /删除用户/ })).not.toBeChecked()
    await user.click(toggle)
    await user.click(screen.getByRole('checkbox', { name: /删除用户/ }))
    await user.click(screen.getByRole('button', { name: /保存/ }))
    await waitFor(() => expect(save).toHaveBeenCalledWith('approver', {
      enabled: true, revision: 0,
      rules: ['site.batch_delete', 'cache.whole_site_purge', 'firewall.policy', 'control.upgrade', 'user.delete'],
    }))
  })

  it('renders nothing without approval permissions', () => {
    authenticate(['platform.admin'])
    const settings = vi.spyOn(approvalCenterApi, 'settings')
    const { container } = renderWithProviders(<ApprovalCenterSettings />)
    expect(container.querySelector('[data-testid="approval-center-settings"]')).toBeNull()
    expect(settings).not.toHaveBeenCalled()
  })
})
