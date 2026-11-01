import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fireEvent, screen, waitFor } from '@testing-library/react'

import { renderWithProviders } from '../test/render'
import { ApprovalPromptHost } from './ApprovalPromptHost'

// 审批弹窗与 approvalCenter 文案按需加载，宿主仍挂在每个页面上，
// 428 approval_required 时照常弹出原因框，填写后带原因重发。
describe('ApprovalPromptHost', () => {
  const original = globalThis.fetch
  afterEach(() => { globalThis.fetch = original })

  it('keeps the dialog and the approvalCenter namespace out of its static imports', () => {
    const source = readFileSync(resolve(__dirname, 'ApprovalPromptHost.tsx'), 'utf8')
    expect(source).not.toMatch(/^import\s+['"][^'"]*i18n\/approvalCenter['"]/m)
    expect(source).not.toMatch(/^import\s+[^'"]*from\s+['"]\.\/ApprovalPromptDialog['"]/m)
  })

  it('opens the reason dialog on approval_required and resends with the reason', async () => {
    const calls: RequestInit[] = []
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(init ?? {})
      if (calls.length === 1) {
        return new Response(JSON.stringify({ error: { code: 'approval_required', details: { rule: 'user.delete' } } }), { status: 428 })
      }
      return new Response(null, { status: 202 })
    }) as typeof fetch
    renderWithProviders(<ApprovalPromptHost />)
    // The host wraps fetch in an effect; wait for it before calling.
    await waitFor(() => expect(globalThis.fetch).not.toBe(original))
    const result = globalThis.fetch('/v1/users/1', { method: 'DELETE' })

    expect(await screen.findByText('该操作需要审批')).toBeInTheDocument()
    expect(screen.getByText(/「删除用户」已纳入审批中心/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('原因'), { target: { value: '清理测试账号' } })
    fireEvent.click(screen.getByRole('button', { name: '提交审批' }))

    expect((await result).status).toBe(409)
    expect(new Headers(calls[1].headers).get('X-Approval-Reason')).toBe(encodeURIComponent('清理测试账号'))
    expect(await screen.findByText('已提交审批，审批人批准后执行')).toBeInTheDocument()
  })
})
