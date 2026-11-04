import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { ProviderEditor } from '../pages/NodeDnsPage'
import { renderWithProviders } from '../test/render'

// DNS API 编辑弹窗只在请求进行中禁用关闭；结果未确认时关闭先确认，确认后走「关闭并刷新」。
function renderEditor(pending: boolean, uncertain: boolean) {
  const onCancel = vi.fn()
  const onCloseAndRefresh = vi.fn()
  renderWithProviders(<ProviderEditor editor={{ mode: 'create' }} isAdmin={false} pending={pending} uncertain={uncertain}
    error={uncertain ? new ApiError('lost', 0, 'network_error') : null} onCancel={onCancel} onSubmit={() => undefined}
    onRetry={() => undefined} onCloseAndRefresh={onCloseAndRefresh} />)
  return { onCancel, onCloseAndRefresh, user: userEvent.setup() }
}

describe('DNS provider editor with an unconfirmed result', () => {
  it('keeps closing disabled while the request is in flight', async () => {
    renderEditor(true, false)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    expect(dialog.querySelector('.ant-modal-close')).toBeNull()
  })

  it('lets an unconfirmed result close after a warning, then closes and refreshes', async () => {
    const { onCancel, onCloseAndRefresh, user } = renderEditor(false, true)
    const dialog = await screen.findByRole('dialog')
    const cancel = within(dialog).getByRole('button', { name: '取消' })
    expect(cancel).toBeEnabled()
    await user.click(cancel)
    const confirm = (await screen.findByText('结果尚未确认，关闭后请刷新列表核对是否已生效')).closest<HTMLElement>('.ant-modal-confirm')!
    expect(onCloseAndRefresh).not.toHaveBeenCalled()
    await user.click(within(confirm).getByRole('button', { name: '关闭' }))
    expect(onCloseAndRefresh).toHaveBeenCalledOnce()
    expect(onCancel).not.toHaveBeenCalled()
  })
})
