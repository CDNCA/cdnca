import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import type { DNSProvider } from '../api/dns'
import { ProviderEditor, type ProviderForm } from '../pages/NodeDnsPage'
import { renderWithProviders } from '../test/render'

// DNS-UX-20261027-02：禁用撤销了旧凭据；重新启用必须录入新凭据，不能只改状态保存。
const disabledProvider: DNSProvider = {
  id: '018f0000-0000-7000-8000-000000000001', scope_id: '018f0000-0000-7000-8000-000000000002',
  name: 'own-cloudflare', remark: '', provider_type: 'cloudflare', credentials_configured: true,
  status: 'disabled', managed_by: 'tenant', version: 3,
  created_at: '2026-10-27T00:00:00Z', updated_at: '2026-10-27T00:00:00Z',
}

function renderEditor(item: DNSProvider, onSubmit: (values: ProviderForm) => void) {
  renderWithProviders(<ProviderEditor editor={{ mode: 'edit', item }} isAdmin={false} pending={false}
    uncertain={false} error={null} onCancel={() => undefined} onSubmit={onSubmit} onRetry={() => undefined}
    onCloseAndRefresh={() => undefined} />)
}

describe('DNS provider editor re-authorization', () => {
  it('requires new credentials to enable a disabled account and submits them', async () => {
    const onSubmit = vi.fn<(values: ProviderForm) => void>()
    const user = userEvent.setup()
    renderEditor(disabledProvider, onSubmit)
    expect(await screen.findByText(/禁用时旧凭据已作废/)).toBeInTheDocument()
    await user.click(screen.getByLabelText('状态'))
    await user.click(await screen.findByText('重新授权并启用', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText(/请填写新的凭据/)).toBeInTheDocument()
    expect(screen.queryByLabelText('替换凭据')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(screen.getAllByText('请输入有效的凭据字段').length).toBeGreaterThan(0))
    expect(onSubmit).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('API Token'), 'new-token')
    await user.click(screen.getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0][0]).toMatchObject({
      status: 'unverified', replace_credentials: true, credentials: { api_token: 'new-token' },
    })
  })

  it('keeps a disabled account disabled without asking for credentials', async () => {
    const onSubmit = vi.fn<(values: ProviderForm) => void>()
    const user = userEvent.setup()
    renderEditor(disabledProvider, onSubmit)
    await user.clear(await screen.findByLabelText('名称'))
    await user.type(screen.getByLabelText('名称'), 'renamed')
    await user.click(screen.getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0][0]).toMatchObject({ status: 'disabled', replace_credentials: false })
  })
})
