import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ProviderEditor, type ProviderForm } from '../pages/NodeDnsPage'
import { renderWithProviders } from '../test/render'

describe('DNS provider editor DNS.COM plan', () => {
  it('submits the plan tier with the keys (default 免费版)', async () => {
    const onSubmit = vi.fn<(values: ProviderForm) => void>()
    const user = userEvent.setup()
    renderWithProviders(<ProviderEditor editor={{ mode: 'create' }} isAdmin={false} pending={false} uncertain={false}
      error={null} onCancel={() => undefined} onSubmit={onSubmit} onRetry={() => undefined} onCloseAndRefresh={() => undefined} />)
    await user.type(await screen.findByLabelText('名称'), 'dnscom')
    await user.click(screen.getByLabelText('DNS 服务商'))
    await user.click(await screen.findByText('DNS.COM', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText('免费版')).toBeInTheDocument()
    expect(screen.getByText(/旗舰版再加境外/)).toBeInTheDocument()
    await user.type(screen.getByLabelText('API Key'), 'dnscom-key')
    await user.type(screen.getByLabelText('API Secret'), 'dnscom-secret')
    await user.click(screen.getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0][0].credentials).toEqual({ api_key: 'dnscom-key', api_secret: 'dnscom-secret', plan: 'free' })
  })
})
