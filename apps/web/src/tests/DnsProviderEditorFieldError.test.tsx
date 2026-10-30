import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'

import { ApiError } from '../api/auth'
import { ProviderEditor } from '../pages/NodeDnsPage'
import { renderWithProviders } from '../test/render'

// fix-fielderr-be2：DNS 账号保存被拒且能定位字段时，原因标在字段下，不出错误条。

function refusal(field: string, reason: string) {
  return Object.assign(new ApiError('API request failed', 400, 'validation_error', 'req-dns'), { field, reason })
}

function Harness({ failure }: { failure: ApiError }) {
  const [error, setError] = useState<ApiError | null>(null)
  return <ProviderEditor editor={{ mode: 'create' }} isAdmin={false} pending={false} uncertain={false} error={error}
    onCancel={() => undefined} onSubmit={() => setError(failure)} onRetry={() => undefined} onCloseAndRefresh={() => undefined} />
}

async function fillAndSave(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText('名称'), 'cf')
  for (const input of screen.getAllByLabelText(/Token|Key|Secret|Email|ID/i)) {
    if (input.tagName === 'INPUT') await user.type(input, 'value-1')
  }
  await user.click(screen.getByRole('button', { name: /保\s*存/ }))
}

describe('DNS provider editor field refusals (fix-fielderr-be2)', () => {
  it('marks a refused name under 名称 without the alert', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Harness failure={refusal('name', 'duplicate')} />)
    await fillAndSave(user)
    const dialog = screen.getByRole('dialog')
    const item = (await within(dialog).findByText('与已有内容重复')).closest('.ant-form-item')
    expect(item?.textContent).toContain('名称')
    expect(dialog.querySelector('.identity-alert')).toBeNull()
  })

  it('marks refused credentials on the first credential input', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Harness failure={refusal('credentials', 'invalid')} />)
    await fillAndSave(user)
    const dialog = screen.getByRole('dialog')
    expect(await within(dialog).findByText('填写的内容不符合要求')).toBeInTheDocument()
    expect(dialog.querySelector('.identity-alert')).toBeNull()
  })

  it('keeps the alert for a refusal without a field', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Harness failure={new ApiError('API request failed', 400, 'validation_error', 'req-dns')} />)
    await fillAndSave(user)
    expect(await screen.findByRole('dialog').then((dialog) => dialog.querySelector('.identity-alert'))).not.toBeNull()
  })
})
