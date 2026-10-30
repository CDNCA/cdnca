import { fireEvent, screen, waitFor } from '@testing-library/react'

import { responseApiError } from '../api/auth'
import * as session from '../auth/session'
import { PasswordChangeGate } from '../components/PasswordChangeGate'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const json = (body: unknown, status: number) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

it('blocks a session that must change the password until it is changed, then signs out', async () => {
  const actor = principal({ password_change_required: true })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ error: { code: 'invalid_credentials' } }, 401))
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
  renderWithProviders(<PasswordChangeGate />, ['/home'])
  expect(await screen.findByText('请先修改密码')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'old password' } })
  fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'A-brand-new-password' } })
  fireEvent.change(screen.getByLabelText('再次输入新密码'), { target: { value: 'A-brand-new-password' } })
  fireEvent.click(screen.getByRole('button', { name: '修改密码' }))
  expect(await screen.findByText('当前密码错误，请重新输入。')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '修改密码' }))
  await waitFor(() => expect(session.useSessionStore.getState().status).toBe('anonymous'))
  const [url, init] = fetchSpy.mock.calls[1]
  expect(String(url)).toMatch(/\/v1\/account\/password$/)
  expect(JSON.parse(String(init?.body))).toEqual({ current_password: 'old password', new_password: 'A-brand-new-password' })
})

it('opens when a request is refused with password_change_required', async () => {
  const actor = principal()
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  renderWithProviders(<PasswordChangeGate />, ['/home'])
  expect(screen.queryByText('请先修改密码')).not.toBeInTheDocument()
  await responseApiError(json({ error: { code: 'password_change_required' } }, 403))
  expect(await screen.findByText('请先修改密码')).toBeInTheDocument()
})

// fix-fielderr-be3: new_password refused by the server is marked under 新密码.
it('marks a refused new password under that field', async () => {
  const actor = principal({ password_change_required: true })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ error: { code: 'validation_error', message: 'm', request_id: 'r',
    details: { field: 'new_password', reason: 'invalid' } } }, 400))
  renderWithProviders(<PasswordChangeGate />, ['/home'])
  expect(await screen.findByText('请先修改密码')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'old password' } })
  fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'A-brand-new-password' } })
  fireEvent.change(screen.getByLabelText('再次输入新密码'), { target: { value: 'A-brand-new-password' } })
  fireEvent.click(screen.getByRole('button', { name: '修改密码' }))
  const item = screen.getByLabelText('新密码').closest('.ant-form-item')!
  await waitFor(() => expect(item).toHaveClass('ant-form-item-has-error'))
  expect(await screen.findByText('填写的内容不符合要求')).toBeInTheDocument()
  expect(document.querySelector('.ant-alert-error')).toBeNull()
})
