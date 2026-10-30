import { fireEvent, screen, waitFor } from '@testing-library/react'

import { responseApiError } from '../api/auth'
import * as session from '../auth/session'
import { SessionRegionGate } from '../components/SessionRegionGate'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const json = (body: unknown, status: number) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

it('asks for the password after session_region_changed and re-binds the session', async () => {
  const actor = principal()
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  const reload = vi.fn()
  Object.defineProperty(window, 'location', { value: { ...window.location, reload }, configurable: true })
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ error: { code: 'invalid_credentials' } }, 401))
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
  renderWithProviders(<SessionRegionGate />, ['/home'])
  expect(screen.queryByText('登录地区发生变化')).not.toBeInTheDocument()
  await responseApiError(json({ error: { code: 'session_region_changed' } }, 401))
  expect(await screen.findByText('登录地区发生变化')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('登录密码'), { target: { value: 'pw' } })
  fireEvent.click(screen.getByRole('button', { name: '验证并继续' }))
  expect(await screen.findByText('密码错误，请重新输入。')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '验证并继续' }))
  await waitFor(() => expect(reload).toHaveBeenCalled())
  const [url, init] = fetchSpy.mock.calls[1]
  expect(String(url)).toMatch(/\/v1\/auth\/session-region-verifications$/)
  expect(JSON.parse(String(init?.body))).toEqual({ password: 'pw' })
})
