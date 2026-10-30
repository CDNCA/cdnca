import { fireEvent, screen, waitFor, within } from '@testing-library/react'

import * as session from '../auth/session'
import AdminAccessPage from '../pages/AdminAccessPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import '../i18n/adminAccess'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const policy = (overrides: Record<string, unknown> = {}) => ({
  revision: 0, enabled: false, allowlist: [], updated_at: null, current_ip: '203.0.113.5', ...overrides,
})

function renderPage() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(<AdminAccessPage />, ['/sys/admin-access'])
}

it('adds the current IP, saves with the seen revision and shows the recovery command', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(policy()))
    .mockResolvedValueOnce(json(policy({ revision: 1, enabled: true, allowlist: ['10.0.0.0/8', '203.0.113.5'] })))
  renderPage()
  expect(await screen.findByText('你当前的 IP：203.0.113.5')).toBeInTheDocument()
  expect(screen.getByText('DATABASE_URL=… control-api admin-access-allowlist disable')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('允许的 IP 或网段'), { target: { value: '10.0.0.0/8, 10.0.0.0/8' } })
  fireEvent.click(screen.getByRole('button', { name: '加入当前 IP' }))
  fireEvent.click(screen.getByRole('switch', { name: '启用白名单' }))
  fireEvent.click(screen.getByRole('button', { name: '保存' }))
  const dialog = await screen.findByRole('dialog', { name: '确认保存后台访问白名单？' })
  expect(dialog).toHaveTextContent('保存后不在白名单的 IP（包括你当前的 IP：203.0.113.5）将无法访问后台。')
  expect(fetchSpy).toHaveBeenCalledTimes(1)
  fireEvent.click(within(dialog).getByRole('button', { name: '确认保存' }))
  await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
  const [, init] = fetchSpy.mock.calls[1]
  expect(init?.method).toBe('PUT')
  expect(JSON.parse(String(init?.body))).toEqual({ expected_revision: 0, enabled: true, allowlist: ['10.0.0.0/8', '203.0.113.5'] })
})

it('explains a refused save that would lock the administrator out', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(policy()))
    .mockResolvedValueOnce(json({ error: { code: 'admin_access_self_lockout' } }, 422))
  renderPage()
  fireEvent.change(await screen.findByLabelText('允许的 IP 或网段'), { target: { value: '198.51.100.0/24' } })
  fireEvent.click(screen.getByRole('switch', { name: '启用白名单' }))
  fireEvent.click(screen.getByRole('button', { name: '保存' }))
  fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确认保存' }))
  expect(await screen.findByText('保存后你当前的 IP 将无法访问后台，请先把当前 IP 加入白名单。')).toBeInTheDocument()
})

it('does not save when the lockout confirmation is cancelled (W4)', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(policy()))
  renderPage()
  fireEvent.click(await screen.findByRole('button', { name: '保存' }))
  fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '取消' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  expect(fetchSpy).toHaveBeenCalledTimes(1)
})
