import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

function render(permissions: string[], scope: 'platform' | 'tenant' = 'platform') {
  const actor = principal(scope === 'platform'
    ? { scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions }
    : { permissions })
  session.useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'shell-token' }, actor)
  return renderWithProviders(
    <Routes><Route element={<AppShell />}><Route path="*" element={<span />} /></Route></Routes>,
    [scope === 'platform' ? '/admin-home' : '/home'],
  )
}

afterEach(() => vi.unstubAllGlobals())

describe('ticket sidebar badge', () => {
  it('shows the open-ticket count from the summary endpoint on the admin menu entry', async () => {
    const fetchMock = vi.fn(async (path: string) => path === '/v1/admin/tickets/summary'
      ? json({ unread: 2, pending: 7, mine: 1, sla_breached: 0 }) : json({ code: 'not_found' }, 404))
    vi.stubGlobal('fetch', fetchMock)
    render(['tickets.read'])
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/tickets/summary', expect.anything()))
    fireEvent.click(screen.getByRole('menuitem', { name: /系统管理/ }))
    const entry = await screen.findByRole('menuitem', { name: /工单管理/ })
    expect(await within(entry).findByText('7')).toBeInTheDocument()
  })

  it('does not ask for the summary without ticket permission or as a tenant', async () => {
    const fetchMock = vi.fn(async (_path: string) => json({ code: 'not_found' }, 404))
    vi.stubGlobal('fetch', fetchMock)
    const { unmount } = render(['sites.read'])
    unmount()
    render(['tickets.read'], 'tenant')
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('/tickets/summary'))).toBe(false)
  })
})
